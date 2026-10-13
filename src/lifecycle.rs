//! Loss accounting and shutdown diagnostics, kept independent of SDK errors.
use opentelemetry::InstrumentationScope;
use opentelemetry_sdk::{
    Resource,
    error::{OTelSdkError, OTelSdkResult},
    logs::{BatchLogProcessor, LogProcessor, SdkLogRecord},
};
use std::{
    cell::Cell,
    fmt,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tracing::{
    Dispatch, Event, Metadata, Subscriber,
    field::{Field, Visit},
    span,
};
use tracing_subscriber::{Layer, layer::Context};

/// A signal's loss counter. Units are log records, measurements and spans.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// Log records.
    Logs,
    /// Measurements (record calls), per ADR-0003 decision 23.
    Metrics,
    /// Spans.
    Traces,
}

/// Signals with SDK queues; metrics cannot enter queue accounting or capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QueueSignal {
    Logs,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "constructed only by the trace pipeline, wired into init by 8c (#8)"
        )
    )]
    Traces,
}
impl QueueSignal {
    /// Number of SDK queues: logs and traces; metrics have no queue.
    const COUNT: usize = 2;
}

/// Flush/shutdown outcome, ordered by precedence: timeout, failure, data loss.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushErrorKind {
    /// The operation did not finish in time; more data than counted may be lost.
    Timeout,
    /// The SDK or sink reported an error.
    Failed,
    /// Export completed but data was lost during the reporting period.
    DataLost,
}

/// A flush/shutdown error with per-signal lower bounds on loss.
/// Concrete error sources are not stable; downcasting is unsupported.
/// `Error::source()` returns the logs source when present, otherwise the
/// metrics source, then the traces source. Display keeps each source on its own signal's part.
/// The `Display` text is for people; it is not part of the stability promise. Match on `kind()`.
#[derive(Debug)]
pub struct FlushError {
    kind: FlushErrorKind,
    signal_kinds: [Option<FlushErrorKind>; 3],
    logs: u64,
    spans: u64,
    measurements: u64,
    data_points_lost: bool,
    metric_names_poisoned: bool,
    sources: [Option<OTelSdkError>; 3],
}
impl FlushError {
    /// The highest-priority outcome: Timeout, then Failed, then DataLost.
    pub fn kind(&self) -> FlushErrorKind {
        self.kind
    }

    /// The outcome belonging to this signal alone.
    pub(crate) fn signal_kind(&self, signal: Signal) -> Option<FlushErrorKind> {
        self.signal_kinds[signal as usize]
    }

    /// A lower bound on lost data, in the signal's own unit.
    ///
    /// Flush and shutdown count losses since the previous flush or startup:
    /// failed exports, diagnostic stubs and queue overflow. Overflow counting
    /// is independent of SDK diagnostics, static max levels and consumer filters.
    /// Counts are exact when producers are quiescent and draining succeeds.
    /// Concurrent arrivals reaching the exporter after the flush watermark can
    /// reduce the overflow lower bound; a later drain or shutdown can recover
    /// it. Timed-out/failed drains leave queued and in-flight records uncounted,
    /// since they may still be exported. Shutdown also reconciles the SDK's
    /// since-start overflow total without counting previously reported losses.
    /// Records arriving concurrently after shutdown's watermark/counter read
    /// or worker disconnection can be lost without being counted.
    ///
    /// A failed durable log line counts its records even if another copy
    /// reached a remote receiver. A failed span line counts its spans.
    /// Metrics count measurements
    /// that never reached the SDK, including records made before initialization.
    /// Records made while metrics are off or failed are not counted, nor are
    /// data-point export failures or measurements aggregated before a later name
    /// conflict (ADR-0003 d23).
    /// Records rejected after shutdown begins are not counted.
    pub fn lost(&self, signal: Signal) -> u64 {
        match signal {
            Signal::Logs => self.logs,
            Signal::Metrics => self.measurements,
            Signal::Traces => self.spans,
        }
    }
}
impl fmt::Display for FlushError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.kind)?;
        let mut separator = ": ";
        self.display_queue(
            f,
            Signal::Logs,
            self.logs,
            "log records",
            "log",
            &mut separator,
        )?;
        if self.measurements != 0 {
            write!(
                f,
                "{separator}at least {} metric measurements lost",
                self.measurements
            )?;
            separator = "; ";
        }
        if self.metric_names_poisoned {
            write!(
                f,
                "{separator}metric names poisoned by conflicting declarations"
            )?;
            separator = "; ";
        }
        if self.data_points_lost {
            write!(f, "{separator}metric data points dropped")?;
            separator = "; ";
        }
        let metric_label = match self.signal_kind(Signal::Metrics) {
            Some(FlushErrorKind::Timeout) => Some("metric export timed out"),
            Some(FlushErrorKind::Failed) => Some("metric export failed"),
            _ => None,
        };
        if let Some(label) = metric_label {
            write!(f, "{separator}{label}")?;
            if let Some(source) = &self.sources[1] {
                write!(f, ": {source}")?;
            }
            separator = "; ";
        }
        self.display_queue(
            f,
            Signal::Traces,
            self.spans,
            "spans",
            "span",
            &mut separator,
        )?;
        Ok(())
    }
}
impl FlushError {
    /// Render a queue signal's count followed by its own outcome and source.
    fn display_queue(
        &self,
        f: &mut fmt::Formatter<'_>,
        signal: Signal,
        count: u64,
        unit: &str,
        name: &str,
        separator: &mut &str,
    ) -> fmt::Result {
        if count != 0 {
            write!(f, "{separator}at least {count} {unit} lost")?;
            *separator = "; ";
        }
        let label = match self.signal_kind(signal) {
            Some(FlushErrorKind::Timeout) => "timed out",
            Some(FlushErrorKind::Failed) => "failed",
            _ => return Ok(()),
        };
        write!(f, "{separator}{name} export {label}")?;
        *separator = "; ";
        if let Some(source) = &self.sources[signal as usize] {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}
impl std::error::Error for FlushError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.sources[0]
            .as_ref()
            .or(self.sources[1].as_ref())
            .or(self.sources[2].as_ref())
            .map(|source| source as _)
    }
}

/// Losses and outcomes since the last completed reporting period.
#[derive(Debug, Default)]
struct Period {
    logs: u64,
    spans: u64,
    measurements: u64,
    metrics_failed: bool,
    metrics_data_lost: bool,
    metric_names_poisoned: bool,
    failed: bool,
    timeout: bool,
    metrics_timeout: bool,
    traces_failed: bool,
    traces_timeout: bool,
}

/// Queue watermarks and diagnostics shared by logs and traces.
#[derive(Debug, Default)]
struct QueueCounts {
    accepted: u64,
    reached: u64,
    overflow_reported: u64,
    sdk_overflow: u64,
    pending_stderr: u64,
    pending_failed: bool,
}
/// Per-signal queue totals and the current reporting period.
#[derive(Debug, Default)]
struct State {
    period: Period,
    queues: [QueueCounts; QueueSignal::COUNT],
    #[cfg(feature = "metrics")]
    pending_measurements: u64,
    #[cfg(feature = "metrics")]
    pending_points: u64,
    #[cfg(feature = "metrics")]
    pending_metrics_failed: bool,
}
#[cfg(all(test, feature = "metrics"))]
#[derive(Debug)]
pub(crate) struct FlushOrderProbe {
    pub(crate) started: std::sync::mpsc::Receiver<()>,
    pub(crate) release: std::sync::mpsc::Sender<()>,
}

#[derive(Debug, Default)]
pub(crate) struct Losses {
    state: Mutex<State>,
    pub(crate) shutting_down: AtomicBool,
    #[cfg(all(test, feature = "metrics"))]
    pub(crate) metric_export_started: Mutex<Option<std::sync::mpsc::Sender<()>>>,
    #[cfg(all(test, feature = "metrics"))]
    pub(crate) before_logs_flush: Mutex<Option<FlushOrderProbe>>,
}
impl Losses {
    #[cfg(all(test, feature = "metrics"))]
    pub(crate) fn observe_flush_order(&self) {
        if let Some(probe) = self.before_logs_flush.lock().unwrap().take() {
            let observed = probe.started.recv_timeout(Duration::from_secs(2));
            probe.release.send(()).unwrap();
            assert!(
                observed.is_ok(),
                "metrics collection must start before logs flush"
            );
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    /// Account for a failed export or diagnostic stub in the signal's unit.
    pub(crate) fn record(&self, signal: QueueSignal, count: u64, failed: bool) {
        let mut state = self.state();
        match signal {
            QueueSignal::Logs => {
                state.period.logs = state.period.logs.saturating_add(count);
                state.period.failed |= failed;
            }
            QueueSignal::Traces => {
                state.period.spans = state.period.spans.saturating_add(count);
                state.period.traces_failed |= failed;
            }
        }
        let queue = &mut state.queues[signal as usize];
        queue.pending_failed |= failed;
        queue.pending_stderr = queue.pending_stderr.saturating_add(count);
    }
    #[cfg(feature = "metrics")]
    pub(crate) fn metric_name_poisoned(&self) {
        self.state().period.metric_names_poisoned = true;
    }
    #[cfg(feature = "metrics")]
    pub(crate) fn measurements_dropped(&self, n: u64) {
        let mut state = self.state();
        state.period.measurements = state.period.measurements.saturating_add(n);
        state.pending_measurements = state.pending_measurements.saturating_add(n);
    }
    #[cfg(feature = "metrics")]
    pub(crate) fn measurements_reported_at_start(&self, n: u64) {
        let mut state = self.state();
        state.period.measurements = state.period.measurements.saturating_add(n);
    }
    #[cfg(feature = "metrics")]
    pub(crate) fn pending_measurements(&self) -> u64 {
        self.state().pending_measurements
    }
    #[cfg(feature = "metrics")]
    pub(crate) fn metric_data_points(&self, failed: bool) {
        let mut state = self.state();
        state.period.metrics_failed |= failed;
        state.period.metrics_data_lost |= !failed;
        state.pending_metrics_failed |= failed;
    }
    #[cfg(feature = "metrics")]
    pub(crate) fn metric_pending(&self, lost: u64, reported: u64) {
        let mut state = self.state();
        state.pending_points = state
            .pending_points
            .saturating_add(lost)
            .saturating_sub(reported);
        if reported != 0 && state.pending_points == 0 {
            state.pending_metrics_failed = false;
        }
    }
    #[cfg(feature = "metrics")]
    pub(crate) fn pending_metrics(&self) -> (u64, bool) {
        let state = self.state();
        (state.pending_points, state.pending_metrics_failed)
    }
    /// Retain a provider outcome under its own signal.
    pub(crate) fn outcome(&self, signal: Signal, result: &OTelSdkResult) {
        let mut state = self.state();
        let timeout = matches!(result, Err(OTelSdkError::Timeout(_)));
        match signal {
            Signal::Metrics => {
                state.period.metrics_timeout |= timeout;
                state.period.metrics_failed |= result.is_err() && !timeout;
            }
            Signal::Traces => {
                state.period.traces_timeout |= timeout;
                state.period.traces_failed |= result.is_err() && !timeout;
            }
            Signal::Logs => {
                state.period.timeout |= timeout;
                state.period.failed |= result.is_err() && !timeout;
            }
        }
    }
    /// Count records or spans handed to the exporter.
    pub(crate) fn reached(&self, signal: QueueSignal, logs: u64) {
        let mut state = self.state();
        state.queues[signal as usize].reached =
            state.queues[signal as usize].reached.saturating_add(logs);
    }
    /// Remove losses already included in a runtime stderr report.
    pub(crate) fn reported(&self, signal: QueueSignal, logs: u64) {
        let mut state = self.state();
        state.queues[signal as usize].pending_stderr = state.queues[signal as usize]
            .pending_stderr
            .saturating_sub(logs);
        state.queues[signal as usize].pending_failed = false;
    }
    /// Losses and failure status still awaiting a stderr report.
    pub(crate) fn pending_stderr(&self, signal: QueueSignal) -> (u64, bool) {
        let state = self.state();
        (
            state.queues[signal as usize].pending_stderr,
            state.queues[signal as usize].pending_failed,
        )
    }
    /// Reconcile the SDK's lifetime queue-overflow count at shutdown.
    fn overflow_total(&self, signal: QueueSignal, total: u64) {
        let mut state = self.state();
        state.queues[signal as usize].sdk_overflow = total;
        Self::overflow(&mut state, signal, total);
    }
    /// Add only the overflow not accounted for by an earlier drain.
    fn overflow(state: &mut State, signal: QueueSignal, total: u64) {
        let lost = total.saturating_sub(state.queues[signal as usize].overflow_reported);
        state.queues[signal as usize].overflow_reported =
            state.queues[signal as usize].overflow_reported.max(total);
        match signal {
            QueueSignal::Logs => state.period.logs = state.period.logs.saturating_add(lost),
            QueueSignal::Traces => state.period.spans = state.period.spans.saturating_add(lost),
        }
        state.queues[signal as usize].pending_stderr = state.queues[signal as usize]
            .pending_stderr
            .saturating_add(lost);
    }
    /// Count the accepted/exported difference only after a successful drain.
    fn drained(&self, signal: QueueSignal, accepted: u64, result: &OTelSdkResult) {
        if result.is_ok() {
            let mut state = self.state();
            // Everything accepted before the request has drained. Later
            // arrivals may have reached the exporter too: subtracting them
            // deliberately undercounts rather than counting queued records.
            let total = accepted.saturating_sub(state.queues[signal as usize].reached);
            Self::overflow(&mut state, signal, total);
        }
    }
    #[cfg(test)]
    /// Finish a logs-only test period.
    pub(crate) fn finish(&self, result: OTelSdkResult) -> Result<(), FlushError> {
        self.finish_signals(result, Ok(()), Ok(()))
    }
    /// Consume a period, retaining each caller's three provider outcomes.
    pub(crate) fn finish_signals(
        &self,
        result: OTelSdkResult,
        metrics: OTelSdkResult,
        traces: OTelSdkResult,
    ) -> Result<(), FlushError> {
        #[cfg(feature = "metrics")]
        crate::metrics::drain_before_init(self, false);
        let mut period = std::mem::take(&mut self.state().period);
        // Each caller retains its own outcome even if another concurrent
        // flush consumed the period's shared counts and exporter flags.
        period.metrics_timeout |= matches!(metrics, Err(OTelSdkError::Timeout(_)));
        period.metrics_failed |= metrics.is_err() && !period.metrics_timeout;
        period.traces_timeout |= matches!(traces, Err(OTelSdkError::Timeout(_)));
        period.traces_failed |= traces.is_err() && !period.traces_timeout;
        let kind = if period.traces_timeout
            || period.timeout
            || period.metrics_timeout
            || matches!(result, Err(OTelSdkError::Timeout(_)))
        {
            FlushErrorKind::Timeout
        } else if period.traces_failed || period.failed || period.metrics_failed || result.is_err()
        {
            FlushErrorKind::Failed
        } else if period.spans != 0
            || period.logs != 0
            || period.measurements != 0
            || period.metrics_data_lost
            || period.metric_names_poisoned
        {
            FlushErrorKind::DataLost
        } else {
            return Ok(());
        };
        let signal_kind = |timeout: bool, failed: bool, lost: bool| {
            if timeout {
                Some(FlushErrorKind::Timeout)
            } else if failed {
                Some(FlushErrorKind::Failed)
            } else if lost {
                Some(FlushErrorKind::DataLost)
            } else {
                None
            }
        };
        Err(FlushError {
            kind,
            signal_kinds: [
                signal_kind(
                    period.timeout || matches!(result, Err(OTelSdkError::Timeout(_))),
                    period.failed || result.is_err(),
                    period.logs != 0,
                ),
                signal_kind(
                    period.metrics_timeout,
                    period.metrics_failed,
                    period.metrics_data_lost
                        || period.measurements != 0
                        || period.metric_names_poisoned,
                ),
                signal_kind(
                    period.traces_timeout,
                    period.traces_failed,
                    period.spans != 0,
                ),
            ],
            spans: period.spans,
            logs: period.logs,
            measurements: period.measurements,
            data_points_lost: period.metrics_data_lost,
            metric_names_poisoned: period.metric_names_poisoned,
            sources: [result.err(), metrics.err(), traces.err()],
        })
    }

    /// Preserve a signal's typed shutdown timeout before SDK stringification.
    fn observe(&self, signal: Signal, result: OTelSdkResult) -> OTelSdkResult {
        if matches!(result, Err(OTelSdkError::Timeout(_))) {
            self.outcome(signal, &result);
        }
        result
    }
}

thread_local! {
    // force_flush runs on its caller's thread. Keep its typed timeout per
    // caller so simultaneous shared-pipeline flushes cannot consume it.
    static FLUSH_TIMEOUT: Cell<Option<Duration>> = const { Cell::new(None) };
}

/// Run either provider's flush, recovering its caller-local typed timeout.
pub(crate) fn flush(flush: impl FnOnce() -> OTelSdkResult) -> OTelSdkResult {
    FLUSH_TIMEOUT.with(|timeout| {
        timeout.set(None);
        let result = flush();
        match timeout.take() {
            Some(duration) => Err(OTelSdkError::Timeout(duration)),
            None => result,
        }
    })
}

/// Preserve typed log processor timeouts before the provider stringifies them.
#[derive(Debug)]
pub(crate) struct ReportingProcessor {
    pub(crate) inner: BatchLogProcessor,
    pub(crate) losses: Arc<Losses>,
}
impl LogProcessor for ReportingProcessor {
    fn emit(&self, data: &mut SdkLogRecord, scope: &InstrumentationScope) {
        // Count only completed emits: an unfinished emit must never be
        // mistaken for overflow at a concurrent flush's watermark.
        self.inner.emit(data, scope);
        let mut state = self.losses.state();
        state.queues[QueueSignal::Logs as usize].accepted = state.queues
            [QueueSignal::Logs as usize]
            .accepted
            .saturating_add(1);
    }
    fn force_flush(&self) -> OTelSdkResult {
        let accepted = self.losses.state().queues[QueueSignal::Logs as usize].accepted;
        let result = self.inner.force_flush();
        self.losses.drained(QueueSignal::Logs, accepted, &result);
        if let Err(OTelSdkError::Timeout(duration)) = &result {
            FLUSH_TIMEOUT.with(|timeout| timeout.set(Some(*duration)));
        }
        result
    }
    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        let accepted = self.losses.state().queues[QueueSignal::Logs as usize].accepted;
        let result = self
            .losses
            .observe(Signal::Logs, self.inner.shutdown_with_timeout(timeout));
        self.losses.drained(QueueSignal::Logs, accepted, &result);
        result
    }
    fn set_resource(&mut self, resource: &Resource) {
        self.inner.set_resource(resource);
    }
}

/// Counts completed span submissions and preserves typed processor timeouts.
#[cfg(feature = "traces")]
#[cfg_attr(not(test), expect(dead_code, reason = "wired into init by 8c (#8)"))]
#[derive(Debug)]
pub(crate) struct ReportingSpanProcessor<P: opentelemetry_sdk::trace::SpanProcessor> {
    pub(crate) inner: P,
    pub(crate) losses: Arc<Losses>,
}
#[cfg(feature = "traces")]
impl<P: opentelemetry_sdk::trace::SpanProcessor> opentelemetry_sdk::trace::SpanProcessor
    for ReportingSpanProcessor<P>
{
    fn on_start(&self, span: &mut opentelemetry_sdk::trace::Span, cx: &opentelemetry::Context) {
        self.inner.on_start(span, cx);
    }
    fn on_end(&self, span: opentelemetry_sdk::trace::SpanData) {
        self.inner.on_end(span);
        let mut state = self.losses.state();
        let queue = &mut state.queues[QueueSignal::Traces as usize];
        queue.accepted = queue.accepted.saturating_add(1);
    }
    fn force_flush(&self) -> OTelSdkResult {
        let accepted = self.losses.state().queues[QueueSignal::Traces as usize].accepted;
        let result = self.inner.force_flush();
        self.losses.drained(QueueSignal::Traces, accepted, &result);
        if let Err(OTelSdkError::Timeout(duration)) = &result {
            FLUSH_TIMEOUT.with(|timeout| timeout.set(Some(*duration)));
        }
        result
    }
    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        let accepted = self.losses.state().queues[QueueSignal::Traces as usize].accepted;
        let result = self
            .losses
            .observe(Signal::Traces, self.inner.shutdown_with_timeout(timeout));
        self.losses.drained(QueueSignal::Traces, accepted, &result);
        result
    }
    fn set_resource(&mut self, resource: &Resource) {
        self.inner.set_resource(resource);
    }
}

// Warnings belong in on_event: constructing a shutdown capture rebuilds
// callsite interest, which evaluates enabled filters without emitting anything.
pub(crate) struct AfterShutdown {
    pub(crate) stopped: Arc<AtomicBool>,
    pub(crate) warned: AtomicBool,
}
impl<S: Subscriber> Layer<S> for AfterShutdown {
    fn on_event(&self, _: &Event<'_>, _: Context<'_, S>) {
        if self.stopped.load(Ordering::Acquire) && !self.warned.swap(true, Ordering::Relaxed) {
            use std::io::Write;
            let _ = writeln!(
                std::io::stderr(),
                "vigil: event after shutdown; further events will be dropped silently"
            );
        }
    }
}

/// Extract the configured SDK overflow field from an event.
struct Count {
    value: u64,
    field: &'static str,
}
impl Visit for Count {
    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == self.field {
            self.value = value;
        }
    }
    fn record_debug(&mut self, _: &Field, _: &dyn fmt::Debug) {}
}

// Enabled independently of the consumer's filters. Every other callback is
// delegated to the dispatcher captured on the calling thread before spawning.
/// Capture one signal's SDK overflow event on the provider shutdown thread.
pub(crate) struct ShutdownCapture {
    event: &'static str,
    field: &'static str,
    signal: QueueSignal,
    forward: Dispatch,
    losses: Arc<Losses>,
}
impl ShutdownCapture {
    /// Install the single SDK event/field definition for this queue signal.
    pub(crate) fn new(signal: QueueSignal, forward: Dispatch, losses: Arc<Losses>) -> Self {
        let (event, field) = match signal {
            QueueSignal::Logs => ("BatchLogProcessor.LogsDropped", "dropped_logs_count"),
            QueueSignal::Traces => ("BatchSpanProcessor.SpansDropped", "dropped_span_count"),
        };
        Self {
            signal,
            event,
            field,
            forward,
            losses,
        }
    }

    /// Match only the configured SDK event, forwarding every other event.
    fn captures(&self, meta: &Metadata<'_>) -> bool {
        meta.target().starts_with("opentelemetry") && meta.name() == self.event
    }
}
impl Subscriber for ShutdownCapture {
    fn enabled(&self, meta: &Metadata<'_>) -> bool {
        self.captures(meta) || self.forward.enabled(meta)
    }
    fn event(&self, event: &Event<'_>) {
        if self.captures(event.metadata()) {
            let mut count = Count {
                value: 0,
                field: self.field,
            };
            event.record(&mut count);
            self.losses.overflow_total(self.signal, count.value);
        } else {
            self.forward.event(event);
        }
    }
    fn new_span(&self, attrs: &span::Attributes<'_>) -> span::Id {
        self.forward.new_span(attrs)
    }
    fn record(&self, id: &span::Id, values: &span::Record<'_>) {
        self.forward.record(id, values);
    }
    fn record_follows_from(&self, id: &span::Id, follows: &span::Id) {
        self.forward.record_follows_from(id, follows);
    }
    fn enter(&self, id: &span::Id) {
        self.forward.enter(id);
    }
    fn exit(&self, id: &span::Id) {
        self.forward.exit(id);
    }
    fn clone_span(&self, id: &span::Id) -> span::Id {
        self.forward.clone_span(id)
    }
    fn try_close(&self, id: span::Id) -> bool {
        self.forward.try_close(id)
    }
    fn current_span(&self) -> tracing_core::span::Current {
        self.forward.current_span()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_outcome_is_isolated() {
        let losses = Losses::default();
        losses.outcome(Signal::Traces, &Err(OTelSdkError::Timeout(Duration::ZERO)));
        let error = losses.finish_signals(Ok(()), Ok(()), Ok(())).unwrap_err();
        assert_eq!(error.signal_kind(Signal::Logs), None);
        assert_eq!(
            error.signal_kind(Signal::Traces),
            Some(FlushErrorKind::Timeout)
        );
        assert_eq!(error.to_string(), "Timeout: span export timed out");
    }

    #[test]
    fn display_three_signals_and_counted_outcomes() {
        for (timeout, label) in [(true, "timed out"), (false, "failed")] {
            let losses = Losses::default();
            losses.record(QueueSignal::Logs, 2, false);
            let result = if timeout {
                Err(OTelSdkError::Timeout(Duration::ZERO))
            } else {
                Err(OTelSdkError::InternalFailure("logs".into()))
            };
            let source = result.as_ref().unwrap_err().to_string();
            let error = losses.finish(result).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!(
                    "{:?}: at least 2 log records lost; log export {label}: {source}",
                    error.kind()
                )
            );
        }
        let losses = Losses::default();
        losses.record(QueueSignal::Traces, 4, true);
        assert_eq!(
            losses.finish(Ok(())).unwrap_err().to_string(),
            "Failed: at least 4 spans lost; span export failed"
        );
        losses.record(QueueSignal::Logs, 2, true);
        losses.record(QueueSignal::Traces, 3, false);
        let metric = OTelSdkError::Timeout(Duration::ZERO);
        let trace = OTelSdkError::InternalFailure("traces".into());
        let expected = format!(
            "Timeout: at least 2 log records lost; log export failed; metric export timed out: {metric}; at least 3 spans lost; span export failed: {trace}"
        );
        let error = losses
            .finish_signals(Ok(()), Err(metric), Err(trace))
            .unwrap_err();
        assert_eq!(error.to_string(), expected);
        assert_eq!(error.lost(Signal::Traces), 3);
        for timeout in [false, true] {
            let mut error = metric_only_error(if timeout {
                FlushErrorKind::Timeout
            } else {
                FlushErrorKind::Failed
            });
            error.data_points_lost = true;
            error.measurements = 5;
            let label = if timeout { "timed out" } else { "failed" };
            assert_eq!(
                error.to_string(),
                format!(
                    "{:?}: at least 5 metric measurements lost; metric data points dropped; metric export {label}: Operation failed: metrics",
                    error.kind()
                )
            );
        }
    }

    #[test]
    fn trace_source_precedence_and_runtime_isolation() {
        let losses = Losses::default();
        let failure = || Err(OTelSdkError::InternalFailure("trace source".into()));
        let error = losses
            .finish_signals(Ok(()), Ok(()), failure())
            .unwrap_err();
        assert_eq!(
            std::error::Error::source(&error).unwrap().to_string(),
            "Operation failed: trace source"
        );
        let error = losses
            .finish_signals(
                Err(OTelSdkError::InternalFailure("log source".into())),
                Ok(()),
                failure(),
            )
            .unwrap_err();
        assert_eq!(
            std::error::Error::source(&error).unwrap().to_string(),
            "Operation failed: log source"
        );
        assert_eq!(losses.pending_stderr(QueueSignal::Logs), (0, false));
        losses.record(QueueSignal::Traces, 4, true);
        assert_eq!(losses.pending_stderr(QueueSignal::Logs), (0, false));
        assert_eq!(losses.pending_stderr(QueueSignal::Traces), (4, true));
        losses.record(QueueSignal::Logs, 2, false);
        losses.record(QueueSignal::Traces, 1, true);
        assert_eq!(losses.pending_stderr(QueueSignal::Logs), (2, false));
        assert_eq!(losses.pending_stderr(QueueSignal::Traces), (5, true));
        let error = losses.finish(Ok(())).unwrap_err();
        assert_eq!(error.lost(Signal::Logs), 2);
        assert_eq!(error.lost(Signal::Traces), 5);
        assert_eq!(
            error.signal_kind(Signal::Logs),
            Some(FlushErrorKind::DataLost)
        );
    }

    #[cfg(feature = "traces")]
    #[test]
    fn trace_shutdown_timeout_is_isolated() {
        use opentelemetry_sdk::trace::{SdkTracerProvider, Span, SpanData, SpanProcessor};
        #[derive(Debug)]
        struct Timeout;
        impl SpanProcessor for Timeout {
            fn on_start(&self, _: &mut Span, _: &opentelemetry::Context) {}
            fn on_end(&self, _: SpanData) {}
            fn force_flush(&self) -> OTelSdkResult {
                Ok(())
            }
            fn shutdown_with_timeout(&self, _: Duration) -> OTelSdkResult {
                Err(OTelSdkError::Timeout(Duration::ZERO))
            }
        }
        let losses = Arc::new(Losses::default());
        let provider = SdkTracerProvider::builder()
            .with_span_processor(ReportingSpanProcessor {
                inner: Timeout,
                losses: losses.clone(),
            })
            .build();
        let result = provider.shutdown_with_timeout(Duration::ZERO);
        assert!(matches!(result, Err(OTelSdkError::InternalFailure(_))));
        let error = losses.finish_signals(Ok(()), Ok(()), result).unwrap_err();
        assert_eq!(
            error.signal_kind(Signal::Traces),
            Some(FlushErrorKind::Timeout)
        );
        assert_eq!(error.signal_kind(Signal::Logs), None);
        assert_eq!(losses.pending_stderr(QueueSignal::Logs), (0, false));
    }

    #[cfg(feature = "traces")]
    #[test]
    fn trace_provider_keeps_typed_timeout() {
        use opentelemetry_sdk::trace::{SdkTracerProvider, Span, SpanData, SpanProcessor};
        #[derive(Debug)]
        struct Timeout;
        impl SpanProcessor for Timeout {
            fn on_start(&self, _: &mut Span, _: &opentelemetry::Context) {}
            fn on_end(&self, _: SpanData) {}
            fn force_flush(&self) -> OTelSdkResult {
                Err(OTelSdkError::Timeout(Duration::ZERO))
            }
            fn shutdown_with_timeout(&self, _: Duration) -> OTelSdkResult {
                Ok(())
            }
        }
        let losses = Arc::new(Losses::default());
        let provider = SdkTracerProvider::builder()
            .with_span_processor(ReportingSpanProcessor {
                inner: Timeout,
                losses: losses.clone(),
            })
            .build();
        assert!(matches!(
            provider.force_flush(),
            Err(OTelSdkError::InternalFailure(_))
        ));
        let result = flush(|| provider.force_flush());
        assert!(matches!(result, Err(OTelSdkError::Timeout(_))));
        let error = losses.finish_signals(Ok(()), Ok(()), result).unwrap_err();
        assert_eq!(
            error.signal_kind(Signal::Traces),
            Some(FlushErrorKind::Timeout)
        );
        assert_eq!(error.signal_kind(Signal::Logs), None);
    }

    #[cfg(feature = "traces")]
    #[test]
    fn trace_overflow_flush_and_shutdown_capture() {
        if !crate::subscriber_test_child(
            "lifecycle::tests::trace_overflow_flush_and_shutdown_capture",
        ) {
            return;
        }
        use opentelemetry::trace::{Tracer as _, TracerProvider as _};
        use opentelemetry_sdk::trace::{
            BatchConfigBuilder, BatchSpanProcessor, SdkTracerProvider, SpanData, SpanExporter,
        };
        #[derive(Debug)]
        struct SpanBlock(Block);
        impl SpanExporter for SpanBlock {
            async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
                self.0
                    .losses
                    .reached(QueueSignal::Traces, batch.len() as u64);
                if self.0.started.send(()).is_ok() {
                    self.0.release.lock().unwrap().recv().unwrap();
                }
                Ok(())
            }
        }
        struct TraceForward(Arc<AtomicU64>);
        impl<S: Subscriber> Layer<S> for TraceForward {
            fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
                if event.metadata().name() == "trace.shutdown.forwarded" {
                    self.0.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        let losses = Arc::new(Losses::default());
        let forwarded = Arc::new(AtomicU64::new(0));
        let _current = tracing::subscriber::set_default(
            tracing_subscriber::registry().with(TraceForward(forwarded.clone())),
        );
        let (started, wait) = mpsc::sync_channel(1);
        let (release, released) = mpsc::sync_channel(0);
        let provider = SdkTracerProvider::builder()
            .with_span_processor(ReportingSpanProcessor {
                losses: losses.clone(),
                inner: BatchSpanProcessor::builder(SpanBlock(Block {
                    started,
                    release: Mutex::new(released),
                    losses: losses.clone(),
                }))
                .with_batch_config(
                    BatchConfigBuilder::default()
                        .with_max_queue_size(1)
                        .with_max_export_batch_size(1)
                        .build(),
                )
                .build(),
            })
            .build();
        let tracer = provider.tracer("overflow");
        drop(tracer.start("first"));
        wait.recv_timeout(Duration::from_secs(5)).unwrap();
        for _ in 0..10 {
            drop(tracer.start("queued"));
        }
        drop(wait);
        release.send(()).unwrap();
        let error = losses
            .finish_signals(Ok(()), Ok(()), flush(|| provider.force_flush()))
            .unwrap_err();
        assert_eq!(error.kind(), FlushErrorKind::DataLost);
        assert_eq!(error.lost(Signal::Traces), 9);
        assert_eq!(error.lost(Signal::Logs), 0);
        assert_eq!(
            losses.state().queues[QueueSignal::Traces as usize].sdk_overflow,
            0
        );
        let capture = ShutdownCapture::new(
            QueueSignal::Traces,
            tracing::dispatcher::get_default(Clone::clone),
            losses.clone(),
        );
        std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    tracing::subscriber::with_default(capture, || {
                        tracing::info!(name: "trace.shutdown.forwarded", "forward");
                        provider.shutdown()
                    })
                })
                .join()
                .unwrap()
                .unwrap()
        });
        assert!(losses.finish(Ok(())).is_ok());
        assert_eq!(
            losses.state().queues[QueueSignal::Traces as usize].sdk_overflow,
            9
        );
        assert_eq!(
            losses.state().queues[QueueSignal::Traces as usize].overflow_reported,
            9
        );
        assert_eq!(forwarded.load(Ordering::Relaxed), 1);
        // A zero-overflow provider must not emit SpansDropped at shutdown.
        losses.state().queues[QueueSignal::Traces as usize].sdk_overflow = 17;
        let capture = ShutdownCapture::new(
            QueueSignal::Traces,
            tracing::dispatcher::get_default(Clone::clone),
            losses.clone(),
        );
        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(SpanBlock(Block {
                started: mpsc::sync_channel(1).0,
                release: Mutex::new(mpsc::channel().1),
                losses: losses.clone(),
            }))
            .build();
        tracing::subscriber::with_default(capture, || provider.shutdown()).unwrap();
        assert_eq!(
            losses.state().queues[QueueSignal::Traces as usize].sdk_overflow,
            17
        );
    }

    fn metric_only_error(kind: FlushErrorKind) -> FlushError {
        FlushError {
            kind,
            signal_kinds: [None, Some(kind), None],
            logs: 0,
            spans: 0,
            measurements: 0,
            data_points_lost: false,
            metric_names_poisoned: false,
            sources: [
                None,
                Some(OTelSdkError::InternalFailure("metrics".into())),
                None,
            ],
        }
    }

    #[test]
    fn display_metrics_only_failed() {
        assert_eq!(
            metric_only_error(FlushErrorKind::Failed).to_string(),
            "Failed: metric export failed: Operation failed: metrics"
        );
    }

    #[test]
    fn display_metrics_only_timeout() {
        assert_eq!(
            metric_only_error(FlushErrorKind::Timeout).to_string(),
            "Timeout: metric export timed out: Operation failed: metrics"
        );
    }

    #[test]
    fn display_poisoned_names_with_metric_export_outcomes() {
        for (kind, expected) in [
            (
                FlushErrorKind::Failed,
                "Failed: metric names poisoned by conflicting declarations; metric export failed: Operation failed: metrics",
            ),
            (
                FlushErrorKind::Timeout,
                "Timeout: metric names poisoned by conflicting declarations; metric export timed out: Operation failed: metrics",
            ),
        ] {
            let mut error = metric_only_error(kind);
            error.metric_names_poisoned = true;
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn display_signal_parts() {
        let cases = [
            (
                FlushErrorKind::Failed,
                None,
                Some(FlushErrorKind::Failed),
                0,
                0,
                false,
                false,
                None,
                Some("metrics"),
                "Failed: metric export failed: metrics",
            ),
            (
                FlushErrorKind::Failed,
                None,
                Some(FlushErrorKind::Failed),
                0,
                0,
                false,
                false,
                None,
                None,
                "Failed: metric export failed",
            ),
            (
                FlushErrorKind::Timeout,
                None,
                Some(FlushErrorKind::Timeout),
                0,
                0,
                false,
                false,
                None,
                Some("metrics"),
                "Timeout: metric export timed out: metrics",
            ),
            (
                FlushErrorKind::DataLost,
                None,
                Some(FlushErrorKind::DataLost),
                0,
                0,
                true,
                false,
                None,
                None,
                "DataLost: metric data points dropped",
            ),
            (
                FlushErrorKind::Failed,
                Some(FlushErrorKind::Failed),
                None,
                2,
                0,
                false,
                false,
                Some("logs"),
                None,
                "Failed: at least 2 log records lost; log export failed: logs",
            ),
            (
                FlushErrorKind::DataLost,
                Some(FlushErrorKind::DataLost),
                None,
                2,
                0,
                false,
                false,
                None,
                None,
                "DataLost: at least 2 log records lost",
            ),
            (
                FlushErrorKind::Failed,
                Some(FlushErrorKind::Failed),
                Some(FlushErrorKind::Failed),
                0,
                0,
                false,
                false,
                Some("logs"),
                Some("metrics"),
                "Failed: log export failed: logs; metric export failed: metrics",
            ),
            (
                FlushErrorKind::DataLost,
                None,
                Some(FlushErrorKind::DataLost),
                0,
                0,
                false,
                true,
                None,
                None,
                "DataLost: metric names poisoned by conflicting declarations",
            ),
            (
                FlushErrorKind::DataLost,
                None,
                Some(FlushErrorKind::DataLost),
                0,
                3,
                false,
                false,
                None,
                None,
                "DataLost: at least 3 metric measurements lost",
            ),
            (
                FlushErrorKind::Timeout,
                Some(FlushErrorKind::Timeout),
                None,
                0,
                0,
                false,
                false,
                None,
                None,
                "Timeout: log export timed out",
            ),
        ];
        for (
            kind,
            logs_kind,
            metrics_kind,
            logs,
            measurements,
            data_points_lost,
            metric_names_poisoned,
            logs_source,
            metrics_source,
            expected,
        ) in cases
        {
            let error = FlushError {
                kind,
                signal_kinds: [logs_kind, metrics_kind, None],
                logs,
                spans: 0,
                measurements,
                data_points_lost,
                metric_names_poisoned,
                sources: [
                    logs_source.map(|s: &str| OTelSdkError::InternalFailure(s.into())),
                    metrics_source.map(|s: &str| OTelSdkError::InternalFailure(s.into())),
                    None,
                ],
            };
            assert_eq!(
                error.to_string(),
                expected
                    .replace(
                        "metrics",
                        &OTelSdkError::InternalFailure("metrics".into()).to_string()
                    )
                    .replace(
                        ": logs",
                        &format!(": {}", OTelSdkError::InternalFailure("logs".into()))
                    )
            );
        }
    }

    use opentelemetry::logs::{Logger as _, LoggerProvider as _};
    use opentelemetry_sdk::logs::{BatchConfigBuilder, LogBatch, LogExporter, SdkLoggerProvider};
    use std::sync::{atomic::AtomicU64, mpsc};
    use tracing_subscriber::layer::SubscriberExt;

    #[derive(Debug)]
    struct Block {
        started: mpsc::SyncSender<()>,
        release: Mutex<mpsc::Receiver<()>>,
        losses: Arc<Losses>,
    }
    impl LogExporter for Block {
        async fn export(&self, batch: LogBatch<'_>) -> OTelSdkResult {
            self.losses
                .reached(QueueSignal::Logs, batch.iter().count() as u64);
            if self.started.send(()).is_ok() {
                self.release.lock().unwrap().recv().unwrap();
            }
            Ok(())
        }
    }

    struct Forwarded(Arc<AtomicU64>);
    impl<S: Subscriber> Layer<S> for Forwarded {
        fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
            if event.metadata().name() == "LoggerProvider.ShutdownInvokedByUser" {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    #[test]
    fn sdk_overflow_capture_does_not_repeat_flushed_losses() {
        if !crate::subscriber_test_child(
            "lifecycle::tests::sdk_overflow_capture_does_not_repeat_flushed_losses",
        ) {
            return;
        }
        let losses = Arc::new(Losses::default());
        let forwarded = Arc::new(AtomicU64::new(0));
        let subscriber = tracing_subscriber::registry()
            .with(Forwarded(forwarded.clone()))
            .with(tracing_subscriber::filter::filter_fn(|meta| {
                meta.name() != "BatchLogProcessor.LogsDropped"
            }));
        let _current = tracing::subscriber::set_default(subscriber);
        let (started, wait) = mpsc::sync_channel(1);
        let (release, released) = mpsc::sync_channel(0);
        let provider = SdkLoggerProvider::builder()
            .with_log_processor(ReportingProcessor {
                losses: losses.clone(),
                inner: BatchLogProcessor::builder(Block {
                    started,
                    release: Mutex::new(released),
                    losses: losses.clone(),
                })
                .with_batch_config(
                    BatchConfigBuilder::default()
                        .with_max_queue_size(1)
                        .with_max_export_batch_size(1)
                        .build(),
                )
                .build(),
            })
            .build();
        let logger = provider.logger("overflow");
        logger.emit(logger.create_log_record());
        wait.recv_timeout(Duration::from_secs(5)).unwrap();
        for _ in 0..10 {
            logger.emit(logger.create_log_record());
        }
        drop(wait);
        release.send(()).unwrap();
        let error = losses.finish(provider.force_flush()).unwrap_err();
        assert_eq!(error.kind(), FlushErrorKind::DataLost);
        assert_eq!(error.lost(Signal::Logs), 9);
        assert!(losses.finish(provider.force_flush()).is_ok());
        let capture = ShutdownCapture::new(
            QueueSignal::Logs,
            tracing::dispatcher::get_default(Clone::clone),
            losses.clone(),
        );
        std::thread::scope(|scope| {
            scope
                .spawn(move || tracing::subscriber::with_default(capture, || provider.shutdown()))
                .join()
                .unwrap()
                .unwrap();
        });
        assert!(losses.finish(Ok(())).is_ok());
        // Pins the SDK event name, field and shutdown thread capture.
        assert_eq!(
            losses.state().queues[QueueSignal::Logs as usize].sdk_overflow,
            9
        );
        assert_eq!(forwarded.load(Ordering::Relaxed), 1);
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn metric_data_point_outcomes_have_no_measurement_or_log_count() {
        let losses = Losses::default();
        for failed in [false, true] {
            losses.metric_data_points(failed);
            let error = losses.finish(Ok(())).unwrap_err();
            assert_eq!(
                error.kind(),
                if failed {
                    FlushErrorKind::Failed
                } else {
                    FlushErrorKind::DataLost
                }
            );
            assert_eq!(error.lost(Signal::Metrics), 0);
            assert_eq!(error.lost(Signal::Logs), 0);
            assert!(!error.to_string().contains("log records"));
            assert_eq!(
                error.to_string(),
                if failed {
                    "Failed: metric export failed"
                } else {
                    "DataLost: metric data points dropped"
                }
            );
            assert!(losses.finish(Ok(())).is_ok());
        }
        losses.metric_data_points(true);
        losses.record(QueueSignal::Logs, 3, false);
        let error = losses.finish(Ok(())).unwrap_err();
        assert_eq!(error.kind(), FlushErrorKind::Failed);
        assert!(error.to_string().contains("3 log records"));
        assert!(error.to_string().contains("metric"));
        losses.metric_data_points(true);
        assert_eq!(
            losses
                .finish(Err(OTelSdkError::Timeout(Duration::ZERO)))
                .unwrap_err()
                .kind(),
            FlushErrorKind::Timeout
        );
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn each_signal_keeps_its_own_kind_and_concurrent_callers_keep_timeouts() {
        let losses = Losses::default();
        losses.record(QueueSignal::Logs, 3, true);
        losses.metric_data_points(false);
        let error = losses.finish(Ok(())).unwrap_err();
        assert_eq!(error.kind(), FlushErrorKind::Failed);
        assert_eq!(
            error.signal_kind(Signal::Logs),
            Some(FlushErrorKind::Failed)
        );
        assert_eq!(
            error.signal_kind(Signal::Metrics),
            Some(FlushErrorKind::DataLost)
        );
        assert_eq!(
            error.to_string(),
            "Failed: at least 3 log records lost; log export failed; metric data points dropped"
        );
        losses.record(QueueSignal::Logs, 2, false);
        losses.metric_data_points(true);
        let error = losses.finish(Ok(())).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Failed: at least 2 log records lost; metric export failed"
        );
        for _ in 0..2 {
            let error = losses
                .finish_signals(Ok(()), Err(OTelSdkError::Timeout(Duration::ZERO)), Ok(()))
                .unwrap_err();
            assert_eq!(error.kind(), FlushErrorKind::Timeout);
            assert_eq!(
                error.signal_kind(Signal::Metrics),
                Some(FlushErrorKind::Timeout)
            );
            assert_eq!(error.signal_kind(Signal::Logs), None);
        }
    }

    #[test]
    fn display_keeps_source_without_lost_logs() {
        let error = Losses::default()
            .finish(Err(OTelSdkError::InternalFailure("source detail".into())))
            .unwrap_err();
        assert!(error.to_string().contains("source detail"));
        assert!(!error.to_string().contains("log records"));
    }

    #[test]
    fn display_orders_log_losses_before_metric_timeout_or_failure() {
        let losses = Losses::default();
        losses.record(QueueSignal::Logs, 2, false);
        let metrics = OTelSdkError::Timeout(Duration::from_secs(1));
        let metrics_text = metrics.to_string();
        let error = losses
            .finish_signals(Ok(()), Err(metrics), Ok(()))
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "Timeout: at least 2 log records lost; metric export timed out: {metrics_text}"
            )
        );
        assert_eq!(
            std::error::Error::source(&error).unwrap().to_string(),
            metrics_text
        );
        losses.record(QueueSignal::Logs, 2, false);
        let logs = OTelSdkError::InternalFailure("logs source".into());
        let metrics = OTelSdkError::InternalFailure("metrics source".into());
        let logs_text = logs.to_string();
        let metrics_text = metrics.to_string();
        let error = losses
            .finish_signals(Err(logs), Err(metrics), Ok(()))
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "Failed: at least 2 log records lost; log export failed: {logs_text}; metric export failed: {metrics_text}"
            )
        );
        assert_eq!(
            std::error::Error::source(&error).unwrap().to_string(),
            logs_text
        );
    }

    #[test]
    fn outcome_precedence_counts_and_period_resets() {
        let losses = Losses::default();
        losses.record(QueueSignal::Logs, 2, true);
        let result = losses.observe(Signal::Logs, Err(OTelSdkError::Timeout(Duration::ZERO)));
        let error = losses.finish(result).unwrap_err();
        assert_eq!(error.kind(), FlushErrorKind::Timeout);
        assert_eq!(error.lost(Signal::Logs), 2);
        assert!(std::error::Error::source(&error).is_some());
        assert!(losses.finish(Ok(())).is_ok());
        losses.record(QueueSignal::Logs, 3, true);
        let error = losses.finish(Ok(())).unwrap_err();
        assert_eq!(error.kind(), FlushErrorKind::Failed);
        assert_eq!(error.lost(Signal::Logs), 3);
        assert!(losses.finish(Ok(())).is_ok());
        losses.record(QueueSignal::Logs, u64::MAX, false);
        losses.record(QueueSignal::Logs, 1, false);
        let error = losses.finish(Ok(())).unwrap_err();
        assert_eq!(error.kind(), FlushErrorKind::DataLost);
        assert_eq!(error.lost(Signal::Logs), u64::MAX);
        assert!(losses.finish(Ok(())).is_ok());
        fn send_sync<T: Send + Sync + 'static>() {}
        send_sync::<FlushError>();
        send_sync::<crate::Guard>();
    }
}
