//! Loss accounting and shutdown diagnostics, kept independent of SDK errors.
use opentelemetry::InstrumentationScope;
use opentelemetry_sdk::{
    Resource,
    error::{OTelSdkError, OTelSdkResult},
    logs::{BatchLogProcessor, LogProcessor, SdkLogRecord, SdkLoggerProvider},
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
/// metrics source. Display keeps each source on its own signal's part.
#[derive(Debug)]
pub struct FlushError {
    kind: FlushErrorKind,
    signal_kinds: [Option<FlushErrorKind>; 2],
    logs: u64,
    measurements: u64,
    data_points_lost: bool,
    metric_names_poisoned: bool,
    sources: [Option<OTelSdkError>; 2],
}
impl FlushError {
    /// The highest-priority outcome: Timeout, then Failed, then DataLost.
    pub fn kind(&self) -> FlushErrorKind {
        self.kind
    }

    pub(crate) fn signal_kind(&self, signal: Signal) -> Option<FlushErrorKind> {
        self.signal_kinds[if signal == Signal::Metrics { 1 } else { 0 }]
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
    /// reached a remote receiver. Traces currently return zero; their
    /// implementation lands in #8. Metrics count measurements
    /// that never reached the SDK, including records made before initialization.
    /// Records made while metrics are off or failed are not counted, nor are
    /// data-point export failures or measurements aggregated before a later name
    /// conflict (ADR-0003 d23).
    /// Records rejected after shutdown begins are not counted.
    pub fn lost(&self, signal: Signal) -> u64 {
        match signal {
            Signal::Logs => self.logs,
            Signal::Metrics => self.measurements,
            Signal::Traces => 0,
        }
    }
}
impl fmt::Display for FlushError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.kind)?;
        let logs_part = self.logs != 0 || self.sources[0].is_some();
        if self.logs != 0 {
            write!(f, ": at least {} log records lost", self.logs)?;
        }
        if let Some(source) = &self.sources[0] {
            write!(f, ": {source}")?;
        }
        if self.measurements != 0 {
            write!(
                f,
                "{}at least {} metric measurements lost",
                if logs_part { "; " } else { ": " },
                self.measurements
            )?;
        }
        if self.metric_names_poisoned {
            write!(
                f,
                "{}metric names poisoned by conflicting declarations",
                if logs_part || self.measurements != 0 {
                    "; "
                } else {
                    ": "
                }
            )?;
        }
        if logs_part || self.measurements != 0 || self.metric_names_poisoned {
            match self.signal_kind(Signal::Metrics) {
                Some(FlushErrorKind::Timeout) => write!(f, "; metric export timed out")?,
                Some(FlushErrorKind::Failed) => write!(f, "; metric export failed")?,
                Some(FlushErrorKind::DataLost) if self.data_points_lost => {
                    write!(f, "; metric data points dropped")?
                }
                Some(FlushErrorKind::DataLost) => {}
                None => return Ok(()),
            }
        }
        if let Some(source) = &self.sources[1] {
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
            .map(|source| source as _)
    }
}

#[derive(Debug, Default)]
struct Period {
    logs: u64,
    measurements: u64,
    metrics_failed: bool,
    metrics_data_lost: bool,
    metric_names_poisoned: bool,
    failed: bool,
    timeout: bool,
    metrics_timeout: bool,
}

#[derive(Debug, Default)]
struct State {
    period: Period,
    accepted: u64,
    reached: u64,
    overflow_reported: u64,
    sdk_overflow: u64,
    pending_stderr: u64,
    #[cfg(feature = "metrics")]
    pending_measurements: u64,
    pending_failed: bool,
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
    pub(crate) fn record(&self, logs: u64, failed: bool) {
        let mut state = self.state();
        state.period.logs = state.period.logs.saturating_add(logs);
        state.period.failed |= failed;
        state.pending_failed |= failed;
        state.pending_stderr = state.pending_stderr.saturating_add(logs);
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
    pub(crate) fn outcome(&self, signal: Signal, result: &OTelSdkResult) {
        let mut state = self.state();
        let timeout = matches!(result, Err(OTelSdkError::Timeout(_)));
        match signal {
            Signal::Metrics => {
                state.period.metrics_timeout |= timeout;
                state.period.metrics_failed |= result.is_err() && !timeout;
            }
            _ => {
                state.period.timeout |= timeout;
                state.period.failed |= result.is_err() && !timeout;
            }
        }
    }
    pub(crate) fn reached(&self, logs: u64) {
        let mut state = self.state();
        state.reached = state.reached.saturating_add(logs);
    }
    pub(crate) fn reported(&self, logs: u64) {
        let mut state = self.state();
        state.pending_stderr = state.pending_stderr.saturating_sub(logs);
        state.pending_failed = false;
    }
    pub(crate) fn pending_stderr(&self) -> (u64, bool) {
        let state = self.state();
        (state.pending_stderr, state.pending_failed)
    }
    fn overflow_total(&self, total: u64) {
        let mut state = self.state();
        state.sdk_overflow = total;
        Self::overflow(&mut state, total);
    }
    fn overflow(state: &mut State, total: u64) {
        let lost = total.saturating_sub(state.overflow_reported);
        state.overflow_reported = state.overflow_reported.max(total);
        state.period.logs = state.period.logs.saturating_add(lost);
        state.pending_stderr = state.pending_stderr.saturating_add(lost);
    }
    fn drained(&self, accepted: u64, result: &OTelSdkResult) {
        if result.is_ok() {
            let mut state = self.state();
            // Everything accepted before the request has drained. Later
            // arrivals may have reached the exporter too: subtracting them
            // deliberately undercounts rather than counting queued records.
            let total = accepted.saturating_sub(state.reached);
            Self::overflow(&mut state, total);
        }
    }
    #[cfg(test)]
    pub(crate) fn finish(&self, result: OTelSdkResult) -> Result<(), FlushError> {
        self.finish_signals(result, Ok(()))
    }
    pub(crate) fn finish_signals(
        &self,
        result: OTelSdkResult,
        metrics: OTelSdkResult,
    ) -> Result<(), FlushError> {
        #[cfg(feature = "metrics")]
        crate::metrics::drain_before_init(self, false);
        let mut period = std::mem::take(&mut self.state().period);
        // Each caller retains its own outcome even if another concurrent
        // flush consumed the period's shared counts and exporter flags.
        period.metrics_timeout |= matches!(metrics, Err(OTelSdkError::Timeout(_)));
        period.metrics_failed |= metrics.is_err() && !period.metrics_timeout;
        let kind = if period.timeout
            || period.metrics_timeout
            || matches!(result, Err(OTelSdkError::Timeout(_)))
        {
            FlushErrorKind::Timeout
        } else if period.failed || period.metrics_failed || result.is_err() {
            FlushErrorKind::Failed
        } else if period.logs != 0
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
            ],
            logs: period.logs,
            measurements: period.measurements,
            data_points_lost: period.metrics_data_lost,
            metric_names_poisoned: period.metric_names_poisoned,
            sources: [result.err(), metrics.err()],
        })
    }

    fn observe(&self, result: OTelSdkResult) -> OTelSdkResult {
        if matches!(result, Err(OTelSdkError::Timeout(_))) {
            self.state().period.timeout = true;
        }
        result
    }
}

thread_local! {
    // force_flush runs on its caller's thread. Keep its typed timeout per
    // caller so simultaneous shared-pipeline flushes cannot consume it.
    static FLUSH_TIMEOUT: Cell<Option<Duration>> = const { Cell::new(None) };
}

pub(crate) fn flush(provider: &SdkLoggerProvider) -> OTelSdkResult {
    FLUSH_TIMEOUT.with(|timeout| {
        timeout.set(None);
        let result = provider.force_flush();
        match timeout.take() {
            Some(duration) => Err(OTelSdkError::Timeout(duration)),
            None => result,
        }
    })
}

// Preserve typed processor timeouts before the provider stringifies them.
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
        state.accepted = state.accepted.saturating_add(1);
    }
    fn force_flush(&self) -> OTelSdkResult {
        let accepted = self.losses.state().accepted;
        let result = self.inner.force_flush();
        self.losses.drained(accepted, &result);
        if let Err(OTelSdkError::Timeout(duration)) = &result {
            FLUSH_TIMEOUT.with(|timeout| timeout.set(Some(*duration)));
        }
        result
    }
    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        let accepted = self.losses.state().accepted;
        let result = self
            .losses
            .observe(self.inner.shutdown_with_timeout(timeout));
        self.losses.drained(accepted, &result);
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

struct Count(u64);
impl Visit for Count {
    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "dropped_logs_count" {
            self.0 = value;
        }
    }
    fn record_debug(&mut self, _: &Field, _: &dyn fmt::Debug) {}
}

// Enabled independently of the consumer's filters. Every other callback is
// delegated to the dispatcher captured on the calling thread before spawning.
pub(crate) struct ShutdownCapture {
    pub(crate) forward: Dispatch,
    pub(crate) losses: Arc<Losses>,
}
impl ShutdownCapture {
    fn captures(meta: &Metadata<'_>) -> bool {
        meta.target().starts_with("opentelemetry") && meta.name() == "BatchLogProcessor.LogsDropped"
    }
}
impl Subscriber for ShutdownCapture {
    fn enabled(&self, meta: &Metadata<'_>) -> bool {
        Self::captures(meta) || self.forward.enabled(meta)
    }
    fn event(&self, event: &Event<'_>) {
        if Self::captures(event.metadata()) {
            let mut count = Count(0);
            event.record(&mut count);
            self.losses.overflow_total(count.0);
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
            self.losses.reached(batch.iter().count() as u64);
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
        let capture = ShutdownCapture {
            forward: tracing::dispatcher::get_default(Clone::clone),
            losses: losses.clone(),
        };
        std::thread::scope(|scope| {
            scope
                .spawn(move || tracing::subscriber::with_default(capture, || provider.shutdown()))
                .join()
                .unwrap()
                .unwrap();
        });
        assert!(losses.finish(Ok(())).is_ok());
        // Pins the SDK event name, field and shutdown thread capture.
        assert_eq!(losses.state().sdk_overflow, 9);
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
            assert_eq!(error.to_string(), format!("{:?}", error.kind()));
            assert!(losses.finish(Ok(())).is_ok());
        }
        losses.metric_data_points(true);
        losses.record(3, false);
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
        losses.record(3, true);
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
            "Failed: at least 3 log records lost; metric data points dropped"
        );
        losses.record(2, false);
        losses.metric_data_points(true);
        let error = losses.finish(Ok(())).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Failed: at least 2 log records lost; metric export failed"
        );
        for _ in 0..2 {
            let error = losses
                .finish_signals(Ok(()), Err(OTelSdkError::Timeout(Duration::ZERO)))
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
        losses.record(2, false);
        let metrics = OTelSdkError::Timeout(Duration::from_secs(1));
        let metrics_text = metrics.to_string();
        let error = losses.finish_signals(Ok(()), Err(metrics)).unwrap_err();
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
        losses.record(2, false);
        let logs = OTelSdkError::InternalFailure("logs source".into());
        let metrics = OTelSdkError::InternalFailure("metrics source".into());
        let logs_text = logs.to_string();
        let metrics_text = metrics.to_string();
        let error = losses.finish_signals(Err(logs), Err(metrics)).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "Failed: at least 2 log records lost: {logs_text}; metric export failed: {metrics_text}"
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
        losses.record(2, true);
        let result = losses.observe(Err(OTelSdkError::Timeout(Duration::ZERO)));
        let error = losses.finish(result).unwrap_err();
        assert_eq!(error.kind(), FlushErrorKind::Timeout);
        assert_eq!(error.lost(Signal::Logs), 2);
        assert!(std::error::Error::source(&error).is_some());
        assert!(losses.finish(Ok(())).is_ok());
        losses.record(3, true);
        let error = losses.finish(Ok(())).unwrap_err();
        assert_eq!(error.kind(), FlushErrorKind::Failed);
        assert_eq!(error.lost(Signal::Logs), 3);
        assert!(losses.finish(Ok(())).is_ok());
        losses.record(u64::MAX, false);
        losses.record(1, false);
        let error = losses.finish(Ok(())).unwrap_err();
        assert_eq!(error.kind(), FlushErrorKind::DataLost);
        assert_eq!(error.lost(Signal::Logs), u64::MAX);
        assert!(losses.finish(Ok(())).is_ok());
        fn send_sync<T: Send + Sync + 'static>() {}
        send_sync::<FlushError>();
        send_sync::<crate::Guard>();
    }
}
