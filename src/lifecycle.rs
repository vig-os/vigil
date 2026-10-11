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
        Arc, Mutex,
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
#[derive(Debug)]
pub struct FlushError {
    kind: FlushErrorKind,
    logs: u64,
    source: Option<OTelSdkError>,
}
impl FlushError {
    /// The highest-priority outcome: Timeout, then Failed, then DataLost.
    pub fn kind(&self) -> FlushErrorKind {
        self.kind
    }

    /// A lower bound on lost data, in the signal's own unit.
    ///
    /// Flush counts losses since the previous flush; shutdown counts since
    /// that flush or startup, plus queue overflow since startup. Flush cannot
    /// count overflow: when it flags overflow, true log loss is at least one
    /// record more than this count. Shared pipelines that never shut down only
    /// flag overflow. Export failures and diagnostic stubs are included.
    ///
    /// A failed durable log line counts its records even if another copy
    /// reached a remote receiver. Metrics and traces currently return zero;
    /// their implementations land in #7/#8. Metrics will count measurements
    /// that never reached the SDK, excluding data-point export failures and
    /// measurements aggregated before a later name conflict (ADR-0003 d23).
    /// Records rejected after shutdown begins are not counted.
    ///
    /// Known gaps: compiling WARN out with tracing's static max-level features
    /// removes the SDK's overflow event; records emitted on other threads
    /// during shutdown may arrive after its counter was read or after the
    /// worker disconnected. Such records are lost but cannot be counted.
    pub fn lost(&self, signal: Signal) -> u64 {
        match signal {
            Signal::Logs => self.logs,
            Signal::Metrics | Signal::Traces => 0,
        }
    }
}
impl fmt::Display for FlushError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?}: at least {} log records lost",
            self.kind, self.logs
        )?;
        if let Some(source) = &self.source {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}
impl std::error::Error for FlushError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|source| source as _)
    }
}

#[derive(Debug, Default)]
struct Period {
    logs: u64,
    failed: bool,
    overflow: bool,
    timeout: bool,
}

#[derive(Debug, Default)]
pub(crate) struct Losses {
    // Publish a failed export's count and kind together; a flush must not
    // split them across periods when the worker starts its next export.
    period: Mutex<Period>,
    pub(crate) shutting_down: AtomicBool,
}
impl Losses {
    pub(crate) fn record(&self, logs: u64, failed: bool) {
        let mut period = self
            .period
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        period.logs = period.logs.saturating_add(logs);
        period.failed |= failed;
    }

    pub(crate) fn add(&self, logs: u64) {
        self.record(logs, false);
    }

    fn overflowed(&self) {
        self.period
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .overflow = true;
    }

    pub(crate) fn finish(&self, result: OTelSdkResult) -> Result<(), FlushError> {
        let Period {
            logs,
            failed,
            overflow,
            timeout,
        } = std::mem::take(
            &mut *self
                .period
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let kind = if timeout || matches!(result, Err(OTelSdkError::Timeout(_))) {
            FlushErrorKind::Timeout
        } else if failed || result.is_err() {
            FlushErrorKind::Failed
        } else if logs != 0 || overflow {
            FlushErrorKind::DataLost
        } else {
            return Ok(());
        };
        Err(FlushError {
            kind,
            logs,
            source: result.err(),
        })
    }

    fn observe(&self, result: OTelSdkResult) -> OTelSdkResult {
        if matches!(result, Err(OTelSdkError::Timeout(_))) {
            self.period
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .timeout = true;
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
        self.inner.emit(data, scope);
    }
    fn force_flush(&self) -> OTelSdkResult {
        let result = self.inner.force_flush();
        if let Err(OTelSdkError::Timeout(duration)) = &result {
            FLUSH_TIMEOUT.with(|timeout| timeout.set(Some(*duration)));
        }
        result
    }
    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.losses
            .observe(self.inner.shutdown_with_timeout(timeout))
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

pub(crate) struct Overflow(pub(crate) Arc<Losses>);
impl<S: Subscriber> Layer<S> for Overflow {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        if event.metadata().name() == "BatchLogProcessor.LogDroppingStarted" {
            self.0.overflowed();
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
            self.losses.add(count.0);
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
    use std::sync::{Condvar, atomic::AtomicU64, mpsc};
    use tracing_subscriber::layer::SubscriberExt;

    #[derive(Debug)]
    struct Block {
        started: mpsc::SyncSender<()>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }
    impl LogExporter for Block {
        async fn export(&self, _: LogBatch<'_>) -> OTelSdkResult {
            let (lock, wake) = &*self.release;
            let mut ready = lock.lock().unwrap();
            if !*ready {
                self.started.send(()).unwrap();
                ready = wake.wait_while(ready, |ready| !*ready).unwrap();
            }
            drop(ready);
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
    fn sdk_overflow_is_flagged_on_flush_and_counted_on_shutdown_thread() {
        let losses = Arc::new(Losses::default());
        let forwarded = Arc::new(AtomicU64::new(0));
        let subscriber = tracing_subscriber::registry()
            .with(Overflow(losses.clone()))
            .with(Forwarded(forwarded.clone()))
            .with(tracing_subscriber::filter::filter_fn(|meta| {
                meta.name() != "BatchLogProcessor.LogsDropped"
            }));
        let _current = tracing::subscriber::set_default(subscriber);
        let (started, wait) = mpsc::sync_channel(1);
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let provider = SdkLoggerProvider::builder()
            .with_log_processor(ReportingProcessor {
                losses: losses.clone(),
                inner: BatchLogProcessor::builder(Block {
                    started,
                    release: release.clone(),
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
        *release.0.lock().unwrap() = true;
        release.1.notify_all();
        let error = losses.finish(provider.force_flush()).unwrap_err();
        assert_eq!(error.kind(), FlushErrorKind::DataLost);
        assert_eq!(error.lost(Signal::Logs), 0, "flush cannot count overflow");
        assert!(
            losses.finish(provider.force_flush()).is_ok(),
            "the one-time overflow flag belongs only to the previous period"
        );
        let forward = tracing::dispatcher::get_default(Clone::clone);
        let captured = losses.clone();
        std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    tracing::subscriber::with_default(
                        ShutdownCapture {
                            forward,
                            losses: captured,
                        },
                        || provider.shutdown_with_timeout(Duration::from_secs(5)),
                    )
                })
                .join()
                .unwrap()
                .unwrap();
        });
        let error = losses.finish(Ok(())).unwrap_err();
        assert_eq!(error.kind(), FlushErrorKind::DataLost);
        assert_eq!(
            error.lost(Signal::Logs),
            9,
            "pins the SDK's LogsDropped event, dropped_logs_count field and calling thread"
        );
        assert_eq!(
            forwarded.load(Ordering::Relaxed),
            1,
            "non-overflow shutdown diagnostics must reach the original dispatcher"
        );
        assert!(losses.finish(Ok(())).is_ok());
    }

    #[test]
    fn typed_timeouts_precede_failures_and_counted_losses() {
        let losses = Losses::default();
        losses.add(2);
        losses.record(0, true);
        let result = losses.observe(Err(OTelSdkError::Timeout(Duration::ZERO)));
        let error = losses.finish(result).unwrap_err();
        assert_eq!(error.kind(), FlushErrorKind::Timeout);
        assert_eq!(error.lost(Signal::Logs), 2);
        assert!(std::error::Error::source(&error).is_some());
    }
    #[test]
    fn failed_precedes_data_loss_and_periods_reset() {
        let losses = Losses::default();
        losses.add(3);
        losses.record(0, true);
        losses.overflowed();
        let error = losses.finish(Ok(())).unwrap_err();
        assert_eq!(error.kind(), FlushErrorKind::Failed);
        assert_eq!(error.lost(Signal::Logs), 3);
        assert!(losses.finish(Ok(())).is_ok());
        losses.add(u64::MAX);
        losses.add(1);
        let error = losses.finish(Ok(())).unwrap_err();
        assert_eq!(error.kind(), FlushErrorKind::DataLost);
        assert_eq!(error.lost(Signal::Logs), u64::MAX);
        assert!(losses.finish(Ok(())).is_ok());
        fn send_sync<T: Send + Sync + 'static>() {}
        send_sync::<FlushError>();
        send_sync::<crate::Guard>();
    }
}
