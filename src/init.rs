//! Process-wide tracing initialization.
use std::{
    env, fmt,
    io::{IsTerminal, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use crate::{FlushErrorKind, Signal};
use opentelemetry::{InstrumentationScope, KeyValue, logs::LoggerProvider};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};
#[cfg(feature = "metrics")]
use opentelemetry_sdk::metrics::{PeriodicReader, PeriodicReaderBuilder, SdkMeterProvider};
use opentelemetry_sdk::{
    Resource,
    logs::{
        BatchConfigBuilder, BatchLogProcessor, LogBatch, LogExporter, SdkLogger, SdkLoggerProvider,
    },
};
use tracing_subscriber::{
    EnvFilter, Layer,
    layer::SubscriberExt,
    registry::{LookupSpan, Registry},
};

use crate::{
    lifecycle::{AfterShutdown, FlushError, Losses, ReportingProcessor, ShutdownCapture},
    logs::OtlpJsonLogExporter,
    rotate::{RotatingFile, RotationConfig},
};

/// A mistake the caller can correct in code. Environmental failures degrade
/// to stderr. Concrete error sources are not part of the stability promise;
/// downcasting them is unsupported.
/// The `Display` text is for people; it is not part of the stability promise. Match on `kind()`.
#[derive(Debug)]
pub struct InitError {
    kind: InitErrorKind,
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

/// Why initialization failed.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitErrorKind {
    /// A vigil pipeline exists or another call has reserved the process slot.
    /// Reuse the pipeline; shutdown does not permit a second one.
    AlreadyRunning,
    /// A global or scoped default subscriber was set, even if that scope
    /// has ended. Compose with `layer` into a consumer-owned Registry,
    /// or initialize in a fresh process.
    ForeignSubscriber,
    /// The service name violates the rule documented by `Config::new`.
    InvalidServiceName,
    /// The configured default filter cannot be parsed.
    InvalidFilter,
}

/// Human-readable stderr output. Its format may change; never parse it.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Console {
    /// No additional console layer (the default).
    #[default]
    Off,
    /// Human-readable stderr, with ANSI only when stderr is a terminal.
    Stderr,
}

impl InitError {
    /// The caller-actionable category of this error.
    pub fn kind(&self) -> InitErrorKind {
        self.kind
    }

    fn new(kind: InitErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            source: None,
        }
    }
}

const MAX_QUEUE_SIZE: usize = 1_048_576;
static RESERVED: AtomicBool = AtomicBool::new(false);
static PIPELINE: OnceLock<PublishedPipeline> = OnceLock::new();

pub(crate) struct PublishedPipeline {
    #[cfg(feature = "metrics")]
    pub(crate) metrics: Option<SdkMeterProvider>,
    #[cfg(feature = "metrics")]
    pub(crate) registry: Arc<crate::metric_identity::Registry>,
    #[cfg(feature = "metrics")]
    pub(crate) losses: Arc<Losses>,
    #[cfg(feature = "metrics")]
    pub(crate) stopped: Arc<AtomicBool>,
}
#[cfg(feature = "metrics")]
pub(crate) fn published_pipeline() -> Option<&'static PublishedPipeline> {
    PIPELINE.get()
}
type PipelineLayer<S> = Box<dyn Layer<S> + Send + Sync + 'static>;

// A failed attempt releases the reservation; successful pipelines retain it
// forever, including after shutdown.
struct Reservation(bool);
impl Reservation {
    fn acquire() -> Result<Self, InitError> {
        RESERVED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self(true))
            .map_err(|_| {
                InitError::new(
                    InitErrorKind::AlreadyRunning,
                    "vigil pipeline already initialized in this process",
                )
            })
    }
    fn commit(mut self, _guard: &Guard) {
        let published = PublishedPipeline {
            #[cfg(feature = "metrics")]
            metrics: _guard.metrics.clone(),
            #[cfg(feature = "metrics")]
            registry: _guard.registry.clone(),
            #[cfg(feature = "metrics")]
            losses: _guard.losses.clone(),
            #[cfg(feature = "metrics")]
            stopped: _guard.stopped.clone(),
        };
        let _ = PIPELINE.set(published);
        #[cfg(feature = "metrics")]
        if let Some(pipeline) = PIPELINE.get() {
            crate::metrics::drain_before_init(&pipeline.losses, true);
        }
        self.0 = false;
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if self.0 {
            RESERVED.store(false, Ordering::Release);
        }
    }
}
impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for InitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|source| &**source as _)
    }
}

#[cfg(feature = "metrics")]
#[derive(Debug, Default)]
struct MetricFlushState {
    started: u64,
    finished: u64,
    result: Option<(u64, Arc<OTelSdkResult>)>,
    waiters: std::collections::BTreeMap<u64, usize>,
    #[cfg(test)]
    calls: usize,
    #[cfg(test)]
    threads: usize,
}

#[cfg(feature = "metrics")]
#[derive(Debug, Default)]
struct MetricFlushes {
    state: Mutex<MetricFlushState>,
    changed: std::sync::Condvar,
}
#[cfg(feature = "metrics")]
impl MetricFlushes {
    fn state(&self) -> std::sync::MutexGuard<'_, MetricFlushState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn register(self: &Arc<Self>, provider: SdkMeterProvider, stopped: Arc<AtomicBool>) -> u64 {
        let mut state = self.state();
        let target = state.started + 1;
        *state.waiters.entry(target).or_default() += 1;
        if state.started == state.finished {
            state.started = target;
            let shared = self.clone();
            let spawned = std::thread::Builder::new()
                .name("vigil-metric-flush".into())
                .spawn(move || {
                    loop {
                        #[cfg(test)]
                        {
                            shared.state().calls += 1;
                        }
                        let result = provider.force_flush();
                        let mut state = shared.state();
                        state.finished = state.started;
                        state.result = Some((state.finished, Arc::new(result)));
                        shared.changed.notify_all();
                        if stopped.load(Ordering::Acquire)
                            || !state.waiters.keys().any(|target| *target > state.finished)
                        {
                            break;
                        }
                        state.started += 1;
                    }
                });
            match spawned {
                Ok(_) => {
                    #[cfg(test)]
                    {
                        state.threads += 1;
                    }
                }
                Err(error) => {
                    state.finished = target;
                    state.result = Some((
                        target,
                        Arc::new(Err(OTelSdkError::InternalFailure(error.to_string()))),
                    ));
                }
            }
        }
        self.changed.notify_all();
        target
    }
    fn wait(&self, target: u64, deadline: Instant) -> OTelSdkResult {
        let mut state = self.state();
        while state.finished < target && Instant::now() < deadline {
            state = self
                .changed
                .wait_timeout(state, deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
        if let Some(waiters) = state.waiters.get_mut(&target) {
            *waiters -= 1;
            if *waiters == 0 {
                state.waiters.remove(&target);
            }
        }
        match &state.result {
            Some((generation, result)) if *generation >= target => match result.as_ref() {
                Ok(()) => Ok(()),
                Err(OTelSdkError::Timeout(duration)) => Err(OTelSdkError::Timeout(*duration)),
                Err(OTelSdkError::AlreadyShutdown) => Err(OTelSdkError::AlreadyShutdown),
                Err(OTelSdkError::InternalFailure(reason)) => {
                    Err(OTelSdkError::InternalFailure(reason.clone()))
                }
            },
            _ => Err(OTelSdkError::Timeout(Duration::from_secs(5))),
        }
    }
}

/// Owns the signal providers. Keep this alive until telemetry is finished.
/// Drop waits up to five seconds, including time blocked on the directory lock.
/// On timeout it warns on stderr; remaining records may be lost. The SDK worker
/// may continue in the background until the lock is released.
#[must_use = "dropping the guard flushes and shuts down logging; bind it: let _guard = vigil::init(..)"]
#[derive(Debug)]
pub struct Guard {
    provider: Option<SdkLoggerProvider>,
    #[cfg(feature = "traces")]
    traces: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
    #[cfg(feature = "traces")]
    trace_storage: Option<Arc<crate::trace_pipeline::TraceStorage>>,
    #[cfg(feature = "metrics")]
    metrics: Option<SdkMeterProvider>,
    #[cfg(feature = "metrics")]
    metrics_flushing: Arc<MetricFlushes>,
    #[cfg(feature = "metrics")]
    registry: Arc<crate::metric_identity::Registry>,
    stopped: Arc<AtomicBool>,
    dir: Option<PathBuf>,
    losses: Arc<Losses>,
    #[cfg(all(test, any(feature = "metrics", feature = "traces")))]
    signal_files: [std::sync::Weak<RotatingFile>; 3],
}
// Keep the scheduling seam shared with the deterministic concurrency proof.
fn flush_logs_and_traces(
    logs: impl FnOnce() -> OTelSdkResult,
    traces: Option<impl FnOnce() -> OTelSdkResult + Send>,
) -> (OTelSdkResult, OTelSdkResult) {
    std::thread::scope(|scope| {
        let traces = traces.map(|flush| scope.spawn(flush));
        let logs = logs();
        let traces = traces.map_or(Ok(()), |thread| {
            thread.join().unwrap_or_else(|_| {
                Err(OTelSdkError::InternalFailure(
                    "span flush thread panicked".into(),
                ))
            })
        });
        (logs, traces)
    })
}

impl Guard {
    /// The actual log directory, or `None` when logs fell back to stderr.
    /// Metrics and traces may still write `metrics.jsonl` and `traces.jsonl` there; `None` does not mean
    /// that no file is written.
    pub fn dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }
    /// Export queued records without stopping the pipeline, waiting up to five
    /// seconds. A timed-out metrics flush may still write to `metrics.jsonl`
    /// after flush or shutdown returns; at most one such collection runs at once.
    /// For cargo test, share a `static LazyLock<Guard>` per binary;
    /// each test flushes and selects records carrying its unique field.
    /// Never shut down that shared guard. See [`init`] for nextest isolation
    /// and the scoped-default restrictions.
    ///
    /// ```no_run
    /// use std::sync::LazyLock;
    /// static GUARD: LazyLock<vigil::Guard> = LazyLock::new(|| {
    ///     vigil::Config::new("tests")
    ///         .dir(std::env::temp_dir().join(format!("vigil-tests-{}", std::process::id())))
    ///         .init().expect("test pipeline")
    /// });
    /// let guard = &*GUARD;
    /// tracing::info!(test_case = "unique_test", "record");
    /// guard.flush()?;
    /// let lines = vigil::rotate::read_since(guard.dir().expect("test storage"), "logs", None)?;
    /// assert!(lines.iter().any(|line| line.contains("unique_test")));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    /// Returns timeout, SDK/sink failure or data loss since the previous flush.
    /// Logs falling back to stderr contribute no error; metrics and traces still
    /// report their outcomes.
    /// Queue overflow is counted independently of SDK diagnostics and filters.
    /// Concurrent arrivals can make this a lower bound; see [`FlushError::lost`].
    /// More than 64 concurrent requests can saturate the logs SDK control channel
    /// and return [`crate::FlushErrorKind::Failed`] before the timeout.
    pub fn flush(&self) -> Result<(), FlushError> {
        let deadline = Instant::now() + Duration::from_secs(5);
        #[cfg(feature = "metrics")]
        let metrics = self.start_metrics_flush();
        #[cfg(all(test, feature = "metrics"))]
        self.losses.observe_flush_order();
        #[cfg(feature = "traces")]
        let traces = self
            .traces
            .as_ref()
            .map(|provider| move || crate::lifecycle::flush(|| provider.force_flush()));
        #[cfg(not(feature = "traces"))]
        let traces: Option<fn() -> OTelSdkResult> = None;
        let (logs, traces) = flush_logs_and_traces(
            || {
                self.provider.as_ref().map_or(Ok(()), |provider| {
                    crate::lifecycle::flush(|| provider.force_flush())
                })
            },
            traces,
        );
        self.losses.outcome(Signal::Logs, &logs);
        #[cfg(feature = "metrics")]
        let metrics = metrics.map_or(Ok(()), |target| {
            self.metrics_flushing.wait(target, deadline)
        });
        #[cfg(not(feature = "metrics"))]
        let metrics = Ok(());
        let _ = deadline;
        self.losses.finish_signals(logs, metrics, traces)
    }

    #[cfg(feature = "metrics")]
    fn start_metrics_flush(&self) -> Option<u64> {
        let provider = self.metrics.as_ref()?.clone();
        Some(
            self.metrics_flushing
                .register(provider, self.stopped.clone()),
        )
    }

    #[cfg(all(test, feature = "metrics"))]
    pub(crate) fn meter_provider(&self) -> Option<&SdkMeterProvider> {
        self.metrics.as_ref()
    }

    /// Flush and stop the pipeline with a five-second timeout. Drop then does
    /// nothing. Logs falling back to stderr contribute no error; metrics and traces
    /// still report their outcomes. The process slot remains occupied.
    ///
    /// # Errors
    /// Returns timeout, SDK/sink failure or data loss. See `FlushError::lost`.
    pub fn shutdown(self) -> Result<(), FlushError> {
        self.shutdown_with_timeout(Duration::from_secs(5))
    }

    /// Flush and stop with an explicit timeout. Queued records may be lost
    /// on timeout; the SDK worker may continue until storage unblocks.
    /// If a shutdown thread cannot be created, shutdown runs inline.
    /// The timeout bounds vigil's waits, but SDK 0.33's periodic reader can
    /// hold a blocked metrics shutdown for its fixed five seconds even with a
    /// shorter timeout, returning metrics `Timeout` ([ADR-0003 decision 4](https://github.com/vig-os/vigil/blob/dev/docs/adr/0003-metrics-and-traces.md#decision)).
    ///
    /// # Errors
    /// Returns timeout, SDK/sink failure or data loss. See `FlushError::lost`.
    pub fn shutdown_with_timeout(mut self, timeout: Duration) -> Result<(), FlushError> {
        let result = self.stop(timeout);
        self.summaries(result.as_ref().err(), false);
        result
    }

    fn stop(&mut self, timeout: Duration) -> Result<(), FlushError> {
        self.stop_with_builder(
            timeout,
            std::thread::Builder::new(),
            std::thread::Builder::new(),
            std::thread::Builder::new(),
        )
    }
    fn stop_with_builder(
        &mut self,
        timeout: Duration,
        logs_builder: std::thread::Builder,
        metrics_builder: std::thread::Builder,
        traces_builder: std::thread::Builder,
    ) -> Result<(), FlushError> {
        self.stopped.store(true, Ordering::Release);
        self.losses.shutting_down.store(true, Ordering::Release);
        let provider = self.provider.take();
        #[cfg(feature = "metrics")]
        let metrics = self.metrics.take();
        #[cfg(feature = "traces")]
        let traces = self.traces.take();
        let forward = tracing::dispatcher::get_default(Clone::clone);
        let capture = || {
            ShutdownCapture::new(
                crate::lifecycle::QueueSignal::Logs,
                forward.clone(),
                self.losses.clone(),
            )
        };
        let started = Instant::now();
        let logs_shutdown = || {
            let result = provider.as_ref().map_or(Ok(()), |provider| {
                tracing::subscriber::with_default(capture(), || {
                    provider.shutdown_with_timeout(timeout.saturating_sub(started.elapsed()))
                })
            });
            self.losses.outcome(Signal::Logs, &result);
            result
        };
        #[cfg(feature = "metrics")]
        let metrics_shutdown = || {
            let mut result = metrics.as_ref().map_or(Ok(()), |provider| {
                tracing::dispatcher::with_default(&forward, || {
                    provider.shutdown_with_timeout(timeout.saturating_sub(started.elapsed()))
                })
            });
            // SDK 0.33 ignores the timeout argument. Retain the actual deadline outcome.
            if metrics.is_some() && started.elapsed() > timeout {
                result = Err(OTelSdkError::Timeout(timeout));
            }
            self.losses.outcome(Signal::Metrics, &result);
            result
        };
        #[cfg(feature = "traces")]
        let traces_shutdown = || {
            let result = traces.as_ref().map_or(Ok(()), |provider| {
                let capture = ShutdownCapture::new(
                    crate::lifecycle::QueueSignal::Traces,
                    forward.clone(),
                    self.losses.clone(),
                );
                tracing::subscriber::with_default(capture, || {
                    provider.shutdown_with_timeout(timeout.saturating_sub(started.elapsed()))
                })
            });
            if let Some(storage) = &self.trace_storage {
                storage.close();
            }
            self.losses.outcome(Signal::Traces, &result);
            result
        };
        let result = std::thread::scope(|scope| {
            let logs_thread = logs_builder.spawn_scoped(scope, logs_shutdown);
            #[cfg(feature = "metrics")]
            let metrics_thread = metrics_builder.spawn_scoped(scope, metrics_shutdown);
            #[cfg(feature = "traces")]
            let traces_thread = traces
                .as_ref()
                .map(|_| traces_builder.spawn_scoped(scope, traces_shutdown));
            let logs = match logs_thread {
                Ok(thread) => thread.join().unwrap_or_else(|_| {
                    Err(OTelSdkError::InternalFailure(
                        "log shutdown thread panicked".into(),
                    ))
                }),
                Err(_) => logs_shutdown(),
            };
            #[cfg(feature = "metrics")]
            let metrics = {
                let metrics = match metrics_thread {
                    Ok(thread) => thread.join().unwrap_or_else(|_| {
                        Err(OTelSdkError::InternalFailure(
                            "metric shutdown thread panicked".into(),
                        ))
                    }),
                    Err(_) => metrics_shutdown(),
                };
                self.losses.outcome(Signal::Metrics, &metrics);
                metrics
            };
            #[cfg(not(feature = "metrics"))]
            let metrics = Ok(());
            self.losses.outcome(Signal::Logs, &logs);
            #[cfg(feature = "traces")]
            let traces = match traces_thread {
                Some(Ok(thread)) => thread.join().unwrap_or_else(|_| {
                    Err(OTelSdkError::InternalFailure(
                        "span shutdown thread panicked".into(),
                    ))
                }),
                Some(Err(_)) => traces_shutdown(),
                None => Ok(()),
            };
            #[cfg(not(feature = "traces"))]
            let traces = Ok(());
            (logs, metrics, traces)
        });
        #[cfg(not(feature = "metrics"))]
        let _ = metrics_builder;
        #[cfg(not(feature = "traces"))]
        let _ = traces_builder;
        self.losses.finish_signals(result.0, result.1, result.2)
    }

    fn summaries(&self, error: Option<&FlushError>, dropping: bool) {
        let (logs, failed) = self
            .losses
            .pending_stderr(crate::lifecycle::QueueSignal::Logs);
        let kind = error
            .and_then(|error| error.signal_kind(Signal::Logs))
            .unwrap_or(if failed {
                FlushErrorKind::Failed
            } else {
                FlushErrorKind::DataLost
            });
        if (dropping && (logs != 0 || kind != FlushErrorKind::DataLost))
            || (!dropping && kind == FlushErrorKind::Timeout)
        {
            if dropping {
                let _ = writeln!(
                    std::io::stderr(),
                    "vigil: log shutdown: {kind:?}; dropped records: {logs}; remaining records may be lost"
                );
            } else {
                let _ = writeln!(
                    std::io::stderr(),
                    "vigil: log shutdown: {kind:?}; remaining records may be lost"
                );
            }
        }
        #[cfg(feature = "metrics")]
        {
            let (points, failed) = self.losses.pending_metrics();
            let measurements = if dropping {
                self.losses.pending_measurements()
            } else {
                0
            };
            let kind = error
                .and_then(|error| error.signal_kind(Signal::Metrics))
                .unwrap_or(if failed {
                    FlushErrorKind::Failed
                } else {
                    FlushErrorKind::DataLost
                });
            if points != 0
                || measurements != 0
                || (dropping && kind != FlushErrorKind::DataLost)
                || kind == FlushErrorKind::Timeout
            {
                let _ = write!(std::io::stderr(), "vigil: metric shutdown: {kind:?}");
                if measurements != 0 {
                    let _ = write!(std::io::stderr(), "; dropped measurements: {measurements}");
                }
                if points != 0 {
                    let _ = write!(std::io::stderr(), "; dropped data points: {points}");
                }
                let _ = writeln!(std::io::stderr());
            }
        }
        #[cfg(feature = "traces")]
        {
            let (spans, failed) = self
                .losses
                .pending_stderr(crate::lifecycle::QueueSignal::Traces);
            let kind = error
                .and_then(|error| error.signal_kind(Signal::Traces))
                .unwrap_or(if failed {
                    FlushErrorKind::Failed
                } else {
                    FlushErrorKind::DataLost
                });
            if (dropping && (spans != 0 || kind != FlushErrorKind::DataLost))
                || (!dropping && kind == FlushErrorKind::Timeout)
            {
                let _ = writeln!(
                    std::io::stderr(),
                    "vigil: span shutdown: {kind:?}; dropped spans: {spans}; remaining spans may be lost"
                );
            }
        }
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        #[cfg(feature = "metrics")]
        let metrics = self.metrics.is_some();
        #[cfg(not(feature = "metrics"))]
        let metrics = false;
        #[cfg(feature = "traces")]
        let traces = self.traces.is_some();
        #[cfg(not(feature = "traces"))]
        let traces = false;
        if self.provider.is_none() && !metrics && !traces {
            return;
        }
        let result = self.stop(Duration::from_secs(5));
        self.summaries(result.as_ref().err(), true);
    }
}

/// Initialize logs with default configuration. See [`Config`] for overrides.
///
/// `let _ = vigil::init(..)` drops the guard immediately. Bind `let _guard = ...`
/// to keep logging alive. An unset or empty `RUST_LOG` uses `info`; builders may
/// choose another filter variable and default.
/// Keep the returned guard alive: dropping it drains and shuts down the batch
/// processor. Its default 65,536-record queue uses memory proportional to
/// queue size times record size. Overflow drops records with a stderr warning.
/// Drop waits up to five seconds for shutdown (including directory-lock waits),
/// then warns that remaining records may be lost. Calling
/// `std::process::exit` skips drop and loses queued records. No async runtime
/// is needed. Storage-open failures fall back to stderr with one warning.
/// Runtime export failures lose the affected records: stderr reports the first
/// failure, then cumulative dropped-record summaries at most once per minute
/// during failing exports, and any unreported losses at shutdown.
///
/// ```compile_fail
/// #![deny(unused_must_use)]
/// vigil::init("example").unwrap();
/// ```
///
/// With nextest, each test initializes once and explicitly shuts down before
/// reading its output:
///
/// ```no_run
/// let dir = std::env::temp_dir().join(format!("vigil-test-{}", std::process::id()));
/// let guard = vigil::Config::new("test").dir(&dir).init()?;
/// tracing::info!(test_case = "unique_test", "record");
/// guard.shutdown()?;
/// let lines = vigil::rotate::read_since(&dir, "logs", None)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// Under cargo test, share one `static LazyLock<Guard>` per binary, never shut
/// it down, and call `Guard::flush` before reading only records with a field
/// unique to the test. See [`Guard::flush`] for the shared-static example.
///
/// With traces enabled, enter a span to correlate log records with its trace/span IDs.
/// An explicit event parent without entering that span does not activate correlation.
///
/// # Errors
/// Returns `AlreadyRunning`, `ForeignSubscriber`, `InvalidServiceName`
/// or `InvalidFilter`. Use nextest for one process per test, or share one
/// pipeline per test binary. An earlier scoped default (`set_default` or
/// `with_default`) causes `ForeignSubscriber` even after its scope ends;
/// use `Config::layer` to compose, or initialize in a fresh test process.
pub fn init(service: impl Into<String>) -> Result<Guard, InitError> {
    Config::new(service).init()
}

/// Logging configuration. Explicit builder values win over environment values;
/// environment values win over defaults. Invalid numeric environment values warn on
/// stderr and use defaults. `filter_env` selects the filter variable (default
/// `RUST_LOG`); `default_filter` selects its fallback (default `info`). Unset or
/// empty filter variables use the fallback; invalid values warn and use it.
/// An invalid fallback returns `InvalidFilter`. Storage defaults to
/// `$XDG_STATE_HOME/<service>`, then `$HOME/.local/state/<service>`.
#[derive(Debug)]
pub struct Config {
    service: String,
    dir: Option<PathBuf>,
    max_bytes: Option<u64>,
    queue_size: Option<usize>,
    retention: Option<Option<Duration>>,
    version: Option<String>,
    revision: Option<String>,
    filter_env: String,
    default_filter: String,
    console: Console,
    #[cfg(vigil_unstable)]
    install_globals: bool,
    #[cfg(feature = "metrics")]
    metrics: Option<bool>,
    #[cfg(feature = "traces")]
    traces: Option<bool>,
    #[cfg(feature = "metrics")]
    metrics_interval: Option<Duration>,
}
impl Config {
    /// Configure a service. Names may contain ASCII letters, digits, `-`, `_`,
    /// and `.`, but cannot be empty, `.` or `..`.
    #[must_use]
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            dir: None,
            max_bytes: None,
            queue_size: None,
            retention: None,
            version: None,
            revision: None,
            filter_env: "RUST_LOG".into(),
            default_filter: "info".into(),
            console: Console::Off,
            #[cfg(vigil_unstable)]
            install_globals: false,
            #[cfg(feature = "metrics")]
            metrics: None,
            #[cfg(feature = "traces")]
            traces: None,
            #[cfg(feature = "metrics")]
            metrics_interval: None,
        }
    }
    /// Crates using `opentelemetry::global` must use vigil's OpenTelemetry minor
    /// (`vigil::unstable::opentelemetry`), or silently record into a no-op provider.
    ///
    /// Installs vigil's meter provider as the OpenTelemetry global meter provider.
    /// The tracer provider follows in #8 8f. No global propagator is installed.
    /// No effect when metrics are off or failed.
    /// Global instruments cannot cause poisoning, but streams under names poisoned
    /// by vigil handles are filtered too (ADR-0003 d21). Use `--cfg vigil_unstable`
    /// and pin vigil with `~1.N`.
    #[cfg(vigil_unstable)]
    #[cfg_attr(docsrs, doc(cfg(vigil_unstable)))]
    #[must_use]
    pub fn install_opentelemetry_globals(mut self) -> Self {
        self.install_globals = true;
        self
    }
    /// Enable metrics (default true); overrides `VIGIL_METRICS` (`0` or `1`).
    /// Disabled metrics create no storage, provider or reader thread;
    /// the startup report still prints when metrics are off.
    #[cfg(feature = "metrics")]
    #[cfg_attr(docsrs, doc(cfg(feature = "metrics")))]
    #[must_use]
    pub fn metrics(mut self, enabled: bool) -> Self {
        self.metrics = Some(enabled);
        self
    }
    /// Enable traces (default true); overrides `VIGIL_TRACES` (`0` or `1`).
    /// Disabled traces create no storage, provider, worker thread or tracing layer.
    #[cfg(feature = "traces")]
    #[cfg_attr(docsrs, doc(cfg(feature = "traces")))]
    #[must_use]
    pub fn traces(mut self, enabled: bool) -> Self {
        self.traces = Some(enabled);
        self
    }
    /// Metrics collection interval (default 60 seconds); overrides
    /// `VIGIL_METRICS_INTERVAL` in whole seconds. Values below one second
    /// clamp to one second. OpenTelemetry environment settings have no effect.
    #[cfg(feature = "metrics")]
    #[cfg_attr(docsrs, doc(cfg(feature = "metrics")))]
    #[must_use]
    pub fn metrics_interval(mut self, interval: Duration) -> Self {
        self.metrics_interval = Some(interval.max(Duration::from_secs(1)));
        self
    }
    /// Full state directory; overrides `VIGIL_DIR`.
    #[must_use]
    pub fn dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.dir = Some(dir.into());
        self
    }
    /// Rotation limit in bytes (minimum 1; builder zero clamps to 1); overrides `VIGIL_MAX_BYTES` (default 50 MiB).
    #[must_use]
    pub fn max_bytes(mut self, bytes: u64) -> Self {
        self.max_bytes = Some(bytes.max(1));
        self
    }
    /// Maximum queued records (default 65,536); overrides `VIGIL_QUEUE_SIZE`.
    /// Minimum 1; maximum 1,048,576. Oversized values clamp with a stderr warning.
    /// Measured memory is approximately 16 bytes per reserved slot (16 MiB at
    /// the cap) plus 0.4 KB per queued small record; larger fields need more.
    /// Memory is bounded by queue size times record size; overflow
    /// drops records and emits a warning to stderr.
    #[must_use]
    pub fn queue_size(mut self, size: usize) -> Self {
        if size > MAX_QUEUE_SIZE {
            let _ = writeln!(
                std::io::stderr(),
                "vigil: queue_size={size} exceeds {MAX_QUEUE_SIZE}; clamping to {MAX_QUEUE_SIZE}"
            );
        }
        self.queue_size = Some(size.clamp(1, MAX_QUEUE_SIZE));
        self
    }
    /// Retention duration; `None` keeps everything and `Some(Duration::ZERO)`
    /// prunes rotated segments at the next prune. Overrides
    /// `VIGIL_RETENTION_DAYS` (whole days, where zero instead keeps everything).
    /// An explicit `retention(None)` overrides the environment too.
    #[must_use]
    pub fn retention(mut self, retention: Option<Duration>) -> Self {
        self.retention = Some(retention);
        self
    }
    /// Producer version, for example `env!("CARGO_PKG_VERSION")` in the caller.
    #[must_use]
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }
    /// Producer commit; overrides `VIGIL_VCS_REVISION`.
    #[must_use]
    pub fn revision(mut self, revision: impl Into<String>) -> Self {
        self.revision = Some(revision.into());
        self
    }
    /// Read log directives from this environment variable (default `RUST_LOG`).
    /// Unset or empty values use `default_filter`; invalid values warn and
    /// use that default.
    #[must_use]
    pub fn filter_env(mut self, name: impl Into<String>) -> Self {
        self.filter_env = name.into();
        self
    }
    /// Filter when the selected environment variable is unset or empty
    /// (default `info`). Invalid directives return `InvalidFilter`.
    #[must_use]
    pub fn default_filter(mut self, directives: impl Into<String>) -> Self {
        self.default_filter = directives.into();
        self
    }
    /// Add a human-readable stderr layer with the same filter. The format
    /// is for people and may change in any release; files are machine-readable.
    #[must_use]
    pub fn console(mut self, console: Console) -> Self {
        self.console = console;
        self
    }
    /// Install the global subscriber and LogTracer using the same pipeline
    /// as `layer`. Keep the guard alive; `let _ = ...` drops it immediately.
    ///
    /// Tests use one process per test with nextest, or one shared pipeline
    /// per binary. A successful pipeline permanently occupies the process slot.
    /// See [`init`] for nextest and [`Guard::flush`] for shared-static tests.
    /// An earlier scoped default (`set_default` or `with_default`) in the same
    /// binary causes `ForeignSubscriber`, even after its scope has ended.
    ///
    /// # Errors
    /// Returns `AlreadyRunning`, `ForeignSubscriber`, `InvalidServiceName`
    /// or `InvalidFilter`. A failed attempt releases its pipeline reservation.
    pub fn init(self) -> Result<Guard, InitError> {
        self.init_with(|_| {})
    }

    fn init_with(self, before_install: impl FnOnce(&Guard)) -> Result<Guard, InitError> {
        if RESERVED.load(Ordering::Acquire) {
            return Err(InitError::new(
                InitErrorKind::AlreadyRunning,
                "vigil pipeline already initialized in this process",
            ));
        }
        if tracing::dispatcher::has_been_set() {
            return Err(InitError::new(
                InitErrorKind::ForeignSubscriber,
                "cannot install global tracing subscriber: a global or scoped default was already set",
            ));
        }
        let reservation = Reservation::acquire()?;
        #[cfg(vigil_unstable)]
        let install_globals = self.install_globals;
        let (layer, guard) = self.build_layer::<Registry>()?;
        before_install(&guard);
        if let Err(source) =
            tracing::subscriber::set_global_default(tracing_subscriber::registry().with(layer))
        {
            drop(guard); // Shutdown and close storage after losing the install race.
            return Err(InitError {
                kind: InitErrorKind::ForeignSubscriber,
                message: format!("cannot install global tracing subscriber: {source}"),
                source: Some(Box::new(source)),
            });
        }
        #[cfg(all(vigil_unstable, feature = "metrics"))]
        if install_globals {
            install_meter_global(&guard);
        }
        #[cfg(all(vigil_unstable, not(feature = "metrics")))]
        let _ = install_globals;
        reservation.commit(&guard);
        if tracing_log::LogTracer::init().is_err() {
            let _ = writeln!(
                std::io::stderr(),
                "vigil: a `log` logger is already installed; `log` records won't reach vigil"
            );
        }
        Ok(guard)
    }

    /// Build a pipeline for a consumer-owned `Registry`, without installing
    /// the global subscriber or LogTracer. The consumer installs its Registry;
    /// `SubscriberInitExt::init()` also installs LogTracer.
    ///
    /// Enter spans to correlate log records with their trace/span IDs when traces are enabled.
    /// Includes per-layer filtering, SDK diagnostics, recursion exclusion,
    /// post-shutdown filtering and the optional console. Other layers retain
    /// their own filters. Tests use nextest (one process per test), or share
    /// one pipeline per binary; dropping its guard stops it permanently.
    /// Earlier scoped defaults also prevent `init`, even after scope exit;
    /// compose with `layer` instead or use a fresh test process.
    ///
    /// With nextest, record, shut down, then read your directory. With cargo
    /// test, share one static guard, flush and select each test's unique field;
    /// never shut it down. See [`Guard::flush`] for the shared-static example.
    ///
    /// ```no_run
    /// use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    /// let (layer, guard) = vigil::Config::new("test").layer()?;
    /// tracing_subscriber::registry().with(layer).init();
    /// tracing::info!(test_case = "unique_test", "record");
    /// guard.shutdown()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    /// Returns `AlreadyRunning`, `InvalidServiceName` or `InvalidFilter`.
    /// Failed attempts release the reservation. Shutdown does not.
    ///
    /// # Panics
    /// Adding this layer panics unless `S` is `Registry` or a stack of
    /// layers built on it: per-layer filters require Registry bookkeeping.
    pub fn layer<S>(self) -> Result<(Box<dyn Layer<S> + Send + Sync + 'static>, Guard), InitError>
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a> + Send + Sync + 'static,
    {
        let reservation = Reservation::acquire()?;
        #[cfg(vigil_unstable)]
        let install_globals = self.install_globals;
        let result = self.build_layer()?;
        reservation.commit(&result.1);
        #[cfg(all(vigil_unstable, feature = "metrics"))]
        if install_globals {
            install_meter_global(&result.1);
        }
        #[cfg(all(vigil_unstable, not(feature = "metrics")))]
        let _ = install_globals;
        Ok(result)
    }

    fn build_layer<S>(self) -> Result<(PipelineLayer<S>, Guard), InitError>
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a> + Send + Sync + 'static,
    {
        validate_service(&self.service)?;
        let default = EnvFilter::try_new(&self.default_filter).map_err(|source| InitError {
            kind: InitErrorKind::InvalidFilter,
            message: format!("invalid default filter: {source}"),
            source: Some(Box::new(source)),
        })?;
        let filter = match env::var_os(&self.filter_env).filter(|value| !value.is_empty()) {
            None => default,
            Some(value) => EnvFilter::try_new(value.to_string_lossy()).unwrap_or_else(|error| {
                let _ = writeln!(
                    std::io::stderr(),
                    "vigil: invalid {}={value:?}: {error}; using {}",
                    self.filter_env,
                    self.default_filter
                );
                default
            }),
        };
        let losses = Arc::new(Losses::default());
        #[cfg(feature = "metrics")]
        let registry = Arc::new(crate::metric_identity::Registry::default());
        let stopped = Arc::new(AtomicBool::new(false));
        let active = stopped.clone();
        let shutdown_filter = tracing_subscriber::filter::dynamic_filter_fn(move |_, _| {
            !active.load(Ordering::Acquire)
        });
        let after_shutdown = AfterShutdown {
            stopped: stopped.clone(),
            warned: AtomicBool::new(false),
            #[cfg(feature = "traces")]
            span_warned: AtomicBool::new(false),
        }
        .with_filter(filter.clone())
        .with_filter(tracing_subscriber::filter::filter_fn(|meta| {
            !meta.target().starts_with("opentelemetry")
        }));
        let dir = self
            .dir
            .or_else(|| {
                env::var_os("VIGIL_DIR").filter(|s| !s.is_empty()).and_then(|value| {
                    let path = PathBuf::from(&value);
                    if path.is_absolute() {
                        Some(path)
                    } else {
                        let _ = writeln!(std::io::stderr(), "vigil: invalid VIGIL_DIR={value:?}; expected an absolute path; using default");
                        None
                    }
                })
            })
            .or_else(|| state_directory(&self.service));
        let mut rotation = RotationConfig::default();
        if let Some(bytes) = self.max_bytes.or_else(|| number("VIGIL_MAX_BYTES", 1)) {
            rotation = rotation.max_bytes(bytes);
        }
        if let Some(retention) = self.retention.or_else(|| {
            number("VIGIL_RETENTION_DAYS", 0)
                .map(|days| (days != 0).then(|| Duration::from_secs(days.saturating_mul(86_400))))
        }) {
            rotation = rotation.retention(retention);
        }
        let queue_size = self
            .queue_size
            .or_else(|| number("VIGIL_QUEUE_SIZE", 1).map(|n| {
                if n > MAX_QUEUE_SIZE as u64 {
                    let _ = writeln!(std::io::stderr(), "vigil: VIGIL_QUEUE_SIZE={n} exceeds {MAX_QUEUE_SIZE}; clamping to {MAX_QUEUE_SIZE}");
                }
                n.min(MAX_QUEUE_SIZE as u64) as usize
            }))
            .unwrap_or(65_536);
        let path_description = dir.as_ref().map_or_else(
            || "<unresolved state directory>".into(),
            |p| p.display().to_string(),
        );
        let id =
            instance_id().map_err(|error| format!("cannot generate service instance id: {error}"));
        let resource = id.as_ref().ok().map(|id| {
            let mut attrs = vec![
                KeyValue::new("service.name", self.service),
                KeyValue::new("service.instance.id", id.clone()),
                KeyValue::new("process.pid", i64::from(std::process::id())),
            ];
            if let Some(host) = hostname() {
                attrs.push(KeyValue::new("host.name", host));
            }
            if let Some(version) = self.version {
                attrs.push(KeyValue::new("service.version", version));
            }
            if let Some(revision) = self.revision.or_else(|| {
                env::var("VIGIL_VCS_REVISION")
                    .ok()
                    .filter(|s| !s.is_empty())
            }) {
                attrs.push(KeyValue::new("vcs.ref.head.revision", revision));
            }
            Resource::builder_empty().with_attributes(attrs).build()
        });
        #[cfg(all(test, any(feature = "metrics", feature = "traces")))]
        let mut signal_files: [std::sync::Weak<RotatingFile>; 3] = Default::default();
        #[cfg(feature = "metrics")]
        let metrics_enabled = self
            .metrics
            .unwrap_or_else(|| signal_switch("VIGIL_METRICS"));
        #[cfg(feature = "metrics")]
        let metrics = if metrics_enabled {
            let interval = metrics_interval(self.metrics_interval);
            resource.as_ref().and_then(|resource| {
                dir.as_ref().and_then(|dir| {
                    match RotatingFile::open(dir, "metrics", rotation.clone()) {
                        Ok(file) => {
                            let file = Arc::new(file);
                            #[cfg(all(test, feature = "metrics"))]
                            { signal_files[1] = Arc::downgrade(&file); }
                            Some(build_metrics(file, resource.clone(), interval, losses.clone(), registry.clone()))
                        },
                        Err(error) => {
                            let _ = writeln!(std::io::stderr(), "vigil: cannot open metrics storage at {}: {error}; disabling metrics", dir.display());
                            None
                        }
                    }
                })
            })
        } else {
            None
        };
        #[cfg(feature = "traces")]
        let traces_enabled = self.traces.unwrap_or_else(|| signal_switch("VIGIL_TRACES"));
        #[cfg(feature = "traces")]
        let trace_storage = traces_enabled.then(|| {
            use crate::trace_pipeline::{TraceStorage, TraceStorageState};
            let state = match (dir.as_ref(), resource.as_ref()) {
                (Some(dir), Some(_)) => match RotatingFile::open(dir, "traces", rotation.clone()) {
                    Ok(file) => {
                        let file = Arc::new(file);
                        #[cfg(test)]
                        {
                            signal_files[2] = Arc::downgrade(&file);
                        }
                        TraceStorageState::Ready(file)
                    }
                    Err(error) => {
                        let _ = writeln!(
                            std::io::stderr(),
                            "vigil: cannot open traces storage at {}: {error}; disabling traces",
                            dir.display()
                        );
                        TraceStorageState::Disabled
                    }
                },
                _ => TraceStorageState::Disabled,
            };
            Arc::new(TraceStorage(Mutex::new(state)))
        });
        #[cfg(feature = "traces")]
        let traces = trace_storage.as_ref().map(|storage| {
            crate::trace_pipeline::build_tracer(
                storage.clone(),
                resource
                    .clone()
                    .unwrap_or_else(|| Resource::builder_empty().build()),
                queue_size,
                losses.clone(),
            )
        });
        #[cfg(feature = "traces")]
        let otel = traces.as_ref().map(|provider| {
            let active = stopped.clone();
            crate::trace_pipeline::otel_layer(provider)
                .with_filter(tracing_subscriber::filter::filter_fn(
                    crate::trace_pipeline::spans_or_error,
                ))
                .with_filter(tracing_subscriber::filter::dynamic_filter_fn(
                    move |_, _| !active.load(Ordering::Acquire),
                ))
                .with_filter(filter.clone())
                .with_filter(tracing_subscriber::filter::filter_fn(|meta| {
                    !meta.target().starts_with("opentelemetry")
                }))
        });
        let file = dir.as_ref()
            .ok_or_else(|| std::io::Error::other(format!("neither XDG_STATE_HOME nor HOME provides an absolute path; rejected XDG_STATE_HOME={:?}, HOME={:?}", env::var_os("XDG_STATE_HOME"), env::var_os("HOME"))))
            .and_then(|dir| RotatingFile::open(dir, "logs", rotation))
            .map_err(|error| format!("cannot open log storage at {path_description}: {error}"))
            .and_then(|file| id.map(|_| file));
        #[cfg(feature = "metrics")]
        let metrics_disabled = metrics_enabled && (resource.is_none() || dir.is_none());
        #[cfg(not(feature = "metrics"))]
        let metrics_disabled = false;
        #[cfg(feature = "traces")]
        let traces_disabled = traces_enabled && (resource.is_none() || dir.is_none());
        #[cfg(not(feature = "traces"))]
        let traces_disabled = false;
        let (destination, provider, log_dir): (PipelineLayer<S>, _, _) = match file {
            Ok(file) => {
                let file = Arc::new(file);
                #[cfg(all(test, any(feature = "metrics", feature = "traces")))]
                {
                    signal_files[0] = Arc::downgrade(&file);
                }
                let provider = SdkLoggerProvider::builder()
                    .with_resource(resource.unwrap_or_else(|| Resource::builder_empty().build()))
                    .with_log_processor(ReportingProcessor {
                        losses: losses.clone(),
                        inner: BatchLogProcessor::builder(ReportingExporter {
                            failures: Mutex::new(Failures::default()),
                            losses: losses.clone(),
                            inner: OtlpJsonLogExporter::new(file),
                        })
                        .with_batch_config(log_batch_config(queue_size))
                        .build(),
                    })
                    .build();
                let bridge = OpenTelemetryTracingBridge::new(&NamedProvider(provider.clone()));
                let console = (self.console == Console::Stderr).then(|| {
                    tracing_subscriber::fmt::layer()
                        .with_writer(std::io::stderr)
                        .with_ansi(std::io::stderr().is_terminal())
                });
                (bridge.and_then(console).boxed(), Some(provider), dir)
            }
            Err(error) => {
                let disabled = match (metrics_disabled, traces_disabled) {
                    (true, true) => " for logs; disabling metrics and traces",
                    (true, false) => " for logs; disabling metrics",
                    (false, true) => " for logs; disabling traces",
                    (false, false) => "",
                };
                let _ = writeln!(
                    std::io::stderr(),
                    "vigil: {error}; falling back to stderr{disabled}"
                );
                (
                    tracing_subscriber::fmt::layer()
                        .with_writer(std::io::stderr)
                        .with_ansi(std::io::stderr().is_terminal())
                        .boxed(),
                    None,
                    None,
                )
            }
        };
        let guard = Guard {
            provider,
            #[cfg(feature = "traces")]
            traces,
            #[cfg(feature = "traces")]
            trace_storage,
            #[cfg(feature = "metrics")]
            metrics,
            #[cfg(feature = "metrics")]
            metrics_flushing: Arc::new(MetricFlushes::default()),
            #[cfg(feature = "metrics")]
            registry,
            stopped,
            losses: losses.clone(),
            dir: log_dir,
            #[cfg(all(test, any(feature = "metrics", feature = "traces")))]
            signal_files,
        };
        let destination = destination
            .with_filter(shutdown_filter)
            .with_filter(filter)
            .with_filter(tracing_subscriber::filter::filter_fn(|meta| {
                !meta.target().starts_with("opentelemetry")
            }));
        let pipeline = diagnostics().and_then(after_shutdown);
        #[cfg(feature = "traces")]
        let pipeline = pipeline.and_then(otel);
        Ok((pipeline.and_then(destination).boxed(), guard))
    }
}
#[cfg(all(vigil_unstable, feature = "metrics"))]
fn install_meter_global(guard: &Guard) {
    if let Some(provider) = &guard.metrics {
        opentelemetry::global::set_meter_provider(provider.clone());
    }
}

#[cfg(feature = "metrics")]
fn metrics_interval(explicit: Option<Duration>) -> Duration {
    explicit
        .or_else(|| number("VIGIL_METRICS_INTERVAL", 1).map(Duration::from_secs))
        .unwrap_or(Duration::from_secs(60))
}

#[cfg(any(feature = "metrics", feature = "traces"))]
fn signal_switch(var: &str) -> bool {
    match env::var_os(var).filter(|value| !value.is_empty()) {
        None => true,
        Some(value) if value == "0" => false,
        Some(value) if value == "1" => true,
        Some(value) => {
            let _ = writeln!(
                std::io::stderr(),
                "vigil: invalid {var}={value:?}; expected 0 or 1; using default"
            );
            true
        }
    }
}

#[cfg(feature = "metrics")]
fn metrics_reader<E: opentelemetry_sdk::metrics::exporter::PushMetricExporter>(
    exporter: E,
    interval: Duration,
) -> PeriodicReaderBuilder<E> {
    PeriodicReader::builder(exporter).with_interval(interval.max(Duration::from_secs(1)))
}

#[cfg(feature = "metrics")]
fn build_metrics(
    file: Arc<RotatingFile>,
    resource: Resource,
    interval: Duration,
    losses: Arc<Losses>,
    registry: Arc<crate::metric_identity::Registry>,
) -> SdkMeterProvider {
    let storage = Arc::new(MetricStorage(Mutex::new(Some(file))));
    let exporter = PipelineMetricExporter {
        inner: crate::metric_export::OtlpJsonMetricExporter::new(storage)
            .with_losses(losses.clone())
            .with_registry(registry),
    };
    SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(ReportingMetricReader {
            inner: metrics_reader(exporter, interval).build(),
            losses,
        })
        .build()
}

// PeriodicReader acknowledges shutdown before dropping its exporter Arc.
// Close storage in the exporter's shutdown, before the SDK acknowledgement.
// A timed-out worker can still write, then releases storage when it stops,
// even while an external provider clone retains the SDK exporter.
#[cfg(feature = "metrics")]
#[derive(Debug)]
struct MetricStorage(Mutex<Option<Arc<RotatingFile>>>);
#[cfg(feature = "metrics")]
impl crate::sink::LineSink for MetricStorage {
    fn write_line(&self, line: &[u8]) -> std::io::Result<()> {
        let file = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        file.as_ref()
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "metric storage closed")
            })?
            .write_line(line)
    }
}
#[cfg(feature = "metrics")]
impl MetricStorage {
    fn close(&self) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }
}

#[cfg(feature = "metrics")]
#[derive(Debug)]
struct PipelineMetricExporter {
    inner: crate::metric_export::OtlpJsonMetricExporter<Arc<MetricStorage>>,
}
#[cfg(feature = "metrics")]
impl opentelemetry_sdk::metrics::exporter::PushMetricExporter for PipelineMetricExporter {
    async fn export(
        &self,
        metrics: &opentelemetry_sdk::metrics::data::ResourceMetrics,
    ) -> OTelSdkResult {
        self.inner.export(metrics).await
    }
    fn force_flush(&self) -> OTelSdkResult {
        self.inner.force_flush()
    }
    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        let result = self.inner.shutdown_with_timeout(timeout);
        self.inner.sink().close();
        result
    }
    fn temporality(&self) -> opentelemetry_sdk::metrics::Temporality {
        self.inner.temporality()
    }
}

// Preserve typed reader timeouts before SdkMeterProvider stringifies them.
// This requires the SDK's custom-reader feature, without its testing feature.
#[cfg(feature = "metrics")]
#[derive(Debug)]
struct ReportingMetricReader {
    inner: PeriodicReader<PipelineMetricExporter>,
    losses: Arc<Losses>,
}
#[cfg(feature = "metrics")]
impl opentelemetry_sdk::metrics::reader::MetricReader for ReportingMetricReader {
    fn register_pipeline(&self, pipeline: std::sync::Weak<opentelemetry_sdk::metrics::Pipeline>) {
        self.inner.register_pipeline(pipeline);
    }
    fn collect(
        &self,
        metrics: &mut opentelemetry_sdk::metrics::data::ResourceMetrics,
    ) -> OTelSdkResult {
        self.inner.collect(metrics)
    }
    fn force_flush(&self) -> OTelSdkResult {
        self.inner.force_flush()
    }
    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        let result = self.inner.shutdown_with_timeout(timeout);
        self.losses.outcome(Signal::Metrics, &result);
        result
    }
    fn temporality(
        &self,
        kind: opentelemetry_sdk::metrics::InstrumentKind,
    ) -> opentelemetry_sdk::metrics::Temporality {
        self.inner.temporality(kind)
    }
}

// The upstream bridge requests an empty scope; supply a named scope to avoid
// the SDK's LoggerNameEmpty diagnostic before subscriber installation.
struct NamedProvider(SdkLoggerProvider);
impl LoggerProvider for NamedProvider {
    type Logger = SdkLogger;
    fn logger_with_scope(&self, _scope: InstrumentationScope) -> Self::Logger {
        self.0.logger("vigil")
    }
}
fn number(key: &str, minimum: u64) -> Option<u64> {
    let value = env::var_os(key).filter(|s| !s.is_empty())?;
    if let Some(number) = value
        .to_str()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n >= minimum)
    {
        Some(number)
    } else {
        let _ = writeln!(
            std::io::stderr(),
            "vigil: invalid {key}={value:?}; minimum {minimum}; using default"
        );
        None
    }
}
// Override every setting available to the synchronous processor. Export
// timeout exists only on the SDK's async processor, which vigil does not use;
// the synchronous processor has no concurrency setting (ADR-0003 decision 6).
fn log_batch_config(queue_size: usize) -> opentelemetry_sdk::logs::BatchConfig {
    BatchConfigBuilder::default()
        .with_max_queue_size(queue_size)
        .with_max_export_batch_size(512)
        .with_scheduled_delay(Duration::from_secs(1))
        .build()
}

// RFC 9562 UUID v4: 122 random bits, version 4 and the RFC variant.
fn instance_id() -> std::io::Result<String> {
    let mut bytes = [0; 16];
    #[cfg(test)]
    if entropy_failure_tests::FAIL_ENTROPY.get() {
        return Err(std::io::Error::other("injected entropy failure"));
    }
    getrandom::fill(&mut bytes).map_err(|error| std::io::Error::other(error.to_string()))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let mut id = String::with_capacity(36);
    for (index, byte) in bytes.into_iter().enumerate() {
        if [4, 6, 8, 10].contains(&index) {
            id.push('-');
        }
        for nibble in [byte >> 4, byte & 0xf] {
            id.push(b"0123456789abcdef"[nibble as usize] as char);
        }
    }
    Ok(id)
}

fn hostname() -> Option<String> {
    let host = rustix::system::uname()
        .nodename()
        .to_string_lossy()
        .into_owned();
    (!host.is_empty()).then_some(host)
}

#[derive(Debug, Default)]
pub(crate) struct Failures {
    dropped: usize,
    reported: usize,
    last_report: Option<Instant>,
}
impl Failures {
    pub(crate) fn record(
        &mut self,
        signal: &str,
        unit: &str,
        lost: usize,
        result: &opentelemetry_sdk::error::OTelSdkResult,
        shutting_down: bool,
    ) -> u64 {
        self.dropped = self.dropped.saturating_add(lost);
        if (lost != 0 || result.is_err())
            && !shutting_down
            && self
                .last_report
                .is_none_or(|last| last.elapsed() >= Duration::from_secs(60))
        {
            let unreported = self.dropped.saturating_sub(self.reported);
            if let Some(error) = result.as_ref().err().filter(|_| self.last_report.is_none()) {
                let _ = writeln!(
                    std::io::stderr(),
                    "vigil: runtime {signal} export failed: {error}; dropped {unit}: {}",
                    self.dropped
                );
            } else {
                let _ = writeln!(
                    std::io::stderr(),
                    "vigil: runtime {signal} export losses; dropped {unit}: {}",
                    self.dropped
                );
            }
            self.reported = self.dropped;
            self.last_report = Some(Instant::now());
            unreported as u64
        } else {
            0
        }
    }
}

// Handle failed batches here so the SDK does not emit an ExportError per batch.
#[derive(Debug)]
struct ReportingExporter {
    inner: OtlpJsonLogExporter<Arc<RotatingFile>>,
    failures: Mutex<Failures>,
    losses: Arc<Losses>,
}
impl LogExporter for ReportingExporter {
    async fn export(&self, batch: LogBatch<'_>) -> opentelemetry_sdk::error::OTelSdkResult {
        self.losses.reached(
            crate::lifecycle::QueueSignal::Logs,
            batch.iter().count() as u64,
        );
        let result = self.inner.export(batch).await;
        let lost = self.inner.take_dropped_records();
        self.losses.record(
            crate::lifecycle::QueueSignal::Logs,
            lost as u64,
            result.is_err(),
        );
        let reported = self
            .failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record(
                "log",
                "records",
                lost,
                &result,
                self.losses.shutting_down.load(Ordering::Acquire),
            );
        self.losses
            .reported(crate::lifecycle::QueueSignal::Logs, reported);
        Ok(())
    }
    fn set_resource(&mut self, resource: &Resource) {
        self.inner.set_resource(resource);
    }
    fn shutdown_with_timeout(&self, timeout: Duration) -> opentelemetry_sdk::error::OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }
}

fn diagnostics<S>() -> PipelineLayer<S>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a> + Send + Sync + 'static,
{
    tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_filter(tracing_subscriber::filter::filter_fn(|meta| {
            meta.target().starts_with("opentelemetry") && *meta.level() <= tracing::Level::WARN
        }))
        .boxed()
}

#[cfg(test)]
mod dropped_stub_tests {
    use super::*;
    use opentelemetry::logs::{LogRecord as _, Logger as _};
    use std::task::{Context, Poll, Waker};

    #[test]
    fn dropped_stubs_are_counted_in_runtime_summary() {
        let dir = std::env::temp_dir().join(format!("vigil-stub-summary-{}", std::process::id()));
        let exporter = ReportingExporter {
            failures: Mutex::new(Failures::default()),
            inner: OtlpJsonLogExporter::new(Arc::new(
                RotatingFile::open(&dir, "logs", RotationConfig::default()).unwrap(),
            )),
            losses: Arc::new(Losses::default()),
        };
        let provider = SdkLoggerProvider::builder().build();
        let logger = provider.logger("summary");
        let mut record = logger.create_log_record();
        record.set_observed_timestamp(std::time::SystemTime::now());
        for index in 0..60_000 {
            record.add_attribute(format!("integer-{index}"), 42_i64);
        }
        let scope = InstrumentationScope::builder("summary").build();
        let records = [(&record, &scope)];
        for count in 1..=2 {
            let mut export = std::pin::pin!(exporter.export(LogBatch::new(&records)));
            assert!(matches!(
                std::future::Future::poll(export.as_mut(), &mut Context::from_waker(Waker::noop())),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(
                exporter
                    .losses
                    .pending_stderr(crate::lifecycle::QueueSignal::Logs),
                (count - 1, false)
            );
        }
        exporter
            .shutdown_with_timeout(Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            exporter
                .losses
                .pending_stderr(crate::lifecycle::QueueSignal::Logs),
            (1, false)
        );
        let loss = exporter.losses.finish(Ok(())).unwrap_err();
        assert_eq!(loss.kind(), crate::FlushErrorKind::DataLost);
        assert_eq!(loss.lost(crate::Signal::Logs), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(test)]
mod install_race_tests {
    use super::*;

    #[cfg(target_os = "linux")]
    fn storage_handles(dir: &Path) -> Vec<PathBuf> {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter_map(|fd| std::fs::read_link(fd).ok())
            .filter(|target| target.starts_with(dir))
            .collect()
    }

    #[cfg(all(vigil_unstable, feature = "metrics"))]
    #[test]
    fn losing_install_keeps_sentinel_meter_global() {
        if !crate::subscriber_test_child(
            "init::install_race_tests::losing_install_keeps_sentinel_meter_global",
        ) {
            return;
        }
        let sink = crate::sink::MemorySink::new();
        let sentinel = SdkMeterProvider::builder()
            .with_reader(
                opentelemetry_sdk::metrics::PeriodicReader::builder(
                    crate::metric_export::OtlpJsonMetricExporter::new(sink.clone()),
                )
                .with_interval(Duration::from_secs(3600))
                .build(),
            )
            .build();
        opentelemetry::global::set_meter_provider(sentinel.clone());
        let dir = std::env::temp_dir().join(format!("vigil-sentinel-{}", std::process::id()));
        let error = Config::new("race")
            .dir(&dir)
            .install_opentelemetry_globals()
            .init_with(|_| {
                tracing::subscriber::set_global_default(tracing_subscriber::registry()).unwrap();
            })
            .unwrap_err();
        assert_eq!(error.kind(), InitErrorKind::ForeignSubscriber);
        opentelemetry::global::meter("sentinel")
            .u64_counter("sentinel.survives")
            .build()
            .add(7, &[]);
        sentinel.force_flush().unwrap();
        assert!(
            sink.lines()
                .iter()
                .any(|line| line.contains("sentinel.survives"))
        );
        sentinel.shutdown().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn foreign_subscriber_winning_install_releases_reservation() {
        if !crate::subscriber_test_child(
            "init::install_race_tests::foreign_subscriber_winning_install_releases_reservation",
        ) {
            return;
        }
        let dir = std::env::temp_dir().join(format!("vigil-install-race-{}", std::process::id()));
        let mut provider = None;
        #[cfg(feature = "metrics")]
        let mut metrics = None;
        let error = Config::new("race")
            .dir(&dir)
            .init_with(|guard| {
                provider = guard.provider.clone();
                #[cfg(feature = "metrics")]
                {
                    metrics = guard.metrics.clone();
                }
                #[cfg(target_os = "linux")]
                {
                    let handles = storage_handles(&dir);
                    assert!(
                        handles.contains(&dir),
                        "test must observe the directory lock handle"
                    );
                    #[cfg(feature = "metrics")]
                    assert!(handles.contains(&dir.join("metrics.jsonl")));
                    assert!(
                        handles.contains(&dir.join("logs.jsonl")),
                        "test must observe the live log handle"
                    );
                }
                tracing::subscriber::set_global_default(tracing_subscriber::registry()).unwrap();
            })
            .unwrap_err();
        assert_eq!(error.kind(), InitErrorKind::ForeignSubscriber);
        assert!(std::error::Error::source(&error).is_some());
        #[cfg(feature = "metrics")]
        let metrics = metrics.unwrap();
        #[cfg(feature = "metrics")]
        assert!(matches!(
            metrics.shutdown(),
            Err(OTelSdkError::AlreadyShutdown)
        ));
        #[cfg(target_os = "linux")]
        assert!(
            storage_handles(&dir).is_empty(),
            "lost install must close storage handles, even with a retained metrics provider"
        );
        #[cfg(feature = "metrics")]
        drop(metrics);
        assert!(
            matches!(
                provider.unwrap().shutdown_with_timeout(Duration::ZERO),
                Err(opentelemetry_sdk::error::OTelSdkError::AlreadyShutdown)
            ),
            "lost install must shut down the provider even when another clone exists"
        );
        let (_, guard) = Config::new("retry").dir(&dir).layer::<Registry>().unwrap();
        assert_eq!(guard.dir(), Some(dir.as_path()));
        drop(guard);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
mod guard_tests {
    use super::*;
    use opentelemetry_sdk::error::OTelSdkError;

    #[test]
    fn stop_consumes_provider_before_drop_and_stops_recording_first() {
        if !crate::subscriber_test_child(
            "init::guard_tests::stop_consumes_provider_before_drop_and_stops_recording_first",
        ) {
            return;
        }
        let provider = SdkLoggerProvider::builder().build();
        let retained = provider.clone();
        let mut guard = Guard {
            provider: Some(provider),
            #[cfg(feature = "traces")]
            traces: None,
            #[cfg(feature = "traces")]
            trace_storage: None,
            #[cfg(feature = "metrics")]
            metrics: None,
            #[cfg(feature = "metrics")]
            metrics_flushing: Arc::new(MetricFlushes::default()),
            #[cfg(feature = "metrics")]
            registry: Arc::new(crate::metric_identity::Registry::default()),
            stopped: Arc::new(AtomicBool::new(false)),
            dir: None,
            #[cfg(all(test, any(feature = "metrics", feature = "traces")))]
            signal_files: Default::default(),
            losses: Arc::new(Losses::default()),
        };
        guard.flush().unwrap();
        assert!(!guard.stopped.load(Ordering::Acquire));
        // A page-aligned, impossibly large stack makes thread creation return
        // an OS error without exhausting the host's thread resources.
        guard
            .stop_with_builder(
                Duration::from_millis(17),
                std::thread::Builder::new().stack_size(usize::MAX / 2 + 1),
                std::thread::Builder::new().stack_size(usize::MAX / 2 + 1),
                std::thread::Builder::new().stack_size(usize::MAX / 2 + 1),
            )
            .unwrap();
        assert!(guard.stopped.load(Ordering::Acquire));
        assert!(guard.provider.is_none());
        assert!(matches!(
            retained.shutdown(),
            Err(OTelSdkError::AlreadyShutdown)
        ));
        drop(guard);
    }
}

#[cfg(test)]
mod batch_config_tests {
    use super::*;

    #[test]
    fn otel_batch_environment_does_not_change_effective_settings() {
        const CHILD: &str = "VIGIL_BATCH_CONFIG_CHILD";
        if env::var_os(CHILD).is_some() {
            assert_eq!(
                format!("{:?}", log_batch_config(65_536)),
                "BatchConfig { max_queue_size: 65536, scheduled_delay: 1s, max_export_batch_size: 512 }"
            );
            assert_eq!(
                format!("{:?}", log_batch_config(16)),
                "BatchConfig { max_queue_size: 16, scheduled_delay: 1s, max_export_batch_size: 16 }"
            );
            return;
        }
        for value in ["7", "999999"] {
            let mut cmd = std::process::Command::new(env::current_exe().unwrap());
            cmd.args(["--exact", "init::batch_config_tests::otel_batch_environment_does_not_change_effective_settings", "--nocapture"]).env(CHILD, "1");
            for key in [
                "OTEL_BLRP_MAX_QUEUE_SIZE",
                "OTEL_BLRP_MAX_EXPORT_BATCH_SIZE",
                "OTEL_BLRP_SCHEDULE_DELAY",
                "OTEL_BLRP_EXPORT_TIMEOUT",
            ] {
                cmd.env(key, value);
            }
            let output = cmd.output().unwrap();
            assert!(output.status.success(), "{output:?}");
        }
    }
}

#[cfg(test)]
mod entropy_failure_tests {
    use super::*;

    thread_local! {
        pub(super) static FAIL_ENTROPY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    struct TempDir(std::path::PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn entropy_failure_degrades_with_the_real_cause() {
        const CHILD: &str = "VIGIL_ENTROPY_FAILURE_DIR";
        if let Some(dir) = env::var_os(CHILD) {
            FAIL_ENTROPY.set(true);
            let guard = Config::new("entropy-failure")
                .dir(std::path::PathBuf::from(dir))
                .filter_env("VIGIL_ENTROPY_TEST_FILTER")
                .default_filter("info")
                .init()
                .unwrap();
            assert!(guard.provider.is_none());
            assert!(guard.dir().is_none());
            #[cfg(feature = "metrics")]
            assert!(guard.metrics.is_none());
            tracing::info!("entropy fallback is alive");
            guard.flush().unwrap();
            guard.shutdown().unwrap();
            return;
        }
        let temp =
            TempDir(env::temp_dir().join(format!("vigil-entropy-failure-{}", std::process::id())));
        let output = std::process::Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "init::entropy_failure_tests::entropy_failure_degrades_with_the_real_cause",
                "--nocapture",
            ])
            .env(CHILD, &temp.0)
            .env_remove("VIGIL_ENTROPY_TEST_FILTER")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(stderr.matches("cannot generate service instance id: injected entropy failure; falling back to stderr").count(), 1, "{stderr}");
        #[cfg(feature = "metrics")]
        {
            assert_eq!(stderr.matches("disabling metrics").count(), 1, "{stderr}");
            assert_eq!(
                stderr
                    .lines()
                    .filter(|line| line.starts_with("vigil:"))
                    .count(),
                1,
                "{stderr}"
            );
        }
        assert!(!stderr.contains("cannot open log storage"), "{stderr}");
        assert!(stderr.contains("entropy fallback is alive"), "{stderr}");
        assert!(std::fs::read(temp.0.join("logs.jsonl")).unwrap().is_empty());
    }
}

#[cfg(test)]
mod failure_reporting_tests {
    use super::*;
    use opentelemetry_sdk::error::OTelSdkError;
    #[test]
    fn log_shutdown_gate_suppresses_an_otherwise_due_report() {
        let mut failures = Failures::default();
        let result = Err(OTelSdkError::InternalFailure("shutdown failure".into()));
        assert_eq!(failures.record("log", "records", 2, &result, true), 0);
        assert_eq!(failures.dropped, 2);
        assert_eq!(failures.reported, 0);
        assert!(failures.last_report.is_none());
        assert_eq!(failures.record("log", "records", 0, &result, false), 2);
    }

    #[test]
    fn first_failure_and_rate_limited_summaries_name_signal_and_unit() {
        const CHILD: &str = "VIGIL_FAILURE_REPORT_TEST";
        if std::env::var_os(CHILD).is_some() {
            for (signal, unit) in [("log", "records"), ("metric", "data points")] {
                let mut failures = Failures::default();
                let result = Err(OTelSdkError::InternalFailure("deliberate failure".into()));
                assert_eq!(failures.record(signal, unit, 2, &result, false), 2);
                assert_eq!(failures.record(signal, unit, 3, &result, false), 0);
                failures.last_report = Some(Instant::now() - Duration::from_secs(61));
                assert_eq!(failures.record(signal, unit, 4, &result, false), 7);
                assert_eq!(failures.record(signal, unit, 1, &result, true), 0);
                assert_eq!(failures.dropped, 10);
                assert_eq!(failures.reported, 9);
            }
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "init::failure_reporting_tests::first_failure_and_rate_limited_summaries_name_signal_and_unit", "--nocapture"])
            .env(CHILD, "1").output().unwrap();
        assert!(output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        for (signal, unit) in [("log", "records"), ("metric", "data points")] {
            assert_eq!(
                stderr
                    .matches(&format!("runtime {signal} export failed:"))
                    .count(),
                1
            );
            assert!(stderr.contains(&format!(
                "runtime {signal} export losses; dropped {unit}: 9"
            )));
        }
    }
}

// Shared by telemetry and audit; VIGIL_DIR is a telemetry-only override.
pub(crate) fn validate_service(service: &str) -> Result<(), InitError> {
    if service.is_empty()
        || service == "."
        || service == ".."
        || !service
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        return Err(InitError::new(
            InitErrorKind::InvalidServiceName,
            "invalid service name: expected ASCII letters, digits, '-', '_' or '.'",
        ));
    }
    Ok(())
}
pub(crate) fn state_directory(service: &str) -> Option<PathBuf> {
    env::var_os("XDG_STATE_HOME")
        .filter(|s| std::path::Path::new(s).is_absolute())
        .map(|s| PathBuf::from(s).join(service))
        .or_else(|| {
            env::var_os("HOME")
                .filter(|s| std::path::Path::new(s).is_absolute())
                .map(|s| PathBuf::from(s).join(".local/state").join(service))
        })
}

#[cfg(all(test, feature = "metrics"))]
mod metrics_lifecycle_tests {
    use super::*;
    use opentelemetry::metrics::MeterProvider as _;
    use serde_json::Value;
    use std::{fs, process::Command, sync::mpsc};

    fn directory(case: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("vigil-metrics-{case}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
    fn child(test: &str, mode: &str, vars: &[(&str, &str)]) -> Option<std::process::Output> {
        if env::var_os("VIGIL_METRICS_TEST_MODE").is_some() {
            return None;
        }
        let output = Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                &format!("init::metrics_lifecycle_tests::{test}"),
                "--nocapture",
            ])
            .env_remove("VIGIL_METRICS")
            .env_remove("VIGIL_METRICS_INTERVAL")
            .env_remove("RUST_LOG")
            .env("VIGIL_METRICS_TEST_MODE", mode)
            .envs(vars.iter().copied())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Some(output)
    }
    fn record(guard: &Guard) {
        guard
            .meter_provider()
            .unwrap()
            .meter("test")
            .u64_counter("requests")
            .build()
            .add(7, &[]);
    }
    fn points(dir: &Path) -> Vec<Value> {
        fs::read_to_string(dir.join("metrics.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
    fn block_directory(dir: &Path) -> (mpsc::Sender<()>, std::thread::JoinHandle<()>) {
        let file = fs::File::open(dir).unwrap();
        let (ready, waiting) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            file.lock().unwrap();
            ready.send(()).unwrap();
            released.recv().unwrap();
            file.unlock().unwrap();
        });
        waiting.recv().unwrap();
        (release, thread)
    }

    #[test]
    fn init_creates_both_signal_files_without_lock_files() {
        if !crate::subscriber_test_child(
            "init::metrics_lifecycle_tests::init_creates_both_signal_files_without_lock_files",
        ) {
            return;
        }
        let dir = directory("layout");
        let guard = Config::new("layout").dir(&dir).init().unwrap();
        assert!(dir.join("logs.jsonl").is_file());
        assert!(dir.join("metrics.jsonl").is_file());
        assert_eq!(
            fs::read_dir(&dir).unwrap().count(),
            2 + usize::from(cfg!(feature = "traces"))
        );
        drop(guard);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn shared_lock_flush_shutdown_cumulative_time_first_and_empty_exemplars() {
        if child(
            "shared_lock_flush_shutdown_cumulative_time_first_and_empty_exemplars",
            "layout",
            &[],
        )
        .is_some()
        {
            return;
        }
        let dir = directory("shared-lock");
        let guard = Config::new("shared").dir(&dir).init().unwrap();
        let logs = guard.signal_files[0].upgrade().unwrap();
        let metrics = guard.signal_files[1].upgrade().unwrap();
        assert!(logs.shares_lock(&metrics));
        record(&guard);
        tracing::info!("a log");
        guard.flush().unwrap();
        guard.shutdown().unwrap();
        assert!(
            !fs::read_to_string(dir.join("logs.jsonl"))
                .unwrap()
                .is_empty()
        );
        let text = fs::read_to_string(dir.join("metrics.jsonl")).unwrap();
        assert_eq!(text.lines().count(), 2);
        for line in text.lines() {
            assert!(line.starts_with("{\"resourceMetrics\":[{\"scopeMetrics\":[{\"metrics\":[{\"sum\":{\"dataPoints\":[{\"timeUnixNano\":"), "{line}");
            let json: Value = serde_json::from_str(line).unwrap();
            let sum = &json["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["sum"];
            assert_eq!(sum["aggregationTemporality"], 2);
            assert_eq!(sum["dataPoints"][0]["asInt"], 7);
            assert!(
                sum["dataPoints"][0]
                    .get("exemplars")
                    .is_none_or(|v| v.as_array().unwrap().is_empty())
            );
        }
        assert_eq!(
            fs::read_dir(&dir).unwrap().count(),
            2 + usize::from(cfg!(feature = "traces"))
        );
        drop((logs, metrics));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn fallback_logs_still_return_metric_failure_without_measurement_loss() {
        if let Some(output) = child(
            "fallback_logs_still_return_metric_failure_without_measurement_loss",
            "fallback",
            &[],
        ) {
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("metric shutdown: Failed; dropped data points: 1"),
                "{stderr}"
            );
            return;
        }
        let dir = directory("fallback-failed-metrics");
        fs::create_dir(dir.join("logs.jsonl")).unwrap();
        let guard = Config::new("fallback").dir(&dir).init().unwrap();
        assert!(guard.dir().is_none());
        record(&guard);
        fs::remove_file(dir.join("metrics.jsonl")).unwrap();
        fs::create_dir(dir.join("metrics.jsonl")).unwrap();
        let error = guard.shutdown().unwrap_err();
        assert_eq!(
            error.signal_kind(Signal::Metrics),
            Some(FlushErrorKind::Failed)
        );
        assert_eq!(error.lost(Signal::Metrics), 0);
        let source = std::error::Error::source(&error).expect("metrics shutdown source");
        assert!(error.to_string().contains(&source.to_string()));
        assert!(
            source.to_string().contains("Failed to shutdown"),
            "{source}"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn metrics_collection_starts_before_logs_flush() {
        if child("metrics_collection_starts_before_logs_flush", "order", &[]).is_some() {
            return;
        }
        let dir = directory("flush-order");
        let guard = Config::new("order").dir(&dir).init().unwrap();
        record(&guard);
        let (release, thread) = block_directory(&dir);
        let (started, observed) = mpsc::channel();
        *guard.losses.metric_export_started.lock().unwrap() = Some(started);
        *guard.losses.before_logs_flush.lock().unwrap() = Some(crate::lifecycle::FlushOrderProbe {
            started: observed,
            release,
        });
        guard.flush().unwrap();
        thread.join().unwrap();
        guard.shutdown().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn explicit_shutdown_returns_failures_without_printing_them() {
        for signal in ["logs", "metrics"] {
            if let Some(output) = child(
                "explicit_shutdown_returns_failures_without_printing_them",
                signal,
                &[],
            ) {
                assert!(
                    output.stderr.is_empty(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            } else {
                let dir = directory("explicit-failed");
                let guard = Config::new("failed").dir(&dir).init().unwrap();
                let signal = if env::var("VIGIL_METRICS_TEST_MODE").unwrap() == "logs" {
                    Signal::Logs
                } else {
                    Signal::Metrics
                };
                guard.losses.outcome(
                    signal,
                    &Err(OTelSdkError::InternalFailure("injected".into())),
                );
                let error = guard.shutdown().unwrap_err();
                assert_eq!(error.signal_kind(signal), Some(FlushErrorKind::Failed));
                fs::remove_dir_all(dir).unwrap();
                return;
            }
        }
    }

    #[test]
    fn flush_returns_losses_without_final_stderr_summary() {
        if let Some(output) = child(
            "flush_returns_losses_without_final_stderr_summary",
            "flush",
            &[],
        ) {
            assert!(
                output.stderr.is_empty(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let dir = directory("flush-silent");
        let guard = Config::new("silent").dir(&dir).init().unwrap();
        guard
            .losses
            .record(crate::lifecycle::QueueSignal::Logs, 2, true);
        guard.losses.metric_data_points(true);
        guard.losses.metric_pending(3, 0);
        let error = guard.flush().unwrap_err();
        assert_eq!(error.kind(), FlushErrorKind::Failed);
        assert_eq!(error.lost(Signal::Logs), 2);
        guard
            .losses
            .reported(crate::lifecycle::QueueSignal::Logs, 2);
        guard.losses.metric_pending(0, 3);
        guard.shutdown().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn short_shutdown_retains_metrics_deadline_after_blocked_export() {
        if child(
            "short_shutdown_retains_metrics_deadline_after_blocked_export",
            "short",
            &[],
        )
        .is_some()
        {
            return;
        }
        let dir = directory("short-shutdown");
        let guard = Config::new("short").dir(&dir).init().unwrap();
        record(&guard);
        let (release, lock_thread) = block_directory(&dir);
        let timeout = Duration::from_millis(100);
        let start = Instant::now();
        let error = guard.shutdown_with_timeout(timeout).unwrap_err();
        let elapsed = start.elapsed();
        release.send(()).unwrap();
        lock_thread.join().unwrap();
        assert!(elapsed < Duration::from_secs(8), "{elapsed:?}");
        assert_eq!(
            error.signal_kind(Signal::Metrics),
            Some(FlushErrorKind::Timeout)
        );
        assert_eq!(
            std::error::Error::source(&error).unwrap().to_string(),
            OTelSdkError::Timeout(timeout).to_string()
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unresolved_directory_warning_covers_logs_and_metrics_once() {
        if let Some(output) = child(
            "unresolved_directory_warning_covers_logs_and_metrics_once",
            "unresolved",
            &[
                ("VIGIL_DIR", ""),
                ("XDG_STATE_HOME", "relative"),
                ("HOME", "relative"),
            ],
        ) {
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(
                stderr
                    .lines()
                    .filter(|line| line.starts_with("vigil:"))
                    .count(),
                1,
                "{stderr}"
            );
            assert!(
                stderr.contains("falling back to stderr for logs; disabling metrics"),
                "{stderr}"
            );
            return;
        }
        let guard = Config::new("unresolved").init().unwrap();
        assert!(guard.dir().is_none());
        assert!(guard.meter_provider().is_none());
        guard.shutdown().unwrap();
    }

    #[test]
    fn signal_switch_environment_and_builder_precedence() {
        for (mode, value, enabled, warning) in [
            ("off", "0", false, false),
            ("on", "1", true, false),
            ("empty", "", true, false),
            ("invalid", "false", true, true),
            ("builder", "0", true, false),
        ] {
            if let Some(output) = child(
                "signal_switch_environment_and_builder_precedence",
                mode,
                &[("VIGIL_METRICS", value)],
            ) {
                assert_eq!(
                    String::from_utf8_lossy(&output.stderr)
                        .matches("invalid VIGIL_METRICS=")
                        .count(),
                    usize::from(warning)
                );
            } else {
                let mode = env::var("VIGIL_METRICS_TEST_MODE").unwrap();
                let dir = directory("switch");
                let mut config = Config::new("switch").dir(&dir);
                if mode == "builder" {
                    config = config.metrics(true);
                }
                let guard = config.init().unwrap();
                let enabled = mode != "off";
                assert_eq!(guard.meter_provider().is_some(), enabled);
                assert_eq!(dir.join("metrics.jsonl").exists(), enabled);
                tracing::info!("logs work");
                guard.shutdown().unwrap();
                assert!(
                    !fs::read_to_string(dir.join("logs.jsonl"))
                        .unwrap()
                        .is_empty()
                );
                fs::remove_dir_all(dir).unwrap();
                return;
            }
            let _ = enabled;
        }
    }

    #[test]
    fn storage_failures_disable_only_the_affected_signal() {
        for signal in ["logs", "metrics"] {
            if let Some(output) = child(
                "storage_failures_disable_only_the_affected_signal",
                signal,
                &[],
            ) {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if signal == "metrics" {
                    assert_eq!(stderr.matches("cannot open metrics storage").count(), 1);
                    assert!(stderr.contains("disabling metrics"));
                }
            } else {
                let signal = env::var("VIGIL_METRICS_TEST_MODE").unwrap();
                let dir = directory("storage-failure");
                fs::create_dir(dir.join(format!("{signal}.jsonl"))).unwrap();
                let guard = Config::new("storage").dir(&dir).init().unwrap();
                if signal == "logs" {
                    record(&guard);
                } else {
                    assert!(guard.meter_provider().is_none());
                }
                tracing::info!("logs still work");
                guard.shutdown().unwrap();
                let other = if signal == "logs" { "metrics" } else { "logs" };
                assert!(
                    !fs::read_to_string(dir.join(format!("{other}.jsonl")))
                        .unwrap()
                        .is_empty()
                );
                fs::remove_dir_all(dir).unwrap();
                return;
            }
        }
    }

    #[test]
    fn vigil_interval_overrides_otel_and_clamps_zero() {
        if child(
            "vigil_interval_overrides_otel_and_clamps_zero",
            "interval",
            &[("OTEL_METRIC_EXPORT_INTERVAL", "1")],
        )
        .is_some()
        {
            return;
        }
        let exporter =
            || crate::metric_export::OtlpJsonMetricExporter::new(crate::sink::MemorySink::new());
        assert!(
            format!("{:?}", metrics_reader(exporter(), Duration::from_secs(60)))
                .contains("interval: 60s")
        );
        assert!(
            format!("{:?}", metrics_reader(exporter(), Duration::ZERO)).contains("interval: 1s")
        );
        assert_eq!(
            Config::new("interval")
                .metrics_interval(Duration::ZERO)
                .metrics_interval,
            Some(Duration::from_secs(1))
        );
    }

    #[test]
    fn sdk_default_cardinality_overflows_without_exemplars() {
        if child(
            "sdk_default_cardinality_overflows_without_exemplars",
            "cardinality",
            &[],
        )
        .is_some()
        {
            return;
        }
        let dir = directory("cardinality");
        let guard = Config::new("cardinality").dir(&dir).init().unwrap();
        let counter = guard
            .meter_provider()
            .unwrap()
            .meter("test")
            .u64_counter("many")
            .build();
        for series in 0..2001 {
            counter.add(1, &[KeyValue::new("series", series)]);
        }
        guard.flush().unwrap();
        guard.shutdown().unwrap();
        for json in points(&dir) {
            let sum = &json["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["sum"];
            assert_eq!(sum["aggregationTemporality"], 2);
            let points = sum["dataPoints"].as_array().unwrap();
            assert_eq!(points.len(), 2001);
            assert!(points.iter().any(|point| {
                point["attributes"].as_array().unwrap().iter().any(|attr| {
                    attr["key"] == "otel.metric.overflow" && attr["value"]["boolValue"] == true
                })
            }));
            for point in points {
                assert!(
                    point
                        .get("exemplars")
                        .is_none_or(|v| v.as_array().unwrap().is_empty())
                );
            }
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn blocked_flush_is_bounded_and_does_not_queue_another_collection() {
        if child(
            "blocked_flush_is_bounded_and_does_not_queue_another_collection",
            "flush",
            &[],
        )
        .is_some()
        {
            return;
        }
        let dir = directory("blocked-flush");
        let guard = Config::new("flush").dir(&dir).init().unwrap();
        record(&guard);
        let (release, thread) = block_directory(&dir);
        let start = Instant::now();
        assert_eq!(guard.flush().unwrap_err().kind(), FlushErrorKind::Timeout);
        assert!(start.elapsed() < Duration::from_secs(6));
        {
            let state = guard.metrics_flushing.state();
            assert_ne!(state.started, state.finished);
        }
        let start = Instant::now();
        assert_eq!(guard.flush().unwrap_err().kind(), FlushErrorKind::Timeout);
        assert!(start.elapsed() < Duration::from_secs(6));
        release.send(()).unwrap();
        thread.join().unwrap();
        guard.shutdown().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn blocked_shutdown_runs_both_providers_concurrently() {
        if let Some(output) = child(
            "blocked_shutdown_runs_both_providers_concurrently",
            "shutdown",
            &[],
        ) {
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(stderr.matches("vigil: log shutdown: Timeout").count(), 1);
            assert_eq!(stderr.matches("vigil: metric shutdown: Timeout").count(), 1);
            return;
        }
        let dir = directory("concurrent-shutdown");
        let guard = Config::new("shutdown").dir(&dir).init().unwrap();
        record(&guard);
        let (release, thread) = block_directory(&dir);
        tracing::info!("block logs too");
        let start = Instant::now();
        let error = guard
            .shutdown_with_timeout(Duration::from_secs(5))
            .unwrap_err();
        let elapsed = start.elapsed();
        release.send(()).unwrap();
        thread.join().unwrap();
        assert_eq!(
            error.signal_kind(Signal::Logs),
            Some(FlushErrorKind::Timeout)
        );
        assert_eq!(
            error.signal_kind(Signal::Metrics),
            Some(FlushErrorKind::Timeout)
        );
        assert!(elapsed < Duration::from_millis(7500), "{elapsed:?}");
        // Detached SDK workers may finish their final append after return.
    }

    fn summary_case(test: &str, mode: &str) {
        if let Some(output) = child(test, mode, &[]) {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let metrics = usize::from(matches!(
                mode,
                "drop-points"
                    | "drop-both"
                    | "explicit-points"
                    | "metric-timeout"
                    | "metric-failed"
            ));
            let logs = usize::from(matches!(mode, "drop-both" | "log-timeout"));
            assert_eq!(
                stderr.matches("vigil: metric shutdown:").count(),
                metrics,
                "{mode}: {stderr}"
            );
            assert_eq!(
                stderr.matches("vigil: log shutdown:").count(),
                logs,
                "{mode}: {stderr}"
            );
            if mode.contains("points") || mode == "drop-both" {
                assert!(stderr.contains("dropped data points: 3"), "{stderr}");
            }
            if mode.contains("timeout") {
                assert!(stderr.contains("Timeout"), "{stderr}");
            }
            if mode == "metric-failed" {
                assert!(stderr.contains("metric shutdown: Failed"));
            }
        } else {
            let mode = env::var("VIGIL_METRICS_TEST_MODE").unwrap();
            let dir = directory("summaries");
            let guard = Config::new("summary").dir(&dir).init().unwrap();
            if mode.contains("points") || mode == "drop-both" {
                guard.losses.metric_data_points(false);
                guard.losses.metric_pending(3, 0);
            }
            if mode == "drop-both" || mode == "explicit-logs" {
                guard
                    .losses
                    .record(crate::lifecycle::QueueSignal::Logs, 2, false);
            }
            if mode == "metric-failed" {
                guard.losses.outcome(
                    Signal::Metrics,
                    &Err(OTelSdkError::InternalFailure("failure".into())),
                );
            }
            if mode.contains("timeout") {
                guard.losses.outcome(
                    if mode == "metric-timeout" {
                        Signal::Metrics
                    } else {
                        Signal::Logs
                    },
                    &Err(OTelSdkError::Timeout(Duration::ZERO)),
                );
            }
            if mode.starts_with("explicit") {
                let error = guard.shutdown().unwrap_err();
                assert_eq!(error.kind(), FlushErrorKind::DataLost);
                assert_eq!(
                    error.lost(Signal::Logs),
                    if mode == "explicit-logs" { 2 } else { 0 }
                );
                assert_eq!(error.lost(Signal::Metrics), 0);
            } else {
                drop(guard);
            }
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn drop_with_only_data_points() {
        summary_case("drop_with_only_data_points", "drop-points");
    }
    #[test]
    fn drop_with_logs_and_data_points() {
        summary_case("drop_with_logs_and_data_points", "drop-both");
    }
    #[test]
    fn explicit_shutdown_with_only_data_points() {
        summary_case("explicit_shutdown_with_only_data_points", "explicit-points");
    }
    #[test]
    fn explicit_shutdown_with_only_logs() {
        summary_case("explicit_shutdown_with_only_logs", "explicit-logs");
    }
    #[test]
    fn clean_period_prints_nothing() {
        summary_case("clean_period_prints_nothing", "clean");
    }
    #[test]
    fn metrics_only_timeout_prints_its_own_kind() {
        summary_case("metrics_only_timeout_prints_its_own_kind", "metric-timeout");
    }
    #[test]
    fn logs_timeout_with_zero_records_still_prints() {
        summary_case("logs_timeout_with_zero_records_still_prints", "log-timeout");
    }
    #[test]
    fn metrics_failed_with_zero_points_still_prints_on_drop() {
        summary_case(
            "metrics_failed_with_zero_points_still_prints_on_drop",
            "metric-failed",
        );
    }

    #[test]
    fn interval_environment_defaults_validation_and_builder_precedence() {
        for (value, expected, invalid) in [
            ("", 60, false),
            ("2", 2, false),
            ("0", 60, true),
            ("1.5", 60, true),
            ("bad", 60, true),
        ] {
            if let Some(output) = child(
                "interval_environment_defaults_validation_and_builder_precedence",
                &expected.to_string(),
                &[("VIGIL_METRICS_INTERVAL", value)],
            ) {
                assert_eq!(
                    String::from_utf8_lossy(&output.stderr)
                        .matches("invalid VIGIL_METRICS_INTERVAL=")
                        .count(),
                    usize::from(invalid)
                );
            } else {
                let expected: u64 = env::var("VIGIL_METRICS_TEST_MODE")
                    .unwrap()
                    .parse()
                    .unwrap();
                assert_eq!(metrics_interval(None), Duration::from_secs(expected));
                assert_eq!(
                    metrics_interval(
                        Config::new("interval")
                            .metrics_interval(Duration::from_secs(3))
                            .metrics_interval
                    ),
                    Duration::from_secs(3)
                );
                return;
            }
        }
    }

    #[test]
    fn sdk_shutdown_timeout_retains_metrics_kind_with_a_longer_caller_budget() {
        if child(
            "sdk_shutdown_timeout_retains_metrics_kind_with_a_longer_caller_budget",
            "sdk-timeout",
            &[],
        )
        .is_some()
        {
            return;
        }
        let dir = directory("sdk-timeout");
        let guard = Config::new("timeout").dir(&dir).init().unwrap();
        record(&guard);
        let (release, thread) = block_directory(&dir);
        let error = guard
            .shutdown_with_timeout(Duration::from_secs(10))
            .unwrap_err();
        release.send(()).unwrap();
        thread.join().unwrap();
        assert_eq!(
            error.signal_kind(Signal::Metrics),
            Some(FlushErrorKind::Timeout)
        );
        assert_eq!(error.signal_kind(Signal::Logs), None);
    }

    #[test]
    fn both_shutdown_spawn_failures_run_inline_and_short_clean_shutdown_is_bounded() {
        if child(
            "both_shutdown_spawn_failures_run_inline_and_short_clean_shutdown_is_bounded",
            "inline",
            &[],
        )
        .is_some()
        {
            return;
        }
        let dir = directory("inline");
        let (_, mut guard) = Config::new("inline").dir(&dir).layer::<Registry>().unwrap();
        record(&guard);
        let metrics = guard.metrics.clone().unwrap();
        let start = Instant::now();
        guard
            .stop_with_builder(
                Duration::from_secs(1),
                std::thread::Builder::new().stack_size(usize::MAX / 2 + 1),
                std::thread::Builder::new().stack_size(usize::MAX / 2 + 1),
                std::thread::Builder::new().stack_size(usize::MAX / 2 + 1),
            )
            .unwrap();
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(guard.metrics.is_none() && guard.provider.is_none());
        assert!(matches!(
            metrics.shutdown(),
            Err(OTelSdkError::AlreadyShutdown)
        ));
        drop(metrics);
        assert!(!points(&dir).is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn first_metrics_failure_during_shutdown_suppresses_runtime_warning() {
        if let Some(output) = child(
            "first_metrics_failure_during_shutdown_suppresses_runtime_warning",
            "shutdown-failure",
            &[],
        ) {
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(!stderr.contains("runtime metric export"), "{stderr}");
            assert_eq!(
                stderr
                    .matches("metric shutdown: Failed; dropped data points: 1")
                    .count(),
                1
            );
            return;
        }
        let dir = directory("first-shutdown-failure");
        let guard = Config::new("failure").dir(&dir).init().unwrap();
        record(&guard);
        fs::remove_file(dir.join("metrics.jsonl")).unwrap();
        fs::create_dir(dir.join("metrics.jsonl")).unwrap();
        assert_eq!(guard.shutdown().unwrap_err().kind(), FlushErrorKind::Failed);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn exporter_data_point_drop_reaches_the_guards_shared_loss_period() {
        if child(
            "exporter_data_point_drop_reaches_the_guards_shared_loss_period",
            "point-drop",
            &[],
        )
        .is_some()
        {
            return;
        }
        let dir = directory("point-drop");
        let guard = Config::new("drop").dir(&dir).init().unwrap();
        let counter = guard
            .meter_provider()
            .unwrap()
            .meter("test")
            .u64_counter("oversize")
            .build();
        counter.add(1, &[KeyValue::new("identity", "x".repeat(1_100_000))]);
        let error = guard.flush().unwrap_err();
        assert_eq!(error.kind(), FlushErrorKind::DataLost);
        assert_eq!(error.lost(Signal::Metrics), 0);
        assert_eq!(error.lost(Signal::Logs), 0);
        assert!(points(&dir).is_empty());
        assert_eq!(
            guard.shutdown().unwrap_err().kind(),
            FlushErrorKind::DataLost
        );
        fs::remove_dir_all(dir).unwrap();
    }

    fn wait_for_registrations(guard: &Guard, count: usize) {
        let mut state = guard.metrics_flushing.state();
        let deadline = Instant::now() + Duration::from_secs(3);
        while state.waiters.values().sum::<usize>() < count {
            assert!(
                Instant::now() < deadline,
                "only {:?} registered",
                state.waiters
            );
            state = guard
                .metrics_flushing
                .changed
                .wait_timeout(state, deadline.saturating_duration_since(Instant::now()))
                .unwrap()
                .0;
        }
    }

    #[test]
    fn concurrent_flush_collects_measurements_after_the_first_collection_started() {
        if child(
            "concurrent_flush_collects_measurements_after_the_first_collection_started",
            "generation",
            &[],
        )
        .is_some()
        {
            return;
        }
        let dir = directory("generations");
        let guard = Config::new("generations")
            .dir(&dir)
            .metrics_interval(Duration::from_secs(3600))
            .init()
            .unwrap();
        record(&guard);
        let (started, observed) = mpsc::channel();
        *guard.losses.metric_export_started.lock().unwrap() = Some(started);
        let (release, thread) = block_directory(&dir);
        std::thread::scope(|scope| {
            let a = scope.spawn(|| guard.flush());
            observed.recv_timeout(Duration::from_secs(2)).unwrap();
            // A has collected its snapshot and is blocked writing it.
            record(&guard);
            let b = scope.spawn(|| guard.flush());
            wait_for_registrations(&guard, 2);
            release.send(()).unwrap();
            a.join().unwrap().unwrap();
            b.join().unwrap().unwrap();
        });
        thread.join().unwrap();
        let lines = points(&dir);
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines.last().unwrap()["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["sum"]["dataPoints"]
                [0]["asInt"],
            14
        );
        guard.shutdown().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    fn timed_out_generations(test: &str, count: usize) {
        if child(test, "waiters", &[]).is_some() {
            return;
        }
        let dir = directory("timed-out-generations");
        let guard = Config::new("waiters")
            .dir(&dir)
            .metrics_interval(Duration::from_secs(3600))
            .init()
            .unwrap();
        record(&guard);
        let (started, observed) = mpsc::channel();
        *guard.losses.metric_export_started.lock().unwrap() = Some(started);
        let (release, thread) = block_directory(&dir);
        let start = Instant::now();
        std::thread::scope(|scope| {
            let a = scope.spawn(|| guard.flush());
            observed.recv_timeout(Duration::from_secs(2)).unwrap();
            let others: Vec<_> = (1..count).map(|_| scope.spawn(|| guard.flush())).collect();
            wait_for_registrations(&guard, count);
            {
                let state = guard.metrics_flushing.state();
                assert_eq!(state.calls, 1);
                assert_eq!(state.threads, 1);
            }
            assert!(a.join().unwrap().is_err());
            for other in others {
                assert!(other.join().unwrap().is_err());
            }
        });
        assert!(start.elapsed() < Duration::from_secs(6));
        {
            let state = guard.metrics_flushing.state();
            assert!(state.waiters.is_empty());
            assert_eq!(state.calls, 1);
        }
        release.send(()).unwrap();
        thread.join().unwrap();
        let mut state = guard.metrics_flushing.state();
        let deadline = Instant::now() + Duration::from_secs(2);
        while state.finished < state.started {
            assert!(Instant::now() < deadline);
            state = guard
                .metrics_flushing
                .changed
                .wait_timeout(state, deadline.saturating_duration_since(Instant::now()))
                .unwrap()
                .0;
        }
        assert_eq!(state.calls, 1, "no orphan successor collection");
        assert_eq!(state.threads, 1);
        drop(state);
        guard.shutdown().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn shutdown_prevents_registered_successor_collection_and_worker() {
        if child(
            "shutdown_prevents_registered_successor_collection_and_worker",
            "stopped",
            &[],
        )
        .is_some()
        {
            return;
        }
        let dir = directory("stopped-successor");
        let guard = Config::new("stopped")
            .dir(&dir)
            .metrics_interval(Duration::from_secs(3600))
            .init()
            .unwrap();
        record(&guard);
        let (release, thread) = block_directory(&dir);
        let (started, observed) = mpsc::channel();
        *guard.losses.metric_export_started.lock().unwrap() = Some(started);
        let flushing = guard.metrics_flushing.clone();
        let first = guard.start_metrics_flush().unwrap();
        observed.recv_timeout(Duration::from_secs(3)).unwrap();
        let successor = guard.start_metrics_flush().unwrap();
        assert_eq!(successor, first + 1);
        assert_eq!(
            guard
                .shutdown_with_timeout(Duration::from_millis(100))
                .unwrap_err()
                .signal_kind(Signal::Metrics),
            Some(FlushErrorKind::Timeout)
        );
        release.send(()).unwrap();
        thread.join().unwrap();
        flushing
            .wait(first, Instant::now() + Duration::from_secs(3))
            .unwrap();
        {
            let state = flushing.state();
            assert_eq!(state.started, first, "no successor after shutdown begins");
            assert_eq!(state.calls, 1, "no new force_flush after shutdown begins");
            assert_eq!(state.threads, 1, "no new worker after shutdown begins");
        }
        assert!(flushing.wait(successor, Instant::now()).is_err());
    }

    #[test]
    fn metrics_wait_uses_remaining_budget_after_blocked_logs_flush() {
        if child(
            "metrics_wait_uses_remaining_budget_after_blocked_logs_flush",
            "budget",
            &[],
        )
        .is_some()
        {
            return;
        }
        let dir = directory("remaining-budget");
        let guard = Config::new("budget")
            .dir(&dir)
            .metrics_interval(Duration::from_secs(3600))
            .init()
            .unwrap();
        record(&guard);
        let (release, thread) = block_directory(&dir);
        tracing::info!("block logs flush too");
        let start = Instant::now();
        let error = guard.flush().unwrap_err();
        let elapsed = start.elapsed();
        release.send(()).unwrap();
        thread.join().unwrap();
        assert_eq!(
            error.signal_kind(Signal::Logs),
            Some(FlushErrorKind::Timeout)
        );
        assert_eq!(
            error.signal_kind(Signal::Metrics),
            Some(FlushErrorKind::Timeout)
        );
        assert!(elapsed < Duration::from_secs(8), "{elapsed:?}");
        guard.shutdown().unwrap();
    }

    #[test]
    fn two_timed_out_flushes_leave_no_orphan_collection() {
        timed_out_generations("two_timed_out_flushes_leave_no_orphan_collection", 2);
    }
    #[test]
    fn hundred_concurrent_flushes_use_one_detached_worker() {
        timed_out_generations("hundred_concurrent_flushes_use_one_detached_worker", 100);
    }

    #[test]
    fn real_export_failure_is_returned_and_shutdown_suppresses_runtime_summary() {
        if let Some(output) = child(
            "real_export_failure_is_returned_and_shutdown_suppresses_runtime_summary",
            "failure",
            &[],
        ) {
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(stderr.matches("runtime metric export failed").count(), 1);
            assert_eq!(stderr.matches("runtime metric export losses").count(), 0);
            assert_eq!(
                stderr
                    .matches("metric shutdown: Failed; dropped data points: 1")
                    .count(),
                1
            );
            assert!(!stderr.contains("log shutdown"));
            return;
        }
        let dir = directory("export-failure");
        let guard = Config::new("failure").dir(&dir).init().unwrap();
        record(&guard);
        fs::remove_file(dir.join("metrics.jsonl")).unwrap();
        fs::create_dir(dir.join("metrics.jsonl")).unwrap();
        let error = guard.flush().unwrap_err();
        assert_eq!(error.kind(), FlushErrorKind::Failed);
        assert_eq!(error.signal_kind(Signal::Logs), None);
        assert_eq!(
            error.signal_kind(Signal::Metrics),
            Some(FlushErrorKind::Failed)
        );
        assert_eq!(guard.shutdown().unwrap_err().kind(), FlushErrorKind::Failed);
        fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(all(test, feature = "metrics"))]
mod metrics_rotation_tests {
    use super::*;
    use crate::sink::LineSink as _;
    use opentelemetry::metrics::MeterProvider as _;
    use std::fs;

    #[test]
    fn rotation_and_retention_are_per_signal() {
        if !crate::subscriber_test_child(
            "init::metrics_rotation_tests::rotation_and_retention_are_per_signal",
        ) {
            return;
        }
        let dir = env::temp_dir().join(format!("vigil-metrics-rotation-{}", std::process::id()));
        let guard = Config::new("rotation")
            .dir(&dir)
            .max_bytes(1)
            .retention(None)
            .init()
            .unwrap();
        let counter = guard
            .meter_provider()
            .unwrap()
            .meter("rotation")
            .u64_counter("requests")
            .build();
        for _ in 0..2 {
            counter.add(1, &[]);
            tracing::info!("rotating log");
            guard.flush().unwrap();
        }
        guard.shutdown().unwrap();
        let logs = crate::rotate::segments(&dir, "logs").unwrap();
        let metrics = crate::rotate::segments(&dir, "metrics").unwrap();
        assert_eq!(logs.len(), 2);
        assert_eq!(metrics.len(), 3);
        for path in logs.iter().chain(&metrics) {
            assert_eq!(fs::read_to_string(path).unwrap().lines().count(), 1);
        }
        // Pruning a signal cannot remove another signal's rotated segments.
        for path in logs.iter().take(1).chain(metrics.iter().take(2)) {
            fs::File::open(path)
                .unwrap()
                .set_times(fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH))
                .unwrap();
        }
        let config = RotationConfig::default()
            .max_bytes(1)
            .retention(Some(Duration::ZERO));
        let logs_writer = RotatingFile::open(&dir, "logs", config.clone()).unwrap();
        logs_writer.write_line(b"one").unwrap();
        assert_eq!(crate::rotate::segments(&dir, "logs").unwrap().len(), 1);
        assert_eq!(crate::rotate::segments(&dir, "metrics").unwrap().len(), 3);
        let metrics_writer = RotatingFile::open(&dir, "metrics", config).unwrap();
        assert_eq!(crate::rotate::segments(&dir, "metrics").unwrap().len(), 1);
        assert!(logs_writer.shares_lock(&metrics_writer));
        drop((logs_writer, metrics_writer));
        fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(all(test, feature = "metrics"))]
mod facade_publication_tests {
    use super::*;
    use crate::metrics::Counter;

    #[test]
    fn pending_reservation_and_failed_install_do_not_publish_or_consume_records() {
        if !crate::subscriber_test_child(
            "init::facade_publication_tests::pending_reservation_and_failed_install_do_not_publish_or_consume_records",
        ) {
            return;
        }
        let dir = env::temp_dir().join(format!("vigil-facade-pending-{}", std::process::id()));
        static C: Counter = Counter::new(crate::scope!(), "pending");
        C.add(1, &[]);
        let error = Config::new("pending")
            .dir(&dir)
            .init_with(|_| {
                assert!(published_pipeline().is_none());
                C.add(1, &[]);
                assert_eq!(
                    Config::new("second")
                        .layer::<Registry>()
                        .err()
                        .unwrap()
                        .kind(),
                    InitErrorKind::AlreadyRunning
                );
                // Force the global installation failure after providers have been built.
                tracing::subscriber::set_global_default(tracing_subscriber::registry()).unwrap();
            })
            .unwrap_err();
        assert_eq!(error.kind(), InitErrorKind::ForeignSubscriber);
        assert!(published_pipeline().is_none());
        let (_, guard) = Config::new("retry").dir(&dir).layer::<Registry>().unwrap();
        C.add(7, &[]);
        assert_eq!(guard.flush().unwrap_err().lost(Signal::Metrics), 2);
        guard.shutdown().unwrap();
        let text = std::fs::read_to_string(dir.join("metrics.jsonl")).unwrap();
        let json: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(
            json["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["sum"]["dataPoints"][0]["asInt"],
            7
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(all(test, feature = "traces"))]
mod traces_wiring_tests {
    use super::*;
    use opentelemetry::trace::{TraceContextExt as _, Tracer as _};
    use serde_json::Value;
    use std::fs;

    fn child(name: &str, env: &[(&str, &str)]) -> Option<std::process::Output> {
        crate::test_child_with_env(
            &format!("init::traces_wiring_tests::{name}"),
            "VIGIL_TRACES_WIRING_CHILD",
            env,
        )
    }
    fn records(dir: &Path, signal: &str, item: &str) -> Vec<Value> {
        fs::read_to_string(dir.join(format!("{signal}.jsonl")))
            .unwrap()
            .lines()
            .flat_map(|line| {
                let value: Value = serde_json::from_str(line).unwrap();
                value[format!("resource{item}")]
                    .as_array()
                    .unwrap()
                    .iter()
                    .flat_map(|resource| {
                        resource[format!("scope{item}")]
                            .as_array()
                            .unwrap()
                            .iter()
                            .flat_map(|scope| {
                                scope[if signal == "logs" {
                                    "logRecords"
                                } else {
                                    "spans"
                                }]
                                .as_array()
                                .unwrap()
                                .clone()
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }
    fn correlation(layer: bool) {
        let dir = crate::test_temp::TempDir::new();
        let config = Config::new("correlation")
            .dir(&dir.0)
            .filter_env("VIGIL_TEST_UNUSED_FILTER");
        let guard = if layer {
            let (layer, guard) = config.layer::<Registry>().unwrap();
            tracing::subscriber::set_global_default(tracing_subscriber::registry().with(layer))
                .unwrap();
            guard
        } else {
            config.init().unwrap()
        };
        tracing::debug_span!("excluded").in_scope(|| tracing::debug!("excluded event"));
        let span = tracing::info_span!("included");
        span.in_scope(|| {
            tracing::info!("ordinary");
            tracing::error!("failure");
        });
        tracing::info!(parent: &span, "explicit parent");
        drop(span);
        drop(opentelemetry::global::tracer("x").start("global-absent"));
        guard.shutdown().unwrap();
        let spans = records(&dir.0, "traces", "Spans");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0]["name"], "included");
        assert_eq!(spans[0]["status"]["code"], 2);
        assert_eq!(spans[0]["droppedEventsCount"], 1);
        assert!(spans[0]["events"].as_array().unwrap().is_empty());
        let logs = records(&dir.0, "logs", "Logs");
        assert_eq!(logs.len(), 3);
        for log in &logs[..2] {
            assert!(!log["traceId"].as_str().unwrap().is_empty());
            assert_eq!(log["traceId"], spans[0]["traceId"]);
            assert_eq!(log["spanId"], spans[0]["spanId"]);
        }
        assert_eq!(logs[2]["traceId"], "");
        assert_eq!(logs[2]["spanId"], "");
        assert_eq!(
            fs::read_dir(&dir.0).unwrap().count(),
            2 + usize::from(cfg!(feature = "metrics"))
        );
    }
    #[test]
    fn init_correlates_and_deduplicates() {
        if child("init_correlates_and_deduplicates", &[]).is_some() {
            return;
        }
        correlation(false);
    }
    #[test]
    fn consumer_layer_correlates_and_deduplicates() {
        if child("consumer_layer_correlates_and_deduplicates", &[]).is_some() {
            return;
        }
        correlation(true);
    }
    fn disabled(builder: Option<bool>, expected: bool) {
        let dir = crate::test_temp::TempDir::new();
        let mut config = Config::new("switch").dir(&dir.0);
        if let Some(value) = builder {
            config = config.traces(value);
        }
        let guard = config.init().unwrap();
        assert_eq!(guard.traces.is_some(), expected);
        assert_eq!(guard.trace_storage.is_some(), expected);
        assert_eq!(guard.signal_files[2].upgrade().is_some(), expected);
        tracing::info_span!("switch").in_scope(|| {
            assert_eq!(
                opentelemetry::Context::current()
                    .span()
                    .span_context()
                    .is_valid(),
                expected
            );
        });
        guard.flush().unwrap();
        drop(guard);
        assert_eq!(dir.0.join("traces.jsonl").exists(), expected);
    }
    #[test]
    fn builder_disables_every_trace_component() {
        if let Some(output) = child(
            "builder_disables_every_trace_component",
            &[("VIGIL_TRACES", "1")],
        ) {
            assert!(output.stderr.is_empty());
            return;
        }
        disabled(Some(false), false);
    }
    #[test]
    fn environment_disables_every_trace_component() {
        if let Some(output) = child(
            "environment_disables_every_trace_component",
            &[("VIGIL_TRACES", "0")],
        ) {
            assert!(output.stderr.is_empty());
            return;
        }
        disabled(None, false);
    }
    #[test]
    fn explicit_builder_wins_over_environment() {
        if child(
            "explicit_builder_wins_over_environment",
            &[("VIGIL_TRACES", "0")],
        )
        .is_some()
        {
            return;
        }
        disabled(Some(true), true);
    }
    #[test]
    fn invalid_switch_warns_once() {
        if let Some(output) = child("invalid_switch_warns_once", &[("VIGIL_TRACES", "x")]) {
            assert_eq!(
                String::from_utf8(output.stderr).unwrap(),
                "vigil: invalid VIGIL_TRACES=\"x\"; expected 0 or 1; using default\n"
            );
            return;
        }
        disabled(None, true);
    }
    #[test]
    fn storage_failure_preserves_context_and_other_signals_without_loss() {
        if let Some(output) = child(
            "storage_failure_preserves_context_and_other_signals_without_loss",
            &[],
        ) {
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert_eq!(stderr.lines().count(), 1);
            assert!(stderr.contains("cannot open traces storage"));
            return;
        }
        let dir = crate::test_temp::TempDir::new();
        fs::create_dir(dir.0.join("traces.jsonl")).unwrap();
        let guard = Config::new("failure").dir(&dir.0).init().unwrap();
        tracing::info_span!("disabled-storage").in_scope(|| {
            assert!(
                opentelemetry::Context::current()
                    .span()
                    .span_context()
                    .is_valid()
            );
            tracing::info!("still logged");
        });
        #[cfg(feature = "metrics")]
        {
            use opentelemetry::metrics::MeterProvider as _;
            guard
                .metrics
                .as_ref()
                .unwrap()
                .meter("test")
                .u64_counter("requests")
                .build()
                .add(1, &[]);
        }
        guard.flush().unwrap();
        guard.shutdown().unwrap();
        assert_eq!(records(&dir.0, "logs", "Logs").len(), 1);
        #[cfg(feature = "metrics")]
        assert!(
            !fs::read_to_string(dir.0.join("metrics.jsonl"))
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn all_levels_produce_zero_stdout_bytes() {
        if let Some(output) = child("all_levels_produce_zero_stdout_bytes", &[]) {
            // The child redirects stdout only around application execution;
            // the shared helper separately verifies libtest ran this test.
            assert!(!String::from_utf8_lossy(&output.stdout).contains("application stdout"));
            return;
        }
        let dir = crate::test_temp::TempDir::new();
        let guard = Config::new("stdout")
            .dir(&dir.0)
            .default_filter("trace")
            .init()
            .unwrap();
        let (reader, writer) = std::io::pipe().unwrap();
        let saved = rustix::io::dup(std::io::stdout()).unwrap();
        rustix::stdio::dup2_stdout(&writer).unwrap();
        tracing::info_span!("stdout").in_scope(|| {
            tracing::trace!("trace");
            tracing::debug!("debug");
            tracing::info!("info");
            tracing::warn!("warn");
            tracing::error!("error");
        });
        guard.shutdown().unwrap();
        rustix::stdio::dup2_stdout(&saved).unwrap();
        drop(writer);
        use std::io::Read as _;
        let mut bytes = Vec::new();
        reader.take(10000).read_to_end(&mut bytes).unwrap();
        assert!(bytes.is_empty(), "application stdout: {bytes:?}");
    }
    #[test]
    fn after_shutdown_warns_once_per_kind() {
        if let Some(output) = child("after_shutdown_warns_once_per_kind", &[]) {
            assert_eq!(
                String::from_utf8(output.stderr).unwrap(),
                "vigil: span after shutdown; further spans will be dropped silently\nvigil: event after shutdown; further events will be dropped silently\n"
            );
            return;
        }
        let dir = crate::test_temp::TempDir::new();
        let guard = Config::new("stopped").dir(&dir.0).init().unwrap();
        guard.shutdown().unwrap();
        for _ in 0..2 {
            tracing::info_span!("late").in_scope(|| tracing::info!("late"));
        }
        assert!(records(&dir.0, "traces", "Spans").is_empty());
    }
    fn summary(name: &str, dropping: bool) {
        if let Some(output) = child(name, &[]) {
            assert_eq!(
                String::from_utf8(output.stderr).unwrap(),
                if dropping {
                    "vigil: span shutdown: DataLost; dropped spans: 3; remaining spans may be lost\n"
                } else {
                    ""
                }
            );
            return;
        }
        let dir = crate::test_temp::TempDir::new();
        let guard = Config::new("summary").dir(&dir.0).init().unwrap();
        guard
            .losses
            .record(crate::lifecycle::QueueSignal::Traces, 3, false);
        if dropping {
            drop(guard);
        } else {
            assert_eq!(guard.shutdown().unwrap_err().lost(Signal::Traces), 3);
        }
    }
    #[test]
    fn drop_reports_unprinted_span_losses() {
        summary("drop_reports_unprinted_span_losses", true);
    }
    #[test]
    fn explicit_shutdown_returns_span_losses_without_printing() {
        summary(
            "explicit_shutdown_returns_span_losses_without_printing",
            false,
        );
    }
    #[test]
    fn flush_returns_span_losses() {
        if child("flush_returns_span_losses", &[]).is_some() {
            return;
        }
        let dir = crate::test_temp::TempDir::new();
        let guard = Config::new("loss").dir(&dir.0).init().unwrap();
        guard
            .losses
            .record(crate::lifecycle::QueueSignal::Traces, 4, true);
        assert_eq!(guard.flush().unwrap_err().lost(Signal::Traces), 4);
        guard.shutdown().unwrap();
    }
    #[test]
    fn directory_lock_child() {
        let Ok(dir) = std::env::var("VIGIL_TRACE_LOCK_DIRECTORY") else {
            return;
        };
        let held = std::fs::File::open(dir).unwrap();
        held.lock().unwrap();
        println!("ready");
        std::io::stdout().flush().unwrap();
        let mut release = String::new();
        std::io::stdin().read_line(&mut release).unwrap();
        assert_eq!(release, "release\n");
        held.unlock().unwrap();
    }
    struct DirectoryBlock(std::process::Child);
    impl DirectoryBlock {
        fn new(dir: &Path) -> Self {
            use std::io::BufRead as _;
            let mut process = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "init::traces_wiring_tests::directory_lock_child",
                    "--nocapture",
                ])
                .env("VIGIL_TRACE_LOCK_DIRECTORY", dir)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let mut ready = String::new();
            let mut output = std::io::BufReader::new(process.stdout.take().unwrap());
            loop {
                ready.clear();
                assert_ne!(output.read_line(&mut ready).unwrap(), 0);
                if ready.ends_with("ready\n") {
                    break;
                }
            }
            process.stdout = Some(output.into_inner());
            Self(process)
        }
    }
    impl Drop for DirectoryBlock {
        fn drop(&mut self) {
            writeln!(self.0.stdin.take().unwrap(), "release").unwrap();
            use std::io::Read as _;
            let mut stdout = Vec::new();
            self.0
                .stdout
                .take()
                .unwrap()
                .read_to_end(&mut stdout)
                .unwrap();
            let output = std::process::Output {
                status: self.0.wait().unwrap(),
                stdout,
                stderr: Vec::new(),
            };
            crate::assert_test_child("init::traces_wiring_tests::directory_lock_child", &output);
        }
    }
    fn blocked_deadline(name: &str, flushing: bool, metrics: bool) {
        if let Some(output) = child(name, &[]) {
            let stderr = String::from_utf8(output.stderr).unwrap();
            if !flushing {
                assert_eq!(stderr.matches("vigil: span shutdown: Timeout; dropped spans: 0; remaining spans may be lost").count(), 1);
            }
            return;
        }
        let dir = crate::test_temp::TempDir::new();
        let config = Config::new("deadline").dir(&dir.0);
        #[cfg(feature = "metrics")]
        let config = config
            .metrics(metrics)
            .metrics_interval(Duration::from_secs(3600));
        let guard = config.init().unwrap();
        #[cfg(feature = "metrics")]
        if metrics {
            use opentelemetry::metrics::MeterProvider as _;
            guard
                .metrics
                .as_ref()
                .unwrap()
                .meter("test")
                .u64_counter("blocked")
                .build()
                .add(1, &[]);
        }
        let block = DirectoryBlock::new(&dir.0);
        drop(tracing::info_span!("blocked"));
        tracing::info!("blocked log");
        let started = Instant::now();
        let mut guard = Some(guard);
        let error = if flushing {
            guard.as_ref().unwrap().flush().unwrap_err()
        } else {
            guard
                .take()
                .unwrap()
                .shutdown_with_timeout(Duration::from_secs(1))
                .unwrap_err()
        };
        let elapsed = started.elapsed();
        drop(block);
        if let Some(guard) = guard {
            guard.shutdown().unwrap();
        }
        assert_eq!(
            error.signal_kind(Signal::Traces),
            Some(FlushErrorKind::Timeout)
        );
        assert_eq!(
            error.signal_kind(Signal::Logs),
            Some(FlushErrorKind::Timeout)
        );
        let bound = if flushing || metrics {
            Duration::from_millis(7500)
        } else {
            Duration::from_secs(2)
        };
        assert!(elapsed < bound, "{elapsed:?}");
    }
    #[test]
    fn flush_runs_logs_and_traces_concurrently() {
        use std::sync::Mutex;
        let logs_thread = Mutex::new(None);
        let traces_thread = Mutex::new(None);
        let (logs, traces) = flush_logs_and_traces(
            || {
                *logs_thread.lock().unwrap() = Some(std::thread::current().id());
                Ok(())
            },
            Some(|| {
                *traces_thread.lock().unwrap() = Some(std::thread::current().id());
                Ok(())
            }),
        );
        logs.unwrap();
        traces.unwrap();
        assert_ne!(
            logs_thread.into_inner().unwrap(),
            traces_thread.into_inner().unwrap()
        );
    }
    #[test]
    fn blocked_flush_keeps_five_second_deadline() {
        blocked_deadline("blocked_flush_keeps_five_second_deadline", true, false);
    }
    #[test]
    fn blocked_shutdown_without_metrics_keeps_short_deadline() {
        blocked_deadline(
            "blocked_shutdown_without_metrics_keeps_short_deadline",
            false,
            false,
        );
    }
    #[cfg(feature = "metrics")]
    #[test]
    fn blocked_shutdown_with_metrics_keeps_sdk_five_second_bound() {
        blocked_deadline(
            "blocked_shutdown_with_metrics_keeps_sdk_five_second_bound",
            false,
            true,
        );
    }
    #[test]
    fn flush_reports_real_export_span_loss() {
        if let Some(output) = child("flush_reports_real_export_span_loss", &[]) {
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert_eq!(stderr.matches("runtime span export failed").count(), 1);
            assert_eq!(stderr.matches("; dropped spans: 1").count(), 1);
            assert!(!stderr.contains("span shutdown"));
            return;
        }
        let dir = crate::test_temp::TempDir::new();
        let guard = Config::new("export-loss").dir(&dir.0).init().unwrap();
        let name = "x".repeat(1_100_000);
        drop(tracing::info_span!("oversized", otel.name = name));
        let error = guard.flush().unwrap_err();
        assert_eq!(error.lost(Signal::Traces), 1);
        assert_eq!(
            error.signal_kind(Signal::Traces),
            Some(FlushErrorKind::Failed)
        );
        assert_eq!(error.lost(Signal::Logs), 0);
        guard.shutdown().unwrap();
    }
    #[test]
    fn trace_shutdown_spawn_failure_runs_inline() {
        if child("trace_shutdown_spawn_failure_runs_inline", &[]).is_some() {
            return;
        }
        let dir = crate::test_temp::TempDir::new();
        let mut guard = Config::new("inline").dir(&dir.0).init().unwrap();
        drop(tracing::info_span!("inline"));
        let retained = guard.traces.clone().unwrap();
        let fail = || std::thread::Builder::new().stack_size(usize::MAX / 2 + 1);
        guard
            .stop_with_builder(Duration::from_secs(1), fail(), fail(), fail())
            .unwrap();
        assert!(matches!(
            retained.shutdown(),
            Err(OTelSdkError::AlreadyShutdown)
        ));
        assert_eq!(records(&dir.0, "traces", "Spans").len(), 1);
    }
}
