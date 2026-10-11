//! Process-wide tracing initialization.
use std::{
    env, fmt,
    io::{IsTerminal, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use opentelemetry::{InstrumentationScope, KeyValue, logs::LoggerProvider};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
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
    logs::OtlpJsonLogExporter,
    rotate::{RotatingFile, RotationConfig},
};

/// A mistake the caller can correct in code. Environmental failures degrade
/// to stderr. Concrete error sources are not part of the stability promise;
/// downcasting them is unsupported.
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
    /// Another crate installed the global subscriber. Compose with `layer`
    /// into its Registry instead, or remove the other initialization.
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
static PIPELINE: AtomicBool = AtomicBool::new(false);
type PipelineLayer<S> = Box<dyn Layer<S> + Send + Sync + 'static>;

// A failed attempt releases the reservation; successful pipelines retain it
// forever, including after shutdown.
struct Reservation(bool);
impl Reservation {
    fn acquire() -> Result<Self, InitError> {
        PIPELINE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self(true))
            .map_err(|_| {
                InitError::new(
                    InitErrorKind::AlreadyRunning,
                    "vigil pipeline already running; global tracing subscriber remains installed",
                )
            })
    }
    fn commit(mut self) {
        self.0 = false;
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if self.0 {
            PIPELINE.store(false, Ordering::Release);
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

/// Owns the batch processor. Keep this alive until logging is finished.
/// Drop waits up to five seconds, including time blocked on the directory lock.
/// On timeout it warns on stderr; remaining records may be lost. The SDK worker
/// may continue in the background until the lock is released.
#[must_use = "dropping the guard flushes and shuts down logging; bind it: let _guard = vigil::init(..)"]
#[derive(Debug)]
pub struct Guard {
    provider: Option<SdkLoggerProvider>,
    stopped: Arc<AtomicBool>,
    dir: Option<PathBuf>,
}
impl Guard {
    /// The actual log directory, or `None` when storage fell back to stderr.
    pub fn dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(provider) = &self.provider
            && let Err(error) = provider.shutdown_with_timeout(Duration::from_secs(5))
        {
            let _ = writeln!(
                std::io::stderr(),
                "vigil: log shutdown failed: {error}; remaining records may be lost"
            );
        }
    }
}

/// Initialize logs with default configuration. See [`Config`] for overrides.
///
/// `let _ = vigil::init(..)` drops the guard immediately.
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
/// Tracing spans alone do not populate OTLP trace/span IDs; distributed trace
/// context integration is planned for the metrics and traces release.
///
/// # Errors
/// Returns `AlreadyRunning`, `ForeignSubscriber`, `InvalidServiceName`
/// or `InvalidFilter`. Use nextest for one process per test, or share one
/// pipeline per test binary.
pub fn init(service: impl Into<String>) -> Result<Guard, InitError> {
    Config::new(service).init()
}

/// Logging configuration. Explicit builder values win over environment values;
/// environment values win over defaults. Invalid numeric environment values warn on stderr and use defaults. `RUST_LOG` selects levels (default `info`). Storage defaults to
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
        }
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
    ///
    /// # Errors
    /// Returns `AlreadyRunning`, `ForeignSubscriber`, `InvalidServiceName`
    /// or `InvalidFilter`. A failed attempt releases its pipeline reservation.
    pub fn init(self) -> Result<Guard, InitError> {
        self.init_with(|| {})
    }

    fn init_with(self, before_install: impl FnOnce()) -> Result<Guard, InitError> {
        if PIPELINE.load(Ordering::Acquire) {
            return Err(InitError::new(
                InitErrorKind::AlreadyRunning,
                "vigil pipeline already running; global tracing subscriber remains installed",
            ));
        }
        if tracing::dispatcher::has_been_set() {
            return Err(InitError::new(
                InitErrorKind::ForeignSubscriber,
                "cannot install global tracing subscriber: another subscriber is set",
            ));
        }
        let reservation = Reservation::acquire()?;
        let (layer, guard) = self.build_layer::<Registry>()?;
        before_install();
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
        reservation.commit();
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
    /// Includes per-layer filtering, SDK diagnostics, recursion exclusion,
    /// post-shutdown filtering and the optional console. Other layers retain
    /// their own filters. Tests use nextest (one process per test), or share
    /// one pipeline per binary; dropping its guard stops it permanently.
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
        let result = self.build_layer()?;
        reservation.commit();
        Ok(result)
    }

    fn build_layer<S>(self) -> Result<(PipelineLayer<S>, Guard), InitError>
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a> + Send + Sync + 'static,
    {
        if self.service.is_empty()
            || self.service == "."
            || self.service == ".."
            || !self
                .service
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err(InitError::new(
                InitErrorKind::InvalidServiceName,
                "invalid service name: expected ASCII letters, digits, '-', '_' or '.'",
            ));
        }
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
        let stopped = Arc::new(AtomicBool::new(false));
        let warned = AtomicBool::new(false);
        let active = stopped.clone();
        let shutdown_filter = tracing_subscriber::filter::dynamic_filter_fn(move |_, _| {
            if !active.load(Ordering::Acquire) {
                return true;
            }
            if !warned.swap(true, Ordering::Relaxed) {
                let _ = writeln!(
                    std::io::stderr(),
                    "vigil: event after shutdown; further events will be dropped silently"
                );
            }
            false
        });
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
            .or_else(|| {
                env::var_os("XDG_STATE_HOME")
                    .filter(|s| std::path::Path::new(s).is_absolute())
                    .map(|s| PathBuf::from(s).join(&self.service))
            })
            .or_else(|| {
                env::var_os("HOME")
                    .filter(|s| std::path::Path::new(s).is_absolute())
                    .map(|s| PathBuf::from(s).join(".local/state").join(&self.service))
            });
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
        let file = dir.as_ref()
            .ok_or_else(|| std::io::Error::other(format!("neither XDG_STATE_HOME nor HOME provides an absolute path; rejected XDG_STATE_HOME={:?}, HOME={:?}", env::var_os("XDG_STATE_HOME"), env::var_os("HOME"))))
            .and_then(|dir| RotatingFile::open(dir, "logs", rotation));
        let (destination, guard): (PipelineLayer<S>, Guard) = match file {
            Ok(file) => {
                let mut attrs = vec![
                    KeyValue::new("service.name", self.service),
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
                let provider = SdkLoggerProvider::builder()
                    .with_resource(Resource::builder_empty().with_attributes(attrs).build())
                    .with_log_processor(
                        BatchLogProcessor::builder(ReportingExporter {
                            inner: OtlpJsonLogExporter::new(Arc::new(file)),
                            failures: Mutex::new(Failures::default()),
                        })
                        .with_batch_config(
                            BatchConfigBuilder::default()
                                .with_max_queue_size(queue_size)
                                .with_max_export_batch_size(512)
                                .with_scheduled_delay(Duration::from_secs(1))
                                .build(),
                        )
                        .build(),
                    )
                    .build();
                let bridge = OpenTelemetryTracingBridge::new(&NamedProvider(provider.clone()));
                let console = (self.console == Console::Stderr).then(|| {
                    tracing_subscriber::fmt::layer()
                        .with_writer(std::io::stderr)
                        .with_ansi(std::io::stderr().is_terminal())
                });
                (
                    bridge.and_then(console).boxed(),
                    Guard {
                        provider: Some(provider),
                        stopped,
                        dir,
                    },
                )
            }
            Err(error) => {
                let _ = writeln!(
                    std::io::stderr(),
                    "vigil: cannot open log storage at {path_description}: {error}; falling back to stderr"
                );
                (
                    tracing_subscriber::fmt::layer()
                        .with_writer(std::io::stderr)
                        .with_ansi(std::io::stderr().is_terminal())
                        .boxed(),
                    Guard {
                        provider: None,
                        stopped,
                        dir: None,
                    },
                )
            }
        };
        let destination = destination
            .with_filter(shutdown_filter)
            .with_filter(filter)
            .with_filter(tracing_subscriber::filter::filter_fn(|meta| {
                !meta.target().starts_with("opentelemetry")
            }));
        Ok((diagnostics().and_then(destination).boxed(), guard))
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
fn hostname() -> Option<String> {
    let host = rustix::system::uname()
        .nodename()
        .to_string_lossy()
        .into_owned();
    (!host.is_empty()).then_some(host)
}

#[derive(Debug, Default)]
struct Failures {
    dropped: usize,
    reported: usize,
    last_report: Option<Instant>,
}
impl Failures {
    fn report(&mut self) {
        let _ = writeln!(
            std::io::stderr(),
            "vigil: runtime log export losses; dropped records: {}",
            self.dropped
        );
        self.reported = self.dropped;
        self.last_report = Some(Instant::now());
    }
}

// Handle failed batches here so the SDK does not emit an ExportError per batch.
#[derive(Debug)]
struct ReportingExporter {
    inner: OtlpJsonLogExporter<Arc<RotatingFile>>,
    failures: Mutex<Failures>,
}
impl LogExporter for ReportingExporter {
    async fn export(&self, batch: LogBatch<'_>) -> opentelemetry_sdk::error::OTelSdkResult {
        let count = batch.iter().count();
        let result = self.inner.export(batch).await;
        let replaced = self.inner.take_dropped_records();
        let lost = if result.is_err() { count } else { replaced };
        if lost != 0 {
            let mut failures = self
                .failures
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            failures.dropped = failures.dropped.saturating_add(lost);
            if failures
                .last_report
                .is_none_or(|last| last.elapsed() >= Duration::from_secs(60))
            {
                if let Err(error) = result {
                    let _ = writeln!(
                        std::io::stderr(),
                        "vigil: runtime log export failed: {error}; dropped records: {}",
                        failures.dropped
                    );
                    failures.reported = failures.dropped;
                    failures.last_report = Some(Instant::now());
                } else {
                    failures.report();
                }
            }
        }
        Ok(())
    }
    fn set_resource(&mut self, resource: &Resource) {
        self.inner.set_resource(resource);
    }
    fn shutdown_with_timeout(&self, timeout: Duration) -> opentelemetry_sdk::error::OTelSdkResult {
        let mut failures = self
            .failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if failures.dropped != failures.reported {
            failures.report();
        }
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
            inner: OtlpJsonLogExporter::new(Arc::new(
                RotatingFile::open(&dir, "logs", RotationConfig::default()).unwrap(),
            )),
            failures: Mutex::new(Failures::default()),
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
        let mut export = std::pin::pin!(exporter.export(LogBatch::new(&records)));
        assert!(matches!(
            std::future::Future::poll(export.as_mut(), &mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(()))
        ));
        let failures = exporter.failures.lock().unwrap();
        assert_eq!(
            failures.dropped, 1,
            "a stub must enter the same cumulative summary as export failures"
        );
        assert_eq!(failures.reported, 1, "the first loss must be reported");
        drop(failures);
        let mut again = std::pin::pin!(exporter.export(LogBatch::new(&records)));
        assert!(matches!(
            std::future::Future::poll(again.as_mut(), &mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(()))
        ));
        {
            let failures = exporter.failures.lock().unwrap();
            assert_eq!(failures.dropped, 2);
            assert_eq!(failures.reported, 1, "summaries must remain rate limited");
        }
        assert!(
            exporter
                .shutdown_with_timeout(Duration::from_secs(1))
                .is_ok()
        );
        assert_eq!(exporter.failures.lock().unwrap().reported, 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(test)]
mod install_race_tests {
    use super::*;

    #[test]
    fn foreign_subscriber_winning_install_releases_reservation() {
        let dir = std::env::temp_dir().join(format!("vigil-install-race-{}", std::process::id()));
        let error = Config::new("race")
            .dir(&dir)
            .init_with(|| {
                tracing::subscriber::set_global_default(tracing_subscriber::registry()).unwrap();
            })
            .unwrap_err();
        assert_eq!(error.kind(), InitErrorKind::ForeignSubscriber);
        assert!(std::error::Error::source(&error).is_some());
        let (_, guard) = Config::new("retry").dir(&dir).layer::<Registry>().unwrap();
        assert_eq!(guard.dir(), Some(dir.as_path()));
        drop(guard);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
