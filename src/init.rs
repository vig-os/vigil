//! Process-wide tracing initialization.
use std::{
    env,
    error::Error as _,
    fmt,
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
    lifecycle::{AfterShutdown, FlushError, Losses, ReportingProcessor, ShutdownCapture},
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
                    "vigil pipeline already initialized in this process",
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
    losses: Arc<Losses>,
}
impl Guard {
    /// The actual log directory, or `None` when storage fell back to stderr.
    pub fn dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }
    /// Export queued records without stopping the pipeline, waiting up to five
    /// seconds. For cargo test, share a `static LazyLock<Guard>` per binary;
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
    /// Queue overflow is counted independently of SDK diagnostics and filters.
    /// Concurrent arrivals can make this a lower bound; see [`FlushError::lost`].
    /// More than 64 concurrent requests can saturate the SDK control channel
    /// and return [`crate::FlushErrorKind::Failed`] before the timeout.
    pub fn flush(&self) -> Result<(), FlushError> {
        match &self.provider {
            Some(provider) => self.losses.finish(crate::lifecycle::flush(provider)),
            None => Ok(()),
        }
    }

    /// Flush and stop the pipeline with a five-second timeout. Drop then does
    /// nothing. Stderr fallback succeeds. The process slot remains occupied.
    ///
    /// # Errors
    /// Returns timeout, SDK/sink failure or data loss. See `FlushError::lost`.
    pub fn shutdown(self) -> Result<(), FlushError> {
        self.shutdown_with_timeout(Duration::from_secs(5))
    }

    /// Flush and stop with an explicit timeout. Queued records may be lost
    /// on timeout; the SDK worker may continue until storage unblocks.
    /// If a shutdown thread cannot be created, shutdown runs inline.
    ///
    /// # Errors
    /// Returns timeout, SDK/sink failure or data loss. See `FlushError::lost`.
    pub fn shutdown_with_timeout(mut self, timeout: Duration) -> Result<(), FlushError> {
        self.stop(timeout)
    }

    fn stop(&mut self, timeout: Duration) -> Result<(), FlushError> {
        self.stop_with_builder(timeout, std::thread::Builder::new())
    }
    fn stop_with_builder(
        &mut self,
        timeout: Duration,
        builder: std::thread::Builder,
    ) -> Result<(), FlushError> {
        self.stopped.store(true, Ordering::Release);
        self.losses.shutting_down.store(true, Ordering::Release);
        let Some(provider) = self.provider.take() else {
            return Ok(());
        };
        let capture = || ShutdownCapture {
            forward: tracing::dispatcher::get_default(Clone::clone),
            losses: self.losses.clone(),
        };
        let subscriber = capture();
        let shutdown = || {
            tracing::subscriber::with_default(subscriber, || {
                provider.shutdown_with_timeout(timeout)
            })
        };
        let result = std::thread::scope(|scope| match builder.spawn_scoped(scope, shutdown) {
            Ok(thread) => thread.join().unwrap_or_else(|_| {
                Err(opentelemetry_sdk::error::OTelSdkError::InternalFailure(
                    "log shutdown thread panicked".into(),
                ))
            }),
            Err(_) => tracing::subscriber::with_default(capture(), || {
                provider.shutdown_with_timeout(timeout)
            }),
        });
        self.losses.finish(result)
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        if self.provider.is_none() {
            return;
        }
        let error = self.stop(Duration::from_secs(5)).err();
        let (pending, failed) = self.losses.pending_stderr();
        if pending == 0 && error.as_ref().is_none_or(|e| e.source().is_none()) {
            return;
        }
        use crate::FlushErrorKind::{DataLost, Failed, Timeout};
        let kind = match error.as_ref().map(FlushError::kind) {
            Some(Timeout) => Timeout,
            _ if failed => Failed,
            Some(kind) => kind,
            None => DataLost,
        };
        let _ = writeln!(
            std::io::stderr(),
            "vigil: log shutdown: {kind:?}; dropped records: {pending}; remaining records may be lost"
        );
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
/// Tracing spans alone do not populate OTLP trace/span IDs; distributed trace
/// context integration is planned for the metrics and traces release.
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
        if PIPELINE.load(Ordering::Acquire) {
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
        let losses = Arc::new(Losses::default());
        let stopped = Arc::new(AtomicBool::new(false));
        let active = stopped.clone();
        let shutdown_filter = tracing_subscriber::filter::dynamic_filter_fn(move |_, _| {
            !active.load(Ordering::Acquire)
        });
        let after_shutdown = AfterShutdown {
            stopped: stopped.clone(),
            warned: AtomicBool::new(false),
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
            .and_then(|dir| RotatingFile::open(dir, "logs", rotation))
            .map_err(|error| format!("cannot open log storage at {path_description}: {error}"))
            .and_then(|file| {
                instance_id()
                    .map(|id| (file, id))
                    .map_err(|error| format!("cannot generate service instance id: {error}"))
            });
        let (destination, guard): (PipelineLayer<S>, Guard) = match file {
            Ok((file, id)) => {
                let mut attrs = vec![
                    KeyValue::new("service.name", self.service),
                    KeyValue::new("service.instance.id", id),
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
                    .with_log_processor(ReportingProcessor {
                        losses: losses.clone(),
                        inner: BatchLogProcessor::builder(ReportingExporter {
                            failures: Mutex::new(Failures::default()),
                            losses: losses.clone(),
                            inner: OtlpJsonLogExporter::new(Arc::new(file)),
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
                (
                    bridge.and_then(console).boxed(),
                    Guard {
                        provider: Some(provider),
                        stopped,
                        losses: losses.clone(),
                        dir,
                    },
                )
            }
            Err(error) => {
                let _ = writeln!(std::io::stderr(), "vigil: {error}; falling back to stderr");
                (
                    tracing_subscriber::fmt::layer()
                        .with_writer(std::io::stderr)
                        .with_ansi(std::io::stderr().is_terminal())
                        .boxed(),
                    Guard {
                        provider: None,
                        stopped,
                        losses: losses.clone(),
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
        Ok((
            diagnostics()
                .and_then(after_shutdown)
                .and_then(destination)
                .boxed(),
            guard,
        ))
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
    losses: Arc<Losses>,
}
impl LogExporter for ReportingExporter {
    async fn export(&self, batch: LogBatch<'_>) -> opentelemetry_sdk::error::OTelSdkResult {
        self.losses.reached(batch.iter().count() as u64);
        let result = self.inner.export(batch).await;
        let lost = self.inner.take_dropped_records();
        self.losses.record(lost as u64, result.is_err());
        if lost != 0 {
            let mut failures = self
                .failures
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            failures.dropped = failures.dropped.saturating_add(lost);
            if !self.losses.shutting_down.load(Ordering::Acquire)
                && failures
                    .last_report
                    .is_none_or(|last| last.elapsed() >= Duration::from_secs(60))
            {
                let unreported = failures.dropped.saturating_sub(failures.reported);
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
                self.losses.reported(unreported as u64);
            }
        }
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
            assert_eq!(exporter.losses.pending_stderr(), (count - 1, false));
        }
        exporter
            .shutdown_with_timeout(Duration::from_secs(1))
            .unwrap();
        assert_eq!(exporter.losses.pending_stderr(), (1, false));
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

    #[test]
    fn foreign_subscriber_winning_install_releases_reservation() {
        if !crate::subscriber_test_child(
            "init::install_race_tests::foreign_subscriber_winning_install_releases_reservation",
        ) {
            return;
        }
        let dir = std::env::temp_dir().join(format!("vigil-install-race-{}", std::process::id()));
        let mut provider = None;
        let error = Config::new("race")
            .dir(&dir)
            .init_with(|guard| {
                provider = guard.provider.clone();
                #[cfg(target_os = "linux")]
                {
                    let handles = storage_handles(&dir);
                    assert!(
                        handles.contains(&dir),
                        "test must observe the directory lock handle"
                    );
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
        #[cfg(target_os = "linux")]
        assert!(
            storage_handles(&dir).is_empty(),
            "lost install must close storage handles"
        );
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
            stopped: Arc::new(AtomicBool::new(false)),
            dir: None,
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
        assert!(!stderr.contains("cannot open log storage"), "{stderr}");
        assert!(stderr.contains("entropy fallback is alive"), "{stderr}");
        assert!(std::fs::read(temp.0.join("logs.jsonl")).unwrap().is_empty());
    }
}
