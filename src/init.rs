//! Process-wide tracing initialization.
use std::{
    env, fmt,
    io::Write,
    path::PathBuf,
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
use tracing_subscriber::{EnvFilter, Layer, layer::SubscriberExt, registry::Registry, reload};

use crate::{
    logs::OtlpJsonLogExporter,
    rotate::{RotatingFile, RotationConfig},
};

/// A programming error: invalid service name or an already installed subscriber.
#[derive(Debug)]
pub struct InitError(String);

const MAX_QUEUE_SIZE: usize = 1_048_576;
type LogLayer = Box<dyn Layer<Registry> + Send + Sync>;
type BaseSubscriber = tracing_subscriber::layer::Layered<LogLayer, Registry>;
type DestinationLayer = Box<dyn Layer<BaseSubscriber> + Send + Sync>;
impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for InitError {}

/// Owns the batch processor. Keep this alive until logging is finished.
/// Drop waits up to five seconds, including time blocked on the directory lock.
/// On timeout it warns on stderr; remaining records may be lost. The SDK worker
/// may continue in the background until the lock is released.
#[must_use = "dropping the guard flushes and shuts down logging; bind it: let _guard = vigil::init(..)"]
#[derive(Debug)]
pub struct Guard {
    provider: Option<SdkLoggerProvider>,
    stopped: Arc<AtomicBool>,
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
/// Returns an error for an invalid service name or an existing global subscriber.
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
    retention_days: Option<u64>,
    version: Option<String>,
    revision: Option<String>,
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
            retention_days: None,
            version: None,
            revision: None,
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
    /// Retention in days; zero keeps everything. Overrides `VIGIL_RETENTION_DAYS`.
    #[must_use]
    pub fn retention_days(mut self, days: u64) -> Self {
        self.retention_days = Some(days);
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
    /// Install the global subscriber and start the batch processor.
    ///
    /// # Errors
    /// Returns an error for an invalid service name or existing global subscriber.
    pub fn init(self) -> Result<Guard, InitError> {
        if tracing::dispatcher::has_been_set() {
            return Err(InitError(
                "cannot install global tracing subscriber: already set".into(),
            ));
        }
        if self.service.is_empty()
            || self.service == "."
            || self.service == ".."
            || !self
                .service
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err(InitError(
                "invalid service name: expected ASCII letters, digits, '-', '_' or '.'".into(),
            ));
        }
        // Reserve the global subscriber before storage or provider side effects.
        // The reload handle attaches the destination once storage is ready.
        let filter = match env::var_os("RUST_LOG") {
            None => EnvFilter::new("info"),
            Some(value) => EnvFilter::try_new(value.to_string_lossy()).unwrap_or_else(|error| {
                let _ = writeln!(
                    std::io::stderr(),
                    "vigil: invalid RUST_LOG={value:?}: {error}; using info"
                );
                EnvFilter::new("info")
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
        let (layer, handle) = reload::Layer::new(None::<DestinationLayer>);
        let subscriber = tracing_subscriber::registry().with(diagnostics()).with(
            layer
                .with_filter(shutdown_filter)
                .with_filter(filter)
                .with_filter(tracing_subscriber::filter::filter_fn(|meta| {
                    !meta.target().starts_with("opentelemetry")
                })),
        );
        tracing::subscriber::set_global_default(subscriber)
            .map_err(|e| InitError(format!("cannot install global tracing subscriber: {e}")))?;
        if tracing_log::LogTracer::init().is_err() {
            let _ = writeln!(
                std::io::stderr(),
                "vigil: a `log` logger is already installed; `log` records won't reach vigil"
            );
        }
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
            rotation.max_bytes = bytes;
        }
        if let Some(days) = self
            .retention_days
            .or_else(|| number("VIGIL_RETENTION_DAYS", 0))
        {
            rotation.retention =
                (days != 0).then(|| Duration::from_secs(days.saturating_mul(86_400)));
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
        let file = dir
            .ok_or_else(|| std::io::Error::other(format!("neither XDG_STATE_HOME nor HOME provides an absolute path; rejected XDG_STATE_HOME={:?}, HOME={:?}", env::var_os("XDG_STATE_HOME"), env::var_os("HOME"))))
            .and_then(|dir| RotatingFile::open(&dir, "logs", rotation));
        match file {
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
                let guard = Guard {
                    provider: Some(provider),
                    stopped: stopped.clone(),
                };
                handle
                    .reload(Some(bridge.boxed()))
                    .map_err(|e| InitError(format!("cannot configure tracing subscriber: {e}")))?;
                Ok(guard)
            }
            Err(error) => {
                let fallback = tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stderr)
                    .with_ansi(false)
                    .boxed();
                handle
                    .reload(Some(fallback))
                    .map_err(|e| InitError(format!("cannot configure tracing subscriber: {e}")))?;
                let _ = writeln!(
                    std::io::stderr(),
                    "vigil: cannot open log storage at {path_description}: {error}; falling back to stderr"
                );
                Ok(Guard {
                    provider: None,
                    stopped,
                })
            }
        }
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

fn diagnostics() -> LogLayer {
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
