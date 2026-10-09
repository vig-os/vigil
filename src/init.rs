//! Process-wide tracing initialization.
use std::{env, fmt, io::Write, path::PathBuf, sync::Arc, time::Duration};

use opentelemetry::{InstrumentationScope, KeyValue, logs::LoggerProvider};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_sdk::{
    Resource,
    logs::{BatchConfigBuilder, BatchLogProcessor, SdkLogger, SdkLoggerProvider},
};
use tracing_subscriber::{EnvFilter, Layer, layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    logs::OtlpJsonLogExporter,
    rotate::{RotatingFile, RotationConfig},
};

/// A programming error: invalid service name or an already installed subscriber.
#[derive(Debug)]
pub struct InitError(String);
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
#[derive(Debug)]
pub struct Guard {
    provider: Option<SdkLoggerProvider>,
}
impl Drop for Guard {
    fn drop(&mut self) {
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
/// is needed. I/O failures fall back to stderr with one warning.
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
    /// Minimum 1. Memory is bounded by queue size times record size; overflow
    /// drops records and emits a warning to stderr.
    #[must_use]
    pub fn queue_size(mut self, size: usize) -> Self {
        self.queue_size = Some(size.max(1));
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
        let dir = self
            .dir
            .or_else(|| {
                env::var_os("VIGIL_DIR")
                    .filter(|s| !s.is_empty())
                    .map(PathBuf::from)
            })
            .or_else(|| {
                env::var_os("XDG_STATE_HOME")
                    .filter(|s| std::path::Path::new(s).is_absolute())
                    .map(|s| PathBuf::from(s).join(&self.service))
            })
            .or_else(|| {
                env::var_os("HOME")
                    .filter(|s| !s.is_empty())
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
            .or_else(|| number("VIGIL_QUEUE_SIZE", 1).and_then(|n| usize::try_from(n).ok()))
            .unwrap_or(65_536);
        let path_description = dir.as_ref().map_or_else(
            || "<unresolved state directory>".into(),
            |p| p.display().to_string(),
        );
        let file = dir
            .ok_or_else(|| std::io::Error::other("neither XDG_STATE_HOME nor HOME is set"))
            .and_then(|dir| RotatingFile::open(&dir, "logs", rotation));
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        let diagnostics = tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::filter_fn(|meta| {
                meta.target().starts_with("opentelemetry") && *meta.level() <= tracing::Level::WARN
            }));
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
                if let Some(revision) = self
                    .revision
                    .or_else(|| env::var("VIGIL_VCS_REVISION").ok())
                {
                    attrs.push(KeyValue::new("vcs.ref.head.revision", revision));
                }
                let provider = SdkLoggerProvider::builder()
                    .with_resource(Resource::builder_empty().with_attributes(attrs).build())
                    .with_log_processor(
                        BatchLogProcessor::builder(OtlpJsonLogExporter::new(Arc::new(file)))
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
                let bridge = OpenTelemetryTracingBridge::new(&NamedProvider(provider.clone()))
                    .with_filter(tracing_subscriber::filter::filter_fn(|meta| {
                        !meta.target().starts_with("opentelemetry")
                    }));
                let guard = Guard {
                    provider: Some(provider),
                };
                tracing_subscriber::registry()
                    .with(diagnostics)
                    .with(bridge.with_filter(filter))
                    .try_init()
                    .map_err(|e| {
                        InitError(format!("cannot install global tracing subscriber: {e}"))
                    })?;
                Ok(guard)
            }
            Err(error) => {
                tracing_subscriber::registry()
                    .with(diagnostics)
                    .with(
                        tracing_subscriber::fmt::layer()
                            .with_writer(std::io::stderr)
                            .with_ansi(false)
                            .with_filter(filter)
                            .with_filter(tracing_subscriber::filter::filter_fn(|meta| {
                                !meta.target().starts_with("opentelemetry")
                            })),
                    )
                    .try_init()
                    .map_err(|e| {
                        InitError(format!("cannot install global tracing subscriber: {e}"))
                    })?;
                let _ = writeln!(
                    std::io::stderr(),
                    "vigil: cannot open log storage at {path_description}: {error}; falling back to stderr"
                );
                Ok(Guard { provider: None })
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
    let value = env::var_os(key)?;
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
    ["/proc/sys/kernel/hostname", "/etc/hostname"]
        .into_iter()
        .find_map(|p| {
            std::fs::read_to_string(p)
                .ok()
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
        })
        .or_else(|| env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
}
