//! Process-wide tracing initialization.
use std::{env, fmt, path::PathBuf, sync::Arc, time::Duration};

use opentelemetry::KeyValue;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_sdk::{Resource, logs::SdkLoggerProvider};
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
#[derive(Debug)]
pub struct Guard {
    provider: Option<SdkLoggerProvider>,
}
impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(provider) = &self.provider {
            let _ = provider.shutdown();
        }
    }
}

/// Initialize logs with default configuration. See [`Config`] for overrides.
///
/// Keep the returned guard alive: dropping it drains and shuts down the batch
/// processor. Its 2048-record queue can drop records when full. Calling
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
/// environment values win over defaults. Invalid numeric environment values are
/// ignored. `RUST_LOG` selects levels (default `info`). Storage defaults to
/// `$XDG_STATE_HOME/<service>`, then `$HOME/.local/state/<service>`.
#[derive(Debug)]
pub struct Config {
    service: String,
    dir: Option<PathBuf>,
    max_bytes: Option<u64>,
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
    /// Rotation limit in bytes; overrides `VIGIL_MAX_BYTES` (default 50 MiB).
    #[must_use]
    pub fn max_bytes(mut self, bytes: u64) -> Self {
        self.max_bytes = Some(bytes);
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
            .or_else(|| env::var_os("VIGIL_DIR").map(PathBuf::from))
            .or_else(|| {
                env::var_os("XDG_STATE_HOME")
                    .filter(|s| !s.is_empty())
                    .map(|s| PathBuf::from(s).join(&self.service))
            })
            .or_else(|| {
                env::var_os("HOME")
                    .filter(|s| !s.is_empty())
                    .map(|s| PathBuf::from(s).join(".local/state").join(&self.service))
            });
        let mut rotation = RotationConfig::default();
        if let Some(bytes) = self.max_bytes.or_else(|| number("VIGIL_MAX_BYTES")) {
            rotation.max_bytes = bytes;
        }
        if let Some(days) = self
            .retention_days
            .or_else(|| number("VIGIL_RETENTION_DAYS"))
        {
            rotation.retention =
                (days != 0).then(|| Duration::from_secs(days.saturating_mul(86_400)));
        }
        let file = dir
            .ok_or_else(|| std::io::Error::other("neither XDG_STATE_HOME nor HOME is set"))
            .and_then(|dir| RotatingFile::open(&dir, "logs", rotation));
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
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
                    .with_batch_exporter(OtlpJsonLogExporter::new(Arc::new(file)))
                    .build();
                let bridge = OpenTelemetryTracingBridge::new(&provider).with_filter(
                    tracing_subscriber::filter::filter_fn(|meta| {
                        !meta.target().starts_with("opentelemetry")
                    }),
                );
                let guard = Guard {
                    provider: Some(provider),
                };
                tracing_subscriber::registry()
                    .with(filter)
                    .with(bridge)
                    .try_init()
                    .map_err(|e| {
                        InitError(format!("cannot install global tracing subscriber: {e}"))
                    })?;
                Ok(guard)
            }
            Err(error) => {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(
                        tracing_subscriber::fmt::layer()
                            .with_writer(std::io::stderr)
                            .with_ansi(false),
                    )
                    .try_init()
                    .map_err(|e| {
                        InitError(format!("cannot install global tracing subscriber: {e}"))
                    })?;
                eprintln!("vigil: cannot open log storage: {error}; falling back to stderr");
                Ok(Guard { provider: None })
            }
        }
    }
}
fn number(key: &str) -> Option<u64> {
    env::var(key).ok()?.parse().ok()
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
