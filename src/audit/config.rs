use super::{AuditError, AuditErrorKind, AuditTrail, Signer, sink, storage::Head};
use std::{path::PathBuf, sync::Arc, time::Duration};

/// Reviewed audit policy, independent of telemetry and `VIGIL_*` variables.
///
/// Builders defer validation until [`Self::create`] or [`Self::open`]. The
/// default directory is `$XDG_STATE_HOME/<service>/audit`, falling back to
/// `$HOME/.local/state/<service>/audit`; relative environment paths are ignored.
#[derive(Debug, Clone)]
#[must_use]
pub struct AuditConfig {
    config: sink::Config,
    dir: Option<PathBuf>,
    mirror: bool,
    expected: Option<Head>,
}
impl AuditConfig {
    /// Sets the service name (ASCII letters, digits, `.`, `_` and `-`, excluding
    /// empty, `.` and `..`; at most 255 bytes), with 50 MiB segments and
    /// 1000-record / 60 s cadence.
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            config: sink::Config {
                service: service.into(),
                ..Default::default()
            },
            dir: None,
            mirror: false,
            expected: None,
        }
    }
    /// Overrides the audit directory itself, rather than the service state directory.
    pub fn dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.dir = Some(dir.into());
        self
    }
    /// Sets the segment size threshold, default 50 MiB. Zero is invalid.
    /// Sealing checkpoints and signer outages may make a segment exceed it.
    pub fn max_bytes(mut self, bytes: u64) -> Self {
        self.config.max_bytes = bytes;
        self
    }
    /// Sets trail-wide checkpoint cadence, default 1000 records. Zero is invalid.
    /// Evaluated at append time against the latest checkpoint on disk.
    pub fn checkpoint_every(mut self, records: u64) -> Self {
        self.config.checkpoint_every = records;
        self
    }
    /// Sets trail-wide checkpoint interval, default 60 s. Zero is invalid.
    /// Evaluated at append time; there is no background thread.
    pub fn checkpoint_interval(mut self, interval: Duration) -> Self {
        self.config.checkpoint_interval = interval;
        self
    }
    /// Enables an INFO event on `vigil::audit` after each durable record and
    /// after releasing the audit lock. Off by default. Only action, object,
    /// sequence and hash are mirrored; filters may discard this telemetry.
    pub fn mirror_to_logs(mut self, on: bool) -> Self {
        self.mirror = on;
        self
    }
    /// Requires the given sequence and hash in the chain when opening.
    /// Use the highest receipt kept outside the audit directory. Invalid on create.
    pub fn expect_head(mut self, seq: u64, hash: [u8; 32]) -> Self {
        self.expected = Some(Head { seq, hash });
        self
    }
    fn validate(&self, create: bool) -> Result<PathBuf, AuditError> {
        let invalid = |text| AuditError::new(AuditErrorKind::InvalidConfig, text);
        if self.config.service.len() > 255 {
            return Err(invalid("service name exceeds 255 bytes".into()));
        }
        crate::init::validate_service(&self.config.service).map_err(|e| invalid(e.to_string()))?;
        if self.config.max_bytes == 0
            || self.config.checkpoint_every == 0
            || self.config.checkpoint_interval.is_zero()
        {
            return Err(invalid(
                "a zero count, interval or size is never a meaningful setting".into(),
            ));
        }
        if create && self.expected.is_some() {
            return Err(invalid("a new trail has no head to expect".into()));
        }
        self.dir
            .clone()
            .or_else(|| {
                crate::init::state_directory(&self.config.service).map(|dir| dir.join("audit"))
            })
            .ok_or_else(|| invalid("missing absolute XDG_STATE_HOME and HOME".into()))
    }
    /// Creates a new trail explicitly and returns its handle. Pin its random
    /// [`AuditTrail::trail`] id outside the audit directory before use.
    ///
    /// A crash or failed fsync after writing the marker but before completing
    /// staging may leave a marker without a trail: open fails `CorruptTrail`,
    /// create fails `TrailExists`. Remove that directory and create again;
    /// pin the newly drawn id. See [`AuditTrail`] for storage requirements.
    ///
    /// # Errors
    /// Returns `InvalidConfig` for invalid service, zero knobs, missing state
    /// variables or `expect_head`; `TrailExists` for existing audit data; and
    /// storage, signer or corruption errors from the durable writer.
    pub fn create(self, signer: Arc<dyn Signer>) -> Result<AuditTrail, AuditError> {
        let dir = self.validate(true)?;
        let sink = sink::Sink::create(&dir, signer, self.config)?;
        Ok(AuditTrail::new(sink, dir, self.mirror))
    }
    /// Opens an existing trail without writing or signing new trail content.
    /// Interrupted staging is settled and the chain is scanned.
    ///
    /// A restarted writer has no memory of the former head: without
    /// [`Self::expect_head`], rollback or rewriting the uncovered tail may go
    /// unnoticed and a later checkpoint may sign it. Regulated deployments
    /// should supply the highest held receipt. Local keys do not protect
    /// against an attacker who can read them and rewrite the trail; keep
    /// receipts and anchors outside the directory. See [`AuditTrail`] for
    /// storage requirements.
    ///
    /// # Errors
    /// Returns `InvalidConfig` for invalid policy or missing state variables,
    /// `MissingTrail` for a missing marker, `HeadMismatch` for a mismatched
    /// expectation, and corruption, poison or storage errors from the sink.
    pub fn open(self, signer: Arc<dyn Signer>) -> Result<AuditTrail, AuditError> {
        let dir = self.validate(false)?;
        let sink = sink::Sink::open(&dir, signer, self.config, self.expected)?;
        Ok(AuditTrail::new(sink, dir, self.mirror))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reviewed_defaults() {
        let config = AuditConfig::new("svc");
        assert_eq!(config.config.max_bytes, 50 * 1024 * 1024);
        assert_eq!(config.config.checkpoint_every, 1000);
        assert_eq!(config.config.checkpoint_interval, Duration::from_secs(60));
        assert!(!config.mirror);
        assert!(config.expected.is_none());
        assert!(config.dir.is_none());
    }
}
