use super::{
    AuditError, AuditErrorKind, AuditTrail, Checkpoint, Receipt, Signer, sink, storage::Head,
};
use std::{path::PathBuf, sync::Arc, time::Duration};

/// Reviewed audit policy, independent of telemetry and `VIGIL_*` variables.
///
/// Builders defer validation until create, open, rotate, checkpoint or resume. The
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
    /// Sealing checkpoints, signer outages and operator writes may exceed it.
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
    fn validate_operator(&self) -> Result<PathBuf, AuditError> {
        if self.expected.is_some() {
            return Err(AuditError::new(
                AuditErrorKind::InvalidConfig,
                "operator calls take an explicit head; builder expect_head is invalid",
            ));
        }
        self.validate(false)
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
    /// Rotates the signing key under ADR-0005 decision 9, returning the
    /// rotation record's receipt and the new-key checkpoint covering it.
    /// `bound` names a present checkpoint whose key is being revoked; restore
    /// an archived segment first, or choose a bound that remains present.
    /// Actor and reason must be nonempty and contain no NUL.
    ///
    /// `expect_head` must come from the application's newest receipt or an
    /// anchor, never from the disk (one exception: the crash outcome (ii) of
    /// amendment 8, where R's hash is pinned to the held head through `prev_hash`).
    /// The sequence and hash must exactly equal the disk head or nothing is signed.
    /// This call holds one lock and writes one record plus one checkpoint without
    /// sealing; the live file may exceed `max_bytes` by those two lines.
    ///
    /// # Crash recovery
    /// For a call that returned `Io` or never returned, clear poison first.
    /// After the held head H, nothing or a fragment permits the same rotate again.
    /// A complete rotation record R at h+1 must link to H and match this call's
    /// actor, reason, trail object and exact old-key/bound details, with its time
    /// inside the call window. R alone (possibly followed by a fragment) permits
    /// [`Self::checkpoint`] with the new key and R's sequence and hash. This is
    /// amendment 8's sole sanctioned disk read of an expected head. R followed
    /// by a complete new-key checkpoint C at h+2 linking to R needs no write.
    /// Anything else requires restarting decision 9 at verification, without signing.
    ///
    /// In the R cases, waive only R, using the operator's record of exact arguments,
    /// start time and observed ending, and one of these fixed reason forms:
    /// `operator rotate started <UTC>: returned Io: <error>` or
    /// `operator rotate started <UTC>: did not return (<killed|host stopped> at <UTC>)`.
    /// With nothing or a fragment, store the re-run's receipt/checkpoint and waive
    /// nothing. Verification reports `NoReceipt` for R, `TornWrite` for a fragment,
    /// and `UncoveredTail`/`RevocationUnconfirmed` until C exists (amendment 8).
    ///
    /// # Errors
    /// Returns `InvalidConfig` for invalid policy, a builder `expect_head`, a bound
    /// above the expected head, or reuse of the bound's key; `InvalidEntry` for
    /// invalid actor/reason; `HeadMismatch` for a mismatched exact head or bound;
    /// and signer, corruption, poison or storage errors. Refusals never sign on Drop.
    pub fn rotate(
        self,
        signer: Arc<dyn Signer>,
        bound: (u64, [u8; 32]),
        expect_head: (u64, [u8; 32]),
        actor: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<(Receipt, Checkpoint), AuditError> {
        let dir = self.validate_operator()?;
        let expect = Head {
            seq: expect_head.0,
            hash: expect_head.1,
        };
        let op = sink::OperatorOp::Rotate {
            bound: Head {
                seq: bound.0,
                hash: bound.1,
            },
            actor: actor.into(),
            reason: reason.into(),
        };
        op.validate(expect)?;
        let sink = sink::Sink::open(&dir, signer, self.config, None)?;
        let trail = sink.trail();
        let written = sink.operator_write(expect, op)?;
        let record = written.record.ok_or_else(|| {
            AuditError::new(AuditErrorKind::CorruptTrail, "missing rotation record")
        })?;
        let receipt = Receipt {
            trail,
            seq: record.context.seq,
            hash: record.hash(),
            unsigned_records: 0,
        };
        if self.mirror
            && let super::format::Kind::Entry(entry) = &record.kind
        {
            super::trail::mirror(entry, &receipt);
        }
        Ok((receipt, super::trail::checkpoint(written.checkpoint)?))
    }
    /// Writes one operator checkpoint under ADR-0005 decision 9.
    /// `expect_head` must come from the application's newest receipt or an anchor,
    /// never from the disk (one exception: the crash outcome (ii) of amendment 8,
    /// where R's hash is pinned to the held head through `prev_hash`).
    /// The sequence and hash must exactly equal the disk head or nothing is signed.
    /// No sealing or cadence checkpoint occurs.
    ///
    /// For rotation crash outcome (ii), use the new key and the matching rotation
    /// record R's head, following [`Self::rotate`]'s content, time and waiver rules.
    /// If C already follows R (outcome (iii)), write nothing. The rotation's
    /// `Io` or never-returned ending and fixed waiver reason forms are documented
    /// on [`Self::rotate`].
    ///
    /// # Errors
    /// Returns `InvalidConfig` for invalid policy or a builder `expect_head`,
    /// `HeadMismatch` for a different disk head, and signer, corruption, poison
    /// or storage errors. Refusals never sign on Drop.
    pub fn checkpoint(
        self,
        signer: Arc<dyn Signer>,
        expect_head: (u64, [u8; 32]),
    ) -> Result<Checkpoint, AuditError> {
        let dir = self.validate_operator()?;
        let sink = sink::Sink::open(&dir, signer, self.config, None)?;
        let written = sink.operator_write(
            Head {
                seq: expect_head.0,
                hash: expect_head.1,
            },
            sink::OperatorOp::Checkpoint,
        )?;
        super::trail::checkpoint(written.checkpoint)
    }
    /// Resumes structural loss under ADR-0005 decision 8, "An operator decides",
    /// and amendment 9. Restore archived segments before resuming: a genesis
    /// restart cannot retain their MMR link. Amendment 6's base must be a
    /// checkpoint; otherwise restore the archived predecessor first.
    ///
    /// `head` must equal the last complete record found, or `(0, genesis digest)`
    /// if none remains. Headless, empty and rolled-back live files are sealed
    /// unchanged; a deleted live file needs no sealing. `lost_through` is "the
    /// highest `seq` the deployment holds any evidence of outside the trail
    /// directory", including all processes' receipts, close checkpoints and pins.
    /// It must be at least the head and at most `u64::MAX - 2`.
    ///
    /// The opening checkpoint is at `lost_through + 1`; the unsigned resume
    /// entry follows at `lost_through + 2`, with the trail id as object and
    /// `audit.details` exactly `head=<seq>:blake3:<hex> lost_through=<seq> file=<name|->`.
    /// "Both lines go into `.audit-resume.jsonl` in one write and one fsync"
    /// before promotion under one lock. With no predecessor, the shared fold
    /// uses the genesis digest as its single leaf (amendment 9 part 1).
    /// The signer signs the opening and becomes the returned handle's signer,
    /// including its best-effort Drop checkpoint. Store the returned receipt
    /// outside the directory before continuing.
    ///
    /// # Crash recovery
    /// "A `resume` that returned `Io` may still take effect, whatever step failed"
    /// (decision 6, amendment 3 rule 2). Clear poison by restarting the machine
    /// or remounting the filesystem, verifying, then removing `audit.poison`.
    /// After restart, open settles staging; read the resume entry from the trail.
    /// For `Io` or a call that never returned, waive only that entry at
    /// `lost_through + 2`, directly after its opening checkpoint. Its full hashed
    /// content must match the recorded call arguments and its time the call
    /// window (decision 5, amendment 8, rulings B3c-d1/d2). Use the fixed reason
    /// `operator resume started <UTC>: returned Io: <error>` or
    /// `operator resume started <UTC>: did not return (<killed|host stopped> at <UTC>)`.
    /// Review `Resumed` separately; amendment 10's `accept-run` pins the run's
    /// `SegmentStructure` loss ranges and does not imply `accept Resumed`.
    ///
    /// # Errors
    /// Returns `InvalidConfig` for invalid policy, builder `expect_head` or loss
    /// bounds; `InvalidEntry` for empty/NUL actor or reason; `TooLarge` for an
    /// oversized record; `HeadMismatch` for a different found head; `MissingTrail`
    /// for a missing marker (a missing directory is created first); `CorruptTrail`
    /// for a noncanonical marker or rejected predecessor fold; `Poisoned` when
    /// the poison barrier exists; `Signer` for signing failure; and `Io` for
    /// storage failures or an invariant failure after promotion. Refusals create
    /// no handle and therefore never checkpoint on Drop.
    pub fn resume(
        self,
        signer: Arc<dyn Signer>,
        head: (u64, [u8; 32]),
        lost_through: u64,
        actor: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<(AuditTrail, Receipt), AuditError> {
        let dir = self.validate_operator()?;
        if lost_through < head.0 || lost_through > u64::MAX - 2 {
            return Err(AuditError::new(
                AuditErrorKind::InvalidConfig,
                "invalid resume loss bound",
            ));
        }
        let (actor, reason) = (actor.into(), reason.into());
        sink::validate_actor_reason(&actor, &reason)?;
        let (sink, record) = sink::Sink::resume(
            &dir,
            signer,
            self.config,
            Head {
                seq: head.0,
                hash: head.1,
            },
            lost_through,
            actor,
            reason,
        )?;
        let receipt = Receipt {
            trail: record.context.trail,
            seq: record.context.seq,
            hash: record.hash(),
            unsigned_records: 0,
        };
        if self.mirror
            && let super::format::Kind::Entry(entry) = &record.kind
        {
            super::trail::mirror(entry, &receipt);
        }
        Ok((AuditTrail::new(sink, dir, self.mirror), receipt))
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
