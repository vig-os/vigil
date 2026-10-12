use super::{AuditError, AuditErrorKind, Checkpoint, Entry, Record, digest_string, sink};
use std::path::{Path, PathBuf};

/// A durable audit writer, shareable across threads (`Send + Sync`).
///
/// Local keys cannot protect against an attacker who can read those keys and
/// rewrite the trail. Keep receipts and anchors outside the trail directory.
///
/// Durability requires the entire storage stack to honour flushes, including
/// the controller and hypervisor. Regulated use supports ext4 in default
/// `data=ordered` mode and APFS only once crash and power-loss tests establish
/// the prefix property on each (#89 and #46). ext4 `data=writeback` and network
/// filesystems are unsupported; other filesystems need equivalent evidence.
///
/// Dropping a healthy handle attempts a checkpoint, best effort, without
/// panicking. Use [`Self::close`] to obtain a signed clean-stop head.
#[must_use]
pub struct AuditTrail {
    sink: sink::Sink,
    dir: PathBuf,
    mirror: bool,
}
impl std::fmt::Debug for AuditTrail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditTrail")
            .field("dir", &self.dir)
            .field("trail", &self.trail())
            .field("service", &self.sink.service())
            .finish()
    }
}
impl AuditTrail {
    pub(super) fn new(sink: sink::Sink, dir: PathBuf, mirror: bool) -> Self {
        Self { sink, dir, mirror }
    }
    /// Appends and fsyncs the entry before returning its receipt. Store that
    /// receipt with the application's record before completing the action.
    /// This blocks on the directory lock and fsync; there is no queue or timeout.
    ///
    /// To review crash orphans, keep a durable request log fsynced **before**
    /// calling record. A waiver requires the orphan's full hashed content to
    /// equal one outstanding request, used by no other waiver, with a timestamp
    /// between the request and crash. Matching only actor/action/object is
    /// insufficient. The application supplies authenticated actor identities.
    ///
    /// # Errors
    /// Returns entry/size, corruption, poison or storage errors. Do not complete
    /// the audited action on error. A due signer's failure still acknowledges
    /// the durable record and increments [`Receipt::unsigned_records`].
    pub fn record(&self, entry: &Entry) -> Result<Receipt, AuditError> {
        let recorded = self.sink.record(entry)?;
        let receipt = Receipt {
            trail: self.trail(),
            seq: recorded.seq,
            hash: recorded.hash,
            unsigned_records: recorded.unsigned_records,
        };
        if self.mirror {
            tracing::event!(target: "vigil::audit", tracing::Level::INFO,
                action = entry.action.as_str(), object = entry.object.as_str(),
                seq = receipt.seq, hash = receipt.hash_string());
        }
        Ok(receipt)
    }
    /// Writes a checkpoint signed by this handle's signer and fsyncs it.
    ///
    /// # Errors
    /// Returns signer, storage, corruption or poison errors from the sink.
    pub fn checkpoint(&self) -> Result<Checkpoint, AuditError> {
        checkpoint(self.sink.checkpoint()?)
    }
    /// Always writes a checkpoint signed by this handle's signer and returns
    /// it after fsync. Consumes the handle even on error; Drop does not retry.
    /// Shared handles must reach their last reference through `Arc::into_inner`.
    /// Keep this clean-stop head alongside receipts for operator key rotation.
    ///
    /// # Errors
    /// Returns signer, storage, corruption or poison errors. If no checkpoint
    /// is returned, reopen using the highest held receipt as `expect_head` and
    /// close that handle; clear any poison through its documented procedure first.
    pub fn close(self) -> Result<Checkpoint, AuditError> {
        checkpoint(self.sink.close()?)
    }
    /// Returns the configured audit directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }
    /// Returns the trail's random identity, which must be pinned out of band.
    pub fn trail(&self) -> [u8; 16] {
        self.sink.trail()
    }
}
fn checkpoint(record: Record) -> Result<Checkpoint, AuditError> {
    let bytes = sink::line(&record)?;
    let line = std::str::from_utf8(&bytes)
        .map_err(|e| AuditError::new(AuditErrorKind::CorruptTrail, e.to_string()))?;
    Checkpoint::parse(line)
}

/// An application-side anchor for one acknowledged durable record.
/// Store outside the trail directory so rollback can be detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Receipt {
    trail: [u8; 16],
    seq: u64,
    hash: [u8; 32],
    unsigned_records: u64,
}
impl Receipt {
    /// Returns the trail identity by value.
    pub fn trail(&self) -> [u8; 16] {
        self.trail
    }
    /// Returns the acknowledged sequence number.
    pub fn seq(&self) -> u64 {
        self.seq
    }
    /// Returns the acknowledged record hash by value.
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }
    /// Returns `blake3:<64 lowercase hex characters>`.
    pub fn hash_string(&self) -> String {
        digest_string(&self.hash)
    }
    /// Returns this call's snapshot of records acknowledged while signing was
    /// unavailable. The count is per handle and cumulative: it never drops
    /// after the signer recovers. Checkpoint cadence is instead trail-wide.
    pub fn unsigned_records(&self) -> u64 {
        self.unsigned_records
    }
}
