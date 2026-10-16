//! Durable, signed audit trails, independent of telemetry (ADR-0005).
//!
//! Call [`AuditConfig::create`] once at deployment, then [`AuditConfig::open`]
//! with the highest held receipt as the expected head. Store receipts outside
//! the trail directory. Operator rotation and checkpoints require the exact
//! expected head (the highest held receipt or checkpoint). [`AuditConfig::resume`]
//! differs: it takes the exact head found on disk after the loss, or
//! `(0, genesis digest)`, plus `lost_through`, the highest `seq` the deployment
//! holds any evidence of outside the trail directory (all processes' receipts,
//! close checkpoints, anchors and pins). Builder `expect_head` is `InvalidConfig`
//! for it. Offline verification follows in #13.
//!
//! Format primitives require `--cfg vigil_unstable` and are provisional. Pin
//! vigil with `~1.N` when opting in; they may change in a minor release.

mod checkpoints;
mod config;
mod format;
mod lines;
mod mmr;
mod signing;
mod sink;
#[cfg_attr(not(test), allow(dead_code))] // Verifier wiring follows in #13.
pub(crate) mod storage;
mod trail;
pub use checkpoints::checkpoints;
pub use config::AuditConfig;
pub use format::{Checkpoint, Entry, Value};
pub use signing::{KeyFileSigner, Signer, SignerError, keygen};
pub use trail::{AuditTrail, Receipt};

#[cfg(vigil_unstable)]
#[cfg_attr(docsrs, doc(cfg(vigil_unstable)))]
pub use format::{CheckpointFields, Record, RecordContext};
#[cfg(not(vigil_unstable))]
pub(crate) use format::{CheckpointFields, Record, RecordContext};
#[cfg(vigil_unstable)]
#[cfg_attr(docsrs, doc(cfg(vigil_unstable)))]
pub use mmr::Mmr;
#[cfg(not(vigil_unstable))]
pub(crate) use mmr::Mmr;
#[cfg(not(vigil_unstable))]
pub(crate) use signing::checkpoint_message;
#[cfg(all(test, not(vigil_unstable)))]
use signing::verify_signature;
#[cfg(vigil_unstable)]
#[cfg_attr(docsrs, doc(cfg(vigil_unstable)))]
pub use signing::{checkpoint_message, verify_signature};

/// Stable categories for fail-closed audit operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditErrorKind {
    /// A storage operation failed.
    Io,
    /// A previous durability failure makes further writes unsafe.
    ///
    /// To clear `audit.poison`, first restart the machine or unmount and remount
    /// the filesystem to discard the page cache, then verify the trail offline (the `vigil-audit verify` command, #13),
    /// and only after verification passes remove `audit.poison`. Leave staging
    /// files for normal settlement. The poison file is not fsynced: a power loss
    /// may drop it, silently skipping verification and removal after restart;
    /// running verification anyway is recommended. A poisoned handle must be
    /// reopened, using the highest held receipt as its expected head.
    Poisoned,
    /// Encoded data exceeds a format field or JSON payload limit.
    TooLarge,
    /// An entry contains invalid text or a reserved action.
    InvalidEntry,
    /// Existing trail bytes violate the format or chain.
    CorruptTrail,
    /// The application's expected head is absent or different. Operator rotate
    /// and checkpoint require the expected head to equal the head on disk,
    /// matching both sequence and hash; resume returns it when the given head
    /// differs from the head found on disk.
    HeadMismatch,
    /// The trail marker is missing.
    MissingTrail,
    /// Creating a trail would overwrite existing audit data.
    TrailExists,
    /// A signer or key failed.
    Signer,
    /// Configuration or supplied format state is invalid.
    InvalidConfig,
}

/// Decoder findings shared with the ADR-0005 verifier (#13).
/// These describe individual lines, not signature trust or trail history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FindingKind {
    /// Payload does not decode to a JSON object, including raw controls,
    /// oversized payloads, invalid JSON, non-objects and blank input.
    Unparsable,
    /// The declared audit version is unsupported.
    UnknownVersion,
    /// A message or record contains a field outside the v1 allowlist.
    UnknownField,
    /// A required field is absent.
    MissingField,
    /// A field is ambiguous, wrongly typed or outside its allowed values.
    InvalidField,
    /// The declared record hash differs from the canonical hash.
    HashMismatch,
}

/// An audit failure with a matchable category and diagnostic context.
/// The `Display` text is for people; it is not part of the stability promise. Match on `kind()`.
#[derive(Debug)]
pub struct AuditError {
    kind: AuditErrorKind,
    detail: String,
    finding: Option<FindingKind>,
}
impl AuditError {
    pub(crate) fn new(kind: AuditErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
            finding: None,
        }
    }
    pub(crate) fn decoding(kind: AuditErrorKind, finding: FindingKind) -> Self {
        Self {
            kind,
            finding: Some(finding),
            detail: format!("{finding:?}: invalid audit v1 OTLP line"),
        }
    }
    /// Returns the decoder's verifier finding, when this is a parsing failure.
    /// Writers may continue to handle these as CorruptTrail; size violations
    /// use TooLarge. Storage, signing and configuration errors return None.
    pub fn finding_kind(&self) -> Option<FindingKind> {
        self.finding
    }
    /// Returns the category without exposing dependency types.
    pub fn kind(&self) -> AuditErrorKind {
        self.kind
    }
}
impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.detail)
    }
}
impl std::error::Error for AuditError {}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}
pub(crate) fn digest_string(bytes: &[u8; 32]) -> String {
    format!("blake3:{}", hex(bytes))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod codec_tests;

#[cfg(test)]
mod trail_tests;
