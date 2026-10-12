//! Audit v1 format primitives and strict OTLP decoding (ADR-0005), enabled by `audit`.
//!
//! Public format primitives perform no I/O and make no durability or authentication
//! claim about supplied identities. The internal reader validates existing storage. The durable trail API follows in #11; offline
//! trail verification follows in #13. Storage must honour flushes. Local keys
//! cannot protect a trail against an attacker who can read keys and rewrite it.
//! These low-level building blocks are provisional until the 1.0 format freeze.

mod format;
mod mmr;
mod signing;
#[allow(dead_code)] // Internal writer; public facade follows in #11 B3.
mod sink;
#[cfg_attr(not(test), allow(dead_code))] // Internal reader; writes follow in #11.
pub(crate) mod storage;
pub use format::{Checkpoint, CheckpointFields, Entry, Record, RecordContext, Value};
pub use mmr::Mmr;
pub use signing::{KeySeed, Signer, SignerError, checkpoint_message, verify_signature};

/// Stable categories for fail-closed audit operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditErrorKind {
    /// A storage operation failed.
    Io,
    /// A previous durability failure makes further writes unsafe.
    ///
    /// To clear `audit.poison`, first restart the machine or unmount and remount
    /// the filesystem to discard the page cache, then run `vigil-audit verify`,
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
    /// The application's expected head is absent or different.
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
    /// Bytes are not one complete JSON value (including blank input).
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
