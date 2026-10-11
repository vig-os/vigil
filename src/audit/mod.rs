//! Pure audit v1 format primitives (ADR-0005), enabled by `audit`.
//!
//! This layer performs no I/O and makes no durability or authentication claim
//! about supplied identities. The durable trail API follows in #11; offline
//! trail verification follows in #13. Storage must honour flushes. Local keys
//! cannot protect a trail against an attacker who can read keys and rewrite it.
//! These low-level building blocks are provisional until the 1.0 format freeze.

mod format;
mod mmr;
mod signing;
pub use format::{CheckpointFields, Entry, Record, RecordContext, Value};
pub use mmr::Mmr;
pub use signing::{KeySeed, Signer, SignerError, checkpoint_message, verify_signature};

/// Stable categories for fail-closed audit operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditErrorKind {
    /// A storage operation failed.
    Io,
    /// A previous durability failure makes further writes unsafe.
    Poisoned,
    /// Encoded data exceeds a format field or JSON payload limit.
    TooLarge,
    /// An entry contains an empty string or NUL.
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

/// An audit failure with a matchable category and diagnostic context.
#[derive(Debug)]
pub struct AuditError {
    kind: AuditErrorKind,
    detail: String,
}
impl AuditError {
    pub(crate) fn new(kind: AuditErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
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
