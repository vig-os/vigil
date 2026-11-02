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
//! for it. `TrustPolicy` supplies the verifier's trust input; the verifier itself follows in #13.
//!
//! Format primitives require `--cfg vigil_unstable` and are provisional.
//! Applications should pin `=0.N.M` before 1.0; pin `~1.N` from 1.0.
//! Before 1.0 they may change in any release; from 1.0, in any minor.

mod verify;
pub use verify::{Finding, Report, Severity, Verifier, verify};
mod trust;
pub use trust::{TrailTrust, TrustPolicy, TrustPolicyBuilder};
mod attributes;
pub use attributes::{AttrValue, FieldKind};
mod schema;
mod schema_validation;
pub use schema::{ActionFields, RecordSchema, RecordSchemaBuilder};
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

/// Findings produced by the offline verifier (#13), including decoder failures.
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
    /// Error: A record does not link to its predecessor.
    ChainBroken,
    /// Error: A required sequence number is absent.
    SeqGap,
    /// Error: Different records claim the same sequence number.
    SeqConflict,
    /// Error: A record belongs to a trail outside the pinned policy.
    TrailMismatch,
    /// Error: A checkpoint has an incorrect MMR root.
    MmrMismatch,
    /// Error: A checkpoint signature is invalid.
    BadSignature,
    /// Error: A signing key is not trusted for this trail.
    UntrustedKey,
    /// Error: A revoked key conflicts with its trusted bound.
    RevocationMismatch,
    /// Error: A revocation bound lacks confirmation.
    RevocationUnconfirmed,
    /// Error: A segment or run violates the required structure.
    SegmentStructure,
    /// Error: An anchor does not match the verified history.
    AnchorMismatch,
    /// Error: The requested start does not match the history.
    StartMismatch,
    /// Error: An input below the start lacks an anchor.
    UnanchoredStart,
    /// Error: The batch start does not anchor the requested end.
    UnanchoredEnd,
    /// Error: A record violates the trail retirement or batch end bound.
    TrailEnded,
    /// Error: The head exceeds the permitted age.
    StaleHead,
    /// Error: A required receipt is absent.
    NoReceipt,
    /// Error: A receipt conflicts with the history.
    ReceiptMismatch,
    /// Error: The following record does not attest the fragment gap.
    RepairMismatch,
    /// Error: A review does not match its record, gap or run digest.
    AcceptMismatch,
    /// Warning: A fragment gap is trailing or not yet covered by a trusted checkpoint.
    TornWrite,
    /// Warning: An operator resumed the trail after a loss.
    Resumed,
    /// Warning: Record time moved backwards.
    ClockWentBackwards,
    /// Warning: The same record appears more than once.
    DuplicateRecord,
    /// Info: Records follow the last trusted checkpoint.
    UncoveredTail,
    /// Info: An input lies outside anchored verification bounds.
    OutOfRange,
    /// Info: Records follow the reconciled receipts prefix.
    Unreconciled,
    /// Info: An operator waived a receipt or supplied a receipt prefix.
    ReceiptWaived,
    /// Info: A fragment gap is attested and covered.
    TornWriteRepaired,
    /// Info: A reviewer accepted a warning or a run finding.
    Accepted,
    /// Info: A review matched no warning.
    AcceptUnused,
    /// Info: An input names a sequence inside a confirmed resume gap.
    LostRecord,
}

/// An audit failure with a matchable category and diagnostic context.
/// Trust-file read failures retain their underlying `io::Error` as the source.
/// The `Display` text is for people; it is not part of the stability promise. Match on `kind()`.
#[derive(Debug)]
pub struct AuditError {
    kind: AuditErrorKind,
    detail: String,
    finding: Option<FindingKind>,
    // The source is an immutable diagnostic: unwinding cannot interrupt a
    // mutation of AuditError's state. Preserve its existing unwind-safety traits.
    source:
        Option<std::panic::AssertUnwindSafe<Box<dyn std::error::Error + Send + Sync + 'static>>>,
}
impl AuditError {
    pub(crate) fn new(kind: AuditErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
            finding: None,
            source: None,
        }
    }
    pub(crate) fn from_io(source: std::io::Error) -> Self {
        Self {
            source: Some(std::panic::AssertUnwindSafe(Box::new(source))),
            ..Self::new(AuditErrorKind::Io, "cannot read trust file")
        }
    }
    pub(crate) fn decoding(kind: AuditErrorKind, finding: FindingKind) -> Self {
        Self {
            kind,
            finding: Some(finding),
            source: None,
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
impl std::error::Error for AuditError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|source| source.0.as_ref() as _)
    }
}
pub(crate) fn parse_hex<const N: usize>(text: &str) -> Result<[u8; N], AuditError> {
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(AuditError::new(
            AuditErrorKind::InvalidEntry,
            "invalid lowercase hex",
        ));
    }
    let mut bytes = [0; N];
    for (out, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        *out = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(bytes)
}

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

#[cfg(test)]
mod schema_writer_tests;

/// Starts the decision-5 gap digest shared by storage and verifier spans.
pub(crate) fn gap_hasher() -> blake3::Hasher {
    let mut hash = blake3::Hasher::new();
    hash.update(b"vigil.audit.v1.repaired\0");
    hash
}
