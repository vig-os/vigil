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
pub(crate) mod runs;
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
pub(crate) use signing::{checkpoint_message, verify_signature};
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
    /// Error: A checkpoint's declared `mmr_size`, root or peaks
    /// differ from the fold of the records present (ADR-0005 decision
    /// 5 rule 2; emitted by the verifier from the shared classifier's
    /// one fold, ruling 13-V4-d10 point 2). Two sources:
    ///
    /// 1. **Rule 2** -- an opening checkpoint or any in-run
    ///    checkpoint before the run's first loss point. Paired with
    ///    a `Violation::CheckpointMmrDiffers` in the classifier (also
    ///    rejected by the reader); any violation empties every run
    ///    (13-V4-d8 point 3).
    /// 2. **Decision 11 `accept-run` item 3** -- an in-run checkpoint
    ///    at or after the first loss point. The reader does not
    ///    compare it (amendment 6 (iii)) so the trail stays valid;
    ///    the verifier still reports it so an `accept-run` line can
    ///    later promote it to `Accepted`. Not a violation; never
    ///    empties the run.
    ///
    /// **Known limits (ruling 13-V4-d10 points 5-6):** openings
    /// present only in a shipped (Collector) copy are not checked at
    /// this head (owner decision 13-V4-d7; spike #224); once a
    /// segment records a violation, the classifier stops checking
    /// the rest of that segment.
    MmrMismatch,
    /// Error: A checkpoint signature does not verify under `verify_strict`
    /// over the 58-byte checkpoint signing message (ADR-0005 decision 8;
    /// ruling 13-V5-d1 point 2). An undecodable public key, a small-order
    /// key and a non-canonical signature are all included. Each distinct
    /// `(seq, hash)` checkpoint is checked once, native or shipped-only,
    /// inside a run or outside one; a byte-identical duplicate yields one
    /// finding at its first occurrence. Detail is `key <64 lowercase hex>`.
    /// Independent of `UntrustedKey`: a checkpoint can carry both.
    BadSignature,
    /// Error: The checkpoint's signing key is not trusted at its `seq` for
    /// the verified trail (ADR-0005 decision 9; ruling 13-V5-d1 point 2).
    /// Two cases, independent of `BadSignature`:
    ///
    /// - the key is not listed for the trail's section of the policy, detail
    ///   `key <64 lowercase hex> not listed for trail <32 hex>`;
    /// - the key is listed with a `through=<n>:<hash>` bound and the
    ///   checkpoint's `seq` exceeds `n`, detail
    ///   `key <64 lowercase hex> bounded through seq <n>`.
    ///
    /// Each distinct `(seq, hash)` checkpoint is checked once. Revocation pin
    /// mismatch and bound confirmation belong to later work.
    UntrustedKey,
    /// Error: A `through=<s>:<h>` revocation bound is not pinned by
    /// the verified set (ADR-0005 decision 9 and amendment 8; rulings
    /// 13-V5-d1 point 4, 13-V5-d3 point 1 and 13-V5-d4). Emitted at
    /// `seq` `s` for each such bound on a key of the verified trail's
    /// section (scope: ruling 13-V5-d3 point 3; one finding per
    /// bound). A bound on key `K` is pinned when exactly one distinct
    /// record exists at `s`, its hash is `h`, it is a checkpoint, and
    /// its `audit.key_id` is `K` (amendment 8: a bound names a
    /// checkpoint `K` itself signed). Byte-identical duplicates count
    /// as one record; a `SeqConflict` fork is not pinned (fail-closed,
    /// same rule as ruling 13-V5-d2).
    ///
    /// Exactly one detail is emitted per bound, chosen by the first
    /// failing condition in this order (ruling 13-V5-d4 point 3):
    ///
    /// 1. `key <64 hex> through=<s>:blake3:<64 hex>: no record at seq <s>`
    /// 2. `…: seq <s> is forked`
    /// 3. `…: record at seq <s> has hash blake3:<64 hex>`
    /// 4. `…: record at seq <s> is not a checkpoint`
    /// 5. `…: record at seq <s> is signed by key <64 hex>`
    ///
    /// Details 1 and 2 carry no location; details 3, 4 and 5 point to
    /// the record's file and line, using the first copy in the
    /// engine's merge order when duplicates are present (ruling
    /// 13-V5-d4 point 4). Independent of `RevocationUnconfirmed`: one
    /// bound can carry both findings; neither suppresses the other.
    RevocationMismatch,
    /// Error: A `through=<s>:<h>` revocation bound is not confirmed
    /// by a trusted checkpoint strictly above `s` signed by another
    /// key (ADR-0005 decision 9; rulings 13-V5-d1 points 3 and 4,
    /// 13-V5-d3 point 2 and 13-V5-d4 points 2 and 5). "Trusted" per
    /// ruling 13-V5-d1 point 3: signature verifies under
    /// `verify_strict` AND the key is trusted at that `seq` for the
    /// verified trail. A shipped-only trusted checkpoint confirms
    /// (ruling 13-V5-d4 point 5). The checkpoint at `s` never
    /// confirms its own bound, whoever signed it (ruling 13-V5-d4
    /// point 2). Emitted at `seq` `s`, located like the pin finding
    /// above (ruling 13-V5-d3 point 2).
    ///
    /// Detail is exactly
    /// `key <64 hex> through=<s>: no trusted checkpoint by another
    /// key above the bound`.
    ///
    /// `end=` interim (ruling 13-V5-d1 point 4): a matching `end=`
    /// will also confirm a bound; until then a retired trail
    /// without a confirming checkpoint reports
    /// `RevocationUnconfirmed` (#13).
    ///
    /// Independent of `RevocationMismatch`: one bound can carry both
    /// findings; neither suppresses the other.
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
    /// Warning: A fragment gap whose attesting record is not a record
    /// of the verified trail, is at a `seq` carrying a `SeqConflict`
    /// (one side of a fork), or has `seq > covered_through`; or a
    /// trailing gap with no attesting record at all. Promotion to
    /// `TornWriteRepaired` requires an attester of the verified trail
    /// whose `seq` has no `SeqConflict` and is at or below
    /// `covered_through` (rulings 13-V5-d1 point 6 and 13-V5-d2).
    /// Detail grammar: either
    /// `lines {first}..={last} ({N} bytes), attested at line {L} seq {S}`
    /// for an attested-but-uncovered gap, or
    /// `trailing gap lines {first}..={last} ({N} bytes), digest {D}`
    /// with an optional `; no crash outcome` suffix for a trailing gap.
    TornWrite,
    /// Warning: An operator resumed the trail after a loss.
    Resumed,
    /// Warning: Record time moved backwards.
    ClockWentBackwards,
    /// Warning: The same record appears more than once.
    DuplicateRecord,
    /// Info: Records follow the last trusted checkpoint (ruling
    /// 13-V5-d1 point 6). Coverage is inclusive: a single
    /// `UncoveredTail` names exactly the records strictly above
    /// `covered_through`, or every record when no checkpoint is
    /// trusted. Detail grammar: `records seq {a}..={last}`, where
    /// `a = covered_through + 1`, or the first verified `seq` when
    /// `covered_through` is `None`. The last record being itself
    /// covered yields no `UncoveredTail`.
    UncoveredTail,
    /// Info: An input lies outside anchored verification bounds.
    OutOfRange,
    /// Info: Records follow the reconciled receipts prefix.
    Unreconciled,
    /// Info: An operator waived a receipt or supplied a receipt prefix.
    ReceiptWaived,
    /// Info: A fragment gap attested by a record of the verified
    /// trail at or below `covered_through`, with no other record at
    /// its `seq` (rulings 13-V5-d1 point 6 and 13-V5-d2). Detail
    /// grammar is the same as `TornWrite`'s attested form:
    /// `lines {first}..={last} ({N} bytes), attested at line {L} seq {S}`.
    /// A fragment is reported by length and digest, never by text. A
    /// native or shipped `audit.repaired` record with no preceding
    /// fragment carries the `fragment not present` detail.
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
    seq: Option<u64>,
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
            seq: None,
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
            seq: None,
            source: None,
            detail: format!("{finding:?}: invalid audit v1 OTLP line"),
        }
    }
    /// Attaches a decoded sequence number so #13 V3 can sort findings in seq order.
    pub(crate) fn with_seq(mut self, seq: u64) -> Self {
        self.seq = Some(seq);
        self
    }
    /// Returns the decoded sequence number when the decoder read it before failing.
    pub(crate) fn seq(&self) -> Option<u64> {
        self.seq
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

/// V4a fixture seam (rulings 13-V4-d3, 13-V4-d4, 13-V4-d5, 13-V4-d6,
/// 13-V4-d8): the A1 / A3 / A8 / A9 layout builders, their helpers
/// and captured run-digest literals, shared by both V4a readers --
/// `runs::classify_v4a_walk` (classify-level pins) and
/// `verify::runs_tests` (V4a verifier rows through `Verifier::verify_*`).
/// Invariant: both readers import the builders and `A*_DIGEST`
/// constants from here, so the pinned digests and layout code live in
/// exactly one place.
#[cfg(test)]
pub(crate) mod runs_v4a_fixtures;

/// Starts the decision-5 gap digest shared by storage and verifier spans.
pub(crate) fn gap_hasher() -> blake3::Hasher {
    let mut hash = blake3::Hasher::new();
    hash.update(b"vigil.audit.v1.repaired\0");
    hash
}
