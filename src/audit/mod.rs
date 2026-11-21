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
    ///
    /// Two detail grammars:
    ///
    /// - The chain-rule form (ruling 13-V6-d6 point 1), emitted by
    ///   the chain loop over the verified set: every record except
    ///   the one at the lowest `seq` is compared with the record at
    ///   the **highest `seq` below it** that is present in the set,
    ///   not only `seq - 1`. When the record's `prev_hash` is not
    ///   among those hashes, the finding is `expected previous
    ///   blake3:<64 hex>[ or blake3:<64 hex>]*, found blake3:<64
    ///   hex>`. Where `seq`s are missing, the `SeqGap` for the
    ///   named range is reported as well. The end record
    ///   (`Verifier::end_before`) is checked by the same rule; its
    ///   finding is unlocated (no file, no line, ruling 13-V6-d4
    ///   point 6).
    /// - The end-specific form, emitted by
    ///   [`Verifier::end_before`](crate::audit::Verifier::end_before)
    ///   per ruling 13-V6-d6 point 3 when the files hold no record
    ///   below `e` and `e > 0`: the end checkpoint is the lowest
    ///   record in the set, so the chain loop does not check it.
    ///   One `ChainBroken` at `e`, unlocated, with the fixed detail
    ///   `end_before seq <e>: no record precedes the end`. At
    ///   `e = 0` nothing is checked. See
    ///   [`end_before`](crate::audit::Verifier::end_before).
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
    /// A matching `end=` whose `seq` is at or above `s` also
    /// confirms the bound, so no `RevocationUnconfirmed` fires there
    /// (ruling 13-V5-d5 point 2.2). A mismatched or absent `end=`
    /// leaves the bound subject to the trusted-checkpoint rule above.
    ///
    /// Independent of `RevocationMismatch`: one bound can carry both
    /// findings; neither suppresses the other.
    RevocationUnconfirmed,
    /// Error: A segment or run violates the required structure.
    SegmentStructure,
    /// Error: An anchor does not match the verified history
    /// (ADR-0005 decision 10; ruling 13-V6-d1 points 1-2, ruling
    /// 13-V6-d4 point 5). The full rule and the four-step detail
    /// precedence for an ordinary anchor are on
    /// [`Verifier::anchor`](crate::audit::Verifier::anchor); each
    /// of those details begins `anchor seq <s> hash blake3:<64
    /// hex>: `. An end-record form with detail exactly `end record
    /// differs from end anchor` is emitted by
    /// [`Verifier::end_before`](crate::audit::Verifier::end_before);
    /// see that method for the rule.
    AnchorMismatch,
    /// Error: The requested start does not match the verified
    /// history (ADR-0005 decision 11 `.start_from`; ruling
    /// 13-V6-d2). The full rule and the seven-step detail
    /// precedence are on
    /// [`Verifier::start_from`](crate::audit::Verifier::start_from);
    /// each detail begins `start seq <s> hash blake3:<64 hex>: `.
    /// Emitted at the start's `seq`, located at the first copy of
    /// the first record (lowest `seq`) in the engine's merge order,
    /// or unlocated when the verified set is empty. The record's
    /// own `BadSignature` and `UntrustedKey` are independent and
    /// still fire as usual.
    StartMismatch,
    /// Error: An input below an **unanchored** accepted start. Detail
    /// grammar, both unlocated:
    /// `anchor seq <a> hash blake3:<64 hex>: below start seq <s>` or
    /// `key <64 hex> through=<b>: below start seq <s>`. See
    /// [`Verifier::start_from`](crate::audit::Verifier::start_from)
    /// for the rule.
    UnanchoredStart,
    /// Error: With
    /// [`Verifier::end_before`](crate::audit::Verifier::end_before)
    /// set and no end anchor supplied, one `UnanchoredEnd` fires
    /// at the end checkpoint's `seq`, unlocated, with detail
    /// exactly `end_before seq <e>: no end anchor` (ADR-0005
    /// decision 11 `.end_before`; ruling 13-V6-d4 point 5). See
    /// [`Verifier::end_before`](crate::audit::Verifier::end_before)
    /// for the rule.
    ///
    /// An input (anchor, `through=` pin or trust-file `end=`) whose
    /// `seq` is strictly above the end record's last line's `seq` is
    /// set aside instead of being checked against the batch, because
    /// nothing above the end can be checked. When the end is not
    /// anchored (no end anchor or the end anchor differs from the
    /// record), one further `UnanchoredEnd` fires per such input,
    /// unlocated, at the input's `seq`; see
    /// [`Verifier::end_before`](crate::audit::Verifier::end_before)
    /// for the detail grammars and the set-aside rule. The
    /// corresponding anchored form is [`FindingKind::OutOfRange`]
    /// (info) (ADR-0005 decision 11 "It ends the range"; ruling
    /// 13-V6-d7).
    UnanchoredEnd,
    /// Error: A record violates the trail's retirement pin
    /// `end=<s>:<h>` (ADR-0005 decision 9; rulings 13-V5-d1 point 5
    /// and 13-V5-d5), or a file record carries a `seq` at or
    /// above an
    /// [`end_before`](crate::audit::Verifier::end_before) record's
    /// end checkpoint (ADR-0005 decision 11 `.end_before`; ruling
    /// 13-V6-d4 point 3).
    ///
    /// - **at `s`:** the verified set holds exactly one distinct
    ///   record at `s` and its hash is `h`. One detail is chosen by
    ///   the first failing check in this order: `seq <s> is forked`
    ///   (no location), `no record at seq <s>` (no location), or
    ///   `record at seq <s> has hash blake3:<64 hex>` (at the first
    ///   copy in the engine's merge order).
    /// - **above `s`:** no record of the verified trail has `seq`
    ///   strictly above `s`. The detail `records seq <a>..=<b>
    ///   above the end` fires at the first such record in merge
    ///   order, with `a` and `b` the lowest and highest such `seq`.
    ///
    /// Every detail starts with `end=<s>:blake3:<64 hex>: `. A
    /// matching `end=` (neither condition fails) grants the tail
    /// exemption, confirmation of `through=` bounds at or below `s`
    /// (the pin still runs) and promotion of 13-V5-d2 repairs at or
    /// below `s`; a mismatch grants none of them, and no `end=`
    /// checks nothing.
    ///
    /// **`end_before` form.** With
    /// [`Verifier::end_before`](crate::audit::Verifier::end_before)
    /// set, one further `TrailEnded` with detail exactly
    /// `end_before seq <e>: records seq <a>..=<b> at or above the
    /// end` is emitted when any file record of the verified trail
    /// carries a `seq` at or above the end checkpoint's `seq`;
    /// see that method for the rule.
    TrailEnded,
    /// Error: With `Verifier::max_age` set, the verified trail is
    /// stale (ADR-0005 decision 5; rulings 13-V5-d1 point 7 and
    /// 13-V5-d6). At most one finding fires per verify call.
    ///
    /// "Newest trusted checkpoint" is the trusted checkpoint (ruling
    /// 13-V5-d1 point 3: `verify_strict` passes AND the signing key
    /// is trusted at the checkpoint's `seq`) with the highest `seq`,
    /// including shipped-only copies; at a forked `seq` (ruling
    /// 13-V5-d2), the highest unforked trusted one below it. "Now" is
    /// the verifier's clock at the start of the verify call. Age is
    /// `now - time` in nanoseconds against the checkpoint's signed
    /// `time` with checked arithmetic; a future `time` saturates to
    /// age zero and is not stale (clock problems are the business of
    /// `ClockWentBackwards`, not `StaleHead`).
    ///
    /// - **stale:** the newest trusted checkpoint's age exceeds
    ///   `max_age`. Detail exactly `newest trusted checkpoint seq
    ///   <n> time <t> is older than max_age <d> at <now>`, located at
    ///   the checkpoint's first copy in the engine's merge order (the
    ///   same copy `DuplicateRecord` treats as the original). `<t>`
    ///   and `<now>` are Unix nanoseconds, `<d>` is nanoseconds; all
    ///   are decimal integers.
    /// - **no trusted checkpoint:** `max_age` is set and no trusted
    ///   checkpoint exists. Detail exactly `no trusted checkpoint
    ///   (max_age <d>)`; no file, no line and no `seq`.
    ///
    /// Without `max_age` set, nothing is checked.
    StaleHead,
    /// Error: An in-range `audit.record` is not named by any
    /// receipt supplied to
    /// [`Verifier::receipts`](crate::audit::Verifier::receipts)
    /// (ADR-0005 decision 5 "Receipt reconciliation"; ruling
    /// 13-V7-d1 point 5). Reconciliation runs only when
    /// `Verifier::receipts` has been called; see that method for the
    /// full rule, the range and the shipped-copy behaviour.
    ///
    /// Detail is exactly
    /// `no receipt for seq <s> hash blake3:<64 hex>`, located at
    /// the record's first copy in the engine's merge order (the
    /// same copy `DuplicateRecord` reports as the original).
    /// Operator `vigil.audit.*` records are included; checkpoints
    /// are not. End-record lines
    /// ([`Verifier::end_before`](crate::audit::Verifier::end_before))
    /// are not reconciled; a receipt naming one still matches.
    NoReceipt,
    /// Error: A receipt supplied to
    /// [`Verifier::receipts`](crate::audit::Verifier::receipts) does
    /// not match the verified history (ADR-0005 decision 5 "Receipt
    /// reconciliation"; ruling 13-V7-d1 point 4). Every
    /// `ReceiptMismatch` fires at the receipt's `seq`, with no
    /// location. Of these details, the first failing one applies:
    ///
    ///   1. `receipt seq <s> hash blake3:<64 hex>: no record`
    ///   2. `receipt seq <s> hash blake3:<64 hex>: seq is forked`
    ///   3. `receipt seq <s> hash blake3:<64 hex>: hash differs (record blake3:<64 hex>)`
    ///
    /// See
    /// [`Verifier::receipts`](crate::audit::Verifier::receipts) for
    /// the match rule, the range and the collapse of identical
    /// receipts. A receipt below an accepted
    /// [`start_from`](crate::audit::Verifier::start_from) or above
    /// an [`end_before`](crate::audit::Verifier::end_before) end is
    /// set aside instead of reported here
    /// ([`FindingKind::OutOfRange`],
    /// [`FindingKind::UnanchoredStart`],
    /// [`FindingKind::UnanchoredEnd`]).
    ReceiptMismatch,
    /// Error: The following record does not attest the fragment gap.
    RepairMismatch,
    /// Error: A review does not match its record, gap or run digest.
    AcceptMismatch,
    /// Warning: A fragment gap whose attesting record is not a record
    /// of the verified trail, is at a `seq` carrying a `SeqConflict`
    /// (one side of a fork), or neither covered by a trusted
    /// checkpoint (`seq > covered_through`) nor pinned by a matching
    /// `end=` (`seq > matched_end`); or a trailing gap with no
    /// attesting record at all. Promotion to `TornWriteRepaired`
    /// requires an attester of the verified trail whose `seq` has no
    /// `SeqConflict` and is reached by either rule (rulings 13-V5-d1
    /// points 5-6, 13-V5-d2 and 13-V5-d5 point 2.3).
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
    /// Info: An input below an **anchored** accepted start, or
    /// strictly above the end record's last line's `seq` under an
    /// anchored
    /// [`Verifier::end_before`](crate::audit::Verifier::end_before)
    /// (ADR-0005 decision 11 "A signature alone never demotes
    /// anything" and "It ends the range"; rulings 13-V6-d3 and
    /// 13-V6-d7). Detail grammars, all unlocated:
    /// `anchor seq <a> hash blake3:<64 hex>: below start seq <s>` or
    /// `key <64 hex> through=<b>: below start seq <s>` (below an
    /// anchored start); and
    /// `anchor seq <a> hash blake3:<64 hex>: above end seq <E>`,
    /// `key <64 hex> through=<b>: above end seq <E>` or
    /// `end=<s>:blake3:<64 hex>: above end seq <E>` (above an
    /// anchored end). See
    /// [`Verifier::start_from`](crate::audit::Verifier::start_from)
    /// and
    /// [`Verifier::end_before`](crate::audit::Verifier::end_before)
    /// for the rules.
    OutOfRange,
    /// Info: Records follow the reconciled receipts prefix.
    Unreconciled,
    /// Info: A matched [`Verifier::waive`](crate::audit::Verifier::waive)
    /// or [`Verifier::receipts_from`](crate::audit::Verifier::receipts_from)
    /// at the record's first copy (ADR-0005 decision 5 "Waivers, for
    /// an honest crash" and "Late adoption"; ruling 13-V7-d1 point 6).
    /// Details: `waived seq <s> hash blake3:<64 hex>: <reason>` (the
    /// record carries no `NoReceipt`) or
    /// `from seq <s> hash blake3:<64 hex>: <reason>` (records at or
    /// below `s` are not reconciled). See those builders for the
    /// match rule, the `InvalidConfig` cases and the review
    /// criterion.
    ReceiptWaived,
    /// Info: A fragment gap attested by a record of the verified
    /// trail with no other record at its `seq` whose `seq` is at or
    /// below `covered_through` or at or below a matching `end=`
    /// (rulings 13-V5-d1 points 5-6, 13-V5-d2 and 13-V5-d5
    /// point 2.3). Detail grammar is the same as `TornWrite`'s
    /// attested form:
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
