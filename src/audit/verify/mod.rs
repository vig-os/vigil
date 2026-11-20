//! Offline collecting verifier and results (ADR-0005).
use super::{AuditError, AuditErrorKind, Checkpoint, FindingKind, TrustPolicy};
use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};
mod anchors;
mod end;
mod end_before;
mod engine;
mod fold;
mod input;
pub(crate) mod lines;
mod position;
mod resume;
mod revocation;
mod signatures;
mod stale;
mod start;

/// The first record copy in the engine's merge order
/// (`(is_end_record, path, line, hash)`): the same copy
/// [`FindingKind::DuplicateRecord`] reports as the original (ruling
/// 13-V5-d4). Shared by the location rule in `anchors`, `end` and
/// `stale`; accepts a borrowed iterator so `stale` can pre-filter by
/// its trusted predicate. [`input::Summary::is_end_record`] sorts
/// the end-record copies strictly after every file copy at a shared
/// `seq`, so "first copy" is always a file copy whenever one exists
/// (ruling 13-V6-d4 point 3).
pub(in crate::audit::verify) fn first_copy<'a, I>(
    copies: I,
) -> Option<(&'a Path, &'a input::Summary)>
where
    I: IntoIterator<Item = &'a (&'a Path, &'a input::Summary)>,
{
    copies
        .into_iter()
        .min_by_key(|(path, record)| (record.is_end_record, *path, record.line, record.hash))
        .copied()
}

/// Severity of a finding produced by the offline verifier (#13).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Severity {
    /// Invalid history or evidence.
    Error,
    /// A condition requiring operator attention.
    Warning,
    /// Additional verification or review information.
    Info,
}

/// One diagnostic produced by the offline verifier (#13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    kind: FindingKind,
    file: Option<PathBuf>,
    line: Option<u64>,
    seq: Option<u64>,
    detail: String,
    accepted_kind: Option<FindingKind>,
    run_digest: Option<[u8; 32]>,
}
impl Finding {
    pub(crate) fn new(
        kind: FindingKind,
        file: Option<PathBuf>,
        line: Option<u64>,
        seq: Option<u64>,
        detail: String,
    ) -> Self {
        Self {
            kind,
            file,
            line,
            seq,
            detail,
            accepted_kind: None,
            run_digest: None,
        }
    }
    #[cfg_attr(not(test), expect(dead_code, reason = "review promotion, #13 V8"))]
    pub(crate) fn accepted(mut self, kind: FindingKind) -> Self {
        assert_eq!(self.kind, FindingKind::Accepted);
        self.accepted_kind = Some(kind);
        self
    }
    /// Sets a run's `blake3` digest on its `SegmentStructure`
    /// finding. Consumed by `verify::fold::check_runs` (#13 V4a) for
    /// the ADR-0005 decision 11 `accept-run` pinning.
    pub(crate) fn with_run_digest(mut self, digest: [u8; 32]) -> Self {
        assert_eq!(self.kind, FindingKind::SegmentStructure);
        self.run_digest = Some(digest);
        self
    }
    /// Clears the finding's file and line (ruling 13-V6-d4
    /// point 6): a finding that sits on an end-record line has no
    /// file and no line, and its `seq` identifies it. Called once
    /// per finding by [`engine::check`] after every rule has run.
    pub(crate) fn strip_location(&mut self) {
        self.file = None;
        self.line = None;
    }
    /// Returns the diagnostic category.
    pub fn kind(&self) -> FindingKind {
        self.kind
    }
    /// Returns the severity assigned by ADR-0005 decision 11.
    pub fn severity(&self) -> Severity {
        severity(self.kind)
    }
    /// Returns the source file, when the finding concerns a file.
    pub fn file(&self) -> Option<&Path> {
        self.file.as_deref()
    }
    /// Returns the 1-based physical line number, when known.
    pub fn line(&self) -> Option<u64> {
        self.line
    }
    /// Returns the sequence number concerned, when known.
    pub fn seq(&self) -> Option<u64> {
        self.seq
    }
    /// Returns a diagnostic including expected and found values when applicable.
    pub fn detail(&self) -> &str {
        &self.detail
    }
    /// Returns the reviewed kind on an `Accepted` finding, and `None` otherwise.
    pub fn accepted_kind(&self) -> Option<FindingKind> {
        self.accepted_kind
    }
    /// Returns a run's digest on its `SegmentStructure` finding, and `None` otherwise.
    pub fn run_digest(&self) -> Option<[u8; 32]> {
        self.run_digest
    }
}

/// Results produced by the offline verifier (#13).
#[derive(Debug, Clone)]
pub struct Report {
    trail: [u8; 16],
    records: u64,
    first_seq: Option<u64>,
    last_seq: Option<u64>,
    covered_through: Option<u64>,
    findings: Vec<Finding>,
    // `--strict` exempts `UncoveredTail` under a matching `end=`
    // (ruling 13-V5-d5 point 2.1); a mismatched or absent `end=`
    // leaves this `false`.
    tail_exempt: bool,
}
impl Report {
    pub(crate) fn new(
        trail: [u8; 16],
        records: u64,
        first_seq: Option<u64>,
        last_seq: Option<u64>,
        covered_through: Option<u64>,
        findings: Vec<Finding>,
    ) -> Self {
        Self {
            trail,
            records,
            first_seq,
            last_seq,
            covered_through,
            findings,
            tail_exempt: false,
        }
    }
    /// Marks the uncovered tail as exempt from `--strict` (consumed
    /// by `is_strict_valid`). Set by [`super::engine::check`] to
    /// `true` exactly when the verified trail's section carries an
    /// `end=` that matches (ruling 13-V5-d5 point 2.1); every other
    /// report leaves it `false`.
    pub(crate) fn with_tail_exempt(mut self, exempt: bool) -> Self {
        self.tail_exempt = exempt;
        self
    }
    /// Returns the pinned trail identifier verified by this report.
    pub fn trail(&self) -> [u8; 16] {
        self.trail
    }
    /// Returns the number of verified records.
    pub fn records(&self) -> u64 {
        self.records
    }
    /// Returns the lowest verified sequence number, the start's when supplied.
    pub fn first_seq(&self) -> Option<u64> {
        self.first_seq
    }
    /// Returns the highest verified sequence number, or `None` for no records.
    pub fn last_seq(&self) -> Option<u64> {
        self.last_seq
    }
    /// Returns the highest `seq` of a trusted checkpoint (ruling
    /// 13-V5-d1 point 6): one whose signature verifies under
    /// `verify_strict` AND whose key is trusted at that `seq`. Coverage
    /// is inclusive, so this `seq` is itself covered; `None` means no
    /// candidate was trusted. Every record above this value (or every
    /// record when `None`) is reported as `UncoveredTail`.
    pub fn covered_through(&self) -> Option<u64> {
        self.covered_through
    }
    /// Returns all diagnostics collected during verification.
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }
    /// Returns true exactly when no finding has severity `Error`.
    pub fn is_valid(&self) -> bool {
        self.findings
            .iter()
            .all(|f| f.severity() != Severity::Error)
    }
    /// Returns true when `--strict` would exit 0 for this report.
    ///
    /// No `Error`, no `Warning`, no `UncoveredTail` without
    /// `tail_exempt`, no `Unreconciled`. `tail_exempt` is set by the
    /// verifier exactly when the verified trail's section carries an
    /// `end=` that matches (both the "at `s`" and "above `s`"
    /// conditions of ruling 13-V5-d5 pass), so `UncoveredTail`
    /// stays an info but does not fail `--strict`. A mismatched or
    /// absent `end=` leaves it `false`. An `Accepted` info does not
    /// suppress a separate warning of the same kind.
    pub fn is_strict_valid(&self) -> bool {
        self.findings.iter().all(|f| match f.severity() {
            Severity::Error | Severity::Warning => false,
            Severity::Info => match f.kind() {
                FindingKind::UncoveredTail => self.tail_exempt,
                FindingKind::Unreconciled => false,
                _ => true,
            },
        })
    }
    /// Returns the first error-severity finding in V3a-2's ruled order,
    /// or `None` when no finding has severity `Error`. Every error kind
    /// qualifies, not only `ChainBroken`.
    pub fn first_broken_link(&self) -> Option<&Finding> {
        self.findings
            .iter()
            .find(|f| f.severity() == Severity::Error)
    }
}

fn severity(kind: FindingKind) -> Severity {
    use FindingKind::*;
    match kind {
        Unparsable
        | UnknownVersion
        | UnknownField
        | MissingField
        | InvalidField
        | HashMismatch
        | ChainBroken
        | SeqGap
        | SeqConflict
        | TrailMismatch
        | MmrMismatch
        | BadSignature
        | UntrustedKey
        | RevocationMismatch
        | RevocationUnconfirmed
        | SegmentStructure
        | AnchorMismatch
        | StartMismatch
        | UnanchoredStart
        | UnanchoredEnd
        | TrailEnded
        | StaleHead
        | NoReceipt
        | ReceiptMismatch
        | RepairMismatch
        | AcceptMismatch => Severity::Error,
        TornWrite | Resumed | ClockWentBackwards | DuplicateRecord => Severity::Warning,
        UncoveredTail | OutOfRange | Unreconciled | ReceiptWaived | TornWriteRepaired
        | Accepted | AcceptUnused | LostRecord => Severity::Info,
    }
}

#[cfg(test)]
mod above_end_tests;
#[cfg(test)]
mod anchors_tests;
#[cfg(test)]
mod coverage_tests;
#[cfg(test)]
mod end_before_tests;
#[cfg(test)]
mod end_link_tests;
#[cfg(test)]
mod end_tests;
#[cfg(test)]
mod mod_tests;
#[cfg(test)]
mod position_tests;
#[cfg(test)]
mod revocation_tests;
#[cfg(test)]
mod rule2_tests;
#[cfg(test)]
mod runs_tests;
#[cfg(test)]
mod stale_tests;
#[cfg(test)]
mod start_tests;

/// Verifies a directory using a cloned, validated trust policy.
///
/// **Incomplete (#13):** V3b-1 adds fragment-run context (condition 3 per
/// run), the "no crash outcome" mark on a trailing `TornWrite`, a plain
/// `Resumed` warning for every `vigil.audit.resume` record (once per
/// `(seq, hash)`, attributed to the native copy when present),
/// and the `is_strict_valid` / `first_broken_link` predicates. V3b-2 adds
/// structural resume validation per ruling 13-V3-d5 (rules 1 and 3): every
/// parseable `Resumed` detail ends with exactly one suffix,
/// ` structural=valid` or ` structural=invalid(<reason>)`, where `<reason>`
/// is the first failing condition token in this exact order: `no-opening`,
/// `resume-not-at-k+1`, `head-not-present`, `head-not-last`,
/// `link-mismatch`, `genesis-not-first`. The suffix changes no severity
/// and removes no finding; every `SeqGap`, `ChainBroken` and `Resumed`
/// stays. A malformed declaration keeps its `malformed declaration`
/// detail and gets no suffix. The genesis gap text is `gap=0..=<L>`
/// (ADR l.407), never `none`. An archived head is indistinguishable from
/// a deleted one and resolves to `head-not-present`; a start checkpoint
/// covering an archived head is V6's. V5b trusts checkpoints (ruling
/// 13-V5-d1 point 6): `covered_through` is the highest `seq` of a
/// trusted candidate, `UncoveredTail` lists exactly the records above
/// it, and an attested native gap is `TornWriteRepaired` only when the
/// attester is a record of the verified trail whose `seq` has no
/// `SeqConflict` (ruling 13-V5-d2); otherwise it stays `TornWrite`.
/// V4/V5c-e/V6-V8/R10 supply folds, revocation,
/// `end=`, `max_age`, anchors, receipts, review and archive rules.
/// A matching `audit.repaired` outside coverage is a `TornWrite`, a
/// missing or different one is `RepairMismatch`, and a trailing gap is
/// `TornWrite` with the bytes-to-EOF digest. A line that classifies as a
/// `Fragment` whose enclosing run cannot link to the next complete record
/// (file-start run, non-`Records` line after, or a mismatched `previous`)
/// becomes `Unparsable` per line; the gap bytes, lengths and digests stay
/// V2-identical. No release from dev carries this partial verifier before
/// #13 through C1.
///
/// A native line carrying several records is accepted (ADR §3): each record
/// chain-checks, and `audit.repaired` is read from the first record only;
/// a later record's `audit.repaired` is a deliberate silence (ruling
/// 13-V3-d4 point 4), because the writer's own `open` refuses such a line
/// (`storage.rs:892`).
///
/// Open, or record once, before reviewing a crashed trail to settle staging.
/// Strict live review must target a stopped trail: an in-flight append can look
/// torn. Reads take no locks and offer per-directory snapshots, not global atomicity.
///
/// # Errors
/// Returns `Io` with its source for unreadable inputs or exhausted snapshot
/// retries, and `InvalidConfig` for ambiguous pins or duplicate native names.
/// Corruption is collected as findings.
///
/// ```no_run
/// use vigil::audit::{verify, TrustPolicy};
/// let trust = TrustPolicy::builder().trail([1; 16]).build()?;
/// let report = verify(std::path::Path::new("audit"), &trust)?;
/// assert_eq!(report.trail(), [1; 16]);
/// # Ok::<(), vigil::audit::AuditError>(())
/// ```
pub fn verify(dir: &Path, trust: &TrustPolicy) -> Result<Report, AuditError> {
    Verifier::new(trust.clone()).verify_dir(dir)
}

/// Collecting verifier with validated pins. See [`verify`] for staged #13
/// limitations and the settlement and stopped-trail review requirements.
#[derive(Debug, Clone)]
pub struct Verifier {
    trust: TrustPolicy,
    trail: Option<[u8; 16]>,
    max_age: Option<Duration>,
    anchors: Vec<Checkpoint>,
    start: Option<Checkpoint>,
    end_before: Option<EndBefore>,
    #[cfg(test)]
    now_override: Option<SystemTime>,
}

/// Parsed archive record and its end anchor, retained between the
/// `end_before` call and the verify call (ADR-0005 decision 11
/// `.end_before`; ruling 13-V6-d4). Private; the verifier's one
/// outside-facing form is [`Verifier::end_before`].
#[derive(Debug, Clone)]
struct EndBefore {
    parsed_bytes: Vec<u8>,
    end_seq: u64,
    /// `E`: the end record's last line's `seq` (ruling 13-V6-d7
    /// point 1). The resume line's `seq` when present, otherwise
    /// equal to `end_seq`.
    last_line_seq: u64,
    first_line: String,
    anchor: Option<Checkpoint>,
}
impl Verifier {
    /// Takes ownership of a validated policy. Multiple pins require [`Self::trail`].
    pub fn new(trust: TrustPolicy) -> Self {
        Self {
            trust,
            trail: None,
            max_age: None,
            anchors: Vec::new(),
            start: None,
            end_before: None,
            #[cfg(test)]
            now_override: None,
        }
    }
    /// Narrows verification to a pinned trail, independently of input contents.
    ///
    /// # Errors
    /// Returns `InvalidConfig` immediately if the id is not pinned.
    pub fn trail(mut self, id: [u8; 16]) -> Result<Self, AuditError> {
        if !self.trust.pinned(&id) {
            return Err(AuditError::new(
                AuditErrorKind::InvalidConfig,
                "trail is not pinned",
            ));
        }
        self.trail = Some(id);
        Ok(self)
    }
    /// Reports [`StaleHead`](FindingKind::StaleHead) when the newest
    /// trusted checkpoint (ruling 13-V5-d1 point 3) is older than
    /// `max_age` (ADR-0005 decision 5; rulings 13-V5-d1 point 7 and
    /// 13-V5-d6). `Duration::ZERO` is accepted; calling this again
    /// replaces the earlier value.
    ///
    /// "Now" is taken once per verify call from the system clock. Age
    /// is `now - time` in nanoseconds against the checkpoint's signed
    /// `time` with checked arithmetic; a `time` in the future
    /// saturates to age zero and is not stale (clock problems are the
    /// business of [`ClockWentBackwards`](FindingKind::ClockWentBackwards),
    /// not `StaleHead`).
    ///
    /// It detects a stopped writer and a rollback after which **no**
    /// checkpoint was signed again. It does **not** detect a rollback
    /// once any writer has signed a fresh checkpoint on the shortened
    /// trail; for example, a writer restarted without `expect_head` on
    /// a live file truncated at a record boundary, or a sealed segment
    /// renamed back to `audit.jsonl`.
    ///
    /// # Errors
    /// Returns `InvalidConfig` when [`Verifier::end_before`] was
    /// already called on this verifier (ADR-0005 §19.2; ruling
    /// 13-V6-d4 point 7): `max_age` and `end_before` are mutually
    /// exclusive, and the error is raised by whichever call comes
    /// second.
    pub fn max_age(mut self, max_age: Duration) -> Result<Self, AuditError> {
        if self.end_before.is_some() {
            return Err(AuditError::new(
                AuditErrorKind::InvalidConfig,
                "max_age conflicts with end_before",
            ));
        }
        self.max_age = Some(max_age);
        Ok(self)
    }
    /// Pins one checkpoint as an anchor, reporting one
    /// [`AnchorMismatch`](FindingKind::AnchorMismatch) (error) per
    /// failing anchor at its `seq` (ADR-0005 decision 10; ruling
    /// 13-V6-d1 points 1-2).
    ///
    /// An anchor matches only when its `trail` is the verified trail,
    /// the verified set holds exactly one distinct record at its
    /// `seq` (a byte-identical duplicate is still one record), and
    /// that record carries the anchor's hash. Shipped-only copies
    /// count as records in the trail (ruling 13-V5-d4). A forked
    /// `seq` (ruling 13-V5-d2) is never matched, even when one copy
    /// carries the anchor's hash. Each distinct `(trail, seq, hash)`
    /// is checked once; duplicate calls collapse.
    ///
    /// A failing anchor yields one `AnchorMismatch` at the first
    /// failing condition, in this order:
    ///
    ///   1. `anchor seq <s> hash <hex>: trail differs`
    ///   2. `anchor seq <s> hash <hex>: no record`
    ///   3. `anchor seq <s> hash <hex>: seq is forked`
    ///   4. `anchor seq <s> hash <hex>: hash differs (record <hex>)`
    ///
    /// The hex values are `blake3:<64 lowercase hex>`; whitespace in
    /// the detail is significant. Every finding locates at the first
    /// copy of the record at `seq` in the engine's merge order (the
    /// same copy [`FindingKind::DuplicateRecord`] reports as the
    /// original); the one `no record` case has no record to locate
    /// against and therefore no location. A `trail differs` anchor
    /// at a `seq` the verified trail holds is still located at that
    /// record's first copy.
    ///
    /// Anchors must come from a source the attacker cannot write: a
    /// [`Checkpoint`] returned by [`AuditTrail::checkpoint`],
    /// [`AuditTrail::close`] or [`AuditConfig::resume`] in process,
    /// the line printed by `vigil-audit checkpoint`, `rotate` or
    /// `resume`, or [`checkpoints`] run on a clean verified snapshot
    /// (ADR-0005 decision 10). Shipped copies are never anchor
    /// sources (ADR-0005 decision 10, "Shipped copies are not
    /// anchors").
    ///
    /// Anchors are not signature-checked: supplying one is the
    /// operator's statement that this checkpoint was observed on the
    /// verified trail at its `seq` (ADR-0005 decision 10). Signature
    /// and key-trust findings are raised by the ordinary signature
    /// and trust checks against the verified records.
    ///
    /// [`AuditTrail::checkpoint`]: crate::audit::AuditTrail::checkpoint
    /// [`AuditTrail::close`]: crate::audit::AuditTrail::close
    /// [`AuditConfig::resume`]: crate::audit::AuditConfig::resume
    /// [`checkpoints`]: crate::audit::checkpoints
    pub fn anchor(mut self, anchor: Checkpoint) -> Self {
        self.anchors.push(anchor);
        self
    }
    /// Accepts the first record as an archived trail's start, so the
    /// prefix [`SeqGap`](FindingKind::SeqGap) for `0..s−1` is not
    /// reported (ADR-0005 decision 11 `.start_from`; ruling
    /// 13-V6-d2). A second call replaces the first. Without a call,
    /// nothing changes.
    ///
    /// The start is accepted only when every condition below holds:
    /// its trail is the verified trail; the verified set has a first
    /// record whose `seq` equals the start's `seq` (the first record
    /// is the record with the lowest `seq` across native and shipped
    /// copies merged by `seq`, a byte-identical duplicate counting
    /// as one record); that `seq` is not forked (ruling 13-V6-d1
    /// point 2; the shared `forked()` predicate, so one hash across
    /// copies stays `DuplicateRecord`); the record is a checkpoint;
    /// its hash equals the start's hash; and it is trusted at its
    /// `seq` (ruling 13-V5-d1 point 3: a valid `verify_strict`
    /// signature by a key trusted for the trail at that `seq`).
    ///
    /// If one condition fails, one
    /// [`StartMismatch`](FindingKind::StartMismatch) (error) is
    /// reported at the start's `seq`, with the detail of the first
    /// failing condition, in this order (ruling 13-V6-d2 point 3):
    ///
    ///   1. `start seq <s> hash <hex>: trail differs`
    ///   2. `start seq <s> hash <hex>: no record`
    ///   3. `start seq <s> hash <hex>: not the first record (first seq <f>)`
    ///   4. `start seq <s> hash <hex>: seq is forked`
    ///   5. `start seq <s> hash <hex>: not a checkpoint`
    ///   6. `start seq <s> hash <hex>: hash differs (record <hex>)`
    ///   7. `start seq <s> hash <hex>: not trusted at its seq`
    ///
    /// The hex values are `blake3:<64 lowercase hex>`; whitespace in
    /// the detail is significant. The finding locates at the first
    /// copy of the first record in the engine's merge order (the
    /// same copy [`FindingKind::DuplicateRecord`] reports as the
    /// original); with no record, there is no location. The record's
    /// own [`BadSignature`](FindingKind::BadSignature) and
    /// [`UntrustedKey`](FindingKind::UntrustedKey) are independent of
    /// this start check and still fire as usual.
    ///
    /// A start that is not accepted is not used (ADR-0005 decision
    /// 11; ruling 13-V6-d2 point 4): verification runs exactly as if
    /// no start had been given, including the prefix `SeqGap`. An
    /// accepted start suppresses only the `SeqGap` for `0..s−1`
    /// (ruling 13-V6-d2 point 5); the chain, the fold, signatures,
    /// trust, coverage and revocation run as they do today from the
    /// first checkpoint, so a forged record later in the file is
    /// still reported, and the revocation rules above the start
    /// still apply.
    ///
    /// The start must come from the **batch-start anchor entry** of
    /// the previous batch in the anchor store (ADR-0005 decision 11
    /// "Where it comes from", amended #123), never the trail
    /// directory and never the archive record.
    ///
    /// An anchor or a `through=<b>:<h>` pin whose `seq` is strictly
    /// below an accepted start is **set aside** (ADR-0005 decision 11
    /// "A signature alone never demotes anything", ~l.753-757; ruling
    /// 13-V6-d3 points 4-5): its ordinary mismatch check is replaced
    /// by one unlocated finding at the input's `seq`, with kind
    /// [`FindingKind::OutOfRange`] (info) when the start is anchored
    /// and [`FindingKind::UnanchoredStart`] (error) otherwise. The
    /// start is anchored exactly when some anchor's `(trail, seq,
    /// hash)` equals the accepted start (point 3); acceptance
    /// guarantees that anchor matches under 13-V6-d1 point 2. Detail
    /// grammars:
    /// `anchor seq <a> hash blake3:<64 hex>: below start seq <s>` and
    /// `key <64 hex> through=<b>: below start seq <s>`. Another
    /// trail's anchor is never set aside and still gives
    /// `AnchorMismatch … trail differs` (point 4). The pin's
    /// confirmation check runs unchanged (point 5), so the revocation
    /// rules above the start still apply; a bound below an accepted
    /// start is always confirmed by that start. A bound at `b = s` or
    /// above it is in range and runs the ordinary pin and
    /// confirmation. Without an accepted start, every `seq` is in
    /// range and nothing is set aside (point 2).
    pub fn start_from(mut self, start: Checkpoint) -> Self {
        self.start = Some(start);
        self
    }
    /// Verifies one archive batch against its end record and the
    /// batch-start anchor entry that pins it (ADR-0005 decision 11
    /// `.end_before`; ruling 13-V6-d4).
    ///
    /// `archive_record` is one line, or two lines separated by one
    /// LF with one optional final LF. The first line passes
    /// [`Checkpoint::parse`]; it is the opening checkpoint of the
    /// batch that follows. A second line, when present, is a single
    /// record whose action is `vigil.audit.resume`, whose `seq` is
    /// the checkpoint's `seq + 1`, and whose `prev_hash` is the
    /// checkpoint's hash. Anything else (an empty record, a third
    /// line, CR, a non-checkpoint first line, a non-resume second
    /// line, a resume line with the wrong `seq` or the wrong
    /// `prev_hash`) is a usage error.
    ///
    /// `end_anchor` must come from the batch-start anchor entry in
    /// the anchor store (ADR-0005 decision 11 "Where the end comes
    /// from"), never the trail directory and never only the archive
    /// record (which is kept with the archive and can be rewritten
    /// by whoever can delete inside it). The record's lines go into
    /// the verified set as the segment that follows the files, so
    /// every existing rule applies to them. File records of the
    /// verified trail with `seq` at or above the end checkpoint's
    /// `seq` yield one [`TrailEnded`](FindingKind::TrailEnded)
    /// (error); a byte-identical file copy of an end line never
    /// becomes `DuplicateRecord`, and a different record at such a
    /// `seq` is still [`SeqConflict`](FindingKind::SeqConflict).
    /// Without `end_anchor`, one
    /// [`UnanchoredEnd`](FindingKind::UnanchoredEnd) (error) fires;
    /// with `end_anchor`, the anchor's line must byte-equal the
    /// record's first line (each side without its LF; whitespace
    /// counts) else one
    /// [`AnchorMismatch`](FindingKind::AnchorMismatch) (error)
    /// fires with detail `end record differs from end anchor`. The
    /// end anchor also joins the anchors ([`Self::anchor`]) and
    /// goes through the ordinary anchor rule. Every end-record
    /// finding carries no file and no line (ruling 13-V6-d4 point
    /// 6).
    ///
    /// An anchor, a `through=<b>:<h>` pin or a trust-file `end=<s>`
    /// whose `seq` is strictly above `E` — the end record's last
    /// line's `seq` (the resume line when present, otherwise the
    /// checkpoint; ruling 13-V6-d7 point 1) — is **set aside**
    /// (ADR-0005 decision 11 "It ends the range"; ruling 13-V6-d7):
    /// its ordinary mismatch check is replaced by one unlocated
    /// finding at the input's `seq`, with kind
    /// [`FindingKind::OutOfRange`] (info) when the end is anchored
    /// (an end anchor was given and byte-equals the record's first
    /// line) and [`FindingKind::UnanchoredEnd`] (error) otherwise.
    /// Detail grammars, all unlocated:
    /// `anchor seq <a> hash blake3:<64 hex>: above end seq <E>`,
    /// `key <64 hex> through=<b>: above end seq <E>` and
    /// `end=<s>:blake3:<64 hex>: above end seq <E>`. Another trail's
    /// anchor above `E` is never set aside and still gives
    /// `AnchorMismatch … trail differs`. A trust-file `end=` above
    /// `E` replaces both `TrailEnded` conditions and grants nothing
    /// from decision 9 (no tail exemption, no bound confirmation and
    /// no repair promotion).
    /// [`FindingKind::RevocationUnconfirmed`] is not reported in an
    /// end-bounded verification (a confirming checkpoint may lie
    /// above the end, ruling 13-V6-d7 point 4); the pinned and
    /// bounded checks still run. A pin at `b = E` or an anchor at
    /// `E` is in range and is checked as usual.
    ///
    /// # Errors
    /// Returns `InvalidConfig` when `archive_record` violates the
    /// grammar above, or when [`Self::max_age`] was already called
    /// on this verifier (ADR-0005 §19.2; ruling 13-V6-d4 point 7):
    /// `max_age` and `end_before` are mutually exclusive, and the
    /// error is raised by whichever call comes second. A second
    /// `end_before` call replaces the first.
    pub fn end_before(
        mut self,
        archive_record: &str,
        end_anchor: Option<Checkpoint>,
    ) -> Result<Self, AuditError> {
        if self.max_age.is_some() {
            return Err(AuditError::new(
                AuditErrorKind::InvalidConfig,
                "end_before conflicts with max_age",
            ));
        }
        let parsed = end_before::parse(archive_record)?;
        self.end_before = Some(EndBefore {
            parsed_bytes: parsed.segment_bytes,
            end_seq: parsed.checkpoint.seq(),
            last_line_seq: parsed.last_line_seq,
            first_line: parsed.checkpoint.line().to_owned(),
            anchor: end_anchor,
        });
        Ok(self)
    }
    /// Expands a directory's vigil files and verifies its confirmed snapshot.
    /// See [`verify`] for review limitations and error semantics.
    ///
    /// # Errors
    /// Returns `Io` for read/retry failure or `InvalidConfig` for ambiguous input.
    pub fn verify_dir(&self, dir: &Path) -> Result<Report, AuditError> {
        self.verify_files([dir.to_owned()])
    }
    /// Verifies files or directories; arbitrary filenames are shipped copies
    /// merged by sequence, without native segment boundary semantics.
    /// Each inode is read once; native segments sort numerically, live last.
    /// See [`verify`] for staged limitations and per-directory snapshot scope.
    ///
    /// # Errors
    /// Returns `Io` with its source for unreadable explicit files or snapshot
    /// exhaustion, or `InvalidConfig` for ambiguous pins/duplicate native names.
    pub fn verify_files(
        &self,
        files: impl IntoIterator<Item = PathBuf>,
    ) -> Result<Report, AuditError> {
        let mut ids = self.trust.trail_ids();
        let trail = self
            .trail
            .or_else(|| {
                let first = *ids.next()?;
                ids.next().is_none().then_some(first)
            })
            .ok_or_else(|| {
                AuditError::new(AuditErrorKind::InvalidConfig, "select a pinned trail")
            })?;
        let mut collection = input::collect(files)?;
        // Ruling 13-V6-d4 points 1 and 5: the archive record goes
        // in as one native segment after the files, and the end
        // anchor also joins the anchors. The path is a plain label
        // for diagnostics only; [`input::Input::is_end_record`]
        // identifies the segment for ordering and strip-location.
        let mut joined_anchors = self.anchors.clone();
        let end_ctx = self.end_before.as_ref().map(|eb| {
            input::append_native(
                &mut collection,
                input::end_record_input(eb.parsed_bytes.clone(), PathBuf::from("<end record>")),
            );
            joined_anchors.extend(eb.anchor.clone());
            end_before::Context {
                end_seq: eb.end_seq,
                last_line_seq: eb.last_line_seq,
                first_line: &eb.first_line,
                anchor: eb.anchor.as_ref(),
                // Placeholder: the real value is computed by
                // `engine::check` (ruling 13-V6-d7 clarification
                // 13-V6-d7a point 2) once the merged groups and
                // fork set are available. The classifier reads it
                // from the rebuilt `Context` there.
                end_anchor_matches: false,
            }
        });
        Ok(engine::check(
            collection,
            trail,
            engine::Policy {
                trust: &self.trust,
                max_age: self.max_age,
                anchors: &joined_anchors,
                start: self.start.as_ref(),
                end_ctx: end_ctx.as_ref(),
                now: self.now(),
            },
        ))
    }
    #[cfg(not(test))]
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
    #[cfg(test)]
    fn now(&self) -> SystemTime {
        self.now_override.unwrap_or_else(SystemTime::now)
    }
    /// `#[cfg(test)]` clock seam (ruling 13-V5-d6 point 2): injects the
    /// fixed instant `verify_*` reads once per call, so the rows pin
    /// the age arithmetic without any wall-clock assertion.
    #[cfg(test)]
    pub(crate) fn with_now_for_test(mut self, now: SystemTime) -> Self {
        self.now_override = Some(now);
        self
    }
}
