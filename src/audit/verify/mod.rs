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
mod receipts;
mod resume;
mod review;
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
    /// Promotes the warning to [`FindingKind::Accepted`] in place
    /// (see [`Verifier::accept`](crate::audit::Verifier::accept) and
    /// [`Verifier::accept_run`](crate::audit::Verifier::accept_run)).
    /// Clears [`Self::run_digest`] (ruling 13-V8-d1 point 4: an
    /// accepted run's digest is `None` on the finding; the digest
    /// survives inside the `was:` tail of the detail).
    pub(crate) fn accepted(mut self, by: &str, reason: &str) -> Self {
        assert!(self.accepted_kind.is_none());
        let original_kind = self.kind;
        let original_detail = std::mem::take(&mut self.detail);
        self.kind = FindingKind::Accepted;
        self.accepted_kind = Some(original_kind);
        self.run_digest = None;
        self.detail = format!("accepted by {by}: {reason}; was: {original_detail}");
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
    /// Test-only builder that sets [`Self::accepted_kind`] on a
    /// pre-built `Accepted` finding so rows can write the expected
    /// value literally, without funnelling through the `accepted()`
    /// promotion path they exercise.
    #[cfg(test)]
    pub(crate) fn with_accepted_kind(mut self, kind: FindingKind) -> Self {
        self.accepted_kind = Some(kind);
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
mod accept_resumed_tests;
#[cfg(test)]
mod accept_run_tests;
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
mod gap_anchors_tests;
#[cfg(test)]
mod gaps_tests;
#[cfg(test)]
mod live_tests;
#[cfg(test)]
mod mod_tests;
#[cfg(test)]
mod position_tests;
#[cfg(test)]
mod receipts_tests;
#[cfg(test)]
mod review_tests;
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
#[cfg(test)]
mod tests_common;
#[cfg(test)]
mod waivers_tests;

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
    /// Reconciliation runs when any of `receipts`, `waivers`,
    /// `receipts_from` or `receipts_live` has been set (ruling
    /// 13-V7-d1 points 2 and 10); see [`Self::receipts`],
    /// [`Self::waive`], [`Self::receipts_from`] and
    /// [`Self::receipts_live`]. `waivers` holds at most one entry
    /// per `seq` and `receipts_from` at most one value overall
    /// (point 6). `receipts_live` carries the stored flag and
    /// `Verifier::new` leaves it `false` (the stopped-mode default);
    /// a second [`Self::receipts_live`] call replaces its value.
    receipts: Option<std::collections::BTreeSet<(u64, [u8; 32])>>,
    waivers: std::collections::BTreeMap<u64, ([u8; 32], String)>,
    receipts_from: Option<(u64, [u8; 32], String)>,
    receipts_live: bool,
    /// Review-file `accept` lines grouped by `seq` so the engine's
    /// review pass runs in order; the inner vec holds the at-most
    /// four acceptable kinds at that `seq` (see [`Self::accept`]).
    accepts: AcceptMap,
    /// Review-file `accept-run` lines keyed by resume `seq` (see
    /// [`Self::accept_run`]).
    accepts_run: AcceptRunMap,
    #[cfg(test)]
    now_override: Option<SystemTime>,
}

/// Review-file accept set: `(kind, hash, by, reason)` per `seq`.
/// See [`Verifier::accept`].
pub(crate) type AcceptEntry = (FindingKind, [u8; 32], String, String);
pub(crate) type AcceptMap = std::collections::BTreeMap<u64, Vec<AcceptEntry>>;
/// Review-file `accept-run` set: one `(resume_hash, run_digest, by,
/// reason)` per `seq` (ruling 13-V8-d1 point 2; a duplicate `seq` is
/// `InvalidConfig`). See [`Verifier::accept_run`].
pub(crate) type AcceptRunEntry = ([u8; 32], [u8; 32], String, String);
pub(crate) type AcceptRunMap = std::collections::BTreeMap<u64, AcceptRunEntry>;

/// Non-empty, single-line reason check for waivers and the `from`
/// input (ruling 13-V7-d1 point 6). Otherwise `InvalidConfig` with
/// `<label>` naming the field.
fn validate_reason(reason: String, label: &str) -> Result<String, AuditError> {
    if reason.is_empty() || reason.contains('\n') || reason.contains('\r') {
        return Err(AuditError::new(
            AuditErrorKind::InvalidConfig,
            format!("{label} must be a non-empty single line (no LF or CR)"),
        ));
    }
    Ok(reason)
}

/// Reviewer token check for [`Verifier::accept`] and
/// [`Verifier::accept_run`] (ruling 13-V8-d1 point 2): non-empty
/// with no ASCII whitespace and no ASCII control bytes. `label`
/// names the field in the `InvalidConfig` message so callers keep
/// their stable error wording.
fn validate_reviewer(by: String, label: &str) -> Result<String, AuditError> {
    if by.is_empty()
        || by
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(AuditError::new(
            AuditErrorKind::InvalidConfig,
            format!("{label} must be a single token (no whitespace or control bytes)"),
        ));
    }
    Ok(by)
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
            receipts: None,
            waivers: std::collections::BTreeMap::new(),
            receipts_from: None,
            receipts_live: false,
            accepts: AcceptMap::new(),
            accepts_run: AcceptRunMap::new(),
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
    /// An anchor whose `seq` lies inside a **confirmed** resume gap
    /// whose opening checkpoint is itself **anchored** (an input
    /// anchor on the verified trail with the opening's full `(trail,
    /// seq, hash)`) is **set aside** as one unlocated
    /// [`FindingKind::LostRecord`] (info) at the anchor's `seq`, with
    /// detail `anchor seq <a> hash blake3:<64 hex>: lost in gap
    /// <a>..=<b>` (ADR-0005 decision 5 "Receipts lost with a
    /// resume"; ruling 13-V7-d1 point 8). The ordinary mismatch
    /// check is replaced, and the demoted anchor is counted by the
    /// gap's `lost_records=<n>` in the [`FindingKind::Resumed`]
    /// detail. Another trail's anchor is never set aside here, by
    /// the precedence above, so it still gives `AnchorMismatch …
    /// trail differs`. An anchor at the opening's `seq` with another
    /// hash does not anchor the opening: the match rule is the full
    /// `(trail, seq, hash)` triple (ruling 13-V6-d1 point 2), and a
    /// receipt or an `accept` line is a text line, not an anchor,
    /// and never anchors an opening. In any other gap state
    /// (unconfirmed, or confirmed with an unanchored opening), an
    /// anchor inside the gap keeps `AnchorMismatch`.
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
    /// grammar above, or when [`Self::max_age`] or
    /// [`Self::receipts_live`]`(true)` was already called on this
    /// verifier (ADR-0005 §19.2; ruling 13-V6-d4 point 7 and ruling
    /// 13-V7-d1 point 10): each pair is mutually exclusive, and the
    /// error is raised by whichever call comes second. A second
    /// `end_before` call replaces the first. `receipts_live(false)`
    /// is the stopped-mode default and does not conflict.
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
        if self.receipts_live {
            return Err(AuditError::new(
                AuditErrorKind::InvalidConfig,
                "end_before conflicts with receipts_live",
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
    /// Reconciles the application's stored receipts against the
    /// verified history (ADR-0005 decision 5 "Receipt reconciliation";
    /// ruling 13-V7-d1 points 2-5 and clarification 13-V7-d1a). Each
    /// receipt is `(seq, hash)` with the raw blake3 bytes.
    ///
    /// **The rule.** The call turns reconciliation on; without it,
    /// and without [`Self::waive`] or [`Self::receipts_from`],
    /// nothing is reconciled. A second call adds to the receipt set,
    /// so several batches can be supplied in sequence; identical
    /// receipts collapse, and two receipts for one `seq` are each
    /// evaluated independently. The reconciled range runs from
    /// `seq 0`, or from the accepted [`Self::start_from`] start,
    /// through the last record in the files. The end record of a
    /// [`Self::end_before`] batch is not reconciled; a receipt naming
    /// an end-record line is still matched. A receipt below the
    /// accepted start or above the end's last line's `seq` is set
    /// aside through the shared position classifier as
    /// [`OutOfRange`](FindingKind::OutOfRange) /
    /// [`UnanchoredStart`](FindingKind::UnanchoredStart) /
    /// [`UnanchoredEnd`](FindingKind::UnanchoredEnd), subject
    /// `receipt seq <s> hash blake3:<64 hex>`.
    ///
    /// See [`FindingKind::NoReceipt`] and
    /// [`FindingKind::ReceiptMismatch`] for the detail grammars.
    /// For a running trail, see [`Self::receipts_live`].
    ///
    /// **Resume-gap confirmation.** A receipt that names a resume
    /// record's `(seq, hash)` **confirms** that resume's gap under
    /// the shared match rule (ADR-0005 decision 5 "Receipts lost
    /// with a resume"; ruling 13-V7-d1 points 8-9). Inside a
    /// confirmed gap each receipt, waiver and [`Self::receipts_from`]
    /// becomes one [`LostRecord`](FindingKind::LostRecord) (info)
    /// instead of a mismatch; the number of such findings in a gap
    /// is reported as `lost_records=<n>` in the gap's
    /// [`Resumed`](FindingKind::Resumed) detail. The rule applies
    /// only to candidates whose opening checkpoint passes the trust
    /// filter ([`BadSignature`](FindingKind::BadSignature) /
    /// [`UntrustedKey`](FindingKind::UntrustedKey) predicate) and
    /// the fail-closed fold filter (ruling 13-V4-d10 point 4). A
    /// shipped-only opening is never fold-matched (owner decision
    /// 13-V4-d7; spike #224), so a Collector copy of the opening
    /// cannot confirm a gap. Anchors and `through=` pins inside a
    /// confirmed gap are demoted to `LostRecord` only when the gap's
    /// opening checkpoint is itself anchored (ruling 13-V7-d1 point
    /// 8): see [`Self::anchor`] and
    /// [`FindingKind::RevocationMismatch`] for that half; a receipt
    /// or an `accept` line is a text line, not an anchor, and never
    /// anchors an opening.
    pub fn receipts(mut self, receipts: impl IntoIterator<Item = (u64, [u8; 32])>) -> Self {
        let set = self
            .receipts
            .get_or_insert_with(std::collections::BTreeSet::new);
        set.extend(receipts);
        self
    }
    /// Waives one unreceipted `audit.record` on its exact `(seq,
    /// hash)` so a crashed writer's orphan is reviewable rather than
    /// a plain [`NoReceipt`](FindingKind::NoReceipt) (ADR-0005
    /// decision 5 "Waivers, for an honest crash"; ruling 13-V7-d1
    /// point 6). The call also turns reconciliation on, so a waiver
    /// alone still reports every other in-range record as
    /// `NoReceipt`. The match rule is [`Self::receipts`]' rule under
    /// subject `waive seq <s> hash blake3:<64 hex>`: a match emits
    /// one [`ReceiptWaived`](FindingKind::ReceiptWaived) at the
    /// record (see that kind for the detail grammar) and suppresses
    /// `NoReceipt` there; a mismatch is `ReceiptMismatch` with that
    /// subject; a waiver below the start or above the end is set
    /// aside. The hash pins the record, so a waiver cannot be moved:
    /// if the record at `<seq>` differs, it is `ReceiptMismatch` and
    /// still `NoReceipt`, never silently applied to the replacement.
    ///
    /// `reason` is accepted verbatim once it is non-empty and
    /// single-line (no LF or CR); whitespace is not trimmed, so a
    /// whitespace-only reason (for example `"   "`) is accepted and
    /// appears verbatim in the `ReceiptWaived` or `ReceiptMismatch`
    /// detail.
    ///
    /// **Review criterion** (ADR-0005 decision 5; vigil cannot apply
    /// it itself). A record may be waived only if its **full hashed
    /// content** equals an entry in the application's durable request
    /// log --- written and fsynced before `record` and marked done
    /// once the receipt is stored --- no other waiver uses that
    /// entry, and the record's time lies between the entry and the
    /// crash. Any other unreceipted record is tampering, not a crash.
    ///
    /// # Errors
    /// Returns [`InvalidConfig`](AuditErrorKind::InvalidConfig) when
    /// `reason` is empty or contains LF/CR, or when a waiver for the
    /// same `seq` was already registered (ruling 13-V7-d1 point 6).
    /// The error's message names the failed check: `waive reason must
    /// be a non-empty single line (no LF or CR)` or `duplicate waive
    /// for seq <s>`.
    pub fn waive(
        mut self,
        seq: u64,
        hash: [u8; 32],
        reason: impl Into<String>,
    ) -> Result<Self, AuditError> {
        let reason = validate_reason(reason.into(), "waive reason")?;
        if self.waivers.contains_key(&seq) {
            return Err(AuditError::new(
                AuditErrorKind::InvalidConfig,
                format!("duplicate waive for seq {seq}"),
            ));
        }
        self.waivers.insert(seq, (hash, reason));
        Ok(self)
    }
    /// Pins a late-adoption deployment's receipt coverage at `(seq,
    /// hash)`: records up to and including that one are not
    /// reconciled (ADR-0005 decision 5 "Late adoption"; ruling
    /// 13-V7-d1 point 6). The call also turns reconciliation on. The
    /// match rule is [`Self::receipts`]' rule under subject
    /// `from seq <s> hash blake3:<64 hex>`: a match emits one
    /// [`ReceiptWaived`](FindingKind::ReceiptWaived) at the record
    /// (see that kind for the detail grammar) and exempts every
    /// record at or below `s` from reconciliation; a mismatch is
    /// `ReceiptMismatch` and exempts nothing, so a mismatched `from`
    /// cannot silently cover a rewritten prefix; a `from` below the
    /// start or above the end is set aside.
    ///
    /// `reason` is accepted verbatim once it is non-empty and
    /// single-line (no LF or CR); whitespace is not trimmed, so a
    /// whitespace-only reason (for example `"   "`) is accepted and
    /// appears verbatim in the `ReceiptWaived` or `ReceiptMismatch`
    /// detail.
    ///
    /// # Errors
    /// Returns [`InvalidConfig`](AuditErrorKind::InvalidConfig) when
    /// `reason` is empty or contains LF/CR, or when `receipts_from`
    /// was already called on this verifier (ruling 13-V7-d1 point 6).
    /// The error's message names the failed check:
    /// `receipts_from reason must be a non-empty single line (no LF
    /// or CR)` or `duplicate receipts_from`.
    pub fn receipts_from(
        mut self,
        seq: u64,
        hash: [u8; 32],
        reason: impl Into<String>,
    ) -> Result<Self, AuditError> {
        let reason = validate_reason(reason.into(), "receipts_from reason")?;
        if self.receipts_from.is_some() {
            return Err(AuditError::new(
                AuditErrorKind::InvalidConfig,
                "duplicate receipts_from",
            ));
        }
        self.receipts_from = Some((seq, hash, reason));
        Ok(self)
    }
    /// Reconciles against a running trail, so in-flight records --
    /// returned from `record` but whose receipt is not stored yet --
    /// do not fail verification (ADR-0005 decision 5 "Live trails";
    /// ruling 13-V7-d1 point 10 and its clarification 13-V7-d1b).
    /// The call also turns reconciliation on (point 2).
    ///
    /// **The cut.** The checked range ends at the longest fully
    /// reconciled prefix: just before the first in-range
    /// `audit.record` that is neither matched by a receipt
    /// ([`Self::receipts`]), nor waived ([`Self::waive`]), nor
    /// exempted by a matched [`Self::receipts_from`]. It never goes
    /// above the highest matched evidence either --- matched
    /// receipts, matched waivers and a matched `from` all count
    /// toward the cap (clarification 13-V7-d1b point 1), so a
    /// late-adoption deployment's exempted history and an
    /// above-the-receipts waiver are not reported as `Unreconciled`.
    /// The comparison is `seq <= highest evidence`, so a receipt at
    /// `u64::MAX` cannot wrap or panic (point 3). With no matched
    /// evidence, the first record of the range is the cut and the
    /// whole range is one `Unreconciled`. Checkpoints need no
    /// receipt, so they never break the prefix; a checkpoint above
    /// the highest matched evidence is still `Unreconciled`, and
    /// the operator can include the checkpoint receipts that
    /// [`AuditTrail::close`] and [`AuditTrail::checkpoint`] return
    /// to extend the cap through it (clarification 13-V7-d1b point
    /// 2; ADR-0005 decision 9). One
    /// [`Unreconciled`](FindingKind::Unreconciled) (info) is reported
    /// at the first record above the cut; records above the cut get
    /// no [`NoReceipt`](FindingKind::NoReceipt). Nothing above the
    /// cut yields no `Unreconciled`.
    ///
    /// **Receipts above the cut are still checked.** A wrong hash
    /// or a receipt above the head stays
    /// [`ReceiptMismatch`](FindingKind::ReceiptMismatch).
    ///
    /// **Export order.** The receipts export must be taken BEFORE
    /// the trail is read (ADR-0005 decision 5 "Live trails"), so
    /// every honest receipt is in the files and a receipt above the
    /// head still means a rollback. An honest hole closes once its
    /// receipt is stored; a forged record is a hole that never
    /// closes, so `Unreconciled` keeps starting at the same `seq`
    /// across reviews and stopped-trail reconciliation reports it as
    /// `NoReceipt`.
    ///
    /// [`AuditTrail::close`]: crate::audit::AuditTrail::close
    /// [`AuditTrail::checkpoint`]: crate::audit::AuditTrail::checkpoint
    ///
    /// **Severity and exit.** [`FindingKind::Unreconciled`] is info,
    /// so `is_valid()` is `true`; [`Report::is_strict_valid`] already
    /// fails on it, so the exit is 0 without `--strict` and 1 with
    /// it. The rotation procedure (ADR-0005 decision 9) and any
    /// review of a stopped trail never call `receipts_live(true)`.
    ///
    /// A second `receipts_live` call replaces the first.
    /// `receipts_live(false)` is the stopped-mode default.
    ///
    /// # Errors
    /// Returns [`InvalidConfig`](AuditErrorKind::InvalidConfig) with
    /// message `receipts_live conflicts with end_before` when `on`
    /// is `true` and [`Self::end_before`] was already called on this
    /// verifier (ADR-0005 §19.2; ruling 13-V7-d1 point 10):
    /// `receipts_live(true)` and `end_before` are mutually
    /// exclusive, and the error is raised by whichever call comes
    /// second. `receipts_live(false)` with `end_before` is allowed.
    pub fn receipts_live(mut self, on: bool) -> Result<Self, AuditError> {
        if on && self.end_before.is_some() {
            return Err(AuditError::new(
                AuditErrorKind::InvalidConfig,
                "receipts_live conflicts with end_before",
            ));
        }
        self.receipts_live = on;
        Ok(self)
    }
    /// Accepts one honest warning so a recorded human sign-off
    /// promotes it to [`FindingKind::Accepted`] (ADR-0005
    /// decision 11 "Review file"; ruling 13-V8-d1).
    ///
    /// `kind` is one of [`FindingKind::TornWrite`],
    /// [`FindingKind::Resumed`], [`FindingKind::ClockWentBackwards`]
    /// or [`FindingKind::DuplicateRecord`] (`OperatorText` joins
    /// when amendment 13 lands). Errors are never acceptable.
    ///
    /// The pin `(seq, hash)` names the record for non-`TornWrite`
    /// kinds; for `TornWrite` it names the last complete record
    /// before the gap in its file plus the gap digest. Only a
    /// **trailing** `TornWrite` with at least one record before
    /// the gap can be accepted (ruling 13-V8-d1 point 5).
    ///
    /// On a match the warning becomes [`FindingKind::Accepted`]
    /// in place. A matched, in-range `accept Resumed` line also
    /// **confirms** that resume's gap under the same match rule
    /// (ADR-0005 decision 5 "Receipts lost with a resume" and
    /// decision 11), so every receipt, waiver,
    /// [`Self::receipts_from`] and `accept` line inside the gap
    /// becomes one [`FindingKind::LostRecord`] (never anchors or
    /// `through=` pins, which need the gap's opening checkpoint
    /// anchored under [`Self::anchor`]); the count is reported as
    /// `lost_records=<n>` in the gap's
    /// [`FindingKind::Resumed`] detail, which the `Accepted`
    /// finding's `was:` tail then carries. A line below an accepted
    /// start or above a bounded end is set aside through the
    /// position classifier; a line inside a confirmed resume gap is
    /// one [`FindingKind::LostRecord`] counted by `lost_records=<n>`.
    /// A mismatch under the shared receipt match rule is
    /// [`FindingKind::AcceptMismatch`]; a match that finds no
    /// warning is [`FindingKind::AcceptUnused`]; a trailing
    /// `TornWrite` on a `no crash outcome` gap is
    /// `AcceptMismatch`. See the three [`FindingKind`] variants
    /// for detail grammars. No error finding can be cleared
    /// through this route.
    ///
    /// **Not detectable** (ADR-0005 decision 11): a reviewer who
    /// accepts tampering. Every acceptance is reported as
    /// [`FindingKind::Accepted`] with the reviewer token and the
    /// reason, so the decision stays attributable; anyone who can
    /// write the review file can accept warnings, but no other
    /// error.
    ///
    /// # Errors
    /// `InvalidConfig` when `kind` is not acceptable, `by` is
    /// empty or contains ASCII whitespace or a control byte,
    /// `reason` is empty or contains LF or CR, or a second
    /// `accept` for the same `(kind, seq)` is registered.
    pub fn accept(
        mut self,
        kind: FindingKind,
        seq: u64,
        hash: [u8; 32],
        by: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<Self, AuditError> {
        use FindingKind::{ClockWentBackwards, DuplicateRecord, Resumed, TornWrite};
        if !matches!(
            kind,
            TornWrite | Resumed | ClockWentBackwards | DuplicateRecord
        ) {
            return Err(AuditError::new(
                AuditErrorKind::InvalidConfig,
                format!("accept kind {kind:?} is not acceptable"),
            ));
        }
        let by = validate_reviewer(by.into(), "accept by")?;
        let reason = validate_reason(reason.into(), "accept reason")?;
        let entries = self.accepts.entry(seq).or_default();
        if entries.iter().any(|(k, _, _, _)| *k == kind) {
            return Err(AuditError::new(
                AuditErrorKind::InvalidConfig,
                format!("duplicate accept for {kind:?} seq {seq}"),
            ));
        }
        entries.push((kind, hash, by, reason));
        Ok(self)
    }
    /// Accepts one closed run through its pinned closing resume
    /// record and run digest (ADR-0005 decision 11 "Review file",
    /// `accept-run`; ruling 13-V8-d1).
    ///
    /// `seq` and `hash` pin the `vigil.audit.resume` record that
    /// closes the run; `run_digest` is that run's own digest from
    /// its [`FindingKind::SegmentStructure`] finding
    /// ([`Finding::run_digest`]). Subject in every outcome text:
    /// `accept-run seq <s> hash blake3:<64 hex>`.
    ///
    /// **On a match** the line replaces exactly these findings, and
    /// no others, with [`FindingKind::Accepted`] (items 1-3; items
    /// 4-5 follow in #13): the run's `SegmentStructure` findings
    /// (the run finding with the digest, and every per-segment one
    /// on a native segment of the run); at each loss point its
    /// [`FindingKind::ChainBroken`] and, when the range has `count
    /// > 0`, its [`FindingKind::SeqGap`]; [`FindingKind::MmrMismatch`]
    /// on every checkpoint in a segment of the run at or after the
    /// run's first loss point, excluding the closing opening
    /// checkpoint. The [`FindingKind::Resumed`] warning, the gap
    /// itself and every other finding keep their severity; receipts
    /// in range stay [`FindingKind::NoReceipt`] until item 4.
    ///
    /// **Mismatches.** No record, forked `seq`, hash-differs, "not
    /// a resume record" and "run digest differs" each give
    /// [`FindingKind::AcceptMismatch`]. A line whose resume closes
    /// no run (the run digest is then the digest of nothing) is
    /// [`FindingKind::AcceptUnused`] when the line carries that
    /// digest and `AcceptMismatch` otherwise. A line below an
    /// accepted [`Self::start_from`] start or above
    /// [`Self::end_before`]'s end is set aside; when a run's
    /// closing opening is itself the start, the line is set aside
    /// under the start rule even though the resume `seq` is in
    /// range (ruling 13-V8-d1 point 8). A line inside a confirmed
    /// resume gap is one [`FindingKind::LostRecord`].
    ///
    /// # Errors
    /// [`InvalidConfig`](AuditErrorKind::InvalidConfig) when
    /// `reviewer` is empty or contains ASCII whitespace or a control
    /// byte, `reason` is empty or contains LF or CR, or a second
    /// `accept_run` for the same `seq` is registered.
    pub fn accept_run(
        mut self,
        seq: u64,
        hash: [u8; 32],
        run_digest: [u8; 32],
        reviewer: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<Self, AuditError> {
        let by = validate_reviewer(reviewer.into(), "accept-run reviewer")?;
        let reason = validate_reason(reason.into(), "accept-run reason")?;
        if self.accepts_run.contains_key(&seq) {
            return Err(AuditError::new(
                AuditErrorKind::InvalidConfig,
                format!("duplicate accept-run for seq {seq}"),
            ));
        }
        self.accepts_run.insert(seq, (hash, run_digest, by, reason));
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
                // 13-V6-d7a) once the merged groups and fork set
                // are available. The classifier reads it from the
                // rebuilt `Context` there.
                end_anchor_matches: false,
            }
        });
        let empty_receipts: std::collections::BTreeSet<(u64, [u8; 32])> =
            std::collections::BTreeSet::new();
        let reconcile = self.receipts.is_some()
            || !self.waivers.is_empty()
            || self.receipts_from.is_some()
            || self.receipts_live;
        let receipt_inputs = reconcile.then(|| receipts::Inputs {
            receipts: self.receipts.as_ref().unwrap_or(&empty_receipts),
            waivers: &self.waivers,
            receipts_from: self.receipts_from.as_ref(),
            live: self.receipts_live,
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
                receipts: receipt_inputs.as_ref(),
                accepts: &self.accepts,
                accepts_run: &self.accepts_run,
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
