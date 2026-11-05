//! Shared pure per-record state machine for the reader (`storage.rs`) and
//! future verifier (#13 V4a/V4b). ADR-0005 amendment 6 "Base", "Sequence
//! gaps inside a run", "Run boundaries", amendment 9 part 1 (genesis base),
//! and rulings 13-V4-d1/d3/d4, B3d1-d1/d3/d4, 107-d1. Issue #197 R1/R2.
//!
//! No I/O. No locks. No writer-only state. Owns `apply_checked`, the
//! resume-declaration validator and the MMR fold (iii). The reader embeds
//! [`RunState`] inside [`super::storage::State`]; writer bookkeeping
//! (`checkpoint_time`, `since_checkpoint`), the walk cursor (`offset`,
//! `length`, `newline`) and the gap-hasher stay in `State`.
//!
//! The strict and tolerant [`Classifier`] paths, with [`check_attestation`],
//! are the reader's first-violation oracle (the reader's per-path order
//! binds; ruling 197-d1 addenda 7 and 12). Classification sites return
//! typed [`Violation`] variants (ruling 197-d1 addendum 16, point 3), and
//! the one dispatcher [`Classifier::on_violation`] turns a [`Violation`]
//! into the reader's [`AuditError`] under reaction [`Reaction::Stop`] or
//! records it into the per-segment violations vector under reaction
//! [`Reaction::Collect`] (addendum 16 point 1). The every-violation
//! collector (see [`Classifier::new_collect`]) accumulates each typed
//! [`Violation`] for the verifier's V4a walk; the `classify` iterator
//! wrapper (#197 R2b S3b) consumes it. Nothing outside the reader or the
//! verifier may call this module as a first-violation oracle.
//!
//! **S3a scope (ruling 197-d1 addendum 18):** [`Reaction::Collect`] in
//! this slice runs **tolerant mode only** -- the only constructor is
//! [`Classifier::new_collect`], which builds a tolerant classifier.
//! Strict-mode Collect, a Collect entry for a `Record(Err)` line, and
//! the collector-first-equals-reader-first sweep over the strict
//! single-segment paths land in **#197 R2b S3a′**; until then the
//! collector is not a first-violation oracle for any strict path, and
//! no caller may treat it as one.
//!
//! Addendum 16 point 2: on a fold (iii) mismatch the record-apply callsite
//! inside the [`Classifier`] special-cases [`Reaction::Collect`] and
//! re-applies through [`apply_checked`] with `compare_mmr = false`,
//! splicing-in the checkpoint's declared MMR (no hand-built MMR, no
//! hand-built `RunState`). Any other violation ends the run under
//! consideration and resumes at the next segment boundary
//! ([`Classifier::reset_at_boundary`]); the tolerant finish-time checks
//! (`invalid undamaged segment`, `first successor lacks resume`,
//! `resume checkpoint lacks its declaration`) are recorded in Collect mode
//! too (addendum 16 point 5).
use super::{
    AuditError, Mmr, Record,
    format::Kind,
    storage::{Head, corrupt},
};

/// Typed enumeration of every `CorruptTrail` detail string the pure
/// classifier emits (ruling 13-V4-d4 point 1, 197-d1 addendum 16 point 3).
/// Each site in [`Classifier`] constructs a [`Violation`] variant directly;
/// the one dispatcher [`Classifier::on_violation`] turns it into the
/// reader's [`AuditError`] under [`Reaction::Stop`] or records it under
/// [`Reaction::Collect`]. The syn coverage gate counts every `Violation::X`
/// construction site in `runs.rs` plus every `corrupt("literal")` in
/// `storage.rs` (addendum 16 point 4). [`Violation::ALL`] enumerates every
/// variant (proven exhaustive by the `violation_detail_roundtrip` unit
/// test).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Violation {
    MissingInitialCheckpoint,
    InitialCheckpointDoesNotLinkGenesis,
    InvalidOpeningPeaks,
    RecordRolledBack,
    SequenceGapLacksResume,
    SequenceGapWithoutCheckpoint,
    CheckpointMmrDiffers,
    ResumeWithoutPredecessor,
    ResumeNotAfterCheckpoint,
    ResumeWithoutDetails,
    MmrOverflow,
    MissingOrMismatchedAttestation,
    InvalidResumeDetails,
    InvalidResumeLossBound,
    InvalidResumeHead,
    InvalidResumeHeadSequence,
    ResumeAfterCreationCheckpoint,
    ResumeDeclarationDoesNotDescribeGap,
    InvalidLineOrOpeningCheckpoint,
    MultipleRecordsInLine,
    TrailIdentityDiffers,
    OpeningCheckpointDuplicatesPredecessor,
    MissingOpeningCheckpoint,
    UnclosedSegmentLacksResume,
    EmptyLiveFile,
    MissingHead,
    ResumeCheckpointLacksDeclaration,
    InvalidRecordInSealedRun,
    UnparsableBeforeRecord,
    SequenceDidNotIncrease,
    SequenceGapInSealedRun,
    FirstSuccessorDoesNotCloseRun,
    FirstSuccessorLacksImmediateResume,
    FirstSuccessorLacksResume,
    InvalidUndamagedSegment,
}

impl Violation {
    /// The byte-identical detail string the reader emits at this site.
    pub(crate) fn detail(self) -> &'static str {
        match self {
            Self::MissingInitialCheckpoint => "missing initial checkpoint",
            Self::InitialCheckpointDoesNotLinkGenesis => "initial checkpoint does not link genesis",
            Self::InvalidOpeningPeaks => "invalid opening peaks",
            Self::RecordRolledBack => "record rolled back, changed or broke its hash link",
            Self::SequenceGapLacksResume => "sequence gap lacks a resume declaration",
            Self::SequenceGapWithoutCheckpoint => "sequence gap without checkpoint",
            Self::CheckpointMmrDiffers => "checkpoint MMR differs from preceding records",
            Self::ResumeWithoutPredecessor => "resume without predecessor",
            Self::ResumeNotAfterCheckpoint => "resume not immediately after checkpoint",
            Self::ResumeWithoutDetails => "resume without details",
            Self::MmrOverflow => "MMR overflow",
            Self::MissingOrMismatchedAttestation => "missing or mismatched repair attestation",
            Self::InvalidResumeDetails => "invalid resume details",
            Self::InvalidResumeLossBound => "invalid resume loss bound",
            Self::InvalidResumeHead => "invalid resume head",
            Self::InvalidResumeHeadSequence => "invalid resume head sequence",
            Self::ResumeAfterCreationCheckpoint => "resume after creation checkpoint",
            Self::ResumeDeclarationDoesNotDescribeGap => {
                "resume declaration does not describe its gap"
            }
            Self::InvalidLineOrOpeningCheckpoint => "invalid audit line or opening checkpoint",
            Self::MultipleRecordsInLine => "multiple records in native audit line",
            Self::TrailIdentityDiffers => "trail identity differs from marker",
            Self::OpeningCheckpointDuplicatesPredecessor => {
                "opening checkpoint duplicates predecessor"
            }
            Self::MissingOpeningCheckpoint => "missing opening checkpoint",
            Self::UnclosedSegmentLacksResume => "unclosed segment lacks matching immediate resume",
            Self::EmptyLiveFile => "empty live file or missing opening checkpoint",
            Self::MissingHead => "missing head",
            Self::ResumeCheckpointLacksDeclaration => "resume checkpoint lacks its declaration",
            Self::InvalidRecordInSealedRun => "invalid audit record in sealed run",
            Self::UnparsableBeforeRecord => "unparsable line before complete record",
            Self::SequenceDidNotIncrease => "record sequence did not increase inside sealed run",
            Self::SequenceGapInSealedRun => "sequence gap inside sealed run segment",
            Self::FirstSuccessorDoesNotCloseRun => "first successor does not close sealed run",
            Self::FirstSuccessorLacksImmediateResume => "first successor lacks immediate resume",
            Self::FirstSuccessorLacksResume => "first successor lacks resume",
            Self::InvalidUndamagedSegment => "invalid undamaged segment",
        }
    }

    /// Exhaustive enumeration of every [`Violation`] variant; the
    /// `violation_detail_roundtrip` unit test asserts no two variants
    /// share a detail string, and the coverage gate consults it to map
    /// each `Violation::<X>` construction site in `runs.rs` to its
    /// `detail()` string (addendum 16 point 4).
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "consumed by the Violation roundtrip unit test and the coverage_gate_pins_every_corrupt_site test (both #[cfg(test)]); between S3a and S3b nothing in non-test code enumerates the variants"
        )
    )]
    pub(crate) const ALL: &'static [Self] = &[
        Self::MissingInitialCheckpoint,
        Self::InitialCheckpointDoesNotLinkGenesis,
        Self::InvalidOpeningPeaks,
        Self::RecordRolledBack,
        Self::SequenceGapLacksResume,
        Self::SequenceGapWithoutCheckpoint,
        Self::CheckpointMmrDiffers,
        Self::ResumeWithoutPredecessor,
        Self::ResumeNotAfterCheckpoint,
        Self::ResumeWithoutDetails,
        Self::MmrOverflow,
        Self::MissingOrMismatchedAttestation,
        Self::InvalidResumeDetails,
        Self::InvalidResumeLossBound,
        Self::InvalidResumeHead,
        Self::InvalidResumeHeadSequence,
        Self::ResumeAfterCreationCheckpoint,
        Self::ResumeDeclarationDoesNotDescribeGap,
        Self::InvalidLineOrOpeningCheckpoint,
        Self::MultipleRecordsInLine,
        Self::TrailIdentityDiffers,
        Self::OpeningCheckpointDuplicatesPredecessor,
        Self::MissingOpeningCheckpoint,
        Self::UnclosedSegmentLacksResume,
        Self::EmptyLiveFile,
        Self::MissingHead,
        Self::ResumeCheckpointLacksDeclaration,
        Self::InvalidRecordInSealedRun,
        Self::UnparsableBeforeRecord,
        Self::SequenceDidNotIncrease,
        Self::SequenceGapInSealedRun,
        Self::FirstSuccessorDoesNotCloseRun,
        Self::FirstSuccessorLacksImmediateResume,
        Self::FirstSuccessorLacksResume,
        Self::InvalidUndamagedSegment,
    ];
}

impl From<Violation> for AuditError {
    fn from(v: Violation) -> Self {
        corrupt(v.detail())
    }
}

/// Reaction of the one [`Classifier`] to a [`Violation`] at a check site
/// (ruling 197-d1 addendum 16 point 1). [`Reaction::Stop`] returns
/// `Err(v.into())` from the enclosing method, byte-identical to today's
/// reader. [`Reaction::Collect`] records `(position, v)` into the per-
/// segment violations vector and latches `recovery_pending` so subsequent
/// feeds are no-ops until the next [`Classifier::reset_at_boundary`]
/// (ruling 197-d1 point 4 "ends the run under consideration"). The fold
/// (iii) salvage in the record-apply callsite is the one asymmetric site:
/// under [`Reaction::Collect`] the mismatch is recorded without latching
/// and classification continues via `apply_checked(.., compare_mmr=false)`.
///
/// **S3a scope (ruling 197-d1 addendum 18):** [`Reaction::Collect`] is
/// wired to **tolerant mode only** in S3a. The only constructor is
/// [`Classifier::new_collect`] (tolerant); there is no strict-mode
/// collect constructor and no Collect entry for a `Record(Err)` line.
/// Strict×Collect and the strict first-equality sweep land in
/// **#197 R2b S3a′**.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reaction {
    /// Return the violation as an [`AuditError`] from the enclosing
    /// [`Classifier`] method (the reader's today-identical behaviour).
    Stop,
    /// Record `(position, v)` and continue under ruling 197-d1 point 4.
    /// Used by [`Classifier::new_collect`]. **S3a wires this to tolerant
    /// mode only (ruling 197-d1 addendum 18); strict-mode Collect lands
    /// in #197 R2b S3a′.**
    Collect,
}

/// Position of a recorded [`Violation`] within the collector's walk, as a
/// `(segment_index, record_index)` pair (both 0-based). The caller of
/// [`Classifier::reset_at_boundary`] threads `segment_index` across
/// segments; the per-feed `record_index` is passed in by the caller
/// (S3b's `classify` iterator supplies it per segment; S3a's own unit
/// rows drive it directly).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CollectorPos {
    pub(crate) segment_index: usize,
    pub(crate) record_index_in_segment: usize,
}

/// Terminal outcome of a collector-mode segment scan
/// ([`Classifier::finish_collect`]). The final `state` is the pure
/// `RunState` the classifier ends on (possibly `None` when no complete
/// record was folded), `run_flag` is the owned `*run` flag (as
/// [`TolerantFinishOutcome::run_flag`]), `violations` is the accumulated
/// typed violations in feed order, and `gap` is the gap hasher the
/// caller threads forward.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "fields consumed by #197 R2b S3b's classify iterator and V4a; between S3a and S3b only #[cfg(test)] rows construct a CollectorOutcome"
    )
)]
pub(crate) struct CollectorOutcome {
    pub(crate) state: Option<RunState>,
    pub(crate) run_flag: bool,
    pub(crate) violations: Vec<(CollectorPos, Violation)>,
    pub(crate) gap: Option<blake3::Hasher>,
}

/// Per-record state machine shared by the reader and the future verifier
/// (#197 R1). The reader embeds this inside `storage::State`; the writer
/// bookkeeping (`checkpoint_time`, `since_checkpoint`), the walk cursor and
/// the gap-hasher stay in `State`.
#[derive(Clone)]
pub(crate) struct RunState {
    /// Sequence and hash of the last complete record (ADR-0005 d2/d7).
    pub(crate) head: Head,
    /// Running MMR fold up to [`head`](Self::head); closing checkpoint compares it with fold (iii) (B3d1-d1/d4).
    pub(crate) mmr: Mmr,
    /// True when [`head`](Self::head) is a `Kind::Checkpoint`.
    pub(crate) checkpoint: bool,
    /// A sequence gap is pending its closing resume declaration (ADR-0005 amendment 6).
    pub(crate) pending_resume: bool,
    /// A broken hash link in the pending run, cleared by its closing resume.
    pub(crate) run_loss: bool,
    /// Record before the last checkpoint; the resume declaration must name this seq (B3d1-d1).
    pub(crate) checkpoint_predecessor: Option<Head>,
    /// `context.previous` of the last checkpoint; the resume declaration must digest-match it (B3d1-d3).
    pub(crate) checkpoint_previous: [u8; 32],
}

/// Advances [`RunState`] by one complete record. Returns the new state on
/// success, `Ok(None)` for a collector-style identical duplicate, and a
/// typed [`Violation`] variant whose [`Violation::detail`] matches the
/// reader's inline per-record state machine (ruling 13-V4-d4 point 1,
/// 197-d1 addendum 16 point 3); the reader's shim delegates here.
/// `broken_boundary` disables the hash-link and in-run seq-gap checks at a
/// damaged run entry (B3d1-d1/d3); `compare_mmr` disables the fold (iii)
/// comparison inside a run segment whose preceding records may be lost
/// (B3d1-d1/d4) AND is the salvage switch the collector flips to splice-in
/// the record after a recorded [`Violation::CheckpointMmrDiffers`]
/// (addendum 16 point 2); `genesis` forces the
/// `(genesis || seq == 0) && !root_link` path (staging settlement and the
/// amendment-9 genesis closer).
pub(crate) fn apply_checked(
    prior: Option<&RunState>,
    record: &Record,
    genesis: bool,
    broken_boundary: bool,
    compare_mmr: bool,
) -> Result<Option<RunState>, Violation> {
    let head = Head::of(record);
    let root_link =
        prior.is_none() && record.context.previous == Record::genesis(&record.context.trail);
    // A root checkpoint above zero declares loss and needs an immediate resume;
    // an archived prefix instead carries its predecessor hash and MMR (d2/d8).
    let mut pending = prior.is_none() && head.seq > 0 && root_link;
    let mut mmr = if let Some(s) = prior {
        s.mmr.clone()
    } else {
        let Kind::Checkpoint(cp) = &record.kind else {
            return Err(Violation::MissingInitialCheckpoint);
        };
        if (genesis || head.seq == 0) && !root_link {
            return Err(Violation::InitialCheckpointDoesNotLinkGenesis);
        }
        if root_link && head.seq > 0 {
            // Amendment 9: the lost creation hash is unavailable. Both reader
            // paths authenticate the computable genesis leaf through this fold.
            let mut fold = Mmr::new();
            fold.push(Record::genesis(&record.context.trail))
                .map_err(|_| Violation::MmrOverflow)?;
            fold
        } else {
            Mmr::from_peaks(cp.size, cp.peaks.clone())
                .map_err(|_| Violation::InvalidOpeningPeaks)?
        }
    };
    let predecessor = prior.map(|s| s.head);
    if let Some(s) = prior {
        if head == s.head {
            return Ok(None);
        } // Collector-style identical duplicates add no leaf.
        if head.seq <= s.head.seq || (!broken_boundary && record.context.previous != s.head.hash) {
            return Err(Violation::RecordRolledBack);
        }
        if s.pending_resume
            && !matches!(&record.kind, Kind::Entry(e) if e.action == "vigil.audit.resume")
        {
            return Err(Violation::SequenceGapLacksResume);
        }
        if !broken_boundary && head.seq != s.head.seq + 1 {
            if !matches!(record.kind, Kind::Checkpoint(_)) {
                return Err(Violation::SequenceGapWithoutCheckpoint);
            }
            pending = true;
        }
    }
    match &record.kind {
        Kind::Checkpoint(cp) => {
            if compare_mmr
                && (cp.size != mmr.size() || cp.root != mmr.root() || cp.peaks != mmr.peaks())
            {
                return Err(Violation::CheckpointMmrDiffers);
            }
        }
        Kind::Entry(entry) if entry.action == "vigil.audit.resume" => {
            let s = prior.ok_or(Violation::ResumeWithoutPredecessor)?;
            if !s.checkpoint {
                return Err(Violation::ResumeNotAfterCheckpoint);
            }
            let details = entry
                .details
                .as_deref()
                .ok_or(Violation::ResumeWithoutDetails)?;
            validate_resume(details, s, record)?;
        }
        Kind::Entry(_) => {}
    }
    mmr.push(head.hash).map_err(|_| Violation::MmrOverflow)?;
    Ok(Some(RunState {
        head,
        mmr,
        checkpoint: matches!(record.kind, Kind::Checkpoint(_)),
        pending_resume: pending,
        run_loss: broken_boundary || prior.is_some_and(|s| s.run_loss),
        checkpoint_predecessor: predecessor,
        checkpoint_previous: record.context.previous,
    }))
}

/// Checks the repair attestation of a fragment gap: the record after the
/// gap must carry `repaired` equal to the digest of the gap's bytes. The
/// reader calls this at its per-path position (ruling 197-d1 addendum 12)
/// so the reader's first violation is unchanged (see the module doc).
pub(crate) fn check_attestation(
    digest: Option<[u8; 32]>,
    repaired: Option<[u8; 32]>,
) -> Result<(), Violation> {
    if let Some(d) = digest
        && repaired != Some(d)
    {
        return Err(Violation::MissingOrMismatchedAttestation);
    }
    Ok(())
}

/// Parses the three positional fields of a resume `details` string; shared
/// with the reader's `resume_header` (ruling 13-V4-d4 point 1).
pub(crate) fn resume_details(details: &str) -> Result<(&str, &str, &str), Violation> {
    let (named, file) = details
        .split_once(" file=")
        .ok_or(Violation::InvalidResumeDetails)?;
    let (named, lost) = named
        .split_once(" lost_through=")
        .ok_or(Violation::InvalidResumeLossBound)?;
    Ok((named, lost, file))
}

/// Validates the resume declaration carried in a `vigil.audit.resume`
/// entry's `details`, emitting the exact first-violation [`Violation`]
/// variant `storage::apply_checked` would emit (ruling 13-V4-d4 point 1).
fn validate_resume(details: &str, s: &RunState, record: &Record) -> Result<(), Violation> {
    let (named, lost, file) = resume_details(details)?;
    let (seq_text, hash) = named
        .strip_prefix("head=")
        .and_then(|v| v.split_once(':'))
        .ok_or(Violation::InvalidResumeHead)?;
    let seq = seq_text
        .parse::<u64>()
        .map_err(|_| Violation::InvalidResumeHeadSequence)?;
    let bound = s
        .head
        .seq
        .checked_sub(1)
        .ok_or(Violation::ResumeAfterCreationCheckpoint)?;
    if lost != bound.to_string()
        || seq.to_string() != seq_text
        || seq >= s.head.seq
        || hash != crate::audit::digest_string(&s.checkpoint_previous)
        || s.checkpoint_predecessor.is_some_and(|p| p.seq != seq)
        || (s.checkpoint_predecessor.is_none()
            && s.checkpoint_previous == Record::genesis(&record.context.trail)
            && seq != 0)
        || file.is_empty()
        || file.bytes().any(|b| b.is_ascii_whitespace())
    {
        return Err(Violation::ResumeDeclarationDoesNotDescribeGap);
    }
    Ok(())
}

/// Strict-mode `invalid audit line or opening checkpoint` site. `Fragment`
/// at `first`/`boundary_resume` and every `Unparsable`/`Record(Err)` payload
/// both reach this single helper, so the syn coverage gate counts one
/// `Violation::InvalidLineOrOpeningCheckpoint` construction site and the
/// pin `pin_sc_invalid_audit_line_or_opening_checkpoint` targets it at
/// occurrence 0.
fn invalid_opening_line() -> Violation {
    Violation::InvalidLineOrOpeningCheckpoint
}

/// Boundary policy for scanning one segment under ADR-0005 amendment 6.
/// Lives in the pure module so the `Classifier` and the `classify` wrapper
/// (see #197 for the follow-up slice) can consume it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SegmentContext {
    /// Whether scanning starts at the segment's opening checkpoint.
    pub(crate) opening: bool,
    /// Whether an absent predecessor requires a genesis link
    /// (staging settlement, ADR-0005 amendment 9 part 1).
    pub(crate) genesis: bool,
    /// Whether predecessor history ends inside a run that must be closed
    /// by the first successor's immediate resume.
    pub(crate) run: bool,
}

/// Classifier mode. `Strict` drives the reader's `scan_inner` family
/// (`scan_inner`/`scan`/`scan_staged`/`scan_closing`); `Tolerant` drives the
/// `history_segment` fallback walk from the saved segment-start state the
/// reader threads in on `CorruptTrail`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Strict single-pass classifier (the reader's `scan_inner` family).
    Strict,
    /// Tolerant fallback classifier (the `history_segment` fallback walk).
    Tolerant,
}

/// Outcome of one successful [`Classifier::feed_record`] call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Advance {
    /// Record folded into state; cursor advances.
    Record,
    /// Collector-style identical duplicate; prior state is unchanged.
    /// Reachable on any strict path whose segment carries two bytewise-
    /// identical records in sequence: a plain live open of `[cp0, e1, e1]`,
    /// `scan_staged`/`scan_closing` over the same layout, and a `refresh`
    /// that re-reads an already-consumed record. The reader advances
    /// offset/newline anyway; the shim leaves the writer-only fields in
    /// place on this outcome.
    Duplicate,
}

/// Resumable segment-level classifier. No I/O. The reader threads this
/// across its lock and refresh paths without buffering the trail. Push
/// API: the reader's shim performs byte-level work (reading a line,
/// running [`super::lines::classify`]) and then calls
/// [`Classifier::feed_record`], [`Classifier::feed_fragment`] or
/// [`Classifier::feed_unparsable`]. [`check_attestation`] runs **inside**
/// [`Classifier::feed_record`], after the `missing opening checkpoint`
/// check and before the `unclosed segment lacks matching immediate resume`
/// check (ruling 197-d1 addenda 7 and 12: the reader's per-path order
/// binds); the shim finalises the current gap via [`Classifier::take_gap`]
/// and hands the digest in as `gap_digest`.
///
/// Under [`Reaction::Collect`] the same [`Classifier`] becomes the
/// every-violation collector (ruling 197-d1 addendum 16): every check
/// site routes its typed [`Violation`] through the one dispatcher
/// [`Classifier::on_violation`], which records it and latches
/// `recovery_pending` instead of returning early. The record-apply
/// callsite special-cases a fold (iii) mismatch and splices-in the
/// checkpoint through [`apply_checked`] with `compare_mmr = false`.
/// **S3a wires Collect to tolerant mode only** (ruling 197-d1
/// addendum 18); strict-mode Collect lands in #197 R2b S3a′.
pub(crate) struct Classifier {
    state: Option<RunState>,
    mode: Mode,
    ctx: SegmentContext,
    first: bool,
    boundary_resume: bool,
    gap: Option<blake3::Hasher>,
    /// Tolerant-mode: saved segment-start run state. The first-record trial
    /// consults this snapshot so a closing checkpoint still compares with its
    /// predecessor's run (the reader clones the run state before the strict
    /// pass and hands it in on `CorruptTrail`).
    saved_prior: Option<RunState>,
    /// Tolerant-mode: `*run || unsealed_boundary` as set by the reader's
    /// `history_segment` shim.
    inherited: bool,
    /// Tolerant-mode: the reader's `*run` out-parameter, owned by the
    /// classifier between `new_tolerant` and `finish_tolerant`; the reader
    /// shim reads it back through [`TolerantFinishOutcome::run_flag`] on
    /// finish.
    run_flag: bool,
    /// Tolerant-mode counter: complete-record count in the fallback walk.
    count: usize,
    /// Tolerant-mode latch: a fragment or Unparsable ran before any record.
    prefix: bool,
    /// Tolerant-mode latch: the first record closed the inherited run and
    /// the next record must be its immediate `vigil.audit.resume`.
    closing: bool,
    /// Tolerant-mode latch: a closer has fired `count==1 && closing` but
    /// the EOF obligation is not yet resolved by a second complete record.
    must_close: bool,
    /// Tolerant-mode latch: a damaged line (Unparsable payload, broken
    /// opening, missing opening) demoted the segment to evidence only.
    damaged: bool,
    /// Tolerant-mode latch: an Unparsable line was observed since the last
    /// complete record; the next complete record errors
    /// `unparsable line before complete record`.
    invalid_line: bool,
    /// Tolerant-mode: `broken` flag carried from
    /// [`Classifier::feed_record_prepare_tolerant`] into
    /// [`Classifier::feed_record_apply_tolerant`] on the General branch
    /// (set when `first && previous != state.head.hash`).
    broken_from_prepare: bool,
    /// Tolerant-mode: `outside_run` flag carried from
    /// [`Classifier::feed_record_prepare_tolerant`] into
    /// [`Classifier::feed_record_apply_tolerant`] on the General branch
    /// (`inherited && !run_flag` at `prepare` time).
    outside_run_from_prepare: bool,
    /// Addendum 16 point 1: one classifier, two reactions. Strict and
    /// tolerant builders default this to [`Reaction::Stop`];
    /// [`Classifier::new_collect`] builds a tolerant classifier with
    /// [`Reaction::Collect`]. [`Classifier::on_violation`] is the one
    /// dispatcher that reads this.
    reaction: Reaction,
    /// Collect-reaction: position reported for every recorded violation.
    /// `segment_index` is threaded across segments by
    /// [`Classifier::reset_at_boundary`]; `record_index_in_segment` is
    /// bumped by each `feed_*_collect` entry point.
    current_pos: CollectorPos,
    /// Collect-reaction: accumulated violations in feed order (ruling
    /// 197-d1 addendum 16 point 1). Fed by
    /// [`Classifier::on_violation`] and by the one fold (iii) salvage
    /// callsite inside the record-apply method.
    collected: Vec<(CollectorPos, Violation)>,
    /// Collect-reaction: once latched, every subsequent `feed_*_collect`
    /// call is a no-op until [`Classifier::reset_at_boundary`] clears it
    /// (ruling 197-d1 point 4 "ends the run under consideration").
    /// Fold (iii) is the one asymmetric site and does NOT set this.
    recovery_pending: bool,
}

/// The run state and gap hasher produced by [`Classifier::finish`] on success.
pub(crate) struct FinishOutcome {
    pub(crate) state: RunState,
    pub(crate) gap: Option<blake3::Hasher>,
}

impl Classifier {
    /// Builds a classifier for one segment. `prior_run` is the predecessor
    /// [`RunState`], or `None` when scanning the first segment. `initial_boundary_resume`
    /// is the reader's own `boundary_resume` (ADR-0005 d8 unsealed boundary); the
    /// Classifier owns the flag thereafter.
    pub(crate) fn new(
        prior_run: Option<RunState>,
        ctx: SegmentContext,
        mode: Mode,
        initial_boundary_resume: bool,
    ) -> Self {
        Self {
            state: prior_run.clone(),
            mode,
            ctx,
            first: ctx.opening,
            boundary_resume: initial_boundary_resume,
            gap: None,
            saved_prior: prior_run,
            inherited: false,
            run_flag: false,
            count: 0,
            prefix: false,
            closing: false,
            must_close: false,
            damaged: false,
            invalid_line: false,
            broken_from_prepare: false,
            outside_run_from_prepare: false,
            reaction: Reaction::Stop,
            current_pos: CollectorPos {
                segment_index: 0,
                record_index_in_segment: 0,
            },
            collected: Vec::new(),
            recovery_pending: false,
        }
    }

    /// Builds a tolerant-mode classifier for the `history_segment` fallback
    /// walk. `prior_run` is the **saved segment-start** run state (the
    /// reader clones it before the strict pass and restores it here on
    /// `CorruptTrail`); `inherited` is `*run || unsealed_boundary` as set in
    /// the reader shim. The classifier owns the `*run` flag between this
    /// call and [`Classifier::finish_tolerant`] (the reader reads it back
    /// via [`TolerantFinishOutcome::run_flag`]).
    pub(crate) fn new_tolerant(
        prior_run: Option<RunState>,
        ctx: SegmentContext,
        inherited: bool,
    ) -> Self {
        Self {
            state: prior_run.clone(),
            mode: Mode::Tolerant,
            ctx,
            first: ctx.opening,
            boundary_resume: false,
            gap: None,
            saved_prior: prior_run,
            inherited,
            run_flag: inherited,
            count: 0,
            prefix: false,
            closing: false,
            must_close: false,
            damaged: false,
            invalid_line: false,
            broken_from_prepare: false,
            outside_run_from_prepare: false,
            reaction: Reaction::Stop,
            current_pos: CollectorPos {
                segment_index: 0,
                record_index_in_segment: 0,
            },
            collected: Vec::new(),
            recovery_pending: false,
        }
    }

    /// Builds a tolerant-mode classifier in Collect reaction (addendum 16
    /// point 1). Same state machine as [`Classifier::new_tolerant`] but
    /// every check site records into [`Classifier::on_violation`] instead
    /// of returning, and the record-apply callsite special-cases the fold
    /// (iii) salvage through [`apply_checked`] with `compare_mmr=false`.
    /// Consumed by S3b's `classify` iterator and the V4a walk; S3a's own
    /// unit rows drive it directly.
    ///
    /// **S3a is tolerant-only (ruling 197-d1 addendum 18).** This is the
    /// sole Collect constructor in S3a: there is no strict-mode
    /// counterpart. A strict Collect constructor and a Collect entry for
    /// a `Record(Err)` line land in **#197 R2b S3a′**. Callers that need
    /// a strict first-violation oracle still use [`Classifier::new`]
    /// under [`Reaction::Stop`]; the collector in S3a must not be
    /// treated as equivalent to the reader on any strict path.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "consumed by #197 R2b S3b's classify iterator and V4a; between S3a and S3b only #[cfg(test)] rows construct a collect-reaction classifier"
        )
    )]
    pub(crate) fn new_collect(
        prior_run: Option<RunState>,
        ctx: SegmentContext,
        inherited: bool,
    ) -> Self {
        let mut c = Self::new_tolerant(prior_run, ctx, inherited);
        c.reaction = Reaction::Collect;
        c
    }

    /// Reader observer: the pure state after the last successful feed.
    pub(crate) fn state(&self) -> Option<&RunState> {
        self.state.as_ref()
    }

    /// Reader hook: finalize the current gap bytes to a digest and clear it,
    /// so the reader's shim can hand it to [`check_attestation`] before the
    /// next `feed_record` (R2a's per-path position, addendum 12).
    pub(crate) fn take_gap(&mut self) -> Option<[u8; 32]> {
        self.gap.take().map(|h| *h.finalize().as_bytes())
    }

    /// Addendum 16 point 1: the one dispatcher every check site runs a
    /// [`Violation`] through. Under [`Reaction::Stop`] it returns the
    /// [`AuditError`] the enclosing method then propagates (today's
    /// behaviour, byte-identical). Under [`Reaction::Collect`] it also
    /// records `(current_pos, v)` into [`Classifier::collected`] and
    /// latches `recovery_pending`, so the enclosing method's `return
    /// Err(..)` is swallowed by the collect wrapper
    /// ([`Classifier::feed_record_collect`] and friends) that invoked
    /// it. Returning an [`AuditError`] from a Collect-reaction method is
    /// allowed and expected: the wrapper discards it because
    /// `recovery_pending` is set by this call.
    #[must_use = "the AuditError must be returned from the enclosing method; dropping it skips the Stop-reaction propagation"]
    fn on_violation(&mut self, v: Violation) -> AuditError {
        if matches!(self.reaction, Reaction::Collect) {
            self.collected.push((self.current_pos, v));
            self.recovery_pending = true;
        }
        AuditError::from(v)
    }

    /// Feeds one complete record (strict mode). Returns [`Advance::Record`]
    /// on a folded record, [`Advance::Duplicate`] on a collector-style
    /// identical duplicate (the classifier preserves `run_loss=false` on the
    /// retained state, and the reader's shim must NOT bump `since_checkpoint`
    /// on this outcome), and `Err` with the exact detail string the reader
    /// emits at this site (ruling 13-V4-d4 point 1). `gap_digest` is
    /// the hasher output from [`Classifier::take_gap`]; the classifier runs
    /// [`check_attestation`] at the reader's per-path position (ruling
    /// 197-d1 addendum 12: between `missing opening checkpoint` and
    /// `unclosed segment lacks matching immediate resume`).
    ///
    /// Duplicates are reachable from `scan_inner`'s wrappers (`refresh`,
    /// a second `scan` after a prior successful advance).
    pub(crate) fn feed_record(
        &mut self,
        record: &Record,
        record_count: usize,
        trail: [u8; 16],
        gap_digest: Option<[u8; 32]>,
    ) -> Result<Advance, AuditError> {
        assert!(
            matches!(self.mode, Mode::Strict),
            "Tolerant mode uses feed_record_prepare_tolerant / feed_record_apply_tolerant"
        );
        if record_count != 1 {
            return Err(self.on_violation(Violation::MultipleRecordsInLine));
        }
        if record.context.trail != trail {
            return Err(self.on_violation(Violation::TrailIdentityDiffers));
        }
        if self.first
            && self
                .state
                .as_ref()
                .is_some_and(|s| s.head == Head::of(record))
        {
            return Err(self.on_violation(Violation::OpeningCheckpointDuplicatesPredecessor));
        }
        if self.first && !matches!(record.kind, Kind::Checkpoint(_)) {
            return Err(self.on_violation(Violation::MissingOpeningCheckpoint));
        }
        // Reader's per-path position for check_attestation (ruling 197-d1
        // addendum 12): after `missing opening checkpoint`, before
        // `unclosed segment lacks matching immediate resume`.
        if let Err(v) = check_attestation(gap_digest, record.context.repaired) {
            return Err(self.on_violation(v));
        }
        if self.boundary_resume
            && !self.first
            && !matches!(&record.kind, Kind::Entry(e) if e.action == "vigil.audit.resume")
        {
            return Err(self.on_violation(Violation::UnclosedSegmentLacksResume));
        }
        // ADR-0005 amendment 9 part 1: a run-opened segment with no predecessor
        // state still requires a genesis link (same disjunct as `scan_inner`).
        let genesis = self.ctx.genesis || (self.ctx.run && self.state.is_none());
        let next_opt = match apply_checked(self.state.as_ref(), record, genesis, false, true) {
            Ok(opt) => opt,
            Err(v) => return Err(self.on_violation(v)),
        };
        let Some(mut next) = next_opt else {
            // Collector-style identical duplicate: state unchanged, cursor
            // still advances in the reader's shim. Clear `run_loss` on the
            // preserved state so the duplicate branch matches the strict
            // `apply` wrapper semantic.
            if let Some(s) = self.state.as_mut() {
                s.run_loss = false;
            }
            if !self.first {
                self.boundary_resume = false;
            }
            self.first = false;
            return Ok(Advance::Duplicate);
        };
        // Strict mode clears `run_loss` on the folded state (matching the
        // storage-side `apply` wrapper semantic).
        next.run_loss = false;
        self.state = Some(next);
        if !self.first {
            self.boundary_resume = false;
        }
        self.first = false;
        Ok(Advance::Record)
    }

    /// Feeds one physical line classified as a [`super::lines::Line::Fragment`].
    /// In strict mode this extends the gap hasher when a prior complete record
    /// is in scope; at the first position or across an unclosed boundary it is
    /// an opening-checkpoint violation. The `Fragment`-at-opening path and the
    /// `Unparsable`/`Record(Err)` path both reach the single reader-side
    /// detail site `invalid audit line or opening checkpoint` (via
    /// [`invalid_opening_line`]).
    pub(crate) fn feed_fragment(&mut self, bytes: &[u8]) -> Result<(), AuditError> {
        assert!(
            matches!(self.mode, Mode::Strict),
            "feed_fragment is strict-mode-only; tolerant mode uses feed_fragment_tolerant"
        );
        if self.first || self.boundary_resume {
            return Err(self.on_violation(invalid_opening_line()));
        }
        self.gap.get_or_insert_with(super::gap_hasher).update(bytes);
        Ok(())
    }

    /// Feeds one physical line classified as [`super::lines::Line::Unparsable`]
    /// or a `Record(Err)`. Strict mode always treats this as an opening-checkpoint
    /// violation at the same [`invalid_opening_line`] site
    /// [`Classifier::feed_fragment`]'s opening/boundary guard reaches; tolerant
    /// mode (see [`Classifier::feed_unparsable_tolerant`]) accepts it as
    /// damaged evidence.
    pub(crate) fn feed_unparsable(&mut self, _bytes: &[u8]) -> Result<(), AuditError> {
        assert!(
            matches!(self.mode, Mode::Strict),
            "feed_unparsable is strict-mode-only; tolerant mode uses feed_unparsable_tolerant"
        );
        Err(self.on_violation(invalid_opening_line()))
    }

    /// Terminal check for one segment. Strict mode produces the reader's
    /// `scan_inner` epilogue errors (`empty live file …`,
    /// `resume checkpoint lacks …`). The reader builds its final `State`
    /// from the returned run plus its own byte-level cursors.
    pub(crate) fn finish(mut self) -> Result<FinishOutcome, AuditError> {
        assert!(
            matches!(self.mode, Mode::Strict),
            "finish is strict-mode-only; tolerant mode uses finish_tolerant"
        );
        if self.first {
            return Err(self.on_violation(Violation::EmptyLiveFile));
        }
        let Some(state) = self.state.take() else {
            return Err(self.on_violation(Violation::MissingHead));
        };
        if state.pending_resume || self.boundary_resume {
            self.state = Some(state);
            return Err(self.on_violation(Violation::ResumeCheckpointLacksDeclaration));
        }
        Ok(FinishOutcome {
            state,
            gap: self.gap,
        })
    }

    // ---- Tolerant mode -------------------------------------------------

    /// Tolerant-mode: feed one Fragment line. Extends the gap hasher when a
    /// prior complete record is in scope so the next record's attestation
    /// covers it; any fragment also sets `prefix` at `count == 0` and
    /// clears `closing` at `count == 1`.
    pub(crate) fn feed_fragment_tolerant(&mut self, bytes: &[u8]) {
        debug_assert!(matches!(self.mode, Mode::Tolerant));
        if !self.first {
            self.gap.get_or_insert_with(super::gap_hasher).update(bytes);
        }
        if self.count == 0 {
            self.prefix = true;
        }
        if self.count == 1 {
            self.closing = false;
        }
    }

    /// Tolerant-mode: feed one Unparsable line (a `Line::Unparsable` or a
    /// non-record payload the parser rejected). Latches `damaged` and
    /// `invalid_line`, plus the same `prefix`/`closing` bookkeeping as
    /// [`Classifier::feed_fragment_tolerant`].
    pub(crate) fn feed_unparsable_tolerant(&mut self) {
        debug_assert!(matches!(self.mode, Mode::Tolerant));
        self.damaged = true;
        self.invalid_line = true;
        if self.count == 0 {
            self.prefix = true;
        }
        if self.count == 1 {
            self.closing = false;
        }
    }

    /// Tolerant-mode: feed a `Line::Record(Err(_))` payload. Returns
    /// `invalid audit record in sealed run` without touching latches.
    pub(crate) fn feed_record_err_tolerant(&mut self) -> Result<(), AuditError> {
        debug_assert!(matches!(self.mode, Mode::Tolerant));
        Err(self.on_violation(Violation::InvalidRecordInSealedRun))
    }

    /// Tolerant-mode: pre-attestation record checks. Returns
    /// [`TolerantPrep::Duplicate`] when the record matches the duplicate
    /// short-circuit (the reader then calls [`check_attestation`] and
    /// continues without updating `state.offset`); [`TolerantPrep::General`]
    /// otherwise (the reader calls [`check_attestation`] and then
    /// [`Classifier::feed_record_apply_tolerant`]).
    ///
    /// Ruling 197-d1 addendum 12: on the General branch this method runs
    /// the pre-attestation checks up to and including the seq-gap check;
    /// the reader then calls `check_attestation`; the apply method runs
    /// the remaining checks (first-record trial, is_resume, apply_checked).
    /// Order inside prepare: multiple records → trail identity →
    /// invalid_line → duplicate short-circuit → (General only) sealed-seq
    /// → broken/damaged latch → missing-cp → seq-gap.
    pub(crate) fn feed_record_prepare_tolerant(
        &mut self,
        record: &Record,
        record_count: usize,
        trail: [u8; 16],
    ) -> Result<TolerantPrep, AuditError> {
        debug_assert!(matches!(self.mode, Mode::Tolerant));
        if record_count != 1 {
            return Err(self.on_violation(Violation::MultipleRecordsInLine));
        }
        if record.context.trail != trail {
            return Err(self.on_violation(Violation::TrailIdentityDiffers));
        }
        if self.invalid_line {
            return Err(self.on_violation(Violation::UnparsableBeforeRecord));
        }
        let head = Head::of(record);
        let allow_dup = !(self.first || (self.closing && self.count == 1));
        if allow_dup && self.state.as_ref().is_some_and(|s| s.head == head) {
            return Ok(TolerantPrep::Duplicate);
        }
        // General branch: the remaining pre-attestation checks.
        if self
            .state
            .as_ref()
            .is_some_and(|s| record.context.seq <= s.head.seq)
        {
            return Err(self.on_violation(Violation::SequenceDidNotIncrease));
        }
        let broken = self.first
            && self
                .state
                .as_ref()
                .is_some_and(|s| record.context.previous != s.head.hash);
        let is_cp = matches!(record.kind, Kind::Checkpoint(_));
        if self.first && (!is_cp || broken) {
            self.damaged = true;
        }
        if self.state.is_none() && !is_cp {
            return Err(self.on_violation(Violation::MissingInitialCheckpoint));
        }
        let outside_run = self.inherited && !self.run_flag;
        if !self.first
            && !outside_run
            && self
                .state
                .as_ref()
                .is_some_and(|s| record.context.seq != s.head.seq + 1)
        {
            return Err(self.on_violation(Violation::SequenceGapInSealedRun));
        }
        self.broken_from_prepare = broken;
        self.outside_run_from_prepare = outside_run;
        Ok(TolerantPrep::General)
    }

    /// Tolerant-mode: post-attestation record apply. Runs the
    /// `history_segment` general-branch checks from the first-record trial
    /// through `apply_checked`, updates state and latches.
    ///
    /// Must be called after [`Classifier::feed_record_prepare_tolerant`]
    /// returned [`TolerantPrep::General`] and the reader has resolved the
    /// gap through [`check_attestation`].
    ///
    /// Addendum 16 point 2 (fold (iii) salvage): under [`Reaction::Collect`]
    /// this is the one asymmetric site. If [`apply_checked`] returns
    /// [`Violation::CheckpointMmrDiffers`] the mismatch is recorded without
    /// latching, then re-applied through [`apply_checked`] with
    /// `compare_mmr = false` so classification continues as if the
    /// checkpoint had matched. Under [`Reaction::Stop`] the mismatch
    /// propagates as it does today, byte-identical.
    pub(crate) fn feed_record_apply_tolerant(&mut self, record: &Record) -> Result<(), AuditError> {
        debug_assert!(matches!(self.mode, Mode::Tolerant));
        let broken = self.broken_from_prepare;
        let outside_run = self.outside_run_from_prepare;
        let is_cp = matches!(record.kind, Kind::Checkpoint(_));
        if self.first {
            // Trial apply against the saved segment-start state so a closing
            // checkpoint still compares with its predecessor's run; matches
            // the reader's pre-fallback run-state snapshot.
            let trial_genesis = self.saved_prior.is_none();
            let trial_ok = runs_trial_apply(self.saved_prior.as_ref(), record, trial_genesis);
            self.closing = self.inherited && !self.prefix && !self.damaged && trial_ok;
            if self.inherited && is_cp && !broken && !self.closing {
                return Err(self.on_violation(Violation::FirstSuccessorDoesNotCloseRun));
            }
            self.must_close = self.closing;
        }
        let is_resume = matches!(
            &record.kind,
            Kind::Entry(e) if e.action == "vigil.audit.resume"
        );
        if self.count == 1 && self.closing {
            self.must_close = false;
            if !is_resume {
                return Err(self.on_violation(Violation::FirstSuccessorLacksImmediateResume));
            }
            self.run_flag = false;
        }
        let before_loss = !(broken || self.state.as_ref().is_some_and(|s| s.run_loss));
        let compare_mmr = outside_run || before_loss;
        // Addendum 16 point 2: fold (iii) salvage under Reaction::Collect.
        // The explicit `Violation::CheckpointMmrDiffers` construction in
        // the push below is a second site for this detail -- marked
        // UNREACHABLE for the reader-side pin gate (the salvage records
        // without returning an `AuditError`; exercised by
        // `collector_tests::collector_fold_iii_mismatch_continues_*`).
        let next = match apply_checked(self.state.as_ref(), record, false, broken, compare_mmr) {
            Ok(opt) => opt,
            Err(Violation::CheckpointMmrDiffers) if matches!(self.reaction, Reaction::Collect) => {
                // Record-only (no `on_violation`, no latch); splice-in.
                self.collected
                    .push((self.current_pos, Violation::CheckpointMmrDiffers));
                match apply_checked(self.state.as_ref(), record, false, broken, false) {
                    Ok(opt) => opt,
                    Err(w) => return Err(self.on_violation(w)),
                }
            }
            Err(v) => return Err(self.on_violation(v)),
        };
        let Some(mut next) = next else {
            // Collector-style identical duplicate reaching the general branch
            // (should not occur because the duplicate short-circuit guards
            // against it, but preserve the invariant).
            self.first = false;
            self.count += 1;
            return Ok(());
        };
        if self.count == 1 && self.closing {
            next.run_loss = false;
        }
        self.state = Some(next);
        self.first = false;
        self.count += 1;
        Ok(())
    }

    /// Tolerant-mode terminal check for one segment. Returns the segment's
    /// final `RunState` (possibly `None` when no complete record was folded),
    /// the gap hasher the reader threads into `State.gap`, and the owned
    /// `*run` flag. Epilogue order: `must_close && run_flag` →
    /// `first successor lacks resume`, `count == 0` latches `damaged`,
    /// `!damaged && !run_flag` → `invalid undamaged segment`, `damaged`
    /// promotes `run_flag`, and a pending-resume state short-circuits
    /// `resume checkpoint lacks its declaration`.
    pub(crate) fn finish_tolerant(mut self) -> Result<TolerantFinishOutcome, AuditError> {
        debug_assert!(matches!(self.mode, Mode::Tolerant));
        if let Some(v) = self.finish_check_first_successor_lacks_resume() {
            return Err(self.on_violation(v));
        }
        if self.count == 0 {
            self.damaged = true;
        }
        if let Some(v) = self.finish_check_invalid_undamaged_segment() {
            return Err(self.on_violation(v));
        }
        if self.damaged {
            self.run_flag = true;
        }
        if let Some(v) = self.finish_check_resume_lacks_declaration() {
            return Err(self.on_violation(v));
        }
        Ok(TolerantFinishOutcome {
            gap: self.gap,
            run_flag: self.run_flag,
        })
    }

    /// Finish-time check shared by [`Classifier::finish_tolerant`] and
    /// [`Classifier::finish_collect`] (addendum 16 point 5). The ONE
    /// [`Violation::FirstSuccessorLacksResume`] construction site lives
    /// here so the coverage gate counts it once.
    fn finish_check_first_successor_lacks_resume(&self) -> Option<Violation> {
        if self.must_close && self.run_flag {
            Some(Violation::FirstSuccessorLacksResume)
        } else {
            None
        }
    }

    /// Finish-time check shared by [`Classifier::finish_tolerant`] and
    /// [`Classifier::finish_collect`] (addendum 16 point 5). The ONE
    /// [`Violation::InvalidUndamagedSegment`] construction site lives
    /// here so the coverage gate counts it once.
    fn finish_check_invalid_undamaged_segment(&self) -> Option<Violation> {
        if !self.damaged && !self.run_flag {
            Some(Violation::InvalidUndamagedSegment)
        } else {
            None
        }
    }

    /// Finish-time check shared by [`Classifier::finish_tolerant`] and
    /// [`Classifier::finish_collect`] (addendum 16 point 5). The
    /// tolerant/collect [`Violation::ResumeCheckpointLacksDeclaration`]
    /// construction site lives here so the coverage gate counts the
    /// tolerant/collect occurrence once (strict `finish` has its own).
    fn finish_check_resume_lacks_declaration(&self) -> Option<Violation> {
        if let Some(s) = self.state.as_ref()
            && s.pending_resume
        {
            Some(Violation::ResumeCheckpointLacksDeclaration)
        } else {
            None
        }
    }

    // ---- Collect reaction (addendum 16) ---------------------------------

    /// Addendum 16 point 1: resets the per-segment latches for a new
    /// segment after a recovered violation (ruling 197-d1 point 4
    /// "classification resumes at the next segment boundary"). Clears
    /// `recovery_pending`, the prefix/closing/damaged/invalid_line/
    /// must_close latches and the gap hasher, carries the current
    /// `self.state` forward as the new `saved_prior`, adopts the caller-
    /// supplied segment context and `inherited` flag, and sets the
    /// collector segment index to `next_segment_index` (0-based).
    /// Tolerant-only in S3a (ruling 197-d1 addendum 18); the Collect
    /// reaction has no strict-mode constructor until #197 R2b S3a′.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "consumed by #197 R2b S3b's classify iterator and V4a; between S3a and S3b only #[cfg(test)] rows cross boundaries"
        )
    )]
    pub(crate) fn reset_at_boundary(
        &mut self,
        boundary_ctx: SegmentContext,
        boundary_inherited: bool,
        next_segment_index: usize,
    ) {
        assert!(
            matches!(self.reaction, Reaction::Collect),
            "reset_at_boundary is Collect-reaction-only"
        );
        // Addendum 17.4: end-of-segment checks run at EVERY segment
        // boundary (not only on the final segment via `finish_collect`),
        // but are SKIPPED when an earlier violation has already ended the
        // run under consideration (`recovery_pending`), since no second
        // report comes from a run that is already dead.
        if !self.recovery_pending {
            if let Some(v) = self.finish_check_first_successor_lacks_resume() {
                self.collected.push((self.current_pos, v));
            }
            if self.count == 0 {
                self.damaged = true;
            }
            if let Some(v) = self.finish_check_invalid_undamaged_segment() {
                self.collected.push((self.current_pos, v));
            }
            if self.damaged {
                self.run_flag = true;
            }
            if let Some(v) = self.finish_check_resume_lacks_declaration() {
                self.collected.push((self.current_pos, v));
            }
        }
        self.saved_prior = self.state.clone();
        self.ctx = boundary_ctx;
        self.first = boundary_ctx.opening;
        self.boundary_resume = false;
        self.gap = None;
        self.inherited = boundary_inherited;
        self.run_flag = boundary_inherited;
        self.count = 0;
        self.prefix = false;
        self.closing = false;
        self.must_close = false;
        self.damaged = false;
        self.invalid_line = false;
        self.broken_from_prepare = false;
        self.outside_run_from_prepare = false;
        self.recovery_pending = false;
        self.current_pos = CollectorPos {
            segment_index: next_segment_index,
            record_index_in_segment: 0,
        };
    }

    /// Addendum 16 point 1: Collect-reaction entry point for a complete
    /// record. A thin wrapper over the shared tolerant methods: bumps the
    /// record index, short-circuits on `recovery_pending`, drives
    /// `feed_record_prepare_tolerant` + `check_attestation` +
    /// `feed_record_apply_tolerant`, and swallows each `Err` because
    /// `on_violation` already recorded the violation and set
    /// `recovery_pending`. The fold (iii) salvage inside
    /// `feed_record_apply_tolerant` continues classification without
    /// latching.
    ///
    /// **Tolerant-only in S3a (ruling 197-d1 addendum 18).** This entry
    /// drives the tolerant state machine exclusively. A strict-mode
    /// Collect entry and a Collect entry for a `Record(Err)` line land
    /// in **#197 R2b S3a′**.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "consumed by #197 R2b S3b's classify iterator and V4a; between S3a and S3b only #[cfg(test)] rows feed a collect-reaction classifier"
        )
    )]
    pub(crate) fn feed_record_collect(
        &mut self,
        record: &Record,
        record_count: usize,
        trail: [u8; 16],
        record_index: usize,
    ) {
        debug_assert!(matches!(self.reaction, Reaction::Collect));
        self.current_pos.record_index_in_segment = record_index;
        if self.recovery_pending {
            return;
        }
        let prep = match self.feed_record_prepare_tolerant(record, record_count, trail) {
            Ok(p) => p,
            Err(_) => return, // on_violation recorded it; recovery_pending set
        };
        // Attestation runs at the reader's per-path position (addendum 12),
        // consuming `self.gap` like the reader's `classifier.take_gap()`.
        if self.recovery_pending {
            return;
        }
        let gap_digest = self.take_gap();
        if let Err(v) = check_attestation(gap_digest, record.context.repaired) {
            let _ = self.on_violation(v);
            return;
        }
        match prep {
            TolerantPrep::Duplicate => {
                // Addendum 17.2: the duplicate-line handling is the
                // reader's own code path. The reader
                // (`history_segment`) calls `check_attestation(...)` and
                // then `continue`s -- no `count += 1`, no `first = false`,
                // no state mutation. Mirroring that here is the whole
                // point. `self.gap` was already consumed by the earlier
                // `check_attestation(gap_digest, ...)` call pattern; the
                // reader passes `classifier.take_gap()`, so S3b's
                // `classify` iterator supplies the same value here
                // through `gap_digest`.
            }
            TolerantPrep::General => {
                let _ = self.feed_record_apply_tolerant(record);
            }
        }
    }

    /// Addendum 16 point 1: Collect-reaction entry point for a Fragment
    /// line. Bumps the record index, short-circuits on `recovery_pending`,
    /// then delegates to the shared [`Classifier::feed_fragment_tolerant`].
    /// Tolerant-only in S3a (ruling 197-d1 addendum 18).
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "consumed by #197 R2b S3b's classify iterator and V4a; between S3a and S3b only #[cfg(test)] rows feed a collect-reaction classifier"
        )
    )]
    pub(crate) fn feed_fragment_collect(&mut self, bytes: &[u8], record_index: usize) {
        debug_assert!(matches!(self.reaction, Reaction::Collect));
        self.current_pos.record_index_in_segment = record_index;
        if self.recovery_pending {
            return;
        }
        self.feed_fragment_tolerant(bytes);
    }

    /// Addendum 16 point 1: Collect-reaction entry point for an Unparsable
    /// line. Bumps the record index, short-circuits on `recovery_pending`,
    /// then delegates to the shared [`Classifier::feed_unparsable_tolerant`].
    /// Tolerant-only in S3a (ruling 197-d1 addendum 18); the Collect entry
    /// for a `Record(Err)` line lands in #197 R2b S3a′.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "consumed by #197 R2b S3b's classify iterator and V4a; between S3a and S3b only #[cfg(test)] rows feed a collect-reaction classifier"
        )
    )]
    pub(crate) fn feed_unparsable_collect(&mut self, record_index: usize) {
        debug_assert!(matches!(self.reaction, Reaction::Collect));
        self.current_pos.record_index_in_segment = record_index;
        if self.recovery_pending {
            return;
        }
        self.feed_unparsable_tolerant();
    }

    /// Addendum 16 point 5: finish the collector. Mirrors
    /// [`Classifier::finish_tolerant`]'s epilogue but **records** each
    /// would-be `Err` into the violations vector instead of returning.
    /// The three tolerant finish-time checks (`first successor lacks
    /// resume`, `invalid undamaged segment`, `resume checkpoint lacks its
    /// declaration`) are recorded in Collect mode too. Returns the
    /// accumulated violations plus the final pure `RunState`, owned
    /// `run_flag`, and the gap hasher.
    ///
    /// Tolerant-only in S3a (ruling 197-d1 addendum 18): this epilogue
    /// is the tolerant mode's finish-time check set; a strict Collect
    /// finish lands with the rest of Strict×Collect in #197 R2b S3a′.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "consumed by #197 R2b S3b's classify iterator and V4a; between S3a and S3b only #[cfg(test)] rows finish a collect-reaction classifier"
        )
    )]
    pub(crate) fn finish_collect(mut self) -> CollectorOutcome {
        debug_assert!(matches!(self.reaction, Reaction::Collect));
        // Shared helpers own the Violation::X construction sites so the
        // coverage gate does not count finish_collect as a second site.
        // Addendum 17.4: skip the end-of-segment checks when the run has
        // already been ended by an earlier violation (`recovery_pending`),
        // since no second report comes from a run that is already dead.
        if !self.recovery_pending {
            if let Some(v) = self.finish_check_first_successor_lacks_resume() {
                self.collected.push((self.current_pos, v));
            }
            if self.count == 0 {
                self.damaged = true;
            }
            if let Some(v) = self.finish_check_invalid_undamaged_segment() {
                self.collected.push((self.current_pos, v));
            }
            if self.damaged {
                self.run_flag = true;
            }
            if let Some(v) = self.finish_check_resume_lacks_declaration() {
                self.collected.push((self.current_pos, v));
            }
        }
        CollectorOutcome {
            state: self.state,
            run_flag: self.run_flag,
            violations: self.collected,
            gap: self.gap,
        }
    }
}

/// Pre-attestation tolerant-mode classification outcome. The reader's shim
/// resolves [`check_attestation`] at the reader-side position (addendum 12)
/// and then either `continue`s on `Duplicate` or calls
/// [`Classifier::feed_record_apply_tolerant`] on `General`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TolerantPrep {
    /// Identical-duplicate branch of the `history_segment` fallback walk.
    /// The reader calls [`check_attestation`] and continues without
    /// updating `state.offset` or `state.newline`.
    Duplicate,
    /// General branch of the `history_segment` fallback walk. The reader
    /// calls [`check_attestation`] and then
    /// [`Classifier::feed_record_apply_tolerant`].
    General,
}

/// Terminal outcome of a tolerant-mode segment scan. The reader observes
/// transient state through `classifier.state()` on each successful
/// `feed_record_apply_tolerant`, so `finish_tolerant` only returns the
/// final `gap` hasher and the owned `*run` flag; the final `RunState` is
/// already in the reader's `Option<State>` and does not need re-export.
/// V4a's `classify` wrapper (see #197 for the follow-up slice) exposes
/// the final state through a separate per-segment record.
pub(crate) struct TolerantFinishOutcome {
    pub(crate) gap: Option<blake3::Hasher>,
    pub(crate) run_flag: bool,
}

/// First-record trial apply used by the tolerant-mode classifier. Calls
/// the pure [`apply_checked`] directly against the saved segment-start
/// [`RunState`] without allocating a full `State`.
fn runs_trial_apply(prior: Option<&RunState>, record: &Record, genesis: bool) -> bool {
    apply_checked(prior, record, genesis, false, true).is_ok()
}

#[cfg(test)]
mod collector_tests {
    //! Minimal collector-API smoke rows. S3a's own unit coverage is a
    //! deliberately small set that exercises every added surface so no
    //! item is `dead_code` in either configuration.
    //!
    //! Per ruling 197-d1 addendum 18, S3a ships Collect for **tolerant
    //! mode only**: the tolerant collector-first-equals-reader-first
    //! sweep over the `history_segment` single-segment paths is the
    //! mandatory PR proof for S3a. Strict×Collect, the Collect entry for
    //! a `Record(Err)` line, the remaining killing rows and the strict
    //! first-equality sweep land in #197 R2b S3a′.
    use super::*;
    use crate::audit::{AuditError, CheckpointFields, Entry, Mmr, Record, RecordContext};

    const TRAIL: [u8; 16] = [0; 16];

    fn context(seq: u64, previous: [u8; 32]) -> RecordContext {
        RecordContext::new(TRAIL, seq, 100 + seq, "test", previous)
    }

    fn cp(seq: u64, previous: [u8; 32], mmr: &Mmr) -> Record {
        let fields = CheckpointFields::new(
            mmr.size(),
            mmr.root(),
            mmr.peaks().to_vec(),
            [1; 32],
            [0; 64],
        )
        .unwrap();
        Record::checkpoint(context(seq, previous), fields).unwrap()
    }

    fn entry(seq: u64, previous: [u8; 32]) -> Record {
        Record::new_internal(
            context(seq, previous),
            Entry::new("operator", "vigil.audit.observe", "trail").reason("x"),
        )
        .unwrap()
    }

    /// R1: `Violation::ALL` enumerates every variant once, `detail()`
    /// strings are pairwise distinct, and `From<Violation> for AuditError`
    /// produces a `CorruptTrail` whose detail matches `detail()`.
    #[test]
    fn violation_detail_roundtrip_and_from_impl() {
        let mut seen = std::collections::HashSet::new();
        for v in Violation::ALL.iter().copied() {
            assert!(seen.insert(v.detail()), "duplicate detail {:?}", v.detail());
            let err: AuditError = v.into();
            assert_eq!(
                format!("{err}")
                    .strip_prefix("CorruptTrail: ")
                    .unwrap_or_default(),
                v.detail(),
                "From<Violation> for AuditError detail mismatch for {v:?}",
            );
        }
        // Enum covers all 35 variants.
        assert_eq!(Violation::ALL.len(), 35);
    }

    /// Smoke row: `Reaction` values, `CollectorPos` default, and the
    /// `CollectorOutcome` fields are all live so the gate doesn't fire
    /// dead_code on them.
    #[test]
    fn reaction_and_collector_types_are_live() {
        assert_eq!(Reaction::Stop, Reaction::Stop);
        assert_ne!(Reaction::Stop, Reaction::Collect);
        let pos = CollectorPos::default();
        assert_eq!(pos.segment_index, 0);
        assert_eq!(pos.record_index_in_segment, 0);
        // Construct an outcome directly to touch every field.
        let outcome = CollectorOutcome {
            state: None,
            run_flag: false,
            violations: vec![(pos, Violation::MissingHead)],
            gap: None,
        };
        assert!(outcome.state.is_none());
        assert!(!outcome.run_flag);
        assert_eq!(outcome.violations.len(), 1);
        assert!(outcome.gap.is_none());
    }

    /// Smoke row: build a collector, feed one checkpoint, finish it.
    /// Exercises `new_collect`, `feed_record_collect`, `finish_collect`.
    /// A clean `cp0` through a run-opening context yields a damaged-
    /// latched segment (no second record), so `finish_collect` records
    /// no violations beyond the tolerant epilogue's.
    #[test]
    fn collector_feed_record_and_finish_smoke() {
        let ctx = SegmentContext {
            opening: true,
            genesis: true,
            run: false,
        };
        let mut c = Classifier::new_collect(None, ctx, false);
        let cp0 = cp(0, Record::genesis(&TRAIL), &Mmr::new());
        c.feed_record_collect(&cp0, 1, TRAIL, 0);
        let out = c.finish_collect();
        // cp0 folded into state. Not inherited, not damaged, one record →
        // the tolerant epilogue records `InvalidUndamagedSegment` in
        // Collect mode (addendum 16 point 5) instead of returning `Err`.
        assert!(out.state.is_some(), "cp0 folded into state");
        assert!(
            out.violations
                .iter()
                .any(|(_, v)| *v == Violation::InvalidUndamagedSegment),
            "finish_collect records tolerant-epilogue invalid_undamaged_segment"
        );
    }

    /// Smoke row: `feed_fragment_collect` extends the internal gap
    /// hasher after a complete record; `feed_unparsable_collect`
    /// latches the invalid_line flag so a subsequent record records
    /// `UnparsableBeforeRecord`. Exercises `feed_fragment_collect`
    /// and `feed_unparsable_collect`.
    #[test]
    fn collector_feed_fragment_and_unparsable_smoke() {
        let ctx = SegmentContext {
            opening: true,
            genesis: true,
            run: false,
        };
        let mut c = Classifier::new_collect(None, ctx, false);
        let cp0 = cp(0, Record::genesis(&TRAIL), &Mmr::new());
        c.feed_record_collect(&cp0, 1, TRAIL, 0);
        c.feed_fragment_collect(b"torn", 1);
        let out = c.finish_collect();
        assert!(out.gap.is_some(), "fragment extended the gap hasher");
        let ctx2 = SegmentContext {
            opening: true,
            genesis: true,
            run: false,
        };
        let mut c2 = Classifier::new_collect(None, ctx2, false);
        c2.feed_record_collect(&cp0, 1, TRAIL, 0);
        c2.feed_unparsable_collect(1);
        let cp1 = cp(1, cp0.hash(), &{
            let mut m = Mmr::new();
            m.push(cp0.hash()).unwrap();
            m
        });
        c2.feed_record_collect(&cp1, 1, TRAIL, 2);
        let out2 = c2.finish_collect();
        assert!(
            out2.violations
                .iter()
                .any(|(_, v)| *v == Violation::UnparsableBeforeRecord),
            "unparsable latched before next record"
        );
    }

    /// Smoke row: `reset_at_boundary` clears per-segment latches
    /// (recovery_pending, damaged, invalid_line) and bumps the segment
    /// index. Exercises `reset_at_boundary`.
    #[test]
    fn collector_reset_at_boundary_smoke() {
        let ctx = SegmentContext {
            opening: true,
            genesis: true,
            run: false,
        };
        let mut c = Classifier::new_collect(None, ctx, false);
        // Feed a non-cp opening record to latch recovery_pending.
        let not_cp = entry(0, Record::genesis(&TRAIL));
        c.feed_record_collect(&not_cp, 1, TRAIL, 0);
        assert!(
            !c.collected.is_empty(),
            "non-cp opening records a violation"
        );
        assert!(c.recovery_pending, "non-cp opening latches recovery");
        let boundary_ctx = SegmentContext {
            opening: true,
            genesis: false,
            run: false,
        };
        c.reset_at_boundary(boundary_ctx, false, 1);
        assert!(!c.recovery_pending, "reset clears recovery_pending");
        assert_eq!(c.current_pos.segment_index, 1);
        assert_eq!(c.current_pos.record_index_in_segment, 0);
        let out = c.finish_collect();
        // One violation was recorded in segment 0.
        assert!(out.violations.iter().any(|(pos, _)| pos.segment_index == 0));
    }

    /// Builds the MMR state after folding the given records in order.
    fn mmr_after(records: &[Record]) -> Mmr {
        let mut m = Mmr::new();
        for r in records {
            m.push(r.hash()).unwrap();
        }
        m
    }

    /// Builds a checkpoint whose declared peaks and root do NOT match
    /// its actual trail fold at `seq`. Used by the amendment-3 row to
    /// trigger a fold-(iii) salvage.
    fn bad_cp(seq: u64, previous: [u8; 32]) -> Record {
        // A peaks list that cannot match the real fold at this position.
        let fields =
            CheckpointFields::new(1, [0x55; 32], vec![[0x55; 32]], [1; 32], [0; 64]).unwrap();
        Record::checkpoint(context(seq, previous), fields).unwrap()
    }

    /// Amendment 3 (addendum 17.3): fold "as if matched" is the computed
    /// fold INCLUDING the checkpoint's own leaf. On `[cp0,e1,bad_cp2,e3,cp4]`
    /// the collector records **exactly one** `CheckpointMmrDiffers`, the
    /// classification continues past the mismatch, and a later honest
    /// checkpoint (`cp4`) that matches the "as if" fold is accepted.
    /// Pins the exact full recorded list, not just a count: the full list
    /// contains exactly one `CheckpointMmrDiffers` and no other variants.
    #[test]
    fn collector_fold_iii_mismatch_continues_full_list() {
        let ctx = SegmentContext {
            opening: true,
            genesis: true,
            run: false,
        };
        let mut c = Classifier::new_collect(None, ctx, false);

        // cp0 at the trail's genesis.
        let cp0 = cp(0, Record::genesis(&TRAIL), &Mmr::new());
        c.feed_record_collect(&cp0, 1, TRAIL, 0);

        // e1 extends cp0.
        let e1 = entry(1, cp0.hash());
        c.feed_record_collect(&e1, 1, TRAIL, 1);

        // bad_cp2: declared peaks don't match the real fold.
        let bc = bad_cp(2, e1.hash());
        c.feed_record_collect(&bc, 1, TRAIL, 2);

        // e3 extends bad_cp2's position (the "as if matched" fold now
        // includes bad_cp2 as a real leaf).
        let e3 = entry(3, bc.hash());
        c.feed_record_collect(&e3, 1, TRAIL, 3);

        // cp4 declares the MMR the trail actually computes including
        // bad_cp2's leaf: this is the "as if matched" semantics.
        let m_at_cp4 = mmr_after(&[cp0.clone(), e1.clone(), bc.clone(), e3.clone()]);
        let cp4 = cp(4, e3.hash(), &m_at_cp4);
        c.feed_record_collect(&cp4, 1, TRAIL, 4);

        let out = c.finish_collect();
        // Exact full list: the ONE CheckpointMmrDiffers at bad_cp2, nothing
        // else (even in the finish-epilogue, since the run flag advanced
        // and the segment is not damaged -- but addendum 17.4 means even
        // the undamaged-epilogue check doesn't run past recovery_pending,
        // which for the fold-(iii) salvage is NOT set).
        let kinds: Vec<Violation> = out.violations.iter().map(|(_, v)| *v).collect();
        assert_eq!(
            kinds
                .iter()
                .filter(|v| **v == Violation::CheckpointMmrDiffers)
                .count(),
            1,
            "exactly one CheckpointMmrDiffers recorded; full list: {kinds:?}",
        );
        // The single recorded violation's position is bad_cp2's (record_index=2).
        let salvage = out
            .violations
            .iter()
            .find(|(_, v)| *v == Violation::CheckpointMmrDiffers)
            .expect("salvage violation exists");
        assert_eq!(salvage.0.record_index_in_segment, 2);
        // The final state's MMR equals the "as if matched" fold (the
        // computed one including every record, cp4's declaration matches).
        let final_state = out.state.expect("fold continued past salvage");
        assert_eq!(
            final_state.mmr.root(),
            mmr_after(&[cp0, e1, bc, e3, cp4]).root(),
            "final MMR is the computed `as if matched` fold",
        );
    }

    /// Amendment 6 killing row: "fold ends the run" mutant. If the fold-(iii)
    /// salvage arm were routed through `on_violation` (latching instead of
    /// salvaging), feeding `[cp0, bad_cp2]` would latch recovery_pending
    /// and a later `cp` wouldn't be processed. This row asserts: a
    /// subsequent record after the mismatch is still processed and bumps
    /// the fold.
    #[test]
    fn collector_salvage_does_not_end_the_run() {
        let ctx = SegmentContext {
            opening: true,
            genesis: true,
            run: false,
        };
        let mut c = Classifier::new_collect(None, ctx, false);
        let cp0 = cp(0, Record::genesis(&TRAIL), &Mmr::new());
        c.feed_record_collect(&cp0, 1, TRAIL, 0);
        let bc = bad_cp(1, cp0.hash());
        c.feed_record_collect(&bc, 1, TRAIL, 1);
        assert!(
            !c.recovery_pending,
            "salvage does NOT latch recovery_pending (fold ends the run mutant)",
        );
        let count_before = c.collected.len();
        let e2 = entry(2, bc.hash());
        c.feed_record_collect(&e2, 1, TRAIL, 2);
        // The next record was processed (no additional violation past the
        // salvage one).
        assert_eq!(
            c.collected.len(),
            count_before,
            "e2 after salvage does not add new violations",
        );
    }

    /// Amendment 6 killing row: "salvage skipped" mutant. If the second
    /// `apply_checked(.., compare_mmr=false)` call were deleted from the
    /// salvage arm, the state's MMR would stay one leaf short. This row
    /// asserts: after a fold mismatch at bad_cp2, the MMR root equals the
    /// recomputed fold INCLUDING bad_cp2's leaf.
    #[test]
    fn collector_salvage_mmr_includes_the_checkpoint_leaf() {
        let ctx = SegmentContext {
            opening: true,
            genesis: true,
            run: false,
        };
        let mut c = Classifier::new_collect(None, ctx, false);
        let cp0 = cp(0, Record::genesis(&TRAIL), &Mmr::new());
        c.feed_record_collect(&cp0, 1, TRAIL, 0);
        let bc = bad_cp(1, cp0.hash());
        c.feed_record_collect(&bc, 1, TRAIL, 1);
        let final_state = c.state().cloned().expect("state advanced past salvage");
        let expected = mmr_after(&[cp0, bc]);
        assert_eq!(
            final_state.mmr.root(),
            expected.root(),
            "salvage re-applied the checkpoint leaf to the MMR",
        );
    }

    /// Amendment 6 killing row: "Collect keeps only the first" mutant.
    /// If `on_violation` under Collect also returned without setting
    /// `recovery_pending`, multi-violation segments would not latch and
    /// subsequent records would be processed. This row asserts the
    /// opposite: after the first (non-salvage) violation, recovery_pending
    /// is latched and further feeds are no-ops.
    #[test]
    fn collector_first_violation_latches_recovery() {
        let ctx = SegmentContext {
            opening: true,
            genesis: true,
            run: false,
        };
        let mut c = Classifier::new_collect(None, ctx, false);
        let cp0 = cp(0, Record::genesis(&TRAIL), &Mmr::new());
        c.feed_record_collect(&cp0, 1, TRAIL, 0);
        // Feed a broken-link record (previous != cp0.hash).
        let broken = entry(1, [0xff; 32]);
        c.feed_record_collect(&broken, 1, TRAIL, 1);
        assert!(
            c.recovery_pending,
            "a non-salvage violation latches recovery_pending",
        );
        let before = c.collected.len();
        // Further feed is a no-op.
        let e2 = entry(2, broken.hash());
        c.feed_record_collect(&e2, 1, TRAIL, 2);
        assert_eq!(c.collected.len(), before, "feeds after latch are no-ops");
    }

    /// Amendment 4 / 6 killing row: `reset_at_boundary` runs the three
    /// finish-time checks before clearing latches, except when the run
    /// has already been ended (`recovery_pending`). This row pins both
    /// behaviours:
    ///   - a healthy pending-resume state at the boundary records
    ///     `ResumeCheckpointLacksDeclaration` into segment 0;
    ///   - after a latched violation, the boundary records NOTHING
    ///     further (the run has already been ended).
    #[test]
    fn collector_reset_at_boundary_records_end_of_segment_unless_dead() {
        // Case A: pending_resume at the boundary -> record the check.
        let ctx = SegmentContext {
            opening: true,
            genesis: true,
            run: false,
        };
        let mut c = Classifier::new_collect(None, ctx, false);
        let cp0 = cp(0, Record::genesis(&TRAIL), &Mmr::new());
        c.feed_record_collect(&cp0, 1, TRAIL, 0);
        // Fake a pending_resume by crossing a sequence gap: feed an entry at
        // seq=5 (gap from 0 -> 5), which the tolerant state machine latches
        // as `pending_resume` through `apply_checked`. Not all gap layouts
        // reach pending_resume; we use the direct state mutation instead so
        // the row is deterministic.
        if let Some(s) = c.state.as_mut() {
            s.pending_resume = true;
        }
        let before_reset = c.collected.len();
        let boundary_ctx = SegmentContext {
            opening: true,
            genesis: false,
            run: false,
        };
        c.reset_at_boundary(boundary_ctx, false, 1);
        // The end-of-segment check `ResumeCheckpointLacksDeclaration`
        // fired against segment 0.
        let after = c.collected.len();
        assert!(after > before_reset, "boundary recorded at least one check");
        assert!(
            c.collected.iter().any(|(pos, v)| pos.segment_index == 0
                && *v == Violation::ResumeCheckpointLacksDeclaration),
            "the boundary recorded pending_resume in segment 0",
        );

        // Case B: recovery_pending is set -> NO new end-of-segment checks.
        let mut c2 = Classifier::new_collect(None, ctx, false);
        let broken = entry(0, [0xff; 32]);
        c2.feed_record_collect(&broken, 1, TRAIL, 0);
        assert!(c2.recovery_pending, "a non-cp opening latches recovery");
        let before = c2.collected.len();
        c2.reset_at_boundary(boundary_ctx, false, 1);
        assert_eq!(
            c2.collected.len(),
            before,
            "boundary skips end-of-segment checks while run is dead",
        );
    }
}
