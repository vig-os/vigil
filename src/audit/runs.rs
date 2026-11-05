//! Shared pure per-record state machine for the reader (`storage.rs`) and
//! future verifier (#13 V4a/V4b). ADR-0005 amendment 6 "Base", "Sequence
//! gaps inside a run", "Run boundaries", amendment 9 part 1 (genesis base),
//! and rulings 13-V4-d1/d3/d4, B3d1-d1/d3/d4, 107-d1. Issue #197 R1.
//!
//! No I/O. No locks. No writer-only state. Owns `apply_checked`, the
//! resume-declaration validator and the MMR fold (iii). The reader embeds
//! [`RunState`] inside [`super::storage::State`]; writer bookkeeping
//! (`checkpoint_time`, `since_checkpoint`), the walk cursor (`offset`,
//! `length`, `newline`) and the gap-hasher stay in `State`.
//!
//! `check_attestation` (a fragment gap's repair attestation, checked as data)
//! and `apply_checked` (the per-record checks) are pure. The push-API
//! [`Classifier`] drives `scan_inner`'s strict-mode per-segment checks and,
//! in tolerant mode, `history_segment`'s fallback walk restored from a saved
//! segment-start state. Together with the reader-side byte-level and
//! file-open checks that still run in `storage.rs`, they reproduce the
//! reader's first violation on every path. See #197 for the follow-up
//! slice (ruling 197-d1 addendum 13) that adds the `classify` iterator over
//! segment summaries, the every-violation collector and V4a's consumption.
//!
//! On their own [`Classifier`] + [`check_attestation`] are **not** a complete
//! first-violation oracle until that slice adds the every-violation
//! collector and the `classify` iterator wrapper; nothing outside the reader
//! may use them as one until then.
use super::{
    AuditError, Mmr, Record,
    format::Kind,
    storage::{Head, corrupt},
};

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
/// success, `Ok(None)` for a collector-style identical duplicate, and an
/// [`AuditError`] whose detail matches the reader's inline per-record
/// state machine (ruling 13-V4-d4 point 1); the reader's shim delegates
/// here.
/// `broken_boundary` disables the hash-link and in-run seq-gap checks at a
/// damaged run entry (B3d1-d1/d3); `compare_mmr` disables the fold (iii)
/// comparison inside a run segment whose preceding records may be lost
/// (B3d1-d1/d4); `genesis` forces the `(genesis || seq == 0) && !root_link`
/// path (staging settlement and the amendment-9 genesis closer).
///
/// The reader calls [`check_attestation`] and `apply_checked` at the
/// reader's per-path position (ruling 197-d1 addenda 7 and 12); see the
/// module caveat for why this pair is not a complete first-violation
/// oracle until the follow-up slice adds the every-violation collector
/// and the `classify` iterator.
pub(crate) fn apply_checked(
    prior: Option<&RunState>,
    record: &Record,
    genesis: bool,
    broken_boundary: bool,
    compare_mmr: bool,
) -> Result<Option<RunState>, AuditError> {
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
            return Err(corrupt("missing initial checkpoint"));
        };
        if (genesis || head.seq == 0) && !root_link {
            return Err(corrupt("initial checkpoint does not link genesis"));
        }
        if root_link && head.seq > 0 {
            // Amendment 9: the lost creation hash is unavailable. Both reader
            // paths authenticate the computable genesis leaf through this fold.
            let mut fold = Mmr::new();
            fold.push(Record::genesis(&record.context.trail))?;
            fold
        } else {
            Mmr::from_peaks(cp.size, cp.peaks.clone())
                .map_err(|_| corrupt("invalid opening peaks"))?
        }
    };
    let predecessor = prior.map(|s| s.head);
    if let Some(s) = prior {
        if head == s.head {
            return Ok(None);
        } // Collector-style identical duplicates add no leaf.
        if head.seq <= s.head.seq || (!broken_boundary && record.context.previous != s.head.hash) {
            return Err(corrupt(
                "record rolled back, changed or broke its hash link",
            ));
        }
        if s.pending_resume
            && !matches!(&record.kind, Kind::Entry(e) if e.action == "vigil.audit.resume")
        {
            return Err(corrupt("sequence gap lacks a resume declaration"));
        }
        if !broken_boundary && head.seq != s.head.seq + 1 {
            if !matches!(record.kind, Kind::Checkpoint(_)) {
                return Err(corrupt("sequence gap without checkpoint"));
            }
            pending = true;
        }
    }
    match &record.kind {
        Kind::Checkpoint(cp) => {
            if compare_mmr
                && (cp.size != mmr.size() || cp.root != mmr.root() || cp.peaks != mmr.peaks())
            {
                return Err(corrupt("checkpoint MMR differs from preceding records"));
            }
        }
        Kind::Entry(entry) if entry.action == "vigil.audit.resume" => {
            let s = prior.ok_or_else(|| corrupt("resume without predecessor"))?;
            if !s.checkpoint {
                return Err(corrupt("resume not immediately after checkpoint"));
            }
            let details = entry
                .details
                .as_deref()
                .ok_or_else(|| corrupt("resume without details"))?;
            validate_resume(details, s, record)?;
        }
        Kind::Entry(_) => {}
    }
    mmr.push(head.hash).map_err(|_| corrupt("MMR overflow"))?;
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
) -> Result<(), AuditError> {
    if let Some(d) = digest
        && repaired != Some(d)
    {
        return Err(corrupt("missing or mismatched repair attestation"));
    }
    Ok(())
}

/// Parses the three positional fields of a resume `details` string; shared
/// with the reader's `resume_header` (ruling 13-V4-d4 point 1).
pub(crate) fn resume_details(details: &str) -> Result<(&str, &str, &str), AuditError> {
    let (named, file) = details
        .split_once(" file=")
        .ok_or_else(|| corrupt("invalid resume details"))?;
    let (named, lost) = named
        .split_once(" lost_through=")
        .ok_or_else(|| corrupt("invalid resume loss bound"))?;
    Ok((named, lost, file))
}

/// Validates the resume declaration carried in a `vigil.audit.resume`
/// entry's `details`, emitting the exact first-violation detail string
/// `storage::apply_checked` emits (ruling 13-V4-d4 point 1).
fn validate_resume(details: &str, s: &RunState, record: &Record) -> Result<(), AuditError> {
    let (named, lost, file) = resume_details(details)?;
    let (seq_text, hash) = named
        .strip_prefix("head=")
        .and_then(|v| v.split_once(':'))
        .ok_or_else(|| corrupt("invalid resume head"))?;
    let seq = seq_text
        .parse::<u64>()
        .map_err(|_| corrupt("invalid resume head sequence"))?;
    let bound = s
        .head
        .seq
        .checked_sub(1)
        .ok_or_else(|| corrupt("resume after creation checkpoint"))?;
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
        return Err(corrupt("resume declaration does not describe its gap"));
    }
    Ok(())
}

/// Strict-mode `invalid audit line or opening checkpoint` site. `Fragment`
/// at `first`/`boundary_resume` and every `Unparsable`/`Record(Err)` payload
/// both reach this single helper, so the syn coverage gate counts one
/// `corrupt("...")` call and the pin
/// `pin_sc_invalid_audit_line_or_opening_checkpoint` targets it at
/// occurrence 0.
fn invalid_opening_line() -> AuditError {
    corrupt("invalid audit line or opening checkpoint")
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
        }
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
            return Err(corrupt("multiple records in native audit line"));
        }
        if record.context.trail != trail {
            return Err(corrupt("trail identity differs from marker"));
        }
        if self.first
            && self
                .state
                .as_ref()
                .is_some_and(|s| s.head == Head::of(record))
        {
            return Err(corrupt("opening checkpoint duplicates predecessor"));
        }
        if self.first && !matches!(record.kind, Kind::Checkpoint(_)) {
            return Err(corrupt("missing opening checkpoint"));
        }
        // Reader's per-path position for check_attestation (ruling 197-d1
        // addendum 12): after `missing opening checkpoint`, before
        // `unclosed segment lacks matching immediate resume`.
        check_attestation(gap_digest, record.context.repaired)?;
        if self.boundary_resume
            && !self.first
            && !matches!(&record.kind, Kind::Entry(e) if e.action == "vigil.audit.resume")
        {
            return Err(corrupt("unclosed segment lacks matching immediate resume"));
        }
        // ADR-0005 amendment 9 part 1: a run-opened segment with no predecessor
        // state still requires a genesis link (same disjunct as `scan_inner`).
        let genesis = self.ctx.genesis || (self.ctx.run && self.state.is_none());
        let next_opt = apply_checked(self.state.as_ref(), record, genesis, false, true)?;
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
            return Err(invalid_opening_line());
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
        Err(invalid_opening_line())
    }

    /// Terminal check for one segment. Strict mode produces the reader's
    /// `scan_inner` epilogue errors (`empty live file …`,
    /// `resume checkpoint lacks …`). The reader builds its final `State`
    /// from the returned run plus its own byte-level cursors.
    pub(crate) fn finish(self) -> Result<FinishOutcome, AuditError> {
        assert!(
            matches!(self.mode, Mode::Strict),
            "finish is strict-mode-only; tolerant mode uses finish_tolerant"
        );
        if self.first {
            return Err(corrupt("empty live file or missing opening checkpoint"));
        }
        let state = self.state.ok_or_else(|| corrupt("missing head"))?;
        if state.pending_resume || self.boundary_resume {
            return Err(corrupt("resume checkpoint lacks its declaration"));
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
    pub(crate) fn feed_record_err_tolerant(&self) -> Result<(), AuditError> {
        debug_assert!(matches!(self.mode, Mode::Tolerant));
        Err(corrupt("invalid audit record in sealed run"))
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
            return Err(corrupt("multiple records in native audit line"));
        }
        if record.context.trail != trail {
            return Err(corrupt("trail identity differs from marker"));
        }
        if self.invalid_line {
            return Err(corrupt("unparsable line before complete record"));
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
            return Err(corrupt(
                "record sequence did not increase inside sealed run",
            ));
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
            return Err(corrupt("missing initial checkpoint"));
        }
        let outside_run = self.inherited && !self.run_flag;
        if !self.first
            && !outside_run
            && self
                .state
                .as_ref()
                .is_some_and(|s| record.context.seq != s.head.seq + 1)
        {
            return Err(corrupt("sequence gap inside sealed run segment"));
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
                return Err(corrupt("first successor does not close sealed run"));
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
                return Err(corrupt("first successor lacks immediate resume"));
            }
            self.run_flag = false;
        }
        let before_loss = !(broken || self.state.as_ref().is_some_and(|s| s.run_loss));
        let compare_mmr = outside_run || before_loss;
        let next = apply_checked(self.state.as_ref(), record, false, broken, compare_mmr)?;
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
        if self.must_close && self.run_flag {
            return Err(corrupt("first successor lacks resume"));
        }
        if self.count == 0 {
            self.damaged = true;
        }
        if !self.damaged && !self.run_flag {
            return Err(corrupt("invalid undamaged segment"));
        }
        if self.damaged {
            self.run_flag = true;
        }
        if let Some(s) = self.state.as_ref()
            && s.pending_resume
        {
            return Err(corrupt("resume checkpoint lacks its declaration"));
        }
        Ok(TolerantFinishOutcome {
            gap: self.gap,
            run_flag: self.run_flag,
        })
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
