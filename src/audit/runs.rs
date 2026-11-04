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
//! `check_attestation` (a fragment gap's repair attestation, checked as data) and
//! `apply_checked` (the per-record checks) are pure. Together with the reader-side
//! segment checks that still run ahead of them in `storage.rs`, they reproduce the
//! reader's first violation on every path. #197 R2b S1 adds the push-API
//! [`Classifier`] (strict mode only) for `scan_inner`/`scan`/`scan_staged`/
//! `scan_closing`; `history_segment`'s fallback walk and tolerant mode land
//! in #197 R2b S2, and the `classify` iterator and V4a's consumption land
//! in #197 R2b S3 (addendum 13).
//!
//! On their own [`Classifier`] + [`check_attestation`] are **not** a complete
//! first-violation oracle until #197 R2b S3 adds the every-violation
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
/// [`AuditError`] whose detail is byte-identical to the former inline state
/// machine (ruling 13-V4-d4 point 1); the reader's shim delegates here.
/// `broken_boundary` disables the hash-link and in-run seq-gap checks at a
/// damaged run entry (B3d1-d1/d3); `compare_mmr` disables the fold (iii)
/// comparison inside a run segment whose preceding records may be lost
/// (B3d1-d1/d4); `genesis` forces the `(genesis || seq == 0) && !root_link`
/// path (staging settlement and the amendment-9 genesis closer).
///
/// The reader calls [`check_attestation`] and `apply_checked` at their
/// pre-#197 R2a positions on each path; see the module caveat for why this
/// pair is not a complete first-violation oracle until R2b.
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
/// reader calls this at the same point on each path as before #197 R2a,
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
/// with the reader's `resume_header` and R1-identical to the former
/// `storage::resume_details` (ruling 13-V4-d4 point 1).
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
/// `storage::apply_checked` emitted today (ruling 13-V4-d4 point 1).
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

/// The merged strict-mode `invalid audit line or opening checkpoint` site.
/// `Fragment` at `first`/`boundary_resume` and every `Unparsable`/`Record(Err)`
/// payload collapse here (197 R2b S1 §2a item 1). The syn coverage gate counts
/// this one `corrupt("...")` call and the pin `pin_sc_invalid_audit_line_or_opening_checkpoint`
/// targets it at occurrence 0.
fn invalid_opening_line() -> AuditError {
    corrupt("invalid audit line or opening checkpoint")
}

/// Boundary policy for scanning one segment under ADR-0005 amendment 6.
/// Moved from `storage.rs` so the pure `Classifier` and the future
/// `classify` wrapper (#197 R2b S3) can consume it.
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

/// Classifier mode. `Strict` mirrors today's `scan_inner`/`scan`/`scan_staged`/
/// `scan_closing`; `Tolerant` (the `history_segment` fallback walk) lands in
/// #197 R2b S2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Strict single-pass classifier (the reader's `scan_inner` family).
    Strict,
    /// Tolerant fallback classifier (reserved for #197 R2b S2).
    #[expect(dead_code, reason = "#197 R2b S2 drives the tolerant path")]
    Tolerant,
}

/// Outcome of one successful [`Classifier::feed_record`] call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Advance {
    /// Record folded into state; cursor advances.
    Record,
    /// Collector-style identical duplicate; prior state is unchanged.
    /// Reachable on refresh paths where an already-seen record is observed
    /// again without an intervening write; the reader advances offset/newline
    /// anyway (matches storage::apply_checked's wrapper behaviour).
    Duplicate,
}

/// Resumable segment-level classifier (#197 R2b S1 strict; R2b S2 and R2b S3
/// extend it). No I/O. The reader threads this across its lock and refresh
/// paths without buffering the trail. Push API: the reader's shim performs
/// byte-level work (reading a line, running [`super::lines::classify`]) and
/// then calls [`Classifier::feed_record`], [`Classifier::feed_fragment`] or
/// [`Classifier::feed_unparsable`]. The reader's shim calls
/// [`check_attestation`] immediately before each `feed_record` (addendum 7
/// / addendum 12: the reader's per-path order binds).
pub(crate) struct Classifier {
    state: Option<RunState>,
    mode: Mode,
    ctx: SegmentContext,
    first: bool,
    boundary_resume: bool,
    gap: Option<blake3::Hasher>,
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
            state: prior_run,
            mode,
            ctx,
            first: ctx.opening,
            boundary_resume: initial_boundary_resume,
            gap: None,
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
    /// identical duplicate (the reader's shim preserves `run_loss=false`
    /// via the classifier, and must NOT bump `since_checkpoint`), and `Err`
    /// with the exact detail string the reader emitted at this site today
    /// (ruling 13-V4-d4 point 1). `gap_digest` is the hasher output from
    /// [`Classifier::take_gap`]; the classifier runs [`check_attestation`]
    /// at base's exact per-path position (addendum 12: between `missing
    /// opening checkpoint` and `unclosed segment lacks matching immediate
    /// resume`).
    ///
    /// Duplicates ARE reachable from `scan_inner`'s wrappers (`refresh`,
    /// a second `scan` after a prior successful advance), despite R2b S1's
    /// draft rustdoc claiming otherwise.
    pub(crate) fn feed_record(
        &mut self,
        record: &Record,
        record_count: usize,
        trail: [u8; 16],
        gap_digest: Option<[u8; 32]>,
    ) -> Result<Advance, AuditError> {
        assert!(
            matches!(self.mode, Mode::Strict),
            "Tolerant mode lands in #197 R2b S2"
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
        // Base's per-path position for check_attestation (addendum 12):
        // after `missing opening checkpoint`, before `unclosed segment lacks
        // matching immediate resume`.
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
            // still advances in the reader's shim. Base's `apply` wrapper
            // clears `run_loss` on the preserved state; preserve that quirk.
            if let Some(s) = self.state.as_mut() {
                s.run_loss = false;
            }
            if !self.first {
                self.boundary_resume = false;
            }
            self.first = false;
            return Ok(Advance::Duplicate);
        };
        // The storage-side `apply` wrapper clears `run_loss` after the fold
        // for the strict path; preserve that here.
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
    /// `Unparsable`/`Record(Err)` path share a single reader-side detail site
    /// `invalid audit line or opening checkpoint` (the merged strict site,
    /// see 197-r2b1 §2a item 1).
    pub(crate) fn feed_fragment(&mut self, bytes: &[u8]) -> Result<(), AuditError> {
        assert!(
            matches!(self.mode, Mode::Strict),
            "Tolerant mode lands in #197 R2b S2"
        );
        if self.first || self.boundary_resume {
            return Err(invalid_opening_line());
        }
        self.gap.get_or_insert_with(super::gap_hasher).update(bytes);
        Ok(())
    }

    /// Feeds one physical line classified as [`super::lines::Line::Unparsable`]
    /// or a `Record(Err)`. Strict mode always treats this as an opening-checkpoint
    /// violation (same merged site as [`Classifier::feed_fragment`]'s guard); the
    /// tolerant mode (R2b S2) accepts it as damaged evidence.
    pub(crate) fn feed_unparsable(&mut self, _bytes: &[u8]) -> Result<(), AuditError> {
        assert!(
            matches!(self.mode, Mode::Strict),
            "Tolerant mode lands in #197 R2b S2"
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
            "Tolerant mode lands in #197 R2b S2"
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
}
