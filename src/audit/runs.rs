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
//! reader's first violation on every path: in `history_segment`, multiple records,
//! trail identity, an unparsable line before a complete record, a non-increasing seq
//! inside a sealed run, a missing initial checkpoint and a sequence gap inside a
//! sealed run segment; in `scan_inner`, the immediate-resume boundary. On their own
//! they are **not** a complete first-violation oracle: until #197 R2b moves those
//! segment-level checks here, nothing outside the reader may use them as one.
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
