//! Position classifier for inputs during verify (rulings 13-V6-d3,
//! 13-V6-d7 and 13-V7-d1 points 7-9; ADR-0005 decision 11 and
//! decision 5 "Receipts lost with a resume"). Built once per verify
//! call from the accepted start, the anchors, the end-record
//! context and every trust-and-fold-kept resume candidate; consumed
//! by [`super::anchors`], [`super::revocation`] and [`super::end`]
//! through [`Classifier::set_aside`] (below-start / above-end), by
//! [`super::receipts`] through [`Classifier::lost_record`] (inside a
//! confirmed resume gap), and by [`super::anchors`] and
//! [`super::revocation`] through [`Classifier::lost_record_anchored`]
//! (inside a confirmed gap whose opening checkpoint is itself
//! anchored). See [`crate::audit::Verifier::start_from`],
//! [`crate::audit::Verifier::end_before`] and
//! [`crate::audit::Verifier::receipts`] for the rules.

use super::{Finding, end_before};
use crate::audit::{Checkpoint, FindingKind as K};
use std::fmt::Display;

/// Trust-and-fold-kept resume candidate (rulings 13-V4-d10 point 4,
/// 13-V5-d1 point 8 and 13-V7-d1 points 7-9). `low..=high` is the
/// gap: `head_seq+1..=lost_through`, or `0..=lost_through` on a
/// genesis resume (ADR-0005 decision 5 "Resume gaps", l.407).
/// `confirmed` is `true` when a receipt matches the resume's
/// `(seq, hash)` under the shared match rule (13-V7-d1 point 8);
/// it gates `LostRecord` emission and the genesis-gap suppression
/// (point 7 exception). `opening_anchored` is `true` when an input
/// anchor's `(trail, seq, hash)` equals the opening checkpoint
/// (ruling 13-V6-d1 point 2); together with `confirmed` it gates
/// the anchor-and-pin `LostRecord` demotion inside a gap (ADR-0005
/// decision 5 "Receipts lost with a resume"; ruling 13-V7-d1 point
/// 8). `resume_seq` and `resume_hash` identify the gap's resume
/// record for the `lost_records=<n>` counter (ruling 13-V7-d1
/// point 8): the count is keyed by the resume `(seq, hash)` on the
/// gap itself, so a candidate the trust or fold filter dropped
/// (absent here) keeps its `lost_records=0` without the two
/// consumers risking a zip alignment.
#[derive(Clone, Copy, Debug)]
pub(super) struct Gap {
    pub(super) low: u64,
    pub(super) high: u64,
    pub(super) is_genesis: bool,
    pub(super) confirmed: bool,
    pub(super) opening_anchored: bool,
    pub(super) resume_seq: u64,
    pub(super) resume_hash: [u8; 32],
}

/// Sorted location of a `seq` versus the accepted start, the end
/// record and every resume candidate gap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Position {
    /// `seq >= start_seq` (or no accepted start) and `seq <= E` (or
    /// no `end_before`) and not inside any resume candidate gap.
    /// Nothing is set aside.
    InRange,
    /// `seq < start_seq` under an accepted start. `start_seq` is the
    /// accepted start's `seq` (carried so the finding detail can name
    /// it); `anchored` is `true` iff the anchor list contains one
    /// whose `(trail, seq, hash)` equals the accepted start.
    BelowStart { start_seq: u64, anchored: bool },
    /// `seq > E` under `Verifier::end_before`. `E` is the `seq` of
    /// the end record's last line (the resume line if there is one,
    /// otherwise the checkpoint, ruling 13-V6-d7 point 1); `anchored`
    /// is `true` iff all three "anchored" conditions hold: the end
    /// anchor was given, it byte-equals the record's first line, and
    /// the shared anchor rule matched it (ruling 13-V6-d4 point 5;
    /// ruling 13-V6-d7 clarification 13-V6-d7a).
    AboveEnd { end_seq: u64, anchored: bool },
    /// `seq` is inside a resume candidate gap (ruling 13-V7-d1
    /// points 7-9). An input below the start or above the end
    /// follows that rule first, so only an in-range `seq` lands
    /// here. See [`Gap`] for the field semantics.
    Gap {
        confirmed: bool,
        opening_anchored: bool,
        low: u64,
        high: u64,
    },
}

/// Built once per verify call from the accepted start (if any), the
/// anchor list, the end-record context (if any) and every structurally
/// valid resume candidate the trust and fold filters kept.
pub(super) struct Classifier {
    accepted: Option<(u64, bool)>,
    end_before: Option<EndBounds>,
    /// Resume candidate gaps, in `low` order; consumed by
    /// [`Self::classify`], [`Self::lost_record`] and
    /// [`Self::candidate_gap`] (ruling 13-V7-d1 points 7-9).
    gaps: Vec<Gap>,
}

/// The two end-of-range bounds the classifier carries under
/// [`crate::audit::Verifier::end_before`]. `end_seq` is the end
/// checkpoint's `seq`, the bound [`super::end_before::check`]
/// opens [`crate::audit::FindingKind::TrailEnded`] at and the one
/// file-record reconciliation cuts at (ruling 13-V6-d4 point 3;
/// clarification 13-V7-d1a point 2). `last_line_seq` is `E`, the
/// `seq` of the end record's last line: the resume line when the
/// end record has one, otherwise the checkpoint (ruling 13-V6-d7
/// point 1); the set-aside bound for receipts above the end.
#[derive(Clone, Copy)]
struct EndBounds {
    end_seq: u64,
    last_line_seq: u64,
    anchored: bool,
}

impl Classifier {
    /// `accepted` is `Some(start)` only when [`super::start::check`]
    /// accepted that start; otherwise every `seq` below the end is in
    /// range. `end_ctx` is the engine's end-record context when
    /// [`crate::audit::Verifier::end_before`] was called; otherwise
    /// every `seq` above the start is in range.
    pub(super) fn new(
        accepted: Option<&Checkpoint>,
        trail: [u8; 16],
        anchors: &[Checkpoint],
        end_ctx: Option<&end_before::Context<'_>>,
        gaps: Vec<Gap>,
    ) -> Self {
        let accepted = accepted.map(|start| {
            let anchored = anchors
                .iter()
                .any(|a| a.trail() == trail && a.seq() == start.seq() && a.hash() == start.hash());
            (start.seq(), anchored)
        });
        let end_before = end_ctx.map(|ctx| EndBounds {
            end_seq: ctx.end_seq,
            last_line_seq: ctx.last_line_seq,
            anchored: ctx.is_anchored(),
        });
        Self {
            accepted,
            end_before,
            gaps,
        }
    }

    /// `true` iff [`crate::audit::Verifier::end_before`] was given a
    /// record, so the end-bounded verification rules apply (ruling
    /// 13-V6-d7 point 4): `RevocationUnconfirmed` is not reported, in
    /// particular. Consumed by [`super::revocation::check`].
    pub(super) fn end_bounded(&self) -> bool {
        self.end_before.is_some()
    }

    /// `true` iff file records at this `seq` are reconciled against
    /// the receipt set (ruling 13-V7-d1 point 3; clarification
    /// 13-V7-d1a point 2): at or above the accepted start and
    /// STRICTLY BELOW the end checkpoint's `seq` under `end_before`.
    /// This upper bound is narrower than [`Self::set_aside`]'s: file
    /// records at or above the end checkpoint are
    /// [`super::super::FindingKind::TrailEnded`] and not reconciled,
    /// while receipts naming an end-record line are still matched at
    /// `E` (the resume line's `seq` when one is present, otherwise
    /// the checkpoint). Reading this bound from the shared
    /// classifier keeps "the same bound `TrailEnded` uses" in one
    /// place; no receipt-side code re-derives it. Consumed by
    /// [`super::receipts::check`] alongside [`Self::set_aside`]: the
    /// predicate here gates `NoReceipt`, and `set_aside` gates the
    /// receipt-side set-aside.
    pub(super) fn is_in_range(&self, seq: u64) -> bool {
        if self.end_before.is_some_and(|e| seq >= e.end_seq) {
            return false;
        }
        if self.accepted.is_some_and(|(start, _)| seq < start) {
            return false;
        }
        true
    }

    fn classify(&self, seq: u64) -> Position {
        if let Some(e) = self.end_before
            && seq > e.last_line_seq
        {
            return Position::AboveEnd {
                end_seq: e.last_line_seq,
                anchored: e.anchored,
            };
        }
        if let Some((start_seq, anchored)) = self.accepted
            && seq < start_seq
        {
            return Position::BelowStart {
                start_seq,
                anchored,
            };
        }
        // Ruling 13-V7-d1 point 7: an input below the start follows
        // the start rule first and one above the end follows the end
        // rule; only an in-range `seq` can be inside a candidate gap.
        if let Some(g) = self.gaps.iter().find(|g| seq >= g.low && seq <= g.high) {
            return Position::Gap {
                confirmed: g.confirmed,
                opening_anchored: g.opening_anchored,
                low: g.low,
                high: g.high,
            };
        }
        Position::InRange
    }

    /// One unlocated [`K::LostRecord`] finding when `seq` is inside a
    /// confirmed resume candidate gap (ruling 13-V7-d1 points 8-9);
    /// `None` outside one or inside an unconfirmed gap. `subject` is
    /// the caller's `<prefix> seq <s> hash <hex>` text (the shared
    /// receipt-side subjects: `receipt`, `waive`, `from`); the detail
    /// completes as `<subject>: lost in gap <a>..=<b>`. Consumed by
    /// [`super::receipts::match_one`].
    pub(super) fn lost_record(&self, seq: u64, subject: impl Display) -> Option<Finding> {
        match self.classify(seq) {
            Position::Gap {
                confirmed: true,
                low,
                high,
                ..
            } => Some(lost_record_finding(seq, low, high, subject)),
            _ => None,
        }
    }

    /// One unlocated [`K::LostRecord`] finding when `seq` is inside a
    /// confirmed resume candidate gap WHOSE OPENING CHECKPOINT IS
    /// ALSO ANCHORED (ADR-0005 decision 5 "Receipts lost with a
    /// resume"; ruling 13-V7-d1 point 8). Consumed by
    /// [`super::anchors::evaluate`] and [`super::revocation::check`]
    /// for anchors and `through=` pins inside a gap, which are
    /// demoted to `LostRecord` only when, in addition to the gap
    /// being confirmed, an input anchor's full `(trail, seq, hash)`
    /// equals the opening checkpoint. A receipt or an `accept` line
    /// is a text line, not an anchor, and never anchors an opening:
    /// otherwise a stolen key could cut back over anchored
    /// checkpoints, sign a gap, and turn every `AnchorMismatch` into
    /// info. The detail grammar matches [`Self::lost_record`]'s
    /// (`<subject>: lost in gap <a>..=<b>`), with subjects
    /// `anchor seq <a> hash <hex>` and `key <64 hex> through=<b>`.
    pub(super) fn lost_record_anchored(&self, seq: u64, subject: impl Display) -> Option<Finding> {
        match self.classify(seq) {
            Position::Gap {
                confirmed: true,
                opening_anchored: true,
                low,
                high,
            } => Some(lost_record_finding(seq, low, high, subject)),
            _ => None,
        }
    }

    /// Returns the matching candidate gap when the range `low..=high`
    /// is **exactly** a candidate gap's range (ruling 13-V7-d1 point
    /// 7): the main seq-loop reads this to suppress its `SeqGap`.
    /// Returns `None` for any other `(low, high)`, so an unrelated
    /// jump keeps its `SeqGap`.
    pub(super) fn candidate_gap(&self, low: u64, high: u64) -> Option<&Gap> {
        self.gaps.iter().find(|g| g.low == low && g.high == high)
    }

    /// Returns the one unlocated set-aside finding when `seq` is
    /// below an accepted start or above the end of a bounded batch,
    /// or `None` when `seq` is in range. `subject` is the caller's
    /// `anchor seq <a> hash <hex>`, `key <hex> through=<b>` or
    /// `end=<s>:<hash>` text; the detail completes as
    /// `<subject>: below start seq <s>` or
    /// `<subject>: above end seq <E>`. The kind is
    /// [`K::OutOfRange`] when the start or end is anchored, and
    /// [`K::UnanchoredStart`] / [`K::UnanchoredEnd`] otherwise
    /// (rulings 13-V6-d3 points 4-5 and 13-V6-d7 points 2-3).
    pub(super) fn set_aside(&self, seq: u64, subject: impl Display) -> Option<Finding> {
        match self.classify(seq) {
            Position::InRange | Position::Gap { .. } => None,
            Position::BelowStart {
                start_seq,
                anchored,
            } => Some(Finding::new(
                if anchored {
                    K::OutOfRange
                } else {
                    K::UnanchoredStart
                },
                None,
                None,
                Some(seq),
                format!("{subject}: below start seq {start_seq}"),
            )),
            Position::AboveEnd { end_seq, anchored } => {
                Some(above_end_finding(seq, end_seq, anchored, subject))
            }
        }
    }

    /// Returns the one unlocated above-end set-aside finding when
    /// `seq` is strictly above the end of a bounded batch, or `None`
    /// otherwise. Unlike [`Self::set_aside`], a `seq` below an
    /// accepted start is left untouched: a trust-file `end=<s>` is
    /// set aside only above the end (ruling 13-V6-d7 clarification
    /// 13-V6-d7a; decision 11 lists the below-start inputs without
    /// `end=`, so an `end=` below an accepted start keeps its
    /// 13-V5-d5 behaviour). Consumed by [`super::end::check`].
    pub(super) fn set_aside_above_end(&self, seq: u64, subject: impl Display) -> Option<Finding> {
        match self.classify(seq) {
            Position::AboveEnd { end_seq, anchored } => {
                Some(above_end_finding(seq, end_seq, anchored, subject))
            }
            Position::InRange | Position::BelowStart { .. } | Position::Gap { .. } => None,
        }
    }
}

/// Builds the one unlocated [`K::LostRecord`] finding shared by
/// [`Classifier::lost_record`] and
/// [`Classifier::lost_record_anchored`] so the detail grammar
/// (`<subject>: lost in gap <a>..=<b>`, unlocated at `seq`) lives in
/// one place (ruling 13-V7-d1 points 8-9; ADR-0005 decision 5
/// "Receipts lost with a resume").
fn lost_record_finding(seq: u64, low: u64, high: u64, subject: impl Display) -> Finding {
    Finding::new(
        K::LostRecord,
        None,
        None,
        Some(seq),
        format!("{subject}: lost in gap {low}..={high}"),
    )
}

/// Builds the one unlocated above-end finding, shared by
/// [`Classifier::set_aside`] and [`Classifier::set_aside_above_end`]
/// so the detail grammar and kind choice live in one place (ruling
/// 13-V6-d7 points 2-3).
fn above_end_finding(seq: u64, end_seq: u64, anchored: bool, subject: impl Display) -> Finding {
    Finding::new(
        if anchored {
            K::OutOfRange
        } else {
            K::UnanchoredEnd
        },
        None,
        None,
        Some(seq),
        format!("{subject}: above end seq {end_seq}"),
    )
}
