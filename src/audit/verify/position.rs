//! Position classifier for inputs during verify (rulings 13-V6-d3
//! and 13-V6-d7; ADR-0005 decision 11). Built once per verify call
//! from the accepted start (if any), the anchors and the end-record
//! context (if any); consumed by [`super::anchors`],
//! [`super::revocation`] and [`super::end`] through
//! [`Classifier::set_aside`] to replace the ordinary mismatch finding
//! with one unlocated set-aside finding when the input is below an
//! accepted start or above the end of a bounded batch. See
//! [`crate::audit::Verifier::start_from`] and
//! [`crate::audit::Verifier::end_before`] for the rules.

use super::{Finding, end_before};
use crate::audit::{Checkpoint, FindingKind as K};
use std::fmt::Display;

/// Sorted location of a `seq` versus the accepted start and the
/// end record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Position {
    /// `seq >= start_seq` (or no accepted start) and `seq <= E` (or
    /// no `end_before`). Nothing is set aside.
    InRange,
    /// `seq < start_seq` under an accepted start. `start_seq` is the
    /// accepted start's `seq` (carried so the finding detail can name
    /// it); `anchored` is `true` iff the anchor list contains one
    /// whose `(trail, seq, hash)` equals the accepted start.
    BelowStart { start_seq: u64, anchored: bool },
    /// `seq > E` under `Verifier::end_before`. `E` is the `seq` of
    /// the end record's last line (the resume line if there is one,
    /// otherwise the checkpoint, ruling 13-V6-d7 point 1); `anchored`
    /// is `true` iff the end anchor was given and byte-equals the
    /// record's first line (ruling 13-V6-d4 point 5; ruling 13-V6-d7
    /// point 2).
    AboveEnd { end_seq: u64, anchored: bool },
}

/// Built once per verify call from the accepted start (if any), the
/// anchor list and the end-record context (if any).
pub(super) struct Classifier {
    accepted: Option<(u64, bool)>,
    end_before: Option<(u64, bool)>,
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
    ) -> Self {
        let accepted = accepted.map(|start| {
            let anchored = anchors
                .iter()
                .any(|a| a.trail() == trail && a.seq() == start.seq() && a.hash() == start.hash());
            (start.seq(), anchored)
        });
        let end_before = end_ctx.map(|ctx| (ctx.last_line_seq, ctx.is_anchored()));
        Self {
            accepted,
            end_before,
        }
    }

    /// `true` iff [`crate::audit::Verifier::end_before`] was given a
    /// record, so the end-bounded verification rules apply (ruling
    /// 13-V6-d7 point 4): `RevocationUnconfirmed` is not reported, in
    /// particular. Consumed by [`super::revocation::check`].
    pub(super) fn end_bounded(&self) -> bool {
        self.end_before.is_some()
    }

    fn classify(&self, seq: u64) -> Position {
        if let Some((end_seq, anchored)) = self.end_before
            && seq > end_seq
        {
            return Position::AboveEnd { end_seq, anchored };
        }
        if let Some((start_seq, anchored)) = self.accepted
            && seq < start_seq
        {
            return Position::BelowStart {
                start_seq,
                anchored,
            };
        }
        Position::InRange
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
            Position::InRange => None,
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
    /// 13-V6-d7a point 1; decision 11 lists the below-start inputs
    /// without `end=`, so an `end=` below an accepted start keeps its
    /// 13-V5-d5 behaviour). Consumed by [`super::end::check`].
    pub(super) fn set_aside_above_end(&self, seq: u64, subject: impl Display) -> Option<Finding> {
        match self.classify(seq) {
            Position::AboveEnd { end_seq, anchored } => {
                Some(above_end_finding(seq, end_seq, anchored, subject))
            }
            Position::InRange | Position::BelowStart { .. } => None,
        }
    }
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
