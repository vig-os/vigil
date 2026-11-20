//! Position classifier for inputs during verify (ruling 13-V6-d3;
//! ADR-0005 decision 11). Built once per verify call from the accepted
//! start (if any) and the anchors; consumed by [`super::anchors`] and
//! [`super::revocation`] through [`Classifier::set_aside`] to replace
//! the ordinary mismatch finding below an accepted start. See
//! [`crate::audit::Verifier::start_from`] for the rule.

use super::Finding;
use crate::audit::{Checkpoint, FindingKind as K};
use std::fmt::Display;

/// Sorted location of a `seq` versus the accepted start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Position {
    /// No accepted start, or `seq >= start_seq` under an accepted start.
    InRange,
    /// `seq < start_seq` under an accepted start. `start_seq` is the
    /// accepted start's `seq` (carried so the finding detail can name
    /// it); `anchored` is `true` iff the anchor list contains one
    /// whose `(trail, seq, hash)` equals the accepted start.
    BelowStart { start_seq: u64, anchored: bool },
}

/// Built once per verify call from the accepted start (if any) and
/// the anchor list.
pub(super) struct Classifier {
    accepted: Option<(u64, bool)>,
}

impl Classifier {
    /// `accepted` is `Some(start)` only when [`super::start::check`]
    /// accepted that start; otherwise every `seq` is in range.
    pub(super) fn new(
        accepted: Option<&Checkpoint>,
        trail: [u8; 16],
        anchors: &[Checkpoint],
    ) -> Self {
        let accepted = accepted.map(|start| {
            let anchored = anchors
                .iter()
                .any(|a| a.trail() == trail && a.seq() == start.seq() && a.hash() == start.hash());
            (start.seq(), anchored)
        });
        Self { accepted }
    }

    fn classify(&self, seq: u64) -> Position {
        match self.accepted {
            Some((start_seq, anchored)) if seq < start_seq => Position::BelowStart {
                start_seq,
                anchored,
            },
            _ => Position::InRange,
        }
    }

    /// Returns the one unlocated set-aside finding when `seq` is below
    /// an accepted start, or `None` when `seq` is in range. `subject`
    /// is the caller's `anchor seq <a> hash <hex>` or
    /// `key <hex> through=<b>` text; the detail completes as
    /// `<subject>: below start seq <s>`. The kind is
    /// [`K::OutOfRange`] when the start is anchored and
    /// [`K::UnanchoredStart`] otherwise (ruling 13-V6-d3 points 4-5).
    pub(super) fn set_aside(&self, seq: u64, subject: impl Display) -> Option<Finding> {
        match self.classify(seq) {
            Position::InRange => None,
            Position::BelowStart {
                start_seq,
                anchored,
            } => {
                let kind = if anchored {
                    K::OutOfRange
                } else {
                    K::UnanchoredStart
                };
                Some(Finding::new(
                    kind,
                    None,
                    None,
                    Some(seq),
                    format!("{subject}: below start seq {start_seq}"),
                ))
            }
        }
    }
}
