//! Position classifier for inputs during verify (ruling 13-V6-d3;
//! ADR-0005 decision 11 "A signature alone never demotes anything",
//! ~l.753-757). Built once per verify call from the accepted start
//! (if any) and the anchors. Below an accepted start, callers in
//! [`super::anchors`] and [`super::revocation`] replace their
//! mismatch check with [`crate::audit::FindingKind::OutOfRange`] /
//! [`crate::audit::FindingKind::UnanchoredStart`] (points 4-5); the
//! classifier is the one place that decides "below the start".
//! "Anchored" means an anchor whose `(trail, seq, hash)` equals the
//! accepted start (point 3); acceptance (ruling 13-V6-d1 point 2)
//! guarantees the anchor matches. With no accepted start, every
//! `seq` is in range (point 2). The `AboveEnd` arm arrives with
//! `Verifier::end_before` and the gap arm with receipts; neither has
//! a producer yet (ruling 13-V6-d1 point 1). See
//! [`crate::audit::Verifier::start_from`] for the start API.

use crate::audit::Checkpoint;

/// Sorted location of a `seq` versus the accepted start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Position {
    /// No accepted start, or `seq >= start_seq` under an accepted start.
    InRange,
    /// `seq < start_seq` under an accepted start. `start_seq` is the
    /// accepted start's `seq` (carried so the finding detail can
    /// name it); `anchored` is `true` iff the anchor list contains
    /// one whose `(trail, seq, hash)` equals the accepted start.
    BelowStart { start_seq: u64, anchored: bool },
}

/// Built once per verify call from the accepted start (if any) and
/// the anchor list.
pub(super) struct Classifier {
    accepted: Option<(u64, bool)>,
}

impl Classifier {
    /// `accepted` is `Some(start)` only when [`super::start::check`]
    /// accepted that start; otherwise every `seq` is `InRange`.
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

    pub(super) fn classify(&self, seq: u64) -> Position {
        match self.accepted {
            Some((start_seq, anchored)) if seq < start_seq => Position::BelowStart {
                start_seq,
                anchored,
            },
            _ => Position::InRange,
        }
    }
}
