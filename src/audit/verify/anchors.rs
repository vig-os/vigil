//! Anchor check for the offline verifier (ADR-0005 decision 10;
//! rulings 13-V6-d1 points 1-2, 13-V6-d3 point 4 and 13-V6-d7
//! clarification 13-V6-d7a point 2). Each distinct `(trail, seq,
//! hash)` anchor yields at most one finding, taken from the first
//! failing step in this order: trail differs, then below the start
//! (through [`super::position::Classifier::set_aside`]), no record,
//! seq is forked, hash differs. The end anchor is never set aside:
//! it skips the position step and always goes through the rule
//! (ruling 13-V6-d7a). The rule and the details are on
//! [`crate::audit::Verifier::anchor`] and the finding kinds
//! ([`crate::audit::FindingKind::AnchorMismatch`],
//! [`crate::audit::FindingKind::OutOfRange`],
//! [`crate::audit::FindingKind::UnanchoredStart`]).

use super::{Finding, input::Summary, position::Classifier};
use crate::audit::{Checkpoint, FindingKind as K, digest_string};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

type Located<'a> = (&'a Path, &'a Summary);

/// The end anchor's identity (trail, seq, hash), passed from
/// [`super::engine::check`] when
/// [`crate::audit::Verifier::end_before`] was given one. Used to
/// (1) skip the position set-aside step for the end anchor itself
/// (ruling 13-V6-d7 clarification 13-V6-d7a point 2: the end anchor
/// always goes through the anchor rule) and (2) skip the finding
/// emission in the main loop because
/// [`super::engine::check`] has already pushed it from
/// [`match_only`]. Emitting it twice would double-count.
type AnchorIdentity = ([u8; 16], u64, [u8; 32]);

/// Evaluates each distinct `(trail, seq, hash)` anchor once in the
/// engine's final seq order and appends one finding per failing
/// anchor. `end_anchor` is the end anchor's identity when
/// [`crate::audit::Verifier::end_before`] was given one; that anchor
/// is left to [`super::engine::check`] / [`match_only`], which has
/// already emitted its finding before the classifier was built, so
/// the shared rule runs in exactly one place.
pub(super) fn check(
    anchors: &[Checkpoint],
    trail: [u8; 16],
    groups: &BTreeMap<u64, Vec<Located<'_>>>,
    conflicting_seqs: &BTreeSet<u64>,
    position: &Classifier,
    end_anchor: Option<AnchorIdentity>,
    findings: &mut Vec<Finding>,
) {
    let mut seen: BTreeSet<([u8; 16], u64, [u8; 32])> = BTreeSet::new();
    let mut unique: Vec<&Checkpoint> = anchors
        .iter()
        .filter(|a| seen.insert((a.trail(), a.seq(), a.hash())))
        .collect();
    unique.sort_by_key(|a| (a.seq(), a.trail(), a.hash()));
    for anchor in unique {
        if end_anchor.is_some_and(|id| id == (anchor.trail(), anchor.seq(), anchor.hash())) {
            continue;
        }
        if let Some(finding) = evaluate(anchor, trail, groups, conflicting_seqs, Some(position)) {
            findings.push(finding);
        }
    }
}

/// Evaluates the anchor rule (ruling 13-V6-d1 point 2) without the
/// position set-aside step, for the end anchor ahead of the
/// classifier (ruling 13-V6-d7 clarification 13-V6-d7a point 2: the
/// end anchor is never set aside, so skipping position is equivalent
/// to the full rule for it). The result lands in two places with no
/// re-check: its "matches" flag drives
/// [`super::end_before::Context::is_anchored`], and its finding (if
/// any) is pushed by [`super::engine::check`] so
/// [`check`] skips the end anchor.
pub(super) fn match_only(
    anchor: &Checkpoint,
    trail: [u8; 16],
    groups: &BTreeMap<u64, Vec<Located<'_>>>,
    conflicting_seqs: &BTreeSet<u64>,
) -> Option<Finding> {
    evaluate(anchor, trail, groups, conflicting_seqs, None)
}

/// Returns at most one finding per anchor, from the first failing
/// step in the module's precedence. `position` is `Some` for the
/// regular anchor path and `None` for the end anchor (ruling
/// 13-V6-d7 clarification 13-V6-d7a point 2: skip the set-aside step
/// so the end anchor always goes through the anchor rule).
fn evaluate(
    anchor: &Checkpoint,
    trail: [u8; 16],
    groups: &BTreeMap<u64, Vec<Located<'_>>>,
    conflicting_seqs: &BTreeSet<u64>,
    position: Option<&Classifier>,
) -> Option<Finding> {
    let prefix = format!(
        "anchor seq {} hash {}",
        anchor.seq(),
        digest_string(&anchor.hash()),
    );
    let located_prefix = format!("{prefix}: ");
    let location = groups.get(&anchor.seq()).and_then(super::first_copy);
    if anchor.trail() != trail {
        return Some(located(
            location,
            anchor.seq(),
            format!("{located_prefix}trail differs"),
        ));
    }
    if let Some(p) = position
        && let Some(finding) = p.set_aside(anchor.seq(), &prefix)
    {
        return Some(finding);
    }
    if location.is_none() {
        return Some(located(
            None,
            anchor.seq(),
            format!("{located_prefix}no record"),
        ));
    }
    if conflicting_seqs.contains(&anchor.seq()) {
        return Some(located(
            location,
            anchor.seq(),
            format!("{located_prefix}seq is forked"),
        ));
    }
    let (_, record) = location.expect("checked is_none above");
    if record.hash != anchor.hash() {
        return Some(located(
            location,
            anchor.seq(),
            format!(
                "{located_prefix}hash differs (record {})",
                digest_string(&record.hash),
            ),
        ));
    }
    None
}

/// Builds an `AnchorMismatch` at `seq`, located at the given first
/// copy when one is passed, and with no location otherwise (ruling
/// 13-V6-d1 point 2).
fn located(location: Option<Located<'_>>, seq: u64, detail: String) -> Finding {
    match location {
        Some((path, record)) => Finding::new(
            K::AnchorMismatch,
            Some(path.to_owned()),
            Some(record.line),
            Some(seq),
            detail,
        ),
        None => Finding::new(K::AnchorMismatch, None, None, Some(seq), detail),
    }
}
