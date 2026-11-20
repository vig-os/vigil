//! Anchor check for the offline verifier (ADR-0005 decision 10;
//! rulings 13-V6-d1 points 1-2 and 13-V6-d3 point 4). Each distinct
//! `(trail, seq, hash)` anchor yields at most one finding, taken
//! from the first failing step in this order: trail differs (then
//! below the start, if applicable), no record, seq is forked, hash
//! differs. The two below-start variants are
//! [`crate::audit::FindingKind::OutOfRange`] /
//! [`crate::audit::FindingKind::UnanchoredStart`] (see the
//! [`crate::audit::verify::position`] module); the others are
//! [`crate::audit::FindingKind::AnchorMismatch`]. The rule and the
//! details are on [`crate::audit::Verifier::anchor`] and the two
//! finding kinds.

use super::{
    Finding,
    input::Summary,
    position::{Classifier, Position},
};
use crate::audit::{Checkpoint, FindingKind as K, digest_string};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

type Located<'a> = (&'a Path, &'a Summary);

/// Evaluates each distinct `(trail, seq, hash)` anchor once in the
/// engine's final seq order and appends one finding per failing
/// anchor.
pub(super) fn check(
    anchors: &[Checkpoint],
    trail: [u8; 16],
    groups: &BTreeMap<u64, Vec<Located<'_>>>,
    conflicting_seqs: &BTreeSet<u64>,
    position: &Classifier,
    findings: &mut Vec<Finding>,
) {
    let mut seen: BTreeSet<([u8; 16], u64, [u8; 32])> = BTreeSet::new();
    let mut unique: Vec<&Checkpoint> = anchors
        .iter()
        .filter(|a| seen.insert((a.trail(), a.seq(), a.hash())))
        .collect();
    unique.sort_by_key(|a| (a.seq(), a.trail(), a.hash()));
    for anchor in unique {
        if let Some(finding) = evaluate(anchor, trail, groups, conflicting_seqs, position) {
            findings.push(finding);
        }
    }
}

/// Returns at most one finding per anchor, from the first failing
/// step in the module's precedence.
fn evaluate(
    anchor: &Checkpoint,
    trail: [u8; 16],
    groups: &BTreeMap<u64, Vec<Located<'_>>>,
    conflicting_seqs: &BTreeSet<u64>,
    position: &Classifier,
) -> Option<Finding> {
    let prefix = format!(
        "anchor seq {} hash {}: ",
        anchor.seq(),
        digest_string(&anchor.hash()),
    );
    let location = groups.get(&anchor.seq()).and_then(super::first_copy);
    if anchor.trail() != trail {
        return Some(located(
            location,
            anchor.seq(),
            format!("{prefix}trail differs"),
        ));
    }
    if let Position::BelowStart {
        start_seq,
        anchored,
    } = position.classify(anchor.seq())
    {
        let kind = if anchored {
            K::OutOfRange
        } else {
            K::UnanchoredStart
        };
        return Some(Finding::new(
            kind,
            None,
            None,
            Some(anchor.seq()),
            format!("{prefix}below start seq {start_seq}"),
        ));
    }
    if location.is_none() {
        return Some(located(None, anchor.seq(), format!("{prefix}no record")));
    }
    if conflicting_seqs.contains(&anchor.seq()) {
        return Some(located(
            location,
            anchor.seq(),
            format!("{prefix}seq is forked"),
        ));
    }
    let (_, record) = location.expect("checked is_none above");
    if record.hash != anchor.hash() {
        return Some(located(
            location,
            anchor.seq(),
            format!(
                "{prefix}hash differs (record {})",
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
