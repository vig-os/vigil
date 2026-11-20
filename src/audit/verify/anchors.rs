//! Anchor check for the offline verifier (ADR-0005 decision 10;
//! ruling 13-V6-d1 points 1-2).
//!
//! Each distinct `(trail, seq, hash)` anchor is checked once. One
//! failing [`crate::audit::FindingKind::AnchorMismatch`] per anchor,
//! located at the first copy of the record at `seq` in the engine's
//! merge order, or with no location when no record exists at `seq`.
//! Only the first failing condition counts (trail differs, no record,
//! seq is forked, hash differs). The full rule and the detail grammar
//! are on [`crate::audit::Verifier::anchor`].

use super::{Finding, input::Summary};
use crate::audit::{Checkpoint, FindingKind as K, digest_string};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

type Located<'a> = (&'a Path, &'a Summary);

/// Evaluates each distinct `(trail, seq, hash)` anchor once in the
/// engine's final seq order and appends one `AnchorMismatch` per
/// failing anchor (ruling 13-V6-d1 point 2).
pub(super) fn check(
    anchors: &[Checkpoint],
    trail: [u8; 16],
    groups: &BTreeMap<u64, Vec<Located<'_>>>,
    conflicting_seqs: &BTreeSet<u64>,
    findings: &mut Vec<Finding>,
) {
    let mut seen: BTreeSet<([u8; 16], u64, [u8; 32])> = BTreeSet::new();
    let mut unique: Vec<&Checkpoint> = anchors
        .iter()
        .filter(|a| seen.insert((a.trail(), a.seq(), a.hash())))
        .collect();
    unique.sort_by_key(|a| (a.seq(), a.trail(), a.hash()));
    for anchor in unique {
        if let Some(finding) = evaluate(anchor, trail, groups, conflicting_seqs) {
            findings.push(finding);
        }
    }
}

/// Applies the four-step precedence and returns the single
/// `AnchorMismatch` (if any) at the first failing condition.
///
/// Every finding except `no record` locates at the first copy of the
/// record at `seq` when one exists on the verified trail, and has no
/// location otherwise (ruling 13-V6-d1 point 2); `no record` is the
/// one case that has no record to locate against.
fn evaluate(
    anchor: &Checkpoint,
    trail: [u8; 16],
    groups: &BTreeMap<u64, Vec<Located<'_>>>,
    conflicting_seqs: &BTreeSet<u64>,
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
    let Some((path, record)) = location else {
        return Some(Finding::new(
            K::AnchorMismatch,
            None,
            None,
            Some(anchor.seq()),
            format!("{prefix}no record"),
        ));
    };
    if conflicting_seqs.contains(&anchor.seq()) {
        return Some(Finding::new(
            K::AnchorMismatch,
            Some(path.to_owned()),
            Some(record.line),
            Some(anchor.seq()),
            format!("{prefix}seq is forked"),
        ));
    }
    if record.hash != anchor.hash() {
        return Some(Finding::new(
            K::AnchorMismatch,
            Some(path.to_owned()),
            Some(record.line),
            Some(anchor.seq()),
            format!(
                "{prefix}hash differs (record {})",
                digest_string(&record.hash),
            ),
        ));
    }
    None
}

/// Builds the finding at a known location (or with none) on the first
/// matching precedence step that still runs when the anchor names
/// another trail.
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
