//! Anchor check for the offline verifier (ADR-0005 decision 10;
//! ruling 13-V6-d1 points 1-2).
//!
//! An anchor is a `(trail, seq, hash)` triple built from a
//! `Checkpoint` outside the trail directory. It matches only when
//! that trail is the verified trail, the verified set holds exactly
//! one distinct record at `seq` (a byte-identical duplicate is still
//! one record), and that record carries the anchor's hash. Each
//! distinct `(trail, seq, hash)` is checked once; duplicates
//! collapse. A failure is one `AnchorMismatch` (error), located at
//! the first copy of the record at `seq` in the engine's merge
//! order, or with no location when no record exists at `seq`. Only
//! the first failing condition counts, in this order (ruling 13-V6-d1
//! point 2):
//!
//!   1. `anchor seq <s> hash <hex>: trail differs`
//!   2. `anchor seq <s> hash <hex>: no record`
//!   3. `anchor seq <s> hash <hex>: seq is forked`
//!   4. `anchor seq <s> hash <hex>: hash differs (record <hex>)`
//!
//! A forked `seq` is never matched, even when one copy carries the
//! anchor's hash; the one fork definition is `engine::forked`
//! (ruling 13-V5-d2). Shipped-only copies count as records "in the
//! trail" for matching (ruling 13-V5-d4). Anchors need no signature
//! check: supplying one is the operator's statement (decision 10).

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
    if anchor.trail() != trail {
        return Some(Finding::new(
            K::AnchorMismatch,
            None,
            None,
            Some(anchor.seq()),
            format!("{prefix}trail differs"),
        ));
    }
    let Some(copies) = groups.get(&anchor.seq()) else {
        return Some(Finding::new(
            K::AnchorMismatch,
            None,
            None,
            Some(anchor.seq()),
            format!("{prefix}no record"),
        ));
    };
    if conflicting_seqs.contains(&anchor.seq()) {
        let (path, record) = first_copy(copies);
        return Some(Finding::new(
            K::AnchorMismatch,
            Some(path.to_owned()),
            Some(record.line),
            Some(anchor.seq()),
            format!("{prefix}seq is forked"),
        ));
    }
    let (path, record) = first_copy(copies);
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

/// The first copy in the engine's merge order (`(path, line, hash)`);
/// the same copy `DuplicateRecord` reports as the original.
fn first_copy<'a>(copies: &[Located<'a>]) -> Located<'a> {
    *copies
        .iter()
        .min_by_key(|(path, record)| (*path, record.line, record.hash))
        .expect("non-empty seq group")
}
