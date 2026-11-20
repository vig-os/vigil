//! `end=` retirement check (ADR-0005 decision 9; rulings 13-V5-d1
//! point 5 and 13-V5-d5).
//!
//! Two independent conditions are evaluated against the engine's
//! merged records per `seq` and the shared `conflicting_seqs` set
//! (same fork definition as [`super::engine::check`], ruling
//! 13-V5-d2). The detail grammar and location per condition are on
//! [`crate::audit::FindingKind::TrailEnded`]. A matching `end=`
//! (neither condition fails) grants the tail exemption, confirmation
//! of `through=` bounds at or below `s` (the pin still runs), and
//! promotion of 13-V5-d2 repairs at or below `s`; a mismatch grants
//! none of them; no `end=` checks nothing (ruling 13-V5-d5 point 2).
//! Reads only what the engine already has from the one snapshot
//! (ruling 13-V4-d5): no second file pass.

use super::{Finding, input::Summary};
use crate::audit::{FindingKind as K, TrustPolicy, digest_string};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

type Located<'a> = (&'a Path, &'a Summary);

/// Evaluates the verified trail's section's `end=` once. Appends
/// 0, 1 or 2 `TrailEnded` findings and returns the matched end `seq`
/// when both conditions pass; `None` covers both mismatch and "no
/// `end=` in the section" (the latter does nothing).
pub(super) fn check(
    trail: [u8; 16],
    trust: &TrustPolicy,
    groups: &BTreeMap<u64, Vec<Located<'_>>>,
    conflicting_seqs: &BTreeSet<u64>,
    findings: &mut Vec<Finding>,
) -> Option<u64> {
    let (s, h) = trust.end(&trail)?;
    let prefix = format!("end={s}:{}: ", digest_string(&h));
    let mut matched = at_seq(s, h, &prefix, groups, conflicting_seqs, findings);
    if above_seq(s, &prefix, groups, findings) {
        matched = false;
    }
    matched.then_some(s)
}

/// Returns `true` when the verified set holds exactly one distinct
/// record at `s` with hash `h`; otherwise emits one `TrailEnded` for
/// the first failing check in the ruling's order (forked, absent,
/// other hash) and returns `false`.
fn at_seq(
    s: u64,
    h: [u8; 32],
    prefix: &str,
    groups: &BTreeMap<u64, Vec<Located<'_>>>,
    conflicting_seqs: &BTreeSet<u64>,
    findings: &mut Vec<Finding>,
) -> bool {
    if conflicting_seqs.contains(&s) {
        findings.push(Finding::new(
            K::TrailEnded,
            None,
            None,
            Some(s),
            format!("{prefix}seq {s} is forked"),
        ));
        return false;
    }
    let Some(copies) = groups.get(&s) else {
        findings.push(Finding::new(
            K::TrailEnded,
            None,
            None,
            Some(s),
            format!("{prefix}no record at seq {s}"),
        ));
        return false;
    };
    let (path, record) = first_copy(copies);
    if record.hash != h {
        findings.push(Finding::new(
            K::TrailEnded,
            Some(path.to_owned()),
            Some(record.line),
            Some(s),
            format!(
                "{prefix}record at seq {s} has hash {}",
                digest_string(&record.hash),
            ),
        ));
        return false;
    }
    true
}

/// Returns `true` and emits one `TrailEnded` when any record of
/// the verified trail has `seq` strictly above `s`, located at the
/// first such record in the engine's merge order.
fn above_seq(
    s: u64,
    prefix: &str,
    groups: &BTreeMap<u64, Vec<Located<'_>>>,
    findings: &mut Vec<Finding>,
) -> bool {
    let Some(next) = s.checked_add(1) else {
        return false;
    };
    let mut above = groups.range(next..);
    let Some((&a, copies)) = above.next() else {
        return false;
    };
    let b = above.next_back().map_or(a, |(&last, _)| last);
    let (path, record) = first_copy(copies);
    findings.push(Finding::new(
        K::TrailEnded,
        Some(path.to_owned()),
        Some(record.line),
        Some(a),
        format!("{prefix}records seq {a}..={b} above the end"),
    ));
    true
}

/// The first copy in the engine's merge order (`(path, line,
/// hash)`): same copy `DuplicateRecord` reports as the original.
fn first_copy<'a>(copies: &[Located<'a>]) -> Located<'a> {
    *copies
        .iter()
        .min_by_key(|(path, record)| (*path, record.line, record.hash))
        .expect("non-empty seq group")
}
