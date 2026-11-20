//! Start acceptance for the offline verifier (ADR-0005 decision 11
//! `.start_from`; ruling 13-V6-d2).
//!
//! The acceptance rule and the seven-step `StartMismatch` detail
//! precedence are on [`crate::audit::Verifier::start_from`]. This
//! module owns neither of them twice: it evaluates the one start the
//! verifier was given against the already-merged records per `seq`
//! and the shared fork set, reusing the shared verified trail id,
//! the `forked()` predicate and the first-copy helper in
//! [`super::first_copy`], and the single `trusted` predicate in
//! [`super::signatures::trusted`] (rulings 13-V6-d1 points 1-2 and
//! 13-V5-d1 point 3).
//!
//! Returns `Some(s)` only when the start is accepted, so the engine
//! suppresses the prefix `SeqGap` for `0..s−1` in exactly one place
//! (ruling 13-V6-d2 point 5); a start that is not accepted is not
//! used (point 4), so `None` runs verification as if no start had
//! been given, including the prefix `SeqGap`.

use super::{Finding, first_copy, input::Summary, signatures};
use crate::audit::{Checkpoint, FindingKind as K, TrustPolicy, digest_string};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

type Located<'a> = (&'a Path, &'a Summary);

/// Evaluates the start against the verified set and either returns
/// the accepted `seq` or appends exactly one `StartMismatch` with
/// the first failing condition's detail (ruling 13-V6-d2 point 3).
/// With no start, returns `None` and appends nothing (point 1).
pub(super) fn check(
    start: Option<&Checkpoint>,
    trail: [u8; 16],
    trust: &TrustPolicy,
    groups: &BTreeMap<u64, Vec<Located<'_>>>,
    conflicting_seqs: &BTreeSet<u64>,
    findings: &mut Vec<Finding>,
) -> Option<u64> {
    let start = start?;
    let prefix = format!(
        "start seq {} hash {}: ",
        start.seq(),
        digest_string(&start.hash()),
    );
    // Ruling 13-V6-d2 point 3: the finding is located at the first
    // copy of the first record (lowest `seq` in the merged set), or
    // without a location when the verified set is empty.
    let first_entry = groups.iter().next();
    let first_location: Option<Located<'_>> =
        first_entry.and_then(|(_, copies)| first_copy(copies));
    let emit = |detail: String| mismatch(first_location, start.seq(), detail);

    if start.trail() != trail {
        findings.push(emit(format!("{prefix}trail differs")));
        return None;
    }
    let Some((&first_seq, _)) = first_entry else {
        findings.push(mismatch(None, start.seq(), format!("{prefix}no record")));
        return None;
    };
    if first_seq != start.seq() {
        findings.push(emit(format!(
            "{prefix}not the first record (first seq {first_seq})"
        )));
        return None;
    }
    if conflicting_seqs.contains(&start.seq()) {
        findings.push(emit(format!("{prefix}seq is forked")));
        return None;
    }
    // From here on, `first_location` names the record at `start.seq()`.
    let (_, record) = first_location.expect("non-empty group at start.seq has a first copy");
    if record.checkpoint.is_none() {
        findings.push(emit(format!("{prefix}not a checkpoint")));
        return None;
    }
    if record.hash != start.hash() {
        findings.push(emit(format!(
            "{prefix}hash differs (record {})",
            digest_string(&record.hash),
        )));
        return None;
    }
    if !signatures::trusted(trail, trust, record) {
        findings.push(emit(format!("{prefix}not trusted at its seq")));
        return None;
    }
    Some(start.seq())
}

fn mismatch(location: Option<Located<'_>>, seq: u64, detail: String) -> Finding {
    match location {
        Some((path, record)) => Finding::new(
            K::StartMismatch,
            Some(path.to_owned()),
            Some(record.line),
            Some(seq),
            detail,
        ),
        None => Finding::new(K::StartMismatch, None, None, Some(seq), detail),
    }
}
