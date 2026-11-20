//! Verifier `max_age` check (ADR-0005 decision 5; rulings 13-V5-d1
//! point 7 and 13-V5-d6).
//!
//! Called once by [`super::engine::check`] after the engine has
//! merged the records per `seq` and built the shared fork set
//! ([`super::engine::forked`], ruling 13-V5-d2). Appends 0 or 1
//! [`crate::audit::FindingKind::StaleHead`]:
//!
//! - **stale:** the newest trusted checkpoint has age > `max_age`,
//!   located at that checkpoint's first copy in the engine's merge
//!   order (`(path, line, hash)`).
//! - **no trusted checkpoint:** `max_age` is set and no trusted
//!   checkpoint exists on the verified trail; no location, no `seq`.
//! - **unset or fresh:** nothing is emitted.
//!
//! "Trusted" is V5a's crate-private predicate ([`signatures::trusted`],
//! ruling 13-V5-d1 point 3); the shared fork set is V5b's. Reads only
//! what the engine already has from the one snapshot (ruling 13-V4-d5).

use super::{Finding, input::Summary, signatures};
use crate::audit::{FindingKind as K, TrustPolicy};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type Located<'a> = (&'a Path, &'a Summary);

/// Appends 0 or 1 `StaleHead`. A no-op when `max_age` is `None`.
pub(super) fn check(
    trail: [u8; 16],
    trust: &TrustPolicy,
    max_age: Option<Duration>,
    now: SystemTime,
    groups: &BTreeMap<u64, Vec<Located<'_>>>,
    conflicting_seqs: &BTreeSet<u64>,
    findings: &mut Vec<Finding>,
) {
    let Some(max_age) = max_age else {
        return;
    };
    let d = max_age.as_nanos();
    let now_ns = now
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    match newest_trusted(groups, conflicting_seqs, trail, trust) {
        Some((path, record)) => {
            let age = now_ns.saturating_sub(u128::from(record.time));
            if age > d {
                let seq = record.seq;
                let t = record.time;
                findings.push(Finding::new(
                    K::StaleHead,
                    Some(path.to_owned()),
                    Some(record.line),
                    Some(seq),
                    format!(
                        "newest trusted checkpoint seq {seq} time {t} \
                         is older than max_age {d} at {now_ns}"
                    ),
                ));
            }
        }
        None => findings.push(Finding::new(
            K::StaleHead,
            None,
            None,
            None,
            format!("no trusted checkpoint (max_age {d})"),
        )),
    }
}

/// Ruling 13-V5-d6 point 3: the trusted (ruling 13-V5-d1 point 3)
/// checkpoint with the highest `seq`, including shipped-only copies.
/// At a forked `seq` (two or more distinct hashes on the verified
/// trail, ruling 13-V5-d2), skip to the highest unforked trusted
/// `seq` below it. The first copy at that `seq` in the engine's merge
/// order (`(path, line, hash)`) carries the location, so byte-
/// identical duplicates report at the same copy `DuplicateRecord`
/// treats as the original.
fn newest_trusted<'a>(
    groups: &'a BTreeMap<u64, Vec<Located<'a>>>,
    conflicting_seqs: &BTreeSet<u64>,
    trail: [u8; 16],
    trust: &TrustPolicy,
) -> Option<Located<'a>> {
    groups
        .iter()
        .rev()
        .filter(|(seq, _)| !conflicting_seqs.contains(seq))
        .find_map(|(_, copies)| {
            copies
                .iter()
                .filter(|(_, r)| signatures::trusted(trail, trust, r))
                .min_by_key(|(path, record)| (*path, record.line, record.hash))
                .copied()
        })
}
