//! Review-file `accept` matching (ADR-0005 decision 11 "Review
//! file"; ruling 13-V8-d1). Called once from [`super::engine::check`]
//! after every warning has been emitted. The shared classifier
//! (below start / above end, confirmed-gap `LostRecord`) and the
//! receipt match rule stay the single owners of position and
//! record-mismatch: this module only drives them and emits
//! [`crate::audit::FindingKind::Accepted`],
//! [`crate::audit::FindingKind::AcceptMismatch`] and
//! [`crate::audit::FindingKind::AcceptUnused`] on top.
//!
//! The rule (ruling 13-V8-d1 point 3) is: for each `(kind, seq,
//! hash)` pin,
//!
//! - a line below an accepted start or above the end of a bounded
//!   batch is set aside through [`super::position::Classifier::set_aside`];
//! - a line inside a confirmed resume gap is one unlocated
//!   [`crate::audit::FindingKind::LostRecord`] through
//!   [`super::position::Classifier::lost_record`];
//! - a line whose `seq` has no record on the verified trail, or
//!   whose `seq` is forked, is [`crate::audit::FindingKind::AcceptMismatch`]
//!   with the shared [`super::receipts::mismatch`] tail;
//! - for `Resumed`, `ClockWentBackwards` and `DuplicateRecord`, a
//!   line whose `seq` holds a record with a different hash is
//!   `AcceptMismatch` with the shared `hash differs (…)` tail;
//! - for a trailing `TornWrite`, the pin is `(seq of the last
//!   complete record before the gap, gap digest)`: a line matching
//!   that pin promotes the finding (unless the gap is marked `no
//!   crash outcome`, in which case the line is `AcceptMismatch`);
//!   a line with any other digest is [`crate::audit::FindingKind::AcceptUnused`];
//!   a trailing `TornWrite` with no record before the gap (FORK 3,
//!   ruling 13-V8-d1 point 5) has no pin and cannot be accepted;
//! - otherwise, a line that matches the record but no warning is
//!   `AcceptUnused`;
//! - a match replaces the warning in place (ruling 13-V8-d1 point
//!   3): the finding keeps its original file, line and `seq`, and
//!   its detail becomes `accepted by <by>: <reason>; was:
//!   <original detail>`.

use super::{AcceptMap, Finding, input::Summary, position::Classifier, receipts};
use crate::audit::{FindingKind as K, digest_string};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

type Groups<'a> = BTreeMap<u64, Vec<(&'a Path, &'a Summary)>>;

/// The one match outcome, as [`check`] drives it.
enum MatchOutcome {
    /// Promote the finding at the given index to `Accepted`.
    Promote(usize),
    /// The trailing `TornWrite` at the pin is marked "no crash
    /// outcome" (ruling 13-V8-d1 point 2; ADR-0005 decision 11).
    NoCrashOutcome,
    /// No matching warning; emit `AcceptUnused`.
    Unused,
}

pub(super) fn check(
    accepts: &AcceptMap,
    groups: &Groups<'_>,
    conflicting_seqs: &BTreeSet<u64>,
    position: &Classifier,
    findings: &mut Vec<Finding>,
) {
    for (&seq, entries) in accepts {
        for (kind, hash, by, reason) in entries {
            let subject = format!("accept {kind:?} seq {seq} hash {}", digest_string(hash));
            if let Some(f) = position.set_aside(seq, &subject) {
                findings.push(f);
                continue;
            }
            if let Some(f) = position.lost_record(seq, &subject) {
                findings.push(f);
                continue;
            }
            // Reuse the shared no-record / forked / hash-differs
            // tail from `receipts::mismatch`. `TornWrite` skips
            // the hash-differs branch (its hash is the gap digest,
            // not the record hash); the trailing-pin walk below
            // reports that outcome as `AcceptUnused` when no pin
            // matches.
            if let Some(tail) = receipts::mismatch(seq, *hash, groups, conflicting_seqs) {
                let hash_differs = tail.starts_with("hash differs");
                if !hash_differs || *kind != K::TornWrite {
                    findings.push(Finding::new(
                        K::AcceptMismatch,
                        None,
                        None,
                        Some(seq),
                        format!("{subject}: {tail}"),
                    ));
                    continue;
                }
            }
            match match_outcome(findings, *kind, seq, *hash) {
                MatchOutcome::Promote(idx) => {
                    findings[idx].promote_to_accepted(by, reason);
                }
                MatchOutcome::NoCrashOutcome => findings.push(Finding::new(
                    K::AcceptMismatch,
                    None,
                    None,
                    Some(seq),
                    format!("{subject}: no crash outcome"),
                )),
                MatchOutcome::Unused => findings.push(Finding::new(
                    K::AcceptUnused,
                    None,
                    None,
                    Some(seq),
                    format!("{subject}: no matching warning"),
                )),
            }
        }
    }
}

/// Which warning (if any) the `(kind, seq, hash)` pin matches
/// (ruling 13-V8-d1 points 3 and 5; ADR-0005 decision 11 "What pins
/// each kind"). For `TornWrite`, the pin is `(pin_seq, pin_hash)`
/// on the trailing finding (file-start FORK 3 keeps its pin `None`
/// and never matches); otherwise it is `(seq, record hash)`, which
/// [`check`] has already verified through
/// [`super::receipts::mismatch`] before this call.
fn match_outcome(findings: &[Finding], kind: K, seq: u64, hash: [u8; 32]) -> MatchOutcome {
    if kind == K::TornWrite {
        for (i, f) in findings.iter().enumerate() {
            if f.kind() != K::TornWrite {
                continue;
            }
            if f.pin_seq() != Some(seq) || f.pin_hash() != Some(hash) {
                continue;
            }
            if f.detail().ends_with("; no crash outcome") {
                return MatchOutcome::NoCrashOutcome;
            }
            return MatchOutcome::Promote(i);
        }
        return MatchOutcome::Unused;
    }
    for (i, f) in findings.iter().enumerate() {
        if f.kind() == kind && f.seq() == Some(seq) {
            return MatchOutcome::Promote(i);
        }
    }
    MatchOutcome::Unused
}
