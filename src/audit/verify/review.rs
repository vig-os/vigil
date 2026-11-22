//! Review-file `accept` matching, driven by [`super::engine::check`]
//! in two passes. The rule and the outcomes are on
//! [`crate::audit::Verifier::accept`].

use super::{AcceptEntry, AcceptMap, Finding, position::Classifier, receipts};
use crate::audit::{FindingKind as K, digest_string};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

type Remaining<'a> = Vec<(u64, &'a AcceptEntry)>;

/// One trailing `TornWrite`'s pin kept in a side map keyed by the
/// finding's index so the public [`Finding`] stays unchanged.
/// `seq` is `None` on a file-start trailing gap (ruling 13-V8-d1
/// FORK 3, cannot be accepted).
#[derive(Clone, Copy)]
pub(super) struct TornWritePin {
    pub(super) seq: Option<u64>,
    pub(super) hash: [u8; 32],
    pub(super) no_crash: bool,
}
pub(super) type TornWritePins = BTreeMap<usize, TornWritePin>;

fn subject(kind: K, seq: u64, hash: &[u8; 32]) -> String {
    format!("accept {kind:?} seq {seq} hash {}", digest_string(hash))
}

/// Phase 1 (pre-count): set aside each `accept` through the
/// position classifier; the remaining `(seq, entry)` pairs go to
/// [`match_warnings`] after `emit_resumed`.
pub(super) fn classify_positions<'a>(
    accepts: &'a AcceptMap,
    position: &Classifier,
    findings: &mut Vec<Finding>,
) -> Remaining<'a> {
    let mut remaining = Remaining::new();
    for (&seq, entries) in accepts {
        for entry in entries {
            let subject = subject(entry.0, seq, &entry.1);
            if let Some(f) = position.set_aside(seq, &subject) {
                findings.push(f);
            } else if let Some(f) = position.lost_record(seq, &subject) {
                findings.push(f);
            } else {
                remaining.push((seq, entry));
            }
        }
    }
    remaining
}

enum Outcome {
    Promote(usize),
    Mismatch(String),
    Unused,
}

/// Phase 2: run the shared receipt match rule (or the `TornWrite`
/// pin walk) and emit the one outcome.
pub(super) fn match_warnings(
    remaining: &Remaining<'_>,
    groups: &BTreeMap<u64, Vec<(&Path, &super::input::Summary)>>,
    conflicting_seqs: &BTreeSet<u64>,
    pins: &TornWritePins,
    findings: &mut Vec<Finding>,
) {
    for (seq, entry) in remaining {
        let (kind, hash, by, reason) = *entry;
        let subject = subject(*kind, *seq, hash);
        let outcome = if *kind == K::TornWrite {
            tornwrite_outcome(pins, groups, conflicting_seqs, *seq, hash)
        } else {
            record_outcome(findings, groups, conflicting_seqs, *kind, *seq, *hash)
        };
        match outcome {
            Outcome::Promote(idx) => {
                findings[idx] = findings[idx].clone().accepted(by, reason);
            }
            Outcome::Mismatch(tail) => findings.push(Finding::new(
                K::AcceptMismatch,
                None,
                None,
                Some(*seq),
                format!("{subject}: {tail}"),
            )),
            Outcome::Unused => findings.push(Finding::new(
                K::AcceptUnused,
                None,
                None,
                Some(*seq),
                format!("{subject}: no matching warning"),
            )),
        }
    }
}

/// `TornWrite` outcome: the shared match rule owns no-record and
/// forked-seq (hash-differs does not apply, since the line carries
/// the gap digest, not the record hash); the pin walk owns
/// AcceptUnused and the no-crash-outcome mismatch.
fn tornwrite_outcome(
    pins: &TornWritePins,
    groups: &BTreeMap<u64, Vec<(&Path, &super::input::Summary)>>,
    conflicting_seqs: &BTreeSet<u64>,
    seq: u64,
    hash: &[u8; 32],
) -> Outcome {
    if !groups.contains_key(&seq) {
        return Outcome::Mismatch("no record".to_owned());
    }
    if conflicting_seqs.contains(&seq) {
        return Outcome::Mismatch("seq is forked".to_owned());
    }
    pins.iter()
        .find(|(_, p)| p.seq == Some(seq) && p.hash == *hash)
        .map_or(Outcome::Unused, |(&idx, p)| {
            if p.no_crash {
                Outcome::Mismatch("no crash outcome".to_owned())
            } else {
                Outcome::Promote(idx)
            }
        })
}

fn record_outcome(
    findings: &[Finding],
    groups: &BTreeMap<u64, Vec<(&Path, &super::input::Summary)>>,
    conflicting_seqs: &BTreeSet<u64>,
    kind: K,
    seq: u64,
    hash: [u8; 32],
) -> Outcome {
    if let Some(tail) = receipts::mismatch(seq, hash, groups, conflicting_seqs) {
        return Outcome::Mismatch(tail);
    }
    findings
        .iter()
        .position(|f| f.kind() == kind && f.seq() == Some(seq))
        .map_or(Outcome::Unused, Outcome::Promote)
}
