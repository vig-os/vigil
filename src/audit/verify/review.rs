//! Review-file `accept` and `accept-run` matching, driven by
//! [`super::engine::check`] in two passes. The rules and outcomes
//! are on [`crate::audit::Verifier::accept`] and
//! [`crate::audit::Verifier::accept_run`].

use super::{
    AcceptEntry, AcceptMap, AcceptRunEntry, AcceptRunMap, Finding, fold::RunIndexEntry,
    position::Classifier, receipts,
};
use crate::audit::{FindingKind as K, digest_string};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

type Remaining<'a> = Vec<(u64, &'a AcceptEntry)>;
type RemainingRuns<'a> = Vec<(u64, &'a AcceptRunEntry)>;

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
            Outcome::Promote(idx) => promote_at(findings, idx, by, reason),
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

/// Shared replacement helper: promotes the finding at `idx` to
/// [`K::Accepted`] in place (ruling 13-V8-d1 point 3). One place so
/// both `accept` and `accept-run` keep each original's location,
/// `seq` and detail unchanged except for the `accepted by` prefix.
fn promote_at(findings: &mut [Finding], idx: usize, by: &str, reason: &str) {
    findings[idx] = findings[idx].clone().accepted(by, reason);
}

fn run_subject(seq: u64, hash: &[u8; 32]) -> String {
    format!("accept-run seq {seq} hash {}", digest_string(hash))
}

/// Phase 1 for `accept-run` (pre-count): set aside each line
/// through the position classifier. The ruling 13-V8-d1 point 8
/// override (clarification 13-V8-d1a) lives on the classifier: it
/// fires exactly when an accepted start exists, the line's `seq`
/// is the start's `seq + 1`, and the verified set holds at that
/// `seq` one unforked `vigil.audit.resume` record whose hash
/// matches the line's and whose opening is the start. The run
/// that line closes then lies wholly below the start and is never
/// in the run index, so the decision never touches it. Every other
/// line falls through to normal matching, where it either matches
/// a run above the start or reports `AcceptMismatch`. The
/// remaining `(seq, entry)` pairs go to [`match_runs`].
pub(super) fn classify_run_positions<'a>(
    accepts_run: &'a AcceptRunMap,
    position: &Classifier,
    findings: &mut Vec<Finding>,
) -> RemainingRuns<'a> {
    let mut remaining = RemainingRuns::new();
    for (&seq, entry) in accepts_run {
        let (hash, _, _, _) = entry;
        let subject = run_subject(seq, hash);
        if let Some(f) = position.set_aside_for_accept_run(seq, *hash, &subject) {
            findings.push(f);
        } else if let Some(f) = position.lost_record(seq, &subject) {
            findings.push(f);
        } else {
            remaining.push((seq, entry));
        }
    }
    remaining
}

/// Phase 2 for `accept-run`: the receipt match rule on `(seq,
/// hash)`, then the "is a resume record", "closes a run" and
/// "digest matches" checks. On a match, items 1-3 of ADR-0005
/// decision 11 `accept-run` are replaced with [`K::Accepted`].
pub(super) fn match_runs(
    remaining: &RemainingRuns<'_>,
    groups: &BTreeMap<u64, Vec<(&Path, &super::input::Summary)>>,
    conflicting_seqs: &BTreeSet<u64>,
    runs: &[RunIndexEntry],
    findings: &mut Vec<Finding>,
) {
    let empty = super::lines::run_digest(&[], &[]);
    let emit = |kind, seq, subject: String, tail: &str, findings: &mut Vec<Finding>| {
        findings.push(Finding::new(
            kind,
            None,
            None,
            Some(seq),
            format!("{subject}: {tail}"),
        ));
    };
    for (seq, entry) in remaining {
        let (hash, run_digest, by, reason) = *entry;
        let subject = run_subject(*seq, hash);
        if let Some(tail) = receipts::mismatch(*seq, *hash, groups, conflicting_seqs) {
            emit(K::AcceptMismatch, *seq, subject, &tail, findings);
            continue;
        }
        // ADR-0005 decision 11: the record at `<seq>` must be a
        // `vigil.audit.resume` record, else `AcceptMismatch`.
        let copies = groups.get(seq).expect("matched implies groups has seq");
        if !copies.iter().any(|(_, r)| r.is_resume()) {
            emit(
                K::AcceptMismatch,
                *seq,
                subject,
                "not a resume record",
                findings,
            );
            continue;
        }
        match runs
            .iter()
            .find(|r| r.resume_seq == *seq && r.resume_hash == *hash)
        {
            Some(run) if run.digest == *run_digest => promote_run(findings, run, by, reason),
            Some(run) => emit(
                K::AcceptMismatch,
                *seq,
                subject,
                &format!("run digest differs (run {})", digest_string(&run.digest)),
                findings,
            ),
            // ADR-0005 decision 11: closes no run → `AcceptUnused`
            // iff the line carries the digest of nothing, else
            // `AcceptMismatch`.
            None if *run_digest == empty => {
                emit(K::AcceptUnused, *seq, subject, "no matching run", findings);
            }
            None => emit(
                K::AcceptMismatch,
                *seq,
                subject,
                &format!("run digest differs (run {})", digest_string(&empty)),
                findings,
            ),
        }
    }
}

/// Replace every items 1-3 finding of `run` with [`K::Accepted`]
/// (ADR-0005 decision 11 `accept-run`). The closing opening
/// checkpoint's `MmrMismatch` is never promoted.
fn promote_run(findings: &mut [Finding], run: &RunIndexEntry, by: &str, reason: &str) {
    let targets: Vec<usize> = (0..findings.len())
        .filter(|&idx| run_includes(run, &findings[idx]))
        .collect();
    for idx in targets {
        promote_at(findings, idx, by, reason);
    }
}

/// `true` iff `finding` is one of the run's items 1-3 and must be
/// replaced with [`K::Accepted`] (ADR-0005 decision 11 `accept-run`;
/// ruling 13-V4-d9: the closer segment belongs to the next run, so
/// its `SegmentStructure` and `MmrMismatch` are never accepted here,
/// including the closing opening checkpoint's `MmrMismatch`). Each
/// loss point's `ChainBroken` and `SeqGap` are matched on the loss
/// point's own `(file, seq)`, so a same-`seq` finding on a different
/// file (a shipped copy; a `ChainBroken` on the closer for a loss
/// that did not fire there) is never promoted. A per-segment
/// `SegmentStructure` with no first record (empty segment) carries
/// `seq = None` but still lies on a run segment, so item 1 is keyed
/// on the finding's file alone for that kind.
fn run_includes(run: &RunIndexEntry, finding: &Finding) -> bool {
    let file = finding.file();
    let on_run_segment = file.is_some_and(|p| run.segment_paths.iter().any(|q| q.as_path() == p));
    let at_loss_point = |pred: &dyn Fn(u64, u64) -> bool| {
        finding.seq().is_some_and(|s| {
            run.loss_ranges.iter().any(|(loss, first, count, path)| {
                *loss == s && file == Some(path.as_path()) && pred(*first, *count)
            })
        })
    };
    match finding.kind() {
        K::SegmentStructure => on_run_segment,
        K::ChainBroken => at_loss_point(&|_, _| true),
        K::SeqGap => at_loss_point(&|first, count| {
            count > 0 && finding.detail() == format!("missing seq {first}..={}", first + count - 1)
        }),
        K::MmrMismatch => finding
            .seq()
            .is_some_and(|s| on_run_segment && run.first_loss_seq.is_some_and(|f| s >= f)),
        _ => false,
    }
}
