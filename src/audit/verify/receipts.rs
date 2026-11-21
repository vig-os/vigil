//! Receipt reconciliation (ADR-0005 decision 5 "Receipt
//! reconciliation", "Waivers, for an honest crash", "Late adoption"
//! and "Live trails"; ruling 13-V7-d1 points 2-6 and 10 and its
//! clarification 13-V7-d1a). The range, match rule, `ReceiptMismatch`
//! precedence and the `NoReceipt` / `ReceiptWaived` / `Unreconciled`
//! detail grammars live on [`crate::audit::Verifier::receipts`],
//! [`crate::audit::Verifier::waive`],
//! [`crate::audit::Verifier::receipts_from`] and
//! [`crate::audit::Verifier::receipts_live`]; this module owns
//! none of them twice.

use super::{Finding, first_copy, input::Summary, position::Classifier};
use crate::audit::{FindingKind as K, digest_string};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

type Located<'a> = (&'a Path, &'a Summary);

/// Reconciliation inputs bundle (ruling 13-V7-d1 points 2 and 10:
/// receipts, waivers, `from` and `live` all turn reconciliation on).
/// Built in [`crate::audit::Verifier::verify_files`].
pub(super) struct Inputs<'a> {
    pub(super) receipts: &'a BTreeSet<(u64, [u8; 32])>,
    pub(super) waivers: &'a BTreeMap<u64, ([u8; 32], String)>,
    pub(super) receipts_from: Option<&'a (u64, [u8; 32], String)>,
    /// `true` iff [`crate::audit::Verifier::receipts_live`]`(true)`
    /// was the last call: records above the longest fully
    /// reconciled prefix collapse to one `Unreconciled` (info) and
    /// get no `NoReceipt` (ruling 13-V7-d1 point 10).
    pub(super) live: bool,
}

/// Which subject the one match rule is running for (ruling 13-V7-d1
/// points 4 and 6): a `Receipt` runs the rule without emitting
/// `ReceiptWaived`; a `Waive` or `From` emits one `ReceiptWaived` at
/// the matched record and carries its reason for the detail. The
/// subject prefix (`receipt`, `waive`, `from`) is the first word of
/// the finding's `subject` text.
enum Subject<'a> {
    Receipt,
    Waive(&'a str),
    From(&'a str),
}
impl Subject<'_> {
    fn prefix(&self) -> &'static str {
        match self {
            Subject::Receipt => "receipt",
            Subject::Waive(_) => "waive",
            Subject::From(_) => "from",
        }
    }
}

/// Evaluates receipts, waivers and `from` against the verified
/// records and appends every `ReceiptMismatch`, in-range `NoReceipt`,
/// `ReceiptWaived` and position set-aside the rules produce. Called
/// once from [`super::engine::check`], only when any of the inputs
/// turned reconciliation on.
pub(super) fn check(
    inputs: &Inputs<'_>,
    groups: &BTreeMap<u64, Vec<Located<'_>>>,
    conflicting_seqs: &BTreeSet<u64>,
    position: &Classifier,
    findings: &mut Vec<Finding>,
) {
    let ctx = Ctx {
        groups,
        conflicting_seqs,
        position,
    };
    // One match path for every receipt, waiver and `from`
    // (ruling 13-V7-d1 points 4 and 6): [`match_one`] runs the
    // shared subject-format, [`Classifier::set_aside`], mismatch
    // and (for a waiver or `from`) the `ReceiptWaived` emission,
    // then returns `true` on a match so the `from` caller can mark
    // its exemption.
    for &(seq, hash) in inputs.receipts {
        match_one(seq, hash, &Subject::Receipt, &ctx, findings);
    }
    // Ruling 13-V7-d1 point 6: a matched `from` exempts every
    // record at or below its `seq` from `NoReceipt`, so the loop
    // below reads back the matched `seq`. A mismatched `from`
    // exempts nothing.
    let matched_from_seq = inputs.receipts_from.and_then(|(seq, hash, reason)| {
        match_one(*seq, *hash, &Subject::From(reason), &ctx, findings).then_some(*seq)
    });
    for (&seq, (hash, reason)) in inputs.waivers {
        match_one(seq, *hash, &Subject::Waive(reason), &ctx, findings);
    }
    // One pass over the in-range groups (ruling 13-V7-d1 points 3
    // and 10): it emits (or defers under `live`) one `NoReceipt`
    // per unmatched non-checkpoint copy and, from the same per-seq
    // match outcome, records the lowest in-range `seq` whose record
    // breaks the reconciled prefix (`first_unreconciled`) and the
    // highest in-range `seq` (`head_in_range`). `first_unreconciled`
    // is `None` when every in-range `audit.record` is matched,
    // waived or exempted by a matched `from`, so checkpoints -- which
    // never emit `NoReceipt` here -- never break the prefix. In
    // stopped mode `findings` grows as it did before; in live mode
    // the per-seq `NoReceipt` vectors are held in `pending` until the
    // cut is known, so no `NoReceipt` ever lands above the cut.
    let mut pending: Vec<(u64, Vec<Finding>)> = Vec::new();
    let mut first_unreconciled: Option<u64> = None;
    let mut head_in_range: Option<u64> = None;
    for (&seq, copies) in groups {
        if !position.is_in_range(seq) {
            continue;
        }
        head_in_range = Some(seq);
        if matched_from_seq.is_some_and(|s| seq <= s) {
            continue;
        }
        // Every distinct record at `seq` is `NoReceipt` unless a
        // receipt or a matching waiver names its exact `(seq, hash)`
        // AND the `seq` is not forked. At a forked `seq` the match
        // rule fails closed, as anchors do (clarification 13-V7-d1a
        // point 1; ruling 13-V6-d1 point 2), so neither a receipt
        // nor a waiver suppresses `NoReceipt` there.
        //
        // `copies` is already sorted by `(is_end_record, path, line,
        // hash)` in [`super::engine::check`], which is the shared
        // merge order used by [`super::first_copy`]. Inserting with
        // `or_insert` picks the first copy per distinct hash in that
        // order --- the same copy `DuplicateRecord` reports as the
        // original (ruling 13-V5-d4) and the same copy `first_copy`
        // would return --- without a dead "no copy for this hash"
        // arm (every hash we iterate came from these `copies`).
        let forked = conflicting_seqs.contains(&seq);
        let mut first_per_hash: BTreeMap<[u8; 32], Located<'_>> = BTreeMap::new();
        for &copy in copies {
            first_per_hash.entry(copy.1.hash).or_insert(copy);
        }
        let mut seq_no_receipts: Vec<Finding> = Vec::new();
        for (hash, (path, record)) in first_per_hash {
            if !forked && inputs.receipts.contains(&(seq, hash)) {
                continue;
            }
            if !forked && inputs.waivers.get(&seq).is_some_and(|(h, _)| *h == hash) {
                continue;
            }
            // Checkpoints are not reconciled (ruling 13-V7-d1 points
            // 5 and 10): they emit no `NoReceipt` and never break
            // the prefix. End-record copies cannot reach this point:
            // their `seq` is at or above the end checkpoint's `seq`,
            // which [`Classifier::is_in_range`] has already cut
            // above.
            if record.checkpoint.is_some() {
                continue;
            }
            seq_no_receipts.push(Finding::new(
                K::NoReceipt,
                Some(path.to_owned()),
                Some(record.line),
                Some(seq),
                format!("no receipt for seq {seq} hash {}", digest_string(&hash)),
            ));
        }
        if !seq_no_receipts.is_empty() && first_unreconciled.is_none() {
            first_unreconciled = Some(seq);
        }
        pending.push((seq, seq_no_receipts));
    }
    if !inputs.live {
        for (_, items) in pending {
            findings.extend(items);
        }
        return;
    }
    // Ruling 13-V7-d1 point 10: `cut = min(first unreconciled seq,
    // highest receipt seq + 1)`, and with no receipts it drops to
    // the first in-range record. A matched `from` or waiver extends
    // the reconciled prefix through its record (both leave
    // `first_unreconciled` unchanged there), while the "never above
    // the highest receipt" cap keeps the cut in the exported history
    // so an honest hole above the receipts is still `Unreconciled`
    // (L6).
    let Some(head) = head_in_range else {
        return;
    };
    let cut = match inputs.receipts.iter().map(|(s, _)| *s).max() {
        Some(hr) => first_unreconciled.map_or(hr + 1, |f| f.min(hr + 1)),
        None => first_record_in_range(groups, position).unwrap_or(head),
    };
    for (seq, items) in pending {
        if seq < cut {
            findings.extend(items);
        }
    }
    // One `Unreconciled` (info) located at the first in-range record
    // whose `seq >= cut` (ruling 13-V7-d1 point 10). Nothing above
    // the cut yields no finding; checkpoints above the cut are
    // eligible locations, so "never above the highest receipt"
    // places the locator on a checkpoint when the next record is one
    // (L6).
    if let Some((&first_seq, copies)) = groups.range(cut..).find(|&(&s, _)| position.is_in_range(s))
        && let Some((path, record)) = first_copy(copies.iter())
    {
        findings.push(Finding::new(
            K::Unreconciled,
            Some(path.to_owned()),
            Some(record.line),
            Some(first_seq),
            format!("records seq {first_seq}..={head} not reconciled"),
        ));
    }
}

/// Lowest in-range `seq` with a record in `groups`, read off the
/// ascending `BTreeMap` iteration once (ruling 13-V7-d1 point 10's
/// "with no receipts at all it is the first record of the range").
fn first_record_in_range(
    groups: &BTreeMap<u64, Vec<Located<'_>>>,
    position: &Classifier,
) -> Option<u64> {
    groups
        .keys()
        .copied()
        .find(|&seq| position.is_in_range(seq))
}

/// Shared verifier state the one match rule reads (ruling 13-V7-d1
/// points 4 and 6). Owned by [`check`], passed into [`match_one`]
/// by reference.
struct Ctx<'a, 'b> {
    groups: &'a BTreeMap<u64, Vec<Located<'b>>>,
    conflicting_seqs: &'a BTreeSet<u64>,
    position: &'a Classifier,
}

/// Runs the shared match rule once for a receipt, a waiver or a
/// `from` (ruling 13-V7-d1 points 4 and 6). On set-aside or
/// mismatch, pushes the finding and returns `false`; on a match,
/// emits one `ReceiptWaived` at the record's first copy for a
/// waiver or `from` (no finding for a receipt) and returns `true`
/// so [`check`] can mark the `from` exemption.
fn match_one(
    seq: u64,
    hash: [u8; 32],
    subject: &Subject<'_>,
    ctx: &Ctx<'_, '_>,
    findings: &mut Vec<Finding>,
) -> bool {
    let subject_text = format!(
        "{} seq {seq} hash {}",
        subject.prefix(),
        digest_string(&hash)
    );
    if let Some(finding) = ctx.position.set_aside(seq, &subject_text) {
        findings.push(finding);
        return false;
    }
    if let Some(tail) = mismatch(seq, hash, ctx.groups, ctx.conflicting_seqs) {
        findings.push(Finding::new(
            K::ReceiptMismatch,
            None,
            None,
            Some(seq),
            format!("{subject_text}: {tail}"),
        ));
        return false;
    }
    if let Some((matched_verb, reason)) = match subject {
        Subject::Receipt => None,
        Subject::Waive(reason) => Some(("waived", *reason)),
        Subject::From(reason) => Some(("from", *reason)),
    } {
        let (path, record) = ctx
            .groups
            .get(&seq)
            .and_then(|c| c.first().copied())
            .expect("match implies groups holds one copy at seq");
        findings.push(Finding::new(
            K::ReceiptWaived,
            Some(path.to_owned()),
            Some(record.line),
            Some(seq),
            format!(
                "{matched_verb} seq {seq} hash {}: {reason}",
                digest_string(&hash)
            ),
        ));
    }
    true
}

/// Returns the first failing step of the match rule as the tail of
/// the `ReceiptMismatch` detail, or `None` when the verified set
/// holds exactly one record at `seq` and its hash equals the
/// receipt's hash (ruling 13-V7-d1 point 4).
fn mismatch(
    seq: u64,
    hash: [u8; 32],
    groups: &BTreeMap<u64, Vec<Located<'_>>>,
    conflicting_seqs: &BTreeSet<u64>,
) -> Option<String> {
    let Some(copies) = groups.get(&seq) else {
        return Some("no record".to_owned());
    };
    if conflicting_seqs.contains(&seq) {
        return Some("seq is forked".to_owned());
    }
    let record_hash = copies[0].1.hash;
    (record_hash != hash).then(|| format!("hash differs (record {})", digest_string(&record_hash)))
}
