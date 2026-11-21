//! Receipt reconciliation (ADR-0005 decision 5 "Receipt
//! reconciliation", "Waivers, for an honest crash" and "Late
//! adoption"; ruling 13-V7-d1 points 2-6 and its clarification
//! 13-V7-d1a). The range, match rule, `ReceiptMismatch` precedence
//! and the `NoReceipt` / `ReceiptWaived` detail grammars live on
//! [`crate::audit::Verifier::receipts`],
//! [`crate::audit::Verifier::waive`] and
//! [`crate::audit::Verifier::receipts_from`]; this module owns
//! none of them twice.

use super::{Finding, input::Summary, position::Classifier};
use crate::audit::{FindingKind as K, digest_string};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

type Located<'a> = (&'a Path, &'a Summary);

/// Reconciliation inputs bundle (ruling 13-V7-d1 point 2: receipts,
/// waivers and `from` all turn reconciliation on). Built in
/// [`crate::audit::Verifier::verify_files`].
pub(super) struct Inputs<'a> {
    pub(super) receipts: &'a BTreeSet<(u64, [u8; 32])>,
    pub(super) waivers: &'a BTreeMap<u64, ([u8; 32], String)>,
    pub(super) receipts_from: Option<&'a (u64, [u8; 32], String)>,
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
    for (&seq, copies) in groups {
        if !position.is_in_range(seq) {
            continue;
        }
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
        for (hash, (path, record)) in first_per_hash {
            if !forked && inputs.receipts.contains(&(seq, hash)) {
                continue;
            }
            if !forked && inputs.waivers.get(&seq).is_some_and(|(h, _)| *h == hash) {
                continue;
            }
            // Checkpoints are not reconciled (ruling 13-V7-d1 point
            // 5). End-record copies cannot reach this point: their
            // `seq` is at or above the end checkpoint's `seq`, which
            // [`Classifier::is_in_range`] has already cut above.
            if record.checkpoint.is_some() {
                continue;
            }
            findings.push(Finding::new(
                K::NoReceipt,
                Some(path.to_owned()),
                Some(record.line),
                Some(seq),
                format!("no receipt for seq {seq} hash {}", digest_string(&hash)),
            ));
        }
    }
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
