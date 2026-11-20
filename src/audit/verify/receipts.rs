//! Receipt reconciliation (ADR-0005 decision 5 "Receipt
//! reconciliation"; ruling 13-V7-d1 points 2-5 and its clarification
//! 13-V7-d1a). The rule, the range, the three `ReceiptMismatch`
//! details with their precedence and the `NoReceipt` grammar live on
//! [`crate::audit::Verifier::receipts`],
//! [`crate::audit::FindingKind::NoReceipt`] and
//! [`crate::audit::FindingKind::ReceiptMismatch`]; this module owns
//! none of them twice. The shared merged records per `seq`, fork
//! set and position classifier come from [`super::engine::check`].

use super::{Finding, first_copy, input::Summary, position::Classifier};
use crate::audit::{FindingKind as K, digest_string};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

type Located<'a> = (&'a Path, &'a Summary);

/// Evaluates the receipt set against the verified records and
/// appends every `ReceiptMismatch`, in-range `NoReceipt` and
/// `OutOfRange` / `UnanchoredStart` / `UnanchoredEnd` the rule
/// produces. Called once from [`super::engine::check`], only when
/// [`crate::audit::Verifier::receipts`] turned reconciliation on.
pub(super) fn check(
    receipts: &BTreeSet<(u64, [u8; 32])>,
    groups: &BTreeMap<u64, Vec<Located<'_>>>,
    conflicting_seqs: &BTreeSet<u64>,
    position: &Classifier,
    findings: &mut Vec<Finding>,
) {
    for &(seq, hash) in receipts {
        let subject = format!("receipt seq {seq} hash {}", digest_string(&hash));
        if let Some(finding) = position.set_aside(seq, &subject) {
            findings.push(finding);
            continue;
        }
        if let Some(tail) = mismatch(seq, hash, groups, conflicting_seqs) {
            findings.push(Finding::new(
                K::ReceiptMismatch,
                None,
                None,
                Some(seq),
                format!("{subject}: {tail}"),
            ));
        }
    }
    for (&seq, copies) in groups {
        if !position.is_in_range(seq) {
            continue;
        }
        // Every distinct record at `seq` is `NoReceipt` unless a
        // receipt names its exact `(seq, hash)` AND the `seq` is not
        // forked. At a forked `seq` the match rule fails closed, as
        // anchors do (clarification 13-V7-d1a point 1; ruling
        // 13-V6-d1 point 2), so a receipt naming one copy there is
        // `ReceiptMismatch "seq is forked"`, never a match, and
        // suppresses no `NoReceipt`.
        let forked = conflicting_seqs.contains(&seq);
        let mut distinct: BTreeSet<[u8; 32]> = BTreeSet::new();
        for &(_, record) in copies {
            distinct.insert(record.hash);
        }
        for hash in distinct {
            if !forked && receipts.contains(&(seq, hash)) {
                continue;
            }
            // Shared `first_copy`: the record's first copy in the
            // engine's merge order (`(is_end_record, path, line,
            // hash)`), the same copy `DuplicateRecord` reports as
            // the original (ruling 13-V5-d4).
            let Some((path, record)) = first_copy(copies.iter().filter(|(_, r)| r.hash == hash))
            else {
                continue;
            };
            if record.checkpoint.is_some() || record.is_end_record {
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
