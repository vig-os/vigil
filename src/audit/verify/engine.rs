//! Collecting chain checks. The collection retains located physical neighbours,
//! spans, checkpoint and operator context for #13 V3b; no gap is confirmed here.
use super::{
    Finding, Report,
    input::{Collection, LineContent, Summary},
};
use crate::audit::{FindingKind as K, Record, digest_string, hex};
use std::{collections::BTreeMap, path::Path};

type Located<'a> = (&'a Path, &'a Summary);
fn finding(kind: K, path: &Path, line: Option<u64>, seq: Option<u64>, detail: String) -> Finding {
    Finding::new(kind, Some(path.to_owned()), line, seq, detail)
}

pub(super) fn check(collection: Collection, trail: [u8; 16]) -> Report {
    let mut findings = Vec::new();
    let mut groups: BTreeMap<u64, Vec<Located<'_>>> = BTreeMap::new();
    for input in &collection.inputs {
        for item in &input.data.items {
            let error = match &item.content {
                LineContent::Invalid(e) | LineContent::Unparsable(e) => Some(e),
                // Located candidates and their unchanged span bytes remain in
                // collection for #13 V3b's fragment conditions 1 and 3.
                LineContent::Fragment | LineContent::Records(_) => None,
            };
            if let Some(error) = error {
                findings.push(finding(
                    error.finding_kind().expect("decoder finding"),
                    &input.path,
                    Some(item.line),
                    None,
                    error.to_string(),
                ));
            }
        }
        if input.native
            && input
                .data
                .records
                .first()
                .is_none_or(|r| r.checkpoint.is_none())
        {
            let first = input.data.records.first();
            findings.push(finding(
                K::SegmentStructure,
                &input.path,
                first.map(|r| r.line),
                first.map(|r| r.seq),
                "expected first complete record to be a checkpoint".into(),
            ));
        }
    }
    let native = collection
        .inputs
        .iter()
        .filter(|i| i.native)
        .flat_map(|i| i.data.records.iter().map(move |r| (i.path.as_path(), r)));
    let shipped = collection.shipped.iter().map(|&(i, r)| {
        let input = &collection.inputs[i];
        (input.path.as_path(), &input.data.records[r])
    });
    for (path, record) in native.chain(shipped) {
        if record.trail != trail {
            findings.push(finding(
                K::TrailMismatch,
                path,
                Some(record.line),
                Some(record.seq),
                format!(
                    "expected trail {}, found {}",
                    hex(&trail),
                    hex(&record.trail)
                ),
            ));
        } else {
            groups.entry(record.seq).or_default().push((path, record));
        }
    }
    let mut count = 0;
    let mut previous: Option<(u64, Vec<Located<'_>>)> = None;
    for (&seq, copies) in &mut groups {
        copies.sort_by_key(|(path, r)| (*path, r.line, r.hash));
        let mut distinct = BTreeMap::new();
        for &(path, record) in copies.iter() {
            distinct.entry(record.hash).or_insert((path, record));
        }
        let candidates: Vec<_> = distinct.into_values().collect();
        count += candidates.len() as u64;
        let (path, record) = copies[0];
        if copies.len() > candidates.len() {
            findings.push(finding(
                K::DuplicateRecord,
                path,
                Some(record.line),
                Some(seq),
                format!(
                    "{} copies of {} distinct records",
                    copies.len(),
                    candidates.len()
                ),
            ));
        }
        if candidates.len() > 1 {
            findings.push(finding(
                K::SeqConflict,
                path,
                Some(record.line),
                Some(seq),
                format!(
                    "conflicting hashes: {}",
                    candidates
                        .iter()
                        .map(|(_, r)| digest_string(&r.hash))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }
        let next = previous.as_ref().map_or(0, |(s, _)| s + 1);
        if seq > next {
            findings.push(finding(
                K::SeqGap,
                path,
                Some(record.line),
                Some(seq),
                format!("missing seq {next}..={}", seq - 1),
            ));
        }
        for &(path, record) in &candidates {
            let expected = if seq == 0 {
                vec![Record::genesis(&trail)]
            } else if let Some((last, records)) = &previous {
                if last.checked_add(1) == Some(seq) {
                    records.iter().map(|(_, r)| r.hash).collect()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };
            if !expected.is_empty() && !expected.contains(&record.previous) {
                findings.push(finding(
                    K::ChainBroken,
                    path,
                    Some(record.line),
                    Some(seq),
                    format!(
                        "expected previous {}, found {}",
                        expected
                            .iter()
                            .map(digest_string)
                            .collect::<Vec<_>>()
                            .join(" or "),
                        digest_string(&record.previous)
                    ),
                ));
            }
        }
        if candidates.len() == 1
            && let Some((_, records)) = &previous
            && records.len() == 1
            && record.time < records[0].1.time
        {
            findings.push(finding(
                K::ClockWentBackwards,
                path,
                Some(record.line),
                Some(seq),
                format!(
                    "expected time >= {}, found {}",
                    records[0].1.time, record.time
                ),
            ));
        }
        previous = Some((seq, candidates));
    }
    findings.sort_by_key(|f| {
        (
            f.seq.is_none(),
            f.seq,
            f.file.clone(),
            f.line,
            format!("{:?}", f.kind),
        )
    });
    Report::new(
        trail,
        count,
        groups.first_key_value().map(|(&s, _)| s),
        groups.last_key_value().map(|(&s, _)| s),
        None,
        findings,
    )
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
