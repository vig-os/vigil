//! Collecting chain and gap checks. Native spans are attested or reported
//! pessimistically (ruling 13-V3-d3); V5 promotes a covered `TornWrite` to
//! `TornWriteRepaired` when trusted coverage lands.
use super::{
    Finding, Report,
    input::{Collection, Input, LineContent, Summary},
};
use crate::audit::{FindingKind as K, Record, digest_string, hex};
use std::{collections::BTreeMap, path::Path};

type Located<'a> = (&'a Path, &'a Summary);
fn finding(kind: K, path: &Path, line: Option<u64>, seq: Option<u64>, detail: String) -> Finding {
    Finding::new(kind, Some(path.to_owned()), line, seq, detail)
}

/// Pessimistic gap and shipped-fragment findings (ruling 13-V3-d3).
fn file_findings(input: &Input, findings: &mut Vec<Finding>) {
    let data = &input.data;
    let path = input.path.as_path();
    let mut spans = data.spans.iter();
    let mut gap: Option<u64> = None;
    let fragment_absent = |r: &Summary| {
        r.repaired.is_some().then(|| {
            let d = "fragment not present".into();
            finding(K::TornWriteRepaired, path, Some(r.line), Some(r.seq), d)
        })
    };
    for item in &data.items {
        let at = Some(item.line);
        match &item.content {
            LineContent::Invalid(e) | LineContent::Unparsable(e) => {
                let k = e.finding_kind().expect("decoder finding");
                findings.push(finding(k, path, at, e.seq(), e.to_string()));
            }
            LineContent::Fragment if !input.native => {
                let d = "fragment line in shipped input".into();
                findings.push(finding(K::Unparsable, path, at, None, d));
            }
            LineContent::Records(range) if !input.native => {
                findings.extend(
                    data.records[range.clone()]
                        .iter()
                        .filter_map(fragment_absent),
                );
            }
            _ => {}
        }
        if !input.native {
            continue;
        }
        match &item.content {
            LineContent::Fragment | LineContent::Unparsable(_) => {
                gap.get_or_insert(item.line);
            }
            LineContent::Records(range) => {
                let r = &data.records[range.start];
                if gap.take().is_none() {
                    findings.extend(fragment_absent(r));
                    continue;
                }
                let s = spans.next().expect("span");
                let got = r.repaired;
                let (kind, detail) = if got == Some(s.digest) {
                    (K::TornWrite, format!("{} gap bytes attested", s.len))
                } else {
                    let got = got.map_or_else(|| "none".into(), |d| digest_string(&d));
                    (
                        K::RepairMismatch,
                        format!("expected {}, got {}", digest_string(&s.digest), got),
                    )
                };
                findings.push(finding(kind, path, at, Some(r.seq), detail));
            }
            LineContent::Invalid(_) if gap.take().is_some() => {
                let s = spans.next().expect("span");
                let d = format!("unattested gap digest {}", digest_string(&s.digest));
                findings.push(finding(K::RepairMismatch, path, at, None, d));
            }
            _ => {}
        }
    }
    if let Some(line) = gap {
        let s = spans.next().expect("trailing span");
        let d = format!(
            "trailing gap of {} bytes, digest {}",
            s.len,
            digest_string(&s.digest)
        );
        findings.push(finding(K::TornWrite, path, Some(line), None, d));
    }
}

pub(super) fn check(collection: Collection, trail: [u8; 16]) -> Report {
    let mut findings = Vec::new();
    let mut groups: BTreeMap<u64, Vec<Located<'_>>> = BTreeMap::new();
    for input in &collection.inputs {
        file_findings(input, &mut findings);
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
