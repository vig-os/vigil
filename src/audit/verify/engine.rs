//! Collecting chain and gap checks (ruling 13-V3-d3). Native spans are
//! reported pessimistically; V5 promotes a covered `TornWrite` to
//! `TornWriteRepaired` when trusted coverage lands.
//!
//! Fragment context: a fragment run (consecutive `Fragment` lines) that fails
//! condition 3 (ruling 13-V3-d4, addendum 10) yields `Unparsable` "fragment
//! line failed context" at each line; the bytes stay in the gap, so V2 spans
//! are byte-for-byte unchanged. Trailing runs trivially pass. A sealed
//! segment whose successor native input starts with an opening checkpoint at
//! `seq+1` and no `vigil.audit.resume` as its second record carries the
//! "no crash outcome" mark on its trailing `TornWrite`. Every
//! `vigil.audit.resume` record raises one `Resumed` warning per `(seq, hash)`,
//! attributed to the native copy when present; a malformed declaration leaves
//! any `SeqGap` the chain loop emitted.
use super::{
    Finding, Report,
    input::{Collection, Input, LineContent, Summary},
};
use crate::audit::{FindingKind as K, Record, digest_string, hex};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

type Located<'a> = (&'a Path, &'a Summary);
fn finding(kind: K, path: &Path, line: Option<u64>, seq: Option<u64>, detail: String) -> Finding {
    Finding::new(kind, Some(path.to_owned()), line, seq, detail)
}

/// Fragment lines whose enclosing run fails condition 3 (ruling 13-V3-d4,
/// addendum 10). A trailing run is excluded; the bytes still accrue to the gap.
fn failed_fragment_lines(input: &Input) -> BTreeSet<u64> {
    let mut failed = BTreeSet::new();
    if !input.native {
        return failed;
    }
    let items = &input.data.items;
    let records = &input.data.records;
    let mut i = 0;
    while i < items.len() {
        if !matches!(items[i].content, LineContent::Fragment) {
            i += 1;
            continue;
        }
        let run_start = i;
        while i < items.len() && matches!(items[i].content, LineContent::Fragment) {
            i += 1;
        }
        let run_end = i;
        let before = items[..run_start]
            .iter()
            .rev()
            .find_map(|it| match &it.content {
                LineContent::Records(range) => Some(&records[range.end - 1]),
                _ => None,
            });
        let after = items.get(run_end).and_then(|it| match &it.content {
            LineContent::Records(range) => Some(&records[range.start]),
            _ => None,
        });
        let passes = match (items.get(run_end), before, after) {
            (None, _, _) => true,        // trailing run: condition 3 holds trivially.
            (Some(_), None, _) => false, // file-start run: no "before" record.
            (Some(_), _, None) => false, // non-Records line after the run.
            (Some(_), Some(b), Some(a)) => a.previous == b.hash,
        };
        if !passes {
            for item in &items[run_start..run_end] {
                failed.insert(item.line);
            }
        }
    }
    failed
}

/// Pessimistic gap and shipped-fragment findings (ruling 13-V3-d3).
fn file_findings(input: &Input, no_crash: bool, findings: &mut Vec<Finding>) {
    let data = &input.data;
    let path = input.path.as_path();
    let mut spans = data.spans.iter();
    let mut gap: Option<(u64, u64)> = None;
    let failed = failed_fragment_lines(input);
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
        if matches!(item.content, LineContent::Fragment) && failed.contains(&item.line) {
            let d = "fragment line failed context".into();
            findings.push(finding(K::Unparsable, path, at, None, d));
        }
        match &item.content {
            LineContent::Fragment | LineContent::Unparsable(_) => {
                let line = item.line;
                gap = Some(gap.map_or((line, line), |(first, _)| (first, line)));
            }
            LineContent::Records(range) => {
                let r = &data.records[range.start];
                let Some((first, last)) = gap.take() else {
                    findings.extend(fragment_absent(r));
                    continue;
                };
                let s = spans.next().expect("span");
                let at = format!(
                    "lines {first}..={last} ({} bytes), attested at line {} seq {}",
                    s.len, r.line, r.seq
                );
                let (kind, detail) = if r.repaired == Some(s.digest) {
                    (K::TornWrite, at)
                } else {
                    let got = r
                        .repaired
                        .map_or_else(|| "none".into(), |d| digest_string(&d));
                    let expected = digest_string(&s.digest);
                    (
                        K::RepairMismatch,
                        format!("{at}: expected {expected}, got {got}"),
                    )
                };
                findings.push(finding(kind, path, Some(first), Some(r.seq), detail));
            }
            LineContent::Invalid(_) => {
                if let Some((first, last)) = gap.take() {
                    let s = spans.next().expect("span");
                    let d = format!(
                        "lines {first}..={last} ({} bytes), unattested gap digest {}",
                        s.len,
                        digest_string(&s.digest)
                    );
                    findings.push(finding(K::RepairMismatch, path, Some(first), None, d));
                }
            }
        }
    }
    if let Some((first, last)) = gap {
        let s = spans.next().expect("trailing span");
        let mark = if no_crash { "; no crash outcome" } else { "" };
        let d = format!(
            "trailing gap lines {first}..={last} ({} bytes), digest {}{mark}",
            s.len,
            digest_string(&s.digest)
        );
        findings.push(finding(K::TornWrite, path, Some(first), None, d));
    }
}

/// True when `input` has a trailing fragment gap and the next native input in
/// `collection.inputs` starts with an opening checkpoint at `closing_seq + 1`
/// whose second complete record is not `vigil.audit.resume` (ADR l.446-451).
fn mark_no_crash(collection: &Collection, idx: usize) -> bool {
    let input = &collection.inputs[idx];
    if !input.native {
        return false;
    }
    let Some(closing) = input.data.records.last() else {
        return false;
    };
    let Some(last) = input.data.items.last() else {
        return false;
    };
    if !matches!(
        last.content,
        LineContent::Fragment | LineContent::Unparsable(_)
    ) {
        return false;
    }
    let Some(next) = collection.inputs[idx + 1..].iter().find(|i| i.native) else {
        return false;
    };
    // The successor must start with its opening checkpoint (ruling 9 (h)).
    let Some(first_item) = next.data.items.first() else {
        return false;
    };
    let LineContent::Records(range) = &first_item.content else {
        return false;
    };
    let opening = &next.data.records[range.start];
    if opening.checkpoint.is_none() || closing.seq.checked_add(1) != Some(opening.seq) {
        return false;
    }
    // Successor's second complete record must not be a resume entry.
    let second = next.data.records.get(1);
    !second.is_some_and(|r| {
        r.operator
            .as_ref()
            .is_some_and(|(action, ..)| action == "vigil.audit.resume")
    })
}

/// Validates a resume `audit.details` block per ruling 13-V3-d4 addendum 9.
/// Returns `Some((head_seq, head_hash_text, lost_through))` when canonical.
fn parse_resume(details: Option<&str>) -> Option<(u64, &str, u64)> {
    let details = details?;
    // Mirrors `storage::resume_details`; ruling 9 keeps the exact split points.
    let (named, file) = details.split_once(" file=")?;
    let (named, lost_text) = named.split_once(" lost_through=")?;
    let seq_hash = named.strip_prefix("head=")?;
    let (seq_text, hash_text) = seq_hash.split_once(':')?;
    let head_seq: u64 = seq_text.parse().ok()?;
    if head_seq.to_string() != seq_text {
        return None;
    }
    let hex_part = hash_text.strip_prefix("blake3:")?;
    if hex_part.len() != 64
        || !hex_part
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let lost: u64 = lost_text.parse().ok()?;
    if lost.to_string() != lost_text || lost < head_seq {
        return None;
    }
    if file.is_empty() || file.bytes().any(|b| b.is_ascii_whitespace()) {
        return None;
    }
    Some((head_seq, hash_text, lost))
}

/// Emits one `Resumed` warning per distinct `(seq, hash)` of a `vigil.audit.resume`
/// record on this trail, attributed to the native copy when present (addendum 8).
fn resume_findings(collection: &Collection, trail: [u8; 16], findings: &mut Vec<Finding>) {
    let mut seen = BTreeSet::new();
    let is_resume = |r: &Summary| {
        r.trail == trail
            && r.operator
                .as_ref()
                .is_some_and(|(action, ..)| action == "vigil.audit.resume")
    };
    let mut emit = |path: &Path, r: &Summary| {
        if !seen.insert((r.seq, r.hash)) {
            return;
        }
        let (actor, reason, details) = r
            .operator
            .as_ref()
            .map(|(_, actor, reason, details)| {
                (actor.as_str(), reason.as_deref(), details.as_deref())
            })
            .expect("resume operator");
        let detail = match parse_resume(details) {
            Some((head_seq, head_hash, lost)) => {
                let reason = reason.unwrap_or("");
                let gap = if lost == head_seq {
                    "none".to_owned()
                } else {
                    format!("{}..={lost}", head_seq + 1)
                };
                format!(
                    "operator={actor} reason={reason} head={head_seq}:{head_hash} gap={gap} lost_records=0"
                )
            }
            None => "malformed declaration".to_owned(),
        };
        findings.push(finding(K::Resumed, path, Some(r.line), Some(r.seq), detail));
    };
    for input in collection.inputs.iter().filter(|i| i.native) {
        for r in input.data.records.iter().filter(|r| is_resume(r)) {
            emit(&input.path, r);
        }
    }
    for input in collection.inputs.iter().filter(|i| !i.native) {
        for r in input.data.records.iter().filter(|r| is_resume(r)) {
            emit(&input.path, r);
        }
    }
}

pub(super) fn check(collection: Collection, trail: [u8; 16]) -> Report {
    let mut findings = Vec::new();
    let mut groups: BTreeMap<u64, Vec<Located<'_>>> = BTreeMap::new();
    for (idx, input) in collection.inputs.iter().enumerate() {
        let no_crash = mark_no_crash(&collection, idx);
        file_findings(input, no_crash, &mut findings);
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
    resume_findings(&collection, trail, &mut findings);
    let first_seq = groups.first_key_value().map(|(&s, _)| s);
    let last_seq = groups.last_key_value().map(|(&s, _)| s);
    if let (Some(first), Some(last)) = (first_seq, last_seq) {
        findings.push(Finding::new(
            K::UncoveredTail,
            None,
            None,
            None,
            format!("records seq {first}..={last}, no trusted coverage yet (signatures are checked in #13 V5)"),
        ));
    }
    findings.sort_by_key(|f| {
        (
            f.seq().is_none(),
            f.seq(),
            f.file().map(Path::to_path_buf),
            f.line(),
            format!("{:?}", f.kind()),
        )
    });
    Report::new(trail, count, first_seq, last_seq, None, findings)
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
