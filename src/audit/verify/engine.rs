//! Collecting chain and gap checks (ruling 13-V3-d3). A native gap
//! attested by a record whose `seq <= covered_through` is reported as
//! `TornWriteRepaired`, but only when that attesting record is itself a
//! record of the verified trail AND its `seq` carries no `SeqConflict`
//! (it is the only distinct hash at that `seq`); otherwise it stays
//! `TornWrite` (rulings 13-V5-d1 point 6 and 13-V5-d2). A byte-
//! identical copy at the attester's `seq` is `DuplicateRecord`, not a
//! fork, and does not block promotion.
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
    Finding, Report, anchors, end, fold,
    input::{Collection, Input, LineContent, Summary},
    resume, revocation, signatures, stale,
};
use crate::audit::{Checkpoint, FindingKind as K, Record, TrustPolicy, digest_string, hex};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{Duration, SystemTime},
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

/// Pessimistic gap and shipped-fragment findings (ruling 13-V3-d3,
/// 13-V5-d1 points 5-6, 13-V5-d2 and 13-V5-d5): an attested gap is
/// promoted to `TornWriteRepaired` only when the attester is a record
/// of the verified `trail`, its `seq` has no other record (not one
/// side of a `SeqConflict` fork), and either its `seq <=
/// covered_through` or a matching `end=` covers it (its `seq <=
/// matched_end`). A trailing gap with no attesting record and
/// `RepairMismatch` are never promoted.
fn file_findings(
    input: &Input,
    no_crash: bool,
    covered_through: Option<u64>,
    matched_end: Option<u64>,
    trail: [u8; 16],
    conflicting_seqs: &BTreeSet<u64>,
    findings: &mut Vec<Finding>,
) {
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
                    // Rulings 13-V5-d2 and 13-V5-d5 point 2.3: a
                    // covered checkpoint protects the records of the
                    // verified trail at or below its `seq` through
                    // the hash chain; a matching `end=` pins every
                    // record at or below its `seq` from outside the
                    // trail directory. Promote when the attester is
                    // a record of the verified trail AND the only
                    // record at its `seq` AND either reaches it.
                    let pinned_tail = covered_through.is_some_and(|c| r.seq <= c)
                        || matched_end.is_some_and(|e| r.seq <= e);
                    let promotable =
                        pinned_tail && r.trail == trail && !conflicting_seqs.contains(&r.seq);
                    let kind = if promotable {
                        K::TornWriteRepaired
                    } else {
                        K::TornWrite
                    };
                    (kind, at)
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

/// True when `input` has a trailing fragment gap after a closing checkpoint,
/// and the next native input in `collection.inputs` starts with an opening
/// checkpoint linked to that closing (ADR l.446-451, ruling 13-V3-d4): all of
///   - the archive's last complete record is a closing checkpoint;
///   - the successor's first complete record is an opening checkpoint;
///   - that opening links back to the closing (`previous == closing.hash`);
///   - its `seq` is `closing.seq + 1`;
///   - the opening is not followed by a `vigil.audit.resume` record;
///   - the archive ends with a trailing fragment gap.
fn mark_no_crash(collection: &Collection, idx: usize) -> bool {
    let input = &collection.inputs[idx];
    if !input.native {
        return false;
    }
    let Some(closing) = input.data.records.last() else {
        return false;
    };
    // The archive's last complete record must itself be a closing checkpoint.
    if closing.checkpoint.is_none() {
        return false;
    }
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
    if opening.checkpoint.is_none()
        || closing.seq.checked_add(1) != Some(opening.seq)
        || opening.previous != closing.hash
    {
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
pub(super) fn parse_resume(details: Option<&str>) -> Option<(u64, &str, u64)> {
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

/// Builds `Resumed` findings from the shared per-declaration outcomes
/// (ruling 13-V3-d5 point 10, #195): one warning per distinct
/// `(resume_seq, resume_hash)` on this trail, attributed to the native
/// copy when present (addendum 8). Reads the outcome in place; the
/// candidate list is derived from the same declarations.
fn emit_resumed(declarations: &[resume::Declaration<'_>], findings: &mut Vec<Finding>) {
    for d in declarations {
        let (actor, reason) = d
            .resume
            .operator
            .as_ref()
            .map(|(_, actor, reason, _)| (actor.as_str(), reason.as_deref()))
            .expect("resume operator");
        let detail = match &d.body {
            resume::DeclarationBody::Parsed(p) => {
                let reason = reason.unwrap_or("");
                // Genesis gap text is `0..=L` (ADR l.407, l.411; d5 point 3).
                let gap = if p.is_genesis {
                    format!("0..={}", p.lost_through)
                } else if p.lost_through == p.head_seq {
                    "none".to_owned()
                } else {
                    format!("{}..={}", p.head_seq + 1, p.lost_through)
                };
                let suffix = match &p.outcome {
                    resume::Outcome::Valid(_) => " structural=valid".to_owned(),
                    resume::Outcome::Invalid(why) => format!(" structural=invalid({why})"),
                };
                let head_seq = p.head_seq;
                let head_hash = p.head_hash_text;
                format!(
                    "operator={actor} reason={reason} \
                     head={head_seq}:{head_hash} \
                     gap={gap} lost_records=0{suffix}"
                )
            }
            resume::DeclarationBody::Malformed => "malformed declaration".to_owned(),
        };
        findings.push(finding(
            K::Resumed,
            d.path,
            Some(d.resume.line),
            Some(d.resume.seq),
            detail,
        ));
    }
}

pub(super) fn check(
    collection: Collection,
    trail: [u8; 16],
    trust: &TrustPolicy,
    max_age: Option<Duration>,
    anchors: &[Checkpoint],
    now: SystemTime,
) -> Report {
    let mut findings = Vec::new();
    let mut groups: BTreeMap<u64, Vec<Located<'_>>> = BTreeMap::new();
    // Bucket records by seq first so coverage (ruling 13-V5-d1 point 6)
    // is known before the gap pass can promote an attested torn write.
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
    // Ruling 13-V5-d1 point 6: `covered_through` is the highest `seq`
    // of a candidate (every distinct `(seq, hash)` checkpoint, native
    // or shipped-only) for which the crate-private predicate holds.
    let covered_through = coverage(&groups, trail, trust);
    // Ruling 13-V5-d2: a `SeqConflict` fork blocks promotion at its
    // `seq` -- the attester must be the only record on the verified
    // trail at that `seq`. One definition of "forked" (the shared
    // `forked` helper): both this pre-pass (so `file_findings` can
    // consult it ahead of the main seq-loop) and the `SeqConflict`
    // emission inside the main seq-loop read it from the same set,
    // so a byte-identical duplicate (same hash across copies) is
    // `DuplicateRecord`, never a fork.
    let conflicting_seqs: BTreeSet<u64> = groups
        .iter()
        .filter_map(|(&seq, copies)| forked(copies).then_some(seq))
        .collect();
    // Ruling 13-V5-d5: evaluate the section's `end=` once. A match
    // grants the tail exemption, confirms bounds at or below `s`,
    // and promotes 13-V5-d2 repairs at or below `s`; a mismatch
    // grants none of them; no `end=` checks nothing. Threaded into
    // file_findings (repair promotion), revocation::check (bound
    // confirmation) and `with_tail_exempt` below.
    let matched_end = end::check(trail, trust, &groups, &conflicting_seqs, &mut findings);
    for (idx, input) in collection.inputs.iter().enumerate() {
        let no_crash = mark_no_crash(&collection, idx);
        file_findings(
            input,
            no_crash,
            covered_through,
            matched_end,
            trail,
            &conflicting_seqs,
            &mut findings,
        );
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
        // Ruling 13-V5-d1 points 1-2: every distinct `(seq, hash)` checkpoint
        // in the verified set is checked exactly once, at its first
        // occurrence; shipped-only checkpoints appear as their shipped
        // `(path, line)`. Run membership does not demote the check.
        for &(path, record) in &candidates {
            signatures::check(trail, trust, path, record, &mut findings);
        }
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
        if conflicting_seqs.contains(&seq) {
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
    // Ruling 13-V5-d1 point 4 and 13-V5-d3: pin and confirm every
    // `through=` bound on a key of the verified trail's section, in
    // key-byte order. Reads the same merged `groups` and fork set the
    // main seq-loop just filled, so no second file pass.
    revocation::check(
        trail,
        trust,
        &groups,
        &conflicting_seqs,
        matched_end,
        &mut findings,
    );
    // Ruling 13-V5-d1 point 7 and 13-V5-d6: emit 0 or 1 `StaleHead`
    // against the verifier's `max_age` and the one `now` read at the
    // start of the verify call. Reuses the shared fork set
    // (`conflicting_seqs`) and the V5a trusted predicate; no second
    // file pass.
    stale::check(
        trail,
        trust,
        max_age,
        now,
        &groups,
        &conflicting_seqs,
        &mut findings,
    );
    // Ruling 13-V6-d1 points 1-2: each distinct `(trail, seq, hash)`
    // anchor is checked once against the already-merged `groups` and
    // the shared fork set, so no second file pass runs.
    anchors::check(anchors, trail, &groups, &conflicting_seqs, &mut findings);
    // Compute the per-declaration structural outcome once (ruling
    // 13-V3-d5 point 10, #195): both the `Resumed` detail suffix and the
    // candidate list derive from the same declarations.
    let declarations = resume::declarations(&collection, trail);
    emit_resumed(&declarations, &mut findings);
    // Validated structural-resume tuples (ruling 13-V3-d5 points 1, 5, 10);
    // consumed by #13 V4 (rule 2 fold) in `pending_resumes` below, and
    // by #13 V6 (start) and #13 V7 (confirmation).
    let candidates = resume::candidates(&declarations);
    // #13 V4a (rulings 13-V4-d3, 13-V4-d4, 13-V4-d5, 13-V4-d6, 13-V4-d8)
    // emits one `SegmentStructure` run finding per closed run; #13 V4b
    // (ruling 13-V4-d10) emits one `MmrMismatch` per differing fold-
    // compare entry AND returns the set of opening `seq`s the fold
    // positively recorded as compared and matched. One classifier pass
    // per verify call (13-V4-d8 point 2, 13-V4-d10 point 1) over the
    // already-retained native bytes (`input::collect` with
    // `keep_bytes = native(path)`) through
    // `storage::SegmentSource::for_snapshot`, which opens nothing.
    // Shipped-copy rule 2 is out of scope (owner decision 13-V4-d7;
    // spike #224); runs that rejection empties keep no finding
    // (addendum 28 point 2).
    let matched_openings = fold::check_runs(&collection, trail, &mut findings);
    // #13 V4b (ruling 13-V4-d10 point 4): fail-closed candidate
    // filter. Keep only candidates whose opening `(seq, hash)` the
    // fold positively recorded as matched; drop anything else --
    // a differing opening, a self-based opening (ADR amendment 6
    // "Base"; never compared), a shipped-only opening (no fold
    // compare at this head, spike #224), an opening the walk did
    // not reach after an earlier violation, and a forged opening
    // whose hash collides on `seq` with an honest Matched opening
    // (`(seq, hash)` match, not `seq` alone). Consumed by the
    // gap confirmation of #13 (V6 start, V7 confirmation), so a
    // gap whose opening rule 2 has not passed can never be
    // confirmed or excused there. The `#[cfg(test)]` seam below
    // returns this list for row B6 without widening visibility
    // otherwise.
    let pending_resumes = filter_candidates(candidates, &matched_openings);
    let _ = &pending_resumes;
    let first_seq = groups.first_key_value().map(|(&s, _)| s);
    let last_seq = groups.last_key_value().map(|(&s, _)| s);
    // Ruling 13-V5-d1 point 6: list records above `covered_through`
    // (or every record when no checkpoint is trusted). When the last
    // record is itself covered, no `UncoveredTail` is emitted.
    if let (Some(first), Some(last)) = (first_seq, last_seq)
        && covered_through.is_none_or(|c| last > c)
    {
        let a = covered_through.map_or(first, |c| c + 1);
        findings.push(Finding::new(
            K::UncoveredTail,
            None,
            None,
            None,
            format!("records seq {a}..={last}"),
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
    Report::new(trail, count, first_seq, last_seq, covered_through, findings)
        .with_tail_exempt(matched_end.is_some())
}

/// Shared fork predicate (ruling 13-V5-d2): `true` iff the records at
/// one `seq` on the verified trail carry two or more DISTINCT hashes
/// (not merely two or more copies). One definition for both the pre-
/// pass `conflicting_seqs` set (which blocks `TornWriteRepaired`
/// promotion) and the main seq-loop's `SeqConflict` emission, so a
/// byte-identical duplicate stays `DuplicateRecord` in both places.
fn forked(copies: &[Located<'_>]) -> bool {
    let hashes: BTreeSet<[u8; 32]> = copies.iter().map(|(_, r)| r.hash).collect();
    hashes.len() > 1
}

/// Highest `seq` whose candidate `(seq, hash)` checkpoint satisfies the
/// crate-private trusted predicate ([`signatures::trusted`]), or `None`
/// when no candidate does (ruling 13-V5-d1 points 1, 3 and 6). Native
/// and shipped-only candidates count equally; a conflict's trusted
/// candidate covers its `seq`.
fn coverage(
    groups: &BTreeMap<u64, Vec<Located<'_>>>,
    trail: [u8; 16],
    trust: &TrustPolicy,
) -> Option<u64> {
    groups
        .iter()
        .rev()
        .find(|(_, copies)| {
            copies
                .iter()
                .any(|(_, r)| signatures::trusted(trail, trust, r))
        })
        .map(|(&s, _)| s)
}

/// #13 V4b (ruling 13-V4-d10 point 4): fail-closed candidate filter.
/// Keeps a candidate only when its `(opening_seq, opening_hash)` is
/// in `matched_openings` -- the set
/// [`fold::check_runs`](super::fold::check_runs) collected from the
/// classifier's positively-compared-and-matched fold entries. Drops
/// anything else: a differing opening, a self-based opening, a
/// shipped-only opening (no fold compare at this head), an opening
/// the walk did not reach after an earlier violation, and a forged
/// opening whose hash does not equal the record the fold compared
/// (`(seq, hash)` match, not `seq` alone). Shared by `check`
/// (non-test) and [`filter_candidates_for_test`] (test only).
fn filter_candidates(
    candidates: Vec<resume::ResumeCandidate>,
    matched_openings: &std::collections::BTreeSet<(u64, [u8; 32])>,
) -> Vec<resume::ResumeCandidate> {
    candidates
        .into_iter()
        .filter(|c| matched_openings.contains(&(c.opening_seq, c.opening_hash)))
        .collect()
}

/// #13 V4b (ruling 13-V4-d10 point 4): `#[cfg(test)]` seam that
/// returns the retained candidates' opening `seq`s for row B6 (one
/// kept-list per layout: honest resume kept, wrong opening dropped,
/// shipped-only dropped, never-compared dropped, honest-A1 closer
/// kept). The test seam reruns the same filter the non-test path
/// uses, through the same two helpers -- no second, test-only
/// filter path -- so the row verifies what production evaluates.
#[cfg(test)]
pub(super) fn filter_candidates_for_test(collection: &Collection, trail: [u8; 16]) -> Vec<u64> {
    let declarations = resume::declarations(collection, trail);
    let candidates = resume::candidates(&declarations);
    let mut findings = Vec::new();
    let matched_openings = fold::check_runs(collection, trail, &mut findings);
    filter_candidates(candidates, &matched_openings)
        .into_iter()
        .map(|c| c.opening_seq)
        .collect()
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
