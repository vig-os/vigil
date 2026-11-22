//! Collecting chain and gap checks (ruling 13-V3-d3). The chain
//! loop compares every record with the record at the **highest
//! `seq` below it** that is present in the verified set, not only
//! `seq - 1` (ruling 13-V6-d6 point 1), so `ChainBroken` fires
//! together with `SeqGap` wherever records are missing between the
//! two. The record at the lowest `seq` keeps the existing genesis
//! and prefix rules. A native gap attested by a record whose
//! `seq <= covered_through` is reported as `TornWriteRepaired`,
//! but only when that attesting record is itself a record of the
//! verified trail AND its `seq` carries no `SeqConflict` (it is the
//! only distinct hash at that `seq`); otherwise it stays
//! `TornWrite` (rulings 13-V5-d1 point 6 and 13-V5-d2). A byte-
//! identical copy at the attester's `seq` is `DuplicateRecord`, not
//! a fork, and does not block promotion.
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
    Finding, Report, anchors, end, end_before, fold,
    input::{Collection, Input, LineContent, Summary},
    position, receipts, resume, review, revocation, signatures, stale, start,
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
#[expect(
    clippy::too_many_arguments,
    reason = "engine-side state needs review::TornWritePins alongside the five scalars"
)]
fn file_findings(
    input: &Input,
    no_crash: bool,
    covered_through: Option<u64>,
    matched_end: Option<u64>,
    trail: [u8; 16],
    conflicting_seqs: &BTreeSet<u64>,
    findings: &mut Vec<Finding>,
    pins: &mut review::TornWritePins,
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
        // ADR-0005 decision 11 "What pins each kind"; ruling
        // 13-V8-d1 points 2 and 5: pin the trailing gap for the
        // review pass in a side map keyed by this finding's index.
        // `u64::MAX` marks a file-start gap (FORK 3), so `seq` is
        // `None` and no `accept TornWrite` can match it.
        let idx = findings.len();
        findings.push(finding(K::TornWrite, path, Some(first), None, d));
        pins.insert(
            idx,
            review::TornWritePin {
                seq: (s.after != u64::MAX).then_some(s.after),
                hash: s.digest,
                no_crash,
            },
        );
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
    !next.data.records.get(1).is_some_and(Summary::is_resume)
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
///
/// `lost_counts` carries, for each candidate gap, the number of
/// [`K::LostRecord`] findings whose `seq` lies in that gap's range
/// (ruling 13-V7-d1 point 8). Resume declarations whose candidate did
/// not pass the trust and fold filters, and malformed declarations,
/// keep `lost_records=0`.
fn emit_resumed(
    declarations: &[resume::Declaration<'_>],
    lost_counts: &BTreeMap<(u64, [u8; 32]), u64>,
    findings: &mut Vec<Finding>,
) {
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
                let lost_records = lost_counts
                    .get(&(d.resume.seq, d.resume.hash))
                    .copied()
                    .unwrap_or(0);
                format!(
                    "operator={actor} reason={reason} \
                     head={head_seq}:{head_hash} \
                     gap={gap} lost_records={lost_records}{suffix}"
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

/// Per-call verifier inputs the engine reads alongside the merged
/// snapshot. Grouping them keeps [`check`] a readable function
/// signature and keeps callers (production and the engine tests)
/// pointed at the same fields.
pub(super) struct Policy<'a> {
    pub(super) trust: &'a TrustPolicy,
    pub(super) max_age: Option<Duration>,
    pub(super) anchors: &'a [Checkpoint],
    pub(super) start: Option<&'a Checkpoint>,
    pub(super) end_ctx: Option<&'a end_before::Context<'a>>,
    /// `None` leaves reconciliation off (ruling 13-V7-d1 point 2);
    /// `Some(inputs)` turns it on. Every bundle carries raw blake3
    /// bytes so no hex parsing lives in `engine::check`.
    pub(super) receipts: Option<&'a receipts::Inputs<'a>>,
    /// Review-file `accept` lines; see
    /// [`crate::audit::Verifier::accept`].
    pub(super) accepts: &'a super::AcceptMap,
    /// Review-file `accept-run` lines; see
    /// [`crate::audit::Verifier::accept_run`].
    pub(super) accepts_run: &'a super::AcceptRunMap,
    pub(super) now: SystemTime,
}

pub(super) fn check(collection: Collection, trail: [u8; 16], policy: Policy<'_>) -> Report {
    let Policy {
        trust,
        max_age,
        anchors,
        start,
        end_ctx,
        receipts: receipt_set,
        accepts,
        accepts_run,
        now,
    } = policy;
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
    // Ruling 13-V6-d2 points 3-5: evaluate the start against the
    // already-merged `groups` and the shared fork set. `Some(s)`
    // marks the one `SeqGap` the chain loop would otherwise emit at
    // the first record (`0..s−1`) for suppression; `None` leaves
    // every other check running exactly as if no start had been
    // given, including that prefix `SeqGap` (point 4).
    let accepted_start = start::check(
        start,
        trail,
        trust,
        &groups,
        &conflicting_seqs,
        &mut findings,
    );
    // Ruling 13-V6-d7 clarification 13-V6-d7a: evaluate the end
    // anchor through the shared anchor rule once, before the
    // classifier is built, so `Context::is_anchored` can reuse the
    // result without re-implementing the rule. The end anchor is
    // never set aside (clarification 13-V6-d7a), so
    // `anchors::match_only` is the full rule for it. The finding
    // (if any) is pushed here and `anchors::check` is told to skip
    // this anchor's identity so it is not emitted twice.
    let (end_anchor_identity, end_anchor_matches) =
        match end_ctx.and_then(|c| c.anchor.map(|a| (c, a))) {
            Some((_, a)) => {
                let result = anchors::match_only(a, trail, &groups, &conflicting_seqs);
                let matches = result.is_none();
                if let Some(f) = result {
                    findings.push(f);
                }
                (Some((a.trail(), a.seq(), a.hash())), matches)
            }
            None => (None, false),
        };
    let end_ctx_filled: Option<end_before::Context<'_>> = end_ctx.map(|c| end_before::Context {
        end_seq: c.end_seq,
        last_line_seq: c.last_line_seq,
        first_line: c.first_line,
        anchor: c.anchor,
        end_anchor_matches,
    });
    let end_ctx = end_ctx_filled.as_ref();
    // Rulings 13-V4-d10 point 4, 13-V5-d1 point 8 and 13-V7-d1 points
    // 7-9 require the fold and the candidate filters BEFORE the
    // classifier so its `Gap { confirmed, opening_anchored }` arm has
    // every input it needs (and the seq-loop can suppress `SeqGap`
    // for a candidate gap in one place). `check_runs` takes only
    // `&collection` and `trail`. Its findings are collected into a
    // side vec and appended at the end so each row's existing
    // tie-break order is preserved (same `(seq, file, line, kind)`
    // keys stay stable). The declarations drive both the classifier
    // and the later `emit_resumed`, so they are computed once.
    let declarations = resume::declarations(&collection, trail);
    let mut fold_findings: Vec<Finding> = Vec::new();
    let mut run_index: Vec<fold::RunIndexEntry> = Vec::new();
    let matched_openings = fold::check_runs(&collection, trail, &mut fold_findings, &mut run_index);
    let pending_resumes = filter_candidates(resume::candidates(&declarations), &matched_openings);
    // Ruling 13-V7-d1 point 8 and ADR-0005 decision 11: a receipt
    // or an `accept Resumed` line confirms a gap only when
    // `receipts::match_one`'s outcome for it would be Matched --
    // both in range and matching the record under the shared match
    // rule. A bare classifier built from the start and end bounds
    // (no gaps yet) runs the same `set_aside` the real pass will,
    // so a line above `end_before`'s last-line `seq` or below
    // an accepted start never confirms. The shared `receipts::matches`
    // is the one match rule, and a gap for a candidate the trust or
    // fold filter dropped is absent from the gap list below, so
    // nothing keys off a dropped candidate.
    // Ruling 13-V8-d1 point 8, clarification 13-V8-d1a: an
    // `accept-run` line whose `seq` is the accepted start's `seq +
    // 1` is set aside under the start rule iff the verified set
    // holds at that `seq` one unforked `vigil.audit.resume` record
    // whose previous equals the start. The run such a line closes
    // lies wholly below the start, so it is never in the run
    // index: this decision reads the merged `groups` and the
    // shared fork set once and hands the classifier the resume's
    // hash to compare against the line's.
    let start_resume_hash =
        start_resume_hash_at(accepted_start.and(start), &groups, &conflicting_seqs);
    let bare_position = position::Classifier::new(
        accepted_start.and(start),
        trail,
        anchors,
        end_ctx,
        Vec::new(),
        start_resume_hash,
    );
    // ADR-0005 decision 5 and decision 11: a gap is confirmed by a
    // receipt OR an `accept Resumed` line matching the resume
    // record's `(seq, hash)` under the shared match rule. Both
    // sources run through the same `set_aside` + `receipts::matches`
    // pair the real receipts and accept passes use, so a line above
    // the end, below an accepted start, at a forked `seq` or with a
    // wrong hash confirms nothing, and the two confirmation sources
    // feed one set.
    let is_matched_in_range = |seq, hash| {
        bare_position.set_aside(seq, "").is_none()
            && receipts::matches(seq, hash, &groups, &conflicting_seqs)
    };
    let mut confirmations: BTreeSet<(u64, [u8; 32])> =
        receipt_set.map_or_else(BTreeSet::new, |rs| {
            rs.receipts
                .iter()
                .filter(|&&(seq, hash)| is_matched_in_range(seq, hash))
                .copied()
                .collect()
        });
    for (&seq, entries) in accepts {
        for entry in entries {
            if entry.0 == K::Resumed && is_matched_in_range(seq, entry.1) {
                confirmations.insert((seq, entry.1));
            }
        }
    }
    let gaps = build_gaps(
        &pending_resumes,
        trail,
        trust,
        anchors,
        &confirmations,
        &groups,
        &conflicting_seqs,
    );
    let position = position::Classifier::new(
        accepted_start.and(start),
        trail,
        anchors,
        end_ctx,
        gaps.clone(),
        start_resume_hash,
    );
    // Ruling 13-V5-d5: evaluate the section's `end=` once. A match
    // grants the tail exemption, confirms bounds at or below `s`,
    // and promotes 13-V5-d2 repairs at or below `s`; a mismatch
    // grants none of them; no `end=` checks nothing. Threaded into
    // file_findings (repair promotion), revocation::check (bound
    // confirmation) and `with_tail_exempt` below.
    let matched_end = end::check(
        trail,
        trust,
        &groups,
        &conflicting_seqs,
        &position,
        &mut findings,
    );
    let mut torn_write_pins = review::TornWritePins::new();
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
            &mut torn_write_pins,
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
        // Order copies by `(is_end_record, path, line, hash)` so
        // the end-record copies always sort after every file copy
        // at the same `seq` (ruling 13-V6-d4 point 3); "first copy"
        // never resolves to the end record, and files are ordered
        // by path exactly as they were before `end_before`.
        copies.sort_by_key(|(path, r)| (r.is_end_record, *path, r.line, r.hash));
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
        // Ruling 13-V6-d4 point 3: at or above the end checkpoint's
        // `seq` no `DuplicateRecord` is reported, even for a
        // byte-identical copy of an end line. One place.
        if copies.len() > candidates.len() && !end_before::covers(end_ctx, seq) {
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
            // Ruling 13-V6-d2 point 5: an accepted start suppresses
            // only the prefix `SeqGap` for `0..s−1`, i.e. the gap
            // the first record would otherwise report; every later
            // gap stays. Ruling 13-V7-d1 point 7: a jump that exactly
            // matches a trust-and-fold-kept candidate's gap is a
            // resume gap and reports no `SeqGap`; a genesis candidate
            // needs the gap to be confirmed as well (the exception).
            let suppress_prefix = previous.is_none() && accepted_start == Some(seq);
            let suppress_candidate = position.candidate_gap(next, seq - 1).is_some_and(|g| {
                // Non-genesis trusted candidate: always suppress.
                // Genesis candidate: suppress only when confirmed.
                !g.is_genesis || g.confirmed
            });
            if !suppress_prefix && !suppress_candidate {
                findings.push(finding(
                    K::SeqGap,
                    path,
                    Some(record.line),
                    Some(seq),
                    format!("missing seq {next}..={}", seq - 1),
                ));
            }
        }
        for &(path, record) in &candidates {
            // Ruling 13-V6-d6 point 1: every record except the record
            // at the lowest `seq` is compared with the record at the
            // highest `seq` below it in the verified set, not only
            // `seq - 1`. The `previous` variable tracks exactly that
            // record because iteration is in ascending `seq` order.
            // The lowest-`seq` record keeps the existing genesis /
            // prefix rules (`seq 0` genesis, `seq > 0` prefix
            // `SeqGap`, accepted-start suppression above). An end
            // record is checked like any other; the strip-location
            // pass below unlocates the finding (ruling 13-V6-d4
            // point 6). No special case for resume openings
            // (point 2): the resume rules (`Resumed structural=...`,
            // `SeqGap`) layer on top of the chain rule.
            let expected = if let Some((_, records)) = &previous {
                records.iter().map(|(_, r)| r.hash).collect::<Vec<_>>()
            } else if seq == 0 {
                vec![Record::genesis(&trail)]
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
    // main seq-loop just filled, so no second file pass. Ruling
    // 13-V6-d7 point 4: `end_bounded` suppresses `RevocationUnconfirmed`
    // in an end-bounded verification.
    revocation::check(
        trail,
        trust,
        &groups,
        &conflicting_seqs,
        matched_end,
        &position,
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
    // Ruling 13-V6-d1 points 1-2 and 13-V6-d7 clarification 13-V6-d7a:
    // each distinct `(trail, seq, hash)` anchor is checked once
    // against the already-merged `groups` and the shared fork set,
    // so no second file pass runs. The end anchor was evaluated
    // ahead of the classifier (its finding was pushed above), so this
    // call skips it by identity -- the shared anchor rule runs once.
    anchors::check(
        anchors,
        trail,
        &groups,
        &conflicting_seqs,
        &position,
        end_anchor_identity,
        &mut findings,
    );
    // Rulings 13-V7-d1 points 2-6: reconcile receipts, waivers and
    // the `from` input against the already-merged `groups` and the
    // shared position classifier. Runs iff one of `Verifier::receipts`,
    // `Verifier::waive` or `Verifier::receipts_from` turned
    // reconciliation on (point 2), so a verifier without the calls
    // sees no receipts work.
    if let Some(inputs) = receipt_set {
        receipts::check(inputs, &groups, &conflicting_seqs, &position, &mut findings);
    }
    // Append the fold's findings in their old position (just before
    // `Resumed`) so same-key tie-break order is preserved across
    // moves of `fold::check_runs`.
    findings.append(&mut fold_findings);
    // ADR-0005 decision 11 "Review file"; ruling 13-V8-d1 points
    // 2, 6 and 8: phase 1 classifies each `accept` line through
    // the position classifier, before `count_lost_records` runs,
    // so an `accept` inside a confirmed resume gap is counted by
    // that gap's `lost_records=<n>` (decision 5).
    let remaining_accepts = review::classify_positions(accepts, &position, &mut findings);
    // ADR-0005 decision 11 `accept-run`; ruling 13-V8-d1 points 2,
    // 7 and 8: phase 1 for `accept-run` runs the same position
    // classifier as `accept`, with the point-8 override driven by
    // the run index -- a line is set aside under the start rule
    // only when a run in the index closes at the accepted start
    // and the line pins that run's resume record.
    let remaining_runs = review::classify_run_positions(accepts_run, &position, &mut findings);
    // Ruling 13-V7-d1 point 8: for each gap in the classifier's
    // list, count the `LostRecord` findings whose `seq` lies in
    // that gap's range, keyed by the gap's resume `(seq, hash)`.
    // Reading the bounds and the key from the gap itself keeps the
    // two consumers aligned: a candidate the trust or fold filter
    // dropped is absent from the gap list and from the count map,
    // and its `Resumed` detail keeps `lost_records=0`.
    let lost_counts = count_lost_records(&findings, &gaps);
    emit_resumed(&declarations, &lost_counts, &mut findings);
    // Phase 2: match each remaining `accept` against the reported
    // warnings and the record at its `seq` (ruling 13-V8-d1).
    review::match_warnings(
        &remaining_accepts,
        &groups,
        &conflicting_seqs,
        &torn_write_pins,
        &mut findings,
    );
    // Phase 2 for `accept-run`: match each remaining line against
    // the resume record at its `seq` and the run it closes, and
    // replace items 1-3 with `Accepted` on a match (ADR-0005
    // decision 11 `accept-run`; ruling 13-V8-d1).
    review::match_runs(
        &remaining_runs,
        &groups,
        &conflicting_seqs,
        &run_index,
        &mut findings,
    );
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
    // Ruling 13-V6-d4 points 3, 5 and 6: the TrailEnded range over
    // the file records at or above the end checkpoint's `seq`, the
    // UnanchoredEnd / end-record AnchorMismatch from the byte
    // equality check, and the unlocation of findings that sit on
    // the end-record segment. The suppression of DuplicateRecord
    // happens inside the seq loop; these three are the rest.
    if let Some(ctx) = end_ctx {
        end_before::check(ctx, &groups, &mut findings);
        // Ruling 13-V6-d6 point 3: the only end-specific link
        // finding -- when the files hold no record below `e` and
        // `e > 0`, the end checkpoint is the lowest record and the
        // chain loop above does not check it. One ChainBroken at
        // `e`, unlocated, with the fixed detail. At `e = 0`
        // nothing is checked.
        end_before::no_record_precedes(ctx, &groups, &mut findings);
        // Identify the end-record inputs by their
        // `Input::is_end_record` flag (not by path value), then
        // unlocate every finding whose file is one of their paths.
        let end_paths: Vec<&Path> = collection
            .inputs
            .iter()
            .filter(|i| i.is_end_record)
            .map(|i| i.path.as_path())
            .collect();
        for f in &mut findings {
            if f.file().is_some_and(|fp| end_paths.contains(&fp)) {
                f.strip_location();
            }
        }
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

/// Resume hash at `start.seq + 1` for the ruling 13-V8-d1a `accept-
/// run` start-override check, or `None` when the record there is
/// absent, forked, not a `vigil.audit.resume`, or does not open
/// from the start. One place reads `groups` and the shared fork
/// set to decide "the run closes at this start" without consulting
/// the run index (which, by construction, never holds a run whose
/// segments all lie below the start).
fn start_resume_hash_at(
    start: Option<&Checkpoint>,
    groups: &BTreeMap<u64, Vec<Located<'_>>>,
    conflicting_seqs: &BTreeSet<u64>,
) -> Option<[u8; 32]> {
    let start = start?;
    let after = start.seq().checked_add(1)?;
    if conflicting_seqs.contains(&after) {
        return None;
    }
    let copies = groups.get(&after)?;
    let hashes: BTreeSet<[u8; 32]> = copies.iter().map(|(_, r)| r.hash).collect();
    if hashes.len() != 1 {
        return None;
    }
    let (_, record) = copies[0];
    if !record.is_resume() || record.previous != start.hash() {
        return None;
    }
    Some(record.hash)
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
    let mut run_index: Vec<fold::RunIndexEntry> = Vec::new();
    let matched_openings = fold::check_runs(collection, trail, &mut findings, &mut run_index);
    filter_candidates(candidates, &matched_openings)
        .into_iter()
        .map(|c| c.opening_seq)
        .collect()
}

/// Builds the classifier's gap list from the trust-and-fold-kept
/// candidates (rulings 13-V4-d10 point 4, 13-V5-d1 point 8 and
/// 13-V7-d1 points 7-9). The trust filter runs here (point 8): a
/// candidate whose opening checkpoint does not pass
/// [`signatures::trusted`] (on the same `(seq, hash)` the candidate
/// names) is dropped, so a trusted record with a different hash at
/// the opening's `seq` never rescues a forged opening; its jump
/// keeps its ordinary `SeqGap` and nothing inside can be
/// `LostRecord`. `opening_anchored` goes through the same
/// [`anchors::match_only`] the anchor rule itself uses (ruling
/// 13-V6-d1 point 2: a forked `seq` never matches, so a forked
/// opening is never anchored even when an input anchor equals its
/// `(trail, seq, hash)`). Confirmation (point 8; ADR-0005 decision
/// 11) uses the shared matched set the caller built through
/// [`receipts::matches`] and [`position::Classifier::set_aside`]
/// from both the receipts and the `accept Resumed` lines, so a
/// mismatched, set-aside or forked line never confirms a gap and
/// never drifts from the real receipts and accept passes.
/// A shipped-only opening is never a candidate (13-V4-d7; spike
/// #224), so a Collector copy cannot confirm a gap through this
/// filter.
fn build_gaps(
    candidates: &[resume::ResumeCandidate],
    trail: [u8; 16],
    trust: &TrustPolicy,
    anchors: &[Checkpoint],
    confirmations: &BTreeSet<(u64, [u8; 32])>,
    groups: &BTreeMap<u64, Vec<Located<'_>>>,
    conflicting_seqs: &BTreeSet<u64>,
) -> Vec<position::Gap> {
    let mut out = Vec::new();
    for c in candidates {
        // Ruling 13-V5-d1 point 8: trust the opening checkpoint by
        // the `signatures::trusted` predicate on the verified-trail
        // record at the opening `(seq, hash)`. A shipped-only
        // opening could appear here only via a fold match, which
        // 13-V4-d7 excludes; iterating the groups' copies covers
        // both native and (future) shipped cases. The hash equality
        // and the trust check run together so a trusted copy with
        // a different hash at the opening's `seq` does not rescue a
        // forged opening.
        let opening_trusted = groups.get(&c.opening_seq).is_some_and(|copies| {
            copies
                .iter()
                .any(|(_, r)| r.hash == c.opening_hash && signatures::trusted(trail, trust, r))
        });
        if !opening_trusted {
            continue;
        }
        // Ruling 13-V6-d1 point 2: "anchored" is the full anchor
        // match, so a forked opening is never anchored (fail-closed,
        // the same rule the anchor finding uses). Running the
        // shared `anchors::match_only` here keeps the one rule in
        // one place: the anchor emits `AnchorMismatch ... seq is
        // forked` at a forked opening, and `opening_anchored` is
        // false.
        let opening_anchored = anchors.iter().any(|a| {
            a.trail() == trail
                && a.seq() == c.opening_seq
                && a.hash() == c.opening_hash
                && anchors::match_only(a, trail, groups, conflicting_seqs).is_none()
        });
        let confirmed = confirmations.contains(&(c.resume_seq, c.resume_hash));
        let low = if c.is_genesis { 0 } else { c.head_seq + 1 };
        out.push(position::Gap {
            low,
            high: c.lost_through,
            is_genesis: c.is_genesis,
            confirmed,
            opening_anchored,
            resume_seq: c.resume_seq,
            resume_hash: c.resume_hash,
        });
    }
    out
}

/// Ruling 13-V7-d1 point 8: count every `LostRecord` finding whose
/// `seq` lies in a gap, keyed by that gap's resume `(seq, hash)` on
/// the gap itself, so [`emit_resumed`] can fill the
/// `lost_records=<n>` slot. The bounds and the key both come from
/// the classifier's gap list, so a candidate the trust or fold
/// filter dropped is absent from both and its `Resumed` detail
/// keeps `lost_records=0`.
fn count_lost_records(
    findings: &[Finding],
    gaps: &[position::Gap],
) -> BTreeMap<(u64, [u8; 32]), u64> {
    let mut out: BTreeMap<(u64, [u8; 32]), u64> = BTreeMap::new();
    for g in gaps {
        let n = findings
            .iter()
            .filter(|f| {
                f.kind() == K::LostRecord && f.seq().is_some_and(|s| s >= g.low && s <= g.high)
            })
            .count() as u64;
        out.insert((g.resume_seq, g.resume_hash), n);
    }
    out
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
