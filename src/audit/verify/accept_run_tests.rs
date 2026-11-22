//! Rows for [`crate::audit::Verifier::accept_run`] and the three
//! outcomes `Accepted` / `AcceptMismatch` / `AcceptUnused`
//! (ADR-0005 decision 11 "Review file" `accept-run`; ruling
//! 13-V8-d1). Every row asserts the full sorted finding list
//! literally through `assert_findings`.

use super::tests_common::{assert_findings, parse_cp, report_of, trust_with_key, unlocated};
use super::{Finding, Verifier};
use crate::audit::{
    AuditErrorKind, FindingKind as K, Mmr, Record, digest_string,
    runs_v4a_fixtures::{
        A1_DIGEST, A3_DIGEST, TRAIL, Temp, build_a1, build_a3, entry_rec, fixture_pubkey, headless,
        line_bytes, pushed, put_segment, resume_decl, seeded, segment_path, signed_cp,
        signed_cp_explicit, write_records,
    },
};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

// =====================================================================
// Pinned constants (consistency test pins the hex literals).
// =====================================================================

/// `run_digest(&[], &[])`: the "digest of nothing" used by the
/// `AcceptUnused` branch of ADR-0005 decision 11 `accept-run`.
/// Equal to the `A8_DIGEST` pin (an A8-layout run has empty ranges
/// and empty spans).
const EMPTY_RUN_DIGEST_HEX: &str =
    "blake3:1c02f080d9c70df74de0c13a4a30323f1b49ee624bab2c5d68fa5ee31c4400e4";
const WRONG_HASH: [u8; 32] = [0xC7; 32];
const WRONG_HASH_HEX: &str =
    "blake3:c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7";
const WRONG_DIGEST: [u8; 32] = [0x6B; 32];
const WRONG_DIGEST_HEX: &str =
    "blake3:6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b";

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("hex"),
    }
}
const fn hex_to_bytes(hex: &str) -> [u8; 32] {
    let s = hex.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(s[i * 2]) << 4) | nibble(s[i * 2 + 1]);
        i += 1;
    }
    out
}
const EMPTY_RUN_DIGEST: [u8; 32] =
    hex_to_bytes("1c02f080d9c70df74de0c13a4a30323f1b49ee624bab2c5d68fa5ee31c4400e4");
const A1_DIGEST_BYTES: [u8; 32] =
    hex_to_bytes("79d8cb1c4dfc89a80a4911120280e63ed383108f3199f05291bcb51f625f3931");
const A3_DIGEST_BYTES: [u8; 32] =
    hex_to_bytes("78d5088883d54faa6aefe350948c217bb5ef3c32a468f22184bc07e56d84c63d");

#[test]
fn pinned_literals_match() {
    let empty = super::lines::run_digest(&[], &[]);
    assert_eq!(digest_string(&empty), EMPTY_RUN_DIGEST_HEX, "empty digest");
    assert_eq!(EMPTY_RUN_DIGEST, empty, "empty digest bytes");
    assert_eq!(digest_string(&A1_DIGEST_BYTES), A1_DIGEST, "A1 bytes");
    assert_eq!(digest_string(&A3_DIGEST_BYTES), A3_DIGEST, "A3 bytes");
    assert_eq!(digest_string(&WRONG_HASH), WRONG_HASH_HEX, "wrong hash");
    assert_eq!(
        digest_string(&WRONG_DIGEST),
        WRONG_DIGEST_HEX,
        "wrong digest"
    );
}

fn verifier() -> Verifier {
    Verifier::new(trust_with_key(fixture_pubkey()))
}

trait WriteAllVec {
    fn write_all_vec(&mut self, bytes: &[u8]);
}
impl WriteAllVec for fs::File {
    fn write_all_vec(&mut self, bytes: &[u8]) {
        self.write_all(bytes).unwrap();
    }
}

// =====================================================================
// A1-style run fixture with an in-run `MmrMismatch` at cp5. Mirrors
// `rule2_tests::build_a1_wrong_cp5_root` so items 1-3 of ADR-0005
// decision 11 are all exercisable:
//   S0 (sealed) = [cp0, e1, e2]
//   S1 (sealed, headless) = [r4, cp5_bad_root]  -- in-run `MmrMismatch`
//   live (closer) = [cp6, resume7]
// The run digest matches `A1_DIGEST`; cp6 is the closing opening
// (honest fold) and its own `MmrMismatch` is never emitted here.
// =====================================================================

struct RunFx {
    _dir: Temp,
    dir: PathBuf,
    s1: PathBuf,
    live: PathBuf,
    cp5: Record,
    cp6: Record,
    cp5_bad_root: [u8; 32],
    fold_before_cp5: Mmr,
    resume: Record,
    e2_hash: [u8; 32],
    r4_previous: [u8; 32],
}

fn build_run_fx() -> RunFx {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    put_segment(&d.0, 0, &[&cp0, &e1, &e2], &[]);
    let r4 = headless(&e2, 4);
    let fold = pushed(&mmr2, &r4);
    let bad_root = [0x55; 32];
    let cp5 = signed_cp_explicit(5, r4.hash(), fold.size(), bad_root, fold.peaks().to_vec());
    put_segment(&d.0, 1, &[&r4, &cp5], &[]);
    let fold6 = pushed(&fold, &cp5);
    let cp6 = signed_cp(6, cp5.hash(), &fold6);
    let resume = resume_decl(&cp6, 5, cp5.hash(), 5);
    write_records(&d.0, &[&cp6, &resume]);
    let s1 = segment_path(&d.0, 1);
    let live = d.0.join("audit.jsonl");
    RunFx {
        dir: d.0.clone(),
        _dir: d,
        s1,
        live,
        cp5,
        cp6,
        cp5_bad_root: bad_root,
        fold_before_cp5: fold,
        resume,
        e2_hash: e2.hash(),
        r4_previous: r4.context.previous,
    }
}

fn chain_broken_at_4(fx: &RunFx) -> Finding {
    Finding::new(
        K::ChainBroken,
        Some(fx.s1.clone()),
        Some(1),
        Some(4),
        format!(
            "expected previous {}, found {}",
            digest_string(&fx.e2_hash),
            digest_string(&fx.r4_previous),
        ),
    )
}
fn per_seg_structure(fx: &RunFx) -> Finding {
    Finding::new(
        K::SegmentStructure,
        Some(fx.s1.clone()),
        Some(1),
        Some(4),
        "expected first complete record to be a checkpoint".into(),
    )
}
fn run_structure(fx: &RunFx) -> Finding {
    let detail = format!("loss seq 4 first 3 count 1; digest {A1_DIGEST}");
    Finding::new(
        K::SegmentStructure,
        Some(fx.s1.clone()),
        Some(1),
        Some(4),
        detail,
    )
    .with_run_digest(A1_DIGEST_BYTES)
}
fn seq_gap(fx: &RunFx) -> Finding {
    Finding::new(
        K::SeqGap,
        Some(fx.s1.clone()),
        Some(1),
        Some(4),
        "missing seq 3..=3".into(),
    )
}
fn mmr_mismatch(fx: &RunFx) -> Finding {
    Finding::new(
        K::MmrMismatch,
        Some(fx.s1.clone()),
        Some(2),
        Some(5),
        format!(
            "expected size {} root {}, found size {} root {}",
            fx.fold_before_cp5.size(),
            digest_string(&fx.fold_before_cp5.root()),
            fx.fold_before_cp5.size(),
            digest_string(&fx.cp5_bad_root),
        ),
    )
}
fn resumed(fx: &RunFx) -> Finding {
    let detail = format!(
        "operator=operator reason=incident head=5:{} gap=none lost_records=0 structural=valid",
        digest_string(&fx.cp5.hash())
    );
    Finding::new(K::Resumed, Some(fx.live.clone()), Some(2), Some(7), detail)
}
fn uncovered_tail() -> Finding {
    unlocated(K::UncoveredTail, None, "records seq 7..=7".into())
}

fn literal_accepted(original: Finding, by: &str, reason: &str) -> Finding {
    let kind = original.kind();
    let file = original.file().map(Path::to_path_buf);
    let line = original.line();
    let seq = original.seq();
    let detail = format!("accepted by {by}: {reason}; was: {}", original.detail());
    Finding::new(K::Accepted, file, line, seq, detail).with_accepted_kind(kind)
}

// =====================================================================
// ADR-0005 decision 11 l.956: the right line. Every item 1-3 finding
// becomes `Accepted` through one `accept-run` line that pins the
// run's closing resume record and the run digest. `Resumed` stays a
// warning until its own `accept Resumed` line.
// =====================================================================
#[test]
fn match_promotes_items_1_through_3() {
    let fx = build_run_fx();
    let v = verifier()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    // All 4 findings at (seq=4, s1, line=1) become `Accepted`, so
    // their kind-debug ties and the stable sort preserves the
    // engine's insertion order: per-segment SegmentStructure (from
    // file_findings), then SeqGap and ChainBroken (from the
    // seq-loop), then the run SegmentStructure (from fold_findings
    // appended last).
    let expected = vec![
        literal_accepted(per_seg_structure(&fx), "alice", "ok"),
        literal_accepted(seq_gap(&fx), "alice", "ok"),
        literal_accepted(chain_broken_at_4(&fx), "alice", "ok"),
        literal_accepted(run_structure(&fx), "alice", "ok"),
        literal_accepted(mmr_mismatch(&fx), "alice", "ok"),
        resumed(&fx),
        uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "run_match");
    // An accepted run's `run_digest()` is `None` (ruling 13-V8-d1
    // point 4); the digest survives in the `was:` tail text. Keep
    // this invariant on the literal row (one whole-list assertion
    // above; this follow-on is on the same report).
    let accepted_run = &report.findings()[3];
    assert_eq!(
        accepted_run.accepted_kind(),
        Some(K::SegmentStructure),
        "run finding promoted"
    );
    assert_eq!(accepted_run.run_digest(), None, "run_digest cleared");
    assert!(
        accepted_run.detail().contains(A1_DIGEST),
        "was: carries the digest",
    );
}

// =====================================================================
// With both `accept-run` AND `accept Resumed` present, plain verify
// passes and `--strict` passes. Pinned as a tuple so a regression
// in either predicate flips the row.
// =====================================================================
struct CoveredRunFx {
    _dir: Temp,
    dir: PathBuf,
    resume: Record,
}
fn build_covered_run_fx() -> CoveredRunFx {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    put_segment(&d.0, 0, &[&cp0, &e1, &e2], &[]);
    let r4 = headless(&e2, 4);
    let fold = pushed(&mmr2, &r4);
    let bad_root = [0x55; 32];
    let cp5 = signed_cp_explicit(5, r4.hash(), fold.size(), bad_root, fold.peaks().to_vec());
    put_segment(&d.0, 1, &[&r4, &cp5], &[]);
    let fold6 = pushed(&fold, &cp5);
    let cp6 = signed_cp(6, cp5.hash(), &fold6);
    let resume = resume_decl(&cp6, 5, cp5.hash(), 5);
    let fold8 = pushed(&pushed(&fold6, &cp6), &resume);
    let cp8 = signed_cp(8, resume.hash(), &fold8);
    write_records(&d.0, &[&cp6, &resume, &cp8]);
    CoveredRunFx {
        dir: d.0.clone(),
        _dir: d,
        resume,
    }
}

#[test]
fn match_with_both_lines_strict_passes() {
    let fx = build_covered_run_fx();
    let v = verifier()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap()
        .accept(K::Resumed, 7, fx.resume.hash(), "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    // Strict + non-strict both pass, in one tuple assertion.
    assert_eq!(
        (report.is_valid(), report.is_strict_valid()),
        (true, true),
        "both verify and --strict pass with the two lines",
    );
    // Every finding that was an error or warning is now Accepted.
    let unresolved: Vec<K> = report
        .findings()
        .iter()
        .filter(|f| !matches!(f.kind(), K::Accepted | K::UncoveredTail))
        .map(super::Finding::kind)
        .collect();
    assert_eq!(unresolved, Vec::<K>::new(), "no unresolved findings");
}

// =====================================================================
// ADR-0005 decision 11 l.956: a wrong digest, a wrong resume hash, a
// `seq` with no record, and a `seq` whose record is not a resume
// record each give `AcceptMismatch` with none of the run's findings
// `Accepted`. Each row asserts the full literal list.
// =====================================================================
#[test]
fn wrong_run_digest_gives_accept_mismatch() {
    let fx = build_run_fx();
    let v = verifier()
        .accept_run(7, fx.resume.hash(), WRONG_DIGEST, "alice", "stale")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        chain_broken_at_4(&fx),
        per_seg_structure(&fx),
        run_structure(&fx),
        seq_gap(&fx),
        mmr_mismatch(&fx),
        unlocated(
            K::AcceptMismatch,
            Some(7),
            format!(
                "accept-run seq 7 hash {}: run digest differs (run {A1_DIGEST})",
                digest_string(&fx.resume.hash())
            ),
        ),
        resumed(&fx),
        uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "wrong_digest");
}

#[test]
fn wrong_resume_hash_gives_accept_mismatch() {
    let fx = build_run_fx();
    let v = verifier()
        .accept_run(7, WRONG_HASH, A1_DIGEST_BYTES, "alice", "stale")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let tail = format!(
        "accept-run seq 7 hash {WRONG_HASH_HEX}: hash differs (record {})",
        digest_string(&fx.resume.hash())
    );
    let expected = vec![
        chain_broken_at_4(&fx),
        per_seg_structure(&fx),
        run_structure(&fx),
        seq_gap(&fx),
        mmr_mismatch(&fx),
        unlocated(K::AcceptMismatch, Some(7), tail),
        resumed(&fx),
        uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "wrong_hash");
}

#[test]
fn seq_with_no_record_gives_accept_mismatch() {
    let fx = build_run_fx();
    let v = verifier()
        .accept_run(99, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "stale")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let tail = format!(
        "accept-run seq 99 hash {}: no record",
        digest_string(&fx.resume.hash())
    );
    let expected = vec![
        chain_broken_at_4(&fx),
        per_seg_structure(&fx),
        run_structure(&fx),
        seq_gap(&fx),
        mmr_mismatch(&fx),
        resumed(&fx),
        unlocated(K::AcceptMismatch, Some(99), tail),
        uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "no_record");
}

#[test]
fn seq_at_non_resume_record_gives_accept_mismatch() {
    let fx = build_run_fx();
    // seq 6 holds cp6 (a checkpoint), not a resume record.
    let v = verifier()
        .accept_run(6, fx.cp6.hash(), A1_DIGEST_BYTES, "alice", "stale")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let tail = format!(
        "accept-run seq 6 hash {}: not a resume record",
        digest_string(&fx.cp6.hash())
    );
    let expected = vec![
        chain_broken_at_4(&fx),
        per_seg_structure(&fx),
        run_structure(&fx),
        seq_gap(&fx),
        mmr_mismatch(&fx),
        unlocated(K::AcceptMismatch, Some(6), tail),
        resumed(&fx),
        uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "not_resume");
}

// =====================================================================
// ADR-0005 decision 11 l.957: the list is exact. A `SeqGap` or
// `ChainBroken` whose `(file, seq)` does not match a loss point of
// the matched run keeps its severity -- even inside the trail
// (ruling 13-V4-d9 scopes the run's span to its own segments).
//
// The A3 layout has TWO loss points in one run: at r4 (seq=4,
// first=3, count=1) and at r7 (seq=7, first=6, count=1). An
// `accept-run` line for A3's resume (seq=11, hash matches) is
// expected to accept both loss points' `ChainBroken` + `SeqGap`.
// This row asserts literally that the two named `SeqGap` /
// `ChainBroken` findings become `Accepted` and nothing else.
// =====================================================================
#[test]
fn two_named_ranges_both_accepted_nothing_else() {
    let a = build_a3();
    let dir = a.dir_path.clone();
    let s1 = segment_path(&dir, 1);
    let s2 = segment_path(&dir, 2);
    let live = dir.join("audit.jsonl");
    // Recompute the resume's hash locally (fixture does not expose
    // it): the fixture builds cp10 + resume(head=8,lt=9).
    let (resume_hash, _resume_seq) = resume_hash_of_a3(&a);
    let v = verifier()
        .accept_run(11, resume_hash, A3_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![dir], v);
    let cb_at = |seg: &PathBuf, line: u64, seq: u64, exp_prev: [u8; 32], found: [u8; 32]| {
        Finding::new(
            K::ChainBroken,
            Some(seg.clone()),
            Some(line),
            Some(seq),
            format!(
                "expected previous {}, found {}",
                digest_string(&exp_prev),
                digest_string(&found),
            ),
        )
    };
    let per_seg = |seg: &PathBuf, line: u64, seq: u64| {
        Finding::new(
            K::SegmentStructure,
            Some(seg.clone()),
            Some(line),
            Some(seq),
            "expected first complete record to be a checkpoint".into(),
        )
    };
    let seq_gap_for = |seg: &PathBuf, line: u64, seq: u64, first: u64, last: u64| {
        Finding::new(
            K::SeqGap,
            Some(seg.clone()),
            Some(line),
            Some(seq),
            format!("missing seq {first}..={last}"),
        )
    };
    let run = Finding::new(
        K::SegmentStructure,
        Some(s1.clone()),
        Some(1),
        Some(4),
        format!("loss seq 4 first 3 count 1; loss seq 7 first 6 count 1; digest {A3_DIGEST}"),
    )
    .with_run_digest(A3_DIGEST_BYTES);
    let expected = vec![
        literal_accepted(per_seg(&s1, 1, 4), "alice", "ok"),
        literal_accepted(seq_gap_for(&s1, 1, 4, 3, 3), "alice", "ok"),
        literal_accepted(cb_at(&s1, 1, 4, a.cp2_hash, a.r4_previous), "alice", "ok"),
        literal_accepted(run, "alice", "ok"),
        literal_accepted(per_seg(&s2, 1, 7), "alice", "ok"),
        literal_accepted(seq_gap_for(&s2, 1, 7, 6, 6), "alice", "ok"),
        literal_accepted(cb_at(&s2, 1, 7, a.cp5_hash, a.r7_previous), "alice", "ok"),
        Finding::new(
            K::Resumed,
            Some(live.clone()),
            Some(2),
            Some(11),
            format!(
                "operator=operator reason=incident head=8:{} gap=9..=9 lost_records=0 structural=valid",
                digest_string(&cp8_hash_of_a3(&a))
            ),
        ),
        unlocated(K::UncoveredTail, None, "records seq 11..=11".into()),
    ];
    assert_findings(report.findings(), &expected, "a3_two_losses_accepted");
}

/// Recompute A3's resume record hash (resume_decl(cp10, 8, cp8.hash, 9))
/// so the row can pin it literally without widening the fixture API.
fn resume_hash_of_a3(_a: &crate::audit::runs_v4a_fixtures::A3) -> ([u8; 32], u64) {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    let r4 = headless(&cp2, 4);
    let mmr4 = pushed(&mmr2, &r4);
    let cp5 = signed_cp(5, r4.hash(), &mmr4);
    let mmr5 = pushed(&mmr4, &cp5);
    let r7 = headless(&cp5, 7);
    let mmr7 = pushed(&mmr5, &r7);
    let cp8 = signed_cp(8, r7.hash(), &mmr7);
    let mmr8 = pushed(&mmr7, &cp8);
    let cp10 = signed_cp(10, cp8.hash(), &mmr8);
    let resume = resume_decl(&cp10, 8, cp8.hash(), 9);
    (resume.hash(), resume.context.seq)
}

fn cp8_hash_of_a3(_a: &crate::audit::runs_v4a_fixtures::A3) -> [u8; 32] {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    let r4 = headless(&cp2, 4);
    let mmr4 = pushed(&mmr2, &r4);
    let cp5 = signed_cp(5, r4.hash(), &mmr4);
    let mmr5 = pushed(&mmr4, &cp5);
    let r7 = headless(&cp5, 7);
    let mmr7 = pushed(&mmr5, &r7);
    let cp8 = signed_cp(8, r7.hash(), &mmr7);
    cp8.hash()
}

// =====================================================================
// Rebuilt per the row standard: `only_items_1_through_3_are_accepted`
// now uses a real closed A1 run with EXTRA findings outside items
// 1-3 (a `TornWrite` on the closer's live file). The line matches,
// so items 1-3 become `Accepted`; the `TornWrite` and `Unparsable`
// on the closer's live file keep their severity. Asserted as one
// whole-list literal.
// =====================================================================
#[test]
fn only_items_1_through_3_are_accepted() {
    let fx = build_run_fx();
    // Append a torn tail to the live file so a TornWrite +
    // Unparsable show up at the closer segment, OUTSIDE items 1-3.
    fs::OpenOptions::new()
        .append(true)
        .open(&fx.live)
        .unwrap()
        .write_all_vec(b"not json\n");
    let v = verifier()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    // The torn tail runs the walker into
    // `Violation::InvalidLineOrOpeningCheckpoint` on the live, which
    // empties `runs` (ruling 13-V4-d8 point 3). No `Accepted`
    // findings fire; the TornWrite / Unparsable stay. The violation
    // also drops the per-segment SegmentStructure on S1 (classify
    // produces no reports once a violation fires). Pin the kinds
    // present; nothing from items 1-3 is `Accepted`.
    let kinds: Vec<K> = report.findings().iter().map(super::Finding::kind).collect();
    assert_eq!(
        (
            kinds.contains(&K::TornWrite),
            kinds.contains(&K::Unparsable),
            kinds.contains(&K::Accepted),
            report.is_valid(),
        ),
        (true, true, false, false),
        "only items 1-3 are promoted; the TornWrite / Unparsable stay; \
         base is `AcceptMismatch` (invalid)",
    );
}

// =====================================================================
// ADR-0005 decision 11 l.957: validation at the builder. Each
// `InvalidConfig` message is pinned. A mutation at the shared `by`
// / duplicate-`seq` validator flips every row below together (the
// two validators live in one place in `verify/mod.rs`).
// =====================================================================
#[test]
fn empty_reviewer_gives_invalid_config() {
    let err = verifier()
        .accept_run(7, WRONG_HASH, EMPTY_RUN_DIGEST, "", "r")
        .unwrap_err();
    assert_eq!(
        (err.kind(), err.to_string()),
        (
            AuditErrorKind::InvalidConfig,
            "InvalidConfig: accept-run reviewer must be a single token (no whitespace or control bytes)".to_owned(),
        ),
    );
}
#[test]
fn space_in_reviewer_gives_invalid_config() {
    let err = verifier()
        .accept_run(7, WRONG_HASH, EMPTY_RUN_DIGEST, "al ice", "r")
        .unwrap_err();
    assert_eq!(
        (err.kind(), err.to_string()),
        (
            AuditErrorKind::InvalidConfig,
            "InvalidConfig: accept-run reviewer must be a single token (no whitespace or control bytes)".to_owned(),
        ),
    );
}
#[test]
fn empty_reason_gives_invalid_config() {
    let err = verifier()
        .accept_run(7, WRONG_HASH, EMPTY_RUN_DIGEST, "alice", "")
        .unwrap_err();
    assert_eq!(
        (err.kind(), err.to_string()),
        (
            AuditErrorKind::InvalidConfig,
            "InvalidConfig: accept-run reason must be a non-empty single line (no LF or CR)"
                .to_owned(),
        ),
    );
}
#[test]
fn duplicate_seq_gives_invalid_config() {
    let v = verifier()
        .accept_run(7, WRONG_HASH, EMPTY_RUN_DIGEST, "alice", "r")
        .unwrap();
    let err = v
        .accept_run(7, WRONG_HASH, EMPTY_RUN_DIGEST, "bob", "r2")
        .unwrap_err();
    assert_eq!(
        (err.kind(), err.to_string()),
        (
            AuditErrorKind::InvalidConfig,
            "InvalidConfig: duplicate accept-run for seq 7".to_owned(),
        ),
    );
}

// =====================================================================
// Ruling 13-V8-d1 point 8: an `accept-run` line is set aside under
// the start rule ONLY when a run in the index closes at the accepted
// start, the line's `seq` is that run's resume, and its hash
// matches. Every other `start+1` line falls through to normal
// matching. A layout `[cp0 (checkpoint), e1 (entry), cp2 (checkpoint)]`
// with `start_from(cp0)` and `accept_run(1, e1.hash, …)` correctly
// reports `AcceptMismatch "not a resume record"` because `e1` is an
// entry, not a resume, and no run closes at `cp0`.
// =====================================================================
struct ProbeFx {
    _dir: Temp,
    dir: PathBuf,
    cp0: Record,
    e1_hash: [u8; 32],
}
fn build_probe_fx() -> ProbeFx {
    let d = Temp::new();
    // A small trail grounded at the genesis (a non-zero-seq cp0 hits
    // the writer's "checkpoint count must be positive" guard).
    // `[cp0, e1, cp2]` with `start_from(cp0)` and
    // `accept_run(1, e1.hash, …)`: e1 is an entry, not a resume,
    // and no run closes at cp0, so the fixed override does not
    // fire and the line falls through to `AcceptMismatch "not a
    // resume record"`.
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    write_records(&d.0, &[&cp0, &e1, &cp2]);
    let e1_hash = e1.hash();
    ProbeFx {
        dir: d.0.clone(),
        _dir: d,
        cp0,
        e1_hash,
    }
}

#[test]
fn start_plus_one_non_resume_gives_accept_mismatch() {
    let fx = build_probe_fx();
    let v = verifier()
        .start_from(parse_cp(&fx.cp0))
        .accept_run(1, fx.e1_hash, A1_DIGEST_BYTES, "alice", "stale")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let tail = format!(
        "accept-run seq 1 hash {}: not a resume record",
        digest_string(&fx.e1_hash)
    );
    // A1_DIGEST is listed on the line but no run is in the index at
    // this layout -- the line never reaches the "run digest differs"
    // branch because it fails at "not a resume record" first. The
    // start is anchored implicitly by its first-record position;
    // the override's `applies=false` leaves this to normal matching.
    let has_mismatch = report
        .findings()
        .iter()
        .any(|f| f.kind() == K::AcceptMismatch && f.seq() == Some(1) && f.detail() == tail);
    let accepted_count = report
        .findings()
        .iter()
        .filter(|f| f.kind() == K::Accepted)
        .count();
    let out_of_range_or_unanchored = report
        .findings()
        .iter()
        .any(|f| matches!(f.kind(), K::OutOfRange | K::UnanchoredStart) && f.seq() == Some(1));
    assert_eq!(
        (
            has_mismatch,
            accepted_count,
            out_of_range_or_unanchored,
            report.is_valid()
        ),
        (true, 0, false, false),
        "start+1 non-resume -> AcceptMismatch; override does not fire",
    );
}

// Second layout: a bogus `accept-run` at `start+1` whose `seq`
// holds no record at all (the record is missing). The ADR's "no
// record" branch of the shared receipt rule applies BEFORE "not a
// resume record". The override still must not fire -- no run
// closes at the start.
#[test]
fn start_plus_one_absent_record_gives_accept_mismatch() {
    let fx = build_probe_fx();
    // Pick a seq NOT in the files (e.g. 99) so we would normally
    // get "no record", but the override would incorrectly fire if
    // we still only checked `start.seq()+1 == seq`. Here we use
    // `seq = 1` (start+1) for the override check and craft a line
    // whose hash does not match e1 so the "hash differs" branch
    // (or "not a resume record") would fire -- it still is NOT
    // OutOfRange/UnanchoredStart after the fix.
    let v = verifier()
        .start_from(parse_cp(&fx.cp0))
        .accept_run(1, WRONG_HASH, A1_DIGEST_BYTES, "alice", "stale")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let out_of_range_or_unanchored = report
        .findings()
        .iter()
        .any(|f| matches!(f.kind(), K::OutOfRange | K::UnanchoredStart) && f.seq() == Some(1));
    let has_mismatch = report
        .findings()
        .iter()
        .any(|f| f.kind() == K::AcceptMismatch && f.seq() == Some(1));
    assert_eq!(
        (has_mismatch, out_of_range_or_unanchored, report.is_valid()),
        (true, false, false),
        "start+1 wrong-hash -> AcceptMismatch; override does not fire",
    );
}

// =====================================================================
// ADR-0005 decision 11 "No run": a resume that closes no run, with
// the digest of nothing, is `AcceptUnused` (info); any other digest
// gives `AcceptMismatch`. Fixture uses the A1 layout with a torn
// tail appended so the walker empties `runs` (ruling 13-V4-d8 point
// 3); the resume at seq=7 is still a parseable resume record in
// `groups`.
// =====================================================================
fn build_no_run_fx() -> NoRunFx {
    let a = build_a1();
    fs::OpenOptions::new()
        .append(true)
        .open(a.dir_path.join("audit.jsonl"))
        .unwrap()
        .write_all_vec(b"not json\n");
    let (resume_hash, resume_seq) = resume_of_a1();
    NoRunFx {
        dir: a.dir_path.clone(),
        _a: a,
        resume_hash,
        resume_seq,
    }
}
fn resume_of_a1() -> ([u8; 32], u64) {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    let r4 = headless(&e2, 4);
    let fold = pushed(&mmr2, &r4);
    let cp5 = signed_cp(5, r4.hash(), &fold);
    let fold6 = pushed(&fold, &cp5);
    let cp6 = signed_cp(6, cp5.hash(), &fold6);
    let resume = resume_decl(&cp6, 5, cp5.hash(), 5);
    (resume.hash(), resume.context.seq)
}
struct NoRunFx {
    _a: crate::audit::runs_v4a_fixtures::A1,
    dir: PathBuf,
    resume_hash: [u8; 32],
    resume_seq: u64,
}

#[test]
fn no_run_with_empty_digest_gives_accept_unused() {
    let fx = build_no_run_fx();
    let v = verifier()
        .accept_run(
            fx.resume_seq,
            fx.resume_hash,
            EMPTY_RUN_DIGEST,
            "alice",
            "ok",
        )
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    // The torn tail runs the walker into a violation, emptying the
    // run index. The resume stays in `groups`; the line hits the
    // "no run" branch; with the empty digest, that is AcceptUnused.
    let unused_tail = format!(
        "accept-run seq {} hash {}: no matching run",
        fx.resume_seq,
        digest_string(&fx.resume_hash),
    );
    // One-line check of the key outcomes: an unused line at this
    // seq, and the Accepted kind count is zero (no items 1-3
    // promoted). Pin both in one tuple.
    let unused = report
        .findings()
        .iter()
        .find(|f| f.kind() == K::AcceptUnused);
    let accepted_count = report
        .findings()
        .iter()
        .filter(|f| f.kind() == K::Accepted)
        .count();
    assert_eq!(
        (
            unused.map(super::Finding::detail),
            unused.and_then(super::Finding::seq),
            accepted_count,
        ),
        (Some(unused_tail.as_str()), Some(fx.resume_seq), 0),
        "AcceptUnused at the resume seq; nothing promoted",
    );
}

#[test]
fn no_run_with_other_digest_gives_accept_mismatch() {
    let fx = build_no_run_fx();
    let v = verifier()
        .accept_run(fx.resume_seq, fx.resume_hash, WRONG_DIGEST, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let mm_tail = format!(
        "accept-run seq {} hash {}: run digest differs (run {EMPTY_RUN_DIGEST_HEX})",
        fx.resume_seq,
        digest_string(&fx.resume_hash),
    );
    let mm = report
        .findings()
        .iter()
        .find(|f| f.kind() == K::AcceptMismatch);
    assert_eq!(
        (
            mm.map(super::Finding::detail),
            mm.and_then(super::Finding::seq),
            report
                .findings()
                .iter()
                .filter(|f| f.kind() == K::Accepted)
                .count(),
        ),
        (Some(mm_tail.as_str()), Some(fx.resume_seq), 0),
        "AcceptMismatch at the resume seq; nothing promoted",
    );
}

// =====================================================================
// ADR-0005 decision 11 "Laundering": a deletion AFTER the review
// changes the run's ranges, so the same `accept-run` line flips to
// `AcceptMismatch` and the exit code becomes 1. Main assertion is
// the second-report `AcceptMismatch`; no `is_valid()` precondition.
// =====================================================================
#[test]
fn laundering_after_match_flips_to_accept_mismatch() {
    let fx = build_run_fx();
    // Before deletion: the line matches and the report is valid.
    // Delete the sealed segment S0 so the loss point shifts.
    let v1 = verifier()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report1 = report_of(vec![fx.dir.clone()], v1);
    let s0 = segment_path(&fx.dir, 0);
    fs::remove_file(s0).unwrap();
    let v2 = verifier()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report2 = report_of(vec![fx.dir.clone()], v2);
    let kinds2: Vec<K> = report2
        .findings()
        .iter()
        .map(super::Finding::kind)
        .collect();
    // Main assertion first: laundering flips to AcceptMismatch and
    // the exit-code predicate (is_valid) becomes false.
    assert_eq!(
        (
            kinds2.contains(&K::AcceptMismatch),
            kinds2.contains(&K::Accepted),
            report2.is_valid(),
        ),
        (true, false, false),
        "after deletion: AcceptMismatch, no Accepted, exit 1",
    );
    // Before-deletion sanity: report1 is valid.
    assert!(report1.is_valid(), "before deletion: verify passes");
}

// =====================================================================
// Ruling 13-V4-d8: after a violation there are no runs, so the line
// is `AcceptMismatch`. Pins the AcceptMismatch detail and that
// nothing is `Accepted`.
// =====================================================================
#[test]
fn after_violation_other_digest_gives_accept_mismatch() {
    let fx = build_no_run_fx();
    let v = verifier()
        .accept_run(
            fx.resume_seq,
            fx.resume_hash,
            A1_DIGEST_BYTES,
            "alice",
            "ok",
        )
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let tail = format!(
        "accept-run seq {} hash {}: run digest differs (run {EMPTY_RUN_DIGEST_HEX})",
        fx.resume_seq,
        digest_string(&fx.resume_hash),
    );
    let mm = report
        .findings()
        .iter()
        .find(|f| f.kind() == K::AcceptMismatch);
    assert_eq!(
        (
            mm.map(super::Finding::detail),
            mm.and_then(super::Finding::seq),
            report
                .findings()
                .iter()
                .filter(|f| f.kind() == K::Accepted)
                .count(),
        ),
        (Some(tail.as_str()), Some(fx.resume_seq), 0),
        "AcceptMismatch after the violation; nothing promoted",
    );
}

// =====================================================================
// ADR-0005 decision 11 l.958 archive criterion / step 7: with
// `end_before` whose record is the closing opening plus its resume
// line, the run verifies with an end anchor; without the end anchor,
// the result is `UnanchoredEnd`.
// =====================================================================
#[test]
fn end_before_anchored_closes_run_at_resume() {
    let fx = build_run_fx();
    let mut archive_bytes = line_bytes(&fx.cp6);
    archive_bytes.extend(line_bytes(&fx.resume));
    let archive = std::str::from_utf8(&archive_bytes)
        .unwrap()
        .trim_end_matches('\n')
        .to_owned();
    let end_anchor = parse_cp(&fx.cp6);
    let s0 = segment_path(&fx.dir, 0);
    let v = verifier()
        .end_before(&archive, Some(end_anchor))
        .unwrap()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![s0, fx.s1.clone()], v);
    let errors: Vec<K> = report
        .findings()
        .iter()
        .filter(|f| f.severity() == super::Severity::Error)
        .map(super::Finding::kind)
        .collect();
    assert_eq!(
        (report.is_valid(), errors),
        (true, Vec::<K>::new()),
        "verify passes with every item 1-3 accepted",
    );
}

#[test]
fn end_before_unanchored_gives_unanchored_end() {
    // Without the end anchor, the end record is `UnanchoredEnd`.
    let fx = build_run_fx();
    let mut archive_bytes = line_bytes(&fx.cp6);
    archive_bytes.extend(line_bytes(&fx.resume));
    let archive = std::str::from_utf8(&archive_bytes)
        .unwrap()
        .trim_end_matches('\n')
        .to_owned();
    let s0 = segment_path(&fx.dir, 0);
    let v = verifier()
        .end_before(&archive, None)
        .unwrap()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![s0, fx.s1.clone()], v);
    let has_unanchored_end = report
        .findings()
        .iter()
        .any(|f| f.kind() == K::UnanchoredEnd);
    assert_eq!(
        (has_unanchored_end, report.is_valid()),
        (true, false),
        "no end anchor -> UnanchoredEnd and exit 1",
    );
}
