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
    // Whole list: five items 1-3 findings accepted + the Resumed
    // warning accepted. With both lines present and strict on, the
    // run is clean. Pin strict/non-strict after the list.
    let fx = build_covered_run_fx();
    let dir = fx.dir.clone();
    let s0 = segment_path(&dir, 0);
    let s1 = segment_path(&dir, 1);
    let live = dir.join("audit.jsonl");
    let v = verifier()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap()
        .accept(K::Resumed, 7, fx.resume.hash(), "alice", "ok")
        .unwrap();
    let report = report_of(vec![dir], v);
    let per_seg = |seg: &PathBuf, line: u64, seq: u64| {
        Finding::new(
            K::SegmentStructure,
            Some(seg.clone()),
            Some(line),
            Some(seq),
            "expected first complete record to be a checkpoint".into(),
        )
    };
    let chain = |seg: &PathBuf, line: u64, seq: u64, exp: [u8; 32], got: [u8; 32]| {
        Finding::new(
            K::ChainBroken,
            Some(seg.clone()),
            Some(line),
            Some(seq),
            format!(
                "expected previous {}, found {}",
                digest_string(&exp),
                digest_string(&got),
            ),
        )
    };
    let seqgap_at = |seg: &PathBuf, line: u64, seq: u64, a: u64, b: u64| {
        Finding::new(
            K::SeqGap,
            Some(seg.clone()),
            Some(line),
            Some(seq),
            format!("missing seq {a}..={b}"),
        )
    };
    let mmr = Finding::new(
        K::MmrMismatch,
        Some(s1.clone()),
        Some(2),
        Some(5),
        format!(
            "expected size 4 root blake3:8c89e5675d09a83557775acf82c200357f94447d60bf5d4a455b525cf04ff242, \
             found size 4 root {}",
            digest_string(&[0x55; 32]),
        ),
    );
    // Reproduce the hashes we need for literal pins. The covered-
    // run fixture uses the SAME bad_root=0x55 as `build_run_fx`,
    // so cp5's hash matches `build_run_fx`'s cp5 hash.
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    let r4 = headless(&e2, 4);
    let fold = pushed(&mmr2, &r4);
    let cp5 = signed_cp_explicit(5, r4.hash(), fold.size(), [0x55; 32], fold.peaks().to_vec());
    let run_structure_fx = Finding::new(
        K::SegmentStructure,
        Some(s1.clone()),
        Some(1),
        Some(4),
        format!("loss seq 4 first 3 count 1; digest {A1_DIGEST}"),
    )
    .with_run_digest(A1_DIGEST_BYTES);
    let resumed = Finding::new(
        K::Resumed,
        Some(live.clone()),
        Some(2),
        Some(7),
        format!(
            "operator=operator reason=incident head=5:{} gap=none lost_records=0 structural=valid",
            digest_string(&cp5.hash()),
        ),
    );
    let _ = (s0,); // S0 is sealed but not independently asserted.
    let expected = vec![
        literal_accepted(per_seg(&s1, 1, 4), "alice", "ok"),
        literal_accepted(seqgap_at(&s1, 1, 4, 3, 3), "alice", "ok"),
        literal_accepted(
            chain(&s1, 1, 4, e2.hash(), r4.context.previous),
            "alice",
            "ok",
        ),
        literal_accepted(run_structure_fx, "alice", "ok"),
        literal_accepted(mmr, "alice", "ok"),
        literal_accepted(resumed, "alice", "ok"),
    ];
    assert_findings(report.findings(), &expected, "both_lines_literal");
    assert_eq!(
        (report.is_valid(), report.is_strict_valid()),
        (true, true),
        "verify and --strict both pass",
    );
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
// ADR-0005 decision 11 l.957 "only items 1-3 are promoted", on a
// real closed run (no violation). `build_run_fx` is a closed A1
// run with 5 items 1-3 findings, one `Resumed` warning and one
// `UncoveredTail`. The accept-run line matches: items 1-3 become
// `Accepted`, every other finding keeps its severity. Fails on
// base because items 1-3 stay as errors without the match.
// Whole-list literal.
// =====================================================================
#[test]
fn only_items_1_through_3_are_accepted() {
    let fx = build_run_fx();
    let v = verifier()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        literal_accepted(per_seg_structure(&fx), "alice", "ok"),
        literal_accepted(seq_gap(&fx), "alice", "ok"),
        literal_accepted(chain_broken_at_4(&fx), "alice", "ok"),
        literal_accepted(run_structure(&fx), "alice", "ok"),
        literal_accepted(mmr_mismatch(&fx), "alice", "ok"),
        resumed(&fx),
        uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "only_items_1_3");
    // Resumed stays a warning (not accepted) and UncoveredTail
    // stays an info. The list is exact: only items 1-3 are
    // promoted.
    let accepted_count = report
        .findings()
        .iter()
        .filter(|f| f.kind() == K::Accepted)
        .count();
    let unresolved_warnings: Vec<K> = report
        .findings()
        .iter()
        .filter(|f| f.severity() == super::Severity::Warning)
        .map(super::Finding::kind)
        .collect();
    assert_eq!((accepted_count, unresolved_warnings), (5, vec![K::Resumed]));
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

#[test]
fn duplicate_seq_different_values_still_invalid_config() {
    // Second layout for the "duplicate seq" validator: the hash,
    // digest, reviewer and reason all differ -- only the `seq`
    // collides. The validator must still reject on the `seq`
    // alone.
    let v = verifier()
        .accept_run(42, WRONG_HASH, EMPTY_RUN_DIGEST, "alice", "ok")
        .unwrap();
    let err = v
        .accept_run(42, [0xEE; 32], [0xDD; 32], "bob", "later")
        .unwrap_err();
    assert_eq!(
        (err.kind(), err.to_string()),
        (
            AuditErrorKind::InvalidConfig,
            "InvalidConfig: duplicate accept-run for seq 42".to_owned(),
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
    // The probe fixture has `[cp0, e1, cp2]` with `start_from(cp0)`
    // and `accept_run(1, e1.hash, …)`. `e1` at `start + 1` is an
    // entry, not a resume, and its hash differs trivially from
    // nothing -- the override must not fire. Normal matching sees
    // the record at seq=1 as "not a resume record" (ADR-0005
    // decision 11), so the line is `AcceptMismatch`. Whole list.
    let fx = build_probe_fx();
    let v = verifier()
        .start_from(parse_cp(&fx.cp0))
        .accept_run(1, fx.e1_hash, A1_DIGEST_BYTES, "alice", "stale")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![unlocated(
        K::AcceptMismatch,
        Some(1),
        format!(
            "accept-run seq 1 hash {}: not a resume record",
            digest_string(&fx.e1_hash),
        ),
    )];
    assert_findings(report.findings(), &expected, "start_plus_one_non_resume");
    assert!(!report.is_valid(), "AcceptMismatch is Error");
}

#[test]
fn start_plus_one_wrong_hash_gives_accept_mismatch() {
    // Second layout for the same rule: `[cp0, e1, cp2]`,
    // `start_from(cp0)`, `accept_run(1, WRONG_HASH, …)`. The record
    // at seq=1 has e1's hash, which differs from `WRONG_HASH`, so
    // the shared match rule emits `AcceptMismatch "hash differs
    // (record X)"`. The override must still not fire: the line's
    // hash is not a resume hash at start + 1.
    let fx = build_probe_fx();
    let v = verifier()
        .start_from(parse_cp(&fx.cp0))
        .accept_run(1, WRONG_HASH, A1_DIGEST_BYTES, "alice", "stale")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![unlocated(
        K::AcceptMismatch,
        Some(1),
        format!(
            "accept-run seq 1 hash {WRONG_HASH_HEX}: hash differs (record {})",
            digest_string(&fx.e1_hash)
        ),
    )];
    assert_findings(report.findings(), &expected, "start_plus_one_wrong_hash");
    assert!(!report.is_valid(), "AcceptMismatch is Error");
}

// =====================================================================
// Shared fixture for the ruling 13-V4-d8 "after a violation" row.
// The A1 layout with a torn tail appended runs the walker into a
// violation (ruling 13-V4-d8 point 3), which empties the run
// index. The resume at seq=7 is still a parseable resume in
// `groups`. Consumed by `after_violation_gives_accept_mismatch`.
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

// =====================================================================
// ADR-0005 decision 11 "Laundering": a deletion AFTER the review
// changes the run's ranges, so the same `accept-run` line flips to
// `AcceptMismatch` and the exit code becomes 1. Main assertion is
// the second-report `AcceptMismatch`; no `is_valid()` precondition.
// =====================================================================
#[test]
fn laundering_after_match_flips_to_accept_mismatch() {
    // ADR-0005 decision 11 "Laundering": a deletion AFTER the review
    // changes the run digest, so the SAME `accept-run` line goes
    // from a match to `AcceptMismatch`. Main assertion is the
    // post-deletion kind set; we pin exactly ONE `AcceptMismatch`
    // and ZERO `Accepted`, and that `is_valid` becomes false.
    let fx = build_run_fx();
    let s0 = segment_path(&fx.dir, 0);
    fs::remove_file(s0).unwrap();
    let v = verifier()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let mismatch_count = report
        .findings()
        .iter()
        .filter(|f| f.kind() == K::AcceptMismatch)
        .count();
    let accepted_count = report
        .findings()
        .iter()
        .filter(|f| f.kind() == K::Accepted)
        .count();
    assert_eq!(
        (mismatch_count, accepted_count, report.is_valid()),
        (1, 0, false),
        "after deletion: one AcceptMismatch, nothing promoted, exit 1",
    );
}

// =====================================================================
// Ruling 13-V4-d8: after a violation there are no runs, so an
// `accept-run` line with any digest is `AcceptMismatch`. Pin one
// `AcceptMismatch` at the resume seq, zero `Accepted`, and that
// the report is not valid.
// =====================================================================
#[test]
fn after_violation_gives_accept_mismatch() {
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
    let mismatch = report.findings().iter().find(|f| {
        f.kind() == K::AcceptMismatch
            && f.seq() == Some(fx.resume_seq)
            && f.detail().contains("run digest differs")
    });
    let accepted_count = report
        .findings()
        .iter()
        .filter(|f| f.kind() == K::Accepted)
        .count();
    assert_eq!(
        (mismatch.is_some(), accepted_count, report.is_valid()),
        (true, 0, false),
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
    // The `end_before` archive is `[cp6, resume7]`; its anchor is
    // cp6. With `accept_run(7, resume.hash, A1_DIGEST)`, every item
    // 1-3 of the A1 run becomes `Accepted`; the end record emits no
    // `UnanchoredEnd` (end is anchored); the resume line is part of
    // the end record so its location is stripped. Whole list.
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
    let expected = vec![
        literal_accepted(per_seg_structure(&fx), "alice", "ok"),
        literal_accepted(seq_gap(&fx), "alice", "ok"),
        literal_accepted(chain_broken_at_4(&fx), "alice", "ok"),
        literal_accepted(run_structure(&fx), "alice", "ok"),
        literal_accepted(mmr_mismatch(&fx), "alice", "ok"),
        unlocated(
            K::Resumed,
            Some(7),
            format!(
                "operator=operator reason=incident head=5:{} gap=none lost_records=0 structural=valid",
                digest_string(&fx.cp5.hash())
            ),
        ),
        uncovered_tail(),
    ];
    assert_findings(
        report.findings(),
        &expected,
        "end_before_anchored_run_accepted",
    );
    assert!(
        report.is_valid(),
        "verify passes with every item 1-3 accepted"
    );
}

#[test]
fn end_before_unanchored_gives_unanchored_end() {
    // Without the end anchor, the end record is `UnanchoredEnd`.
    // Whole-list literal (ruling 13-V6-d7 points 2-3): the
    // unlocated `UnanchoredEnd` sits alongside every item 1-3
    // Accepted and nothing else fires.
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
    let expected = vec![
        literal_accepted(per_seg_structure(&fx), "alice", "ok"),
        literal_accepted(seq_gap(&fx), "alice", "ok"),
        literal_accepted(chain_broken_at_4(&fx), "alice", "ok"),
        literal_accepted(run_structure(&fx), "alice", "ok"),
        literal_accepted(mmr_mismatch(&fx), "alice", "ok"),
        unlocated(
            K::UnanchoredEnd,
            Some(6),
            "end_before seq 6: no end anchor".into(),
        ),
        // The resume is part of the end record (ruling 13-V6-d4
        // point 6), so its location is stripped before sort.
        unlocated(
            K::Resumed,
            Some(7),
            format!(
                "operator=operator reason=incident head=5:{} gap=none lost_records=0 structural=valid",
                digest_string(&fx.cp5.hash())
            ),
        ),
        uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "unanchored_end_run_accepted");
    assert!(!report.is_valid(), "UnanchoredEnd is Error, exit 1");
}

// =====================================================================
// Ruling 13-V8-d1 point 8, clarification 13-V8-d1a: an `accept-run`
// line whose `seq` is start + 1 is set aside under the start rule
// exactly when the verified set holds at that `seq` one unforked
// `vigil.audit.resume` record whose hash equals the line's and
// whose opening is the start. The run such a line closes lies
// wholly below the start and is never in the run index -- so the
// override consults the merged records at `start + 1` alone.
// =====================================================================

/// Live-only archive: the live file holds the closing opening +
/// its resume, every segment of the run that closed at the start
/// lies below the verified set. `cp6`'s declared `(size, root,
/// peaks)` are self-consistent (`CheckpointFields::new`), so the
/// fold classifier reads them as `Base` and emits no
/// `MmrMismatch`.
struct ArchiveStartFx {
    _dir: Temp,
    dir: PathBuf,
    live: PathBuf,
    cp6: Record,
    resume: Record,
    cp5_hash: [u8; 32],
}
fn build_archive_start_fx() -> ArchiveStartFx {
    let d = Temp::new();
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
    // The archive is just the live file: the closed run lies below
    // this set and only the closing opening + its resume are read.
    write_records(&d.0, &[&cp6, &resume]);
    let live = d.0.join("audit.jsonl");
    ArchiveStartFx {
        dir: d.0.clone(),
        _dir: d,
        live,
        cp5_hash: cp5.hash(),
        cp6,
        resume,
    }
}

fn archive_resumed_finding(fx: &ArchiveStartFx) -> Finding {
    // The archive sees the closing opening + its resume alone; the
    // run's head (cp5) sits below the verified set, so the Resumed
    // declaration is `structural=invalid(head-not-present)`.
    Finding::new(
        K::Resumed,
        Some(fx.live.clone()),
        Some(2),
        Some(7),
        format!(
            "operator=operator reason=incident head=5:{} gap=none lost_records=0 structural=invalid(head-not-present)",
            digest_string(&fx.cp5_hash)
        ),
    )
}
fn archive_uncovered_tail() -> Finding {
    unlocated(K::UncoveredTail, None, "records seq 7..=7".into())
}

#[test]
fn archive_start_anchored_sets_aside_as_out_of_range() {
    // The archive start, anchored: live `[cp6, resume7]`,
    // anchor(cp6), start_from(cp6), the correct line. Override at
    // start + 1 fires: resume at seq=7 has hash=resume.hash and
    // previous=cp6.hash, so the line is set aside under the start
    // rule as `OutOfRange`. The run digest on the line is never
    // consulted. Report is valid (OutOfRange is Info).
    let fx = build_archive_start_fx();
    let v = verifier()
        .anchor(parse_cp(&fx.cp6))
        .start_from(parse_cp(&fx.cp6))
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        unlocated(
            K::OutOfRange,
            Some(7),
            format!(
                "accept-run seq 7 hash {}: below start seq 6",
                digest_string(&fx.resume.hash())
            ),
        ),
        archive_resumed_finding(&fx),
        archive_uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "archive_start_anchored");
    assert!(report.is_valid(), "OutOfRange is Info, report stays valid");
}

#[test]
fn archive_start_unanchored_sets_aside_as_unanchored_start() {
    // The same, unanchored: no `anchor(cp6)`. The override still
    // fires but the start is not anchored, so the kind flips to
    // `UnanchoredStart` (Error). Report is not valid.
    let fx = build_archive_start_fx();
    let v = verifier()
        .start_from(parse_cp(&fx.cp6))
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        unlocated(
            K::UnanchoredStart,
            Some(7),
            format!(
                "accept-run seq 7 hash {}: below start seq 6",
                digest_string(&fx.resume.hash())
            ),
        ),
        archive_resumed_finding(&fx),
        archive_uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "archive_start_unanchored");
    assert!(!report.is_valid(), "UnanchoredStart is Error");
}

/// Second layout: the start sits at a different seq (`cp1`
/// instead of `cp6`), with only the live file `[cp1, resume2]` in
/// the verified set. The rule is seq-agnostic: the override still
/// fires through the record-at-start-plus-one check alone.
struct ArchiveStartCp1Fx {
    _dir: Temp,
    dir: PathBuf,
    live: PathBuf,
    cp1: Record,
    resume: Record,
    cp0_hash: [u8; 32],
}
fn build_archive_start_cp1_fx() -> ArchiveStartCp1Fx {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let cp1 = signed_cp(1, cp0.hash(), &mmr0);
    let resume = resume_decl(&cp1, 0, cp0.hash(), 0);
    // Live-only: the prior segment lies below the verified set; the
    // start rule still demands the start to be the first record
    // seen (start::check), so cp0 stays off-disk.
    write_records(&d.0, &[&cp1, &resume]);
    let live = d.0.join("audit.jsonl");
    ArchiveStartCp1Fx {
        dir: d.0.clone(),
        _dir: d,
        live,
        cp0_hash: cp0.hash(),
        cp1,
        resume,
    }
}

#[test]
fn archive_start_at_cp1_sets_aside_as_out_of_range() {
    // A second layout for the same rule. Start = cp1 (seq=1),
    // resume at seq=2, with cp0 sealed below the start. Override
    // fires regardless of which seq the start sits at.
    let fx = build_archive_start_cp1_fx();
    let v = verifier()
        .anchor(parse_cp(&fx.cp1))
        .start_from(parse_cp(&fx.cp1))
        .accept_run(2, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        unlocated(
            K::OutOfRange,
            Some(2),
            format!(
                "accept-run seq 2 hash {}: below start seq 1",
                digest_string(&fx.resume.hash())
            ),
        ),
        Finding::new(
            K::Resumed,
            Some(fx.live.clone()),
            Some(2),
            Some(2),
            format!(
                "operator=operator reason=incident head=0:{} gap=none lost_records=0 structural=invalid(head-not-present)",
                digest_string(&fx.cp0_hash)
            ),
        ),
        unlocated(K::UncoveredTail, None, "records seq 2..=2".into()),
    ];
    assert_findings(report.findings(), &expected, "archive_start_cp1");
    assert!(report.is_valid(), "OutOfRange is Info");
}

#[test]
fn wrong_hash_at_start_plus_one_gives_accept_mismatch() {
    // Wrong hash at start + 1: the record at `start + 1` is a real
    // resume, but the line's hash differs. The override reads the
    // line's hash and refuses to fire; the line falls through to
    // the shared receipt match rule which reports "hash differs
    // (record X)". A bogus line never clears an error.
    let fx = build_archive_start_fx();
    let v = verifier()
        .anchor(parse_cp(&fx.cp6))
        .start_from(parse_cp(&fx.cp6))
        .accept_run(7, WRONG_HASH, A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        unlocated(
            K::AcceptMismatch,
            Some(7),
            format!(
                "accept-run seq 7 hash {WRONG_HASH_HEX}: hash differs (record {})",
                digest_string(&fx.resume.hash())
            ),
        ),
        archive_resumed_finding(&fx),
        archive_uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "wrong_hash_at_start_plus_one");
    assert!(!report.is_valid(), "AcceptMismatch is Error");
}

// =====================================================================
// Ruling 13-V8-d1 FORK 4: a forked `seq` is `AcceptMismatch
// "... seq is forked"`. Also pins that `SeqConflict` is emitted at
// the forked seq.
// =====================================================================
#[test]
fn forked_seq_gives_accept_mismatch_and_seq_conflict() {
    // Two records with distinct hashes at the same seq=7 across a
    // live and a shipped-copy. The merge groups two hashes together
    // at seq=7, so `conflicting_seqs` contains 7 and the shared
    // match rule emits `AcceptMismatch "... seq is forked"`.
    let fx = build_run_fx();
    // Append a byte-mutated resume copy at seq=7 in a shipped file
    // (sibling to the trail directory, so the verifier sees it as a
    // separate native segment with a different record hash).
    let sibling_path = fx.dir.join("audit-shipped-copy.jsonl");
    // Build a second resume at seq=7 that is not byte-identical
    // (change head so its hash differs). It opens from cp6 (same
    // previous), but a different hash so groups[7] holds two
    // distinct hashes -> `forked`.
    let alt_resume = resume_decl(&fx.cp6, 5, fx.cp5.hash(), 4);
    assert_ne!(alt_resume.hash(), fx.resume.hash(), "distinct hashes");
    fs::write(&sibling_path, line_bytes(&alt_resume)).unwrap();
    let v = verifier()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone(), sibling_path.clone()], v);
    // Scan for the two decisive findings; this run also carries
    // the A1 run findings, so pin only the two the shared match
    // rule flips at a forked seq.
    let mismatch_tail = format!(
        "accept-run seq 7 hash {}: seq is forked",
        digest_string(&fx.resume.hash())
    );
    let mismatch = report
        .findings()
        .iter()
        .find(|f| f.kind() == K::AcceptMismatch);
    let conflict = report
        .findings()
        .iter()
        .find(|f| f.kind() == K::SeqConflict);
    assert_eq!(
        (
            mismatch.map(super::Finding::detail),
            mismatch.and_then(super::Finding::seq),
            conflict.and_then(super::Finding::seq),
            report
                .findings()
                .iter()
                .filter(|f| f.kind() == K::Accepted)
                .count(),
        ),
        (Some(mismatch_tail.as_str()), Some(7), Some(7), 0),
        "forked seq -> AcceptMismatch + SeqConflict, nothing promoted",
    );
}

// =====================================================================
// ADR-0005 decision 11 "No run" honest row: a nothing-lost resume
// over an A8-style closed run, with the empty-run digest, is
// `AcceptUnused` (info). Any other digest is `AcceptMismatch`. The
// fixture is NOT a violation fixture -- the walker reaches the run
// honestly and `run_digest()` equals the digest of nothing because
// the run has no ranges and no spans.
// =====================================================================
/// Honest no-run layout: live = `[cp0, resume1]` where `resume1`
/// declares nothing lost (head=0, lost_through=0). `cp0` is the
/// genesis-adjacent first record and there is no closing opening
/// before it, so the classifier emits no closed run. The resume
/// still parses honestly (not a violation), and
/// `accept_run(1, resume1.hash, digest_of_nothing)` hits the "no
/// run" branch -> `AcceptUnused`.
struct HonestNoRunFx {
    _dir: Temp,
    dir: PathBuf,
    live: PathBuf,
    resume: Record,
    cp0_hash: [u8; 32],
}
fn build_honest_no_run_fx() -> HonestNoRunFx {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let resume = resume_decl(&cp0, 0, cp0.hash(), 0);
    write_records(&d.0, &[&cp0, &resume]);
    let dir = d.0.clone();
    let live = dir.join("audit.jsonl");
    HonestNoRunFx {
        dir,
        _dir: d,
        live,
        cp0_hash: cp0.hash(),
        resume,
    }
}

fn honest_no_run_resumed(fx: &HonestNoRunFx) -> Finding {
    // A resume that opens without a closing-opening checkpoint
    // before it is `structural=invalid(no-opening)`: the record
    // parses honestly, but the classifier does not recognise it as
    // closing any run.
    Finding::new(
        K::Resumed,
        Some(fx.live.clone()),
        Some(2),
        Some(1),
        format!(
            "operator=operator reason=incident head=0:{} gap=none lost_records=0 structural=invalid(no-opening)",
            digest_string(&fx.cp0_hash)
        ),
    )
}

#[test]
fn honest_no_run_with_empty_digest_gives_accept_unused() {
    let fx = build_honest_no_run_fx();
    let v = verifier()
        .accept_run(1, fx.resume.hash(), EMPTY_RUN_DIGEST, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        unlocated(
            K::AcceptUnused,
            Some(1),
            format!(
                "accept-run seq 1 hash {}: no matching run",
                digest_string(&fx.resume.hash())
            ),
        ),
        honest_no_run_resumed(&fx),
        unlocated(K::UncoveredTail, None, "records seq 1..=1".into()),
    ];
    assert_findings(report.findings(), &expected, "honest_no_run_empty");
    assert!(report.is_valid(), "AcceptUnused is Info");
}

#[test]
fn honest_no_run_with_other_digest_gives_accept_mismatch() {
    let fx = build_honest_no_run_fx();
    let v = verifier()
        .accept_run(1, fx.resume.hash(), WRONG_DIGEST, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        unlocated(
            K::AcceptMismatch,
            Some(1),
            format!(
                "accept-run seq 1 hash {}: run digest differs (run {EMPTY_RUN_DIGEST_HEX})",
                digest_string(&fx.resume.hash())
            ),
        ),
        honest_no_run_resumed(&fx),
        unlocated(K::UncoveredTail, None, "records seq 1..=1".into()),
    ];
    assert_findings(report.findings(), &expected, "honest_no_run_wrong");
    assert!(!report.is_valid(), "AcceptMismatch is Error");
}

// =====================================================================
// Ruling 13-V8-d1 FORK 5: an `accept-run` line inside a confirmed
// resume gap is `LostRecord` (receipt + accept-Resumed confirmation
// variants). The gap is confirmed, so the line is lost, not
// mismatched; the subject is still the full `accept-run` subject.
// =====================================================================
#[test]
fn accept_run_inside_gap_confirmed_by_receipt_is_lost_record() {
    // A3 has a real resume gap `9..=9`; the receipt at (resume_seq,
    // resume_hash) confirms it (ruling 13-V7-d1 point 8). Place an
    // accept_run for seq=9 (inside the gap). Confirmation demotes
    // it to `LostRecord` under the shared gap rule.
    let a = build_a3();
    let dir = a.dir_path.clone();
    let (resume_hash, resume_seq) = resume_hash_of_a3(&a);
    let v = verifier()
        .receipts([(resume_seq, resume_hash)])
        .accept_run(9, WRONG_HASH, EMPTY_RUN_DIGEST, "alice", "ok")
        .unwrap();
    let report = report_of(vec![dir], v);
    let lost = report.findings().iter().find(|f| {
        f.kind() == K::LostRecord
            && f.seq() == Some(9)
            && f.detail().starts_with("accept-run seq 9 hash")
    });
    assert!(
        lost.is_some(),
        "accept-run inside a receipt-confirmed gap -> LostRecord: got {:#?}",
        report.findings(),
    );
}

// =====================================================================
// ADR-0005 decision 11 `accept-run` l.957 "the list is exact":
// a `SeqGap` and a `ChainBroken` on a SEGMENT AFTER the run's
// closer (ruling 13-V4-d9: the closer segment belongs to the
// next run; anything beyond it is outside this run's scope) keep
// their severity even when the matching `accept-run` line
// accepts items 1-3. On A1, append an `entry_rec(9, GARBAGE)` to
// the live file so the walker reports SeqGap(8..=8) and
// ChainBroken at seq=9 on the closer segment, OUTSIDE the
// accepted run. Items 1-3 become `Accepted`; the extra findings
// stay as errors.
// =====================================================================
/// Variant of `build_run_fx` where `cp6`'s declared root is also
/// bad, so the fold classifier reports `MmrMismatch` at cp6 (the
/// closing opening). The run's `accept-run` line must NOT
/// promote this `MmrMismatch`: ruling 13-V8-d1 (`accept-run`) /
/// ADR-0005 decision 11 say the closing opening's `MmrMismatch`
/// is never accepted. The fixture witnesses the equivalence
/// argument: an honest trail cannot carry a matchable run
/// alongside a mismatched closing opening.
struct BadCp6Fx {
    _dir: Temp,
    dir: PathBuf,
    live: PathBuf,
    resume: Record,
}
fn build_bad_cp6_fx() -> BadCp6Fx {
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
    let bad5 = [0x55; 32];
    let cp5 = signed_cp_explicit(5, r4.hash(), fold.size(), bad5, fold.peaks().to_vec());
    put_segment(&d.0, 1, &[&r4, &cp5], &[]);
    let fold6 = pushed(&fold, &cp5);
    let bad6 = [0xAA; 32];
    let cp6 = signed_cp_explicit(6, cp5.hash(), fold6.size(), bad6, fold6.peaks().to_vec());
    let resume = resume_decl(&cp6, 5, cp5.hash(), 5);
    write_records(&d.0, &[&cp6, &resume]);
    let dir = d.0.clone();
    let live = dir.join("audit.jsonl");
    BadCp6Fx {
        dir,
        _dir: d,
        live,
        resume,
    }
}

#[test]
fn closing_opening_mmr_mismatch_fixture_closes_no_run() {
    // cp6 is the closing opening; its own declared root is bad,
    // so the fold classifier reports `CheckpointFoldOutcome::
    // Differs` at cp6. By ruling 13-V4-d8 point 3 / ADR-0005
    // decision 5 amendment 6 (iii), a `Differs` at a checkpoint
    // is a violation that empties the run set. The accept-run
    // line therefore cannot match (run index is empty) and
    // emits `AcceptMismatch`; nothing is promoted. This is the
    // writer-side witness for the ADR rule that the closing
    // opening's `MmrMismatch` is never accepted: the writer
    // cannot produce a layout where cp6's `MmrMismatch` stands
    // alongside a matchable run, so the review path never sees
    // that pairing on an honest trail.
    let fx = build_bad_cp6_fx();
    let v = verifier()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let cp6_mmr_mismatch = report.findings().iter().find(|f| {
        f.kind() == K::MmrMismatch && f.seq() == Some(6) && f.file() == Some(fx.live.as_path())
    });
    let mismatch = report
        .findings()
        .iter()
        .find(|f| f.kind() == K::AcceptMismatch && f.seq() == Some(7));
    let accepted_count = report
        .findings()
        .iter()
        .filter(|f| f.kind() == K::Accepted)
        .count();
    assert_eq!(
        (
            cp6_mmr_mismatch.is_some(),
            mismatch.is_some(),
            accepted_count
        ),
        (true, true, 0),
        "bad cp6 closes no run: MmrMismatch stays, line is AcceptMismatch, \
         nothing is promoted",
    );
}

/// Extend `build_run_fx` with a shipped copy that carries a
/// chain-breaking record at `seq = resume + 2`. Shipped records
/// live in `groups` (so the main seq-loop sees them) but are not
/// in the native segment set (so the run classifier ignores
/// them). `ChainBroken` and `SeqGap` at seq=9 are therefore
/// outside the run's loss-point ranges AND outside its segment
/// paths -- the test for the matching line pins that items 1-3
/// are accepted and these two findings keep severity.
fn write_shipped_trailing_r9(dir: &Path, after: &Record) -> PathBuf {
    let r9 = headless(after, 9);
    let path = dir.join("audit-shipped-trailing.jsonl");
    fs::write(&path, line_bytes(&r9)).unwrap();
    path
}

#[test]
fn list_is_exact_seq_gap_outside_run_stays_error() {
    // Run 0's line matches and promotes items 1-3; the shipped-
    // copy's `SeqGap(8..=8)` and `ChainBroken` at seq=9 stay as
    // errors because the shipped file is not on the run's
    // segment paths and seq=9 is not a run loss point.
    let fx = build_run_fx();
    let shipped = write_shipped_trailing_r9(&fx.dir, &fx.resume);
    let v = verifier()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone(), shipped.clone()], v);
    let accepted_count = report
        .findings()
        .iter()
        .filter(|f| f.kind() == K::Accepted)
        .count();
    let seq_gap_outside = report
        .findings()
        .iter()
        .any(|f| f.kind() == K::SeqGap && f.seq() == Some(9));
    let chain_broken_outside = report
        .findings()
        .iter()
        .any(|f| f.kind() == K::ChainBroken && f.seq() == Some(9));
    assert_eq!(
        (
            accepted_count,
            seq_gap_outside,
            chain_broken_outside,
            report.is_valid()
        ),
        (5, true, true, false),
        "items 1-3 promoted; SeqGap/ChainBroken outside the run stay: {:#?}",
        report.findings(),
    );
}

#[test]
fn list_is_exact_second_layout_a3_shipped_trailing_seq_gap() {
    // Second layout: A3 with a shipped trailing r13 after
    // resume11. Items 1-3 become Accepted; `SeqGap(12..=12)` and
    // `ChainBroken` at seq=13 stay.
    let a = build_a3();
    let dir = a.dir_path.clone();
    let (resume_hash, resume_seq) = resume_hash_of_a3(&a);
    // Build the A3 resume record locally so we can take its hash
    // for `headless`.
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
    let shipped_path = dir.join("audit-shipped-trailing.jsonl");
    let r13 = headless(&resume, 13);
    fs::write(&shipped_path, line_bytes(&r13)).unwrap();
    let v = verifier()
        .accept_run(resume_seq, resume_hash, A3_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![dir, shipped_path], v);
    let accepted_count = report
        .findings()
        .iter()
        .filter(|f| f.kind() == K::Accepted)
        .count();
    let seq_gap_outside = report
        .findings()
        .iter()
        .any(|f| f.kind() == K::SeqGap && f.seq() == Some(13));
    let chain_broken_outside = report
        .findings()
        .iter()
        .any(|f| f.kind() == K::ChainBroken && f.seq() == Some(13));
    assert_eq!(
        (
            accepted_count,
            seq_gap_outside,
            chain_broken_outside,
            report.is_valid()
        ),
        (7, true, true, false),
        "A3 shipped trailing: items 1-3 promoted; outside findings stay",
    );
}

// =====================================================================
// ADR-0005 decision 11 `accept-run` l.957 "the list is exact", on
// a run with non-empty spans (A9). A9's digest covers both spans
// (`run_digest(&ranges, &spans)`), so `A9_DIGEST` differs from
// `EMPTY_RUN_DIGEST`: a match requires the spans to feed the
// digest. Each row names the full A9 digest; findings outside
// items 1-3 (TornWrite / Unparsable on S1 and S2; UncoveredTail)
// keep their severity.
// =====================================================================
#[test]
fn a9_run_with_spans_accepts_items_1_through_3() {
    let a = crate::audit::runs_v4a_fixtures::build_a9();
    // Recompute resume seq/hash (A9 does not expose them).
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let fold = seeded(&cp0);
    let cp_opening = signed_cp(1, cp0.hash(), &fold);
    let resume = resume_decl(&cp_opening, 0, cp0.hash(), 0);
    let a9_digest = crate::audit::runs_v4a_fixtures::A9_DIGEST;
    let a9_digest_bytes: [u8; 32] = {
        // Strip the `blake3:` prefix.
        let hex = &a9_digest[7..];
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    };
    let v = verifier()
        .accept_run(2, resume.hash(), a9_digest_bytes, "alice", "ok")
        .unwrap();
    let report = report_of(vec![a.dir_path.clone()], v);
    // Count: 3 items 1-3 Accepted (per-seg@S1, per-seg@S2, run@S1),
    // Resumed + UncoveredTail + TornWrite x2 + Unparsable x2 stay.
    let accepted_count = report
        .findings()
        .iter()
        .filter(|f| f.kind() == K::Accepted)
        .count();
    let unresolved_errors: Vec<K> = report
        .findings()
        .iter()
        .filter(|f| f.severity() == super::Severity::Error)
        .map(super::Finding::kind)
        .collect();
    // Unresolved errors should be only the Unparsable (not any
    // items 1-3 kind).
    assert_eq!(
        (accepted_count, !unresolved_errors.is_empty()),
        (3, true),
        "A9 spans: items 1-3 promoted, non-items-1-3 errors stay: {:#?}",
        report.findings(),
    );
}

#[test]
fn a9_run_with_spans_wrong_digest_gives_accept_mismatch() {
    // Same A9 layout; the line names the EMPTY digest (what an
    // implementation that digests ranges only would compute).
    // The run's actual digest includes spans, so the match
    // reports `run digest differs (run A9_DIGEST)`.
    let a = crate::audit::runs_v4a_fixtures::build_a9();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let fold = seeded(&cp0);
    let cp_opening = signed_cp(1, cp0.hash(), &fold);
    let resume = resume_decl(&cp_opening, 0, cp0.hash(), 0);
    let v = verifier()
        .accept_run(2, resume.hash(), EMPTY_RUN_DIGEST, "alice", "ok")
        .unwrap();
    let report = report_of(vec![a.dir_path.clone()], v);
    let tail = format!(
        "accept-run seq 2 hash {}: run digest differs (run {})",
        digest_string(&resume.hash()),
        crate::audit::runs_v4a_fixtures::A9_DIGEST,
    );
    let mm = report
        .findings()
        .iter()
        .find(|f| f.kind() == K::AcceptMismatch);
    let accepted_count = report
        .findings()
        .iter()
        .filter(|f| f.kind() == K::Accepted)
        .count();
    assert_eq!(
        (
            mm.map(super::Finding::detail),
            mm.and_then(super::Finding::seq),
            accepted_count,
        ),
        (Some(tail.as_str()), Some(2), 0),
        "A9 wrong digest -> AcceptMismatch, nothing promoted",
    );
}

#[test]
fn accept_run_inside_gap_confirmed_by_accept_resumed_is_lost_record() {
    // Same A3 gap, confirmed through `accept Resumed` on the
    // resume at seq=11 instead of a receipt (ADR-0005 decision 11
    // "accept Resumed confirms the gap"). The gap `9..=9` is then
    // confirmed and the accept_run at seq=9 is `LostRecord`.
    let a = build_a3();
    let dir = a.dir_path.clone();
    let (resume_hash, _) = resume_hash_of_a3(&a);
    let v = verifier()
        .accept(K::Resumed, 11, resume_hash, "alice", "ok")
        .unwrap()
        .accept_run(9, WRONG_HASH, EMPTY_RUN_DIGEST, "bob", "lost")
        .unwrap();
    let report = report_of(vec![dir], v);
    let lost = report.findings().iter().find(|f| {
        f.kind() == K::LostRecord
            && f.seq() == Some(9)
            && f.detail().starts_with("accept-run seq 9 hash")
    });
    assert!(
        lost.is_some(),
        "accept-run inside an accept-Resumed-confirmed gap -> LostRecord: got {:#?}",
        report.findings(),
    );
}
