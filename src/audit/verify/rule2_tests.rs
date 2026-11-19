//! #13 V4b verifier-level acceptance rows for ADR-0005 decision 5
//! rule 2 and amendment 6 (iii) refined by decision 11 `accept-run`
//! item 3 (ruling 13-V4-d10 points 2-4). Each row drives
//! `Verifier::verify_dir` / `Verifier::verify_files` and asserts the
//! **literal, sorted, full** finding list on the verified trail; the
//! filter rows drive the `#[cfg(test)]` seam in `verify::engine` and
//! assert the literal retained candidate `opening_seq` list; the
//! classifier rows assert the literal per-checkpoint outcome list
//! from a Collect pass over the same snapshot, and the Stop row
//! asserts the exact `Reaction::Stop` outcome.
//!
//! Row standard (vigil `_traps.md`): the main literal assertion of
//! each acceptance row fails on base `0xafe9942` through this crate's
//! single-pass apply + fixture (or by failing to compile, when the
//! row touches the new [`CheckpointFoldOutcome::Base`] variant or the
//! new `filter_candidates_for_test` seam -- neither exists on base).
//! The pinned A1 run digest (`79d8cb1c…`) does not change.
//!
//! **Known limits (ruling 13-V4-d10 points 5-6):** openings present
//! only in a shipped copy and segments the walker never finished
//! because of an earlier violation are covered here via the
//! fail-closed filter; a second mismatch in the same segment is not
//! reported.

use super::{
    Finding, Verifier,
    engine::filter_candidates_for_test,
    input::{self, Collection},
};
use crate::audit::{
    FindingKind as K, Mmr, Record, TrustPolicy, digest_string,
    runs_v4a_fixtures::{
        A1_DIGEST, TRAIL, Temp, build_a1, entry_rec, headless, line_bytes, pushed, put_segment,
        resume_decl, seeded, segment_path, signed_cp, signed_cp_explicit, write_records,
    },
    storage::{Head, TrailReader},
};
use std::{
    fs,
    path::{Path, PathBuf},
};

fn policy_trail() -> TrustPolicy {
    TrustPolicy::builder().trail(TRAIL).build().unwrap()
}

fn verify_dir(dir: &Path) -> Vec<Finding> {
    Verifier::new(policy_trail())
        .verify_dir(dir)
        .unwrap()
        .findings()
        .to_vec()
}

fn verify_files(files: impl IntoIterator<Item = PathBuf>) -> Vec<Finding> {
    Verifier::new(policy_trail())
        .verify_files(files)
        .unwrap()
        .findings()
        .to_vec()
}

/// Shape matches `runs_tests::rows`: the full ordered tuple per
/// finding so a mismatch reports the whole row, not a component.
type Row = (
    K,
    Option<PathBuf>,
    Option<u64>,
    Option<u64>,
    String,
    Option<String>,
);

fn rows(findings: &[Finding]) -> Vec<Row> {
    findings
        .iter()
        .map(|f| {
            (
                f.kind(),
                f.file().map(Path::to_path_buf),
                f.line(),
                f.seq(),
                f.detail().to_owned(),
                f.run_digest().as_ref().map(digest_string),
            )
        })
        .collect()
}

/// Build the `MmrMismatch` detail per ruling 13-V4-d10 point 2's
/// grammar. Mirrors `fold::emit_mmr_mismatch` so a grammar drift
/// trips the row.
fn mmr_mismatch_detail(
    expected_size: u64,
    expected_root: &[u8; 32],
    declared_size: u64,
    declared_root: &[u8; 32],
) -> String {
    format!(
        "expected size {} root {}, found size {} root {}",
        expected_size,
        digest_string(expected_root),
        declared_size,
        digest_string(declared_root),
    )
}

/// Parse the module's exposed `A1_DIGEST` constant back to bytes so a
/// row can assert the run finding's `run_digest()` directly.
fn parse_digest(hex: &str) -> [u8; 32] {
    let hex = hex.strip_prefix("blake3:").expect("blake3 prefix");
    assert_eq!(hex.len(), 64, "32-byte digest in hex");
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex");
    }
    out
}

/// Builds A1's run detail string (loss points, then spans, then
/// digest). The honest A1 has one loss point (seq=4 first=3 count=1)
/// and no spans (S1's `[r4, cp5]` are both records, so the segment
/// contributes no gap span).
fn a1_run_detail() -> String {
    format!("loss seq 4 first 3 count 1; digest {A1_DIGEST}")
}

/// Formats the honest A1 `Resumed` detail; the writer-honest variant
/// (Blocker 3) shares this exact text because the resume names the
/// same head (`seq 5`) and the cp5 hash is derived from the record's
/// signed bytes -- see each fixture builder for the dependency.
fn resume_detail_at_seq(head_seq: u64, head_hash: &[u8; 32], gap: &str) -> String {
    format!(
        "operator=operator reason=incident head={head_seq}:{hash} \
         gap={gap} lost_records=0 structural=valid",
        hash = digest_string(head_hash)
    )
}

fn uncovered_tail_row(first: u64, last: u64) -> Row {
    (
        K::UncoveredTail,
        None,
        None,
        None,
        format!(
            "records seq {first}..={last}, no trusted coverage yet (signatures are checked in #13 V5)"
        ),
        None,
    )
}

// =======================================================================
// B1 -- A1 whose CLOSING opening cp6 has a wrong root (then a wrong
// size). The reader rejects it with `CorruptTrail` (ruling 13-V4-d8
// probe: "A1 with cp6 wrong root/size: `TrailReader::open` rejects
// with `CorruptTrail`"); under V4b the verifier reports `MmrMismatch`
// at cp6 AND no run finding (ruling 13-V4-d10 point 2; ruling
// 13-V4-d8 point 3: any violation empties every run). Each row
// asserts the full sorted literal finding list.
// =======================================================================

fn build_a1_wrong_cp6_root() -> (Temp, PathBuf) {
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
    let cp5 = signed_cp(5, r4.hash(), &fold);
    put_segment(&d.0, 1, &[&r4, &cp5], &[]);
    let fold6 = pushed(&fold, &cp5);
    let bad_root = [0xAA; 32];
    let cp6 = signed_cp_explicit(
        6,
        cp5.hash(),
        fold6.size(),
        bad_root,
        fold6.peaks().to_vec(),
    );
    let resume = resume_decl(&cp6, 5, cp5.hash(), 5);
    write_records(&d.0, &[&cp6, &resume]);
    let dir_path = d.0.clone();
    (d, dir_path)
}

#[test]
fn b1_a1_closing_cp6_wrong_root_full_literal_list() {
    let (_temp, dir) = build_a1_wrong_cp6_root();
    let s1 = dir.join("audit-20260101T000000.000000000Z_000001.jsonl");
    let live = dir.join("audit.jsonl");
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
    let bad_root = [0xAA; 32];
    let mmr_detail = mmr_mismatch_detail(fold6.size(), &fold6.root(), fold6.size(), &bad_root);
    let per_seg_detail = "expected first complete record to be a checkpoint".to_owned();
    let resume_detail = resume_detail_at_seq(5, &cp5.hash(), "none");
    let got = rows(&verify_dir(&dir));
    // Any violation empties every run (13-V4-d8 point 3), so NO
    // `SegmentStructure` with a run digest; the per-segment "expected
    // first complete record to be a checkpoint" finding on S1 stays.
    // On base `0xafe9942` no `MmrMismatch` is emitted (the fold compare
    // is discarded there); this row is red on base through the
    // `MmrMismatch` at cp6 line.
    let expected: Vec<Row> = vec![
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            per_seg_detail,
            None,
        ),
        (
            K::SeqGap,
            Some(s1),
            Some(1),
            Some(4),
            "missing seq 3..=3".to_owned(),
            None,
        ),
        (
            K::MmrMismatch,
            Some(live.clone()),
            Some(1),
            Some(6),
            mmr_detail,
            None,
        ),
        (
            K::Resumed,
            Some(live),
            Some(2),
            Some(7),
            resume_detail,
            None,
        ),
        uncovered_tail_row(0, 7),
    ];
    assert_eq!(got, expected, "B1-root full literal list");
}

fn build_a1_wrong_cp6_size() -> (Temp, PathBuf) {
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
    let cp5 = signed_cp(5, r4.hash(), &fold);
    put_segment(&d.0, 1, &[&r4, &cp5], &[]);
    let fold6 = pushed(&fold, &cp5);
    // `CheckpointFields::new` requires `peaks.len() == size.count_ones()`.
    // Pick size=1 (one peak) and declare root=fold6.root(), peaks=[fold6.root()]:
    // the compare fires on `size` and records a mismatch.
    let bad_size: u64 = 1;
    let fake_peaks: Vec<[u8; 32]> = vec![fold6.root()];
    let cp6 = signed_cp_explicit(6, cp5.hash(), bad_size, fold6.root(), fake_peaks);
    let resume = resume_decl(&cp6, 5, cp5.hash(), 5);
    write_records(&d.0, &[&cp6, &resume]);
    let dir_path = d.0.clone();
    (d, dir_path)
}

#[test]
fn b1_a1_closing_cp6_wrong_size_full_literal_list() {
    let (_temp, dir) = build_a1_wrong_cp6_size();
    let s1 = dir.join("audit-20260101T000000.000000000Z_000001.jsonl");
    let live = dir.join("audit.jsonl");
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
    let mmr_detail = mmr_mismatch_detail(fold6.size(), &fold6.root(), 1, &fold6.root());
    let per_seg_detail = "expected first complete record to be a checkpoint".to_owned();
    let resume_detail = resume_detail_at_seq(5, &cp5.hash(), "none");
    let got = rows(&verify_dir(&dir));
    let expected: Vec<Row> = vec![
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            per_seg_detail,
            None,
        ),
        (
            K::SeqGap,
            Some(s1),
            Some(1),
            Some(4),
            "missing seq 3..=3".to_owned(),
            None,
        ),
        (
            K::MmrMismatch,
            Some(live.clone()),
            Some(1),
            Some(6),
            mmr_detail,
            None,
        ),
        (
            K::Resumed,
            Some(live),
            Some(2),
            Some(7),
            resume_detail,
            None,
        ),
        uncovered_tail_row(0, 7),
    ];
    assert_eq!(got, expected, "B1-size full literal list");
}

// =======================================================================
// B2 -- A plain genesis-linked resume (ADR-0005 amendment 9) whose
// opening cp1's root is wrong. The walker folds the computable
// genesis leaf (amendment 9 branch of `apply_checked`), compares
// the opening's declared size/root/peaks, and emits one
// `MmrMismatch` at cp1 (ruling 13-V4-d10 point 2).
// =======================================================================

fn build_plain_resume_wrong_root() -> (Temp, PathBuf) {
    let d = Temp::new();
    let genesis_hash = Record::genesis(&TRAIL);
    let mut good_fold = Mmr::new();
    good_fold.push(genesis_hash).unwrap();
    let bad_root = [0x11; 32];
    let cp1 = signed_cp_explicit(
        1,
        genesis_hash,
        good_fold.size(),
        bad_root,
        good_fold.peaks().to_vec(),
    );
    let resume = resume_decl(&cp1, 0, genesis_hash, 0);
    write_records(&d.0, &[&cp1, &resume]);
    let dir_path = d.0.clone();
    (d, dir_path)
}

#[test]
fn b2_plain_resume_wrong_opening_root_full_literal_list() {
    let (_temp, dir) = build_plain_resume_wrong_root();
    let live = dir.join("audit.jsonl");
    let genesis_hash = Record::genesis(&TRAIL);
    let mut good_fold = Mmr::new();
    good_fold.push(genesis_hash).unwrap();
    let bad_root = [0x11; 32];
    let mmr_detail = mmr_mismatch_detail(
        good_fold.size(),
        &good_fold.root(),
        good_fold.size(),
        &bad_root,
    );
    // Rebuild cp1 so the resume detail references its exact hash.
    let cp1 = signed_cp_explicit(
        1,
        genesis_hash,
        good_fold.size(),
        bad_root,
        good_fold.peaks().to_vec(),
    );
    let _ = cp1; // referenced for clarity; the resume names head=0:genesis.
    let got = rows(&verify_dir(&dir));
    // `gap=0..=0` is the genesis-resume text (ADR l.407; d5 point 3).
    let resume_detail = resume_detail_at_seq(0, &genesis_hash, "0..=0");
    // Sort key `(seq, file, line, kind)`: both `MmrMismatch` and
    // `SeqGap` carry (live, 1, 1); `MmrMismatch` ("M") sorts before
    // `SeqGap` ("Se"). Base `0xafe9942` has no `MmrMismatch`.
    let expected: Vec<Row> = vec![
        (
            K::MmrMismatch,
            Some(live.clone()),
            Some(1),
            Some(1),
            mmr_detail,
            None,
        ),
        (
            K::SeqGap,
            Some(live.clone()),
            Some(1),
            Some(1),
            "missing seq 0..=0".to_owned(),
            None,
        ),
        (
            K::Resumed,
            Some(live),
            Some(2),
            Some(2),
            resume_detail,
            None,
        ),
        uncovered_tail_row(1, 2),
    ];
    assert_eq!(got, expected, "B2 full literal list");
}

// =======================================================================
// B3 -- A1 whose in-run cp5 (after the run's first loss point) has a
// wrong root or a wrong size. The walker does NOT compare at cp5
// (`compare_mmr = false`, amendment 6 (iii)), so there is no
// `CheckpointMmrDiffers` violation and the run finding stays
// (ruling 13-V4-d10 point 3; decision 11 `accept-run` item 3). The
// verifier emits one `MmrMismatch` as a `DiffersAfterLoss` entry.
// =======================================================================

fn build_a1_wrong_cp5_root() -> (Temp, PathBuf) {
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
    let dir_path = d.0.clone();
    (d, dir_path)
}

#[test]
fn b3_a1_in_run_cp5_wrong_root_full_literal_list() {
    let (_temp, dir) = build_a1_wrong_cp5_root();
    let s1 = dir.join("audit-20260101T000000.000000000Z_000001.jsonl");
    let live = dir.join("audit.jsonl");
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    let r4 = headless(&e2, 4);
    let fold = pushed(&mmr2, &r4);
    let bad_root = [0x55; 32];
    let mmr_detail = mmr_mismatch_detail(fold.size(), &fold.root(), fold.size(), &bad_root);
    let cp5 = signed_cp_explicit(5, r4.hash(), fold.size(), bad_root, fold.peaks().to_vec());
    let a1_digest = parse_digest(A1_DIGEST);
    let run_detail = a1_run_detail();
    let per_seg_detail = "expected first complete record to be a checkpoint".to_owned();
    let resume_detail = resume_detail_at_seq(5, &cp5.hash(), "none");
    let got = rows(&verify_dir(&dir));
    // Sort key: seq=4 (s1) findings (per-seg, run, SeqGap) sort by
    // kind-debug (`Seg...` < `Seq...`), then seq=5 MmrMismatch at s1
    // line=2, then Resumed at live, then UncoveredTail. V4b adds the
    // MmrMismatch which base `0xafe9942` does not emit.
    let expected: Vec<Row> = vec![
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            per_seg_detail,
            None,
        ),
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            run_detail,
            Some(digest_string(&a1_digest)),
        ),
        (
            K::SeqGap,
            Some(s1.clone()),
            Some(1),
            Some(4),
            "missing seq 3..=3".to_owned(),
            None,
        ),
        (K::MmrMismatch, Some(s1), Some(2), Some(5), mmr_detail, None),
        (
            K::Resumed,
            Some(live),
            Some(2),
            Some(7),
            resume_detail,
            None,
        ),
        uncovered_tail_row(0, 7),
    ];
    assert_eq!(got, expected, "B3-root full literal list");
}

fn build_a1_wrong_cp5_size() -> (Temp, PathBuf) {
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
    let cp5 = signed_cp_explicit(5, r4.hash(), 1, fold.root(), vec![fold.root()]);
    put_segment(&d.0, 1, &[&r4, &cp5], &[]);
    let fold6 = pushed(&fold, &cp5);
    let cp6 = signed_cp(6, cp5.hash(), &fold6);
    let resume = resume_decl(&cp6, 5, cp5.hash(), 5);
    write_records(&d.0, &[&cp6, &resume]);
    let dir_path = d.0.clone();
    (d, dir_path)
}

#[test]
fn b3_a1_in_run_cp5_wrong_size_full_literal_list() {
    let (_temp, dir) = build_a1_wrong_cp5_size();
    let s1 = dir.join("audit-20260101T000000.000000000Z_000001.jsonl");
    let live = dir.join("audit.jsonl");
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    let r4 = headless(&e2, 4);
    let fold = pushed(&mmr2, &r4);
    let cp5 = signed_cp_explicit(5, r4.hash(), 1, fold.root(), vec![fold.root()]);
    let mmr_detail = mmr_mismatch_detail(fold.size(), &fold.root(), 1, &fold.root());
    let a1_digest = parse_digest(A1_DIGEST);
    let run_detail = a1_run_detail();
    let per_seg_detail = "expected first complete record to be a checkpoint".to_owned();
    let resume_detail = resume_detail_at_seq(5, &cp5.hash(), "none");
    let got = rows(&verify_dir(&dir));
    let expected: Vec<Row> = vec![
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            per_seg_detail,
            None,
        ),
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            run_detail,
            Some(digest_string(&a1_digest)),
        ),
        (
            K::SeqGap,
            Some(s1.clone()),
            Some(1),
            Some(4),
            "missing seq 3..=3".to_owned(),
            None,
        ),
        (K::MmrMismatch, Some(s1), Some(2), Some(5), mmr_detail, None),
        (
            K::Resumed,
            Some(live),
            Some(2),
            Some(7),
            resume_detail,
            None,
        ),
        uncovered_tail_row(0, 7),
    ];
    assert_eq!(got, expected, "B3-size full literal list");
}

/// Blocker 3 (writer-honest A1): `cp5` is signed over the writer's
/// REAL fold, which counts the lost leaf at seq 3 (ghost record), so
/// its declared size is 5 while the reader's fold at cp5 time has
/// size 4. The reader opens successfully (amendment 6 (iii):
/// post-loss checkpoints are not compared by the reader), and the
/// verifier emits one `MmrMismatch` at cp5 while the run finding
/// stays (ruling 13-V4-d10 point 3).
fn build_a1_writer_honest() -> (Temp, PathBuf) {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    put_segment(&d.0, 0, &[&cp0, &e1, &e2], &[]);
    let r4 = headless(&e2, 4);
    // Reader's fold ignoring lost seq 3: size 4.
    let reader_fold_r4 = pushed(&mmr2, &r4);
    // Writer's REAL fold counting the lost leaf at seq 3: size 5.
    let ghost = entry_rec(3, e2.hash());
    let writer_mmr3 = pushed(&mmr2, &ghost);
    let writer_mmr4 = pushed(&writer_mmr3, &r4);
    let cp5_writer = signed_cp(5, r4.hash(), &writer_mmr4);
    put_segment(&d.0, 1, &[&r4, &cp5_writer], &[]);
    // Closer cp6 folds on the reader's state after cp5: size 4 then
    // push cp5 -> size 5.
    let fold_after_cp5 = pushed(&reader_fold_r4, &cp5_writer);
    let cp6 = signed_cp(6, cp5_writer.hash(), &fold_after_cp5);
    let resume = resume_decl(&cp6, 5, cp5_writer.hash(), 5);
    write_records(&d.0, &[&cp6, &resume]);
    let dir_path = d.0.clone();
    (d, dir_path)
}

/// The writer-honest A1 MMR mismatch detail. The reader's fold at
/// cp5 has size 4 and the exact root constant captured at head; the
/// writer's fold (counting the lost leaf at seq 3) has size 5 and
/// the exact root constant below. Literal digests per blocker 4 so
/// a drift in the `apply_checked` fold or in `digest_string` trips
/// this row directly, not through the helper.
const B3_WRITER_HONEST_EXPECTED_ROOT: &str =
    "blake3:8c89e5675d09a83557775acf82c200357f94447d60bf5d4a455b525cf04ff242";
const B3_WRITER_HONEST_FOUND_ROOT: &str =
    "blake3:f44b2effb111c0bac54116a71afd9894eb4e00e2378121376e3a9b2ec3b8ce0e";
const B3_WRITER_HONEST_DETAIL: &str = "expected size 4 root \
blake3:8c89e5675d09a83557775acf82c200357f94447d60bf5d4a455b525cf04ff242, \
found size 5 root \
blake3:f44b2effb111c0bac54116a71afd9894eb4e00e2378121376e3a9b2ec3b8ce0e";

#[test]
fn b3_a1_writer_honest_reader_opens_and_verifier_mmr_mismatch() {
    let (_temp, dir) = build_a1_writer_honest();
    // (1) Reader opens successfully: amendment 6 (iii) skips the
    // post-loss cp5 compare in the reader, so a writer-honest cp5
    // with size 5 is accepted.
    let _reader = TrailReader::open(&dir, TRAIL, None)
        .expect("writer-honest A1: TrailReader::open must succeed (amendment 6 (iii))");
    // (2) Verifier emits `MmrMismatch` at cp5 AND the run finding
    // stays. Full literal finding list with literal digest
    // constants in the detail (blocker 4: no helper).
    let s1 = dir.join("audit-20260101T000000.000000000Z_000001.jsonl");
    let live = dir.join("audit.jsonl");
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    let r4 = headless(&e2, 4);
    let ghost = entry_rec(3, e2.hash());
    let writer_mmr3 = pushed(&mmr2, &ghost);
    let writer_mmr4 = pushed(&writer_mmr3, &r4);
    let cp5_writer = signed_cp(5, r4.hash(), &writer_mmr4);
    let a1_digest = parse_digest(A1_DIGEST);
    let run_detail = a1_run_detail();
    let per_seg_detail = "expected first complete record to be a checkpoint".to_owned();
    let resume_detail = resume_detail_at_seq(5, &cp5_writer.hash(), "none");
    let got = rows(&verify_dir(&dir));
    let expected: Vec<Row> = vec![
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            per_seg_detail,
            None,
        ),
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            run_detail,
            Some(digest_string(&a1_digest)),
        ),
        (
            K::SeqGap,
            Some(s1.clone()),
            Some(1),
            Some(4),
            "missing seq 3..=3".to_owned(),
            None,
        ),
        (
            K::MmrMismatch,
            Some(s1),
            Some(2),
            Some(5),
            B3_WRITER_HONEST_DETAIL.to_owned(),
            None,
        ),
        (
            K::Resumed,
            Some(live),
            Some(2),
            Some(7),
            resume_detail,
            None,
        ),
        uncovered_tail_row(0, 7),
    ];
    assert_eq!(got, expected, "writer-honest A1 full literal list");
    // Literal digest constants are written as full 64-hex blake3
    // strings; a drift in the fold's expected or found root flips
    // the assertion above with a precise diff. The explicit sub-
    // constants are kept so the row's intent is readable.
    assert_eq!(
        B3_WRITER_HONEST_DETAIL,
        format!(
            "expected size 4 root {}, found size 5 root {}",
            B3_WRITER_HONEST_EXPECTED_ROOT, B3_WRITER_HONEST_FOUND_ROOT
        )
    );
}

// =======================================================================
// B4 -- A run whose in-run checkpoint sits BEFORE its first loss
// point (here: no loss point at all, a closer opened by an unsealed
// boundary with a wrong root). `compare_mmr = true` fires at that
// opening, the walker records `CheckpointMmrDiffers`, every run is
// emptied (13-V4-d8 point 3, 13-V4-d10 point 2).
// =======================================================================

fn build_pre_loss_wrong_root() -> (Temp, PathBuf) {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    put_segment(&d.0, 0, &[&cp0, &e1], &[]);
    let bad_root = [0x77; 32];
    let cp2 = signed_cp_explicit(2, e1.hash(), mmr1.size(), bad_root, mmr1.peaks().to_vec());
    let resume = resume_decl(&cp2, 1, e1.hash(), 1);
    write_records(&d.0, &[&cp2, &resume]);
    let dir_path = d.0.clone();
    (d, dir_path)
}

#[test]
fn b4_pre_loss_in_run_wrong_root_full_literal_list() {
    let (_temp, dir) = build_pre_loss_wrong_root();
    let live = dir.join("audit.jsonl");
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let bad_root = [0x77; 32];
    let mmr_detail = mmr_mismatch_detail(mmr1.size(), &mmr1.root(), mmr1.size(), &bad_root);
    let resume_detail = resume_detail_at_seq(1, &e1.hash(), "none");
    let got = rows(&verify_dir(&dir));
    // The violation at cp2 empties every run (13-V4-d8 point 3), so
    // no `SegmentStructure` run finding.
    let expected: Vec<Row> = vec![
        (
            K::MmrMismatch,
            Some(live.clone()),
            Some(1),
            Some(2),
            mmr_detail,
            None,
        ),
        (
            K::Resumed,
            Some(live),
            Some(2),
            Some(3),
            resume_detail,
            None,
        ),
        uncovered_tail_row(0, 3),
    ];
    assert_eq!(got, expected, "B4 full literal list");
}

// =======================================================================
// B5 -- Genesis-linked resume (ADR-0005 amendment 9 part 1) whose
// cp1's declared root does NOT equal the amendment-9 1-leaf fold.
// The genesis-fold branch in `apply_checked` is a REAL compare
// (not a self-base), so a wrong root yields `MmrMismatch`.
//
// **Known limit:** `Record::checkpoint`'s `validation::checkpoint_count`
// rejects `size == 0` at `seq > 0` and `size > seq`, so the ruling's
// `size 0 (peaks=[])` case is unreachable through `CheckpointFields::new`.
// We test the amendment-9 compare on the root axis, which is the
// difference the format lets us craft at seq=1.
// =======================================================================

fn build_genesis_resume_wrong_root() -> (Temp, PathBuf) {
    let d = Temp::new();
    let genesis_hash = Record::genesis(&TRAIL);
    let mut fold = Mmr::new();
    fold.push(genesis_hash).unwrap();
    let bad_root = [0xBE; 32];
    let cp1 = signed_cp_explicit(
        1,
        genesis_hash,
        fold.size(),
        bad_root,
        fold.peaks().to_vec(),
    );
    let resume = resume_decl(&cp1, 0, genesis_hash, 0);
    write_records(&d.0, &[&cp1, &resume]);
    let dir_path = d.0.clone();
    (d, dir_path)
}

#[test]
fn b5_genesis_linked_resume_wrong_root_full_literal_list() {
    let (_temp, dir) = build_genesis_resume_wrong_root();
    let live = dir.join("audit.jsonl");
    let genesis_hash = Record::genesis(&TRAIL);
    let mut fold = Mmr::new();
    fold.push(genesis_hash).unwrap();
    let bad_root = [0xBE; 32];
    let mmr_detail = mmr_mismatch_detail(fold.size(), &fold.root(), fold.size(), &bad_root);
    let resume_detail = resume_detail_at_seq(0, &genesis_hash, "0..=0");
    let got = rows(&verify_dir(&dir));
    // Both `MmrMismatch` and `SeqGap` at (live, line=1, seq=1):
    // `MmrMismatch` ("M") sorts before `SeqGap` ("Se"). A wrong
    // opening empties every run (13-V4-d8 point 3), so no
    // `SegmentStructure` run finding.
    let expected: Vec<Row> = vec![
        (
            K::MmrMismatch,
            Some(live.clone()),
            Some(1),
            Some(1),
            mmr_detail,
            None,
        ),
        (
            K::SeqGap,
            Some(live.clone()),
            Some(1),
            Some(1),
            "missing seq 0..=0".to_owned(),
            None,
        ),
        (
            K::Resumed,
            Some(live),
            Some(2),
            Some(2),
            resume_detail,
            None,
        ),
        uncovered_tail_row(1, 2),
    ];
    assert_eq!(got, expected, "B5-root full literal list");
}

// =======================================================================
// Self-based opening rows. A self-base is the ADR amendment 6
// "Base" branch of `apply_checked` where the fold is loaded from
// the opening's own `(size, peaks)` through `Mmr::from_peaks`.
// Two shapes:
//   (a) self-consistent self-base -- `cp.root == mmr.root()` by
//       construction: records
//       [`CheckpointFoldOutcome::Base`] and NEVER emits
//       `MmrMismatch`; the fail-closed filter drops any candidate
//       whose opening is only self-based.
//   (b) non-self-consistent self-base -- `cp.root` disagrees with
//       the fold loaded from `cp.peaks`: the compare FIRED and
//       failed, so the classifier records
//       [`CheckpointFoldOutcome::Differs`] and the verifier emits
//       one `MmrMismatch` (blocker 1: one enum value for one
//       compare outcome, two separate flags cannot contradict).
// =======================================================================

/// Builds the reviewer's repro: a shipped copy holding `[cp0, e1]`,
/// a native live file holding `[cp2 (self-based opening), resume3]`.
/// cp2 is signed over the honest `[cp0, e1]` fold so the record
/// parses, but the walker opens cp2 with no prior native state and
/// loads its declared fields through `Mmr::from_peaks` (the
/// amendment-6 self-base branch).
fn build_self_based_opening_repro() -> (Temp, PathBuf, PathBuf) {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    let mmr0 = seeded(&cp0);
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let resume = resume_decl(&cp2, 1, e1.hash(), 1);
    write_records(&d.0, &[&cp2, &resume]);
    let live = d.0.join("audit.jsonl");
    let shipped = d.0.join("shipped.jsonl");
    let shipped_bytes: Vec<u8> = [&cp0, &e1].iter().flat_map(|r| line_bytes(r)).collect();
    fs::write(&shipped, shipped_bytes).unwrap();
    (d, live, shipped)
}

#[test]
fn self_based_opening_fails_closed_full_literal_list() {
    let (_temp, live, shipped) = build_self_based_opening_repro();
    // Rebuild cp0, e1 to compute the resume's `head=1:<e1 hash>`.
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    let got = rows(&verify_files([live.clone(), shipped.clone()]));
    let resume_detail = resume_detail_at_seq(1, &e1.hash(), "none");
    // The walker never compares cp2 (`CheckpointFoldOutcome::Base`
    // for a self-consistent self-base), no `MmrMismatch` emitted;
    // no SeqGap/ChainBroken (the shipped records fill the 0..=1
    // prefix). The fail-closed filter drops the resume candidate,
    // so no gap-confirmation leak lands either. On base the
    // `filter_candidates_for_test` seam does not exist, so this
    // row is red on base through a COMPILE failure.
    let expected: Vec<Row> = vec![
        (
            K::Resumed,
            Some(live.clone()),
            Some(2),
            Some(3),
            resume_detail,
            None,
        ),
        uncovered_tail_row(0, 3),
    ];
    assert_eq!(got, expected, "self-based repro: full literal list");
    let collection = collect_files(&[live, shipped]);
    let kept = filter_candidates_for_test(&collection, TRAIL);
    assert_eq!(
        kept,
        Vec::<u64>::new(),
        "self-based repro: fail-closed filter drops the self-based opening"
    );
}

/// Blocker 1 repro (`13-v4b-r3` points 1): a self-base whose
/// declared `(size, root, peaks)` do NOT agree with the fold loaded
/// from `cp.peaks`. The compare FIRES at the apply site
/// (`cp.root != mmr.root()` with `mmr = Mmr::from_peaks(cp.size,
/// cp.peaks)`), so the outcome is `Differs`, not `Base` -- one
/// enum value derived from what the fold did at this record.
/// The verifier emits one `MmrMismatch` at cp2 with the grammar
/// detail; the fail-closed filter drops the candidate.
///
/// On base `0xafe9942` the pre-blocker-1 bug records this case as
/// `Base` (is_base tested before differs), so no `MmrMismatch` is
/// emitted and the finding list differs from this row's literal.
fn build_self_based_opening_differs_repro() -> (Temp, PathBuf, PathBuf) {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    // cp2 declares size=2, one peak=[7;32] and root=[5;32] -- the
    // root of a single-peak fold is that one peak, so `cp.root` must
    // be [7;32] to match. Declaring root=[5;32] trips the compare.
    let bad_peak: [u8; 32] = [7; 32];
    let bad_root: [u8; 32] = [5; 32];
    let cp2 = signed_cp_explicit(2, e1.hash(), 2, bad_root, vec![bad_peak]);
    let resume = resume_decl(&cp2, 1, e1.hash(), 1);
    write_records(&d.0, &[&cp2, &resume]);
    let live = d.0.join("audit.jsonl");
    let shipped = d.0.join("shipped.jsonl");
    let shipped_bytes: Vec<u8> = [&cp0, &e1].iter().flat_map(|r| line_bytes(r)).collect();
    fs::write(&shipped, shipped_bytes).unwrap();
    (d, live, shipped)
}

#[test]
fn self_based_opening_differs_emits_mmr_mismatch_full_literal_list() {
    let (_temp, live, shipped) = build_self_based_opening_differs_repro();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    // Compute the fold the walker loaded from cp2's own peaks: a
    // single peak fold has the peak as its root.
    let bad_peak: [u8; 32] = [7; 32];
    let bad_root: [u8; 32] = [5; 32];
    let mut from_peaks = Mmr::new();
    from_peaks = Mmr::from_peaks(2, vec![bad_peak]).unwrap_or(from_peaks);
    // `from_peaks.root()` is [7;32] by construction (one peak => root = peak).
    let expected_root = from_peaks.root();
    let mmr_detail = mmr_mismatch_detail(2, &expected_root, 2, &bad_root);
    let got = rows(&verify_files([live.clone(), shipped.clone()]));
    let resume_detail = resume_detail_at_seq(1, &e1.hash(), "none");
    // Any violation empties every run (13-V4-d8 point 3), so no
    // run finding. The non-self-consistent self-base now emits
    // `MmrMismatch`; the fail-closed filter drops the candidate.
    let expected: Vec<Row> = vec![
        (
            K::MmrMismatch,
            Some(live.clone()),
            Some(1),
            Some(2),
            mmr_detail,
            None,
        ),
        (
            K::Resumed,
            Some(live.clone()),
            Some(2),
            Some(3),
            resume_detail,
            None,
        ),
        uncovered_tail_row(0, 3),
    ];
    assert_eq!(
        got, expected,
        "blocker 1: differing self-base emits MmrMismatch, full literal list"
    );
    let collection = collect_files(&[live, shipped]);
    let kept = filter_candidates_for_test(&collection, TRAIL);
    assert_eq!(
        kept,
        Vec::<u64>::new(),
        "blocker 1: fail-closed filter drops the differing self-base"
    );
}

// =======================================================================
// B6 -- Candidate filter (ruling 13-V4-d10 point 4, fail-closed).
// Each row asserts the literal retained candidate opening `seq` list
// through the `#[cfg(test)]` seam `filter_candidates_for_test`. On
// base `0xafe9942` the seam does not exist, so every B6 row is red on
// base through a compile failure.
// =======================================================================

fn collect_from_dir(dir: &Path) -> Collection {
    input::collect(std::iter::once(dir.to_path_buf())).unwrap()
}

fn collect_files(paths: &[PathBuf]) -> Collection {
    input::collect(paths.iter().cloned()).unwrap()
}

/// Honest genesis-linked resume: cp1 matches the amendment-9 fold;
/// the filter keeps the candidate. Regression row (compile-red on
/// base through the absent `filter_candidates_for_test` seam):
/// kills **V9** (filter drops every candidate -> kept becomes
/// `[]`, mismatches the literal `[1]`) AND **V7** (the genesis
/// base pushes the raw digest instead of the leaf, so the
/// amendment-9 compare differs -> cp1 becomes `Differs` and
/// matched_openings loses it, so kept becomes `[]`).
#[test]
fn b6_honest_plain_resume_kept_literal() {
    let d = Temp::new();
    let genesis_hash = Record::genesis(&TRAIL);
    let mut fold = Mmr::new();
    fold.push(genesis_hash).unwrap();
    let cp1 = signed_cp(1, genesis_hash, &fold);
    let resume = resume_decl(&cp1, 0, genesis_hash, 0);
    write_records(&d.0, &[&cp1, &resume]);
    let collection = collect_from_dir(&d.0);
    let kept = filter_candidates_for_test(&collection, TRAIL);
    assert_eq!(kept, vec![1], "B6: honest genesis-linked resume kept");
}

/// B2's wrong-root cp1: Differs, filter drops. Kills V5 (filter
/// keeps differing candidates) in combination with
/// `b6_a1_wrong_closing_cp6_dropped_literal` below.
#[test]
fn b6_wrong_opening_root_dropped_literal() {
    let (_temp, dir) = build_plain_resume_wrong_root();
    let collection = collect_from_dir(&dir);
    let kept = filter_candidates_for_test(&collection, TRAIL);
    assert_eq!(
        kept,
        Vec::<u64>::new(),
        "B6: wrong-root opening dropped by filter"
    );
}

/// A1 with wrong-root cp6: Differs, filter drops. Second V5 killer.
#[test]
fn b6_a1_wrong_closing_cp6_dropped_literal() {
    let (_temp, dir) = build_a1_wrong_cp6_root();
    let collection = collect_from_dir(&dir);
    let kept = filter_candidates_for_test(&collection, TRAIL);
    assert_eq!(
        kept,
        Vec::<u64>::new(),
        "B6: A1 wrong-cp6 closing resume dropped (opening Differs)"
    );
}

/// Shipped-only opening: cp1 in a shipped (non-native) file, cp0
/// in shipped too; native live carries only the resume. The
/// structural check passes via `native_then_shipped`, but the
/// classifier walks native only (cp1 absent), so nothing records a
/// `Matched` outcome at seq=1 and the fail-closed filter drops the
/// candidate. Kills V4 (filter keeps never-compared candidates):
/// V4 would keep the shipped-only opening despite rule 2 having
/// never validated it. On base `filter_candidates_for_test` is
/// absent, so this row is red on base through compile failure.
#[test]
fn b6_shipped_only_opening_dropped_by_filter_literal() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    // Opening at seq=1 lives only in a shipped copy.
    let cp1 = signed_cp(1, cp0.hash(), &mmr0);
    let shipped = d.0.join("shipped.jsonl");
    let bytes: Vec<u8> = [&cp0, &cp1].iter().flat_map(|r| line_bytes(r)).collect();
    fs::write(&shipped, bytes).unwrap();
    // Native live: a resume naming the shipped-only cp1 as its
    // opening. `apply_checked` on the first native record (the
    // resume, not a checkpoint) fires `MissingInitialCheckpoint` --
    // the walker never reaches a `Matched` at seq=1 because cp1 is
    // not native and the native walk opens on a non-checkpoint.
    let resume = resume_decl(&cp1, 0, cp0.hash(), 0);
    let live = d.0.join("audit.jsonl");
    fs::write(&live, line_bytes(&resume)).unwrap();
    let collection = collect_files(&[live, shipped]);
    let kept = filter_candidates_for_test(&collection, TRAIL);
    // The structural check accepts the candidate (opening at seq=1
    // IS a checkpoint via `native_then_shipped`), but it is never
    // in the matched-openings set. V4 would keep [1]; V4b drops.
    assert_eq!(
        kept,
        Vec::<u64>::new(),
        "B6: shipped-only opening dropped by the fail-closed filter"
    );
}

/// A sealed segment with an `Unparsable` line BEFORE the next
/// complete record records a violation; ruling 13-V4-d10 point 6
/// says "once a segment records a violation the classifier stops
/// checking the rest of that segment", so the walker never reaches
/// cp2 and `cp2` has no fold entry at all (not `Matched`, not
/// `Differs`). `kept` is empty because the fail-closed filter
/// drops any opening the classifier did not positively record as
/// compared and matched.
#[test]
fn b6_opening_after_earlier_violation_dropped_literal() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mut s0_bytes: Vec<u8> = line_bytes(&cp0);
    s0_bytes.extend(b"not json\n");
    s0_bytes.extend(line_bytes(&e1));
    fs::write(segment_path(&d.0, 0), s0_bytes).unwrap();
    let mmr_after_e1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr_after_e1);
    let resume = resume_decl(&cp2, 1, e1.hash(), 1);
    write_records(&d.0, &[&cp2, &resume]);
    let collection = collect_from_dir(&d.0);
    let kept = filter_candidates_for_test(&collection, TRAIL);
    // The candidate is structurally valid at base `0xafe9942` (e1
    // and cp2 are both on the trail and link); with V4b the filter
    // drops opening_seq=2 because cp2 has no fold entry (ruling
    // 13-V4-d10 point 6: it was never reached after the earlier
    // violation). `kept` is empty.
    assert_eq!(
        kept,
        Vec::<u64>::new(),
        "B6: opening after an earlier violation is dropped by the filter"
    );
}

// =======================================================================
// Blocker 2 repro: filter matches on `(opening_seq, opening_hash)`,
// not `seq` alone. A shipped resume names a forged `head=e1'` (a
// record at seq=1 with a different hash from native e1), so the
// structural check picks a FORGED cp2' from shipped (whose
// previous links to e1') -- not the honest native cp2 (whose
// previous links to e1). The classifier walks native only, so
// matched_openings holds `(2, cp2.hash)`; the candidate's
// `(2, cp2'.hash)` differs on hash, so the filter drops it.
//
// Under the pre-blocker-2 bug (filter matches on seq alone), the
// filter would keep `[2]` because native cp2 is Matched. The row
// asserts the full literal finding list AND retained `[]`, red on
// base through `filter_candidates_for_test` being absent.
// =======================================================================

/// Builds blocker 2's repro. Returns `(temp, live, shipped, cp2_native_hash,
/// cp2_shipped_hash)` so the test can assert the hash mismatch.
fn build_hash_forgery_repro() -> (
    Temp,
    PathBuf,
    PathBuf,
    Record,
    Record,
    Record,
    Record,
    Record,
) {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr_cp0_e1 = pushed(&mmr0, &e1);
    let cp2_native = signed_cp(2, e1.hash(), &mmr_cp0_e1);
    // e1' is a FORKED record at seq=1 with previous=cp0.hash: use a
    // checkpoint at seq=1 instead of an entry so the hash differs
    // from native e1 while still chaining to cp0.
    let e1_forged = signed_cp(1, cp0.hash(), &mmr0);
    // cp2' declares size=1 and one bad peak+root so the record
    // parses but the fold would differ; this never runs through the
    // walker (shipped is not folded), it only shows up in the
    // candidate's `opening_hash`.
    let bad_peak: [u8; 32] = [0x44; 32];
    let bad_root: [u8; 32] = [0x44; 32];
    let cp2_forged = signed_cp_explicit(2, e1_forged.hash(), 1, bad_root, vec![bad_peak]);
    // Shipped resume at seq=3 names `head=1:<e1'.hash>` so the
    // structural check picks the forged cp2' as the opening.
    let resume_forged = resume_decl(&cp2_forged, 1, e1_forged.hash(), 1);
    // Native: [cp0, e1, cp2_native]
    write_records(&d.0, &[&cp0, &e1, &cp2_native]);
    // Shipped: [e1', cp2', resume3']
    let live = d.0.join("audit.jsonl");
    let shipped = d.0.join("shipped.jsonl");
    let shipped_bytes: Vec<u8> = [&e1_forged, &cp2_forged, &resume_forged]
        .iter()
        .flat_map(|r| line_bytes(r))
        .collect();
    fs::write(&shipped, shipped_bytes).unwrap();
    (
        d,
        live,
        shipped,
        cp0,
        e1,
        cp2_native,
        e1_forged,
        resume_forged,
    )
}

#[test]
fn hash_forgery_candidate_opening_dropped_full_literal_list() {
    let (_temp, live, shipped, _cp0, e1, cp2_native, e1_forged, resume_forged) =
        build_hash_forgery_repro();
    // Sanity: the two candidates at seq=1 and seq=2 really have
    // different hashes (so the forgery is real, not a duplicate).
    let cp2_native_head = Head::of(&cp2_native);
    assert_ne!(
        e1.hash(),
        e1_forged.hash(),
        "e1' is a fork with a different hash"
    );
    // Verify the full literal finding list. Trail groups:
    //   seq=0: native cp0 (only copy)
    //   seq=1: native e1 + shipped e1' -> SeqConflict
    //   seq=2: native cp2 + shipped cp2' -> SeqConflict
    //   seq=3: shipped resume3' only
    // Chain holds everywhere (both e1 and e1' link to cp0;
    // cp2.previous=e1.hash and cp2'.previous=e1'.hash both appear
    // in the previous group; resume3'.previous=cp2'.hash appears).
    // The classifier walks native only (cp0 Base, e1 added,
    // cp2_native Matched); matched_openings holds
    // `(2, cp2_native.hash)`. Verifier emits no `MmrMismatch`.
    //
    // SeqConflict detail: `conflicting hashes: <h1>, <h2>` where
    // `candidates` are sorted BY HASH in the engine; we sort the
    // two candidate hashes here to match that order.
    let mut seq1_hashes = [e1.hash(), e1_forged.hash()];
    seq1_hashes.sort();
    let seq1_detail = format!(
        "conflicting hashes: {}, {}",
        digest_string(&seq1_hashes[0]),
        digest_string(&seq1_hashes[1]),
    );
    let mut seq2_hashes = [cp2_native.hash(), {
        // cp2_forged's hash (recompute).
        let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
        let e1_forged2 = signed_cp(1, cp0.hash(), &seeded(&cp0));
        let bad_peak: [u8; 32] = [0x44; 32];
        let bad_root: [u8; 32] = [0x44; 32];
        signed_cp_explicit(2, e1_forged2.hash(), 1, bad_root, vec![bad_peak]).hash()
    }];
    seq2_hashes.sort();
    let seq2_detail = format!(
        "conflicting hashes: {}, {}",
        digest_string(&seq2_hashes[0]),
        digest_string(&seq2_hashes[1]),
    );
    let got = rows(&verify_files([live.clone(), shipped.clone()]));
    let resume_detail = resume_detail_at_seq(1, &e1_forged.hash(), "none");
    // Expected sort key (seq, file, line, kind). Both SeqConflicts
    // attribute to copies[0], sorted by (path, line, hash) ->
    // native file first (lexically "audit" < "shipped"), lines 2
    // and 3 respectively. The Resumed finding on seq=3 comes from
    // the shipped file.
    let expected: Vec<Row> = vec![
        (
            K::SeqConflict,
            Some(live.clone()),
            Some(2),
            Some(1),
            seq1_detail,
            None,
        ),
        (
            K::SeqConflict,
            Some(live.clone()),
            Some(3),
            Some(2),
            seq2_detail,
            None,
        ),
        (
            K::Resumed,
            Some(shipped.clone()),
            Some(3),
            Some(3),
            resume_detail,
            None,
        ),
        uncovered_tail_row(0, 3),
    ];
    assert_eq!(got, expected, "blocker 2: full literal finding list");
    let collection = collect_files(&[live, shipped]);
    let kept = filter_candidates_for_test(&collection, TRAIL);
    assert_eq!(
        kept,
        Vec::<u64>::new(),
        "blocker 2: filter drops a candidate whose opening_hash differs \
         from the native Matched (seq, hash)"
    );
    // Sanity on what the filter reads: the candidate's opening_hash
    // is the forged cp2' hash, not cp2_native. If the filter ever
    // keyed on seq alone again, this would silently flip to `[2]`.
    let _ = cp2_native_head; // referenced for clarity
    let _ = resume_forged;
}

/// Second blocker 2 killer: a different hash-forgery layout where
/// the forgery is at seq=4 (after a longer native prefix). Native:
/// `[cp0, e1, e2, e3, cp4 honest]`. Shipped: `[e3' (forked), cp4'
/// (prev=e3', bad fields), resume5' (head=e3', lt=3)]`. The
/// classifier walks native only -- cp4_native is Matched. The
/// shipped resume names head=e3', so `structural_check` picks the
/// shipped cp4' (whose `previous` links to e3') as the opening.
/// Under the fixed `(seq, hash)` filter, cp4'.hash != cp4_native.hash
/// -> drop. Under a seq-only filter (the pre-blocker-2 bug), seq=4
/// is in the matched_openings set -> keep `[4]`. Row expects `[]`.
#[test]
fn hash_forgery_candidate_opening_dropped_at_later_seq_literal() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    let e3 = entry_rec(3, e2.hash());
    let mmr3 = pushed(&mmr2, &e3);
    let cp4_native = signed_cp(4, e3.hash(), &mmr3);
    // e3' is a FORK at seq=3: use a checkpoint with cp0 fold so the
    // record has a different hash from the native entry e3.
    let e3_forged = signed_cp(3, e2.hash(), &mmr2);
    assert_ne!(e3.hash(), e3_forged.hash(), "e3' is a fork of e3");
    let bad_peak: [u8; 32] = [0x55; 32];
    let bad_root: [u8; 32] = [0x55; 32];
    let cp4_forged = signed_cp_explicit(4, e3_forged.hash(), 1, bad_root, vec![bad_peak]);
    let resume_forged = resume_decl(&cp4_forged, 3, e3_forged.hash(), 3);
    write_records(&d.0, &[&cp0, &e1, &e2, &e3, &cp4_native]);
    let live = d.0.join("audit.jsonl");
    let shipped = d.0.join("shipped.jsonl");
    let shipped_bytes: Vec<u8> = [&e3_forged, &cp4_forged, &resume_forged]
        .iter()
        .flat_map(|r| line_bytes(r))
        .collect();
    fs::write(&shipped, shipped_bytes).unwrap();
    let collection = collect_files(&[live, shipped]);
    let kept = filter_candidates_for_test(&collection, TRAIL);
    assert_eq!(
        kept,
        Vec::<u64>::new(),
        "V4u second killer: forged cp4' is dropped by the (seq,hash) filter"
    );
}

// =======================================================================
// Blocker 3 repro: an honest resume in a SEALED segment. S0 holds
// `[cp0, e1, e2]`, S1 is sealed with `[cp4, r5(head=e2, lt=3), e6]`
// (an honest opening at cp4 that resumes a lost seq=3), live is
// `[cp7, r8(head=cp6? no, head=e6)]`. Under the pre-blocker-3 bug
// the strict closure in `storage::history_segment` short-circuits
// `record_fold_entry` in `Reaction::Stop`, so cp4 is not recorded
// and the filter drops the honest cp4 candidate. The fix records
// regardless of reaction; the outer classify loop drops entries
// under outer Stop (`build_reports == false`), so reader behaviour
// stays byte-for-byte the same while cp4 now lands in
// `matched_openings` and the honest gap is confirmable.
// =======================================================================

/// Builds blocker 3's repro and returns `(temp, dir, r5_opening_seq,
/// r8_opening_seq)` so the test asserts the exact seqs. S0 has
/// records [cp0, e1, e2]; S1 (sealed) opens with cp4, then
/// r5(head=e2, lt=3), then e6 (entry chain continues); live opens
/// with cp7 and carries r8 (head=e6, lt=6) as its resume.
fn build_honest_resume_in_sealed_segment() -> (Temp, PathBuf) {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    put_segment(&d.0, 0, &[&cp0, &e1, &e2], &[]);
    // S1 opens with cp4 (honest: fold is [cp0, e1, e2]), then a
    // resume naming the gap seq=3 (head=e2 at seq=2, lt=3).
    let cp4 = signed_cp(4, e2.hash(), &mmr2);
    let mmr_cp4 = pushed(&mmr2, &cp4);
    let r5 = resume_decl(&cp4, 2, e2.hash(), 3);
    let mmr_r5 = pushed(&mmr_cp4, &r5);
    let e6 = entry_rec(6, r5.hash());
    put_segment(&d.0, 1, &[&cp4, &r5, &e6], &[]);
    // live opens with cp7 (honest: fold is [cp0..=e6] + cp4 + r5),
    // then a resume naming head=e6 at seq=6, lt=6 (no missed leaves).
    let mmr_e6 = pushed(&mmr_r5, &e6);
    let cp7 = signed_cp(7, e6.hash(), &mmr_e6);
    let r8 = resume_decl(&cp7, 6, e6.hash(), 6);
    write_records(&d.0, &[&cp7, &r8]);
    let dir_path = d.0.clone();
    (d, dir_path)
}

#[test]
fn honest_resume_in_sealed_segment_candidate_kept_literal() {
    let (_temp, dir) = build_honest_resume_in_sealed_segment();
    let collection = collect_from_dir(&dir);
    let kept = filter_candidates_for_test(&collection, TRAIL);
    // Both resumes are honest: r5 opens via sealed cp4 (strict-
    // passed), r8 opens via live cp7 (scan_closing strict Collect).
    // With blocker 3 fixed, cp4's Matched entry lands in
    // `matched_openings`, so the fail-closed filter keeps BOTH
    // candidates. Pre-blocker-3 kept only [7] because the sealed
    // strict closure's `record_fold_entry` short-circuited in Stop.
    assert_eq!(
        kept,
        vec![4, 7],
        "blocker 3: honest resume in a sealed segment is kept, not dropped"
    );
    // The reader opens Ok on this layout (every segment is honest).
    let _reader = TrailReader::open(&dir, TRAIL, None)
        .expect("honest sealed-segment resume: TrailReader::open must succeed");
}

// =======================================================================
// B7 -- Classifier rows (`runs.rs` compiled Collect pass). Each row
// asserts the literal per-checkpoint outcome list for a layout, plus
// the `Reaction::Stop` outcome. On base `CheckpointFoldOutcome::Base`
// does not exist, so the self-based B7 row below is compile-red on
// base; the honest A1 row changes outcome count under blocker 3's
// fix (cp0 now appears as `Base`, so base's 2-entry list ≠ head's
// 3-entry list -- compile green but value-red).
// =======================================================================

use crate::audit::runs::{self, CheckpointFoldOutcome, ClassifyArgs, Reaction, ReaderPath};
use crate::audit::storage::SegmentSource;

fn fold_outcome_list(dir: &Path) -> Vec<(u64, CheckpointFoldOutcome)> {
    let collection = input::collect(std::iter::once(dir.to_path_buf())).unwrap();
    let natives = collection.native_segments();
    let tuples: Vec<(std::rc::Rc<[u8]>, bool)> = natives
        .iter()
        .map(|seg| (std::rc::Rc::clone(&seg.bytes), seg.is_live))
        .collect();
    let mut source = SegmentSource::for_snapshot(&tuples);
    let out = runs::classify(
        ClassifyArgs {
            trail: TRAIL,
            prior_state: None,
        },
        ReaderPath::LiveOpen { expected: None },
        &mut source,
        Reaction::Collect,
    )
    .unwrap();
    let mut list: Vec<(u64, CheckpointFoldOutcome)> = out
        .fold_entries
        .iter()
        .map(|e| (e.seq, e.outcome))
        .collect();
    list.sort_by_key(|x| x.0);
    list
}

fn fold_outcome_list_files(paths: &[PathBuf]) -> Vec<(u64, CheckpointFoldOutcome)> {
    let collection = input::collect(paths.iter().cloned()).unwrap();
    let natives = collection.native_segments();
    let tuples: Vec<(std::rc::Rc<[u8]>, bool)> = natives
        .iter()
        .map(|seg| (std::rc::Rc::clone(&seg.bytes), seg.is_live))
        .collect();
    let mut source = SegmentSource::for_snapshot(&tuples);
    let out = runs::classify(
        ClassifyArgs {
            trail: TRAIL,
            prior_state: None,
        },
        ReaderPath::LiveOpen { expected: None },
        &mut source,
        Reaction::Collect,
    )
    .unwrap();
    let mut list: Vec<(u64, CheckpointFoldOutcome)> = out
        .fold_entries
        .iter()
        .map(|e| (e.seq, e.outcome))
        .collect();
    list.sort_by_key(|x| x.0);
    list
}

#[test]
fn b7_a1_honest_fold_entries_literal() {
    let a = build_a1();
    let list = fold_outcome_list(&a.dir_path);
    // S0 is sealed and strict-passes under `storage::history_segment`'s
    // strict closure. `record_fold_entry` records regardless of the
    // walker's reaction (blocker 3; ruling 13-V4-d10 points 1-4), so
    // cp0 lands as `Base` (ADR amendment 6 "Base": `Mmr::from_peaks`
    // with size 0 and empty peaks, self-consistent against its own
    // peaks). S1 falls back to tolerant Collect (r4's broken
    // boundary trips strict), so cp5 lands as `Matched`. The live
    // segment walks under strict Collect through `scan_closing`, so
    // cp6 lands as `Matched` too.
    assert_eq!(
        list,
        vec![
            (0, CheckpointFoldOutcome::Base),
            (5, CheckpointFoldOutcome::Matched),
            (6, CheckpointFoldOutcome::Matched),
        ],
        "B7-honest: per-checkpoint outcome list"
    );
}

#[test]
fn b7_a1_wrong_cp6_root_fold_entries_literal() {
    let (_temp, dir) = build_a1_wrong_cp6_root();
    let list = fold_outcome_list(&dir);
    // Same shape as honest-A1 with cp6 flipping `Matched` ->
    // `Differs` (compare_mmr=true on a closer opening). cp0 is
    // still `Base` because the walker's strict pass records
    // regardless of reaction (blocker 3).
    assert_eq!(
        list,
        vec![
            (0, CheckpointFoldOutcome::Base),
            (5, CheckpointFoldOutcome::Matched),
            (6, CheckpointFoldOutcome::Differs),
        ],
        "B7-wrong-cp6: per-checkpoint outcome list"
    );
}

#[test]
fn b7_self_based_opening_fold_entry_literal() {
    let (_temp, live, shipped) = build_self_based_opening_repro();
    let list = fold_outcome_list_files(&[live, shipped]);
    // The native live segment opens on cp2 with no prior state, so
    // `apply_checked` loads cp2's declared `(size, root, peaks)`
    // through `Mmr::from_peaks` and records
    // `CheckpointFoldOutcome::Base`. This variant does NOT exist on
    // base `0xafe9942`, so this row is compile-red there.
    assert_eq!(
        list,
        vec![(2, CheckpointFoldOutcome::Base)],
        "B7-self-based: single Base entry at the self-based opening"
    );
}

#[test]
fn b7_reaction_stop_a1_honest_literal_outcome() {
    // `Reaction::Stop` must stay byte-for-byte the same as the
    // reader (ruling 13-V4-d10 point 1). On A1 honest, the reader
    // opens `Ok`; classify under Stop also returns `Ok`. The row
    // asserts the result as literal values (no `is_some()`): the
    // Ok value's `fold_entries` / `runs` / `segments` /
    // `violations` are empty, `head_mismatch` is false, and the
    // `final_state`'s `run.head` equals `Head::of(&resume7)`.
    let a = build_a1();
    // Rebuild A1's resume record so the row asserts the Stop
    // final-state `Head` as a literal value derived from the one
    // last-record constructor.
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
    let expected_head = Head::of(&resume);
    let collection = input::collect(std::iter::once(a.dir_path.to_path_buf())).unwrap();
    let natives = collection.native_segments();
    let tuples: Vec<(std::rc::Rc<[u8]>, bool)> = natives
        .iter()
        .map(|seg| (std::rc::Rc::clone(&seg.bytes), seg.is_live))
        .collect();
    let mut source = SegmentSource::for_snapshot(&tuples);
    let out = runs::classify(
        ClassifyArgs {
            trail: TRAIL,
            prior_state: None,
        },
        ReaderPath::LiveOpen { expected: None },
        &mut source,
        Reaction::Stop,
    )
    .expect("A1 honest classify under Reaction::Stop must succeed");
    let fold_entries_seq_outcome: Vec<(u64, CheckpointFoldOutcome)> = out
        .fold_entries
        .iter()
        .map(|e| (e.seq, e.outcome))
        .collect();
    assert_eq!(
        fold_entries_seq_outcome,
        Vec::<(u64, CheckpointFoldOutcome)>::new(),
        "Stop's trail-level fold_entries is empty (build_reports=false drops every entry)"
    );
    assert_eq!(out.runs.len(), 0, "Stop runs empty");
    assert_eq!(out.segments.len(), 0, "Stop segments empty");
    assert_eq!(out.violations.len(), 0, "Stop violations empty");
    assert!(!out.head_mismatch, "Stop head_mismatch false on A1 honest");
    let final_state = out
        .final_state
        .expect("Stop's live arm fired on A1 honest so final_state is Some");
    assert_eq!(
        final_state.run.head, expected_head,
        "Stop final_state.run.head == Head::of(&resume7)"
    );
}
