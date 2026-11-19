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
    storage::TrailReader,
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

#[test]
fn b3_a1_writer_honest_reader_opens_and_verifier_mmr_mismatch() {
    let (_temp, dir) = build_a1_writer_honest();
    // (1) Reader opens successfully: amendment 6 (iii) skips the
    // post-loss cp5 compare in the reader, so a writer-honest cp5
    // with size 5 is accepted.
    let _reader = TrailReader::open(&dir, TRAIL, None)
        .expect("writer-honest A1: TrailReader::open must succeed (amendment 6 (iii))");
    // (2) Verifier emits `MmrMismatch` at cp5 AND the run finding
    // stays. Full literal finding list.
    let s1 = dir.join("audit-20260101T000000.000000000Z_000001.jsonl");
    let live = dir.join("audit.jsonl");
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    let r4 = headless(&e2, 4);
    let reader_fold_r4 = pushed(&mmr2, &r4);
    let ghost = entry_rec(3, e2.hash());
    let writer_mmr3 = pushed(&mmr2, &ghost);
    let writer_mmr4 = pushed(&writer_mmr3, &r4);
    let cp5_writer = signed_cp(5, r4.hash(), &writer_mmr4);
    let mmr_detail = mmr_mismatch_detail(
        reader_fold_r4.size(),
        &reader_fold_r4.root(),
        writer_mmr4.size(),
        &writer_mmr4.root(),
    );
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
    assert_eq!(got, expected, "writer-honest A1 full literal list");
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
// Blocker 1 repro -- the self-based opening fail-open case the
// reviewer found. The shipped copy `shipped.jsonl = [cp0, e1]` is
// NOT part of the fold (spike #224); the native `audit.jsonl =
// [cp2, resume3]` starts from cp2 with no prior native state, so
// `apply_checked` loads cp2's declared `(size, root, peaks)` through
// `Mmr::from_peaks` (amendment 6 "Base") -- NO comparison happens.
// Under V4b this records `CheckpointFoldOutcome::Base` and the
// fail-closed filter drops the resume candidate; the verifier emits
// no `MmrMismatch`.
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
    // The walker never compares cp2 (`CheckpointFoldOutcome::Base`),
    // no `MmrMismatch` emitted; no SeqGap/ChainBroken (the shipped
    // records fill the 0..=1 prefix). The fail-closed filter drops
    // the resume candidate, so no gap-confirmation leak lands either.
    // On base the fold compare is discarded and the filter does not
    // exist; this row's main assertion (retained=[]) fails on base
    // through a COMPILE failure of `filter_candidates_for_test`, and
    // the finding-list sub-assertion also fails because base DOES
    // NOT record cp2 as `Base`.
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

/// Honest A1 closing resume: cp6 matches the walker's fold; the
/// filter keeps the candidate. Regression row (also passes on base
/// through the seam's absence making it compile-red): kills V4
/// (fail-open filter still keeps a matched opening -- unchanged)
/// only trivially, but IS the positive anchor for the negative rows.
#[test]
fn b6_honest_a1_closing_resume_kept_literal() {
    let a = build_a1();
    let collection = collect_from_dir(&a.dir_path);
    let kept = filter_candidates_for_test(&collection, TRAIL);
    assert_eq!(kept, vec![6], "B6 honest A1: closing resume at cp6 kept");
}

/// Honest genesis-linked resume: cp1 matches the amendment-9 fold;
/// the filter keeps the candidate. Same role as above.
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
/// complete record is a damaged prefix (ruling 13-V4-d10 point 6:
/// "once a segment records a violation the classifier stops
/// checking the rest of that segment"). The live-segment opening
/// cp2 is reached by the live walker with a reduced prior state
/// (e1 was rejected on `UnparsableBeforeRecord` in S0), so the
/// compare at cp2 under `compare_mmr=true` sees a declared fold that
/// does not match the walker's reduced fold -- outcome is
/// `Differs`. The filter drops it.
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
    // The candidate IS structurally valid at base `0xafe9942` (e1 and
    // cp2 are both on the trail and link); with V4b the filter
    // drops opening_seq=2 because the earlier violation prevents the
    // walker from recording a `Matched` outcome at cp2 (`Differs`
    // against the walker's reduced fold). `kept` is empty.
    assert_eq!(
        kept,
        Vec::<u64>::new(),
        "B6: opening after an earlier violation is dropped by the filter"
    );
}

// =======================================================================
// B7 -- Classifier rows (`runs.rs` compiled Collect pass). Each row
// asserts the literal per-checkpoint outcome list for a layout, plus
// the `Reaction::Stop` outcome. On base `CheckpointFoldOutcome::Base`
// does not exist, so the self-based B7 row below is compile-red on
// base; the honest A1 row changes outcome count (cp0 in S0 is
// strict-Stop under `storage::history_segment`, so Stop records
// nothing; the row's expected list of 2 entries becomes 3 on base
// -- compile green but value-red).
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
    // strict closure (which is hardcoded to `Reaction::Stop`); the
    // classifier's `record_fold_entry` short-circuits in the Stop
    // reaction (ruling 13-V4-d10 point 1), so cp0 does NOT appear in
    // `fold_entries`. S1 falls back to tolerant Collect (r4's broken
    // boundary trips strict), so cp5 lands as `Matched`. The live
    // segment walks under strict Collect through `scan_closing`, so
    // cp6 lands as `Matched` too.
    assert_eq!(
        list,
        vec![
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
    // Same as honest-A1 shape with cp6 flipping `Matched` -> `Differs`
    // (compare_mmr=true on a closer opening).
    assert_eq!(
        list,
        vec![
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
    // opens `Ok`, so classify under Stop also returns `Ok`; the
    // Ok value's `fold_entries` is empty, as are `runs`, `segments`,
    // `violations`, and `head_mismatch` is false. No `Err(_) => {}`
    // arm (brief blocker 2).
    let a = build_a1();
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
    assert!(
        out.fold_entries.is_empty(),
        "Stop records no fold entries: got {:?}",
        out.fold_entries
            .iter()
            .map(|e| (e.seq, e.outcome))
            .collect::<Vec<_>>()
    );
    assert!(
        out.runs.is_empty(),
        "Stop produces no run reports: got {} runs",
        out.runs.len()
    );
    assert!(
        out.segments.is_empty(),
        "Stop produces no segment reports: got {} segments",
        out.segments.len()
    );
    assert!(
        out.violations.is_empty(),
        "Stop produces no violations on honest A1"
    );
    assert!(
        !out.head_mismatch,
        "Stop head_mismatch false on A1 honest with expected=None"
    );
    assert!(
        out.final_state.is_some(),
        "Stop's final_state is Some on A1 honest"
    );
}
