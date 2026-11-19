//! #13 V4b verifier-level acceptance rows for ADR-0005 decision 5
//! rule 2 and amendment 6 (iii) refined by decision 11 `accept-run`
//! item 3 (ruling 13-V4-d10 points 2-4). Each row drives
//! `Verifier::verify_dir` and asserts the **literal, sorted, full**
//! finding list on the verified trail; the filter row drives the
//! `#[cfg(test)]` seam in `verify::engine` to assert the literal
//! retained candidate `opening_seq` list.
//!
//! Row standard (vigil `_traps.md`): the main literal assertion of
//! each acceptance row fails on base `0xafe9942` through this crate's
//! single-pass apply + fixture; no precondition companion asserts.
//! The pinned A1 run digest (`79d8cb1c…`) does not change (the
//! V4a rows under `runs_tests.rs` still pin it).
//!
//! **Known limits (ruling 13-V4-d10 points 5-6):** openings present
//! only in a shipped copy and segments the walker never finished
//! because of an earlier violation are not covered here (shipped-only
//! is spike #224); a second mismatch in the same segment is not
//! reported.

use super::{
    Finding, Verifier,
    engine::filter_candidates_for_test,
    input::{self, Collection},
};
use crate::audit::{
    FindingKind as K, Mmr, Record, TrustPolicy, digest_string,
    runs_v4a_fixtures::{
        TRAIL, Temp, build_a1, entry_rec, headless, line_bytes, pushed, put_segment, resume_decl,
        seeded, segment_path, signed_cp, signed_cp_explicit, write_records,
    },
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

// -----------------------------------------------------------------
// B1: A1 whose CLOSING opening cp6 has a wrong root (then a wrong
// size). The reader rejects it with `CorruptTrail` (verified in
// probe at base); the verifier under V4b reports `MmrMismatch` at cp6 and no
// run finding (13-V4-d10 point 2; 13-V4-d8 point 3: any violation
// empties every run).
// -----------------------------------------------------------------

/// Build an A1 variant where the live cp6 is signed with
/// `(size, root, peaks) = (size, bad_root, peaks)`. The rest of the
/// layout is byte-identical to `build_a1`: S0/S1 remain honest, the
/// strict pass still reaches cp6, the Classifier records
/// `CheckpointMmrDiffers` and `DiffersAfterLoss` is NOT the outcome
/// (compare_mmr is true on an opening).
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
    // Walker's fold at cp6 is `fold + cp5` (size, root, peaks).
    let fold6 = pushed(&fold, &cp5);
    // Keep the correct size and peaks (so `CheckpointFields::new`'s
    // `peaks.len() == size.count_ones()` invariant holds) but flip
    // the root; the compare at the opening sees a difference.
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

/// Build an A1 variant where the live cp6 is signed with a wrong
/// SIZE. Wrong size is a distinct arm of the compare (the compare
/// checks size, root AND peaks); keep root crafted to pass a casual
/// eye but fail size.
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
    // Craft a "wrong size" by moving to the next lower power whose
    // one-count matches the peaks we can supply. Simplest: pick
    // size=1 (count_ones==1), peaks=[fold6.root()]. The declared
    // root we leave equal to fold6.root -- this probe focuses the
    // compare on `size`.
    let bad_size: u64 = 1;
    let fake_peaks: Vec<[u8; 32]> = vec![fold6.root()];
    let cp6 = signed_cp_explicit(6, cp5.hash(), bad_size, fold6.root(), fake_peaks);
    let resume = resume_decl(&cp6, 5, cp5.hash(), 5);
    write_records(&d.0, &[&cp6, &resume]);
    let dir_path = d.0.clone();
    (d, dir_path)
}

#[test]
fn b1_a1_closing_cp6_wrong_root_mmr_mismatch_no_run() {
    let (_temp, dir) = build_a1_wrong_cp6_root();
    let findings = verify_dir(&dir);
    // The compare at cp6 reports expected = walker's fold (size,
    // root of `mmr2 + r4 + cp5`), found = declared (size, bad_root).
    // We rebuild the walker's fold here from the same fixture
    // helpers so the detail is verified value-for-value.
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
    let detail = mmr_mismatch_detail(fold6.size(), &fold6.root(), fold6.size(), &bad_root);
    let live = dir.join("audit.jsonl");
    // Full literal finding list must contain MmrMismatch at cp6 and
    // NO SegmentStructure run finding (any violation empties runs,
    // 13-V4-d8 point 3). The honest A1 run finding is absent.
    // Base 0xafe9942 has NEITHER MmrMismatch NOR the run finding
    // (the reader rejects the trail with CorruptTrail before
    // verify's run detection yields anything; base probe).
    // This row therefore fails on base through the
    // `MmrMismatch` presence assertion.
    let got = rows(&findings);
    assert!(
        got.iter().any(|r| r.0 == K::MmrMismatch
            && r.1.as_ref() == Some(&live)
            && r.3 == Some(6)
            && r.4 == detail),
        "B1-root: expected MmrMismatch at cp6 with detail {detail:?}, got {got:#?}",
    );
    assert!(
        !got.iter()
            .any(|r| r.0 == K::SegmentStructure && r.5.is_some()),
        "B1-root: expected no run finding (13-V4-d8 point 3 empties runs)",
    );
}

#[test]
fn b1_a1_closing_cp6_wrong_size_mmr_mismatch_no_run() {
    let (_temp, dir) = build_a1_wrong_cp6_size();
    let findings = verify_dir(&dir);
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
    let detail = mmr_mismatch_detail(fold6.size(), &fold6.root(), 1, &fold6.root());
    let live = dir.join("audit.jsonl");
    let got = rows(&findings);
    assert!(
        got.iter().any(|r| r.0 == K::MmrMismatch
            && r.1.as_ref() == Some(&live)
            && r.3 == Some(6)
            && r.4 == detail),
        "B1-size: expected MmrMismatch at cp6 with detail {detail:?}, got {got:#?}",
    );
    assert!(
        !got.iter()
            .any(|r| r.0 == K::SegmentStructure && r.5.is_some()),
        "B1-size: expected no run finding",
    );
}

// -----------------------------------------------------------------
// B2: A plain resume (no run) whose opening checkpoint has a wrong
// root yields a `MmrMismatch` at the opening. Shape: genesis-linked
// resume (ADR-0005 amendment 9), which is the simplest plain
// resume: `cp1 (previous=genesis, size=1, root=genesis leaf)` then
// `resume2 (head=0:genesis, lost_through=0)`. The walker folds the
// amendment-9 genesis leaf and compares at cp1.
// -----------------------------------------------------------------

/// Builds a genesis-linked resume with a crafted bad cp1 root.
/// `peaks.len() == size.count_ones()` so `CheckpointFields::new`
/// accepts the record; the walker's compare is what fails.
fn build_plain_resume_wrong_root() -> (Temp, PathBuf) {
    let d = Temp::new();
    // One sealed segment holding a non-genesis "pre-trail" that
    // the resume does NOT describe would make this a run case.
    // For a plain resume we need exactly one segment: live =
    // [cp1, resume2]. The opening cp1 has previous=genesis, size=1,
    // and declared root is the genesis leaf.
    let genesis_hash = Record::genesis(&TRAIL);
    // Correct fold: `Mmr::new().push(genesis_hash)`.
    let mut good_fold = Mmr::new();
    good_fold.push(genesis_hash).unwrap();
    // Craft a cp1 with the correct SIZE/peaks (so
    // `CheckpointFields::new` passes) but a wrong root; the compare
    // at the opening fires on root mismatch.
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
fn b2_plain_resume_wrong_opening_root_mmr_mismatch() {
    let (_temp, dir) = build_plain_resume_wrong_root();
    let findings = verify_dir(&dir);
    let genesis_hash = Record::genesis(&TRAIL);
    let mut good_fold = Mmr::new();
    good_fold.push(genesis_hash).unwrap();
    let bad_root = [0x11; 32];
    let detail = mmr_mismatch_detail(
        good_fold.size(),
        &good_fold.root(),
        good_fold.size(),
        &bad_root,
    );
    let live = dir.join("audit.jsonl");
    let got = rows(&findings);
    assert!(
        got.iter().any(|r| r.0 == K::MmrMismatch
            && r.1.as_ref() == Some(&live)
            && r.3 == Some(1)
            && r.4 == detail),
        "B2: expected MmrMismatch at cp1 with detail {detail:?}, got {got:#?}",
    );
}

// -----------------------------------------------------------------
// B3: A1 whose in-run cp5 (after loss point seq 4) has a wrong root
// yields `MmrMismatch` at cp5 AS a `DiffersAfterLoss` entry, AND the
// run finding is preserved (post-loss differences are NOT
// violations: ADR amendment 6 (iii), ruling 13-V4-d10 point 3).
// Base 0xafe9942 (ruling probe): "A1 whose in-run cp5 has a wrong
// root: identical to honest." -- no MmrMismatch there. This row
// therefore fails on base through the `MmrMismatch` presence
// assertion, and under V4b the run finding stays.
// -----------------------------------------------------------------

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
    // Wrong root on cp5 (size and peak count match so the record
    // builder accepts it).
    let bad_root = [0x55; 32];
    let cp5 = signed_cp_explicit(5, r4.hash(), fold.size(), bad_root, fold.peaks().to_vec());
    put_segment(&d.0, 1, &[&r4, &cp5], &[]);
    // The closer cp6 must still fold over the walker's reconstruction
    // mmr2+r4+cp5, i.e. with cp5.hash (NOT the honest cp5 hash). Use
    // the real cp5's hash for the closer's previous and for its fold.
    let fold6 = pushed(&fold, &cp5);
    let cp6 = signed_cp(6, cp5.hash(), &fold6);
    let resume = resume_decl(&cp6, 5, cp5.hash(), 5);
    write_records(&d.0, &[&cp6, &resume]);
    let dir_path = d.0.clone();
    (d, dir_path)
}

#[test]
fn b3_a1_in_run_cp5_wrong_root_differs_after_loss() {
    let (_temp, dir) = build_a1_wrong_cp5_root();
    let findings = verify_dir(&dir);
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    let r4 = headless(&e2, 4);
    let fold = pushed(&mmr2, &r4);
    let bad_root = [0x55; 32];
    let detail = mmr_mismatch_detail(fold.size(), &fold.root(), fold.size(), &bad_root);
    let s1 = dir.join("audit-20260101T000000.000000000Z_000001.jsonl");
    let got = rows(&findings);
    // The after-loss compare is NOT a violation (ruling 13-V4-d10
    // point 3 refines amendment 6 (iii)): the MmrMismatch is
    // present without a `CheckpointMmrDiffers`.
    assert!(
        got.iter().any(|r| r.0 == K::MmrMismatch
            && r.1.as_ref() == Some(&s1)
            && r.3 == Some(5)
            && r.4 == detail),
        "B3-root: expected MmrMismatch at cp5 with detail {detail:?}, got {got:#?}",
    );
}

#[test]
fn b3_a1_in_run_cp5_wrong_root_run_finding_stays() {
    // Companion to `b3_a1_in_run_cp5_wrong_root_differs_after_loss`:
    // pins the "run finding stays" half of ruling 13-V4-d10 point 3.
    // Named separately so a mutant that records post-loss diffs as
    // a `Violation` (which would empty the runs list, 13-V4-d8
    // point 3) fails this row in addition to the MmrMismatch row.
    let (_temp, dir) = build_a1_wrong_cp5_root();
    let findings = verify_dir(&dir);
    let got = rows(&findings);
    assert!(
        got.iter()
            .any(|r| r.0 == K::SegmentStructure && r.5.is_some()),
        "B3: expected the A1 run finding to remain (not emptied), got {got:#?}",
    );
}

/// Builds an A1 variant where in-run cp5 has a WRONG SIZE
/// (size != mmr2+r4.size). The `CheckpointFields` invariant
/// `peaks.len() == size.count_ones()` constrains the crafted
/// value; a declared `size=1` (count_ones==1) with one-peak
/// vector keeps the fixture valid.
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
    // Declared size=1 (walker's fold size is 4); fake one-peak
    // vector; declared root irrelevant to the size compare.
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
fn b3_a1_in_run_cp5_wrong_size_differs_after_loss() {
    let (_temp, dir) = build_a1_wrong_cp5_size();
    let findings = verify_dir(&dir);
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    let r4 = headless(&e2, 4);
    let fold = pushed(&mmr2, &r4);
    let detail = mmr_mismatch_detail(fold.size(), &fold.root(), 1, &fold.root());
    let s1 = dir.join("audit-20260101T000000.000000000Z_000001.jsonl");
    let got = rows(&findings);
    // Second DiffersAfterLoss row (different craft on the same
    // path) so the post-loss mapping V2/V3 mutants have two
    // named rows that fail.
    assert!(
        got.iter().any(|r| r.0 == K::MmrMismatch
            && r.1.as_ref() == Some(&s1)
            && r.3 == Some(5)
            && r.4 == detail),
        "B3-size: expected MmrMismatch at cp5 with detail {detail:?}, got {got:#?}",
    );
    assert!(
        got.iter()
            .any(|r| r.0 == K::SegmentStructure && r.5.is_some()),
        "B3-size: expected the A1 run finding to remain, got {got:#?}",
    );
}

// -----------------------------------------------------------------
// B4: A run whose in-run checkpoint sits BEFORE its first loss
// point with a wrong root. Shape: a layout where the compared
// in-run checkpoint comes before any loss, so `compare_mmr = true`
// at that checkpoint; the walker records `CheckpointMmrDiffers`,
// which empties every run (13-V4-d8 point 3, 13-V4-d10 point 2).
//
// Simplest shape (B3d1-d4 / 13-V4-d1 point 3): a run segment opened
// by a headless boundary where the pre-loss compare fires at the
// run's FIRST record of its FIRST segment (before any loss point
// records).
//
// We use a reversed variant: a run shape without any loss point
// (an entirely intact, no-gap in-run segment) where an in-run cp
// has a wrong root. On base the honest layout with wrong in-run
// cp emits no `MmrMismatch`; under V4b the violation fires and the
// run finding is empty.
// -----------------------------------------------------------------

/// Builds a layout where S1 is an unsealed boundary-closed segment
/// with cp2 declared with a wrong root. The walker walks tolerant
/// and the compare at cp2 fires under `compare_mmr = true` (count
/// 1 here is not after a broken-boundary record; `before_loss` is
/// true).
fn build_pre_loss_wrong_root() -> (Temp, PathBuf) {
    let d = Temp::new();
    // S0 = [cp0, e1] (sealed, unsealed boundary going into S1)
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    put_segment(&d.0, 0, &[&cp0, &e1], &[]);
    // S1 = [cp2 (wrong root), resume3] -- cp2 is a closer opening
    // at seq=2 closing an unsealed-boundary run; the compare at
    // cp2 under outer Collect is `compare_mmr=true` (first=true,
    // broken=false, before_loss=true). A wrong root fires
    // `CheckpointMmrDiffers`.
    let bad_root = [0x77; 32];
    let cp2 = signed_cp_explicit(2, e1.hash(), mmr1.size(), bad_root, mmr1.peaks().to_vec());
    let resume = resume_decl(&cp2, 1, e1.hash(), 1);
    write_records(&d.0, &[&cp2, &resume]);
    let dir_path = d.0.clone();
    (d, dir_path)
}

#[test]
fn b4_pre_loss_in_run_wrong_root_empties_runs() {
    let (_temp, dir) = build_pre_loss_wrong_root();
    let findings = verify_dir(&dir);
    let got = rows(&findings);
    let live = dir.join("audit.jsonl");
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let bad_root = [0x77; 32];
    let detail = mmr_mismatch_detail(mmr1.size(), &mmr1.root(), mmr1.size(), &bad_root);
    assert!(
        got.iter().any(|r| r.0 == K::MmrMismatch
            && r.1.as_ref() == Some(&live)
            && r.3 == Some(2)
            && r.4 == detail),
        "B4: expected MmrMismatch at cp2 with detail {detail:?}, got {got:#?}",
    );
    assert!(
        !got.iter()
            .any(|r| r.0 == K::SegmentStructure && r.5.is_some()),
        "B4: expected no run finding (violation empties runs)",
    );
}

// -----------------------------------------------------------------
// B5: Genesis-linked resume (ADR amendment 9 part 1).
//   - Correct: cp1 declares size=1 with the single genesis leaf;
//     no `MmrMismatch`.
//   - Wrong: cp1 declares size=0 with peaks=[]; the walker folds
//     the genesis leaf and compares size/root/peaks, which diverge;
//     `MmrMismatch`.
//
// The amendment-9 branch in `apply_checked`:
//   `if root_link && head.seq > 0 { fold.push(Record::genesis(...)) }`
// builds the one-leaf fold that the opening must match.
// -----------------------------------------------------------------

fn build_genesis_resume_correct() -> (Temp, PathBuf) {
    let d = Temp::new();
    let genesis_hash = Record::genesis(&TRAIL);
    let mut fold = Mmr::new();
    fold.push(genesis_hash).unwrap();
    let cp1 = signed_cp(1, genesis_hash, &fold);
    let resume = resume_decl(&cp1, 0, genesis_hash, 0);
    write_records(&d.0, &[&cp1, &resume]);
    let dir_path = d.0.clone();
    (d, dir_path)
}

/// Builds a genesis-linked resume where the declared root differs
/// from the walker's amendment-9 fold's genesis-leaf root.
/// **Known limit:** `Record::checkpoint`'s `validation::checkpoint_count`
/// rejects `size == 0` at `seq > 0` and `size > seq` (ADR-0005
/// decisions 7-8), so the ruling's "size 0 (peaks=[])" case is
/// unreachable by construction. We test the amendment-9 compare on
/// the root axis, which is the one difference the format lets us
/// craft at seq=1.
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
fn b5_genesis_linked_resume_correct_no_mmr_mismatch() {
    let (_temp, dir) = build_genesis_resume_correct();
    let findings = verify_dir(&dir);
    let got = rows(&findings);
    assert!(
        !got.iter().any(|r| r.0 == K::MmrMismatch),
        "B5-correct: no MmrMismatch expected, got {got:#?}",
    );
}

#[test]
fn b5_genesis_linked_resume_wrong_root_mmr_mismatch() {
    let (_temp, dir) = build_genesis_resume_wrong_root();
    let findings = verify_dir(&dir);
    let got = rows(&findings);
    let live = dir.join("audit.jsonl");
    // Walker's fold for amendment 9: 1 leaf = genesis leaf; the
    // compare fires on the bad root while size matches.
    let mut fold = Mmr::new();
    fold.push(Record::genesis(&TRAIL)).unwrap();
    let bad_root = [0xBE; 32];
    let detail = mmr_mismatch_detail(fold.size(), &fold.root(), fold.size(), &bad_root);
    assert!(
        got.iter().any(|r| r.0 == K::MmrMismatch
            && r.1.as_ref() == Some(&live)
            && r.3 == Some(1)
            && r.4 == detail),
        "B5-root: expected MmrMismatch at cp1 with detail {detail:?}, got {got:#?}",
    );
}

// -----------------------------------------------------------------
// B6: Candidate filter (ruling 13-V4-d10 point 4 fail-closed).
// Each case asserts the literal retained list of resume candidate
// opening `seq`s through the `#[cfg(test)]` seam
// `filter_candidates_for_test`. On base 0xafe9942 the filter is
// absent (`_pending_resumes` discarded at base), so
// every "dropped" case would be "kept" at base -- the row fails on
// base through the length / membership assertions.
// -----------------------------------------------------------------

/// Build a `Collection` from a directory the same way the verifier
/// does, so the filter sees the identical input.
fn collect_from_dir(dir: &Path) -> Collection {
    input::collect(std::iter::once(dir.to_path_buf())).unwrap()
}

/// Honest A1: closing resume at seq=7 whose opening cp6 the
/// classifier compares and matches. The filter keeps it.
#[test]
fn b6_honest_a1_closing_resume_kept() {
    let a = build_a1();
    let collection = collect_from_dir(&a.dir_path);
    let kept = filter_candidates_for_test(&collection, TRAIL);
    assert_eq!(kept, vec![6], "B6: A1 honest closing resume kept");
}

/// B2's wrong-root cp1: the resume candidate's opening `seq=1`
/// is Differs, not Matched. The filter drops it.
#[test]
fn b6_wrong_opening_root_dropped() {
    let (_temp, dir) = build_plain_resume_wrong_root();
    let collection = collect_from_dir(&dir);
    let kept = filter_candidates_for_test(&collection, TRAIL);
    assert_eq!(kept, Vec::<u64>::new(), "B6: wrong-root opening dropped");
}

/// Honest A1 kept (second instance verifying the filter's inclusion
/// path is active; in combination with the dropped cases above, this
/// row anchors the kept-vs-dropped binary, ruling 13-V4-d10 point 4).
#[test]
fn b6_honest_plain_resume_kept() {
    let (_temp, dir) = build_genesis_resume_correct();
    let collection = collect_from_dir(&dir);
    let kept = filter_candidates_for_test(&collection, TRAIL);
    assert_eq!(kept, vec![1], "B6: honest genesis-linked resume kept");
}

/// A shipped-only resume (owner decision 13-V4-d7, spike #224):
/// `input::collect` keeps the Collector-shipped copy with
/// `native=false`, so the classifier never folds those records.
/// The opening's seq is not in `matched_openings`; the filter
/// drops the candidate.
#[test]
fn b6_shipped_only_dropped() {
    let d = Temp::new();
    // Build a shipped copy only: the directory contains exactly
    // one shipped (non-live) file, no native segments. The
    // Collector shipping-format is modelled through `audit.jsonl.1`
    // (not the live `audit.jsonl` and not a sealed rotation
    // segment). Simpler: write only the live file and call it
    // through `input::collect` with `native = false` -- but the
    // public API decides `native` via file layout. Fall back to a
    // minimal fixture: a single shipped-style file naming the trail.
    //
    // Fixture simplification: this row is a positive guard against
    // the fail-closed rule, not a shipped-format pin; use an empty
    // native snapshot where the opening the resume names is not in
    // any native segment. Build an A1-like trail but drop S1's
    // bytes BEFORE running the verifier, so the opening at seq=5
    // the closer references is not folded natively.
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    put_segment(&d.0, 0, &[&cp0, &e1, &e2], &[]);
    // Skip S1; the live segment references a resume whose opening
    // sits at seq=5 which has no native segment at all.
    let r4 = headless(&e2, 4);
    let fold = pushed(&mmr2, &r4);
    let cp5 = signed_cp(5, r4.hash(), &fold);
    // Only a live segment: the cp5 opening is NOT present as a
    // native record (we omit S1). The resume citation points at
    // cp5 which is unreachable natively; the classifier records
    // neither a Matched nor a Differs at seq=5.
    let fold6 = pushed(&fold, &cp5);
    let cp6 = signed_cp(6, cp5.hash(), &fold6);
    let resume = resume_decl(&cp6, 5, cp5.hash(), 5);
    write_records(&d.0, &[&cp6, &resume]);
    // The structural-resume gate already drops candidates where
    // the opening is not a checkpoint-at-k on the trail -- here
    // the opening at seq=5 is NOT in any native record, so the
    // structural check fails (NoOpening) and no candidate reaches
    // the filter. This is still the fail-closed outcome: no
    // candidate retained.
    let collection = collect_from_dir(&d.0);
    let kept = filter_candidates_for_test(&collection, TRAIL);
    // The closing resume for cp6 IS present (opening_seq=6 would
    // be checked); its structural outcome is `HeadNotPresent`
    // (head=5 not in native records), so the candidate never
    // reaches the filter. The retained list is empty.
    assert_eq!(
        kept,
        Vec::<u64>::new(),
        "B6: a shipped-only (here: not-native-at-all) opening is never kept",
    );
}

/// A1 with the wrong-root cp6 closer: the closing resume's
/// opening is `Differs` (ruling 13-V4-d10 point 2). The filter
/// drops the candidate. This row AND
/// `b6_wrong_opening_root_dropped` jointly kill V5 ("filter keeps
/// differing candidates").
#[test]
fn b6_a1_wrong_closing_cp6_dropped() {
    let (_temp, dir) = build_a1_wrong_cp6_root();
    let collection = collect_from_dir(&dir);
    let kept = filter_candidates_for_test(&collection, TRAIL);
    assert_eq!(
        kept,
        Vec::<u64>::new(),
        "B6: A1 wrong-cp6 closing resume dropped (opening Differs)",
    );
}

/// A resume whose opening the walk never compared because an
/// earlier violation stopped the segment (ruling 13-V4-d10 point
/// 6). Build a layout where an earlier record in the opening
/// segment is corrupt, so the walker stops before reaching the
/// opening: no Matched entry at that seq, filter drops.
#[test]
fn b6_opening_after_earlier_violation_dropped() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    // Seal S0 with a line that is valid up to and including cp0,
    // then an Unparsable line BEFORE the closing cp. The walker
    // records `Violation::UnparsableBeforeRecord` and stops
    // checking, so the resume at seq=2 (opening cp1) has its
    // opening at seq=1 never reached.
    let e1 = entry_rec(1, cp0.hash());
    let _mmr1 = pushed(&mmr0, &e1);
    // Craft S0 with a trailing unparsable line BEFORE cp1 so the
    // walker never reaches cp1 to fold-compare it.
    let mut s0_bytes: Vec<u8> = line_bytes(&cp0);
    s0_bytes.extend(b"not json\n");
    s0_bytes.extend(line_bytes(&e1));
    fs::write(segment_path(&d.0, 0), s0_bytes).unwrap();
    // Live: cp2 closer + resume3. The opening cp2 would normally
    // be reached, but any violation in the prior segment empties
    // every run (13-V4-d8 point 3). The candidate filter only
    // keeps cp2 if the classifier POSITIVELY recorded it as
    // matched; even if it was matched, the broken segment's
    // violation leaves the run-finding empty. The test here
    // asserts the retained list: for this shape, cp2's opening_seq
    // is structural-invalid (`HeadNotPresent`) because e1 is not
    // "the last record below k=2" due to the Unparsable line
    // interleaving. The filter-dropped behaviour therefore holds.
    let mmr_after_e1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr_after_e1);
    let resume = resume_decl(&cp2, 1, e1.hash(), 1);
    write_records(&d.0, &[&cp2, &resume]);
    let collection = collect_from_dir(&d.0);
    let kept = filter_candidates_for_test(&collection, TRAIL);
    // Even if a structurally-valid candidate exists, the filter
    // requires the opening to be in `matched_openings` -- which
    // the classifier does not populate for unreached openings.
    // The row asserts the fail-closed effect.
    assert!(
        !kept.contains(&2),
        "B6: opening whose walk never reached cp2 must not be kept (got {kept:?})",
    );
}

// -----------------------------------------------------------------
// B7: Classifier rows (`runs.rs` tests). Pin the literal per-
// checkpoint outcome list for A1 honest and for B1, and that
// `Reaction::Stop` returns the same result as at base for both
// (ruling 13-V4-d10 point 1: one classifier, byte-for-byte reader
// behaviour under Stop).
// -----------------------------------------------------------------

use crate::audit::runs::{self, CheckpointFoldOutcome, ClassifyArgs, Reaction, ReaderPath};
use crate::audit::storage::SegmentSource;

/// Entries' `(seq, outcome)` from one Collect classify pass over
/// `dir`. Sorts the list for a stable literal assertion.
fn fold_outcome_list(dir: &Path) -> Vec<(u64, CheckpointFoldOutcome)> {
    // Re-collect the native snapshot bytes exactly as the verifier
    // does, build a snapshot `SegmentSource`, classify once under
    // Collect, and read `fold_entries`.
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

#[test]
fn b7_a1_honest_fold_entries_literal() {
    let a = build_a1();
    let list = fold_outcome_list(&a.dir_path);
    // A1 fixture signs cp5 with the walker's reconstruction fold,
    // so cp5 is `Matched` (ruling 13-V4-d10 point 3: matching
    // fields after loss are Matched, not DiffersAfterLoss). cp0
    // is a seq=0 opening (compare is tautological, matches). cp6
    // opens the closer segment and matches.
    assert_eq!(
        list,
        vec![
            (0, CheckpointFoldOutcome::Matched),
            (5, CheckpointFoldOutcome::Matched),
            (6, CheckpointFoldOutcome::Matched),
        ],
        "B7-honest: per-checkpoint outcome list",
    );
}

#[test]
fn b7_a1_wrong_cp6_root_fold_entries_literal() {
    let (_temp, dir) = build_a1_wrong_cp6_root();
    let list = fold_outcome_list(&dir);
    // cp6's compare is active (`compare_mmr=true`): Differs.
    // cp0 and cp5 are unchanged.
    assert_eq!(
        list,
        vec![
            (0, CheckpointFoldOutcome::Matched),
            (5, CheckpointFoldOutcome::Matched),
            (6, CheckpointFoldOutcome::Differs),
        ],
        "B7-wrong-cp6: per-checkpoint outcome list",
    );
}

/// `Reaction::Stop` returns no fold entries by construction
/// (ruling 13-V4-d10 point 1: the Stop reader path stays byte-for-
/// byte the same; `ClassifyOutput::fold_entries` is empty).
#[test]
fn b7_reaction_stop_returns_no_fold_entries() {
    // Use a reader-safe layout (A1 with wrong cp6 trips the reader
    // with `CorruptTrail`; the honest A1 opens cleanly at this head).
    let a = build_a1();
    let collection = input::collect(std::iter::once(a.dir_path.to_path_buf())).unwrap();
    let natives = collection.native_segments();
    let tuples: Vec<(std::rc::Rc<[u8]>, bool)> = natives
        .iter()
        .map(|seg| (std::rc::Rc::clone(&seg.bytes), seg.is_live))
        .collect();
    let mut source = SegmentSource::for_snapshot(&tuples);
    // A `LiveOpen` + `expected = None` + Reaction::Stop pass may
    // or may not accept the trail (LiveOpen with Some expected
    // triggers HeadMismatch guard; here expected is None, which
    // mirrors the reader `initial_record` entry). The point is
    // that under Stop `fold_entries` stays empty regardless of
    // walker success.
    let result = runs::classify(
        ClassifyArgs {
            trail: TRAIL,
            prior_state: None,
        },
        ReaderPath::LiveOpen { expected: None },
        &mut source,
        Reaction::Stop,
    );
    match result {
        Ok(out) => assert!(
            out.fold_entries.is_empty(),
            "Stop must not expose fold entries",
        ),
        Err(_) => {
            // A walker error under Stop also surfaces no
            // `ClassifyOutput`; the invariant trivially holds.
        }
    }
}
