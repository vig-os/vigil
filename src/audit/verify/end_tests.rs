//! Rows for the verifier's `end=` retirement check (ADR-0005
//! decision 9; rulings 13-V5-d1 point 5 and 13-V5-d5).
//!
//! Row standard (repo-wide): every acceptance row asserts the FULL
//! sorted literal [`Finding`] list through [`assert_findings`] (a
//! thin wrapper around `assert_eq!` on `Vec<Finding>`), and also
//! [`Report::is_strict_valid`] and [`Report::covered_through`]
//! wherever the row's claim involves them. Regression rows are
//! labelled in their doc comments. Every digest and key in an
//! expected detail is a written-out hex constant pinned by
//! [`fixture_hashes_match_literals`]. Expected lists are written in
//! the engine's final sort order (`(seq.is_none(), seq, file, line,
//! kind_debug)`), so no per-row sort runs here.

use crate::audit::{
    Entry, FindingKind as K, KeyFileSigner, Mmr, Record, Signer as _, TrustPolicy, digest_string,
    format::Kind,
    gap_hasher, hex,
    runs_v4a_fixtures::{
        TRAIL, Temp, context, entry_rec, fixture_pubkey, line_bytes, pushed, put_segment, seeded,
        segment_path, signed_cp, signed_cp_explicit, write_bytes,
    },
    verify::{Finding, Report, Verifier},
};
use std::{fs, path::PathBuf};

// =====================================================================
// Shared literal hex constants (see `fixture_hashes_match_literals`).
// =====================================================================

const FIXTURE_KEY_HEX: &str = "ee45ecb9aca01a0abd83ef56dd985c8c874e6e7f4aebcedf20bd8d88c2a0add7";
const NEW_KEY_HEX: &str = "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0";
const CP0_HONEST_DIGEST: &str =
    "blake3:fc26c6f2bb830592aaaca5413da1599489d86ac6e240a4a7a010681e0d4c8e77";
const E1_HONEST_DIGEST: &str =
    "blake3:c121282b5135adfe7a17142cae6bfc4c9040c4aed26d74bddc923b8dafcdb6e8";
const CP2_HONEST_DIGEST: &str =
    "blake3:4164966a12a675e55eb6e133b9e50313907f164fe142d941447defcdfdb25d06";
const CP2_TWIN_V6_DIGEST: &str =
    "blake3:aee5a47d9814a55594371fa3bb0bd34a48531533983898590ef72f511d42f45c";
const CP0_TWIN_V6B_DIGEST: &str =
    "blake3:ca0beffeaf4ac9b032b9e4b350a04c8870a116631288eb5e460e0e8e83da5c57";
const BOUND_HASH_5A_DIGEST: &str =
    "blake3:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
const BOUND_HASH_33_DIGEST: &str =
    "blake3:3333333333333333333333333333333333333333333333333333333333333333";
const FRAG: &[u8] = b"{\"torn\":\n";
const FRAG_DIGEST: &str = "blake3:e07ec37e78aa91ad5e973df286a9e563f1b9b5c3d69ba53fa990ac2b80f89fe9";
/// `e1` hash in the `[cp0, frag, e1(repaired=FRAG), cp2]` crashed
/// layout: the entry carries the gap's `audit.repaired` digest, so
/// its hash differs from `entry_rec`'s unrepaired e1 in
/// `two_checkpoints()`.
const CRASHED_E1_DIGEST: &str =
    "blake3:6fe4128226d928b7f2c266bb9e8b02f2e1bce617c2105a2d9008f3beb09157f6";
/// `cp2` hash in the crashed layout: cp2's MMR fold covers the
/// repaired e1, so its hash differs from `two_checkpoints()`'s cp2.
const CRASHED_CP2_DIGEST: &str =
    "blake3:9c0055973508dfe13d166f4ebabbfac7dd981e2471dc518c051c59f8832e3c66";

// Secondary trail id used by E8/E12 to probe mutant T11 (scope).
const OTHER_TRAIL: [u8; 16] = [0x01; 16];

// =====================================================================
// Helpers.
// =====================================================================

fn located(kind: K, file: PathBuf, line: u64, seq: u64, detail: String) -> Finding {
    Finding::new(kind, Some(file), Some(line), Some(seq), detail)
}
fn unlocated(kind: K, seq: Option<u64>, detail: String) -> Finding {
    Finding::new(kind, None, None, seq, detail)
}
fn uncovered(first: u64, last: u64) -> Finding {
    unlocated(
        K::UncoveredTail,
        None,
        format!("records seq {first}..={last}"),
    )
}

#[track_caller]
fn assert_findings(actual: &[Finding], expected: &[Finding], label: &str) {
    assert_eq!(actual, expected, "{label} literal finding list");
}

fn report_of(files: Vec<PathBuf>, trust: TrustPolicy) -> Report {
    Verifier::new(trust).verify_files(files).unwrap()
}
fn report_on_trail(files: Vec<PathBuf>, trust: TrustPolicy, trail: [u8; 16]) -> Report {
    Verifier::new(trust)
        .trail(trail)
        .unwrap()
        .verify_files(files)
        .unwrap()
}

fn new_pubkey() -> [u8; 32] {
    KeyFileSigner::from_hex(&"22".repeat(32))
        .unwrap()
        .public_key()
}

fn entry_with_repaired(seq: u64, previous: [u8; 32], repair: [u8; 32]) -> Record {
    let ctx = context(seq, previous).repaired(repair);
    Record::new(ctx, Entry::new("a", "change", "c")).unwrap()
}
fn repair_digest(frag: &[u8]) -> [u8; 32] {
    let mut h = gap_hasher();
    h.update(frag);
    *h.finalize().as_bytes()
}

/// `[cp0, e1, cp2]` on `TRAIL` with the fixture key.
struct TwoCheckpointLayout {
    _dir: Temp,
    path: PathBuf,
    cp0: Record,
    e1: Record,
    cp2: Record,
}
fn two_checkpoints() -> TwoCheckpointLayout {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let path = segment_path(&d.0, 0);
    TwoCheckpointLayout {
        _dir: d,
        path,
        cp0,
        e1,
        cp2,
    }
}
/// `[cp0, frag, e1(repaired), cp2]` honest-crash layout.
struct CrashedLayout {
    _dir: Temp,
    path: PathBuf,
    cp0: Record,
    e1: Record,
    cp2: Record,
}
fn crashed() -> CrashedLayout {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let gap = repair_digest(FRAG);
    let e1 = entry_with_repaired(1, cp0.hash(), gap);
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mut bytes = line_bytes(&cp0);
    bytes.extend_from_slice(FRAG);
    bytes.extend_from_slice(&line_bytes(&e1));
    bytes.extend_from_slice(&line_bytes(&cp2));
    let path = segment_path(&d.0, 0);
    write_bytes(&path, &bytes);
    CrashedLayout {
        _dir: d,
        path,
        cp0,
        e1,
        cp2,
    }
}

// =====================================================================
// E1 — ACCEPTANCE. Wrong hash at the `end=` `seq`: the detail is
// `record at seq 2 has hash <actual>`, located at cp2. On base
// (`end::check` stubbed) the expected list is non-empty, so the
// first `assert_findings` fails.
// =====================================================================
#[test]
fn e1_wrong_hash_at_end_seq_emits_has_hash() {
    let fx = two_checkpoints();
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .end(2, [0x5a; 32])
        .build()
        .unwrap();
    let report = report_of(vec![fx.path.clone()], trust);
    let expected = vec![located(
        K::TrailEnded,
        fx.path.clone(),
        3,
        2,
        format!("end=2:{BOUND_HASH_5A_DIGEST}: record at seq 2 has hash {CP2_HONEST_DIGEST}"),
    )];
    assert_findings(report.findings(), &expected, "E1");
    assert!(!report.is_strict_valid(), "E1 strict fails on TrailEnded");
    assert_eq!(report.covered_through(), Some(2));
}

// =====================================================================
// E2 — ACCEPTANCE. Records above a matching `end=` emit one
// `TrailEnded` at the first such record, with the `a..=b` seq range.
// Pairs with E11 to pin the location at the FIRST record above
// (mutant T12) and the `seq > s` boundary (mutant T2).
// =====================================================================
#[test]
fn e2_records_above_end_emit_records_above() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let e3 = entry_rec(3, cp2.hash());
    let e4 = entry_rec(4, e3.hash());
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2, &e3, &e4], &[]);
    let path = segment_path(&d.0, 0);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .end(2, cp2.hash())
        .build()
        .unwrap();
    let report = report_of(vec![path.clone()], trust);
    let expected = vec![
        located(
            K::TrailEnded,
            path.clone(),
            4,
            3,
            format!("end=2:{CP2_HONEST_DIGEST}: records seq 3..=4 above the end"),
        ),
        uncovered(3, 4),
    ];
    assert_findings(report.findings(), &expected, "E2");
    assert!(!report.is_strict_valid(), "E2 strict fails on TrailEnded");
    assert_eq!(report.covered_through(), Some(2));
}

// =====================================================================
// E2v — ACCEPTANCE (d11 l.931 "a record forged after it is
// `TrailEnded` (and `UntrustedKey` for a forged checkpoint)"). A
// retired trail with its old key bounded at an earlier anchored
// checkpoint, `end=` at the last clean record, and a forged
// checkpoint by the old key above the end: the forged checkpoint
// also emits `UntrustedKey`.
// =====================================================================
#[test]
fn e2v_forged_checkpoint_above_bound_also_emits_untrusted_key() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    let cp3 = signed_cp(3, cp2.hash(), &mmr2);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2, &cp3], &[]);
    let path = segment_path(&d.0, 0);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, cp0.hash())
        .end(2, cp2.hash())
        .build()
        .unwrap();
    let report = report_of(vec![path.clone()], trust);
    let expected = vec![
        located(
            K::RevocationUnconfirmed,
            path.clone(),
            1,
            0,
            format!(
                "key {FIXTURE_KEY_HEX} through=0: no trusted checkpoint by another key above the bound"
            ),
        ),
        located(
            K::UntrustedKey,
            path.clone(),
            3,
            2,
            format!("key {FIXTURE_KEY_HEX} bounded through seq 0"),
        ),
        located(
            K::TrailEnded,
            path.clone(),
            4,
            3,
            format!("end=2:{CP2_HONEST_DIGEST}: records seq 3..=3 above the end"),
        ),
        located(
            K::UntrustedKey,
            path,
            4,
            3,
            format!("key {FIXTURE_KEY_HEX} bounded through seq 0"),
        ),
        uncovered(1, 3),
    ];
    assert_findings(report.findings(), &expected, "E2v");
    assert!(!report.is_strict_valid(), "E2v strict fails on errors");
    assert_eq!(report.covered_through(), Some(0));
}

// =====================================================================
// E3 — ACCEPTANCE. The `end=` `seq` is absent from the verified
// files: `TrailEnded "no record at seq 5"`, no location, no tail
// exemption (`TrailEnded` is an error so strict fails). Pairs with
// E3b to pin "absent" precedence (mutant T4).
// =====================================================================
#[test]
fn e3_absent_at_end_seq_emits_no_record_unlocated() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    put_segment(&d.0, 0, &[&cp0, &e1], &[]);
    let path = segment_path(&d.0, 0);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .end(5, [0x5a; 32])
        .build()
        .unwrap();
    let report = report_of(vec![path], trust);
    let expected = vec![
        unlocated(
            K::TrailEnded,
            Some(5),
            format!("end=5:{BOUND_HASH_5A_DIGEST}: no record at seq 5"),
        ),
        uncovered(1, 1),
    ];
    assert_findings(report.findings(), &expected, "E3");
    assert!(!report.is_strict_valid(), "E3 strict fails: not exempt");
    assert_eq!(report.covered_through(), Some(0));
}

// =====================================================================
// E3b — ACCEPTANCE. Second absent-at-end-seq row at a different
// `seq`: pairs with E3 so mutant T4 (absent counts as match) is
// killed on two rows.
// =====================================================================
#[test]
fn e3b_absent_at_different_end_seq_also_emits_no_record() {
    let fx = two_checkpoints();
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .end(9, [0x33; 32])
        .build()
        .unwrap();
    let report = report_of(vec![fx.path], trust);
    let expected = vec![unlocated(
        K::TrailEnded,
        Some(9),
        format!("end=9:{BOUND_HASH_33_DIGEST}: no record at seq 9"),
    )];
    assert_findings(report.findings(), &expected, "E3b");
    assert!(!report.is_strict_valid(), "E3b strict fails: not exempt");
    assert_eq!(report.covered_through(), Some(2));
}

// =====================================================================
// E4 — ACCEPTANCE. The `end=` `seq` is forked: honest cp2 plus a
// shipped twin. Precedence (ruling 13-V5-d5): forked wins over
// hash, so the detail is `seq 2 is forked`, unlocated, plus the
// engine's `SeqConflict`.
// =====================================================================
#[test]
fn e4_forked_at_end_seq_emits_forked_and_seq_conflict() {
    let fx = two_checkpoints();
    let twin = signed_cp_explicit(2, fx.e1.hash(), 2, [0xde; 32], vec![[0x22; 32]]);
    let twin_path = fx._dir.0.join("cp2.twin");
    fs::write(&twin_path, line_bytes(&twin)).unwrap();
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .end(2, fx.cp2.hash())
        .build()
        .unwrap();
    let report = report_of(vec![fx.path.clone(), twin_path], trust);
    let expected = vec![
        unlocated(
            K::TrailEnded,
            Some(2),
            format!("end=2:{CP2_HONEST_DIGEST}: seq 2 is forked"),
        ),
        located(
            K::SeqConflict,
            fx.path,
            3,
            2,
            format!("conflicting hashes: {CP2_HONEST_DIGEST}, {CP2_TWIN_V6_DIGEST}"),
        ),
    ];
    assert_findings(report.findings(), &expected, "E4");
    assert!(!report.is_strict_valid(), "E4 strict fails on TrailEnded");
    assert_eq!(report.covered_through(), Some(2));
}

// =====================================================================
// E4b — ACCEPTANCE. Second forked-at-end-seq row at `seq=0`:
// pairs with E4 so mutant T3 (no fork check at s; first copy wins)
// is killed on two rows.
// =====================================================================
#[test]
fn e4b_forked_at_end_seq_zero_emits_forked_and_seq_conflict() {
    let d = Temp::new();
    let honest = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    put_segment(&d.0, 0, &[&honest], &[]);
    let native = segment_path(&d.0, 0);
    let twin = signed_cp_explicit(0, Record::genesis(&TRAIL), 0, [0xde; 32], vec![]);
    let twin_path = d.0.join("cp0.twin");
    fs::write(&twin_path, line_bytes(&twin)).unwrap();
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .end(0, honest.hash())
        .build()
        .unwrap();
    let report = report_of(vec![native.clone(), twin_path], trust);
    let expected = vec![
        unlocated(
            K::TrailEnded,
            Some(0),
            format!("end=0:{CP0_HONEST_DIGEST}: seq 0 is forked"),
        ),
        located(
            K::SeqConflict,
            native,
            1,
            0,
            format!("conflicting hashes: {CP0_TWIN_V6B_DIGEST}, {CP0_HONEST_DIGEST}"),
        ),
    ];
    assert_findings(report.findings(), &expected, "E4b");
    assert!(!report.is_strict_valid(), "E4b strict fails on TrailEnded");
    assert_eq!(report.covered_through(), Some(0));
}

// =====================================================================
// E5a — ACCEPTANCE (d11 l.930). Retired trail whose last writer
// crashed with `end=` on its last (non-checkpoint) record. Matched
// `end=` grants the tail exemption: `UncoveredTail` stays an info
// and `--strict` passes.
// =====================================================================
#[test]
fn e5a_retired_crashed_tail_with_matching_end_is_strict_valid() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    put_segment(&d.0, 0, &[&cp0, &e1], &[]);
    let path = segment_path(&d.0, 0);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .end(1, e1.hash())
        .build()
        .unwrap();
    let report = report_of(vec![path], trust);
    assert_findings(report.findings(), &[uncovered(1, 1)], "E5a");
    assert!(report.is_strict_valid(), "E5a strict passes: tail exempt");
    assert_eq!(report.covered_through(), Some(0));
}

// =====================================================================
// E5b — SEPARATE ROW. The same trail without `end=`: `UncoveredTail`
// is not exempt and `--strict` fails.
// =====================================================================
#[test]
fn e5b_retired_crashed_tail_without_end_is_not_strict_valid() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    put_segment(&d.0, 0, &[&cp0, &e1], &[]);
    let path = segment_path(&d.0, 0);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .build()
        .unwrap();
    let report = report_of(vec![path], trust);
    assert_findings(report.findings(), &[uncovered(1, 1)], "E5b");
    assert!(!report.is_strict_valid(), "E5b strict fails: not exempt");
    assert_eq!(report.covered_through(), Some(0));
}

// =====================================================================
// E6 — ACCEPTANCE (d11 l.931 "with `end=` at its last record and
// the key's bound at the same record, it verifies clean with no
// confirming checkpoint"). The matched `end=` confirms the bound at
// `s` on WORM storage.
// =====================================================================
#[test]
fn e6_end_and_bound_at_last_checkpoint_verifies_clean() {
    let fx = two_checkpoints();
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 2, fx.cp2.hash())
        .end(2, fx.cp2.hash())
        .build()
        .unwrap();
    let report = report_of(vec![fx.path], trust);
    assert_findings(report.findings(), &[], "E6");
    assert!(report.is_strict_valid(), "E6 strict passes: clean");
    assert_eq!(report.covered_through(), Some(2));
}

// =====================================================================
// E6b — ACCEPTANCE. Second `end=` and bound at the same last record,
// at `seq=0` instead of `seq=2`: pairs with E6 so mutant T8 (bound
// confirmation uses `<` instead of `<=`) is killed on two rows.
// =====================================================================
#[test]
fn e6b_end_and_bound_at_single_checkpoint_verifies_clean() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    put_segment(&d.0, 0, &[&cp0], &[]);
    let path = segment_path(&d.0, 0);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, cp0.hash())
        .end(0, cp0.hash())
        .build()
        .unwrap();
    let report = report_of(vec![path], trust);
    assert_findings(report.findings(), &[], "E6b");
    assert!(report.is_strict_valid(), "E6b strict passes: clean");
    assert_eq!(report.covered_through(), Some(0));
}

// =====================================================================
// E7 — ACCEPTANCE (d11 l.931 "with the bound at an earlier anchored
// checkpoint, the bound is confirmed and the old key's later
// checkpoints are `UntrustedKey`"). Matched `end=` confirms the
// bound; the old key's later checkpoints emit `UntrustedKey`.
// =====================================================================
#[test]
fn e7_bound_earlier_end_at_last_confirms_bound_and_flags_later_cps() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    let e3 = entry_rec(3, cp2.hash());
    let mmr3 = pushed(&mmr2, &e3);
    let cp4 = signed_cp(4, e3.hash(), &mmr3);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2, &e3, &cp4], &[]);
    let path = segment_path(&d.0, 0);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, cp0.hash())
        .end(4, cp4.hash())
        .build()
        .unwrap();
    let report = report_of(vec![path.clone()], trust);
    let expected = vec![
        located(
            K::UntrustedKey,
            path.clone(),
            3,
            2,
            format!("key {FIXTURE_KEY_HEX} bounded through seq 0"),
        ),
        located(
            K::UntrustedKey,
            path,
            5,
            4,
            format!("key {FIXTURE_KEY_HEX} bounded through seq 0"),
        ),
        uncovered(1, 4),
    ];
    assert_findings(report.findings(), &expected, "E7");
    assert!(!report.is_strict_valid(), "E7 strict fails: UntrustedKey");
    assert_eq!(report.covered_through(), Some(0));
}

// =====================================================================
// E8 — REGRESSION (d11 l.931 "without `end=`, the bound is
// `RevocationUnconfirmed`"). Same retired-trail layout as E7 but
// WITHOUT `end=` on `TRAIL` (the only live section with a bound).
// A foreign section carries an `end=` so mutant T11 (scope: use the
// first section's `end=`) applies that `end=` to `TRAIL` under the
// mutant, confirms the bound and drops `RevocationUnconfirmed` ---
// which kills T11. Base already reports `RevocationUnconfirmed` and
// the two `UntrustedKey` findings, so this is a regression row.
// =====================================================================
#[test]
fn e8_retired_trail_without_end_is_revocation_unconfirmed() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    let e3 = entry_rec(3, cp2.hash());
    let mmr3 = pushed(&mmr2, &e3);
    let cp4 = signed_cp(4, e3.hash(), &mmr3);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2, &e3, &cp4], &[]);
    let path = segment_path(&d.0, 0);
    let trust = TrustPolicy::builder()
        .trail(OTHER_TRAIL)
        .end(4, cp4.hash())
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, cp0.hash())
        .build()
        .unwrap();
    let report = report_on_trail(vec![path.clone()], trust, TRAIL);
    let expected = vec![
        located(
            K::RevocationUnconfirmed,
            path.clone(),
            1,
            0,
            format!(
                "key {FIXTURE_KEY_HEX} through=0: no trusted checkpoint by another key above the bound"
            ),
        ),
        located(
            K::UntrustedKey,
            path.clone(),
            3,
            2,
            format!("key {FIXTURE_KEY_HEX} bounded through seq 0"),
        ),
        located(
            K::UntrustedKey,
            path,
            5,
            4,
            format!("key {FIXTURE_KEY_HEX} bounded through seq 0"),
        ),
        uncovered(1, 4),
    ];
    assert_findings(report.findings(), &expected, "E8");
    assert!(!report.is_strict_valid(), "E8 strict fails");
    assert_eq!(report.covered_through(), Some(0));
}

// =====================================================================
// E9a — ACCEPTANCE (d11 l.973 "an attesting line in the uncovered
// tail of a retired trail whose `end=` matches it: `TornWriteRepaired`,
// because a matching `end=` pins it"). Crashed-tail layout
// `[cp0, frag, e1(repaired)]` with `end=1:e1.hash`: the matched
// `end=` promotes the attested gap to `TornWriteRepaired` and
// `--strict` passes.
// =====================================================================
#[test]
fn e9a_crashed_repair_with_matching_end_is_torn_write_repaired() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let gap = repair_digest(FRAG);
    let e1 = entry_with_repaired(1, cp0.hash(), gap);
    let mut bytes = line_bytes(&cp0);
    bytes.extend_from_slice(FRAG);
    bytes.extend_from_slice(&line_bytes(&e1));
    let path = segment_path(&d.0, 0);
    write_bytes(&path, &bytes);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .end(1, e1.hash())
        .build()
        .unwrap();
    let report = report_of(vec![path.clone()], trust);
    let expected = vec![
        located(
            K::TornWriteRepaired,
            path,
            2,
            1,
            format!(
                "lines 2..=2 ({len} bytes), attested at line 3 seq 1",
                len = FRAG.len()
            ),
        ),
        uncovered(1, 1),
    ];
    assert_findings(report.findings(), &expected, "E9a");
    assert!(report.is_strict_valid(), "E9a strict passes: tail exempt");
    assert_eq!(report.covered_through(), Some(0));
}

// =====================================================================
// E9b — SEPARATE ROW. Same layout as E9a without `end=`: the
// attested gap stays `TornWrite` (warning) and `--strict` fails.
// =====================================================================
#[test]
fn e9b_crashed_repair_without_end_stays_torn_write() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let gap = repair_digest(FRAG);
    let e1 = entry_with_repaired(1, cp0.hash(), gap);
    let mut bytes = line_bytes(&cp0);
    bytes.extend_from_slice(FRAG);
    bytes.extend_from_slice(&line_bytes(&e1));
    let path = segment_path(&d.0, 0);
    write_bytes(&path, &bytes);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .build()
        .unwrap();
    let report = report_of(vec![path.clone()], trust);
    let expected = vec![
        located(
            K::TornWrite,
            path,
            2,
            1,
            format!(
                "lines 2..=2 ({len} bytes), attested at line 3 seq 1",
                len = FRAG.len()
            ),
        ),
        uncovered(1, 1),
    ];
    assert_findings(report.findings(), &expected, "E9b");
    assert!(!report.is_strict_valid(), "E9b strict fails on TornWrite");
    assert_eq!(report.covered_through(), Some(0));
}

// =====================================================================
// E9c — ACCEPTANCE. Second matched-`end=` repair promotion with
// the attester at `seq == matched_end` but at a different `seq`,
// pairs with E9a so mutant T9 (repair promotion uses `<`) is killed
// on two rows.
// =====================================================================
#[test]
fn e9c_crashed_repair_at_seq_two_with_matching_end_is_torn_write_repaired() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    let gap = repair_digest(FRAG);
    let e2 = entry_with_repaired(2, e1.hash(), gap);
    let mut bytes = line_bytes(&cp0);
    bytes.extend_from_slice(&line_bytes(&e1));
    bytes.extend_from_slice(FRAG);
    bytes.extend_from_slice(&line_bytes(&e2));
    let path = segment_path(&d.0, 0);
    write_bytes(&path, &bytes);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .end(2, e2.hash())
        .build()
        .unwrap();
    let report = report_of(vec![path.clone()], trust);
    let expected = vec![
        located(
            K::TornWriteRepaired,
            path,
            3,
            2,
            format!(
                "lines 3..=3 ({len} bytes), attested at line 4 seq 2",
                len = FRAG.len()
            ),
        ),
        uncovered(1, 2),
    ];
    assert_findings(report.findings(), &expected, "E9c");
    assert!(report.is_strict_valid(), "E9c strict passes: tail exempt");
    assert_eq!(report.covered_through(), Some(0));
}

// =====================================================================
// E10 — ACCEPTANCE. Ruling 13-V5-d5 point 2: a mismatched `end=`
// (E1's wrong-hash layout) grants NONE of the three things. The
// expected list proves all three literally:
//  - `UncoveredTail` is present and not exempt (strict still fails);
//  - the bound at `seq <= s` emits `RevocationUnconfirmed`;
//  - the attested gap stays `TornWrite` (not `TornWriteRepaired`).
// =====================================================================
#[test]
fn e10_mismatched_end_grants_no_exemption_no_confirmation_no_promotion() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let gap = repair_digest(FRAG);
    let e1 = entry_with_repaired(1, cp0.hash(), gap);
    let mmr0 = seeded(&cp0);
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mut bytes = line_bytes(&cp0);
    bytes.extend_from_slice(FRAG);
    bytes.extend_from_slice(&line_bytes(&e1));
    bytes.extend_from_slice(&line_bytes(&cp2));
    let path = segment_path(&d.0, 0);
    write_bytes(&path, &bytes);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, cp0.hash())
        .end(2, [0x5a; 32])
        .build()
        .unwrap();
    let report = report_of(vec![path.clone()], trust);
    let expected = vec![
        located(
            K::RevocationUnconfirmed,
            path.clone(),
            1,
            0,
            format!(
                "key {FIXTURE_KEY_HEX} through=0: no trusted checkpoint by another key above the bound"
            ),
        ),
        located(
            K::TornWrite,
            path.clone(),
            2,
            1,
            format!(
                "lines 2..=2 ({len} bytes), attested at line 3 seq 1",
                len = FRAG.len()
            ),
        ),
        located(
            K::TrailEnded,
            path.clone(),
            4,
            2,
            format!("end=2:{BOUND_HASH_5A_DIGEST}: record at seq 2 has hash {CRASHED_CP2_DIGEST}"),
        ),
        located(
            K::UntrustedKey,
            path,
            4,
            2,
            format!("key {FIXTURE_KEY_HEX} bounded through seq 0"),
        ),
        uncovered(1, 2),
    ];
    assert_findings(report.findings(), &expected, "E10");
    assert!(!report.is_strict_valid(), "E10 strict fails: not exempt");
    assert_eq!(report.covered_through(), Some(0));
}

// =====================================================================
// E10b — ACCEPTANCE. Second mismatched-`end=` scenario where the
// MISMATCH is on the "above" side (records above the end) rather
// than the "at `s`" side. Pairs with E10 so mutants T6 (mismatched
// confirms bounds) and T7 (mismatched promotes repairs) are each
// killed on two rows. `end=1:e1.hash` matches at `s=1` but cp2 at
// seq=2 above makes the overall end= a MISMATCH.
// =====================================================================
#[test]
fn e10b_mismatched_above_end_grants_none_of_the_three() {
    let fx = crashed();
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, fx.cp0.hash())
        .end(1, fx.e1.hash())
        .build()
        .unwrap();
    let report = report_of(vec![fx.path.clone()], trust);
    let expected = vec![
        located(
            K::RevocationUnconfirmed,
            fx.path.clone(),
            1,
            0,
            format!(
                "key {FIXTURE_KEY_HEX} through=0: no trusted checkpoint by another key above the bound"
            ),
        ),
        located(
            K::TornWrite,
            fx.path.clone(),
            2,
            1,
            format!(
                "lines 2..=2 ({len} bytes), attested at line 3 seq 1",
                len = FRAG.len()
            ),
        ),
        located(
            K::TrailEnded,
            fx.path.clone(),
            4,
            2,
            format!("end=1:{CRASHED_E1_DIGEST}: records seq 2..=2 above the end"),
        ),
        located(
            K::UntrustedKey,
            fx.path,
            4,
            2,
            format!("key {FIXTURE_KEY_HEX} bounded through seq 0"),
        ),
        uncovered(1, 2),
    ];
    assert_findings(report.findings(), &expected, "E10b");
    assert!(!report.is_strict_valid(), "E10b strict fails: not exempt");
    assert_eq!(report.covered_through(), Some(0));
}

// =====================================================================
// E11 — ACCEPTANCE. Both conditions fail at once: a wrong hash at
// `s=2` AND records above `s=2`. Two independent `TrailEnded`
// findings fire. Pairs with E2 so mutant T12 (above location at
// last record) is killed on two rows.
// =====================================================================
#[test]
fn e11_both_conditions_fail_emits_two_trail_ended() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let e3 = entry_rec(3, cp2.hash());
    let e4 = entry_rec(4, e3.hash());
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2, &e3, &e4], &[]);
    let path = segment_path(&d.0, 0);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .end(2, [0x5a; 32])
        .build()
        .unwrap();
    let report = report_of(vec![path.clone()], trust);
    let expected = vec![
        located(
            K::TrailEnded,
            path.clone(),
            3,
            2,
            format!("end=2:{BOUND_HASH_5A_DIGEST}: record at seq 2 has hash {CP2_HONEST_DIGEST}"),
        ),
        located(
            K::TrailEnded,
            path,
            4,
            3,
            format!("end=2:{BOUND_HASH_5A_DIGEST}: records seq 3..=4 above the end"),
        ),
        uncovered(3, 4),
    ];
    assert_findings(report.findings(), &expected, "E11");
    assert!(!report.is_strict_valid(), "E11 strict fails on TrailEnded");
    assert_eq!(report.covered_through(), Some(2));
}

// =====================================================================
// E12 — REGRESSION. An `end=` ONLY in another trail's section is
// ignored on the verified trail. The verified trail includes a
// fragment-gap attester at `seq=1` and a torn-write target at
// `seq=2` (so under mutant T11, the foreign `end=2:cp2.hash` would
// apply to `TRAIL`, confirm the bound at `seq=0`, promote the
// attester, and exempt the tail --- three distinct finding-list
// changes). Base already reports the layout's `RevocationUnconfirmed`,
// `TornWrite` and `UncoveredTail`, so this is a regression row.
// =====================================================================
#[test]
fn e12_end_only_in_another_section_is_ignored() {
    let fx = crashed();
    let trust = TrustPolicy::builder()
        .trail(OTHER_TRAIL)
        .end(2, fx.cp2.hash())
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, fx.cp0.hash())
        .build()
        .unwrap();
    let report = report_on_trail(vec![fx.path.clone()], trust, TRAIL);
    let expected = vec![
        located(
            K::RevocationUnconfirmed,
            fx.path.clone(),
            1,
            0,
            format!(
                "key {FIXTURE_KEY_HEX} through=0: no trusted checkpoint by another key above the bound"
            ),
        ),
        located(
            K::TornWrite,
            fx.path.clone(),
            2,
            1,
            format!(
                "lines 2..=2 ({len} bytes), attested at line 3 seq 1",
                len = FRAG.len()
            ),
        ),
        located(
            K::UntrustedKey,
            fx.path,
            4,
            2,
            format!("key {FIXTURE_KEY_HEX} bounded through seq 0"),
        ),
        uncovered(1, 2),
    ];
    assert_findings(report.findings(), &expected, "E12");
    assert!(!report.is_strict_valid(), "E12 strict fails: not exempt");
    assert_eq!(report.covered_through(), Some(0));
}

// =====================================================================
// Fixture-hash consistency: every digest / key constant in the row
// details corresponds to the record the fixtures actually produce.
// =====================================================================
#[test]
fn fixture_hashes_match_literals() {
    assert_eq!(hex(&fixture_pubkey()), FIXTURE_KEY_HEX);
    assert_eq!(hex(&new_pubkey()), NEW_KEY_HEX);
    let fx = two_checkpoints();
    assert_eq!(digest_string(&fx.cp0.hash()), CP0_HONEST_DIGEST);
    assert_eq!(digest_string(&fx.e1.hash()), E1_HONEST_DIGEST);
    assert_eq!(digest_string(&fx.cp2.hash()), CP2_HONEST_DIGEST);
    let twin_v6 = signed_cp_explicit(2, fx.e1.hash(), 2, [0xde; 32], vec![[0x22; 32]]);
    assert_eq!(digest_string(&twin_v6.hash()), CP2_TWIN_V6_DIGEST);
    let twin_v6b = signed_cp_explicit(0, Record::genesis(&TRAIL), 0, [0xde; 32], vec![]);
    assert_eq!(digest_string(&twin_v6b.hash()), CP0_TWIN_V6B_DIGEST);
    assert_eq!(digest_string(&[0x5a; 32]), BOUND_HASH_5A_DIGEST);
    assert_eq!(digest_string(&[0x33; 32]), BOUND_HASH_33_DIGEST);
    assert_eq!(digest_string(&repair_digest(FRAG)), FRAG_DIGEST);
    let crashed = crashed();
    assert_eq!(digest_string(&crashed.cp0.hash()), CP0_HONEST_DIGEST);
    assert_eq!(digest_string(&crashed.e1.hash()), CRASHED_E1_DIGEST);
    assert_eq!(digest_string(&crashed.cp2.hash()), CRASHED_CP2_DIGEST);
    // Checkpoint-kind sanity: the fixture cp0 is a checkpoint, so
    // the `signed_cp` helper did not drift.
    assert!(matches!(fx.cp0.kind, Kind::Checkpoint(_)));
}
