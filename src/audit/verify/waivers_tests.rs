//! Rows for `Verifier::waive`, `Verifier::receipts_from` and
//! `ReceiptWaived` (ADR-0005 decision 5 "Waivers, for an honest
//! crash" and "Late adoption"; ruling 13-V7-d1 point 6). The
//! acceptance-row base is dev with the waiver and `from` values
//! stored by the builders but ignored by the engine; each row's
//! doc comment gives the first assertion that fails there. Row
//! standard is the receipts-tests one: every acceptance row ends
//! in one whole-list [`assert_findings`] (a thin wrapper around
//! `assert_eq!` on `Vec<Finding>`); every digest and hash in an
//! expected detail is a written-out hex constant pinned by
//! [`fixture_hashes_match_literals`]; regression rows are labelled
//! in their doc comments. Expected lists are in the engine's final
//! sort order (`(seq.is_none(), seq, file, line, kind_debug)`).
//!
//! Fixture style: wall-clock stamps on the real writer would drift
//! record hashes per run and the row literals with them, so these
//! rows build records through the same `signed_cp`, `entry_rec` and
//! `Record::new_internal` helpers the receipts rows use; receipts,
//! waivers and `from` inputs are `(seq, hash[, reason])` tuples
//! read off those records, so no real writer is needed.

use crate::audit::{
    AuditErrorKind, Entry, FindingKind as K, Mmr, Record, TrustPolicy, digest_string,
    runs_v4a_fixtures::{
        TRAIL, Temp, context, entry_rec, fixture_pubkey, pushed, put_segment, seeded, segment_path,
        signed_cp, signed_cp_explicit,
    },
    verify::{Finding, Report, Verifier},
};
use std::path::PathBuf;

// =====================================================================
// Shared literal hex constants (duplicated across the fixture-hash
// consistency check and the row literals so a fixture drift fails
// in one place rather than many).
// =====================================================================

/// `signed_cp(0, Record::genesis(&TRAIL), &Mmr::new())` -- the
/// honest seq=0 opening used by every single-segment row.
const CP0_HONEST_DIGEST: &str =
    "blake3:fc26c6f2bb830592aaaca5413da1599489d86ac6e240a4a7a010681e0d4c8e77";
/// `entry_rec(1, cp0.hash())`.
const E1_HONEST_DIGEST: &str =
    "blake3:c121282b5135adfe7a17142cae6bfc4c9040c4aed26d74bddc923b8dafcdb6e8";
/// `entry_rec(2, e1.hash())`.
const E2_HONEST_DIGEST: &str =
    "blake3:8a5ea9c989aad7e89033b58ad6f59a6384af43dfe6df5bada042420c0040c306";
/// `entry_rec(3, e2.hash())`.
const E3_HONEST_DIGEST: &str =
    "blake3:b378374409602bc24aa87765b3cc3361e3b647368f57d9a06816f9b2bd0696c9";
/// `signed_cp(3, e2.hash(), &mmr2)`.
const CP3_FROM_E2_DIGEST: &str =
    "blake3:dda83f7bbaaf877076831dd97e6563148bf337d350bc58cf8bc6e8802eed2f66";
/// `signed_cp(2, e1.hash(), &mmr1)` -- the honest cp2 used by the
/// fork row to chain the honest seq=1 to its closing checkpoint.
const CP2_HONEST_DIGEST: &str =
    "blake3:4164966a12a675e55eb6e133b9e50313907f164fe142d941447defcdfdb25d06";
/// `Record::new(context(1, cp0.hash()), Entry::new("actor", "change", "alt"))`
/// -- the alt-hash entry at seq=1 for the fork row.
const E1_ALT_DIGEST: &str =
    "blake3:125619e12e657407511645cac8c311f0d32ac0f97377eb1e45f9ca0217516a1e";
/// `signed_cp_explicit(2, e1_alt.hash(), 2, [0xee; 32], vec![[0xdd; 32]])`
/// -- the alt cp2 for the fork row.
const CP2_ALT_FROM_E1_ALT_DIGEST: &str =
    "blake3:8e56403afaf555ef2720aa4539cab56111fc744c51f0a9da44a1a5af04a3ff73";
/// A placeholder 32-byte hash for a wrong-hash scenario: `[0x5a; 32]`.
const WRONG_HASH_5A_DIGEST: &str =
    "blake3:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

const WRONG_HASH_5A: [u8; 32] = [0x5a; 32];

fn located(kind: K, file: PathBuf, line: u64, seq: u64, detail: String) -> Finding {
    Finding::new(kind, Some(file), Some(line), Some(seq), detail)
}
fn unlocated(kind: K, seq: Option<u64>, detail: String) -> Finding {
    Finding::new(kind, None, None, seq, detail)
}
#[track_caller]
fn assert_findings(actual: &[Finding], expected: &[Finding], label: &str) {
    assert_eq!(actual, expected, "{label} literal finding list");
}
fn trust_with_key(key: [u8; 32]) -> TrustPolicy {
    TrustPolicy::builder()
        .trail(TRAIL)
        .key(key)
        .build()
        .unwrap()
}
fn report_of(files: Vec<PathBuf>, verifier: Verifier) -> Report {
    verifier.verify_files(files).unwrap()
}
fn parse_cp(record: &Record) -> crate::audit::Checkpoint {
    let mut bytes = crate::audit::runs_v4a_fixtures::line_bytes(record);
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    crate::audit::Checkpoint::parse(std::str::from_utf8(&bytes).unwrap()).unwrap()
}

/// Four-record honest chain `[cp0, e1, e2, cp3]` sealed in one
/// segment. Retained for the rows that need `e1`/`e2`/`cp3` hashes.
struct FourRecord {
    _dir: Temp,
    path: PathBuf,
    e1: Record,
    e2: Record,
    cp3: Record,
}
fn four_record() -> FourRecord {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    let cp3 = signed_cp(3, e2.hash(), &mmr2);
    put_segment(&d.0, 0, &[&cp0, &e1, &e2, &cp3], &[]);
    let path = segment_path(&d.0, 0);
    FourRecord {
        _dir: d,
        path,
        e1,
        e2,
        cp3,
    }
}

// =====================================================================
// Shared literal-hex consistency test (fixture-drift catch-all).
// =====================================================================
#[test]
fn fixture_hashes_match_literals() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    let cp3 = signed_cp(3, e2.hash(), &mmr2);
    let e3 = entry_rec(3, e2.hash());
    let e1_alt = Record::new(context(1, cp0.hash()), Entry::new("actor", "change", "alt")).unwrap();
    let cp2_alt_from_e1_alt = signed_cp_explicit(2, e1_alt.hash(), 2, [0xee; 32], vec![[0xdd; 32]]);
    assert_eq!(digest_string(&cp0.hash()), CP0_HONEST_DIGEST, "cp0");
    assert_eq!(digest_string(&e1.hash()), E1_HONEST_DIGEST, "e1");
    assert_eq!(digest_string(&e2.hash()), E2_HONEST_DIGEST, "e2");
    assert_eq!(digest_string(&cp3.hash()), CP3_FROM_E2_DIGEST, "cp3");
    assert_eq!(digest_string(&e3.hash()), E3_HONEST_DIGEST, "e3");
    // cp2 chained from honest `e1` for the fork row's seq=2
    // SeqConflict.
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    assert_eq!(digest_string(&cp2.hash()), CP2_HONEST_DIGEST, "cp2");
    assert_eq!(digest_string(&e1_alt.hash()), E1_ALT_DIGEST, "e1_alt");
    assert_eq!(
        digest_string(&cp2_alt_from_e1_alt.hash()),
        CP2_ALT_FROM_E1_ALT_DIGEST,
        "cp2_alt_from_e1_alt"
    );
    assert_eq!(
        digest_string(&WRONG_HASH_5A),
        WRONG_HASH_5A_DIGEST,
        "wrong5a"
    );
}

// =====================================================================
// W1a (crash orphan, ADR l.922). REGRESSION. A record with no
// receipt gives `NoReceipt` as the baseline (reconciliation is on
// through the companion `.receipts(...)` call). Base: passes.
// =====================================================================
#[test]
fn w1a_record_without_receipt_or_waiver_is_no_receipt() {
    let fx = four_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash()), (3, fx.cp3.hash())]);
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![located(
        K::NoReceipt,
        fx.path,
        3,
        2,
        format!("no receipt for seq 2 hash {E2_HONEST_DIGEST}"),
    )];
    assert_findings(report.findings(), &expected, "w1a");
}

// =====================================================================
// W1b (crash orphan, ADR l.922). ACCEPTANCE. The same record now
// carries a matching `waive` naming its exact `(seq, hash)`: the
// result is one `ReceiptWaived` (info) at the record, no
// `NoReceipt` for it, and `is_strict_valid()` holds. First failing
// line on the stub base: the `assert_findings` (`NoReceipt` still
// fires because the waiver is ignored).
// =====================================================================
#[test]
fn w1b_waiver_matches_crash_orphan_strict_passes() {
    let fx = four_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash()), (3, fx.cp3.hash())])
        .waive(2, fx.e2.hash(), "orphan request id=42")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![located(
        K::ReceiptWaived,
        fx.path,
        3,
        2,
        format!("waived seq 2 hash {E2_HONEST_DIGEST}: orphan request id=42"),
    )];
    assert_findings(report.findings(), &expected, "w1b");
    assert!(report.is_strict_valid(), "w1b strict passes");
}

// =====================================================================
// W2 (ADR l.922). ACCEPTANCE. A waiver whose hash differs from the
// record at its `seq`: `ReceiptMismatch "waive seq ... hash differs
// (record ...)"` at `seq`, and the record still produces its
// ordinary `NoReceipt`. First failing line on the stub base: the
// `assert_findings` (the waiver is ignored so `ReceiptMismatch`
// never fires).
// =====================================================================
#[test]
fn w2_waiver_hash_differs_is_receipt_mismatch() {
    let fx = four_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash()), (3, fx.cp3.hash())])
        .waive(2, WRONG_HASH_5A, "orphan request id=42")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        unlocated(
            K::ReceiptMismatch,
            Some(2),
            format!(
                "waive seq 2 hash {WRONG_HASH_5A_DIGEST}: hash differs (record {E2_HONEST_DIGEST})"
            ),
        ),
        located(
            K::NoReceipt,
            fx.path,
            3,
            2,
            format!("no receipt for seq 2 hash {E2_HONEST_DIGEST}"),
        ),
    ];
    assert_findings(report.findings(), &expected, "w2");
}

// =====================================================================
// W3 (late adoption, ADR l.923). ACCEPTANCE. Records before the
// first receipt. A matching `from seq=2 hash=e2` emits one
// `ReceiptWaived` (info) at the record, records at or below `seq=2`
// are not reconciled (no `NoReceipt`), and strict passes. First
// failing line on the stub base: the `assert_findings` (the `from`
// is ignored so `NoReceipt` fires for e1).
// =====================================================================
#[test]
fn w3_receipts_from_matches_exempts_prefix_strict_passes() {
    let fx = four_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(3, fx.cp3.hash())])
        .receipts_from(2, fx.e2.hash(), "late adoption")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![located(
        K::ReceiptWaived,
        fx.path,
        3,
        2,
        format!("from seq 2 hash {E2_HONEST_DIGEST}: late adoption"),
    )];
    assert_findings(report.findings(), &expected, "w3");
    assert!(report.is_strict_valid(), "w3 strict passes");
}

// =====================================================================
// W4 (ADR l.923). ACCEPTANCE. A `from` line with a wrong hash:
// one `ReceiptMismatch` at `seq`, and because the mismatched `from`
// exempts nothing, records at or below `seq` keep their ordinary
// `NoReceipt`. First failing line on the stub base: the
// `assert_findings` (`ReceiptMismatch` never fires).
// =====================================================================
#[test]
fn w4_receipts_from_wrong_hash_is_receipt_mismatch_and_exempts_nothing() {
    let fx = four_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(3, fx.cp3.hash())])
        .receipts_from(2, WRONG_HASH_5A, "late adoption")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        located(
            K::NoReceipt,
            fx.path.clone(),
            2,
            1,
            format!("no receipt for seq 1 hash {E1_HONEST_DIGEST}"),
        ),
        unlocated(
            K::ReceiptMismatch,
            Some(2),
            format!(
                "from seq 2 hash {WRONG_HASH_5A_DIGEST}: hash differs (record {E2_HONEST_DIGEST})"
            ),
        ),
        located(
            K::NoReceipt,
            fx.path,
            3,
            2,
            format!("no receipt for seq 2 hash {E2_HONEST_DIGEST}"),
        ),
    ];
    assert_findings(report.findings(), &expected, "w4");
}

// =====================================================================
// W5. ACCEPTANCE. A waiver at a `seq` with no record: the match
// rule's first failing step is `no record`, so `ReceiptMismatch
// "waive seq ... no record"` fires. First failing line on the stub
// base: the `assert_findings` (no `ReceiptMismatch` fires).
// =====================================================================
#[test]
fn w5_waiver_at_seq_with_no_record_is_receipt_mismatch_no_record() {
    let fx = four_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash()), (2, fx.e2.hash()), (3, fx.cp3.hash())])
        .waive(42, WRONG_HASH_5A, "unknown orphan")
        .unwrap();
    let report = report_of(vec![fx.path], verifier);
    let expected = vec![unlocated(
        K::ReceiptMismatch,
        Some(42),
        format!("waive seq 42 hash {WRONG_HASH_5A_DIGEST}: no record"),
    )];
    assert_findings(report.findings(), &expected, "w5");
}

// =====================================================================
// W6 (clarification 13-V7-d1a point 1). ACCEPTANCE. A waiver at a
// forked `seq`: `ReceiptMismatch "waive seq ... seq is forked"`,
// plus `SeqConflict` at the fork and `NoReceipt` per distinct
// non-checkpoint copy. First failing line on the stub base: the
// `assert_findings` (no `ReceiptMismatch` fires).
// =====================================================================
#[test]
fn w6_waiver_at_forked_seq_is_forked_and_per_copy_no_receipt() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let e1_alt = Record::new(context(1, cp0.hash()), Entry::new("actor", "change", "alt")).unwrap();
    let cp2_alt = signed_cp_explicit(2, e1_alt.hash(), 2, [0xee; 32], vec![[0xdd; 32]]);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let seg0 = segment_path(&d.0, 0);
    put_segment(&d.0, 1, &[&cp0, &e1_alt, &cp2_alt], &[]);
    let seg1 = segment_path(&d.0, 1);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .waive(1, e1.hash(), "orphan")
        .unwrap();
    let report = report_of(vec![seg0.clone(), seg1.clone()], verifier);
    let expected = vec![
        located(
            K::DuplicateRecord,
            seg0.clone(),
            1,
            0,
            "2 copies of 1 distinct records".to_owned(),
        ),
        unlocated(
            K::ReceiptMismatch,
            Some(1),
            format!("waive seq 1 hash {E1_HONEST_DIGEST}: seq is forked"),
        ),
        located(
            K::NoReceipt,
            seg0.clone(),
            2,
            1,
            format!("no receipt for seq 1 hash {E1_HONEST_DIGEST}"),
        ),
        located(
            K::SeqConflict,
            seg0.clone(),
            2,
            1,
            format!("conflicting hashes: {E1_ALT_DIGEST}, {E1_HONEST_DIGEST}"),
        ),
        located(
            K::NoReceipt,
            seg1,
            2,
            1,
            format!("no receipt for seq 1 hash {E1_ALT_DIGEST}"),
        ),
        located(
            K::SeqConflict,
            seg0,
            3,
            2,
            format!("conflicting hashes: {CP2_HONEST_DIGEST}, {CP2_ALT_FROM_E1_ALT_DIGEST}"),
        ),
    ];
    drop(d);
    assert_findings(report.findings(), &expected, "w6");
}

// =====================================================================
// W7 (library half of ADR l.927; ruling 13-V7-d1 point 6). ACCEPTANCE.
// Builder validation split per check so each `InvalidConfig` case
// pins its own named row; the stub base, which stores the values
// without validating, fails at every `.unwrap_err()`.
// =====================================================================

/// A second `waive` for the same `seq` is `InvalidConfig`.
#[test]
fn w7_second_waive_same_seq_is_invalid_config() {
    let err = Verifier::new(trust_with_key(fixture_pubkey()))
        .waive(2, [0x11; 32], "first")
        .unwrap()
        .waive(2, [0x22; 32], "second")
        .unwrap_err();
    assert_eq!(err.kind(), AuditErrorKind::InvalidConfig);
}

/// A second `waive` for the same `seq` at a non-zero `seq`
/// different from the first row's, so the duplicate check runs
/// on more than one hard-coded `seq` value.
#[test]
fn w7_second_waive_same_seq_at_seq7_is_invalid_config() {
    let err = Verifier::new(trust_with_key(fixture_pubkey()))
        .waive(1, [0x11; 32], "first")
        .unwrap()
        .waive(7, [0x22; 32], "middle")
        .unwrap()
        .waive(7, [0x33; 32], "second at seq 7")
        .unwrap_err();
    assert_eq!(err.kind(), AuditErrorKind::InvalidConfig);
}

/// A second `receipts_from` is `InvalidConfig`.
#[test]
fn w7_second_receipts_from_is_invalid_config() {
    let err = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts_from(2, [0x11; 32], "first")
        .unwrap()
        .receipts_from(3, [0x22; 32], "second")
        .unwrap_err();
    assert_eq!(err.kind(), AuditErrorKind::InvalidConfig);
}

/// A second `receipts_from` with a matching `(seq, hash)` is still
/// `InvalidConfig` (the check is on prior presence, not on
/// contents).
#[test]
fn w7_second_receipts_from_same_values_is_invalid_config() {
    let err = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts_from(5, [0x11; 32], "first")
        .unwrap()
        .receipts_from(5, [0x11; 32], "copy")
        .unwrap_err();
    assert_eq!(err.kind(), AuditErrorKind::InvalidConfig);
}

/// `waive` with an empty reason is `InvalidConfig`.
#[test]
fn w7_waive_empty_reason_is_invalid_config() {
    let err = Verifier::new(trust_with_key(fixture_pubkey()))
        .waive(2, [0x11; 32], "")
        .unwrap_err();
    assert_eq!(err.kind(), AuditErrorKind::InvalidConfig);
}

/// `receipts_from` with an empty reason is `InvalidConfig`.
#[test]
fn w7_receipts_from_empty_reason_is_invalid_config() {
    let err = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts_from(2, [0x11; 32], "")
        .unwrap_err();
    assert_eq!(err.kind(), AuditErrorKind::InvalidConfig);
}

/// `waive` with an LF in the reason is `InvalidConfig`.
#[test]
fn w7_waive_reason_with_lf_is_invalid_config() {
    let err = Verifier::new(trust_with_key(fixture_pubkey()))
        .waive(2, [0x11; 32], "a\nb")
        .unwrap_err();
    assert_eq!(err.kind(), AuditErrorKind::InvalidConfig);
}

/// `receipts_from` with an LF in the reason is `InvalidConfig`.
#[test]
fn w7_receipts_from_reason_with_lf_is_invalid_config() {
    let err = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts_from(2, [0x11; 32], "a\nb")
        .unwrap_err();
    assert_eq!(err.kind(), AuditErrorKind::InvalidConfig);
}

/// `waive` with a CR in the reason is `InvalidConfig`.
#[test]
fn w7_waive_reason_with_cr_is_invalid_config() {
    let err = Verifier::new(trust_with_key(fixture_pubkey()))
        .waive(2, [0x11; 32], "a\rb")
        .unwrap_err();
    assert_eq!(err.kind(), AuditErrorKind::InvalidConfig);
}

/// `receipts_from` with a CR in the reason is `InvalidConfig`.
#[test]
fn w7_receipts_from_reason_with_cr_is_invalid_config() {
    let err = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts_from(2, [0x11; 32], "a\rb")
        .unwrap_err();
    assert_eq!(err.kind(), AuditErrorKind::InvalidConfig);
}

/// REGRESSION. Two receipts for one `seq` with different hashes
/// are accepted; `.receipts` never errors.
#[test]
fn w7_two_receipts_same_seq_different_hashes_are_not_invalid_config() {
    let _ = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(2, [0x11; 32]), (2, [0x33; 32])]);
}

/// Shared fixture: an anchored start at `cp2`, so file records
/// above seq=2 are in range and anything with `seq < 2` is below.
struct AnchoredStart {
    _dir: Temp,
    path: PathBuf,
    cp2_anchor: crate::audit::Checkpoint,
    e3_hash: [u8; 32],
}
fn anchored_start_from_cp2() -> AnchoredStart {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    let e3 = entry_rec(3, cp2.hash());
    let mmr3 = pushed(&mmr2, &e3);
    let cp4 = signed_cp(4, e3.hash(), &mmr3);
    let d = Temp::new();
    put_segment(&d.0, 0, &[&cp2, &e3, &cp4], &[]);
    let path = segment_path(&d.0, 0);
    AnchoredStart {
        _dir: d,
        path,
        cp2_anchor: parse_cp(&cp2),
        e3_hash: e3.hash(),
    }
}

// =====================================================================
// W8a. ACCEPTANCE. A waiver below an accepted anchored start is
// set aside through the shared position classifier as `OutOfRange`
// with its subject (ruling 13-V6-d3; ruling 13-V7-d1 point 6).
// First failing line on the stub base: the `assert_findings`
// (nothing is set aside).
// =====================================================================
#[test]
fn w8a_waiver_below_anchored_start_is_out_of_range() {
    let fx = anchored_start_from_cp2();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .anchor(fx.cp2_anchor.clone())
        .start_from(fx.cp2_anchor)
        .receipts([(3, fx.e3_hash)])
        .waive(0, WRONG_HASH_5A, "below start")
        .unwrap();
    let report = report_of(vec![fx.path], verifier);
    let expected = vec![unlocated(
        K::OutOfRange,
        Some(0),
        format!("waive seq 0 hash {WRONG_HASH_5A_DIGEST}: below start seq 2"),
    )];
    assert_findings(report.findings(), &expected, "w8a");
}

// =====================================================================
// W8b. ACCEPTANCE. A `from` below an accepted anchored start is
// also set aside as `OutOfRange` with its own subject. Pairs with
// W8a so the `below start` branch is covered for both subjects.
// First failing line on the stub base: the `assert_findings`.
// =====================================================================
#[test]
fn w8b_receipts_from_below_anchored_start_is_out_of_range() {
    let fx = anchored_start_from_cp2();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .anchor(fx.cp2_anchor.clone())
        .start_from(fx.cp2_anchor)
        .receipts([(3, fx.e3_hash)])
        .receipts_from(0, WRONG_HASH_5A, "below start")
        .unwrap();
    let report = report_of(vec![fx.path], verifier);
    let expected = vec![unlocated(
        K::OutOfRange,
        Some(0),
        format!("from seq 0 hash {WRONG_HASH_5A_DIGEST}: below start seq 2"),
    )];
    assert_findings(report.findings(), &expected, "w8b");
}

// =====================================================================
// W8c. ACCEPTANCE. Under an anchored `end_before` at seq=2 (so
// `E=2`), a waiver whose `seq` is strictly above `E` is set aside
// as `OutOfRange "above end seq 2"` (ruling 13-V6-d7; ruling
// 13-V7-d1 point 6). First failing line on the stub base: the
// `assert_findings`.
// =====================================================================
#[test]
fn w8c_waiver_above_anchored_end_is_out_of_range() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1], &[]);
    let path = segment_path(&d.0, 0);
    let archive = std::str::from_utf8(&crate::audit::runs_v4a_fixtures::line_bytes(&cp2))
        .unwrap()
        .trim_end()
        .to_owned();
    let end_anchor = parse_cp(&cp2);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .end_before(&archive, Some(end_anchor))
        .unwrap()
        .receipts([(1, e1.hash())])
        .waive(100, WRONG_HASH_5A, "above end")
        .unwrap();
    let report = report_of(vec![path], verifier);
    let expected = vec![unlocated(
        K::OutOfRange,
        Some(100),
        format!("waive seq 100 hash {WRONG_HASH_5A_DIGEST}: above end seq 2"),
    )];
    drop(d);
    assert_findings(report.findings(), &expected, "w8c");
}

// =====================================================================
// W9 (ruling 13-V7-d1 point 2). ACCEPTANCE. `waive` alone (no
// `.receipts(...)` call) turns reconciliation on, so every other
// in-range `audit.record` is `NoReceipt` while the waived one is
// `ReceiptWaived`. First failing line on the stub base: the
// `assert_findings` (nothing is reconciled because the stub's
// `receipt_inputs` is `None` when only waivers are set).
// =====================================================================
#[test]
fn w9_waive_alone_turns_reconciliation_on() {
    let fx = four_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .waive(2, fx.e2.hash(), "orphan")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        located(
            K::NoReceipt,
            fx.path.clone(),
            2,
            1,
            format!("no receipt for seq 1 hash {E1_HONEST_DIGEST}"),
        ),
        located(
            K::ReceiptWaived,
            fx.path,
            3,
            2,
            format!("waived seq 2 hash {E2_HONEST_DIGEST}: orphan"),
        ),
    ];
    assert_findings(report.findings(), &expected, "w9");
}

// =====================================================================
// W10. ACCEPTANCE pin. Both a matching receipt and a matching
// waiver name the same `(seq, hash)`. Decision 5 lets a receipt
// match any record (checkpoints or audit records) and treats a
// matched waiver as operator-attention info at the record; neither
// cancels the other. Literal outcome: one `ReceiptWaived` (info)
// at the record, no `NoReceipt` (the receipt match suppresses it),
// and `is_strict_valid()`. First failing line on the stub base:
// the `assert_findings` (the waiver is ignored so no
// `ReceiptWaived` fires).
// =====================================================================
#[test]
fn w10_waiver_and_receipt_same_record_both_apply() {
    let fx = four_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash()), (2, fx.e2.hash()), (3, fx.cp3.hash())])
        .waive(2, fx.e2.hash(), "belt and suspenders")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![located(
        K::ReceiptWaived,
        fx.path,
        3,
        2,
        format!("waived seq 2 hash {E2_HONEST_DIGEST}: belt and suspenders"),
    )];
    assert_findings(report.findings(), &expected, "w10");
    assert!(report.is_strict_valid(), "w10 strict passes");
}

// =====================================================================
// W1c. ACCEPTANCE. Second crash-orphan layout: the waived record
// sits at seq=1 (the first entry record) rather than at seq=2, so
// the `waived` detail's `seq` and record hash both differ from
// W1b, and the ReceiptWaived location moves to line 2. First
// failing line on the stub base: the `assert_findings` (the
// waiver is ignored so `NoReceipt` fires at seq=1 instead of
// `ReceiptWaived`).
// =====================================================================
#[test]
fn w1c_waiver_matches_earlier_record_strict_passes() {
    let fx = four_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(2, fx.e2.hash()), (3, fx.cp3.hash())])
        .waive(1, fx.e1.hash(), "orphan first record")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![located(
        K::ReceiptWaived,
        fx.path,
        2,
        1,
        format!("waived seq 1 hash {E1_HONEST_DIGEST}: orphan first record"),
    )];
    assert_findings(report.findings(), &expected, "w1c");
    assert!(report.is_strict_valid(), "w1c strict passes");
}

// =====================================================================
// W2b. ACCEPTANCE. Second wrong-hash-waiver layout at a different
// `seq` than W2: the waiver names seq=1 with a wrong hash, so the
// match rule's `hash differs` tail fires at seq=1 and the record
// at seq=1 still gets `NoReceipt` (the mismatched waiver does not
// suppress `NoReceipt`). Pairs with W2 on the hash-check behaviour
// at two distinct seqs. First failing line on the stub base: the
// `assert_findings` (`ReceiptMismatch` never fires because the
// stub ignores the waiver).
// =====================================================================
#[test]
fn w2b_waiver_hash_differs_at_earlier_seq_is_receipt_mismatch() {
    let fx = four_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(2, fx.e2.hash()), (3, fx.cp3.hash())])
        .waive(1, WRONG_HASH_5A, "orphan with wrong hash")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        unlocated(
            K::ReceiptMismatch,
            Some(1),
            format!(
                "waive seq 1 hash {WRONG_HASH_5A_DIGEST}: hash differs (record {E1_HONEST_DIGEST})"
            ),
        ),
        located(
            K::NoReceipt,
            fx.path,
            2,
            1,
            format!("no receipt for seq 1 hash {E1_HONEST_DIGEST}"),
        ),
    ];
    assert_findings(report.findings(), &expected, "w2b");
}

// =====================================================================
// W3b. ACCEPTANCE. Second late-adoption layout: `from` names
// seq=1 (one earlier than W3), so the `ReceiptWaived` detail's
// `seq` differs and only records at or below seq=1 are exempted.
// Pairs with W3 on the exemption boundary at two distinct cutoffs.
// First failing line on the stub base: the `assert_findings`
// (NoReceipt at seq=1 still fires).
// =====================================================================
#[test]
fn w3b_receipts_from_at_earlier_seq_exempts_only_up_to_there() {
    let fx = four_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(2, fx.e2.hash()), (3, fx.cp3.hash())])
        .receipts_from(1, fx.e1.hash(), "late adoption early")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![located(
        K::ReceiptWaived,
        fx.path,
        2,
        1,
        format!("from seq 1 hash {E1_HONEST_DIGEST}: late adoption early"),
    )];
    assert_findings(report.findings(), &expected, "w3b");
    assert!(report.is_strict_valid(), "w3b strict passes");
}

// =====================================================================
// W4b. ACCEPTANCE. Second mismatched-`from` layout: a `from` with
// a wrong hash at seq=1 fires `ReceiptMismatch "hash differs"`
// and, because a mismatched `from` exempts nothing, the ordinary
// `NoReceipt` loop still runs. Pairs with W4 on the "a mismatched
// `from` exempts nothing" behaviour at two distinct seqs. First
// failing line on the stub base: the `assert_findings`
// (`ReceiptMismatch` never fires).
// =====================================================================
#[test]
fn w4b_receipts_from_wrong_hash_at_earlier_seq_exempts_nothing() {
    let fx = four_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(2, fx.e2.hash()), (3, fx.cp3.hash())])
        .receipts_from(1, WRONG_HASH_5A, "late adoption wrong")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        unlocated(
            K::ReceiptMismatch,
            Some(1),
            format!(
                "from seq 1 hash {WRONG_HASH_5A_DIGEST}: hash differs (record {E1_HONEST_DIGEST})"
            ),
        ),
        located(
            K::NoReceipt,
            fx.path,
            2,
            1,
            format!("no receipt for seq 1 hash {E1_HONEST_DIGEST}"),
        ),
    ];
    assert_findings(report.findings(), &expected, "w4b");
}

// =====================================================================
// W9b. ACCEPTANCE. Second "`waive` alone turns reconciliation on"
// layout: waives seq=1 (the first entry) instead of seq=2, so the
// reconciled list differs from W9 (the waived record at seq=1 is
// `ReceiptWaived` and the record at seq=2 is `NoReceipt`). Pairs
// with W9 on the "`waive` turns reconciliation on" behaviour at
// two distinct seqs. First failing line on the stub base: the
// `assert_findings` (nothing is reconciled).
// =====================================================================
#[test]
fn w9b_waive_alone_at_earlier_seq_still_reconciles() {
    let fx = four_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .waive(1, fx.e1.hash(), "orphan first")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        located(
            K::ReceiptWaived,
            fx.path.clone(),
            2,
            1,
            format!("waived seq 1 hash {E1_HONEST_DIGEST}: orphan first"),
        ),
        located(
            K::NoReceipt,
            fx.path,
            3,
            2,
            format!("no receipt for seq 2 hash {E2_HONEST_DIGEST}"),
        ),
    ];
    assert_findings(report.findings(), &expected, "w9b");
}
