//! Rows for the verifier's live-mode receipt reconciliation
//! (ADR-0005 decision 5 "Live trails"; ruling 13-V7-d1 point 10).
//!
//! Row standard (repo-wide): every acceptance row asserts the FULL
//! sorted literal finding list as whole [`Finding`] values through
//! [`assert_findings`] (a thin wrapper around `assert_eq!` on
//! `Vec<Finding>`). Regression rows are labelled in their doc
//! comments. Every digest in an expected detail is a written-out
//! hex constant pinned by [`fixture_hashes_match_literals`].
//! Expected lists are written in the engine's final sort order
//! (`(seq.is_none(), seq, file, line, kind_debug)`), so no per-row
//! sort runs here.

use super::tests_common::{
    assert_findings, located, parse_cp, report_of, trust_with_key, unlocated,
};
use crate::audit::{
    AuditErrorKind, FindingKind as K, Mmr, Record, digest_string,
    runs_v4a_fixtures::{
        TRAIL, Temp, entry_rec, fixture_pubkey, pushed, put_segment, seeded, segment_path,
        signed_cp,
    },
    verify::Verifier,
};
use std::path::PathBuf;

// =====================================================================
// Shared literal hex constants. Pinned by `fixture_hashes_match_literals`.
// =====================================================================

/// `signed_cp(0, Record::genesis(&TRAIL), &Mmr::new())`.
const CP0_HONEST_DIGEST: &str =
    "blake3:fc26c6f2bb830592aaaca5413da1599489d86ac6e240a4a7a010681e0d4c8e77";
/// `entry_rec(1, cp0.hash())`.
const E1_HONEST_DIGEST: &str =
    "blake3:c121282b5135adfe7a17142cae6bfc4c9040c4aed26d74bddc923b8dafcdb6e8";
/// `signed_cp(2, e1.hash(), &mmr1)`.
const CP2_HONEST_DIGEST: &str =
    "blake3:4164966a12a675e55eb6e133b9e50313907f164fe142d941447defcdfdb25d06";
/// `entry_rec(2, e1.hash())` -- an entry record at seq=2 chained to e1.
const E2_HONEST_DIGEST: &str =
    "blake3:8a5ea9c989aad7e89033b58ad6f59a6384af43dfe6df5bada042420c0040c306";
/// `signed_cp(3, e2.hash(), &mmr2)` after the three-record chain.
const CP3_FROM_E2_DIGEST: &str =
    "blake3:dda83f7bbaaf877076831dd97e6563148bf337d350bc58cf8bc6e8802eed2f66";
/// `entry_rec(3, e2.hash())` -- an entry record at seq=3 chained to e2.
const E3_FROM_E2_DIGEST: &str =
    "blake3:b378374409602bc24aa87765b3cc3361e3b647368f57d9a06816f9b2bd0696c9";
/// `signed_cp(4, e3.hash(), &mmr3)` after the four-record chain.
const CP4_FROM_E3_DIGEST: &str =
    "blake3:e1d62ae3be94079ce6b6e664b4d225fc764033173ce51b446fc8c38f86778810";
/// `entry_rec(4, cp3.hash())` -- the "writer B" entry on the
/// six-record chain `[cp0, e1, e2, cp3, e4, cp5]`.
const E4_FROM_CP3_DIGEST: &str =
    "blake3:c0d53ffca7d1358ec842a15694a00833b408e2a6d43f49f2f1de7225fabba4e6";
/// `signed_cp(5, e4.hash(), &mmr4)` after the six-record chain.
const CP5_FROM_E4_DIGEST: &str =
    "blake3:8c2a212152faa447de5f329dc79b90a503eec4ec0f18cfb9b6717a749d6a4cd0";
/// Placeholder 32-byte hashes for the "wrong hash" / "above head"
/// receipts (ruling 13-V7-d1 point 4's `ReceiptMismatch` fallback).
const WRONG_HASH_5A: [u8; 32] = [0x5a; 32];
const WRONG_HASH_5A_DIGEST: &str =
    "blake3:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
const WRONG_HASH_66: [u8; 32] = [0x66; 32];
const WRONG_HASH_66_DIGEST: &str =
    "blake3:6666666666666666666666666666666666666666666666666666666666666666";

// =====================================================================
// Fixture chains. Each builds a single sealed segment on a fresh
// temp dir and hands back the records so a row can read their
// hashes.
// =====================================================================

/// Five-record chain `[cp0, e1, e2, e3, cp4]`: an entry run after
/// the genesis checkpoint closed by `cp4`. The closing checkpoint
/// keeps `UncoveredTail` out of every row below without any extra
/// knob.
struct FiveRecord {
    _dir: Temp,
    path: PathBuf,
    e1: Record,
    e2: Record,
    e3: Record,
}
fn five_record() -> FiveRecord {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    let e3 = entry_rec(3, e2.hash());
    let mmr3 = pushed(&mmr2, &e3);
    let cp4 = signed_cp(4, e3.hash(), &mmr3);
    let d = Temp::new();
    put_segment(&d.0, 0, &[&cp0, &e1, &e2, &e3, &cp4], &[]);
    let path = segment_path(&d.0, 0);
    FiveRecord {
        _dir: d,
        path,
        e1,
        e2,
        e3,
    }
}

/// Three-record chain `[cp0, e1, cp2]`: an entry closed by the next
/// checkpoint. Used by L6 (checkpoint just after the highest
/// receipt).
struct ThreeRecord {
    _dir: Temp,
    path: PathBuf,
    e1: Record,
    cp2: Record,
}
fn three_record() -> ThreeRecord {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let d = Temp::new();
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let path = segment_path(&d.0, 0);
    ThreeRecord {
        _dir: d,
        path,
        e1,
        cp2,
    }
}

/// Four-record chain `[cp0, e1, cp2, e2]` where the entry at seq=2
/// forks against the checkpoint at seq=2... no, better: the
/// receipted-two-checkpoints chain `[cp0, e1, cp2, e3, cp4]` with
/// two closing checkpoints. Used by L5 (every audit.record
/// receipted) to exercise the "checkpoints never break the prefix"
/// rule through a mid-chain checkpoint.
struct ReceiptedChain {
    _dir: Temp,
    path: PathBuf,
    e1: Record,
    e3: Record,
    cp4: Record,
}
fn receipted_chain() -> ReceiptedChain {
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
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2, &e3, &cp4], &[]);
    let path = segment_path(&d.0, 0);
    ReceiptedChain {
        _dir: d,
        path,
        e1,
        e3,
        cp4,
    }
}

/// Six-record chain `[cp0, e1, e2, cp3, e4, cp5]` for the
/// waiver-and-`from` row (L7). The intermediate `cp3` closes the
/// run opened by cp0 so no `UncoveredTail` fires and so a mid-chain
/// checkpoint sits above the waiver and below the closing one.
struct SixRecord {
    _dir: Temp,
    path: PathBuf,
    e1: Record,
    e2: Record,
    cp3: Record,
    e4: Record,
    cp5: Record,
}
fn six_record() -> SixRecord {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    let cp3 = signed_cp(3, e2.hash(), &mmr2);
    let mmr3 = pushed(&mmr2, &cp3);
    let e4 = entry_rec(4, cp3.hash());
    let mmr4 = pushed(&mmr3, &e4);
    let cp5 = signed_cp(5, e4.hash(), &mmr4);
    let d = Temp::new();
    put_segment(&d.0, 0, &[&cp0, &e1, &e2, &cp3, &e4, &cp5], &[]);
    let path = segment_path(&d.0, 0);
    SixRecord {
        _dir: d,
        path,
        e1,
        e2,
        cp3,
        e4,
        cp5,
    }
}

// =====================================================================
// Shared literal-hex consistency test.
// =====================================================================
#[test]
fn fixture_hashes_match_literals() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &e1);
    let _ = mmr2;
    let e2 = entry_rec(2, e1.hash());
    let mmr2_e = pushed(&mmr1, &e2);
    let cp3 = signed_cp(3, e2.hash(), &mmr2_e);
    let e3 = entry_rec(3, e2.hash());
    let mmr3 = pushed(&mmr2_e, &e3);
    let cp4 = signed_cp(4, e3.hash(), &mmr3);
    let mmr_cp3 = pushed(&mmr2_e, &cp3);
    let e4 = entry_rec(4, cp3.hash());
    let mmr4 = pushed(&mmr_cp3, &e4);
    let cp5 = signed_cp(5, e4.hash(), &mmr4);
    assert_eq!(digest_string(&cp0.hash()), CP0_HONEST_DIGEST, "cp0");
    assert_eq!(digest_string(&e1.hash()), E1_HONEST_DIGEST, "e1");
    assert_eq!(digest_string(&cp2.hash()), CP2_HONEST_DIGEST, "cp2");
    assert_eq!(digest_string(&e2.hash()), E2_HONEST_DIGEST, "e2");
    assert_eq!(digest_string(&cp3.hash()), CP3_FROM_E2_DIGEST, "cp3");
    assert_eq!(digest_string(&e3.hash()), E3_FROM_E2_DIGEST, "e3");
    assert_eq!(digest_string(&cp4.hash()), CP4_FROM_E3_DIGEST, "cp4");
    assert_eq!(digest_string(&e4.hash()), E4_FROM_CP3_DIGEST, "e4");
    assert_eq!(digest_string(&cp5.hash()), CP5_FROM_E4_DIGEST, "cp5");
    assert_eq!(
        digest_string(&WRONG_HASH_5A),
        WRONG_HASH_5A_DIGEST,
        "wrong5a"
    );
    assert_eq!(
        digest_string(&WRONG_HASH_66),
        WRONG_HASH_66_DIGEST,
        "wrong66"
    );
}

// =====================================================================
// L1a -- ACCEPTANCE. Stopped-mode baseline: the five-record chain
// `[cp0, e1, e2, e3, cp4]` with the application having stored only
// `e1`'s receipt reports `NoReceipt` for every unreceipted record
// (ADR-0005 decision 5 l.925; ruling 13-V7-d1 point 3). This row is
// the base against which every live-mode row below is measured.
// =====================================================================
#[test]
fn l1a_records_after_export_stopped_mode_each_no_receipt() {
    let fx = five_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([(1, fx.e1.hash())]);
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        located(
            K::NoReceipt,
            fx.path.clone(),
            3,
            2,
            format!("no receipt for seq 2 hash {E2_HONEST_DIGEST}"),
        ),
        located(
            K::NoReceipt,
            fx.path,
            4,
            3,
            format!("no receipt for seq 3 hash {E3_FROM_E2_DIGEST}"),
        ),
    ];
    assert_findings(report.findings(), &expected, "l1a stopped");
}

// =====================================================================
// L1b -- ACCEPTANCE. Live mode on the same scenario: one
// `Unreconciled` at the first record above the cut (`e2`), the
// detail names the cut-to-head seq range, and no `NoReceipt` fires
// (ADR-0005 decision 5 "Live trails"; ruling 13-V7-d1 point 10).
// The cut is `min(first unreconciled = 2, highest receipt + 1 = 2)
// = 2`; the head is the highest in-range seq, 4.
// =====================================================================
#[test]
fn l1b_records_after_export_live_mode_one_unreconciled() {
    let fx = five_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash())])
        .receipts_live(true)
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![located(
        K::Unreconciled,
        fx.path,
        3,
        2,
        "records seq 2..=4 not reconciled".to_owned(),
    )];
    assert_findings(report.findings(), &expected, "l1b live one unreconciled");
}

// =====================================================================
// L1c -- ACCEPTANCE. The strict-mode outcome of L1b: `is_valid()`
// stays `true` (Unreconciled is info) but `is_strict_valid()` is
// `false`, so `--strict` exits 1 and the default `verify` exits 0
// (ADR-0005 decision 5 "Live trails"; ruling 13-V7-d1 point 10).
// =====================================================================
#[test]
fn l1c_live_mode_strict_outcome_pinned() {
    let fx = five_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash())])
        .receipts_live(true)
        .unwrap();
    let report = report_of(vec![fx.path], verifier);
    assert!(report.is_valid(), "l1c is_valid");
    assert!(!report.is_strict_valid(), "l1c !is_strict_valid");
}

// =====================================================================
// L1d -- ACCEPTANCE. Live mode plus a receipt above the head: the
// receipt-above-the-head still gives `ReceiptMismatch "no record"`
// (ADR-0005 decision 5 "Live trails" bullet 2; ruling 13-V7-d1
// point 10 "receipts above the cut are still checked"). The usual
// `Unreconciled` for the unreceipted tail runs alongside it.
// =====================================================================
#[test]
fn l1d_live_mode_receipt_above_head_still_mismatch() {
    let fx = five_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash()), (10, WRONG_HASH_5A)])
        .receipts_live(true)
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        located(
            K::Unreconciled,
            fx.path,
            3,
            2,
            "records seq 2..=4 not reconciled".to_owned(),
        ),
        unlocated(
            K::ReceiptMismatch,
            Some(10),
            format!("receipt seq 10 hash {WRONG_HASH_5A_DIGEST}: no record"),
        ),
    ];
    assert_findings(report.findings(), &expected, "l1d receipt above head");
}

// =====================================================================
// L1e -- ACCEPTANCE. A wrong-hash receipt between the reconciled
// prefix and the head is still `ReceiptMismatch "hash differs"` in
// live mode (ADR-0005 decision 5 "Live trails" bullet 2; ruling
// 13-V7-d1 point 10). The unreceipted tail collapses to one
// `Unreconciled` at the first record above the cut, so the record
// named by the wrong-hash receipt carries no `NoReceipt`.
// =====================================================================
#[test]
fn l1e_live_mode_wrong_hash_between_prefix_and_head_mismatch() {
    let fx = five_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash()), (3, WRONG_HASH_66)])
        .receipts_live(true)
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        located(
            K::Unreconciled,
            fx.path,
            3,
            2,
            "records seq 2..=4 not reconciled".to_owned(),
        ),
        unlocated(
            K::ReceiptMismatch,
            Some(3),
            format!(
                "receipt seq 3 hash {WRONG_HASH_66_DIGEST}: hash differs (record {E3_FROM_E2_DIGEST})"
            ),
        ),
    ];
    assert_findings(report.findings(), &expected, "l1e wrong hash between");
}

// =====================================================================
// L2 -- ACCEPTANCE. An in-flight record below the highest receipt:
// writer A's receipt is not stored, writer B's is. Live mode
// reports one `Unreconciled` starting at A's `seq` (ADR-0005
// decision 5 l.926; ruling 13-V7-d1 point 10). The cut is `min(1,
// hr + 1 = 3) = 1`.
// =====================================================================
#[test]
fn l2_inflight_below_highest_receipt_unreconciled_from_a() {
    let fx = five_record();
    // A is e1 (seq=1, no receipt), B is e2 (seq=2, receipt stored).
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(2, fx.e2.hash())])
        .receipts_live(true)
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![located(
        K::Unreconciled,
        fx.path,
        2,
        1,
        "records seq 1..=4 not reconciled".to_owned(),
    )];
    assert_findings(report.findings(), &expected, "l2 inflight below highest");
}

// =====================================================================
// L3 -- ACCEPTANCE (two sub-rows). A hole that stays open across
// later receipts: the receipts for `e2` and `e3` are stored but
// `e1`'s is not. Without live mode, `e1` is `NoReceipt`; with live
// mode, one `Unreconciled` keeps starting at `e1`'s `seq` (ADR-0005
// decision 5 l.926; ruling 13-V7-d1 point 10). The live-mode row
// also pins that the record list collapses to ONE `Unreconciled`
// no matter how many records sit above the cut.
// =====================================================================
#[test]
fn l3_stopped_hole_persists_as_no_receipt() {
    let fx = five_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(2, fx.e2.hash()), (3, fx.e3.hash())]);
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![located(
        K::NoReceipt,
        fx.path,
        2,
        1,
        format!("no receipt for seq 1 hash {E1_HONEST_DIGEST}"),
    )];
    assert_findings(report.findings(), &expected, "l3 stopped hole");
}
#[test]
fn l3_live_hole_persists_as_unreconciled_from_same_seq() {
    let fx = five_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(2, fx.e2.hash()), (3, fx.e3.hash())])
        .receipts_live(true)
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![located(
        K::Unreconciled,
        fx.path,
        2,
        1,
        "records seq 1..=4 not reconciled".to_owned(),
    )];
    assert_findings(report.findings(), &expected, "l3 live hole");
}

// =====================================================================
// L4 -- ACCEPTANCE. Live mode with no receipts gives everything
// `Unreconciled`, starting at the range's first record (ADR-0005
// decision 5 "Live trails"; ruling 13-V7-d1 point 10's "with no
// receipts at all it is the first record of the range"). The
// detail covers the full `0..=head` span and no `NoReceipt` fires.
// =====================================================================
#[test]
fn l4_live_no_receipts_everything_unreconciled_from_first() {
    let fx = five_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts_live(true)
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![located(
        K::Unreconciled,
        fx.path,
        1,
        0,
        "records seq 0..=4 not reconciled".to_owned(),
    )];
    assert_findings(report.findings(), &expected, "l4 live no receipts");
}

// =====================================================================
// L5 -- ACCEPTANCE. Live mode with every `audit.record` receipted
// and the intermediate `cp2` carrying NO receipt gives an empty
// finding list: checkpoints need no receipt and never break the
// prefix (ADR-0005 decision 5 "Live trails"; ruling 13-V7-d1
// points 5 and 10). The cut caps at `highest receipt + 1 = 4`, the
// head is 4, so nothing sits above the cut.
// =====================================================================
#[test]
fn l5_live_all_records_receipted_middle_checkpoint_no_unreconciled() {
    let fx = receipted_chain();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([
            (1, fx.e1.hash()),
            (3, fx.e3.hash()),
            // cp4 is a checkpoint -- it needs no receipt -- but
            // naming it anyway also exercises that `highest_receipt`
            // includes checkpoint receipts (decision 5 l.397).
            (4, fx.cp4.hash()),
        ])
        .receipts_live(true)
        .unwrap();
    let report = report_of(vec![fx.path], verifier);
    assert_findings(report.findings(), &[], "l5 all receipted");
}

// =====================================================================
// L6 -- ACCEPTANCE. A checkpoint just after the highest receipt,
// with no receipt for the checkpoint, gives one `Unreconciled`
// located at that checkpoint (ADR-0005 decision 5 "Live trails" --
// "never above the highest receipt"; ruling 13-V7-d1 point 10).
// The cap caps the cut at `highest receipt + 1 = 2`; without the
// cap, the prefix would run through the checkpoint and no
// `Unreconciled` would fire.
// =====================================================================
#[test]
fn l6_live_checkpoint_just_above_highest_receipt_unreconciled_at_cp() {
    let fx = three_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash())])
        .receipts_live(true)
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![located(
        K::Unreconciled,
        fx.path,
        3,
        2,
        "records seq 2..=2 not reconciled".to_owned(),
    )];
    let _cp2 = fx.cp2; // silence unused if the path/line already pin it.
    assert_findings(report.findings(), &expected, "l6 checkpoint above highest");
}

// =====================================================================
// L7 -- ACCEPTANCE. A matched `receipts_from` and a matched
// `waive` both count as reconciled for the prefix, so the prefix
// extends through them to the cap at `highest receipt + 1 = 5`
// (ADR-0005 decision 5 "Live trails" with "Waivers" and "Late
// adoption"; ruling 13-V7-d1 points 6 and 10). The intermediate
// `cp3` carries no receipt but does not break the prefix
// (checkpoints never do), and the unreceipted closing `cp5` is
// the first record above the cut.
// =====================================================================
#[test]
fn l7_waived_and_matched_from_count_as_reconciled_for_prefix() {
    let fx = six_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts_from(1, fx.e1.hash(), "late adoption")
        .unwrap()
        .waive(2, fx.e2.hash(), "orphan")
        .unwrap()
        .receipts([(4, fx.e4.hash())])
        .receipts_live(true)
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        located(
            K::ReceiptWaived,
            fx.path.clone(),
            2,
            1,
            format!("from seq 1 hash {E1_HONEST_DIGEST}: late adoption"),
        ),
        located(
            K::ReceiptWaived,
            fx.path.clone(),
            3,
            2,
            format!("waived seq 2 hash {E2_HONEST_DIGEST}: orphan"),
        ),
        located(
            K::Unreconciled,
            fx.path,
            6,
            5,
            "records seq 5..=5 not reconciled".to_owned(),
        ),
    ];
    let _ = fx.cp3;
    let _ = fx.cp5;
    assert_findings(report.findings(), &expected, "l7 waived+from");
}

// =====================================================================
// L7b -- ACCEPTANCE. A matched `waive` alone extends the
// reconciled prefix across its record even when no `receipts_from`
// is given (ADR-0005 decision 5 "Live trails" with "Waivers";
// ruling 13-V7-d1 points 6 and 10). The cap at `highest receipt +
// 1 = 5` lands the cut at 5, so the unreceipted closing `cp5` is
// the first record above the cut, exactly as in L7 -- the paired
// row with `from` -- but through the waiver's single-record
// exemption instead.
// =====================================================================
#[test]
fn l7b_waived_record_counts_as_reconciled_for_prefix() {
    let fx = six_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .waive(2, fx.e2.hash(), "orphan")
        .unwrap()
        .receipts([(1, fx.e1.hash()), (4, fx.e4.hash())])
        .receipts_live(true)
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        located(
            K::ReceiptWaived,
            fx.path.clone(),
            3,
            2,
            format!("waived seq 2 hash {E2_HONEST_DIGEST}: orphan"),
        ),
        located(
            K::Unreconciled,
            fx.path,
            6,
            5,
            "records seq 5..=5 not reconciled".to_owned(),
        ),
    ];
    let _ = fx.cp3;
    let _ = fx.cp5;
    assert_findings(report.findings(), &expected, "l7b waive alone");
}

// =====================================================================
// L8 -- ACCEPTANCE. The conflict between `receipts_live(true)` and
// `end_before` in both call orders, raised by whichever call comes
// second (ADR-0005 §19.2; ruling 13-V7-d1 point 10). Exact wording
// mirrors the `max_age` pattern (ruling 13-V6-d4 point 7): each
// side spells its own name first, then "conflicts with" and the
// other side's name.
// =====================================================================
#[test]
fn l8a_receipts_live_true_then_end_before_errors() {
    let fx = three_record();
    let cp2_line = line_without_lf(&fx.cp2);
    let v = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts_live(true)
        .unwrap();
    match v.end_before(&cp2_line, None) {
        Ok(_) => panic!("l8a expected InvalidConfig, got Ok"),
        Err(e) => {
            assert_eq!(e.kind(), AuditErrorKind::InvalidConfig, "l8a kind");
            assert!(
                e.to_string()
                    .contains("end_before conflicts with receipts_live"),
                "l8a message: {e}",
            );
        }
    }
}
#[test]
fn l8b_end_before_then_receipts_live_true_errors() {
    let fx = three_record();
    let cp2_line = line_without_lf(&fx.cp2);
    let v = Verifier::new(trust_with_key(fixture_pubkey()))
        .end_before(&cp2_line, None)
        .unwrap();
    match v.receipts_live(true) {
        Ok(_) => panic!("l8b expected InvalidConfig, got Ok"),
        Err(e) => {
            assert_eq!(e.kind(), AuditErrorKind::InvalidConfig, "l8b kind");
            assert!(
                e.to_string()
                    .contains("receipts_live conflicts with end_before"),
                "l8b message: {e}",
            );
        }
    }
}
// ADR-0005 §19.2 and ruling 13-V7-d1 point 10 single out
// `receipts_live(true)` in the conflict; the stopped-mode default
// `receipts_live(false)` is not a conflict, so the builder accepts
// both call orders.
#[test]
fn l8c_receipts_live_false_with_end_before_both_orders_ok() {
    let fx = three_record();
    let cp2_line = line_without_lf(&fx.cp2);
    assert!(
        Verifier::new(trust_with_key(fixture_pubkey()))
            .receipts_live(false)
            .unwrap()
            .end_before(&cp2_line, None)
            .is_ok(),
        "l8c receipts_live(false) then end_before",
    );
    assert!(
        Verifier::new(trust_with_key(fixture_pubkey()))
            .end_before(&cp2_line, None)
            .unwrap()
            .receipts_live(false)
            .is_ok(),
        "l8c end_before then receipts_live(false)",
    );
}

// =====================================================================
// L9 -- ACCEPTANCE (two sub-rows). A second `receipts_live` call
// replaces the first's stored flag (ruling 13-V7-d1 point 10). The
// row verifies both directions end-to-end: after
// `receipts_live(true).receipts_live(false)` the verifier runs in
// stopped mode (`NoReceipt`), and after
// `receipts_live(false).receipts_live(true)` it runs in live mode
// (one `Unreconciled`).
// =====================================================================
#[test]
fn l9_second_receipts_live_true_then_false_runs_stopped_mode() {
    let fx = five_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash())])
        .receipts_live(true)
        .unwrap()
        .receipts_live(false)
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        located(
            K::NoReceipt,
            fx.path.clone(),
            3,
            2,
            format!("no receipt for seq 2 hash {E2_HONEST_DIGEST}"),
        ),
        located(
            K::NoReceipt,
            fx.path,
            4,
            3,
            format!("no receipt for seq 3 hash {E3_FROM_E2_DIGEST}"),
        ),
    ];
    assert_findings(report.findings(), &expected, "l9 replace true then false");
}
#[test]
fn l9_second_receipts_live_false_then_true_runs_live_mode() {
    let fx = five_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash())])
        .receipts_live(false)
        .unwrap()
        .receipts_live(true)
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![located(
        K::Unreconciled,
        fx.path,
        3,
        2,
        "records seq 2..=4 not reconciled".to_owned(),
    )];
    assert_findings(report.findings(), &expected, "l9 replace false then true");
}

// =====================================================================
// L10 -- ACCEPTANCE. An accepted `start_from` moves the first
// in-range record to the start's `seq`, so the live-mode prefix
// starts at the start (ADR-0005 decision 11 `.start_from`; ruling
// 13-V7-d1 point 10's reading of the reconciled range, the one
// from `Verifier::receipts`). With no receipts, the cut drops to
// the first in-range record (the accepted start's `seq`), and the
// `Unreconciled` is located there with `head` the highest in-range
// `seq`.
// =====================================================================
#[test]
fn l10_accepted_start_prefix_starts_at_start() {
    // Build the full chain offline to compute the hashes and the
    // MMR fold cp2 declares, then seal only `[cp2, e3, cp4]` so
    // `start_from(cp2)` acceptance fires on the first record of the
    // verified set (ruling 13-V6-d2).
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
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .start_from(parse_cp(&cp2))
        .receipts_live(true)
        .unwrap();
    let report = report_of(vec![path.clone()], verifier);
    let expected = vec![located(
        K::Unreconciled,
        path,
        1,
        2,
        "records seq 2..=4 not reconciled".to_owned(),
    )];
    let _ = cp4;
    assert_findings(report.findings(), &expected, "l10 accepted start");
}

/// Strips a trailing LF from a record line, mirroring
/// `end_before_tests::line_without_lf`.
fn line_without_lf(record: &Record) -> String {
    let bytes = crate::audit::runs_v4a_fixtures::line_bytes(record);
    let mut text = String::from_utf8(bytes).unwrap();
    if text.ends_with('\n') {
        text.pop();
    }
    text
}
