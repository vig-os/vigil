//! Rows for [`Verifier::waive`], [`Verifier::receipts_from`] and
//! [`FindingKind::ReceiptWaived`] (ADR-0005 decision 5 "Waivers, for
//! an honest crash" and "Late adoption"; ruling 13-V7-d1 point 6).
//! Row standard is `receipts_tests`': every acceptance row ends in
//! one whole-list [`assert_findings`] (a thin wrapper around
//! `assert_eq!` on `Vec<Finding>`); every digest and hash in an
//! expected detail is a written-out hex constant pinned by
//! [`fixture_hashes_match_literals`]; regression rows are labelled
//! in their doc comments. Expected lists are in the engine's final
//! sort order (`(seq.is_none(), seq, file, line, kind_debug)`).
//!
//! Fixture style: wall-clock stamps on the real writer would drift
//! record hashes per run and the row literals with them, so these
//! rows build records through the same `signed_cp`, `entry_rec` and
//! `Record::new` helpers the receipts rows use; receipts, waivers
//! and `from` inputs are `(seq, hash[, reason])` tuples read off
//! those records, so no real writer is needed. Shared `located`,
//! `unlocated`, `assert_findings`, `trust_with_key`, `report_of`
//! and `parse_cp` come from [`super::tests_common`].

use super::tests_common::{
    assert_findings, located, parse_cp, report_of, trust_with_key, unlocated,
};
use crate::audit::{
    AuditError, AuditErrorKind, Entry, FindingKind as K, Mmr, Record, digest_string,
    runs_v4a_fixtures::{
        TRAIL, Temp, context, entry_rec, fixture_pubkey, line_bytes, pushed, put_segment, seeded,
        segment_path, signed_cp, signed_cp_explicit,
    },
    verify::Verifier,
};
use std::path::PathBuf;

// =====================================================================
// Shared literal hex constants (pinned by `fixture_hashes_match_literals`
// so a fixture drift fails in one place rather than many).
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
/// `signed_cp(3, e2.hash(), &mmr2)` on the four-record honest chain.
const CP3_FROM_E2_DIGEST: &str =
    "blake3:dda83f7bbaaf877076831dd97e6563148bf337d350bc58cf8bc6e8802eed2f66";
/// `signed_cp(4, e3.hash(), &mmr3)` on the five-record honest chain
/// `[cp0, e1, e2, e3, cp4]` used by the records-above-`s` rows.
const CP4_FROM_E3_DIGEST: &str =
    "blake3:e1d62ae3be94079ce6b6e664b4d225fc764033173ce51b446fc8c38f86778810";
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
/// `Record::new(context(1, cp0.hash()), Entry::new("orphan-actor",
/// "orphan-change", "orphan-object"))`: the real pre-crash hash of
/// an orphan at seq=1, used by the "waiver names a record later
/// replaced" layout (ADR l.922). Not in the trail.
const E1_ORPHAN_DIGEST: &str =
    "blake3:a9495f343ae993984b188139f2156a34ad5d81b95a5577b199ee647c1561e70f";
/// `Record::new(context(2, e1.hash()), Entry::new("orphan-actor",
/// "orphan-change", "orphan-object"))`: the real pre-crash hash of
/// an orphan at seq=2 (ADR l.922). Not in the trail.
const E2_ORPHAN_DIGEST: &str =
    "blake3:1a4a81a938557cf86e08fc0bdf0699cedf29f192f57117ba2df851e4c5b58b55";
/// A 32-byte placeholder for a wrong-receipt scenario: `[0x5a; 32]`.
const WRONG_HASH_5A_DIGEST: &str =
    "blake3:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

const WRONG_HASH_5A: [u8; 32] = [0x5a; 32];

/// `signed_cp(0, Record::genesis(&TRAIL), &Mmr::new())` built fresh
/// where a row needs cp0's hash to chain an orphan record from.
fn cp0_honest() -> Record {
    signed_cp(0, Record::genesis(&TRAIL), &Mmr::new())
}

/// The orphan record at seq=1, chained from cp0 with a distinct
/// entry so its hash differs from `entry_rec(1, cp0.hash())`.
fn e1_orphan() -> Record {
    Record::new(
        context(1, cp0_honest().hash()),
        Entry::new("orphan-actor", "orphan-change", "orphan-object"),
    )
    .unwrap()
}

/// The orphan record at seq=2, chained from e1 with a distinct
/// entry so its hash differs from `entry_rec(2, e1.hash())`.
fn e2_orphan(e1_hash: [u8; 32]) -> Record {
    Record::new(
        context(2, e1_hash),
        Entry::new("orphan-actor", "orphan-change", "orphan-object"),
    )
    .unwrap()
}

/// Four-record honest chain `[cp0, e1, e2, cp3]` sealed in one
/// segment.
struct FourRecord {
    _dir: Temp,
    path: PathBuf,
    e1: Record,
    e2: Record,
    cp3: Record,
}
fn four_record() -> FourRecord {
    let d = Temp::new();
    let cp0 = cp0_honest();
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

/// Five-record honest chain `[cp0, e1, e2, e3, cp4]` sealed in one
/// segment, used by the rows that need `audit.record`s above the
/// `from` seq (so the "records above `s` are not reconciled" path
/// has something to reconcile). `e3` chains into `cp4` inside the
/// builder; the rows read its hash through the pinned
/// [`E3_HONEST_DIGEST`] constant.
struct FiveRecord {
    _dir: Temp,
    path: PathBuf,
    e1: Record,
    e2: Record,
    cp4: Record,
}
fn five_record() -> FiveRecord {
    let d = Temp::new();
    let cp0 = cp0_honest();
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    let e3 = entry_rec(3, e2.hash());
    let mmr3 = pushed(&mmr2, &e3);
    let cp4 = signed_cp(4, e3.hash(), &mmr3);
    put_segment(&d.0, 0, &[&cp0, &e1, &e2, &e3, &cp4], &[]);
    let path = segment_path(&d.0, 0);
    FiveRecord {
        _dir: d,
        path,
        e1,
        e2,
        cp4,
    }
}

// =====================================================================
// Shared literal-hex consistency test (fixture-drift catch-all).
// =====================================================================
#[test]
fn fixture_hashes_match_literals() {
    let cp0 = cp0_honest();
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    let cp3 = signed_cp(3, e2.hash(), &mmr2);
    let e3 = entry_rec(3, e2.hash());
    let mmr3 = pushed(&mmr2, &e3);
    let cp4 = signed_cp(4, e3.hash(), &mmr3);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let e1_alt = Record::new(context(1, cp0.hash()), Entry::new("actor", "change", "alt")).unwrap();
    let cp2_alt_from_e1_alt = signed_cp_explicit(2, e1_alt.hash(), 2, [0xee; 32], vec![[0xdd; 32]]);
    assert_eq!(digest_string(&cp0.hash()), CP0_HONEST_DIGEST, "cp0");
    assert_eq!(digest_string(&e1.hash()), E1_HONEST_DIGEST, "e1");
    assert_eq!(digest_string(&e2.hash()), E2_HONEST_DIGEST, "e2");
    assert_eq!(digest_string(&e3.hash()), E3_HONEST_DIGEST, "e3");
    assert_eq!(digest_string(&cp3.hash()), CP3_FROM_E2_DIGEST, "cp3");
    assert_eq!(digest_string(&cp4.hash()), CP4_FROM_E3_DIGEST, "cp4");
    assert_eq!(digest_string(&cp2.hash()), CP2_HONEST_DIGEST, "cp2");
    assert_eq!(digest_string(&e1_alt.hash()), E1_ALT_DIGEST, "e1_alt");
    assert_eq!(
        digest_string(&cp2_alt_from_e1_alt.hash()),
        CP2_ALT_FROM_E1_ALT_DIGEST,
        "cp2_alt_from_e1_alt"
    );
    assert_eq!(
        digest_string(&e1_orphan().hash()),
        E1_ORPHAN_DIGEST,
        "e1_orphan"
    );
    assert_eq!(
        digest_string(&e2_orphan(e1.hash()).hash()),
        E2_ORPHAN_DIGEST,
        "e2_orphan"
    );
    assert_eq!(
        digest_string(&WRONG_HASH_5A),
        WRONG_HASH_5A_DIGEST,
        "wrong5a"
    );
}

// =====================================================================
// W1a (crash orphan, ADR l.922). ACCEPTANCE. A matching waiver at
// one `seq` emits one `ReceiptWaived` at its record and does not
// suppress `NoReceipt` for other unreceipted records: a second
// unreceipted record at a different `seq` still emits its own
// `NoReceipt` at its own first copy.
// =====================================================================
#[test]
fn w1a_waiver_does_not_suppress_other_no_receipts() {
    let fx = four_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(3, fx.cp3.hash())])
        .waive(1, fx.e1.hash(), "orphan request id=41")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        located(
            K::ReceiptWaived,
            fx.path.clone(),
            2,
            1,
            format!("waived seq 1 hash {E1_HONEST_DIGEST}: orphan request id=41"),
        ),
        located(
            K::NoReceipt,
            fx.path,
            3,
            2,
            format!("no receipt for seq 2 hash {E2_HONEST_DIGEST}"),
        ),
    ];
    assert_findings(report.findings(), &expected, "w1a");
}

// =====================================================================
// W1b (crash orphan, ADR l.922). ACCEPTANCE. The same record now
// carries a matching `waive` naming its exact `(seq, hash)`: the
// result is one `ReceiptWaived` (info) at the record, no
// `NoReceipt` for it, and `is_strict_valid()` holds.
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
// W1c (crash orphan, ADR l.922). ACCEPTANCE. Second crash-orphan
// layout: the waived record sits at seq=1 rather than seq=2, so
// the `waived` detail's `seq` and record hash both differ from
// W1b, and the ReceiptWaived location moves to line 2.
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
// W2 (ADR l.922). ACCEPTANCE. A crash orphan at `seq=2` is waived
// with its real hash. The record at `seq=2` was later replaced by
// a different record (same chain position, different content), and
// no receipt names a `seq` above 2 to mask the replacement. The
// waiver's hash differs from the record's hash, so one
// `ReceiptMismatch "waive seq 2 hash <orig>: hash differs (record
// <new>)"` fires at `seq=2`, and the record at `seq=2` still
// produces its ordinary `NoReceipt` (a mismatched waiver does not
// suppress `NoReceipt`).
// =====================================================================
#[test]
fn w2_waiver_names_replaced_record_is_receipt_mismatch() {
    let fx = four_record();
    let orphan = e2_orphan(fx.e1.hash());
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash())])
        .waive(2, orphan.hash(), "orphan request id=42")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        unlocated(
            K::ReceiptMismatch,
            Some(2),
            format!(
                "waive seq 2 hash {E2_ORPHAN_DIGEST}: hash differs (record {E2_HONEST_DIGEST})"
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
// W2b (ADR l.922). ACCEPTANCE. Second honest variant of W2 with
// the replacement at a different position: the waiver names the
// real pre-crash hash of seq=1, the trail now carries a different
// record there, and no receipt names a `seq` above 1. The waiver's
// hash differs from the record's hash at seq=1, so one
// `ReceiptMismatch` fires and the record at seq=1 still emits
// `NoReceipt`; the record at seq=2 is also unreceipted and emits
// its own `NoReceipt`.
// =====================================================================
#[test]
fn w2b_waiver_names_replaced_record_at_earlier_seq_is_receipt_mismatch() {
    let fx = four_record();
    let orphan = e1_orphan();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .waive(1, orphan.hash(), "orphan request id=41")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        unlocated(
            K::ReceiptMismatch,
            Some(1),
            format!(
                "waive seq 1 hash {E1_ORPHAN_DIGEST}: hash differs (record {E1_HONEST_DIGEST})"
            ),
        ),
        located(
            K::NoReceipt,
            fx.path.clone(),
            2,
            1,
            format!("no receipt for seq 1 hash {E1_HONEST_DIGEST}"),
        ),
        located(
            K::NoReceipt,
            fx.path,
            3,
            2,
            format!("no receipt for seq 2 hash {E2_HONEST_DIGEST}"),
        ),
    ];
    assert_findings(report.findings(), &expected, "w2b");
}

// =====================================================================
// W3 (late adoption, ADR l.923). ACCEPTANCE. Records before the
// first receipt. A matching `from seq=2 hash=e2` emits one
// `ReceiptWaived` (info) at the record, records at or below `seq=2`
// are not reconciled (no `NoReceipt`), and strict passes.
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
// W3b. ACCEPTANCE. Second late-adoption layout: `from` names
// seq=1 (one earlier than W3), so the `ReceiptWaived` detail's
// `seq` differs and only records at or below seq=1 are exempted.
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
// W3c (late adoption, ADR l.923). ACCEPTANCE. A matching `from` at
// `seq=2` exempts every record at or below `seq=2` from
// reconciliation, but records with `seq > 2` without a matching
// receipt still emit `NoReceipt`. Trail `[cp0, e1, e2, e3, cp4]`
// (five records) and `from(2, e2)` with no receipt for `e3` at
// `seq=3` yields one `ReceiptWaived` at `e2` and one `NoReceipt`
// at `e3`.
// =====================================================================
#[test]
fn w3c_receipts_from_exempts_only_at_or_below_record_above_is_no_receipt() {
    let fx = five_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(4, fx.cp4.hash())])
        .receipts_from(2, fx.e2.hash(), "late adoption")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        located(
            K::ReceiptWaived,
            fx.path.clone(),
            3,
            2,
            format!("from seq 2 hash {E2_HONEST_DIGEST}: late adoption"),
        ),
        located(
            K::NoReceipt,
            fx.path,
            4,
            3,
            format!("no receipt for seq 3 hash {E3_HONEST_DIGEST}"),
        ),
    ];
    assert_findings(report.findings(), &expected, "w3c");
}

// =====================================================================
// W3d (late adoption, ADR l.923). ACCEPTANCE. Second layout for the
// "records above `s` are reconciled" boundary: `from` names `seq=1`
// so `e1` is exempt and both `e2` and `e3` (above `s`) emit their
// own `NoReceipt` at their own first copies.
// =====================================================================
#[test]
fn w3d_receipts_from_at_earlier_seq_leaves_multiple_above_as_no_receipt() {
    let fx = five_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(4, fx.cp4.hash())])
        .receipts_from(1, fx.e1.hash(), "late adoption early")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        located(
            K::ReceiptWaived,
            fx.path.clone(),
            2,
            1,
            format!("from seq 1 hash {E1_HONEST_DIGEST}: late adoption early"),
        ),
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
            format!("no receipt for seq 3 hash {E3_HONEST_DIGEST}"),
        ),
    ];
    assert_findings(report.findings(), &expected, "w3d");
}

// =====================================================================
// W4 (ADR l.923). ACCEPTANCE. A `from` line with a wrong hash:
// one `ReceiptMismatch` at `seq`, and because the mismatched `from`
// exempts nothing, records at or below `seq` keep their ordinary
// `NoReceipt`.
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
// W4b. ACCEPTANCE. Second mismatched-`from` layout: a `from` with
// a wrong hash at seq=1 fires `ReceiptMismatch "hash differs"`
// and, because a mismatched `from` exempts nothing, the ordinary
// `NoReceipt` loop still runs.
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
// W5. ACCEPTANCE. A waiver at a `seq` with no record: the match
// rule's first failing step is `no record`, so `ReceiptMismatch
// "waive seq ... no record"` fires.
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
// non-checkpoint copy.
// =====================================================================
#[test]
fn w6_waiver_at_forked_seq_is_forked_and_per_copy_no_receipt() {
    let d = Temp::new();
    let cp0 = cp0_honest();
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
// W7 (library half of ADR l.927; ruling 13-V7-d1 point 6).
// Builder validation: each `InvalidConfig` row asserts kind AND
// the full message literally, so dropping a check or changing its
// text fails the row.
// =====================================================================

/// Helper asserting [`InvalidConfig`] kind and the exact
/// `Display`-rendered message returned by a builder call
/// (`AuditError` writes `<kind>: <detail>` in `std::fmt::Display`,
/// ADR-0005 §19 error table, so the expected string names the
/// detail and the helper prepends the kind label). One check per
/// row (see individual rows for the paired validation input).
#[track_caller]
fn assert_invalid_config(err: AuditError, expected_detail: &str, label: &str) {
    assert_eq!(err.kind(), AuditErrorKind::InvalidConfig, "{label} kind");
    assert_eq!(
        err.to_string(),
        format!("InvalidConfig: {expected_detail}"),
        "{label} message",
    );
}

/// A second `waive` for the same `seq` is `InvalidConfig` with the
/// `duplicate waive for seq <s>` message.
#[test]
fn w7_second_waive_same_seq_is_invalid_config() {
    let err = Verifier::new(trust_with_key(fixture_pubkey()))
        .waive(2, [0x11; 32], "first")
        .unwrap()
        .waive(2, [0x22; 32], "second")
        .unwrap_err();
    assert_invalid_config(err, "duplicate waive for seq 2", "w7_second_waive");
}

/// A duplicate `waive` with the same `(seq, hash)` but a different
/// reason is also `InvalidConfig` (the check is on prior presence
/// at `seq`, not on contents). Pairs with
/// `w7_second_waive_same_seq_is_invalid_config` as a distinct
/// input shape (same values vs. different values) for the duplicate
/// check.
#[test]
fn w7_duplicate_waive_different_reasons_is_invalid_config() {
    let err = Verifier::new(trust_with_key(fixture_pubkey()))
        .waive(5, [0x11; 32], "same hash first reason")
        .unwrap()
        .waive(5, [0x11; 32], "same hash different reason")
        .unwrap_err();
    assert_invalid_config(err, "duplicate waive for seq 5", "w7_waive_same_values");
}

/// A second `receipts_from` is `InvalidConfig` with the
/// `duplicate receipts_from` message.
#[test]
fn w7_second_receipts_from_is_invalid_config() {
    let err = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts_from(2, [0x11; 32], "first")
        .unwrap()
        .receipts_from(3, [0x22; 32], "second")
        .unwrap_err();
    assert_invalid_config(err, "duplicate receipts_from", "w7_second_receipts_from");
}

/// Second `receipts_from` with a matching `(seq, hash)` is still
/// `InvalidConfig`: distinct from `w7_second_receipts_from_...` on
/// input shape (same values vs. different values), covering both
/// branches of the duplicate check.
#[test]
fn w7_second_receipts_from_same_values_is_invalid_config() {
    let err = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts_from(5, [0x11; 32], "first")
        .unwrap()
        .receipts_from(5, [0x11; 32], "copy")
        .unwrap_err();
    assert_invalid_config(
        err,
        "duplicate receipts_from",
        "w7_second_receipts_from_same_values",
    );
}

/// `waive` with an empty `&str` literal reason is `InvalidConfig`.
#[test]
fn w7_waive_empty_str_reason_is_invalid_config() {
    let err = Verifier::new(trust_with_key(fixture_pubkey()))
        .waive(2, [0x11; 32], "")
        .unwrap_err();
    assert_invalid_config(
        err,
        "waive reason must be a non-empty single line (no LF or CR)",
        "w7_waive_empty_str",
    );
}

/// `receipts_from` with an empty `String` (built from
/// `String::new()`) is also `InvalidConfig`: distinct Rust input
/// shape from the `&str` literal.
#[test]
fn w7_receipts_from_empty_string_reason_is_invalid_config() {
    let err = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts_from(2, [0x11; 32], String::new())
        .unwrap_err();
    assert_invalid_config(
        err,
        "receipts_from reason must be a non-empty single line (no LF or CR)",
        "w7_receipts_from_empty_string",
    );
}

/// `waive` with an LF in the reason is `InvalidConfig`.
#[test]
fn w7_waive_reason_with_lf_is_invalid_config() {
    let err = Verifier::new(trust_with_key(fixture_pubkey()))
        .waive(2, [0x11; 32], "a\nb")
        .unwrap_err();
    assert_invalid_config(
        err,
        "waive reason must be a non-empty single line (no LF or CR)",
        "w7_waive_lf",
    );
}

/// `receipts_from` with an LF in the reason is `InvalidConfig`.
#[test]
fn w7_receipts_from_reason_with_lf_is_invalid_config() {
    let err = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts_from(2, [0x11; 32], "a\nb")
        .unwrap_err();
    assert_invalid_config(
        err,
        "receipts_from reason must be a non-empty single line (no LF or CR)",
        "w7_receipts_from_lf",
    );
}

/// `waive` with a CR in the reason is `InvalidConfig` (covers the
/// CR branch of the single-line check, paired with the LF rows).
#[test]
fn w7_waive_reason_with_cr_is_invalid_config() {
    let err = Verifier::new(trust_with_key(fixture_pubkey()))
        .waive(2, [0x11; 32], "a\rb")
        .unwrap_err();
    assert_invalid_config(
        err,
        "waive reason must be a non-empty single line (no LF or CR)",
        "w7_waive_cr",
    );
}

/// `receipts_from` with a CR in the reason is `InvalidConfig`.
#[test]
fn w7_receipts_from_reason_with_cr_is_invalid_config() {
    let err = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts_from(2, [0x11; 32], "a\rb")
        .unwrap_err();
    assert_invalid_config(
        err,
        "receipts_from reason must be a non-empty single line (no LF or CR)",
        "w7_receipts_from_cr",
    );
}

// =====================================================================
// W7 (whitespace-only reason). ACCEPTANCE. A whitespace-only reason
// is accepted (ruling 13-V7-d1 point 6 and d1a do not forbid it;
// the reason is not trimmed): the waiver lands, reconciliation
// runs, and the whitespace appears verbatim in the `ReceiptWaived`
// detail. Pins the expected outcome against any later proposal to
// trim the reason.
// =====================================================================
#[test]
fn w7_waive_whitespace_only_reason_is_accepted() {
    let fx = four_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash()), (3, fx.cp3.hash())])
        .waive(2, fx.e2.hash(), "   ")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![located(
        K::ReceiptWaived,
        fx.path,
        3,
        2,
        format!("waived seq 2 hash {E2_HONEST_DIGEST}:    "),
    )];
    assert_findings(report.findings(), &expected, "w7_whitespace_reason");
}

// =====================================================================
// W7 regression. Two receipts for one `seq` with different hashes
// are accepted (`.receipts` never errors on a duplicate `seq`, and
// each tuple is evaluated independently). The matching one yields
// no finding; the other yields one `ReceiptMismatch "hash differs"`
// at `seq`. Paired with a waiver at a different `seq` so the
// row also exercises the waiver emission alongside the receipts
// path.
// =====================================================================
#[test]
fn w7_two_receipts_same_seq_different_hashes_are_not_invalid_config() {
    let fx = four_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([
            (1, fx.e1.hash()),
            (2, fx.e2.hash()),
            (2, WRONG_HASH_5A),
            (3, fx.cp3.hash()),
        ])
        .waive(1, fx.e1.hash(), "orphan one")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        located(
            K::ReceiptWaived,
            fx.path,
            2,
            1,
            format!("waived seq 1 hash {E1_HONEST_DIGEST}: orphan one"),
        ),
        unlocated(
            K::ReceiptMismatch,
            Some(2),
            format!(
                "receipt seq 2 hash {WRONG_HASH_5A_DIGEST}: hash differs (record {E2_HONEST_DIGEST})"
            ),
        ),
    ];
    assert_findings(report.findings(), &expected, "w7_two_receipts");
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
    let cp0 = cp0_honest();
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
// 13-V7-d1 point 6).
// =====================================================================
#[test]
fn w8c_waiver_above_anchored_end_is_out_of_range() {
    let d = Temp::new();
    let cp0 = cp0_honest();
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1], &[]);
    let path = segment_path(&d.0, 0);
    let archive = std::str::from_utf8(&line_bytes(&cp2))
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
// `ReceiptWaived`.
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
// W9b. ACCEPTANCE. Second "`waive` alone turns reconciliation on"
// layout: waives seq=1 (the first entry) instead of seq=2, so the
// reconciled list differs from W9 (the waived record at seq=1 is
// `ReceiptWaived` and the record at seq=2 is `NoReceipt`).
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

// =====================================================================
// W10. ACCEPTANCE pin. Both a matching receipt and a matching
// waiver name the same `(seq, hash)`. Decision 5 lets a receipt
// match any record (checkpoints or audit records) and treats a
// matched waiver as operator-attention info at the record; neither
// cancels the other. Literal outcome: one `ReceiptWaived` (info)
// at the record, no `NoReceipt` (the receipt match suppresses it),
// and `is_strict_valid()`.
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
// W11 (ruling 13-V7-d1 point 6). ACCEPTANCE. A matching waiver and
// a mismatched receipt at the same `seq`: the waiver matches and
// emits `ReceiptWaived` (suppressing `NoReceipt`); the receipt's
// mismatch still fires its own `ReceiptMismatch`. A matched waiver
// does not hide a receipt mismatch at the same `seq`.
// =====================================================================
#[test]
fn w11_matched_waiver_does_not_hide_receipt_mismatch_at_same_seq() {
    let fx = four_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash()), (2, WRONG_HASH_5A), (3, fx.cp3.hash())])
        .waive(2, fx.e2.hash(), "orphan both")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        unlocated(
            K::ReceiptMismatch,
            Some(2),
            format!(
                "receipt seq 2 hash {WRONG_HASH_5A_DIGEST}: hash differs (record {E2_HONEST_DIGEST})"
            ),
        ),
        located(
            K::ReceiptWaived,
            fx.path,
            3,
            2,
            format!("waived seq 2 hash {E2_HONEST_DIGEST}: orphan both"),
        ),
    ];
    assert_findings(report.findings(), &expected, "w11");
}

// =====================================================================
// W11b. ACCEPTANCE. Second layout for the "a waiver does not hide
// a receipt mismatch" property: both the waiver and the receipt
// mismatch at the same `seq`, with distinct hashes. Both
// `ReceiptMismatch`es fire with their own subject, and the record
// still emits `NoReceipt` because neither matched.
// =====================================================================
#[test]
fn w11b_mismatched_waiver_and_mismatched_receipt_both_fire() {
    let fx = four_record();
    let orphan = e2_orphan(fx.e1.hash());
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash()), (2, WRONG_HASH_5A), (3, fx.cp3.hash())])
        .waive(2, orphan.hash(), "orphan mismatch")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        unlocated(
            K::ReceiptMismatch,
            Some(2),
            format!(
                "receipt seq 2 hash {WRONG_HASH_5A_DIGEST}: hash differs (record {E2_HONEST_DIGEST})"
            ),
        ),
        unlocated(
            K::ReceiptMismatch,
            Some(2),
            format!(
                "waive seq 2 hash {E2_ORPHAN_DIGEST}: hash differs (record {E2_HONEST_DIGEST})"
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
    assert_findings(report.findings(), &expected, "w11b");
}
