//! Rows for the verifier's receipt reconciliation (ADR-0005
//! decision 5 "Receipt reconciliation"; ruling 13-V7-d1 points 2-5
//! and its clarification 13-V7-d1a).
//!
//! Row standard (repo-wide): every acceptance row asserts the FULL
//! sorted literal finding list as whole [`Finding`] values through
//! [`assert_findings`] (a thin wrapper around `assert_eq!` on
//! `Vec<Finding>`). Regression rows are labelled in their doc
//! comments. Every digest and hash in an expected detail is a
//! written-out hex constant pinned by
//! [`fixture_hashes_match_literals`]. Expected lists are written in
//! the engine's final sort order (`(seq.is_none(), seq, file, line,
//! kind_debug)`), so no per-row sort runs here.
//!
//! Fixture style: wall-clock time stamps on the real writer would
//! drift the record hashes per run and the row literals with them,
//! so most records are hand-built through the same `signed_cp`,
//! `entry_rec` and `Record::new_internal` helpers the end-link rows
//! use; these go through the same `Record::checkpoint` /
//! `CheckpointFields` paths the writer's `sink::signed` uses, with
//! fixture timestamps `100 + seq`, so the resulting records are
//! byte-for-byte what a writer would emit at the fixture clock.
//! Receipts are `(seq, hash)` tuples read off those records, so no
//! real writer is needed for them. The one exception is the
//! operator-record rotate row, which drives the real writer
//! `AuditConfig::create → record → close → rotate` through its
//! public API and asserts the one non-fixed value --- the rotation
//! record's hash --- from the `Receipt` the writer returned, with
//! every other field pinned literally.

use super::tests_common::{
    assert_findings, located, parse_cp, report_of, trust_with_key, unlocated,
};
use crate::audit::{
    AuditConfig, Entry, FindingKind as K, KeyFileSigner, Mmr, Record, Signer, TrustPolicy,
    digest_string,
    runs_v4a_fixtures::{
        TRAIL, Temp, context, entry_rec, fixture_pubkey, line_bytes, pushed, put_segment, seeded,
        segment_path, signed_cp, signed_cp_explicit,
    },
    verify::Verifier,
};
use std::{path::PathBuf, sync::Arc};

// =====================================================================
// Shared literal hex constants. Pinned by `fixture_hashes_match_literals`
// so a drift in a fixture builder surfaces there rather than across
// many rows.
// =====================================================================

/// `signed_cp(0, Record::genesis(&TRAIL), &Mmr::new())` -- the honest
/// seq=0 opening used by every single-segment row.
const CP0_HONEST_DIGEST: &str =
    "blake3:fc26c6f2bb830592aaaca5413da1599489d86ac6e240a4a7a010681e0d4c8e77";
/// `entry_rec(1, cp0.hash())` on the honest chain -- e1.
const E1_HONEST_DIGEST: &str =
    "blake3:c121282b5135adfe7a17142cae6bfc4c9040c4aed26d74bddc923b8dafcdb6e8";
/// `signed_cp(2, e1.hash(), &mmr1)` on the honest `[cp0, e1]` fold.
const CP2_HONEST_DIGEST: &str =
    "blake3:4164966a12a675e55eb6e133b9e50313907f164fe142d941447defcdfdb25d06";
/// `entry_rec(2, e1.hash())` on the honest chain -- the "forged e2"
/// by convention (a byte-identical entry at seq 2; the verifier has
/// no out-of-band way to tell it from a legitimate append).
const E2_HONEST_DIGEST: &str =
    "blake3:8a5ea9c989aad7e89033b58ad6f59a6384af43dfe6df5bada042420c0040c306";
/// `entry_rec(3, e2.hash())` on the honest chain -- the "forged e3"
/// the second forged append at seq 3 in the two-forged rows.
const E3_HONEST_DIGEST: &str =
    "blake3:b378374409602bc24aa87765b3cc3361e3b647368f57d9a06816f9b2bd0696c9";
/// `signed_cp(3, e2.hash(), &mmr2)` on the four-record honest chain
/// `[cp0, e1, e2, cp3]`; the honest close after the
/// forged seq=2 append.
const CP3_FROM_E2_DIGEST: &str =
    "blake3:dda83f7bbaaf877076831dd97e6563148bf337d350bc58cf8bc6e8802eed2f66";
/// `signed_cp(4, e3.hash(), &mmr3)` on the five-record chain
/// `[cp0, e1, e2, e3, cp4]` used by the two-forged rows.
const CP4_FROM_E3_DIGEST: &str =
    "blake3:e1d62ae3be94079ce6b6e664b4d225fc764033173ce51b446fc8c38f86778810";
/// `entry_rec(4, cp3.hash())` on the six-record honest chain
/// `[cp0, e1, e2, cp3, e4, cp5]` -- the "writer B" entry.
const E4_HONEST_DIGEST: &str =
    "blake3:c0d53ffca7d1358ec842a15694a00833b408e2a6d43f49f2f1de7225fabba4e6";
/// `signed_cp(5, e4.hash(), &mmr4)` on the six-record honest chain
/// used by the writer-A/attacker/writer-B row.
const CP5_FROM_E4_DIGEST: &str =
    "blake3:8c2a212152faa447de5f329dc79b90a503eec4ec0f18cfb9b6717a749d6a4cd0";
/// `op_resume_rec(1, cp0.hash(), 0, cp0.hash())` -- the hand-built
/// genesis-resume operator record retained for the `end_before`
/// rows as the end record's second line.
const OP_RESUME_SEQ1_DIGEST: &str =
    "blake3:bd4592e04f5a3aceecbbcece85b973925af53b961a60f8d1a760eb3aae0df79e";
/// `Record::new(context(1, cp0.hash()), Entry::new("actor", "change", "alt"))`
/// -- the alt-hash entry at seq=1 for the fork rows.
const E1_ALT_DIGEST: &str =
    "blake3:125619e12e657407511645cac8c311f0d32ac0f97377eb1e45f9ca0217516a1e";
/// `signed_cp_explicit(2, e1_alt.hash(), 2, [0xee; 32], vec![[0xdd; 32]])`
/// -- the alt seq=2 checkpoint for the entry-fork row.
const CP2_ALT_FROM_E1_ALT_DIGEST: &str =
    "blake3:8e56403afaf555ef2720aa4539cab56111fc744c51f0a9da44a1a5af04a3ff73";
/// `signed_cp_explicit(2, e1.hash(), 2, [0x22; 32], vec![[0x33; 32]])`
/// -- the alt seq=2 checkpoint for the checkpoint-fork row.
const CP2_ALT_FROM_E1_DIGEST: &str =
    "blake3:b3ab6729d499c918c63764e4d9a06db29f387db57295c3c28615e377666eb1b0";
/// A placeholder 32-byte hash for an unknown-receipt scenario:
/// `[0x5a; 32]`.
const WRONG_HASH_5A_DIGEST: &str =
    "blake3:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
/// Another placeholder: `[0x66; 32]`.
const WRONG_HASH_66_DIGEST: &str =
    "blake3:6666666666666666666666666666666666666666666666666666666666666666";
/// Shared `Resumed` detail for the end-record resume line whose
/// head is cp2 (seq=2); reused across every `end_before` row that
/// builds this layout so the head hex is not spelled three times.
/// The head hex equals [`CP2_HONEST_DIGEST`]; pinned by
/// [`fixture_hashes_match_literals`].
const RESUME_DETAIL_END_HEAD_CP2: &str = "operator=operator reason=incident head=2:blake3:4164966a12a675e55eb6e133b9e50313907f164fe142d941447defcdfdb25d06 \
     gap=none lost_records=0 structural=invalid(no-opening)";

// =====================================================================
// Helpers. Shared `located`, `unlocated`, `assert_findings`,
// `trust_with_key`, `report_of` and `parse_cp` come from
// [`super::tests_common`].
// =====================================================================

const WRONG_HASH_5A: [u8; 32] = [0x5a; 32];
const WRONG_HASH_66: [u8; 32] = [0x66; 32];

/// Builds a `vigil.audit.resume` operator record at `seq` on the
/// honest fixture clock. Mirrors `resume_decl` but takes arbitrary
/// `(seq, previous)` so a row can plant such a record where it needs
/// one.
fn op_resume_rec(seq: u64, previous: [u8; 32], head_seq: u64, head_hash: [u8; 32]) -> Record {
    Record::new_internal(
        context(seq, previous),
        Entry::new("operator", "vigil.audit.resume", "trail")
            .reason("incident")
            .details(format!(
                "head={head_seq}:{hex} lost_through={head_seq} file=-",
                hex = digest_string(&head_hash)
            )),
    )
    .unwrap()
}

/// A single sealed segment holding `records` under a fresh temp dir.
struct Segment {
    _dir: Temp,
    path: PathBuf,
}
fn seal(records: &[&Record]) -> Segment {
    let d = Temp::new();
    put_segment(&d.0, 0, records, &[]);
    let path = segment_path(&d.0, 0);
    Segment { _dir: d, path }
}

/// The honest `[cp0, e1, cp2]` three-record trail, retained for the
/// rows that need `e1`/`cp2` hashes.
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
    let seg = seal(&[&cp0, &e1, &cp2]);
    ThreeRecord {
        _dir: seg._dir,
        path: seg.path,
        e1,
        cp2,
    }
}

// =====================================================================
// Shared literal-hex consistency test. Pins every `const` in this
// module against its builder's live hash, so a fixture drift surfaces
// here rather than in each row's expected list.
// =====================================================================
#[test]
fn fixture_hashes_match_literals() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    let cp3 = signed_cp(3, e2.hash(), &mmr2);
    let e3 = entry_rec(3, e2.hash());
    let mmr3 = pushed(&mmr2, &e3);
    let cp4 = signed_cp(4, e3.hash(), &mmr3);
    let mmr_cp3 = pushed(&mmr2, &cp3);
    let e4 = entry_rec(4, cp3.hash());
    let mmr4 = pushed(&mmr_cp3, &e4);
    let cp5 = signed_cp(5, e4.hash(), &mmr4);
    let op = op_resume_rec(1, cp0.hash(), 0, cp0.hash());
    let e1_alt = Record::new(context(1, cp0.hash()), Entry::new("actor", "change", "alt")).unwrap();
    let cp2_alt_from_e1_alt = signed_cp_explicit(2, e1_alt.hash(), 2, [0xee; 32], vec![[0xdd; 32]]);
    let cp2_alt_from_e1 = signed_cp_explicit(2, e1.hash(), 2, [0x22; 32], vec![[0x33; 32]]);
    assert_eq!(digest_string(&cp0.hash()), CP0_HONEST_DIGEST, "cp0");
    assert_eq!(digest_string(&e1.hash()), E1_HONEST_DIGEST, "e1");
    assert_eq!(digest_string(&cp2.hash()), CP2_HONEST_DIGEST, "cp2");
    assert_eq!(digest_string(&e2.hash()), E2_HONEST_DIGEST, "e2");
    assert_eq!(digest_string(&cp3.hash()), CP3_FROM_E2_DIGEST, "cp3");
    assert_eq!(digest_string(&e3.hash()), E3_HONEST_DIGEST, "e3");
    assert_eq!(digest_string(&cp4.hash()), CP4_FROM_E3_DIGEST, "cp4");
    assert_eq!(digest_string(&e4.hash()), E4_HONEST_DIGEST, "e4");
    assert_eq!(digest_string(&cp5.hash()), CP5_FROM_E4_DIGEST, "cp5");
    assert_eq!(
        digest_string(&op.hash()),
        OP_RESUME_SEQ1_DIGEST,
        "op_resume_seq1"
    );
    assert_eq!(digest_string(&e1_alt.hash()), E1_ALT_DIGEST, "e1_alt");
    assert_eq!(
        digest_string(&cp2_alt_from_e1_alt.hash()),
        CP2_ALT_FROM_E1_ALT_DIGEST,
        "cp2_alt_from_e1_alt"
    );
    assert_eq!(
        digest_string(&cp2_alt_from_e1.hash()),
        CP2_ALT_FROM_E1_DIGEST,
        "cp2_alt_from_e1"
    );
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
    assert_eq!(
        RESUME_DETAIL_END_HEAD_CP2,
        format!(
            "operator=operator reason=incident head=2:{CP2_HONEST_DIGEST} \
             gap=none lost_records=0 structural=invalid(no-opening)"
        ),
        "resume_detail_end_head_cp2",
    );
}

// =====================================================================
// REGRESSION. Every record has its receipt and no finding
// fires. Supplied in two `.receipts(...)` calls so the "second call
// adds" semantic (ADR-0005 decision 11 `.receipts`) is exercised,
// and checkpoints need no receipt (ruling 13-V7-d1 point 5).
// =====================================================================
#[test]
fn every_record_has_its_receipt() {
    let fx = three_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash())])
        .receipts([(2, fx.cp2.hash())]);
    let report = report_of(vec![fx.path], verifier);
    assert_findings(report.findings(), &[], "every_record_has_its_receipt");
}

// =====================================================================
// ACCEPTANCE. Writer A closes, an attacker appends a record
// at seq=2 with no receipt, writer B records and closes (ADR-0005
// decision 11 l.918). The forged record is reported as `NoReceipt`
// at its first copy; honest records with their receipts are
// matched.
// =====================================================================
#[test]
fn forged_append_between_writers_emits_no_receipt() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2_forged = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2_forged);
    let cp3 = signed_cp(3, e2_forged.hash(), &mmr2);
    let mmr_cp3 = pushed(&mmr2, &cp3);
    let e4 = entry_rec(4, cp3.hash());
    let mmr4 = pushed(&mmr_cp3, &e4);
    let cp5 = signed_cp(5, e4.hash(), &mmr4);
    let seg = seal(&[&cp0, &e1, &e2_forged, &cp3, &e4, &cp5]);
    let verifier =
        Verifier::new(trust_with_key(fixture_pubkey())).receipts([(1, e1.hash()), (4, e4.hash())]);
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![located(
        K::NoReceipt,
        seg.path,
        3,
        2,
        format!("no receipt for seq 2 hash {E2_HONEST_DIGEST}"),
    )];
    assert_findings(
        report.findings(),
        &expected,
        "forged_append_between_writers_emits_no_receipt",
    );
}

// =====================================================================
// ACCEPTANCE. Two forged records after the last receipt, then
// an honest close (ADR-0005 decision 11 l.919). Both forgeds are
// reported as `NoReceipt`: the reconciled range runs through the
// last record in the files, not through the last receipt (ruling
// 13-V7-d1 point 3).
// =====================================================================
#[test]
fn two_forged_after_last_receipt_emit_no_receipt_each() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2_forged = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2_forged);
    let e3_forged = entry_rec(3, e2_forged.hash());
    let mmr3 = pushed(&mmr2, &e3_forged);
    let cp4 = signed_cp(4, e3_forged.hash(), &mmr3);
    let seg = seal(&[&cp0, &e1, &e2_forged, &e3_forged, &cp4]);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([(1, e1.hash())]);
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![
        located(
            K::NoReceipt,
            seg.path.clone(),
            3,
            2,
            format!("no receipt for seq 2 hash {E2_HONEST_DIGEST}"),
        ),
        located(
            K::NoReceipt,
            seg.path,
            4,
            3,
            format!("no receipt for seq 3 hash {E3_HONEST_DIGEST}"),
        ),
    ];
    assert_findings(
        report.findings(),
        &expected,
        "two_forged_after_last_receipt_emit_no_receipt_each",
    );
}

// =====================================================================
// ACCEPTANCE. A forged record between `create` and the first
// application record (ADR-0005 decision 11 l.920). The reconciled
// range runs from `seq 0` through the last record in the files, so
// `NoReceipt` fires for the forged seq=1 even though every receipt
// supplied names a higher `seq` (ruling 13-V7-d1 point 3).
// =====================================================================
#[test]
fn forged_before_first_app_record_emits_no_receipt() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1_forged = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1_forged);
    let e2_app = entry_rec(2, e1_forged.hash());
    let mmr2 = pushed(&mmr1, &e2_app);
    let cp3 = signed_cp(3, e2_app.hash(), &mmr2);
    let seg = seal(&[&cp0, &e1_forged, &e2_app, &cp3]);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([(2, e2_app.hash())]);
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![located(
        K::NoReceipt,
        seg.path,
        2,
        1,
        format!("no receipt for seq 1 hash {E1_HONEST_DIGEST}"),
    )];
    assert_findings(
        report.findings(),
        &expected,
        "forged_before_first_app_record_emits_no_receipt",
    );
}

// =====================================================================
// ACCEPTANCE. Two `ReceiptMismatch` details: one for a receipt
// above the head (`no record`) and one for a receipt with a
// different hash (`hash differs`) (ADR-0005 decision 11 l.921). The
// receipt for seq=1 has the wrong hash, so `e1` also gets a
// `NoReceipt` because no receipt in the set names `(1, e1.hash())`.
// =====================================================================
#[test]
fn receipt_above_head_and_wrong_hash_emit_receipt_mismatch() {
    let fx = three_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, WRONG_HASH_5A), (5, WRONG_HASH_66)]);
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        unlocated(
            K::ReceiptMismatch,
            Some(1),
            format!(
                "receipt seq 1 hash {WRONG_HASH_5A_DIGEST}: hash differs (record {E1_HONEST_DIGEST})"
            ),
        ),
        located(
            K::NoReceipt,
            fx.path,
            2,
            1,
            format!("no receipt for seq 1 hash {E1_HONEST_DIGEST}"),
        ),
        unlocated(
            K::ReceiptMismatch,
            Some(5),
            format!("receipt seq 5 hash {WRONG_HASH_66_DIGEST}: no record"),
        ),
    ];
    assert_findings(
        report.findings(),
        &expected,
        "receipt_above_head_and_wrong_hash_emit_receipt_mismatch",
    );
}

// =====================================================================
// ACCEPTANCE. Second rollback layout -- several receipts strictly
// above the head, each one its own `ReceiptMismatch "no record"`
// with no set-aside (no `end_before` is in effect, so nothing is
// set aside here). Paired with the single-receipt row above (ADR-
// 0005 decision 11 l.921; ruling 13-V7-d1 point 4).
// =====================================================================
#[test]
fn several_receipts_above_head_each_emit_receipt_mismatch_no_record() {
    let fx = three_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([
        (1, fx.e1.hash()),
        (2, fx.cp2.hash()),
        (5, WRONG_HASH_5A),
        (6, WRONG_HASH_66),
        (7, WRONG_HASH_66),
    ]);
    let report = report_of(vec![fx.path], verifier);
    let expected = vec![
        unlocated(
            K::ReceiptMismatch,
            Some(5),
            format!("receipt seq 5 hash {WRONG_HASH_5A_DIGEST}: no record"),
        ),
        unlocated(
            K::ReceiptMismatch,
            Some(6),
            format!("receipt seq 6 hash {WRONG_HASH_66_DIGEST}: no record"),
        ),
        unlocated(
            K::ReceiptMismatch,
            Some(7),
            format!("receipt seq 7 hash {WRONG_HASH_66_DIGEST}: no record"),
        ),
    ];
    assert_findings(
        report.findings(),
        &expected,
        "several_receipts_above_head_each_emit_receipt_mismatch_no_record",
    );
}

// =====================================================================
// ACCEPTANCE. Writer-built: `AuditConfig::create → record →
// close → rotate` through the public API, with the rotation
// receipt deliberately omitted from the set. Exactly one
// `NoReceipt` fires at the rotation record (ADR-0005 decision 11
// l.922). Timestamps come from the system clock, so the record's
// hash is non-fixed and is computed from the `Receipt` the writer
// returned; the rotation record's `seq` and the audit.jsonl line
// number are literal (`create → record → close → rotate` always
// places them at seq=3 line=4 in a fresh directory), and every
// other field is pinned literally. No incidental `Resumed … invalid`
// or `SeqGap` findings arise, because the chain is clean and no
// resume is issued.
// =====================================================================
#[test]
fn operator_rotate_without_receipt_emits_no_receipt_at_rotate_record() {
    let (dir, trust, rec_receipt, rot_receipt) = writer_rotate_scenario();
    // Omit the rotation receipt deliberately; keep the entry's.
    let verifier = Verifier::new(trust).receipts([(rec_receipt.seq(), rec_receipt.hash())]);
    let report = verifier.verify_dir(&dir.0).unwrap();
    let live = dir.0.join("audit.jsonl");
    let expected = vec![located(
        K::NoReceipt,
        live,
        4,
        3,
        format!(
            "no receipt for seq 3 hash {}",
            digest_string(&rot_receipt.hash())
        ),
    )];
    assert_findings(
        report.findings(),
        &expected,
        "operator_rotate_without_receipt_emits_no_receipt_at_rotate_record",
    );
}

// =====================================================================
// REGRESSION. Same writer-built scenario with every writer
// receipt supplied -- the "with the receipt, no finding" branch of
// ADR-0005 decision 11 l.922 and ruling 13-V7-d1 point 5.
// =====================================================================
#[test]
fn operator_rotate_with_its_receipt_has_no_reconciliation_finding() {
    let (dir, trust, rec_receipt, rot_receipt) = writer_rotate_scenario();
    // Supplied across two `.receipts(...)` calls so the second-call
    // "adds to the set" semantic (ADR-0005 decision 11 `.receipts`)
    // is exercised alongside the match.
    let verifier = Verifier::new(trust)
        .receipts([(rec_receipt.seq(), rec_receipt.hash())])
        .receipts([(rot_receipt.seq(), rot_receipt.hash())]);
    let report = verifier.verify_dir(&dir.0).unwrap();
    assert_findings(
        report.findings(),
        &[],
        "operator_rotate_with_its_receipt_has_no_reconciliation_finding",
    );
}

/// Drives the public writer API `create → record → close → rotate`
/// through two signing keys and returns the trust policy, the
/// entry's receipt and the rotation record's receipt. The rotation
/// record is the only non-checkpoint operator record in the trail.
fn writer_rotate_scenario() -> (
    Temp,
    TrustPolicy,
    crate::audit::Receipt,
    crate::audit::Receipt,
) {
    let dir = Temp::new();
    let signer_a: Arc<dyn Signer> = Arc::new(KeyFileSigner::from_hex(&"27".repeat(32)).unwrap());
    let signer_b: Arc<dyn Signer> = Arc::new(KeyFileSigner::from_hex(&"28".repeat(32)).unwrap());
    let pubkey_a = signer_a.public_key();
    let pubkey_b = signer_b.public_key();
    let trail = AuditConfig::new("svc")
        .dir(&dir.0)
        .create(signer_a)
        .unwrap();
    let trail_id = trail.trail();
    let rec_receipt = trail
        .record(&Entry::new("actor", "change", "object"))
        .unwrap();
    let close_cp = trail.close().unwrap();
    let head = (close_cp.seq(), close_cp.hash());
    let (rot_receipt, _new_opening) = AuditConfig::new("svc")
        .dir(&dir.0)
        .rotate(signer_b, head, head, "operator", "incident")
        .unwrap();
    let trust = TrustPolicy::builder()
        .trail(trail_id)
        .key(pubkey_a)
        .key(pubkey_b)
        .build()
        .unwrap();
    (dir, trust, rec_receipt, rot_receipt)
}

// =====================================================================
// ACCEPTANCE. A fork at seq=1 with receipts naming both forked
// copies at distinct forked `seq`s: each receipt is `ReceiptMismatch
// "seq is forked"` (the match rule fails closed at a forked `seq`,
// as anchors do -- ruling 13-V7-d1 point 4; clarification 13-V7-d1a
// point 1; ruling 13-V6-d1 point 2), and every distinct non-
// checkpoint record at a forked `seq` is `NoReceipt` at its own
// first copy (clarification 13-V7-d1a point 1: no receipt can
// suppress a `NoReceipt` at a forked `seq`). `SeqConflict` fires
// per fork alongside, and the shared cp0 produces one
// `DuplicateRecord`.
// =====================================================================
#[test]
fn receipt_at_forked_seq_is_forked_not_matched() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    // Alternative seq=1 payload at the fork (same previous, different
    // "object" field): a distinct hash at seq=1 produces a fork.
    let e1_alt = Record::new(context(1, cp0.hash()), Entry::new("actor", "change", "alt")).unwrap();
    // Segment 0 is the honest `[cp0, e1, cp2]`.
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let seg0 = segment_path(&d.0, 0);
    // The alternative seq=1 lives on its own sealed segment so the
    // reader sees two distinct records at seq=1 (a fork). A paired
    // cp2 chains from `e1_alt` and forks seq=2 so the match rule is
    // exercised on both a checkpoint-only and an entry fork at once.
    let cp2_alt = signed_cp_explicit(2, e1_alt.hash(), 2, [0xee; 32], vec![[0xdd; 32]]);
    put_segment(&d.0, 1, &[&cp0, &e1_alt, &cp2_alt], &[]);
    let seg1 = segment_path(&d.0, 1);
    let verifier =
        Verifier::new(trust_with_key(fixture_pubkey())).receipts([(1, e1.hash()), (2, cp2.hash())]);
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
            format!("receipt seq 1 hash {E1_HONEST_DIGEST}: seq is forked"),
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
        unlocated(
            K::ReceiptMismatch,
            Some(2),
            format!("receipt seq 2 hash {CP2_HONEST_DIGEST}: seq is forked"),
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
    assert_findings(
        report.findings(),
        &expected,
        "receipt_at_forked_seq_is_forked_not_matched",
    );
}

// =====================================================================
// ACCEPTANCE. A fork at seq=1 with ONE receipt that names ONE copy:
// `ReceiptMismatch "seq is forked"` fires for that receipt, every
// distinct record at the fork gets its own `NoReceipt` at its own
// first copy, and `SeqConflict` fires alongside (clarification
// 13-V7-d1a point 1). Paired with the dual-fork row above; here
// the honest-named receipt still does not suppress any `NoReceipt`
// -- the fork makes it fail closed.
// =====================================================================
#[test]
fn fork_with_receipt_naming_one_copy_fails_closed_each_copy() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let e1_alt = Record::new(context(1, cp0.hash()), Entry::new("actor", "change", "alt")).unwrap();
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let seg0 = segment_path(&d.0, 0);
    // The alternative seq=1 lives on its own sealed segment; a cp2
    // chain from each distinct seq=1 keeps the chain checks clean
    // (no `ChainBroken`), so this row isolates the forked-seq
    // `NoReceipt` and `ReceiptMismatch` behaviour.
    let cp2_alt = signed_cp_explicit(2, e1_alt.hash(), 2, [0xee; 32], vec![[0xdd; 32]]);
    put_segment(&d.0, 1, &[&cp0, &e1_alt, &cp2_alt], &[]);
    let seg1 = segment_path(&d.0, 1);
    // Only the honest-seq=1 receipt is supplied, plus a cp2 receipt
    // for each fork so seq=2 is fully accounted for and no NoReceipt
    // fires for the checkpoint fork.
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([
        (1, e1.hash()),
        (2, cp2.hash()),
        (2, cp2_alt.hash()),
    ]);
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
            format!("receipt seq 1 hash {E1_HONEST_DIGEST}: seq is forked"),
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
        unlocated(
            K::ReceiptMismatch,
            Some(2),
            format!("receipt seq 2 hash {CP2_HONEST_DIGEST}: seq is forked"),
        ),
        unlocated(
            K::ReceiptMismatch,
            Some(2),
            format!("receipt seq 2 hash {CP2_ALT_FROM_E1_ALT_DIGEST}: seq is forked"),
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
    assert_findings(
        report.findings(),
        &expected,
        "fork_with_receipt_naming_one_copy_fails_closed_each_copy",
    );
}

// =====================================================================
// ACCEPTANCE. Companion to the entry-fork rows above with the
// fork raised one step higher (seq=2 cp2 fork, no fork at seq=1).
// The receipt names one copy of the checkpoint at the forked
// `seq`; the shared forked predicate still refuses to match
// (clarification 13-V7-d1a point 1; ruling 13-V6-d1 point 2), so
// `ReceiptMismatch "seq is forked"` fires without reference to the
// matching copy's hash. Both forked records are checkpoints, so no
// `NoReceipt` fires at the fork (ruling 13-V7-d1 point 5).
// =====================================================================
#[test]
fn receipt_at_forked_checkpoint_seq_is_forked_not_matched() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let cp2_alt = signed_cp_explicit(2, e1.hash(), 2, [0x22; 32], vec![[0x33; 32]]);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let seg0 = segment_path(&d.0, 0);
    put_segment(&d.0, 1, &[&cp0, &e1, &cp2_alt], &[]);
    let seg1 = segment_path(&d.0, 1);
    let verifier =
        Verifier::new(trust_with_key(fixture_pubkey())).receipts([(1, e1.hash()), (2, cp2.hash())]);
    let report = report_of(vec![seg0.clone(), seg1], verifier);
    let expected = vec![
        located(
            K::DuplicateRecord,
            seg0.clone(),
            1,
            0,
            "2 copies of 1 distinct records".to_owned(),
        ),
        located(
            K::DuplicateRecord,
            seg0.clone(),
            2,
            1,
            "2 copies of 1 distinct records".to_owned(),
        ),
        unlocated(
            K::ReceiptMismatch,
            Some(2),
            format!("receipt seq 2 hash {CP2_HONEST_DIGEST}: seq is forked"),
        ),
        located(
            K::SeqConflict,
            seg0,
            3,
            2,
            format!("conflicting hashes: {CP2_HONEST_DIGEST}, {CP2_ALT_FROM_E1_DIGEST}"),
        ),
    ];
    drop(d);
    assert_findings(
        report.findings(),
        &expected,
        "receipt_at_forked_checkpoint_seq_is_forked_not_matched",
    );
}

// =====================================================================
// ACCEPTANCE. `.receipts([])` on a trail with records turns
// reconciliation on (ruling 13-V7-d1 point 2) and reports every
// `audit.record` in range as `NoReceipt`; checkpoints get no
// finding.
// =====================================================================
#[test]
fn empty_receipts_call_flags_every_audit_record() {
    let fx = three_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([]);
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![located(
        K::NoReceipt,
        fx.path,
        2,
        1,
        format!("no receipt for seq 1 hash {E1_HONEST_DIGEST}"),
    )];
    assert_findings(
        report.findings(),
        &expected,
        "empty_receipts_call_flags_every_audit_record",
    );
}

// =====================================================================
// REGRESSION. Without a `.receipts(...)` call reconciliation
// is off (ruling 13-V7-d1 point 2), even with a matching anchor
// supplied: no `NoReceipt`, no `ReceiptMismatch`, and no
// `OutOfRange` from set-aside. The anchor rule still runs on its
// own and the matching anchor gives no finding.
// =====================================================================
#[test]
fn no_receipts_call_runs_no_reconciliation() {
    let fx = three_record();
    let cp2_anchor = parse_cp(&fx.cp2);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).anchor(cp2_anchor);
    let report = report_of(vec![fx.path], verifier);
    assert_findings(
        report.findings(),
        &[],
        "no_receipts_call_runs_no_reconciliation",
    );
}

// =====================================================================
// ACCEPTANCE. Two different receipts for one `seq` are each
// evaluated independently (ruling 13-V7-d1 point 4): the matching
// one yields no finding, the other yields one `ReceiptMismatch`
// "hash differs". Supplied across two `.receipts(...)` calls so the
// "second call adds" semantic is exercised.
// =====================================================================
#[test]
fn two_receipts_one_seq_only_mismatch_fires() {
    let fx = three_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash())])
        .receipts([(1, WRONG_HASH_5A)]);
    let report = report_of(vec![fx.path], verifier);
    let expected = vec![unlocated(
        K::ReceiptMismatch,
        Some(1),
        format!(
            "receipt seq 1 hash {WRONG_HASH_5A_DIGEST}: hash differs (record {E1_HONEST_DIGEST})"
        ),
    )];
    assert_findings(
        report.findings(),
        &expected,
        "two_receipts_one_seq_only_mismatch_fires",
    );
}

// =====================================================================
// ACCEPTANCE. Two different receipts for one `seq`, both differing
// from the record: each yields its own `ReceiptMismatch "hash
// differs"` and the unnamed `(seq, record_hash)` gets one
// `NoReceipt`. Pairs with the row above by replacing the matching
// receipt with a second non-matching one, so collapse by `seq`
// alone would merge the two mismatches into one (ruling 13-V7-d1
// point 4).
// =====================================================================
#[test]
fn two_different_receipts_for_one_seq_each_emit_hash_differs() {
    let fx = three_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, WRONG_HASH_5A), (1, WRONG_HASH_66)]);
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        unlocated(
            K::ReceiptMismatch,
            Some(1),
            format!(
                "receipt seq 1 hash {WRONG_HASH_5A_DIGEST}: hash differs (record {E1_HONEST_DIGEST})"
            ),
        ),
        unlocated(
            K::ReceiptMismatch,
            Some(1),
            format!(
                "receipt seq 1 hash {WRONG_HASH_66_DIGEST}: hash differs (record {E1_HONEST_DIGEST})"
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
    assert_findings(
        report.findings(),
        &expected,
        "two_different_receipts_for_one_seq_each_emit_hash_differs",
    );
}

// =====================================================================
// REGRESSION. Two identical receipts for one `seq` collapse
// to one (ruling 13-V7-d1 point 4): the matching receipt is still
// a match, no `ReceiptMismatch` fires.
// =====================================================================
#[test]
fn identical_receipts_collapse() {
    let fx = three_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash()), (1, fx.e1.hash())]);
    let report = report_of(vec![fx.path], verifier);
    assert_findings(report.findings(), &[], "identical_receipts_collapse");
}

// =====================================================================
// ACCEPTANCE. With an accepted anchored start, a receipt
// below the start is set aside as `OutOfRange` (info) through the
// shared position classifier, and records below the start are not
// reconciled (ruling 13-V7-d1 point 3; ruling 13-V6-d3 points 4-5).
// =====================================================================
#[test]
fn receipt_below_anchored_start_is_set_aside() {
    // Archive layout: the segment starts at seq=2 (cp2) with no
    // cp0/e1 in the files. The start anchor at cp2 is both the
    // accepted start and an anchor (so the start is "anchored" per
    // ruling 13-V6-d3 point 4).
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    let e3 = entry_rec(3, cp2.hash());
    let mmr3 = pushed(&mmr2, &e3);
    let cp4 = signed_cp(4, e3.hash(), &mmr3);
    let seg = seal(&[&cp2, &e3, &cp4]);
    let cp2_checkpoint = parse_cp(&cp2);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .anchor(cp2_checkpoint.clone())
        .start_from(cp2_checkpoint)
        .receipts([(0, WRONG_HASH_5A), (3, e3.hash())]);
    let report = report_of(vec![seg.path], verifier);
    let expected = vec![unlocated(
        K::OutOfRange,
        Some(0),
        format!("receipt seq 0 hash {WRONG_HASH_5A_DIGEST}: below start seq 2"),
    )];
    assert_findings(
        report.findings(),
        &expected,
        "receipt_below_anchored_start_is_set_aside",
    );
}

// =====================================================================
// ACCEPTANCE. Second below-start layout: the accepted start is
// NOT anchored (no matching anchor is supplied), so the shared
// position classifier reports `UnanchoredStart` (error) for the
// below-start receipt instead of `OutOfRange` (info). Records below
// the accepted start are still not reconciled (ruling 13-V7-d1
// point 3; ruling 13-V6-d3 points 4-5). The start-checkpoint record
// is the record at seq=2 and gets no `NoReceipt` because
// checkpoints are not reconciled (ruling 13-V7-d1 point 5), so this
// row also pins "checkpoints need no receipt" at the accepted
// start.
// =====================================================================
#[test]
fn receipt_below_unanchored_start_is_unanchored_start() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    let e3 = entry_rec(3, cp2.hash());
    let mmr3 = pushed(&mmr2, &e3);
    let cp4 = signed_cp(4, e3.hash(), &mmr3);
    let seg = seal(&[&cp2, &e3, &cp4]);
    let cp2_checkpoint = parse_cp(&cp2);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .start_from(cp2_checkpoint)
        .receipts([(0, WRONG_HASH_5A), (3, e3.hash())]);
    let report = report_of(vec![seg.path], verifier);
    let expected = vec![unlocated(
        K::UnanchoredStart,
        Some(0),
        format!("receipt seq 0 hash {WRONG_HASH_5A_DIGEST}: below start seq 2"),
    )];
    assert_findings(
        report.findings(),
        &expected,
        "receipt_below_unanchored_start_is_unanchored_start",
    );
}

// =====================================================================
// ACCEPTANCE. With `end_before`, a receipt above `E` is set
// aside and the end record's resume line gets no `NoReceipt` even
// though no receipt names it: the end-record lines are not
// reconciled (ruling 13-V7-d1 point 3; ruling 13-V6-d7). The end
// anchor is supplied so the above-end set-aside is `OutOfRange`
// (info) rather than `UnanchoredEnd`.
// =====================================================================
#[test]
fn end_before_receipts_above_end_set_aside_end_record_not_reconciled() {
    // Files hold `[cp0, e1]`; the end record is `cp2` + a
    // `vigil.audit.resume` second line (seq=3, prev=cp2.hash) that
    // byte-equals the end anchor's first line.
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let resume_line = op_resume_rec(3, cp2.hash(), 2, cp2.hash());
    let seg = seal(&[&cp0, &e1]);
    // Build the archive-record string: cp2's line, LF, resume line
    // (no trailing LF).
    let end_record = end_record_string(&cp2, &resume_line);
    let end_anchor = parse_cp(&cp2);
    // No receipt names the resume line at seq=3 -- the end-record
    // skip is the only reason no `NoReceipt` fires for it.
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .end_before(&end_record, Some(end_anchor))
        .unwrap()
        .receipts([(1, e1.hash()), (100, WRONG_HASH_66)]);
    let report = report_of(vec![seg.path], verifier);
    let expected = vec![
        unlocated(K::Resumed, Some(3), RESUME_DETAIL_END_HEAD_CP2.to_owned()),
        unlocated(
            K::OutOfRange,
            Some(100),
            format!("receipt seq 100 hash {WRONG_HASH_66_DIGEST}: above end seq 3"),
        ),
        unlocated(K::UncoveredTail, None, "records seq 3..=3".to_owned()),
    ];
    assert_findings(
        report.findings(),
        &expected,
        "end_before_receipts_above_end_set_aside_end_record_not_reconciled",
    );
}

// =====================================================================
// ACCEPTANCE. A second `end_before` layout with no end anchor:
// the above-`E` receipt becomes `UnanchoredEnd` (error) instead of
// `OutOfRange` (info), and the end record's resume line still gets
// no `NoReceipt` even though no receipt names it (ruling 13-V7-d1
// point 3; ruling 13-V6-d7).
// =====================================================================
#[test]
fn end_before_no_anchor_resume_line_not_reconciled() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let resume_line = op_resume_rec(3, cp2.hash(), 2, cp2.hash());
    let seg = seal(&[&cp0, &e1]);
    let end_record = end_record_string(&cp2, &resume_line);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .end_before(&end_record, None)
        .unwrap()
        .receipts([(1, e1.hash()), (42, WRONG_HASH_5A)]);
    let report = report_of(vec![seg.path], verifier);
    let expected = vec![
        unlocated(
            K::UnanchoredEnd,
            Some(2),
            "end_before seq 2: no end anchor".to_owned(),
        ),
        unlocated(K::Resumed, Some(3), RESUME_DETAIL_END_HEAD_CP2.to_owned()),
        unlocated(
            K::UnanchoredEnd,
            Some(42),
            format!("receipt seq 42 hash {WRONG_HASH_5A_DIGEST}: above end seq 3"),
        ),
        unlocated(K::UncoveredTail, None, "records seq 3..=3".to_owned()),
    ];
    assert_findings(
        report.findings(),
        &expected,
        "end_before_no_anchor_resume_line_not_reconciled",
    );
}

// =====================================================================
// REGRESSION. The same `end_before` layout with a receipt that
// names the end record's resume line matches cleanly (ruling
// 13-V7-d1 point 3: a receipt naming an end-record line is still
// matched, not a mismatch).
// =====================================================================
#[test]
fn end_before_receipt_naming_resume_line_is_matched() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let resume_line = op_resume_rec(3, cp2.hash(), 2, cp2.hash());
    let seg = seal(&[&cp0, &e1]);
    let end_record = end_record_string(&cp2, &resume_line);
    let end_anchor = parse_cp(&cp2);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .end_before(&end_record, Some(end_anchor))
        .unwrap()
        .receipts([(1, e1.hash()), (3, resume_line.hash())]);
    let report = report_of(vec![seg.path], verifier);
    let expected = vec![
        unlocated(K::Resumed, Some(3), RESUME_DETAIL_END_HEAD_CP2.to_owned()),
        unlocated(K::UncoveredTail, None, "records seq 3..=3".to_owned()),
    ];
    assert_findings(
        report.findings(),
        &expected,
        "end_before_receipt_naming_resume_line_is_matched",
    );
}

// =====================================================================
// REGRESSION. Second `end_before` layout: file records strictly
// ABOVE the end record's last line (`E`) yield one `TrailEnded`
// (ruling 13-V6-d4 point 3) and no `NoReceipt` for them. Pairs
// with the two "at or above the end checkpoint" rows below by
// pinning the strictly-above-`E` case; together the three rows pin
// `TrailEnded` from `end_seq` upward and no `NoReceipt` for any
// file record in that range (ruling 13-V7-d1 point 3 and
// clarification 13-V7-d1a point 2).
// =====================================================================
#[test]
fn end_before_file_records_above_end_are_trail_ended_not_no_receipt() {
    // Files: `[cp0, e1, e_above]` with e_above at seq=3 chaining
    // from cp2 (the end record's checkpoint). End record is cp2
    // alone (no resume line), so `end_seq = E = 2`. The file record
    // at seq=3 is strictly above `E` and gets `TrailEnded` with no
    // `NoReceipt`.
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let e_above = entry_rec(3, cp2.hash());
    let seg = seal(&[&cp0, &e1, &e_above]);
    let end_record = cp_only_end_record_string(&cp2);
    let end_anchor = parse_cp(&cp2);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .end_before(&end_record, Some(end_anchor))
        .unwrap()
        .receipts([(1, e1.hash())]);
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![
        located(
            K::TrailEnded,
            seg.path,
            3,
            3,
            "end_before seq 2: records seq 3..=3 at or above the end".to_owned(),
        ),
        unlocated(K::UncoveredTail, None, "records seq 3..=3".to_owned()),
    ];
    assert_findings(
        report.findings(),
        &expected,
        "end_before_file_records_above_end_are_trail_ended_not_no_receipt",
    );
}

// =====================================================================
// ACCEPTANCE. Honest overlap: the files hold the end record's two
// lines (`cp2` + a `vigil.audit.resume` at seq=3 chaining from
// `cp2`) as their last records, and the end record carries the
// same two lines as its archive copy with the matching end anchor.
// The band from the end checkpoint's `seq` through `E` (here
// `[2..=3]`) is `TrailEnded` and not reconciled, even though `E=3`
// would put the resume line "in range" for receipt reconciliation:
// the file-record cut is at the end checkpoint's `seq`, the same
// bound `TrailEnded` opens at (ruling 13-V6-d4 point 3;
// clarification 13-V7-d1a point 2). No `NoReceipt` for the file
// resume line.
// =====================================================================
#[test]
fn end_before_file_records_in_end_band_are_trail_ended_not_no_receipt() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let resume_line = op_resume_rec(3, cp2.hash(), 2, cp2.hash());
    let seg = seal(&[&cp0, &e1, &cp2, &resume_line]);
    let end_record = end_record_string(&cp2, &resume_line);
    let end_anchor = parse_cp(&cp2);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .end_before(&end_record, Some(end_anchor))
        .unwrap()
        .receipts([(1, e1.hash())]);
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![
        located(
            K::TrailEnded,
            seg.path.clone(),
            3,
            2,
            "end_before seq 2: records seq 2..=3 at or above the end".to_owned(),
        ),
        located(
            K::Resumed,
            seg.path,
            4,
            3,
            RESUME_DETAIL_END_HEAD_CP2.to_owned(),
        ),
        unlocated(K::UncoveredTail, None, "records seq 3..=3".to_owned()),
    ];
    assert_findings(
        report.findings(),
        &expected,
        "end_before_file_records_in_end_band_are_trail_ended_not_no_receipt",
    );
}

// =====================================================================
// ACCEPTANCE. A fork at the end checkpoint's `seq`: the files
// hold an entry `e2` at seq=2 (chaining from `e1`), the end record
// is `cp2` alone (also at seq=2) with no end anchor. The two
// records at seq=2 fork, so `SeqConflict` fires at the file copy,
// `UnanchoredEnd` fires without a location, and `TrailEnded` opens
// at `end_seq=2`. The file-record cut at the end checkpoint's
// `seq` leaves no `NoReceipt` for the file `e2` even though its
// `seq` equals `E=2` (the end record has no resume line here), and
// even though the forked `seq` would otherwise mean each distinct
// record at the fork is `NoReceipt` at its own first copy
// (clarification 13-V7-d1a points 1 and 2 at once).
// =====================================================================
#[test]
fn end_before_fork_at_end_checkpoint_no_no_receipt_for_file_fork_copy() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let _mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let cp2 = signed_cp(2, e1.hash(), &_mmr1);
    let seg = seal(&[&cp0, &e1, &e2]);
    let end_record = cp_only_end_record_string(&cp2);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .end_before(&end_record, None)
        .unwrap()
        .receipts([(1, e1.hash())]);
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![
        unlocated(
            K::UnanchoredEnd,
            Some(2),
            "end_before seq 2: no end anchor".to_owned(),
        ),
        located(
            K::SeqConflict,
            seg.path.clone(),
            3,
            2,
            format!("conflicting hashes: {CP2_HONEST_DIGEST}, {E2_HONEST_DIGEST}"),
        ),
        located(
            K::TrailEnded,
            seg.path,
            3,
            2,
            "end_before seq 2: records seq 2..=2 at or above the end".to_owned(),
        ),
    ];
    assert_findings(
        report.findings(),
        &expected,
        "end_before_fork_at_end_checkpoint_no_no_receipt_for_file_fork_copy",
    );
}

/// Formats an `end_before` archive record string (checkpoint line +
/// LF + resume line, no trailing LF). Shared by the end_before rows
/// so the formatting is not spelled three times.
fn end_record_string(cp: &Record, resume: &Record) -> String {
    let mut s = String::new();
    s.push_str(std::str::from_utf8(&line_bytes(cp)).unwrap().trim_end());
    s.push('\n');
    s.push_str(std::str::from_utf8(&line_bytes(resume)).unwrap().trim_end());
    s
}

/// Formats an `end_before` archive record string with only the
/// checkpoint line (no resume second line), so `last_line_seq =
/// end_seq`.
fn cp_only_end_record_string(cp: &Record) -> String {
    std::str::from_utf8(&line_bytes(cp))
        .unwrap()
        .trim_end()
        .to_owned()
}

// =====================================================================
// ACCEPTANCE. A shipped-only `audit.record` without a
// receipt is reported as `NoReceipt` at the shipped copy (ruling
// 13-V7-d1 point 5: in-range `audit.record` is reconciled whether
// native or shipped-only). The native segment carries only the
// trusted checkpoints to pin the chain.
// =====================================================================
#[test]
fn shipped_only_record_without_receipt_gets_no_receipt() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    // Native segment: `[cp0, cp2]` -- no `e1`.
    put_segment(&d.0, 0, &[&cp0, &cp2], &[]);
    let native = segment_path(&d.0, 0);
    // Shipped file: a single-line copy of `e1`, filename outside the
    // native-segment naming scheme so the verifier reads it as a
    // shipped copy (ruling 13-V3-d2).
    let shipped = d.0.join("collector-01.jsonl");
    std::fs::write(&shipped, line_bytes(&e1)).unwrap();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([]);
    let report = report_of(vec![native, shipped.clone()], verifier);
    let expected = vec![located(
        K::NoReceipt,
        shipped,
        1,
        1,
        format!("no receipt for seq 1 hash {E1_HONEST_DIGEST}"),
    )];
    drop(d);
    assert_findings(
        report.findings(),
        &expected,
        "shipped_only_record_without_receipt_gets_no_receipt",
    );
}

// =====================================================================
// ACCEPTANCE. Companion to the shipped-only entry row above with
// the shipped record moved to an operator `vigil.audit.resume`
// record: a shipped-only operator record with no matching receipt
// still gets `NoReceipt` at its shipped copy (ruling 13-V7-d1
// point 5 covers native and shipped-only equally, and includes
// operator `vigil.audit.*` records).
// =====================================================================
#[test]
fn shipped_only_operator_record_without_receipt_gets_no_receipt() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let op = op_resume_rec(1, cp0.hash(), 0, cp0.hash());
    let mmr1 = pushed(&mmr0, &op);
    let cp2 = signed_cp(2, op.hash(), &mmr1);
    // Native segment: `[cp0, cp2]` -- the operator record is
    // shipped-only through a Collector-style filename.
    put_segment(&d.0, 0, &[&cp0, &cp2], &[]);
    let native = segment_path(&d.0, 0);
    let shipped = d.0.join("collector-op.jsonl");
    std::fs::write(&shipped, line_bytes(&op)).unwrap();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([]);
    let report = report_of(vec![native, shipped.clone()], verifier);
    let expected = vec![
        located(
            K::NoReceipt,
            shipped.clone(),
            1,
            1,
            format!("no receipt for seq 1 hash {OP_RESUME_SEQ1_DIGEST}"),
        ),
        located(
            K::Resumed,
            shipped,
            1,
            1,
            format!(
                "operator=operator reason=incident head=0:{CP0_HONEST_DIGEST} \
                 gap=none lost_records=0 structural=invalid(no-opening)"
            ),
        ),
    ];
    drop(d);
    assert_findings(
        report.findings(),
        &expected,
        "shipped_only_operator_record_without_receipt_gets_no_receipt",
    );
}

// =====================================================================
// REGRESSION. Second shipped-only layout with a matching receipt:
// the receipt names the shipped-only record's `(seq, hash)` and
// matches, so no finding fires (ruling 13-V7-d1 point 5; ruling
// 13-V5-d4: shipped-only copies count as records). Pairs with the
// `shipped_only_record_without_receipt_gets_no_receipt` row above
// by replacing the empty receipt set with a matching one.
// =====================================================================
#[test]
fn shipped_only_record_with_receipt_matches() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &cp2], &[]);
    let native = segment_path(&d.0, 0);
    let shipped = d.0.join("collector-01.jsonl");
    std::fs::write(&shipped, line_bytes(&e1)).unwrap();
    // Two `.receipts(...)` calls so the second-call "adds to the
    // set" semantic (ADR-0005 decision 11 `.receipts`) is exercised
    // alongside the match.
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, e1.hash())])
        .receipts([(2, cp2.hash())]);
    let report = report_of(vec![native, shipped], verifier);
    drop(d);
    assert_findings(
        report.findings(),
        &[],
        "shipped_only_record_with_receipt_matches",
    );
}

// =====================================================================
// REGRESSION. A `close()` checkpoint passed in as a receipt
// is checked like any other receipt (ADR-0005 decision 11:
// "A receipt may name a checkpoint"). Here `(2, cp2.hash())` names
// the close checkpoint; the record at seq=2 is that checkpoint, so
// the match holds and no finding fires.
// =====================================================================
#[test]
fn checkpoint_as_receipt_is_matched() {
    let fx = three_record();
    // Two `.receipts(...)` calls so the second-call "adds to the
    // set" semantic (ADR-0005 decision 11 `.receipts`) is exercised
    // alongside the match on the checkpoint record.
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash())])
        .receipts([(2, fx.cp2.hash())]);
    let report = report_of(vec![fx.path], verifier);
    assert_findings(report.findings(), &[], "checkpoint_as_receipt_is_matched");
}
