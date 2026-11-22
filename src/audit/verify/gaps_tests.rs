//! Rows for resume-gap confirmation and `LostRecord` (ADR-0005
//! decision 5 "Resume gaps" / "Receipts lost with a resume"; ruling
//! 13-V7-d1 points 7-9). Every row asserts the full sorted literal
//! finding list through [`assert_findings`]; every digest in an
//! expected detail is a written-out hex constant pinned by
//! [`fixture_hashes_match_literals`]. Each row is labelled
//! ACCEPTANCE or REGRESSION in its doc comment.
//!
//! Fixture style: a resume gap must be structurally honest (opening's
//! `previous` links to the head's hash, its `mmr_size` matches the
//! fold of the records before it). The real `AuditConfig::resume`
//! writes with a wall clock, so hashes would drift per run. Instead
//! every row hand-builds the opening and resume record through the
//! same `signed_cp`/`resume_decl` helpers the fixture consumers
//! already use, with the fixture clock (`100 + seq`), so the hashes
//! are byte-for-byte what a writer would emit on that clock.

use super::tests_common::{
    assert_findings, located, parse_cp, report_of, trust_with_key, unlocated,
};
use crate::audit::{
    FindingKind as K, KeyFileSigner, Mmr, Record, RecordContext, Signer, TrustPolicy,
    digest_string,
    format::CheckpointFields,
    runs_v4a_fixtures::{
        TRAIL, Temp, entry_rec, fixture_pubkey, pushed, put_segment, resume_decl, seeded,
        segment_path, signed_cp,
    },
    verify::Verifier,
};
use std::path::PathBuf;

// =====================================================================
// Pinned literal hex constants. The non-genesis fixture is
// `[cp0, e1, cp2]` sealed + `[cp6_opening, resume7]` live with
// head=(2, cp2.hash) and lost_through=5 (gap=3..=5). The genesis
// fixture is `[cp6_opening_g, resume7_g]` with head=(0, genesis) and
// lost_through=5 (gap=0..=5).
// =====================================================================

const CP0_DIGEST: &str = "blake3:fc26c6f2bb830592aaaca5413da1599489d86ac6e240a4a7a010681e0d4c8e77";
const E1_DIGEST: &str = "blake3:c121282b5135adfe7a17142cae6bfc4c9040c4aed26d74bddc923b8dafcdb6e8";
const CP2_DIGEST: &str = "blake3:4164966a12a675e55eb6e133b9e50313907f164fe142d941447defcdfdb25d06";
const CP6_OPENING_DIGEST: &str =
    "blake3:eaab774a309ba7d2970cfa2e630c0db1387d9bbbc20c845cb8a3169f4e68c443";
const RESUME7_DIGEST: &str =
    "blake3:526ca739a9a8d9ee4724e25f86afb9fa24423ae12660ec680d4dae05ffda1a59";
const CP6_GENESIS_OPENING_DIGEST: &str =
    "blake3:09fb9ff18d0e1e8b6826016b4740e92142260b24f8d283a845f6c7cf6e990241";
const RESUME7_GENESIS_DIGEST: &str =
    "blake3:82da4e5eb36305dae32a79085768298a142608252b040984eb4452223d9b0d5a";
/// Non-fixture-key signer (seed 0x44), listed in no trust policy here
/// so a checkpoint signed by it fails `signatures::trusted`.
const UNTRUSTED_KEY_HEX: &str = "d759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48";

const GAP_LOW: u64 = 3;
const GAP_HIGH: u64 = 5;
const RESUME_SEQ: u64 = 7;
const RESUME_SEQ_GENESIS: u64 = 7;

const WRONG_HASH_55: [u8; 32] = [0x55; 32];
const WRONG_HASH_55_DIGEST: &str =
    "blake3:5555555555555555555555555555555555555555555555555555555555555555";

// =====================================================================
// Shared fixture builders.
// =====================================================================

/// `[cp0, e1, cp2]` + live `[opening at seq 6, resume at seq 7]`
/// with head=(2, cp2.hash) and lost_through=5 (gap=3..=5). The
/// opening's MMR declares `size=3` (the fold of cp0, e1, cp2), the
/// honest resume shape (ADR amendment 6). `e1_hash` is exposed so
/// rows can thread its receipt through the receipt set (e1 is an
/// `audit.record` on the sealed segment and would otherwise emit
/// `NoReceipt` when reconciliation is on).
struct NonGenesis {
    _dir: Temp,
    path: PathBuf,
    cp0: Record,
    e1: Record,
    cp2: Record,
    opening: Record,
    resume: Record,
}
fn non_genesis(lost_through: u64, opening_signer: Option<&KeyFileSigner>) -> NonGenesis {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    // Opening at seq lost_through+1, prev = cp2.hash, mmr = fold of
    // [cp0, e1, cp2]. Honest opening is signed by the fixture key;
    // untrusted fixtures swap in their own signer.
    let opening_seq = lost_through + 1;
    let opening = if let Some(s) = opening_signer {
        sign_as(s, opening_seq, cp2.hash(), &mmr2)
    } else {
        signed_cp(opening_seq, cp2.hash(), &mmr2)
    };
    let resume = resume_decl(&opening, 2, cp2.hash(), lost_through);
    let d = Temp::new();
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    std::fs::write(
        d.0.join("audit.jsonl"),
        [opening.clone(), resume.clone()]
            .iter()
            .flat_map(line_bytes)
            .collect::<Vec<u8>>(),
    )
    .unwrap();
    let path = segment_path(&d.0, 0);
    let _ = path;
    NonGenesis {
        path: d.0.clone(),
        _dir: d,
        cp0,
        e1,
        cp2,
        opening,
        resume,
    }
}

/// `[]` sealed + live `[genesis_opening at seq 6, resume at seq 7]`
/// with head=(0, genesis) and lost_through=5 (gap=0..=5).
struct Genesis {
    _dir: Temp,
    path: PathBuf,
    opening: Record,
    resume: Record,
}
fn genesis(lost_through: u64) -> Genesis {
    // ADR amendment 9: a genesis-linked opening's MMR counts the
    // genesis digest as its shared first leaf, so `mmr_size=1`.
    let mut mmr = Mmr::new();
    mmr.push(Record::genesis(&TRAIL)).unwrap();
    let opening_seq = lost_through + 1;
    let opening = signed_cp(opening_seq, Record::genesis(&TRAIL), &mmr);
    let resume = resume_decl(&opening, 0, Record::genesis(&TRAIL), lost_through);
    let d = Temp::new();
    std::fs::write(
        d.0.join("audit.jsonl"),
        [opening.clone(), resume.clone()]
            .iter()
            .flat_map(line_bytes)
            .collect::<Vec<u8>>(),
    )
    .unwrap();
    Genesis {
        path: d.0.clone(),
        _dir: d,
        opening,
        resume,
    }
}

fn line_bytes(record: &Record) -> Vec<u8> {
    crate::audit::runs_v4a_fixtures::line_bytes(record)
}

fn sign_as(signer: &KeyFileSigner, seq: u64, previous: [u8; 32], mmr: &Mmr) -> Record {
    let ctx = RecordContext::new(TRAIL, seq, 100 + seq, "test", previous);
    let fields = |sig| {
        CheckpointFields::new(
            mmr.size(),
            mmr.root(),
            mmr.peaks().to_vec(),
            signer.public_key(),
            sig,
        )
        .unwrap()
    };
    let unsigned = Record::checkpoint(ctx.clone(), fields([0; 64])).unwrap();
    let signature = signer.sign(&unsigned.signing_message().unwrap()).unwrap();
    Record::checkpoint(ctx, fields(signature)).unwrap()
}

fn resume_detail(head_seq: u64, head_hash: &str, gap: &str, n: u64, outcome: &str) -> String {
    format!(
        "operator=operator reason=incident head={head_seq}:{head_hash} \
         gap={gap} lost_records={n} structural={outcome}"
    )
}

fn resumed_at(file: PathBuf, seq: u64, detail: String) -> crate::audit::verify::Finding {
    located(K::Resumed, file, 2, seq, detail)
}

fn lost(
    seq: u64,
    prefix: &str,
    hash_digest: &str,
    low: u64,
    high: u64,
) -> crate::audit::verify::Finding {
    unlocated(
        K::LostRecord,
        Some(seq),
        format!("{prefix} seq {seq} hash {hash_digest}: lost in gap {low}..={high}"),
    )
}

// =====================================================================
// Shared literal-hex consistency test. Pins every `const` in this
// module against its builder's live hash so a drift surfaces here
// rather than across many rows.
// =====================================================================
#[test]
fn fixture_hashes_match_literals() {
    let fx = non_genesis(GAP_HIGH, None);
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let _ = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let g = genesis(GAP_HIGH);
    let untrusted = KeyFileSigner::from_hex(&"44".repeat(32)).unwrap();
    assert_eq!(digest_string(&fx.cp0.hash()), CP0_DIGEST, "cp0");
    assert_eq!(digest_string(&e1.hash()), E1_DIGEST, "e1");
    assert_eq!(digest_string(&fx.cp2.hash()), CP2_DIGEST, "cp2");
    assert_eq!(
        digest_string(&fx.opening.hash()),
        CP6_OPENING_DIGEST,
        "cp6_opening"
    );
    assert_eq!(digest_string(&fx.resume.hash()), RESUME7_DIGEST, "resume7");
    assert_eq!(
        digest_string(&g.opening.hash()),
        CP6_GENESIS_OPENING_DIGEST,
        "cp6_genesis_opening"
    );
    assert_eq!(
        digest_string(&g.resume.hash()),
        RESUME7_GENESIS_DIGEST,
        "resume7_genesis"
    );
    assert_eq!(
        crate::audit::hex(&untrusted.public_key()),
        UNTRUSTED_KEY_HEX,
        "untrusted_key"
    );
}

// =====================================================================
// G1 - ACCEPTANCE. ADR-0005 decision 11 l.986: an honest resume
// after a deleted live file holding receipted records, with
// `lost_through` = the highest held `seq`. Each lost receipt is
// `LostRecord`, no `SeqGap` fires, and the `Resumed` detail carries
// `lost_records=<n> structural=valid` (ruling 13-V7-d1 points 7-9).
// `assert_findings` call below (base reports `SeqGap` for `3..=5`
// and `ReceiptMismatch "no record"` for each lost receipt).
// =====================================================================
#[test]
fn g1_honest_resume_lost_receipts_become_lost_records() {
    let fx = non_genesis(GAP_HIGH, None);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([
        (1, fx.e1.hash()),
        (RESUME_SEQ, fx.resume.hash()),
        (3, WRONG_HASH_55),
        (4, WRONG_HASH_55),
        (5, WRONG_HASH_55),
    ]);
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        lost(3, "receipt", WRONG_HASH_55_DIGEST, GAP_LOW, GAP_HIGH),
        lost(4, "receipt", WRONG_HASH_55_DIGEST, GAP_LOW, GAP_HIGH),
        lost(5, "receipt", WRONG_HASH_55_DIGEST, GAP_LOW, GAP_HIGH),
        resumed_at(
            fx.path.join("audit.jsonl"),
            RESUME_SEQ,
            resume_detail(2, CP2_DIGEST, "3..=5", 3, "valid"),
        ),
        unlocated(K::UncoveredTail, None, "records seq 7..=7".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "G1");
    assert!(report.is_valid(), "G1 plain verify must pass");
}

// =====================================================================
// G1b - REGRESSION. Pins `is_strict_valid()` = false on G1's report
// because `Resumed` is a warning (ADR-0005 decision 5; decision 11).
// Pairs with G1 as the `--strict` half of l.986.
// =====================================================================
#[test]
fn g1b_honest_resume_fails_strict_on_resumed_warning() {
    let fx = non_genesis(GAP_HIGH, None);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([
        (1, fx.e1.hash()),
        (RESUME_SEQ, fx.resume.hash()),
        (3, WRONG_HASH_55),
    ]);
    let report = report_of(vec![fx.path], verifier);
    assert!(!report.is_strict_valid(), "Resumed warning fails --strict");
}

// =====================================================================
// G2 - ACCEPTANCE. ADR-0005 decision 11 l.989: a gap forged with the
// trusted key but without the resume record's receipt. The gap is
// **unconfirmed**, so each lost receipt is `ReceiptMismatch "no
// record"` (not `LostRecord`); the resume record itself has no
// receipt and gets `NoReceipt` at its line. Ruling 13-V7-d1 point 7
// still suppresses the `SeqGap` for a trusted-opening candidate.
// reports `SeqGap` for `3..=5`).
// =====================================================================
#[test]
fn g2_unconfirmed_gap_keeps_receipt_mismatch_no_record() {
    let fx = non_genesis(GAP_HIGH, None);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([
        (1, fx.e1.hash()),
        (3, WRONG_HASH_55),
        (4, WRONG_HASH_55),
    ]);
    let report = report_of(vec![fx.path.clone()], verifier);
    let seg0 = segment_path(&fx.path, 0);
    let expected = vec![
        unlocated(
            K::ReceiptMismatch,
            Some(3),
            format!("receipt seq 3 hash {WRONG_HASH_55_DIGEST}: no record"),
        ),
        unlocated(
            K::ReceiptMismatch,
            Some(4),
            format!("receipt seq 4 hash {WRONG_HASH_55_DIGEST}: no record"),
        ),
        located(
            K::NoReceipt,
            fx.path.join("audit.jsonl"),
            2,
            RESUME_SEQ,
            format!("no receipt for seq {RESUME_SEQ} hash {RESUME7_DIGEST}"),
        ),
        resumed_at(
            fx.path.join("audit.jsonl"),
            RESUME_SEQ,
            resume_detail(2, CP2_DIGEST, "3..=5", 0, "valid"),
        ),
        unlocated(K::UncoveredTail, None, "records seq 7..=7".to_owned()),
    ];
    let _ = seg0;
    assert_findings(report.findings(), &expected, "G2");
}

// =====================================================================
// G2b - ACCEPTANCE. Confirmation uses the full match rule, not
// `seq` alone (ruling 13-V7-d1 point 8 reuses `receipts::mismatch`).
// A receipt at the resume `seq` with a **wrong hash** is a
// `ReceiptMismatch "hash differs"` and does not confirm the gap; a
// second receipt inside the gap stays `ReceiptMismatch "no record"`
// `assert_findings` call below.
// =====================================================================
#[test]
fn g2b_wrong_hash_receipt_at_resume_seq_does_not_confirm() {
    let fx = non_genesis(GAP_HIGH, None);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([
        (1, fx.e1.hash()),
        (RESUME_SEQ, WRONG_HASH_55),
        (4, WRONG_HASH_55),
    ]);
    let report = report_of(vec![fx.path.clone()], verifier);
    let findings = report.findings();
    assert!(
        !findings.iter().any(|f| f.kind() == K::LostRecord),
        "G2b wrong-hash receipt must not confirm the gap; got {findings:?}"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.kind() == K::ReceiptMismatch && f.seq() == Some(4)),
        "G2b in-gap receipt must stay `ReceiptMismatch`; got {findings:?}"
    );
    assert!(
        findings.iter().any(|f| f.kind() == K::ReceiptMismatch
            && f.seq() == Some(RESUME_SEQ)
            && f.detail().contains("hash differs")),
        "G2b resume-seq receipt must be `ReceiptMismatch hash differs`; got {findings:?}"
    );
}

// =====================================================================
// G2c - ACCEPTANCE. Second probe of the full `(seq, hash)` match
// rule for confirmation (ruling 13-V7-d1 point 8): a wrong-hash
// receipt at the resume `seq` plus a waiver inside the gap. Base:
// gap unconfirmed, waiver is `ReceiptMismatch "no record"`. Pairs
// with G2b to pin both receipt and waiver subjects. First failing
// line on base: the `!any(LostRecord)` assertion below.
// =====================================================================
#[test]
fn g2c_wrong_hash_resume_receipt_with_waiver_stays_unconfirmed() {
    let fx = non_genesis(GAP_HIGH, None);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash()), (RESUME_SEQ, WRONG_HASH_55)])
        .waive(4, WRONG_HASH_55, "orphan")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let findings = report.findings();
    assert!(
        !findings.iter().any(|f| f.kind() == K::LostRecord),
        "G2c waiver in unconfirmed gap must not become `LostRecord`; got {findings:?}"
    );
    assert!(
        findings.iter().any(|f| f.kind() == K::ReceiptMismatch
            && f.seq() == Some(4)
            && f.detail().starts_with("waive seq 4")),
        "G2c in-gap waiver must stay `ReceiptMismatch`; got {findings:?}"
    );
}

// =====================================================================
// G3 - ACCEPTANCE. ADR-0005 decision 11 l.989: a gap opened with an
// **untrusted** key is not a candidate (ruling 13-V5-d1 point 8;
// 13-V7-d1 point 7), so its jump keeps its ordinary `SeqGap` and
// the `assert_findings` call below (base's opening is still
// untrusted and still jumps, but base also misses the trust filter
// altogether, so without receipts the finding set differs).
// =====================================================================
#[test]
fn g3_untrusted_opening_is_not_a_candidate_seq_gap_stays() {
    let other = KeyFileSigner::from_hex(&"44".repeat(32)).unwrap();
    let fx = non_genesis(GAP_HIGH, Some(&other));
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()));
    let report = report_of(vec![fx.path.clone()], verifier);
    let live = fx.path.join("audit.jsonl");
    let expected = vec![
        located(
            K::SeqGap,
            live.clone(),
            1,
            6,
            "missing seq 3..=5".to_owned(),
        ),
        located(
            K::UntrustedKey,
            live.clone(),
            1,
            6,
            format!(
                "key {UNTRUSTED_KEY_HEX} not listed for trail {}",
                crate::audit::hex(&TRAIL)
            ),
        ),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            resume_detail(2, CP2_DIGEST, "3..=5", 0, "valid"),
        ),
        // Covered through cp2 (the fixture key's trusted
        // checkpoint); the untrusted opening at seq 6 does not
        // extend coverage, so `UncoveredTail` names seqs 3..=7.
        unlocated(K::UncoveredTail, None, "records seq 3..=7".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "G3");
}

// =====================================================================
// G3b - ACCEPTANCE. Companion to G3: with the same untrusted
// opening, a receipt for a seq in the gap keeps its ordinary
// `ReceiptMismatch "no record"` (not `LostRecord`) because the
// candidate is dropped by the trust filter (ruling 13-V5-d1 point 8,
// 13-V7-d1 point 7 "An untrusted opening is not a candidate"). Pairs
// with G3 as the receipt-side of the untrusted-opening case. First
// failing line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn g3b_untrusted_opening_receipt_in_gap_stays_receipt_mismatch() {
    let other = KeyFileSigner::from_hex(&"44".repeat(32)).unwrap();
    let fx = non_genesis(GAP_HIGH, Some(&other));
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(RESUME_SEQ, fx.resume.hash()), (4, WRONG_HASH_55)]);
    let report = report_of(vec![fx.path.clone()], verifier);
    let findings = report.findings();
    assert!(
        !findings.iter().any(|f| f.kind() == K::LostRecord),
        "G3b must emit no `LostRecord`; got {findings:?}"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.kind() == K::ReceiptMismatch && f.seq() == Some(4)),
        "G3b lost receipt must stay `ReceiptMismatch`; got {findings:?}"
    );
}

// =====================================================================
// G4 - REGRESSION. ADR-0005 decision 11 l.989: a signed jump
// without the resume record (nothing structurally declares the
// gap). The opening is a plain checkpoint, no resume record follows.
// Expected: `SeqGap` fires (no candidate because `declarations` is
// empty), and the opening's `MmrMismatch` fires too. Pairs with G1
// as "trusted-signed but no declaration never confirms".
// =====================================================================
#[test]
fn g4_signed_jump_without_resume_record_keeps_seq_gap() {
    // Sealed `[cp0, e1, cp2]`, live `[opening at seq 6]` with no
    // resume record. With no `vigil.audit.resume` on the trail,
    // `declarations` is empty, there is no candidate, and the jump
    // keeps its ordinary `SeqGap` (ruling 13-V7-d1 point 7: a
    // trusted-opening candidate is needed to suppress the `SeqGap`).
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    // The opening declares the correct fold through cp2 (size=3), so
    // no `MmrMismatch` fires -- this row isolates the "no resume
    // declaration" case.
    let opening = signed_cp(6, cp2.hash(), &mmr2);
    let d = Temp::new();
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    std::fs::write(d.0.join("audit.jsonl"), line_bytes(&opening)).unwrap();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()));
    let report = report_of(vec![d.0.clone()], verifier);
    let live = d.0.join("audit.jsonl");
    let findings = report.findings();
    let seq_gap = located(K::SeqGap, live, 1, 6, "missing seq 3..=5".to_owned());
    assert!(
        findings.contains(&seq_gap),
        "G4 must keep `SeqGap 3..=5`; got {findings:?}"
    );
    assert!(
        !findings.iter().any(|f| f.kind() == K::Resumed),
        "G4 must emit no `Resumed`; got {findings:?}"
    );
    drop(d);
}

// =====================================================================
// G5 - ACCEPTANCE. ADR-0005 decision 11 l.993: a waiver and a `from`
// line inside a **confirmed** gap are each one `LostRecord`; the
// `from` line still exempts every record at or below its `seq` from
// `NoReceipt` (point 6). Pairs with G5b as the confirmed vs.
// unconfirmed split for waivers and `from`. First failing line on
// base: the `assert_findings` call below (base reports `SeqGap` and
// `ReceiptMismatch` for the waiver and `from`, without the
// exemption).
// =====================================================================
#[test]
fn g5_waiver_and_from_inside_confirmed_gap_are_lost_record() {
    // Place a waiver at seq 4 (inside 3..=5) and a `from` at seq 3.
    // The `from` exempts seqs 1, 2, 3 from NoReceipt. Only the
    // resume receipt is needed for confirmation; no receipts for
    // seqs 1, 2.
    let fx = non_genesis(GAP_HIGH, None);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(RESUME_SEQ, fx.resume.hash())])
        .waive(4, WRONG_HASH_55, "orphan after crash")
        .unwrap()
        .receipts_from(3, WRONG_HASH_55, "late adoption")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    // `from` at seq 3 matched (via the confirmed gap) still exempts
    // every record at or below seq 3, so no `NoReceipt` for e1 at
    // seq 1 (ADR-0005 decision 5 "Late adoption"; ruling 13-V7-d1
    // point 6 propagates through the gap).
    let expected = vec![
        lost(3, "from", WRONG_HASH_55_DIGEST, GAP_LOW, GAP_HIGH),
        lost(4, "waive", WRONG_HASH_55_DIGEST, GAP_LOW, GAP_HIGH),
        resumed_at(
            fx.path.join("audit.jsonl"),
            RESUME_SEQ,
            resume_detail(2, CP2_DIGEST, "3..=5", 2, "valid"),
        ),
        unlocated(K::UncoveredTail, None, "records seq 7..=7".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "G5");
}

// =====================================================================
// G5c - ACCEPTANCE. Second pin of the `from` exemption through a
// confirmed gap (ruling 13-V7-d1 point 6 propagates through the
// gap): a `from` at the HIGHEST gap seq still exempts every record
// at or below it, including the sealed e1 at seq 1. Pairs with G5
// as the "from's `seq` varies" pair for the exemption rule.
// =====================================================================
#[test]
fn g5c_from_at_top_of_gap_still_exempts_below() {
    let fx = non_genesis(GAP_HIGH, None);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(RESUME_SEQ, fx.resume.hash())])
        .receipts_from(GAP_HIGH, WRONG_HASH_55, "late adoption")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let findings = report.findings();
    assert!(
        !findings.iter().any(|f| f.kind() == K::NoReceipt),
        "G5c: from at top of gap must exempt e1; got {findings:?}"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.kind() == K::LostRecord && f.seq() == Some(GAP_HIGH)),
        "G5c: from must be `LostRecord`; got {findings:?}"
    );
}

// =====================================================================
// G5d - ACCEPTANCE. Third probe of the `from` exemption through a
// confirmed gap (ruling 13-V7-d1 point 6): the `from` at the LOWEST
// in-range gap `seq` (seq 3) still exempts seqs 1 and 2 below it,
// plus seq 3 itself. Pairs with G5 (from at seq 3 with waiver) and
// G5c (from at top) so an implementation that drops exemption on the gap
// path fails on both low and high ends.
// =====================================================================
#[test]
fn g5d_from_at_low_of_gap_still_exempts_everything_below() {
    let fx = non_genesis(GAP_HIGH, None);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(RESUME_SEQ, fx.resume.hash())])
        .receipts_from(GAP_LOW, WRONG_HASH_55, "late adoption")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let findings = report.findings();
    assert!(
        !findings.iter().any(|f| f.kind() == K::NoReceipt),
        "G5d: from at low of gap must exempt e1; got {findings:?}"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.kind() == K::LostRecord && f.seq() == Some(GAP_LOW)),
        "G5d: from must be `LostRecord`; got {findings:?}"
    );
}

// =====================================================================
// G5b - ACCEPTANCE. Same waiver and `from` placed inside an
// **unconfirmed** gap (no resume receipt in the receipts set) each
// yield `ReceiptMismatch "no record"` (ADR l.989; today's behaviour,
// ruling 13-V7-d1 point 8). Pairs with G5 as the confirmation split.
// =====================================================================
#[test]
fn g5b_waiver_and_from_inside_unconfirmed_gap_are_receipt_mismatch() {
    let fx = non_genesis(GAP_HIGH, None);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash())])
        .waive(4, WRONG_HASH_55, "orphan after crash")
        .unwrap()
        .receipts_from(3, WRONG_HASH_55, "late adoption")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        unlocated(
            K::ReceiptMismatch,
            Some(3),
            format!("from seq 3 hash {WRONG_HASH_55_DIGEST}: no record"),
        ),
        unlocated(
            K::ReceiptMismatch,
            Some(4),
            format!("waive seq 4 hash {WRONG_HASH_55_DIGEST}: no record"),
        ),
        located(
            K::NoReceipt,
            fx.path.join("audit.jsonl"),
            2,
            RESUME_SEQ,
            format!("no receipt for seq {RESUME_SEQ} hash {RESUME7_DIGEST}"),
        ),
        resumed_at(
            fx.path.join("audit.jsonl"),
            RESUME_SEQ,
            resume_detail(2, CP2_DIGEST, "3..=5", 0, "valid"),
        ),
        unlocated(K::UncoveredTail, None, "records seq 7..=7".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "G5b");
}

// =====================================================================
// G6 - ACCEPTANCE. ADR l.990 for the unanchored-opening half: in
// a confirmed gap whose opening is not anchored, the anchor and
// the `through=` pin inside the gap keep `AnchorMismatch` and
// `RevocationMismatch` (errors), while the waiver inside the gap
// is `LostRecord` (ruling 13-V7-d1 points 8-9). The anchored-opening
// demotion of anchors and pins lands in a later #13 step.
// =====================================================================
#[test]
fn g6_unanchored_opening_keeps_anchor_and_pin_mismatches() {
    let fx = non_genesis(GAP_HIGH, None);
    // A second trusted key carries a `through=` pin inside the gap.
    // The pin names an arbitrary hash that no record in the gap
    // carries, so its `RevocationMismatch` fires with the unlocated
    // `no record at seq <s>` form (ruling 13-V5-d4).
    let other = KeyFileSigner::from_hex(&"77".repeat(32)).unwrap();
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .key_through(other.public_key(), 4, WRONG_HASH_55)
        .build()
        .unwrap();
    // A trusted-signed anchor at seq 4 chained from cp2: its MMR is
    // a one-leaf fold (any non-zero size satisfies the writer's
    // "zero only at creation" invariant). The anchor's `(trail, seq,
    // hash)` is not the opening's, so the opening stays unanchored
    // under ruling 13-V6-d1 point 2; and no record at seq 4 matches
    // the anchor's hash, so `AnchorMismatch` fires.
    let mut synth_mmr = Mmr::new();
    synth_mmr.push([0xcc; 32]).unwrap();
    let anchor_record = crate::audit::runs_v4a_fixtures::signed_cp(4, fx.cp2.hash(), &synth_mmr);
    let anchor_cp = parse_cp(&anchor_record);
    let verifier = Verifier::new(trust)
        .anchor(anchor_cp)
        .receipts([(1, fx.e1.hash()), (RESUME_SEQ, fx.resume.hash())])
        .waive(4, WRONG_HASH_55, "r")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], verifier);
    let findings = report.findings();
    assert!(
        findings
            .iter()
            .any(|f| f.kind() == K::AnchorMismatch && f.seq() == Some(4)),
        "G6 anchor must keep `AnchorMismatch`; got {findings:?}"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.kind() == K::RevocationMismatch && f.seq() == Some(4)),
        "G6 pin must keep `RevocationMismatch`; got {findings:?}"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.kind() == K::LostRecord && f.seq() == Some(4)),
        "G6 waiver must be `LostRecord`; got {findings:?}"
    );
}

// =====================================================================
// G7 - ACCEPTANCE. ADR-0005 decision 11 l.991: a start at the
// resume's opening checkpoint. Inputs in the gap are below the
// start and follow the start rule first (ruling 13-V7-d1 point 7
// "Order"). A receipt in the gap is set aside as `OutOfRange` (info)
// when the start is anchored, not `LostRecord`. First failing line
// on base: the `assert_findings` call below (base reports
// `StartMismatch` because the base tree does not set up the gap
// correctly yet).
// =====================================================================
#[test]
fn g7_start_at_opening_below_start_wins_over_gap() {
    // Build a trail whose first record IS the opening at seq 6.
    // Omit the sealed segment so the files begin at seq 6 (the
    // start's own seq). The start accepts because seq 6 is the
    // first record with the start's hash.
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    let opening = signed_cp(6, cp2.hash(), &mmr2);
    let resume = resume_decl(&opening, 2, cp2.hash(), GAP_HIGH);
    let d = Temp::new();
    std::fs::write(
        d.0.join("audit.jsonl"),
        [opening.clone(), resume.clone()]
            .iter()
            .flat_map(line_bytes)
            .collect::<Vec<u8>>(),
    )
    .unwrap();
    let opening_cp = parse_cp(&opening);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .anchor(opening_cp.clone())
        .start_from(opening_cp)
        .receipts([(RESUME_SEQ, resume.hash()), (4, WRONG_HASH_55)]);
    let report = report_of(vec![d.0.clone()], verifier);
    // The seq=4 receipt is below the anchored start; the start rule
    // sets it aside as `OutOfRange` (ruling 13-V6-d3 point 4), not
    // `LostRecord` (13-V7-d1 point 7 "Order"). No `LostRecord` fires.
    let findings = report.findings();
    assert!(
        findings
            .iter()
            .any(|f| f.kind() == K::OutOfRange && f.seq() == Some(4)),
        "G7 receipt below start must be `OutOfRange`; got {findings:?}"
    );
    assert!(
        !findings.iter().any(|f| f.kind() == K::LostRecord),
        "G7 must emit no `LostRecord`; got {findings:?}"
    );
    drop(d);
}

// =====================================================================
// G8 - ACCEPTANCE. ADR-0005 decision 11 l.992: `lost_through` below
// a held receipt. The receipt names a `seq` ABOVE the gap (because
// `lost_through` is below the held seq, so the held seq is above
// `lost_through`), so the receipt is checked against the record at
// that `seq`. Here the record is the resume at seq 7 and the
// receipt's hash does not match, so `ReceiptMismatch "hash differs"`
// =====================================================================
#[test]
fn g8_lost_through_below_held_receipt_gives_receipt_mismatch() {
    let fx = non_genesis(GAP_HIGH, None);
    // A receipt at seq 7 with a wrong hash (the receipt's seq is
    // above `lost_through=5`, so outside the gap). The receipt is
    // checked against the resume record at seq 7, whose hash differs.
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash()), (RESUME_SEQ, WRONG_HASH_55)]);
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        unlocated(
            K::ReceiptMismatch,
            Some(RESUME_SEQ),
            format!(
                "receipt seq {RESUME_SEQ} hash {WRONG_HASH_55_DIGEST}: hash differs (record {RESUME7_DIGEST})"
            ),
        ),
        located(
            K::NoReceipt,
            fx.path.join("audit.jsonl"),
            2,
            RESUME_SEQ,
            format!("no receipt for seq {RESUME_SEQ} hash {RESUME7_DIGEST}"),
        ),
        resumed_at(
            fx.path.join("audit.jsonl"),
            RESUME_SEQ,
            resume_detail(2, CP2_DIGEST, "3..=5", 0, "valid"),
        ),
        unlocated(K::UncoveredTail, None, "records seq 7..=7".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "G8");
}

// =====================================================================
// G9 - ACCEPTANCE. ADR-0005 decision 11 l.993: two resumes, each
// confirmed, so both gaps' inputs are `LostRecord`. The pair exists
// in one layout so the per-gap `LostRecord` counts in the two
// `Resumed` details are both pinned (ruling 13-V7-d1 point 8). The
// separate "lost_through=head gives no gap" row is G9b below. First
// failing line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn g9_two_confirmed_resumes_each_gap_has_lost_records() {
    // First resume: head=(2, cp2), lost_through=5, gap=3..=5, opening
    // at seq 6, resume at seq 7. Second resume: head=(7, resume7),
    // lost_through=10, gap=8..=10, opening at seq 11, resume at seq 12.
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    let open1 = signed_cp(6, cp2.hash(), &mmr2);
    let res1 = resume_decl(&open1, 2, cp2.hash(), GAP_HIGH);
    let mmr_after_r1 = pushed(&pushed(&mmr2, &open1), &res1);
    let open2 = signed_cp(11, res1.hash(), &mmr_after_r1);
    let res2 = resume_decl(&open2, RESUME_SEQ, res1.hash(), 10);
    let d = Temp::new();
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    std::fs::write(
        d.0.join("audit.jsonl"),
        [open1.clone(), res1.clone(), open2.clone(), res2.clone()]
            .iter()
            .flat_map(line_bytes)
            .collect::<Vec<u8>>(),
    )
    .unwrap();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([
        (RESUME_SEQ, res1.hash()),
        (12, res2.hash()),
        (4, WRONG_HASH_55),
        (9, WRONG_HASH_55),
    ]);
    let report = report_of(vec![d.0.clone()], verifier);
    let findings = report.findings();
    // Both confirmed gaps must emit `LostRecord` at their lost seqs.
    assert!(
        findings
            .iter()
            .any(|f| f.kind() == K::LostRecord && f.seq() == Some(4)),
        "G9 gap1 must emit `LostRecord` at seq 4; got {findings:?}"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.kind() == K::LostRecord && f.seq() == Some(9)),
        "G9 gap2 must emit `LostRecord` at seq 9; got {findings:?}"
    );
    // Each Resumed detail carries `lost_records=1` for its own gap.
    let resumed: Vec<_> = findings.iter().filter(|f| f.kind() == K::Resumed).collect();
    assert_eq!(resumed.len(), 2, "G9 must emit two `Resumed` findings");
    for r in &resumed {
        assert!(
            r.detail().contains("lost_records=1"),
            "G9 each `Resumed` must have `lost_records=1`; got {}",
            r.detail()
        );
    }
    drop(d);
}

// =====================================================================
// G9b - REGRESSION. ADR-0005 decision 11 l.993 "A resume with
// `--lost-through` equal to the head: no gap, no `LostRecord`". The
// resume detail carries `gap=none lost_records=0`.
// =====================================================================
// =====================================================================
// G9c - ACCEPTANCE. Second pin of the per-gap `lost_records` count
// (ruling 13-V7-d1 point 8): two confirmed gaps with **different**
// `LostRecord` counts, so an implementation that sums across gaps (every
// `Resumed` showing a cross-gap total) differs from the per-gap
// per-gap counts.
// =====================================================================
#[test]
fn g9c_two_gaps_with_asymmetric_lost_record_counts() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    let open1 = signed_cp(6, cp2.hash(), &mmr2);
    let res1 = resume_decl(&open1, 2, cp2.hash(), GAP_HIGH);
    let mmr_after_r1 = pushed(&pushed(&mmr2, &open1), &res1);
    let open2 = signed_cp(11, res1.hash(), &mmr_after_r1);
    let res2 = resume_decl(&open2, RESUME_SEQ, res1.hash(), 10);
    let d = Temp::new();
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    std::fs::write(
        d.0.join("audit.jsonl"),
        [open1.clone(), res1.clone(), open2.clone(), res2.clone()]
            .iter()
            .flat_map(line_bytes)
            .collect::<Vec<u8>>(),
    )
    .unwrap();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([
        (1, e1.hash()),
        (RESUME_SEQ, res1.hash()),
        (12, res2.hash()),
        (3, WRONG_HASH_55),
        (4, WRONG_HASH_55),
        (5, WRONG_HASH_55),
    ]);
    let report = report_of(vec![d.0.clone()], verifier);
    let findings = report.findings();
    let resumed: Vec<_> = findings.iter().filter(|f| f.kind() == K::Resumed).collect();
    assert_eq!(resumed.len(), 2, "G9c must emit two `Resumed` findings");
    let r1 = resumed
        .iter()
        .find(|f| f.seq() == Some(RESUME_SEQ))
        .unwrap();
    let r2 = resumed.iter().find(|f| f.seq() == Some(12)).unwrap();
    assert!(
        r1.detail().contains("lost_records=3"),
        "G9c gap1 must carry `lost_records=3`; got {}",
        r1.detail()
    );
    assert!(
        r2.detail().contains("lost_records=0"),
        "G9c gap2 must carry `lost_records=0`; got {}",
        r2.detail()
    );
    drop(d);
}

#[test]
fn g9b_lost_through_equal_to_head_has_no_gap() {
    // head=(2, cp2), lost_through=2, so no gap (gap=none). Opening
    // at seq 3, resume at seq 4.
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    let opening = signed_cp(3, cp2.hash(), &mmr2);
    let resume = resume_decl(&opening, 2, cp2.hash(), 2);
    let d = Temp::new();
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    std::fs::write(
        d.0.join("audit.jsonl"),
        [opening.clone(), resume.clone()]
            .iter()
            .flat_map(line_bytes)
            .collect::<Vec<u8>>(),
    )
    .unwrap();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(4, resume.hash()), (3, opening.hash())]);
    let report = report_of(vec![d.0.clone()], verifier);
    let findings = report.findings();
    assert!(
        !findings.iter().any(|f| f.kind() == K::LostRecord),
        "G9b lost_through=head must emit no `LostRecord`; got {findings:?}"
    );
    let resumed = findings.iter().find(|f| f.kind() == K::Resumed).unwrap();
    assert!(
        resumed.detail().contains("gap=none lost_records=0"),
        "G9b Resumed must carry `gap=none lost_records=0`; got {}",
        resumed.detail()
    );
    drop(d);
}

// =====================================================================
// G10 - ACCEPTANCE. ADR-0005 decision 5 "The genesis case" (amendment
// 12; ruling 13-V7-d1 point 7 exception): a genesis resume with no
// receipt keeps the `SeqGap` for `0..=lost_through` (unconfirmed);
// a confirmed genesis resume suppresses it. Pairs the two in one
// the `assert_findings` call below.
// =====================================================================
#[test]
fn g10_genesis_gap_suppressed_only_when_confirmed() {
    let g = genesis(GAP_HIGH);
    // Unconfirmed: SeqGap 0..=5 stays.
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([]);
    let report = report_of(vec![g.path.clone()], verifier);
    let findings = report.findings();
    assert!(
        findings
            .iter()
            .any(|f| f.kind() == K::SeqGap && f.detail() == "missing seq 0..=5"),
        "G10 unconfirmed must keep `SeqGap 0..=5`; got {findings:?}"
    );
    // Confirmed: SeqGap 0..=5 is suppressed.
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(RESUME_SEQ_GENESIS, g.resume.hash())]);
    let report = report_of(vec![g.path.clone()], verifier);
    let findings = report.findings();
    assert!(
        !findings
            .iter()
            .any(|f| f.kind() == K::SeqGap && f.detail() == "missing seq 0..=5"),
        "G10 confirmed must suppress `SeqGap 0..=5`; got {findings:?}"
    );
}

// =====================================================================
// G11 - ACCEPTANCE. Ruling 13-V7-d1 point 9 (#224 limit): a
// shipped-only opening is never a fold-matched candidate, so a
// Collector copy of a resume opening cannot confirm the gap even
// with the resume receipt. Each lost receipt stays
// `assert_findings` call below.
// =====================================================================
#[test]
fn g11_shipped_only_opening_cannot_confirm_gap() {
    // Sealed `[cp0, e1, cp2]`. The opening at seq 6 and resume at
    // seq 7 live in a shipped (Collector-style) file whose basename
    // is NOT a native-segment name. The fold does not run on
    // shipped inputs, so the opening is never fold-matched, so the
    // candidate is dropped by `filter_candidates` (13-V4-d10 p.5).
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    let opening = signed_cp(6, cp2.hash(), &mmr2);
    let resume = resume_decl(&opening, 2, cp2.hash(), GAP_HIGH);
    let d = Temp::new();
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let shipped = d.0.join("collector.jsonl");
    std::fs::write(
        &shipped,
        [opening.clone(), resume.clone()]
            .iter()
            .flat_map(line_bytes)
            .collect::<Vec<u8>>(),
    )
    .unwrap();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(RESUME_SEQ, resume.hash()), (4, WRONG_HASH_55)]);
    let report = report_of(vec![segment_path(&d.0, 0), shipped], verifier);
    let findings = report.findings();
    assert!(
        !findings.iter().any(|f| f.kind() == K::LostRecord),
        "G11 shipped-only opening must emit no `LostRecord`; got {findings:?}"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.kind() == K::ReceiptMismatch && f.seq() == Some(4)),
        "G11 lost receipt must be `ReceiptMismatch`; got {findings:?}"
    );
    drop(d);
}
