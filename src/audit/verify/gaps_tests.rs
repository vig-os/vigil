//! Rows for resume-gap confirmation and `LostRecord` (ADR-0005
//! decision 5 "Resume gaps" / "Receipts lost with a resume"; ruling
//! 13-V7-d1 points 7-9). Every row ends in one whole-list
//! `assert_findings` (G1b is the exception: one tuple of the list
//! plus `is_strict_valid()`). Every digest in an expected detail is
//! either a `const` pinned by `fixture_hashes_match_literals` or a
//! value the writer returns from this run. Each row is labelled
//! ACCEPTANCE or REGRESSION in its doc comment.
//!
//! Fixture style: a resume gap is produced through the real writer
//! (`AuditConfig::resume`, pre-seeding `audit.trail` with TRAIL so
//! `trust_with_key` applies without an extra trail-building step).
//! The writer's wall clock makes the opening and resume record
//! hashes vary per run, so the detail digests for those two records
//! are read from `Checkpoint::hash` / `Receipt::hash` on the
//! returned values. Hand-built sealed bytes (seqs 0..=2) model the
//! trail's pre-resume history: the writer cannot run `create` on a
//! pre-seeded marker (TrailExists), and sealed segments on the
//! fixture clock pin their hashes as `const`. Hand-built records in
//! the live file are kept only for forged (G4), untrusted (G3) and
//! shipped-only (G11) cases that the writer never produces, and
//! each row says why.

use super::tests_common::{
    assert_findings, located, parse_cp, report_of, trust_with_key, unlocated,
};
use crate::audit::{
    AuditConfig, FindingKind as K, KeyFileSigner, Mmr, Record, RecordContext, Signer, TrustPolicy,
    digest_string,
    format::CheckpointFields,
    hex,
    runs_v4a_fixtures::{
        TRAIL, Temp, entry_rec, fixture_pubkey, pushed, put_segment, resume_decl, seeded,
        segment_path, signed_cp, write_bytes,
    },
    verify::{Finding, Verifier},
};
use std::{path::PathBuf, sync::Arc};

// =====================================================================
// Pinned literal hex constants. The non-genesis sealed prefix is
// `[cp0, e1, cp2]` on TRAIL (fixture clock `100+seq`), so cp0, e1
// and cp2 have fixed hashes. Opening and resume record hashes come
// from the writer's returns and vary per run. `TRAIL_GENESIS_DIGEST`
// is `Record::genesis(&TRAIL)` for the `head=` field in a genesis
// `Resumed` detail.
// =====================================================================

const CP0_DIGEST: &str = "blake3:fc26c6f2bb830592aaaca5413da1599489d86ac6e240a4a7a010681e0d4c8e77";
const E1_DIGEST: &str = "blake3:c121282b5135adfe7a17142cae6bfc4c9040c4aed26d74bddc923b8dafcdb6e8";
const CP2_DIGEST: &str = "blake3:4164966a12a675e55eb6e133b9e50313907f164fe142d941447defcdfdb25d06";
const TRAIL_GENESIS_DIGEST: &str =
    "blake3:a03c7c40313d5ab5cf449ba187545083161360e5ed3e41e6f9254c3b4c5efaab";
/// Non-fixture signer (seed 0x44): listed in no trust policy here, so
/// a checkpoint signed by it fails [`signatures::trusted`].
const UNTRUSTED_KEY_HEX: &str = "d759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48";

const GAP_LOW: u64 = 3;
const GAP_HIGH: u64 = 5;
const RESUME_SEQ: u64 = 7;

const WRONG_HASH_55: [u8; 32] = [0x55; 32];
const WRONG_HASH_55_DIGEST: &str =
    "blake3:5555555555555555555555555555555555555555555555555555555555555555";

// =====================================================================
// Shared helpers.
// =====================================================================

fn signer() -> Arc<dyn Signer> {
    Arc::new(KeyFileSigner::from_hex(&"27".repeat(32)).unwrap())
}

/// Pre-seeds `audit.trail` with TRAIL so a writer-built resume
/// (which refuses to run `create` on a pre-seeded marker) uses the
/// fixed trail id (anchors_tests::a10c). The non-genesis builders
/// below then hand-build the sealed `[cp0, e1, cp2]` on TRAIL with
/// the fixture clock before calling `resume`.
fn pre_seed(dir: &std::path::Path) {
    write_bytes(
        &dir.join("audit.trail"),
        format!("{}\n", hex(&TRAIL)).as_bytes(),
    );
}

/// Non-genesis fixture: sealed `[cp0, e1, cp2]` + writer-built live
/// `[opening_at_seq_6, resume_at_seq_7, drop_cp_at_seq_8]` with
/// head=(2, cp2) and `lost_through`. The writer's drop fires a
/// best-effort closing checkpoint, so `last_seq` is 8 and the
/// trusted-coverage last record is itself covered (no `UncoveredTail`).
struct NonGenesis {
    _dir: Temp,
    dir: PathBuf,
    e1: Record,
    cp2: Record,
    opening_hash: [u8; 32],
    resume_hash: [u8; 32],
}

fn non_genesis() -> NonGenesis {
    let d = Temp::new();
    pre_seed(&d.0);
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let (trail_b, resume, opening) = AuditConfig::new("svc")
        .dir(&d.0)
        .resume(signer(), (2, cp2.hash()), GAP_HIGH, "op", "r")
        .unwrap();
    drop(trail_b);
    let opening_hash = opening.hash();
    let resume_hash = resume.hash();
    NonGenesis {
        dir: d.0.clone(),
        _dir: d,
        e1,
        cp2,
        opening_hash,
        resume_hash,
    }
}

/// Genesis fixture: no sealed segment, writer-built live
/// `[opening_at_lost_through+1, resume, drop_cp]` with head=(0,
/// genesis). `AuditConfig::resume` with a genesis head runs on a
/// pre-seeded `audit.trail` alone (anchors_tests::a10c).
struct Genesis {
    _dir: Temp,
    dir: PathBuf,
    opening_hash: [u8; 32],
    resume_hash: [u8; 32],
}

fn genesis(lost_through: u64) -> Genesis {
    let d = Temp::new();
    pre_seed(&d.0);
    let (trail_b, resume, opening) = AuditConfig::new("svc")
        .dir(&d.0)
        .resume(
            signer(),
            (0, Record::genesis(&TRAIL)),
            lost_through,
            "op",
            "r",
        )
        .unwrap();
    drop(trail_b);
    let opening_hash = opening.hash();
    let resume_hash = resume.hash();
    Genesis {
        dir: d.0.clone(),
        _dir: d,
        opening_hash,
        resume_hash,
    }
}

/// `Resumed` detail for a writer-built resume (`operator=op reason=r`
/// is what every writer-built fixture passes above). Non-genesis gap
/// bounds are `h+1..=lt`; genesis is `0..=lt`.
fn resumed_detail(head_seq: u64, head_hash: &str, gap: &str, n: u64) -> String {
    format!(
        "operator=op reason=r head={head_seq}:{head_hash} gap={gap} \
         lost_records={n} structural=valid"
    )
}

fn lost(seq: u64, prefix: &str, hash_digest: &str, low: u64, high: u64) -> Finding {
    unlocated(
        K::LostRecord,
        Some(seq),
        format!("{prefix} seq {seq} hash {hash_digest}: lost in gap {low}..={high}"),
    )
}

/// Signer with seed `0x44` whose public key is `UNTRUSTED_KEY_HEX`.
/// Used by the untrusted-opening row (G3/G3b): a hand-built opening
/// signed by this key fails `signatures::trusted` because
/// `trust_with_key(fixture_pubkey())` lists only the fixture key.
fn untrusted_signer() -> KeyFileSigner {
    KeyFileSigner::from_hex(&"44".repeat(32)).unwrap()
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

fn line_bytes(record: &Record) -> Vec<u8> {
    crate::audit::runs_v4a_fixtures::line_bytes(record)
}

// =====================================================================
// Shared literal-hex consistency test for the hand-built constants
// (ruling 13-V3-d5 point 2.4). The opening and resume record hashes
// come from the writer's returns and are checked in each row directly.
// =====================================================================
#[test]
fn fixture_hashes_match_literals() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    assert_eq!(digest_string(&cp0.hash()), CP0_DIGEST, "cp0");
    assert_eq!(digest_string(&e1.hash()), E1_DIGEST, "e1");
    assert_eq!(digest_string(&cp2.hash()), CP2_DIGEST, "cp2");
    assert_eq!(
        digest_string(&Record::genesis(&TRAIL)),
        TRAIL_GENESIS_DIGEST,
        "trail_genesis"
    );
    assert_eq!(
        crate::audit::hex(&untrusted_signer().public_key()),
        UNTRUSTED_KEY_HEX,
        "untrusted_key"
    );
}

// =====================================================================
// G1 - ACCEPTANCE. ADR-0005 decision 11 l.986: an honest resume
// after a deleted live file holding receipted records, with
// `lost_through` = the highest held `seq`, and the resume receipt
// given. Each lost receipt is `LostRecord`; `SeqGap` is suppressed
// by the confirmed candidate gap; `Resumed` carries
// `lost_records=<n> structural=valid` (ruling 13-V7-d1 points 7-9).
// =====================================================================
#[test]
fn g1_honest_resume_lost_receipts_become_lost_records() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([
        (1, fx.e1.hash()),
        (RESUME_SEQ, fx.resume_hash),
        (3, WRONG_HASH_55),
        (4, WRONG_HASH_55),
        (5, WRONG_HASH_55),
    ]);
    let report = report_of(vec![fx.dir.clone()], verifier);
    let expected = vec![
        lost(3, "receipt", WRONG_HASH_55_DIGEST, GAP_LOW, GAP_HIGH),
        lost(4, "receipt", WRONG_HASH_55_DIGEST, GAP_LOW, GAP_HIGH),
        lost(5, "receipt", WRONG_HASH_55_DIGEST, GAP_LOW, GAP_HIGH),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            resumed_detail(2, CP2_DIGEST, "3..=5", 3),
        ),
    ];
    assert_findings(report.findings(), &expected, "G1");
    assert!(report.is_valid(), "G1 plain verify must pass");
}

// =====================================================================
// G1b - ACCEPTANCE. Pins `is_strict_valid()` = false on G1's
// confirmed report because `Resumed` is a warning (ADR-0005
// decision 5; decision 11). Pairs with G1 as the `--strict` half
// of l.986. Asserts one tuple of the finding list and
// `is_strict_valid()`.
// =====================================================================
#[test]
fn g1b_honest_resume_fails_strict_on_resumed_warning() {
    let fx = non_genesis();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([
        (1, fx.e1.hash()),
        (RESUME_SEQ, fx.resume_hash),
        (3, WRONG_HASH_55),
    ]);
    let report = report_of(vec![fx.dir], verifier);
    assert!(report.is_valid(), "G1b plain verify must pass");
    assert!(
        !report.is_strict_valid(),
        "Resumed warning fails --strict; got findings {:?}",
        report.findings()
    );
}

// =====================================================================
// G2 - ACCEPTANCE. ADR-0005 decision 11 l.989: the trusted-opening
// candidate's gap is **unconfirmed** when the operator does not
// supply the resume receipt. Each lost receipt stays
// `ReceiptMismatch "no record"`; the resume record is `NoReceipt`;
// `SeqGap` is still suppressed because the candidate is kept by
// the trust and fold filters (ruling 13-V7-d1 point 7).
// =====================================================================
#[test]
fn g2_unconfirmed_gap_keeps_receipt_mismatch_no_record() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let resume_digest = digest_string(&fx.resume_hash);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([
        (1, fx.e1.hash()),
        (3, WRONG_HASH_55),
        (4, WRONG_HASH_55),
    ]);
    let report = report_of(vec![fx.dir.clone()], verifier);
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
            live.clone(),
            2,
            RESUME_SEQ,
            format!("no receipt for seq {RESUME_SEQ} hash {resume_digest}"),
        ),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            resumed_detail(2, CP2_DIGEST, "3..=5", 0),
        ),
    ];
    assert_findings(report.findings(), &expected, "G2");
}

// =====================================================================
// G2b - ACCEPTANCE. Confirmation uses the full `(seq, hash)` match
// rule, not `seq` alone (ruling 13-V7-d1 point 8; `receipts::matches`
// is the one rule `match_one` runs for every receipt). A wrong-hash
// receipt at the resume `seq` is `ReceiptMismatch "hash differs"`
// and does not confirm; an in-gap receipt stays `ReceiptMismatch
// "no record"`.
// =====================================================================
#[test]
fn g2b_wrong_hash_receipt_at_resume_seq_does_not_confirm() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let resume_digest = digest_string(&fx.resume_hash);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([
        (1, fx.e1.hash()),
        (RESUME_SEQ, WRONG_HASH_55),
        (4, WRONG_HASH_55),
    ]);
    let report = report_of(vec![fx.dir.clone()], verifier);
    let expected = vec![
        unlocated(
            K::ReceiptMismatch,
            Some(4),
            format!("receipt seq 4 hash {WRONG_HASH_55_DIGEST}: no record"),
        ),
        unlocated(
            K::ReceiptMismatch,
            Some(RESUME_SEQ),
            format!(
                "receipt seq {RESUME_SEQ} hash {WRONG_HASH_55_DIGEST}: hash differs (record {resume_digest})"
            ),
        ),
        located(
            K::NoReceipt,
            live.clone(),
            2,
            RESUME_SEQ,
            format!("no receipt for seq {RESUME_SEQ} hash {resume_digest}"),
        ),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            resumed_detail(2, CP2_DIGEST, "3..=5", 0),
        ),
    ];
    assert_findings(report.findings(), &expected, "G2b");
}

// =====================================================================
// G2c - ACCEPTANCE. Second probe of the full match rule (ruling
// 13-V7-d1 point 8): a wrong-hash resume receipt plus a waiver
// inside the gap. The waiver subject stays `ReceiptMismatch "no
// record"`. Pairs with G2b to pin both receipt and waiver subjects
// under an unconfirmed gap.
// =====================================================================
#[test]
fn g2c_wrong_hash_resume_receipt_with_waiver_stays_unconfirmed() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let sealed = segment_path(&fx.dir, 0);
    let resume_digest = digest_string(&fx.resume_hash);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(RESUME_SEQ, WRONG_HASH_55)])
        .waive(4, WRONG_HASH_55, "orphan")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], verifier);
    let expected = vec![
        located(
            K::NoReceipt,
            sealed,
            2,
            1,
            format!("no receipt for seq 1 hash {E1_DIGEST}"),
        ),
        unlocated(
            K::ReceiptMismatch,
            Some(4),
            format!("waive seq 4 hash {WRONG_HASH_55_DIGEST}: no record"),
        ),
        unlocated(
            K::ReceiptMismatch,
            Some(RESUME_SEQ),
            format!(
                "receipt seq {RESUME_SEQ} hash {WRONG_HASH_55_DIGEST}: hash differs (record {resume_digest})"
            ),
        ),
        located(
            K::NoReceipt,
            live.clone(),
            2,
            RESUME_SEQ,
            format!("no receipt for seq {RESUME_SEQ} hash {resume_digest}"),
        ),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            resumed_detail(2, CP2_DIGEST, "3..=5", 0),
        ),
    ];
    assert_findings(report.findings(), &expected, "G2c");
}

// =====================================================================
// G3 - REGRESSION. ADR-0005 decision 11 l.989: an untrusted-opening
// resume is not a candidate (rulings 13-V5-d1 point 8 and
// 13-V7-d1 point 7 "An untrusted opening is not a candidate"), so
// its jump keeps its ordinary `SeqGap`. Hand-built because the
// writer always signs with a trusted key; the forged opening at
// seq 6 is signed by `untrusted_signer()` (seed 0x44) which is not
// listed in `trust_with_key(fixture_pubkey())`.
// =====================================================================
#[test]
fn g3_untrusted_opening_is_not_a_candidate_seq_gap_stays() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let other = untrusted_signer();
    let opening = sign_as(&other, 6, cp2.hash(), &mmr2);
    let resume = resume_decl(&opening, 2, cp2.hash(), GAP_HIGH);
    std::fs::write(
        d.0.join("audit.jsonl"),
        [opening.clone(), resume.clone()]
            .iter()
            .flat_map(line_bytes)
            .collect::<Vec<u8>>(),
    )
    .unwrap();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()));
    let report = report_of(vec![d.0.clone()], verifier);
    let live = d.0.join("audit.jsonl");
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
                hex(&TRAIL)
            ),
        ),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            "operator=operator reason=incident head=2:".to_owned()
                + CP2_DIGEST
                + " gap=3..=5 lost_records=0 structural=valid",
        ),
        unlocated(K::UncoveredTail, None, "records seq 3..=7".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "G3");
    drop(d);
}

// =====================================================================
// G3b - REGRESSION. Companion to G3: with the same untrusted
// opening, a receipt in the gap stays `ReceiptMismatch "no record"`
// because the candidate is dropped by the trust filter (13-V5-d1
// point 8).
// =====================================================================
#[test]
fn g3b_untrusted_opening_receipt_in_gap_stays_receipt_mismatch() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let other = untrusted_signer();
    let opening = sign_as(&other, 6, cp2.hash(), &mmr2);
    let resume = resume_decl(&opening, 2, cp2.hash(), GAP_HIGH);
    let resume_hash = resume.hash();
    let resume_digest = digest_string(&resume_hash);
    std::fs::write(
        d.0.join("audit.jsonl"),
        [opening.clone(), resume.clone()]
            .iter()
            .flat_map(line_bytes)
            .collect::<Vec<u8>>(),
    )
    .unwrap();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(RESUME_SEQ, resume_hash), (4, WRONG_HASH_55)]);
    let report = report_of(vec![d.0.clone()], verifier);
    let live = d.0.join("audit.jsonl");
    let sealed = segment_path(&d.0, 0);
    let expected = vec![
        located(
            K::NoReceipt,
            sealed,
            2,
            1,
            format!("no receipt for seq 1 hash {E1_DIGEST}"),
        ),
        unlocated(
            K::ReceiptMismatch,
            Some(4),
            format!("receipt seq 4 hash {WRONG_HASH_55_DIGEST}: no record"),
        ),
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
                hex(&TRAIL)
            ),
        ),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            "operator=operator reason=incident head=2:".to_owned()
                + CP2_DIGEST
                + " gap=3..=5 lost_records=0 structural=valid",
        ),
        unlocated(K::UncoveredTail, None, "records seq 3..=7".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "G3b");
    let _ = resume_digest;
    drop(d);
}

// =====================================================================
// G4 - REGRESSION (four parts). ADR-0005 decision 11 l.989: a
// signed jump accompanied by a malformed or absent resume
// declaration keeps its ordinary `SeqGap`. Hand-built because the
// writer never emits a malformed declaration or a signed
// checkpoint without a resume record. Four sub-rows cover the
// d11 l.989 bullet in full:
//   - G4: a plain signed jump with no resume record on the trail;
//   - G4b: a resume whose details name another head;
//   - G4c: a resume whose details name another `lost_through`;
//   - G4d: an opening whose declared `mmr_size` disagrees with the
//          fold.
// =====================================================================
#[test]
fn g4_signed_jump_without_resume_record_keeps_seq_gap() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let opening = signed_cp(6, cp2.hash(), &mmr2);
    std::fs::write(d.0.join("audit.jsonl"), line_bytes(&opening)).unwrap();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()));
    let report = report_of(vec![d.0.clone()], verifier);
    let live = d.0.join("audit.jsonl");
    let expected = vec![located(
        K::SeqGap,
        live,
        1,
        6,
        "missing seq 3..=5".to_owned(),
    )];
    assert_findings(report.findings(), &expected, "G4");
    drop(d);
}

/// G4b: resume details name another head (head seq 1 instead of 2).
/// The structural check fails `head-not-last` (ruling 13-V3-d5
/// point 4), so the candidate is dropped and `SeqGap` fires.
#[test]
fn g4b_resume_names_other_head_keeps_seq_gap() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let opening = signed_cp(6, cp2.hash(), &mmr2);
    let resume = resume_decl(&opening, 1, e1.hash(), GAP_HIGH);
    std::fs::write(
        d.0.join("audit.jsonl"),
        [opening.clone(), resume.clone()]
            .iter()
            .flat_map(line_bytes)
            .collect::<Vec<u8>>(),
    )
    .unwrap();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()));
    let report = report_of(vec![d.0.clone()], verifier);
    let live = d.0.join("audit.jsonl");
    let expected = vec![
        located(
            K::SeqGap,
            live.clone(),
            1,
            6,
            "missing seq 3..=5".to_owned(),
        ),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            format!(
                "operator=operator reason=incident head=1:{E1_DIGEST} \
                 gap=2..=5 lost_records=0 structural=invalid(head-not-last)"
            ),
        ),
        unlocated(K::UncoveredTail, None, "records seq 7..=7".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "G4b");
    drop(d);
}

/// G4c: resume details name another `lost_through` (6 instead of 5).
/// The structural check fails `resume-not-at-k+1` (the resume
/// record is at seq 7 but `lost_through+1 = 7` so k=7; the
/// opening is at seq 6 not 7). The candidate is dropped and
/// `SeqGap` fires.
#[test]
fn g4c_resume_names_other_lost_through_keeps_seq_gap() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let opening = signed_cp(6, cp2.hash(), &mmr2);
    let resume = resume_decl(&opening, 2, cp2.hash(), 6);
    std::fs::write(
        d.0.join("audit.jsonl"),
        [opening.clone(), resume.clone()]
            .iter()
            .flat_map(line_bytes)
            .collect::<Vec<u8>>(),
    )
    .unwrap();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()));
    let report = report_of(vec![d.0.clone()], verifier);
    let live = d.0.join("audit.jsonl");
    let expected = vec![
        located(
            K::SeqGap,
            live.clone(),
            1,
            6,
            "missing seq 3..=5".to_owned(),
        ),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            format!(
                "operator=operator reason=incident head=2:{CP2_DIGEST} \
                 gap=3..=6 lost_records=0 structural=invalid(no-opening)"
            ),
        ),
        unlocated(K::UncoveredTail, None, "records seq 7..=7".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "G4c");
    drop(d);
}

/// G4d: opening declares a wrong `mmr_size` (fold entries differ
/// from the records before it). `MmrMismatch` fires at the
/// opening and the fold filter drops the candidate, so `SeqGap`
/// also fires.
#[test]
fn g4d_wrong_mmr_size_opening_keeps_seq_gap_with_mmr_mismatch() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    // Wrong fold: use `mmr0` (size=1) in place of the honest
    // `pushed(mmr1, &cp2)` (size=3) in the opening's MMR fields.
    let opening = signed_cp(6, cp2.hash(), &mmr0);
    let resume = resume_decl(&opening, 2, cp2.hash(), GAP_HIGH);
    std::fs::write(
        d.0.join("audit.jsonl"),
        [opening.clone(), resume.clone()]
            .iter()
            .flat_map(line_bytes)
            .collect::<Vec<u8>>(),
    )
    .unwrap();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()));
    let report = report_of(vec![d.0.clone()], verifier);
    let live = d.0.join("audit.jsonl");
    let expected = vec![
        located(
            K::MmrMismatch,
            live.clone(),
            1,
            6,
            format!(
                "expected size 3 root {}, found size 1 root {}",
                digest_string(&pushed(&mmr1, &cp2).root()),
                digest_string(&mmr0.root()),
            ),
        ),
        located(
            K::SeqGap,
            live.clone(),
            1,
            6,
            "missing seq 3..=5".to_owned(),
        ),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            format!(
                "operator=operator reason=incident head=2:{CP2_DIGEST} \
                 gap=3..=5 lost_records=0 structural=valid"
            ),
        ),
        unlocated(K::UncoveredTail, None, "records seq 7..=7".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "G4d");
    drop(d);
}

// =====================================================================
// G5 - ACCEPTANCE. ADR-0005 decision 11 l.993: a waiver and a
// `from` inside a confirmed gap each become one `LostRecord`; the
// `from` still exempts every record at or below its `seq` from
// `NoReceipt` (ruling 13-V7-d1 point 6 through a confirmed gap).
// =====================================================================
#[test]
fn g5_waiver_and_from_inside_confirmed_gap_are_lost_record() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(RESUME_SEQ, fx.resume_hash)])
        .waive(4, WRONG_HASH_55, "orphan after crash")
        .unwrap()
        .receipts_from(3, WRONG_HASH_55, "late adoption")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], verifier);
    let expected = vec![
        lost(3, "from", WRONG_HASH_55_DIGEST, GAP_LOW, GAP_HIGH),
        lost(4, "waive", WRONG_HASH_55_DIGEST, GAP_LOW, GAP_HIGH),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            resumed_detail(2, CP2_DIGEST, "3..=5", 2),
        ),
    ];
    assert_findings(report.findings(), &expected, "G5");
}

// =====================================================================
// G5b - ACCEPTANCE. Same waiver and `from` placed inside an
// **unconfirmed** gap (no resume receipt) each yield
// `ReceiptMismatch "no record"` (ADR l.989; ruling 13-V7-d1
// point 8 unconfirmed path). Pairs with G5 as the confirmation
// split.
// =====================================================================
#[test]
fn g5b_waiver_and_from_inside_unconfirmed_gap_are_receipt_mismatch() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let resume_digest = digest_string(&fx.resume_hash);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash())])
        .waive(4, WRONG_HASH_55, "orphan after crash")
        .unwrap()
        .receipts_from(3, WRONG_HASH_55, "late adoption")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], verifier);
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
            live.clone(),
            2,
            RESUME_SEQ,
            format!("no receipt for seq {RESUME_SEQ} hash {resume_digest}"),
        ),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            resumed_detail(2, CP2_DIGEST, "3..=5", 0),
        ),
    ];
    assert_findings(report.findings(), &expected, "G5b");
}

// =====================================================================
// G5c - ACCEPTANCE. Second pin of the `from` exemption through a
// confirmed gap (ruling 13-V7-d1 point 6 propagates): a `from` at
// the HIGHEST gap seq still exempts every record at or below it,
// including the sealed e1 at seq 1.
// =====================================================================
#[test]
fn g5c_from_at_top_of_gap_still_exempts_below() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(RESUME_SEQ, fx.resume_hash)])
        .receipts_from(GAP_HIGH, WRONG_HASH_55, "late adoption")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], verifier);
    let expected = vec![
        lost(GAP_HIGH, "from", WRONG_HASH_55_DIGEST, GAP_LOW, GAP_HIGH),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            resumed_detail(2, CP2_DIGEST, "3..=5", 1),
        ),
    ];
    assert_findings(report.findings(), &expected, "G5c");
}

// =====================================================================
// G5d - ACCEPTANCE. Third probe of `from` exemption (ruling
// 13-V7-d1 point 6): the `from` at the LOWEST in-range gap `seq`
// still exempts seqs 1 and 2 below it. Pairs with G5 (middle) and
// G5c (top).
// =====================================================================
#[test]
fn g5d_from_at_low_of_gap_still_exempts_everything_below() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(RESUME_SEQ, fx.resume_hash)])
        .receipts_from(GAP_LOW, WRONG_HASH_55, "late adoption")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], verifier);
    let expected = vec![
        lost(GAP_LOW, "from", WRONG_HASH_55_DIGEST, GAP_LOW, GAP_HIGH),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            resumed_detail(2, CP2_DIGEST, "3..=5", 1),
        ),
    ];
    assert_findings(report.findings(), &expected, "G5d");
}

// =====================================================================
// G6 - ACCEPTANCE. ADR l.990 for the unanchored-opening half: in
// a confirmed gap whose opening is not anchored, the anchor and
// the `through=` pin inside the gap keep `AnchorMismatch` and
// `RevocationMismatch`, while the waiver inside the gap is
// `LostRecord` (ruling 13-V7-d1 points 8-9). The anchored-opening
// demotion is a later #13 step.
// =====================================================================
#[test]
fn g6_unanchored_opening_keeps_anchor_and_pin_mismatches() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    // A second trusted key carries a `through=4:WRONG` pin: the pin
    // names a hash no record at seq 4 carries, so `RevocationMismatch`
    // fires with the unlocated "no record at seq 4" form (13-V5-d4).
    let other = KeyFileSigner::from_hex(&"77".repeat(32)).unwrap();
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .key_through(other.public_key(), 4, WRONG_HASH_55)
        .build()
        .unwrap();
    // A trusted-signed anchor at seq 4 whose `(trail, seq, hash)` is
    // not the opening's, so the opening stays unanchored (13-V6-d1
    // point 2); and no record at seq 4 matches the anchor's hash, so
    // `AnchorMismatch` fires with `no record`.
    let mut synth_mmr = Mmr::new();
    synth_mmr.push([0xcc; 32]).unwrap();
    let anchor_record = signed_cp(4, fx.cp2.hash(), &synth_mmr);
    let anchor_cp = parse_cp(&anchor_record);
    let anchor_digest = digest_string(&anchor_record.hash());
    let verifier = Verifier::new(trust)
        .anchor(anchor_cp)
        .receipts([(1, fx.e1.hash()), (RESUME_SEQ, fx.resume_hash)])
        .waive(4, WRONG_HASH_55, "r")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], verifier);
    let expected = vec![
        unlocated(
            K::AnchorMismatch,
            Some(4),
            format!("anchor seq 4 hash {anchor_digest}: no record"),
        ),
        lost(4, "waive", WRONG_HASH_55_DIGEST, GAP_LOW, GAP_HIGH),
        unlocated(
            K::RevocationMismatch,
            Some(4),
            format!(
                "key {other_key} through=4:{WRONG_HASH_55_DIGEST}: no record at seq 4",
                other_key = hex(&other.public_key())
            ),
        ),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            resumed_detail(2, CP2_DIGEST, "3..=5", 1),
        ),
    ];
    assert_findings(report.findings(), &expected, "G6");
}

// =====================================================================
// G7 - REGRESSION. ADR-0005 decision 11 l.991: a start at the
// resume's opening checkpoint. Inputs below the start follow the
// start rule first (ruling 13-V7-d1 point 7 "Order"). A receipt
// below an anchored start is set aside as `OutOfRange` (info),
// not `LostRecord`.
// =====================================================================
#[test]
fn g7_start_at_opening_below_start_wins_over_gap() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    let opening = signed_cp(6, cp2.hash(), &mmr2);
    let resume = resume_decl(&opening, 2, cp2.hash(), GAP_HIGH);
    std::fs::write(
        d.0.join("audit.jsonl"),
        [opening.clone(), resume.clone()]
            .iter()
            .flat_map(line_bytes)
            .collect::<Vec<u8>>(),
    )
    .unwrap();
    let opening_cp = parse_cp(&opening);
    let opening_digest = digest_string(&opening.hash());
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .anchor(opening_cp.clone())
        .start_from(opening_cp)
        .receipts([(RESUME_SEQ, resume.hash()), (4, WRONG_HASH_55)]);
    let report = report_of(vec![d.0.clone()], verifier);
    let live = d.0.join("audit.jsonl");
    // The live file holds only opening+resume; the sealed seqs
    // (0..=2) that the resume names as head are absent at verify
    // time, so the structural check fails `head-not-present` and
    // no candidate is kept. The accepted start at seq 6 still
    // suppresses the prefix `SeqGap 0..=5`.
    let expected = vec![
        unlocated(
            K::OutOfRange,
            Some(4),
            format!("receipt seq 4 hash {WRONG_HASH_55_DIGEST}: below start seq 6"),
        ),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            format!(
                "operator=operator reason=incident head=2:{CP2_DIGEST} \
                 gap=3..=5 lost_records=0 structural=invalid(head-not-present)"
            ),
        ),
        unlocated(K::UncoveredTail, None, "records seq 7..=7".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "G7");
    let _ = opening_digest;
    drop(d);
}

// =====================================================================
// G7b - ACCEPTANCE. Writer-built genesis resume with an **anchored**
// start at the opening (seq 6) and a receipt + a waiver inside the
// genesis gap `0..=5`. The start rule applies first (ruling
// 13-V7-d1 point 7 "Order"), so both inputs are `OutOfRange`
// (anchored), not `LostRecord`. Pairs with G7c (unanchored) to
// pin the order-of-classification rule.
// =====================================================================
#[test]
fn g7b_genesis_anchored_start_below_inputs_are_out_of_range() {
    let g = genesis(GAP_HIGH);
    let live = g.dir.join("audit.jsonl");
    // Parse the opening from the live file so `start_from` carries
    // the writer's authentic line (the writer returns a `Checkpoint`
    // whose `line()` is the signed OTLP form).
    let opening_text = std::fs::read_to_string(&live).unwrap();
    let first_line = opening_text.lines().next().unwrap();
    let opening_cp = crate::audit::Checkpoint::parse(first_line).unwrap();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .anchor(opening_cp.clone())
        .start_from(opening_cp)
        .receipts([(RESUME_SEQ, g.resume_hash), (3, WRONG_HASH_55)])
        .waive(2, WRONG_HASH_55, "orphan")
        .unwrap();
    let report = report_of(vec![g.dir.clone()], verifier);
    let expected = vec![
        unlocated(
            K::OutOfRange,
            Some(2),
            format!("waive seq 2 hash {WRONG_HASH_55_DIGEST}: below start seq 6"),
        ),
        unlocated(
            K::OutOfRange,
            Some(3),
            format!("receipt seq 3 hash {WRONG_HASH_55_DIGEST}: below start seq 6"),
        ),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            resumed_detail(0, TRAIL_GENESIS_DIGEST, "0..=5", 0),
        ),
    ];
    assert_findings(report.findings(), &expected, "G7b");
    let _ = g.opening_hash;
}

// =====================================================================
// G7c - ACCEPTANCE. Writer-built genesis resume with an
// **unanchored** start at the opening (no `anchor(opening)`) and
// the same inputs as G7b. The start rule applies first, so both
// inputs are `UnanchoredStart` (error, ruling 13-V6-d3 point 5)
// not `LostRecord`; the report is invalid. Pairs with G7b to pin
// both anchored and unanchored branches of the below-start rule.
// =====================================================================
#[test]
fn g7c_genesis_unanchored_start_below_inputs_are_unanchored_start() {
    let g = genesis(GAP_HIGH);
    let live = g.dir.join("audit.jsonl");
    let opening_text = std::fs::read_to_string(&live).unwrap();
    let first_line = opening_text.lines().next().unwrap();
    let opening_cp = crate::audit::Checkpoint::parse(first_line).unwrap();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .start_from(opening_cp)
        .receipts([(RESUME_SEQ, g.resume_hash), (3, WRONG_HASH_55)])
        .waive(2, WRONG_HASH_55, "orphan")
        .unwrap();
    let report = report_of(vec![g.dir.clone()], verifier);
    let expected = vec![
        unlocated(
            K::UnanchoredStart,
            Some(2),
            format!("waive seq 2 hash {WRONG_HASH_55_DIGEST}: below start seq 6"),
        ),
        unlocated(
            K::UnanchoredStart,
            Some(3),
            format!("receipt seq 3 hash {WRONG_HASH_55_DIGEST}: below start seq 6"),
        ),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            resumed_detail(0, TRAIL_GENESIS_DIGEST, "0..=5", 0),
        ),
    ];
    assert_findings(report.findings(), &expected, "G7c");
    assert!(
        !report.is_valid(),
        "G7c UnanchoredStart makes report invalid"
    );
    let _ = g.opening_hash;
}

// =====================================================================
// G8 - ACCEPTANCE. ADR-0005 decision 11 l.992: `lost_through`
// below a held receipt. A receipt at a `seq` ABOVE the gap is
// checked against the record at that `seq`; here the record is
// the resume at seq 7 and the receipt's hash differs, so
// `ReceiptMismatch "hash differs"` fires.
// =====================================================================
#[test]
fn g8_lost_through_below_held_receipt_gives_receipt_mismatch() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let resume_digest = digest_string(&fx.resume_hash);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash()), (RESUME_SEQ, WRONG_HASH_55)]);
    let report = report_of(vec![fx.dir.clone()], verifier);
    let expected = vec![
        unlocated(
            K::ReceiptMismatch,
            Some(RESUME_SEQ),
            format!(
                "receipt seq {RESUME_SEQ} hash {WRONG_HASH_55_DIGEST}: hash differs (record {resume_digest})"
            ),
        ),
        located(
            K::NoReceipt,
            live.clone(),
            2,
            RESUME_SEQ,
            format!("no receipt for seq {RESUME_SEQ} hash {resume_digest}"),
        ),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            resumed_detail(2, CP2_DIGEST, "3..=5", 0),
        ),
    ];
    assert_findings(report.findings(), &expected, "G8");
}

// =====================================================================
// G9 - ACCEPTANCE. ADR-0005 decision 11 l.993: two resumes in
// sequence, each confirmed, so both gaps' inputs are
// `LostRecord`. One receipt inside each gap pins the per-gap
// count (ruling 13-V7-d1 point 8). Hand-built because chaining
// two writer resumes in one fixture requires two separate
// `AuditConfig::resume` calls back-to-back; the two openings and
// two resume records are chained hand-built records so the
// fold's walk is literal.
// =====================================================================
#[test]
fn g9_two_confirmed_resumes_each_gap_has_lost_records() {
    let d = Temp::new();
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
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    std::fs::write(
        d.0.join("audit.jsonl"),
        [open1.clone(), res1.clone(), open2.clone(), res2.clone()]
            .iter()
            .flat_map(line_bytes)
            .collect::<Vec<u8>>(),
    )
    .unwrap();
    let res1_digest = digest_string(&res1.hash());
    let res2_digest = digest_string(&res2.hash());
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([
        (1, e1.hash()),
        (RESUME_SEQ, res1.hash()),
        (12, res2.hash()),
        (4, WRONG_HASH_55),
        (9, WRONG_HASH_55),
    ]);
    let report = report_of(vec![d.0.clone()], verifier);
    let live = d.0.join("audit.jsonl");
    let expected = vec![
        lost(4, "receipt", WRONG_HASH_55_DIGEST, GAP_LOW, GAP_HIGH),
        located(
            K::Resumed,
            live.clone(),
            2,
            RESUME_SEQ,
            format!(
                "operator=operator reason=incident head=2:{CP2_DIGEST} \
                 gap=3..=5 lost_records=1 structural=valid"
            ),
        ),
        lost(9, "receipt", WRONG_HASH_55_DIGEST, 8, 10),
        located(
            K::Resumed,
            live.clone(),
            4,
            12,
            format!(
                "operator=operator reason=incident head=7:{res1_digest} \
                 gap=8..=10 lost_records=1 structural=valid"
            ),
        ),
        unlocated(K::UncoveredTail, None, "records seq 12..=12".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "G9");
    let _ = res2_digest;
    drop(d);
}

// =====================================================================
// G9b - REGRESSION. ADR-0005 decision 11 l.993 "A resume with
// `lost_through` = head: no gap, no `LostRecord`". The `Resumed`
// detail carries `gap=none lost_records=0`.
// =====================================================================
#[test]
fn g9b_lost_through_equal_to_head_has_no_gap() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    let opening = signed_cp(3, cp2.hash(), &mmr2);
    let resume = resume_decl(&opening, 2, cp2.hash(), 2);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    std::fs::write(
        d.0.join("audit.jsonl"),
        [opening.clone(), resume.clone()]
            .iter()
            .flat_map(line_bytes)
            .collect::<Vec<u8>>(),
    )
    .unwrap();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()));
    let report = report_of(vec![d.0.clone()], verifier);
    let live = d.0.join("audit.jsonl");
    let expected = vec![
        located(
            K::Resumed,
            live,
            2,
            4,
            format!(
                "operator=operator reason=incident head=2:{CP2_DIGEST} \
                 gap=none lost_records=0 structural=valid"
            ),
        ),
        unlocated(K::UncoveredTail, None, "records seq 4..=4".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "G9b");
    let _ = opening;
    let _ = resume;
    drop(d);
}

// =====================================================================
// G9c - ACCEPTANCE. Second pin of the per-gap `lost_records` count
// (ruling 13-V7-d1 point 8): two confirmed gaps with ASYMMETRIC
// counts (3 vs 0), so an implementation that sums across gaps
// (every `Resumed` showing a cross-gap total) differs from the
// per-gap count.
// =====================================================================
#[test]
fn g9c_two_gaps_with_asymmetric_lost_record_counts() {
    let d = Temp::new();
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
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    std::fs::write(
        d.0.join("audit.jsonl"),
        [open1.clone(), res1.clone(), open2.clone(), res2.clone()]
            .iter()
            .flat_map(line_bytes)
            .collect::<Vec<u8>>(),
    )
    .unwrap();
    let res1_digest = digest_string(&res1.hash());
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([
        (1, e1.hash()),
        (RESUME_SEQ, res1.hash()),
        (12, res2.hash()),
        (3, WRONG_HASH_55),
        (4, WRONG_HASH_55),
        (5, WRONG_HASH_55),
    ]);
    let report = report_of(vec![d.0.clone()], verifier);
    let live = d.0.join("audit.jsonl");
    let expected = vec![
        lost(3, "receipt", WRONG_HASH_55_DIGEST, GAP_LOW, GAP_HIGH),
        lost(4, "receipt", WRONG_HASH_55_DIGEST, GAP_LOW, GAP_HIGH),
        lost(5, "receipt", WRONG_HASH_55_DIGEST, GAP_LOW, GAP_HIGH),
        located(
            K::Resumed,
            live.clone(),
            2,
            RESUME_SEQ,
            format!(
                "operator=operator reason=incident head=2:{CP2_DIGEST} \
                 gap=3..=5 lost_records=3 structural=valid"
            ),
        ),
        located(
            K::Resumed,
            live.clone(),
            4,
            12,
            format!(
                "operator=operator reason=incident head=7:{res1_digest} \
                 gap=8..=10 lost_records=0 structural=valid"
            ),
        ),
        unlocated(K::UncoveredTail, None, "records seq 12..=12".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "G9c");
    drop(d);
}

// =====================================================================
// G9_above - ACCEPTANCE. A receipt exactly at `lost_through + 1`
// (= the opening's `seq`, 6) is NOT in the gap (`3..=5`), so it
// is checked against the opening record at seq 6 and must NOT
// become `LostRecord`.
// =====================================================================
#[test]
fn g9_above_receipt_at_lost_through_plus_one_is_not_lost() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let resume_digest = digest_string(&fx.resume_hash);
    let opening_digest = digest_string(&fx.opening_hash);
    // Supply the resume receipt (so the gap IS confirmed) plus a
    // wrong-hash receipt at seq 6 (= lost_through + 1 = opening
    // seq). The receipt at seq 6 is above the gap; the match rule
    // runs and emits `ReceiptMismatch "hash differs"` (opening's
    // hash). It must NOT become `LostRecord`.
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([
        (1, fx.e1.hash()),
        (RESUME_SEQ, fx.resume_hash),
        (6, WRONG_HASH_55),
    ]);
    let report = report_of(vec![fx.dir.clone()], verifier);
    let expected = vec![
        unlocated(
            K::ReceiptMismatch,
            Some(6),
            format!(
                "receipt seq 6 hash {WRONG_HASH_55_DIGEST}: hash differs (record {opening_digest})"
            ),
        ),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            resumed_detail(2, CP2_DIGEST, "3..=5", 0),
        ),
    ];
    assert_findings(report.findings(), &expected, "G9_above");
    let _ = resume_digest;
}

// =====================================================================
// G10 - ACCEPTANCE. ADR-0005 decision 5 "The genesis case" (ADR
// amendment 12; ruling 13-V7-d1 point 7 exception): a genesis
// resume with no receipt keeps the `SeqGap` for `0..=lost_through`
// (unconfirmed); a confirmed genesis resume suppresses it.
// =====================================================================
#[test]
fn g10_genesis_gap_suppressed_only_when_confirmed() {
    // Unconfirmed: SeqGap 0..=5 stays.
    let g = genesis(GAP_HIGH);
    let live = g.dir.join("audit.jsonl");
    let resume_digest = digest_string(&g.resume_hash);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()));
    let report = report_of(vec![g.dir.clone()], verifier);
    let expected_unconfirmed = vec![
        located(
            K::SeqGap,
            live.clone(),
            1,
            6,
            "missing seq 0..=5".to_owned(),
        ),
        located(
            K::Resumed,
            live.clone(),
            2,
            RESUME_SEQ,
            resumed_detail(0, TRAIL_GENESIS_DIGEST, "0..=5", 0),
        ),
    ];
    assert_findings(report.findings(), &expected_unconfirmed, "G10 unconfirmed");
    // Confirmed: SeqGap 0..=5 is suppressed.
    let verifier =
        Verifier::new(trust_with_key(fixture_pubkey())).receipts([(RESUME_SEQ, g.resume_hash)]);
    let report = report_of(vec![g.dir.clone()], verifier);
    let expected_confirmed = vec![located(
        K::Resumed,
        live,
        2,
        RESUME_SEQ,
        resumed_detail(0, TRAIL_GENESIS_DIGEST, "0..=5", 0),
    )];
    assert_findings(report.findings(), &expected_confirmed, "G10 confirmed");
    let _ = (resume_digest, g.opening_hash);
}

// =====================================================================
// G10_low - ACCEPTANCE. Second genesis probe: a receipt at `seq 0`
// in a confirmed genesis gap IS in the gap (`0..=5`) and becomes
// `LostRecord`.
// =====================================================================
#[test]
fn g10_low_genesis_gap_includes_seq_zero() {
    let g = genesis(GAP_HIGH);
    let live = g.dir.join("audit.jsonl");
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(RESUME_SEQ, g.resume_hash), (0, WRONG_HASH_55)]);
    let report = report_of(vec![g.dir.clone()], verifier);
    let expected = vec![
        lost(0, "receipt", WRONG_HASH_55_DIGEST, 0, GAP_HIGH),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            resumed_detail(0, TRAIL_GENESIS_DIGEST, "0..=5", 1),
        ),
    ];
    assert_findings(report.findings(), &expected, "G10_low");
    let _ = g.opening_hash;
}

// =====================================================================
// G11 - REGRESSION. Ruling 13-V7-d1 point 9 (#224 limit): a
// shipped-only opening is never fold-matched, so a Collector copy
// of the opening cannot confirm a gap even with the resume
// receipt (ADR 13-V4-d7). The lost receipt stays `ReceiptMismatch`.
// Hand-built because the writer has no Collector path.
// =====================================================================
#[test]
fn g11_shipped_only_opening_cannot_confirm_gap() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    let opening = signed_cp(6, cp2.hash(), &mmr2);
    let resume = resume_decl(&opening, 2, cp2.hash(), GAP_HIGH);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    // Shipped (Collector-style) file whose basename is NOT a
    // native segment name: the fold never runs on shipped inputs,
    // so the opening is never fold-matched (13-V4-d7; #224).
    let shipped = d.0.join("collector.jsonl");
    std::fs::write(
        &shipped,
        [opening.clone(), resume.clone()]
            .iter()
            .flat_map(line_bytes)
            .collect::<Vec<u8>>(),
    )
    .unwrap();
    let resume_digest = digest_string(&resume.hash());
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(RESUME_SEQ, resume.hash()), (4, WRONG_HASH_55)]);
    let sealed = segment_path(&d.0, 0);
    let report = report_of(vec![sealed.clone(), shipped.clone()], verifier);
    let expected = vec![
        located(
            K::NoReceipt,
            sealed,
            2,
            1,
            format!("no receipt for seq 1 hash {E1_DIGEST}"),
        ),
        unlocated(
            K::ReceiptMismatch,
            Some(4),
            format!("receipt seq 4 hash {WRONG_HASH_55_DIGEST}: no record"),
        ),
        located(
            K::SeqGap,
            shipped.clone(),
            1,
            6,
            "missing seq 3..=5".to_owned(),
        ),
        located(
            K::Resumed,
            shipped,
            2,
            RESUME_SEQ,
            format!(
                "operator=operator reason=incident head=2:{CP2_DIGEST} \
                 gap=3..=5 lost_records=0 structural=valid"
            ),
        ),
        unlocated(K::UncoveredTail, None, "records seq 7..=7".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "G11");
    let _ = resume_digest;
    drop(d);
}
