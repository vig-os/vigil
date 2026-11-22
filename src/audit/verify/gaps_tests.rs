//! Rows for resume-gap confirmation and `LostRecord` (ADR-0005
//! decision 5 "Resume gaps" / "Receipts lost with a resume"; ruling
//! 13-V7-d1 points 7-9). Every row ends in one whole-list
//! `assert_findings`, with G1b using one `assert_eq!` over the
//! `(findings, is_valid, is_strict_valid)` tuple. Every digest in
//! an expected detail is either a `const` pinned by
//! `fixture_hashes_match_literals` or a value the writer returns
//! from this run. Each row is labelled ACCEPTANCE or REGRESSION in
//! its doc comment.
//!
//! Fixture style: a resume gap is produced through the real writer
//! (`AuditConfig::resume`, pre-seeding `audit.trail` with TRAIL so
//! `trust_with_key` applies without an extra trail-building step).
//! The writer's wall clock makes the opening and resume record
//! hashes vary per run, so the detail digests for those two records
//! are read from `Checkpoint::hash` / `Receipt::hash` on the
//! returned values. Hand-built sealed bytes (seqs 0..=2) model the
//! trail's pre-resume history: the writer cannot run `create` on a
//! pre-seeded marker (`TrailExists`), and sealed segments on the
//! fixture clock pin their hashes as `const`. Hand-built records in
//! the live file are kept only for forged (G4), untrusted (G3),
//! shipped-only (G11), chained-double-resume (G9) and trusted-decoy
//! fork (G14) cases the writer never produces, and each row says
//! why. A chained double resume cannot be writer-built: a second
//! `AuditConfig::resume` would refuse the directory's existing head
//! through the resume loss-bound / `HeadMismatch` checks on the
//! drop-on-close checkpoint the first call leaves behind.

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
/// Second trusted signer (seed 0x77) consumed by G6's `through=` pin.
/// Its public key is pinned here so the expected-detail format
/// string reads the literal rather than recomputing from the fixture.
const OTHER_KEY_HEX: &str = "c853ad0f0cd2b619aea92ceec4fd56a24d6499d584ce79257e45cfd8139b60a7";

const GAP_LOW: u64 = 3;
const GAP_HIGH: u64 = 5;
const RESUME_SEQ: u64 = 7;

const WRONG_HASH_55: [u8; 32] = [0x55; 32];
const WRONG_HASH_55_DIGEST: &str =
    "blake3:5555555555555555555555555555555555555555555555555555555555555555";

/// `pushed(&mmr1, &cp2).root()`: the honest MMR root at size=3 after
/// cp0, e1, cp2 on `TRAIL`. Consumed by G4d's `MmrMismatch` detail
/// (expected side). Pinned so the row reads the literal digest
/// rather than recomputing it from the fold.
const MMR_AT_CP2_ROOT_DIGEST: &str =
    "blake3:3e3070dd2dba8c267662fb89cbeb5b88848d5146895bc4bb1258bf87aa510160";
/// `mmr0.root()`: the honest MMR root at size=1 after only cp0.
/// Consumed by G4d's `MmrMismatch` detail (found side).
const MMR_AT_CP0_ROOT_DIGEST: &str =
    "blake3:e3a0ca91e171d05a5877b1352376e6e54fc54312c7d9295d4e7643bdba23f723";
/// G6's `through=4:WRONG` anchor record: seq 4, previous = cp2,
/// synthetic single-leaf MMR with hash `[0xcc; 32]`, signed by the
/// fixture key. The row asserts against this literal digest instead
/// of recomputing it from the record builder.
const G6_ANCHOR_DIGEST: &str =
    "blake3:bd5ecd0d74a95fd880720aaf151a5c751ff1ffeefd2817d89fb1528630927e3f";
/// `sign_as(untrusted_signer(), 6, cp2.hash(), &mmr_at_cp2)`: an
/// opening at seq 6 signed by the `0x44` key with the honest
/// `previous` (`cp2.hash()`) and MMR fold (mmr_size=3). Shared by
/// G12 (the native, dropped candidate) and G14/G14b (native
/// opening paired with a trusted shipped decoy).
const UNTRUSTED_OPENING_SEQ_6_DIGEST: &str =
    "blake3:75efc48ddc3efc21294017a7c4587165188a6e6ba45138a0f7d86791c672f07a";
/// `resume_decl(open1, 2, cp2.hash(), GAP_HIGH)` built on
/// [`UNTRUSTED_OPENING_SEQ_6_DIGEST`]: the resume declaration at
/// seq 7 after the untrusted opening. G12's res2 `head=7:...` text
/// reads this.
const G12_RES1_DIGEST: &str =
    "blake3:6be51ae098f7b9a601bf3de56e2abf2d0ce8413d628fe98d0813313aa1f7f752";
/// `signed_cp(6, cp2.hash(), &mmr0)`: G14's trusted shipped-only
/// decoy at seq 6, same `previous` as the native opening but a
/// different MMR (size=1) so its hash differs from the native.
const G14_DECOY_DIGEST: &str =
    "blake3:5624a7084f437f68596f5d722caea34f6ceacc9920294a520bef1a15fb2a12fb";
/// `signed_cp(6, e1.hash(), &mmr_at_cp2)`: G14b's trusted
/// shipped-only decoy at seq 6, different `previous` (`e1.hash()`)
/// and the honest MMR so its hash differs from the native and its
/// chain link to `cp2` is broken.
const G14B_DECOY_DIGEST: &str =
    "blake3:c7c3ac9ea68380ed41a73ec7ffc31b96b05be7e8794de46c65de744652b70357";
/// G12b's res1 (seq 7, trusted opening at seq 6): the first of
/// three chained resume declarations. Used as the `head=7:...`
/// text in res2's `Resumed` detail.
const G12B_RES1_DIGEST: &str =
    "blake3:526ca739a9a8d9ee4724e25f86afb9fa24423ae12660ec680d4dae05ffda1a59";
/// G12b's res2 (seq 12, untrusted opening at seq 11): the second
/// of three chained resume declarations, whose candidate is
/// dropped by `signatures::trusted`. Used as the record hash in
/// its own `NoReceipt` detail and as the `head=12:...` text in
/// res3's `Resumed` detail.
const G12B_RES2_DIGEST: &str =
    "blake3:2d61f5297986d049e022fee9038a547a7aa6204c33654be432fb0b1b0fb89065";

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
    Genesis {
        dir: d.0.clone(),
        _dir: d,
        opening_hash: opening.hash(),
        resume_hash: resume.hash(),
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

/// Second trusted signer (seed `0x77`) whose public key is
/// `OTHER_KEY_HEX`. Carries G6's `through=4:WRONG` pin so the
/// `RevocationMismatch` detail reads a `const` key rather than
/// recomputing it from the signer at test time.
fn other_signer() -> KeyFileSigner {
    KeyFileSigner::from_hex(&"77".repeat(32)).unwrap()
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
    let mmr_at_cp2 = pushed(&mmr1, &cp2);
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
    assert_eq!(
        digest_string(&mmr0.root()),
        MMR_AT_CP0_ROOT_DIGEST,
        "mmr_at_cp0_root"
    );
    assert_eq!(
        digest_string(&mmr_at_cp2.root()),
        MMR_AT_CP2_ROOT_DIGEST,
        "mmr_at_cp2_root"
    );
    assert_eq!(
        crate::audit::hex(&other_signer().public_key()),
        OTHER_KEY_HEX,
        "other_key"
    );
    let mut synth_mmr = Mmr::new();
    synth_mmr.push([0xcc; 32]).unwrap();
    let anchor_record = signed_cp(4, cp2.hash(), &synth_mmr);
    assert_eq!(
        digest_string(&anchor_record.hash()),
        G6_ANCHOR_DIGEST,
        "g6_anchor"
    );
    // Pin the untrusted opening at seq 6 shared by G12/G14/G14b
    // (same `previous` and MMR as the native, only the signing key
    // differs), its chained resume at seq 7 for G12, and the two
    // decoys for G14 and G14b.
    let untrusted_open_at_6 = sign_as(&untrusted_signer(), 6, cp2.hash(), &mmr_at_cp2);
    assert_eq!(
        digest_string(&untrusted_open_at_6.hash()),
        UNTRUSTED_OPENING_SEQ_6_DIGEST,
        "untrusted_opening_seq_6"
    );
    let g12_res1 = resume_decl(&untrusted_open_at_6, 2, cp2.hash(), GAP_HIGH);
    assert_eq!(digest_string(&g12_res1.hash()), G12_RES1_DIGEST, "g12_res1");
    let g14_decoy = signed_cp(6, cp2.hash(), &mmr0);
    assert_eq!(
        digest_string(&g14_decoy.hash()),
        G14_DECOY_DIGEST,
        "g14_decoy"
    );
    let g14b_decoy = signed_cp(6, e1.hash(), &mmr_at_cp2);
    assert_eq!(
        digest_string(&g14b_decoy.hash()),
        G14B_DECOY_DIGEST,
        "g14b_decoy"
    );
    // Pin G12b's three-resume layout: a trusted res1 at seq 7, an
    // untrusted res2 at seq 12 whose candidate is dropped, and a
    // trusted res3 at seq 17. Only res1 and res2 appear in another
    // row's expected detail; res3 is used only as a receipt
    // argument, so its hash does not need a `const`.
    let g12b_open1 = signed_cp(6, cp2.hash(), &mmr_at_cp2);
    let g12b_res1 = resume_decl(&g12b_open1, 2, cp2.hash(), GAP_HIGH);
    assert_eq!(
        digest_string(&g12b_res1.hash()),
        G12B_RES1_DIGEST,
        "g12b_res1"
    );
    let mmr_after_r1 = pushed(&pushed(&mmr_at_cp2, &g12b_open1), &g12b_res1);
    let g12b_open2 = sign_as(&untrusted_signer(), 11, g12b_res1.hash(), &mmr_after_r1);
    let g12b_res2 = resume_decl(&g12b_open2, RESUME_SEQ, g12b_res1.hash(), 10);
    assert_eq!(
        digest_string(&g12b_res2.hash()),
        G12B_RES2_DIGEST,
        "g12b_res2"
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
}

// =====================================================================
// G1b - ACCEPTANCE. Pins `is_valid()` = true and
// `is_strict_valid()` = false on G1's confirmed report in one
// `assert_eq!` tuple (`findings`, `is_valid`, `is_strict_valid`),
// covering ADR-0005 decision 5 and decision 11's `--strict` half of
// l.986. The lost receipts become `LostRecord`, `is_valid` stays
// true, and the `Resumed` warning fails `--strict`.
// =====================================================================
#[test]
fn g1b_honest_resume_fails_strict_on_resumed_warning() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([
        (1, fx.e1.hash()),
        (RESUME_SEQ, fx.resume_hash),
        (3, WRONG_HASH_55),
    ]);
    let report = report_of(vec![fx.dir.clone()], verifier);
    let expected_findings = vec![
        lost(3, "receipt", WRONG_HASH_55_DIGEST, GAP_LOW, GAP_HIGH),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            resumed_detail(2, CP2_DIGEST, "3..=5", 1),
        ),
    ];
    assert_eq!(
        (
            report.findings().to_vec(),
            report.is_valid(),
            report.is_strict_valid(),
        ),
        (expected_findings, true, false),
        "G1b literal (findings, is_valid, is_strict_valid)"
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
/// With `lost_through = 6`, `k = lost_through + 1 = 7`, and the
/// record at seq 7 is the resume itself, not a checkpoint; the
/// structural check fails `no-opening`. The candidate is dropped
/// and `SeqGap` fires.
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
                "expected size 3 root {MMR_AT_CP2_ROOT_DIGEST}, \
                 found size 1 root {MMR_AT_CP0_ROOT_DIGEST}"
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
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .key_through(other_signer().public_key(), 4, WRONG_HASH_55)
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
            format!("anchor seq 4 hash {G6_ANCHOR_DIGEST}: no record"),
        ),
        lost(4, "waive", WRONG_HASH_55_DIGEST, GAP_LOW, GAP_HIGH),
        unlocated(
            K::RevocationMismatch,
            Some(4),
            format!("key {OTHER_KEY_HEX} through=4:{WRONG_HASH_55_DIGEST}: no record at seq 4"),
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
    drop(d);
}

// =====================================================================
// G7b - REGRESSION. Writer-built genesis resume with an **anchored**
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
}

// =====================================================================
// G7c - REGRESSION. Writer-built genesis resume with an
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
    drop(d);
}

// =====================================================================
// G9c - ACCEPTANCE. Per-gap `lost_records` count (ruling 13-V7-d1
// point 8) under two confirmed resumes with ASYMMETRIC counts (3 vs
// 0), plus the ADR-0005 decision 11 l.993 "`lost_through` = head:
// no gap, no `LostRecord`" bullet on the second resume (`gap=none
// lost_records=0`). Hand-built because chaining two writer resumes
// requires two separate `AuditConfig::resume` calls that the
// directory state after the first does not accept; the two openings
// and two resume records are chained hand-built records.
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
    // Second resume with `lost_through = head_seq` on the first
    // resume's head (seq 7): the gap is empty, `Resumed` reads
    // `gap=none lost_records=0`, and no `LostRecord` can fall in
    // the (empty) range (ADR-0005 decision 11 l.993).
    let open2 = signed_cp(8, res1.hash(), &mmr_after_r1);
    let res2 = resume_decl(&open2, RESUME_SEQ, res1.hash(), RESUME_SEQ);
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
        (9, res2.hash()),
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
            9,
            format!(
                "operator=operator reason=incident head=7:{res1_digest} \
                 gap=none lost_records=0 structural=valid"
            ),
        ),
        unlocated(K::UncoveredTail, None, "records seq 9..=9".to_owned()),
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
}

// =====================================================================
// G10 - REGRESSION. ADR-0005 decision 5 "The genesis case" (ADR
// amendment 12; ruling 13-V7-d1 point 7 exception), unconfirmed
// half: a genesis resume with no resume receipt keeps the `SeqGap`
// for `0..=lost_through`. Pairs with G10b (confirmed half).
// =====================================================================
#[test]
fn g10_genesis_gap_unconfirmed_keeps_seq_gap() {
    let g = genesis(GAP_HIGH);
    let live = g.dir.join("audit.jsonl");
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()));
    let report = report_of(vec![g.dir.clone()], verifier);
    let expected = vec![
        located(
            K::SeqGap,
            live.clone(),
            1,
            6,
            "missing seq 0..=5".to_owned(),
        ),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            resumed_detail(0, TRAIL_GENESIS_DIGEST, "0..=5", 0),
        ),
    ];
    assert_findings(report.findings(), &expected, "G10");
}

// =====================================================================
// G10b - ACCEPTANCE. Confirmed half of ADR-0005 decision 5 "The
// genesis case" (ruling 13-V7-d1 point 7 exception): once a receipt
// matches the genesis resume's `(seq, hash)`, `SeqGap 0..=lt` is
// suppressed. Pairs with G10 (unconfirmed half).
// =====================================================================
#[test]
fn g10b_genesis_gap_confirmed_suppresses_seq_gap() {
    let g = genesis(GAP_HIGH);
    let live = g.dir.join("audit.jsonl");
    let verifier =
        Verifier::new(trust_with_key(fixture_pubkey())).receipts([(RESUME_SEQ, g.resume_hash)]);
    let report = report_of(vec![g.dir.clone()], verifier);
    let expected = vec![located(
        K::Resumed,
        live,
        2,
        RESUME_SEQ,
        resumed_detail(0, TRAIL_GENESIS_DIGEST, "0..=5", 0),
    )];
    assert_findings(report.findings(), &expected, "G10b");
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
}

// =====================================================================
// G10_above - ACCEPTANCE. A receipt at `seq 6` (= `lost_through +
// 1` = opening seq) on a confirmed genesis gap is NOT in the gap
// (`0..=5`); it is checked against the opening record and emits
// `ReceiptMismatch "hash differs"`. Pairs with G9_above (non-
// genesis) to pin the upper boundary across both gap kinds.
// =====================================================================
#[test]
fn g10_above_receipt_at_lost_through_plus_one_is_not_lost_genesis() {
    let g = genesis(GAP_HIGH);
    let live = g.dir.join("audit.jsonl");
    let opening_digest = digest_string(&g.opening_hash);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(RESUME_SEQ, g.resume_hash), (6, WRONG_HASH_55)]);
    let report = report_of(vec![g.dir.clone()], verifier);
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
            resumed_detail(0, TRAIL_GENESIS_DIGEST, "0..=5", 0),
        ),
    ];
    assert_findings(report.findings(), &expected, "G10_above");
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
    drop(d);
}

// =====================================================================
// G12 - ACCEPTANCE. Ruling 13-V7-d1 point 8 (per-gap
// `lost_records`): two resumes on one trail where the first has an
// untrusted opening (candidate dropped by `signatures::trusted`;
// ruling 13-V5-d1 point 8) and the second is trusted and
// confirmed. The count map keys `lost_records=<n>` by each gap's
// resume `(seq, hash)`; a candidate absent from the gap list keeps
// `lost_records=0`, and the trusted resume's gap gets its own
// per-gap count, so a receipt inside the second gap is not
// attributed to the first resume. Hand-built because the writer
// never signs with an untrusted key.
// =====================================================================
#[test]
fn g12_untrusted_first_resume_keeps_zero_while_trusted_second_counts() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    // Resume 1: untrusted opening at seq 6 (0x44 key), resume at
    // seq 7. The structural check passes (opening is a checkpoint
    // linking to cp2), but `signatures::trusted` fails and
    // `build_gaps` drops the candidate, so its jump keeps its
    // ordinary `SeqGap 3..=5` and no `LostRecord` can fall inside
    // its would-be gap.
    let other = untrusted_signer();
    let open1 = sign_as(&other, 6, cp2.hash(), &mmr2);
    let res1 = resume_decl(&open1, 2, cp2.hash(), GAP_HIGH);
    let mmr_after_r1 = pushed(&pushed(&mmr2, &open1), &res1);
    // Resume 2: trusted opening at seq 11 (fixture key), resume at
    // seq 12, lost_through=10. Its gap `8..=10` is confirmed when
    // the receipt at `(12, res2.hash())` is supplied.
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
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([
        (1, e1.hash()),
        (12, res2.hash()),
        (4, WRONG_HASH_55),
        (9, WRONG_HASH_55),
    ]);
    let report = report_of(vec![d.0.clone()], verifier);
    let live = d.0.join("audit.jsonl");
    let res1_resumed_detail = format!(
        "operator=operator reason=incident head=2:{CP2_DIGEST} \
         gap=3..=5 lost_records=0 structural=valid"
    );
    let res2_resumed_detail = format!(
        "operator=operator reason=incident head=7:{G12_RES1_DIGEST} \
         gap=8..=10 lost_records=1 structural=valid"
    );
    let expected = vec![
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
            K::NoReceipt,
            live.clone(),
            2,
            RESUME_SEQ,
            format!("no receipt for seq {RESUME_SEQ} hash {G12_RES1_DIGEST}"),
        ),
        located(K::Resumed, live.clone(), 2, RESUME_SEQ, res1_resumed_detail),
        lost(9, "receipt", WRONG_HASH_55_DIGEST, 8, 10),
        located(K::Resumed, live, 4, 12, res2_resumed_detail),
        unlocated(K::UncoveredTail, None, "records seq 12..=12".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "G12");
    drop(d);
}

// =====================================================================
// G12b - ACCEPTANCE. Second layout for per-gap `lost_records`
// (ruling 13-V7-d1 point 8): three chained resumes on one trail
// where only the middle one (seq 11..=12) is untrusted. Each gap's
// `lost_records` is keyed by its own resume `(seq, hash)` on the
// gap list, so a candidate dropped by `signatures::trusted` keeps
// its own `lost_records=0` AND the surrounding gaps' counts are
// not shifted by its absence. Res1 (trusted, gap 3..=5) counts
// `lost_records=1`, res2 (untrusted, candidate dropped) keeps
// `lost_records=0` with `SeqGap 8..=10`, and res3 (trusted, gap
// 13..=15) counts `lost_records=2`. Pairs with G12 (one dropped +
// one trusted) to pin the keyed-by-gap-resume rule under both
// shapes. Hand-built because chaining three resumes requires
// hand-built records and because the middle resume uses an
// untrusted key the writer never signs with.
// =====================================================================
#[test]
fn g12b_three_resumes_each_counted_independently_of_a_dropped_middle() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    // Res1 (trusted) at seq 7, gap 3..=5.
    let open1 = signed_cp(6, cp2.hash(), &mmr2);
    let res1 = resume_decl(&open1, 2, cp2.hash(), GAP_HIGH);
    let mmr_after_r1 = pushed(&pushed(&mmr2, &open1), &res1);
    // Res2 (untrusted) at seq 12, candidate dropped. SeqGap 8..=10
    // is kept at open2's line/seq.
    let other = untrusted_signer();
    let open2 = sign_as(&other, 11, res1.hash(), &mmr_after_r1);
    let res2 = resume_decl(&open2, RESUME_SEQ, res1.hash(), 10);
    let mmr_after_r2 = pushed(&pushed(&mmr_after_r1, &open2), &res2);
    // Res3 (trusted) at seq 17, gap 13..=15.
    let open3 = signed_cp(16, res2.hash(), &mmr_after_r2);
    let res3 = resume_decl(&open3, 12, res2.hash(), 15);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    std::fs::write(
        d.0.join("audit.jsonl"),
        [
            open1.clone(),
            res1.clone(),
            open2.clone(),
            res2.clone(),
            open3.clone(),
            res3.clone(),
        ]
        .iter()
        .flat_map(line_bytes)
        .collect::<Vec<u8>>(),
    )
    .unwrap();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([
        (1, e1.hash()),
        (RESUME_SEQ, res1.hash()),
        (17, res3.hash()),
        (4, WRONG_HASH_55),
        (13, WRONG_HASH_55),
        (14, WRONG_HASH_55),
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
        located(
            K::SeqGap,
            live.clone(),
            3,
            11,
            "missing seq 8..=10".to_owned(),
        ),
        located(
            K::UntrustedKey,
            live.clone(),
            3,
            11,
            format!(
                "key {UNTRUSTED_KEY_HEX} not listed for trail {}",
                hex(&TRAIL)
            ),
        ),
        located(
            K::NoReceipt,
            live.clone(),
            4,
            12,
            format!("no receipt for seq 12 hash {G12B_RES2_DIGEST}"),
        ),
        located(
            K::Resumed,
            live.clone(),
            4,
            12,
            format!(
                "operator=operator reason=incident head=7:{G12B_RES1_DIGEST} \
                 gap=8..=10 lost_records=0 structural=valid"
            ),
        ),
        lost(13, "receipt", WRONG_HASH_55_DIGEST, 13, 15),
        lost(14, "receipt", WRONG_HASH_55_DIGEST, 13, 15),
        located(
            K::Resumed,
            live,
            6,
            17,
            format!(
                "operator=operator reason=incident head=12:{G12B_RES2_DIGEST} \
                 gap=13..=15 lost_records=2 structural=valid"
            ),
        ),
        unlocated(K::UncoveredTail, None, "records seq 17..=17".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "G12b");
    drop(d);
}

// =====================================================================
// G13 - ACCEPTANCE. Ruling 13-V7-d1 point 8 confirmation path: a
// receipt confirms a gap only when the shared match rule's outcome
// is Matched, which includes passing `Classifier::set_aside`. Under
// `.end_before(<opening line>, Some(opening))`, `E = opening_seq`,
// so a receipt at the resume record's `seq` (above `E`) is
// `OutOfRange` and MUST NOT confirm the gap; a receipt inside the
// gap then stays `ReceiptMismatch "no record"`, and the `Resumed`
// detail keeps `lost_records=0`.
// =====================================================================
#[test]
fn g13_end_before_sets_aside_resume_receipt_so_gap_stays_unconfirmed() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let opening_text = std::fs::read_to_string(&live).unwrap();
    let opening_line = opening_text.lines().next().unwrap();
    let opening_cp = crate::audit::Checkpoint::parse(opening_line).unwrap();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .end_before(opening_line, Some(opening_cp))
        .unwrap()
        .receipts([
            (1, fx.e1.hash()),
            (4, WRONG_HASH_55),
            (RESUME_SEQ, fx.resume_hash),
        ]);
    let report = report_of(vec![fx.dir.clone()], verifier);
    let expected = vec![
        unlocated(
            K::ReceiptMismatch,
            Some(4),
            format!("receipt seq 4 hash {WRONG_HASH_55_DIGEST}: no record"),
        ),
        located(
            K::TrailEnded,
            live.clone(),
            1,
            6,
            "end_before seq 6: records seq 6..=8 at or above the end".to_owned(),
        ),
        unlocated(
            K::OutOfRange,
            Some(RESUME_SEQ),
            format!(
                "receipt seq {RESUME_SEQ} hash {}: above end seq 6",
                digest_string(&fx.resume_hash)
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
    assert_findings(report.findings(), &expected, "G13");
}

// =====================================================================
// G13b - ACCEPTANCE. Second layout for the set-aside confirmation
// rule (ruling 13-V7-d1 point 8): same `.end_before` on the opening
// but with NO end anchor, so the resume receipt above `E` is
// `UnanchoredEnd` (error) rather than `OutOfRange` (info). The gap
// still stays unconfirmed and the in-gap waiver keeps
// `ReceiptMismatch "no record"`.
// =====================================================================
#[test]
fn g13b_end_before_unanchored_set_aside_resume_receipt_stays_unconfirmed() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let opening_text = std::fs::read_to_string(&live).unwrap();
    let opening_line = opening_text.lines().next().unwrap();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .end_before(opening_line, None)
        .unwrap()
        .receipts([(1, fx.e1.hash()), (RESUME_SEQ, fx.resume_hash)])
        .waive(4, WRONG_HASH_55, "orphan")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], verifier);
    let expected = vec![
        unlocated(
            K::ReceiptMismatch,
            Some(4),
            format!("waive seq 4 hash {WRONG_HASH_55_DIGEST}: no record"),
        ),
        unlocated(
            K::UnanchoredEnd,
            Some(6),
            "end_before seq 6: no end anchor".to_owned(),
        ),
        located(
            K::TrailEnded,
            live.clone(),
            1,
            6,
            "end_before seq 6: records seq 6..=8 at or above the end".to_owned(),
        ),
        unlocated(
            K::UnanchoredEnd,
            Some(RESUME_SEQ),
            format!(
                "receipt seq {RESUME_SEQ} hash {}: above end seq 6",
                digest_string(&fx.resume_hash)
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
    assert_findings(report.findings(), &expected, "G13b");
}

// =====================================================================
// G14 - REGRESSION. Trust filter (ruling 13-V5-d1 point 8) pairs
// the hash equality with the trusted predicate on the same copy:
// an untrusted native opening at the opening `seq` is NOT rescued
// by a different, trusted shipped copy at that `seq`. Fork at seq
// 6 (`SeqConflict`), the shipped-trusted copy covers the tail
// (`UncoveredTail` starts at the resume seq), the candidate is
// dropped so the jump keeps its `SeqGap 3..=5`, and no
// `LostRecord` can fall in its would-be gap. Hand-built because
// the writer never signs with an untrusted key.
// =====================================================================
#[test]
fn g14_untrusted_native_opening_trusted_shipped_copy_does_not_confirm() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    // Native opening at seq 6: untrusted key, correct previous and
    // `mmr_size = 3` so the fold matches it (structural check and
    // fold filter both pass), only the trust filter drops it.
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
    // Shipped (Collector-style) decoy at seq 6: trusted key, SAME
    // `previous` so the chain check passes, DIFFERENT MMR fields
    // so its hash differs from the native opening. Fold does not
    // run on shipped inputs (ruling 13-V4-d7; #224).
    let shipped_decoy = signed_cp(6, cp2.hash(), &mmr0);
    let shipped = d.0.join("collector.jsonl");
    std::fs::write(&shipped, line_bytes(&shipped_decoy)).unwrap();
    let verifier =
        Verifier::new(trust_with_key(fixture_pubkey())).receipts([(RESUME_SEQ, resume.hash())]);
    let sealed = segment_path(&d.0, 0);
    let report = report_of(vec![d.0.clone(), shipped.clone()], verifier);
    let live = d.0.join("audit.jsonl");
    // SeqConflict renders the distinct hashes in `BTreeMap` byte
    // order (`engine::check`). For G14's pair, `G14_DECOY_DIGEST`
    // sorts before `UNTRUSTED_OPENING_SEQ_6_DIGEST`, so the detail
    // lists the decoy first.
    let expected = vec![
        located(
            K::NoReceipt,
            sealed,
            2,
            1,
            format!("no receipt for seq 1 hash {E1_DIGEST}"),
        ),
        located(
            K::SeqConflict,
            live.clone(),
            1,
            6,
            format!("conflicting hashes: {G14_DECOY_DIGEST}, {UNTRUSTED_OPENING_SEQ_6_DIGEST}"),
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
            format!(
                "operator=operator reason=incident head=2:{CP2_DIGEST} \
                 gap=3..=5 lost_records=0 structural=valid"
            ),
        ),
        unlocated(K::UncoveredTail, None, "records seq 7..=7".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "G14");
    drop(d);
}

// =====================================================================
// G14b - REGRESSION. Second layout for the paired hash+trust check
// (ruling 13-V5-d1 point 8): the shipped copy carries a DIFFERENT
// `previous` from the native opening, so the trusted shipped-only
// copy at the opening `seq` neither links to cp2 nor matches the
// native opening's hash. The candidate is still dropped, the jump
// keeps its `SeqGap 3..=5`, and the gap stays unconfirmed. Pairs
// with G14 (same `previous`, different MMR) to pin the hash-vs-
// trust pairing across two shapes of different-hash decoys.
// =====================================================================
#[test]
fn g14b_different_previous_trusted_shipped_copy_does_not_confirm() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    // Native opening at seq 6: untrusted key, `previous = cp2`,
    // honest MMR. Fold matches, structural check passes, trust
    // filter drops.
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
    // Shipped trusted decoy at seq 6: trusted key, DIFFERENT
    // `previous` (`e1.hash()` instead of `cp2.hash()`) and the
    // same honest MMR, so its hash differs from the native opening
    // and `ChainBroken` fires for the decoy's broken link.
    let shipped_decoy = signed_cp(6, e1.hash(), &mmr2);
    let shipped = d.0.join("collector.jsonl");
    std::fs::write(&shipped, line_bytes(&shipped_decoy)).unwrap();
    let verifier =
        Verifier::new(trust_with_key(fixture_pubkey())).receipts([(RESUME_SEQ, resume.hash())]);
    let sealed = segment_path(&d.0, 0);
    let report = report_of(vec![d.0.clone(), shipped.clone()], verifier);
    let live = d.0.join("audit.jsonl");
    // For G14b's pair, `UNTRUSTED_OPENING_SEQ_6_DIGEST` sorts
    // before `G14B_DECOY_DIGEST`, so the detail lists the native
    // opening first. The decoy's chain link points at `e1.hash()`
    // instead of `cp2.hash()`, so `ChainBroken` reads `E1_DIGEST`
    // for the `found` side.
    let expected = vec![
        located(
            K::NoReceipt,
            sealed,
            2,
            1,
            format!("no receipt for seq 1 hash {E1_DIGEST}"),
        ),
        located(
            K::SeqConflict,
            live.clone(),
            1,
            6,
            format!("conflicting hashes: {UNTRUSTED_OPENING_SEQ_6_DIGEST}, {G14B_DECOY_DIGEST}"),
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
            K::ChainBroken,
            shipped.clone(),
            1,
            6,
            format!("expected previous {CP2_DIGEST}, found {E1_DIGEST}"),
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
    assert_findings(report.findings(), &expected, "G14b");
    drop(d);
}
