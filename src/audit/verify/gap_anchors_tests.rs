//! Rows for anchors and `through=<b>:<h>` revocation pins inside a
//! confirmed resume gap whose opening checkpoint is itself anchored
//! (ADR-0005 decision 5 "Receipts lost with a resume"; ruling
//! 13-V7-d1 point 8). Every row ends in one whole-list
//! [`assert_findings`]. Every digest in an expected detail is a
//! written-out hex `const` pinned by
//! [`fixture_hashes_match_literals`], or a value the writer returns
//! from this run (opening and resume hashes, which vary per run on
//! the wall clock).
//!
//! Fixture style: the confirmed non-genesis resume uses the real
//! writer (`AuditConfig::resume` on a pre-seeded `audit.trail`), as
//! in `gaps_tests.rs`. Hand-built records are used only where the
//! writer cannot produce the layout (a bounded-key checkpoint
//! signed above the pin, an other-trail anchor, and the stolen-key
//! scenario), and each row says why.

use super::tests_common::{
    assert_findings, located, parse_cp, report_of, trust_with_key, unlocated,
};
use crate::audit::{
    AuditConfig, Checkpoint, FindingKind as K, KeyFileSigner, Mmr, Record, RecordContext, Signer,
    TrustPolicy, digest_string,
    format::CheckpointFields,
    hex,
    runs_v4a_fixtures::{
        TRAIL, Temp, entry_rec, fixture_pubkey, line_bytes, pushed, put_segment, resume_decl,
        seeded, signed_cp, write_bytes,
    },
    verify::{Finding, Verifier},
};
use std::{path::PathBuf, sync::Arc};

// =====================================================================
// Shared literal hex constants and seqs. The non-genesis sealed
// prefix is `[cp0, e1, cp2]` on `TRAIL` (fixture clock `100+seq`), so
// cp0, e1 and cp2 have fixed hashes. Opening and resume record hashes
// come from the writer's returns and vary per run. `TRAIL_GENESIS_DIGEST`
// is `Record::genesis(&TRAIL)` for a genesis `Resumed` detail.
// =====================================================================

const CP0_DIGEST: &str = "blake3:fc26c6f2bb830592aaaca5413da1599489d86ac6e240a4a7a010681e0d4c8e77";
const E1_DIGEST: &str = "blake3:c121282b5135adfe7a17142cae6bfc4c9040c4aed26d74bddc923b8dafcdb6e8";
const CP2_DIGEST: &str = "blake3:4164966a12a675e55eb6e133b9e50313907f164fe142d941447defcdfdb25d06";
const TRAIL_GENESIS_DIGEST: &str =
    "blake3:a03c7c40313d5ab5cf449ba187545083161360e5ed3e41e6f9254c3b4c5efaab";
/// Second trusted signer (seed `0x77`) consumed by the pin rows. Its
/// public key is pinned here so the expected-detail format reads the
/// literal rather than recomputing from the signer at test time.
const OTHER_KEY_HEX: &str = "c853ad0f0cd2b619aea92ceec4fd56a24d6499d584ce79257e45cfd8139b60a7";

const GAP_LOW: u64 = 3;
const GAP_HIGH: u64 = 5;
const RESUME_SEQ: u64 = 7;
const OPENING_SEQ: u64 = 6;

const WRONG_HASH_55: [u8; 32] = [0x55; 32];
const WRONG_HASH_55_DIGEST: &str =
    "blake3:5555555555555555555555555555555555555555555555555555555555555555";

/// `signed_cp_explicit(4, cp2.hash, 1, [0xcc; 32], [[0xcc; 32]])`: a
/// trusted-signed anchor record at `seq 4` whose `(trail, seq, hash)`
/// is not the opening's; pinned here so the rows read the literal
/// digest.
const ANCHOR_SEQ_4_DIGEST: &str =
    "blake3:bd5ecd0d74a95fd880720aaf151a5c751ff1ffeefd2817d89fb1528630927e3f";

const OTHER_TRAIL: [u8; 16] = [0x01; 16];

// =====================================================================
// Shared helpers.
// =====================================================================

fn signer() -> Arc<dyn Signer> {
    Arc::new(KeyFileSigner::from_hex(&"27".repeat(32)).unwrap())
}

/// Second trusted signer (seed `0x77`): consumed by the `through=`
/// pin rows so the `RevocationMismatch` / `LostRecord` detail reads
/// `OTHER_KEY_HEX` rather than recomputing from the signer.
fn other_signer() -> KeyFileSigner {
    KeyFileSigner::from_hex(&"77".repeat(32)).unwrap()
}

fn pre_seed(dir: &std::path::Path) {
    write_bytes(
        &dir.join("audit.trail"),
        format!("{}\n", hex(&TRAIL)).as_bytes(),
    );
}

/// Non-genesis fixture: sealed `[cp0, e1, cp2]` + writer-built live
/// `[opening_at_seq_6, resume_at_seq_7, drop_cp_at_seq_8]` with
/// head=(2, cp2) and `lost_through=5`.
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
/// genesis).
struct Genesis {
    _dir: Temp,
    dir: PathBuf,
    resume_hash: [u8; 32],
}

fn genesis_fixture(lost_through: u64) -> Genesis {
    let d = Temp::new();
    pre_seed(&d.0);
    let (trail_b, resume, _opening) = AuditConfig::new("svc")
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
        resume_hash: resume.hash(),
    }
}

/// `Resumed` detail for a writer-built resume (`operator=op reason=r`).
fn resumed_detail(head_seq: u64, head_hash: &str, gap: &str, n: u64) -> String {
    format!(
        "operator=op reason=r head={head_seq}:{head_hash} gap={gap} \
         lost_records={n} structural=valid"
    )
}

fn lost(seq: u64, subject: &str, hash_digest: &str, low: u64, high: u64) -> Finding {
    unlocated(
        K::LostRecord,
        Some(seq),
        format!("{subject} seq {seq} hash {hash_digest}: lost in gap {low}..={high}"),
    )
}

fn lost_pin(seq: u64, key_hex: &str, low: u64, high: u64) -> Finding {
    unlocated(
        K::LostRecord,
        Some(seq),
        format!("key {key_hex} through={seq}: lost in gap {low}..={high}"),
    )
}

fn lost_anchor(seq: u64, hash_digest: &str, low: u64, high: u64) -> Finding {
    unlocated(
        K::LostRecord,
        Some(seq),
        format!("anchor seq {seq} hash {hash_digest}: lost in gap {low}..={high}"),
    )
}

/// Builds a trusted-signed anchor record at `seq 4` on `TRAIL` with
/// an mmr fold of one leaf `[0xcc; 32]`. The record is used as the
/// in-gap anchor whose `(trail, seq, hash)` is not the opening's.
fn anchor_record_seq_4(cp2_hash: [u8; 32]) -> Record {
    let mut synth_mmr = Mmr::new();
    synth_mmr.push([0xcc; 32]).unwrap();
    signed_cp(4, cp2_hash, &synth_mmr)
}

/// Builds and signs a checkpoint record under `signer` on `trail` at
/// `seq`, `previous` and `mmr`, with fixture clock `time = 100+seq`.
fn sign_as(
    signer: &KeyFileSigner,
    seq: u64,
    trail: [u8; 16],
    previous: [u8; 32],
    mmr: &Mmr,
) -> Record {
    let ctx = RecordContext::new(trail, seq, 100 + seq, "test", previous);
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

/// Builds and signs an other-trail checkpoint record under the
/// fixture key, at `seq` on `OTHER_TRAIL`. Used by rows that need an
/// other-trail anchor (A5b, A6, A6b): the anchor only has to carry a
/// valid `(trail, seq, hash)` triple, so its MMR holds one synthetic
/// leaf to satisfy the checkpoint-count invariant.
fn other_trail_cp(seq: u64, leaf: [u8; 32]) -> Record {
    let key = KeyFileSigner::from_hex(&"27".repeat(32)).unwrap();
    let previous = if seq == 0 {
        Record::genesis(&OTHER_TRAIL)
    } else {
        // `previous` for a free-standing anchor doesn't need to chain
        // to anything the verified set holds; the anchor rule reports
        // `trail differs` first.
        [0u8; 32]
    };
    let mut mmr = Mmr::new();
    if seq > 0 {
        mmr.push(leaf).unwrap();
    }
    sign_as(&key, seq, OTHER_TRAIL, previous, &mmr)
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
        hex(&other_signer().public_key()),
        OTHER_KEY_HEX,
        "other_key"
    );
    let anchor = anchor_record_seq_4(cp2.hash());
    assert_eq!(
        digest_string(&anchor.hash()),
        ANCHOR_SEQ_4_DIGEST,
        "anchor_seq_4"
    );
    assert_eq!(hex(&TRAIL), "11111111111111111111111111111111", "trail_hex");
}

// =====================================================================
// A1 - ACCEPTANCE. ADR-0005 decision 11 ~l.990 anchored-opening
// half (ruling 13-V7-d1 point 8): inside a confirmed resume gap
// whose opening checkpoint is itself anchored, an anchor, a
// `through=` pin and a waiver inside the gap each become one
// [`K::LostRecord`] (info), and the gap's `lost_records=<n>` counts
// every such finding.
// =====================================================================
#[test]
fn a1_anchored_opening_demotes_anchor_pin_and_waiver_to_lost_record() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .key_through(other_signer().public_key(), 4, WRONG_HASH_55)
        .build()
        .unwrap();
    let anchor_record = anchor_record_seq_4(fx.cp2.hash());
    let anchor_cp = parse_cp(&anchor_record);
    let live_text = std::fs::read_to_string(&live).unwrap();
    let opening_cp = Checkpoint::parse(live_text.lines().next().unwrap()).unwrap();
    let verifier = Verifier::new(trust)
        .anchor(opening_cp)
        .anchor(anchor_cp)
        .receipts([(1, fx.e1.hash()), (RESUME_SEQ, fx.resume_hash)])
        .waive(4, WRONG_HASH_55, "r")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], verifier);
    let expected = vec![
        lost_pin(4, OTHER_KEY_HEX, GAP_LOW, GAP_HIGH),
        lost_anchor(4, ANCHOR_SEQ_4_DIGEST, GAP_LOW, GAP_HIGH),
        lost(4, "waive", WRONG_HASH_55_DIGEST, GAP_LOW, GAP_HIGH),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            resumed_detail(2, CP2_DIGEST, "3..=5", 3),
        ),
    ];
    assert_findings(report.findings(), &expected, "A1");
}

// =====================================================================
// A2 - REGRESSION. ADR-0005 decision 11 ~l.990 unanchored-opening
// half (ruling 13-V7-d1 point 8): inside a confirmed resume gap
// whose opening is NOT anchored, the anchor keeps `AnchorMismatch`
// and the `through=` pin keeps `RevocationMismatch`; only the waiver
// becomes `LostRecord`, so `lost_records=1`. Pairs with A1 on the
// confirmation split.
// =====================================================================
#[test]
fn a2_unanchored_opening_keeps_anchor_and_pin_mismatches() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .key_through(other_signer().public_key(), 4, WRONG_HASH_55)
        .build()
        .unwrap();
    let anchor_record = anchor_record_seq_4(fx.cp2.hash());
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
            format!("anchor seq 4 hash {ANCHOR_SEQ_4_DIGEST}: no record"),
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
    assert_findings(report.findings(), &expected, "A2");
}

// =====================================================================
// A3 - REGRESSION. ADR-0005 decision 11 ~l.990 stolen-key case: a
// cut back over an anchored checkpoint, a forged opening and resume
// signed with the trusted key, and the resume's receipt do not
// anchor the opening (no anchor matches the forged opening's
// `(trail, seq, hash)`), so every anchor inside the gap stays
// `AnchorMismatch` and the report is invalid: a text line never
// anchors an opening on its own. Hand-built because the writer
// never signs a stolen-key cut.
// =====================================================================
#[test]
fn a3_stolen_key_receipt_does_not_anchor_opening_so_anchors_stay() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    // Forged opening at seq 6 signed with the trusted key: the chain
    // links to cp2, mmr_size = 3 so the fold matches, trust passes.
    // The declared `lost_through = 5` cuts back over the anchor
    // operator keeps for seq 5. No anchor is given for the opening
    // itself.
    let opening = signed_cp(OPENING_SEQ, cp2.hash(), &mmr2);
    let resume = resume_decl(&opening, 2, cp2.hash(), GAP_HIGH);
    std::fs::write(
        d.0.join("audit.jsonl"),
        [opening.clone(), resume.clone()]
            .iter()
            .flat_map(line_bytes)
            .collect::<Vec<u8>>(),
    )
    .unwrap();
    // Outside anchor at seq 5 (inside the cut gap `3..=5`), signed
    // with a synthetic mmr leaf, whose record was cut from the trail
    // at verify time; the anchor rule reports `no record`.
    let mut synth = Mmr::new();
    synth.push([0xcc; 32]).unwrap();
    let anchor_at_5 = signed_cp(5, cp2.hash(), &synth);
    let anchor_at_5_digest = digest_string(&anchor_at_5.hash());
    let anchor_cp = parse_cp(&anchor_at_5);
    // A receipt inside the gap (at seq 4, wrong hash) becomes
    // `LostRecord` because the gap is confirmed (receipts-side
    // demotion needs only confirmed, ruling 13-V7-d1 point 8). The
    // stolen-key probe is the anchor row that stays `AnchorMismatch`
    // because the opening is not anchored.
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .anchor(anchor_cp)
        .receipts([
            (1, e1.hash()),
            (RESUME_SEQ, resume.hash()),
            (4, WRONG_HASH_55),
        ]);
    let report = report_of(vec![d.0.clone()], verifier);
    let live = d.0.join("audit.jsonl");
    let expected = vec![
        lost(4, "receipt", WRONG_HASH_55_DIGEST, GAP_LOW, GAP_HIGH),
        unlocated(
            K::AnchorMismatch,
            Some(5),
            format!("anchor seq 5 hash {anchor_at_5_digest}: no record"),
        ),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            format!(
                "operator=operator reason=incident head=2:{CP2_DIGEST} \
                 gap=3..=5 lost_records=1 structural=valid"
            ),
        ),
        unlocated(K::UncoveredTail, None, "records seq 7..=7".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "A3");
    assert!(!report.is_valid(), "A3 report must be invalid");
    drop(d);
}

// =====================================================================
// A4 - REGRESSION. ADR-0005 decision 11 ~l.989 unconfirmed-gap
// half: a resume gap kept by the trust and fold filters but not
// confirmed (no matching resume receipt) suppresses `SeqGap` for a
// non-genesis candidate (ruling 13-V7-d1 point 7) but keeps anchors
// and pins inside the gap as `AnchorMismatch` and
// `RevocationMismatch` even when the opening checkpoint is
// anchored: confirmation is REQUIRED for the demotion, not just the
// opening anchor.
// =====================================================================
#[test]
fn a4_unconfirmed_gap_keeps_anchor_and_pin_even_when_opening_anchored() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let resume_digest = digest_string(&fx.resume_hash);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .key_through(other_signer().public_key(), 4, WRONG_HASH_55)
        .build()
        .unwrap();
    let anchor_record = anchor_record_seq_4(fx.cp2.hash());
    let anchor_cp = parse_cp(&anchor_record);
    let live_text = std::fs::read_to_string(&live).unwrap();
    let opening_cp = Checkpoint::parse(live_text.lines().next().unwrap()).unwrap();
    let verifier = Verifier::new(trust)
        .anchor(opening_cp)
        .anchor(anchor_cp)
        .receipts([(1, fx.e1.hash())]);
    let report = report_of(vec![fx.dir.clone()], verifier);
    let expected = vec![
        unlocated(
            K::AnchorMismatch,
            Some(4),
            format!("anchor seq 4 hash {ANCHOR_SEQ_4_DIGEST}: no record"),
        ),
        unlocated(
            K::RevocationMismatch,
            Some(4),
            format!("key {OTHER_KEY_HEX} through=4:{WRONG_HASH_55_DIGEST}: no record at seq 4"),
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
    assert_findings(report.findings(), &expected, "A4");
}

// =====================================================================
// A4b - REGRESSION. Second layout for ADR-0005 ~l.989 unconfirmed-
// gap half (ruling 13-V7-d1 point 8): the writer-built GENESIS
// resume whose opening is anchored, but no resume receipt is given.
// The anchor and the pin inside the gap `0..=5` stay
// `AnchorMismatch` and `RevocationMismatch`. The genesis-case
// exception (ruling 13-V7-d1 point 7) keeps `SeqGap 0..=5` because
// the gap is not confirmed. Pairs with A4 on the unconfirmed-gap /
// anchored-opening split.
// =====================================================================
#[test]
fn a4b_genesis_unconfirmed_gap_keeps_anchor_pin_and_seq_gap() {
    let g = genesis_fixture(GAP_HIGH);
    let live = g.dir.join("audit.jsonl");
    let resume_digest = digest_string(&g.resume_hash);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .key_through(other_signer().public_key(), 4, WRONG_HASH_55)
        .build()
        .unwrap();
    let cp2_hash = {
        let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
        let mmr0 = seeded(&cp0);
        let e1 = entry_rec(1, cp0.hash());
        let mmr1 = pushed(&mmr0, &e1);
        signed_cp(2, e1.hash(), &mmr1).hash()
    };
    let anchor_record = anchor_record_seq_4(cp2_hash);
    let anchor_cp = parse_cp(&anchor_record);
    let live_text = std::fs::read_to_string(&live).unwrap();
    let opening_cp = Checkpoint::parse(live_text.lines().next().unwrap()).unwrap();
    let verifier = Verifier::new(trust)
        .anchor(opening_cp)
        .anchor(anchor_cp)
        .receipts([]);
    let report = report_of(vec![g.dir.clone()], verifier);
    let expected = vec![
        unlocated(
            K::AnchorMismatch,
            Some(4),
            format!("anchor seq 4 hash {ANCHOR_SEQ_4_DIGEST}: no record"),
        ),
        unlocated(
            K::RevocationMismatch,
            Some(4),
            format!("key {OTHER_KEY_HEX} through=4:{WRONG_HASH_55_DIGEST}: no record at seq 4"),
        ),
        located(
            K::SeqGap,
            live.clone(),
            1,
            OPENING_SEQ,
            "missing seq 0..=5".to_owned(),
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
            resumed_detail(0, TRAIL_GENESIS_DIGEST, "0..=5", 0),
        ),
    ];
    assert_findings(report.findings(), &expected, "A4b");
}

// =====================================================================
// A5 - REGRESSION. Ruling 13-V6-d1 point 2: "anchored" is the full
// `(trail, seq, hash)` match, not `seq` alone. An anchor that names
// the opening's `seq` with another hash does NOT anchor the
// opening: the anchor inside the gap and the pin stay
// `AnchorMismatch` and `RevocationMismatch`. The anchor at the
// opening's `seq` itself is in range (above the gap) and is checked
// by the ordinary rule, which reports `hash differs`.
// =====================================================================
#[test]
fn a5_anchor_at_opening_seq_with_wrong_hash_does_not_anchor_opening() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let opening_digest = digest_string(&fx.opening_hash);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .key_through(other_signer().public_key(), 4, WRONG_HASH_55)
        .build()
        .unwrap();
    // Trusted-signed checkpoint at the opening's `seq` (6) with a
    // different `mmr`, so its hash differs from the writer's opening.
    let mut synth = Mmr::new();
    synth.push([0xcc; 32]).unwrap();
    let decoy_at_opening = signed_cp(OPENING_SEQ, fx.cp2.hash(), &synth);
    let decoy_digest = digest_string(&decoy_at_opening.hash());
    let anchor_at_opening = parse_cp(&decoy_at_opening);
    let anchor_record = anchor_record_seq_4(fx.cp2.hash());
    let anchor_in_gap = parse_cp(&anchor_record);
    let verifier = Verifier::new(trust)
        .anchor(anchor_at_opening)
        .anchor(anchor_in_gap)
        .receipts([(1, fx.e1.hash()), (RESUME_SEQ, fx.resume_hash)]);
    let report = report_of(vec![fx.dir.clone()], verifier);
    let expected = vec![
        unlocated(
            K::AnchorMismatch,
            Some(4),
            format!("anchor seq 4 hash {ANCHOR_SEQ_4_DIGEST}: no record"),
        ),
        unlocated(
            K::RevocationMismatch,
            Some(4),
            format!("key {OTHER_KEY_HEX} through=4:{WRONG_HASH_55_DIGEST}: no record at seq 4"),
        ),
        located(
            K::AnchorMismatch,
            live.clone(),
            1,
            OPENING_SEQ,
            format!("anchor seq 6 hash {decoy_digest}: hash differs (record {opening_digest})"),
        ),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            resumed_detail(2, CP2_DIGEST, "3..=5", 0),
        ),
    ];
    assert_findings(report.findings(), &expected, "A5");
}

// =====================================================================
// A5b - REGRESSION. Second layout for the full-triple match rule
// (ruling 13-V6-d1 point 2): an anchor at the opening's `seq` on
// ANOTHER trail stays `AnchorMismatch … trail differs`, and the
// opening is not anchored. The in-gap anchor therefore keeps
// `AnchorMismatch`. Pairs with A5 (same seq, wrong hash) on the
// trail half of the triple. Hand-built: the other-trail anchor is
// an anchor the writer never produces here.
// =====================================================================
#[test]
fn a5b_other_trail_anchor_at_opening_seq_does_not_anchor_opening() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let other_cp_record = other_trail_cp(OPENING_SEQ, [0xaa; 32]);
    let other_cp_digest = digest_string(&other_cp_record.hash());
    let other_cp = parse_cp(&other_cp_record);
    let anchor_record = anchor_record_seq_4(fx.cp2.hash());
    let anchor_in_gap = parse_cp(&anchor_record);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .anchor(other_cp)
        .anchor(anchor_in_gap)
        .receipts([(1, fx.e1.hash()), (RESUME_SEQ, fx.resume_hash)]);
    let report = report_of(vec![fx.dir.clone()], verifier);
    let expected = vec![
        unlocated(
            K::AnchorMismatch,
            Some(4),
            format!("anchor seq 4 hash {ANCHOR_SEQ_4_DIGEST}: no record"),
        ),
        located(
            K::AnchorMismatch,
            live.clone(),
            1,
            OPENING_SEQ,
            format!("anchor seq 6 hash {other_cp_digest}: trail differs"),
        ),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            resumed_detail(2, CP2_DIGEST, "3..=5", 0),
        ),
    ];
    assert_findings(report.findings(), &expected, "A5b");
}

// =====================================================================
// A6 - REGRESSION. Ruling 13-V6-d3 point 4 and 13-V7-d1 point 8:
// an anchor from another trail inside a confirmed resume gap whose
// opening is anchored still gives `AnchorMismatch … trail differs`.
// Trail-differs runs before the gap set-aside; another trail's
// anchor is never demoted. A waiver inside the same gap is
// `LostRecord`, confirming the gap-demotion path runs for the
// other inputs.
// =====================================================================
#[test]
fn a6_other_trail_anchor_in_confirmed_anchored_gap_stays_trail_differs() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let other_anchor_record = other_trail_cp(4, [0xbb; 32]);
    let other_anchor_digest = digest_string(&other_anchor_record.hash());
    let other_anchor = parse_cp(&other_anchor_record);
    let live_text = std::fs::read_to_string(&live).unwrap();
    let opening_cp = Checkpoint::parse(live_text.lines().next().unwrap()).unwrap();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .anchor(opening_cp)
        .anchor(other_anchor)
        .receipts([(1, fx.e1.hash()), (RESUME_SEQ, fx.resume_hash)])
        .waive(4, WRONG_HASH_55, "r")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], verifier);
    let expected = vec![
        unlocated(
            K::AnchorMismatch,
            Some(4),
            format!("anchor seq 4 hash {other_anchor_digest}: trail differs"),
        ),
        lost(4, "waive", WRONG_HASH_55_DIGEST, GAP_LOW, GAP_HIGH),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            resumed_detail(2, CP2_DIGEST, "3..=5", 1),
        ),
    ];
    assert_findings(report.findings(), &expected, "A6");
}

// =====================================================================
// A7 - ACCEPTANCE. ADR-0005 decision 11 ~l.990 pin half (ruling
// 13-V7-d1 point 8): a `through=` pin and an anchor inside a
// confirmed resume gap whose opening is anchored each become one
// [`K::LostRecord`] (info), counted in the gap's `lost_records=<n>`.
// Only the pin's hash check is replaced; the bound still limits the
// key, so a bounded-key checkpoint ABOVE the bound still fires
// `UntrustedKey`. Hand-built because the writer never signs with
// the bounded `OTHER_KEY_HEX` key.
// =====================================================================
#[test]
fn a7_anchored_opening_demotes_pin_and_anchor_but_keeps_untrusted_key_above_bound() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let opening = signed_cp(OPENING_SEQ, cp2.hash(), &mmr2);
    let resume = resume_decl(&opening, 2, cp2.hash(), GAP_HIGH);
    let mmr_after_resume = pushed(&pushed(&mmr2, &opening), &resume);
    let bounded_cp = sign_as(&other_signer(), 8, TRAIL, resume.hash(), &mmr_after_resume);
    std::fs::write(
        d.0.join("audit.jsonl"),
        [opening.clone(), resume.clone(), bounded_cp.clone()]
            .iter()
            .flat_map(line_bytes)
            .collect::<Vec<u8>>(),
    )
    .unwrap();
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .key_through(other_signer().public_key(), 4, WRONG_HASH_55)
        .build()
        .unwrap();
    let anchor_record = anchor_record_seq_4(cp2.hash());
    let anchor_in_gap = parse_cp(&anchor_record);
    let opening_cp = parse_cp(&opening);
    let verifier = Verifier::new(trust)
        .anchor(opening_cp)
        .anchor(anchor_in_gap)
        .receipts([(1, e1.hash()), (RESUME_SEQ, resume.hash())]);
    let report = report_of(vec![d.0.clone()], verifier);
    let live = d.0.join("audit.jsonl");
    let expected = vec![
        lost_pin(4, OTHER_KEY_HEX, GAP_LOW, GAP_HIGH),
        lost_anchor(4, ANCHOR_SEQ_4_DIGEST, GAP_LOW, GAP_HIGH),
        located(
            K::Resumed,
            live.clone(),
            2,
            RESUME_SEQ,
            format!(
                "operator=operator reason=incident head=2:{CP2_DIGEST} \
                 gap=3..=5 lost_records=2 structural=valid"
            ),
        ),
        located(
            K::UntrustedKey,
            live.clone(),
            3,
            8,
            format!("key {OTHER_KEY_HEX} bounded through seq 4"),
        ),
        unlocated(K::UncoveredTail, None, "records seq 7..=8".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "A7");
    drop(d);
}

// =====================================================================
// A7b - REGRESSION. Second layout for the pin half (ruling 13-V7-d1
// point 8): the pin alone inside a confirmed resume gap whose
// opening is anchored. The pin's hash check is replaced by
// `LostRecord`, and a bounded-key checkpoint ABOVE the bound in the
// live file still fires `UntrustedKey`. Pairs with A7 to pin the
// bounded-check-still-runs rule across two shapes (A7 with both an
// anchor and a pin; A7b with the pin alone). Hand-built for the
// same reason as A7.
// =====================================================================
#[test]
fn a7b_pin_alone_in_anchored_gap_still_fires_untrusted_key_above_bound() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let opening = signed_cp(OPENING_SEQ, cp2.hash(), &mmr2);
    let resume = resume_decl(&opening, 2, cp2.hash(), GAP_HIGH);
    let mmr_after_resume = pushed(&pushed(&mmr2, &opening), &resume);
    let bounded_cp = sign_as(&other_signer(), 8, TRAIL, resume.hash(), &mmr_after_resume);
    std::fs::write(
        d.0.join("audit.jsonl"),
        [opening.clone(), resume.clone(), bounded_cp.clone()]
            .iter()
            .flat_map(line_bytes)
            .collect::<Vec<u8>>(),
    )
    .unwrap();
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .key_through(other_signer().public_key(), 4, WRONG_HASH_55)
        .build()
        .unwrap();
    let opening_cp = parse_cp(&opening);
    let verifier = Verifier::new(trust)
        .anchor(opening_cp)
        .receipts([(1, e1.hash()), (RESUME_SEQ, resume.hash())]);
    let report = report_of(vec![d.0.clone()], verifier);
    let live = d.0.join("audit.jsonl");
    let expected = vec![
        lost_pin(4, OTHER_KEY_HEX, GAP_LOW, GAP_HIGH),
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
            K::UntrustedKey,
            live.clone(),
            3,
            8,
            format!("key {OTHER_KEY_HEX} bounded through seq 4"),
        ),
        unlocated(K::UncoveredTail, None, "records seq 7..=8".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "A7b");
    drop(d);
}

// =====================================================================
// A8 - REGRESSION. Ruling 13-V7-d1 point 7 ("Order"): an input
// below an accepted start follows the start rule first, even when
// its `seq` is also inside a confirmed resume gap whose opening is
// anchored. Below-start / above-end runs through
// `Classifier::set_aside` before the gap-set-aside path, so an
// anchored start demotes the in-gap anchor to `OutOfRange` (info),
// not `LostRecord`. Uses the writer-built genesis fixture so the
// `start_from(opening)` acceptance rule holds (the opening is the
// first record of the verified set).
// =====================================================================
#[test]
fn a8_start_at_opening_below_start_wins_over_gap() {
    let g = genesis_fixture(GAP_HIGH);
    let live = g.dir.join("audit.jsonl");
    let live_text = std::fs::read_to_string(&live).unwrap();
    let opening_cp = Checkpoint::parse(live_text.lines().next().unwrap()).unwrap();
    // The anchor in the gap targets a hash that does not match any
    // record at `seq 4` (there is no record there, so the ordinary
    // rule would say `no record`). With the start accepted at seq 6,
    // the anchor is `OutOfRange` through `Classifier::set_aside`
    // before the gap-demotion path runs.
    let mut synth = Mmr::new();
    synth.push([0xcc; 32]).unwrap();
    let anchor_record = {
        // Parent is irrelevant for the anchor rule's set-aside
        // branch; the record only needs to carry valid `(trail,
        // seq, hash)`.
        let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
        let mmr0 = seeded(&cp0);
        let e1 = entry_rec(1, cp0.hash());
        let mmr1 = pushed(&mmr0, &e1);
        let cp2 = signed_cp(2, e1.hash(), &mmr1);
        anchor_record_seq_4(cp2.hash())
    };
    let anchor_in_gap = parse_cp(&anchor_record);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .anchor(opening_cp.clone())
        .start_from(opening_cp)
        .anchor(anchor_in_gap)
        .receipts([(RESUME_SEQ, g.resume_hash)]);
    let report = report_of(vec![g.dir.clone()], verifier);
    let expected = vec![
        unlocated(
            K::OutOfRange,
            Some(4),
            format!("anchor seq 4 hash {ANCHOR_SEQ_4_DIGEST}: below start seq 6"),
        ),
        located(
            K::Resumed,
            live,
            2,
            RESUME_SEQ,
            resumed_detail(0, TRAIL_GENESIS_DIGEST, "0..=5", 0),
        ),
    ];
    assert_findings(report.findings(), &expected, "A8");
}
