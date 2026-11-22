//! Rows for an `accept Resumed` line confirming a resume gap
//! (ADR-0005 decision 5 and decision 11 "Review file"; ruling
//! 13-V7-d1 points 7-9 and 13-V8-d1). Every row ends in one
//! whole-list [`assert_findings`]; the honest-crash row pins the
//! `--strict` outcome in one `assert_eq!` tuple with its finding
//! list. Every deterministic hash in an expected detail is a
//! written-out hex `const` pinned by [`fixture_hashes_match_literals`];
//! opening and resume record hashes come from the writer's returns
//! and vary per run.
//!
//! Fixture style: writer-built resumes (`AuditConfig::resume` on a
//! pre-seeded `audit.trail`), as in `review_tests.rs` and
//! `gap_anchors_tests.rs`. Hand-built records are used for the
//! two-resumes row (two writer-built `AuditConfig::resume` calls
//! cannot chain on one directory), for the stolen-key cut's honest
//! anchors above head (the attacker's trail never records them), and
//! for the untrusted-opening rows (the writer always signs with the
//! trusted fixture key).

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
        seeded, segment_path, signed_cp, write_bytes,
    },
    verify::{Finding, Verifier},
};
use std::{path::PathBuf, sync::Arc};

// =====================================================================
// Shared literals. The non-genesis sealed prefix `[cp0, e1, cp2]` on
// `TRAIL` (fixture clock `100+seq`) pins cp0, e1 and cp2's hashes;
// opening and resume hashes vary per run and are read from the
// writer's returns. `TRAIL_GENESIS_DIGEST` is `Record::genesis(&TRAIL)`
// for the genesis `Resumed` detail.
// =====================================================================
const CP0_DIGEST: &str = "blake3:fc26c6f2bb830592aaaca5413da1599489d86ac6e240a4a7a010681e0d4c8e77";
const E1_DIGEST: &str = "blake3:c121282b5135adfe7a17142cae6bfc4c9040c4aed26d74bddc923b8dafcdb6e8";
const CP2_DIGEST: &str = "blake3:4164966a12a675e55eb6e133b9e50313907f164fe142d941447defcdfdb25d06";
const TRAIL_GENESIS_DIGEST: &str =
    "blake3:a03c7c40313d5ab5cf449ba187545083161360e5ed3e41e6f9254c3b4c5efaab";

const WRONG_HASH_11: [u8; 32] = [0x11; 32];
const WRONG_HASH_11_DIGEST: &str =
    "blake3:1111111111111111111111111111111111111111111111111111111111111111";
const WRONG_HASH_22: [u8; 32] = [0x22; 32];
const WRONG_HASH_22_DIGEST: &str =
    "blake3:2222222222222222222222222222222222222222222222222222222222222222";
const WRONG_HASH_55: [u8; 32] = [0x55; 32];
const WRONG_HASH_55_DIGEST: &str =
    "blake3:5555555555555555555555555555555555555555555555555555555555555555";
const WRONG_HASH_88: [u8; 32] = [0x88; 32];
const WRONG_HASH_88_DIGEST: &str =
    "blake3:8888888888888888888888888888888888888888888888888888888888888888";

/// Public key of the seed-`0x44` signer that no trust policy in this
/// file lists. A checkpoint signed by it is `UntrustedKey` at verify
/// time, which the untrusted-opening rows read into the expected
/// `UntrustedKey` detail text.
const UNTRUSTED_KEY_HEX: &str = "d759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48";

const GAP_LOW: u64 = 3;
const GAP_HIGH: u64 = 5;
const OPENING_SEQ: u64 = 6;
const RESUME_SEQ: u64 = 7;

// =====================================================================
// Shared helpers and fixtures.
// =====================================================================
fn signer() -> Arc<dyn Signer> {
    Arc::new(KeyFileSigner::from_hex(&"27".repeat(32)).unwrap())
}
fn pre_seed(dir: &std::path::Path) {
    write_bytes(
        &dir.join("audit.trail"),
        format!("{}\n", hex(&TRAIL)).as_bytes(),
    );
}
fn verifier() -> Verifier {
    Verifier::new(trust_with_key(fixture_pubkey()))
}
fn resumed_detail(head_seq: u64, head_hash: &str, gap: &str, n: u64) -> String {
    format!(
        "operator=op reason=r head={head_seq}:{head_hash} gap={gap} \
         lost_records={n} structural=valid"
    )
}
fn accepted_resume(file: PathBuf, line: u64, seq: u64, was_detail: String) -> Finding {
    Finding::new(
        K::Accepted,
        Some(file),
        Some(line),
        Some(seq),
        format!("accepted by alice: ok; was: {was_detail}"),
    )
    .with_accepted_kind(K::Resumed)
}
fn lost_accept(seq: u64, kind: &str, hash_digest: &str, low: u64, high: u64) -> Finding {
    unlocated(
        K::LostRecord,
        Some(seq),
        format!("accept {kind} seq {seq} hash {hash_digest}: lost in gap {low}..={high}"),
    )
}

/// Signer with seed `0x44` whose public key is [`UNTRUSTED_KEY_HEX`].
/// Consumed by the untrusted-opening rows (hand-built because the
/// writer always signs with the trusted fixture key).
fn untrusted_signer() -> KeyFileSigner {
    KeyFileSigner::from_hex(&"44".repeat(32)).unwrap()
}

/// Hand-builds a signed checkpoint record at `seq` on [`TRAIL`] with
/// the given `previous` link and MMR fold, using the fixture clock
/// (`100 + seq`) so repeated runs produce the same hash. Used by the
/// untrusted-opening rows to produce an opening whose
/// `signatures::trusted` check fails.
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

/// Non-genesis layout: pre-seeded `audit.trail`, sealed segment 0
/// `[cp0, e1, cp2]`, and a writer-built live `[opening, resume]` cut
/// back to head=(2, cp2) with `lost_through=5`. Opening lands at
/// `seq 6`, resume at `seq 7`, and the resume gap is `3..=5`.
struct NonGenesis {
    _dir: Temp,
    dir: PathBuf,
    e1: Record,
    cp2: Record,
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
    let (trail_b, resume, _opening) = AuditConfig::new("svc")
        .dir(&d.0)
        .resume(signer(), (2, cp2.hash()), GAP_HIGH, "op", "r")
        .unwrap();
    drop(trail_b);
    NonGenesis {
        dir: d.0.clone(),
        _dir: d,
        e1,
        cp2,
        resume_hash: resume.hash(),
    }
}

/// Genesis layout: pre-seeded `audit.trail` only, writer-built
/// `[opening, resume]` cut from `head=(0, genesis)` with the given
/// `lost_through`. The genesis gap is `0..=lost_through`.
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

/// Builds hand-signed trusted checkpoints at seqs 3, 4 and 5 above
/// `cp2` on `TRAIL` (previous links and MMR folds advance one step
/// per seq). The stolen-key row uses these to anchor the honest
/// chain a cut operator would have observed before an attacker
/// rewrote the trail.
fn honest_chain_cp(cp2: &Record, mmr_before_cp2: &Mmr) -> (Record, Record, Record) {
    let mmr2 = pushed(mmr_before_cp2, cp2);
    let cp3 = signed_cp(3, cp2.hash(), &mmr2);
    let mmr3 = pushed(&mmr2, &cp3);
    let cp4 = signed_cp(4, cp3.hash(), &mmr3);
    let mmr4 = pushed(&mmr3, &cp4);
    let cp5 = signed_cp(5, cp4.hash(), &mmr4);
    (cp3, cp4, cp5)
}

// =====================================================================
// Pinned-literals consistency test. Re-derives every `const` from
// the fixture builders so a drift in the clock or the segment
// layout flips the pin instead of silently miscomparing.
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
    assert_eq!(digest_string(&WRONG_HASH_11), WRONG_HASH_11_DIGEST, "0x11");
    assert_eq!(digest_string(&WRONG_HASH_22), WRONG_HASH_22_DIGEST, "0x22");
    assert_eq!(digest_string(&WRONG_HASH_55), WRONG_HASH_55_DIGEST, "0x55");
    assert_eq!(digest_string(&WRONG_HASH_88), WRONG_HASH_88_DIGEST, "0x88");
    assert_eq!(
        hex(&untrusted_signer().public_key()),
        UNTRUSTED_KEY_HEX,
        "untrusted_key"
    );
}

// =====================================================================
// (ADR-0005 decision 5 and decision 11 l.986 honest-crash case): a
// matched, in-range `accept Resumed` confirms the resume gap. The
// in-prefix receipt at seq 1 matches `e1`; the waiver at the resume
// `seq` matches the resume record and emits one `ReceiptWaived` at
// its line; the waiver and the `accept` line inside the gap each
// become one unlocated `LostRecord`, both counted by the gap's
// `lost_records=2` in the `Resumed` detail that the promoted
// `Accepted` finding's `was:` tail carries; `--strict` passes so a
// `close()` after the resume is clean. The strict outcome is
// pinned in one `assert_eq!` tuple with the finding list.
// =====================================================================
#[test]
fn accept_resumed_confirms_gap_waiver_and_accept_inside_become_lost_record() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let resume_digest = digest_string(&fx.resume_hash);
    let v = verifier()
        .receipts([(1, fx.e1.hash())])
        .waive(RESUME_SEQ, fx.resume_hash, "orphan request id=42")
        .unwrap()
        .waive(4, WRONG_HASH_55, "orphan request id=43")
        .unwrap()
        .accept(K::ClockWentBackwards, GAP_LOW, WRONG_HASH_22, "alice", "l3")
        .unwrap()
        .accept(K::Resumed, RESUME_SEQ, fx.resume_hash, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        lost_accept(
            GAP_LOW,
            "ClockWentBackwards",
            WRONG_HASH_22_DIGEST,
            GAP_LOW,
            GAP_HIGH,
        ),
        unlocated(
            K::LostRecord,
            Some(4),
            format!("waive seq 4 hash {WRONG_HASH_55_DIGEST}: lost in gap 3..=5"),
        ),
        accepted_resume(
            live.clone(),
            2,
            RESUME_SEQ,
            resumed_detail(2, CP2_DIGEST, "3..=5", 2),
        ),
        located(
            K::ReceiptWaived,
            live,
            2,
            RESUME_SEQ,
            format!("waived seq {RESUME_SEQ} hash {resume_digest}: orphan request id=42"),
        ),
    ];
    assert_eq!(
        (report.findings().to_vec(), report.is_strict_valid()),
        (expected, true),
        "accept-resumed-honest literal (findings, is_strict_valid)",
    );
}

// =====================================================================
// (ADR-0005 decision 11 l.986): the companion scenario without the
// `accept Resumed` line. The gap stays unconfirmed, so a waiver
// and an `accept` line inside the gap keep `ReceiptMismatch "no
// record"` and `AcceptMismatch "no record"`; `--strict` fails.
// =====================================================================
#[test]
fn no_accept_resumed_waiver_and_accept_inside_gap_keep_mismatch_strict_fails() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let resume_digest = digest_string(&fx.resume_hash);
    let v = verifier()
        .receipts([(1, fx.e1.hash())])
        .waive(GAP_LOW, WRONG_HASH_11, "l3")
        .unwrap()
        .accept(K::ClockWentBackwards, 4, WRONG_HASH_22, "alice", "l4")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        unlocated(
            K::ReceiptMismatch,
            Some(GAP_LOW),
            format!("waive seq {GAP_LOW} hash {WRONG_HASH_11_DIGEST}: no record"),
        ),
        unlocated(
            K::AcceptMismatch,
            Some(4),
            format!("accept ClockWentBackwards seq 4 hash {WRONG_HASH_22_DIGEST}: no record"),
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
    assert_findings(report.findings(), &expected, "no-accept-resumed");
    assert!(
        !report.is_strict_valid(),
        "strict fails without confirmation"
    );
}

// =====================================================================
// (ADR-0005 decision 11 l.990 anchored-opening half): a confirmed
// gap whose opening checkpoint is itself anchored demotes an
// anchor and a `through=` pin inside the gap to `LostRecord`
// (info), counted alongside the accept-line `LostRecord` in the
// gap's `lost_records=<n>` on the promoted `Accepted` finding's
// `was:` tail.
// =====================================================================
#[test]
fn accept_resumed_anchored_opening_demotes_anchor_pin_and_accept_inside_gap() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let other_key = KeyFileSigner::from_hex(&"77".repeat(32)).unwrap();
    let other_key_hex = hex(&other_key.public_key());
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .key_through(other_key.public_key(), 4, WRONG_HASH_55)
        .build()
        .unwrap();
    // Synthetic anchor record at seq 4: trusted-signed, `(trail, seq,
    // hash)` is not the opening's. The MMR fold of one leaf satisfies
    // the checkpoint invariant.
    let mut anchor_mmr = Mmr::new();
    anchor_mmr.push([0xcc; 32]).unwrap();
    let anchor_record = signed_cp(4, fx.cp2.hash(), &anchor_mmr);
    let anchor_digest = digest_string(&anchor_record.hash());
    let live_text = std::fs::read_to_string(&live).unwrap();
    let opening_cp = Checkpoint::parse(live_text.lines().next().unwrap()).unwrap();
    let v = Verifier::new(trust)
        .anchor(opening_cp)
        .anchor(parse_cp(&anchor_record))
        .accept(K::ClockWentBackwards, GAP_LOW, WRONG_HASH_22, "alice", "l3")
        .unwrap()
        .accept(K::Resumed, RESUME_SEQ, fx.resume_hash, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        lost_accept(
            GAP_LOW,
            "ClockWentBackwards",
            WRONG_HASH_22_DIGEST,
            GAP_LOW,
            GAP_HIGH,
        ),
        unlocated(
            K::LostRecord,
            Some(4),
            format!("key {other_key_hex} through=4: lost in gap 3..=5"),
        ),
        unlocated(
            K::LostRecord,
            Some(4),
            format!("anchor seq 4 hash {anchor_digest}: lost in gap 3..=5"),
        ),
        accepted_resume(
            live,
            2,
            RESUME_SEQ,
            resumed_detail(2, CP2_DIGEST, "3..=5", 3),
        ),
    ];
    assert_findings(report.findings(), &expected, "accept-resumed-anchored");
}

// =====================================================================
// (ADR-0005 decision 11 l.990 unanchored-opening half): a
// confirmed gap whose opening is NOT anchored keeps an anchor
// inside the gap as `AnchorMismatch` and a `through=` pin as
// `RevocationMismatch`; only the accept line inside the gap is
// demoted to `LostRecord`, so `lost_records=1`.
// =====================================================================
#[test]
fn accept_resumed_unanchored_opening_keeps_anchor_and_pin_mismatch() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let other_key = KeyFileSigner::from_hex(&"77".repeat(32)).unwrap();
    let other_key_hex = hex(&other_key.public_key());
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .key_through(other_key.public_key(), 4, WRONG_HASH_55)
        .build()
        .unwrap();
    let mut anchor_mmr = Mmr::new();
    anchor_mmr.push([0xcc; 32]).unwrap();
    let anchor_record = signed_cp(4, fx.cp2.hash(), &anchor_mmr);
    let anchor_digest = digest_string(&anchor_record.hash());
    let v = Verifier::new(trust)
        .anchor(parse_cp(&anchor_record))
        .accept(K::ClockWentBackwards, GAP_LOW, WRONG_HASH_22, "alice", "l3")
        .unwrap()
        .accept(K::Resumed, RESUME_SEQ, fx.resume_hash, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        lost_accept(
            GAP_LOW,
            "ClockWentBackwards",
            WRONG_HASH_22_DIGEST,
            GAP_LOW,
            GAP_HIGH,
        ),
        unlocated(
            K::AnchorMismatch,
            Some(4),
            format!("anchor seq 4 hash {anchor_digest}: no record"),
        ),
        unlocated(
            K::RevocationMismatch,
            Some(4),
            format!("key {other_key_hex} through=4:{WRONG_HASH_55_DIGEST}: no record at seq 4"),
        ),
        accepted_resume(
            live,
            2,
            RESUME_SEQ,
            resumed_detail(2, CP2_DIGEST, "3..=5", 1),
        ),
    ];
    assert_findings(report.findings(), &expected, "accept-resumed-unanchored");
}

// =====================================================================
// (ADR-0005 decision 11 l.990 stolen-key case): a cut operator
// would have anchored each honest checkpoint at seqs 3, 4 and 5
// above head=(2, cp2) before an attacker rewrote the trail. An
// `accept Resumed` line pinned to the attacker's resume confirms
// the gap but does NOT anchor the attacker's opening (a text line
// is not an anchor), so every honest-chain anchor inside the gap
// stays `AnchorMismatch` and the report is invalid.
// =====================================================================
#[test]
fn accept_resumed_stolen_key_cut_anchors_stay_anchor_mismatch_report_invalid() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let mmr_before_cp2 = {
        let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
        pushed(&seeded(&cp0), &fx.e1)
    };
    let (cp3, cp4, cp5) = honest_chain_cp(&fx.cp2, &mmr_before_cp2);
    let cp3_digest = digest_string(&cp3.hash());
    let cp4_digest = digest_string(&cp4.hash());
    let cp5_digest = digest_string(&cp5.hash());
    let v = verifier()
        .anchor(parse_cp(&cp3))
        .anchor(parse_cp(&cp4))
        .anchor(parse_cp(&cp5))
        .accept(K::Resumed, RESUME_SEQ, fx.resume_hash, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        unlocated(
            K::AnchorMismatch,
            Some(3),
            format!("anchor seq 3 hash {cp3_digest}: no record"),
        ),
        unlocated(
            K::AnchorMismatch,
            Some(4),
            format!("anchor seq 4 hash {cp4_digest}: no record"),
        ),
        unlocated(
            K::AnchorMismatch,
            Some(5),
            format!("anchor seq 5 hash {cp5_digest}: no record"),
        ),
        accepted_resume(
            live,
            2,
            RESUME_SEQ,
            resumed_detail(2, CP2_DIGEST, "3..=5", 0),
        ),
    ];
    assert_findings(report.findings(), &expected, "accept-resumed-stolen-key");
    assert!(!report.is_valid(), "stolen-key report must be invalid");
}

// =====================================================================
// (ADR-0005 decision 5 "Resume gaps" genesis case; ruling
// 13-V7-d1 point 7): a genesis resume confirmed only by an
// `accept Resumed` line has its `SeqGap 0..=<L>` suppressed, and
// an `accept` line inside the gap becomes one `LostRecord`.
// =====================================================================
#[test]
fn genesis_resume_accept_resumed_confirms_and_suppresses_seq_gap() {
    let g = genesis_fixture(GAP_HIGH);
    let live = g.dir.join("audit.jsonl");
    let v = verifier()
        .accept(K::ClockWentBackwards, 2, WRONG_HASH_22, "alice", "l2")
        .unwrap()
        .accept(K::Resumed, RESUME_SEQ, g.resume_hash, "alice", "ok")
        .unwrap();
    let report = report_of(vec![g.dir.clone()], v);
    let expected = vec![
        unlocated(
            K::LostRecord,
            Some(2),
            format!(
                "accept ClockWentBackwards seq 2 hash {WRONG_HASH_22_DIGEST}: lost in gap 0..=5"
            ),
        ),
        accepted_resume(
            live,
            2,
            RESUME_SEQ,
            resumed_detail(0, TRAIL_GENESIS_DIGEST, "0..=5", 1),
        ),
    ];
    assert_findings(report.findings(), &expected, "accept-resumed-genesis");
}

// =====================================================================
// (ADR-0005 decision 5 "Resume gaps" genesis case): a second
// genesis layout with a shorter `lost_through=2` gap (`0..=2`,
// opening at `seq 3`, resume at `seq 4`): the `accept Resumed`
// line confirms the gap and the `SeqGap 0..=2` is suppressed.
// Pairs with the longer genesis row on the genesis-exception half.
// =====================================================================
#[test]
fn genesis_resume_accept_resumed_short_gap_confirms_and_suppresses_seq_gap() {
    let g = genesis_fixture(2);
    let live = g.dir.join("audit.jsonl");
    let v = verifier()
        .accept(K::Resumed, 4, g.resume_hash, "alice", "ok")
        .unwrap();
    let report = report_of(vec![g.dir.clone()], v);
    let expected = vec![accepted_resume(
        live,
        2,
        4,
        resumed_detail(0, TRAIL_GENESIS_DIGEST, "0..=2", 0),
    )];
    assert_findings(report.findings(), &expected, "accept-resumed-genesis-short");
}

// =====================================================================
// (ADR-0005 decision 11 "set-aside"): a second above-end layout
// for the "set-aside confirms nothing" rule, pairing a waiver
// inside the gap with a set-aside `accept Resumed`. The waiver
// stays `ReceiptMismatch "no record"` because the gap is not
// confirmed; pairs with the accept-line-inside-gap row on the
// receipt / accept split.
// =====================================================================
#[test]
fn set_aside_accept_resumed_above_end_leaves_waiver_in_gap_as_receipt_mismatch() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let opening_line = {
        let text = std::fs::read_to_string(&live).unwrap();
        text.lines().next().unwrap().to_owned()
    };
    let opening_cp = Checkpoint::parse(&opening_line).unwrap();
    let resume_digest = digest_string(&fx.resume_hash);
    let v = verifier()
        .end_before(&opening_line, Some(opening_cp))
        .unwrap()
        .receipts([(1, fx.e1.hash())])
        .waive(4, WRONG_HASH_55, "l4")
        .unwrap()
        .accept(K::Resumed, RESUME_SEQ, fx.resume_hash, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        unlocated(
            K::ReceiptMismatch,
            Some(4),
            format!("waive seq 4 hash {WRONG_HASH_55_DIGEST}: no record"),
        ),
        located(
            K::TrailEnded,
            live.clone(),
            1,
            OPENING_SEQ,
            format!("end_before seq {OPENING_SEQ}: records seq 6..=8 at or above the end"),
        ),
        unlocated(
            K::OutOfRange,
            Some(RESUME_SEQ),
            format!(
                "accept Resumed seq {RESUME_SEQ} hash {resume_digest}: \
                 above end seq {OPENING_SEQ}"
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
    assert_findings(report.findings(), &expected, "set-aside-above-end-waiver");
}

// =====================================================================
// (ADR-0005 decision 11 l.993 two-resumes case): two resumes on
// one trail, each confirmed by its own `accept Resumed` line, and
// each gap's accept-line input becomes one `LostRecord` counted in
// its own gap's `lost_records=<n>`. Hand-built so both sealed
// segments have deterministic names (the writer's second
// `AuditConfig::resume` rotates `audit.jsonl` under a timestamped
// name).
// =====================================================================
#[test]
fn two_resumes_each_confirmed_by_own_accept_resumed_inputs_become_lost_record() {
    let d = Temp::new();
    pre_seed(&d.0);
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    // First resume cuts head=(2, cp2) with `lost_through=5`;
    // opening lands at `seq 6` and resume at `seq 7`. Add a drop
    // checkpoint at `seq 8` so the second resume can declare it as
    // head.
    let mmr2 = pushed(&mmr1, &cp2);
    let opening1 = signed_cp(6, cp2.hash(), &mmr2);
    let resume1 = resume_decl(&opening1, 2, cp2.hash(), GAP_HIGH);
    let mmr_after_resume1 = pushed(&pushed(&mmr2, &opening1), &resume1);
    let drop1 = signed_cp(8, resume1.hash(), &mmr_after_resume1);
    put_segment(&d.0, 1, &[&opening1, &resume1, &drop1], &[]);
    // Second resume cuts head=(8, drop1) with `lost_through=11`;
    // opening at `seq 12`, resume at `seq 13`.
    const GAP2_LOW: u64 = 9;
    const GAP2_HIGH: u64 = 11;
    const OPENING2_SEQ: u64 = 12;
    const RESUME2_SEQ: u64 = 13;
    let mmr_after_drop1 = pushed(&mmr_after_resume1, &drop1);
    let opening2 = signed_cp(OPENING2_SEQ, drop1.hash(), &mmr_after_drop1);
    let resume2 = resume_decl(&opening2, 8, drop1.hash(), GAP2_HIGH);
    let live = d.0.join("audit.jsonl");
    write_bytes(
        &live,
        &[&opening2, &resume2]
            .iter()
            .flat_map(|r| line_bytes(r))
            .collect::<Vec<u8>>(),
    );
    let drop1_digest = digest_string(&drop1.hash());
    let v = verifier()
        .accept(K::ClockWentBackwards, GAP_LOW, WRONG_HASH_22, "alice", "l3")
        .unwrap()
        .accept(
            K::DuplicateRecord,
            GAP2_LOW + 1,
            WRONG_HASH_88,
            "alice",
            "l10",
        )
        .unwrap()
        .accept(K::Resumed, RESUME_SEQ, resume1.hash(), "alice", "ok")
        .unwrap()
        .accept(K::Resumed, RESUME2_SEQ, resume2.hash(), "alice", "ok")
        .unwrap();
    let report = report_of(vec![d.0.clone()], v);
    let seg1 = segment_path(&d.0, 1);
    let resumed1_detail = format!(
        "operator=operator reason=incident head=2:{CP2_DIGEST} gap=3..=5 lost_records=1 structural=valid"
    );
    let resumed2_detail = format!(
        "operator=operator reason=incident head=8:{drop1_digest} \
         gap={GAP2_LOW}..={GAP2_HIGH} lost_records=1 structural=valid"
    );
    let expected = vec![
        lost_accept(
            GAP_LOW,
            "ClockWentBackwards",
            WRONG_HASH_22_DIGEST,
            GAP_LOW,
            GAP_HIGH,
        ),
        Finding::new(
            K::Accepted,
            Some(seg1),
            Some(2),
            Some(RESUME_SEQ),
            format!("accepted by alice: ok; was: {resumed1_detail}"),
        )
        .with_accepted_kind(K::Resumed),
        unlocated(
            K::LostRecord,
            Some(GAP2_LOW + 1),
            format!(
                "accept DuplicateRecord seq {} hash {WRONG_HASH_88_DIGEST}: lost in gap {GAP2_LOW}..={GAP2_HIGH}",
                GAP2_LOW + 1
            ),
        ),
        accepted_resume(live, 2, RESUME2_SEQ, resumed2_detail),
        unlocated(
            K::UncoveredTail,
            None,
            format!("records seq {RESUME2_SEQ}..={RESUME2_SEQ}"),
        ),
    ];
    assert_findings(report.findings(), &expected, "two-resumes");
    drop(d);
}

// =====================================================================
// (ADR-0005 decision 11 "Only a matched, in-range `accept Resumed`
// line confirms"): a mismatched `accept Resumed` whose hash differs
// from the resume record is `AcceptMismatch "hash differs"` and
// confirms nothing, so an `accept` line inside the gap stays
// `AcceptMismatch "no record"` and the `Resumed` warning stays.
// =====================================================================
#[test]
fn mismatched_accept_resumed_wrong_hash_does_not_confirm_gap() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let resume_digest = digest_string(&fx.resume_hash);
    let v = verifier()
        .accept(K::ClockWentBackwards, GAP_LOW, WRONG_HASH_22, "alice", "l3")
        .unwrap()
        .accept(K::Resumed, RESUME_SEQ, WRONG_HASH_11, "alice", "wrong")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        unlocated(
            K::AcceptMismatch,
            Some(GAP_LOW),
            format!(
                "accept ClockWentBackwards seq {GAP_LOW} hash {WRONG_HASH_22_DIGEST}: no record"
            ),
        ),
        unlocated(
            K::AcceptMismatch,
            Some(RESUME_SEQ),
            format!(
                "accept Resumed seq {RESUME_SEQ} hash {WRONG_HASH_11_DIGEST}: \
                 hash differs (record {resume_digest})"
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
    assert_findings(report.findings(), &expected, "mismatched-wrong-hash");
}

// =====================================================================
// (ADR-0005 decision 11): a mismatched `accept Resumed` at a
// genesis resume keeps the genesis `SeqGap 0..=<L>` because
// confirmation is required for its suppression, even at the
// genesis candidate. Pairs with the non-genesis mismatched row on
// the "wrong hash confirms nothing" rule.
// =====================================================================
#[test]
fn mismatched_accept_resumed_at_genesis_keeps_seq_gap() {
    let g = genesis_fixture(GAP_HIGH);
    let live = g.dir.join("audit.jsonl");
    let resume_digest = digest_string(&g.resume_hash);
    let v = verifier()
        .accept(K::Resumed, RESUME_SEQ, WRONG_HASH_11, "alice", "wrong")
        .unwrap();
    let report = report_of(vec![g.dir.clone()], v);
    // Sort key is `(seq_is_none, seq, file, line, kind)`: SeqGap at
    // seq 6 precedes the AcceptMismatch at seq 7, which has no file
    // and so sorts before the Resumed finding at the same seq.
    let expected = vec![
        located(
            K::SeqGap,
            live.clone(),
            1,
            OPENING_SEQ,
            "missing seq 0..=5".to_owned(),
        ),
        unlocated(
            K::AcceptMismatch,
            Some(RESUME_SEQ),
            format!(
                "accept Resumed seq {RESUME_SEQ} hash {WRONG_HASH_11_DIGEST}: \
                 hash differs (record {resume_digest})"
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
    assert_findings(report.findings(), &expected, "mismatched-genesis");
}

// =====================================================================
// (ADR-0005 decision 11 "set-aside"): an `accept Resumed` whose
// `seq` sits strictly above the end record's last line's `seq`
// under an anchored `end_before` is set aside through the shared
// position classifier as `OutOfRange` (info) and confirms nothing.
// The resume candidate gap `3..=5` is below the end `E = 6` (pinned
// to the writer's opening), so an `accept` line at `seq 4` inside
// the gap is in range and the row asserts it keeps
// `AcceptMismatch "no record"` because the set-aside line does
// not confirm the gap.
// =====================================================================
#[test]
fn set_aside_accept_resumed_above_end_does_not_confirm_gap() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let opening_line = {
        let text = std::fs::read_to_string(&live).unwrap();
        text.lines().next().unwrap().to_owned()
    };
    let opening_cp = Checkpoint::parse(&opening_line).unwrap();
    let v = verifier()
        .end_before(&opening_line, Some(opening_cp))
        .unwrap()
        .accept(K::ClockWentBackwards, 4, WRONG_HASH_22, "alice", "l4")
        .unwrap()
        .accept(K::Resumed, RESUME_SEQ, fx.resume_hash, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let resume_digest = digest_string(&fx.resume_hash);
    let expected = vec![
        unlocated(
            K::AcceptMismatch,
            Some(4),
            format!("accept ClockWentBackwards seq 4 hash {WRONG_HASH_22_DIGEST}: no record"),
        ),
        located(
            K::TrailEnded,
            live.clone(),
            1,
            OPENING_SEQ,
            format!("end_before seq {OPENING_SEQ}: records seq 6..=8 at or above the end"),
        ),
        unlocated(
            K::OutOfRange,
            Some(RESUME_SEQ),
            format!(
                "accept Resumed seq {RESUME_SEQ} hash {resume_digest}: \
                 above end seq {OPENING_SEQ}"
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
    assert_findings(report.findings(), &expected, "set-aside-above-end");
}

// =====================================================================
// (ADR-0005 decision 11 "Review file", `accept` kind filter): only an
// `accept Resumed` line confirms a resume gap. An `accept` of
// another kind pinned to the resume record's exact (seq, hash)
// matches the record under the shared receipt rule but has no
// warning of its kind at that `seq` to promote, so it emits one
// `AcceptUnused` and confirms nothing. The in-gap accept keeps its
// `AcceptMismatch "no record"` and the `Resumed` warning stays with
// `lost_records=0`.
// =====================================================================
#[test]
fn non_resumed_accept_at_resume_record_gives_accept_unused_without_confirming() {
    let fx = non_genesis();
    let live = fx.dir.join("audit.jsonl");
    let resume_digest = digest_string(&fx.resume_hash);
    let v = verifier()
        .accept(K::ClockWentBackwards, GAP_LOW, WRONG_HASH_22, "alice", "l3")
        .unwrap()
        .accept(
            K::ClockWentBackwards,
            RESUME_SEQ,
            fx.resume_hash,
            "alice",
            "wrong-kind",
        )
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        unlocated(
            K::AcceptMismatch,
            Some(GAP_LOW),
            format!(
                "accept ClockWentBackwards seq {GAP_LOW} hash {WRONG_HASH_22_DIGEST}: no record"
            ),
        ),
        unlocated(
            K::AcceptUnused,
            Some(RESUME_SEQ),
            format!(
                "accept ClockWentBackwards seq {RESUME_SEQ} hash {resume_digest}: \
                 no matching warning"
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
    assert_findings(report.findings(), &expected, "non-resumed-accept-at-resume");
}

// =====================================================================
// (ADR-0005 decision 11 "Review file", `accept` kind filter,
// genesis case): a second layout for the "only Resumed confirms"
// rule, pairing a genesis resume with a `DuplicateRecord` accept at
// the resume record's (seq, hash). The non-Resumed accept emits
// `AcceptUnused` and confirms nothing, so the genesis
// `SeqGap 0..=5` stays at the opening's line and the in-gap accept
// at seq 2 keeps `AcceptMismatch "no record"`.
// =====================================================================
#[test]
fn non_resumed_accept_at_genesis_resume_record_gives_accept_unused_without_confirming() {
    let g = genesis_fixture(GAP_HIGH);
    let live = g.dir.join("audit.jsonl");
    let resume_digest = digest_string(&g.resume_hash);
    let v = verifier()
        .accept(K::DuplicateRecord, 2, WRONG_HASH_22, "alice", "l2")
        .unwrap()
        .accept(
            K::DuplicateRecord,
            RESUME_SEQ,
            g.resume_hash,
            "alice",
            "wrong-kind",
        )
        .unwrap();
    let report = report_of(vec![g.dir.clone()], v);
    let expected = vec![
        unlocated(
            K::AcceptMismatch,
            Some(2),
            format!("accept DuplicateRecord seq 2 hash {WRONG_HASH_22_DIGEST}: no record"),
        ),
        located(
            K::SeqGap,
            live.clone(),
            1,
            OPENING_SEQ,
            "missing seq 0..=5".to_owned(),
        ),
        unlocated(
            K::AcceptUnused,
            Some(RESUME_SEQ),
            format!(
                "accept DuplicateRecord seq {RESUME_SEQ} hash {resume_digest}: \
                 no matching warning"
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
    assert_findings(
        report.findings(),
        &expected,
        "non-resumed-accept-at-genesis-resume",
    );
}

// =====================================================================
// (ADR-0005 decision 11 "Review file", untrusted-opening gate): a
// resume candidate whose opening checkpoint is signed by a key not
// listed in the trust policy is dropped by `build_gaps`, so an
// `accept Resumed` line pinned to its resume record does not
// confirm the gap. The `SeqGap` for the missing seqs stays, the
// `UntrustedKey` finding at the opening stays, and the in-gap
// accept keeps `AcceptMismatch "no record"`. The `accept Resumed`
// still matches the record under the shared receipt rule and
// promotes the `Resumed` warning to `Accepted`, whose `was:` tail
// carries `lost_records=0`. Hand-built because the writer always
// signs with the trusted fixture key.
// =====================================================================
#[test]
fn untrusted_opening_accept_resumed_does_not_confirm_keeps_seq_gap_and_accept_mismatch() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let opening = sign_as(&untrusted_signer(), OPENING_SEQ, cp2.hash(), &mmr2);
    let resume = resume_decl(&opening, 2, cp2.hash(), GAP_HIGH);
    let resume_hash = resume.hash();
    write_bytes(
        &d.0.join("audit.jsonl"),
        &[&opening, &resume]
            .iter()
            .flat_map(|r| line_bytes(r))
            .collect::<Vec<u8>>(),
    );
    let live = d.0.join("audit.jsonl");
    let v = verifier()
        .accept(K::ClockWentBackwards, GAP_LOW, WRONG_HASH_22, "alice", "l3")
        .unwrap()
        .accept(K::Resumed, RESUME_SEQ, resume_hash, "alice", "ok")
        .unwrap();
    let report = report_of(vec![d.0.clone()], v);
    let expected = vec![
        unlocated(
            K::AcceptMismatch,
            Some(GAP_LOW),
            format!(
                "accept ClockWentBackwards seq {GAP_LOW} hash {WRONG_HASH_22_DIGEST}: no record"
            ),
        ),
        located(
            K::SeqGap,
            live.clone(),
            1,
            OPENING_SEQ,
            "missing seq 3..=5".to_owned(),
        ),
        located(
            K::UntrustedKey,
            live.clone(),
            1,
            OPENING_SEQ,
            format!(
                "key {UNTRUSTED_KEY_HEX} not listed for trail {}",
                hex(&TRAIL)
            ),
        ),
        accepted_resume(
            live,
            2,
            RESUME_SEQ,
            format!(
                "operator=operator reason=incident head=2:{CP2_DIGEST} \
                 gap=3..=5 lost_records=0 structural=valid"
            ),
        ),
        unlocated(K::UncoveredTail, None, "records seq 3..=7".to_owned()),
    ];
    assert_findings(
        report.findings(),
        &expected,
        "untrusted-opening-accept-resumed",
    );
    drop(d);
}

// =====================================================================
// (ADR-0005 decision 11 "Review file", untrusted-opening gate,
// genesis case): the untrusted-opening gate applies at a genesis
// resume too. An opening at seq 1 signed by a key not listed in the
// trust policy, with a resume at seq 2 naming `head=(0, genesis)`,
// is dropped by `build_gaps`; an `accept Resumed` pinned to its
// resume record does not confirm the gap, so the genesis
// `SeqGap 0..=0` stays and the in-gap accept at seq 0 keeps its
// `AcceptMismatch "no record"`. Pairs with the non-genesis
// untrusted-opening row on the "untrusted opening is not kept"
// rule. Hand-built for the same reason.
// =====================================================================
#[test]
fn untrusted_genesis_opening_accept_resumed_does_not_confirm_keeps_seq_gap() {
    let d = Temp::new();
    pre_seed(&d.0);
    // Genesis-resume MMR shape: no prior records, so the opening's
    // fold includes the trail's genesis digest (see `Sink::resume`).
    let mut mmr = Mmr::new();
    mmr.push(Record::genesis(&TRAIL)).unwrap();
    let opening = sign_as(&untrusted_signer(), 1, Record::genesis(&TRAIL), &mmr);
    let resume = resume_decl(&opening, 0, Record::genesis(&TRAIL), 0);
    let resume_hash = resume.hash();
    write_bytes(
        &d.0.join("audit.jsonl"),
        &[&opening, &resume]
            .iter()
            .flat_map(|r| line_bytes(r))
            .collect::<Vec<u8>>(),
    );
    let live = d.0.join("audit.jsonl");
    let v = verifier()
        .accept(K::ClockWentBackwards, 0, WRONG_HASH_22, "alice", "l0")
        .unwrap()
        .accept(K::Resumed, 2, resume_hash, "alice", "ok")
        .unwrap();
    let report = report_of(vec![d.0.clone()], v);
    let expected = vec![
        unlocated(
            K::AcceptMismatch,
            Some(0),
            format!("accept ClockWentBackwards seq 0 hash {WRONG_HASH_22_DIGEST}: no record"),
        ),
        located(
            K::SeqGap,
            live.clone(),
            1,
            1,
            "missing seq 0..=0".to_owned(),
        ),
        located(
            K::UntrustedKey,
            live.clone(),
            1,
            1,
            format!(
                "key {UNTRUSTED_KEY_HEX} not listed for trail {}",
                hex(&TRAIL)
            ),
        ),
        accepted_resume(
            live,
            2,
            2,
            format!(
                "operator=operator reason=incident head=0:{TRAIL_GENESIS_DIGEST} \
                 gap=0..=0 lost_records=0 structural=valid"
            ),
        ),
        unlocated(K::UncoveredTail, None, "records seq 1..=2".to_owned()),
    ];
    assert_findings(
        report.findings(),
        &expected,
        "untrusted-genesis-opening-accept-resumed",
    );
    drop(d);
}
