//! Rows for the verifier's start acceptance check (ADR-0005
//! decision 11 `.start_from`; ruling 13-V6-d2).
//!
//! Row standard (repo-wide): every acceptance row asserts the full
//! sorted literal finding list, compared as whole [`Finding`] values
//! through [`assert_findings`] (a thin wrapper around `assert_eq!` on
//! `Vec<Finding>`); every digest and key in an expected detail is a
//! written-out hex constant pinned by
//! [`fixture_hashes_match_literals`]. Each row is labelled
//! ACCEPTANCE or REGRESSION in its doc comment.

use crate::audit::{
    Checkpoint, Entry, FindingKind as K, KeyFileSigner, Mmr, Record, RecordContext, Signer,
    TrustPolicy, digest_string,
    format::CheckpointFields,
    hex,
    runs_v4a_fixtures::{
        TRAIL, Temp, entry_rec, fixture_pubkey, line_bytes, pushed, put_segment, seeded,
        segment_path, signed_cp, signed_cp_explicit, write_bytes, write_records,
    },
    verify::{Finding, Report, Verifier},
};
use std::path::PathBuf;

// =====================================================================
// Shared literal hex constants.
// =====================================================================

const OTHER_TRAIL: [u8; 16] = [0x01; 16];
const OTHER_TRAIL_HEX: &str = "01010101010101010101010101010101";
const FIXTURE_KEY_HEX: &str = "ee45ecb9aca01a0abd83ef56dd985c8c874e6e7f4aebcedf20bd8d88c2a0add7";
const ALT_KEY_HEX: &str = "c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242";
const TRAIL_HEX: &str = "11111111111111111111111111111111";

/// The shared fixture `signed_cp(0, genesis(TRAIL), &Mmr::new())`.
const CP0_HONEST_DIGEST: &str =
    "blake3:fc26c6f2bb830592aaaca5413da1599489d86ac6e240a4a7a010681e0d4c8e77";
/// The shared fixture `entry_rec(1, cp0.hash())`.
const E1_HONEST_DIGEST: &str =
    "blake3:c121282b5135adfe7a17142cae6bfc4c9040c4aed26d74bddc923b8dafcdb6e8";
/// The shared fixture `signed_cp(2, e1.hash(), &mmr1)`.
const CP2_HONEST_DIGEST: &str =
    "blake3:4164966a12a675e55eb6e133b9e50313907f164fe142d941447defcdfdb25d06";
/// `signed_cp_explicit(2, e1.hash(), 2, [0x5a; 32], vec![[0x22; 32]])`,
/// shared with the anchors module.
const SYNTH_CP2_DIGEST: &str =
    "blake3:a4145e2e1465ae13c3afccdf696b8354b0a8620d167615d4ea72cbab57a5cf56";
/// `signed_cp_other(0, Record::genesis(&OTHER_TRAIL), &Mmr::new())` on `OTHER_TRAIL`.
const CP0_OTHER_DIGEST: &str =
    "blake3:b57a644cf07f1180908b840976740bf6624c17aab435a2d9f6b4e9b77aa177c0";
/// `signed_cp_other(2, [0xaa; 32], &foreign_mmr_one())` on `OTHER_TRAIL`.
const CP2_OTHER_DIGEST: &str =
    "blake3:301689fd93fc2ff30bc03a1f775f6f1590dd0f4cd92f2e50847003c4ebd5e87b";
/// `signed_cp_other(3, [0xaa; 32], &foreign_mmr_one())` on `OTHER_TRAIL`.
const CP3_OTHER_DIGEST: &str =
    "blake3:9c77bb62a57fed3f28d22014354c4fccc0b35051f1c1d4579c9624709eb9d97d";
/// `signed_cp_other(5, [0xaa; 32], &foreign_mmr_one())` on `OTHER_TRAIL`.
const CP5_OTHER_DIGEST: &str =
    "blake3:5642c84c7cb858d1acc2b0bb8ea45adda145d419d63ff35810b507212afcfbc0";
/// `signed_cp(3, cp2.hash(), &mmr2)` chained from the honest `cp2`.
const CP3_FROM_CP2_DIGEST: &str =
    "blake3:dfbf4e5a7173125e6d43847fa1c1b05420adc1c09022566ebbb292b72cf0203c";
/// `signed_cp(4, e3.hash(), &mmr3)` chained through `[cp0, e1, cp2, e3]`.
const CP4_FROM_E3_DIGEST: &str =
    "blake3:3800e98faa1a668c094936a2489dd8d0c1db9ed5dd3c337dd1de87e030b784cd";
/// `signed_cp(6, e5.hash(), &mmr5)` chained through `[cp0..cp4, e5]`.
const CP6_FROM_E5_DIGEST: &str =
    "blake3:85f86bd031d34d32b96c4d3c18aca8611cbcd59a488ca05dab0acec33a81d510";
/// `signed_cp_explicit(3, cp2.hash(), 1, [0x33; 32], vec![[0x55; 32]])`
/// — a synthetic start for B5b.
const SYNTH_CP3_DIGEST: &str =
    "blake3:ec4b9033352cdb098e5cfc809deeac07a142d5f5847e338e32c702508605c6d8";
/// `cp2` signed by the alt key `0x55` (`sign_as(alt, 2, e1.hash, &mmr1)`).
const CP2_UNLISTED_DIGEST: &str =
    "blake3:8f71deebb1a2b11df8703bc9210730f478d3f5f0688e042b9469a5bf4eaaba33";
/// Honest `cp2` with one bit of its signature flipped
/// (`flip_signature_byte`). Shared by the signature-flip rows for the
/// start's hash and for the rewritten record on the trail.
const CP2_FLIPPED_DIGEST: &str =
    "blake3:6cd338542f05123f02d86b51c67a880924320e64ef06f9fc1c7aed0ae7c5925d";
/// `signed_cp_explicit(0, genesis(TRAIL), 0, [0xaa; 32], vec![])`, shared
/// with the anchors module.
const CP0_TWIN_DIGEST: &str =
    "blake3:1c2090cbf40864380a0bf92e4dc439c77146d8020e46fe172da7098a6b3077a7";
/// `signed_cp_explicit(2, e1.hash(), 2, [0xde; 32], vec![[0x22; 32]])`,
/// shared with the anchors module.
const CP2_TWIN_DIGEST: &str =
    "blake3:aee5a47d9814a55594371fa3bb0bd34a48531533983898590ef72f511d42f45c";

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

fn parse_start(record: &Record) -> Checkpoint {
    let mut bytes = line_bytes(record);
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    Checkpoint::parse(std::str::from_utf8(&bytes).unwrap()).unwrap()
}

fn trust_with_key(key: [u8; 32]) -> TrustPolicy {
    TrustPolicy::builder()
        .trail(TRAIL)
        .key(key)
        .build()
        .unwrap()
}

fn trust_with_bound(key: [u8; 32], through: u64, through_hash: [u8; 32]) -> TrustPolicy {
    TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(key, through, through_hash)
        .build()
        .unwrap()
}

fn report_of(files: Vec<PathBuf>, verifier: Verifier) -> Report {
    verifier.verify_files(files).unwrap()
}

/// A one-leaf MMR used by the B7 and B10 foreign-trail starts (every
/// foreign checkpoint at `seq >= 1` needs `size >= 1`, ADR-0005
/// decision 7, so these rows build a stable one-leaf state).
fn foreign_mmr_one() -> Mmr {
    let mut m = Mmr::new();
    m.push([0xaa; 32]).unwrap();
    m
}

/// A checkpoint signed on `OTHER_TRAIL` by the shared fixture key.
fn signed_cp_other(seq: u64, previous: [u8; 32], mmr: &Mmr) -> Record {
    let key = KeyFileSigner::from_hex(&"27".repeat(32)).unwrap();
    let ctx = RecordContext::new(OTHER_TRAIL, seq, 100 + seq, "test", previous);
    let fields = |sig| {
        CheckpointFields::new(
            mmr.size(),
            mmr.root(),
            mmr.peaks().to_vec(),
            key.public_key(),
            sig,
        )
        .unwrap()
    };
    let unsigned = Record::checkpoint(ctx.clone(), fields([0; 64])).unwrap();
    let signature = key.sign(&unsigned.signing_message().unwrap()).unwrap();
    Record::checkpoint(ctx, fields(signature)).unwrap()
}

/// A checkpoint at `(seq, previous, mmr)` on `TRAIL`, signed by an
/// explicit key. Used by the B6 unlisted-key row.
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

/// Clones a signed checkpoint while rewriting its signature; this
/// changes the record's canonical hash.
fn with_signature(signed: &Record, sig: [u8; 64]) -> Record {
    let cp = match &signed.kind {
        crate::audit::format::Kind::Checkpoint(cp) => cp,
        _ => panic!("checkpoint record expected"),
    };
    let fields = CheckpointFields::new(cp.size, cp.root, cp.peaks.clone(), cp.key, sig).unwrap();
    Record::checkpoint(signed.context.clone(), fields).unwrap()
}

fn flip_signature_byte(signed: &Record) -> Record {
    let sig = match &signed.kind {
        crate::audit::format::Kind::Checkpoint(cp) => cp.signature(),
        _ => panic!("checkpoint record expected"),
    };
    let mut flipped = *sig;
    flipped[0] ^= 0x01;
    with_signature(signed, flipped)
}

fn alt_signer() -> KeyFileSigner {
    KeyFileSigner::from_hex(&"55".repeat(32)).unwrap()
}

/// Honest `[cp0, e1, cp2]` on `TRAIL`. `cp0`, `e1` and `cp2` records
/// are returned for anchors and start values.
struct Honest {
    cp0: Record,
    e1: Record,
    cp2: Record,
    mmr1: Mmr,
    mmr2: Mmr,
}
fn honest() -> Honest {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    Honest {
        cp0,
        e1,
        cp2,
        mmr1,
        mmr2,
    }
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

// =====================================================================
// B1 — ACCEPTANCE. The live directory begins at the opening
// checkpoint of a kept segment, and the start is that checkpoint ->
// no finding. Pairs with the existing engine row
// `missing_prefix_does_not_hide_later_forgery`, which pins the same
// layout without a start. First failing line on base: the
// `assert_findings` call below.
// =====================================================================
#[test]
fn b1_accepted_start_suppresses_prefix_seqgap() {
    let fx = honest();
    let seg = seal(&[&fx.cp2]);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).start_from(parse_start(&fx.cp2));
    let report = report_of(vec![seg.path], verifier);
    assert_findings(report.findings(), &[], "B1");
}

// =====================================================================
// B1b — ACCEPTANCE. Shipped-only `cp2` as the first record. Pairs
// with B1 to pin that the "first record" is the lowest `seq` across
// native AND shipped copies. First failing line on base: the
// `assert_findings` call below.
// =====================================================================
#[test]
fn b1b_accepted_start_with_shipped_only_first_record() {
    let fx = honest();
    let d = Temp::new();
    let shipped = d.0.join("cp2.shipped");
    write_bytes(&shipped, &line_bytes(&fx.cp2));
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).start_from(parse_start(&fx.cp2));
    let report = report_of(vec![shipped], verifier);
    assert_findings(report.findings(), &[], "B1b");
}

// =====================================================================
// B1c — ACCEPTANCE. The lowest `seq` record is only in a shipped
// copy, but a later native segment carries a higher-`seq` record;
// the start matches the shipped-only record. Pairs with B1b to pin
// that the "first record" merge includes shipped copies. First
// failing line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn b1c_shipped_first_record_native_above_accepts() {
    let fx = honest();
    let mmr3 = pushed(&fx.mmr2, &entry_rec(3, fx.cp2.hash()));
    let cp4 = signed_cp(4, entry_rec(3, fx.cp2.hash()).hash(), &mmr3);
    let d = Temp::new();
    put_segment(&d.0, 0, &[&cp4], &[]);
    let native_path = segment_path(&d.0, 0);
    let shipped = d.0.join("cp2.shipped");
    write_bytes(&shipped, &line_bytes(&fx.cp2));
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).start_from(parse_start(&fx.cp2));
    let report = report_of(vec![native_path.clone(), shipped], verifier);
    // No prefix `SeqGap` for 0..=1 (start accepted). The `SeqGap` at
    // cp4 for the missing seq=3 is a non-prefix gap and still fires.
    let expected = vec![located(
        K::SeqGap,
        native_path,
        1,
        4,
        "missing seq 3..=3".into(),
    )];
    assert_findings(report.findings(), &expected, "B1c");
}

// =====================================================================
// B2 — ACCEPTANCE. `hash differs`: the start has the right `seq` but
// another hash (a synthetic checkpoint with the same `seq` as the
// first record). First failing-line on base is the `StartMismatch`
// detail equality.
// =====================================================================
#[test]
fn b2_start_hash_differs_at_first_record() {
    let fx = honest();
    let seg = seal(&[&fx.cp2]);
    let synth = signed_cp_explicit(2, fx.e1.hash(), 2, [0x5a; 32], vec![[0x22; 32]]);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).start_from(parse_start(&synth));
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![
        located(
            K::SeqGap,
            seg.path.clone(),
            1,
            2,
            "missing seq 0..=1".into(),
        ),
        located(
            K::StartMismatch,
            seg.path,
            1,
            2,
            format!(
                "start seq 2 hash {SYNTH_CP2_DIGEST}: hash differs (record {CP2_HONEST_DIGEST})"
            ),
        ),
    ];
    assert_findings(report.findings(), &expected, "B2");
}

// =====================================================================
// B2b — ACCEPTANCE. Second `hash differs` row. The first record is
// the honest `cp2` with its signature byte flipped (so its canonical
// hash shifts), and the start is the honest `cp2`. Pairs with B2 so
// the hash check and the prefix `SeqGap` suppression on failure are
// pinned on two independent rows.
// =====================================================================
#[test]
fn b2b_rewritten_record_hash_differs_from_honest_start() {
    let fx = honest();
    let rewritten = flip_signature_byte(&fx.cp2);
    let seg = seal(&[&rewritten]);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).start_from(parse_start(&fx.cp2));
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![
        located(
            K::BadSignature,
            seg.path.clone(),
            1,
            2,
            format!("key {FIXTURE_KEY_HEX}"),
        ),
        located(
            K::SeqGap,
            seg.path.clone(),
            1,
            2,
            "missing seq 0..=1".into(),
        ),
        located(
            K::StartMismatch,
            seg.path,
            1,
            2,
            format!(
                "start seq 2 hash {CP2_HONEST_DIGEST}: hash differs (record {CP2_FLIPPED_DIGEST})"
            ),
        ),
        uncovered(2, 2),
    ];
    assert_findings(report.findings(), &expected, "B2b");
}

// =====================================================================
// B3 — ACCEPTANCE. Full trail from `seq 0` with the start at a later
// checkpoint. The first record is `cp0`, not the start's `seq 2`;
// "not the first record (first seq 0)" wins over "hash differs"
// (which would otherwise fire at `cp0`).
// =====================================================================
#[test]
fn b3_full_trail_start_above_first_record() {
    let fx = honest();
    let seg = seal(&[&fx.cp0, &fx.e1, &fx.cp2]);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).start_from(parse_start(&fx.cp2));
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![located(
        K::StartMismatch,
        seg.path,
        1,
        2,
        format!("start seq 2 hash {CP2_HONEST_DIGEST}: not the first record (first seq 0)"),
    )];
    assert_findings(report.findings(), &expected, "B3");
}

// =====================================================================
// B3b — ACCEPTANCE. A second `not the first record` layout: the
// start is present at `s`, records below `s` exist, and the first
// record is not `seq 0`. An older kept segment opens at `cp2` and
// continues with `[e3, cp4]`; the start names `cp4`. First failing
// line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn b3b_start_present_at_s_records_below_first_not_zero() {
    let fx = honest();
    let e3 = entry_rec(3, fx.cp2.hash());
    let mmr3 = pushed(&fx.mmr2, &e3);
    let cp4 = signed_cp(4, e3.hash(), &mmr3);
    let seg = seal(&[&fx.cp2, &e3, &cp4]);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).start_from(parse_start(&cp4));
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![
        located(
            K::SeqGap,
            seg.path.clone(),
            1,
            2,
            "missing seq 0..=1".into(),
        ),
        located(
            K::StartMismatch,
            seg.path,
            1,
            4,
            format!("start seq 4 hash {CP4_FROM_E3_DIGEST}: not the first record (first seq 2)"),
        ),
    ];
    assert_findings(report.findings(), &expected, "B3b");
}

// =====================================================================
// B4 — ACCEPTANCE. "Kept segments deleted up to a later opening
// checkpoint": the first record is at a seq strictly above the
// start's. Every checkpoint of the original trail is passed as an
// anchor, so the anchors below the start keep their current
// `AnchorMismatch … no record` findings (ruling 13-V6-d2 point 6).
// Expected: `StartMismatch (first seq <f>)` plus the prefix `SeqGap`
// plus `AnchorMismatch` for every checkpoint absent from the live
// set.
// =====================================================================
#[test]
fn b4_kept_segment_deleted_leaves_first_record_above_start() {
    let fx = honest();
    let e3 = entry_rec(3, fx.cp2.hash());
    let mmr3 = pushed(&fx.mmr2, &e3);
    let cp4 = signed_cp(4, e3.hash(), &mmr3);
    let seg = seal(&[&cp4]);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .anchor(parse_start(&fx.cp0))
        .anchor(parse_start(&fx.cp2))
        .anchor(parse_start(&cp4))
        .start_from(parse_start(&fx.cp2));
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![
        unlocated(
            K::AnchorMismatch,
            Some(0),
            format!("anchor seq 0 hash {CP0_HONEST_DIGEST}: no record"),
        ),
        unlocated(
            K::AnchorMismatch,
            Some(2),
            format!("anchor seq 2 hash {CP2_HONEST_DIGEST}: no record"),
        ),
        located(
            K::StartMismatch,
            seg.path.clone(),
            1,
            2,
            format!("start seq 2 hash {CP2_HONEST_DIGEST}: not the first record (first seq 4)"),
        ),
        located(K::SeqGap, seg.path, 1, 4, "missing seq 0..=3".into()),
    ];
    assert_findings(report.findings(), &expected, "B4");
}

// =====================================================================
// B5 — ACCEPTANCE. `not a checkpoint`: the first record at the
// start's seq is an `audit.record` entry, not a checkpoint.
// =====================================================================
#[test]
fn b5_first_record_at_start_seq_is_an_entry() {
    let fx = honest();
    let synth = signed_cp_explicit(1, fx.cp0.hash(), 1, [0x77; 32], vec![[0x55; 32]]);
    let seg = seal(&[&fx.e1]);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).start_from(parse_start(&synth));
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![
        located(
            K::SegmentStructure,
            seg.path.clone(),
            1,
            1,
            "expected first complete record to be a checkpoint".into(),
        ),
        located(
            K::SeqGap,
            seg.path.clone(),
            1,
            1,
            "missing seq 0..=0".into(),
        ),
        located(
            K::StartMismatch,
            seg.path,
            1,
            1,
            format!("start seq 1 hash {SYNTH_CP1_DIGEST}: not a checkpoint"),
        ),
        uncovered(1, 1),
    ];
    assert_findings(report.findings(), &expected, "B5");
}

/// `signed_cp_explicit(1, cp0.hash(), 1, [0x77; 32], vec![[0x55; 32]])`,
/// shared with the anchors module.
const SYNTH_CP1_DIGEST: &str =
    "blake3:6f29546e36b4f2e5563838f6a53d324832a27d0fb89ea9768459a028992bf915";

// =====================================================================
// B5b — ACCEPTANCE. Second `not a checkpoint` row at a different
// `seq`. Pairs with B5 so the "not a checkpoint" step is pinned on
// two independent rows.
// =====================================================================
#[test]
fn b5b_first_record_at_start_seq_is_a_distinct_entry() {
    let fx = honest();
    let e3 = entry_rec(3, fx.cp2.hash());
    let synth = signed_cp_explicit(3, fx.cp2.hash(), 1, [0x33; 32], vec![[0x55; 32]]);
    let seg = seal(&[&e3]);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).start_from(parse_start(&synth));
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![
        located(
            K::SegmentStructure,
            seg.path.clone(),
            1,
            3,
            "expected first complete record to be a checkpoint".into(),
        ),
        located(
            K::SeqGap,
            seg.path.clone(),
            1,
            3,
            "missing seq 0..=2".into(),
        ),
        located(
            K::StartMismatch,
            seg.path,
            1,
            3,
            format!("start seq 3 hash {SYNTH_CP3_DIGEST}: not a checkpoint"),
        ),
        uncovered(3, 3),
    ];
    assert_findings(report.findings(), &expected, "B5b");
}

// =====================================================================
// B6 — ACCEPTANCE. `not trusted at its seq`: the start and the
// first record are the same checkpoint, signed by an unlisted key.
// The record's own `UntrustedKey` is independent of the start check.
// =====================================================================
#[test]
fn b6_start_signed_by_unlisted_key_not_trusted() {
    let fx = honest();
    let cp2_alt = sign_as(&alt_signer(), 2, fx.e1.hash(), &fx.mmr1);
    let seg = seal(&[&cp2_alt]);
    let verifier =
        Verifier::new(trust_with_key(fixture_pubkey())).start_from(parse_start(&cp2_alt));
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![
        located(
            K::SeqGap,
            seg.path.clone(),
            1,
            2,
            "missing seq 0..=1".into(),
        ),
        located(
            K::StartMismatch,
            seg.path.clone(),
            1,
            2,
            format!("start seq 2 hash {CP2_UNLISTED_DIGEST}: not trusted at its seq"),
        ),
        located(
            K::UntrustedKey,
            seg.path,
            1,
            2,
            format!("key {ALT_KEY_HEX} not listed for trail {TRAIL_HEX}"),
        ),
        uncovered(2, 2),
    ];
    assert_findings(report.findings(), &expected, "B6");
}

// =====================================================================
// B6b — ACCEPTANCE. `not trusted at its seq` through a bad
// signature: the start carries the listed fixture key but with its
// signature byte flipped. The record's own `BadSignature` is
// independent.
// =====================================================================
#[test]
fn b6b_start_bad_signature_not_trusted() {
    let fx = honest();
    let cp2_bad = flip_signature_byte(&fx.cp2);
    let seg = seal(&[&cp2_bad]);
    let verifier =
        Verifier::new(trust_with_key(fixture_pubkey())).start_from(parse_start(&cp2_bad));
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![
        located(
            K::BadSignature,
            seg.path.clone(),
            1,
            2,
            format!("key {FIXTURE_KEY_HEX}"),
        ),
        located(
            K::SeqGap,
            seg.path.clone(),
            1,
            2,
            "missing seq 0..=1".into(),
        ),
        located(
            K::StartMismatch,
            seg.path,
            1,
            2,
            format!("start seq 2 hash {CP2_FLIPPED_DIGEST}: not trusted at its seq"),
        ),
        uncovered(2, 2),
    ];
    assert_findings(report.findings(), &expected, "B6b");
}

// =====================================================================
// B6c — ACCEPTANCE. `not trusted at its seq` through a `through=`
// bound: the start is signed by a listed key at a `seq` above that
// key's bound, after a rotation whose confirmation (`cp3` by alt) is
// above the bound. The bound's pin record was archived, so the pin
// fires `RevocationMismatch` at seq 0; the confirmation keeps
// `RevocationUnconfirmed` silent. First failing line on base: the
// `assert_findings` call below.
// =====================================================================
#[test]
fn b6c_start_signed_by_bounded_key_above_its_bound() {
    let fx = honest();
    let cp3_alt = sign_as(&alt_signer(), 3, fx.cp2.hash(), &fx.mmr2);
    let seg = seal(&[&fx.cp2, &cp3_alt]);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, fx.cp0.hash())
        .key(alt_signer().public_key())
        .build()
        .unwrap();
    let verifier = Verifier::new(trust).start_from(parse_start(&fx.cp2));
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![
        unlocated(
            K::RevocationMismatch,
            Some(0),
            format!("key {FIXTURE_KEY_HEX} through=0:{CP0_HONEST_DIGEST}: no record at seq 0"),
        ),
        located(
            K::SeqGap,
            seg.path.clone(),
            1,
            2,
            "missing seq 0..=1".into(),
        ),
        located(
            K::StartMismatch,
            seg.path.clone(),
            1,
            2,
            format!("start seq 2 hash {CP2_HONEST_DIGEST}: not trusted at its seq"),
        ),
        located(
            K::UntrustedKey,
            seg.path,
            1,
            2,
            format!("key {FIXTURE_KEY_HEX} bounded through seq 0"),
        ),
    ];
    assert_findings(report.findings(), &expected, "B6c");
}

// =====================================================================
// B7 — ACCEPTANCE. `trail differs`: the start comes from another
// trail, at the same `seq` as the verified trail's first record.
// `trail differs` wins over any later step.
// =====================================================================
#[test]
fn b7_start_from_other_trail_same_seq() {
    let fx = honest();
    let seg = seal(&[&fx.cp2]);
    let foreign = signed_cp_other(2, [0xaa; 32], &foreign_mmr_one());
    let verifier =
        Verifier::new(trust_with_key(fixture_pubkey())).start_from(parse_start(&foreign));
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![
        located(
            K::SeqGap,
            seg.path.clone(),
            1,
            2,
            "missing seq 0..=1".into(),
        ),
        located(
            K::StartMismatch,
            seg.path,
            1,
            2,
            format!("start seq 2 hash {CP2_OTHER_DIGEST}: trail differs"),
        ),
    ];
    assert_findings(report.findings(), &expected, "B7");
}

// =====================================================================
// B8 — ACCEPTANCE. `seq is forked`: two different records at `s`,
// one matching the start (native and shipped copy). A forked `seq`
// is never matched (fail-closed, same rule as the anchor check,
// ruling 13-V6-d1 point 2).
// =====================================================================
#[test]
fn b8_forked_seq_never_accepts_even_with_match() {
    let fx = honest();
    let twin = signed_cp_explicit(2, fx.e1.hash(), 2, [0xde; 32], vec![[0x22; 32]]);
    let seg = seal(&[&fx.cp2]);
    let twin_path = seg._dir.0.join("cp2.twin");
    write_bytes(&twin_path, &line_bytes(&twin));
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).start_from(parse_start(&fx.cp2));
    let report = report_of(vec![seg.path.clone(), twin_path], verifier);
    let expected = vec![
        located(
            K::SeqConflict,
            seg.path.clone(),
            1,
            2,
            format!("conflicting hashes: {CP2_HONEST_DIGEST}, {CP2_TWIN_DIGEST}"),
        ),
        located(
            K::SeqGap,
            seg.path.clone(),
            1,
            2,
            "missing seq 0..=1".into(),
        ),
        located(
            K::StartMismatch,
            seg.path,
            1,
            2,
            format!("start seq 2 hash {CP2_HONEST_DIGEST}: seq is forked"),
        ),
    ];
    assert_findings(report.findings(), &expected, "B8");
}

// =====================================================================
// B8b — ACCEPTANCE. Second forked-`seq` row at `seq=0`. Pairs with
// B8 so the forked-`seq` precedence (never match a forked `seq`) is
// pinned on two independent `seq`s.
// =====================================================================
#[test]
fn b8b_forked_seq_zero_never_accepts_even_with_match() {
    let d = Temp::new();
    let honest_cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    put_segment(&d.0, 0, &[&honest_cp0], &[]);
    let native = segment_path(&d.0, 0);
    let twin = signed_cp_explicit(0, Record::genesis(&TRAIL), 0, [0xaa; 32], vec![]);
    let twin_path = d.0.join("cp0.twin");
    write_bytes(&twin_path, &line_bytes(&twin));
    let verifier =
        Verifier::new(trust_with_key(fixture_pubkey())).start_from(parse_start(&honest_cp0));
    let report = report_of(vec![native.clone(), twin_path], verifier);
    let expected = vec![
        located(
            K::SeqConflict,
            native.clone(),
            1,
            0,
            format!("conflicting hashes: {CP0_TWIN_DIGEST}, {CP0_HONEST_DIGEST}"),
        ),
        located(
            K::StartMismatch,
            native,
            1,
            0,
            format!("start seq 0 hash {CP0_HONEST_DIGEST}: seq is forked"),
        ),
    ];
    assert_findings(report.findings(), &expected, "B8b");
}

// =====================================================================
// B9 — ACCEPTANCE. `no record`: an empty directory with a start.
// The finding has no location (ruling 13-V6-d2 point 3).
// =====================================================================
#[test]
fn b9_empty_directory_no_record() {
    let d = Temp::new();
    let fx = honest();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).start_from(parse_start(&fx.cp2));
    let report = verifier.verify_dir(&d.0).unwrap();
    let expected = vec![unlocated(
        K::StartMismatch,
        Some(2),
        format!("start seq 2 hash {CP2_HONEST_DIGEST}: no record"),
    )];
    assert_findings(report.findings(), &expected, "B9");
}

// =====================================================================
// B9b — ACCEPTANCE. `trail differs`: the start's trail differs from
// the verified trail, and the start's `seq` is absent from the
// verified set. The finding carries a location, the first copy of
// the first record on the verified trail (ruling 13-V6-d2 point 3).
// First failing line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn b9b_other_trail_start_seq_absent_locates_at_first_record() {
    let fx = honest();
    let seg = seal(&[&fx.cp0, &fx.e1, &fx.cp2]);
    let foreign = signed_cp_other(5, [0xaa; 32], &foreign_mmr_one());
    let verifier =
        Verifier::new(trust_with_key(fixture_pubkey())).start_from(parse_start(&foreign));
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![located(
        K::StartMismatch,
        seg.path,
        1,
        5,
        format!("start seq 5 hash {CP5_OTHER_DIGEST}: trail differs"),
    )];
    assert_findings(report.findings(), &expected, "B9b");
}

// =====================================================================
// B9c — ACCEPTANCE. `no record` with records from another trail
// present: the verified set is empty because every file carries a
// foreign-trail record, which `engine::check` filters out of the
// merged set and reports as `TrailMismatch`. The `no record` branch
// still fires with no location, since there is no record on the
// verified trail to locate against (ruling 13-V6-d2 point 3). First
// failing line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn b9c_foreign_trail_records_only_no_record_unlocated() {
    let fx = honest();
    let foreign = signed_cp_other(0, Record::genesis(&OTHER_TRAIL), &Mmr::new());
    let d = Temp::new();
    let shipped = d.0.join("foreign.shipped");
    write_bytes(&shipped, &line_bytes(&foreign));
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).start_from(parse_start(&fx.cp2));
    let report = report_of(vec![shipped.clone()], verifier);
    let expected = vec![
        located(
            K::TrailMismatch,
            shipped,
            1,
            0,
            format!("expected trail {TRAIL_HEX}, found {OTHER_TRAIL_HEX}"),
        ),
        unlocated(
            K::StartMismatch,
            Some(2),
            format!("start seq 2 hash {CP2_HONEST_DIGEST}: no record"),
        ),
    ];
    assert_findings(report.findings(), &expected, "B9c");
}

// =====================================================================
// B9d — ACCEPTANCE. Second `no record` row with foreign-trail records
// coming from a different source than B9c: here they live in a native
// segment file (B9c uses a shipped copy). The engine still filters
// every record out of the verified set as `TrailMismatch`, so the
// `no record` branch fires with no location (ruling 13-V6-d2 point 3).
// First failing line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn b9d_foreign_trail_native_segment_no_record_unlocated() {
    let fx = honest();
    let foreign = signed_cp_other(0, Record::genesis(&OTHER_TRAIL), &Mmr::new());
    let d = Temp::new();
    put_segment(&d.0, 0, &[&foreign], &[]);
    let seg = segment_path(&d.0, 0);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).start_from(parse_start(&fx.cp2));
    let report = report_of(vec![seg.clone()], verifier);
    let expected = vec![
        located(
            K::TrailMismatch,
            seg,
            1,
            0,
            format!("expected trail {TRAIL_HEX}, found {OTHER_TRAIL_HEX}"),
        ),
        unlocated(
            K::StartMismatch,
            Some(2),
            format!("start seq 2 hash {CP2_HONEST_DIGEST}: no record"),
        ),
    ];
    assert_findings(report.findings(), &expected, "B9d");
}

// =====================================================================
// B10 — ACCEPTANCE. Precedence: another trail AND not the first
// record. `trail differs` wins.
// =====================================================================
#[test]
fn b10_other_trail_above_first_record_still_trail_differs() {
    let fx = honest();
    let seg = seal(&[&fx.cp2]);
    let foreign = signed_cp_other(3, [0xaa; 32], &foreign_mmr_one());
    let verifier =
        Verifier::new(trust_with_key(fixture_pubkey())).start_from(parse_start(&foreign));
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![
        located(
            K::SeqGap,
            seg.path.clone(),
            1,
            2,
            "missing seq 0..=1".into(),
        ),
        located(
            K::StartMismatch,
            seg.path,
            1,
            3,
            format!("start seq 3 hash {CP3_OTHER_DIGEST}: trail differs"),
        ),
    ];
    assert_findings(report.findings(), &expected, "B10");
}

// =====================================================================
// B11 — ACCEPTANCE. Two `start_from` calls: the second one replaces
// the first (ruling 13-V6-d2 point 1). Wrong first, right second:
// accepted.
// =====================================================================
#[test]
fn b11_second_start_from_call_overrides_wrong_first() {
    let fx = honest();
    let seg = seal(&[&fx.cp2]);
    let wrong = signed_cp_explicit(2, fx.e1.hash(), 2, [0x5a; 32], vec![[0x22; 32]]);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .start_from(parse_start(&wrong))
        .start_from(parse_start(&fx.cp2));
    let report = report_of(vec![seg.path], verifier);
    assert_findings(report.findings(), &[], "B11 right-wins");
}

// =====================================================================
// B11b — ACCEPTANCE. Pairs with B11: right first, wrong second
// (rejected on the wrong one). Together they give ruling 13-V6-d2
// point 1 ("a second call replaces the first") two named kills.
// =====================================================================
#[test]
fn b11b_second_start_from_call_overrides_right_first() {
    let fx = honest();
    let seg = seal(&[&fx.cp2]);
    let wrong = signed_cp_explicit(2, fx.e1.hash(), 2, [0x5a; 32], vec![[0x22; 32]]);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .start_from(parse_start(&fx.cp2))
        .start_from(parse_start(&wrong));
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![
        located(
            K::SeqGap,
            seg.path.clone(),
            1,
            2,
            "missing seq 0..=1".into(),
        ),
        located(
            K::StartMismatch,
            seg.path,
            1,
            2,
            format!(
                "start seq 2 hash {SYNTH_CP2_DIGEST}: hash differs (record {CP2_HONEST_DIGEST})"
            ),
        ),
    ];
    assert_findings(report.findings(), &expected, "B11b wrong-wins");
}

// =====================================================================
// B12 — ACCEPTANCE. With an accepted start, a forged record later in
// the file is still reported. Pins "the chain, the fold, signatures,
// trust, coverage and revocation run as they do today from the first
// checkpoint" (ruling 13-V6-d2 point 5).
// =====================================================================
#[test]
fn b12_accepted_start_still_reports_forged_record_above() {
    let fx = honest();
    let e3_forged = Record::new_internal(
        RecordContext::new(TRAIL, 3, 103, "test", [0x99; 32]),
        Entry::new("actor", "change", "object"),
    )
    .unwrap();
    let seg = seal(&[&fx.cp2, &e3_forged]);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).start_from(parse_start(&fx.cp2));
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![
        located(
            K::ChainBroken,
            seg.path,
            2,
            3,
            format!(
                "expected previous {CP2_HONEST_DIGEST}, found blake3:{}",
                "99".repeat(32)
            ),
        ),
        uncovered(3, 3),
    ];
    assert_findings(report.findings(), &expected, "B12");
}

// =====================================================================
// B13 — ACCEPTANCE. Above an accepted start, the revocation rules
// still apply (ruling 13-V6-d2 point 5, "the revocation rules above
// the start still apply"). A bound with no confirming checkpoint
// above it is `RevocationUnconfirmed`; an old-key checkpoint above
// its bound is `UntrustedKey`.
// =====================================================================
#[test]
fn b13_revocation_rules_still_apply_above_accepted_start() {
    let fx = honest();
    let cp3 = signed_cp(3, fx.cp2.hash(), &fx.mmr2);
    let seg = seal(&[&fx.cp2, &cp3]);
    let trust = trust_with_bound(fixture_pubkey(), 2, fx.cp2.hash());
    let verifier = Verifier::new(trust).start_from(parse_start(&fx.cp2));
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![
        located(
            K::RevocationUnconfirmed,
            seg.path.clone(),
            1,
            2,
            format!(
                "key {FIXTURE_KEY_HEX} through=2: no trusted checkpoint by another key above the bound"
            ),
        ),
        located(
            K::UntrustedKey,
            seg.path,
            2,
            3,
            format!("key {FIXTURE_KEY_HEX} bounded through seq 2"),
        ),
        uncovered(3, 3),
    ];
    assert_findings(report.findings(), &expected, "B13");
}

// =====================================================================
// B14 — decision 2 step 6, batch 2 (ADR-0005 d11 bullet).
//   (a) `start_from(batch-start entry 1)` over archive 2 + live is
//       clean (ACCEPTANCE; first failing line on base: the (a)
//       `assert_findings` call).
//   (b) a segment deleted from archive 2 -> `SeqGap` (ACCEPTANCE).
//   (c) the first segment of archive 2 deleted -> `StartMismatch`
//       (ACCEPTANCE).
// =====================================================================
#[test]
fn b14_batch2_step6_clean_delete_segment_delete_first_segment() {
    let fx = honest();
    let e3 = entry_rec(3, fx.cp2.hash());
    let mmr3 = pushed(&fx.mmr2, &e3);
    let cp4 = signed_cp(4, e3.hash(), &mmr3);
    let mmr4 = pushed(&mmr3, &cp4);
    let e5 = entry_rec(5, cp4.hash());
    let mmr5 = pushed(&mmr4, &e5);
    let cp6 = signed_cp(6, e5.hash(), &mmr5);

    // (a) Clean: archive_2 = {segA=[cp2, e3], segB=[cp4, e5]}, live
    // = [cp6]. `start_from(cp2)` over them is clean.
    let d = Temp::new();
    put_segment(&d.0, 1, &[&fx.cp2, &e3], &[]);
    put_segment(&d.0, 2, &[&cp4, &e5], &[]);
    write_records(&d.0, &[&cp6]);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).start_from(parse_start(&fx.cp2));
    let report = verifier.verify_dir(&d.0).unwrap();
    assert_findings(report.findings(), &[], "B14 (a) clean");

    // (b) Delete segB from archive 2: segA + live remain.
    let d = Temp::new();
    put_segment(&d.0, 1, &[&fx.cp2, &e3], &[]);
    write_records(&d.0, &[&cp6]);
    let live = d.0.join("audit.jsonl");
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).start_from(parse_start(&fx.cp2));
    let report = verifier.verify_dir(&d.0).unwrap();
    let expected = vec![located(K::SeqGap, live, 1, 6, "missing seq 4..=5".into())];
    assert_findings(report.findings(), &expected, "B14 (b) segment deleted");

    // (c) Delete segA from archive 2 (the one holding the start):
    // segB + live remain. First record is cp4 (seq=4) != start.seq=2.
    let d = Temp::new();
    put_segment(&d.0, 2, &[&cp4, &e5], &[]);
    write_records(&d.0, &[&cp6]);
    let seg_b = segment_path(&d.0, 2);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).start_from(parse_start(&fx.cp2));
    let report = verifier.verify_dir(&d.0).unwrap();
    let expected = vec![
        located(
            K::StartMismatch,
            seg_b.clone(),
            1,
            2,
            format!("start seq 2 hash {CP2_HONEST_DIGEST}: not the first record (first seq 4)"),
        ),
        located(K::SeqGap, seg_b, 1, 4, "missing seq 0..=3".into()),
    ];
    assert_findings(
        report.findings(),
        &expected,
        "B14 (c) first segment deleted",
    );
}

// =====================================================================
// Pins every literal hex constant in this module to the fixture it
// names so a hash change anywhere in `runs_v4a_fixtures` or in the
// code under test never slips through the literal-row assertions.
// =====================================================================
#[test]
fn fixture_hashes_match_literals() {
    let fx = honest();
    assert_eq!(hex(&OTHER_TRAIL), OTHER_TRAIL_HEX);
    assert_eq!(hex(&TRAIL), TRAIL_HEX);
    assert_eq!(hex(&fixture_pubkey()), FIXTURE_KEY_HEX);
    assert_eq!(hex(&alt_signer().public_key()), ALT_KEY_HEX);
    assert_eq!(digest_string(&fx.cp0.hash()), CP0_HONEST_DIGEST);
    assert_eq!(digest_string(&fx.e1.hash()), E1_HONEST_DIGEST);
    assert_eq!(digest_string(&fx.cp2.hash()), CP2_HONEST_DIGEST);
    let synth = signed_cp_explicit(2, fx.e1.hash(), 2, [0x5a; 32], vec![[0x22; 32]]);
    assert_eq!(digest_string(&synth.hash()), SYNTH_CP2_DIGEST);
    let synth_cp1 = signed_cp_explicit(1, fx.cp0.hash(), 1, [0x77; 32], vec![[0x55; 32]]);
    assert_eq!(digest_string(&synth_cp1.hash()), SYNTH_CP1_DIGEST);
    let cp2_alt = sign_as(&alt_signer(), 2, fx.e1.hash(), &fx.mmr1);
    assert_eq!(digest_string(&cp2_alt.hash()), CP2_UNLISTED_DIGEST);
    let cp2_bad = flip_signature_byte(&fx.cp2);
    assert_eq!(digest_string(&cp2_bad.hash()), CP2_FLIPPED_DIGEST);
    let foreign0 = signed_cp_other(0, Record::genesis(&OTHER_TRAIL), &Mmr::new());
    assert_eq!(digest_string(&foreign0.hash()), CP0_OTHER_DIGEST);
    let foreign2 = signed_cp_other(2, [0xaa; 32], &foreign_mmr_one());
    assert_eq!(digest_string(&foreign2.hash()), CP2_OTHER_DIGEST);
    let foreign3 = signed_cp_other(3, [0xaa; 32], &foreign_mmr_one());
    assert_eq!(digest_string(&foreign3.hash()), CP3_OTHER_DIGEST);
    let foreign5 = signed_cp_other(5, [0xaa; 32], &foreign_mmr_one());
    assert_eq!(digest_string(&foreign5.hash()), CP5_OTHER_DIGEST);
    let cp3 = signed_cp(3, fx.cp2.hash(), &fx.mmr2);
    assert_eq!(digest_string(&cp3.hash()), CP3_FROM_CP2_DIGEST);
    let e3 = entry_rec(3, fx.cp2.hash());
    let mmr3 = pushed(&fx.mmr2, &e3);
    let cp4 = signed_cp(4, e3.hash(), &mmr3);
    assert_eq!(digest_string(&cp4.hash()), CP4_FROM_E3_DIGEST);
    let mmr4 = pushed(&mmr3, &cp4);
    let e5 = entry_rec(5, cp4.hash());
    let mmr5 = pushed(&mmr4, &e5);
    let cp6 = signed_cp(6, e5.hash(), &mmr5);
    assert_eq!(digest_string(&cp6.hash()), CP6_FROM_E5_DIGEST);
    let synth_cp3 = signed_cp_explicit(3, fx.cp2.hash(), 1, [0x33; 32], vec![[0x55; 32]]);
    assert_eq!(digest_string(&synth_cp3.hash()), SYNTH_CP3_DIGEST);
    let twin2 = signed_cp_explicit(2, fx.e1.hash(), 2, [0xde; 32], vec![[0x22; 32]]);
    assert_eq!(digest_string(&twin2.hash()), CP2_TWIN_DIGEST);
    let twin0 = signed_cp_explicit(0, Record::genesis(&TRAIL), 0, [0xaa; 32], vec![]);
    assert_eq!(digest_string(&twin0.hash()), CP0_TWIN_DIGEST);
}
