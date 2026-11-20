//! Rows for the verifier's below-the-start set-aside and the one
//! position classifier it is built on (ADR-0005 decision 11
//! "A signature alone never demotes anything", ~l.753-757; ruling
//! 13-V6-d3). Every row asserts the full sorted literal finding list
//! as whole [`Finding`] values through [`assert_findings`]; every
//! digest and key in an expected detail is a written-out hex
//! constant pinned by [`fixture_hashes_match_literals`]. Each row is
//! labelled ACCEPTANCE or REGRESSION in its doc comment.

use crate::audit::{
    Checkpoint, FindingKind as K, KeyFileSigner, Mmr, Record, RecordContext, Signer, TrustPolicy,
    digest_string,
    format::CheckpointFields,
    hex,
    runs_v4a_fixtures::{
        TRAIL, Temp, entry_rec, fixture_pubkey, line_bytes, pushed, put_segment, seeded,
        segment_path, signed_cp, signed_cp_explicit,
    },
    verify::{Finding, Report, Verifier},
};
use std::path::PathBuf;

// =====================================================================
// Shared literal hex constants.
// =====================================================================

const OTHER_TRAIL: [u8; 16] = [0x01; 16];
const OTHER_TRAIL_HEX: &str = "01010101010101010101010101010101";
const TRAIL_HEX: &str = "11111111111111111111111111111111";
const FIXTURE_KEY_HEX: &str = "ee45ecb9aca01a0abd83ef56dd985c8c874e6e7f4aebcedf20bd8d88c2a0add7";
const ALT_KEY_HEX: &str = "c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242";

/// `signed_cp(0, genesis(TRAIL), &Mmr::new())`.
const CP0_HONEST_DIGEST: &str =
    "blake3:fc26c6f2bb830592aaaca5413da1599489d86ac6e240a4a7a010681e0d4c8e77";
/// `signed_cp(2, e1.hash(), &mmr1)` on the honest `[cp0, e1]` fold.
const CP2_HONEST_DIGEST: &str =
    "blake3:4164966a12a675e55eb6e133b9e50313907f164fe142d941447defcdfdb25d06";
/// `signed_cp(4, e3.hash(), &mmr3)` chained through `[cp0, e1, cp2, e3]`.
const CP4_FROM_E3_DIGEST: &str =
    "blake3:3800e98faa1a668c094936a2489dd8d0c1db9ed5dd3c337dd1de87e030b784cd";
/// `signed_cp_explicit(4, e1.hash(), 2, [0x7a; 32], vec![[0x66; 32]])`
/// — a synthetic checkpoint whose `(seq, hash)` lands at seq=4 with a
/// hash distinct from `cp4`, used by P2 as the wrong-hash anchor at
/// the start's seq. `size.count_ones()` must equal `peaks.len()`
/// (a `CheckpointFields::new` invariant).
const SYNTH_CP4_DIGEST: &str =
    "blake3:cd206e8a87ea53009646223e7b02e87b34f383ec651c5a4f9f4e926669c47585";
/// `signed_cp_other(1, [0xaa; 32], &foreign_mmr_one())` on `OTHER_TRAIL`.
const CP1_OTHER_DIGEST: &str =
    "blake3:daa8d58284a56556b8ef654cf1bf13bb1151e582d4ffebe3b2ce3b6df454f2e2";
/// `sign_as(&alt_signer(), 2, e1.hash(), &mmr1)` — `cp2` re-signed
/// under the alt key so it is trusted at seq=2 without the fixture
/// bound ever naming it.
const CP2_ALT_DIGEST: &str =
    "blake3:8f71deebb1a2b11df8703bc9210730f478d3f5f0688e042b9469a5bf4eaaba33";

/// `signed_cp(3, cp2.hash(), &mmr2)` chained from the honest `cp2`,
/// used by P3 as the "attacker's new start" cut just above the
/// newest honest anchor (`cp2`) with the not-yet-revoked key.
const CP3_ATTACK_DIGEST: &str =
    "blake3:dfbf4e5a7173125e6d43847fa1c1b05420adc1c09022566ebbb292b72cf0203c";
/// `signed_cp_explicit(3, cp2.hash(), 2, [0x9a; 32], vec![[0x88; 32]])`
/// — the P3 wrong-hash anchor at the attack start's `seq`, probing
/// the "anchored requires the start's own hash" predicate.
const SYNTH_CP3_DIGEST: &str =
    "blake3:81aca3b3b25a37dadd43ab6763dc0d142e8e29ca0eb26a23c3a909bfba4bddbe";

/// `signed_cp_explicit(0, Record::genesis(&TRAIL), 0, [0xaa; 32], vec![])`
/// — a `seq=0` checkpoint on `TRAIL` whose root bytes land it at a
/// hash distinct from the honest `cp0`. Used by P11 as a wrong-hash
/// anchor below an anchored start.
const CP0_TWIN_DIGEST: &str =
    "blake3:1c2090cbf40864380a0bf92e4dc439c77146d8020e46fe172da7098a6b3077a7";

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

fn parse_cp(record: &Record) -> Checkpoint {
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

fn report_of(files: Vec<PathBuf>, verifier: Verifier) -> Report {
    verifier.verify_files(files).unwrap()
}

/// A one-leaf MMR used by the foreign-trail starts.
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

fn alt_signer() -> KeyFileSigner {
    KeyFileSigner::from_hex(&"55".repeat(32)).unwrap()
}

/// A checkpoint at `(seq, previous, mmr)` on `TRAIL`, signed by an
/// explicit key.
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

/// Honest `[cp0, e1, cp2]` on `TRAIL`, returned for anchors and
/// start values.
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

fn below_anchor(seq: u64, hash_digest: &str, start_seq: u64) -> Finding {
    unlocated(
        K::OutOfRange,
        Some(seq),
        format!("anchor seq {seq} hash {hash_digest}: below start seq {start_seq}"),
    )
}
fn below_anchor_err(seq: u64, hash_digest: &str, start_seq: u64) -> Finding {
    unlocated(
        K::UnanchoredStart,
        Some(seq),
        format!("anchor seq {seq} hash {hash_digest}: below start seq {start_seq}"),
    )
}

// Build `cp4` on top of the honest `[cp0, e1, cp2]` fold.
fn cp4_above(fx: &Honest) -> (Record, Mmr) {
    let e3 = entry_rec(3, fx.cp2.hash());
    let mmr3 = pushed(&fx.mmr2, &e3);
    let cp4 = signed_cp(4, e3.hash(), &mmr3);
    (cp4, mmr3)
}

// =====================================================================
// P1 — ACCEPTANCE. The archived trail has been cut back to `cp4`,
// the start is `cp4`, every original checkpoint (`cp0`, `cp2`, `cp4`)
// is passed as an anchor, and `cp4` anchors the start. The two
// anchors below the start are set aside as `OutOfRange` (info) and
// the report passes `--strict` (ADR-0005 d11 l.935, anchor half;
// ruling 13-V6-d3 point 4). First failing line on base: the
// `assert_findings` call below (base reports
// `AnchorMismatch … no record` for the below-start anchors).
// =====================================================================
#[test]
fn p1_anchored_start_below_start_anchors_are_out_of_range() {
    let fx = honest();
    let (cp4, _) = cp4_above(&fx);
    let seg = seal(&[&cp4]);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .anchor(parse_cp(&fx.cp0))
        .anchor(parse_cp(&fx.cp2))
        .anchor(parse_cp(&cp4))
        .start_from(parse_cp(&cp4));
    let report = report_of(vec![seg.path], verifier);
    let expected = vec![
        below_anchor(0, CP0_HONEST_DIGEST, 4),
        below_anchor(2, CP2_HONEST_DIGEST, 4),
    ];
    assert_findings(report.findings(), &expected, "P1");
    assert!(report.is_strict_valid(), "P1 report must pass --strict");
}

// =====================================================================
// P2 — ACCEPTANCE. P1's layout with the start unanchored: the anchor
// at the start's `seq` carries a wrong hash on the verified trail, so
// it does not anchor the start. Every anchor below the start is
// `UnanchoredStart` (error); the wrong-hash anchor keeps its ordinary
// `AnchorMismatch … hash differs` (ADR-0005 d11 l.937; ruling
// 13-V6-d3 points 3-4; "anchored" is `(trail, seq, hash)` equality,
// not a bare `seq` match). First failing line on base: the
// `assert_findings` call below.
// =====================================================================
#[test]
fn p2_unanchored_start_wrong_hash_anchor_at_s_below_is_error() {
    let fx = honest();
    let (cp4, _) = cp4_above(&fx);
    let seg = seal(&[&cp4]);
    // Wrong-hash anchor at seq=4 on TRAIL: same trail, same seq, but
    // its `(size, root, peaks, key)` combination yields a different
    // record hash from `cp4`. `size.count_ones()` must equal
    // `peaks.len()` (a `CheckpointFields::new` invariant).
    let wrong = signed_cp_explicit(4, fx.e1.hash(), 2, [0x7a; 32], vec![[0x66; 32]]);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .anchor(parse_cp(&fx.cp0))
        .anchor(parse_cp(&fx.cp2))
        .anchor(parse_cp(&wrong))
        .start_from(parse_cp(&cp4));
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![
        below_anchor_err(0, CP0_HONEST_DIGEST, 4),
        below_anchor_err(2, CP2_HONEST_DIGEST, 4),
        located(
            K::AnchorMismatch,
            seg.path,
            1,
            4,
            format!(
                "anchor seq 4 hash {SYNTH_CP4_DIGEST}: hash differs (record {CP4_FROM_E3_DIGEST})"
            ),
        ),
    ];
    assert_findings(report.findings(), &expected, "P2");
    assert!(!report.is_strict_valid(), "P2 report must fail --strict");
}

// =====================================================================
// P3 — ACCEPTANCE. The stolen-key cut (ADR-0005 d11 l.937): the
// operator took anchors at `cp0` and `cp2`; an attacker with the
// not-yet-revoked key cut just above `cp2`, signed a new start at
// `cp3`, rewrote and re-signed above it, and moved the rest away.
// Verifying with every honest anchor (`cp0`, `cp2`) and that start,
// and nothing else, yields `UnanchoredStart` for each anchor and the
// report fails `--strict` (ruling 13-V6-d3 point 4). First failing
// line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn p3_stolen_key_cut_above_newest_anchor_is_unanchored_start() {
    let fx = honest();
    let cp3 = signed_cp(3, fx.cp2.hash(), &fx.mmr2);
    let seg = seal(&[&cp3]);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .anchor(parse_cp(&fx.cp0))
        .anchor(parse_cp(&fx.cp2))
        .start_from(parse_cp(&cp3));
    let report = report_of(vec![seg.path], verifier);
    let expected = vec![
        below_anchor_err(0, CP0_HONEST_DIGEST, 3),
        below_anchor_err(2, CP2_HONEST_DIGEST, 3),
    ];
    assert_findings(report.findings(), &expected, "P3");
    assert!(!report.is_strict_valid(), "P3 report must fail --strict");
}

// =====================================================================
// P4 — ACCEPTANCE. An honest unanchored start with a `through=` pin
// below it: the pin's `RevocationMismatch` check is replaced by one
// unlocated `UnanchoredStart` (ADR-0005 d11 l.938, pin half; ruling
// 13-V6-d3 point 5). The confirmation check is unchanged and the
// start's own trusted checkpoint confirms the bound, so no
// `RevocationUnconfirmed` fires. First failing line on base: the
// `assert_findings` call below.
// =====================================================================
#[test]
fn p4_unanchored_start_through_pin_below_is_unanchored_start() {
    let fx = honest();
    let cp2_alt = sign_as(&alt_signer(), 2, fx.e1.hash(), &fx.mmr1);
    let seg = seal(&[&cp2_alt]);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, fx.cp0.hash())
        .key(alt_signer().public_key())
        .build()
        .unwrap();
    let verifier = Verifier::new(trust).start_from(parse_cp(&cp2_alt));
    let report = report_of(vec![seg.path], verifier);
    let expected = vec![unlocated(
        K::UnanchoredStart,
        Some(0),
        format!("key {FIXTURE_KEY_HEX} through=0: below start seq 2"),
    )];
    assert_findings(report.findings(), &expected, "P4");
    assert!(!report.is_strict_valid(), "P4 report must fail --strict");
}

// =====================================================================
// P5 — REGRESSION. An honest unanchored start with nothing below it
// is accepted by its signature alone (ADR-0005 d11 l.938 "An
// unanchored start with nothing below it"): no error, no warning, no
// info. Pairs with P1 as the baseline "no inputs below" case.
// =====================================================================
#[test]
fn p5_unanchored_start_nothing_below_is_clean() {
    let fx = honest();
    let seg = seal(&[&fx.cp2]);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).start_from(parse_cp(&fx.cp2));
    let report = report_of(vec![seg.path], verifier);
    assert_findings(report.findings(), &[], "P5");
    assert!(report.is_strict_valid(), "P5 report must pass --strict");
}

// =====================================================================
// P6 — ACCEPTANCE. Above an anchored start the revocation rules
// still apply (ADR-0005 d11 l.939). The bound itself is below the
// start, so its pin is `OutOfRange` and the confirmation still runs
// (ruling 13-V6-d3 point 5); the old-key checkpoint above the bound
// stays `UntrustedKey`. First failing line on base: the
// `assert_findings` call below.
// =====================================================================
#[test]
fn p6_anchored_start_below_pin_is_out_of_range_above_still_untrusted() {
    let fx = honest();
    let cp2_alt = sign_as(&alt_signer(), 2, fx.e1.hash(), &fx.mmr1);
    let mmr2_alt = pushed(&fx.mmr1, &cp2_alt);
    let cp3_old = signed_cp(3, cp2_alt.hash(), &mmr2_alt);
    let seg = seal(&[&cp2_alt, &cp3_old]);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, fx.cp0.hash())
        .key(alt_signer().public_key())
        .build()
        .unwrap();
    let verifier = Verifier::new(trust)
        .anchor(parse_cp(&cp2_alt))
        .start_from(parse_cp(&cp2_alt));
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![
        unlocated(
            K::OutOfRange,
            Some(0),
            format!("key {FIXTURE_KEY_HEX} through=0: below start seq 2"),
        ),
        located(
            K::UntrustedKey,
            seg.path,
            2,
            3,
            format!("key {FIXTURE_KEY_HEX} bounded through seq 0"),
        ),
        uncovered(3, 3),
    ];
    assert_findings(report.findings(), &expected, "P6");
}

// =====================================================================
// P7 — REGRESSION. An anchor from another trail with a `seq` below
// the start keeps its ordinary `AnchorMismatch … trail differs`
// (ruling 13-V6-d3 point 4 "another trail still gives `trail
// differs`"): another trail's anchor is never set aside.
// =====================================================================
#[test]
fn p7_anchored_start_other_trail_anchor_below_keeps_trail_differs() {
    let fx = honest();
    let seg = seal(&[&fx.cp2]);
    let foreign = signed_cp_other(1, [0xaa; 32], &foreign_mmr_one());
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .anchor(parse_cp(&fx.cp2))
        .anchor(parse_cp(&foreign))
        .start_from(parse_cp(&fx.cp2));
    let report = report_of(vec![seg.path], verifier);
    let expected = vec![unlocated(
        K::AnchorMismatch,
        Some(1),
        format!("anchor seq 1 hash {CP1_OTHER_DIGEST}: trail differs"),
    )];
    assert_findings(report.findings(), &expected, "P7");
    // The `trail differs` AnchorMismatch is an error (ADR-0005 d10).
    assert!(!report.is_valid(), "P7 report must carry the error");
}

// =====================================================================
// P8 — REGRESSION. An anchor exactly at the start's `seq` with the
// start's hash anchors the start and matches; no below-start finding
// fires for it (ruling 13-V6-d3 points 2-3; "below" uses `<`, not
// `<=`). Pairs with P9 as the b == s pair. Base passes.
// =====================================================================
#[test]
fn p8_anchor_at_start_seq_with_start_hash_is_in_range() {
    let fx = honest();
    let seg = seal(&[&fx.cp2]);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .anchor(parse_cp(&fx.cp2))
        .start_from(parse_cp(&fx.cp2));
    let report = report_of(vec![seg.path], verifier);
    assert_findings(report.findings(), &[], "P8");
}

// =====================================================================
// P9 — REGRESSION. A `through=` pin at `b = s` is in range, so the
// pin is checked as usual (ruling 13-V6-d3 point 5 "A bound at
// `b = s` or above it is in range"). The pin passes (one record at
// `s`, same hash, checkpoint signed by the bounded key), and the
// confirmation runs as usual: with no trusted checkpoint by another
// key above the bound, `RevocationUnconfirmed` fires at `s`. A bound
// below an accepted start is always confirmed by that start, so this
// row doubles as the pair to P6: the `RevocationUnconfirmed` half of
// ADR-0005 d11 l.939 fires only when the bound is `>= s`.
// =====================================================================
#[test]
fn p9_pin_at_b_equals_s_runs_as_usual() {
    let fx = honest();
    let seg = seal(&[&fx.cp2]);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 2, fx.cp2.hash())
        .build()
        .unwrap();
    let verifier = Verifier::new(trust)
        .anchor(parse_cp(&fx.cp2))
        .start_from(parse_cp(&fx.cp2));
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![located(
        K::RevocationUnconfirmed,
        seg.path,
        1,
        2,
        format!(
            "key {FIXTURE_KEY_HEX} through=2: no trusted checkpoint by another key above the bound"
        ),
    )];
    assert_findings(report.findings(), &expected, "P9");
}

// =====================================================================
// P10 — REGRESSION. A start that is not accepted
// (`StartMismatch … not the first record`) with inputs below its
// `seq` leaves those inputs with their ordinary findings; nothing is
// set aside (ruling 13-V6-d3 point 2 "InRange otherwise, including
// always when no start was accepted"). Pairs the anchor and pin
// below an unaccepted start in one layout. Base passes.
// =====================================================================
#[test]
fn p10_unaccepted_start_below_inputs_keep_their_findings() {
    let fx = honest();
    let (cp4, _) = cp4_above(&fx);
    let seg = seal(&[&cp4]);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, fx.cp0.hash())
        .build()
        .unwrap();
    let verifier = Verifier::new(trust)
        .anchor(parse_cp(&fx.cp0))
        .start_from(parse_cp(&fx.cp2));
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![
        unlocated(
            K::AnchorMismatch,
            Some(0),
            format!("anchor seq 0 hash {CP0_HONEST_DIGEST}: no record"),
        ),
        unlocated(
            K::RevocationMismatch,
            Some(0),
            format!("key {FIXTURE_KEY_HEX} through=0:{CP0_HONEST_DIGEST}: no record at seq 0"),
        ),
        unlocated(
            K::RevocationUnconfirmed,
            Some(0),
            format!(
                "key {FIXTURE_KEY_HEX} through=0: no trusted checkpoint by another key above the bound"
            ),
        ),
        located(
            K::StartMismatch,
            seg.path.clone(),
            1,
            2,
            format!("start seq 2 hash {CP2_HONEST_DIGEST}: not the first record (first seq 4)"),
        ),
        located(
            K::SeqGap,
            seg.path.clone(),
            1,
            4,
            "missing seq 0..=3".into(),
        ),
        located(
            K::UntrustedKey,
            seg.path,
            1,
            4,
            format!("key {FIXTURE_KEY_HEX} bounded through seq 0"),
        ),
        uncovered(4, 4),
    ];
    assert_findings(report.findings(), &expected, "P10");
}

// =====================================================================
// P11 — ACCEPTANCE. An anchor whose `seq` is below an anchored
// start but whose hash is not the record's: still `OutOfRange` with
// the d3 detail — nothing below can be checked, so the record's
// hash does not enter the detail (ruling 13-V6-d3 point 4). The
// anchor's own hash is in the detail, not the record's. First
// failing line on base: the `assert_findings` call below (base
// returns `AnchorMismatch … no record` here).
// =====================================================================
#[test]
fn p11_anchor_below_with_wrong_hash_under_anchored_start() {
    let fx = honest();
    let (cp4, _) = cp4_above(&fx);
    let seg = seal(&[&cp4]);
    // A checkpoint on TRAIL at seq=0 whose root differs from
    // `fx.cp0`: same trail and same seq, distinct hash. No record
    // on the verified trail carries this hash.
    let cp0_twin = signed_cp_explicit(0, Record::genesis(&TRAIL), 0, [0xaa; 32], vec![]);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .anchor(parse_cp(&cp4))
        .anchor(parse_cp(&cp0_twin))
        .start_from(parse_cp(&cp4));
    let report = report_of(vec![seg.path], verifier);
    let expected = vec![below_anchor(0, CP0_TWIN_DIGEST, 4)];
    assert_findings(report.findings(), &expected, "P11");
    assert!(report.is_strict_valid(), "P11 report must pass --strict");
}

// =====================================================================
// P12 — REGRESSION. Below-start anchors coexist with an extra
// wrong-hash anchor at the start's `seq` on the verified trail and
// an extra other-trail anchor. The wrong-hash anchor keeps
// `AnchorMismatch … hash differs` (ruling 13-V6-d3 point 3:
// "anchored" is `(trail, seq, hash)` equality, not a bare `seq`
// match); the other-trail anchor keeps `AnchorMismatch … trail
// differs` (point 4: another trail is never set aside); the
// below-start honest anchors stay `UnanchoredStart`. Pairs with P3
// as the "stolen-key cut with incidental anchors" variant.
// =====================================================================
#[test]
fn p12_stolen_key_cut_with_extra_wrong_hash_and_foreign_anchors() {
    let fx = honest();
    let cp3 = signed_cp(3, fx.cp2.hash(), &fx.mmr2);
    let seg = seal(&[&cp3]);
    // Wrong-hash anchor at the start's seq=3 on TRAIL: same trail
    // and same seq, distinct hash.
    let wrong_at_s = signed_cp_explicit(3, fx.cp2.hash(), 2, [0x9a; 32], vec![[0x88; 32]]);
    let foreign = signed_cp_other(1, [0xaa; 32], &foreign_mmr_one());
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .anchor(parse_cp(&fx.cp0))
        .anchor(parse_cp(&fx.cp2))
        .anchor(parse_cp(&wrong_at_s))
        .anchor(parse_cp(&foreign))
        .start_from(parse_cp(&cp3));
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![
        below_anchor_err(0, CP0_HONEST_DIGEST, 3),
        unlocated(
            K::AnchorMismatch,
            Some(1),
            format!("anchor seq 1 hash {CP1_OTHER_DIGEST}: trail differs"),
        ),
        below_anchor_err(2, CP2_HONEST_DIGEST, 3),
        located(
            K::AnchorMismatch,
            seg.path,
            1,
            3,
            format!(
                "anchor seq 3 hash {SYNTH_CP3_DIGEST}: hash differs (record {CP3_ATTACK_DIGEST})"
            ),
        ),
    ];
    assert_findings(report.findings(), &expected, "P12");
    assert!(!report.is_strict_valid(), "P12 report must fail --strict");
}

// =====================================================================
// Pins every literal hex constant in this module to the fixture it
// names so a hash change anywhere in `runs_v4a_fixtures` or in the
// code under test never slips through the literal-row assertions.
// =====================================================================
#[test]
fn fixture_hashes_match_literals() {
    let fx = honest();
    assert_eq!(hex(&TRAIL), TRAIL_HEX);
    assert_eq!(hex(&OTHER_TRAIL), OTHER_TRAIL_HEX);
    assert_eq!(hex(&fixture_pubkey()), FIXTURE_KEY_HEX);
    assert_eq!(hex(&alt_signer().public_key()), ALT_KEY_HEX);
    assert_eq!(digest_string(&fx.cp0.hash()), CP0_HONEST_DIGEST);
    assert_eq!(digest_string(&fx.cp2.hash()), CP2_HONEST_DIGEST);
    let (cp4, _) = cp4_above(&fx);
    assert_eq!(digest_string(&cp4.hash()), CP4_FROM_E3_DIGEST);
    let wrong = signed_cp_explicit(4, fx.e1.hash(), 2, [0x7a; 32], vec![[0x66; 32]]);
    assert_eq!(digest_string(&wrong.hash()), SYNTH_CP4_DIGEST);
    let foreign = signed_cp_other(1, [0xaa; 32], &foreign_mmr_one());
    assert_eq!(digest_string(&foreign.hash()), CP1_OTHER_DIGEST);
    let cp2_alt = sign_as(&alt_signer(), 2, fx.e1.hash(), &fx.mmr1);
    assert_eq!(digest_string(&cp2_alt.hash()), CP2_ALT_DIGEST);
    let cp3 = signed_cp(3, fx.cp2.hash(), &fx.mmr2);
    assert_eq!(digest_string(&cp3.hash()), CP3_ATTACK_DIGEST);
    let synth3 = signed_cp_explicit(3, fx.cp2.hash(), 2, [0x9a; 32], vec![[0x88; 32]]);
    assert_eq!(digest_string(&synth3.hash()), SYNTH_CP3_DIGEST);
    let cp0_twin = signed_cp_explicit(0, Record::genesis(&TRAIL), 0, [0xaa; 32], vec![]);
    assert_eq!(digest_string(&cp0_twin.hash()), CP0_TWIN_DIGEST);
}
