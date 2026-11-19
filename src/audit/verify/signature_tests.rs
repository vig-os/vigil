//! Verifier-level rows for `BadSignature` / `UntrustedKey` and the
//! crate-private `trusted` predicate (ADR-0005 decisions 8 and 9,
//! ruling 13-V5-d1 points 1-3).
//!
//! Row standard (vigil repo's traps): every acceptance row asserts the
//! FULL sorted literal finding list as literal values -- every kind,
//! file, line, seq and detail, including the existing ones such as
//! `UncoveredTail`, `SeqConflict`, `DuplicateRecord`, run-fold findings
//! (`SegmentStructure` with `run_digest`), `SeqGap`, and `Resumed`. The
//! comparison helper `assert_rows` is the only way a row asserts on
//! findings in this file. Regression rows (R2) are labelled in their
//! doc comments; predicate tests (A4b, A8b and the direct predicate
//! rows) are labelled as predicate tests -- they cannot even compile
//! on base, so they are not acceptance rows.
//!
//! Every signed checkpoint carries the shared fixture key `0x27`; its
//! public key is spelled out literally as [`FIXTURE_KEY_HEX`] so a drift
//! in the captured bytes fails the row assertion. Keys for crafted
//! unlisted / small-order / bounded-only scenarios appear in
//! [`ALT_KEY_HEX`] and [`IDENTITY_KEY_HEX`].

use super::{check, trusted};
use crate::audit::{
    AuditErrorKind, CheckpointFields, FindingKind as K, KeyFileSigner, Mmr, Record, Signer,
    TrustPolicy, digest_string,
    format::Kind,
    hex,
    runs_v4a_fixtures::{
        A1_DIGEST, TRAIL, Temp, build_a1, context, entry_rec, fixture_pubkey, headless, line_bytes,
        pushed, put_segment, resume_decl, seeded, segment_path, signed_cp, write_records,
    },
    verify::{Finding, Verifier, input},
};
use std::path::{Path, PathBuf};

type Row = (K, Option<PathBuf>, Option<u64>, Option<u64>, String);

// =====================================================================
// Literal hex constants (every row's detail uses these directly).
// =====================================================================

/// Public key derived from the fixture signing seed `0x27` repeated, which
/// every honest signed checkpoint in this test module (and every
/// `runs_v4a_fixtures` builder) uses (`ee45…add7` written out in full).
const FIXTURE_KEY_HEX: &str = "ee45ecb9aca01a0abd83ef56dd985c8c874e6e7f4aebcedf20bd8d88c2a0add7";
/// Public key derived from the unlisted signing seed `0x55` repeated.
/// Used by the A2 / A6 / A7b / F2 crafted-unlisted rows.
const ALT_KEY_HEX: &str = "c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242";
/// Ed25519 identity-point encoding `01 00 … 00`: a small-order key that
/// `verify_strict` rejects unconditionally (A4).
const IDENTITY_KEY_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000";
/// Hex of `runs_v4a_fixtures::TRAIL` = `[17; 16]`.
const TRAIL_HEX: &str = "11111111111111111111111111111111";

/// `UncoveredTail` detail for a `first..=last` range (ADR-0005 l.400-407;
/// the placeholder text is V5a-authoritative and replaced by V5b).
fn uncovered_tail(first: u64, last: u64) -> String {
    format!(
        "records seq {first}..={last}, no trusted coverage yet (signatures are checked in #13 V5)"
    )
}

/// `Resumed` detail (ruling 13-V3-d5; same reason+gap shape for every
/// resume this test module builds via `resume_decl`).
fn resume_detail(head_seq: u64, head_hash: [u8; 32], gap: &str) -> String {
    format!(
        "operator=operator reason=incident head={head_seq}:{} gap={gap} lost_records=0 structural=valid",
        digest_string(&head_hash)
    )
}

fn rows(findings: &[Finding]) -> Vec<Row> {
    findings
        .iter()
        .map(|f| {
            (
                f.kind(),
                f.file().map(Path::to_path_buf),
                f.line(),
                f.seq(),
                f.detail().to_owned(),
            )
        })
        .collect()
}

/// Asserts that the full sorted literal finding list (every field of
/// every finding) is exactly `expected`. This is the only way a row
/// in this file asserts on `check`'s output.
#[track_caller]
fn assert_rows(findings: &[Finding], expected: &[Row], label: &str) {
    let actual = rows(findings);
    assert_eq!(actual, expected, "{label} literal finding list");
}

fn verify_files_with(files: Vec<PathBuf>, trust: TrustPolicy) -> Vec<Finding> {
    Verifier::new(trust)
        .verify_files(files)
        .unwrap()
        .findings()
        .to_vec()
}

fn trust_with_key(key: [u8; 32]) -> TrustPolicy {
    TrustPolicy::builder()
        .trail(TRAIL)
        .key(key)
        .build()
        .unwrap()
}

/// Clones a signed checkpoint while rewriting its signature and re-hashing.
fn with_signature(signed: &Record, sig: [u8; 64]) -> Record {
    let cp = match &signed.kind {
        Kind::Checkpoint(cp) => cp,
        _ => panic!("checkpoint record expected"),
    };
    let fields = CheckpointFields::new(cp.size, cp.root, cp.peaks.clone(), cp.key, sig).unwrap();
    Record::checkpoint(signed.context.clone(), fields).unwrap()
}

/// Flips one bit of the signature's `R` half so the honest layout becomes
/// bit-identical except for the signature bytes. The record's hash changes
/// under this mutation (0x24 is covered by `Record::hash`), so callers that
/// chain further records must link against the flipped record's new hash.
fn flip_signature_byte(signed: &Record) -> Record {
    let sig = match &signed.kind {
        Kind::Checkpoint(cp) => cp.signature(),
        _ => panic!("checkpoint record expected"),
    };
    let mut flipped = *sig;
    flipped[0] ^= 0x01;
    with_signature(signed, flipped)
}

/// Clones a signed checkpoint while rewriting its `key` field, keeping its
/// `size`/`root`/`peaks` the same. For crafting an opening with a different
/// public key.
fn with_key_and_signature(signed: &Record, key: [u8; 32], sig: [u8; 64]) -> Record {
    let cp = match &signed.kind {
        Kind::Checkpoint(cp) => cp,
        _ => panic!("checkpoint record expected"),
    };
    let fields = CheckpointFields::new(cp.size, cp.root, cp.peaks.clone(), key, sig).unwrap();
    Record::checkpoint(signed.context.clone(), fields).unwrap()
}

fn alt_signer() -> KeyFileSigner {
    KeyFileSigner::from_hex(&"55".repeat(32)).unwrap()
}

fn sign_as(signer: &KeyFileSigner, seq: u64, previous: [u8; 32], mmr: &Mmr) -> Record {
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
    let unsigned = Record::checkpoint(context(seq, previous), fields([0; 64])).unwrap();
    let sig = signer.sign(&unsigned.signing_message().unwrap()).unwrap();
    Record::checkpoint(context(seq, previous), fields(sig)).unwrap()
}

/// Single sealed segment `[cp0, e1, cp2]` on `TRAIL`, cp2 signed by the
/// fixture key. The chain is honest; row-specific tests mutate cp2 and
/// rewrite the segment in place via [`put_segment`].
struct TwoCheckpointLayout {
    _dir: Temp,
    path: PathBuf,
    cp0: Record,
    e1: Record,
    cp2: Record,
}

fn two_checkpoints() -> TwoCheckpointLayout {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let path = segment_path(&d.0, 0);
    TwoCheckpointLayout {
        _dir: d,
        path,
        cp0,
        e1,
        cp2,
    }
}

// =====================================================================
// A1 — listed key, one byte of cp2's signature flipped → BadSignature@2.
// Acceptance row. Base emits only `UncoveredTail`; this row asserts the
// `BadSignature` as part of the literal list so base fails on the equality.
// Kills M1. Does NOT kill M7 (cp2 lives in a single sealed segment —
// "member of a run" does not cover this layout); M7's named kills are
// the two in-run rows A9 and A10.
// =====================================================================
#[test]
fn a1_listed_key_flipped_signature_is_bad_signature_at_cp2() {
    let fx = two_checkpoints();
    let bad = flip_signature_byte(&fx.cp2);
    put_segment(&fx._dir.0, 0, &[&fx.cp0, &fx.e1, &bad], &[]);
    let findings = verify_files_with(vec![fx.path.clone()], trust_with_key(fixture_pubkey()));
    let expected: Vec<Row> = vec![
        (
            K::BadSignature,
            Some(fx.path.clone()),
            Some(3),
            Some(2),
            format!("key {FIXTURE_KEY_HEX}"),
        ),
        (K::UncoveredTail, None, None, None, uncovered_tail(0, 2)),
    ];
    assert_rows(&findings, &expected, "A1");
}

// =====================================================================
// A2 — cp2 validly signed by an unlisted key `0x55`
// → UntrustedKey@2 "… not listed for trail …". Acceptance row.
// =====================================================================
#[test]
fn a2_unlisted_key_valid_signature_is_untrusted_not_listed() {
    let d = Temp::new();
    let signer = alt_signer();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = sign_as(&signer, 2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let path = segment_path(&d.0, 0);
    let findings = verify_files_with(vec![path.clone()], trust_with_key(fixture_pubkey()));
    let expected: Vec<Row> = vec![
        (
            K::UntrustedKey,
            Some(path),
            Some(3),
            Some(2),
            format!("key {ALT_KEY_HEX} not listed for trail {TRAIL_HEX}"),
        ),
        (K::UncoveredTail, None, None, None, uncovered_tail(0, 2)),
    ];
    assert_rows(&findings, &expected, "A2");
}

// =====================================================================
// A3 — listed with through=0:<cp0 hash>, cp2 honestly signed →
// UntrustedKey@2 "… bounded through seq 0"; cp0 itself not flagged.
// Acceptance row.
// =====================================================================
#[test]
fn a3_bound_key_cp2_above_bound_is_untrusted_bounded() {
    let fx = two_checkpoints();
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, fx.cp0.hash())
        .build()
        .unwrap();
    let findings = verify_files_with(vec![fx.path.clone()], trust);
    let expected: Vec<Row> = vec![
        (
            K::UntrustedKey,
            Some(fx.path.clone()),
            Some(3),
            Some(2),
            format!("key {FIXTURE_KEY_HEX} bounded through seq 0"),
        ),
        (K::UncoveredTail, None, None, None, uncovered_tail(0, 2)),
    ];
    assert_rows(&findings, &expected, "A3");
}

// =====================================================================
// A4 — small-order (identity-point) key with a signature legacy `verify`
// accepts, key listed → BadSignature. Acceptance row.
//
// Kills M1 (`verify_strict` → `verify`): `[s]B = R + [h]A` holds for the
// identity-point key on every message because `[h]·identity = identity`,
// so RFC 8032 non-strict `verify` accepts (identity, 0, 1). `verify_strict`
// rejects the small-order key unconditionally (ADR-0005 decision 8).
// =====================================================================
#[test]
fn a4_small_order_key_is_bad_signature_under_strict() {
    let fx = two_checkpoints();
    // Ed25519 identity: (x=0, y=1), encoded little-endian as `01 00…00`.
    let mut identity_key = [0u8; 32];
    identity_key[0] = 0x01;
    // Signature: R = identity encoding, s = 0 (also a scalar < ℓ).
    let mut bad_sig = [0u8; 64];
    bad_sig[0] = 0x01;
    let cp2 = with_key_and_signature(&fx.cp2, identity_key, bad_sig);
    put_segment(&fx._dir.0, 0, &[&fx.cp0, &fx.e1, &cp2], &[]);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .key(identity_key)
        .build()
        .unwrap();
    let findings = verify_files_with(vec![fx.path.clone()], trust);
    let expected: Vec<Row> = vec![
        (
            K::BadSignature,
            Some(fx.path.clone()),
            Some(3),
            Some(2),
            format!("key {IDENTITY_KEY_HEX}"),
        ),
        (K::UncoveredTail, None, None, None, uncovered_tail(0, 2)),
    ];
    assert_rows(&findings, &expected, "A4");
}

// =====================================================================
// A4b — predicate test (new API; does not compile on base). Rebuilds
// A4's small-order fixture and asserts `trusted(...)` is `false` for the
// identity-key cp2 even with the key listed. Pairs with A4 to give M1 a
// second runtime kill.
// =====================================================================
#[test]
fn a4b_trusted_predicate_rejects_small_order_key() {
    let fx = two_checkpoints();
    let mut identity_key = [0u8; 32];
    identity_key[0] = 0x01;
    let mut bad_sig = [0u8; 64];
    bad_sig[0] = 0x01;
    let cp2 = with_key_and_signature(&fx.cp2, identity_key, bad_sig);
    put_segment(&fx._dir.0, 0, &[&fx.cp0, &fx.e1, &cp2], &[]);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .key(identity_key)
        .build()
        .unwrap();
    let collection = input::collect([fx.path]).unwrap();
    let cp2_summary = collection
        .inputs
        .iter()
        .flat_map(|i| i.data.records.iter())
        .find(|r| r.seq == 2)
        .expect("cp2 in the small-order fixture");
    assert!(!trusted(TRAIL, &trust, cp2_summary));
}

// =====================================================================
// A5 — non-canonical signature (`s ≥ ℓ`, built as honest `s + ℓ`) →
// BadSignature. Acceptance row.
// =====================================================================
#[test]
fn a5_non_canonical_signature_is_bad_signature() {
    let fx = two_checkpoints();
    const ELL_LE: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    let honest = match &fx.cp2.kind {
        Kind::Checkpoint(cp) => *cp.signature(),
        _ => panic!("checkpoint"),
    };
    // `s' = s + ℓ (little-endian)`. `s' ≥ ℓ`, so `verify_strict` rejects
    // it; `s' ≡ s (mod ℓ)` would re-verify under legacy `verify`.
    let mut sig = honest;
    let mut carry: u16 = 0;
    for i in 0..32 {
        let s = sig[32 + i] as u16 + ELL_LE[i] as u16 + carry;
        sig[32 + i] = (s & 0xff) as u8;
        carry = s >> 8;
    }
    let bad = with_signature(&fx.cp2, sig);
    put_segment(&fx._dir.0, 0, &[&fx.cp0, &fx.e1, &bad], &[]);
    let findings = verify_files_with(vec![fx.path.clone()], trust_with_key(fixture_pubkey()));
    let expected: Vec<Row> = vec![
        (
            K::BadSignature,
            Some(fx.path.clone()),
            Some(3),
            Some(2),
            format!("key {FIXTURE_KEY_HEX}"),
        ),
        (K::UncoveredTail, None, None, None, uncovered_tail(0, 2)),
    ];
    assert_rows(&findings, &expected, "A5");
}

// =====================================================================
// A6 — unlisted key `0x55` plus a flipped signature → BOTH BadSignature@2
// and UntrustedKey@2 (ruling 13-V5-d1 point 2 independence). Acceptance row.
// =====================================================================
#[test]
fn a6_unlisted_key_with_flipped_signature_emits_both() {
    let d = Temp::new();
    let signer = alt_signer();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let valid = sign_as(&signer, 2, e1.hash(), &mmr1);
    let bad = flip_signature_byte(&valid);
    put_segment(&d.0, 0, &[&cp0, &e1, &bad], &[]);
    let path = segment_path(&d.0, 0);
    let findings = verify_files_with(vec![path.clone()], trust_with_key(fixture_pubkey()));
    let expected: Vec<Row> = vec![
        (
            K::BadSignature,
            Some(path.clone()),
            Some(3),
            Some(2),
            format!("key {ALT_KEY_HEX}"),
        ),
        (
            K::UntrustedKey,
            Some(path),
            Some(3),
            Some(2),
            format!("key {ALT_KEY_HEX} not listed for trail {TRAIL_HEX}"),
        ),
        (K::UncoveredTail, None, None, None, uncovered_tail(0, 2)),
    ];
    assert_rows(&findings, &expected, "A6");
}

// =====================================================================
// A6b — bounded fixture key, cp2 signature flipped above the bound →
// BOTH BadSignature@2 and UntrustedKey@2 "bounded through seq 0".
// Acceptance row. Pairs with A6 to give M4 (skip BadSignature when
// UntrustedKey fired) two named runtime kills.
// =====================================================================
#[test]
fn a6b_bounded_key_with_flipped_signature_emits_both() {
    let fx = two_checkpoints();
    let bad = flip_signature_byte(&fx.cp2);
    put_segment(&fx._dir.0, 0, &[&fx.cp0, &fx.e1, &bad], &[]);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, fx.cp0.hash())
        .build()
        .unwrap();
    let findings = verify_files_with(vec![fx.path.clone()], trust);
    let expected: Vec<Row> = vec![
        (
            K::BadSignature,
            Some(fx.path.clone()),
            Some(3),
            Some(2),
            format!("key {FIXTURE_KEY_HEX}"),
        ),
        (
            K::UntrustedKey,
            Some(fx.path.clone()),
            Some(3),
            Some(2),
            format!("key {FIXTURE_KEY_HEX} bounded through seq 0"),
        ),
        (K::UncoveredTail, None, None, None, uncovered_tail(0, 2)),
    ];
    assert_rows(&findings, &expected, "A6b");
}

// =====================================================================
// A7 — shipped-only cp2 with a flipped signature → BadSignature at the
// shipped file and line 1. Acceptance row.
// =====================================================================
#[test]
fn a7_shipped_only_checkpoint_bad_signature_uses_shipped_file_and_line() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let bad = flip_signature_byte(&cp2);
    let shipped = d.0.join("cp2.copy");
    std::fs::write(&shipped, line_bytes(&bad)).unwrap();
    let findings = verify_files_with(vec![shipped.clone()], trust_with_key(fixture_pubkey()));
    let expected: Vec<Row> = vec![
        (
            K::BadSignature,
            Some(shipped.clone()),
            Some(1),
            Some(2),
            format!("key {FIXTURE_KEY_HEX}"),
        ),
        (
            K::SeqGap,
            Some(shipped),
            Some(1),
            Some(2),
            "missing seq 0..=1".to_owned(),
        ),
        (K::UncoveredTail, None, None, None, uncovered_tail(2, 2)),
    ];
    assert_rows(&findings, &expected, "A7");
}

// =====================================================================
// A7b — shipped-only cp2 signed by unlisted key `0x55` → UntrustedKey at
// the shipped file and line 1. Acceptance row. Pairs with A7 to give M3
// (skip shipped-only) two named runtime kills.
// =====================================================================
#[test]
fn a7b_shipped_only_unlisted_key_is_untrusted_at_shipped_path() {
    let d = Temp::new();
    let signer = alt_signer();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = sign_as(&signer, 2, e1.hash(), &mmr1);
    let shipped = d.0.join("cp2.copy");
    std::fs::write(&shipped, line_bytes(&cp2)).unwrap();
    let findings = verify_files_with(vec![shipped.clone()], trust_with_key(fixture_pubkey()));
    let expected: Vec<Row> = vec![
        (
            K::SeqGap,
            Some(shipped.clone()),
            Some(1),
            Some(2),
            "missing seq 0..=1".to_owned(),
        ),
        (
            K::UntrustedKey,
            Some(shipped),
            Some(1),
            Some(2),
            format!("key {ALT_KEY_HEX} not listed for trail {TRAIL_HEX}"),
        ),
        (K::UncoveredTail, None, None, None, uncovered_tail(2, 2)),
    ];
    assert_rows(&findings, &expected, "A7b");
}

// =====================================================================
// A8 — fixture key listed only in ANOTHER trail's section of the same
// policy → UntrustedKey on every cp of this trail. Acceptance row. Kills
// M5 (accept a key listed in any trail's section).
// =====================================================================
#[test]
fn a8_key_listed_on_another_trail_is_untrusted_on_this_trail() {
    let other: [u8; 16] = [0x99; 16];
    assert_ne!(other, TRAIL);
    let trust = TrustPolicy::builder()
        .trail(other)
        .key(fixture_pubkey())
        .trail(TRAIL)
        .build()
        .unwrap();
    let fx = two_checkpoints();
    let findings = Verifier::new(trust)
        .trail(TRAIL)
        .unwrap()
        .verify_files([fx.path.clone()])
        .unwrap()
        .findings()
        .to_vec();
    let expected: Vec<Row> = vec![
        (
            K::UntrustedKey,
            Some(fx.path.clone()),
            Some(1),
            Some(0),
            format!("key {FIXTURE_KEY_HEX} not listed for trail {TRAIL_HEX}"),
        ),
        (
            K::UntrustedKey,
            Some(fx.path.clone()),
            Some(3),
            Some(2),
            format!("key {FIXTURE_KEY_HEX} not listed for trail {TRAIL_HEX}"),
        ),
        (K::UncoveredTail, None, None, None, uncovered_tail(0, 2)),
    ];
    assert_rows(&findings, &expected, "A8");
}

// =====================================================================
// A8b — predicate test (new API; does not compile on base). Pins the
// same key-listed-on-another-trail behaviour A8 asserts through the
// verifier, but through the direct `trusted` predicate. Pairs with A8
// to give M5 a second runtime kill.
// =====================================================================
#[test]
fn a8b_trusted_predicate_rejects_key_listed_on_another_trail() {
    let other: [u8; 16] = [0x99; 16];
    assert_ne!(other, TRAIL);
    let trust = TrustPolicy::builder()
        .trail(other)
        .key(fixture_pubkey())
        .trail(TRAIL)
        .build()
        .unwrap();
    let fx = two_checkpoints();
    let collection = input::collect([fx.path.clone()]).unwrap();
    let records: Vec<_> = collection
        .inputs
        .iter()
        .flat_map(|i| i.data.records.iter())
        .collect();
    let cp2 = records.iter().find(|r| r.seq == 2).unwrap();
    assert!(!trusted(TRAIL, &trust, cp2));
}

// =====================================================================
// A9 — bad signature on an in-run checkpoint after a loss point, in an
// A1-style sealed run → BadSignature at cp5 reported, with the full
// literal list. Acceptance row. Together with A10 gives M7 (skip in-run
// checkpoints) and the new M7′ two named runtime kills; A1-A8, R1, R1b
// are single-segment layouts WITHOUT a run so they do NOT kill M7.
// =====================================================================
#[test]
fn a9_in_run_bad_signature_reports_without_changing_run_findings() {
    // Rebuild A1 by hand with cp5 — the in-run closing opening of S1
    // — carrying a flipped signature. The chain downstream (cp6) relinks
    // against the flipped record's new hash.
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    put_segment(&d.0, 0, &[&cp0, &e1, &e2], &[]);
    let r4 = headless(&e2, 4);
    let fold = pushed(&mmr2, &r4);
    let cp5 = signed_cp(5, r4.hash(), &fold);
    let cp5_bad = flip_signature_byte(&cp5);
    put_segment(&d.0, 1, &[&r4, &cp5_bad], &[]);
    let fold6 = pushed(&fold, &cp5_bad);
    let cp6 = signed_cp(6, cp5_bad.hash(), &fold6);
    let resume = resume_decl(&cp6, 5, cp5_bad.hash(), 5);
    write_records(&d.0, &[&cp6, &resume]);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .build()
        .unwrap();
    let findings = Verifier::new(trust)
        .verify_dir(&d.0)
        .unwrap()
        .findings()
        .to_vec();
    let s1 = segment_path(&d.0, 1);
    let live = d.0.join("audit.jsonl");
    let expected: Vec<Row> = vec![
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            "expected first complete record to be a checkpoint".to_owned(),
        ),
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            format!("loss seq 4 first 3 count 1; digest {A1_DIGEST}"),
        ),
        (
            K::SeqGap,
            Some(s1.clone()),
            Some(1),
            Some(4),
            "missing seq 3..=3".to_owned(),
        ),
        (
            K::BadSignature,
            Some(s1),
            Some(2),
            Some(5),
            format!("key {FIXTURE_KEY_HEX}"),
        ),
        (
            K::Resumed,
            Some(live),
            Some(2),
            Some(7),
            resume_detail(5, cp5_bad.hash(), "none"),
        ),
        (K::UncoveredTail, None, None, None, uncovered_tail(0, 7)),
    ];
    assert_rows(&findings, &expected, "A9");
}

// =====================================================================
// A10 — bad signature on an in-run checkpoint of an A3-style two-range
// layout (cp8 is a run member sealed in S2). Acceptance row that pins
// M7 / M7′ (skip checkpoints that are members of a run) with its second
// named runtime kill: both A9 and A10 lose their main `BadSignature`
// finding if the pass drops in-run candidates.
// =====================================================================
#[test]
fn a10_in_run_bad_signature_on_a3_style_closing_checkpoint() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let mmr2 = pushed(&mmr1, &cp2);
    let r4 = headless(&cp2, 4);
    let mmr4 = pushed(&mmr2, &r4);
    let cp5 = signed_cp(5, r4.hash(), &mmr4);
    put_segment(&d.0, 1, &[&r4, &cp5], &[]);
    let mmr5 = pushed(&mmr4, &cp5);
    let r7 = headless(&cp5, 7);
    let mmr7 = pushed(&mmr5, &r7);
    let cp8 = signed_cp(8, r7.hash(), &mmr7);
    let cp8_bad = flip_signature_byte(&cp8);
    put_segment(&d.0, 2, &[&r7, &cp8_bad], &[]);
    let mmr8 = pushed(&mmr7, &cp8_bad);
    let cp10 = signed_cp(10, cp8_bad.hash(), &mmr8);
    let resume = resume_decl(&cp10, 8, cp8_bad.hash(), 9);
    write_records(&d.0, &[&cp10, &resume]);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .build()
        .unwrap();
    let findings = Verifier::new(trust)
        .verify_dir(&d.0)
        .unwrap()
        .findings()
        .to_vec();
    let s1 = segment_path(&d.0, 1);
    let s2 = segment_path(&d.0, 2);
    let live = d.0.join("audit.jsonl");
    // Dynamic digests are stable across runs because every fixture
    // field is deterministic; captured literally here so a drift in
    // `run_digest` or the signing message bytes flips the row.
    let a3_digest_line =
        "loss seq 4 first 3 count 1; loss seq 7 first 6 count 1; digest blake3:78d5088883d54faa6aefe350948c217bb5ef3c32a468f22184bc07e56d84c63d"
            .to_owned();
    let expected: Vec<Row> = vec![
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            "expected first complete record to be a checkpoint".to_owned(),
        ),
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            a3_digest_line,
        ),
        (
            K::SeqGap,
            Some(s1),
            Some(1),
            Some(4),
            "missing seq 3..=3".to_owned(),
        ),
        (
            K::SegmentStructure,
            Some(s2.clone()),
            Some(1),
            Some(7),
            "expected first complete record to be a checkpoint".to_owned(),
        ),
        (
            K::SeqGap,
            Some(s2.clone()),
            Some(1),
            Some(7),
            "missing seq 6..=6".to_owned(),
        ),
        (
            K::BadSignature,
            Some(s2),
            Some(2),
            Some(8),
            format!("key {FIXTURE_KEY_HEX}"),
        ),
        (
            K::SeqGap,
            Some(live.clone()),
            Some(1),
            Some(10),
            "missing seq 9..=9".to_owned(),
        ),
        (
            K::Resumed,
            Some(live),
            Some(2),
            Some(11),
            resume_detail(8, cp8_bad.hash(), "9..=9"),
        ),
        (K::UncoveredTail, None, None, None, uncovered_tail(0, 11)),
    ];
    assert_rows(&findings, &expected, "A10");
}

// =====================================================================
// F1 — fork-flipped: honest native cp2 + shipped cp2 copy holding a
// DIFFERENT cp2 whose signature is flipped (different record hash).
// Acceptance row. Together with F2 pins:
//   - X1 ("every finding at copies[0].0"): the `BadSignature` here must
//     land on the shipped file, not the native one that `copies[0]`
//     sorts to.
//   - X3 (`candidates.iter().take(1)`): the flipped candidate has the
//     higher record hash of the two (so BTreeMap orders it second),
//     so dropping candidates[1..] would drop this `BadSignature`.
// =====================================================================
#[test]
fn f1_fork_flipped_reports_bad_signature_at_shipped_path() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2_honest = signed_cp(2, e1.hash(), &mmr1);
    let cp2_flipped = flip_signature_byte(&cp2_honest);
    // Deterministic from the fixture: the flipped record hash is
    // greater, so BTreeMap<hash, _> orders [honest, flipped]. If this
    // ever flipped, `take(1)` under X3 would no longer drop the flipped
    // candidate; the `assert!` here catches that drift before the
    // row misleads.
    assert!(
        cp2_honest.hash() < cp2_flipped.hash(),
        "fixture no longer orders honest before flipped",
    );
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2_honest], &[]);
    let native = segment_path(&d.0, 0);
    let shipped = d.0.join("cp2.shipped");
    std::fs::write(&shipped, line_bytes(&cp2_flipped)).unwrap();
    let findings = verify_files_with(
        vec![native.clone(), shipped.clone()],
        trust_with_key(fixture_pubkey()),
    );
    let expected: Vec<Row> = vec![
        (
            K::SeqConflict,
            Some(native),
            Some(3),
            Some(2),
            format!(
                "conflicting hashes: {}, {}",
                digest_string(&cp2_honest.hash()),
                digest_string(&cp2_flipped.hash()),
            ),
        ),
        (
            K::BadSignature,
            Some(shipped),
            Some(1),
            Some(2),
            format!("key {FIXTURE_KEY_HEX}"),
        ),
        (K::UncoveredTail, None, None, None, uncovered_tail(0, 2)),
    ];
    assert_rows(&findings, &expected, "F1");
}

// =====================================================================
// F2 — fork-unlisted: honest native cp2 + shipped cp2 copy holding a
// DIFFERENT cp2 validly signed by the unlisted key `0x55`. Acceptance
// row. Pairs with F1 to pin X1 and X3 (see F1 header) with a second
// kill each via `UntrustedKey` instead of `BadSignature`.
// =====================================================================
#[test]
fn f2_fork_unlisted_reports_untrusted_at_shipped_path() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2_honest = signed_cp(2, e1.hash(), &mmr1);
    let alt = alt_signer();
    let cp2_unlisted = sign_as(&alt, 2, e1.hash(), &mmr1);
    // Same fixture-level invariant as F1: the unlisted-signed record
    // hash is strictly greater than the honest one, so the X3 mutant
    // deterministically drops the UntrustedKey finding.
    assert!(
        cp2_honest.hash() < cp2_unlisted.hash(),
        "fixture no longer orders honest before unlisted",
    );
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2_honest], &[]);
    let native = segment_path(&d.0, 0);
    let shipped = d.0.join("cp2.shipped");
    std::fs::write(&shipped, line_bytes(&cp2_unlisted)).unwrap();
    let findings = verify_files_with(
        vec![native.clone(), shipped.clone()],
        trust_with_key(fixture_pubkey()),
    );
    let expected: Vec<Row> = vec![
        (
            K::SeqConflict,
            Some(native),
            Some(3),
            Some(2),
            format!(
                "conflicting hashes: {}, {}",
                digest_string(&cp2_honest.hash()),
                digest_string(&cp2_unlisted.hash()),
            ),
        ),
        (
            K::UntrustedKey,
            Some(shipped),
            Some(1),
            Some(2),
            format!("key {ALT_KEY_HEX} not listed for trail {TRAIL_HEX}"),
        ),
        (K::UncoveredTail, None, None, None, uncovered_tail(0, 2)),
    ];
    assert_rows(&findings, &expected, "F2");
}

// =====================================================================
// R1 — acceptance row (reclassified): the same checkpoint byte-identical
// in a native segment and a shipped copy with a flipped signature yields
// exactly ONE `BadSignature` at the first-occurrence native path the
// engine's merge keeps (one `(seq, hash)` candidate). R1 fails on base
// (base stubs the signature pass to a no-op, so no `BadSignature` is
// emitted and the literal list below doesn't match); it is the second
// named kill for M6 (one finding per occurrence) alongside R1b.
// =====================================================================
#[test]
fn r1_byte_identical_native_and_shipped_yields_one_bad_signature() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let bad = flip_signature_byte(&cp2);
    put_segment(&d.0, 0, &[&cp0, &e1, &bad], &[]);
    let native = segment_path(&d.0, 0);
    let shipped = d.0.join("copy");
    std::fs::copy(&native, &shipped).unwrap();
    let findings = verify_files_with(
        vec![native.clone(), shipped.clone()],
        trust_with_key(fixture_pubkey()),
    );
    let expected: Vec<Row> = vec![
        (
            K::DuplicateRecord,
            Some(native.clone()),
            Some(1),
            Some(0),
            "2 copies of 1 distinct records".to_owned(),
        ),
        (
            K::DuplicateRecord,
            Some(native.clone()),
            Some(2),
            Some(1),
            "2 copies of 1 distinct records".to_owned(),
        ),
        (
            K::BadSignature,
            Some(native.clone()),
            Some(3),
            Some(2),
            format!("key {FIXTURE_KEY_HEX}"),
        ),
        (
            K::DuplicateRecord,
            Some(native),
            Some(3),
            Some(2),
            "2 copies of 1 distinct records".to_owned(),
        ),
        (K::UncoveredTail, None, None, None, uncovered_tail(0, 2)),
    ];
    assert_rows(&findings, &expected, "R1");
}

// =====================================================================
// R1b — acceptance row (reclassified): three byte-identical copies
// (native + two shipped) of the flipped-signature cp2 still yield
// exactly ONE `BadSignature`. Pairs with R1 to give M6 (one finding per
// occurrence) its two named runtime kills.
// =====================================================================
#[test]
fn r1b_triplicate_copies_yield_one_bad_signature() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let bad = flip_signature_byte(&cp2);
    put_segment(&d.0, 0, &[&cp0, &e1, &bad], &[]);
    let native = segment_path(&d.0, 0);
    let a = d.0.join("copy-a");
    let b = d.0.join("copy-b");
    std::fs::copy(&native, &a).unwrap();
    std::fs::copy(&native, &b).unwrap();
    let findings = verify_files_with(vec![native.clone(), a, b], trust_with_key(fixture_pubkey()));
    let expected: Vec<Row> = vec![
        (
            K::DuplicateRecord,
            Some(native.clone()),
            Some(1),
            Some(0),
            "3 copies of 1 distinct records".to_owned(),
        ),
        (
            K::DuplicateRecord,
            Some(native.clone()),
            Some(2),
            Some(1),
            "3 copies of 1 distinct records".to_owned(),
        ),
        (
            K::BadSignature,
            Some(native.clone()),
            Some(3),
            Some(2),
            format!("key {FIXTURE_KEY_HEX}"),
        ),
        (
            K::DuplicateRecord,
            Some(native),
            Some(3),
            Some(2),
            "3 copies of 1 distinct records".to_owned(),
        ),
        (K::UncoveredTail, None, None, None, uncovered_tail(0, 2)),
    ];
    assert_rows(&findings, &expected, "R1b");
}

// =====================================================================
// R2 — REGRESSION row. Honest multi-segment A1 trail with a resume,
// key bounded through the live opening `cp6`. Under production, every
// checkpoint is trusted and the signature pass emits NO `BadSignature`
// / `UntrustedKey`. Passes on base (base emits no signature findings
// anyway). The full literal finding list below is unchanged from the
// honest A1, and additional predicate assertions pin M2 (bound exactly
// at `through=`) and M8 (predicate ignores signature) with ≥ 2 named
// runtime kills.
// =====================================================================
#[test]
fn r2_honest_bounded_at_head_has_no_signature_findings_and_head_is_trusted() {
    let a1 = build_a1();
    let cp6 = a1.cp6_head;
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), cp6.seq, cp6.hash)
        .build()
        .unwrap();
    let findings = Verifier::new(trust.clone())
        .verify_dir(&a1.dir_path)
        .unwrap()
        .findings()
        .to_vec();
    // cp5's hash lives in the confirmed snapshot (cp6.previous = cp5.hash);
    // read it from the collection so the literal `Resumed` detail below
    // doesn't need a second accessor on the fixture.
    let collection = input::collect([a1.dir_path.clone()]).unwrap();
    let cp5_hash = collection
        .inputs
        .iter()
        .flat_map(|i| i.data.records.iter())
        .find(|r| r.seq == 5)
        .expect("cp5 must appear in the A1 confirmed snapshot")
        .hash;
    let s1 = segment_path(&a1.dir_path, 1);
    let live = a1.dir_path.join("audit.jsonl");
    let expected: Vec<Row> = vec![
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            "expected first complete record to be a checkpoint".to_owned(),
        ),
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            format!("loss seq 4 first 3 count 1; digest {A1_DIGEST}"),
        ),
        (
            K::SeqGap,
            Some(s1),
            Some(1),
            Some(4),
            "missing seq 3..=3".to_owned(),
        ),
        (
            K::Resumed,
            Some(live),
            Some(2),
            Some(7),
            resume_detail(5, cp5_hash, "none"),
        ),
        (K::UncoveredTail, None, None, None, uncovered_tail(0, 7)),
    ];
    assert_rows(&findings, &expected, "R2");
    // Predicate M2: cp6 at exactly `through=` must be trusted.
    let cp6_summary = collection
        .inputs
        .iter()
        .flat_map(|i| i.data.records.iter())
        .find(|r| r.seq == cp6.seq && r.hash == cp6.hash)
        .expect("cp6 must appear in the A1 confirmed snapshot");
    assert!(
        trusted(TRAIL, &trust, cp6_summary),
        "cp6 at exactly through= must be trusted per ruling 13-V5-d1 point 3",
    );
    // Predicate M8: a flipped-signature shipped cp2 is `!trusted` even
    // with the listed-key policy.
    let fx = two_checkpoints();
    let bad = flip_signature_byte(&fx.cp2);
    let shipped = fx._dir.0.join("bad.copy");
    std::fs::write(&shipped, line_bytes(&bad)).unwrap();
    let bad_collection = input::collect([shipped]).unwrap();
    let bad_cp2 = bad_collection
        .inputs
        .iter()
        .flat_map(|i| i.data.records.iter())
        .find(|r| r.seq == 2)
        .expect("cp2 shipped copy");
    let listing_trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .build()
        .unwrap();
    assert!(!trusted(TRAIL, &listing_trust, bad_cp2));
}

// =====================================================================
// Direct predicate test (new API; does not compile on base). Pins
// ruling 13-V5-d1 point 3 directly (kills M8 and M2).
// =====================================================================
#[test]
fn trusted_predicate_requires_signature_and_key_trust() {
    let fx = two_checkpoints();
    let collection = input::collect([fx.path.clone()]).unwrap();
    let records: Vec<_> = collection
        .inputs
        .iter()
        .flat_map(|i| i.data.records.iter())
        .collect();
    let cp0_summary = records.iter().find(|r| r.seq == 0).unwrap();
    let cp2_summary = records.iter().find(|r| r.seq == 2).unwrap();
    let full = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .build()
        .unwrap();
    // Honest: both trusted by the listed unbounded key.
    assert!(trusted(TRAIL, &full, cp0_summary));
    assert!(trusted(TRAIL, &full, cp2_summary));
    // M8 (predicate ignoring signature): rebuild cp2 with a flipped
    // signature; predicate must say false even with listed key.
    let bad_cp2 = flip_signature_byte(&fx.cp2);
    put_segment(&fx._dir.0, 0, &[&fx.cp0, &fx.e1, &bad_cp2], &[]);
    let collection = input::collect([fx.path.clone()]).unwrap();
    let records: Vec<_> = collection
        .inputs
        .iter()
        .flat_map(|i| i.data.records.iter())
        .collect();
    let bad_cp2_summary = records.iter().find(|r| r.seq == 2).unwrap();
    assert!(!trusted(TRAIL, &full, bad_cp2_summary));
    // Restore cp2's honest bytes for the bound case.
    put_segment(&fx._dir.0, 0, &[&fx.cp0, &fx.e1, &fx.cp2], &[]);
    let collection = input::collect([fx.path.clone()]).unwrap();
    let records: Vec<_> = collection
        .inputs
        .iter()
        .flat_map(|i| i.data.records.iter())
        .collect();
    let cp0_summary = records.iter().find(|r| r.seq == 0).unwrap();
    let cp2_summary = records.iter().find(|r| r.seq == 2).unwrap();
    // M2 (`<=` → `<`): cp0 is EXACTLY at the bound and must be trusted.
    let bound = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, fx.cp0.hash())
        .build()
        .unwrap();
    assert!(
        trusted(TRAIL, &bound, cp0_summary),
        "cp0 at the bound is trusted"
    );
    assert!(
        !trusted(TRAIL, &bound, cp2_summary),
        "cp2 above the bound is not"
    );
    // `check` is called from every verifier-level row above through
    // `engine::check`; this reference keeps symbol-use parity with
    // the public pass for the test binary.
    let _ = check;
}

// =====================================================================
// Predicate test: a flipped signature on a shipped-only checkpoint with
// the key listed is still `!trusted`. Pairs with
// `trusted_predicate_requires_signature_and_key_trust` (kills M8).
// =====================================================================
#[test]
fn trusted_predicate_rejects_shipped_only_bad_signature() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let bad = flip_signature_byte(&cp2);
    let shipped = d.0.join("cp2.copy");
    std::fs::write(&shipped, line_bytes(&bad)).unwrap();
    let collection = input::collect([shipped]).unwrap();
    let records: Vec<_> = collection
        .inputs
        .iter()
        .flat_map(|i| i.data.records.iter())
        .collect();
    let cp2_summary = records.iter().find(|r| r.seq == 2).unwrap();
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .build()
        .unwrap();
    assert!(!trusted(TRAIL, &trust, cp2_summary));
}

// =====================================================================
// Sanity: an unpinned trail errors before the signature pass runs.
// =====================================================================
#[test]
fn unpinned_trail_errors_before_signature_pass_runs() {
    let other: [u8; 16] = [0x33; 16];
    let trust = TrustPolicy::builder().trail(other).build().unwrap();
    let err = Verifier::new(trust).trail(TRAIL).map(|_| ()).unwrap_err();
    assert_eq!(err.kind(), AuditErrorKind::InvalidConfig);
}

// =====================================================================
// Consistency check on the key and trail literals every row's detail
// uses: if these drift from the fixture bytes, every A1-A10 / F1-F2 row
// would fail confusingly on the hex substring. Spelling them both ways
// lands any such drift here instead.
// =====================================================================
#[test]
fn fixture_pubkey_matches_the_literal_hex_in_details() {
    assert_eq!(hex(&fixture_pubkey()), FIXTURE_KEY_HEX);
    assert_eq!(hex(&alt_signer().public_key()), ALT_KEY_HEX);
    assert_eq!(hex(&TRAIL), TRAIL_HEX);
}
