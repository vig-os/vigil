//! Verifier-level rows for `BadSignature` / `UntrustedKey` and the
//! crate-private `trusted` predicate (ADR-0005 decisions 8 and 9,
//! ruling 13-V5-d1 points 1-3).
//!
//! Row standard (repo-wide): every acceptance row asserts the FULL
//! sorted literal finding list, compared as whole [`Finding`] values
//! (every field: kind, file, line, seq, detail, `accepted_kind`,
//! `run_digest`). The comparison helper [`assert_findings`] is a thin
//! wrapper around `assert_eq!` on `Vec<Finding>` so a drift in the
//! dropped-field mutant (for example a run finding losing its
//! `run_digest`) reddens the row. Regression rows (R2) are labelled
//! in their doc comments; predicate tests (A4b, A8b, Y1b and the two
//! `trusted_predicate_...` rows) are labelled as predicate tests.
//!
//! Every signed checkpoint carries the shared fixture key `0x27`; its
//! public key is spelled out literally as [`FIXTURE_KEY_HEX`] so a drift
//! in the captured bytes fails the row assertion. Keys for crafted
//! unlisted / small-order / bounded-only scenarios appear in
//! [`ALT_KEY_HEX`] and [`IDENTITY_KEY_HEX`]. Every record-hash digest
//! that lands in an expected `Finding::detail` is a written-out hex
//! constant ([`CP2_HONEST_DIGEST`] ...), never computed from the fixture
//! or from the code under test. A companion test
//! [`fixture_hashes_match_literals`] pins each literal to the record
//! the fixtures produce.

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
use std::path::PathBuf;

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

/// Record hash (`blake3:<hex>`) of the honest cp2 the shared `two_checkpoints`
/// / fork fixtures produce (seq=2, `previous=e1.hash()`, fixture-key signed
/// at honest fold `mmr1`). Appears in F1 and F2's `SeqConflict` detail.
const CP2_HONEST_DIGEST: &str =
    "blake3:4164966a12a675e55eb6e133b9e50313907f164fe142d941447defcdfdb25d06";
/// Record hash of the flipped-signature cp2 that F1 ships beside the honest
/// one (one byte of the honest signature XORed with `0x01`).
const CP2_FLIPPED_DIGEST: &str =
    "blake3:6cd338542f05123f02d86b51c67a880924320e64ef06f9fc1c7aed0ae7c5925d";
/// Record hash of F2's shipped cp2 copy, validly signed by unlisted key
/// `0x55` over the same honest fold.
const CP2_UNLISTED_DIGEST: &str =
    "blake3:8f71deebb1a2b11df8703bc9210730f478d3f5f0688e042b9469a5bf4eaaba33";
/// Record hash of the honest cp5 opening checkpoint in `runs_v4a_fixtures::build_a1`.
/// Appears in R2's `Resumed` detail (`head=5:<this>`).
const CP5_A1_DIGEST: &str =
    "blake3:4181d394847e4274645a1b39a8366b0217c32abc5ab45e4dbee9f064c25361aa";
/// Record hash of A9's cp5 after flipping its signature (sealed-run opening
/// cp5 under A1-style layout). Appears in A9's `Resumed` detail.
const CP5_A9_BAD_DIGEST: &str =
    "blake3:5aaa6866c59ceff7c8150206e7c244e5ae23af426a531b937ec8469cdf2e96cd";
/// Record hash of A10's cp8 after flipping its signature (sealed-run opening
/// cp8 under A3-style two-range layout). Appears in A10's `Resumed` detail.
const CP8_A10_BAD_DIGEST: &str =
    "blake3:0f853869e6f11781afe571f046d324ac56f1a8d4e3a8edf9b5e5450cca601d2f";

/// Raw bytes of `A1_DIGEST` (fold-level run digest for A9's single-range run
/// and for the honest A1 trail reused by R2). Written out so the dropped
/// `run_digest` mutant reddens the row through the whole-`Finding` equality.
const A1_RUN_DIGEST_BYTES: [u8; 32] = [
    0x79, 0xd8, 0xcb, 0x1c, 0x4d, 0xfc, 0x89, 0xa8, 0x0a, 0x49, 0x11, 0x12, 0x02, 0x80, 0xe6, 0x3e,
    0xd3, 0x83, 0x10, 0x8f, 0x31, 0x99, 0xf0, 0x52, 0x91, 0xbc, 0xb5, 0x1f, 0x62, 0x5f, 0x39, 0x31,
];
/// Raw bytes of the A3-style two-range run digest used by A10's fold finding
/// (`78d50…c63d`).
const A3_RUN_DIGEST_BYTES: [u8; 32] = [
    0x78, 0xd5, 0x08, 0x88, 0x83, 0xd5, 0x4f, 0xaa, 0x6a, 0xef, 0xe3, 0x50, 0x94, 0x8c, 0x21, 0x7b,
    0xb5, 0xef, 0x3c, 0x32, 0xa4, 0x68, 0xf2, 0x21, 0x84, 0xbc, 0x07, 0xe5, 0x6d, 0x84, 0xc6, 0x3d,
];

/// `UncoveredTail` detail for a `first..=last` range (ADR-0005 l.400-407;
/// ruling 13-V5-d1 point 6).
fn uncovered_tail(first: u64, last: u64) -> String {
    format!("records seq {first}..={last}")
}

/// `Resumed` detail (ruling 13-V3-d5; same reason+gap shape for every
/// resume this test module builds via `resume_decl`). `head_hash` is a
/// pre-formatted `blake3:<hex>` literal so the Resumed detail carries no
/// hash computed from the record under test.
fn resume_detail(head_seq: u64, head_hash: &str, gap: &str) -> String {
    format!(
        "operator=operator reason=incident head={head_seq}:{head_hash} gap={gap} lost_records=0 structural=valid"
    )
}

/// Finding constructor for a located row (one `(kind, file, line, seq,
/// detail)` tuple). All located findings in this file go through here so
/// the whole-value equality in [`assert_findings`] is the sole assertion
/// surface on `check`'s output.
fn located(kind: K, file: PathBuf, line: u64, seq: u64, detail: String) -> Finding {
    Finding::new(kind, Some(file), Some(line), Some(seq), detail)
}

/// `UncoveredTail` finding (unlocated info).
fn uncovered(first: u64, last: u64) -> Finding {
    Finding::new(
        K::UncoveredTail,
        None,
        None,
        None,
        uncovered_tail(first, last),
    )
}

/// Asserts the full sorted literal finding list is exactly `expected`,
/// comparing whole [`Finding`] values (so a dropped `run_digest` or
/// `accepted_kind` reddens the row). This is the only way a row in this
/// file asserts on `check`'s output.
#[track_caller]
fn assert_findings(actual: &[Finding], expected: &[Finding], label: &str) {
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
// Does NOT kill M1: `verify_strict` → `verify` only separates on the
// small-order / non-canonical mutants (A4, A4b) — a bit-flipped Ed25519
// signature still fails legacy `verify`. Does NOT kill M7: cp2 lives in
// a single sealed segment ("member of a run" does not cover this layout);
// M7 and M7′'s named kills are the two in-run rows A9 and A10.
// =====================================================================
#[test]
fn a1_listed_key_flipped_signature_is_bad_signature_at_cp2() {
    let fx = two_checkpoints();
    let bad = flip_signature_byte(&fx.cp2);
    put_segment(&fx._dir.0, 0, &[&fx.cp0, &fx.e1, &bad], &[]);
    let findings = verify_files_with(vec![fx.path.clone()], trust_with_key(fixture_pubkey()));
    let expected = vec![
        located(
            K::BadSignature,
            fx.path.clone(),
            3,
            2,
            format!("key {FIXTURE_KEY_HEX}"),
        ),
        uncovered(1, 2),
    ];
    assert_findings(&findings, &expected, "A1");
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
    let expected = vec![
        located(
            K::UntrustedKey,
            path,
            3,
            2,
            format!("key {ALT_KEY_HEX} not listed for trail {TRAIL_HEX}"),
        ),
        uncovered(1, 2),
    ];
    assert_findings(&findings, &expected, "A2");
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
    // V5c (ruling 13-V5-d1 point 4): the bound is pinned at cp0 but
    // never confirmed (cp2 is signed by the same bounded key), so one
    // `RevocationUnconfirmed` at the bound's seq is added here.
    let expected = vec![
        Finding::new(
            K::RevocationUnconfirmed,
            Some(fx.path.clone()),
            Some(1),
            Some(0),
            format!(
                "key {FIXTURE_KEY_HEX} through=0: no trusted checkpoint by another key above the bound"
            ),
        ),
        located(
            K::UntrustedKey,
            fx.path.clone(),
            3,
            2,
            format!("key {FIXTURE_KEY_HEX} bounded through seq 0"),
        ),
        uncovered(1, 2),
    ];
    assert_findings(&findings, &expected, "A3");
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
    let expected = vec![
        located(
            K::BadSignature,
            fx.path.clone(),
            3,
            2,
            format!("key {IDENTITY_KEY_HEX}"),
        ),
        uncovered(1, 2),
    ];
    assert_findings(&findings, &expected, "A4");
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
    let expected = vec![
        located(
            K::BadSignature,
            fx.path.clone(),
            3,
            2,
            format!("key {FIXTURE_KEY_HEX}"),
        ),
        uncovered(1, 2),
    ];
    assert_findings(&findings, &expected, "A5");
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
    let expected = vec![
        located(
            K::BadSignature,
            path.clone(),
            3,
            2,
            format!("key {ALT_KEY_HEX}"),
        ),
        located(
            K::UntrustedKey,
            path,
            3,
            2,
            format!("key {ALT_KEY_HEX} not listed for trail {TRAIL_HEX}"),
        ),
        uncovered(1, 2),
    ];
    assert_findings(&findings, &expected, "A6");
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
    // V5c (ruling 13-V5-d1 point 4): the bound is pinned at cp0; cp2's
    // only candidate has a bad signature so it is not trusted and
    // cannot confirm the bound. One `RevocationUnconfirmed` is added.
    let expected = vec![
        Finding::new(
            K::RevocationUnconfirmed,
            Some(fx.path.clone()),
            Some(1),
            Some(0),
            format!(
                "key {FIXTURE_KEY_HEX} through=0: no trusted checkpoint by another key above the bound"
            ),
        ),
        located(
            K::BadSignature,
            fx.path.clone(),
            3,
            2,
            format!("key {FIXTURE_KEY_HEX}"),
        ),
        located(
            K::UntrustedKey,
            fx.path.clone(),
            3,
            2,
            format!("key {FIXTURE_KEY_HEX} bounded through seq 0"),
        ),
        uncovered(1, 2),
    ];
    assert_findings(&findings, &expected, "A6b");
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
    let expected = vec![
        located(
            K::BadSignature,
            shipped.clone(),
            1,
            2,
            format!("key {FIXTURE_KEY_HEX}"),
        ),
        located(K::SeqGap, shipped, 1, 2, "missing seq 0..=1".to_owned()),
        uncovered(2, 2),
    ];
    assert_findings(&findings, &expected, "A7");
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
    let expected = vec![
        located(
            K::SeqGap,
            shipped.clone(),
            1,
            2,
            "missing seq 0..=1".to_owned(),
        ),
        located(
            K::UntrustedKey,
            shipped,
            1,
            2,
            format!("key {ALT_KEY_HEX} not listed for trail {TRAIL_HEX}"),
        ),
        uncovered(2, 2),
    ];
    assert_findings(&findings, &expected, "A7b");
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
    let expected = vec![
        located(
            K::UntrustedKey,
            fx.path.clone(),
            1,
            0,
            format!("key {FIXTURE_KEY_HEX} not listed for trail {TRAIL_HEX}"),
        ),
        located(
            K::UntrustedKey,
            fx.path.clone(),
            3,
            2,
            format!("key {FIXTURE_KEY_HEX} not listed for trail {TRAIL_HEX}"),
        ),
        uncovered(0, 2),
    ];
    assert_findings(&findings, &expected, "A8");
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
// literal list and literal digest constants (the fold's A1 run digest
// lives in `SegmentStructure::run_digest`; the resume head hash is
// `CP5_A9_BAD_DIGEST`). Acceptance row. Together with A10 gives M7 (skip
// in-run checkpoints) and the new M7′ two named runtime kills; A1-A8,
// R1 and R1b are single-sealed-segment layouts WITHOUT a run so they do
// NOT kill M7.
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
    let expected = vec![
        located(
            K::ChainBroken,
            s1.clone(),
            1,
            4,
            format!(
                "expected previous {}, found {}",
                digest_string(&e2.hash()),
                digest_string(&r4.context.previous),
            ),
        ),
        located(
            K::SegmentStructure,
            s1.clone(),
            1,
            4,
            "expected first complete record to be a checkpoint".to_owned(),
        ),
        located(
            K::SegmentStructure,
            s1.clone(),
            1,
            4,
            format!("loss seq 4 first 3 count 1; digest {A1_DIGEST}"),
        )
        .with_run_digest(A1_RUN_DIGEST_BYTES),
        located(K::SeqGap, s1.clone(), 1, 4, "missing seq 3..=3".to_owned()),
        located(K::BadSignature, s1, 2, 5, format!("key {FIXTURE_KEY_HEX}")),
        located(
            K::Resumed,
            live,
            2,
            7,
            resume_detail(5, CP5_A9_BAD_DIGEST, "none"),
        ),
        uncovered(7, 7),
    ];
    assert_findings(&findings, &expected, "A9");
}

// =====================================================================
// A10 — bad signature on an in-run checkpoint of an A3-style two-range
// layout (cp8 is a run member sealed in S2). Acceptance row that pins
// M7 / M7′ (skip checkpoints that are members of a run) with its second
// named runtime kill: both A9 and A10 lose their main `BadSignature`
// finding if the pass drops in-run candidates. The fold's A3 run digest
// lives in `SegmentStructure::run_digest`; the resume head hash is
// `CP8_A10_BAD_DIGEST`.
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
    let a3_digest_line =
        "loss seq 4 first 3 count 1; loss seq 7 first 6 count 1; digest blake3:78d5088883d54faa6aefe350948c217bb5ef3c32a468f22184bc07e56d84c63d"
            .to_owned();
    let expected = vec![
        located(
            K::ChainBroken,
            s1.clone(),
            1,
            4,
            format!(
                "expected previous {}, found {}",
                digest_string(&cp2.hash()),
                digest_string(&r4.context.previous),
            ),
        ),
        located(
            K::SegmentStructure,
            s1.clone(),
            1,
            4,
            "expected first complete record to be a checkpoint".to_owned(),
        ),
        located(K::SegmentStructure, s1.clone(), 1, 4, a3_digest_line)
            .with_run_digest(A3_RUN_DIGEST_BYTES),
        located(K::SeqGap, s1, 1, 4, "missing seq 3..=3".to_owned()),
        located(
            K::ChainBroken,
            s2.clone(),
            1,
            7,
            format!(
                "expected previous {}, found {}",
                digest_string(&cp5.hash()),
                digest_string(&r7.context.previous),
            ),
        ),
        located(
            K::SegmentStructure,
            s2.clone(),
            1,
            7,
            "expected first complete record to be a checkpoint".to_owned(),
        ),
        located(K::SeqGap, s2.clone(), 1, 7, "missing seq 6..=6".to_owned()),
        located(K::BadSignature, s2, 2, 8, format!("key {FIXTURE_KEY_HEX}")),
        located(
            K::SeqGap,
            live.clone(),
            1,
            10,
            "missing seq 9..=9".to_owned(),
        ),
        located(
            K::Resumed,
            live,
            2,
            11,
            resume_detail(8, CP8_A10_BAD_DIGEST, "9..=9"),
        ),
        uncovered(11, 11),
    ];
    assert_findings(&findings, &expected, "A10");
}

// =====================================================================
// F1 — fork-flipped: honest native cp2 + shipped cp2 copy holding a
// DIFFERENT cp2 whose signature is flipped (different record hash).
// Acceptance row. Every hash in the `SeqConflict` detail is a literal
// `blake3:…` constant ([`CP2_HONEST_DIGEST`], [`CP2_FLIPPED_DIGEST`]).
// Together with F2 pins:
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
    let expected = vec![
        located(
            K::SeqConflict,
            native,
            3,
            2,
            format!("conflicting hashes: {CP2_HONEST_DIGEST}, {CP2_FLIPPED_DIGEST}"),
        ),
        located(
            K::BadSignature,
            shipped,
            1,
            2,
            format!("key {FIXTURE_KEY_HEX}"),
        ),
    ];
    assert_findings(&findings, &expected, "F1");
}

// =====================================================================
// F2 — fork-unlisted: honest native cp2 + shipped cp2 copy holding a
// DIFFERENT cp2 validly signed by the unlisted key `0x55`. Acceptance
// row with literal `blake3:…` digest constants in the `SeqConflict`
// detail. Pairs with F1 to pin X1 and X3 (see F1 header) with a second
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
    let expected = vec![
        located(
            K::SeqConflict,
            native,
            3,
            2,
            format!("conflicting hashes: {CP2_HONEST_DIGEST}, {CP2_UNLISTED_DIGEST}"),
        ),
        located(
            K::UntrustedKey,
            shipped,
            1,
            2,
            format!("key {ALT_KEY_HEX} not listed for trail {TRAIL_HEX}"),
        ),
    ];
    assert_findings(&findings, &expected, "F2");
}

// =====================================================================
// R1 — acceptance row: the same checkpoint byte-identical in a native
// segment and a shipped copy with a flipped signature yields exactly
// ONE `BadSignature` at the first-occurrence native path the engine's
// merge keeps (one `(seq, hash)` candidate). R1 fails on base (base
// stubs the signature pass to a no-op, so no `BadSignature` is emitted
// and the literal list below doesn't match); it is the second named
// kill for M6 (one finding per occurrence) alongside R1b.
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
    let expected = vec![
        located(
            K::DuplicateRecord,
            native.clone(),
            1,
            0,
            "2 copies of 1 distinct records".to_owned(),
        ),
        located(
            K::DuplicateRecord,
            native.clone(),
            2,
            1,
            "2 copies of 1 distinct records".to_owned(),
        ),
        located(
            K::BadSignature,
            native.clone(),
            3,
            2,
            format!("key {FIXTURE_KEY_HEX}"),
        ),
        located(
            K::DuplicateRecord,
            native,
            3,
            2,
            "2 copies of 1 distinct records".to_owned(),
        ),
        uncovered(1, 2),
    ];
    assert_findings(&findings, &expected, "R1");
}

// =====================================================================
// R1b — acceptance row: three byte-identical copies (native + two
// shipped) of the flipped-signature cp2 still yield exactly ONE
// `BadSignature`. Pairs with R1 to give M6 (one finding per occurrence)
// its two named runtime kills.
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
    let expected = vec![
        located(
            K::DuplicateRecord,
            native.clone(),
            1,
            0,
            "3 copies of 1 distinct records".to_owned(),
        ),
        located(
            K::DuplicateRecord,
            native.clone(),
            2,
            1,
            "3 copies of 1 distinct records".to_owned(),
        ),
        located(
            K::BadSignature,
            native.clone(),
            3,
            2,
            format!("key {FIXTURE_KEY_HEX}"),
        ),
        located(
            K::DuplicateRecord,
            native,
            3,
            2,
            "3 copies of 1 distinct records".to_owned(),
        ),
        uncovered(1, 2),
    ];
    assert_findings(&findings, &expected, "R1b");
}

// =====================================================================
// R2 — REGRESSION row. Honest multi-segment A1 trail with a resume,
// key bounded through the live opening `cp6`. Under production, every
// checkpoint is trusted and the signature pass emits NO `BadSignature`
// / `UntrustedKey`. Compiles and passes on the stubbed base (`check`
// is stubbed to a no-op; the honest A1 list below is identical to what
// base produces). Killed by M2 (`<=` → `<`: cp6 at exactly `through=`
// becomes untrusted, so coverage moves and the row's coverage changes
// — the predicate assertion `trusted(cp6) == true` reddens) and by M8
// (predicate ignores the signature: `!trusted(bad cp2)` flips). All
// hashes in the expected list are literal constants ([`CP5_A1_DIGEST`]
// and the A1 run digest bytes).
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
    let s1 = segment_path(&a1.dir_path, 1);
    let live = a1.dir_path.join("audit.jsonl");
    let expected = vec![
        located(
            K::ChainBroken,
            s1.clone(),
            1,
            4,
            format!(
                "expected previous {}, found {}",
                digest_string(&a1.e2_hash),
                digest_string(&a1.r4_previous),
            ),
        ),
        located(
            K::SegmentStructure,
            s1.clone(),
            1,
            4,
            "expected first complete record to be a checkpoint".to_owned(),
        ),
        located(
            K::SegmentStructure,
            s1.clone(),
            1,
            4,
            format!("loss seq 4 first 3 count 1; digest {A1_DIGEST}"),
        )
        .with_run_digest(A1_RUN_DIGEST_BYTES),
        located(K::SeqGap, s1, 1, 4, "missing seq 3..=3".to_owned()),
        // V5c (ruling 13-V5-d1 point 4): cp6 is bound exactly and
        // pinned; no checkpoint above the bound is signed by another
        // key, so the bound is unconfirmed. The live cp6 sits at line 1.
        Finding::new(
            K::RevocationUnconfirmed,
            Some(live.clone()),
            Some(1),
            Some(6),
            format!(
                "key {FIXTURE_KEY_HEX} through=6: no trusted checkpoint by another key above the bound"
            ),
        ),
        located(
            K::Resumed,
            live,
            2,
            7,
            resume_detail(5, CP5_A1_DIGEST, "none"),
        ),
        uncovered(7, 7),
    ];
    assert_findings(&findings, &expected, "R2");
    // Predicate M2: cp6 at exactly `through=` must be trusted. Separate
    // from the literal finding equality above per the row standard --
    // this is a predicate pin, not a comparison on `check`'s output.
    let collection = input::collect([a1.dir_path.clone()]).unwrap();
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
// ruling 13-V5-d1 point 3 directly (kills M8 and M2) and the Y1 mutant
// (`trusted` using `listed` instead of `trusted_at`, which ignores
// `through=`): when cp2 is above the bound, `trusted` must be false
// though `listed` is true.
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
    // Y1 (predicate uses `listed` instead of `trusted_at`): cp2 is
    // listed but above the bound, so `trusted` must be false.
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
// Y1b — predicate test (new API; does not compile on base). Second
// named kill for the Y1 mutant: a `through=` bound STRICTLY BELOW the
// checkpoint's `seq` means `listed(key) == true` while `trusted_at(key,
// seq) == false`, so a Y1-mutated `trusted` (which would call `listed`
// instead of `trusted_at`) wrongly reports `true` and this assertion
// flips.
// =====================================================================
#[test]
fn y1b_trusted_predicate_rejects_key_bounded_below_checkpoint_seq() {
    let fx = two_checkpoints();
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, fx.cp0.hash())
        .build()
        .unwrap();
    let collection = input::collect([fx.path.clone()]).unwrap();
    let cp2_summary = collection
        .inputs
        .iter()
        .flat_map(|i| i.data.records.iter())
        .find(|r| r.seq == 2)
        .expect("cp2 in the honest two-checkpoint fixture");
    // cp2 is honestly signed by the listed fixture key but its `seq`
    // exceeds the key's `through=0` bound: the predicate is false.
    assert!(!trusted(TRAIL, &trust, cp2_summary));
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
// Consistency check on the key, trail and record-hash literals every
// row's detail uses. A drift in the captured bytes lands here instead
// of in a confusing per-row digest mismatch. The record-hash constants
// (`CP2_*_DIGEST`, `CP5_*_DIGEST`, `CP8_A10_BAD_DIGEST`) stay OUT of
// the row literals' expected values and are pinned here to the
// fixture-produced records.
// =====================================================================
#[test]
fn fixture_hashes_match_literals() {
    assert_eq!(hex(&fixture_pubkey()), FIXTURE_KEY_HEX);
    assert_eq!(hex(&alt_signer().public_key()), ALT_KEY_HEX);
    assert_eq!(hex(&TRAIL), TRAIL_HEX);
    // Two-checkpoint / fork fixtures.
    let fx = two_checkpoints();
    let cp2_flipped = flip_signature_byte(&fx.cp2);
    let signer = alt_signer();
    let mmr0 = seeded(&fx.cp0);
    let mmr1 = pushed(&mmr0, &fx.e1);
    let cp2_unlisted = sign_as(&signer, 2, fx.e1.hash(), &mmr1);
    assert_eq!(digest_string(&fx.cp2.hash()), CP2_HONEST_DIGEST);
    assert_eq!(digest_string(&cp2_flipped.hash()), CP2_FLIPPED_DIGEST);
    assert_eq!(digest_string(&cp2_unlisted.hash()), CP2_UNLISTED_DIGEST);
    // A1-style honest cp5 (reused by R2) and A9's flipped cp5.
    let a1 = build_a1();
    let collection = input::collect([a1.dir_path.clone()]).unwrap();
    let cp5_hash = collection
        .inputs
        .iter()
        .flat_map(|i| i.data.records.iter())
        .find(|r| r.seq == 5)
        .expect("cp5 in the A1 confirmed snapshot")
        .hash;
    assert_eq!(digest_string(&cp5_hash), CP5_A1_DIGEST);
    // A9's cp5_bad has the honest A1 layout with a flipped cp5 signature.
    {
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
        assert_eq!(digest_string(&cp5_bad.hash()), CP5_A9_BAD_DIGEST);
    }
    // A10's cp8_bad has the A3-style two-range layout with a flipped cp8.
    {
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
        assert_eq!(digest_string(&cp8_bad.hash()), CP8_A10_BAD_DIGEST);
    }
    // Run-digest constants (byte form) decode to the published `blake3:…`
    // strings used in the detail text.
    assert_eq!(digest_string(&A1_RUN_DIGEST_BYTES), A1_DIGEST);
    assert_eq!(
        digest_string(&A3_RUN_DIGEST_BYTES),
        "blake3:78d5088883d54faa6aefe350948c217bb5ef3c32a468f22184bc07e56d84c63d",
    );
}
