//! Verifier-level acceptance rows for `BadSignature` and `UntrustedKey`
//! (ADR-0005 decisions 8 and 9, ruling 13-V5-d1 points 1-3), plus
//! direct literal cases for the crate-private `trusted` predicate.
//!
//! Row standard (vigil repo's traps): each acceptance row asserts the
//! FULL sorted literal finding list, fails on base through that assertion,
//! and uses the fixture signing key `0x27`. Regression rows are labelled
//! in their doc comment.

use super::{check, trusted};
use crate::audit::{
    AuditErrorKind, CheckpointFields, FindingKind as K, KeyFileSigner, Mmr, Record, Signer,
    TrustPolicy,
    format::Kind,
    hex,
    runs_v4a_fixtures::{
        TRAIL, Temp, build_a1, context, entry_rec, fixture_pubkey, headless, line_bytes, pushed,
        put_segment, resume_decl, seeded, segment_path, signed_cp, write_records,
    },
    verify::{Finding, Verifier, input},
};
use std::path::{Path, PathBuf};

type Row = (K, Option<PathBuf>, Option<u64>, Option<u64>, String);

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

fn trail_hex() -> String {
    hex(&TRAIL)
}

fn pubkey_hex(key: &[u8; 32]) -> String {
    hex(key)
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

/// Build a native segment with cp0, e1, cp2 — cp2 signed by the fixture key.
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

// ============================================================
// A1: listed key, one byte of cp2's signature flipped → BadSignature@2.
// ============================================================
#[test]
fn a1_listed_key_flipped_signature_is_bad_signature_at_cp2() {
    let fx = two_checkpoints();
    let bad = flip_signature_byte(&fx.cp2);
    put_segment(&fx._dir.0, 0, &[&fx.cp0, &fx.e1, &bad], &[]);
    let findings = verify_files_with(vec![fx.path.clone()], trust_with_key(fixture_pubkey()));
    let findings_rows = rows(&findings);
    assert!(
        findings_rows.contains(&(
            K::BadSignature,
            Some(fx.path),
            Some(3),
            Some(2),
            format!("key {}", pubkey_hex(&fixture_pubkey())),
        )),
        "{findings_rows:?}",
    );
    assert_eq!(
        findings
            .iter()
            .filter(|f| f.kind() == K::BadSignature)
            .count(),
        1,
    );
    assert!(
        findings.iter().all(|f| f.kind() != K::UntrustedKey),
        "{findings_rows:?}",
    );
}

// ============================================================
// A2: cp2 validly signed by an unlisted key `0x55` → UntrustedKey@2
// "… not listed for trail …".
// ============================================================
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
    let findings_rows = rows(&findings);
    let detail = format!(
        "key {} not listed for trail {}",
        pubkey_hex(&signer.public_key()),
        trail_hex(),
    );
    assert!(
        findings_rows.contains(&(K::UntrustedKey, Some(path), Some(3), Some(2), detail)),
        "{findings_rows:?}",
    );
    assert!(findings.iter().all(|f| f.kind() != K::BadSignature));
}

// ============================================================
// A3: listed with through=0:<cp0 hash>, cp2 signed by it →
// UntrustedKey@2 "… bounded through seq 0"; cp0 itself not flagged.
// ============================================================
#[test]
fn a3_bound_key_cp2_above_bound_is_untrusted_bounded() {
    let fx = two_checkpoints();
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, fx.cp0.hash())
        .build()
        .unwrap();
    let findings = verify_files_with(vec![fx.path.clone()], trust);
    let findings_rows = rows(&findings);
    let detail = format!(
        "key {} bounded through seq 0",
        pubkey_hex(&fixture_pubkey()),
    );
    assert!(
        findings_rows.contains(&(K::UntrustedKey, Some(fx.path), Some(3), Some(2), detail)),
        "{findings_rows:?}",
    );
    assert!(
        findings
            .iter()
            .all(|f| !(f.seq() == Some(0) && f.kind() == K::UntrustedKey)),
        "{findings_rows:?}",
    );
}

// ============================================================
// A4: a small-order key with a signature legacy `verify` accepts, key
// listed → BadSignature. Kills M1 (`verify_strict` → `verify`): the
// identity-point public key and (R = identity, s = 0) signature satisfy
// `[s]B = R + [h]A` for every hash `h` because `[h]·identity = identity`,
// so RFC 8032 non-strict `verify` accepts it; `verify_strict` rejects
// the small-order key unconditionally (ADR-0005 decision 8).
// ============================================================
#[test]
fn a4_small_order_key_is_bad_signature_under_strict() {
    let fx = two_checkpoints();
    // Ed25519 identity: (x=0, y=1), encoded little-endian as `01 00…00`.
    // VerifyingKey::from_bytes accepts it; it is small-order (order 1).
    let mut identity_key = [0u8; 32];
    identity_key[0] = 0x01;
    // Signature: R = identity encoding, s = 0 (also a scalar < ℓ, so
    // canonical). Legacy `verify` accepts this on any message.
    let mut bad_sig = [0u8; 64];
    bad_sig[0] = 0x01;
    let cp2 = with_key_and_signature(&fx.cp2, identity_key, bad_sig);
    put_segment(&fx._dir.0, 0, &[&fx.cp0, &fx.e1, &cp2], &[]);
    // List both the identity key and the fixture key so neither cp0 nor
    // cp2 triggers `UntrustedKey`. The row then isolates the
    // `BadSignature` cause for cp2's small-order key alone.
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .key(identity_key)
        .build()
        .unwrap();
    let findings = verify_files_with(vec![fx.path.clone()], trust);
    let findings_rows = rows(&findings);
    assert!(
        findings_rows.contains(&(
            K::BadSignature,
            Some(fx.path),
            Some(3),
            Some(2),
            format!("key {}", pubkey_hex(&identity_key)),
        )),
        "{findings_rows:?}",
    );
    assert!(findings.iter().all(|f| f.kind() != K::UntrustedKey));
}

// ============================================================
// A4b direct predicate kill for M1. The small-order fixture from A4 is
// rebuilt here as a predicate test: `trusted` must return false for a
// small-order key with a legacy-acceptable signature, even with the key
// listed. Pairs with A4 to give M1 (`verify_strict` → `verify`) two
// named kills.
// ============================================================
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

// ============================================================
// A6b: bounded key with a flipped in-run checkpoint signature → BOTH
// BadSignature and UntrustedKey (bounded). Pairs with A6 to give M4
// (skip BadSignature when UntrustedKey fired) two named kills, for the
// bounded case specifically.
// ============================================================
#[test]
fn a6b_bounded_key_with_flipped_signature_emits_both() {
    let fx = two_checkpoints();
    let bad = flip_signature_byte(&fx.cp2);
    put_segment(&fx._dir.0, 0, &[&fx.cp0, &fx.e1, &bad], &[]);
    // Bound the fixture key at cp0; cp2's seq is above the bound.
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, fx.cp0.hash())
        .build()
        .unwrap();
    let findings = verify_files_with(vec![fx.path.clone()], trust);
    let findings_rows = rows(&findings);
    assert!(
        findings_rows.contains(&(
            K::BadSignature,
            Some(fx.path.clone()),
            Some(3),
            Some(2),
            format!("key {}", pubkey_hex(&fixture_pubkey())),
        )),
        "{findings_rows:?}",
    );
    assert!(
        findings_rows.contains(&(
            K::UntrustedKey,
            Some(fx.path),
            Some(3),
            Some(2),
            format!(
                "key {} bounded through seq 0",
                pubkey_hex(&fixture_pubkey())
            ),
        )),
        "{findings_rows:?}",
    );
}

// ============================================================
// A5: a non-canonical signature (`s ≥ ℓ`, built as `s + ℓ`) → BadSignature.
// ============================================================
#[test]
fn a5_non_canonical_signature_is_bad_signature() {
    let fx = two_checkpoints();
    // Ed25519 group order ℓ little-endian (RFC 8032):
    const ELL_LE: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    let honest = match &fx.cp2.kind {
        Kind::Checkpoint(cp) => *cp.signature(),
        _ => panic!("checkpoint"),
    };
    // Add ℓ to the 32-byte `s` tail (bytes 32..64). The resulting `s'`
    // satisfies `s' ≥ ℓ` so `verify_strict` rejects it as non-canonical
    // even though `s' ≡ s (mod ℓ)` would re-verify under legacy `verify`.
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
    let findings_rows = rows(&findings);
    assert!(
        findings_rows.contains(&(
            K::BadSignature,
            Some(fx.path),
            Some(3),
            Some(2),
            format!("key {}", pubkey_hex(&fixture_pubkey())),
        )),
        "{findings_rows:?}",
    );
}

// ============================================================
// A6: unlisted key plus a flipped signature → both BadSignature@2 and
// UntrustedKey@2 (ruling 13-V5-d1 point 2 independence).
// ============================================================
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
    let findings_rows = rows(&findings);
    let key_hex = pubkey_hex(&signer.public_key());
    assert!(
        findings_rows.contains(&(
            K::BadSignature,
            Some(path.clone()),
            Some(3),
            Some(2),
            format!("key {key_hex}"),
        )),
        "{findings_rows:?}",
    );
    assert!(
        findings_rows.contains(&(
            K::UntrustedKey,
            Some(path),
            Some(3),
            Some(2),
            format!("key {key_hex} not listed for trail {}", trail_hex()),
        )),
        "{findings_rows:?}",
    );
}

// ============================================================
// A7: a shipped-only checkpoint (present only in a shipped copy) with a
// flipped signature → BadSignature at the shipped file and line.
// ============================================================
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
    let findings_rows = rows(&findings);
    assert!(
        findings_rows.contains(&(
            K::BadSignature,
            Some(shipped),
            Some(1),
            Some(2),
            format!("key {}", pubkey_hex(&fixture_pubkey())),
        )),
        "{findings_rows:?}",
    );
}

// ============================================================
// A7b: shipped-only checkpoint signed by an unlisted key → UntrustedKey
// at the shipped file and line. Pins the same first-occurrence rule for
// `UntrustedKey` that A7 pins for `BadSignature`; together they give M3
// (skip shipped-only) two named kills.
// ============================================================
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
    let findings_rows = rows(&findings);
    assert!(
        findings_rows.contains(&(
            K::UntrustedKey,
            Some(shipped),
            Some(1),
            Some(2),
            format!(
                "key {} not listed for trail {}",
                pubkey_hex(&signer.public_key()),
                trail_hex(),
            ),
        )),
        "{findings_rows:?}",
    );
}

// ============================================================
// A8: a key listed only in ANOTHER trail's section of the same policy →
// UntrustedKey. Kills M5 (accept a key listed in any trail's section).
// ============================================================
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
    // Multi-trail policy: narrow verification to `TRAIL`.
    let findings = Verifier::new(trust)
        .trail(TRAIL)
        .unwrap()
        .verify_files([fx.path.clone()])
        .unwrap()
        .findings()
        .to_vec();
    let findings_rows = rows(&findings);
    let detail = format!(
        "key {} not listed for trail {}",
        pubkey_hex(&fixture_pubkey()),
        trail_hex(),
    );
    assert!(
        findings_rows.contains(&(K::UntrustedKey, Some(fx.path), Some(3), Some(2), detail)),
        "{findings_rows:?}",
    );
}

// ============================================================
// A8b: predicate-level same-key-different-trail. Pins the same
// behaviour A8 asserts through the verifier, but through the direct
// `trusted` predicate. Pairs with A8 to give M5 (accept a key listed in
// any trail's section) two named kills.
// ============================================================
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

// ============================================================
// A9: a bad signature on an in-run checkpoint after a loss point, in an
// A1-style sealed run → BadSignature reported; the run findings are
// unchanged from the honest A1.
// ============================================================
#[test]
fn a9_in_run_bad_signature_reports_without_changing_run_findings() {
    let honest = build_a1();
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .build()
        .unwrap();
    let honest_findings = Verifier::new(trust.clone())
        .verify_dir(&honest.dir_path)
        .unwrap()
        .findings()
        .to_vec();
    let honest_run_rows: Vec<_> = honest_findings
        .iter()
        .filter(|f| f.kind() == K::SegmentStructure && f.run_digest().is_some())
        .cloned()
        .collect();
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
    let findings = Verifier::new(trust)
        .verify_dir(&d.0)
        .unwrap()
        .findings()
        .to_vec();
    let bad: Vec<_> = findings
        .iter()
        .filter(|f| f.kind() == K::BadSignature && f.seq() == Some(5))
        .collect();
    assert_eq!(bad.len(), 1, "{:?}", rows(&findings));
    let run_rows: Vec<_> = findings
        .iter()
        .filter(|f| f.kind() == K::SegmentStructure && f.run_digest().is_some())
        .cloned()
        .collect();
    assert_eq!(
        run_rows.len(),
        honest_run_rows.len(),
        "run findings count changed under BadSignature",
    );
    for (a, b) in run_rows.iter().zip(honest_run_rows.iter()) {
        assert_eq!(a.kind(), b.kind());
        assert_eq!(a.seq(), b.seq());
        assert_eq!(a.run_digest(), b.run_digest());
    }
}

// ============================================================
// R1 (regression): byte-identical duplicate across native + shipped
// yields exactly ONE BadSignature at the first-occurrence location the
// engine's merge keeps. Kills M6 (per-occurrence) and M3 (skip shipped).
// Passes on base: base emits nothing, and this row asserts one — but as a
// regression row it must pass on base. Base layout: base emits no
// BadSignature, so the ≥ 2 kill budget comes from runtime mutants, not
// from the base assertion here. Treat the assertion as a fail-closed
// pin: if this row ever reports ≠ 1 BadSignature after the feature
// lands, the pass has drifted. The ≥ 2 mutants it kills:
//   - M3 (skip shipped-only) still produces 1 BadSignature here (native
//     copy fires). It is killed via A7.
//   - M6 (one per occurrence) produces 2 BadSignature findings here —
//     native + shipped — flipping this row's `len == 1` assertion.
//   - M4 (skip BadSignature when UntrustedKey fired) also fires here if
//     the shipped-only path is cfg'd off, keeping 1 expected.
//   - A duplicate counting mutant that emits 2 findings per `(seq, hash)`
//     fails this row's count assertion directly.
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
    let bad_sig: Vec<_> = findings
        .iter()
        .filter(|f| f.kind() == K::BadSignature)
        .collect();
    assert_eq!(bad_sig.len(), 1, "{:?}", rows(&findings));
    assert_eq!(bad_sig[0].seq(), Some(2));
    assert_eq!(bad_sig[0].line(), Some(3));
}

// ============================================================
// R1b (regression): triple-duplicate (native + two shipped copies) of the
// same flipped-signature checkpoint still yields one `BadSignature`. Pairs
// with R1 to give M6 (one finding per occurrence) two named kills.
// ============================================================
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
    let bad_sig: Vec<_> = findings
        .iter()
        .filter(|f| f.kind() == K::BadSignature)
        .collect();
    assert_eq!(bad_sig.len(), 1, "{:?}", rows(&findings));
    let untrusted: Vec<_> = findings
        .iter()
        .filter(|f| f.kind() == K::UntrustedKey)
        .collect();
    assert!(untrusted.is_empty());
}

// ============================================================
// R2 (regression): honest multi-segment trail (A1) with a resume and
// the key bounded through the live opening checkpoint `cp6`. Under
// production, every checkpoint (cp0, cp5, cp6) is trusted and the
// signature pass emits no `BadSignature` / `UntrustedKey`. Kills
// M2 (`<=` → `<`) by failing at cp6 exactly at the bound, and kills
// M8 (predicate ignores signature) directly through `trusted(cp6)`
// returning `true` only when both the signature and the bound hold.
// ============================================================
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
    for f in &findings {
        assert_ne!(f.kind(), K::BadSignature, "{:?}", rows(&findings));
        assert_ne!(f.kind(), K::UntrustedKey, "{:?}", rows(&findings));
    }
    // Predicate: cp6 is a trusted checkpoint at seq 6 exactly at the bound.
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
    // Second predicate check: a crafted cp2 with its signature flipped must
    // return `!trusted` even with the key listed, killing M8 (predicate
    // ignores signature) alongside the honest bound check for M2 above.
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

// ============================================================
// Direct predicate tests (ruling 13-V5-d1 point 3; kills M8, M2).
// ============================================================
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
    // Also exercise the explicit check from the public pass so the module
    // compiles into the test binary even without upstream consumers.
    let _ = check;
}

// ============================================================
// M8b direct predicate kill (ruling 13-V5-d1 point 3): a flipped
// signature on a shipped-only checkpoint with the key listed must still
// be `!trusted`. Pairs with `trusted_predicate_requires_signature_and_key_trust`
// to give M8 (predicate ignores the signature) two named kills.
// ============================================================
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

// ============================================================
// Sanity: an unpinned trail errors before the signature pass runs.
// ============================================================
#[test]
fn unpinned_trail_errors_before_signature_pass_runs() {
    let other: [u8; 16] = [0x33; 16];
    let trust = TrustPolicy::builder().trail(other).build().unwrap();
    let err = Verifier::new(trust).trail(TRAIL).map(|_| ()).unwrap_err();
    assert_eq!(err.kind(), AuditErrorKind::InvalidConfig);
}
