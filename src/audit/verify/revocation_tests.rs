//! Rows for the verifier revocation pin and confirmation checks
//! (ADR-0005 decision 9 and amendment 8; rulings 13-V5-d1 point 4,
//! 13-V5-d3 and 13-V5-d4).
//!
//! Row standard (repo-wide): every acceptance row asserts the FULL
//! sorted literal finding list, compared as whole [`Finding`] values
//! through [`assert_findings`] (a thin wrapper around `assert_eq!` on
//! `Vec<Finding>`). Regression rows are labelled in their doc
//! comments. Every digest and key in an expected detail is a
//! written-out hex constant pinned by [`fixture_hashes_match_literals`].
//! Expected lists are written in the engine's final sort order
//! (`(seq.is_none(), seq, file, line, kind_debug)`), so no per-row
//! sort runs here.
//!
//! `AuditConfig::rotate` runs the integration row V10; hand-built
//! records build the forgeries and the smaller honest layouts.

use crate::audit::{
    AuditConfig, CheckpointFields, FindingKind as K, KeyFileSigner, Mmr, Record, Signer,
    TrustPolicy, digest_string,
    format::Kind,
    hex,
    runs_v4a_fixtures::{
        TRAIL, Temp, context, entry_rec, fixture_pubkey, line_bytes, pushed, put_segment, seeded,
        segment_path, signed_cp, signed_cp_explicit,
    },
    verify::{Finding, Verifier},
};
use std::{fs, path::PathBuf, sync::Arc};

// =====================================================================
// Shared literal hex constants.
// =====================================================================

/// Fixture signing seed `0x27` repeated (same as `runs_v4a_fixtures`).
const FIXTURE_KEY_HEX: &str = "ee45ecb9aca01a0abd83ef56dd985c8c874e6e7f4aebcedf20bd8d88c2a0add7";
/// Alternative "new key" signing seed `0x22` repeated.
const NEW_KEY_HEX: &str = "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0";

/// Hex of `runs_v4a_fixtures::TRAIL` = `[17; 16]`.
const TRAIL_HEX: &str = "11111111111111111111111111111111";

/// Record hash of the honest fixture cp0 (`signed_cp(0, genesis, &Mmr::new())`),
/// reused across many rows.
const CP0_HONEST_DIGEST: &str =
    "blake3:fc26c6f2bb830592aaaca5413da1599489d86ac6e240a4a7a010681e0d4c8e77";
/// Record hash of the honest fixture cp2 (A1-style two-checkpoint layout).
const CP2_HONEST_DIGEST: &str =
    "blake3:4164966a12a675e55eb6e133b9e50313907f164fe142d941447defcdfdb25d06";
/// Record hash of entry e1 (seq=1, previous = cp0.hash).
const E1_HONEST_DIGEST: &str =
    "blake3:c121282b5135adfe7a17142cae6bfc4c9040c4aed26d74bddc923b8dafcdb6e8";
/// V6 twin cp2: `signed_cp_explicit(2, e1.hash, 2, [0xde;32], [[0x22;32]])`.
/// Pinned so V6's `SeqConflict` detail carries no computed value. Lies
/// above `CP2_HONEST_DIGEST` in byte order, which fixes the pair
/// ordering the engine uses for the `conflicting hashes` detail.
const CP2_TWIN_V6_DIGEST: &str =
    "blake3:aee5a47d9814a55594371fa3bb0bd34a48531533983898590ef72f511d42f45c";
/// V6b twin cp0: `signed_cp_explicit(0, genesis, 0, [0xde;32], vec![])`.
/// Pinned so V6b's `SeqConflict` detail is literal end to end. Less
/// than `CP0_HONEST_DIGEST` byte-wise, so it appears first in the
/// "conflicting hashes: X, Y" list.
const CP0_TWIN_V6B_DIGEST: &str =
    "blake3:ca0beffeaf4ac9b032b9e4b350a04c8870a116631288eb5e460e0e8e83da5c57";
/// Hand-crafted bound hash `[0x5a; 32]` used as a wrong-pin-hash value
/// in several rows.
const BOUND_HASH_5A_DIGEST: &str =
    "blake3:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
/// Hand-crafted bound hash `[0xee; 32]` used by V13/V13b's absent
/// second bound.
const BOUND_HASH_EE_DIGEST: &str =
    "blake3:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
/// Seed-`0x44` public key, used by V13/V13b as the C side of the
/// failing absent-seq bound.
const C_KEY_HEX: &str = "d759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48";
/// New-key checkpoint at seq=1 (`sign_with(new, 1, cp0.hash, &mmr0)`).
/// Reused by the other-key-cp precedence rows.
const NEW_CP1_DIGEST: &str =
    "blake3:1acb508d66bef3c41553d03c3ad762cc53915716f882ac8a01b080b246d4937e";
/// New-key checkpoint at seq=1 with explicit alternative fields
/// (`sign_with_fields(new, 1, cp0.hash, 1, [0xbb;32], vec![[0xbb;32]])`).
/// Pinned so the seq=1 fork-with-other-key probes carry no computed
/// value.
const NEW_CP1_TWIN_DIGEST: &str =
    "blake3:ec9e7df483d272013bce736629ee51feeb2657bfe2bd5eb68ea53c74cfe4e68f";
/// Entry at seq=2 chained from `entry_rec(1, cp0.hash)` on the shared
/// fixture trail (`entry_rec(2, e1.hash)`). Pinned so the entry-at-
/// seq=2 wrong-hash row carries no computed value.
const E2_DIGEST: &str = "blake3:8a5ea9c989aad7e89033b58ad6f59a6384af43dfe6df5bada042420c0040c306";

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

fn verify_files_with(files: Vec<PathBuf>, trust: TrustPolicy) -> Vec<Finding> {
    Verifier::new(trust)
        .verify_files(files)
        .unwrap()
        .findings()
        .to_vec()
}

fn verify_dir_with(dir: &std::path::Path, trust: TrustPolicy) -> Vec<Finding> {
    Verifier::new(trust)
        .verify_dir(dir)
        .unwrap()
        .findings()
        .to_vec()
}

fn verify_files_on_trail(files: Vec<PathBuf>, trust: TrustPolicy, trail: [u8; 16]) -> Vec<Finding> {
    Verifier::new(trust)
        .trail(trail)
        .unwrap()
        .verify_files(files)
        .unwrap()
        .findings()
        .to_vec()
}

fn new_signer() -> Arc<dyn Signer> {
    Arc::new(KeyFileSigner::from_hex(&"22".repeat(32)).unwrap())
}
fn old_signer() -> Arc<dyn Signer> {
    Arc::new(KeyFileSigner::from_hex(&"27".repeat(32)).unwrap())
}
fn new_pubkey() -> [u8; 32] {
    new_signer().public_key()
}

/// Clones a signed checkpoint while rewriting its signature; re-hashes.
fn with_signature(signed: &Record, sig: [u8; 64]) -> Record {
    let cp = match &signed.kind {
        Kind::Checkpoint(cp) => cp,
        _ => panic!("checkpoint record expected"),
    };
    let fields = CheckpointFields::new(cp.size, cp.root, cp.peaks.clone(), cp.key, sig).unwrap();
    Record::checkpoint(signed.context.clone(), fields).unwrap()
}
fn flip_signature(signed: &Record) -> Record {
    let sig = match &signed.kind {
        Kind::Checkpoint(cp) => cp.signature(),
        _ => panic!("checkpoint"),
    };
    let mut flipped = *sig;
    flipped[0] ^= 0x01;
    with_signature(signed, flipped)
}
fn sign_with(signer: &dyn Signer, seq: u64, previous: [u8; 32], mmr: &Mmr) -> Record {
    sign_with_fields(
        signer,
        seq,
        previous,
        mmr.size(),
        mmr.root(),
        mmr.peaks().to_vec(),
    )
}
/// As `sign_with` but with explicit `(size, root, peaks)` fields. Lets
/// a fork at `s` carry two distinct checkpoints signed by the SAME
/// non-bounded key, so the key-identity check fires on either copy
/// regardless of merge-order sort. `peaks.len() == size.count_ones()`
/// must hold (`CheckpointFields::new` invariant).
fn sign_with_fields(
    signer: &dyn Signer,
    seq: u64,
    previous: [u8; 32],
    size: u64,
    root: [u8; 32],
    peaks: Vec<[u8; 32]>,
) -> Record {
    let fields =
        |sig| CheckpointFields::new(size, root, peaks.clone(), signer.public_key(), sig).unwrap();
    let unsigned = Record::checkpoint(context(seq, previous), fields([0; 64])).unwrap();
    let sig = signer.sign(&unsigned.signing_message().unwrap()).unwrap();
    Record::checkpoint(context(seq, previous), fields(sig)).unwrap()
}

/// Single sealed segment `[cp0, e1, cp2]` on `TRAIL`, with cp2 honestly
/// signed by the fixture key. Shared across many rows.
struct TwoCheckpointLayout {
    dir: Temp,
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
        dir: d,
        path,
        cp0,
        e1,
        cp2,
    }
}

// =====================================================================
// V2 — ACCEPTANCE. Cut the trail back to the bound, then forge a
// record and a checkpoint above it signed by the (now-revoked) old key.
// Bound = close_cp (seq=1, hash matches) → pin passes. The only
// checkpoint above is the forged cp signed by the same old key →
// confirmation fails, and the forged cp is `UntrustedKey`.
// =====================================================================
#[test]
fn v2_cut_to_bound_then_forge_above_with_old_key_is_unconfirmed() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let close_cp = signed_cp(1, cp0.hash(), &mmr0);
    let mmr1 = pushed(&mmr0, &close_cp);
    let e2 = entry_rec(2, close_cp.hash());
    let mmr2 = pushed(&mmr1, &e2);
    let forged_cp = signed_cp(3, e2.hash(), &mmr2);
    put_segment(&d.0, 0, &[&cp0, &close_cp, &e2, &forged_cp], &[]);
    let path = segment_path(&d.0, 0);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), close_cp.context.seq, close_cp.hash())
        .build()
        .unwrap();
    let findings = verify_files_with(vec![path.clone()], trust);
    let expected = vec![
        located(
            K::RevocationUnconfirmed,
            path.clone(),
            2,
            1,
            format!(
                "key {FIXTURE_KEY_HEX} through=1: no trusted checkpoint by another key above the bound"
            ),
        ),
        located(
            K::UntrustedKey,
            path,
            4,
            3,
            format!("key {FIXTURE_KEY_HEX} bounded through seq 1"),
        ),
        uncovered(2, 3),
    ];
    assert_findings(&findings, &expected, "V2");
}

// =====================================================================
// V3 — ACCEPTANCE. Forge BELOW the bound: the record at the bound
// `seq` has a different hash than the bound names. Minimal layout: one
// opening checkpoint at seq=0; the bound carries a different hash, so
// pin fails with `RevocationMismatch "…has hash …"`. Confirmation
// also fails (no other-key checkpoint above). The cp0 is trusted
// (signed by fixture key, within `through=0`), so coverage = 0 and no
// `UncoveredTail` fires on the last record.
// =====================================================================
#[test]
fn v3_forge_below_bound_with_old_key_has_hash_mismatch() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    put_segment(&d.0, 0, &[&cp0], &[]);
    let path = segment_path(&d.0, 0);
    let bound_hash: [u8; 32] = [0x5a; 32];
    assert_ne!(cp0.hash(), bound_hash);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, bound_hash)
        .build()
        .unwrap();
    let findings = verify_files_with(vec![path.clone()], trust);
    let expected = vec![
        located(
            K::RevocationMismatch,
            path.clone(),
            1,
            0,
            format!(
                "key {FIXTURE_KEY_HEX} through=0:{BOUND_HASH_5A_DIGEST}: record at seq 0 has hash {CP0_HONEST_DIGEST}"
            ),
        ),
        located(
            K::RevocationUnconfirmed,
            path,
            1,
            0,
            format!(
                "key {FIXTURE_KEY_HEX} through=0: no trusted checkpoint by another key above the bound"
            ),
        ),
    ];
    assert_findings(&findings, &expected, "V3");
}

// =====================================================================
// V3b — ACCEPTANCE. Hash mismatch at `seq=2` to pair with V3 for a
// hash-vs-seq separation (pin must compare both).
// =====================================================================
#[test]
fn v3b_hash_mismatch_at_seq_two() {
    let fx = two_checkpoints();
    let bound_hash: [u8; 32] = [0x5a; 32];
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 2, bound_hash)
        .build()
        .unwrap();
    let findings = verify_files_with(vec![fx.path.clone()], trust);
    let expected = vec![
        located(
            K::RevocationMismatch,
            fx.path.clone(),
            3,
            2,
            format!(
                "key {FIXTURE_KEY_HEX} through=2:{BOUND_HASH_5A_DIGEST}: record at seq 2 has hash {CP2_HONEST_DIGEST}"
            ),
        ),
        located(
            K::RevocationUnconfirmed,
            fx.path.clone(),
            3,
            2,
            format!(
                "key {FIXTURE_KEY_HEX} through=2: no trusted checkpoint by another key above the bound"
            ),
        ),
    ];
    assert_findings(&findings, &expected, "V3b");
    let _keep = fx.dir;
}

// =====================================================================
// V4 — ACCEPTANCE. The bound names an entry seq, not a checkpoint seq.
// Pin fails with `RevocationMismatch "…is not a checkpoint"`.
// =====================================================================
#[test]
fn v4_bound_at_entry_is_not_a_checkpoint() {
    let fx = two_checkpoints();
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 1, fx.e1.hash())
        .build()
        .unwrap();
    let findings = verify_files_with(vec![fx.path.clone()], trust);
    let expected = vec![
        located(
            K::RevocationMismatch,
            fx.path.clone(),
            2,
            1,
            format!(
                "key {FIXTURE_KEY_HEX} through=1:{E1_HONEST_DIGEST}: record at seq 1 is not a checkpoint"
            ),
        ),
        located(
            K::RevocationUnconfirmed,
            fx.path.clone(),
            2,
            1,
            format!(
                "key {FIXTURE_KEY_HEX} through=1: no trusted checkpoint by another key above the bound"
            ),
        ),
        located(
            K::UntrustedKey,
            fx.path.clone(),
            3,
            2,
            format!("key {FIXTURE_KEY_HEX} bounded through seq 1"),
        ),
        uncovered(1, 2),
    ];
    assert_findings(&findings, &expected, "V4");
    let _keep = fx.dir;
}

// =====================================================================
// V4b — ACCEPTANCE. Bound at an entry at `seq=1` in a shorter segment.
// Pairs with V4 so a kind-check skip leaves two failing rows.
// =====================================================================
#[test]
fn v4b_bound_at_entry_only_segment() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    put_segment(&d.0, 0, &[&cp0, &e1], &[]);
    let path = segment_path(&d.0, 0);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 1, e1.hash())
        .build()
        .unwrap();
    let findings = verify_files_with(vec![path.clone()], trust);
    let expected = vec![
        located(
            K::RevocationMismatch,
            path.clone(),
            2,
            1,
            format!(
                "key {FIXTURE_KEY_HEX} through=1:{E1_HONEST_DIGEST}: record at seq 1 is not a checkpoint"
            ),
        ),
        located(
            K::RevocationUnconfirmed,
            path,
            2,
            1,
            format!(
                "key {FIXTURE_KEY_HEX} through=1: no trusted checkpoint by another key above the bound"
            ),
        ),
        uncovered(1, 1),
    ];
    assert_findings(&findings, &expected, "V4b");
}

// =====================================================================
// V5 — ACCEPTANCE. The bound's `seq` is absent from the files. Pin
// fails with `RevocationMismatch "…no record at seq …"`, no location.
// =====================================================================
#[test]
fn v5_bound_seq_absent_has_no_record_and_no_location() {
    let fx = two_checkpoints();
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 99, [0x5a; 32])
        .build()
        .unwrap();
    let findings = verify_files_with(vec![fx.path.clone()], trust);
    let expected = vec![
        unlocated(
            K::RevocationMismatch,
            Some(99),
            format!("key {FIXTURE_KEY_HEX} through=99:{BOUND_HASH_5A_DIGEST}: no record at seq 99"),
        ),
        unlocated(
            K::RevocationUnconfirmed,
            Some(99),
            format!(
                "key {FIXTURE_KEY_HEX} through=99: no trusted checkpoint by another key above the bound"
            ),
        ),
    ];
    assert_findings(&findings, &expected, "V5");
    let _keep = fx.dir;
}

// =====================================================================
// V6 — ACCEPTANCE. The bound's `seq` is forked: honest cp2 plus a
// shipped twin with a different hash. Pin fails with
// `RevocationMismatch "…seq s is forked"` (no location), plus
// `SeqConflict`. `CP2_TWIN_V6_DIGEST` exceeds `CP2_HONEST_DIGEST`
// byte-wise, so the engine's "conflicting hashes: X, Y" lists honest
// first then twin.
// =====================================================================
#[test]
fn v6_bound_at_forked_seq_is_forked_and_has_seq_conflict() {
    let fx = two_checkpoints();
    let twin_cp2 = signed_cp_explicit(2, fx.e1.hash(), 2, [0xde; 32], vec![[0x22; 32]]);
    let twin_path = fx.dir.0.join("cp2.twin");
    fs::write(&twin_path, line_bytes(&twin_cp2)).unwrap();
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 2, fx.cp2.hash())
        .build()
        .unwrap();
    let findings = verify_files_with(vec![fx.path.clone(), twin_path], trust);
    let expected = vec![
        unlocated(
            K::RevocationMismatch,
            Some(2),
            format!("key {FIXTURE_KEY_HEX} through=2:{CP2_HONEST_DIGEST}: seq 2 is forked"),
        ),
        unlocated(
            K::RevocationUnconfirmed,
            Some(2),
            format!(
                "key {FIXTURE_KEY_HEX} through=2: no trusted checkpoint by another key above the bound"
            ),
        ),
        located(
            K::SeqConflict,
            fx.path.clone(),
            3,
            2,
            format!("conflicting hashes: {CP2_HONEST_DIGEST}, {CP2_TWIN_V6_DIGEST}"),
        ),
    ];
    assert_findings(&findings, &expected, "V6");
    let _keep = fx.dir;
}

// =====================================================================
// V6b — ACCEPTANCE. Fork at `seq=0`. Pairs with V6 so a fork-ignoring
// pin leaves two failing rows.
// =====================================================================
#[test]
fn v6b_bound_at_forked_seq_zero() {
    let d = Temp::new();
    let honest_cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    put_segment(&d.0, 0, &[&honest_cp0], &[]);
    let native = segment_path(&d.0, 0);
    let twin_cp0 = signed_cp_explicit(0, Record::genesis(&TRAIL), 0, [0xde; 32], vec![]);
    let twin_path = d.0.join("cp0.twin");
    fs::write(&twin_path, line_bytes(&twin_cp0)).unwrap();
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, honest_cp0.hash())
        .build()
        .unwrap();
    let findings = verify_files_with(vec![native.clone(), twin_path], trust);
    // Honest `CP0_HONEST_DIGEST` (`fc...`) is greater than the twin
    // digest `CP0_TWIN_V6B_DIGEST` byte-wise, so the twin appears first
    // in the engine's conflict list.
    let expected = vec![
        unlocated(
            K::RevocationMismatch,
            Some(0),
            format!("key {FIXTURE_KEY_HEX} through=0:{CP0_HONEST_DIGEST}: seq 0 is forked"),
        ),
        unlocated(
            K::RevocationUnconfirmed,
            Some(0),
            format!(
                "key {FIXTURE_KEY_HEX} through=0: no trusted checkpoint by another key above the bound"
            ),
        ),
        located(
            K::SeqConflict,
            native,
            1,
            0,
            format!("conflicting hashes: {CP0_TWIN_V6B_DIGEST}, {CP0_HONEST_DIGEST}"),
        ),
    ];
    assert_findings(&findings, &expected, "V6b");
}

// =====================================================================
// V7 — ACCEPTANCE. A confirming checkpoint above the bound is signed by
// the SAME old key → confirmation fails. The above-bound checkpoint
// also emits `UntrustedKey` (above its own `through=` bound).
// =====================================================================
#[test]
fn v7_confirming_checkpoint_same_key_is_unconfirmed() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let path = segment_path(&d.0, 0);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, cp0.hash())
        .build()
        .unwrap();
    let findings = verify_files_with(vec![path.clone()], trust);
    let expected = vec![
        located(
            K::RevocationUnconfirmed,
            path.clone(),
            1,
            0,
            format!(
                "key {FIXTURE_KEY_HEX} through=0: no trusted checkpoint by another key above the bound"
            ),
        ),
        located(
            K::UntrustedKey,
            path,
            3,
            2,
            format!("key {FIXTURE_KEY_HEX} bounded through seq 0"),
        ),
        uncovered(1, 2),
    ];
    assert_findings(&findings, &expected, "V7");
}

// =====================================================================
// V8 — ACCEPTANCE. The only checkpoint above the bound is by the new
// (different) key but with a flipped signature → not trusted (ruling
// 13-V5-d1 point 3) → unconfirmed. The flipped checkpoint also emits
// `BadSignature`.
// =====================================================================
#[test]
fn v8_only_confirming_cp_has_bad_signature_is_unconfirmed() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let new = new_signer();
    let new_cp1 = sign_with(&*new, 1, cp0.hash(), &mmr0);
    let bad_cp1 = flip_signature(&new_cp1);
    put_segment(&d.0, 0, &[&cp0, &bad_cp1], &[]);
    let path = segment_path(&d.0, 0);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, cp0.hash())
        .key(new.public_key())
        .build()
        .unwrap();
    let findings = verify_files_with(vec![path.clone()], trust);
    let expected = vec![
        located(
            K::RevocationUnconfirmed,
            path.clone(),
            1,
            0,
            format!(
                "key {FIXTURE_KEY_HEX} through=0: no trusted checkpoint by another key above the bound"
            ),
        ),
        located(K::BadSignature, path, 2, 1, format!("key {NEW_KEY_HEX}")),
        uncovered(1, 1),
    ];
    assert_findings(&findings, &expected, "V8");
}

// =====================================================================
// V9 — ACCEPTANCE. The confirming key is listed only in another trail's
// section. It is not trusted on this trail → unconfirmed. The
// confirming cp also emits `UntrustedKey`.
// =====================================================================
#[test]
fn v9_confirming_key_only_on_other_trail_is_unconfirmed() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let new = new_signer();
    let new_cp1 = sign_with(&*new, 1, cp0.hash(), &mmr0);
    put_segment(&d.0, 0, &[&cp0, &new_cp1], &[]);
    let path = segment_path(&d.0, 0);
    let other: [u8; 16] = [0x99; 16];
    let trust = TrustPolicy::builder()
        .trail(other)
        .key(new.public_key())
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, cp0.hash())
        .build()
        .unwrap();
    let findings = verify_files_on_trail(vec![path.clone()], trust, TRAIL);
    let expected = vec![
        located(
            K::RevocationUnconfirmed,
            path.clone(),
            1,
            0,
            format!(
                "key {FIXTURE_KEY_HEX} through=0: no trusted checkpoint by another key above the bound"
            ),
        ),
        located(
            K::UntrustedKey,
            path,
            2,
            1,
            format!("key {NEW_KEY_HEX} not listed for trail {TRAIL_HEX}"),
        ),
        uncovered(1, 1),
    ];
    assert_findings(&findings, &expected, "V9");
}

// =====================================================================
// V10 — REGRESSION (d11 compromise branch). Real `AuditConfig::rotate`:
// create (cp0, old) + record + close (cp2, old) + reopen + record +
// close (cp4, old) + rotate (new). The bound names the first close;
// the new-key rotate checkpoint confirms; the second close is an
// untrusted old-key checkpoint above the bound. No revocation finding.
// Mutant kills (see the PR body table):
// - a pin that requires the bound to name the LAST old-key checkpoint
//   (the first close is not the last) adds a `RevocationMismatch`;
// - a confirmation that fails when ANY old-key checkpoint exists above
//   the bound (the untrusted second close) adds a `RevocationUnconfirmed`.
// =====================================================================
#[test]
fn v10_compromise_branch_untrusted_key_above_bound() {
    let temp = Temp::new();
    let dir = temp.0.clone();
    let old = old_signer();
    let new = new_signer();
    let (trail_id, first_close) = {
        let handle = AuditConfig::new("svc")
            .dir(&dir)
            .create(old.clone())
            .unwrap();
        let trail_id = handle.trail();
        handle
            .record(&crate::audit::Entry::new("actor", "change", "obj"))
            .unwrap();
        let close = handle.close().unwrap();
        (trail_id, close)
    };
    let _second_close = {
        let handle = AuditConfig::new("svc")
            .dir(&dir)
            .expect_head(first_close.seq(), first_close.hash())
            .open(old.clone())
            .unwrap();
        handle
            .record(&crate::audit::Entry::new("actor", "change", "obj"))
            .unwrap();
        handle.close().unwrap()
    };
    let (_r, _c) = AuditConfig::new("svc")
        .dir(&dir)
        .rotate(
            new.clone(),
            (first_close.seq(), first_close.hash()),
            (
                /* second close */ first_close.seq() + 2,
                _second_close.hash(),
            ),
            "operator",
            "scheduled",
        )
        .unwrap();
    let trust = TrustPolicy::builder()
        .trail(trail_id)
        .key_through(old.public_key(), first_close.seq(), first_close.hash())
        .key(new.public_key())
        .build()
        .unwrap();
    let findings = verify_dir_with(&dir, trust);
    let live = dir.join("audit.jsonl");
    let expected = vec![located(
        K::UntrustedKey,
        live,
        5,
        4,
        format!("key {FIXTURE_KEY_HEX} bounded through seq 2"),
    )];
    // The key_rotated entry is not a `Finding`, so the finding list
    // alone captures the verifier's view; the operator record's
    // on-disk presence is proven by the real `rotate()` succeeding.
    assert_findings(&findings, &expected, "V10");
}

// =====================================================================
// V10b — REGRESSION (hand-built companion to V10). Pairs with V10 for
// the compromise-branch mutants: pin requires the bound to name the
// last old-key checkpoint, and confirmation fails when any old-key
// checkpoint exists above the bound. Here cp2 (the bound) is signed by
// the old fixture key; cp3 (also fixture key) is untrusted and above
// the bound; cp4 (new key) confirms.
// =====================================================================
#[test]
fn v10b_hand_built_compromise_branch_untrusted_key_above_bound() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    let cp3 = signed_cp(3, cp2.hash(), &mmr2);
    let mmr3 = pushed(&mmr2, &cp3);
    let new = new_signer();
    let cp4 = sign_with(&*new, 4, cp3.hash(), &mmr3);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2, &cp3, &cp4], &[]);
    let path = segment_path(&d.0, 0);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 2, cp2.hash())
        .key(new.public_key())
        .build()
        .unwrap();
    let findings = verify_files_with(vec![path.clone()], trust);
    let expected = vec![located(
        K::UntrustedKey,
        path,
        4,
        3,
        format!("key {FIXTURE_KEY_HEX} bounded through seq 2"),
    )];
    assert_findings(&findings, &expected, "V10b");
}

// =====================================================================
// V11 — ACCEPTANCE. Scope. The same old key is revoked on both the
// verified trail Y (= `TRAIL`) and another trail X (the "other"
// section), each rotated to its own new key. The X-side bound is
// listed before Y in `BTreeMap` byte order (`[0x01; 16]` < `[17; 16]`),
// which exercises the "first section only" scope mutant too.
// =====================================================================
#[test]
fn v11_key_revoked_on_two_trails_each_trail_verifies_separately() {
    // Clean Y: bound at cp0 is pinned (cp0 signed by fixture) and
    // confirmed by the new-key cp1.
    let d_clean = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let new = new_signer();
    let new_cp1 = sign_with(&*new, 1, cp0.hash(), &mmr0);
    put_segment(&d_clean.0, 0, &[&cp0, &new_cp1], &[]);
    let path_clean = segment_path(&d_clean.0, 0);
    let x_other_new = Arc::new(KeyFileSigner::from_hex(&"33".repeat(32)).unwrap());
    let other: [u8; 16] = [0x01; 16];
    assert_ne!(other, TRAIL);
    assert!(other < TRAIL);
    let x_bound_hash: [u8; 32] = [0xaa; 32];
    let trust = TrustPolicy::builder()
        .trail(other)
        .key_through(fixture_pubkey(), 7, x_bound_hash)
        .key(x_other_new.public_key())
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, cp0.hash())
        .key(new.public_key())
        .build()
        .unwrap();
    let findings = verify_files_on_trail(vec![path_clean], trust, TRAIL);
    assert_findings(&findings, &[], "V11 clean Y");

    // Forged Y: cut back to the bound and forge above with the old key.
    let d_forged = Temp::new();
    let cp0b = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0b = seeded(&cp0b);
    let e1 = entry_rec(1, cp0b.hash());
    let mmr1 = pushed(&mmr0b, &e1);
    let forged_cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d_forged.0, 0, &[&cp0b, &e1, &forged_cp2], &[]);
    let path_forged = segment_path(&d_forged.0, 0);
    let trust_forged = TrustPolicy::builder()
        .trail(other)
        .key_through(fixture_pubkey(), 7, x_bound_hash)
        .key(x_other_new.public_key())
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, cp0b.hash())
        .key(new.public_key())
        .build()
        .unwrap();
    let findings_forged = verify_files_on_trail(vec![path_forged.clone()], trust_forged, TRAIL);
    let expected = vec![
        located(
            K::RevocationUnconfirmed,
            path_forged.clone(),
            1,
            0,
            format!(
                "key {FIXTURE_KEY_HEX} through=0: no trusted checkpoint by another key above the bound"
            ),
        ),
        located(
            K::UntrustedKey,
            path_forged,
            3,
            2,
            format!("key {FIXTURE_KEY_HEX} bounded through seq 0"),
        ),
        uncovered(1, 2),
    ];
    assert_findings(&findings_forged, &expected, "V11 forged Y");
}

// =====================================================================
// V12 — REGRESSION. A bound on an unrelated key in ANOTHER trail's
// section only; the verified trail has no bound. Expected list is
// empty. The other section's trail id precedes `TRAIL`
// (`[0x01; 16]` < `[17; 16]`) so the "first section only" scope mutant
// fires on it too (it points at an absent seq on `TRAIL`'s files).
// =====================================================================
#[test]
fn v12_bound_only_on_another_trail_is_scoped_out() {
    let fx = two_checkpoints();
    let other: [u8; 16] = [0x01; 16];
    assert_ne!(other, TRAIL);
    assert!(other < TRAIL);
    let unlisted = Arc::new(KeyFileSigner::from_hex(&"44".repeat(32)).unwrap());
    let bound_hash: [u8; 32] = [0xcc; 32];
    let trust = TrustPolicy::builder()
        .trail(other)
        .key_through(unlisted.public_key(), 42, bound_hash)
        .trail(TRAIL)
        .key(fixture_pubkey())
        .build()
        .unwrap();
    let findings = verify_files_on_trail(vec![fx.path.clone()], trust, TRAIL);
    assert_findings(&findings, &[], "V12");
    let _keep = fx.dir;
}

// =====================================================================
// V13 — ACCEPTANCE. A shipped-only trusted checkpoint confirms A's
// bound (ruling 13-V5-d4 point 5). A second, unrelated bound on key C
// at `seq=99` is absent and makes the acceptance row's main assertion
// non-empty; the shipped-only confirmation of A's bound is visible
// through the absence of any A-side revocation finding. Under a
// confirmation that counts native copies only, the shipped cp2 is
// dropped and A's bound emits `RevocationUnconfirmed` at cp0.
//
// Red on base (`revocation::check` stubbed to emit nothing): the
// expected list carries a `RevocationMismatch "…no record at seq 99"`
// and `RevocationUnconfirmed` for C's absent bound; neither is emitted
// on base, so the `assert_findings` literal comparison fails first.
// =====================================================================
#[test]
fn v13_shipped_only_confirming_checkpoint_confirms() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let new = new_signer();
    let shipped_cp2 = sign_with(&*new, 2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1], &[]);
    let native = segment_path(&d.0, 0);
    let shipped = d.0.join("cp2.copy");
    fs::write(&shipped, line_bytes(&shipped_cp2)).unwrap();
    let c = Arc::new(KeyFileSigner::from_hex(&"44".repeat(32)).unwrap());
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, cp0.hash())
        .key(new.public_key())
        .key_through(c.public_key(), 99, [0xee; 32])
        .build()
        .unwrap();
    let findings = verify_files_with(vec![native, shipped], trust);
    let expected = vec![
        unlocated(
            K::RevocationMismatch,
            Some(99),
            format!("key {C_KEY_HEX} through=99:{BOUND_HASH_EE_DIGEST}: no record at seq 99"),
        ),
        unlocated(
            K::RevocationUnconfirmed,
            Some(99),
            format!(
                "key {C_KEY_HEX} through=99: no trusted checkpoint by another key above the bound"
            ),
        ),
    ];
    assert_findings(&findings, &expected, "V13");
}

// =====================================================================
// V13b — ACCEPTANCE. As V13 but the shipped confirming checkpoint is
// at seq=1 (just above the bound). Pairs with V13 so a native-only
// confirmation leaves two failing rows.
//
// Red on base (`revocation::check` stubbed): same mechanism as V13 —
// the C-side `RevocationMismatch "…no record at seq 99"` and its
// `RevocationUnconfirmed` are missing on base.
// =====================================================================
#[test]
fn v13b_shipped_only_confirming_checkpoint_at_seq_one_confirms() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let new = new_signer();
    let shipped_cp1 = sign_with(&*new, 1, cp0.hash(), &mmr0);
    put_segment(&d.0, 0, &[&cp0], &[]);
    let native = segment_path(&d.0, 0);
    let shipped = d.0.join("cp1.copy");
    fs::write(&shipped, line_bytes(&shipped_cp1)).unwrap();
    let c = Arc::new(KeyFileSigner::from_hex(&"44".repeat(32)).unwrap());
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, cp0.hash())
        .key(new.public_key())
        .key_through(c.public_key(), 99, [0xee; 32])
        .build()
        .unwrap();
    let findings = verify_files_with(vec![native, shipped], trust);
    let expected = vec![
        unlocated(
            K::RevocationMismatch,
            Some(99),
            format!("key {C_KEY_HEX} through=99:{BOUND_HASH_EE_DIGEST}: no record at seq 99"),
        ),
        unlocated(
            K::RevocationUnconfirmed,
            Some(99),
            format!(
                "key {C_KEY_HEX} through=99: no trusted checkpoint by another key above the bound"
            ),
        ),
    ];
    assert_findings(&findings, &expected, "V13b");
}

// =====================================================================
// V14 — ACCEPTANCE. Pin location with a byte-identical duplicate: a
// shipped copy of the native cp0 shares the record at seq=0. A failing
// pin (wrong bound hash) emits `RevocationMismatch` at the native
// (first-in-merge-order) copy. A pin that reports the LAST copy would
// fail instead at the shipped path.
// =====================================================================
#[test]
fn v14_pin_location_uses_first_copy_on_wrong_hash() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    put_segment(&d.0, 0, &[&cp0], &[]);
    let native = segment_path(&d.0, 0);
    let shipped = d.0.join("cp0.copy");
    fs::write(&shipped, line_bytes(&cp0)).unwrap();
    let bound_hash: [u8; 32] = [0x5a; 32];
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, bound_hash)
        .build()
        .unwrap();
    let findings = verify_files_with(vec![native.clone(), shipped], trust);
    let expected = vec![
        located(
            K::DuplicateRecord,
            native.clone(),
            1,
            0,
            "2 copies of 1 distinct records".into(),
        ),
        located(
            K::RevocationMismatch,
            native.clone(),
            1,
            0,
            format!(
                "key {FIXTURE_KEY_HEX} through=0:{BOUND_HASH_5A_DIGEST}: record at seq 0 has hash {CP0_HONEST_DIGEST}"
            ),
        ),
        located(
            K::RevocationUnconfirmed,
            native,
            1,
            0,
            format!(
                "key {FIXTURE_KEY_HEX} through=0: no trusted checkpoint by another key above the bound"
            ),
        ),
    ];
    assert_findings(&findings, &expected, "V14");
}

// =====================================================================
// V14b — ACCEPTANCE. Byte-identical duplicate at seq=2 inside a longer
// layout. Pairs with V14 so a last-copy pin fails at two rows.
// =====================================================================
#[test]
fn v14b_pin_location_uses_first_copy_at_seq_two() {
    let fx = two_checkpoints();
    let shipped = fx.dir.0.join("cp2.copy");
    fs::write(&shipped, line_bytes(&fx.cp2)).unwrap();
    let bound_hash: [u8; 32] = [0x5a; 32];
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 2, bound_hash)
        .build()
        .unwrap();
    let findings = verify_files_with(vec![fx.path.clone(), shipped], trust);
    let expected = vec![
        located(
            K::DuplicateRecord,
            fx.path.clone(),
            3,
            2,
            "2 copies of 1 distinct records".into(),
        ),
        located(
            K::RevocationMismatch,
            fx.path.clone(),
            3,
            2,
            format!(
                "key {FIXTURE_KEY_HEX} through=2:{BOUND_HASH_5A_DIGEST}: record at seq 2 has hash {CP2_HONEST_DIGEST}"
            ),
        ),
        located(
            K::RevocationUnconfirmed,
            fx.path,
            3,
            2,
            format!(
                "key {FIXTURE_KEY_HEX} through=2: no trusted checkpoint by another key above the bound"
            ),
        ),
    ];
    assert_findings(&findings, &expected, "V14b");
    let _keep = fx.dir;
}

// =====================================================================
// V15 — ACCEPTANCE. Detail precedence: the record at `s` is an ENTRY
// whose hash differs from the bound. Under ruling 13-V5-d4 point 3,
// "has hash" wins over "not a checkpoint". A swap of those two detail
// strings leaves two failing rows (V15 and the V3/V3b "has hash" pair).
// =====================================================================
#[test]
fn v15_entry_with_wrong_hash_has_hash_wins_over_not_a_checkpoint() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    put_segment(&d.0, 0, &[&cp0, &e1], &[]);
    let path = segment_path(&d.0, 0);
    let bound_hash: [u8; 32] = [0x5a; 32];
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 1, bound_hash)
        .build()
        .unwrap();
    let findings = verify_files_with(vec![path.clone()], trust);
    let expected = vec![
        located(
            K::RevocationMismatch,
            path.clone(),
            2,
            1,
            format!(
                "key {FIXTURE_KEY_HEX} through=1:{BOUND_HASH_5A_DIGEST}: record at seq 1 has hash {E1_HONEST_DIGEST}"
            ),
        ),
        located(
            K::RevocationUnconfirmed,
            path,
            2,
            1,
            format!(
                "key {FIXTURE_KEY_HEX} through=1: no trusted checkpoint by another key above the bound"
            ),
        ),
        uncovered(1, 1),
    ];
    assert_findings(&findings, &expected, "V15");
}

// =====================================================================
// V15b — ACCEPTANCE. Detail precedence: `s` is forked AND the bound
// hash matches neither copy. Under ruling 13-V5-d4 point 3, "forked"
// wins over "has hash" (unlocated, no hash text). A swap of those
// adjacent precedences would emit a located "has hash" instead. Pairs
// with V15c below.
// =====================================================================
#[test]
fn v15b_forked_wins_over_has_hash_at_seq_two() {
    let fx = two_checkpoints();
    let twin_cp2 = signed_cp_explicit(2, fx.e1.hash(), 2, [0xde; 32], vec![[0x22; 32]]);
    let twin_path = fx.dir.0.join("cp2.twin");
    fs::write(&twin_path, line_bytes(&twin_cp2)).unwrap();
    let bound_hash: [u8; 32] = [0x5a; 32];
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 2, bound_hash)
        .build()
        .unwrap();
    let findings = verify_files_with(vec![fx.path.clone(), twin_path], trust);
    let expected = vec![
        unlocated(
            K::RevocationMismatch,
            Some(2),
            format!("key {FIXTURE_KEY_HEX} through=2:{BOUND_HASH_5A_DIGEST}: seq 2 is forked"),
        ),
        unlocated(
            K::RevocationUnconfirmed,
            Some(2),
            format!(
                "key {FIXTURE_KEY_HEX} through=2: no trusted checkpoint by another key above the bound"
            ),
        ),
        located(
            K::SeqConflict,
            fx.path.clone(),
            3,
            2,
            format!("conflicting hashes: {CP2_HONEST_DIGEST}, {CP2_TWIN_V6_DIGEST}"),
        ),
    ];
    assert_findings(&findings, &expected, "V15b");
    let _keep = fx.dir;
}

// =====================================================================
// V15c — ACCEPTANCE. Companion to V15b: forked at seq=0 with a wrong
// bound hash. Pairs with V15b so a forked/has-hash swap leaves two
// failing rows.
// =====================================================================
#[test]
fn v15c_forked_wins_over_has_hash_at_seq_zero() {
    let d = Temp::new();
    let honest_cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    put_segment(&d.0, 0, &[&honest_cp0], &[]);
    let native = segment_path(&d.0, 0);
    let twin_cp0 = signed_cp_explicit(0, Record::genesis(&TRAIL), 0, [0xde; 32], vec![]);
    let twin_path = d.0.join("cp0.twin");
    fs::write(&twin_path, line_bytes(&twin_cp0)).unwrap();
    let bound_hash: [u8; 32] = [0x5a; 32];
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, bound_hash)
        .build()
        .unwrap();
    let findings = verify_files_with(vec![native.clone(), twin_path], trust);
    let expected = vec![
        unlocated(
            K::RevocationMismatch,
            Some(0),
            format!("key {FIXTURE_KEY_HEX} through=0:{BOUND_HASH_5A_DIGEST}: seq 0 is forked"),
        ),
        unlocated(
            K::RevocationUnconfirmed,
            Some(0),
            format!(
                "key {FIXTURE_KEY_HEX} through=0: no trusted checkpoint by another key above the bound"
            ),
        ),
        located(
            K::SeqConflict,
            native,
            1,
            0,
            format!("conflicting hashes: {CP0_TWIN_V6B_DIGEST}, {CP0_HONEST_DIGEST}"),
        ),
    ];
    assert_findings(&findings, &expected, "V15c");
}

// =====================================================================
// Bound at an other-key cp, strict confirmation. At `s=1` the record
// is a checkpoint signed by B ≠ A, so the key-identity pin emits
// `RevocationMismatch "…signed by key B"`. Confirmation strictly above
// `s=1` has no records → `RevocationUnconfirmed`. An inclusive
// confirmation would accept cp1 itself as the confirming other-key
// checkpoint and drop `RevocationUnconfirmed`; a pin that skips the
// key-identity check would drop `RevocationMismatch`.
// =====================================================================
#[test]
fn bound_at_other_key_cp_strict_confirmation_is_unconfirmed_and_pin_fails_on_key() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let new = new_signer();
    let cp1 = sign_with(&*new, 1, cp0.hash(), &mmr0);
    put_segment(&d.0, 0, &[&cp0, &cp1], &[]);
    let path = segment_path(&d.0, 0);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 1, cp1.hash())
        .key(new.public_key())
        .build()
        .unwrap();
    let findings = verify_files_with(vec![path.clone()], trust);
    let expected = vec![
        located(
            K::RevocationMismatch,
            path.clone(),
            2,
            1,
            format!(
                "key {FIXTURE_KEY_HEX} through=1:{NEW_CP1_DIGEST}: record at seq 1 is signed by key {NEW_KEY_HEX}"
            ),
        ),
        located(
            K::RevocationUnconfirmed,
            path,
            2,
            1,
            format!(
                "key {FIXTURE_KEY_HEX} through=1: no trusted checkpoint by another key above the bound"
            ),
        ),
    ];
    assert_findings(&findings, &expected, "bound_at_other_key_cp");
}

// =====================================================================
// As the preceding row plus an entry at `seq=2` above the bound, so
// cp1 is not the only record above `s`. The record at `seq=2` is an
// entry, not a checkpoint, so strict confirmation still has no
// confirming cp → `RevocationUnconfirmed`. An inclusive confirmation
// would still accept cp1 and drop `RevocationUnconfirmed`. The
// coverage pass promotes the trail through seq=1 (cp1 trusted) so
// `UncoveredTail` names the entry at seq=2 only.
// =====================================================================
#[test]
fn bound_at_other_key_cp_with_entry_above_is_unconfirmed_and_pin_fails_on_key() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let new = new_signer();
    let cp1 = sign_with(&*new, 1, cp0.hash(), &mmr0);
    let e2 = entry_rec(2, cp1.hash());
    put_segment(&d.0, 0, &[&cp0, &cp1, &e2], &[]);
    let path = segment_path(&d.0, 0);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 1, cp1.hash())
        .key(new.public_key())
        .build()
        .unwrap();
    let findings = verify_files_with(vec![path.clone()], trust);
    let expected = vec![
        located(
            K::RevocationMismatch,
            path.clone(),
            2,
            1,
            format!(
                "key {FIXTURE_KEY_HEX} through=1:{NEW_CP1_DIGEST}: record at seq 1 is signed by key {NEW_KEY_HEX}"
            ),
        ),
        located(
            K::RevocationUnconfirmed,
            path,
            2,
            1,
            format!(
                "key {FIXTURE_KEY_HEX} through=1: no trusted checkpoint by another key above the bound"
            ),
        ),
        uncovered(2, 2),
    ];
    assert_findings(
        &findings,
        &expected,
        "bound_at_other_key_cp_with_entry_above",
    );
}

// =====================================================================
// V1 — REGRESSION (ADR-0005 decision 11 revocation bullet:
// "Following the procedure exactly after a clean stop → no error").
// Drives the real `AuditConfig::rotate` on a freshly closed trail: the
// bound names the old key's close checkpoint, and the rotate writes a
// `vigil.audit.key_rotated` operator entry followed by a new-key
// checkpoint. The verified list is empty.
//
// Measured over-strict mutant kills (runtime exit 101 on this row):
// - confirmation that requires the same key as the bounded one
//   (Q1R): the new-key checkpoint no longer confirms, so the row
//   emits `RevocationUnconfirmed`;
// - confirmation that requires the confirming checkpoint at exactly
//   `s + 1` (R2): seq `s + 1` is the `key_rotated` entry on a clean
//   stop, not a checkpoint, so the row emits `RevocationUnconfirmed`.
// =====================================================================
#[test]
fn v1_clean_stop_rotation_is_clean() {
    let temp = Temp::new();
    let dir = temp.0.clone();
    let old = old_signer();
    let new = new_signer();
    let (trail_id, close) = {
        let handle = AuditConfig::new("svc")
            .dir(&dir)
            .create(old.clone())
            .unwrap();
        let trail_id = handle.trail();
        handle
            .record(&crate::audit::Entry::new("actor", "change", "obj"))
            .unwrap();
        let close = handle.close().unwrap();
        (trail_id, close)
    };
    let (_r, _c) = AuditConfig::new("svc")
        .dir(&dir)
        .rotate(
            new.clone(),
            (close.seq(), close.hash()),
            (close.seq(), close.hash()),
            "operator",
            "scheduled",
        )
        .unwrap();
    let trust = TrustPolicy::builder()
        .trail(trail_id)
        .key_through(old.public_key(), close.seq(), close.hash())
        .key(new.public_key())
        .build()
        .unwrap();
    let findings = verify_dir_with(&dir, trust);
    assert_findings(&findings, &[], "V1");
}

// =====================================================================
// P1 — ACCEPTANCE. Precedence under d4 point 3: the record at `s=1`
// is a checkpoint signed by the OTHER key (B) and the bound carries a
// wrong hash. Hash precedence (3) wins over signed-by-another-key (5),
// so the pin emits `"…has hash …"`, located at the first copy. A pin
// that runs the key check before the hash check (M7) swaps the two
// details and emits `"…is signed by key …"`; a pin that runs the key
// check before the fork check (M8) also fires the key detail since
// no fork exists at `s=1`.
// =====================================================================
#[test]
fn p1_other_key_cp_with_wrong_hash_emits_hash_detail() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let new = new_signer();
    let cp1 = sign_with(&*new, 1, cp0.hash(), &mmr0);
    put_segment(&d.0, 0, &[&cp0, &cp1], &[]);
    let path = segment_path(&d.0, 0);
    let bound_hash: [u8; 32] = [0x5a; 32];
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 1, bound_hash)
        .key(new.public_key())
        .build()
        .unwrap();
    let findings = verify_files_with(vec![path.clone()], trust);
    let expected = vec![
        located(
            K::RevocationMismatch,
            path.clone(),
            2,
            1,
            format!(
                "key {FIXTURE_KEY_HEX} through=1:{BOUND_HASH_5A_DIGEST}: record at seq 1 has hash {NEW_CP1_DIGEST}"
            ),
        ),
        located(
            K::RevocationUnconfirmed,
            path,
            2,
            1,
            format!(
                "key {FIXTURE_KEY_HEX} through=1: no trusted checkpoint by another key above the bound"
            ),
        ),
    ];
    assert_findings(&findings, &expected, "P1");
}

// =====================================================================
// P1b — ACCEPTANCE. As P1 plus a byte-identical shipped copy of the
// pinned record. Pairs with P1 so a key-check-before-hash reordering
// leaves two failing rows for M7.
// =====================================================================
#[test]
fn p1b_other_key_cp_with_wrong_hash_duplicated_emits_hash_detail() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let new = new_signer();
    let cp1 = sign_with(&*new, 1, cp0.hash(), &mmr0);
    put_segment(&d.0, 0, &[&cp0, &cp1], &[]);
    let native = segment_path(&d.0, 0);
    let shipped = d.0.join("cp1.copy");
    fs::write(&shipped, line_bytes(&cp1)).unwrap();
    let bound_hash: [u8; 32] = [0x5a; 32];
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 1, bound_hash)
        .key(new.public_key())
        .build()
        .unwrap();
    let findings = verify_files_with(vec![native.clone(), shipped], trust);
    let expected = vec![
        located(
            K::DuplicateRecord,
            native.clone(),
            2,
            1,
            "2 copies of 1 distinct records".into(),
        ),
        located(
            K::RevocationMismatch,
            native.clone(),
            2,
            1,
            format!(
                "key {FIXTURE_KEY_HEX} through=1:{BOUND_HASH_5A_DIGEST}: record at seq 1 has hash {NEW_CP1_DIGEST}"
            ),
        ),
        located(
            K::RevocationUnconfirmed,
            native,
            2,
            1,
            format!(
                "key {FIXTURE_KEY_HEX} through=1: no trusted checkpoint by another key above the bound"
            ),
        ),
    ];
    assert_findings(&findings, &expected, "P1b");
}

// =====================================================================
// P2 — ACCEPTANCE. Precedence under d4 point 3: `s=1` is forked, and
// every copy at `s` is a checkpoint signed by the OTHER key (B).
// Fork precedence (2) wins over signed-by-another-key (5), so the pin
// emits `"…seq s is forked"`, unlocated. A pin that runs the key
// check before the fork check (M8) fires the key detail instead,
// located at the first copy.
// =====================================================================
#[test]
fn p2_other_key_cp_fork_emits_forked_detail() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let new = new_signer();
    let cp1 = sign_with(&*new, 1, cp0.hash(), &mmr0);
    let twin_cp1 = sign_with_fields(&*new, 1, cp0.hash(), 1, [0xbb; 32], vec![[0xbb; 32]]);
    put_segment(&d.0, 0, &[&cp0, &cp1], &[]);
    let native = segment_path(&d.0, 0);
    let shipped = d.0.join("cp1.twin");
    fs::write(&shipped, line_bytes(&twin_cp1)).unwrap();
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 1, cp1.hash())
        .key(new.public_key())
        .build()
        .unwrap();
    let findings = verify_files_with(vec![native.clone(), shipped], trust);
    let expected = vec![
        unlocated(
            K::RevocationMismatch,
            Some(1),
            format!("key {FIXTURE_KEY_HEX} through=1:{NEW_CP1_DIGEST}: seq 1 is forked"),
        ),
        unlocated(
            K::RevocationUnconfirmed,
            Some(1),
            format!(
                "key {FIXTURE_KEY_HEX} through=1: no trusted checkpoint by another key above the bound"
            ),
        ),
        located(
            K::SeqConflict,
            native,
            2,
            1,
            format!("conflicting hashes: {NEW_CP1_DIGEST}, {NEW_CP1_TWIN_DIGEST}"),
        ),
    ];
    assert_findings(&findings, &expected, "P2");
}

// =====================================================================
// P2b — ACCEPTANCE. As P2 plus an entry at seq=2 above the forked
// seq, so the layout differs from P2 even though the fork mechanism
// is the same. Pairs with P2 so a key-check-before-fork reordering
// leaves two failing rows for M8.
// =====================================================================
#[test]
fn p2b_other_key_cp_fork_with_entry_above_emits_forked_detail() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let new = new_signer();
    let cp1 = sign_with(&*new, 1, cp0.hash(), &mmr0);
    let twin_cp1 = sign_with_fields(&*new, 1, cp0.hash(), 1, [0xbb; 32], vec![[0xbb; 32]]);
    let e2 = entry_rec(2, cp1.hash());
    put_segment(&d.0, 0, &[&cp0, &cp1, &e2], &[]);
    let native = segment_path(&d.0, 0);
    let shipped = d.0.join("cp1.twin");
    fs::write(&shipped, line_bytes(&twin_cp1)).unwrap();
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 1, cp1.hash())
        .key(new.public_key())
        .build()
        .unwrap();
    let findings = verify_files_with(vec![native.clone(), shipped], trust);
    let expected = vec![
        unlocated(
            K::RevocationMismatch,
            Some(1),
            format!("key {FIXTURE_KEY_HEX} through=1:{NEW_CP1_DIGEST}: seq 1 is forked"),
        ),
        unlocated(
            K::RevocationUnconfirmed,
            Some(1),
            format!(
                "key {FIXTURE_KEY_HEX} through=1: no trusted checkpoint by another key above the bound"
            ),
        ),
        located(
            K::SeqConflict,
            native,
            2,
            1,
            format!("conflicting hashes: {NEW_CP1_DIGEST}, {NEW_CP1_TWIN_DIGEST}"),
        ),
        uncovered(2, 2),
    ];
    assert_findings(&findings, &expected, "P2b");
}

// =====================================================================
// V15d — ACCEPTANCE. Precedence under d4 point 3: an entry at `s=2`
// with a wrong hash. Hash precedence (3) wins over not-a-checkpoint
// (4), so the pin emits `"…has hash …"`. Pairs with V15 (same
// scenario at `s=1`) so a swap of those two details leaves two
// failing rows for M2r.
// =====================================================================
#[test]
fn v15d_entry_at_seq_two_wrong_hash_emits_hash_detail() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    let e2 = entry_rec(2, e1.hash());
    put_segment(&d.0, 0, &[&cp0, &e1, &e2], &[]);
    let path = segment_path(&d.0, 0);
    let bound_hash: [u8; 32] = [0x5a; 32];
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 2, bound_hash)
        .build()
        .unwrap();
    let findings = verify_files_with(vec![path.clone()], trust);
    let expected = vec![
        located(
            K::RevocationMismatch,
            path.clone(),
            3,
            2,
            format!(
                "key {FIXTURE_KEY_HEX} through=2:{BOUND_HASH_5A_DIGEST}: record at seq 2 has hash {E2_DIGEST}"
            ),
        ),
        located(
            K::RevocationUnconfirmed,
            path,
            3,
            2,
            format!(
                "key {FIXTURE_KEY_HEX} through=2: no trusted checkpoint by another key above the bound"
            ),
        ),
        uncovered(1, 2),
    ];
    assert_findings(&findings, &expected, "V15d");
}

// =====================================================================
// Fixture-hash consistency: every digest / key constant in the row
// details corresponds to the record the fixtures actually produce.
// A drift lands here instead of in a per-row digest mismatch.
// =====================================================================
#[test]
fn fixture_hashes_match_literals() {
    assert_eq!(hex(&fixture_pubkey()), FIXTURE_KEY_HEX);
    assert_eq!(hex(&new_pubkey()), NEW_KEY_HEX);
    assert_eq!(hex(&TRAIL), TRAIL_HEX);
    let fx = two_checkpoints();
    assert_eq!(digest_string(&fx.cp0.hash()), CP0_HONEST_DIGEST);
    assert_eq!(digest_string(&fx.e1.hash()), E1_HONEST_DIGEST);
    assert_eq!(digest_string(&fx.cp2.hash()), CP2_HONEST_DIGEST);
    let _keep = fx.dir;
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    // V6's twin cp2 hash.
    let twin_v6 = signed_cp_explicit(2, e1.hash(), 2, [0xde; 32], vec![[0x22; 32]]);
    assert_eq!(digest_string(&twin_v6.hash()), CP2_TWIN_V6_DIGEST);
    // V6b's twin cp0 hash.
    let twin_v6b = signed_cp_explicit(0, Record::genesis(&TRAIL), 0, [0xde; 32], vec![]);
    assert_eq!(digest_string(&twin_v6b.hash()), CP0_TWIN_V6B_DIGEST);
    // Other-key cp1 hash (new-key sign of seq=1 chained from cp0).
    let new = new_signer();
    let new_cp1 = sign_with(&*new, 1, cp0.hash(), &mmr0);
    assert_eq!(digest_string(&new_cp1.hash()), NEW_CP1_DIGEST);
    // Twin other-key cp1 hash (new-key sign with alt fields).
    let twin_new_cp1 = sign_with_fields(&*new, 1, cp0.hash(), 1, [0xbb; 32], vec![[0xbb; 32]]);
    assert_eq!(digest_string(&twin_new_cp1.hash()), NEW_CP1_TWIN_DIGEST);
    // Entry at seq=2 chained from e1.
    let e2 = entry_rec(2, e1.hash());
    assert_eq!(digest_string(&e2.hash()), E2_DIGEST);
    // Hand-crafted bound hashes.
    assert_eq!(digest_string(&[0x5a; 32]), BOUND_HASH_5A_DIGEST);
    assert_eq!(digest_string(&[0xee; 32]), BOUND_HASH_EE_DIGEST);
    // V13/V13b's C key (seed `0x44`).
    let c = Arc::new(KeyFileSigner::from_hex(&"44".repeat(32)).unwrap());
    assert_eq!(hex(&c.public_key()), C_KEY_HEX);
}
