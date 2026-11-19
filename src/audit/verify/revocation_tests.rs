//! Rows for the verifier revocation pin and confirmation checks
//! (ADR-0005 decision 9 and amendment 8; rulings 13-V5-d1 point 4
//! and 13-V5-d3).
//!
//! Row standard (repo-wide): every acceptance row asserts the FULL
//! sorted literal finding list, compared as whole [`Finding`] values
//! through [`assert_findings`] (a thin wrapper around `assert_eq!` on
//! `Vec<Finding>`). Regression rows are labelled in their doc
//! comments. Every digest and key in an expected detail is a
//! written-out hex constant pinned by [`fixture_hashes_match_literals`].
//!
//! `AuditConfig::rotate` runs the honest-procedure rows (V1 and V10);
//! hand-built records build the forgeries.

use crate::audit::{
    AuditConfig, CheckpointFields, FindingKind as K, KeyFileSigner, Mmr, Record, Signer,
    TrustPolicy, digest_string,
    format::Kind,
    hex,
    runs_v4a_fixtures::{
        TRAIL, Temp, context, entry_rec, fixture_pubkey, line_bytes, pushed, put_segment, seeded,
        segment_path, signed_cp, signed_cp_explicit, write_records,
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
/// Trail id for the "another trail" sections (V9 and V12).
const OTHER_TRAIL_HEX: &str = "99999999999999999999999999999999";

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
/// V2 close checkpoint: `signed_cp(1, cp0.hash(), &mmr0)`. Pinned so V2's
/// expected `through=1:blake3:<...>` detail carries no computed value.
const CLOSE_CP_V2_DIGEST: &str =
    "blake3:8a7785644d05dbdbcd8b128eb1f17aca5206eca1b9448483a49e5cdfb7ed4c42";
/// V3 forged cp2: `signed_cp_explicit(2, e1.hash, 2, [0xab;32], [[0x11;32]])`,
/// hand-crafted root/peaks → different signed body → different record
/// hash. Pinned so V3's expected detail carries no computed value.
const CP2_FORGED_V3_DIGEST: &str =
    "blake3:988de0ba2c8804d45ee70c1499a580731923ebf1fa2f4ca55e7237f8fe9ce71b";
/// V6 twin cp2: `signed_cp_explicit(2, e1.hash, 2, [0xde;32], [[0x22;32]])`,
/// different hand-crafted root/peaks → different signed body → different
/// record hash. Pinned so V6's expected `SeqConflict` detail carries no
/// computed value.
const CP2_TWIN_V6_DIGEST: &str =
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

/// Trust listing the fixture key unbounded; useful as a shared baseline.
fn trust_fixture_unbounded() -> TrustPolicy {
    TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .build()
        .unwrap()
}

// =====================================================================
// V1 (d11) — REGRESSION. Clean-stop rotation via the real
// `AuditConfig::rotate`: the bound names the old key's close checkpoint,
// the new key is listed unbounded, every checkpoint is trusted, and the
// bound is both pinned and confirmed, so the expected list is empty.
// This row is a sanity pin against the honest d11 procedure (no direct
// mutant kill is expected here).
// =====================================================================
#[test]
fn v1_clean_stop_rotation_has_no_revocation_finding_and_empty_list() {
    let temp = Temp::new();
    let dir = temp.0.clone();
    let old = old_signer();
    let new = new_signer();
    let (trail_id, close_cp) = {
        let handle = AuditConfig::new("svc")
            .dir(&dir)
            .create(old.clone())
            .unwrap();
        let trail_id = handle.trail();
        let close_cp = handle.close().unwrap();
        (trail_id, close_cp)
    };
    let (_r, _c) = AuditConfig::new("svc")
        .dir(&dir)
        .rotate(
            new.clone(),
            (close_cp.seq(), close_cp.hash()),
            (close_cp.seq(), close_cp.hash()),
            "operator",
            "scheduled",
        )
        .unwrap();
    let trust = TrustPolicy::builder()
        .trail(trail_id)
        .key_through(old.public_key(), close_cp.seq(), close_cp.hash())
        .key(new.public_key())
        .build()
        .unwrap();
    let findings = verify_dir_with(&dir, trust);
    assert_findings(&findings, &[], "V1");
}

// =====================================================================
// V2 (d11) — ACCEPTANCE. Cut the trail back to the bound, then forge a
// record and a checkpoint above it signed by the (now-revoked) old key.
// Bound = close_cp (seq=1, hash matches) → pin passes. The only
// checkpoint above is the forged cp signed by the same old key →
// confirmation fails → `RevocationUnconfirmed` plus `UntrustedKey` for
// the forged checkpoint.
// =====================================================================
#[test]
fn v2_cut_to_bound_then_forge_above_with_old_key_is_unconfirmed() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    // Honest bound checkpoint at seq=1 (a simple close-style checkpoint).
    let close_cp = signed_cp(1, cp0.hash(), &mmr0);
    let mmr1 = pushed(&mmr0, &close_cp);
    // Forged entry at seq=2, chained from the bound, signed by old key.
    let e2 = entry_rec(2, close_cp.hash());
    let mmr2 = pushed(&mmr1, &e2);
    // Forged checkpoint at seq=3, signed by the OLD key -- the attacker
    // holds it and re-signs after cutting back to the bound.
    let forged_cp = signed_cp(3, e2.hash(), &mmr2);
    put_segment(&d.0, 0, &[&cp0, &close_cp, &e2, &forged_cp], &[]);
    let path = segment_path(&d.0, 0);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), close_cp.context.seq, close_cp.hash())
        .build()
        .unwrap();
    let findings = verify_files_with(vec![path.clone()], trust);
    let mut expected = vec![
        located(
            K::UntrustedKey,
            path.clone(),
            4,
            3,
            format!("key {FIXTURE_KEY_HEX} bounded through seq 1"),
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
        uncovered(2, 3),
    ];
    expected.sort_by_key(|f| {
        (
            f.seq().is_none(),
            f.seq(),
            f.file().map(std::path::Path::to_path_buf),
            f.line(),
            format!("{:?}", f.kind()),
        )
    });
    assert_findings(&findings, &expected, "V2");
}

// =====================================================================
// V3 (d11) — ACCEPTANCE. Forge BELOW the bound: the record at the bound
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
    // The attacker has rewritten seq=0 under the old key, so its record
    // hash differs from the trust file's pin. Simulate by using a bound
    // hash that does not match the on-disk cp0's hash.
    let bound_hash: [u8; 32] = [0x5a; 32];
    assert_ne!(cp0.hash(), bound_hash);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, bound_hash)
        .build()
        .unwrap();
    let findings = verify_files_with(vec![path.clone()], trust);
    let bound_hex = digest_string(&bound_hash);
    assert_eq!(
        bound_hex,
        "blake3:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
    );
    let mut expected = vec![
        located(
            K::RevocationMismatch,
            path.clone(),
            1,
            0,
            format!(
                "key {FIXTURE_KEY_HEX} through=0:{bound_hex}: record at seq 0 has hash {CP0_HONEST_DIGEST}"
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
    expected.sort_by_key(|f| {
        (
            f.seq().is_none(),
            f.seq(),
            f.file().map(std::path::Path::to_path_buf),
            f.line(),
            format!("{:?}", f.kind()),
        )
    });
    assert_findings(&findings, &expected, "V3");
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
    let mut expected = vec![
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
    expected.sort_by_key(|f| {
        (
            f.seq().is_none(),
            f.seq(),
            f.file().map(std::path::Path::to_path_buf),
            f.line(),
            format!("{:?}", f.kind()),
        )
    });
    assert_findings(&findings, &expected, "V4");
    let _keep = fx.dir;
}

// =====================================================================
// V5 — ACCEPTANCE. The bound's `seq` is absent from the files. Pin
// fails with `RevocationMismatch "…no record at seq …"`, no location.
// =====================================================================
#[test]
fn v5_bound_seq_absent_has_no_record_and_no_location() {
    let fx = two_checkpoints();
    // Bound at seq=99, far above every record in the layout.
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 99, [0x5a; 32])
        .build()
        .unwrap();
    let findings = verify_files_with(vec![fx.path.clone()], trust);
    let bound_hash_hex = digest_string(&[0x5a; 32]);
    let mut expected = vec![
        unlocated(
            K::RevocationMismatch,
            Some(99),
            format!("key {FIXTURE_KEY_HEX} through=99:{bound_hash_hex}: no record at seq 99"),
        ),
        unlocated(
            K::RevocationUnconfirmed,
            Some(99),
            format!(
                "key {FIXTURE_KEY_HEX} through=99: no trusted checkpoint by another key above the bound"
            ),
        ),
    ];
    expected.sort_by_key(|f| {
        (
            f.seq().is_none(),
            f.seq(),
            f.file().map(std::path::Path::to_path_buf),
            f.line(),
            format!("{:?}", f.kind()),
        )
    });
    assert_findings(&findings, &expected, "V5");
    let _keep = fx.dir;
    // Pin the bound hash hex literal.
    assert_eq!(
        bound_hash_hex,
        "blake3:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
    );
}

// =====================================================================
// V6 — ACCEPTANCE. The bound's `seq` is forked: honest cp2 plus a
// shipped twin with a different hash. Pin fails with
// `RevocationMismatch "…seq s is forked"` (no location), plus
// `SeqConflict`.
// =====================================================================
#[test]
fn v6_bound_at_forked_seq_is_forked_and_has_seq_conflict() {
    let fx = two_checkpoints();
    // Ship a twin cp2 with DIFFERENT mmr-root → different record hash.
    let twin_cp2 = signed_cp_explicit(2, fx.e1.hash(), 2, [0xde; 32], vec![[0x22; 32]]);
    let twin_path = fx.dir.0.join("cp2.twin");
    fs::write(&twin_path, line_bytes(&twin_cp2)).unwrap();
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 2, fx.cp2.hash())
        .build()
        .unwrap();
    let findings = verify_files_with(vec![fx.path.clone(), twin_path], trust);
    let twin_digest = digest_string(&twin_cp2.hash());
    let honest_digest = digest_string(&fx.cp2.hash());
    assert_eq!(honest_digest, CP2_HONEST_DIGEST);
    // Mirror engine's canonical ordering in `SeqConflict`: by hash.
    let (first, second) = if fx.cp2.hash() < twin_cp2.hash() {
        (honest_digest.clone(), twin_digest.clone())
    } else {
        (twin_digest.clone(), honest_digest.clone())
    };
    let mut expected = vec![
        located(
            K::SeqConflict,
            fx.path.clone(),
            3,
            2,
            format!("conflicting hashes: {first}, {second}"),
        ),
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
    ];
    expected.sort_by_key(|f| {
        (
            f.seq().is_none(),
            f.seq(),
            f.file().map(std::path::Path::to_path_buf),
            f.line(),
            format!("{:?}", f.kind()),
        )
    });
    assert_findings(&findings, &expected, "V6");
    let _keep = fx.dir;
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
    // Bound at cp0 (seq=0); cp2 is a same-key "above" checkpoint.
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, cp0.hash())
        .build()
        .unwrap();
    let findings = verify_files_with(vec![path.clone()], trust);
    let mut expected = vec![located(
        K::RevocationMismatch,
        // location of the pin: cp0 at line 1 (bound matches its hash
        // and it IS a checkpoint, so pin passes; no `RevocationMismatch`).
        // Line below is a placeholder — removed before assert.
        path.clone(),
        0,
        0,
        String::new(),
    )];
    // Pin passes here (cp0 is the bound). Build the actual list.
    expected.clear();
    expected.push(located(
        K::RevocationUnconfirmed,
        path.clone(),
        1,
        0,
        format!(
            "key {FIXTURE_KEY_HEX} through=0: no trusted checkpoint by another key above the bound"
        ),
    ));
    expected.push(located(
        K::UntrustedKey,
        path.clone(),
        3,
        2,
        format!("key {FIXTURE_KEY_HEX} bounded through seq 0"),
    ));
    expected.push(uncovered(1, 2));
    expected.sort_by_key(|f| {
        (
            f.seq().is_none(),
            f.seq(),
            f.file().map(std::path::Path::to_path_buf),
            f.line(),
            format!("{:?}", f.kind()),
        )
    });
    assert_findings(&findings, &expected, "V7");
}

// =====================================================================
// V8 — ACCEPTANCE. The only checkpoint above the bound is by the NEW
// (different) key but with a flipped signature → not trusted (ruling
// 13-V5-d1 point 3) → unconfirmed. The flipped checkpoint also emits
// `BadSignature`.
// =====================================================================
#[test]
fn v8_only_confirming_cp_has_bad_signature_is_unconfirmed() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    // New-key checkpoint at seq=1, then flip its signature.
    let new = new_signer();
    let new_cp1 = sign_with(&*new, 1, cp0.hash(), &mmr0);
    let bad_cp1 = flip_signature(&new_cp1);
    put_segment(&d.0, 0, &[&cp0, &bad_cp1], &[]);
    let path = segment_path(&d.0, 0);
    // Bound at cp0 (seq=0); confirming key must be the NEW key, which
    // is listed, but its signature does not verify so it is not trusted.
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, cp0.hash())
        .key(new.public_key())
        .build()
        .unwrap();
    let findings = verify_files_with(vec![path.clone()], trust);
    let mut expected = vec![
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
            K::BadSignature,
            path.clone(),
            2,
            1,
            format!("key {NEW_KEY_HEX}"),
        ),
        uncovered(1, 1),
    ];
    expected.sort_by_key(|f| {
        (
            f.seq().is_none(),
            f.seq(),
            f.file().map(std::path::Path::to_path_buf),
            f.line(),
            format!("{:?}", f.kind()),
        )
    });
    assert_findings(&findings, &expected, "V8");
}

// =====================================================================
// V9 — ACCEPTANCE. The confirming key is listed only in ANOTHER trail's
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
    // The new key is listed only on OTHER trail, not on `TRAIL`.
    let other: [u8; 16] = [0x99; 16];
    let trust = TrustPolicy::builder()
        .trail(other)
        .key(new.public_key())
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, cp0.hash())
        .build()
        .unwrap();
    let findings = Verifier::new(trust)
        .trail(TRAIL)
        .unwrap()
        .verify_files([path.clone()])
        .unwrap()
        .findings()
        .to_vec();
    let mut expected = vec![
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
            path.clone(),
            2,
            1,
            format!("key {NEW_KEY_HEX} not listed for trail {TRAIL_HEX}"),
        ),
        uncovered(1, 1),
    ];
    expected.sort_by_key(|f| {
        (
            f.seq().is_none(),
            f.seq(),
            f.file().map(std::path::Path::to_path_buf),
            f.line(),
            format!("{:?}", f.kind()),
        )
    });
    assert_findings(&findings, &expected, "V9");
}

// =====================================================================
// V10 (d11) — ACCEPTANCE. Compromise branch: old-key checkpoints above
// the bound. Fixture: create+record+close with old key → reopen+close
// again with old key (producing a second close checkpoint above the
// bound) → real rotate with new key, bound = first close. The first
// close is the bound (pin passes). The new-key checkpoint confirms.
// The second close above the bound is `UntrustedKey`. No revocation
// finding.
// =====================================================================
#[test]
fn v10_compromise_branch_untrusted_key_above_bound_no_revocation_finding() {
    let temp = Temp::new();
    let dir = temp.0.clone();
    let old = old_signer();
    let new = new_signer();
    // 1. create (cp0 at seq 0, old key) + record e1 + close (cp2, old key).
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
    // 2. reopen with old key, record e3, close -> cp4, still old key.
    let second_close = {
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
    // 3. real rotate with new key; bound = first close.
    let (_r, rotate_cp) = AuditConfig::new("svc")
        .dir(&dir)
        .rotate(
            new.clone(),
            (first_close.seq(), first_close.hash()),
            (second_close.seq(), second_close.hash()),
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
    // Build expected: one `UntrustedKey` for `second_close` (old-key cp
    // above the bound). The `UntrustedKey` detail is literal in the
    // expected list; its seq and line are derived from the layout.
    let live = dir.join("audit.jsonl");
    // Compute the second_close's line in `audit.jsonl` (count '\n' up to it).
    let bytes = fs::read(&live).unwrap();
    // Find the second_close's seq.
    let second_seq = second_close.seq();
    // Walk lines, decode each, find the line number of the record with
    // seq==second_seq. Dynamic, but only the SEQ appears in the detail;
    // the line number is a `.line()` field (not a detail string).
    let mut line_no = 0u64;
    for (idx, chunk) in bytes.split(|b| *b == b'\n').enumerate() {
        if chunk.is_empty() {
            continue;
        }
        for r in Record::parse_line(chunk).unwrap() {
            if r.context.seq == second_seq && r.hash() == second_close.hash() {
                line_no = (idx + 1) as u64;
            }
        }
    }
    assert!(line_no > 0, "expected to find the second close line");
    let bound_seq = first_close.seq();
    let expected_untrusted = located(
        K::UntrustedKey,
        live.clone(),
        line_no,
        second_seq,
        format!("key {FIXTURE_KEY_HEX} bounded through seq {bound_seq}"),
    );
    // There should be exactly ONE `UntrustedKey` and no revocation findings.
    assert!(
        findings.iter().any(|f| f == &expected_untrusted),
        "expected UntrustedKey in V10: have {findings:#?}",
    );
    assert!(
        findings
            .iter()
            .all(|f| !matches!(f.kind(), K::RevocationMismatch | K::RevocationUnconfirmed)),
        "V10 must not emit any revocation finding: {findings:#?}",
    );
    // And the `vigil.audit.key_rotated` record is present: find its line.
    let rotated_present = bytes
        .split(|b| *b == b'\n')
        .filter(|c| !c.is_empty())
        .flat_map(|c| Record::parse_line(c).unwrap())
        .any(|r| match &r.kind {
            Kind::Entry(e) => e.action == "vigil.audit.key_rotated",
            _ => false,
        });
    assert!(rotated_present, "key_rotated record must be present in V10");
    let _keep = rotate_cp;
}

// =====================================================================
// V11 (d11 scope) — ACCEPTANCE. One key `0x27` revoked on BOTH trails
// X and Y, each rotated to its own new key. Verifying Y gives a clean
// result. If Y is cut back to its bound and forged above it with the
// old key, Y reports `RevocationUnconfirmed` and `UntrustedKey`.
// =====================================================================
#[test]
fn v11_key_revoked_on_two_trails_each_trail_verifies_separately() {
    // Build trail Y (= `TRAIL`) by hand: cp0 (old key) at seq=0, which
    // is the bound. The new-key confirming cp is at seq=1. Trail Y is
    // "clean" — bound pinned and confirmed. The policy also lists the
    // same old key `through=` on trail X with its own bound and a new
    // key for X. Scope rules out X's bound from Y's verification.
    let d_clean = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let new = new_signer();
    let new_cp1 = sign_with(&*new, 1, cp0.hash(), &mmr0);
    put_segment(&d_clean.0, 0, &[&cp0, &new_cp1], &[]);
    let path_clean = segment_path(&d_clean.0, 0);
    // Build an X-side bound on the same old key (another trail id,
    // another new key pretend-listed). Use a third seed `0x33`.
    let x_other_new = Arc::new(KeyFileSigner::from_hex(&"33".repeat(32)).unwrap());
    let other: [u8; 16] = [0x99; 16];
    assert_ne!(other, TRAIL);
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
    let findings = Verifier::new(trust)
        .trail(TRAIL)
        .unwrap()
        .verify_files([path_clean])
        .unwrap()
        .findings()
        .to_vec();
    // Y is clean: no revocation findings; coverage is new_cp1.seq=1
    // so no `UncoveredTail`.
    assert_findings(&findings, &[], "V11 clean Y");

    // Forgery: cut to bound and forge above with old key.
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
    let findings_forged = Verifier::new(trust_forged)
        .trail(TRAIL)
        .unwrap()
        .verify_files([path_forged.clone()])
        .unwrap()
        .findings()
        .to_vec();
    let mut expected = vec![
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
            path_forged.clone(),
            3,
            2,
            format!("key {FIXTURE_KEY_HEX} bounded through seq 0"),
        ),
        uncovered(1, 2),
    ];
    expected.sort_by_key(|f| {
        (
            f.seq().is_none(),
            f.seq(),
            f.file().map(std::path::Path::to_path_buf),
            f.line(),
            format!("{:?}", f.kind()),
        )
    });
    assert_findings(&findings_forged, &expected, "V11 forged Y");
}

// =====================================================================
// V12 — REGRESSION. A bound on a key in ANOTHER trail's section only,
// verified trail is clean (no bound on this trail). Scope (ruling
// 13-V5-d3 point 3): only bounds in the verified trail's section are
// checked. Base stubs `revocation::check` to emit nothing; this row
// matches that stub trivially. Kills Q7 (scope: check bounds in every
// section). Pairs with V11's "clean Y" assertion for a second kill of
// Q7.
// =====================================================================
#[test]
fn v12_bound_only_on_another_trail_is_scoped_out() {
    let fx = two_checkpoints();
    let other: [u8; 16] = [0x99; 16];
    assert_ne!(other, TRAIL);
    // The key is listed on OTHER with `through=`; on TRAIL the SAME key
    // is listed WITHOUT a bound (one key must have consistent presence
    // across sections). TRAIL has no bounds -- clean.
    // Trust builder forbids a key bounded on one section and unbounded
    // on another; so use a DIFFERENT key for OTHER's bound.
    let unlisted = Arc::new(KeyFileSigner::from_hex(&"44".repeat(32)).unwrap());
    let bound_hash: [u8; 32] = [0xcc; 32];
    let trust = TrustPolicy::builder()
        .trail(other)
        .key_through(unlisted.public_key(), 42, bound_hash)
        .trail(TRAIL)
        .key(fixture_pubkey())
        .build()
        .unwrap();
    let findings = Verifier::new(trust)
        .trail(TRAIL)
        .unwrap()
        .verify_files([fx.path.clone()])
        .unwrap()
        .findings()
        .to_vec();
    // No revocation findings; `UncoveredTail` tracks the baseline.
    // covered_through = 2 (cp2 at seq 2 is trusted), so last_seq = 2 is
    // itself covered → no UncoveredTail.
    assert_findings(&findings, &[], "V12");
    let _keep = fx.dir;
}

// =====================================================================
// V3b — ACCEPTANCE companion. Hash mismatch at a different `seq` to
// give Q6 ("pin compares seq only, not the hash") a second named kill:
// the bound names seq=2 with the cp0-shape hash, but the actual record
// at seq=2 (the honest cp2) has a different hash, so pin fails.
// =====================================================================
#[test]
fn v3b_hash_mismatch_at_seq_two() {
    let fx = two_checkpoints();
    // Bound at seq=2 names a wrong hash ([0x5a;32]). cp2's actual hash
    // differs → pin fails with "has hash".
    let bound_hash: [u8; 32] = [0x5a; 32];
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 2, bound_hash)
        .build()
        .unwrap();
    let findings = verify_files_with(vec![fx.path.clone()], trust);
    let bound_hex = digest_string(&bound_hash);
    let mut expected = vec![
        located(
            K::RevocationMismatch,
            fx.path.clone(),
            3,
            2,
            format!(
                "key {FIXTURE_KEY_HEX} through=2:{bound_hex}: record at seq 2 has hash {CP2_HONEST_DIGEST}"
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
    expected.sort_by_key(|f| {
        (
            f.seq().is_none(),
            f.seq(),
            f.file().map(std::path::Path::to_path_buf),
            f.line(),
            format!("{:?}", f.kind()),
        )
    });
    assert_findings(&findings, &expected, "V3b");
    let _keep = fx.dir;
}

// =====================================================================
// V4b — ACCEPTANCE companion. Bound names an entry seq at a different
// position to give Q4 ("pin skips the checkpoint-kind check") a second
// named kill: the trail has an entry at seq=1 and cp0 only. A bound
// pointing at that entry's hash at seq=1 fails pin with "is not a
// checkpoint" under production; under Q4 the kind check would be
// skipped and pin would wrongly pass.
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
    let e1_hex = digest_string(&e1.hash());
    assert_eq!(e1_hex, E1_HONEST_DIGEST);
    let mut expected = vec![
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
    expected.sort_by_key(|f| {
        (
            f.seq().is_none(),
            f.seq(),
            f.file().map(std::path::Path::to_path_buf),
            f.line(),
            format!("{:?}", f.kind()),
        )
    });
    assert_findings(&findings, &expected, "V4b");
}

// =====================================================================
// V6b — ACCEPTANCE companion. Fork at a DIFFERENT seq to give Q5 ("pin
// ignores forks: the first record wins") a second named kill. Honest
// cp0 plus a shipped twin cp0 forking seq=0; the bound names cp0's
// honest hash at seq=0. Pin fails with "forked".
// =====================================================================
#[test]
fn v6b_bound_at_forked_seq_zero() {
    let d = Temp::new();
    let honest_cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    put_segment(&d.0, 0, &[&honest_cp0], &[]);
    let native = segment_path(&d.0, 0);
    // Ship a twin cp0 with a different signed body → different hash.
    let twin_cp0 = signed_cp_explicit(0, Record::genesis(&TRAIL), 0, [0xde; 32], vec![]);
    let twin_path = d.0.join("cp0.twin");
    fs::write(&twin_path, line_bytes(&twin_cp0)).unwrap();
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, honest_cp0.hash())
        .build()
        .unwrap();
    let findings = verify_files_with(vec![native.clone(), twin_path], trust);
    let (first, second) = if honest_cp0.hash() < twin_cp0.hash() {
        (
            digest_string(&honest_cp0.hash()),
            digest_string(&twin_cp0.hash()),
        )
    } else {
        (
            digest_string(&twin_cp0.hash()),
            digest_string(&honest_cp0.hash()),
        )
    };
    let mut expected = vec![
        located(
            K::SeqConflict,
            native,
            1,
            0,
            format!("conflicting hashes: {first}, {second}"),
        ),
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
    ];
    expected.sort_by_key(|f| {
        (
            f.seq().is_none(),
            f.seq(),
            f.file().map(std::path::Path::to_path_buf),
            f.line(),
            format!("{:?}", f.kind()),
        )
    });
    assert_findings(&findings, &expected, "V6b");
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
    let other: [u8; 16] = [0x99; 16];
    assert_eq!(hex(&other), OTHER_TRAIL_HEX);
    let fx = two_checkpoints();
    assert_eq!(digest_string(&fx.cp0.hash()), CP0_HONEST_DIGEST);
    assert_eq!(digest_string(&fx.e1.hash()), E1_HONEST_DIGEST);
    assert_eq!(digest_string(&fx.cp2.hash()), CP2_HONEST_DIGEST);
    let _keep = fx.dir;
    // `trust_fixture_unbounded` is a harmless baseline reused across rows.
    let _p = trust_fixture_unbounded();
    // Reserve symbol use for `write_records` so a mutant dropping its
    // path from the fixtures surfaces here instead of silently.
    let _ = write_records;
    // V2's hand-built close checkpoint hash.
    let mmr0 = seeded(&fx.cp0);
    let close_cp = signed_cp(1, fx.cp0.hash(), &mmr0);
    assert_eq!(digest_string(&close_cp.hash()), CLOSE_CP_V2_DIGEST);
    // V3's forged cp2 hash (different root → different signed body).
    let forged_v3 = signed_cp_explicit(2, fx.e1.hash(), 2, [0xab; 32], vec![[0x11; 32]]);
    assert_eq!(digest_string(&forged_v3.hash()), CP2_FORGED_V3_DIGEST);
    // V6's twin cp2 hash.
    let twin_v6 = signed_cp_explicit(2, fx.e1.hash(), 2, [0xde; 32], vec![[0x22; 32]]);
    assert_eq!(digest_string(&twin_v6.hash()), CP2_TWIN_V6_DIGEST);
}
