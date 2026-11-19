//! Verifier-level acceptance rows for trusted-checkpoint coverage,
//! the `UncoveredTail` detail grammar and covered-repair promotion
//! (ADR-0005 decision 5 and decision 11; rulings 13-V5-d1 point 6 and
//! 13-V5-d2).
//!
//! Row shape. Every row compares a whole `Vec<Finding>` and
//! `Report::covered_through()` with `assert_eq!`. Every digest, key
//! and trail id in an expected detail is a written-out hex constant
//! (the companion [`fixture_hashes_match_literals`] test reddens if
//! any constant drifts from the fixture). Fragments are reported by
//! length and digest, never by text (ruling 13-V5-d1 point 6).
//!
//! Acceptance rows (C1-C9, R1-R3b, P6b, P6b2, P6c, P6c2). Each
//! acceptance row's first assertion is the full literal finding list
//! (`assert_findings`), and that assertion is what reddens on base:
//! base is the head with `covered_through` forced to `None`, so
//! either the list itself or `covered_through()` differs; the list
//! is asserted first in every row.
//!
//! The honest-crash d11 bullet shape `[cp0, frag, e1(repaired), cp2]`
//! drives C6, C7 and C9 and their `is_strict_valid` assertion: the
//! trail has no error findings and `--strict` passes once a trusted
//! checkpoint covers the attesting record.

use super::{Finding, Report, Verifier, input, signatures::trusted};
use crate::audit::{
    CheckpointFields, Entry, FindingKind as K, KeyFileSigner, Mmr, Record, RecordContext, Signer,
    TrustPolicy, digest_string,
    format::Kind,
    gap_hasher, hex,
    runs_v4a_fixtures::{
        TRAIL, Temp, context, entry_rec, fixture_pubkey, line_bytes, pushed, put_segment, seeded,
        segment_path, signed_cp, write_bytes,
    },
};
use std::path::PathBuf;

// =====================================================================
// Literal hex constants (see `fixture_hashes_match_literals`).
// =====================================================================

/// `KeyFileSigner::from_hex(&"27".repeat(32)).public_key()` in hex.
const FIXTURE_KEY_HEX: &str = "ee45ecb9aca01a0abd83ef56dd985c8c874e6e7f4aebcedf20bd8d88c2a0add7";
/// `KeyFileSigner::from_hex(&"55".repeat(32)).public_key()` in hex;
/// not listed on any `TrustPolicy`, used by R1.
const UNLISTED_KEY_HEX: &str = "c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242";
/// Hex of `runs_v4a_fixtures::TRAIL` = `[17; 16]`.
const TRAIL_HEX: &str = "11111111111111111111111111111111";
/// Hex of [`FOREIGN_TRAIL`] = `[22; 16]`, used by P6b and P6b2.
const FOREIGN_TRAIL_HEX: &str = "22222222222222222222222222222222";
/// A second trail id (not on the verified trail).
const FOREIGN_TRAIL: [u8; 16] = [0x22; 16];

/// `digest_string(&repair_digest(b"{\"torn\":\n"))`. Used by C6, C9a,
/// C9b and R2/R2b/R3/R3b, and by P6b/P6b2/P6c/P6c2.
const REPAIR_DIGEST_TORN: &str =
    "blake3:e07ec37e78aa91ad5e973df286a9e563f1b9b5c3d69ba53fa990ac2b80f89fe9";
/// `digest_string(&repair_digest(b"{\"crash\":\n"))`. Used by C8.
const REPAIR_DIGEST_CRASH: &str =
    "blake3:fa5dfbc5e0300a12bf1750855daa616b9346fb9aab4eddd7e6584f1cfcf4f884";
/// `digest_string(&repair_digest(b"{\"a\":\n{\"b\":\n"))`. Used by
/// C7 and C8b.
const REPAIR_DIGEST_AB: &str =
    "blake3:8fd91a67a35221ff17201ecc251195ffcaac90af4bb002a52cc73d48fad10ac6";

// =====================================================================
// Shared helpers.
// =====================================================================

fn trust_fixture() -> TrustPolicy {
    TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .build()
        .unwrap()
}

fn report_of(files: Vec<PathBuf>, trust: TrustPolicy) -> Report {
    Verifier::new(trust).verify_files(files).unwrap()
}

#[track_caller]
fn assert_findings(actual: &[Finding], expected: &[Finding], label: &str) {
    assert_eq!(actual, expected, "{label} literal finding list");
}

fn located(kind: K, file: PathBuf, line: u64, seq: u64, detail: String) -> Finding {
    Finding::new(kind, Some(file), Some(line), Some(seq), detail)
}

fn uncovered(first: u64, last: u64) -> Finding {
    Finding::new(
        K::UncoveredTail,
        None,
        None,
        None,
        format!("records seq {first}..={last}"),
    )
}

/// Clones a signed checkpoint while rewriting its signature.
fn with_signature(signed: &Record, sig: [u8; 64]) -> Record {
    let cp = match &signed.kind {
        Kind::Checkpoint(cp) => cp,
        _ => panic!("checkpoint record expected"),
    };
    let fields = CheckpointFields::new(cp.size, cp.root, cp.peaks.clone(), cp.key, sig).unwrap();
    Record::checkpoint(signed.context.clone(), fields).unwrap()
}

fn flip_signature_byte(signed: &Record) -> Record {
    let sig = match &signed.kind {
        Kind::Checkpoint(cp) => *cp.signature(),
        _ => panic!("checkpoint record expected"),
    };
    let mut flipped = sig;
    flipped[0] ^= 0x01;
    with_signature(signed, flipped)
}

/// Honestly signs a checkpoint with a `RecordContext` (used when a
/// row needs a specific `time` or a `repaired` digest in the
/// context). The `mmr` must already reflect the records before this
/// checkpoint's own hash.
fn signed_cp_with_ctx(ctx: RecordContext, mmr: &Mmr) -> Record {
    let signer = KeyFileSigner::from_hex(&"27".repeat(32)).unwrap();
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
    let sig = signer.sign(&unsigned.signing_message().unwrap()).unwrap();
    Record::checkpoint(ctx, fields(sig)).unwrap()
}

/// Entry record on `TRAIL` with an `audit.repaired` digest set.
fn entry_rec_with_repaired(seq: u64, previous: [u8; 32], repair: [u8; 32]) -> Record {
    let ctx = context(seq, previous).repaired(repair);
    Record::new(ctx, Entry::new("a", "change", "c")).unwrap()
}

/// Entry record on a foreign trail with an `audit.repaired` digest.
fn foreign_entry_with_repaired(seq: u64, previous: [u8; 32], repair: [u8; 32]) -> Record {
    let ctx = RecordContext::new(FOREIGN_TRAIL, seq, 100 + seq, "test", previous).repaired(repair);
    Record::new(ctx, Entry::new("a", "change", "c")).unwrap()
}

/// BLAKE3(`vigil.audit.v1.repaired\0` || fragment bytes) -- the same
/// digest the verifier's streaming span emits for the gap.
fn repair_digest(fragment: &[u8]) -> [u8; 32] {
    let mut h = gap_hasher();
    h.update(fragment);
    *h.finalize().as_bytes()
}

/// Shared fragment byte string for the honest-crash shape.
const FRAG_TORN: &[u8] = b"{\"torn\":\n";

/// Builds `[cp0, e1, cp2]` on `TRAIL` with the fixture key.
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

/// Builds the honest-crash d11 shape `[cp0, frag, e1(repaired), cp2]`
/// on `TRAIL`: a trusted opening cp0, a captured crash fragment, the
/// resuming attester e1 at seq 1, and a trusted sealing cp2.
struct HonestCrashLayout {
    _dir: Temp,
    path: PathBuf,
    frag: &'static [u8],
}
fn honest_crash() -> HonestCrashLayout {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let frag = FRAG_TORN;
    let gap_digest = repair_digest(frag);
    let e1 = entry_rec_with_repaired(1, cp0.hash(), gap_digest);
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mut bytes = line_bytes(&cp0);
    bytes.extend_from_slice(frag);
    bytes.extend_from_slice(&line_bytes(&e1));
    bytes.extend_from_slice(&line_bytes(&cp2));
    let path = segment_path(&d.0, 0);
    write_bytes(&path, &bytes);
    HonestCrashLayout {
        _dir: d,
        path,
        frag,
    }
}

// =====================================================================
// C1 -- honest `[cp0, e1, cp2]`, fixture key listed:
// `covered_through == Some(2)` and NO `UncoveredTail` (ruling
// 13-V5-d1 point 6, last record covered -> no tail). Acceptance row.
// First failing line on base: `assert_findings(..., &[], "C1")`.
// =====================================================================
#[test]
fn c1_covered_through_names_highest_trusted_seq_and_full_coverage_omits_tail() {
    let fx = two_checkpoints();
    let report = report_of(vec![fx.path.clone()], trust_fixture());
    assert_findings(report.findings(), &[], "C1");
    assert_eq!(report.covered_through(), Some(2));
    assert!(report.is_strict_valid(), "C1 --strict passes");
}

// =====================================================================
// C2 -- `[cp0, e1, cp2, e3, e4]`: trusted head is cp2, so
// `UncoveredTail` names `records seq 3..=4` exactly. Acceptance row.
// First failing line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn c2_uncovered_tail_starts_at_covered_plus_one() {
    let fx = two_checkpoints();
    let e3 = entry_rec(3, fx.cp2.hash());
    let e4 = entry_rec(4, e3.hash());
    put_segment(&fx._dir.0, 0, &[&fx.cp0, &fx.e1, &fx.cp2, &e3, &e4], &[]);
    let report = report_of(vec![fx.path.clone()], trust_fixture());
    assert_findings(report.findings(), &[uncovered(3, 4)], "C2");
    assert_eq!(report.covered_through(), Some(2));
}

// =====================================================================
// C3 -- the last checkpoint carries a flipped signature. Coverage
// falls back to the previous trusted checkpoint (cp0), and the full
// list includes its `BadSignature`. Acceptance row.
// First failing line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn c3_bad_signature_at_head_falls_back_coverage_to_previous_trusted() {
    let fx = two_checkpoints();
    let bad = flip_signature_byte(&fx.cp2);
    put_segment(&fx._dir.0, 0, &[&fx.cp0, &fx.e1, &bad], &[]);
    let report = report_of(vec![fx.path.clone()], trust_fixture());
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
    assert_findings(report.findings(), &expected, "C3");
    assert_eq!(report.covered_through(), Some(0));
}

// =====================================================================
// C4 -- the last checkpoint is signed by a key bounded below its seq
// (`through=0:<cp0 hash>`): coverage falls back to cp0 and the list
// includes `UntrustedKey ... bounded through seq ...`. Acceptance row.
// First failing line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn c4_untrusted_key_at_head_falls_back_coverage_to_previous_trusted() {
    let fx = two_checkpoints();
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, fx.cp0.hash())
        .build()
        .unwrap();
    let report = report_of(vec![fx.path.clone()], trust);
    let expected = vec![
        located(
            K::UntrustedKey,
            fx.path.clone(),
            3,
            2,
            format!("key {FIXTURE_KEY_HEX} bounded through seq 0"),
        ),
        uncovered(1, 2),
    ];
    assert_findings(report.findings(), &expected, "C4");
    assert_eq!(report.covered_through(), Some(0));
}

// =====================================================================
// C5 -- a trusted checkpoint present only in a shipped copy covers
// (ruling 13-V5-d1 point 1). Native: [cp0, e1]; shipped: a copy of
// cp2 linked to e1. The shipped-only cp2 is the highest trusted
// candidate; coverage = Some(2). Acceptance row.
// First failing line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn c5_shipped_only_trusted_checkpoint_covers() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1], &[]);
    let native = segment_path(&d.0, 0);
    let shipped = d.0.join("cp2.copy");
    write_bytes(&shipped, &line_bytes(&cp2));
    let report = report_of(vec![native, shipped], trust_fixture());
    assert_findings(report.findings(), &[], "C5");
    assert_eq!(report.covered_through(), Some(2));
    assert!(report.is_strict_valid(), "C5 --strict passes");
}

// =====================================================================
// C5b -- SECOND row for N4 (ignores shipped-only). A trail whose
// ONLY trusted checkpoint is in a shipped copy: no native
// checkpoint at all, one shipped-only cp0 linked to genesis.
// Coverage = Some(0); N4 mutation would give `None`. Acceptance row.
// First failing line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn c5b_shipped_only_genesis_checkpoint_is_the_sole_coverage_source() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let shipped = d.0.join("cp0.copy");
    write_bytes(&shipped, &line_bytes(&cp0));
    let report = report_of(vec![shipped], trust_fixture());
    assert_findings(report.findings(), &[], "C5b");
    assert_eq!(report.covered_through(), Some(0));
    assert!(report.is_strict_valid(), "C5b --strict passes");
}

// =====================================================================
// C6 -- ADR-0005 d11 "Attested repairs" honest bullet "SIGKILLed
// mid-write, then another process records and a trusted checkpoint
// covers that record". Honest shape: `[cp0, frag, e1(repaired), cp2]`
// (no fake `SeqGap`: the attester sits at seq 1 right after cp0). The
// gap is covered by cp2, so the attested gap is one `TornWriteRepaired`
// info and `is_strict_valid()` is true. Acceptance row.
// First failing line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn c6_sigkilled_then_recorded_and_covered_is_one_torn_write_repaired() {
    let fx = honest_crash();
    let report = report_of(vec![fx.path.clone()], trust_fixture());
    let expected = vec![located(
        K::TornWriteRepaired,
        fx.path.clone(),
        2,
        1,
        format!(
            "lines 2..=2 ({len} bytes), attested at line 3 seq 1",
            len = fx.frag.len(),
        ),
    )];
    assert_findings(report.findings(), &expected, "C6");
    assert_eq!(report.covered_through(), Some(2));
    assert!(report.is_strict_valid(), "C6 --strict passes");
}

// =====================================================================
// C7 -- d11 bullet "a crash during the repairing write": two
// fragment lines in one gap, attested once by e1 at seq 1, and the
// whole trail covered by cp2. One `TornWriteRepaired` (d11; ruling
// 13-V5-d1 point 6: one attested-and-covered gap, one info).
// Acceptance row. First failing line on base: the `assert_findings`
// call below.
// =====================================================================
#[test]
fn c7_two_fragments_one_gap_attested_and_covered_is_one_torn_write_repaired() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let frag_a = b"{\"a\":\n";
    let frag_b = b"{\"b\":\n";
    let mut all = Vec::new();
    all.extend_from_slice(frag_a);
    all.extend_from_slice(frag_b);
    let gap_digest = repair_digest(&all);
    let e1 = entry_rec_with_repaired(1, cp0.hash(), gap_digest);
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mut bytes: Vec<u8> = line_bytes(&cp0);
    bytes.extend_from_slice(frag_a);
    bytes.extend_from_slice(frag_b);
    bytes.extend_from_slice(&line_bytes(&e1));
    bytes.extend_from_slice(&line_bytes(&cp2));
    let path = segment_path(&d.0, 0);
    write_bytes(&path, &bytes);
    let report = report_of(vec![path.clone()], trust_fixture());
    let expected = vec![located(
        K::TornWriteRepaired,
        path.clone(),
        2,
        1,
        format!(
            "lines 2..=3 ({len} bytes), attested at line 4 seq 1",
            len = all.len(),
        ),
    )];
    assert_findings(report.findings(), &expected, "C7");
    assert_eq!(report.covered_through(), Some(2));
    assert!(report.is_strict_valid(), "C7 --strict passes");
}

// =====================================================================
// C8 -- the attesting line is itself the trusted checkpoint (the
// sealing checkpoint attests its own repaired tail). Coverage is
// inclusive (ruling 13-V5-d1 point 6, the "at or below" rule), so
// the gap becomes `TornWriteRepaired`. Acceptance row.
// First failing line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn c8_attesting_line_is_itself_the_trusted_checkpoint_is_torn_write_repaired() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let fragment = b"{\"crash\":\n";
    let gap_digest = repair_digest(fragment);
    // cp1 is the sealing checkpoint: a trusted checkpoint carrying
    // `audit.repaired` for the fragment it immediately follows.
    let ctx = context(1, cp0.hash()).repaired(gap_digest);
    let cp1 = signed_cp_with_ctx(ctx, &mmr0);
    let mut bytes = line_bytes(&cp0);
    bytes.extend_from_slice(fragment);
    bytes.extend_from_slice(&line_bytes(&cp1));
    let path = segment_path(&d.0, 0);
    write_bytes(&path, &bytes);
    let report = report_of(vec![path.clone()], trust_fixture());
    let expected = vec![located(
        K::TornWriteRepaired,
        path,
        2,
        1,
        format!(
            "lines 2..=2 ({len} bytes), attested at line 3 seq 1",
            len = fragment.len(),
        ),
    )];
    assert_findings(report.findings(), &expected, "C8");
    assert_eq!(report.covered_through(), Some(1));
    assert!(report.is_strict_valid(), "C8 --strict passes");
}

// =====================================================================
// C8b -- sealing checkpoint attesting a TWO-fragment gap (distinct
// fixture from C8's single-fragment seal). Same inclusive-coverage
// rule (`attesting_seq == covered_through`), so this is the second
// named kill for N1 and M2. Acceptance row.
// First failing line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn c8b_sealing_checkpoint_attesting_two_fragments_is_torn_write_repaired() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let frag_a = b"{\"a\":\n";
    let frag_b = b"{\"b\":\n";
    let mut all = Vec::new();
    all.extend_from_slice(frag_a);
    all.extend_from_slice(frag_b);
    let gap_digest = repair_digest(&all);
    let ctx = context(1, cp0.hash()).repaired(gap_digest);
    let cp1 = signed_cp_with_ctx(ctx, &mmr0);
    let mut bytes = line_bytes(&cp0);
    bytes.extend_from_slice(frag_a);
    bytes.extend_from_slice(frag_b);
    bytes.extend_from_slice(&line_bytes(&cp1));
    let path = segment_path(&d.0, 0);
    write_bytes(&path, &bytes);
    let report = report_of(vec![path.clone()], trust_fixture());
    let expected = vec![located(
        K::TornWriteRepaired,
        path,
        2,
        1,
        format!(
            "lines 2..=3 ({len} bytes), attested at line 4 seq 1",
            len = all.len(),
        ),
    )];
    assert_findings(report.findings(), &expected, "C8b");
    assert_eq!(report.covered_through(), Some(1));
    assert!(report.is_strict_valid(), "C8b --strict passes");
}

// =====================================================================
// C9a -- d11 bullet "attesting line not yet covered: `TornWrite`
// until the next trusted checkpoint". The "before" phase of the
// before-and-after case: `[cp0, frag, e1(repaired)]`. Honest
// shape; the attester e1 at seq 1 is beyond `covered_through = 0`,
// so the gap stays `TornWrite` and `UncoveredTail` names seq 1.
// Acceptance row. First failing line on base: the `assert_findings`
// call below.
// =====================================================================
#[test]
fn c9a_attesting_line_not_yet_covered_before_a_trusted_checkpoint_is_torn_write() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let frag = FRAG_TORN;
    let gap_digest = repair_digest(frag);
    let e1 = entry_rec_with_repaired(1, cp0.hash(), gap_digest);
    let _mmr1 = pushed(&mmr0, &e1);
    let mut bytes = line_bytes(&cp0);
    bytes.extend_from_slice(frag);
    bytes.extend_from_slice(&line_bytes(&e1));
    let path = segment_path(&d.0, 0);
    write_bytes(&path, &bytes);
    let report = report_of(vec![path.clone()], trust_fixture());
    let expected = vec![
        located(
            K::TornWrite,
            path.clone(),
            2,
            1,
            format!(
                "lines 2..=2 ({len} bytes), attested at line 3 seq 1",
                len = frag.len(),
            ),
        ),
        uncovered(1, 1),
    ];
    assert_findings(report.findings(), &expected, "C9a-before");
    assert_eq!(report.covered_through(), Some(0));
}

// =====================================================================
// C9b -- d11 bullet "... then `TornWriteRepaired` once the next
// trusted checkpoint covers". The "after" phase: the same shape
// extended with cp2. Honest d11 outcome: one `TornWriteRepaired`
// and no error findings, so `--strict` passes. Acceptance row.
// First failing line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn c9b_attesting_line_covered_after_the_next_trusted_checkpoint_is_torn_write_repaired() {
    let fx = honest_crash();
    let report = report_of(vec![fx.path.clone()], trust_fixture());
    let expected = vec![located(
        K::TornWriteRepaired,
        fx.path.clone(),
        2,
        1,
        format!(
            "lines 2..=2 ({len} bytes), attested at line 3 seq 1",
            len = fx.frag.len(),
        ),
    )];
    assert_findings(report.findings(), &expected, "C9b-after");
    assert_eq!(report.covered_through(), Some(2));
    assert!(report.is_strict_valid(), "C9b --strict passes");
}

// =====================================================================
// R1 -- ACCEPTANCE row: the attesting line is covered only by a
// checkpoint signed by an unlisted key; the gap stays `TornWrite`
// and `covered_through` is the lower trusted one (cp0). Fails on
// base: on base `covered_through = None`, so `UncoveredTail` spans
// `records seq 0..=3` instead of `1..=3`. Named runtime killers:
//   N2 (promote without a coverage check) -- would flip TornWrite to
//      TornWriteRepaired here; the row's literal list reddens.
//   N3 (coverage predicate ignores trust) -- would raise
//      `covered_through` to 3 and promote; the row reddens.
// First failing line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn r1_acceptance_covered_only_by_unlisted_key_stays_torn_write() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let fragment = FRAG_TORN;
    let gap_digest = repair_digest(fragment);
    let e2 = entry_rec_with_repaired(2, cp0.hash(), gap_digest);
    let mmr2 = pushed(&mmr0, &e2);
    // cp3 is signed by an unlisted key `0x55`: not trusted.
    let signer = KeyFileSigner::from_hex(&"55".repeat(32)).unwrap();
    let fields = |sig| {
        CheckpointFields::new(
            mmr2.size(),
            mmr2.root(),
            mmr2.peaks().to_vec(),
            signer.public_key(),
            sig,
        )
        .unwrap()
    };
    let unsigned = Record::checkpoint(context(3, e2.hash()), fields([0; 64])).unwrap();
    let sig = signer.sign(&unsigned.signing_message().unwrap()).unwrap();
    let cp3_unlisted = Record::checkpoint(context(3, e2.hash()), fields(sig)).unwrap();
    let mut bytes = line_bytes(&cp0);
    bytes.extend_from_slice(fragment);
    bytes.extend_from_slice(&line_bytes(&e2));
    bytes.extend_from_slice(&line_bytes(&cp3_unlisted));
    let path = segment_path(&d.0, 0);
    write_bytes(&path, &bytes);
    let report = report_of(vec![path.clone()], trust_fixture());
    let expected = vec![
        located(
            K::TornWrite,
            path.clone(),
            2,
            2,
            format!(
                "lines 2..=2 ({len} bytes), attested at line 3 seq 2",
                len = fragment.len(),
            ),
        ),
        located(
            K::SeqGap,
            path.clone(),
            3,
            2,
            "missing seq 1..=1".to_owned(),
        ),
        located(
            K::UntrustedKey,
            path,
            4,
            3,
            format!("key {UNLISTED_KEY_HEX} not listed for trail {TRAIL_HEX}"),
        ),
        uncovered(1, 3),
    ];
    assert_findings(report.findings(), &expected, "R1 acceptance");
    assert_eq!(report.covered_through(), Some(0));
}

// =====================================================================
// R2 -- ACCEPTANCE row: an inserted fragment before a line with NO
// `audit.repaired`, under coverage. Stays `RepairMismatch` (ruling
// 13-V5-d1 point 6: `RepairMismatch` is never promoted). Fails on
// base because on base `covered_through = None` adds an
// `UncoveredTail` the head's covered trail does not have. Named
// runtime killers:
//   N7 (RepairMismatch promoted under coverage) -- would flip the
//      `K::RepairMismatch` here to `TornWriteRepaired`; row reddens.
//   M1 (`UncoveredTail` emitted even when fully covered) -- the row
//      has no `UncoveredTail` at head, so M1 reddens the list.
// First failing line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn r2_acceptance_repair_mismatch_under_coverage_is_not_promoted() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let fragment = FRAG_TORN;
    // e2 carries NO `audit.repaired` -- the gap attests nothing, so
    // the engine emits `RepairMismatch` (expected digest versus
    // `none`).
    let e2 = entry_rec(2, cp0.hash());
    let mmr2 = pushed(&mmr0, &e2);
    let cp3 = signed_cp(3, e2.hash(), &mmr2);
    let mut bytes = line_bytes(&cp0);
    bytes.extend_from_slice(fragment);
    bytes.extend_from_slice(&line_bytes(&e2));
    bytes.extend_from_slice(&line_bytes(&cp3));
    let path = segment_path(&d.0, 0);
    write_bytes(&path, &bytes);
    let report = report_of(vec![path.clone()], trust_fixture());
    let expected = vec![
        located(
            K::RepairMismatch,
            path.clone(),
            2,
            2,
            format!(
                "lines 2..=2 ({len} bytes), attested at line 3 seq 2: expected {REPAIR_DIGEST_TORN}, got none",
                len = fragment.len(),
            ),
        ),
        located(K::SeqGap, path, 3, 2, "missing seq 1..=1".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "R2 acceptance");
    assert_eq!(report.covered_through(), Some(3));
}

// =====================================================================
// R2b -- ACCEPTANCE row paired with R2: same shape (missing
// `audit.repaired`) but with the attesting record at exactly the
// trusted-checkpoint seq. On head, `RepairMismatch` is already the
// outcome; N7 would promote both R2 and R2b to `TornWriteRepaired`.
// Named runtime killers: N7, M1 (see R2).
// First failing line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn r2b_acceptance_repair_mismatch_at_covered_seq_is_not_promoted() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let fragment = FRAG_TORN;
    // cp1 at seq=1 is a trusted checkpoint AND the attesting line,
    // but carries NO `audit.repaired` field, so the attestation
    // fails: `RepairMismatch` stays even though `cp1.seq ==
    // covered_through`.
    let cp1 = signed_cp(1, cp0.hash(), &mmr0);
    let mut bytes = line_bytes(&cp0);
    bytes.extend_from_slice(fragment);
    bytes.extend_from_slice(&line_bytes(&cp1));
    let path = segment_path(&d.0, 0);
    write_bytes(&path, &bytes);
    let report = report_of(vec![path.clone()], trust_fixture());
    let expected = vec![located(
        K::RepairMismatch,
        path,
        2,
        1,
        format!(
            "lines 2..=2 ({len} bytes), attested at line 3 seq 1: expected {REPAIR_DIGEST_TORN}, got none",
            len = fragment.len(),
        ),
    )];
    assert_findings(report.findings(), &expected, "R2b acceptance");
    assert_eq!(report.covered_through(), Some(1));
}

// =====================================================================
// R3 -- ACCEPTANCE row: a trailing gap under coverage of everything
// before it stays `TornWrite` (ruling 13-V5-d1 point 6: a trailing
// gap with no attesting line is never promoted). Fails on base: on
// base an `UncoveredTail` is added that head covered omits. Named
// runtime killers:
//   N8 (trailing gap promoted under coverage) -- would flip the
//      trailing `TornWrite` to `TornWriteRepaired`; row reddens.
//   M1 (`UncoveredTail` emitted even when fully covered) -- same
//      reason as R2.
// First failing line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn r3_acceptance_trailing_gap_under_coverage_stays_torn_write() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let fragment = FRAG_TORN;
    let mut bytes = line_bytes(&cp0);
    bytes.extend_from_slice(fragment);
    let path = segment_path(&d.0, 0);
    write_bytes(&path, &bytes);
    let report = report_of(vec![path.clone()], trust_fixture());
    // The trailing TornWrite has `seq: None` (no attesting record).
    let expected = vec![Finding::new(
        K::TornWrite,
        Some(path),
        Some(2),
        None,
        format!(
            "trailing gap lines 2..=2 ({len} bytes), digest {REPAIR_DIGEST_TORN}",
            len = fragment.len(),
        ),
    )];
    assert_findings(report.findings(), &expected, "R3 acceptance");
    assert_eq!(report.covered_through(), Some(0));
}

// =====================================================================
// R3b -- ACCEPTANCE row paired with R3: trailing gap after a
// trusted MID-trail checkpoint (not just cp0). Pairs with R3 to
// give N8 a second named kill at a higher `covered_through`.
// Named runtime killers: N8, M1 (see R3).
// First failing line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn r3b_acceptance_trailing_gap_after_higher_coverage_stays_torn_write() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let fragment = FRAG_TORN;
    let mut bytes = line_bytes(&cp0);
    bytes.extend_from_slice(&line_bytes(&e1));
    bytes.extend_from_slice(&line_bytes(&cp2));
    bytes.extend_from_slice(fragment);
    let path = segment_path(&d.0, 0);
    write_bytes(&path, &bytes);
    let report = report_of(vec![path.clone()], trust_fixture());
    let expected = vec![Finding::new(
        K::TornWrite,
        Some(path),
        Some(4),
        None,
        format!(
            "trailing gap lines 4..=4 ({len} bytes), digest {REPAIR_DIGEST_TORN}",
            len = fragment.len(),
        ),
    )];
    assert_findings(report.findings(), &expected, "R3b acceptance");
    assert_eq!(report.covered_through(), Some(2));
}

// =====================================================================
// P6b -- ACCEPTANCE row for ruling 13-V5-d2: an attester of a
// foreign trail must NOT promote a covered gap. Layout:
// `[cp0, frag, e1_foreign(repaired), cp2]`. cp0 and cp2 are trusted
// on `TRAIL`; e1_foreign carries `audit.repaired` for the fragment
// but is on `FOREIGN_TRAIL`, so it is reported as `TrailMismatch`.
// The attested gap stays `TornWrite`; a `SeqGap` fills the hole the
// foreign-trail record leaves in the verified `seq` axis. Named
// runtime killer: N10 (drop the trail check from promotion).
// First failing line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn p6b_acceptance_attester_of_foreign_trail_stays_torn_write() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let frag = FRAG_TORN;
    let gap_digest = repair_digest(frag);
    // e1 attests the gap digest but is on FOREIGN_TRAIL.
    let e1_foreign = foreign_entry_with_repaired(1, cp0.hash(), gap_digest);
    // cp2 advances the verified-trail fold past the gap. Because
    // e1_foreign is not on TRAIL, the native-trail bucketing skips
    // it; cp2 is linked straight from cp0 for the verified side.
    let cp2 = signed_cp(2, cp0.hash(), &mmr0);
    let mut bytes = line_bytes(&cp0);
    bytes.extend_from_slice(frag);
    bytes.extend_from_slice(&line_bytes(&e1_foreign));
    bytes.extend_from_slice(&line_bytes(&cp2));
    let path = segment_path(&d.0, 0);
    write_bytes(&path, &bytes);
    let report = report_of(vec![path.clone()], trust_fixture());
    let expected = vec![
        located(
            K::TornWrite,
            path.clone(),
            2,
            1,
            format!(
                "lines 2..=2 ({len} bytes), attested at line 3 seq 1",
                len = frag.len(),
            ),
        ),
        located(
            K::TrailMismatch,
            path.clone(),
            3,
            1,
            format!("expected trail {TRAIL_HEX}, found {FOREIGN_TRAIL_HEX}"),
        ),
        located(K::SeqGap, path, 4, 2, "missing seq 1..=1".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "P6b");
    assert_eq!(report.covered_through(), Some(2));
}

// =====================================================================
// P6b2 -- ACCEPTANCE row paired with P6b: second N10 killer at a
// different seq. Layout: `[cp0, e1, frag, e2_foreign(repaired),
// cp3]`. The foreign-trail attester sits at seq 2 instead of seq 1;
// the trusted sealing cp3 raises `covered_through` to 3. The
// attested gap again stays `TornWrite` + `TrailMismatch` with a
// `SeqGap` for the hole seq 2 leaves in the verified axis.
// Named runtime killer: N10.
// First failing line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn p6b2_acceptance_attester_of_foreign_trail_at_mid_covered_seq_stays_torn_write() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let frag = FRAG_TORN;
    let gap_digest = repair_digest(frag);
    let e2_foreign = foreign_entry_with_repaired(2, e1.hash(), gap_digest);
    let cp3 = signed_cp(3, e1.hash(), &mmr1);
    let mut bytes = line_bytes(&cp0);
    bytes.extend_from_slice(&line_bytes(&e1));
    bytes.extend_from_slice(frag);
    bytes.extend_from_slice(&line_bytes(&e2_foreign));
    bytes.extend_from_slice(&line_bytes(&cp3));
    let path = segment_path(&d.0, 0);
    write_bytes(&path, &bytes);
    let report = report_of(vec![path.clone()], trust_fixture());
    let expected = vec![
        located(
            K::TornWrite,
            path.clone(),
            3,
            2,
            format!(
                "lines 3..=3 ({len} bytes), attested at line 4 seq 2",
                len = frag.len(),
            ),
        ),
        located(
            K::TrailMismatch,
            path.clone(),
            4,
            2,
            format!("expected trail {TRAIL_HEX}, found {FOREIGN_TRAIL_HEX}"),
        ),
        located(K::SeqGap, path, 5, 3, "missing seq 2..=2".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "P6b2");
    assert_eq!(report.covered_through(), Some(3));
}

// =====================================================================
// P6c -- ACCEPTANCE row for ruling 13-V5-d2: a forked attester
// (one side of a `SeqConflict`) must NOT promote a covered gap.
// Native: `[cp0, frag, e1(repaired), cp2]`; shipped: a second
// record at seq 1 with a different hash (same `previous`, different
// `time`) that also carries the same `audit.repaired` digest. The
// native attested gap stays `TornWrite`; the shipped copy's
// `audit.repaired` with no preceding fragment keeps the
// `fragment not present` info; outer bucketing emits `SeqConflict`
// at the first copy. Named runtime killer: N11 (drop the fork
// check from promotion).
// First failing line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn p6c_acceptance_forked_attester_native_vs_shipped_stays_torn_write() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let frag = FRAG_TORN;
    let gap_digest = repair_digest(frag);
    let e1 = entry_rec_with_repaired(1, cp0.hash(), gap_digest);
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    // Shipped twin: same previous, same repaired, different `time`
    // -> different record hash.
    let alt_ctx = RecordContext::new(TRAIL, 1, 999, "test", cp0.hash()).repaired(gap_digest);
    let e1_alt = Record::new(alt_ctx, Entry::new("a", "change", "c")).unwrap();
    let mut bytes = line_bytes(&cp0);
    bytes.extend_from_slice(frag);
    bytes.extend_from_slice(&line_bytes(&e1));
    bytes.extend_from_slice(&line_bytes(&cp2));
    let native = segment_path(&d.0, 0);
    write_bytes(&native, &bytes);
    let shipped = d.0.join("e1-alt.copy");
    write_bytes(&shipped, &line_bytes(&e1_alt));
    let report = report_of(vec![native.clone(), shipped.clone()], trust_fixture());
    // The engine's `SeqConflict` detail lists the two distinct hashes
    // in `BTreeMap<[u8; 32], _>` iteration order (bytewise ascending).
    let (h_lo, h_hi) = if e1.hash() < e1_alt.hash() {
        (e1.hash(), e1_alt.hash())
    } else {
        (e1_alt.hash(), e1.hash())
    };
    let expected = vec![
        located(
            K::TornWrite,
            native.clone(),
            2,
            1,
            format!(
                "lines 2..=2 ({len} bytes), attested at line 3 seq 1",
                len = frag.len(),
            ),
        ),
        located(
            K::SeqConflict,
            native,
            3,
            1,
            format!(
                "conflicting hashes: {}, {}",
                digest_string(&h_lo),
                digest_string(&h_hi),
            ),
        ),
        located(
            K::TornWriteRepaired,
            shipped,
            1,
            1,
            "fragment not present".to_owned(),
        ),
    ];
    assert_findings(report.findings(), &expected, "P6c");
    assert_eq!(report.covered_through(), Some(2));
}

// =====================================================================
// P6c2 -- ACCEPTANCE row paired with P6c: second N11 killer with a
// different fork. Native: `[cp0, frag, cp1(repaired)]` (the sealing
// checkpoint attests its own repaired tail); shipped: a second
// checkpoint at seq 1 with the same signed fields but a different
// `time` (different record hash), giving a `SeqConflict` at the
// attesting `seq`. Named runtime killer: N11.
// First failing line on base: the `assert_findings` call below.
// =====================================================================
#[test]
fn p6c2_acceptance_forked_sealing_checkpoint_stays_torn_write() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let frag = FRAG_TORN;
    let gap_digest = repair_digest(frag);
    let cp1_ctx = context(1, cp0.hash()).repaired(gap_digest);
    let cp1 = signed_cp_with_ctx(cp1_ctx, &mmr0);
    // Shipped twin: same previous, same repaired, different `time`
    // -> different record hash. Signed independently (its
    // signing-message `time` field differs).
    let alt_ctx = RecordContext::new(TRAIL, 1, 999, "test", cp0.hash()).repaired(gap_digest);
    let cp1_alt = signed_cp_with_ctx(alt_ctx, &mmr0);
    let mut bytes = line_bytes(&cp0);
    bytes.extend_from_slice(frag);
    bytes.extend_from_slice(&line_bytes(&cp1));
    let native = segment_path(&d.0, 0);
    write_bytes(&native, &bytes);
    let shipped = d.0.join("cp1-alt.copy");
    write_bytes(&shipped, &line_bytes(&cp1_alt));
    let report = report_of(vec![native.clone(), shipped.clone()], trust_fixture());
    let (h_lo, h_hi) = if cp1.hash() < cp1_alt.hash() {
        (cp1.hash(), cp1_alt.hash())
    } else {
        (cp1_alt.hash(), cp1.hash())
    };
    let expected = vec![
        located(
            K::TornWrite,
            native.clone(),
            2,
            1,
            format!(
                "lines 2..=2 ({len} bytes), attested at line 3 seq 1",
                len = frag.len(),
            ),
        ),
        located(
            K::SeqConflict,
            native,
            3,
            1,
            format!(
                "conflicting hashes: {}, {}",
                digest_string(&h_lo),
                digest_string(&h_hi),
            ),
        ),
        located(
            K::TornWriteRepaired,
            shipped,
            1,
            1,
            "fragment not present".to_owned(),
        ),
    ];
    assert_findings(report.findings(), &expected, "P6c2");
    assert_eq!(report.covered_through(), Some(1));
}

// =====================================================================
// Consistency check on the key, trail and fixture digests every row
// uses. Mirrors `signature_tests::fixture_hashes_match_literals`; a
// drift in a captured byte reddens here rather than one of the
// acceptance rows.
// =====================================================================
#[test]
fn fixture_hashes_match_literals() {
    let unlisted = KeyFileSigner::from_hex(&"55".repeat(32))
        .unwrap()
        .public_key();
    assert_eq!(hex(&fixture_pubkey()), FIXTURE_KEY_HEX);
    assert_eq!(hex(&unlisted), UNLISTED_KEY_HEX);
    assert_eq!(hex(&TRAIL), TRAIL_HEX);
    assert_eq!(hex(&FOREIGN_TRAIL), FOREIGN_TRAIL_HEX);
    assert_eq!(digest_string(&repair_digest(FRAG_TORN)), REPAIR_DIGEST_TORN);
    assert_eq!(
        digest_string(&repair_digest(b"{\"crash\":\n")),
        REPAIR_DIGEST_CRASH,
    );
    let mut ab = Vec::new();
    ab.extend_from_slice(b"{\"a\":\n");
    ab.extend_from_slice(b"{\"b\":\n");
    assert_eq!(digest_string(&repair_digest(&ab)), REPAIR_DIGEST_AB);
}

// =====================================================================
// Predicate parity: the `trusted` predicate the engine's coverage
// uses is the same one pinned by `signature_tests`, so coverage
// cannot ignore the signature pass without a predicate change.
// =====================================================================
#[test]
fn coverage_uses_the_same_trusted_predicate_as_signatures() {
    let fx = two_checkpoints();
    let bad = flip_signature_byte(&fx.cp2);
    put_segment(&fx._dir.0, 0, &[&fx.cp0, &fx.e1, &bad], &[]);
    let collection = input::collect([fx.path.clone()]).unwrap();
    let cp2 = collection
        .inputs
        .iter()
        .flat_map(|i| i.data.records.iter())
        .find(|r| r.seq == 2)
        .expect("cp2 in the honest fixture");
    assert!(!trusted(TRAIL, &trust_fixture(), cp2));
}
