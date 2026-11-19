//! #13 V5b verifier-level acceptance rows for trusted-checkpoint
//! coverage, the `UncoveredTail` detail grammar and covered-repair
//! promotion (ADR-0005 decision 5 and decision 11; ruling 13-V5-d1
//! point 6).
//!
//! Row standard (repo-wide `_traps.md`): every acceptance row asserts
//! the full sorted literal finding list (whole [`Finding`] values) AND
//! `Report::covered_through`; the main assertion fails on V5a base
//! because base pins `covered_through = None` and emits the V5a
//! placeholder `UncoveredTail` over every record. Regression rows
//! (R1-R3) pass on base; each is labelled and lists its named
//! runtime killers.
//!
//! Every digest, trail id and key in an expected detail is a literal
//! hex constant; a drift in a captured byte reddens the companion
//! [`fixture_hashes_match_literals`] test rather than one acceptance
//! row. Fragments are reported by length and digest (ruling
//! 13-V5-d1 point 6), never by text.

use super::{Finding, Verifier, input, signatures::trusted};
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
// Literal hex constants.
// =====================================================================

/// `KeyFileSigner::from_hex(&"27".repeat(32)).public_key()` in hex.
const FIXTURE_KEY_HEX: &str = "ee45ecb9aca01a0abd83ef56dd985c8c874e6e7f4aebcedf20bd8d88c2a0add7";
/// Hex of `runs_v4a_fixtures::TRAIL` = `[17; 16]`.
const TRAIL_HEX: &str = "11111111111111111111111111111111";

// =====================================================================
// Shared helpers (every row goes through `assert_findings` so a drift
// in `run_digest` / `accepted_kind` reddens the row).
// =====================================================================

fn trust_fixture() -> TrustPolicy {
    TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .build()
        .unwrap()
}

fn report_of_files(files: Vec<PathBuf>, trust: TrustPolicy) -> (Option<u64>, Vec<Finding>) {
    let report = Verifier::new(trust).verify_files(files).unwrap();
    (report.covered_through(), report.findings().to_vec())
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

/// Honestly signs a checkpoint with a `RecordContext` carrying a
/// `repaired` digest. Used by C6-C8 to attest a fragment gap at the
/// crafted record. `mmr.push(leaf)` for the leaf argument must be
/// `record.hash()` so the honest fold through this record advances.
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

fn entry_rec_with_repaired(seq: u64, previous: [u8; 32], repair: [u8; 32]) -> Record {
    let ctx = context(seq, previous).repaired(repair);
    Record::new(ctx, Entry::new("a", "change", "c")).unwrap()
}

/// BLAKE3(`vigil.audit.v1.repaired\0` || fragment bytes) — the same
/// digest the verifier's streaming span emits for the gap.
fn repair_digest(fragment: &[u8]) -> [u8; 32] {
    let mut h = gap_hasher();
    h.update(fragment);
    *h.finalize().as_bytes()
}

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

// =====================================================================
// C1 — honest `[cp0, e1, cp2]`, fixture key listed:
// `covered_through == Some(2)` and NO `UncoveredTail` (ruling
// 13-V5-d1 point 6, last record covered → no tail). Acceptance row.
// =====================================================================
#[test]
fn c1_covered_through_names_highest_trusted_seq_and_full_coverage_omits_tail() {
    let fx = two_checkpoints();
    let (covered, findings) = report_of_files(vec![fx.path.clone()], trust_fixture());
    assert_eq!(covered, Some(2));
    assert_findings(&findings, &[], "C1");
}

// =====================================================================
// C2 — `[cp0, e1, cp2, e3, e4]`: trusted head is cp2, so `UncoveredTail`
// names `records seq 3..=4` exactly. Acceptance row.
// =====================================================================
#[test]
fn c2_uncovered_tail_starts_at_covered_plus_one() {
    let fx = two_checkpoints();
    let e3 = entry_rec(3, fx.cp2.hash());
    let e4 = entry_rec(4, e3.hash());
    put_segment(&fx._dir.0, 0, &[&fx.cp0, &fx.e1, &fx.cp2, &e3, &e4], &[]);
    let (covered, findings) = report_of_files(vec![fx.path.clone()], trust_fixture());
    assert_eq!(covered, Some(2));
    assert_findings(&findings, &[uncovered(3, 4)], "C2");
}

// =====================================================================
// C3 — the last checkpoint carries a flipped signature. Coverage
// falls back to the previous trusted checkpoint (cp0), and the full
// list includes its `BadSignature`. Acceptance row.
// =====================================================================
#[test]
fn c3_bad_signature_at_head_falls_back_coverage_to_previous_trusted() {
    let fx = two_checkpoints();
    let bad = flip_signature_byte(&fx.cp2);
    put_segment(&fx._dir.0, 0, &[&fx.cp0, &fx.e1, &bad], &[]);
    let (covered, findings) = report_of_files(vec![fx.path.clone()], trust_fixture());
    assert_eq!(covered, Some(0));
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
    assert_findings(&findings, &expected, "C3");
}

// =====================================================================
// C4 — the last checkpoint is signed by a key bounded below its seq
// (`through=0:<cp0 hash>`): coverage falls back to cp0 and the list
// includes `UntrustedKey … bounded through seq …`. Acceptance row.
// =====================================================================
#[test]
fn c4_untrusted_key_at_head_falls_back_coverage_to_previous_trusted() {
    let fx = two_checkpoints();
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, fx.cp0.hash())
        .build()
        .unwrap();
    let (covered, findings) = report_of_files(vec![fx.path.clone()], trust);
    assert_eq!(covered, Some(0));
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
    assert_findings(&findings, &expected, "C4");
}

// =====================================================================
// C5 — a trusted checkpoint present only in a shipped copy covers
// (ruling 13-V5-d1 point 1). Native: [cp0, e1]; shipped: a copy of
// cp2 linked to e1. The shipped-only cp2 is the highest trusted
// candidate; coverage = Some(2). Acceptance row.
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
    let (covered, findings) = report_of_files(vec![native, shipped], trust_fixture());
    assert_eq!(covered, Some(2));
    assert_findings(&findings, &[], "C5");
}

// =====================================================================
// C5b — SECOND row for N4 (ignores shipped-only). A trail whose
// ONLY trusted checkpoint is in a shipped copy: no native
// checkpoint at all, one shipped-only cp0 linked to genesis.
// Coverage = Some(0) under V5b; N4 mutation would give `None`.
// Acceptance row paired with C5.
// =====================================================================
#[test]
fn c5b_shipped_only_genesis_checkpoint_is_the_sole_coverage_source() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    // No native inputs; pass only a shipped file carrying cp0.
    let shipped = d.0.join("cp0.copy");
    write_bytes(&shipped, &line_bytes(&cp0));
    let (covered, findings) = report_of_files(vec![shipped], trust_fixture());
    assert_eq!(covered, Some(0));
    assert_findings(&findings, &[], "C5b");
}

// =====================================================================
// C6 — ADR-0005 decision 11 "Attested repairs": SIGKILLed mid-write,
// then another process records and a trusted checkpoint covers that
// record. Layout: [cp0, <fragment>, e2(repaired), cp3]. e2 attests
// the fragment; cp3 is a trusted checkpoint at seq >= e2.seq, so
// coverage promotes the attested gap to one `TornWriteRepaired`.
// Acceptance row.
// =====================================================================
#[test]
fn c6_sigkilled_then_recorded_and_covered_is_one_torn_write_repaired() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let fragment = b"{\"torn\":\n";
    let gap_digest = repair_digest(fragment);
    let e2 = entry_rec_with_repaired(2, cp0.hash(), gap_digest);
    let mmr2 = pushed(&mmr0, &e2);
    let cp3 = signed_cp(3, e2.hash(), &mmr2);
    let mut bytes: Vec<u8> = line_bytes(&cp0);
    bytes.extend_from_slice(fragment);
    bytes.extend_from_slice(&line_bytes(&e2));
    bytes.extend_from_slice(&line_bytes(&cp3));
    write_bytes(&segment_path(&d.0, 0), &bytes);
    let path = segment_path(&d.0, 0);
    let (covered, findings) = report_of_files(vec![path.clone()], trust_fixture());
    assert_eq!(covered, Some(3));
    let expected = vec![
        located(
            K::TornWriteRepaired,
            path.clone(),
            2,
            2,
            format!(
                "lines 2..=2 ({len} bytes), attested at line 3 seq 2",
                len = fragment.len(),
            ),
        ),
        located(K::SeqGap, path, 3, 2, "missing seq 1..=1".to_owned()),
    ];
    assert_findings(&findings, &expected, "C6");
}

// =====================================================================
// C7 — ADR-0005 decision 11 "a crash during the repairing write":
// two fragment lines in one gap, attested once by e3, and the whole
// trail covered by cp4. One `TornWriteRepaired` finding (ruling
// 13-V5-d1 point 6: one attested-and-covered gap, one info).
// Acceptance row.
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
    let e3 = entry_rec_with_repaired(3, cp0.hash(), gap_digest);
    let mmr3 = pushed(&mmr0, &e3);
    let cp4 = signed_cp(4, e3.hash(), &mmr3);
    let mut bytes: Vec<u8> = line_bytes(&cp0);
    bytes.extend_from_slice(frag_a);
    bytes.extend_from_slice(frag_b);
    bytes.extend_from_slice(&line_bytes(&e3));
    bytes.extend_from_slice(&line_bytes(&cp4));
    let path = segment_path(&d.0, 0);
    write_bytes(&path, &bytes);
    let (covered, findings) = report_of_files(vec![path.clone()], trust_fixture());
    assert_eq!(covered, Some(4));
    let expected = vec![
        located(
            K::TornWriteRepaired,
            path.clone(),
            2,
            3,
            format!(
                "lines 2..=3 ({len} bytes), attested at line 4 seq 3",
                len = all.len(),
            ),
        ),
        located(K::SeqGap, path, 4, 3, "missing seq 1..=2".to_owned()),
    ];
    assert_findings(&findings, &expected, "C7");
}

// =====================================================================
// C8 — the attesting line is itself the trusted checkpoint (the
// sealing checkpoint attests its own repaired tail). Coverage is
// inclusive (ruling 13-V5-d1 point 6, the "at or below" rule), so
// the gap becomes `TornWriteRepaired`. Acceptance row.
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
    let (covered, findings) = report_of_files(vec![path.clone()], trust_fixture());
    assert_eq!(covered, Some(1));
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
    assert_findings(&findings, &expected, "C8");
}

// =====================================================================
// C8b — second row for N1 (coverage inclusive `<=` → exclusive `<`).
// The attesting record is an entry at `seq == covered_through`; the
// closing checkpoint lives at the same `seq` is impossible, so this
// variant uses a non-sealing checkpoint cp1 whose repaired attests
// the preceding fragment AND whose seq is the highest trusted
// checkpoint: `covered_through == attesting_seq`. Pairs with C8.
// =====================================================================
#[test]
fn c8b_attesting_seq_equals_covered_through_is_torn_write_repaired() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let fragment = b"{\"half\":\n";
    let gap_digest = repair_digest(fragment);
    // cp1 at seq=1 attests the fragment preceding it and is itself a
    // trusted checkpoint: `covered_through == attesting_seq == 1`.
    let ctx = context(1, cp0.hash()).repaired(gap_digest);
    let cp1 = signed_cp_with_ctx(ctx, &mmr0);
    let mut bytes = line_bytes(&cp0);
    bytes.extend_from_slice(fragment);
    bytes.extend_from_slice(&line_bytes(&cp1));
    let path = segment_path(&d.0, 0);
    write_bytes(&path, &bytes);
    let (covered, findings) = report_of_files(vec![path.clone()], trust_fixture());
    assert_eq!(covered, Some(1));
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
    assert_findings(&findings, &expected, "C8b");
}

// =====================================================================
// C9 — ADR-0005 d11 bullet: "attesting line not yet covered: the gap
// stays `TornWrite` until the next trusted checkpoint, then
// `TornWriteRepaired`". The same trail is verified twice, before and
// after appending a trusted checkpoint. Both full lists are
// asserted; the "after" assertion is the acceptance assertion.
// =====================================================================
#[test]
fn c9_attesting_line_not_yet_covered_until_next_trusted_checkpoint() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let fragment = b"{\"torn\":\n";
    let gap_digest = repair_digest(fragment);
    let e2 = entry_rec_with_repaired(2, cp0.hash(), gap_digest);
    let mmr2 = pushed(&mmr0, &e2);
    // "Before": the attesting record e2 is NOT yet covered by a
    // trusted checkpoint (cp0 covers only seq 0 < e2.seq = 2).
    let mut bytes = line_bytes(&cp0);
    bytes.extend_from_slice(fragment);
    bytes.extend_from_slice(&line_bytes(&e2));
    let path = segment_path(&d.0, 0);
    write_bytes(&path, &bytes);
    let (covered, findings) = report_of_files(vec![path.clone()], trust_fixture());
    assert_eq!(covered, Some(0));
    let expected_before = vec![
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
        uncovered(1, 2),
    ];
    assert_findings(&findings, &expected_before, "C9-before");
    // "After": append cp3, a trusted checkpoint that covers e2.
    let cp3 = signed_cp(3, e2.hash(), &mmr2);
    bytes.extend_from_slice(&line_bytes(&cp3));
    write_bytes(&path, &bytes);
    let (covered, findings) = report_of_files(vec![path.clone()], trust_fixture());
    assert_eq!(covered, Some(3));
    let expected_after = vec![
        located(
            K::TornWriteRepaired,
            path.clone(),
            2,
            2,
            format!(
                "lines 2..=2 ({len} bytes), attested at line 3 seq 2",
                len = fragment.len(),
            ),
        ),
        located(K::SeqGap, path, 3, 2, "missing seq 1..=1".to_owned()),
    ];
    // Acceptance assertion.
    assert_findings(&findings, &expected_after, "C9-after");
}

// =====================================================================
// R1 — REGRESSION row: the attesting line is covered only by a
// checkpoint signed with an unlisted key; the gap stays `TornWrite`
// and `covered_through` is the lower trusted one (cp0). Labelled
// regression. Named runtime killers (each exit 101 at head, exit 0
// after revert):
//   N2 (promote without a coverage check) — would flip TornWrite to
//      TornWriteRepaired here even though cp_unlisted is not
//      trusted; the row's literal list reddens.
//   N3 (coverage counts every checkpoint, ignoring the trusted
//      predicate) — would raise `covered_through` to 3 and the
//      TornWrite finding to TornWriteRepaired; the row reddens.
// =====================================================================
#[test]
fn r1_regression_covered_only_by_unlisted_key_stays_torn_write() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let fragment = b"{\"torn\":\n";
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
    let (covered, findings) = report_of_files(vec![path.clone()], trust_fixture());
    // Coverage falls back to cp0; cp3 is `UntrustedKey`.
    assert_eq!(covered, Some(0));
    let unlisted_hex = hex(&signer.public_key());
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
            format!("key {unlisted_hex} not listed for trail {TRAIL_HEX}"),
        ),
        uncovered(1, 3),
    ];
    assert_findings(&findings, &expected, "R1 regression");
}

// =====================================================================
// R2 — REGRESSION row: an inserted fragment before a line with NO
// `audit.repaired`, under coverage. Stays `RepairMismatch`
// (ruling 13-V5-d1 point 6: RepairMismatch is never promoted).
// Named runtime killers:
//   N7 (RepairMismatch promoted under coverage) — would flip the
//      `K::RepairMismatch` here to `TornWriteRepaired`; the row's
//      literal list reddens.
//   N2 (promote without coverage check) — would also replace
//      RepairMismatch with the promoted variant on any attested
//      gap; this row's non-attesting layout still reddens because
//      the e2.repaired is `None` (no digest match).
// =====================================================================
#[test]
fn r2_regression_repair_mismatch_under_coverage_is_not_promoted() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let fragment = b"{\"torn\":\n";
    // e2 carries NO `audit.repaired` — the gap attests nothing, so
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
    let (covered, findings) = report_of_files(vec![path.clone()], trust_fixture());
    assert_eq!(covered, Some(3));
    let gap_digest = digest_string(&repair_digest(fragment));
    let expected = vec![
        located(
            K::RepairMismatch,
            path.clone(),
            2,
            2,
            format!(
                "lines 2..=2 ({len} bytes), attested at line 3 seq 2: expected {gap_digest}, got none",
                len = fragment.len(),
            ),
        ),
        located(K::SeqGap, path, 3, 2, "missing seq 1..=1".to_owned()),
    ];
    assert_findings(&findings, &expected, "R2 regression");
}

// =====================================================================
// R2b — REGRESSION row paired with R2: same shape (missing
// `audit.repaired`) but with the attesting record at exactly the
// trusted-checkpoint seq. On base, `RepairMismatch` is already the
// outcome; N7 would promote both R2 and R2b to `TornWriteRepaired`.
// =====================================================================
#[test]
fn r2b_regression_repair_mismatch_at_covered_seq_is_not_promoted() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let fragment = b"{\"torn\":\n";
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
    let (covered, findings) = report_of_files(vec![path.clone()], trust_fixture());
    assert_eq!(covered, Some(1));
    let gap_digest = digest_string(&repair_digest(fragment));
    let expected = vec![located(
        K::RepairMismatch,
        path,
        2,
        1,
        format!(
            "lines 2..=2 ({len} bytes), attested at line 3 seq 1: expected {gap_digest}, got none",
            len = fragment.len(),
        ),
    )];
    assert_findings(&findings, &expected, "R2b regression");
}

// =====================================================================
// R3 — REGRESSION row: a trailing gap under coverage of everything
// before it stays `TornWrite` (ruling 13-V5-d1 point 6: a trailing
// gap with no attesting line is never promoted). Named runtime
// killers:
//   N8 (trailing gap promoted under coverage) — would flip the
//      trailing `TornWrite` to `TornWriteRepaired`; the row's
//      literal list reddens.
//   N2 (promote without coverage check) — same promotion on the
//      trailing `TornWrite`; row reddens.
// =====================================================================
#[test]
fn r3_regression_trailing_gap_under_coverage_stays_torn_write() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let fragment = b"{\"torn\":\n";
    let mut bytes = line_bytes(&cp0);
    bytes.extend_from_slice(fragment);
    let path = segment_path(&d.0, 0);
    write_bytes(&path, &bytes);
    let (covered, findings) = report_of_files(vec![path.clone()], trust_fixture());
    assert_eq!(covered, Some(0));
    let gap_digest = digest_string(&repair_digest(fragment));
    // The trailing TornWrite has `seq: None` (no attesting record).
    let expected = vec![Finding::new(
        K::TornWrite,
        Some(path),
        Some(2),
        None,
        format!(
            "trailing gap lines 2..=2 ({len} bytes), digest {gap_digest}",
            len = fragment.len(),
        ),
    )];
    assert_findings(&findings, &expected, "R3 regression");
}

// =====================================================================
// R3b — REGRESSION row paired with R3: trailing gap after a
// trusted MID-trail checkpoint (not just cp0). Pairs with R3 to
// give N8 (trailing gap promoted under coverage) a second named
// kill with a higher `covered_through`.
// =====================================================================
#[test]
fn r3b_regression_trailing_gap_after_higher_coverage_stays_torn_write() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let fragment = b"{\"torn\":\n";
    let mut bytes = line_bytes(&cp0);
    bytes.extend_from_slice(&line_bytes(&e1));
    bytes.extend_from_slice(&line_bytes(&cp2));
    bytes.extend_from_slice(fragment);
    let path = segment_path(&d.0, 0);
    write_bytes(&path, &bytes);
    let (covered, findings) = report_of_files(vec![path.clone()], trust_fixture());
    assert_eq!(covered, Some(2));
    let gap_digest = digest_string(&repair_digest(fragment));
    let expected = vec![Finding::new(
        K::TornWrite,
        Some(path),
        Some(4),
        None,
        format!(
            "trailing gap lines 4..=4 ({len} bytes), digest {gap_digest}",
            len = fragment.len(),
        ),
    )];
    assert_findings(&findings, &expected, "R3b regression");
}

// =====================================================================
// Consistency check on the key, trail and fixture hashes every row
// uses. Mirrors `signature_tests::fixture_hashes_match_literals`.
// =====================================================================
#[test]
fn fixture_hashes_match_literals() {
    assert_eq!(hex(&fixture_pubkey()), FIXTURE_KEY_HEX);
    assert_eq!(hex(&TRAIL), TRAIL_HEX);
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
