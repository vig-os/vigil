//! Rows for the verifier's receipt reconciliation (ADR-0005
//! decision 5 "Receipt reconciliation"; ruling 13-V7-d1 points 2-5).
//!
//! Row standard (repo-wide): every acceptance row asserts the FULL
//! sorted literal finding list as whole [`Finding`] values through
//! [`assert_findings`] (a thin wrapper around `assert_eq!` on
//! `Vec<Finding>`). Regression rows are labelled in their doc
//! comments. Every digest and hash in an expected detail is a
//! written-out hex constant pinned by
//! [`fixture_hashes_match_literals`]. Expected lists are written in
//! the engine's final sort order (`(seq.is_none(), seq, file, line,
//! kind_debug)`), so no per-row sort runs here.
//!
//! Fixture style: wall-clock time stamps on the real writer would
//! drift the record hashes per run and the row literals with them,
//! so the records are hand-built through the same `signed_cp`,
//! `entry_rec` and `Record::new_internal` helpers the end-link rows
//! use; these go through the same `Record::checkpoint` /
//! `CheckpointFields` paths the writer's `sink::signed` uses, with
//! fixture timestamps `100 + seq`, so the resulting records are
//! byte-for-byte what a writer would emit at the fixture clock.
//! Receipts are `(seq, hash)` tuples read off those records, so no
//! real writer is needed.

use crate::audit::{
    Entry, FindingKind as K, Mmr, Record, RecordContext, TrustPolicy, digest_string,
    runs_v4a_fixtures::{
        TRAIL, Temp, context, entry_rec, fixture_pubkey, line_bytes, pushed, put_segment, seeded,
        segment_path, signed_cp, signed_cp_explicit,
    },
    verify::{Finding, Report, Verifier},
};
use std::path::PathBuf;

// =====================================================================
// Shared literal hex constants. Pinned by `fixture_hashes_match_literals`
// so a drift in a fixture builder surfaces there rather than across
// many rows.
// =====================================================================

/// `signed_cp(0, Record::genesis(&TRAIL), &Mmr::new())` — the honest
/// seq=0 opening used by every single-segment row.
const CP0_HONEST_DIGEST: &str =
    "blake3:fc26c6f2bb830592aaaca5413da1599489d86ac6e240a4a7a010681e0d4c8e77";
/// `entry_rec(1, cp0.hash())` on the honest chain — e1.
const E1_HONEST_DIGEST: &str =
    "blake3:c121282b5135adfe7a17142cae6bfc4c9040c4aed26d74bddc923b8dafcdb6e8";
/// `signed_cp(2, e1.hash(), &mmr1)` on the honest `[cp0, e1]` fold.
const CP2_HONEST_DIGEST: &str =
    "blake3:4164966a12a675e55eb6e133b9e50313907f164fe142d941447defcdfdb25d06";
/// `entry_rec(2, e1.hash())` on the honest chain — the "forged e2"
/// by convention (a byte-identical entry at seq 2; the verifier has
/// no out-of-band way to tell it from a legitimate append).
const E2_HONEST_DIGEST: &str =
    "blake3:8a5ea9c989aad7e89033b58ad6f59a6384af43dfe6df5bada042420c0040c306";
/// `entry_rec(3, e2.hash())` on the honest chain — the "forged e3"
/// the second forged append at seq 3 in the two-forged rows.
const E3_HONEST_DIGEST: &str =
    "blake3:b378374409602bc24aa87765b3cc3361e3b647368f57d9a06816f9b2bd0696c9";
/// `signed_cp(3, e2.hash(), &mmr2)` on the four-record honest chain
/// `[cp0, e1, e2, cp3]`; the honest close after the
/// forged seq=2 append.
const CP3_FROM_E2_DIGEST: &str =
    "blake3:dda83f7bbaaf877076831dd97e6563148bf337d350bc58cf8bc6e8802eed2f66";
/// `signed_cp(4, e3.hash(), &mmr3)` on the five-record chain
/// `[cp0, e1, e2, e3, cp4]` used by the two-forged rows.
const CP4_FROM_E3_DIGEST: &str =
    "blake3:e1d62ae3be94079ce6b6e664b4d225fc764033173ce51b446fc8c38f86778810";
/// `entry_rec(4, cp3.hash())` on the six-record honest chain
/// `[cp0, e1, e2, cp3, e4, cp5]` — the "writer B" entry.
const E4_HONEST_DIGEST: &str =
    "blake3:c0d53ffca7d1358ec842a15694a00833b408e2a6d43f49f2f1de7225fabba4e6";
/// `signed_cp(5, e4.hash(), &mmr4)` on the six-record honest chain
/// used by the writer-A/attacker/writer-B row.
const CP5_FROM_E4_DIGEST: &str =
    "blake3:8c2a212152faa447de5f329dc79b90a503eec4ec0f18cfb9b6717a749d6a4cd0";
/// A placeholder 32-byte hash for an unknown-receipt scenario:
/// `[0x5a; 32]`.
const WRONG_HASH_5A_DIGEST: &str =
    "blake3:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
/// Another placeholder: `[0x66; 32]`.
const WRONG_HASH_66_DIGEST: &str =
    "blake3:6666666666666666666666666666666666666666666666666666666666666666";

// =====================================================================
// Helpers.
// =====================================================================

const WRONG_HASH_5A: [u8; 32] = [0x5a; 32];
const WRONG_HASH_66: [u8; 32] = [0x66; 32];

fn located(kind: K, file: PathBuf, line: u64, seq: u64, detail: String) -> Finding {
    Finding::new(kind, Some(file), Some(line), Some(seq), detail)
}
fn unlocated(kind: K, seq: Option<u64>, detail: String) -> Finding {
    Finding::new(kind, None, None, seq, detail)
}

#[track_caller]
fn assert_findings(actual: &[Finding], expected: &[Finding], label: &str) {
    assert_eq!(actual, expected, "{label} literal finding list");
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

/// Builds a `vigil.audit.resume` operator record at `seq` on the
/// honest fixture clock. Mirrors `resume_decl` but takes arbitrary
/// `(seq, previous)` so a row can plant such a record where it needs
/// one.
fn op_resume_rec(seq: u64, previous: [u8; 32], head_seq: u64, head_hash: [u8; 32]) -> Record {
    Record::new_internal(
        context(seq, previous),
        Entry::new("operator", "vigil.audit.resume", "trail")
            .reason("incident")
            .details(format!(
                "head={head_seq}:{hex} lost_through={head_seq} file=-",
                hex = digest_string(&head_hash)
            )),
    )
    .unwrap()
}

/// Entry record on an arbitrary trail, used to plant a forged record
/// of another trail (gated out of the verified set by the engine's
/// trail filter).
#[allow(dead_code)]
fn entry_on_trail(trail: [u8; 16], seq: u64, previous: [u8; 32]) -> Record {
    let ctx = RecordContext::new(trail, seq, 100 + seq, "test", previous);
    Record::new(ctx, Entry::new("a", "change", "c")).unwrap()
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

/// The honest `[cp0, e1, cp2]` three-record trail, retained for the
/// rows that need `e1`/`cp2` hashes.
struct ThreeRecord {
    _dir: Temp,
    path: PathBuf,
    e1: Record,
    cp2: Record,
}
fn three_record() -> ThreeRecord {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let seg = seal(&[&cp0, &e1, &cp2]);
    ThreeRecord {
        _dir: seg._dir,
        path: seg.path,
        e1,
        cp2,
    }
}

// =====================================================================
// Shared literal-hex consistency test. Pins every `const` in this
// module against its builder's live hash, so a fixture drift surfaces
// here rather than in each row's expected list.
// =====================================================================
#[test]
fn fixture_hashes_match_literals() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2_cp = pushed(&mmr1, &cp2);
    let _ = mmr2_cp;
    let mmr2 = pushed(&mmr1, &e2);
    let cp3 = signed_cp(3, e2.hash(), &mmr2);
    let e3 = entry_rec(3, e2.hash());
    let mmr3 = pushed(&mmr2, &e3);
    let cp4 = signed_cp(4, e3.hash(), &mmr3);
    let mmr_cp3 = pushed(&mmr2, &cp3);
    let e4 = entry_rec(4, cp3.hash());
    let mmr4 = pushed(&mmr_cp3, &e4);
    let cp5 = signed_cp(5, e4.hash(), &mmr4);
    assert_eq!(digest_string(&cp0.hash()), CP0_HONEST_DIGEST, "cp0");
    assert_eq!(digest_string(&e1.hash()), E1_HONEST_DIGEST, "e1");
    assert_eq!(digest_string(&cp2.hash()), CP2_HONEST_DIGEST, "cp2");
    assert_eq!(digest_string(&e2.hash()), E2_HONEST_DIGEST, "e2");
    assert_eq!(digest_string(&cp3.hash()), CP3_FROM_E2_DIGEST, "cp3");
    assert_eq!(digest_string(&e3.hash()), E3_HONEST_DIGEST, "e3");
    assert_eq!(digest_string(&cp4.hash()), CP4_FROM_E3_DIGEST, "cp4");
    assert_eq!(digest_string(&e4.hash()), E4_HONEST_DIGEST, "e4");
    assert_eq!(digest_string(&cp5.hash()), CP5_FROM_E4_DIGEST, "cp5");
    assert_eq!(
        digest_string(&WRONG_HASH_5A),
        WRONG_HASH_5A_DIGEST,
        "wrong5a"
    );
    assert_eq!(
        digest_string(&WRONG_HASH_66),
        WRONG_HASH_66_DIGEST,
        "wrong66"
    );
}

// =====================================================================
// REGRESSION. Every record has its receipt and no finding
// fires. Supplied in two `.receipts(...)` calls so the "second call
// adds" semantic (ADR-0005 decision 11 `.receipts`) is exercised,
// and checkpoints need no receipt (ruling 13-V7-d1 point 5).
// =====================================================================
#[test]
fn every_record_has_its_receipt() {
    let fx = three_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash())])
        .receipts([(2, fx.cp2.hash())]);
    let report = report_of(vec![fx.path], verifier);
    assert_findings(report.findings(), &[], "every_record_has_its_receipt");
    assert!(
        report.is_strict_valid(),
        "every_record_has_its_receipt must pass --strict"
    );
}

// =====================================================================
// ACCEPTANCE. Writer A closes, an attacker appends a record
// at seq=2 with no receipt, writer B records and closes (ADR-0005
// decision 11 l.918). The forged record is reported as `NoReceipt`
// at its first copy; honest records with their receipts are
// matched.
// =====================================================================
#[test]
fn forged_append_between_writers_emits_no_receipt() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2_forged = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2_forged);
    let cp3 = signed_cp(3, e2_forged.hash(), &mmr2);
    let mmr_cp3 = pushed(&mmr2, &cp3);
    let e4 = entry_rec(4, cp3.hash());
    let mmr4 = pushed(&mmr_cp3, &e4);
    let cp5 = signed_cp(5, e4.hash(), &mmr4);
    let seg = seal(&[&cp0, &e1, &e2_forged, &cp3, &e4, &cp5]);
    let verifier =
        Verifier::new(trust_with_key(fixture_pubkey())).receipts([(1, e1.hash()), (4, e4.hash())]);
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![located(
        K::NoReceipt,
        seg.path,
        3,
        2,
        format!("no receipt for seq 2 hash {E2_HONEST_DIGEST}"),
    )];
    assert_findings(
        report.findings(),
        &expected,
        "forged_append_between_writers_emits_no_receipt",
    );
}

// =====================================================================
// ACCEPTANCE. Two forged records after the last receipt, then
// an honest close (ADR-0005 decision 11 l.919). Both forgeds are
// reported as `NoReceipt`: the reconciled range runs through the
// last record in the files, not through the last receipt (ruling
// 13-V7-d1 point 3).
// =====================================================================
#[test]
fn two_forged_after_last_receipt_emit_no_receipt_each() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2_forged = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2_forged);
    let e3_forged = entry_rec(3, e2_forged.hash());
    let mmr3 = pushed(&mmr2, &e3_forged);
    let cp4 = signed_cp(4, e3_forged.hash(), &mmr3);
    let seg = seal(&[&cp0, &e1, &e2_forged, &e3_forged, &cp4]);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([(1, e1.hash())]);
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![
        located(
            K::NoReceipt,
            seg.path.clone(),
            3,
            2,
            format!("no receipt for seq 2 hash {E2_HONEST_DIGEST}"),
        ),
        located(
            K::NoReceipt,
            seg.path,
            4,
            3,
            format!("no receipt for seq 3 hash {E3_HONEST_DIGEST}"),
        ),
    ];
    assert_findings(
        report.findings(),
        &expected,
        "two_forged_after_last_receipt_emit_no_receipt_each",
    );
}

// =====================================================================
// ACCEPTANCE. A forged record between `create` and the first
// application record (ADR-0005 decision 11 l.920). The reconciled
// range runs from `seq 0` through the last record in the files, so
// `NoReceipt` fires for the forged seq=1 even though every receipt
// supplied names a higher `seq` (ruling 13-V7-d1 point 3).
// =====================================================================
#[test]
fn forged_before_first_app_record_emits_no_receipt() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1_forged = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1_forged);
    let e2_app = entry_rec(2, e1_forged.hash());
    let mmr2 = pushed(&mmr1, &e2_app);
    let cp3 = signed_cp(3, e2_app.hash(), &mmr2);
    let seg = seal(&[&cp0, &e1_forged, &e2_app, &cp3]);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([(2, e2_app.hash())]);
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![located(
        K::NoReceipt,
        seg.path,
        2,
        1,
        format!("no receipt for seq 1 hash {E1_HONEST_DIGEST}"),
    )];
    assert_findings(
        report.findings(),
        &expected,
        "forged_before_first_app_record_emits_no_receipt",
    );
}

// =====================================================================
// ACCEPTANCE. Two `ReceiptMismatch` details: one for a receipt
// above the head (`no record`) and one for a receipt with a
// different hash (`hash differs`) (ADR-0005 decision 11 l.921). The
// receipt for seq=1 has the wrong hash, so `e1` also gets a
// `NoReceipt` because no receipt in the set names `(1, e1.hash())`.
// =====================================================================
#[test]
fn receipt_above_head_and_wrong_hash_emit_receipt_mismatch() {
    let fx = three_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, WRONG_HASH_5A), (5, WRONG_HASH_66)]);
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![
        unlocated(
            K::ReceiptMismatch,
            Some(1),
            format!(
                "receipt seq 1 hash {WRONG_HASH_5A_DIGEST}: hash differs (record {E1_HONEST_DIGEST})"
            ),
        ),
        located(
            K::NoReceipt,
            fx.path,
            2,
            1,
            format!("no receipt for seq 1 hash {E1_HONEST_DIGEST}"),
        ),
        unlocated(
            K::ReceiptMismatch,
            Some(5),
            format!("receipt seq 5 hash {WRONG_HASH_66_DIGEST}: no record"),
        ),
    ];
    assert_findings(
        report.findings(),
        &expected,
        "receipt_above_head_and_wrong_hash_emit_receipt_mismatch",
    );
}

/// The hand-built `vigil.audit.resume` detail the operator-resume rows share. The scenario
/// does not exercise the engine's resume structural check (that is
/// `resume`'s job); `structural=invalid(no-opening)` is the shared
/// finding both operator-resume rows carry, so each row's assertion remains
/// about reconciliation.
const OP_RESUME_DETAIL: &str = "operator=operator reason=incident head=0:blake3:fc26c6f2bb830592aaaca5413da1599489d86ac6e240a4a7a010681e0d4c8e77 \
     gap=none lost_records=0 structural=invalid(no-opening)";

// =====================================================================
// ACCEPTANCE. A `vigil.audit.resume` operator record with no
// receipt gets `NoReceipt` at its first copy (ruling 13-V7-d1
// point 5: operator `vigil.audit.*` records are included). The
// engine's `Resumed` warning is unaffected by reconciliation.
// =====================================================================
#[test]
fn operator_resume_without_receipt_emits_no_receipt() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let op = op_resume_rec(1, cp0.hash(), 0, cp0.hash());
    let mmr1 = pushed(&mmr0, &op);
    let cp2 = signed_cp(2, op.hash(), &mmr1);
    let seg = seal(&[&cp0, &op, &cp2]);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([]);
    let report = report_of(vec![seg.path.clone()], verifier);
    let op_digest = digest_string(&op.hash());
    let expected = vec![
        located(
            K::NoReceipt,
            seg.path.clone(),
            2,
            1,
            format!("no receipt for seq 1 hash {op_digest}"),
        ),
        located(K::Resumed, seg.path, 2, 1, OP_RESUME_DETAIL.to_owned()),
    ];
    assert_findings(
        report.findings(),
        &expected,
        "operator_resume_without_receipt_emits_no_receipt",
    );
}

// =====================================================================
// REGRESSION. The same resume-record scenario with its matching
// receipt emits no reconciliation finding — the "with the receipt,
// no finding" branch of ruling 13-V7-d1 point 5.
// =====================================================================
#[test]
fn operator_resume_with_receipt_has_no_reconciliation_finding() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let op = op_resume_rec(1, cp0.hash(), 0, cp0.hash());
    let mmr1 = pushed(&mmr0, &op);
    let cp2 = signed_cp(2, op.hash(), &mmr1);
    let seg = seal(&[&cp0, &op, &cp2]);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([(1, op.hash())]);
    let report = report_of(vec![seg.path.clone()], verifier);
    let expected = vec![located(
        K::Resumed,
        seg.path,
        2,
        1,
        OP_RESUME_DETAIL.to_owned(),
    )];
    assert_findings(
        report.findings(),
        &expected,
        "operator_resume_with_receipt_has_no_reconciliation_finding",
    );
}

// =====================================================================
// ACCEPTANCE. A receipt at a forked `seq` where one copy
// carries its hash is still `ReceiptMismatch "seq is forked"`
// (ruling 13-V7-d1 point 4: matching at a forked `seq` fails
// closed, as anchors do, ruling 13-V6-d1 point 2). The engine's
// `SeqConflict` for the fork fires alongside; the distinct
// record carrying a different hash gets its own `NoReceipt`
// because the set holds no receipt naming its `(seq, hash)`.
// =====================================================================
#[test]
fn receipt_at_forked_seq_is_forked_not_matched() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    // Alternative seq=1 payload at the fork (same previous, different
    // "object" field): a distinct hash at seq=1 produces a fork.
    let e1_alt = Record::new(context(1, cp0.hash()), Entry::new("actor", "change", "alt")).unwrap();
    // Segment 0 is the honest `[cp0, e1, cp2]`.
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let seg0 = segment_path(&d.0, 0);
    // The alternative seq=1 lives on its own sealed segment so the
    // reader sees two distinct records at seq=1 (a fork).
    let cp2_alt = signed_cp_explicit(2, e1_alt.hash(), 2, [0xee; 32], vec![[0xdd; 32]]);
    put_segment(&d.0, 1, &[&cp0, &e1_alt, &cp2_alt], &[]);
    let seg1 = segment_path(&d.0, 1);
    // Receipt (1, e1.hash()) names the honest entry at the fork;
    // receipt (2, cp2.hash()) names the honest checkpoint at the
    // other fork. Both must fail closed with `seq is forked`
    // (ruling 13-V7-d1 point 4), the matching-copy rule used by
    // anchors (ruling 13-V6-d1 point 2) is replaced by the shared
    // forked predicate.
    let verifier =
        Verifier::new(trust_with_key(fixture_pubkey())).receipts([(1, e1.hash()), (2, cp2.hash())]);
    let report = report_of(vec![seg0.clone(), seg1.clone()], verifier);
    // cp0 is byte-identical in both segments: one `DuplicateRecord`
    // fires at the first (seg0) copy. Forked seq=1 and seq=2 each
    // raise a `SeqConflict`; "conflicting hashes" sorts the distinct
    // hashes in byte order and `e1_alt` (0x125619...) < `e1`
    // (0xc12128...), so the alt hash is listed first. The one
    // `NoReceipt` for the alt-hash record at seq=1 locates at its
    // first copy (seg1).
    let cp2_alt_digest = digest_string(&cp2_alt.hash());
    let e1_alt_digest = digest_string(&e1_alt.hash());
    let expected = vec![
        located(
            K::DuplicateRecord,
            seg0.clone(),
            1,
            0,
            "2 copies of 1 distinct records".to_owned(),
        ),
        unlocated(
            K::ReceiptMismatch,
            Some(1),
            format!("receipt seq 1 hash {E1_HONEST_DIGEST}: seq is forked"),
        ),
        located(
            K::SeqConflict,
            seg0.clone(),
            2,
            1,
            format!("conflicting hashes: {e1_alt_digest}, {E1_HONEST_DIGEST}"),
        ),
        located(
            K::NoReceipt,
            seg1.clone(),
            2,
            1,
            format!("no receipt for seq 1 hash {e1_alt_digest}"),
        ),
        unlocated(
            K::ReceiptMismatch,
            Some(2),
            format!("receipt seq 2 hash {CP2_HONEST_DIGEST}: seq is forked"),
        ),
        located(
            K::SeqConflict,
            seg0.clone(),
            3,
            2,
            format!("conflicting hashes: {CP2_HONEST_DIGEST}, {cp2_alt_digest}"),
        ),
    ];
    // Drop `_dir` only after reporting; `d` keeps the segments alive
    // through `report_of`.
    let _dir = d;
    assert_findings(
        report.findings(),
        &expected,
        "receipt_at_forked_seq_is_forked_not_matched",
    );
}

// =====================================================================
// ACCEPTANCE. Companion to the fork row above with the fork raised
// one step higher (seq=2 `cp2` fork, no fork at seq=1). The receipt
// names one copy of the checkpoint at the forked `seq`; the shared
// forked predicate still refuses to match (ruling 13-V7-d1 point 4;
// ruling 13-V6-d1 point 2), so `ReceiptMismatch "seq is forked"`
// fires without reference to the matching copy's hash.
// =====================================================================
#[test]
fn receipt_at_forked_checkpoint_seq_is_forked_not_matched() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    // Alternative seq=2 checkpoint (same previous, different declared
    // fields): a distinct hash at seq=2 produces a cp-only fork, while
    // cp0 and e1 stay byte-identical across segments.
    let cp2_alt = signed_cp_explicit(2, e1.hash(), 2, [0x22; 32], vec![[0x33; 32]]);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let seg0 = segment_path(&d.0, 0);
    put_segment(&d.0, 1, &[&cp0, &e1, &cp2_alt], &[]);
    let seg1 = segment_path(&d.0, 1);
    let verifier =
        Verifier::new(trust_with_key(fixture_pubkey())).receipts([(1, e1.hash()), (2, cp2.hash())]);
    let report = report_of(vec![seg0.clone(), seg1.clone()], verifier);
    let cp2_alt_digest = digest_string(&cp2_alt.hash());
    let expected = vec![
        located(
            K::DuplicateRecord,
            seg0.clone(),
            1,
            0,
            "2 copies of 1 distinct records".to_owned(),
        ),
        located(
            K::DuplicateRecord,
            seg0.clone(),
            2,
            1,
            "2 copies of 1 distinct records".to_owned(),
        ),
        unlocated(
            K::ReceiptMismatch,
            Some(2),
            format!("receipt seq 2 hash {CP2_HONEST_DIGEST}: seq is forked"),
        ),
        located(
            K::SeqConflict,
            seg0,
            3,
            2,
            format!("conflicting hashes: {CP2_HONEST_DIGEST}, {cp2_alt_digest}"),
        ),
    ];
    let _dir = d;
    assert_findings(
        report.findings(),
        &expected,
        "receipt_at_forked_checkpoint_seq_is_forked_not_matched",
    );
}

// =====================================================================
// ACCEPTANCE. `.receipts([])` on a trail with records turns
// reconciliation on (ruling 13-V7-d1 point 2) and reports every
// `audit.record` in range as `NoReceipt`; checkpoints get no
// finding.
// =====================================================================
#[test]
fn empty_receipts_call_flags_every_audit_record() {
    let fx = three_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([]);
    let report = report_of(vec![fx.path.clone()], verifier);
    let expected = vec![located(
        K::NoReceipt,
        fx.path,
        2,
        1,
        format!("no receipt for seq 1 hash {E1_HONEST_DIGEST}"),
    )];
    assert_findings(
        report.findings(),
        &expected,
        "empty_receipts_call_flags_every_audit_record",
    );
}

// =====================================================================
// REGRESSION. Without a `.receipts(...)` call reconciliation
// is off (ruling 13-V7-d1 point 2): no `NoReceipt`, no
// `ReceiptMismatch`, and no `OutOfRange` from set-aside.
// =====================================================================
#[test]
fn no_receipts_call_runs_no_reconciliation() {
    let fx = three_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()));
    let report = report_of(vec![fx.path], verifier);
    assert_findings(
        report.findings(),
        &[],
        "no_receipts_call_runs_no_reconciliation",
    );
}

// =====================================================================
// REGRESSION. Companion to `no_receipts_call_runs_no_reconciliation`
// with an anchor added: anchors run as usual, and no reconciliation
// finding fires because `.receipts(...)` was not called (ruling
// 13-V7-d1 point 2).
// =====================================================================
#[test]
fn no_receipts_call_with_matching_anchor_runs_no_reconciliation() {
    let fx = three_record();
    let cp2_anchor = parse_cp(&fx.cp2);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).anchor(cp2_anchor);
    let report = report_of(vec![fx.path], verifier);
    assert_findings(
        report.findings(),
        &[],
        "no_receipts_call_with_matching_anchor_runs_no_reconciliation",
    );
}

// =====================================================================
// ACCEPTANCE. Two different receipts for one `seq` are each
// evaluated independently (ruling 13-V7-d1 point 4): the matching
// one yields no finding, the other yields one `ReceiptMismatch`
// "hash differs". Supplied across two `.receipts(...)` calls so the
// "second call adds" semantic is exercised.
// =====================================================================
#[test]
fn two_receipts_one_seq_only_mismatch_fires() {
    let fx = three_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash())])
        .receipts([(1, WRONG_HASH_5A)]);
    let report = report_of(vec![fx.path], verifier);
    let expected = vec![unlocated(
        K::ReceiptMismatch,
        Some(1),
        format!(
            "receipt seq 1 hash {WRONG_HASH_5A_DIGEST}: hash differs (record {E1_HONEST_DIGEST})"
        ),
    )];
    assert_findings(
        report.findings(),
        &expected,
        "two_receipts_one_seq_only_mismatch_fires",
    );
}

// =====================================================================
// REGRESSION. Two identical receipts for one `seq` collapse
// to one (ruling 13-V7-d1 point 4): the matching receipt is still
// a match, no `ReceiptMismatch` fires.
// =====================================================================
#[test]
fn identical_receipts_collapse() {
    let fx = three_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash()), (1, fx.e1.hash())]);
    let report = report_of(vec![fx.path], verifier);
    assert_findings(report.findings(), &[], "identical_receipts_collapse");
}

// =====================================================================
// ACCEPTANCE. With an accepted anchored start, a receipt
// below the start is set aside as `OutOfRange` (info) through the
// shared position classifier, and records below the start are not
// reconciled (ruling 13-V7-d1 point 3; ruling 13-V6-d3 points 4-5).
// =====================================================================
#[test]
fn receipt_below_anchored_start_is_set_aside() {
    // Archive layout: the segment starts at seq=2 (cp2) with no
    // cp0/e1 in the files. The start anchor at cp2 is both the
    // accepted start and an anchor (so the start is "anchored" per
    // ruling 13-V6-d3 point 4).
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    let e3 = entry_rec(3, cp2.hash());
    let mmr3 = pushed(&mmr2, &e3);
    let cp4 = signed_cp(4, e3.hash(), &mmr3);
    let seg = seal(&[&cp2, &e3, &cp4]);
    let cp2_cp = Record::parse_line(&line_bytes(&cp2))
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let _ = cp2_cp;
    let cp2_checkpoint = parse_cp(&cp2);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .anchor(cp2_checkpoint.clone())
        .start_from(cp2_checkpoint)
        .receipts([(0, WRONG_HASH_5A), (3, e3.hash())]);
    let report = report_of(vec![seg.path], verifier);
    let expected = vec![unlocated(
        K::OutOfRange,
        Some(0),
        format!("receipt seq 0 hash {WRONG_HASH_5A_DIGEST}: below start seq 2"),
    )];
    assert_findings(
        report.findings(),
        &expected,
        "receipt_below_anchored_start_is_set_aside",
    );
    assert!(
        report.is_strict_valid(),
        "receipt_below_anchored_start_is_set_aside must pass --strict"
    );
}

// =====================================================================
// ACCEPTANCE. With `end_before`, a receipt above `E` is set
// aside and the end record's resume line gets no `NoReceipt` even
// though no receipt names it: the end-record lines are not
// reconciled (ruling 13-V7-d1 point 3; ruling 13-V6-d7). The end
// anchor is supplied so the above-end set-aside is `OutOfRange`
// (info) rather than `UnanchoredEnd`.
// =====================================================================
#[test]
fn end_before_receipts_above_end_set_aside_end_record_not_reconciled() {
    // Files hold `[cp0, e1]`; the end record is `cp2` + a
    // `vigil.audit.resume` second line (seq=3, prev=cp2.hash) that
    // byte-equals the end anchor's first line.
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let resume_line = op_resume_rec(3, cp2.hash(), 2, cp2.hash());
    let seg = seal(&[&cp0, &e1]);
    // Build the archive-record string: cp2's line, LF, resume line
    // (no trailing LF).
    let mut end_record = String::new();
    end_record.push_str(std::str::from_utf8(&line_bytes(&cp2)).unwrap().trim_end());
    end_record.push('\n');
    end_record.push_str(
        std::str::from_utf8(&line_bytes(&resume_line))
            .unwrap()
            .trim_end(),
    );
    let end_anchor = parse_cp(&cp2);
    // No receipt names the resume line at seq=3 — the end-record
    // skip is the only reason no `NoReceipt` fires for it.
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .end_before(&end_record, Some(end_anchor))
        .unwrap()
        .receipts([(1, e1.hash()), (100, WRONG_HASH_66)]);
    let report = report_of(vec![seg.path], verifier);
    // The engine's `Resumed` warning for the end record's resume
    // line is unlocated (`strip_location` for end-record findings,
    // ruling 13-V6-d4 point 6). `UncoveredTail` names the one
    // record above the trusted checkpoint at cp0 (seq=1).
    let expected = vec![
        unlocated(
            K::Resumed,
            Some(3),
            "operator=operator reason=incident head=2:blake3:4164966a12a675e55eb6e133b9e50313907f164fe142d941447defcdfdb25d06 \
             gap=none lost_records=0 structural=invalid(no-opening)"
                .to_owned(),
        ),
        unlocated(
            K::OutOfRange,
            Some(100),
            format!("receipt seq 100 hash {WRONG_HASH_66_DIGEST}: above end seq 3"),
        ),
        unlocated(K::UncoveredTail, None, "records seq 3..=3".to_owned()),
    ];
    assert_findings(
        report.findings(),
        &expected,
        "end_before_receipts_above_end_set_aside_end_record_not_reconciled",
    );
}

// =====================================================================
// ACCEPTANCE. A second `end_before` layout with no end anchor:
// the above-`E` receipt becomes `UnanchoredEnd` (error) instead of
// `OutOfRange` (info), and the end record's resume line still gets
// no `NoReceipt` even though no receipt names it (ruling 13-V7-d1
// point 3; ruling 13-V6-d7).
// =====================================================================
#[test]
fn end_before_no_anchor_resume_line_not_reconciled() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let resume_line = op_resume_rec(3, cp2.hash(), 2, cp2.hash());
    let seg = seal(&[&cp0, &e1]);
    let mut end_record = String::new();
    end_record.push_str(std::str::from_utf8(&line_bytes(&cp2)).unwrap().trim_end());
    end_record.push('\n');
    end_record.push_str(
        std::str::from_utf8(&line_bytes(&resume_line))
            .unwrap()
            .trim_end(),
    );
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .end_before(&end_record, None)
        .unwrap()
        .receipts([(1, e1.hash()), (42, WRONG_HASH_5A)]);
    let report = report_of(vec![seg.path], verifier);
    let expected = vec![
        unlocated(
            K::UnanchoredEnd,
            Some(2),
            "end_before seq 2: no end anchor".to_owned(),
        ),
        unlocated(
            K::Resumed,
            Some(3),
            "operator=operator reason=incident head=2:blake3:4164966a12a675e55eb6e133b9e50313907f164fe142d941447defcdfdb25d06 \
             gap=none lost_records=0 structural=invalid(no-opening)"
                .to_owned(),
        ),
        unlocated(
            K::UnanchoredEnd,
            Some(42),
            format!("receipt seq 42 hash {WRONG_HASH_5A_DIGEST}: above end seq 3"),
        ),
        unlocated(K::UncoveredTail, None, "records seq 3..=3".to_owned()),
    ];
    assert_findings(
        report.findings(),
        &expected,
        "end_before_no_anchor_resume_line_not_reconciled",
    );
}

// =====================================================================
// REGRESSION. The same `end_before` layout with a receipt that
// names the end record's resume line matches cleanly (ruling
// 13-V7-d1 point 3: a receipt naming an end-record line is still
// matched, not a mismatch).
// =====================================================================
#[test]
fn end_before_receipt_naming_resume_line_is_matched() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let resume_line = op_resume_rec(3, cp2.hash(), 2, cp2.hash());
    let seg = seal(&[&cp0, &e1]);
    let mut end_record = String::new();
    end_record.push_str(std::str::from_utf8(&line_bytes(&cp2)).unwrap().trim_end());
    end_record.push('\n');
    end_record.push_str(
        std::str::from_utf8(&line_bytes(&resume_line))
            .unwrap()
            .trim_end(),
    );
    let end_anchor = parse_cp(&cp2);
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .end_before(&end_record, Some(end_anchor))
        .unwrap()
        .receipts([(1, e1.hash()), (3, resume_line.hash())]);
    let report = report_of(vec![seg.path], verifier);
    let expected = vec![
        unlocated(
            K::Resumed,
            Some(3),
            "operator=operator reason=incident head=2:blake3:4164966a12a675e55eb6e133b9e50313907f164fe142d941447defcdfdb25d06 \
             gap=none lost_records=0 structural=invalid(no-opening)"
                .to_owned(),
        ),
        unlocated(K::UncoveredTail, None, "records seq 3..=3".to_owned()),
    ];
    assert_findings(
        report.findings(),
        &expected,
        "end_before_receipt_naming_resume_line_is_matched",
    );
}

// =====================================================================
// ACCEPTANCE. A shipped-only `audit.record` without a
// receipt is reported as `NoReceipt` at the shipped copy (ruling
// 13-V7-d1 point 5: in-range `audit.record` is reconciled whether
// native or shipped-only). A receipt for the same shipped-only
// record matches (ruling 13-V5-d4: shipped-only copies count as
// records). The native segment carries only the trusted
// checkpoints to pin the chain.
// =====================================================================
#[test]
fn shipped_only_record_without_receipt_gets_no_receipt() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    // Native segment: `[cp0, cp2]` — no `e1`.
    put_segment(&d.0, 0, &[&cp0, &cp2], &[]);
    let native = segment_path(&d.0, 0);
    // Shipped file: a single-line copy of `e1`, filename outside the
    // native-segment naming scheme so the verifier reads it as a
    // shipped copy (ruling 13-V3-d2).
    let shipped = d.0.join("collector-01.jsonl");
    std::fs::write(&shipped, line_bytes(&e1)).unwrap();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([]);
    let report = report_of(vec![native, shipped.clone()], verifier);
    let expected = vec![located(
        K::NoReceipt,
        shipped,
        1,
        1,
        format!("no receipt for seq 1 hash {E1_HONEST_DIGEST}"),
    )];
    let _dir = d;
    assert_findings(
        report.findings(),
        &expected,
        "shipped_only_record_without_receipt_gets_no_receipt",
    );
}

// =====================================================================
// ACCEPTANCE. Companion to the shipped-only-without-receipt row
// with the shipped record moved further up the chain: a
// shipped-only operator `vigil.audit.resume` record with no
// matching receipt still gets `NoReceipt` at its shipped copy
// (ruling 13-V7-d1 point 5: in-range `audit.record` is reconciled
// whether native or shipped-only, and operator `vigil.audit.*`
// records are included).
// =====================================================================
#[test]
fn shipped_only_operator_record_without_receipt_gets_no_receipt() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let op = op_resume_rec(1, cp0.hash(), 0, cp0.hash());
    let mmr1 = pushed(&mmr0, &op);
    let cp2 = signed_cp(2, op.hash(), &mmr1);
    // Native segment: `[cp0, cp2]` — the operator record is
    // shipped-only through a Collector-style filename.
    put_segment(&d.0, 0, &[&cp0, &cp2], &[]);
    let native = segment_path(&d.0, 0);
    let shipped = d.0.join("collector-op.jsonl");
    std::fs::write(&shipped, line_bytes(&op)).unwrap();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey())).receipts([]);
    let report = report_of(vec![native.clone(), shipped.clone()], verifier);
    let op_digest = digest_string(&op.hash());
    let _ = native;
    let expected = vec![
        located(
            K::NoReceipt,
            shipped.clone(),
            1,
            1,
            format!("no receipt for seq 1 hash {op_digest}"),
        ),
        located(
            K::Resumed,
            shipped,
            1,
            1,
            format!(
                "operator=operator reason=incident head=0:{CP0_HONEST_DIGEST} \
                 gap=none lost_records=0 structural=invalid(no-opening)"
            ),
        ),
    ];
    let _dir = d;
    assert_findings(
        report.findings(),
        &expected,
        "shipped_only_operator_record_without_receipt_gets_no_receipt",
    );
}

// =====================================================================
// REGRESSION. A `close()` checkpoint passed in as a receipt
// is checked like any other receipt (ADR-0005 decision 11:
// "A receipt may name a checkpoint"). Here `(2, cp2.hash())` names
// the close checkpoint; the record at seq=2 is that checkpoint, so
// the match holds and no finding fires.
// =====================================================================
#[test]
fn checkpoint_as_receipt_is_matched() {
    let fx = three_record();
    let verifier = Verifier::new(trust_with_key(fixture_pubkey()))
        .receipts([(1, fx.e1.hash()), (2, fx.cp2.hash())]);
    let report = report_of(vec![fx.path], verifier);
    assert_findings(report.findings(), &[], "checkpoint_as_receipt_is_matched");
}

// =====================================================================
// Shared helper: parse a `Record` into a `Checkpoint` by its native
// line bytes. Mirrors the same two-step the other verify-tests use.
// =====================================================================
fn parse_cp(record: &Record) -> crate::audit::Checkpoint {
    let mut bytes = line_bytes(record);
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    crate::audit::Checkpoint::parse(std::str::from_utf8(&bytes).unwrap()).unwrap()
}
