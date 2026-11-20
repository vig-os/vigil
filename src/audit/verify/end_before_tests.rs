//! Rows for `Verifier::end_before` (ADR-0005 decision 11
//! `.end_before`; ruling 13-V6-d4; #13).
//!
//! Row standard (repo-wide): every acceptance row asserts the FULL
//! sorted literal [`Finding`] list through [`assert_findings`] (a
//! thin wrapper around `assert_eq!` on `Vec<Finding>`). Regression
//! rows are labelled in their doc comments. Every digest, key and
//! trail id in an expected detail is a written-out hex constant,
//! pinned by [`fixture_hashes_match_literals`] by equality against
//! the fixture builders. Expected lists are written in the engine's
//! final sort order (`(seq.is_none(), seq, file, line, kind_debug)`),
//! so no per-row sort runs here.

use crate::audit::{
    AuditError, AuditErrorKind, Checkpoint, CheckpointFields, Entry, FindingKind as K,
    KeyFileSigner, Mmr, Record, Signer, TrustPolicy, digest_string, hex,
    runs_v4a_fixtures::{
        TRAIL, Temp, context, entry_rec, fixture_pubkey, line_bytes, pushed, put_segment,
        resume_decl, seeded, segment_path, signed_cp, write_bytes,
    },
    verify::{Finding, Verifier},
};
use std::path::PathBuf;

// =====================================================================
// Shared literal hex constants. `fixture_hashes_match_literals`
// recomputes each one from its builder and asserts equality by
// `assert_eq!`, so a change in the layout (key, chain, seq) fails
// there instead of silently drifting through many rows.
// =====================================================================

/// Hex of `runs_v4a_fixtures::TRAIL` = `[17; 16]`.
const TRAIL_HEX: &str = "11111111111111111111111111111111";
/// Fixture signing key (seed `0x27` repeated).
const FIXTURE_KEY_HEX: &str = "ee45ecb9aca01a0abd83ef56dd985c8c874e6e7f4aebcedf20bd8d88c2a0add7";
/// Public key of `KeyFileSigner::from_hex(&"42".repeat(32))`, used
/// to sign the end-record checkpoint in E11 and NOT listed on the
/// trust policy, so the verifier reports `UntrustedKey`.
const UNTRUSTED_KEY_HEX: &str = "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";
/// Record hash of `signed_cp(0, Record::genesis(&TRAIL), &Mmr::new())`.
const CP0_HONEST_DIGEST: &str =
    "blake3:fc26c6f2bb830592aaaca5413da1599489d86ac6e240a4a7a010681e0d4c8e77";
/// Record hash of `entry_rec(1, cp0.hash())` on the honest chain.
const E1_HONEST_DIGEST: &str =
    "blake3:c121282b5135adfe7a17142cae6bfc4c9040c4aed26d74bddc923b8dafcdb6e8";
/// Record hash of `signed_cp(2, e1.hash(), &fold(cp0, e1))`.
const CP2_HONEST_DIGEST: &str =
    "blake3:4164966a12a675e55eb6e133b9e50313907f164fe142d941447defcdfdb25d06";
/// Record hash of `entry_rec(2, e1.hash())`, the forged record at
/// the end `seq` in E7 (a non-checkpoint whose distinct hash drives
/// `SeqConflict`).
const FORGED_E2_DIGEST: &str =
    "blake3:8a5ea9c989aad7e89033b58ad6f59a6384af43dfe6df5bada042420c0040c306";
/// Run digest the shared classifier emits for the E10/E10b
/// A8-style archive (`S0=[cp0]`, `S1=[]`) walked with the
/// end-record segment `[cp_opening, resume]`.
const RUN_DIGEST_E10_HEX: &str = "1c02f080d9c70df74de0c13a4a30323f1b49ee624bab2c5d68fa5ee31c4400e4";
/// `Resumed` detail emitted by both step 6 (archive + live) and
/// step 7 (archive + `end_before`) in E10, with the honest cp0
/// hash substituted in.
const RESUMED_DETAIL_E10: &str = concat!(
    "operator=operator reason=incident head=0:",
    "blake3:fc26c6f2bb830592aaaca5413da1599489d86ac6e240a4a7a010681e0d4c8e77",
    " gap=none lost_records=0 structural=valid",
);

// =====================================================================
// Helpers.
// =====================================================================

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
#[track_caller]
fn assert_invalid(result: Result<Verifier, AuditError>, reason: &str, label: &str) {
    match result {
        Ok(_) => panic!("{label}: expected InvalidConfig, got Ok"),
        Err(e) => {
            assert_eq!(
                e.kind(),
                AuditErrorKind::InvalidConfig,
                "{label}: expected InvalidConfig",
            );
            let text = e.to_string();
            assert!(
                text.contains(reason),
                "{label}: expected detail to contain {reason:?}, got {text:?}",
            );
        }
    }
}

fn trust() -> TrustPolicy {
    TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .build()
        .unwrap()
}

fn verifier() -> Verifier {
    Verifier::new(trust())
}

/// Honest archived batch mirroring what the writer produces on
/// `AuditTrail::close()` for a simple run (cp0 opens, one entry at
/// seq 1, sealing cp2). The chain, signatures and MMR fields are
/// built from the same canonical bytes the real writer emits, then
/// archived by writing a sealed-pattern segment file (see
/// `put_segment`).
struct Batch {
    _dir: Temp,
    archive_dir: PathBuf,
    cp0: Record,
    e1: Record,
    cp2: Record,
    cp2_line: String,
}
fn honest_batch() -> Batch {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1], &[]);
    let cp2_line = line_without_lf(&cp2);
    Batch {
        archive_dir: d.0.clone(),
        _dir: d,
        cp0,
        e1,
        cp2,
        cp2_line,
    }
}

fn line_without_lf(record: &Record) -> String {
    let bytes = line_bytes(record);
    let text = std::str::from_utf8(&bytes).unwrap();
    text.strip_suffix('\n').unwrap().to_owned()
}

/// Builds a signed `vigil.audit.resume` record. The fixture signer
/// (seed `0x27` repeated) matches `fixture_pubkey`, so parsing a
/// resume second line stays symmetric with the writer's one.
fn resume_entry(seq: u64, previous: [u8; 32], head_seq: u64, head: [u8; 32]) -> Record {
    let details = format!(
        "head={head_seq}:{} lost_through={head_seq} file=audit.jsonl",
        digest_string(&head),
    );
    let entry = Entry::new("op", "vigil.audit.resume", "obj")
        .reason("a")
        .details(details);
    let ctx = context(seq, previous);
    Record::new_internal(ctx, entry).unwrap()
}

/// Makes a `Checkpoint` from a signed `Record` by round-tripping
/// through its line so the `Checkpoint::parse` path is exercised.
fn checkpoint_of(record: &Record) -> Checkpoint {
    let bytes = line_bytes(record);
    let text = std::str::from_utf8(&bytes).unwrap();
    Checkpoint::parse(text).unwrap()
}

/// Signs a checkpoint with the UNTRUSTED key, used by E11. The
/// writer cannot produce this (the untrusted key is deliberately
/// not listed on the policy); hand-built so the row isolates
/// `UntrustedKey` on the end-record checkpoint.
fn signed_cp_other(seq: u64, previous: [u8; 32], mmr: &Mmr) -> Record {
    let key = KeyFileSigner::from_hex(&"42".repeat(32)).unwrap();
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
    let unsigned = Record::checkpoint(context(seq, previous), fields([0; 64])).unwrap();
    let signature = key.sign(&unsigned.signing_message().unwrap()).unwrap();
    Record::checkpoint(context(seq, previous), fields(signature)).unwrap()
}

// =====================================================================
// E1 -- ACCEPTANCE. Honest batch: the archive sealed segment ends
// at e1, the archive record carries the opening checkpoint cp2 of
// the next batch, and the end anchor from the anchor store equals
// cp2. No `TrailEnded`, no `AnchorMismatch`, no `UnanchoredEnd`,
// no `UncoveredTail` (the end record's cp2 is trusted, so
// `covered_through` reaches seq 2). Base (without the end-record
// segment and with `end_before` stubbed) would carry
// `UncoveredTail` for records seq 1..=1, which the whole-list
// assertion rules out.
// =====================================================================
#[test]
fn e1_honest_batch_equal_end_anchor_emits_layout_only() {
    let fx = honest_batch();
    let anchor = checkpoint_of(&fx.cp2);
    let report = verifier()
        .end_before(&fx.cp2_line, Some(anchor))
        .unwrap()
        .verify_files(vec![fx.archive_dir.clone()])
        .unwrap();
    let expected: Vec<Finding> = Vec::new();
    assert_findings(report.findings(), &expected, "E1");
    assert_eq!(report.covered_through(), Some(2));
    assert!(report.is_valid(), "E1 is valid");
    let _ = (&fx.cp0, &fx.e1); // retained for layout clarity.
}

// =====================================================================
// E2 -- ACCEPTANCE. No end anchor given: one unlocated
// `UnanchoredEnd` at the end checkpoint's `seq` with detail exactly
// `end_before seq <e>: no end anchor`, and nothing else from
// `end_before`.
// =====================================================================
#[test]
fn e2_no_end_anchor_emits_unanchored_end() {
    let fx = honest_batch();
    let report = verifier()
        .end_before(&fx.cp2_line, None)
        .unwrap()
        .verify_files(vec![fx.archive_dir.clone()])
        .unwrap();
    let expected = vec![unlocated(
        K::UnanchoredEnd,
        Some(2),
        "end_before seq 2: no end anchor".into(),
    )];
    assert_findings(report.findings(), &expected, "E2");
    assert!(!report.is_strict_valid(), "E2 fails on UnanchoredEnd");
}

// =====================================================================
// E3a -- ACCEPTANCE. Decision 11 bullet "Step 7 takes the end from
// the anchor store": an attacker deletes batch n from a periodic
// checkpoint P onwards, so P and everything after it are gone from
// the files, and rewrites the archive record with P's line. With
// the end anchor S (here cp2 from the anchor store, which the
// attacker cannot write), the record (P = cp0) differs from S's
// line, so `AnchorMismatch "end record differs from end anchor"`
// fires at P's seq. S also joins the anchors; S points at seq 2,
// which the verified set does not hold, so the ordinary anchor
// rule emits `anchor seq 2 hash <cp2>: no record`. No file records
// at or above P's seq remain (P was cp0 and everything was cut), so
// no `TrailEnded`. Exit is 1 either way.
// =====================================================================
#[test]
fn e3a_record_replaced_with_p_line_has_anchor_mismatch_with_s() {
    let fx = honest_batch();
    let empty = Temp::new();
    let p_line = line_without_lf(&fx.cp0);
    let anchor = checkpoint_of(&fx.cp2);
    let report = verifier()
        .end_before(&p_line, Some(anchor))
        .unwrap()
        .verify_files(vec![empty.0.clone()])
        .unwrap();
    let expected = vec![
        unlocated(
            K::AnchorMismatch,
            Some(0),
            "end record differs from end anchor".into(),
        ),
        unlocated(
            K::AnchorMismatch,
            Some(2),
            format!("anchor seq 2 hash {CP2_HONEST_DIGEST}: no record"),
        ),
    ];
    assert_findings(report.findings(), &expected, "E3a");
    assert!(!report.is_valid(), "E3a exit 1");
}

// =====================================================================
// E3b -- ACCEPTANCE. Same layout as E3a but without an end anchor:
// one `UnanchoredEnd` at the record's seq. Pairs with E3a to pin
// the two bullets of decision 11 "Where the end comes from".
// =====================================================================
#[test]
fn e3b_record_replaced_with_p_line_no_anchor_is_unanchored_end() {
    let fx = honest_batch();
    let empty = Temp::new();
    let p_line = line_without_lf(&fx.cp0);
    let report = verifier()
        .end_before(&p_line, None)
        .unwrap()
        .verify_files(vec![empty.0.clone()])
        .unwrap();
    let expected = vec![unlocated(
        K::UnanchoredEnd,
        Some(0),
        "end_before seq 0: no end anchor".into(),
    )];
    assert_findings(report.findings(), &expected, "E3b");
}

// =====================================================================
// E4 -- ACCEPTANCE. The record's first line differs from the end
// anchor only by trailing whitespace (JSON accepts it, so the
// canonical hash is unchanged; `Checkpoint::parse` returns the same
// `(seq, hash)` for both). The end-anchor byte-equality rule
// (ruling 13-V6-d4 point 5: each side without its LF, whitespace
// counts) still reports `AnchorMismatch` with detail `end record
// differs from end anchor`. The ordinary anchor check sees the
// matching hash at seq 2 and does NOT emit a second finding.
// =====================================================================
#[test]
fn e4_trailing_whitespace_still_anchor_mismatch_by_byte_equality() {
    let fx = honest_batch();
    let anchor = checkpoint_of(&fx.cp2);
    let record = format!("{} ", fx.cp2_line);
    let report = verifier()
        .end_before(&record, Some(anchor))
        .unwrap()
        .verify_files(vec![fx.archive_dir.clone()])
        .unwrap();
    let expected = vec![unlocated(
        K::AnchorMismatch,
        Some(2),
        "end record differs from end anchor".into(),
    )];
    assert_findings(report.findings(), &expected, "E4");
}

// =====================================================================
// E4b -- REGRESSION. A second non-canonical variant: a leading
// space before the JSON object. JSON parses it the same way, so
// the canonical hash is unchanged; the end-anchor byte-equality
// rule (ruling 13-V6-d4 point 5) still catches the difference.
// Pairs with E4 to force byte equality to be exact at both sides.
// =====================================================================
#[test]
fn e4b_leading_whitespace_still_anchor_mismatch_by_byte_equality() {
    let fx = honest_batch();
    let anchor = checkpoint_of(&fx.cp2);
    let record = format!(" {}", fx.cp2_line);
    let report = verifier()
        .end_before(&record, Some(anchor))
        .unwrap()
        .verify_files(vec![fx.archive_dir.clone()])
        .unwrap();
    let expected = vec![unlocated(
        K::AnchorMismatch,
        Some(2),
        "end record differs from end anchor".into(),
    )];
    assert_findings(report.findings(), &expected, "E4b");
}

// =====================================================================
// E5 -- ACCEPTANCE. The files already hold a byte-identical copy
// of the end line: `TrailEnded` fires at the shipped copy's path
// and line, and `DuplicateRecord` is suppressed (ruling 13-V6-d4
// point 3). The anchor equals the record's first line so no
// `AnchorMismatch` fires.
// =====================================================================
#[test]
fn e5_byte_identical_copy_of_end_line_is_trail_ended_not_duplicate() {
    let fx = honest_batch();
    let shipped_dir = Temp::new();
    let shipped = shipped_dir.0.join("shipped.jsonl");
    write_bytes(&shipped, &line_bytes(&fx.cp2));
    let anchor = checkpoint_of(&fx.cp2);
    let report = verifier()
        .end_before(&fx.cp2_line, Some(anchor))
        .unwrap()
        .verify_files(vec![fx.archive_dir.clone(), shipped.clone()])
        .unwrap();
    let expected = vec![located(
        K::TrailEnded,
        shipped.clone(),
        1,
        2,
        "end_before seq 2: records seq 2..=2 at or above the end".into(),
    )];
    assert_findings(report.findings(), &expected, "E5");
}

// =====================================================================
// E5b -- REGRESSION. One duplicate strictly below the end (shipped
// copy of cp0 at seq 0) PLUS a record at the end seq (the archive
// still ends at cp2, so the end-record copy pairs with the archive
// copy). `DuplicateRecord` still fires at seq 0 (below the end);
// `TrailEnded` fires at seq 2 (at or above the end) and
// `DuplicateRecord` is suppressed there. The whole-list literal
// below pins the two findings together, so widening the
// suppression to cover `seq` strictly below the end fails at the
// seq-0 entry (ruling 13-V6-d4 point 3).
// =====================================================================
#[test]
fn e5b_duplicate_below_end_still_fires_at_or_above_is_suppressed() {
    let d = Temp::new();
    // Hand-built: the archive ends at cp2 inclusive, which the
    // honest writer would do with checkpoint() + close(); the extra
    // shipped copy of cp0 is what makes the fork-less duplicate
    // below the end.
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let shipped_dir = Temp::new();
    let shipped = shipped_dir.0.join("shipped.jsonl");
    write_bytes(&shipped, &line_bytes(&cp0));
    let cp2_line = line_without_lf(&cp2);
    let anchor = checkpoint_of(&cp2);
    let report = verifier()
        .end_before(&cp2_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone(), shipped])
        .unwrap();
    let archive = segment_path(&d.0, 0);
    let expected = vec![
        located(
            K::DuplicateRecord,
            archive.clone(),
            1,
            0,
            "2 copies of 1 distinct records".into(),
        ),
        located(
            K::TrailEnded,
            archive,
            3,
            2,
            "end_before seq 2: records seq 2..=2 at or above the end".into(),
        ),
    ];
    assert_findings(report.findings(), &expected, "E5b");
}

// =====================================================================
// E6 -- ACCEPTANCE. The files hold two records above the end that
// were not cut: one `TrailEnded` at the FIRST such record with the
// `a..=b` seq range.
// =====================================================================
#[test]
fn e6_files_hold_records_above_end_emits_trail_ended_range() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let e3 = entry_rec(3, cp2.hash());
    let e4 = entry_rec(4, e3.hash());
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2, &e3, &e4], &[]);
    let path = segment_path(&d.0, 0);
    let cp2_line = line_without_lf(&cp2);
    let anchor = checkpoint_of(&cp2);
    let report = verifier()
        .end_before(&cp2_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let expected = vec![
        located(
            K::TrailEnded,
            path,
            3,
            2,
            "end_before seq 2: records seq 2..=4 at or above the end".into(),
        ),
        unlocated(K::UncoveredTail, None, "records seq 3..=4".into()),
    ];
    assert_findings(report.findings(), &expected, "E6");
}

// =====================================================================
// E6b -- REGRESSION. A second layout with more than one record
// above the end, pinning that `TrailEnded` locates at the FIRST
// such record. The range differs from E6's so two rows together
// force both the FIRST-record location and the correct `a..=b`
// span (ruling 13-V6-d4 point 3).
// =====================================================================
#[test]
fn e6b_trail_ended_locates_at_first_record_above_end() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let e3 = entry_rec(3, cp2.hash());
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2, &e3], &[]);
    let path = segment_path(&d.0, 0);
    let cp2_line = line_without_lf(&cp2);
    let anchor = checkpoint_of(&cp2);
    let report = verifier()
        .end_before(&cp2_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let expected = vec![
        located(
            K::TrailEnded,
            path,
            3,
            2,
            "end_before seq 2: records seq 2..=3 at or above the end".into(),
        ),
        unlocated(K::UncoveredTail, None, "records seq 3..=3".into()),
    ];
    assert_findings(report.findings(), &expected, "E6b");
}

// =====================================================================
// E7 -- ACCEPTANCE. The files hold a DIFFERENT record at the end
// seq: `TrailEnded` plus `SeqConflict` plus the end anchor's `seq
// is forked`. The forged record at seq 2 is hand-built (a
// non-checkpoint whose distinct hash drives `SeqConflict`); the
// rest of the batch is the honest chain. Input-position ordering
// (ruling 13-V6-d4 point 3) locates `AnchorMismatch`, `SeqConflict`
// and `TrailEnded` at the archive copy, not at the end-record
// segment.
// =====================================================================
#[test]
fn e7_files_hold_different_record_at_end_seq_is_trail_ended_plus_fork() {
    let fx = honest_batch();
    let forged = entry_rec(2, fx.e1.hash());
    let d = Temp::new();
    put_segment(&d.0, 0, &[&fx.cp0, &fx.e1, &forged], &[]);
    let anchor = checkpoint_of(&fx.cp2);
    let report = verifier()
        .end_before(&fx.cp2_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let path = segment_path(&d.0, 0);
    // `candidates` is `BTreeMap<hash, _>::iter`, ascending by hash
    // bytes. 0x41... (cp2 from the end record) sorts before 0x8a...
    // (the forged record) -- pinned by `fixture_hashes_match_literals`.
    let expected = vec![
        located(
            K::AnchorMismatch,
            path.clone(),
            3,
            2,
            format!("anchor seq 2 hash {CP2_HONEST_DIGEST}: seq is forked"),
        ),
        located(
            K::SeqConflict,
            path.clone(),
            3,
            2,
            format!("conflicting hashes: {CP2_HONEST_DIGEST}, {FORGED_E2_DIGEST}"),
        ),
        located(
            K::TrailEnded,
            path,
            3,
            2,
            "end_before seq 2: records seq 2..=2 at or above the end".into(),
        ),
    ];
    assert_findings(report.findings(), &expected, "E7");
}

// =====================================================================
// E8 -- REGRESSION (parse-only). Each row below drives one line
// of ruling 13-V6-d4 point 4 ("anything else is `InvalidConfig`
// and names the reason"). Each check has two rows with distinct
// inputs so removing that check fails on two independent inputs
// at runtime. `assert_invalid` matches the full `InvalidConfig`
// message against a stable reason substring that names the check.
// =====================================================================

/// A record payload whose first line is an ordinary entry rather
/// than a checkpoint; shared by E8d/E8d2.
fn non_checkpoint_line(fx: &Batch) -> String {
    line_without_lf(&fx.e1)
}

#[test]
fn e8a_empty_record_rejected() {
    assert_invalid(verifier().end_before("", None), "empty", "E8a empty");
}
#[test]
fn e8a2_lone_lf_rejected() {
    // Distinct from E8a: a single LF strips to an empty remainder,
    // which the parser must reject with the same reason.
    assert_invalid(verifier().end_before("\n", None), "empty", "E8a2 lone LF");
}
#[test]
fn e8b_three_lines_after_valid_resume_rejected() {
    let fx = honest_batch();
    let resume = resume_entry(
        fx.cp2.context.seq + 1,
        fx.cp2.hash(),
        fx.cp2.context.seq,
        fx.cp2.hash(),
    );
    let three = format!("{}\n{}\nextra", fx.cp2_line, line_without_lf(&resume));
    assert_invalid(
        verifier().end_before(&three, None),
        "more than two lines",
        "E8b three lines",
    );
}
#[test]
fn e8b2_three_lines_with_cp2_tail_rejected() {
    let fx = honest_batch();
    let resume = resume_entry(
        fx.cp2.context.seq + 1,
        fx.cp2.hash(),
        fx.cp2.context.seq,
        fx.cp2.hash(),
    );
    // Distinct third-line payload keeps the three-line body
    // independent of E8b's `extra` literal.
    let three = format!(
        "{}\n{}\n{}",
        fx.cp2_line,
        line_without_lf(&resume),
        fx.cp2_line,
    );
    assert_invalid(
        verifier().end_before(&three, None),
        "more than two lines",
        "E8b2 three lines twin",
    );
}
#[test]
fn e8c_trailing_cr_rejected() {
    let fx = honest_batch();
    let cr = format!("{}\r", fx.cp2_line);
    assert_invalid(verifier().end_before(&cr, None), "CR", "E8c trailing CR");
}
#[test]
fn e8c2_cr_lf_pair_rejected() {
    let fx = honest_batch();
    // A bare CR followed by LF (a line ending the end-record rule
    // does not accept): a distinct input that still trips the CR
    // check.
    let cr = format!("{}\r\n", fx.cp2_line);
    assert_invalid(verifier().end_before(&cr, None), "CR", "E8c2 CRLF");
}
#[test]
fn e8d_non_checkpoint_first_line_rejected() {
    let fx = honest_batch();
    assert_invalid(
        verifier().end_before(&non_checkpoint_line(&fx), None),
        "first line is not a checkpoint",
        "E8d non-cp",
    );
}
#[test]
fn e8d2_non_checkpoint_first_line_with_second_rejected() {
    let fx = honest_batch();
    // Even with a syntactically valid second line, the first-line
    // check still fires: a non-checkpoint first line is the reason.
    let first = non_checkpoint_line(&fx);
    let body = format!("{first}\nanything");
    assert_invalid(
        verifier().end_before(&body, None),
        "first line is not a checkpoint",
        "E8d2 non-cp with 2nd",
    );
}
#[test]
fn e8e_second_line_not_a_record_rejected() {
    let fx = honest_batch();
    let both = format!("{}\nnot-a-record", fx.cp2_line);
    assert_invalid(
        verifier().end_before(&both, None),
        "second line is not a resume",
        "E8e non-record second",
    );
}
#[test]
fn e8e2_second_line_entry_not_resume_rejected() {
    let fx = honest_batch();
    let line2 = line_without_lf(&fx.e1);
    let both = format!("{}\n{line2}", fx.cp2_line);
    assert_invalid(
        verifier().end_before(&both, None),
        "second line is not a resume",
        "E8e2 entry second",
    );
}
#[test]
fn e8f_resume_line_with_wrong_seq_rejected() {
    let fx = honest_batch();
    let wrong = resume_entry(
        fx.cp2.context.seq + 2,
        fx.cp2.hash(),
        fx.cp2.context.seq,
        fx.cp2.hash(),
    );
    let both = format!("{}\n{}", fx.cp2_line, line_without_lf(&wrong));
    assert_invalid(
        verifier().end_before(&both, None),
        "resume line seq is not cp.seq + 1",
        "E8f wrong resume seq",
    );
}
#[test]
fn e8f2_resume_line_with_zero_seq_rejected() {
    let fx = honest_batch();
    let wrong = resume_entry(0, fx.cp2.hash(), fx.cp2.context.seq, fx.cp2.hash());
    let both = format!("{}\n{}", fx.cp2_line, line_without_lf(&wrong));
    assert_invalid(
        verifier().end_before(&both, None),
        "resume line seq is not cp.seq + 1",
        "E8f2 zero resume seq",
    );
}
#[test]
fn e8g_resume_line_with_wrong_prev_hash_rejected() {
    let fx = honest_batch();
    let wrong = resume_entry(
        fx.cp2.context.seq + 1,
        [0; 32],
        fx.cp2.context.seq,
        fx.cp2.hash(),
    );
    let both = format!("{}\n{}", fx.cp2_line, line_without_lf(&wrong));
    assert_invalid(
        verifier().end_before(&both, None),
        "resume line prev_hash does not equal cp.hash",
        "E8g wrong resume prev",
    );
}
#[test]
fn e8g2_resume_line_prev_hash_e1_rejected() {
    let fx = honest_batch();
    let wrong = resume_entry(
        fx.cp2.context.seq + 1,
        fx.e1.hash(),
        fx.cp2.context.seq,
        fx.cp2.hash(),
    );
    let both = format!("{}\n{}", fx.cp2_line, line_without_lf(&wrong));
    assert_invalid(
        verifier().end_before(&both, None),
        "resume line prev_hash does not equal cp.hash",
        "E8g2 prev as e1",
    );
}
#[test]
fn e8h_trailing_lf_accepted() {
    let fx = honest_batch();
    let with_lf = format!("{}\n", fx.cp2_line);
    assert!(
        verifier().end_before(&with_lf, None).is_ok(),
        "E8h trailing LF"
    );
}
#[test]
fn e8i_valid_resume_accepted() {
    let fx = honest_batch();
    let ok = resume_entry(
        fx.cp2.context.seq + 1,
        fx.cp2.hash(),
        fx.cp2.context.seq,
        fx.cp2.hash(),
    );
    let both = format!("{}\n{}", fx.cp2_line, line_without_lf(&ok));
    assert!(
        verifier().end_before(&both, None).is_ok(),
        "E8i valid resume"
    );
}

// =====================================================================
// E9 -- REGRESSION. The conflict between `max_age` and
// `end_before` in both call orders (ruling 13-V6-d4 point 7): each
// is `InvalidConfig` from whichever call comes second. `end_before`
// called twice keeps the second call's record and anchor.
// =====================================================================
#[test]
fn e9a_max_age_then_end_before_errors() {
    let fx = honest_batch();
    let v = verifier().max_age(std::time::Duration::ZERO).unwrap();
    assert_invalid(
        v.end_before(&fx.cp2_line, None),
        "end_before conflicts with max_age",
        "E9a max_age then end_before",
    );
}
#[test]
fn e9b_end_before_then_max_age_errors() {
    let fx = honest_batch();
    let v = verifier().end_before(&fx.cp2_line, None).unwrap();
    match v.max_age(std::time::Duration::ZERO) {
        Ok(_) => panic!("E9b: expected InvalidConfig, got Ok"),
        Err(e) => {
            assert_eq!(e.kind(), AuditErrorKind::InvalidConfig);
            assert!(
                e.to_string().contains("max_age conflicts with end_before"),
                "E9b: {}",
                e,
            );
        }
    }
}
#[test]
fn e9c_end_before_twice_keeps_second() {
    let fx = honest_batch();
    let anchor = checkpoint_of(&fx.cp2);
    let report = verifier()
        .end_before(&line_without_lf(&fx.cp0), None)
        .unwrap()
        .end_before(&fx.cp2_line, Some(anchor))
        .unwrap()
        .verify_files(vec![fx.archive_dir.clone()])
        .unwrap();
    let expected: Vec<Finding> = Vec::new();
    assert_findings(report.findings(), &expected, "E9c second wins");
}

/// Decodes a 64-char lowercase-hex blake3 digest into the raw bytes
/// that [`Finding::with_run_digest`] takes, so expected lists stay
/// literal in hex and the decoder is an in-test helper (not a
/// compile-time macro).
fn digest_bytes_from_hex(h: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

// =====================================================================
// E10 -- ACCEPTANCE. Decision 2 l.956 "run digest equality": step 6
// (archive + live) and step 7 (archive + `end_before`) each
// produce a `SegmentStructure` run finding whose digest is equal.
// Both whole lists are asserted below; their only difference is
// where the shared classifier's `Resumed` finding lands (step 6
// pins it to the live segment, step 7 strips its location per
// ruling 13-V6-d4 point 6). The run digest, `UncoveredTail` and
// the empty-S1 `SegmentStructure` are identical.
// =====================================================================
#[test]
fn e10_step6_and_step7_report_the_same_findings() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let fold = seeded(&cp0);
    let cp_opening = signed_cp(1, cp0.hash(), &fold);
    let resume = resume_decl(&cp_opening, 0, cp0.hash(), 0);
    let run_digest = digest_bytes_from_hex(RUN_DIGEST_E10_HEX);

    // Step 6: archive = [S0=[cp0], S1=[]] + live = [cp_opening, resume].
    let d6 = Temp::new();
    put_segment(&d6.0, 0, &[&cp0], &[]);
    put_segment(&d6.0, 1, &[], &[]);
    let live6 = d6.0.join("audit.jsonl");
    write_bytes(
        &live6,
        &[&line_bytes(&cp_opening)[..], &line_bytes(&resume)[..]].concat(),
    );
    let report6 = verifier().verify_files(vec![d6.0.clone()]).unwrap();

    // Step 7: same archive + `end_before(cp_opening + resume)`.
    let d7 = Temp::new();
    put_segment(&d7.0, 0, &[&cp0], &[]);
    put_segment(&d7.0, 1, &[], &[]);
    let record = format!(
        "{}\n{}",
        line_without_lf(&cp_opening),
        line_without_lf(&resume),
    );
    let anchor = checkpoint_of(&cp_opening);
    let report7 = verifier()
        .end_before(&record, Some(anchor))
        .unwrap()
        .verify_files(vec![d7.0.clone()])
        .unwrap();

    let s1_6 = segment_path(&d6.0, 1);
    let expected6 = vec![
        located(K::Resumed, live6, 2, 2, RESUMED_DETAIL_E10.into()),
        unlocated(K::UncoveredTail, None, "records seq 2..=2".into()),
        Finding::new(
            K::SegmentStructure,
            Some(s1_6.clone()),
            None,
            None,
            "expected first complete record to be a checkpoint".into(),
        ),
        Finding::new(
            K::SegmentStructure,
            Some(s1_6),
            None,
            None,
            format!("digest blake3:{RUN_DIGEST_E10_HEX}"),
        )
        .with_run_digest(run_digest),
    ];
    assert_findings(report6.findings(), &expected6, "E10 step 6");

    let s1_7 = segment_path(&d7.0, 1);
    let expected7 = vec![
        unlocated(K::Resumed, Some(2), RESUMED_DETAIL_E10.into()),
        unlocated(K::UncoveredTail, None, "records seq 2..=2".into()),
        Finding::new(
            K::SegmentStructure,
            Some(s1_7.clone()),
            None,
            None,
            "expected first complete record to be a checkpoint".into(),
        ),
        Finding::new(
            K::SegmentStructure,
            Some(s1_7),
            None,
            None,
            format!("digest blake3:{RUN_DIGEST_E10_HEX}"),
        )
        .with_run_digest(run_digest),
    ];
    assert_findings(report7.findings(), &expected7, "E10 step 7");

    // Both whole lists already pin their run findings to the same
    // literal digest; this `assert_eq!` ties them together so a
    // change that drifted the two digests apart still fails
    // here, not only inside either expected list.
    let run6 = report6
        .findings()
        .iter()
        .find(|f| f.run_digest().is_some())
        .expect("E10 step 6 has a run finding");
    let run7 = report7
        .findings()
        .iter()
        .find(|f| f.run_digest().is_some())
        .expect("E10 step 7 has a run finding");
    assert_eq!(run6.run_digest(), run7.run_digest(), "E10 run digest");
}

// =====================================================================
// E10b -- ACCEPTANCE. On the same A8-style archive the end-record
// path contributes a `SegmentStructure` run finding (ruling
// 13-V6-d4 point 1). An end record merged by `seq` only would
// emit no run finding and the whole list below would shrink.
// First-failing line on base is the `assert_findings` below (base
// stubs out `end_before` so the classifier does not see the
// end-record bytes).
// =====================================================================
#[test]
fn e10b_end_record_produces_a_segment_structure_run_finding() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let fold = seeded(&cp0);
    let cp_opening = signed_cp(1, cp0.hash(), &fold);
    let resume = resume_decl(&cp_opening, 0, cp0.hash(), 0);
    let run_digest = digest_bytes_from_hex(RUN_DIGEST_E10_HEX);
    let d = Temp::new();
    put_segment(&d.0, 0, &[&cp0], &[]);
    put_segment(&d.0, 1, &[], &[]);
    let record = format!(
        "{}\n{}",
        line_without_lf(&cp_opening),
        line_without_lf(&resume),
    );
    let anchor = checkpoint_of(&cp_opening);
    let report = verifier()
        .end_before(&record, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let s1 = segment_path(&d.0, 1);
    let expected = vec![
        unlocated(K::Resumed, Some(2), RESUMED_DETAIL_E10.into()),
        unlocated(K::UncoveredTail, None, "records seq 2..=2".into()),
        Finding::new(
            K::SegmentStructure,
            Some(s1.clone()),
            None,
            None,
            "expected first complete record to be a checkpoint".into(),
        ),
        Finding::new(
            K::SegmentStructure,
            Some(s1),
            None,
            None,
            format!("digest blake3:{RUN_DIGEST_E10_HEX}"),
        )
        .with_run_digest(run_digest),
    ];
    assert_findings(report.findings(), &expected, "E10b");
}

// =====================================================================
// E11 -- ACCEPTANCE. The end checkpoint is signed by an untrusted
// key: `UntrustedKey` fires on it, with no file and no line (ruling
// 13-V6-d4 point 6). The forged key is listed in a scenario
// comment because the real writer cannot produce a checkpoint with
// a key the policy does not trust.
// =====================================================================
#[test]
fn e11_untrusted_end_checkpoint_has_untrusted_key_without_location() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    put_segment(&d.0, 0, &[&cp0, &e1], &[]);
    let cp2 = signed_cp_other(2, e1.hash(), &mmr1);
    let cp2_line = line_without_lf(&cp2);
    let anchor = checkpoint_of(&cp2);
    let report = verifier()
        .end_before(&cp2_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let expected = vec![
        unlocated(
            K::UntrustedKey,
            Some(2),
            format!("key {UNTRUSTED_KEY_HEX} not listed for trail {TRAIL_HEX}"),
        ),
        unlocated(K::UncoveredTail, None, "records seq 1..=2".into()),
    ];
    assert_findings(report.findings(), &expected, "E11");
}

// =====================================================================
// REGRESSION. Fixture-hash pins: recompute the hashes the rows
// assert literally and compare with the layout builders by
// equality. A change in the fixture (seq, chain, key) fails here
// instead of drifting through many rows.
// =====================================================================
#[test]
fn fixture_hashes_match_literals() {
    let fx = honest_batch();
    assert_eq!(hex(&TRAIL), TRAIL_HEX);
    assert_eq!(hex(&fixture_pubkey()), FIXTURE_KEY_HEX);
    let untrusted = KeyFileSigner::from_hex(&"42".repeat(32)).unwrap();
    assert_eq!(hex(&untrusted.public_key()), UNTRUSTED_KEY_HEX);
    assert_eq!(digest_string(&fx.cp0.hash()), CP0_HONEST_DIGEST);
    assert_eq!(digest_string(&fx.e1.hash()), E1_HONEST_DIGEST);
    assert_eq!(digest_string(&fx.cp2.hash()), CP2_HONEST_DIGEST);
    let forged = entry_rec(2, fx.e1.hash());
    assert_eq!(digest_string(&forged.hash()), FORGED_E2_DIGEST);
    // The cp2 line's parse round-trips to the same hash so
    // `Checkpoint::parse` applied to the stored line of an honest
    // writer produces a checkpoint equal to the one the fixture
    // builder returned.
    let parsed = Checkpoint::parse(&fx.cp2_line).unwrap();
    assert_eq!(parsed.hash(), fx.cp2.hash());
}
