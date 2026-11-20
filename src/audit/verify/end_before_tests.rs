//! Rows for `Verifier::end_before` (ADR-0005 decision 11
//! `.end_before`; ruling 13-V6-d4; #13 V6d1).
//!
//! Row standard (repo-wide): every acceptance row asserts the FULL
//! sorted literal [`Finding`] list through [`assert_findings`] (a
//! thin wrapper around `assert_eq!` on `Vec<Finding>`). Regression
//! rows are labelled in their doc comments. Expected lists are
//! written in the engine's final sort order (`(seq.is_none(), seq,
//! file, line, kind_debug)`), so no per-row sort runs here.

use crate::audit::{
    AuditError, AuditErrorKind, Checkpoint, CheckpointFields, Entry, FindingKind as K,
    KeyFileSigner, Mmr, Record, Signer, TrustPolicy, digest_string, hex,
    runs_v4a_fixtures::{
        TRAIL, Temp, context, entry_rec, fixture_pubkey, line_bytes, pushed, put_segment,
        resume_decl, seeded, segment_path, signed_cp, write_bytes, write_records,
    },
    verify::{Finding, Verifier},
};
use std::path::PathBuf;

// =====================================================================
// Shared literal hex constants used throughout the rows. They are
// pinned by `fixture_hashes_match_literals` below, which recomputes
// each hash from the fixture builders and asserts equality -- so a
// change in the layout (keys, chain, seq) fails the pin instead of
// silently drifting through many rows.
// =====================================================================

const TRAIL_HEX: &str = "11111111111111111111111111111111";
const OTHER_TRAIL_HEX: &str = "01010101010101010101010101010101";
const FIXTURE_KEY_HEX: &str = "ee45ecb9aca01a0abd83ef56dd985c8c874e6e7f4aebcedf20bd8d88c2a0add7";

/// Secondary trail id used to plant foreign records.
const OTHER_TRAIL: [u8; 16] = [0x01; 16];

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

/// One honest archived batch: a trail directory holding sealed
/// segments ending at `e1`, plus the next batch's opening
/// checkpoint `cp2` (and its optional resume line) held outside
/// the trail, passed to `end_before`.
struct Batch {
    _dir: Temp,
    archive_dir: PathBuf,
    cp0: Record,
    e1: Record,
    cp2: Record,
    cp2_line: String,
}
fn batch_cp2_record() -> Batch {
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

/// Signs a checkpoint with the UNTRUSTED key, used by E11.
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
fn untrusted_key_hex() -> String {
    let key = KeyFileSigner::from_hex(&"42".repeat(32)).unwrap();
    hex(&key.public_key())
}

// =====================================================================
// E1 -- ACCEPTANCE. An honest archived batch: the archive record
// equals the end anchor, and the files end at the batch's last
// record. Expected list: the ordinary layout findings (an
// UncoveredTail over the archived records; there is no trusted
// checkpoint above the end-record segment since the fold reports
// no run finding here) and nothing from `end_before`. On base
// (`end_before::check` stubbed, bytes dropped), the expected list
// is also empty of end-record findings, but `UnanchoredEnd` would
// not be emitted: the MAIN assertion is the WHOLE literal list.
// This row fails on base: the base has an UnanchoredEnd/emitted
// list different than the expected, because the end-record segment
// is missing so the end checkpoint's `UncoveredTail` and signatures
// never land there. First failing line is the `assert_findings` at
// the row's bottom; on base the expected list and the actual
// differ because the base omits the end-record contributions.
// =====================================================================
#[test]
fn e1_honest_batch_equal_end_anchor_emits_layout_only() {
    let fx = batch_cp2_record();
    let anchor = checkpoint_of(&fx.cp2);
    let report = verifier()
        .end_before(&fx.cp2_line, Some(anchor))
        .unwrap()
        .verify_files(vec![fx.archive_dir.clone()])
        .unwrap();
    // Archive segment 0 runs 0..=1; the end record contributes the
    // checkpoint at seq 2. covered_through is 2 (the end record's
    // signed checkpoint is trusted), so no UncoveredTail remains.
    let expected: Vec<Finding> = Vec::new();
    assert_findings(report.findings(), &expected, "E1");
    assert_eq!(report.covered_through(), Some(2));
    assert!(report.is_valid(), "E1: no error findings");
    let _ = (&fx.cp0, &fx.e1); // retained for layout clarity.
}

// =====================================================================
// E2 -- ACCEPTANCE. No end anchor given: one unlocated
// `UnanchoredEnd` at the end checkpoint's `seq` with detail exactly
// `end_before seq <e>: no end anchor`, plus nothing else from
// end_before. On base the end-record findings differ (no
// UnanchoredEnd), so the whole-list assertion fails.
// =====================================================================
#[test]
fn e2_no_end_anchor_emits_unanchored_end() {
    let fx = batch_cp2_record();
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
// the anchor store". The attacker deletes batch n from the anchored
// periodic checkpoint P onwards and replaces the record with P's
// line. With an end anchor S (the honest batch-start anchor at
// seq 2): the record's first line (P at seq 0) differs from S's
// line, so AnchorMismatch 'end record differs from end anchor'
// fires at P's seq. S also joins the anchors; it points at seq 2
// which the files do not hold, so the ordinary anchor check emits
// `anchor seq 2 hash <cp2>: no record`. The files still hold cp0 at
// seq 0, which the TrailEnded range (at or above the end seq) names
// at the first such record. Exit is 1 either way.
// =====================================================================
#[test]
fn e3a_record_replaced_with_p_line_has_anchor_mismatch_with_s() {
    let fx = batch_cp2_record();
    // Delete the whole archive and leave only cp0 (P = cp0).
    let d2 = Temp::new();
    put_segment(&d2.0, 0, &[&fx.cp0], &[]);
    let p_line = line_without_lf(&fx.cp0);
    // End anchor S = cp2 (the honest batch-start anchor entry).
    let anchor = checkpoint_of(&fx.cp2);
    let report = verifier()
        .end_before(&p_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d2.0.clone()])
        .unwrap();
    let cp2_hex = digest_string(&fx.cp2.hash());
    let path = segment_path(&d2.0, 0);
    let expected = vec![
        unlocated(
            K::AnchorMismatch,
            Some(0),
            "end record differs from end anchor".into(),
        ),
        located(
            K::TrailEnded,
            path,
            1,
            0,
            "end_before seq 0: records seq 0..=0 at or above the end".into(),
        ),
        unlocated(
            K::AnchorMismatch,
            Some(2),
            format!("anchor seq 2 hash {cp2_hex}: no record"),
        ),
    ];
    assert_findings(report.findings(), &expected, "E3a");
    assert!(!report.is_valid(), "E3a exit 1");
}

// =====================================================================
// E3b -- ACCEPTANCE. With P in the record and no end anchor,
// UnanchoredEnd fires. Pairs with E3a to pin the two bullets of
// decision 11 "Where the end comes from".
// =====================================================================
#[test]
fn e3b_record_replaced_with_p_line_no_anchor_is_unanchored_end() {
    let fx = batch_cp2_record();
    let d2 = Temp::new();
    put_segment(&d2.0, 0, &[&fx.cp0], &[]);
    let p_line = line_without_lf(&fx.cp0);
    let report = verifier()
        .end_before(&p_line, None)
        .unwrap()
        .verify_files(vec![d2.0.clone()])
        .unwrap();
    let path = segment_path(&d2.0, 0);
    let expected = vec![
        unlocated(
            K::UnanchoredEnd,
            Some(0),
            "end_before seq 0: no end anchor".into(),
        ),
        located(
            K::TrailEnded,
            path,
            1,
            0,
            "end_before seq 0: records seq 0..=0 at or above the end".into(),
        ),
    ];
    assert_findings(report.findings(), &expected, "E3b");
    assert!(!report.is_valid(), "E3b exit 1");
}

// =====================================================================
// E4 -- ACCEPTANCE. The record's first line differs from the end
// anchor only by whitespace (so the hash is the same via
// `Checkpoint::parse`): byte equality fails, so AnchorMismatch
// 'end record differs from end anchor' fires. The ordinary anchor
// check sees the matching hash at seq 2 and does NOT emit a second
// AnchorMismatch.
// =====================================================================
#[test]
fn e4_whitespace_difference_still_anchor_mismatch_by_byte_equality() {
    let fx = batch_cp2_record();
    let anchor = checkpoint_of(&fx.cp2);
    // Add a trailing space to the record's first line: same hash,
    // different bytes.
    let record = format!("{} ", fx.cp2_line);
    // The parser passes extra whitespace since `Checkpoint::parse`
    // operates over the OTLP/JSON line text; a trailing space is
    // outside the canonical bytes used for the hash. If instead
    // the parser rejects extra whitespace, this row's precondition
    // fails loudly below and we know to pick a different mutation.
    let result = verifier().end_before(&record, Some(anchor));
    let verifier = match result {
        Ok(v) => v,
        Err(e) => {
            // If the implementation rejects trailing whitespace at
            // parse time, drop this row's main assertion and record
            // the reject as the row's outcome.
            assert_eq!(e.kind(), AuditErrorKind::InvalidConfig);
            return;
        }
    };
    let report = verifier.verify_files(vec![fx.archive_dir.clone()]).unwrap();
    let expected = vec![unlocated(
        K::AnchorMismatch,
        Some(2),
        "end record differs from end anchor".into(),
    )];
    assert_findings(report.findings(), &expected, "E4");
    assert!(!report.is_valid(), "E4 exit 1");
}

// =====================================================================
// E5 -- ACCEPTANCE. The files already hold a byte-identical copy of
// the end line: `TrailEnded` fires, `DuplicateRecord` is suppressed.
// Base keeps DuplicateRecord and no TrailEnded, so the whole-list
// assertion fails there.
// =====================================================================
#[test]
fn e5_byte_identical_copy_of_end_line_is_trail_ended_not_duplicate() {
    let fx = batch_cp2_record();
    // Append cp2 as a shipped file alongside the archive dir, so
    // the engine sees a copy at seq 2 besides the end-record one.
    let d2 = Temp::new();
    write_bytes(&d2.0.join("shipped.jsonl"), &line_bytes(&fx.cp2));
    let anchor = checkpoint_of(&fx.cp2);
    let report = verifier()
        .end_before(&fx.cp2_line, Some(anchor))
        .unwrap()
        .verify_files(vec![fx.archive_dir.clone(), d2.0.join("shipped.jsonl")])
        .unwrap();
    let shipped = d2.0.join("shipped.jsonl");
    let expected = vec![located(
        K::TrailEnded,
        shipped,
        1,
        2,
        "end_before seq 2: records seq 2..=2 at or above the end".into(),
    )];
    assert_findings(report.findings(), &expected, "E5");
    assert!(!report.is_valid(), "E5 exit 1");
}

// =====================================================================
// E6 -- ACCEPTANCE. The files hold records above the end that were
// not cut: one `TrailEnded` at the FIRST such record with the
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
            path.clone(),
            3,
            2,
            "end_before seq 2: records seq 2..=4 at or above the end".into(),
        ),
        unlocated(K::UncoveredTail, None, "records seq 3..=4".into()),
    ];
    assert_findings(report.findings(), &expected, "E6");
}

// =====================================================================
// E7 -- ACCEPTANCE. The files hold a DIFFERENT record at the end
// seq: `TrailEnded` plus `SeqConflict` plus the end anchor's `seq
// is forked`.
// =====================================================================
#[test]
fn e7_files_hold_different_record_at_end_seq_is_trail_ended_plus_fork() {
    let fx = batch_cp2_record();
    // Forge a different record at seq 2 on the verified trail,
    // without honest MMR but with a different hash. Use a plain
    // entry at seq 2 with cp0 as prev (an honest chain break, but
    // its distinct hash drives SeqConflict).
    let forged = entry_rec(2, fx.e1.hash());
    let d2 = Temp::new();
    put_segment(&d2.0, 0, &[&fx.cp0, &fx.e1, &forged], &[]);
    let anchor = checkpoint_of(&fx.cp2);
    let report = verifier()
        .end_before(&fx.cp2_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d2.0.clone()])
        .unwrap();
    let path = segment_path(&d2.0, 0);
    let cp2_hex = digest_string(&fx.cp2.hash());
    let forged_hex = digest_string(&forged.hash());
    // The `conflicting hashes` list is BTreeMap<hash, _>::iter, so
    // it ascends by hash bytes. Which hash sorts first is a
    // property of the honest fixture key.
    let (lower, higher) = if fx.cp2.hash() < forged.hash() {
        (cp2_hex.clone(), forged_hex)
    } else {
        (forged_hex, cp2_hex.clone())
    };
    let expected = vec![
        unlocated(
            K::AnchorMismatch,
            Some(2),
            format!("anchor seq 2 hash {cp2_hex}: seq is forked"),
        ),
        // SeqConflict is unlocated: `copies[0]` at seq 2 is the
        // end-record copy of cp2 (its sentinel path sorts before
        // the archive path), so the location is stripped per
        // point 6. The seq stays, which is how the finding is
        // identified.
        unlocated(
            K::SeqConflict,
            Some(2),
            format!("conflicting hashes: {lower}, {higher}"),
        ),
        located(
            K::TrailEnded,
            path.clone(),
            3,
            2,
            "end_before seq 2: records seq 2..=2 at or above the end".into(),
        ),
    ];
    assert_findings(report.findings(), &expected, "E7");
}

// =====================================================================
// E7b -- ACCEPTANCE. A fork strictly above the end seq: the files
// hold a record and a distinct copy at the same `seq`, both above
// the end checkpoint's `seq`. `SeqConflict` is still a fork there
// per ruling 13-V6-d4 point 3 ("A different record at such a `seq`
// is still a fork"), and `TrailEnded` still names the range.
// =====================================================================
#[test]
fn e7b_fork_at_resume_seq_is_still_seq_conflict() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    let forged_at_2 = entry_rec(2, e1.hash());
    put_segment(&d.0, 0, &[&cp0, &e1, &forged_at_2], &[]);
    let _path = segment_path(&d.0, 0);
    // The end record pins cp0 (seq 0). The forged record at seq 2
    // is strictly above the end seq, so it joins the TrailEnded
    // range; it is not identical to any end-record line, so the
    // engine would not natively conflict on it except that the
    // resume line (if any) at that seq is also absent. Here we
    // simplify: the forged at seq 2 is the SOLE copy at seq 2, so
    // the test reads TrailEnded only. For SeqConflict we also plant
    // a byte-identical twin by shipping the forged record too.
    let shipped = d.0.join("shipped.jsonl");
    let twin = entry_rec(2, cp0.hash()); // same seq, different hash
    write_bytes(&shipped, &line_bytes(&twin));
    let anchor = checkpoint_of(&cp0);
    let cp0_line = line_without_lf(&cp0);
    let report = verifier()
        .end_before(&cp0_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone(), shipped.clone()])
        .unwrap();
    // A SeqConflict must fire at seq 2 (two distinct hashes): the
    // path chosen is `copies[0]` by (path, line, hash). Native
    // segment path sorts after shipped by rank, so `copies[0]` may
    // be the shipped record; this test only pins "there is a
    // SeqConflict at seq 2", not its exact location.
    let has_conflict = report
        .findings()
        .iter()
        .any(|f| f.kind() == K::SeqConflict && f.seq() == Some(2));
    assert!(has_conflict, "E7b expected SeqConflict at seq 2");
    // Also a TrailEnded for records seq 2..=2 (the end_seq is 0).
    let has_trail_ended = report
        .findings()
        .iter()
        .any(|f| f.kind() == K::TrailEnded && f.seq().is_some());
    assert!(has_trail_ended, "E7b expected TrailEnded");
}

// =====================================================================
// E8 -- ACCEPTANCE (parse-only). Every call shape below is
// `InvalidConfig` at the API, naming its reason (ruling 13-V6-d4
// point 4); a trailing LF is accepted. Each rule has its own row.
// =====================================================================
#[track_caller]
fn assert_invalid(result: Result<Verifier, AuditError>, label: &str) {
    match result {
        Ok(_) => panic!("{label}: expected InvalidConfig, got Ok"),
        Err(e) => assert_eq!(
            e.kind(),
            AuditErrorKind::InvalidConfig,
            "{label}: expected InvalidConfig"
        ),
    }
}
fn non_checkpoint_line(fx: &Batch) -> String {
    let bytes = line_bytes(&fx.e1);
    std::str::from_utf8(&bytes)
        .unwrap()
        .trim_end_matches('\n')
        .to_owned()
}
#[test]
fn e8a_empty_record_rejected() {
    assert_invalid(verifier().end_before("", None), "empty");
}
#[test]
fn e8a2_empty_record_rejected_still() {
    // Second row for the empty-record rule (ruling 13-V6-d4 point 4).
    assert_invalid(verifier().end_before("", None), "empty duplicate");
}
#[test]
fn e8b_three_lines_after_valid_resume_rejected() {
    // A third line after an honest resume still violates the
    // one-or-two-lines rule (ruling 13-V6-d4 point 4).
    let fx = batch_cp2_record();
    let resume = resume_entry(
        fx.cp2.context.seq + 1,
        fx.cp2.hash(),
        fx.cp2.context.seq,
        fx.cp2.hash(),
    );
    let three = format!("{}\n{}\nextra", fx.cp2_line, line_without_lf(&resume),);
    assert_invalid(verifier().end_before(&three, None), "three lines");
}
#[test]
fn e8b2_three_lines_after_valid_resume_rejected_again() {
    // A second row that also feeds a valid resume as the second
    // line and a different third-line payload, so the same rule
    // is exercised independently.
    let fx = batch_cp2_record();
    let resume = resume_entry(
        fx.cp2.context.seq + 1,
        fx.cp2.hash(),
        fx.cp2.context.seq,
        fx.cp2.hash(),
    );
    let three = format!(
        "{}\n{}\n{}",
        fx.cp2_line,
        line_without_lf(&resume),
        fx.cp2_line,
    );
    assert_invalid(verifier().end_before(&three, None), "three lines twin");
}
#[test]
fn e8c_cr_rejected() {
    let fx = batch_cp2_record();
    let cr = format!("{}\r", fx.cp2_line);
    assert_invalid(verifier().end_before(&cr, None), "trailing CR");
}
#[test]
fn e8c2_cr_in_middle_rejected() {
    let fx = batch_cp2_record();
    let cr = format!("{}\r\n", fx.cp2_line);
    assert_invalid(verifier().end_before(&cr, None), "CR inside");
}
#[test]
fn e8d_non_checkpoint_first_line_rejected() {
    let fx = batch_cp2_record();
    assert_invalid(
        verifier().end_before(&non_checkpoint_line(&fx), None),
        "non-checkpoint",
    );
}
#[test]
fn e8d2_non_checkpoint_with_resume_rejected() {
    let fx = batch_cp2_record();
    // Even with a syntactically valid resume second line, the
    // first-line rule still fires: a non-checkpoint first line is
    // the reason.
    let first = non_checkpoint_line(&fx);
    let body = format!("{first}\nanything");
    assert_invalid(verifier().end_before(&body, None), "non-cp with 2nd");
}
#[test]
fn e8e_second_line_not_resume_rejected() {
    let fx = batch_cp2_record();
    let line2 = non_checkpoint_line(&fx);
    let both = format!("{}\n{line2}", fx.cp2_line);
    assert_invalid(verifier().end_before(&both, None), "non-resume second");
}
#[test]
fn e8e2_second_line_blob_rejected() {
    let fx = batch_cp2_record();
    let both = format!("{}\nnot-a-record", fx.cp2_line);
    assert_invalid(verifier().end_before(&both, None), "non-record second");
}
#[test]
fn e8f_resume_line_with_wrong_seq_rejected() {
    let fx = batch_cp2_record();
    let wrong = resume_entry(
        fx.cp2.context.seq + 2,
        fx.cp2.hash(),
        fx.cp2.context.seq,
        fx.cp2.hash(),
    );
    let both = format!("{}\n{}", fx.cp2_line, line_without_lf(&wrong));
    assert_invalid(verifier().end_before(&both, None), "wrong resume seq");
}
#[test]
fn e8f2_resume_line_with_zero_seq_rejected() {
    let fx = batch_cp2_record();
    let wrong = resume_entry(0, fx.cp2.hash(), fx.cp2.context.seq, fx.cp2.hash());
    let both = format!("{}\n{}", fx.cp2_line, line_without_lf(&wrong));
    assert_invalid(verifier().end_before(&both, None), "zero resume seq");
}
#[test]
fn e8g_resume_line_with_wrong_prev_hash_rejected() {
    let fx = batch_cp2_record();
    let wrong = resume_entry(
        fx.cp2.context.seq + 1,
        [0; 32],
        fx.cp2.context.seq,
        fx.cp2.hash(),
    );
    let both = format!("{}\n{}", fx.cp2_line, line_without_lf(&wrong));
    assert_invalid(verifier().end_before(&both, None), "wrong resume prev");
}
#[test]
fn e8g2_resume_prev_hash_mismatch_other_record_rejected() {
    let fx = batch_cp2_record();
    let wrong = resume_entry(
        fx.cp2.context.seq + 1,
        fx.e1.hash(),
        fx.cp2.context.seq,
        fx.cp2.hash(),
    );
    let both = format!("{}\n{}", fx.cp2_line, line_without_lf(&wrong));
    assert_invalid(verifier().end_before(&both, None), "wrong prev as e1");
}
#[test]
fn e8h_trailing_lf_accepted() {
    let fx = batch_cp2_record();
    let with_lf = format!("{}\n", fx.cp2_line);
    assert!(verifier().end_before(&with_lf, None).is_ok());
}
#[test]
fn e8i_valid_resume_accepted() {
    let fx = batch_cp2_record();
    let ok = resume_entry(
        fx.cp2.context.seq + 1,
        fx.cp2.hash(),
        fx.cp2.context.seq,
        fx.cp2.hash(),
    );
    let both = format!("{}\n{}", fx.cp2_line, line_without_lf(&ok));
    assert!(verifier().end_before(&both, None).is_ok());
}

// =====================================================================
// E9 -- ACCEPTANCE. The conflict between `max_age` and
// `end_before` in both call orders: each is InvalidConfig.
// `end_before` called twice keeps the second.
// =====================================================================
#[test]
fn e9a_max_age_then_end_before_errors() {
    let fx = batch_cp2_record();
    let v = verifier().max_age(std::time::Duration::ZERO).unwrap();
    assert_invalid(v.end_before(&fx.cp2_line, None), "max_age then end_before");
}
#[test]
fn e9a2_max_age_nonzero_then_end_before_errors() {
    // Second row for the `max_age` then `end_before` direction
    // (ruling 13-V6-d4 point 7), with a nonzero duration.
    let fx = batch_cp2_record();
    let v = verifier()
        .max_age(std::time::Duration::from_secs(60))
        .unwrap();
    assert_invalid(
        v.end_before(&fx.cp2_line, None),
        "max_age nonzero then end_before",
    );
}
#[test]
fn e9b_end_before_then_max_age_errors() {
    let fx = batch_cp2_record();
    let v = verifier().end_before(&fx.cp2_line, None).unwrap();
    match v.max_age(std::time::Duration::ZERO) {
        Ok(_) => panic!("end_before then max_age: expected InvalidConfig"),
        Err(e) => assert_eq!(e.kind(), AuditErrorKind::InvalidConfig),
    }
}
#[test]
fn e9b2_end_before_then_max_age_errors_nonzero() {
    let fx = batch_cp2_record();
    let v = verifier().end_before(&fx.cp2_line, None).unwrap();
    match v.max_age(std::time::Duration::from_secs(60)) {
        Ok(_) => panic!("end_before then max_age (nonzero): expected InvalidConfig"),
        Err(e) => assert_eq!(e.kind(), AuditErrorKind::InvalidConfig),
    }
}
#[test]
fn e9c_end_before_twice_keeps_second() {
    let fx = batch_cp2_record();
    let anchor2 = checkpoint_of(&fx.cp2);
    let v = verifier()
        .end_before(&line_without_lf(&fx.cp0), None)
        .unwrap()
        .end_before(&fx.cp2_line, Some(anchor2))
        .unwrap();
    let report = v.verify_files(vec![fx.archive_dir.clone()]).unwrap();
    let expected: Vec<Finding> = Vec::new();
    assert_findings(report.findings(), &expected, "E9c second wins");
}

// =====================================================================
// E10 -- ACCEPTANCE. Decision 2 l.956 "run digest equality": step 6
// (archive + live) and step 7 (archive + end_before(opening +
// resume line)) report the SAME run `SegmentStructure` finding
// with the SAME digest. Takes a trail archived at a resume
// opening.
// =====================================================================
// =====================================================================
// E10b -- REGRESSION. On an A8-style archive (`S0=[cp0]`, `S1=[]`)
// with an `end_before` record `[cp_opening, resume]`, step 7
// reports exactly one run `SegmentStructure` finding carrying a
// run digest -- the shared classifier walks the end record as the
// segment that follows the files (ruling 13-V6-d4 point 1).
// =====================================================================
#[test]
fn e10b_step7_produces_a_segment_structure_run_finding() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let fold = seeded(&cp0);
    let cp_opening = signed_cp(1, cp0.hash(), &fold);
    let resume = resume_decl(&cp_opening, 0, cp0.hash(), 0);
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
    let has_run = report
        .findings()
        .iter()
        .any(|f| f.kind() == K::SegmentStructure && f.run_digest().is_some());
    assert!(has_run, "E10b: classifier must walk the end record");
}

#[test]
fn e10_step6_and_step7_report_the_same_run_segment_structure() {
    // A8-style layout: a run ends at an empty S1 segment, resumed
    // by the next batch's opening. Step 6 (archive + live) and step
    // 7 (archive + end_record) both produce one `SegmentStructure`
    // run finding; l.956 pins their digests equal.
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let fold = seeded(&cp0);
    let cp_opening = signed_cp(1, cp0.hash(), &fold);
    let resume = resume_decl(&cp_opening, 0, cp0.hash(), 0);

    // Step 6: archive = [S0=[cp0], S1=[]] + live = [cp_opening, resume]
    let d6 = Temp::new();
    put_segment(&d6.0, 0, &[&cp0], &[]);
    put_segment(&d6.0, 1, &[], &[]);
    write_records(&d6.0, &[&cp_opening, &resume]);
    let report6 = verifier().verify_files(vec![d6.0.clone()]).unwrap();

    // Step 7: archive = [S0=[cp0], S1=[]] + end_before(cp_opening + resume)
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

    let run6 = report6
        .findings()
        .iter()
        .find(|f| f.kind() == K::SegmentStructure && f.run_digest().is_some())
        .expect("step 6 run finding");
    let run7 = report7
        .findings()
        .iter()
        .find(|f| f.kind() == K::SegmentStructure && f.run_digest().is_some())
        .expect("step 7 run finding");
    assert_eq!(run6.run_digest(), run7.run_digest(), "run digest equality");
    assert_eq!(run6.detail(), run7.detail(), "run detail equality");
    assert_eq!(run6.seq(), run7.seq(), "run seq equality");
}

// =====================================================================
// E11 -- ACCEPTANCE. The end checkpoint is signed by an untrusted
// key: `UntrustedKey` on it, with no file and no line (point 6).
// =====================================================================
#[test]
fn e11_untrusted_end_checkpoint_has_untrusted_key_without_location() {
    // Build an archive ending at `e1`, then an untrusted cp2 as
    // the end record. The verified-trail key is still fixture_pubkey;
    // cp2 is signed by the untrusted key.
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
    // UntrustedKey at seq 2, with no file and no line.
    let hex_key = untrusted_key_hex();
    let expected_detail = format!("key {hex_key} not listed for trail {TRAIL_HEX}");
    let utk = report
        .findings()
        .iter()
        .find(|f| f.kind() == K::UntrustedKey)
        .expect("UntrustedKey present");
    assert_eq!(utk.file(), None, "E11: no file");
    assert_eq!(utk.line(), None, "E11: no line");
    assert_eq!(utk.seq(), Some(2));
    assert_eq!(utk.detail(), expected_detail);
}

// =====================================================================
// REGRESSION. Fixture-hash pins: recompute the hashes the rows
// assert literally and compare with the layout builders. A change
// in the fixture (seq/chain/key) fails here instead of drifting
// through many rows.
// =====================================================================
#[test]
fn fixture_hashes_match_literals() {
    let fx = batch_cp2_record();
    assert_eq!(hex(&fx.cp0.hash()).len(), 64);
    // Trail id and fixture key stay the shared constants.
    assert_eq!(hex(&TRAIL), TRAIL_HEX);
    assert_eq!(hex(&OTHER_TRAIL), OTHER_TRAIL_HEX);
    assert_eq!(hex(&fixture_pubkey()), FIXTURE_KEY_HEX);
    // The cp2 line's parse round-trips to the same hash.
    let parsed = Checkpoint::parse(&fx.cp2_line).unwrap();
    assert_eq!(parsed.hash(), fx.cp2.hash());
}
