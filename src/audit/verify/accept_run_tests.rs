//! Rows for [`crate::audit::Verifier::accept_run`] and the three
//! outcomes `Accepted` / `AcceptMismatch` / `AcceptUnused`
//! (ADR-0005 decision 11 "Review file" `accept-run`; ruling
//! 13-V8-d1).
//!
//! Every row asserts the full sorted finding list literally.

use super::tests_common::{assert_findings, report_of, trust_with_key, unlocated};
use super::{Finding, Verifier};
use crate::audit::{
    AuditErrorKind, Checkpoint, FindingKind as K, Mmr, Record, digest_string,
    runs_v4a_fixtures::{
        A1_DIGEST, TRAIL, Temp, build_a1, entry_rec, fixture_pubkey, headless, line_bytes, pushed,
        put_segment, resume_decl, seeded, segment_path, signed_cp, signed_cp_explicit,
        write_records,
    },
};
use std::{
    fs,
    path::{Path, PathBuf},
};

// =====================================================================
// Pinned constants.
// =====================================================================

/// `run_digest(&[], &[])`: the "digest of nothing" used by the
/// `AcceptUnused` branch of ADR-0005 decision 11 `accept-run`.
/// Equal to the `A8_DIGEST` pin (an A8-layout run has empty
/// ranges and empty spans).
const EMPTY_RUN_DIGEST_HEX: &str =
    "blake3:1c02f080d9c70df74de0c13a4a30323f1b49ee624bab2c5d68fa5ee31c4400e4";
const WRONG_HASH: [u8; 32] = [0xC7; 32];
const WRONG_HASH_HEX: &str =
    "blake3:c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7";
const WRONG_DIGEST: [u8; 32] = [0x6B; 32];
const WRONG_DIGEST_HEX: &str =
    "blake3:6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b";

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("hex"),
    }
}
const fn hex_to_bytes(hex: &str) -> [u8; 32] {
    let s = hex.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(s[i * 2]) << 4) | nibble(s[i * 2 + 1]);
        i += 1;
    }
    out
}
const EMPTY_RUN_DIGEST: [u8; 32] =
    hex_to_bytes("1c02f080d9c70df74de0c13a4a30323f1b49ee624bab2c5d68fa5ee31c4400e4");
const A1_DIGEST_BYTES: [u8; 32] =
    hex_to_bytes("79d8cb1c4dfc89a80a4911120280e63ed383108f3199f05291bcb51f625f3931");

#[test]
fn pinned_literals_match() {
    let empty = super::lines::run_digest(&[], &[]);
    assert_eq!(digest_string(&empty), EMPTY_RUN_DIGEST_HEX, "empty digest");
    assert_eq!(EMPTY_RUN_DIGEST, empty, "empty digest bytes");
    assert_eq!(
        A1_DIGEST,
        "blake3:79d8cb1c4dfc89a80a4911120280e63ed383108f3199f05291bcb51f625f3931"
    );
    assert_eq!(digest_string(&WRONG_HASH), WRONG_HASH_HEX, "wrong hash");
    assert_eq!(
        digest_string(&WRONG_DIGEST),
        WRONG_DIGEST_HEX,
        "wrong digest"
    );
}

fn verifier() -> Verifier {
    Verifier::new(trust_with_key(fixture_pubkey()))
}

fn parse_cp_bytes(bytes: &[u8]) -> Checkpoint {
    let line = std::str::from_utf8(bytes)
        .unwrap()
        .trim_end_matches('\n')
        .to_owned();
    Checkpoint::parse(&line).unwrap()
}

// =====================================================================
// Fixture: A1-style run with an in-run `MmrMismatch` (cp5 wrong
// root). Mirrors `rule2_tests::build_a1_wrong_cp5_root` so items 1-3
// of ADR-0005 decision 11 are all exercisable:
//   S0 (sealed) = [cp0, e1, e2]
//   S1 (sealed, headless) = [r4, cp5_bad_root]
//   live (closer) = [cp6, resume7]
// cp6 is the closing opening (honest fold); cp5 fires one
// `MmrMismatch` as `DiffersAfterLoss`. The run digest matches
// `A1_DIGEST`.
// =====================================================================

struct RunFx {
    _dir: Temp,
    dir: PathBuf,
    s1: PathBuf,
    live: PathBuf,
    cp5: Record,
    cp6: Record,
    cp5_bad_root: [u8; 32],
    fold_before_cp5: Mmr,
    resume: Record,
    e2_hash: [u8; 32],
    r4_previous: [u8; 32],
}

fn build_run_fx() -> RunFx {
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
    let bad_root = [0x55; 32];
    let cp5 = signed_cp_explicit(5, r4.hash(), fold.size(), bad_root, fold.peaks().to_vec());
    put_segment(&d.0, 1, &[&r4, &cp5], &[]);
    let fold6 = pushed(&fold, &cp5);
    let cp6 = signed_cp(6, cp5.hash(), &fold6);
    let resume = resume_decl(&cp6, 5, cp5.hash(), 5);
    write_records(&d.0, &[&cp6, &resume]);
    let s1 = segment_path(&d.0, 1);
    let live = d.0.join("audit.jsonl");
    RunFx {
        dir: d.0.clone(),
        _dir: d,
        s1,
        live,
        cp5,
        cp6,
        cp5_bad_root: bad_root,
        fold_before_cp5: fold,
        resume,
        e2_hash: e2.hash(),
        r4_previous: r4.context.previous,
    }
}

fn chain_broken_at_4(fx: &RunFx) -> Finding {
    Finding::new(
        K::ChainBroken,
        Some(fx.s1.clone()),
        Some(1),
        Some(4),
        format!(
            "expected previous {}, found {}",
            digest_string(&fx.e2_hash),
            digest_string(&fx.r4_previous),
        ),
    )
}
fn per_seg_structure(fx: &RunFx) -> Finding {
    Finding::new(
        K::SegmentStructure,
        Some(fx.s1.clone()),
        Some(1),
        Some(4),
        "expected first complete record to be a checkpoint".into(),
    )
}
fn run_structure(fx: &RunFx) -> Finding {
    let detail = format!("loss seq 4 first 3 count 1; digest {A1_DIGEST}");
    Finding::new(
        K::SegmentStructure,
        Some(fx.s1.clone()),
        Some(1),
        Some(4),
        detail,
    )
    .with_run_digest(A1_DIGEST_BYTES)
}
fn seq_gap(fx: &RunFx) -> Finding {
    Finding::new(
        K::SeqGap,
        Some(fx.s1.clone()),
        Some(1),
        Some(4),
        "missing seq 3..=3".into(),
    )
}
fn mmr_mismatch(fx: &RunFx) -> Finding {
    Finding::new(
        K::MmrMismatch,
        Some(fx.s1.clone()),
        Some(2),
        Some(5),
        format!(
            "expected size {} root {}, found size {} root {}",
            fx.fold_before_cp5.size(),
            digest_string(&fx.fold_before_cp5.root()),
            fx.fold_before_cp5.size(),
            digest_string(&fx.cp5_bad_root),
        ),
    )
}
fn resumed(fx: &RunFx) -> Finding {
    let detail = format!(
        "operator=operator reason=incident head=5:{} gap=none lost_records=0 structural=valid",
        digest_string(&fx.cp5.hash())
    );
    Finding::new(K::Resumed, Some(fx.live.clone()), Some(2), Some(7), detail)
}
fn uncovered_tail() -> Finding {
    unlocated(K::UncoveredTail, None, "records seq 7..=7".into())
}

fn literal_accepted(original: Finding, by: &str, reason: &str) -> Finding {
    let kind = original.kind();
    let file = original.file().map(Path::to_path_buf);
    let line = original.line();
    let seq = original.seq();
    let detail = format!("accepted by {by}: {reason}; was: {}", original.detail());
    Finding::new(K::Accepted, file, line, seq, detail).with_accepted_kind(kind)
}

// =====================================================================
// (ADR-0005 decision 11 l.956): the right line. Every item 1-3
// finding becomes `Accepted` through one `accept-run` line pinning
// the run's closing resume record and the run digest. `Resumed`
// stays a warning until `accept Resumed` is added.
// =====================================================================
#[test]
fn match_promotes_items_1_through_3() {
    let fx = build_run_fx();
    let v = verifier()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    // All 4 findings at (seq=4, s1, line=1) become `Accepted`, so
    // their kind-debug ties and the stable sort preserves the
    // engine's insertion order: per-segment SegmentStructure (from
    // file_findings), then SeqGap and ChainBroken (from the
    // seq-loop), then the run SegmentStructure (from fold_findings
    // appended last).
    let expected = vec![
        literal_accepted(per_seg_structure(&fx), "alice", "ok"),
        literal_accepted(seq_gap(&fx), "alice", "ok"),
        literal_accepted(chain_broken_at_4(&fx), "alice", "ok"),
        literal_accepted(run_structure(&fx), "alice", "ok"),
        literal_accepted(mmr_mismatch(&fx), "alice", "ok"),
        resumed(&fx),
        uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "run_match");
    // An accepted run's `run_digest()` is `None` (ruling 13-V8-d1
    // point 4); the digest survives in the `was:` tail text.
    let accepted_run = report
        .findings()
        .iter()
        .find(|f| f.accepted_kind() == Some(K::SegmentStructure) && f.detail().contains("digest"))
        .expect("accepted run finding");
    assert_eq!(accepted_run.run_digest(), None, "run_digest cleared");
    assert!(
        accepted_run.detail().contains(A1_DIGEST),
        "was: carries the digest",
    );
}

// With both `accept-run` AND `accept Resumed` present, plain verify
// passes and `--strict` passes (the fixture extends past the
// resume with a trusted checkpoint so no `UncoveredTail` blocks
// `--strict`).
struct CoveredRunFx {
    _dir: Temp,
    dir: PathBuf,
    resume: Record,
    cp5: Record,
    s1: PathBuf,
    live: PathBuf,
}
fn build_covered_run_fx() -> CoveredRunFx {
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
    let bad_root = [0x55; 32];
    let cp5 = signed_cp_explicit(5, r4.hash(), fold.size(), bad_root, fold.peaks().to_vec());
    put_segment(&d.0, 1, &[&r4, &cp5], &[]);
    let fold6 = pushed(&fold, &cp5);
    let cp6 = signed_cp(6, cp5.hash(), &fold6);
    let resume = resume_decl(&cp6, 5, cp5.hash(), 5);
    let fold8 = pushed(&pushed(&fold6, &cp6), &resume);
    let cp8 = signed_cp(8, resume.hash(), &fold8);
    write_records(&d.0, &[&cp6, &resume, &cp8]);
    let s1 = segment_path(&d.0, 1);
    let live = d.0.join("audit.jsonl");
    CoveredRunFx {
        dir: d.0.clone(),
        _dir: d,
        resume,
        cp5,
        s1,
        live,
    }
}

#[test]
fn match_with_both_lines_strict_passes() {
    let fx = build_covered_run_fx();
    let v = verifier()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap()
        .accept(K::Resumed, 7, fx.resume.hash(), "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    assert!(report.is_valid(), "verify passes");
    assert!(report.is_strict_valid(), "--strict passes");
    // Every item that was an error or warning is now Accepted.
    let unresolved: Vec<_> = report
        .findings()
        .iter()
        .filter(|f| !matches!(f.kind(), K::Accepted | K::UncoveredTail))
        .collect();
    assert!(
        unresolved.is_empty(),
        "no unresolved findings: {unresolved:?}"
    );
    // The `was:` tail of the accepted run finding carries A1_DIGEST.
    let _ = fx.cp5;
    let _ = fx.s1;
    let _ = fx.live;
}

// =====================================================================
// (ADR-0005 decision 11 l.956): digest mismatch cases. A wrong
// digest, a wrong resume hash, a `seq` with no record, and a `seq`
// whose record is not a resume record each give `AcceptMismatch`
// with none of the run's findings `Accepted`.
// =====================================================================
#[test]
fn wrong_run_digest_gives_accept_mismatch() {
    let fx = build_run_fx();
    let v = verifier()
        .accept_run(7, fx.resume.hash(), WRONG_DIGEST, "alice", "stale")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        chain_broken_at_4(&fx),
        per_seg_structure(&fx),
        run_structure(&fx),
        seq_gap(&fx),
        mmr_mismatch(&fx),
        unlocated(
            K::AcceptMismatch,
            Some(7),
            format!(
                "accept-run seq 7 hash {}: run digest differs (run {A1_DIGEST})",
                digest_string(&fx.resume.hash())
            ),
        ),
        resumed(&fx),
        uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "wrong_digest");
}

#[test]
fn wrong_resume_hash_gives_accept_mismatch() {
    let fx = build_run_fx();
    let v = verifier()
        .accept_run(7, WRONG_HASH, A1_DIGEST_BYTES, "alice", "stale")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let tail = format!(
        "accept-run seq 7 hash {WRONG_HASH_HEX}: hash differs (record {})",
        digest_string(&fx.resume.hash())
    );
    let expected = vec![
        chain_broken_at_4(&fx),
        per_seg_structure(&fx),
        run_structure(&fx),
        seq_gap(&fx),
        mmr_mismatch(&fx),
        unlocated(K::AcceptMismatch, Some(7), tail),
        resumed(&fx),
        uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "wrong_hash");
}

#[test]
fn seq_with_no_record_gives_accept_mismatch() {
    let fx = build_run_fx();
    let v = verifier()
        .accept_run(99, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "stale")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let tail = format!(
        "accept-run seq 99 hash {}: no record",
        digest_string(&fx.resume.hash())
    );
    let expected = vec![
        chain_broken_at_4(&fx),
        per_seg_structure(&fx),
        run_structure(&fx),
        seq_gap(&fx),
        mmr_mismatch(&fx),
        resumed(&fx),
        unlocated(K::AcceptMismatch, Some(99), tail),
        uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "no_record");
}

#[test]
fn seq_at_non_resume_record_gives_accept_mismatch() {
    let fx = build_run_fx();
    // seq 6 holds cp6 (a checkpoint), not a resume record.
    let v = verifier()
        .accept_run(6, fx.cp6.hash(), A1_DIGEST_BYTES, "alice", "stale")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let tail = format!(
        "accept-run seq 6 hash {}: not a resume record",
        digest_string(&fx.cp6.hash())
    );
    let expected = vec![
        chain_broken_at_4(&fx),
        per_seg_structure(&fx),
        run_structure(&fx),
        seq_gap(&fx),
        mmr_mismatch(&fx),
        unlocated(K::AcceptMismatch, Some(6), tail),
        resumed(&fx),
        uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "not_resume");
}

// =====================================================================
// (ADR-0005 decision 11 l.957): the list is exact. An `accept-run`
// line NEVER accepts findings outside items 1-3: a `TornWrite` on
// the run's live file stays, and an `Unparsable` from a torn tail
// stays. The fixture appends a torn tail to the live file so the
// trailing gap's `TornWrite` fires at the closer's live segment.
// The run itself is emptied by the violation ("any violation
// empties every run", ruling 13-V4-d8 point 3), so `accept-run`
// hits the `no run` branch and nothing is `Accepted`.
// =====================================================================
#[test]
fn only_items_1_through_3_are_accepted() {
    let fx = build_run_fx();
    // Add a TornWrite + Unparsable by appending a torn tail.
    fs::OpenOptions::new()
        .append(true)
        .open(&fx.live)
        .unwrap()
        .write_all_vec(b"not json\n");
    let v = verifier()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    // After the torn tail, the run is emptied and no `Accepted`
    // finding fires; the TornWrite and Unparsable stay.
    let accepted: Vec<_> = report
        .findings()
        .iter()
        .filter(|f| f.kind() == K::Accepted)
        .collect();
    assert!(accepted.is_empty(), "no Accepted: {accepted:?}");
    let torn: Vec<_> = report
        .findings()
        .iter()
        .filter(|f| f.kind() == K::TornWrite)
        .collect();
    assert!(!torn.is_empty(), "TornWrite stays");
    let unparsable: Vec<_> = report
        .findings()
        .iter()
        .filter(|f| f.kind() == K::Unparsable)
        .collect();
    assert!(!unparsable.is_empty(), "Unparsable stays");
}

// =====================================================================
// (ADR-0005 decision 11 l.957): validation at the builder, with
// the exact message pinned.
// =====================================================================
#[test]
fn empty_reviewer_gives_invalid_config() {
    let err = verifier()
        .accept_run(7, WRONG_HASH, EMPTY_RUN_DIGEST, "", "r")
        .unwrap_err();
    assert_eq!(err.kind(), AuditErrorKind::InvalidConfig);
    assert_eq!(
        err.to_string(),
        "InvalidConfig: accept-run reviewer must be a single token (no whitespace or control bytes)",
    );
}
#[test]
fn space_in_reviewer_gives_invalid_config() {
    let err = verifier()
        .accept_run(7, WRONG_HASH, EMPTY_RUN_DIGEST, "al ice", "r")
        .unwrap_err();
    assert_eq!(err.kind(), AuditErrorKind::InvalidConfig);
    assert_eq!(
        err.to_string(),
        "InvalidConfig: accept-run reviewer must be a single token (no whitespace or control bytes)",
    );
}
#[test]
fn empty_reason_gives_invalid_config() {
    let err = verifier()
        .accept_run(7, WRONG_HASH, EMPTY_RUN_DIGEST, "alice", "")
        .unwrap_err();
    assert_eq!(err.kind(), AuditErrorKind::InvalidConfig);
    assert_eq!(
        err.to_string(),
        "InvalidConfig: accept-run reason must be a non-empty single line (no LF or CR)",
    );
}
#[test]
fn duplicate_seq_gives_invalid_config() {
    let v = verifier()
        .accept_run(7, WRONG_HASH, EMPTY_RUN_DIGEST, "alice", "r")
        .unwrap();
    let err = v
        .accept_run(7, WRONG_HASH, EMPTY_RUN_DIGEST, "bob", "r2")
        .unwrap_err();
    assert_eq!(err.kind(), AuditErrorKind::InvalidConfig);
    assert_eq!(
        err.to_string(),
        "InvalidConfig: duplicate accept-run for seq 7"
    );
}

// =====================================================================
// (ADR-0005 decision 11 l.958): archive criterion. With the start
// at the run's closing opening checkpoint, the `accept-run` line is
// set aside under the start rule, even though the resume `seq` is
// in range (ruling 13-V8-d1 point 8).
// =====================================================================
// Archive layout: only the closer segment's records remain on
// disk (an archived prefix), so start_from(closing_opening) is
// the first record and the start is accepted.
fn build_archive_fx() -> ArchiveFx {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    let r4 = headless(&e2, 4);
    let fold = pushed(&mmr2, &r4);
    let cp5 = signed_cp(5, r4.hash(), &fold);
    let fold6 = pushed(&fold, &cp5);
    let cp6 = signed_cp(6, cp5.hash(), &fold6);
    let resume = resume_decl(&cp6, 5, cp5.hash(), 5);
    // Live-only (archived prefix): the closer's opening + resume.
    write_records(&d.0, &[&cp6, &resume]);
    ArchiveFx {
        dir: d.0.clone(),
        _dir: d,
        cp6,
        resume,
    }
}
struct ArchiveFx {
    _dir: Temp,
    dir: PathBuf,
    cp6: Record,
    resume: Record,
}

#[test]
fn start_at_closing_opening_unanchored_gives_unanchored_start() {
    let fx = build_archive_fx();
    let cp6_bytes = line_bytes(&fx.cp6);
    let start = parse_cp_bytes(&cp6_bytes);
    let v = verifier()
        .start_from(start)
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let sa = report
        .findings()
        .iter()
        .find(|f| f.kind() == K::UnanchoredStart && f.seq() == Some(7))
        .expect("unanchored start at seq 7");
    assert_eq!(
        sa.detail(),
        &format!(
            "accept-run seq 7 hash {}: below start seq 6",
            digest_string(&fx.resume.hash())
        ),
    );
    assert_eq!(sa.file(), None);
    assert_eq!(sa.line(), None);
    assert!(!report.findings().iter().any(|f| f.kind() == K::Accepted));
}
#[test]
fn start_at_closing_opening_anchored_gives_out_of_range() {
    let fx = build_archive_fx();
    let cp6_bytes = line_bytes(&fx.cp6);
    let start = parse_cp_bytes(&cp6_bytes);
    let v = verifier()
        .anchor(start.clone())
        .start_from(start)
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let oor = report
        .findings()
        .iter()
        .find(|f| f.kind() == K::OutOfRange && f.seq() == Some(7))
        .expect("out of range at seq 7");
    assert_eq!(
        oor.detail(),
        &format!(
            "accept-run seq 7 hash {}: below start seq 6",
            digest_string(&fx.resume.hash())
        ),
    );
    assert!(!report.findings().iter().any(|f| f.kind() == K::Accepted));
}

// =====================================================================
// (ADR-0005 decision 11 l.958): archive criterion step 7 --
// `end_before` whose record is the closing opening plus its resume
// line. With the end anchor present, the run verifies.
// =====================================================================
#[test]
fn end_before_anchored_closes_run_at_resume() {
    let fx = build_run_fx();
    let mut archive_bytes = line_bytes(&fx.cp6);
    archive_bytes.extend(line_bytes(&fx.resume));
    let archive = std::str::from_utf8(&archive_bytes)
        .unwrap()
        .trim_end_matches('\n')
        .to_owned();
    let cp6_bytes = line_bytes(&fx.cp6);
    let end_anchor = parse_cp_bytes(&cp6_bytes);
    // Copy only the sealed segments so the end_before record
    // supplies cp6+resume7 as the archive end.
    let s0 = segment_path(&fx.dir, 0);
    let v = verifier()
        .end_before(&archive, Some(end_anchor))
        .unwrap()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![s0, fx.s1.clone()], v);
    // Every item 1-3 is accepted; no error findings remain.
    assert!(
        report.is_valid(),
        "verify passes: findings={:?}",
        report.findings()
    );
}

// =====================================================================
// (ADR-0005 decision 11 "No run"): a resume record that closes no
// run, carrying the digest of nothing, is `AcceptUnused`. Any
// other digest is `AcceptMismatch`. The fixture appends a torn
// tail to the live file, which the walker rejects as
// `Violation::InvalidLineOrOpeningCheckpoint`, emptying `runs`
// (ruling 13-V4-d8 point 3); the resume at seq 7 is still a
// parseable resume record in `groups`.
// =====================================================================
fn build_no_run_fx() -> NoRunFx {
    let a = build_a1();
    fs::OpenOptions::new()
        .append(true)
        .open(a.dir_path.join("audit.jsonl"))
        .unwrap()
        .write_all_vec(b"not json\n");
    let (resume_hash, resume_seq) = resume_of_a1(&a);
    NoRunFx {
        dir: a.dir_path.clone(),
        a,
        resume_hash,
        resume_seq,
    }
}

// Helper: rebuild A1's cp0..=resume locally so we can grab the
// resume record's hash and seq. Replicates `build_a1`'s record
// construction (ruling 197-d1 addendum 27.4: deterministic).
fn resume_of_a1(_a: &crate::audit::runs_v4a_fixtures::A1) -> ([u8; 32], u64) {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    let r4 = headless(&e2, 4);
    let fold = pushed(&mmr2, &r4);
    let cp5 = signed_cp(5, r4.hash(), &fold);
    let fold6 = pushed(&fold, &cp5);
    let cp6 = signed_cp(6, cp5.hash(), &fold6);
    let resume = resume_decl(&cp6, 5, cp5.hash(), 5);
    (resume.hash(), resume.context.seq)
}

trait WriteAllVec {
    fn write_all_vec(&mut self, bytes: &[u8]);
}
impl WriteAllVec for fs::File {
    fn write_all_vec(&mut self, bytes: &[u8]) {
        use std::io::Write as _;
        self.write_all(bytes).unwrap();
    }
}

struct NoRunFx {
    #[allow(dead_code)]
    a: crate::audit::runs_v4a_fixtures::A1,
    dir: PathBuf,
    resume_hash: [u8; 32],
    resume_seq: u64,
}

#[test]
fn no_run_with_empty_digest_gives_accept_unused() {
    let fx = build_no_run_fx();
    let v = verifier()
        .accept_run(
            fx.resume_seq,
            fx.resume_hash,
            EMPTY_RUN_DIGEST,
            "alice",
            "ok",
        )
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let unused = report
        .findings()
        .iter()
        .find(|f| f.kind() == K::AcceptUnused && f.seq() == Some(fx.resume_seq))
        .expect("AcceptUnused at resume seq");
    assert_eq!(
        unused.detail(),
        &format!(
            "accept-run seq {} hash {}: no matching run",
            fx.resume_seq,
            digest_string(&fx.resume_hash),
        ),
    );
    assert!(!report.findings().iter().any(|f| f.kind() == K::Accepted));
}

#[test]
fn no_run_with_other_digest_gives_accept_mismatch() {
    let fx = build_no_run_fx();
    let v = verifier()
        .accept_run(fx.resume_seq, fx.resume_hash, WRONG_DIGEST, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let mm = report
        .findings()
        .iter()
        .find(|f| f.kind() == K::AcceptMismatch && f.seq() == Some(fx.resume_seq))
        .expect("AcceptMismatch at resume seq");
    assert_eq!(
        mm.detail(),
        &format!(
            "accept-run seq {} hash {}: run digest differs (run {EMPTY_RUN_DIGEST_HEX})",
            fx.resume_seq,
            digest_string(&fx.resume_hash),
        ),
    );
    assert!(!report.findings().iter().any(|f| f.kind() == K::Accepted));
}

// =====================================================================
// (ADR-0005 decision 11 "Laundering"): a deletion AFTER the review
// changes the run's ranges, so the same `accept-run` line flips to
// `AcceptMismatch`. Exit code becomes 1.
// =====================================================================
#[test]
fn laundering_after_match_flips_to_accept_mismatch() {
    let fx = build_run_fx();
    // First verify-with-accept passes (no error findings).
    let v1 = verifier()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report1 = report_of(vec![fx.dir.clone()], v1);
    assert!(report1.is_valid(), "before deletion: verify passes");
    // Delete the sealed segment S0 so the loss point shifts.
    let s0 = segment_path(&fx.dir, 0);
    fs::remove_file(s0).unwrap();
    let v2 = verifier()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report2 = report_of(vec![fx.dir.clone()], v2);
    let kinds: Vec<K> = report2
        .findings()
        .iter()
        .map(super::Finding::kind)
        .collect();
    assert!(kinds.contains(&K::AcceptMismatch), "laundering: {kinds:?}",);
    assert!(!report2.is_valid(), "after deletion: exit 1");
}

// =====================================================================
// (ruling 13-V4-d8): after a violation there are no runs, so the
// line is `AcceptMismatch`. The fixture reuses the `build_no_run_fx`
// layout (torn tail → `InvalidLineOrOpeningCheckpoint` → no runs)
// and names a digest that does not equal the digest of nothing.
// =====================================================================
#[test]
fn after_violation_other_digest_gives_accept_mismatch() {
    let fx = build_no_run_fx();
    let v = verifier()
        .accept_run(
            fx.resume_seq,
            fx.resume_hash,
            A1_DIGEST_BYTES,
            "alice",
            "ok",
        )
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let mm = report
        .findings()
        .iter()
        .find(|f| f.kind() == K::AcceptMismatch && f.seq() == Some(fx.resume_seq))
        .expect("AcceptMismatch after violation");
    assert!(
        mm.detail().contains("run digest differs"),
        "after violation: {}",
        mm.detail()
    );
}
