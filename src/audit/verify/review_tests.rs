//! Rows for [`crate::audit::Verifier::accept`] and the three
//! outcomes `Accepted` / `AcceptMismatch` / `AcceptUnused`
//! (ADR-0005 decision 11 "Review file"; ruling 13-V8-d1).
//!
//! Every row asserts the full sorted finding list literally; each
//! deterministic hash in an expected detail is a `const` pinned by
//! [`fixture_hashes_match_literals`] against the fixture builder.

use super::tests_common::{assert_findings, report_of, trust_with_key, unlocated};
use super::{Finding, Verifier};
use crate::audit::{
    AuditConfig, AuditError, AuditErrorKind, Checkpoint, CheckpointFields, Entry, FindingKind as K,
    KeyFileSigner, Mmr, Record, RecordContext, Signer, digest_string, gap_hasher, hex,
    runs_v4a_fixtures::{
        TRAIL, Temp, context, entry_rec, fixture_pubkey, line_bytes, pushed, put_segment, seeded,
        segment_path, signed_cp,
    },
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

// =====================================================================
// Pinned constants and helpers.
// =====================================================================
/// `signed_cp(0, Record::genesis(&TRAIL), &Mmr::new())`.
const CP0_DIGEST: &str = "blake3:fc26c6f2bb830592aaaca5413da1599489d86ac6e240a4a7a010681e0d4c8e77";
/// `entry_rec(1, cp0.hash())`.
const E1_DIGEST: &str = "blake3:c121282b5135adfe7a17142cae6bfc4c9040c4aed26d74bddc923b8dafcdb6e8";
/// 32-byte placeholder for a wrong-digest scenario: `[0xA5; 32]`.
const WRONG_HASH_A5_DIGEST: &str =
    "blake3:a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5";
const WRONG_HASH_A5: [u8; 32] = [0xA5; 32];

/// The one-byte Fragment used as the trailing gap. `{` is an
/// incomplete JSON value so the trailing run passes condition 3
/// (no "after" record), so no `Unparsable` finding fires.
const FRAG_TAIL: &[u8] = b"{";
/// `gap_hasher().update(b"{").finalize()` -- the gap digest the
/// trailing `TornWrite` reports and `accept TornWrite` matches on.
const FRAG_DIGEST_HEX: &str = "8d8bd64465582c77a7d0edad4aed07153955fcaf24b4518503a4bab8b4f4307b";
const FRAG_DIGEST: &str = "blake3:8d8bd64465582c77a7d0edad4aed07153955fcaf24b4518503a4bab8b4f4307b";

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("hex"),
    }
}
const FRAG_DIGEST_BYTES: [u8; 32] = {
    let s = FRAG_DIGEST_HEX.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(s[i * 2]) << 4) | nibble(s[i * 2 + 1]);
        i += 1;
    }
    out
};

fn frag_digest_bytes() -> [u8; 32] {
    let mut h = gap_hasher();
    h.update(FRAG_TAIL);
    *h.finalize().as_bytes()
}

#[test]
fn fixture_hashes_match_literals() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    assert_eq!(digest_string(&cp0.hash()), CP0_DIGEST, "cp0");
    assert_eq!(digest_string(&e1.hash()), E1_DIGEST, "e1");
    assert_eq!(digest_string(&WRONG_HASH_A5), WRONG_HASH_A5_DIGEST, "wrong");
    assert_eq!(digest_string(&frag_digest_bytes()), FRAG_DIGEST, "frag");
    assert_eq!(FRAG_DIGEST_BYTES, frag_digest_bytes(), "frag const bytes");
}

fn verifier() -> Verifier {
    Verifier::new(trust_with_key(fixture_pubkey()))
}
fn signer() -> Arc<dyn Signer> {
    Arc::new(KeyFileSigner::from_hex(&"27".repeat(32)).unwrap())
}
fn pre_seed(dir: &Path) {
    std::fs::write(
        dir.join("audit.trail"),
        format!("{}\n", hex(&TRAIL)).as_bytes(),
    )
    .unwrap();
}

fn parse_cp(record: &Record) -> Checkpoint {
    let bytes = line_bytes(record);
    let line = std::str::from_utf8(&bytes)
        .unwrap()
        .trim_end_matches('\n')
        .to_owned();
    Checkpoint::parse(&line).unwrap()
}

/// `signed_cp` with a `.repaired()` context so a row can seal an
/// attested gap without hand-building `CheckpointFields`.
fn cp_with_repair(seq: u64, previous: [u8; 32], mmr: &Mmr, repaired: [u8; 32]) -> Record {
    let key = KeyFileSigner::from_hex(&"27".repeat(32)).unwrap();
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
    let ctx = context(seq, previous).repaired(repaired);
    let unsigned = Record::checkpoint(ctx.clone(), fields([0; 64])).unwrap();
    let signature = key.sign(&unsigned.signing_message().unwrap()).unwrap();
    Record::checkpoint(ctx, fields(signature)).unwrap()
}

/// A stopped trail: segment with `[cp0, cp1]` + 1-byte Fragment
/// tail. Reports one trailing `TornWrite` pinned at
/// `(seq 1, FRAG_DIGEST_BYTES)` and no other finding.
struct Trailing {
    _dir: Temp,
    path: PathBuf,
    cp1_hash: [u8; 32],
}
fn trailing_fixture() -> Trailing {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let cp1 = signed_cp(1, cp0.hash(), &seeded(&cp0));
    put_segment(&d.0, 0, &[&cp0, &cp1], FRAG_TAIL);
    let path = segment_path(&d.0, 0);
    Trailing {
        _dir: d,
        path,
        cp1_hash: cp1.hash(),
    }
}
fn base_torn_write(path: &Path) -> Finding {
    Finding::new(
        K::TornWrite,
        Some(path.to_path_buf()),
        Some(3),
        None,
        format!("trailing gap lines 3..=3 (1 bytes), digest {FRAG_DIGEST}"),
    )
}

// =====================================================================
// (ADR-0005 decision 11 l.977-983): a trailing fragment on a
// stopped trail is `TornWrite`; `accept TornWrite` pinning the
// record before it with that digest replaces the warning with
// `Accepted` (info), and `--strict` passes.
// =====================================================================
#[test]
fn r1a_trailing_torn_write_accept_match_gives_accepted() {
    let v = verifier()
        .accept(K::TornWrite, 1, FRAG_DIGEST_BYTES, "alice", "reviewed")
        .unwrap();
    let fx = trailing_fixture();
    let report = report_of(vec![fx.path.clone()], v);
    let expected = vec![base_torn_write(&fx.path).accepted("alice", "reviewed")];
    assert_findings(report.findings(), &expected, "r1a");
    assert!(report.is_strict_valid(), "r1a strict passes");
}

// : an `accept TornWrite` naming the correct `seq` but another
// gap digest leaves the `TornWrite` warning and emits one
// unlocated `AcceptUnused`; `--strict` still fails.
#[test]
fn r1b_trailing_torn_write_wrong_digest_gives_accept_unused() {
    let v = verifier()
        .accept(K::TornWrite, 1, WRONG_HASH_A5, "alice", "wrong digest")
        .unwrap();
    let fx = trailing_fixture();
    let report = report_of(vec![fx.path.clone()], v);
    let expected = vec![
        unlocated(
            K::AcceptUnused,
            Some(1),
            format!("accept TornWrite seq 1 hash {WRONG_HASH_A5_DIGEST}: no matching warning"),
        ),
        base_torn_write(&fx.path),
    ];
    assert_findings(report.findings(), &expected, "r1b");
    assert!(!report.is_strict_valid(), "r1b strict fails");
}

// =====================================================================
// (ADR-0005 decision 11 l.977-983): the trailing-fragment trail opened again
// (the next write seals the fragment with a `repaired=<digest>`
// checkpoint): the trailing `TornWrite` becomes `TornWriteRepaired`,
// the old `accept TornWrite` line is `AcceptUnused`, and `--strict`
// passes.
// =====================================================================
#[test]
fn r2_repaired_fragment_leaves_accept_unused_strict_passes() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let cp1 = signed_cp(1, cp0.hash(), &seeded(&cp0));
    let gap_bytes: &[u8] = b"{\n";
    let gap_digest = {
        let mut h = gap_hasher();
        h.update(gap_bytes);
        *h.finalize().as_bytes()
    };
    let mmr1 = pushed(&seeded(&cp0), &cp1);
    let cp2 = cp_with_repair(2, cp1.hash(), &mmr1, gap_digest);
    let mut seg = line_bytes(&cp0);
    seg.extend(line_bytes(&cp1));
    seg.extend_from_slice(gap_bytes);
    seg.extend(line_bytes(&cp2));
    let seg_path = segment_path(&d.0, 0);
    std::fs::write(&seg_path, seg).unwrap();
    let v = verifier()
        .accept(K::TornWrite, 1, FRAG_DIGEST_BYTES, "alice", "reviewed")
        .unwrap();
    let report = report_of(vec![d.0.clone()], v);
    let expected = vec![
        unlocated(
            K::AcceptUnused,
            Some(1),
            format!("accept TornWrite seq 1 hash {FRAG_DIGEST}: no matching warning"),
        ),
        Finding::new(
            K::TornWriteRepaired,
            Some(seg_path),
            Some(3),
            Some(2),
            "lines 3..=3 (2 bytes), attested at line 4 seq 2".to_owned(),
        ),
    ];
    assert_findings(report.findings(), &expected, "r2");
    assert!(report.is_strict_valid(), "r2 strict passes");
}

// =====================================================================
// split into two rows so each ADR-pin case passes `--strict`
// on its own clean scenario (no incidental error findings).
// : an `accept ClockWentBackwards` matching a warning record
// promotes it to `Accepted` and `--strict` passes.
// =====================================================================
#[test]
fn r3a_clock_backwards_accept_match_gives_accepted_strict_passes() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    // ClockWentBackwards at seq 1: time 50 < cp0.time 100.
    let e1_clock = Record::new(
        RecordContext::new(TRAIL, 1, 50, "test", cp0.hash()),
        Entry::new("actor", "change", "object"),
    )
    .unwrap();
    let mmr1 = pushed(&seeded(&cp0), &e1_clock);
    let cp2 = signed_cp(2, e1_clock.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1_clock, &cp2], &[]);
    let seg = segment_path(&d.0, 0);
    let v = verifier()
        .accept(K::ClockWentBackwards, 1, e1_clock.hash(), "alice", "ok")
        .unwrap();
    let report = report_of(vec![d.0.clone()], v);
    let expected = vec![
        Finding::new(
            K::ClockWentBackwards,
            Some(seg),
            Some(2),
            Some(1),
            "expected time >= 100, found 50".to_owned(),
        )
        .accepted("alice", "ok"),
    ];
    assert_findings(report.findings(), &expected, "r3a");
    assert!(report.is_strict_valid(), "r3a strict passes");
}

// : an `accept Resumed` matching a writer-built resume line
// promotes it to `Accepted` and `--strict` passes.
fn resume_fixture() -> ResumeFx {
    let d = Temp::new();
    pre_seed(&d.0);
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let (trail_b, resume, _opening) = AuditConfig::new("svc")
        .dir(&d.0)
        .resume(signer(), (2, cp2.hash()), 5, "op", "r")
        .unwrap();
    drop(trail_b);
    ResumeFx {
        _dir: d.0.clone(),
        root: d,
        resume_hash: resume.hash(),
        resume_seq: resume.seq(),
        cp2_digest: digest_string(&cp2.hash()),
    }
}
struct ResumeFx {
    root: Temp,
    _dir: PathBuf,
    resume_hash: [u8; 32],
    resume_seq: u64,
    cp2_digest: String,
}
#[test]
fn r3b_resumed_accept_match_gives_accepted_strict_passes() {
    let fx = resume_fixture();
    let dir = fx.root.0.clone();
    let v = verifier()
        .accept(K::Resumed, fx.resume_seq, fx.resume_hash, "alice", "ok")
        .unwrap();
    let report = report_of(vec![dir.clone()], v);
    let live = dir.join("audit.jsonl");
    let detail = format!(
        "operator=op reason=r head=2:{} gap=3..=5 lost_records=0 structural=valid",
        fx.cp2_digest
    );
    let expected = vec![
        Finding::new(K::Resumed, Some(live), Some(2), Some(fx.resume_seq), detail)
            .accepted("alice", "ok"),
    ];
    assert_findings(report.findings(), &expected, "r3b");
    assert!(report.is_strict_valid(), "r3b strict passes");
}

// =====================================================================
// (ADR-0005 decision 11 l.977-983): an `accept` line at a `seq`
// whose record has a different hash on the verified trail is
// `AcceptMismatch` via the shared receipt match rule.
// =====================================================================
#[test]
fn r4_replaced_record_gives_accept_mismatch() {
    let fx = trailing_fixture();
    let cp1_text = digest_string(&fx.cp1_hash);
    let v = verifier()
        .accept(K::ClockWentBackwards, 1, WRONG_HASH_A5, "alice", "stale")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], v);
    let expected = vec![
        unlocated(
            K::AcceptMismatch,
            Some(1),
            format!(
                "accept ClockWentBackwards seq 1 hash {WRONG_HASH_A5_DIGEST}: \
                 hash differs (record {cp1_text})"
            ),
        ),
        base_torn_write(&fx.path),
    ];
    assert_findings(report.findings(), &expected, "r4");
}

// (rollback): the trail is rolled back below the line's `seq`
// so no record exists at `seq`, giving `AcceptMismatch "no record"`.
#[test]
fn r4b_rolled_back_record_gives_accept_mismatch() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    put_segment(&d.0, 0, &[&cp0], &[]);
    let v = verifier()
        .accept(K::Resumed, 5, WRONG_HASH_A5, "alice", "stale")
        .unwrap();
    let report = report_of(vec![d.0.clone()], v);
    let expected = vec![unlocated(
        K::AcceptMismatch,
        Some(5),
        format!("accept Resumed seq 5 hash {WRONG_HASH_A5_DIGEST}: no record"),
    )];
    assert_findings(report.findings(), &expected, "r4b");
}

// (hash-differs on DuplicateRecord): a duplicated record
// whose accept carries a wrong hash is `AcceptMismatch via hash
// differs`.
#[test]
fn r4c_duplicate_record_wrong_hash_gives_accept_mismatch() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&seeded(&cp0), &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let shipped = d.0.join("audit-shipped.jsonl");
    let mut bytes = line_bytes(&e1);
    bytes.extend(line_bytes(&e1));
    std::fs::write(&shipped, bytes).unwrap();
    let v = verifier()
        .accept(K::DuplicateRecord, 1, WRONG_HASH_A5, "alice", "stale")
        .unwrap();
    let report = report_of(vec![d.0.clone(), shipped], v);
    let seg = segment_path(&d.0, 0);
    let expected = vec![
        unlocated(
            K::AcceptMismatch,
            Some(1),
            format!(
                "accept DuplicateRecord seq 1 hash {WRONG_HASH_A5_DIGEST}: \
                 hash differs (record {E1_DIGEST})"
            ),
        ),
        Finding::new(
            K::DuplicateRecord,
            Some(seg),
            Some(2),
            Some(1),
            "3 copies of 1 distinct records".to_owned(),
        ),
    ];
    assert_findings(report.findings(), &expected, "r4c");
}

// =====================================================================
// (ADR-0005 decision 11 l.977-983): each registration pattern
// gives `InvalidConfig` at the builder call, with the exact
// message pinned.
// =====================================================================
fn expect_invalid(err: &AuditError, msg: &str) {
    assert_eq!(err.kind(), AuditErrorKind::InvalidConfig, "{err}");
    assert_eq!(err.to_string(), format!("InvalidConfig: {msg}"));
}
#[test]
fn r5a_error_kind_gives_invalid_config() {
    let err = verifier()
        .accept(K::NoReceipt, 1, FRAG_DIGEST_BYTES, "alice", "r")
        .unwrap_err();
    expect_invalid(&err, "accept kind NoReceipt is not acceptable");
}
#[test]
fn r5a2_info_kind_gives_invalid_config() {
    let err = verifier()
        .accept(K::UncoveredTail, 1, FRAG_DIGEST_BYTES, "alice", "r")
        .unwrap_err();
    expect_invalid(&err, "accept kind UncoveredTail is not acceptable");
}
#[test]
fn r5a3_accepted_kind_gives_invalid_config() {
    let err = verifier()
        .accept(K::Accepted, 1, FRAG_DIGEST_BYTES, "alice", "r")
        .unwrap_err();
    expect_invalid(&err, "accept kind Accepted is not acceptable");
}
#[test]
fn r5b_empty_by_gives_invalid_config() {
    let err = verifier()
        .accept(K::TornWrite, 1, FRAG_DIGEST_BYTES, "", "r")
        .unwrap_err();
    expect_invalid(
        &err,
        "accept by must be a single token (no whitespace or control bytes)",
    );
}
#[test]
fn r5c_space_in_by_gives_invalid_config() {
    let err = verifier()
        .accept(K::TornWrite, 1, FRAG_DIGEST_BYTES, "al ice", "r")
        .unwrap_err();
    expect_invalid(
        &err,
        "accept by must be a single token (no whitespace or control bytes)",
    );
}
// Second whitespace form (tab).
#[test]
fn r5c2_tab_in_by_gives_invalid_config() {
    let err = verifier()
        .accept(K::TornWrite, 1, FRAG_DIGEST_BYTES, "al\tice", "r")
        .unwrap_err();
    expect_invalid(
        &err,
        "accept by must be a single token (no whitespace or control bytes)",
    );
}
#[test]
fn r5d_empty_reason_gives_invalid_config() {
    let err = verifier()
        .accept(K::TornWrite, 1, FRAG_DIGEST_BYTES, "alice", "")
        .unwrap_err();
    expect_invalid(
        &err,
        "accept reason must be a non-empty single line (no LF or CR)",
    );
}
#[test]
fn r5e_duplicate_kind_and_seq_gives_invalid_config() {
    let v = verifier()
        .accept(K::TornWrite, 1, FRAG_DIGEST_BYTES, "alice", "r")
        .unwrap();
    let err = v
        .accept(K::TornWrite, 1, FRAG_DIGEST_BYTES, "bob", "r2")
        .unwrap_err();
    expect_invalid(&err, "duplicate accept for TornWrite seq 1");
}
#[test]
fn r5e2_duplicate_resumed_gives_invalid_config() {
    let v = verifier()
        .accept(K::Resumed, 3, [1u8; 32], "alice", "r")
        .unwrap();
    let err = v.accept(K::Resumed, 3, [2u8; 32], "bob", "r2").unwrap_err();
    expect_invalid(&err, "duplicate accept for Resumed seq 3");
}

// =====================================================================
// (ADR-0005 decision 11 l.977-983): an `accept` line below an
// accepted start goes through the shared position classifier.
// =====================================================================
fn start_cp2_layout() -> (Temp, Checkpoint) {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&seeded(&cp0), &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d.0, 2, &[&cp2], &[]);
    let start = parse_cp(&cp2);
    (d, start)
}
#[test]
fn r6a_accept_below_unanchored_start_gives_unanchored_start() {
    let (d, start) = start_cp2_layout();
    let v = verifier()
        .start_from(start)
        .accept(K::Resumed, 1, [0u8; 32], "alice", "below")
        .unwrap();
    let report = report_of(vec![d.0.clone()], v);
    let hash_text = digest_string(&[0u8; 32]);
    let expected = vec![unlocated(
        K::UnanchoredStart,
        Some(1),
        format!("accept Resumed seq 1 hash {hash_text}: below start seq 2"),
    )];
    assert_findings(report.findings(), &expected, "r6a");
}
#[test]
fn r6b_accept_below_anchored_start_gives_out_of_range() {
    let (d, start) = start_cp2_layout();
    let anchor = start.clone();
    let v = verifier()
        .start_from(start)
        .anchor(anchor)
        .accept(K::Resumed, 1, [0u8; 32], "alice", "below")
        .unwrap();
    let report = report_of(vec![d.0.clone()], v);
    let hash_text = digest_string(&[0u8; 32]);
    let expected = vec![unlocated(
        K::OutOfRange,
        Some(1),
        format!("accept Resumed seq 1 hash {hash_text}: below start seq 2"),
    )];
    assert_findings(report.findings(), &expected, "r6b");
}

// =====================================================================
// (ADR-0005 decision 11 l.977-983): a line delivered three
// times yields one `DuplicateRecord` warning at that `seq`; an
// `accept DuplicateRecord` matching it promotes it to `Accepted`
// and `--strict` passes.
// =====================================================================
#[test]
fn r7_duplicate_record_accept_match_gives_accepted_strict_passes() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&seeded(&cp0), &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let shipped = d.0.join("audit-shipped.jsonl");
    let mut bytes = line_bytes(&e1);
    bytes.extend(line_bytes(&e1));
    std::fs::write(&shipped, bytes).unwrap();
    let v = verifier()
        .accept(K::DuplicateRecord, 1, e1.hash(), "alice", "collector")
        .unwrap();
    let report = report_of(vec![d.0.clone(), shipped.clone()], v);
    let expected = vec![
        Finding::new(
            K::DuplicateRecord,
            Some(segment_path(&d.0, 0)),
            Some(2),
            Some(1),
            "3 copies of 1 distinct records".to_owned(),
        )
        .accepted("alice", "collector"),
    ];
    assert_findings(report.findings(), &expected, "r7");
    assert!(report.is_strict_valid(), "r7 strict passes");
}

// =====================================================================
// (ADR-0005 decision 11 l.977-983): an `accept TornWrite`
// naming a `seq` with no record on the verified trail is
// `AcceptMismatch` through the shared receipt match rule's
// "no record" branch.
// =====================================================================
#[test]
fn r8_accept_torn_write_at_seq_with_no_record_gives_accept_mismatch() {
    let v = verifier()
        .accept(K::TornWrite, 99, FRAG_DIGEST_BYTES, "alice", "r")
        .unwrap();
    let fx = trailing_fixture();
    let report = report_of(vec![fx.path.clone()], v);
    let expected = vec![
        unlocated(
            K::AcceptMismatch,
            Some(99),
            format!("accept TornWrite seq 99 hash {FRAG_DIGEST}: no record"),
        ),
        base_torn_write(&fx.path),
    ];
    assert_findings(report.findings(), &expected, "r8");
}

// =====================================================================
// (ADR-0005 decision 11 l.977-983): an `accept TornWrite`
// matching a gap marked "no crash outcome" is `AcceptMismatch`.
// =====================================================================
#[test]
fn r9_accept_torn_write_on_no_crash_gap_gives_accept_mismatch() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    put_segment(&d.0, 0, &[&cp0], FRAG_TAIL);
    let cp1 = signed_cp(1, cp0.hash(), &seeded(&cp0));
    put_segment(&d.0, 1, &[&cp1], &[]);
    let v = verifier()
        .accept(K::TornWrite, 0, FRAG_DIGEST_BYTES, "alice", "r")
        .unwrap();
    let report = report_of(vec![d.0.clone()], v);
    let expected = vec![
        unlocated(
            K::AcceptMismatch,
            Some(0),
            format!("accept TornWrite seq 0 hash {FRAG_DIGEST}: no crash outcome"),
        ),
        Finding::new(
            K::TornWrite,
            Some(segment_path(&d.0, 0)),
            Some(2),
            None,
            format!("trailing gap lines 2..=2 (1 bytes), digest {FRAG_DIGEST}; no crash outcome"),
        ),
    ];
    assert_findings(report.findings(), &expected, "r9");
}

// : the same no-crash gap with a wrong digest is `AcceptUnused`
// (the pin hash check blocks the match before the no-crash test).
#[test]
fn r9b_accept_torn_write_wrong_digest_on_no_crash_gap_gives_accept_unused() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    put_segment(&d.0, 0, &[&cp0], FRAG_TAIL);
    let cp1 = signed_cp(1, cp0.hash(), &seeded(&cp0));
    put_segment(&d.0, 1, &[&cp1], &[]);
    let v = verifier()
        .accept(K::TornWrite, 0, WRONG_HASH_A5, "alice", "r")
        .unwrap();
    let report = report_of(vec![d.0.clone()], v);
    let expected = vec![
        unlocated(
            K::AcceptUnused,
            Some(0),
            format!("accept TornWrite seq 0 hash {WRONG_HASH_A5_DIGEST}: no matching warning"),
        ),
        Finding::new(
            K::TornWrite,
            Some(segment_path(&d.0, 0)),
            Some(2),
            None,
            format!("trailing gap lines 2..=2 (1 bytes), digest {FRAG_DIGEST}; no crash outcome"),
        ),
    ];
    assert_findings(report.findings(), &expected, "r9b");
}

// : a second no-crash layout pinning the closing record's `seq`.
#[test]
fn r9c_accept_torn_write_second_no_crash_gives_accept_mismatch() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let cp1 = signed_cp(1, cp0.hash(), &seeded(&cp0));
    let mut seg0 = line_bytes(&cp0);
    seg0.extend(line_bytes(&cp1));
    seg0.extend_from_slice(FRAG_TAIL);
    std::fs::write(segment_path(&d.0, 0), seg0).unwrap();
    let mmr1 = pushed(&seeded(&cp0), &cp1);
    let cp2 = signed_cp(2, cp1.hash(), &mmr1);
    put_segment(&d.0, 1, &[&cp2], &[]);
    let v = verifier()
        .accept(K::TornWrite, 1, FRAG_DIGEST_BYTES, "alice", "r")
        .unwrap();
    let report = report_of(vec![d.0.clone()], v);
    let expected = vec![
        unlocated(
            K::AcceptMismatch,
            Some(1),
            format!("accept TornWrite seq 1 hash {FRAG_DIGEST}: no crash outcome"),
        ),
        Finding::new(
            K::TornWrite,
            Some(segment_path(&d.0, 0)),
            Some(3),
            None,
            format!("trailing gap lines 3..=3 (1 bytes), digest {FRAG_DIGEST}; no crash outcome"),
        ),
    ];
    assert_findings(report.findings(), &expected, "r9c");
}

// =====================================================================
// (ADR-0005 decision 11 l.977-983): an `accept` line at a
// forked `seq` is `AcceptMismatch "… seq is forked"` through the
// shared match rule (ruling 13-V8-d1 point 6).
// =====================================================================
#[test]
fn r10_accept_at_forked_seq_gives_accept_mismatch() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    let e1_alt = Record::new(
        RecordContext::new(TRAIL, 1, 101, "test", cp0.hash()),
        Entry::new("other", "change", "object"),
    )
    .unwrap();
    put_segment(&d.0, 0, &[&cp0, &e1], &[]);
    let shipped = d.0.join("shipped.jsonl");
    std::fs::write(&shipped, line_bytes(&e1_alt)).unwrap();
    let v = verifier()
        .accept(K::Resumed, 1, e1.hash(), "alice", "r")
        .unwrap();
    let report = report_of(vec![d.0.clone(), shipped], v);
    let e1_text = digest_string(&e1.hash());
    let e1_alt_text = digest_string(&e1_alt.hash());
    let seg = segment_path(&d.0, 0);
    let expected = vec![
        unlocated(
            K::AcceptMismatch,
            Some(1),
            format!("accept Resumed seq 1 hash {e1_text}: seq is forked"),
        ),
        Finding::new(
            K::SeqConflict,
            Some(seg),
            Some(2),
            Some(1),
            format!("conflicting hashes: {e1_text}, {e1_alt_text}"),
        ),
        unlocated(K::UncoveredTail, None, "records seq 1..=1".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "r10");
}

// : same forked `seq` with an `accept DuplicateRecord` -- the
// shared match rule's fork check fires regardless of kind.
#[test]
fn r10b_accept_duplicate_at_forked_seq_gives_accept_mismatch() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    let e1_alt = Record::new(
        RecordContext::new(TRAIL, 1, 101, "test", cp0.hash()),
        Entry::new("other", "change", "object"),
    )
    .unwrap();
    put_segment(&d.0, 0, &[&cp0, &e1], &[]);
    let shipped = d.0.join("shipped.jsonl");
    std::fs::write(&shipped, line_bytes(&e1_alt)).unwrap();
    let v = verifier()
        .accept(K::DuplicateRecord, 1, e1.hash(), "alice", "r")
        .unwrap();
    let report = report_of(vec![d.0.clone(), shipped], v);
    let e1_text = digest_string(&e1.hash());
    let e1_alt_text = digest_string(&e1_alt.hash());
    let seg = segment_path(&d.0, 0);
    let expected = vec![
        unlocated(
            K::AcceptMismatch,
            Some(1),
            format!("accept DuplicateRecord seq 1 hash {e1_text}: seq is forked"),
        ),
        Finding::new(
            K::SeqConflict,
            Some(seg),
            Some(2),
            Some(1),
            format!("conflicting hashes: {e1_text}, {e1_alt_text}"),
        ),
        unlocated(K::UncoveredTail, None, "records seq 1..=1".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "r10b");
}

// =====================================================================
// (ruling 13-V8-d1 FORK 3): a trailing `TornWrite` with no
// record before the gap in its file (file-start gap) carries
// pin `seq = None` and no `accept TornWrite` line can match. A
// line naming it stays `AcceptMismatch "no record"` and the
// warning stays.
// =====================================================================
#[test]
fn r11_torn_write_with_no_record_before_gap_cannot_be_accepted() {
    let d = Temp::new();
    std::fs::write(segment_path(&d.0, 0), FRAG_TAIL).unwrap();
    let v = verifier()
        .accept(K::TornWrite, 0, FRAG_DIGEST_BYTES, "alice", "r")
        .unwrap();
    let report = report_of(vec![d.0.clone()], v);
    let seg = segment_path(&d.0, 0);
    let expected = vec![
        unlocated(
            K::AcceptMismatch,
            Some(0),
            format!("accept TornWrite seq 0 hash {FRAG_DIGEST}: no record"),
        ),
        Finding::new(
            K::SegmentStructure,
            Some(seg.clone()),
            None,
            None,
            "expected first complete record to be a checkpoint".into(),
        ),
        Finding::new(
            K::TornWrite,
            Some(seg),
            Some(1),
            None,
            format!("trailing gap lines 1..=1 (1 bytes), digest {FRAG_DIGEST}"),
        ),
    ];
    assert_findings(report.findings(), &expected, "r11");
}

// =====================================================================
// (ruling 13-V8-d1 point 3): `Accepted` keeps the original
// location and `seq`, and its detail is exact. Asserts non-`None`
// location fields that r1a does not.
// =====================================================================
#[test]
fn r12_accepted_finding_keeps_location_and_detail() {
    let fx = trailing_fixture();
    let v = verifier()
        .accept(K::TornWrite, 1, FRAG_DIGEST_BYTES, "alice", "reviewed")
        .unwrap();
    let report = report_of(vec![fx.path.clone()], v);
    let expected = vec![base_torn_write(&fx.path).accepted("alice", "reviewed")];
    assert_findings(report.findings(), &expected, "r12");
    let a = &report.findings()[0];
    assert_eq!(a.kind(), K::Accepted);
    assert_eq!(a.accepted_kind(), Some(K::TornWrite));
    assert_eq!(a.file(), Some(fx.path.as_path()));
    assert_eq!(a.line(), Some(3));
    assert_eq!(a.seq(), None);
    assert_eq!(
        a.detail(),
        format!(
            "accepted by alice: reviewed; was: trailing gap lines 3..=3 (1 bytes), digest {FRAG_DIGEST}"
        )
    );
}

// =====================================================================
// (ADR-0005 decision 5 "Receipts lost with a resume"; ruling
// 13-V8-d1 point 8): a receipt confirms a resume gap and an
// `accept` line inside the gap is one unlocated `LostRecord` that
// the `Resumed` detail counts as `lost_records=1`.
// =====================================================================
fn confirmed_gap_fixture() -> ConfirmedGap {
    let d = Temp::new();
    pre_seed(&d.0);
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let (trail_b, resume, _opening) = AuditConfig::new("svc")
        .dir(&d.0)
        .resume(signer(), (2, cp2.hash()), 5, "op", "r")
        .unwrap();
    drop(trail_b);
    ConfirmedGap {
        root: d,
        resume_hash: resume.hash(),
        resume_seq: resume.seq(),
        cp2_digest: digest_string(&cp2.hash()),
        e1_hash: e1.hash(),
    }
}
struct ConfirmedGap {
    root: Temp,
    resume_hash: [u8; 32],
    resume_seq: u64,
    cp2_digest: String,
    e1_hash: [u8; 32],
}
#[test]
fn r13_accept_inside_confirmed_gap_gives_lost_record_counted() {
    let fx = confirmed_gap_fixture();
    let dir = fx.root.0.clone();
    let v = verifier()
        .receipts([(1, fx.e1_hash), (fx.resume_seq, fx.resume_hash)])
        .accept(K::DuplicateRecord, 4, [0x11u8; 32], "alice", "lost")
        .unwrap();
    let report = report_of(vec![dir.clone()], v);
    let hash_text = digest_string(&[0x11u8; 32]);
    let lost_detail = format!("accept DuplicateRecord seq 4 hash {hash_text}: lost in gap 3..=5");
    let resumed_detail = format!(
        "operator=op reason=r head=2:{} gap=3..=5 lost_records=1 structural=valid",
        fx.cp2_digest
    );
    let expected = vec![
        unlocated(K::LostRecord, Some(4), lost_detail),
        Finding::new(
            K::Resumed,
            Some(dir.join("audit.jsonl")),
            Some(2),
            Some(fx.resume_seq),
            resumed_detail,
        ),
    ];
    assert_findings(report.findings(), &expected, "r13");
}
// : same scenario with `accept ClockWentBackwards` instead.
#[test]
fn r13b_accept_clock_inside_confirmed_gap_gives_lost_record_counted() {
    let fx = confirmed_gap_fixture();
    let dir = fx.root.0.clone();
    let v = verifier()
        .receipts([(1, fx.e1_hash), (fx.resume_seq, fx.resume_hash)])
        .accept(K::ClockWentBackwards, 3, [0x22u8; 32], "alice", "lost")
        .unwrap();
    let report = report_of(vec![dir.clone()], v);
    let hash_text = digest_string(&[0x22u8; 32]);
    let lost_detail =
        format!("accept ClockWentBackwards seq 3 hash {hash_text}: lost in gap 3..=5");
    let resumed_detail = format!(
        "operator=op reason=r head=2:{} gap=3..=5 lost_records=1 structural=valid",
        fx.cp2_digest
    );
    let expected = vec![
        unlocated(K::LostRecord, Some(3), lost_detail),
        Finding::new(
            K::Resumed,
            Some(dir.join("audit.jsonl")),
            Some(2),
            Some(fx.resume_seq),
            resumed_detail,
        ),
    ];
    assert_findings(report.findings(), &expected, "r13b");
}

// =====================================================================
// (ruling 13-V8-d1 point 5): an attested-but-uncovered
// (non-trailing) `TornWrite` has no pin, so any
// `accept TornWrite` line stays `AcceptUnused` (or
// `AcceptMismatch` when the shared match rule routes it).
// =====================================================================
fn attested_torn_write_fixture() -> AttestedTw {
    // Build a layout where an in-segment gap is attested by a
    // checkpoint but the gap stays `TornWrite` (not
    // `TornWriteRepaired`) because its `seq` is forked: a shipped
    // copy of the attester at a different hash puts the attester's
    // `seq` into the fork set, blocking promotion.
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let cp1 = signed_cp(1, cp0.hash(), &seeded(&cp0));
    let gap_bytes: &[u8] = b"{\n";
    let gap_digest = {
        let mut h = gap_hasher();
        h.update(gap_bytes);
        *h.finalize().as_bytes()
    };
    let mmr1 = pushed(&seeded(&cp0), &cp1);
    let cp2 = cp_with_repair(2, cp1.hash(), &mmr1, gap_digest);
    let mut seg = line_bytes(&cp0);
    seg.extend(line_bytes(&cp1));
    seg.extend_from_slice(gap_bytes);
    seg.extend(line_bytes(&cp2));
    std::fs::write(segment_path(&d.0, 0), seg).unwrap();
    // Forked copy at seq 2 blocks `TornWriteRepaired` promotion.
    let e2_alt = Record::new(
        RecordContext::new(TRAIL, 2, 200, "test", cp1.hash()),
        Entry::new("other", "change", "object"),
    )
    .unwrap();
    let shipped = d.0.join("shipped.jsonl");
    std::fs::write(&shipped, line_bytes(&e2_alt)).unwrap();
    AttestedTw {
        _dir: d,
        shipped,
        gap_digest,
    }
}
struct AttestedTw {
    _dir: Temp,
    shipped: PathBuf,
    gap_digest: [u8; 32],
}
#[test]
fn r14_accept_torn_write_on_non_trailing_gap_gives_accept_unused_or_mismatch() {
    let fx = attested_torn_write_fixture();
    let dir = fx._dir.0.clone();
    let v = verifier()
        // Pin the attester's seq + the gap digest. The non-trailing
        // TornWrite has no side-map pin, so this never promotes.
        .accept(K::TornWrite, 2, fx.gap_digest, "alice", "r")
        .unwrap();
    let report = report_of(vec![dir, fx.shipped], v);
    assert!(
        report
            .findings()
            .iter()
            .any(|f| matches!(f.kind(), K::AcceptUnused | K::AcceptMismatch) && f.seq() == Some(2)),
        "r14 accept line stays unused or mismatched: {:?}",
        report.findings()
    );
    assert!(
        report.findings().iter().any(|f| f.kind() == K::TornWrite),
        "r14 non-trailing TornWrite remains: {:?}",
        report.findings()
    );
}
// : non-trailing TornWrite via a different attester `seq`.
#[test]
fn r14b_accept_torn_write_on_non_trailing_second_layout() {
    // Same shape as the row but with the gap pinned at a different
    // `seq` (attester at seq 3) so the pin seq differs.
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let cp1 = signed_cp(1, cp0.hash(), &seeded(&cp0));
    let e2 = entry_rec(2, cp1.hash());
    let gap_bytes: &[u8] = b"{\n";
    let gap_digest = {
        let mut h = gap_hasher();
        h.update(gap_bytes);
        *h.finalize().as_bytes()
    };
    let mmr1 = pushed(&seeded(&cp0), &cp1);
    let mmr2 = pushed(&mmr1, &e2);
    let cp3 = cp_with_repair(3, e2.hash(), &mmr2, gap_digest);
    let mut seg = line_bytes(&cp0);
    seg.extend(line_bytes(&cp1));
    seg.extend(line_bytes(&e2));
    seg.extend_from_slice(gap_bytes);
    seg.extend(line_bytes(&cp3));
    std::fs::write(segment_path(&d.0, 0), seg).unwrap();
    // Forked seq 3 blocks TornWriteRepaired.
    let cp3_alt = signed_cp(3, cp1.hash(), &mmr1);
    let shipped = d.0.join("shipped.jsonl");
    std::fs::write(&shipped, line_bytes(&cp3_alt)).unwrap();
    let v = verifier()
        .accept(K::TornWrite, 3, gap_digest, "alice", "r")
        .unwrap();
    let report = report_of(vec![d.0.clone(), shipped], v);
    assert!(
        report
            .findings()
            .iter()
            .any(|f| matches!(f.kind(), K::AcceptUnused | K::AcceptMismatch) && f.seq() == Some(3)),
        "r14b accept line stays unused or mismatched: {:?}",
        report.findings()
    );
    assert!(
        report.findings().iter().any(|f| f.kind() == K::TornWrite),
        "r14b non-trailing TornWrite remains: {:?}",
        report.findings()
    );
}
