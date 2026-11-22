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
    AuditConfig, AuditError, AuditErrorKind, Checkpoint, Entry, FindingKind as K, KeyFileSigner,
    Mmr, Record, RecordContext, Signer, TrustPolicy, digest_string, gap_hasher, hex,
    runs_v4a_fixtures::{
        TRAIL, Temp, context, entry_rec, fixture_pubkey, line_bytes, pushed, put_segment, seeded,
        segment_path, signed_cp,
    },
};
use std::{
    io::Write,
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
const FRAG_DIGEST_BYTES: [u8; 32] = hex_to_bytes(FRAG_DIGEST_HEX);

/// `gap_hasher().update(b"{\n").finalize()` -- the gap digest the
/// `open`-driven repair prepends (fragment + LF) in r2.
const REPAIR_LF_DIGEST_HEX: &str =
    "38248ab7321962bbd336f61fda853759e20457cba575b3857046f3057de76add";
const REPAIR_LF_DIGEST: &str =
    "blake3:38248ab7321962bbd336f61fda853759e20457cba575b3857046f3057de76add";
const REPAIR_LF_DIGEST_BYTES: [u8; 32] = hex_to_bytes(REPAIR_LF_DIGEST_HEX);

/// `gap_hasher().update(b"not json\n{").finalize()` -- the gap
/// digest for the `Unparsable` + trailing fragment layout in r15b.
const UNPARSABLE_GAP_DIGEST_HEX: &str =
    "2d1c223259971411c7c7c9b9f4dee83cb9ea7e6ee56e478e60d44159bd460058";
const UNPARSABLE_GAP_DIGEST: &str =
    "blake3:2d1c223259971411c7c7c9b9f4dee83cb9ea7e6ee56e478e60d44159bd460058";
const UNPARSABLE_GAP_DIGEST_BYTES: [u8; 32] = hex_to_bytes(UNPARSABLE_GAP_DIGEST_HEX);

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
    let repair_lf = {
        let mut h = gap_hasher();
        h.update(b"{\n");
        *h.finalize().as_bytes()
    };
    assert_eq!(digest_string(&repair_lf), REPAIR_LF_DIGEST, "repair_lf");
    assert_eq!(REPAIR_LF_DIGEST_BYTES, repair_lf, "repair_lf const bytes");
    let unparsable_gap = {
        let mut h = gap_hasher();
        h.update(b"not json\n{");
        *h.finalize().as_bytes()
    };
    assert_eq!(
        digest_string(&unparsable_gap),
        UNPARSABLE_GAP_DIGEST,
        "unparsable_gap",
    );
    assert_eq!(
        UNPARSABLE_GAP_DIGEST_BYTES, unparsable_gap,
        "unparsable_gap const bytes",
    );
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

/// Builds an `Accepted` finding from literal fields without going
/// through [`Finding::accepted`], so the rows that assert the
/// promoted shape do not funnel the expected value through the code
/// under test.
fn literal_accepted(
    file: Option<PathBuf>,
    line: Option<u64>,
    seq: Option<u64>,
    detail: String,
    original: K,
) -> Finding {
    Finding::new(K::Accepted, file, line, seq, detail).with_accepted_kind(original)
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
    let expected = vec![literal_accepted(
        Some(fx.path.clone()),
        Some(3),
        None,
        format!(
            "accepted by alice: reviewed; was: \
             trailing gap lines 3..=3 (1 bytes), digest {FRAG_DIGEST}"
        ),
        K::TornWrite,
    )];
    assert_findings(report.findings(), &expected, "r1a");
    assert!(report.is_strict_valid(), "r1a strict passes");
}

// An `accept TornWrite` naming the correct `seq` but another gap
// digest leaves the `TornWrite` warning and emits one unlocated
// `AcceptUnused`; `--strict` still fails.
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
// (ADR-0005 decision 11 l.977-983): the trailing-fragment trail
// built by the real writer and reopened (`create` -> `record` ->
// `close` -> append a one-byte fragment to the live file -> `open`
// -> `close`): the trailing `TornWrite` becomes `TornWriteRepaired`
// at the opening checkpoint's seq, the old `accept TornWrite` line
// is `AcceptUnused`, and `--strict` passes.
// =====================================================================
#[test]
fn r2_repaired_fragment_leaves_accept_unused_strict_passes() {
    let d = Temp::new();
    // create -> record -> close.
    let trail = AuditConfig::new("svc").dir(&d.0).create(signer()).unwrap();
    let trail_id = trail.trail();
    trail
        .record(&Entry::new("actor", "change", "object"))
        .unwrap();
    trail.close().unwrap();
    // Append `{` to the live file so open sees a torn write.
    let live = d.0.join("audit.jsonl");
    std::fs::OpenOptions::new()
        .append(true)
        .open(&live)
        .unwrap()
        .write_all(b"{")
        .unwrap();
    // open -> close. `open` prepends a repair LF, then writes the
    // opening checkpoint with `repaired = gap_hasher(&`{\n`)` =
    // `REPAIR_LF_DIGEST_BYTES`.
    AuditConfig::new("svc")
        .dir(&d.0)
        .open(signer())
        .unwrap()
        .close()
        .unwrap();
    let trust = TrustPolicy::builder()
        .trail(trail_id)
        .key(fixture_pubkey())
        .build()
        .unwrap();
    let v = Verifier::new(trust)
        .accept(K::TornWrite, 2, REPAIR_LF_DIGEST_BYTES, "alice", "reviewed")
        .unwrap();
    let report = report_of(vec![d.0.clone()], v);
    let expected = vec![
        unlocated(
            K::AcceptUnused,
            Some(2),
            format!("accept TornWrite seq 2 hash {REPAIR_LF_DIGEST}: no matching warning"),
        ),
        Finding::new(
            K::TornWriteRepaired,
            Some(live),
            Some(4),
            Some(3),
            "lines 4..=4 (2 bytes), attested at line 5 seq 3".to_owned(),
        ),
    ];
    assert_findings(report.findings(), &expected, "r2");
    assert!(report.is_strict_valid(), "r2 strict passes");
}

// =====================================================================
// (ADR-0005 decision 11 l.977-983): two rows so each pin case
// passes `--strict` on its own clean scenario (no incidental error
// findings). An `accept ClockWentBackwards` matching a warning
// record promotes it to `Accepted` and `--strict` passes.
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
    let expected = vec![literal_accepted(
        Some(seg),
        Some(2),
        Some(1),
        "accepted by alice: ok; was: expected time >= 100, found 50".to_owned(),
        K::ClockWentBackwards,
    )];
    assert_findings(report.findings(), &expected, "r3a");
    assert!(report.is_strict_valid(), "r3a strict passes");
}

// An `accept Resumed` matching a writer-built resume line
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
        "accepted by alice: ok; was: operator=op reason=r head=2:{} \
         gap=3..=5 lost_records=0 structural=valid",
        fx.cp2_digest
    );
    let expected = vec![literal_accepted(
        Some(live),
        Some(2),
        Some(fx.resume_seq),
        detail,
        K::Resumed,
    )];
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
// Second non-acceptable error kind so the non-acceptable-kind
// clause has more than one `InvalidConfig` row.
#[test]
fn r5a4_chain_broken_kind_gives_invalid_config() {
    let err = verifier()
        .accept(K::ChainBroken, 1, FRAG_DIGEST_BYTES, "alice", "r")
        .unwrap_err();
    expect_invalid(&err, "accept kind ChainBroken is not acceptable");
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
// Space in the token: whitespace that is not a control byte, so
// only the whitespace clause can reject it.
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
// Non-whitespace control byte in the token: only the control-byte
// clause can reject it.
#[test]
fn r5c3_control_byte_in_by_gives_invalid_config() {
    let err = verifier()
        .accept(K::TornWrite, 1, FRAG_DIGEST_BYTES, "a\x01b", "r")
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
// Reason with LF: the single-line clause rejects it.
#[test]
fn r5d_lf_in_reason_gives_invalid_config() {
    let err = verifier()
        .accept(K::TornWrite, 1, FRAG_DIGEST_BYTES, "alice", "ok\nmore")
        .unwrap_err();
    expect_invalid(
        &err,
        "accept reason must be a non-empty single line (no LF or CR)",
    );
}
// Reason with CR: the single-line clause rejects it.
#[test]
fn r5d_cr_in_reason_gives_invalid_config() {
    let err = verifier()
        .accept(K::TornWrite, 1, FRAG_DIGEST_BYTES, "alice", "ok\rmore")
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
    let expected = vec![literal_accepted(
        Some(segment_path(&d.0, 0)),
        Some(2),
        Some(1),
        "accepted by alice: collector; was: 3 copies of 1 distinct records".to_owned(),
        K::DuplicateRecord,
    )];
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

// The same no-crash gap with a wrong digest is `AcceptUnused`
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

// A second no-crash layout pinning the closing record's `seq`.
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

// Same forked `seq` with an `accept DuplicateRecord` -- the
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
// location and `seq`. Pins a kind whose warning carries a non-`None`
// `seq` (`ClockWentBackwards`), so the assertion covers file, line
// AND `seq` -- the fields r1a cannot pin because a `TornWrite`'s
// `seq` is `None`. The layout places the warning in a second
// segment, so the preserved file is segment 1 (not 0) and the line
// is 2 (not the first line of the trail).
// =====================================================================
#[test]
fn r12_accepted_finding_keeps_non_none_seq_file_and_line() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let cp1 = signed_cp(1, cp0.hash(), &seeded(&cp0));
    let mmr_01 = pushed(&seeded(&cp0), &cp1);
    put_segment(&d.0, 0, &[&cp0, &cp1], &[]);
    let cp2 = signed_cp(2, cp1.hash(), &mmr_01);
    // ClockWentBackwards at seq 3 (second line of segment 1):
    // time 50 < cp2.time 102.
    let e3_clock = Record::new(
        RecordContext::new(TRAIL, 3, 50, "test", cp2.hash()),
        Entry::new("actor", "change", "object"),
    )
    .unwrap();
    let mmr_0123 = pushed(&pushed(&mmr_01, &cp2), &e3_clock);
    let cp4 = signed_cp(4, e3_clock.hash(), &mmr_0123);
    put_segment(&d.0, 1, &[&cp2, &e3_clock, &cp4], &[]);
    let seg1 = segment_path(&d.0, 1);
    let v = verifier()
        .accept(K::ClockWentBackwards, 3, e3_clock.hash(), "alice", "ok")
        .unwrap();
    let report = report_of(vec![d.0.clone()], v);
    let expected = vec![literal_accepted(
        Some(seg1.clone()),
        Some(2),
        Some(3),
        "accepted by alice: ok; was: expected time >= 102, found 50".to_owned(),
        K::ClockWentBackwards,
    )];
    assert_findings(report.findings(), &expected, "r12");
    // The literal list already pins every field; these mirrors pin
    // the per-field non-`None` shape ruling 13-V8-d1 point 3 names.
    let a = &report.findings()[0];
    assert_eq!(a.kind(), K::Accepted);
    assert_eq!(a.accepted_kind(), Some(K::ClockWentBackwards));
    assert_eq!(a.file(), Some(seg1.as_path()));
    assert_eq!(a.line(), Some(2));
    assert_eq!(a.seq(), Some(3));
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
// Same scenario with `accept ClockWentBackwards` instead.
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
// (ruling 13-V8-d1 point 5): an attested, non-trailing `TornWrite`
// has no side-map pin. The fixture uses an entry attester with a
// repair digest that is beyond `covered_through`, so no fork is
// needed to keep the gap at `TornWrite`. Two `accept TornWrite`
// lines -- one pinned at the record before the gap (`s.after`) and
// one pinned at the attester's `seq` -- each stay `AcceptUnused`.
// =====================================================================
/// Entry record on `TRAIL` with a `repaired` digest. The gap is
/// attested but `e.seq` is beyond `covered_through`, so promotion
/// stays off the honest crash d11 shape without any fork.
fn entry_rec_with_repaired(seq: u64, previous: [u8; 32], repair: [u8; 32]) -> Record {
    let ctx = context(seq, previous).repaired(repair);
    Record::new(ctx, Entry::new("a", "change", "c")).unwrap()
}

#[test]
fn r14_accept_torn_write_on_non_trailing_gap_at_record_before_and_attester_stays_unused() {
    // Layout: `[cp0, {\n, e1(repaired)]`. cp0 covers seq 0 only;
    // e1 at seq 1 is beyond `covered_through = 0`, so the attested
    // gap stays `TornWrite`. s.after = 0 (cp0), attester seq = 1.
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let gap_bytes: &[u8] = b"{\n";
    let gap_digest = REPAIR_LF_DIGEST_BYTES;
    let e1 = entry_rec_with_repaired(1, cp0.hash(), gap_digest);
    let mut seg = line_bytes(&cp0);
    seg.extend_from_slice(gap_bytes);
    seg.extend(line_bytes(&e1));
    let seg_path = segment_path(&d.0, 0);
    std::fs::write(&seg_path, seg).unwrap();
    let v = verifier()
        .accept(K::TornWrite, 0, gap_digest, "alice", "r1")
        .unwrap()
        .accept(K::TornWrite, 1, gap_digest, "bob", "r2")
        .unwrap();
    let report = report_of(vec![d.0.clone()], v);
    let expected = vec![
        unlocated(
            K::AcceptUnused,
            Some(0),
            format!("accept TornWrite seq 0 hash {REPAIR_LF_DIGEST}: no matching warning"),
        ),
        unlocated(
            K::AcceptUnused,
            Some(1),
            format!("accept TornWrite seq 1 hash {REPAIR_LF_DIGEST}: no matching warning"),
        ),
        Finding::new(
            K::TornWrite,
            Some(seg_path),
            Some(2),
            Some(1),
            "lines 2..=2 (2 bytes), attested at line 3 seq 1".to_owned(),
        ),
        unlocated(K::UncoveredTail, None, "records seq 1..=1".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "r14");
}

// Same shape at a different position: `[cp0, cp1, {\n, e2(repaired)]`.
// s.after = 1 (cp1), attester seq = 2.
#[test]
fn r14b_accept_torn_write_on_non_trailing_gap_second_position_stays_unused() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let cp1 = signed_cp(1, cp0.hash(), &seeded(&cp0));
    let gap_bytes: &[u8] = b"{\n";
    let gap_digest = REPAIR_LF_DIGEST_BYTES;
    let e2 = entry_rec_with_repaired(2, cp1.hash(), gap_digest);
    let mut seg = line_bytes(&cp0);
    seg.extend(line_bytes(&cp1));
    seg.extend_from_slice(gap_bytes);
    seg.extend(line_bytes(&e2));
    let seg_path = segment_path(&d.0, 0);
    std::fs::write(&seg_path, seg).unwrap();
    let v = verifier()
        .accept(K::TornWrite, 1, gap_digest, "alice", "r1")
        .unwrap()
        .accept(K::TornWrite, 2, gap_digest, "bob", "r2")
        .unwrap();
    let report = report_of(vec![d.0.clone()], v);
    let expected = vec![
        unlocated(
            K::AcceptUnused,
            Some(1),
            format!("accept TornWrite seq 1 hash {REPAIR_LF_DIGEST}: no matching warning"),
        ),
        unlocated(
            K::AcceptUnused,
            Some(2),
            format!("accept TornWrite seq 2 hash {REPAIR_LF_DIGEST}: no matching warning"),
        ),
        Finding::new(
            K::TornWrite,
            Some(seg_path),
            Some(3),
            Some(2),
            "lines 3..=3 (2 bytes), attested at line 4 seq 2".to_owned(),
        ),
        unlocated(K::UncoveredTail, None, "records seq 2..=2".to_owned()),
    ];
    assert_findings(report.findings(), &expected, "r14b");
}

// =====================================================================
// (ruling 13-V8-d1 point 2): the `TornWrite` side-map pin is
// keyed by the finding's index, not by its position in the sorted
// report. A layout with another finding ahead of the trailing
// `TornWrite` in the insertion-order list makes the key
// observable: an `accept TornWrite` promotes the right finding.
// =====================================================================
#[test]
fn r15_accept_promotes_the_right_trailing_torn_write_when_two_segments_report() {
    // Two native segments, each with a trailing fragment. seg 0's
    // closing record is an entry (not a checkpoint), which drops
    // the `mark_no_crash` path, so both segments report a plain
    // `TornWrite`. The accept line names the second segment's pin.
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&seeded(&cp0), &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    put_segment(&d.0, 0, &[&cp0, &e1, &e2], FRAG_TAIL);
    let cp3 = signed_cp(3, e2.hash(), &mmr2);
    let cp4 = signed_cp(4, cp3.hash(), &pushed(&mmr2, &cp3));
    put_segment(&d.0, 1, &[&cp3, &cp4], FRAG_TAIL);
    let seg0 = segment_path(&d.0, 0);
    let seg1 = segment_path(&d.0, 1);
    let v = verifier()
        .accept(K::TornWrite, 4, FRAG_DIGEST_BYTES, "alice", "reviewed")
        .unwrap();
    let report = report_of(vec![d.0.clone()], v);
    let expected = vec![
        Finding::new(
            K::TornWrite,
            Some(seg0),
            Some(4),
            None,
            format!("trailing gap lines 4..=4 (1 bytes), digest {FRAG_DIGEST}"),
        ),
        literal_accepted(
            Some(seg1),
            Some(3),
            None,
            format!(
                "accepted by alice: reviewed; was: \
                 trailing gap lines 3..=3 (1 bytes), digest {FRAG_DIGEST}"
            ),
            K::TornWrite,
        ),
    ];
    assert_findings(report.findings(), &expected, "r15");
}

// Second layout: a single native segment with an `Unparsable`
// line before the trailing fragment. `file_findings` pushes the
// `Unparsable` finding first, then the trailing gap, so the pin's
// key points past the earlier finding and the `accept TornWrite`
// promotes the right one. The pin seq is the record before the
// `Unparsable` line, the last complete record in the file.
#[test]
fn r15b_accept_promotes_trailing_torn_write_past_an_earlier_finding() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    let mut seg = line_bytes(&cp0);
    seg.extend(line_bytes(&e1));
    // "not json\n" classifies as `Unparsable` (framing check in
    // `lines::classify`); the trailing `{` is the fragment that
    // flushes the trailing gap.
    let gap_bytes: Vec<u8> = {
        let mut v = b"not json\n".to_vec();
        v.extend_from_slice(FRAG_TAIL);
        v
    };
    seg.extend_from_slice(&gap_bytes);
    let seg_path = segment_path(&d.0, 0);
    std::fs::write(&seg_path, seg).unwrap();
    let gap_digest = UNPARSABLE_GAP_DIGEST_BYTES;
    let v = verifier()
        .accept(K::TornWrite, 1, gap_digest, "alice", "reviewed")
        .unwrap();
    let report = report_of(vec![d.0.clone()], v);
    let expected = vec![
        unlocated(K::UncoveredTail, None, "records seq 1..=1".to_owned()),
        literal_accepted(
            Some(seg_path.clone()),
            Some(3),
            None,
            format!(
                "accepted by alice: reviewed; was: \
                 trailing gap lines 3..=4 ({} bytes), digest {UNPARSABLE_GAP_DIGEST}",
                gap_bytes.len()
            ),
            K::TornWrite,
        ),
        Finding::new(
            K::Unparsable,
            Some(seg_path),
            Some(3),
            None,
            "CorruptTrail: Unparsable: invalid audit v1 OTLP line".to_owned(),
        ),
    ];
    assert_findings(report.findings(), &expected, "r15b");
}
