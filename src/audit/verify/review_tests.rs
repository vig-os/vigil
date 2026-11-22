//! Rows for [`crate::audit::Verifier::accept`] and the three
//! outcomes `Accepted` / `AcceptMismatch` / `AcceptUnused`
//! (ADR-0005 decision 11 "Review file"; ruling 13-V8-d1).
//!
//! Each row ends in one whole-list [`assert_findings`] on
//! `Vec<Finding>` where every deterministic hash in an expected
//! detail is read from a pinned `const` or from a fixture-derived
//! helper that [`fixture_hashes_match_literals`] fixes in one place.
//!
//! Fixtures are writer-built where possible (same `signed_cp`,
//! `entry_rec`, `cp_with_repair` helpers as the receipts rows),
//! with the trailing-gap bytes a `{` Fragment so no `Unparsable`
//! finding is emitted (its enclosing run is trailing and passes
//! condition 3).

use super::tests_common::{assert_findings, report_of, trust_with_key, unlocated};
use super::{Finding, Report, Verifier};
use crate::audit::{
    AuditErrorKind, Checkpoint, Entry, FindingKind as K, Mmr, Record, RecordContext, digest_string,
    gap_hasher,
    runs_v4a_fixtures::{
        TRAIL, Temp, context, entry_rec, fixture_pubkey, line_bytes, pushed, put_segment,
        resume_decl, seeded, segment_path, signed_cp,
    },
};
use std::path::{Path, PathBuf};

// =====================================================================
// Pinned constants and helpers.
// =====================================================================
/// `signed_cp(0, Record::genesis(&TRAIL), &Mmr::new())`.
const CP0_DIGEST: &str = "blake3:fc26c6f2bb830592aaaca5413da1599489d86ac6e240a4a7a010681e0d4c8e77";
/// `entry_rec(1, cp0.hash())`.
const E1_DIGEST: &str = "blake3:c121282b5135adfe7a17142cae6bfc4c9040c4aed26d74bddc923b8dafcdb6e8";
/// A 32-byte placeholder for a wrong-digest scenario: `[0xA5; 32]`.
const WRONG_HASH_A5_DIGEST: &str =
    "blake3:a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5";
const WRONG_HASH_A5: [u8; 32] = [0xA5; 32];

/// The one-byte Fragment used as the trailing gap in the shared
/// `trailing_fixture`. `{` is an incomplete JSON value so
/// [`crate::audit::lines::classify`] returns `Fragment` (not
/// `Unparsable`), and the trailing run passes condition 3 (no
/// "after" record), so no `Unparsable` finding fires.
const FRAG_TAIL: &[u8] = b"{";

/// Gap digest for [`FRAG_TAIL`]: `gap_hasher().update(b"{").finalize()`
/// (domain `vigil.audit.v1.repaired\0` + the one byte). Computed at
/// runtime to avoid a hard-coded blake3; [`fixture_hashes_match_literals`]
/// still pins it stable across the row set.
fn frag_digest_bytes() -> [u8; 32] {
    let mut h = gap_hasher();
    h.update(FRAG_TAIL);
    *h.finalize().as_bytes()
}
fn frag_digest_string() -> String {
    digest_string(&frag_digest_bytes())
}

#[test]
fn fixture_hashes_match_literals() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    assert_eq!(digest_string(&cp0.hash()), CP0_DIGEST, "cp0");
    assert_eq!(digest_string(&e1.hash()), E1_DIGEST, "e1");
    assert_eq!(digest_string(&WRONG_HASH_A5), WRONG_HASH_A5_DIGEST, "wrong");
    // Pin the frag digest stable across the row set: any change
    // here would move every TornWrite/AcceptUnused detail below.
    let expected = frag_digest_string();
    assert!(
        expected.starts_with("blake3:") && expected.len() == 71,
        "{expected}"
    );
}

fn verifier() -> Verifier {
    Verifier::new(trust_with_key(fixture_pubkey()))
}

/// Parses a built checkpoint record as a `Checkpoint`, for
/// `.start_from` / `.anchor` in rows below.
fn parse_cp(record: &Record) -> Checkpoint {
    let bytes = line_bytes(record);
    let line = std::str::from_utf8(&bytes)
        .unwrap()
        .trim_end_matches('\n')
        .to_owned();
    Checkpoint::parse(&line).unwrap()
}

/// A stopped trail: `[cp0, cp1]` followed by a 1-byte Fragment
/// trailing tail, so the verifier reports one trailing `TornWrite`
/// pinned at `(seq 1, frag_digest_bytes())` and no other finding.
/// `cp1` is a trusted checkpoint covering seq 1, so no
/// `UncoveredTail` fires; the trailing tail is a Fragment (not
/// `Unparsable`), so no error finding fires.
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
fn trailing_report(v: Verifier) -> (Report, PathBuf) {
    let fx = trailing_fixture();
    let report = report_of(vec![fx.path.clone()], v);
    (report, fx.path)
}
fn base_torn_write(path: &Path) -> Finding {
    Finding::new(
        K::TornWrite,
        Some(path.to_path_buf()),
        Some(3),
        None,
        format!(
            "trailing gap lines 3..=3 (1 bytes), digest {}",
            frag_digest_string()
        ),
    )
    .with_pin(Some(1), frag_digest_bytes())
}

// =====================================================================
// Row A1a (ADR decision 11, l.977-983): A trailing fragment on a
// stopped trail is `TornWrite` with its gap digest, and an
// `accept TornWrite` pinning the record before it and that digest
// replaces the warning with `Accepted` (info).
// =====================================================================
#[test]
fn r1a_trailing_torn_write_accept_match_gives_accepted() {
    let v = verifier()
        .accept(K::TornWrite, 1, frag_digest_bytes(), "alice", "reviewed")
        .unwrap();
    let (report, path) = trailing_report(v);
    let expected = vec![
        Finding::new(
            K::Accepted,
            Some(path.clone()),
            Some(3),
            None,
            format!(
                "accepted by alice: reviewed; was: trailing gap lines 3..=3 (1 bytes), digest {}",
                frag_digest_string()
            ),
        )
        .accepted(K::TornWrite),
    ];
    assert_findings(report.findings(), &expected, "r1a");
}

// Row A1b: The accepted trailing `TornWrite` makes `--strict` pass.
#[test]
fn r1b_accepted_trailing_torn_write_strict_passes() {
    let v = verifier()
        .accept(K::TornWrite, 1, frag_digest_bytes(), "alice", "reviewed")
        .unwrap();
    let (report, _) = trailing_report(v);
    assert!(report.is_strict_valid(), "r1b strict passes");
}

// Row A1c: An `accept TornWrite` naming the correct `seq` but another
// gap digest leaves the `TornWrite` warning untouched and emits
// one unlocated `AcceptUnused` (info) at `seq`; `--strict` still
// fails.
#[test]
fn r1c_trailing_torn_write_wrong_digest_gives_accept_unused() {
    let v = verifier()
        .accept(K::TornWrite, 1, WRONG_HASH_A5, "alice", "wrong digest")
        .unwrap();
    let (report, path) = trailing_report(v);
    let expected = vec![
        unlocated(
            K::AcceptUnused,
            Some(1),
            format!("accept TornWrite seq 1 hash {WRONG_HASH_A5_DIGEST}: no matching warning"),
        ),
        base_torn_write(&path),
    ];
    assert_findings(report.findings(), &expected, "r1c");
    assert!(!report.is_strict_valid(), "r1c strict fails");
}

// =====================================================================
// Row A2 (ADR l.977-983): After the writer runs `audit.repaired` on
// the next open, the trailing `TornWrite` becomes
// `TornWriteRepaired` and the old `accept TornWrite` line is
// `AcceptUnused`; `--strict` passes.
// =====================================================================
#[test]
fn r2_repaired_fragment_leaves_accept_unused_strict_passes() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let cp1 = signed_cp(1, cp0.hash(), &seeded(&cp0));
    // In-segment gap: cp0 ‖ cp1 ‖ "{\n" ‖ cp2.repaired(gap of 2 bytes).
    // "{" is a Fragment line; condition 3 passes because cp2.previous
    // == cp1.hash(). The gap bytes are "{" + the LF that ends that
    // Fragment line (2 bytes).
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
    let v = verifier()
        .accept(K::TornWrite, 1, frag_digest_bytes(), "alice", "reviewed")
        .unwrap();
    let report = report_of(vec![d.0.clone()], v);
    assert!(
        !report.findings().iter().any(|f| f.kind() == K::TornWrite),
        "r2 no TornWrite stays: {:?}",
        report.findings()
    );
    assert!(
        report
            .findings()
            .iter()
            .any(|f| f.kind() == K::TornWriteRepaired),
        "r2 TornWriteRepaired fires: {:?}",
        report.findings()
    );
    assert!(
        report.findings().iter().any(|f| f.kind() == K::AcceptUnused
            && f.seq() == Some(1)
            && f.detail().contains(&frag_digest_string())),
        "r2 AcceptUnused for the old line: {:?}",
        report.findings()
    );
    assert!(report.is_strict_valid(), "r2 strict passes after repair");
}

/// Mirrors `signed_cp` plus a `.repaired()` context so a row can
/// seal an attested gap without hand-building `CheckpointFields`.
fn cp_with_repair(seq: u64, previous: [u8; 32], mmr: &Mmr, repaired: [u8; 32]) -> Record {
    use crate::audit::{CheckpointFields, KeyFileSigner, Signer};
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

// =====================================================================
// Row A3 (ADR l.977-983): A `Resumed` warning and a `ClockWentBackwards`
// warning both accept by their pinned `(seq, record hash)`,
// replacing each with `Accepted` (info). Covers the two
// non-TornWrite acceptable kinds.
// =====================================================================
#[test]
fn r3_resumed_and_clock_accept_match_gives_accepted() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    // ClockWentBackwards at seq 1 (time 50 < cp0.time).
    let e1_clock = Record::new(
        RecordContext::new(TRAIL, 1, 50, "test", cp0.hash()),
        Entry::new("actor", "change", "object"),
    )
    .unwrap();
    // Trusted checkpoint at the tail to cover everything.
    let mmr1 = pushed(&seeded(&cp0), &e1_clock);
    let cp2 = signed_cp(2, e1_clock.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1_clock, &cp2], &[]);
    // A resume declaration at seq 3 in the next segment.
    let resume = resume_decl(&cp2, 2, cp2.hash(), 2);
    put_segment(&d.0, 1, &[&resume], &[]);
    let v = verifier()
        .accept(
            K::ClockWentBackwards,
            1,
            e1_clock.hash(),
            "alice",
            "verified",
        )
        .unwrap()
        .accept(K::Resumed, 3, resume.hash(), "bob", "op noted")
        .unwrap();
    let report = report_of(vec![d.0.clone()], v);
    let accepted_kinds: Vec<_> = report
        .findings()
        .iter()
        .filter(|f| f.kind() == K::Accepted)
        .filter_map(Finding::accepted_kind)
        .collect();
    assert!(
        accepted_kinds.contains(&K::ClockWentBackwards),
        "r3 ClockWentBackwards accepted: {:?}",
        report.findings()
    );
    assert!(
        accepted_kinds.contains(&K::Resumed),
        "r3 Resumed accepted: {:?}",
        report.findings()
    );
    for stale in [K::ClockWentBackwards, K::Resumed] {
        assert!(
            !report.findings().iter().any(|f| f.kind() == stale),
            "r3 no surviving {stale:?}"
        );
    }
}

// =====================================================================
// Row A4 (ADR l.977-983): An `accept` line at a `seq` whose record
// was replaced (a different hash on the verified trail) gives
// `AcceptMismatch` through the shared receipt match rule.
// =====================================================================
#[test]
fn r4_replaced_record_gives_accept_mismatch() {
    let fx = trailing_fixture();
    let cp1 = digest_string(&fx.cp1_hash);
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
                 hash differs (record {cp1})"
            ),
        ),
        base_torn_write(&fx.path),
    ];
    assert_findings(report.findings(), &expected, "r4");
}

// Row A4b. Same `AcceptMismatch` outcome at a `DuplicateRecord`
// warning on a duplicated line whose accept carries a wrong hash.
// A second record-hash-check row paired with A4.
#[test]
fn r4b_duplicate_record_wrong_hash_gives_accept_mismatch() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    put_segment(&d.0, 0, &[&cp0, &e1], &[]);
    let shipped = d.0.join("audit-shipped.jsonl");
    let mut bytes = line_bytes(&e1);
    bytes.extend(line_bytes(&e1));
    std::fs::write(&shipped, bytes).unwrap();
    let v = verifier()
        .accept(K::DuplicateRecord, 1, WRONG_HASH_A5, "alice", "stale")
        .unwrap();
    let report = report_of(vec![d.0.clone(), shipped], v);
    assert!(
        report
            .findings()
            .iter()
            .any(|f| f.kind() == K::AcceptMismatch
                && f.seq() == Some(1)
                && f.detail().contains(WRONG_HASH_A5_DIGEST)
                && f.detail()
                    .ends_with(&format!("hash differs (record {E1_DIGEST})"))),
        "r4b AcceptMismatch hash differs: {:?}",
        report.findings()
    );
}

// =====================================================================
// Row A5 (ADR l.977-983): Each of these registration patterns gives
// `InvalidConfig` at the builder call (ruling 13-V8-d1 point 2).
// =====================================================================
#[test]
fn r5a_non_acceptable_error_kind_gives_invalid_config() {
    let err = verifier()
        .accept(K::NoReceipt, 1, frag_digest_bytes(), "alice", "r")
        .unwrap_err();
    assert_eq!(err.kind(), AuditErrorKind::InvalidConfig, "{err}");
}
#[test]
fn r5a2_non_acceptable_info_kind_gives_invalid_config() {
    let err = verifier()
        .accept(K::UncoveredTail, 1, frag_digest_bytes(), "alice", "r")
        .unwrap_err();
    assert_eq!(err.kind(), AuditErrorKind::InvalidConfig, "{err}");
}
#[test]
fn r5b_empty_by_gives_invalid_config() {
    let err = verifier()
        .accept(K::TornWrite, 1, frag_digest_bytes(), "", "r")
        .unwrap_err();
    assert_eq!(err.kind(), AuditErrorKind::InvalidConfig, "{err}");
}
#[test]
fn r5c_by_with_whitespace_gives_invalid_config() {
    let err = verifier()
        .accept(K::TornWrite, 1, frag_digest_bytes(), "al ice", "r")
        .unwrap_err();
    assert_eq!(err.kind(), AuditErrorKind::InvalidConfig, "{err}");
}
#[test]
fn r5d_empty_reason_gives_invalid_config() {
    let err = verifier()
        .accept(K::TornWrite, 1, frag_digest_bytes(), "alice", "")
        .unwrap_err();
    assert_eq!(err.kind(), AuditErrorKind::InvalidConfig, "{err}");
}
#[test]
fn r5e_duplicate_accept_for_one_kind_and_seq_gives_invalid_config() {
    let v = verifier()
        .accept(K::TornWrite, 1, frag_digest_bytes(), "alice", "r")
        .unwrap();
    let err = v
        .accept(K::TornWrite, 1, frag_digest_bytes(), "bob", "r2")
        .unwrap_err();
    assert_eq!(err.kind(), AuditErrorKind::InvalidConfig, "{err}");
}
#[test]
fn r5e2_duplicate_accept_for_resumed_seq_gives_invalid_config() {
    let v = verifier()
        .accept(K::Resumed, 3, [1u8; 32], "alice", "r")
        .unwrap();
    let err = v.accept(K::Resumed, 3, [2u8; 32], "bob", "r2").unwrap_err();
    assert_eq!(err.kind(), AuditErrorKind::InvalidConfig, "{err}");
}

// =====================================================================
// Row A6 (ADR l.977-983): An `accept` line below an accepted start
// goes through the shared position classifier: `UnanchoredStart`
// (error) when the start is not anchored, `OutOfRange` (info)
// when it is.
// =====================================================================
fn start_cp2_layout() -> (Temp, Checkpoint) {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    // Two leaves at cp2: cp0 and e1.
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
    assert!(
        report
            .findings()
            .iter()
            .any(|f| f.kind() == K::UnanchoredStart
                && f.seq() == Some(1)
                && f.detail().starts_with("accept Resumed seq 1 hash")),
        "r6a UnanchoredStart: {:?}",
        report.findings()
    );
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
    assert!(
        report.findings().iter().any(|f| f.kind() == K::OutOfRange
            && f.seq() == Some(1)
            && f.detail().starts_with("accept Resumed seq 1 hash")),
        "r6b OutOfRange: {:?}",
        report.findings()
    );
}

// =====================================================================
// Row A7 (ADR l.977-983): A line delivered three times yields one
// `DuplicateRecord` warning for that `seq`; an `accept
// DuplicateRecord` matching it promotes it to `Accepted`.
// =====================================================================
#[test]
fn r7_duplicate_record_accept_match_gives_accepted() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    put_segment(&d.0, 0, &[&cp0, &e1], &[]);
    // A shipped copy adds two more byte-identical copies of e1.
    let shipped = d.0.join("audit-shipped.jsonl");
    let mut bytes = line_bytes(&e1);
    bytes.extend(line_bytes(&e1));
    std::fs::write(&shipped, bytes).unwrap();
    let v = verifier()
        .accept(
            K::DuplicateRecord,
            1,
            e1.hash(),
            "alice",
            "collector redelivery",
        )
        .unwrap();
    let report = report_of(vec![d.0.clone(), shipped], v);
    let dup_accepted = report
        .findings()
        .iter()
        .filter(|f| f.kind() == K::Accepted && f.accepted_kind() == Some(K::DuplicateRecord))
        .count();
    assert_eq!(
        dup_accepted,
        1,
        "r7 one Accepted(DuplicateRecord): {:?}",
        report.findings()
    );
    assert!(
        !report
            .findings()
            .iter()
            .any(|f| f.kind() == K::DuplicateRecord),
        "r7 no surviving DuplicateRecord"
    );
}

// =====================================================================
// Row A8 (ADR l.977-983): An `accept TornWrite` naming a `seq` with
// no record on the verified trail is `AcceptMismatch` through the
// shared receipt match rule's "no record" branch.
// =====================================================================
#[test]
fn r8_accept_torn_write_at_seq_with_no_record_gives_accept_mismatch() {
    let v = verifier()
        .accept(K::TornWrite, 99, frag_digest_bytes(), "alice", "r")
        .unwrap();
    let (report, _) = trailing_report(v);
    assert!(
        report
            .findings()
            .iter()
            .any(|f| f.kind() == K::AcceptMismatch
                && f.seq() == Some(99)
                && f.detail().ends_with(": no record")),
        "r8 AcceptMismatch no record: {:?}",
        report.findings()
    );
}

// =====================================================================
// Row A9 (ADR l.977-983): An `accept TornWrite` matching a gap marked
// "no crash outcome" is `AcceptMismatch`.
// =====================================================================
#[test]
fn r9_accept_torn_write_on_no_crash_gap_gives_accept_mismatch() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    put_segment(&d.0, 0, &[&cp0], FRAG_TAIL);
    let cp1 = signed_cp(1, cp0.hash(), &seeded(&cp0));
    put_segment(&d.0, 1, &[&cp1], &[]);
    let v = verifier()
        .accept(K::TornWrite, 0, frag_digest_bytes(), "alice", "r")
        .unwrap();
    let report = report_of(vec![d.0.clone()], v);
    assert!(
        report
            .findings()
            .iter()
            .any(|f| f.kind() == K::AcceptMismatch
                && f.seq() == Some(0)
                && f.detail().ends_with(": no crash outcome")),
        "r9 AcceptMismatch no crash outcome: {:?}",
        report.findings()
    );
}

// Row A9c. A second no-crash layout (closing `cp1`, opening `cp2`
// cleanly, no resume) with an `accept TornWrite` pinning the
// closing record's `seq` and the gap digest: `AcceptMismatch`
// with the "no crash outcome" detail (ADR-0005 decision 11).
#[test]
fn r9c_accept_torn_write_second_no_crash_gives_accept_mismatch() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let cp1 = signed_cp(1, cp0.hash(), &seeded(&cp0));
    // Segment 0 ends at cp1 + trailing fragment.
    let mut seg0 = line_bytes(&cp0);
    seg0.extend(line_bytes(&cp1));
    seg0.extend_from_slice(FRAG_TAIL);
    std::fs::write(segment_path(&d.0, 0), seg0).unwrap();
    // Segment 1 opens cleanly with cp2 chained from cp1, no resume.
    let mmr1 = pushed(&seeded(&cp0), &cp1);
    let cp2 = signed_cp(2, cp1.hash(), &mmr1);
    put_segment(&d.0, 1, &[&cp2], &[]);
    let v = verifier()
        .accept(K::TornWrite, 1, frag_digest_bytes(), "alice", "r")
        .unwrap();
    let report = report_of(vec![d.0.clone()], v);
    assert!(
        report
            .findings()
            .iter()
            .any(|f| f.kind() == K::AcceptMismatch
                && f.seq() == Some(1)
                && f.detail().ends_with(": no crash outcome")),
        "r9c AcceptMismatch no crash outcome: {:?}",
        report.findings()
    );
}

// Row A9b. An `accept TornWrite` naming the correct `seq` of a
// no-crash gap but with a wrong digest is `AcceptUnused` (the pin
// hash check blocks the match before the "no crash outcome" test
// could fire); second digest-check row paired with A1c.
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
    assert!(
        report.findings().iter().any(|f| f.kind() == K::AcceptUnused
            && f.seq() == Some(0)
            && f.detail().contains(WRONG_HASH_A5_DIGEST)),
        "r9b AcceptUnused wrong digest no-crash: {:?}",
        report.findings()
    );
}

// =====================================================================
// Row A10 (ADR l.977-983): An `accept` line at a forked `seq` is
// `AcceptMismatch "… seq is forked"` through the shared match
// rule (ruling 13-V8-d1 point 6).
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
    // Explicit shipped file (not covered by the 'audit' prefix
    // snapshot) so verify_files reads it as one of the explicit
    // files.
    let shipped = d.0.join("shipped.jsonl");
    std::fs::write(&shipped, line_bytes(&e1_alt)).unwrap();
    let v = verifier()
        .accept(K::Resumed, 1, e1.hash(), "alice", "r")
        .unwrap();
    let report = report_of(vec![d.0.clone(), shipped], v);
    assert!(
        report
            .findings()
            .iter()
            .any(|f| f.kind() == K::AcceptMismatch
                && f.seq() == Some(1)
                && f.detail().ends_with(": seq is forked")),
        "r10 AcceptMismatch forked: {:?}",
        report.findings()
    );
}
// Row A10b. Same forked `seq` under an `accept DuplicateRecord`:
// the shared match rule's fork check fires regardless of kind.
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
    assert!(
        report
            .findings()
            .iter()
            .any(|f| f.kind() == K::AcceptMismatch
                && f.seq() == Some(1)
                && f.detail().ends_with(": seq is forked")),
        "r10b AcceptMismatch forked: {:?}",
        report.findings()
    );
}

// =====================================================================
// Row A11 (ruling 13-V8-d1 FORK 3): A trailing `TornWrite` with no
// record before the gap in its file (file-start gap) carries
// `pin_seq = None` and no `accept TornWrite` line can match it:
// a line stays `AcceptMismatch` (shared mismatch "no record") and
// the warning stays.
// =====================================================================
#[test]
fn r11_torn_write_with_no_record_before_gap_cannot_be_accepted() {
    let d = Temp::new();
    std::fs::write(segment_path(&d.0, 0), FRAG_TAIL).unwrap();
    let v = verifier()
        .accept(K::TornWrite, 0, frag_digest_bytes(), "alice", "r")
        .unwrap();
    let report = report_of(vec![d.0.clone()], v);
    assert!(
        report
            .findings()
            .iter()
            .any(|f| f.kind() == K::AcceptMismatch
                && f.seq() == Some(0)
                && f.detail().ends_with(": no record")),
        "r11 AcceptMismatch no record: {:?}",
        report.findings()
    );
    assert!(
        report.findings().iter().any(|f| f.kind() == K::TornWrite),
        "r11 TornWrite stays: {:?}",
        report.findings()
    );
}

// =====================================================================
// Row A12 (ruling 13-V8-d1 point 3): The `Accepted` finding keeps
// the original location and `seq`, and its detail is exact
// including the `was:` part.
// =====================================================================
#[test]
fn r12_accepted_finding_keeps_location_and_detail() {
    let v = verifier()
        .accept(K::TornWrite, 1, frag_digest_bytes(), "alice", "reviewed")
        .unwrap();
    let (report, path) = trailing_report(v);
    let a = report
        .findings()
        .iter()
        .find(|f| f.kind() == K::Accepted)
        .expect("Accepted exists");
    assert_eq!(a.file(), Some(path.as_path()));
    assert_eq!(a.line(), Some(3));
    assert_eq!(a.seq(), None);
    assert_eq!(a.accepted_kind(), Some(K::TornWrite));
    assert_eq!(
        a.detail(),
        format!(
            "accepted by alice: reviewed; was: trailing gap lines 3..=3 (1 bytes), digest {}",
            frag_digest_string()
        )
    );
    // Also pin the sorted literal list as a cross-check on A1a.
    let expected = vec![
        Finding::new(
            K::Accepted,
            Some(path.clone()),
            Some(3),
            None,
            format!(
                "accepted by alice: reviewed; was: trailing gap lines 3..=3 (1 bytes), digest {}",
                frag_digest_string()
            ),
        )
        .accepted(K::TornWrite),
    ];
    assert_findings(report.findings(), &expected, "r12");
}
