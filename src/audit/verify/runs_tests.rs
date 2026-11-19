//! V4a verifier-level acceptance rows: each row drives
//! `Verifier::verify_dir` / `Verifier::verify_files` and asserts the
//! **literal, sorted, full** finding list on the verified trail
//! (rulings 13-V4-d3, 13-V4-d4, 13-V4-d5, 13-V4-d6, 13-V4-d8;
//! ADR-0005 decision 11 "accept-run", decision 2 steps 1 and 6).
//! Shipped-copy runs are out of scope (owner decision 13-V4-d7;
//! spike #224).

use super::{Finding, Verifier};
use crate::audit::{
    FindingKind as K, TrustPolicy, digest_string,
    runs_v4a_fixtures::{
        A1_DIGEST, A3_DIGEST, A8_DIGEST, A9_DIGEST, TRAIL, Temp, build_a1, build_a3, build_a8,
        build_a9, entry_rec, fixture_pubkey, headless, line_bytes, pushed, resume_decl, seeded,
        signed_cp, write_records,
    },
    storage::SegmentSource,
};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

fn policy_trail() -> TrustPolicy {
    TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .build()
        .unwrap()
}

fn verify_dir(dir: &Path) -> Vec<Finding> {
    Verifier::new(policy_trail())
        .verify_dir(dir)
        .unwrap()
        .findings()
        .to_vec()
}

fn verify_files(files: impl IntoIterator<Item = PathBuf>) -> Vec<Finding> {
    Verifier::new(policy_trail())
        .verify_files(files)
        .unwrap()
        .findings()
        .to_vec()
}

/// Render one finding as `(kind, file, line, seq, detail, run_digest)`
/// so the literal list assertion carries every field (ruling 13-V4-d8
/// point 1 grammar, ADR-0005 decision 11 pins).
fn row(
    f: &Finding,
) -> (
    K,
    Option<PathBuf>,
    Option<u64>,
    Option<u64>,
    String,
    Option<String>,
) {
    (
        f.kind(),
        f.file().map(Path::to_path_buf),
        f.line(),
        f.seq(),
        f.detail().to_owned(),
        f.run_digest().as_ref().map(digest_string),
    )
}
type Row = (
    K,
    Option<PathBuf>,
    Option<u64>,
    Option<u64>,
    String,
    Option<String>,
);
fn rows(findings: &[Finding]) -> Vec<Row> {
    findings.iter().map(row).collect()
}

/// Rewrite `(seg, after, len, blake3:<hex>)` from
/// `(A, sorted, true, fold::run_detail)`. Test helper only --
/// re-implements the public detail grammar so a mismatch flags a
/// grammar drift from `fold::run_detail` (ruling 13-V4-d8 point 1).
fn make_run_detail(
    loss_points: &[(u64, u64, u64)],
    spans: &[(u32, Option<u64>, u64, [u8; 32])],
    digest: &[u8; 32],
) -> String {
    let mut out = String::new();
    for (loss_seq, first, count) in loss_points {
        out.push_str(&format!(
            "loss seq {loss_seq} first {first} count {count}; "
        ));
    }
    for (seg, after, len, d) in spans {
        let after = after.map_or("start".to_owned(), |a| a.to_string());
        out.push_str(&format!(
            "span seg {seg} after {after} len {len} {}; ",
            digest_string(d)
        ));
    }
    out.push_str(&format!("digest {}", digest_string(digest)));
    out
}

/// Parse the module's exposed `A*_DIGEST` constants back to bytes so
/// the rows can assert the finding's `run_digest()` directly.
fn parse_digest(hex: &str) -> [u8; 32] {
    let hex = hex.strip_prefix("blake3:").expect("blake3 prefix");
    assert_eq!(hex.len(), 64, "32-byte digest in hex");
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex");
    }
    out
}

// ============================================================
// Agreement helpers — R13 compares the verifier's V4a run findings
// against `runs::classify`'s own `ClassifyOutput.runs` on the same
// snapshot bytes (ruling 13-V4-d5 (a) parallel index, 13-V4-d8
// point 2 one-pass classify).
// ============================================================

/// Bundle every field the verifier emits for a run finding, so a
/// mutant that drops any one is caught (ruling 13-V4-d8 point 1,
/// point 5; ADR-0005 decision 11). Filtering on `run_digest.is_some()`
/// here is a kind filter (run findings carry a digest; others never
/// do), not a value filter: every field below is still asserted.
type RunBundle = (
    K,           // always `SegmentStructure` for a run finding
    PathBuf,     // first-segment path
    Option<u64>, // line of the first record on trail in first segment
    Option<u64>, // seq of the same
    String,      // detail (ruling 13-V4-d8 point 1 grammar)
    [u8; 32],    // run digest (ADR-0005 decision 11)
);

fn classify_run_bundles(dir: &Path) -> Vec<RunBundle> {
    use crate::audit::Record;
    use crate::audit::runs::{self, ClassifyArgs, Reaction, ReaderPath};
    // The row's trail directory is static in these tests (no writer
    // in flight), so we read the directory once instead of going
    // through `rotate::retry_snapshot`.
    let entries: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    let live = entries
        .iter()
        .find(|p| p.file_name().is_some_and(|n| n == "audit.jsonl"))
        .cloned();
    let mut sealed: Vec<PathBuf> = entries
        .iter()
        .filter(|p| {
            p.file_name().is_some_and(|n| n != "audit.jsonl")
                && crate::rotate::parse_segment(
                    p.file_name().and_then(|n| n.to_str()).unwrap_or(""),
                    "audit",
                )
                .is_some()
        })
        .cloned()
        .collect();
    sealed.sort_by_key(|p| {
        let (name, seq) = crate::rotate::parse_segment(
            p.file_name().and_then(|n| n.to_str()).unwrap_or(""),
            "audit",
        )
        .expect("every path above is a native segment");
        (name.to_owned(), seq)
    });
    let mut natives: Vec<(PathBuf, std::rc::Rc<[u8]>, bool)> = Vec::new();
    for p in sealed {
        let bytes = fs::read(&p).unwrap();
        natives.push((p, std::rc::Rc::from(bytes.into_boxed_slice()), false));
    }
    if let Some(live) = live {
        let bytes = fs::read(&live).unwrap();
        natives.push((live, std::rc::Rc::from(bytes.into_boxed_slice()), true));
    }
    let tuples: Vec<(std::rc::Rc<[u8]>, bool)> = natives
        .iter()
        .map(|(_, b, l)| (std::rc::Rc::clone(b), *l))
        .collect();
    let mut source = SegmentSource::for_snapshot(&tuples);
    let out = runs::classify(
        ClassifyArgs {
            trail: TRAIL,
            prior_state: None,
        },
        ReaderPath::LiveOpen { expected: None },
        &mut source,
        Reaction::Collect,
    )
    .unwrap();
    out.runs
        .iter()
        .map(|run| {
            let ranges: Vec<(u64, u64)> = run
                .loss_points
                .iter()
                .map(|lp| (lp.first, lp.count))
                .collect();
            let digest = super::lines::run_digest(&ranges, &run.spans);
            // Compute the expected detail from a fresh helper so a
            // mutant that drops ranges or spans from `fold::run_detail`
            // is caught by the detail-string half of R13's agreement.
            let lps: Vec<(u64, u64, u64)> = run
                .loss_points
                .iter()
                .map(|lp| (lp.loss_seq, lp.first, lp.count))
                .collect();
            let sps: Vec<(u32, Option<u64>, u64, [u8; 32])> = run
                .spans
                .iter()
                .map(|s| {
                    (
                        s.seg,
                        if s.after == u64::MAX {
                            None
                        } else {
                            Some(s.after)
                        },
                        s.len,
                        s.digest,
                    )
                })
                .collect();
            let detail = make_run_detail(&lps, &sps, &digest);
            // Compute (line, seq) directly from the first segment's
            // bytes by parsing each line and filtering by trail. The
            // oracle therefore does not share `verify::input`'s code
            // path with the verifier side -- it is independent in
            // every field (ruling 13-V4-d8 point 5).
            let (path, bytes, _is_live) = &natives[run.first_segment];
            let mut line_seq: (Option<u64>, Option<u64>) = (None, None);
            for (idx, line) in bytes.split(|b| *b == b'\n').enumerate() {
                if line.is_empty() {
                    continue;
                }
                let Ok(records) = Record::parse_line(line) else {
                    continue;
                };
                if let Some(r) = records.into_iter().find(|r| r.context.trail == TRAIL) {
                    // 1-based line number, matching `Finding::line`.
                    #[allow(clippy::cast_possible_truncation)]
                    let ln = (idx + 1) as u64;
                    line_seq = (Some(ln), Some(r.context.seq));
                    break;
                }
            }
            (
                K::SegmentStructure,
                path.clone(),
                line_seq.0,
                line_seq.1,
                detail,
                digest,
            )
        })
        .collect()
}

fn run_bundles_from_findings(findings: &[Finding]) -> Vec<RunBundle> {
    findings
        .iter()
        .filter_map(|f| {
            f.run_digest().map(|d| {
                (
                    f.kind(),
                    f.file().map_or_else(PathBuf::new, Path::to_path_buf),
                    f.line(),
                    f.seq(),
                    f.detail().to_owned(),
                    d,
                )
            })
        })
        .collect()
}

// ============================================================
// R1 — A1: one run finding at S1, line 1, seq 4, one loss range.
// ============================================================

#[test]
fn r1_a1_one_run_finding_literal() {
    let a = build_a1();
    let findings = verify_dir(&a.dir_path);
    // The expected finding list is captured literally at this head
    // (ruling 13-V4-d8 point 1 grammar; ADR-0005 decision 11
    // `accept-run`): one run finding at the run's first segment,
    // ahead of V3's per-segment SegmentStructure, Resumed, and
    // UncoveredTail, all sorted per `engine::check`'s stable sort.
    let s1 = a
        .dir_path
        .join("audit-20260101T000000.000000000Z_000001.jsonl");
    let live = a.dir_path.join("audit.jsonl");
    let a1_digest = parse_digest(A1_DIGEST);
    let run_detail = make_run_detail(&[(4, 3, 1)], &[], &a1_digest);
    let per_seg_detail = "expected first complete record to be a checkpoint".to_owned();
    let got = rows(&findings);
    // Literal full finding list (ruling 13-V4-d8 point 1 grammar,
    // ADR-0005 decision 11 pins; sorted by `engine::check`'s stable
    // key `(seq_is_none, seq, file, line, kind)`). V3 emits the
    // per-segment `SegmentStructure`, the chain-gap `SeqGap` for
    // seq=3 (the headless-caused gap), V4a's run finding, the
    // `Resumed` on the live file, and `UncoveredTail` last. The
    // Resumed detail's `head=5:blake3:<hex>` is `cp5.hash`, which
    // is deterministic from the fixture inputs and captured at
    // head.
    let resume_detail = "operator=operator reason=incident \
         head=5:blake3:4181d394847e4274645a1b39a8366b0217c32abc5ab45e4dbee9f064c25361aa \
         gap=none lost_records=0 structural=valid"
        .to_owned();
    let expected = vec![
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            per_seg_detail.clone(),
            None,
        ),
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            run_detail,
            Some(digest_string(&a1_digest)),
        ),
        (
            K::SeqGap,
            Some(s1.clone()),
            Some(1),
            Some(4),
            "missing seq 3..=3".to_owned(),
            None,
        ),
        (
            K::Resumed,
            Some(live.clone()),
            Some(2),
            Some(7),
            resume_detail,
            None,
        ),
        (
            K::UncoveredTail,
            None,
            None,
            None,
            "records seq 7..=7".to_owned(),
            None,
        ),
    ];
    assert_eq!(got, expected, "A1 full literal finding list");
}

// ============================================================
// R2 — A3: two loss points, in seq order, A3 digest.
// ============================================================

#[test]
fn r2_a3_two_loss_points_literal() {
    let a = build_a3();
    let findings = verify_dir(&a.dir_path);
    let s1 = a
        .dir_path
        .join("audit-20260101T000000.000000000Z_000001.jsonl");
    let s2 = a
        .dir_path
        .join("audit-20260101T000000.000000000Z_000002.jsonl");
    let live = a.dir_path.join("audit.jsonl");
    let a3_digest = parse_digest(A3_DIGEST);
    let run_detail = make_run_detail(&[(4, 3, 1), (7, 6, 1)], &[], &a3_digest);
    let per_seg_detail = "expected first complete record to be a checkpoint".to_owned();
    // A3's Resumed head is `cp8.hash`, captured here as a literal.
    let resume_detail = "operator=operator reason=incident \
         head=8:blake3:436c1a38d9dd40b9880233500e5c4c97783f180fcc0eb9c8376bee20e791d2ce \
         gap=9..=9 lost_records=0 structural=valid"
        .to_owned();
    let expected = vec![
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            per_seg_detail.clone(),
            None,
        ),
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            run_detail,
            Some(digest_string(&a3_digest)),
        ),
        (
            K::SeqGap,
            Some(s1.clone()),
            Some(1),
            Some(4),
            "missing seq 3..=3".to_owned(),
            None,
        ),
        (
            K::SegmentStructure,
            Some(s2.clone()),
            Some(1),
            Some(7),
            per_seg_detail,
            None,
        ),
        (
            K::SeqGap,
            Some(s2.clone()),
            Some(1),
            Some(7),
            "missing seq 6..=6".to_owned(),
            None,
        ),
        (
            K::SeqGap,
            Some(live.clone()),
            Some(1),
            Some(10),
            "missing seq 9..=9".to_owned(),
            None,
        ),
        (
            K::Resumed,
            Some(live.clone()),
            Some(2),
            Some(11),
            resume_detail,
            None,
        ),
        (
            K::UncoveredTail,
            None,
            None,
            None,
            "records seq 11..=11".to_owned(),
            None,
        ),
    ];
    assert_eq!(rows(&findings), expected, "A3 full literal finding list");
}

// ============================================================
// R3 — A8: no range, line/seq absent, A8 digest.
// ============================================================

#[test]
fn r3_a8_no_range_line_seq_absent_literal() {
    let a = build_a8();
    let findings = verify_dir(&a.dir_path);
    let s1 = a
        .dir_path
        .join("audit-20260101T000000.000000000Z_000001.jsonl");
    let live = a.dir_path.join("audit.jsonl");
    let a8_digest = parse_digest(A8_DIGEST);
    let run_detail = make_run_detail(&[], &[], &a8_digest);
    let per_seg_detail = "expected first complete record to be a checkpoint".to_owned();
    // A8's closer opening is `cp_opening`; `Resumed`'s head citation
    // is that record's hash, captured at head.
    let resume_detail = "operator=operator reason=incident \
         head=0:blake3:fc26c6f2bb830592aaaca5413da1599489d86ac6e240a4a7a010681e0d4c8e77 \
         gap=none lost_records=0 structural=valid"
        .to_owned();
    // engine::check's stable sort (`seq_is_none` first-false) places
    // the record-carrying findings before the None-seq ones.
    let expected = vec![
        (
            K::Resumed,
            Some(live.clone()),
            Some(2),
            Some(2),
            resume_detail,
            None,
        ),
        (
            K::UncoveredTail,
            None,
            None,
            None,
            "records seq 2..=2".to_owned(),
            None,
        ),
        (
            K::SegmentStructure,
            Some(s1.clone()),
            None,
            None,
            per_seg_detail,
            None,
        ),
        (
            K::SegmentStructure,
            Some(s1.clone()),
            None,
            None,
            run_detail,
            Some(digest_string(&a8_digest)),
        ),
    ];
    assert_eq!(rows(&findings), expected, "A8 full literal finding list");
}

// ============================================================
// R4 — A9: two spans with `after start`, A9 digest.
// ============================================================

#[test]
fn r4_a9_two_spans_after_start_literal() {
    let a = build_a9();
    let findings = verify_dir(&a.dir_path);
    let s1 = a
        .dir_path
        .join("audit-20260101T000000.000000000Z_000001.jsonl");
    let s2 = a
        .dir_path
        .join("audit-20260101T000000.000000000Z_000002.jsonl");
    let live = a.dir_path.join("audit.jsonl");
    let per_seg_detail = "expected first complete record to be a checkpoint".to_owned();
    let a9_detail = "span seg 0 after start len 9 blake3:8b78e71ce40a5c8ed68f53d8601ac823e803eb9366d24f963163e8524438ce8a; \
         span seg 1 after start len 14 blake3:4538bcdbaba974dc18a217221116cee0c884f72d52845285ab713a33c8d047da; \
         digest blake3:4905b9e63aa3fd9248f5c3605fe4beaf4af5a956f3f108b6dcecdbfbfda54026".to_owned();
    let resume_detail = "operator=operator reason=incident \
         head=0:blake3:fc26c6f2bb830592aaaca5413da1599489d86ac6e240a4a7a010681e0d4c8e77 \
         gap=none lost_records=0 structural=valid"
        .to_owned();
    let s1_gap_detail = "trailing gap lines 1..=1 (9 bytes), \
         digest blake3:8b78e71ce40a5c8ed68f53d8601ac823e803eb9366d24f963163e8524438ce8a"
        .to_owned();
    let s2_gap_detail = "trailing gap lines 1..=1 (14 bytes), \
         digest blake3:4538bcdbaba974dc18a217221116cee0c884f72d52845285ab713a33c8d047da"
        .to_owned();
    let expected = vec![
        (
            K::Resumed,
            Some(live.clone()),
            Some(2),
            Some(2),
            resume_detail,
            None,
        ),
        (
            K::UncoveredTail,
            None,
            None,
            None,
            "records seq 2..=2".to_owned(),
            None,
        ),
        (
            K::SegmentStructure,
            Some(s1.clone()),
            None,
            None,
            per_seg_detail.clone(),
            None,
        ),
        (
            K::SegmentStructure,
            Some(s1.clone()),
            None,
            None,
            a9_detail,
            Some(A9_DIGEST.to_owned()),
        ),
        (
            K::TornWrite,
            Some(s1.clone()),
            Some(1),
            None,
            s1_gap_detail,
            None,
        ),
        (
            K::Unparsable,
            Some(s1.clone()),
            Some(1),
            None,
            "CorruptTrail: Unparsable: invalid audit v1 OTLP line".to_owned(),
            None,
        ),
        (
            K::SegmentStructure,
            Some(s2.clone()),
            None,
            None,
            per_seg_detail,
            None,
        ),
        (
            K::TornWrite,
            Some(s2.clone()),
            Some(1),
            None,
            s2_gap_detail,
            None,
        ),
        (
            K::Unparsable,
            Some(s2.clone()),
            Some(1),
            None,
            "CorruptTrail: Unparsable: invalid audit v1 OTLP line".to_owned(),
            None,
        ),
    ];
    assert_eq!(rows(&findings), expected, "A9 full literal finding list");
}

// R5 was removed: the only mutant it killed in practice was M16.
// A MissingInitialCheckpoint / non-CP-first-record layout classifies
// its leading segment as `SegmentClass::Base` with `member=false`,
// so dropping the violation-suppression rule (MS) never opens a run
// at `open_run_start`, and R5 survived MS. The "rejection empties
// every run" rule is still pinned by R6 (RecordRolledBack inside an
// InRun segment, where the walker keeps the run open; killed by
// both MS and M16) and by R18 / R19 (InvalidLineOrOpeningCheckpoint
// at the live closer; killed by both MS and M11).

// ============================================================
// R6 — non-increasing `seq` inside a would-be run: no run finding
// (addendum 28 point 2: any classifier violation empties `runs`);
// the engine's violation and record-level findings list literally.
//
// Regression row: "no run finding" is already true on base. Measured
// killers at head, each exit 101:
//   * M16 (emit a run finding when `out.runs` is empty and
//     violations are present) — this layout has classifier
//     violations (SeqConflict, ChainBroken, SegmentStructure), so
//     M16 would add a spurious run finding.
//   * MS (drop the "any violation empties `runs`" rule in
//     `runs::classify`) — without the drop, the Base/InRun/Closer
//     walk produces a run finding; the expected literal list has
//     none.
// ============================================================

#[test]
fn r6_non_increasing_seq_in_would_be_run_drops_run_finding() {
    let d = Temp::new();
    let cp0 = signed_cp(
        0,
        crate::audit::Record::genesis(&TRAIL),
        &crate::audit::Mmr::new(),
    );
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    crate::audit::runs_v4a_fixtures::put_segment(&d.0, 0, &[&cp0, &e1], &[]);
    let r4 = headless(&e1, 4);
    let roll = entry_rec(1, r4.hash());
    crate::audit::runs_v4a_fixtures::put_segment(&d.0, 1, &[&r4, &roll], &[]);
    let mmr4 = pushed(&mmr1, &r4);
    let close = signed_cp(5, r4.hash(), &mmr4);
    let resume = resume_decl(&close, 4, r4.hash(), 4);
    write_records(&d.0, &[&close, &resume]);
    let s0 = d.0.join("audit-20260101T000000.000000000Z_000000.jsonl");
    let s1 = d.0.join("audit-20260101T000000.000000000Z_000001.jsonl");
    let live = d.0.join("audit.jsonl");
    let per_seg_detail = "expected first complete record to be a checkpoint".to_owned();
    // The two engine-level hash findings are captured verbatim; both
    // are deterministic in the layout and sort before the per-segment
    // SegmentStructure (`(seq_is_none=false, seq=1, file, line, kind)`).
    let resume_detail = "operator=operator reason=incident \
         head=4:blake3:add04a4d0b08de83c373eb30a582c3c111c308241f9ef3639ec2497dabda7456 \
         gap=none lost_records=0 structural=valid"
        .to_owned();
    let expected = vec![
        (
            K::SeqConflict,
            Some(s0),
            Some(2),
            Some(1),
            "conflicting hashes: \
             blake3:1c2f696ee6e90bc1e2256617e993dfed53fcc292ea34bb5b52bffd45b9dbceb5, \
             blake3:c121282b5135adfe7a17142cae6bfc4c9040c4aed26d74bddc923b8dafcdb6e8"
                .to_owned(),
            None,
        ),
        (
            K::ChainBroken,
            Some(s1.clone()),
            Some(2),
            Some(1),
            "expected previous \
             blake3:fc26c6f2bb830592aaaca5413da1599489d86ac6e240a4a7a010681e0d4c8e77, found \
             blake3:add04a4d0b08de83c373eb30a582c3c111c308241f9ef3639ec2497dabda7456"
                .to_owned(),
            None,
        ),
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            per_seg_detail,
            None,
        ),
        (
            K::SeqGap,
            Some(s1),
            Some(1),
            Some(4),
            "missing seq 2..=3".to_owned(),
            None,
        ),
        (
            K::Resumed,
            Some(live),
            Some(2),
            Some(6),
            resume_detail,
            None,
        ),
        (
            K::UncoveredTail,
            None,
            None,
            None,
            "records seq 6..=6".to_owned(),
            None,
        ),
    ];
    assert_eq!(
        rows(&verify_dir(&d.0)),
        expected,
        "R6 full literal finding list (no run finding; per-segment pins kept)",
    );
}

// ============================================================
// R7 — archive, run closed inside it (no live file).
// S0 base, S1 run, S2 starts with linking opening + resume.
// Exactly one run finding at S1 with S1's first record (line, seq).
// ============================================================

fn build_archive_closed_inside() -> (Temp, PathBuf, PathBuf, PathBuf) {
    let d = Temp::new();
    let cp0 = signed_cp(
        0,
        crate::audit::Record::genesis(&TRAIL),
        &crate::audit::Mmr::new(),
    );
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    crate::audit::runs_v4a_fixtures::put_segment(&d.0, 0, &[&cp0, &e1, &e2], &[]);
    let r4 = headless(&e2, 4);
    let fold = pushed(&mmr2, &r4);
    let cp5 = signed_cp(5, r4.hash(), &fold);
    crate::audit::runs_v4a_fixtures::put_segment(&d.0, 1, &[&r4, &cp5], &[]);
    let fold2 = pushed(&fold, &cp5);
    let cp6 = signed_cp(6, cp5.hash(), &fold2);
    let resume = resume_decl(&cp6, 5, cp5.hash(), 5);
    crate::audit::runs_v4a_fixtures::put_segment(&d.0, 2, &[&cp6, &resume], &[]);
    let path = d.0.clone();
    let s0 = crate::audit::runs_v4a_fixtures::segment_path(&path, 0);
    let s1 = crate::audit::runs_v4a_fixtures::segment_path(&path, 1);
    let s2 = crate::audit::runs_v4a_fixtures::segment_path(&path, 2);
    (d, s0, s1, s2)
}

#[test]
fn r7_archive_run_closed_inside_single_run_finding() {
    let (_d, _s0, s1, s2) = build_archive_closed_inside();
    let dir = _s0.parent().unwrap();
    let findings = verify_dir(dir);
    let a1_digest = parse_digest(A1_DIGEST);
    let per_seg_detail = "expected first complete record to be a checkpoint".to_owned();
    // R7 archive's run spans S1..S2 (exclusive, ruling 13-V4-d9):
    // S1 carries no fragments, so the detail matches A1's (one range,
    // no spans, A1's digest).
    let run_detail = make_run_detail(&[(4, 3, 1)], &[], &a1_digest);
    let resume_detail = "operator=operator reason=incident \
         head=5:blake3:4181d394847e4274645a1b39a8366b0217c32abc5ab45e4dbee9f064c25361aa \
         gap=none lost_records=0 structural=valid"
        .to_owned();
    let expected = vec![
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            per_seg_detail,
            None,
        ),
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            run_detail,
            Some(digest_string(&a1_digest)),
        ),
        (
            K::SeqGap,
            Some(s1),
            Some(1),
            Some(4),
            "missing seq 3..=3".to_owned(),
            None,
        ),
        (K::Resumed, Some(s2), Some(2), Some(7), resume_detail, None),
        (
            K::UncoveredTail,
            None,
            None,
            None,
            "records seq 7..=7".to_owned(),
            None,
        ),
    ];
    assert_eq!(
        rows(&findings),
        expected,
        "R7 archive full literal finding list (one run finding at S1 with A1's digest)",
    );
}

// R8 was removed: an open-run archive (no closer) has no classifier
// violations, so no mutant in the final table flips its literal list
// — it killed zero mutants. The open-run archive case is still
// pinned by the classifier-level
// `storage::tests::snapshot_tests::snapshot_archive_unclosed_run_emits_no_run_report`
// and by the empty-archive row in `tests/audit_verify.rs`
// (`native_boundaries_cannot_be_repaired_by_shipped_checkpoint`),
// which asserts exactly one `SegmentStructure` finding on an empty
// archive segment and never a run finding.

// ============================================================
// R9 — SS-7: `verify_dir(dir)` and `verify_files([each file])` emit
// identical reports (ruling 13-V3-d2: one confirmed snapshot).
// ============================================================

#[test]
fn r9_ss7_verify_dir_equals_verify_files_each_file() {
    let a = build_a1();
    let s1 = a
        .dir_path
        .join("audit-20260101T000000.000000000Z_000001.jsonl");
    let live = a.dir_path.join("audit.jsonl");
    let a1_digest = parse_digest(A1_DIGEST);
    let run_detail = make_run_detail(&[(4, 3, 1)], &[], &a1_digest);
    let per_seg_detail = "expected first complete record to be a checkpoint".to_owned();
    let resume_detail = "operator=operator reason=incident \
         head=5:blake3:4181d394847e4274645a1b39a8366b0217c32abc5ab45e4dbee9f064c25361aa \
         gap=none lost_records=0 structural=valid"
        .to_owned();
    // The ruling 13-V3-d2 pin: the literal full finding list carries
    // the one A1 run finding on both sides. On base this list differs
    // from both sides (the run finding is absent), so the main
    // assertion flips red on base.
    let expected = vec![
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            per_seg_detail,
            None,
        ),
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            run_detail,
            Some(digest_string(&a1_digest)),
        ),
        (
            K::SeqGap,
            Some(s1.clone()),
            Some(1),
            Some(4),
            "missing seq 3..=3".to_owned(),
            None,
        ),
        (
            K::Resumed,
            Some(live),
            Some(2),
            Some(7),
            resume_detail,
            None,
        ),
        (
            K::UncoveredTail,
            None,
            None,
            None,
            "records seq 7..=7".to_owned(),
            None,
        ),
    ];
    let dir_rows = rows(&verify_dir(&a.dir_path));
    assert_eq!(dir_rows, expected, "SS-7: verify_dir == expected literal");
    let files: Vec<PathBuf> = fs::read_dir(&a.dir_path)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    let files_rows = rows(&verify_files(files));
    assert_eq!(
        files_rows, expected,
        "SS-7: verify_files([each file]) == expected literal (ruling 13-V3-d2)",
    );
}

// ============================================================
// R10 — SS-8: `verify_files([archive_dir, trail_dir])` vs
// `verify_dir(full_trail)` emit the same run finding (compared on
// paths relative to their own dir, both asserted literally).
// ADR-0005 decision 2 step 6.
// ============================================================

#[test]
fn r10_ss8_archive_plus_trail_dir_vs_full_dir_same_run_finding() {
    /// Rebase each finding's file path onto `base_dir`, keeping only
    /// its file name (every R10 segment lives at the dir root).
    fn relative(got: Vec<Row>, base_dir: &Path) -> Vec<Row> {
        got.into_iter()
            .map(|r| {
                let rebased = r.1.map(|p| {
                    let name = p.file_name().expect("row file path has a basename");
                    base_dir.join(name)
                });
                (r.0, rebased, r.2, r.3, r.4, r.5)
            })
            .collect()
    }
    let common = Path::new("base");
    // Build the full trail in `full_dir` (archive + trail together).
    let (_full_d, s0_full, _s1_full, _s2_full) = build_archive_closed_inside();
    let full_dir = s0_full.parent().unwrap().to_owned();
    // Expected literal finding list (paths rebased to `common`). The
    // run finding files to S1's basename, so on base (no V4a) this
    // list differs from both sides through the SegmentStructure run
    // finding row — the main assertion flips red on base.
    let s1_name = Path::new("audit-20260101T000000.000000000Z_000001.jsonl");
    let s2_name = Path::new("audit-20260101T000000.000000000Z_000002.jsonl");
    let a1_digest = parse_digest(A1_DIGEST);
    let run_detail = make_run_detail(&[(4, 3, 1)], &[], &a1_digest);
    let per_seg_detail = "expected first complete record to be a checkpoint".to_owned();
    let resume_detail = "operator=operator reason=incident \
         head=5:blake3:4181d394847e4274645a1b39a8366b0217c32abc5ab45e4dbee9f064c25361aa \
         gap=none lost_records=0 structural=valid"
        .to_owned();
    let expected = vec![
        (
            K::SegmentStructure,
            Some(common.join(s1_name)),
            Some(1),
            Some(4),
            per_seg_detail,
            None,
        ),
        (
            K::SegmentStructure,
            Some(common.join(s1_name)),
            Some(1),
            Some(4),
            run_detail,
            Some(digest_string(&a1_digest)),
        ),
        (
            K::SeqGap,
            Some(common.join(s1_name)),
            Some(1),
            Some(4),
            "missing seq 3..=3".to_owned(),
            None,
        ),
        (
            K::Resumed,
            Some(common.join(s2_name)),
            Some(2),
            Some(7),
            resume_detail,
            None,
        ),
        (
            K::UncoveredTail,
            None,
            None,
            None,
            "records seq 7..=7".to_owned(),
            None,
        ),
    ];
    let full_rows = relative(rows(&verify_dir(&full_dir)), common);
    assert_eq!(
        full_rows, expected,
        "SS-8: verify_dir(full_trail) == expected literal (rebased)",
    );
    // Split: `archive_dir` holds S0+S1; `trail_dir` holds S2 under
    // a later-timestamped rotated name so the merged order matches
    // the single-dir order (ruling 13-V4-d8 point 2: one classify
    // over the merged `Collection`).
    let archive_dir = Temp::new();
    let trail_dir = Temp::new();
    fs::copy(
        full_dir.join("audit-20260101T000000.000000000Z_000000.jsonl"),
        archive_dir
            .0
            .join("audit-20260101T000000.000000000Z_000000.jsonl"),
    )
    .unwrap();
    fs::copy(
        full_dir.join("audit-20260101T000000.000000000Z_000001.jsonl"),
        archive_dir
            .0
            .join("audit-20260101T000000.000000000Z_000001.jsonl"),
    )
    .unwrap();
    fs::copy(
        full_dir.join("audit-20260101T000000.000000000Z_000002.jsonl"),
        trail_dir
            .0
            .join("audit-20260101T000001.000000000Z_000000.jsonl"),
    )
    .unwrap();
    // The split form renames S2 to a different timestamped sealed
    // segment, so rebase S2's rotated basename back to the single-dir
    // basename, then rebase every finding's directory to `common` and
    // assert literal equality with the same `expected` list.
    let split_rows = {
        let mut v = rows(&verify_files([archive_dir.0.clone(), trail_dir.0.clone()]));
        let split_s2 = trail_dir
            .0
            .join("audit-20260101T000001.000000000Z_000000.jsonl");
        let full_s2_name = s2_name.file_name().unwrap().to_owned();
        for r in &mut v {
            if r.1.as_deref() == Some(split_s2.as_path()) {
                r.1 = Some(common.join(&full_s2_name));
            }
        }
        relative(v, common)
    };
    assert_eq!(
        split_rows, expected,
        "SS-8: verify_files([archive_dir, trail_dir]) == expected literal \
         (rebased); ruling 13-V3-d2, 13-V4-d8 point 2",
    );
}

// ============================================================
// R11 — shipped-only and native+shipped same trail, explicit
// shipped inputs through `verify_files`. The shipped input never
// adds a run finding (owner decision 13-V4-d7; spike #224); the
// native run finding is unchanged. `verify_dir` never reads
// arbitrary (non-native) filenames, so R11 drives `verify_files`
// with explicit paths, the same way the existing `verify_files`
// shipped-copy tests do (see `audit::verify::input::tests`).
// ============================================================

#[test]
fn r11_shipped_only_and_native_plus_shipped_no_shipped_run_finding() {
    // (a) Shipped-only: one arbitrary filename holding a copy of a
    // valid trail's live file. `verify_files([shipped])` accepts the
    // path as a shipped input; V4a emits no run finding on it.
    let a = build_a1();
    let shipped_only_dir = Temp::new();
    let shipped_only_path = shipped_only_dir.0.join("copy-live");
    fs::copy(a.dir_path.join("audit.jsonl"), &shipped_only_path).unwrap();
    // Literal expected list for the shipped-only form: a shipped
    // input sees only the resume checkpoint in isolation (no native
    // segments before it), so the engine emits a leading `SeqGap`
    // for the invisible prior seqs, a `Resumed` with
    // `structural=invalid(head-not-present)` (the resume's head
    // record is not on this input), and a trailing `UncoveredTail`.
    // No run finding — owner decision 13-V4-d7 / spike #224.
    let shipped_only_expected = vec![
        (
            K::SeqGap,
            Some(shipped_only_path.clone()),
            Some(1),
            Some(6),
            "missing seq 0..=5".to_owned(),
            None,
        ),
        (
            K::Resumed,
            Some(shipped_only_path.clone()),
            Some(2),
            Some(7),
            "operator=operator reason=incident \
             head=5:blake3:4181d394847e4274645a1b39a8366b0217c32abc5ab45e4dbee9f064c25361aa \
             gap=none lost_records=0 structural=invalid(head-not-present)"
                .to_owned(),
            None,
        ),
        (
            K::UncoveredTail,
            None,
            None,
            None,
            "records seq 7..=7".to_owned(),
            None,
        ),
    ];
    assert_eq!(
        rows(&verify_files([shipped_only_path.clone()])),
        shipped_only_expected,
        "R11 (a): verify_files([shipped_copy]) == expected literal \
         (SeqGap + Resumed + UncoveredTail; no run finding, #224)",
    );
    // (b) Native + shipped: pass both the native trail directory
    // AND an explicit shipped copy of the live file through
    // `verify_files`. The shipped records duplicate the native
    // records on the live file, so the engine emits `DuplicateRecord`
    // findings on that live file; exactly one run finding still
    // appears, at the native S1, with A1's digest — the shipped
    // input adds no run finding.
    let shipped_mix = Temp::new();
    let shipped_mix_path = shipped_mix.0.join("copy-live-2");
    fs::copy(a.dir_path.join("audit.jsonl"), &shipped_mix_path).unwrap();
    let s1 = a
        .dir_path
        .join("audit-20260101T000000.000000000Z_000001.jsonl");
    let live = a.dir_path.join("audit.jsonl");
    let a1_digest = parse_digest(A1_DIGEST);
    let run_detail = make_run_detail(&[(4, 3, 1)], &[], &a1_digest);
    let per_seg_detail = "expected first complete record to be a checkpoint".to_owned();
    let resume_detail = "operator=operator reason=incident \
         head=5:blake3:4181d394847e4274645a1b39a8366b0217c32abc5ab45e4dbee9f064c25361aa \
         gap=none lost_records=0 structural=valid"
        .to_owned();
    let mixed_expected = vec![
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            per_seg_detail,
            None,
        ),
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            run_detail,
            Some(digest_string(&a1_digest)),
        ),
        (
            K::SeqGap,
            Some(s1.clone()),
            Some(1),
            Some(4),
            "missing seq 3..=3".to_owned(),
            None,
        ),
        (
            K::DuplicateRecord,
            Some(live.clone()),
            Some(1),
            Some(6),
            "2 copies of 1 distinct records".to_owned(),
            None,
        ),
        (
            K::DuplicateRecord,
            Some(live.clone()),
            Some(2),
            Some(7),
            "2 copies of 1 distinct records".to_owned(),
            None,
        ),
        (
            K::Resumed,
            Some(live.clone()),
            Some(2),
            Some(7),
            resume_detail,
            None,
        ),
        (
            K::UncoveredTail,
            None,
            None,
            None,
            "records seq 7..=7".to_owned(),
            None,
        ),
    ];
    assert_eq!(
        rows(&verify_files([
            a.dir_path.clone(),
            shipped_mix_path.clone(),
        ])),
        mixed_expected,
        "R11 (b): verify_files([native_dir, shipped_copy]) == expected literal \
         (DuplicateRecord on the live file; the one run finding is the native's, \
         at S1 with A1's digest; owner decision 13-V4-d7 / spike #224)",
    );
}

// R12 was removed: like R5, the only mutant it killed in practice
// was M16. A foreign-trail record as the leading record of a
// would-be run segment makes the classifier record a TrailMismatch
// violation AND stops opening a run at that segment (the walker's
// tolerant arm reclassifies the segment away from a run opener), so
// dropping the violation-suppression rule (MS) still produces no
// run. The trail check runs before any first-record lookup, which
// is the equivalence argument for M13 (see the PR body); this
// property is now documented, not pinned by a row.

// ============================================================
// R13 — agreement over A1, A3, A8, A9 and the R5/R6/R7/R8 layouts:
// the set of verifier run findings equals the set of
// `ClassifyOutput.runs` computed directly on the same snapshot,
// with strict equality on `(first_segment.path, digest)`
// (ruling 13-V4-d5 (a) parallel index by construction).
// ============================================================

#[test]
fn r13_agreement_verifier_run_findings_equal_classify_output_runs() {
    let a1 = build_a1();
    assert_eq!(
        run_bundles_from_findings(&verify_dir(&a1.dir_path)),
        classify_run_bundles(&a1.dir_path),
        "A1 agreement",
    );
    let a3 = build_a3();
    assert_eq!(
        run_bundles_from_findings(&verify_dir(&a3.dir_path)),
        classify_run_bundles(&a3.dir_path),
        "A3 agreement",
    );
    let a8 = build_a8();
    assert_eq!(
        run_bundles_from_findings(&verify_dir(&a8.dir_path)),
        classify_run_bundles(&a8.dir_path),
        "A8 agreement",
    );
    let a9 = build_a9();
    assert_eq!(
        run_bundles_from_findings(&verify_dir(&a9.dir_path)),
        classify_run_bundles(&a9.dir_path),
        "A9 agreement",
    );
    // R5 shape (p07): both sides emit the empty run set.
    let r5_dir = Temp::new();
    let e0 = entry_rec(0, crate::audit::Record::genesis(&TRAIL));
    let fold = seeded(&e0);
    let close = signed_cp(1, e0.hash(), &fold);
    let resume = resume_decl(&close, 0, e0.hash(), 0);
    fs::write(
        r5_dir
            .0
            .join("audit-20260101T000000.000000000Z_000000.jsonl"),
        line_bytes(&e0),
    )
    .unwrap();
    write_records(&r5_dir.0, &[&close, &resume]);
    assert_eq!(
        run_bundles_from_findings(&verify_dir(&r5_dir.0)),
        classify_run_bundles(&r5_dir.0),
        "R5 (p07) agreement: both sides empty",
    );
    // R6: non-increasing seq empties runs.
    let r6_dir = Temp::new();
    let cp0 = signed_cp(
        0,
        crate::audit::Record::genesis(&TRAIL),
        &crate::audit::Mmr::new(),
    );
    let e1 = entry_rec(1, cp0.hash());
    crate::audit::runs_v4a_fixtures::put_segment(&r6_dir.0, 0, &[&cp0, &e1], &[]);
    let r4 = headless(&e1, 4);
    let roll = entry_rec(1, r4.hash());
    crate::audit::runs_v4a_fixtures::put_segment(&r6_dir.0, 1, &[&r4, &roll], &[]);
    let mmr1 = pushed(&seeded(&cp0), &e1);
    let mmr4 = pushed(&mmr1, &r4);
    let close = signed_cp(5, r4.hash(), &mmr4);
    let resume = resume_decl(&close, 4, r4.hash(), 4);
    write_records(&r6_dir.0, &[&close, &resume]);
    assert_eq!(
        run_bundles_from_findings(&verify_dir(&r6_dir.0)),
        classify_run_bundles(&r6_dir.0),
        "R6 agreement: both sides empty",
    );
    // R7: archive run closed inside — one bundle on each side.
    let (r7, r7_s0, _r7_s1, _r7_s2) = build_archive_closed_inside();
    let r7_dir = r7_s0.parent().unwrap().to_owned();
    assert_eq!(
        run_bundles_from_findings(&verify_dir(&r7_dir)),
        classify_run_bundles(&r7_dir),
        "R7 agreement",
    );
    drop(r7);
    // R8: archive open at the end — empty on each side.
    let r8_dir = Temp::new();
    let cp0 = signed_cp(
        0,
        crate::audit::Record::genesis(&TRAIL),
        &crate::audit::Mmr::new(),
    );
    let e1 = entry_rec(1, cp0.hash());
    let e2 = entry_rec(2, e1.hash());
    crate::audit::runs_v4a_fixtures::put_segment(&r8_dir.0, 0, &[&cp0, &e1, &e2], &[]);
    let r4 = headless(&e2, 4);
    crate::audit::runs_v4a_fixtures::put_segment(&r8_dir.0, 1, &[&r4], &[]);
    assert_eq!(
        run_bundles_from_findings(&verify_dir(&r8_dir.0)),
        classify_run_bundles(&r8_dir.0),
        "R8 agreement",
    );
    // The split archive+trail form is pinned literally by R10
    // (ruling 13-V4-d8 point 2: one classify over the merged
    // Collection), not by this agreement row.
}

// ============================================================
// R14 — ruling 13-V4-d9: a torn fragment appended to the live
// (closing) segment is excluded from the run's spans and digest.
// The run finding's digest stays pinned to A1's `79d8cb1c…`, and
// the detail carries no `span` entry from the closer.
// ============================================================

#[test]
fn r14_d9_a1_torn_live_tail_run_digest_unchanged() {
    let a = build_a1();
    // Append a torn JSON fragment (6 bytes, no trailing newline) to
    // the live closer. Ruling 13-V4-d9: this fragment lands in the
    // closer segment (last_segment) and is excluded from the run's
    // spans and its run digest.
    fs::OpenOptions::new()
        .append(true)
        .open(a.dir_path.join("audit.jsonl"))
        .unwrap()
        .write_all(b"{\"half")
        .unwrap();
    let s1 = a
        .dir_path
        .join("audit-20260101T000000.000000000Z_000001.jsonl");
    let live = a.dir_path.join("audit.jsonl");
    let a1_digest = parse_digest(A1_DIGEST);
    // Detail: A1's one loss range, no span entries, A1's pinned digest.
    let run_detail = make_run_detail(&[(4, 3, 1)], &[], &a1_digest);
    let per_seg_detail = "expected first complete record to be a checkpoint".to_owned();
    let resume_detail = "operator=operator reason=incident \
         head=5:blake3:4181d394847e4274645a1b39a8366b0217c32abc5ab45e4dbee9f064c25361aa \
         gap=none lost_records=0 structural=valid"
        .to_owned();
    // The 6-byte `{"half` fragment hashes to this blake3 digest; a
    // mutant that admits the fragment into the run's spans would
    // make this digest appear in the run detail (flipping R14).
    let torn_gap_detail = "trailing gap lines 3..=3 (6 bytes), \
         digest blake3:d9a5b587318eff723676e5ae0e4f95bc2b2617255722fea8409d547b4cb020cc"
        .to_owned();
    let expected = vec![
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            per_seg_detail,
            None,
        ),
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            run_detail,
            Some(digest_string(&a1_digest)),
        ),
        (
            K::SeqGap,
            Some(s1),
            Some(1),
            Some(4),
            "missing seq 3..=3".to_owned(),
            None,
        ),
        (
            K::Resumed,
            Some(live.clone()),
            Some(2),
            Some(7),
            resume_detail,
            None,
        ),
        (
            K::UncoveredTail,
            None,
            None,
            None,
            "records seq 7..=7".to_owned(),
            None,
        ),
        (
            K::TornWrite,
            Some(live),
            Some(3),
            None,
            torn_gap_detail,
            None,
        ),
    ];
    assert_eq!(
        rows(&verify_dir(&a.dir_path)),
        expected,
        "R14 (ruling 13-V4-d9): A1+torn live emits one run finding with A1's \
         pinned digest `79d8cb1c…` and NO `span` entry in the detail (closer \
         fragment excluded); TornWrite records the torn trailing bytes with \
         their own gap digest, distinct from A1's pinned run digest",
    );
}

// ============================================================
// R15 — ruling 13-V4-d9: p01 shape (sealed closer that re-opens)
// places the closer segment's trailing fragment in run 2 ONLY,
// never run 1. Asserts literal spans on both runs.
// ============================================================

#[test]
fn r15_d9_p01_closer_span_in_second_run_only() {
    // p01 shape built with the shared classifier-level helpers so
    // the layout matches `closer_spans_excluded_in_sealed_closer_p01`.
    use crate::audit::storage::tests::{self as st, runs as st_runs};
    let d = st::Temp::new();
    let first = st_runs::base(&d);
    st_runs::put(&d, 0, &[&first], &[]);
    let kept = st_runs::headless(&first, 3);
    st_runs::put(&d, 1, &[&kept], &[]);
    let mut fold = st::seeded_pair(&first, &kept);
    let (checkpoint, resume) = st_runs::close_run(&d, &kept, &fold);
    st_runs::put(&d, 2, &[&checkpoint, &resume], b"broken\n");
    fold.push(checkpoint.hash()).unwrap();
    fold.push(resume.hash()).unwrap();
    let _ = st_runs::close_run(&d, &resume, &fold);
    let s1 = d.0.join("audit-20260101T000000.000000000Z_000001.jsonl");
    let s2 = d.0.join("audit-20260101T000000.000000000Z_000002.jsonl");
    let live = d.0.join("audit.jsonl");
    // Run 1 lives over S1 only (closer S2 excluded per ruling
    // 13-V4-d9), so it has no `span` entry; its single loss point
    // is `seq 3 first 1 count 2` (missing seqs 1..=2 before `kept`).
    let run1_digest =
        parse_digest("blake3:704ee3cfabb1bc4a578dfa0f678084188f7ccb8fede0f6077d0c2a621a479656");
    let run1_detail = make_run_detail(&[(3, 1, 2)], &[], &run1_digest);
    // Run 2 lives over S2 only (its own first segment, closer is the
    // live file). S2's trailing `broken\n` is a 7-byte span sitting
    // after seq 8 (S2's `resume` record on this fixture; ruling
    // 13-V4-d8 point 1).
    let broken_span_digest =
        parse_digest("blake3:8b09328c8766397df3eadace558cdd4ef653e8df4e7526bc3dce37e6dfd62116");
    let run2_digest =
        parse_digest("blake3:6bfc835246e5c5bed97d27e155faf709a50bf972f1ccdadcf6ea1545c0039b46");
    let run2_detail = make_run_detail(&[], &[(0, Some(8), 7, broken_span_digest)], &run2_digest);
    let per_seg_detail = "expected first complete record to be a checkpoint".to_owned();
    // Pin the two `Resumed` details literally; both are deterministic
    // from the fixture inputs. First `Resumed` cites `kept`'s hash;
    // the second cites `resume`'s hash. Their `gap=` suffix carries
    // the loss range `kept` opened (seqs 4..=6) and the final closer
    // opened (seqs 9..=11).
    let resume1_detail = "operator=operator reason=incident \
         head=3:blake3:e8a61e83396580ddf71275b181d0fe95bb922083544ae6767d001cb35fdf2cd4 \
         gap=4..=6 lost_records=0 structural=valid"
        .to_owned();
    let resume2_detail = "operator=operator reason=incident \
         head=8:blake3:3fe635742eb540ce2a878ab83bdf08ac4b41667c8afb405e94f5810a5e05324a \
         gap=9..=11 lost_records=0 structural=valid"
        .to_owned();
    let torn_gap_detail = "trailing gap lines 3..=3 (7 bytes), \
         digest blake3:8b09328c8766397df3eadace558cdd4ef653e8df4e7526bc3dce37e6dfd62116"
        .to_owned();
    let expected = vec![
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(3),
            per_seg_detail,
            None,
        ),
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(3),
            run1_detail,
            Some(digest_string(&run1_digest)),
        ),
        (
            K::SeqGap,
            Some(s1),
            Some(1),
            Some(3),
            "missing seq 1..=2".to_owned(),
            None,
        ),
        (
            K::SegmentStructure,
            Some(s2.clone()),
            Some(1),
            Some(7),
            run2_detail,
            Some(digest_string(&run2_digest)),
        ),
        (
            K::SeqGap,
            Some(s2.clone()),
            Some(1),
            Some(7),
            "missing seq 4..=6".to_owned(),
            None,
        ),
        (
            K::Resumed,
            Some(s2.clone()),
            Some(2),
            Some(8),
            resume1_detail,
            None,
        ),
        (
            K::SeqGap,
            Some(live.clone()),
            Some(1),
            Some(12),
            "missing seq 9..=11".to_owned(),
            None,
        ),
        (
            K::Resumed,
            Some(live),
            Some(2),
            Some(13),
            resume2_detail,
            None,
        ),
        (
            K::UncoveredTail,
            None,
            None,
            None,
            "records seq 13..=13".to_owned(),
            None,
        ),
        (
            K::TornWrite,
            Some(s2.clone()),
            Some(3),
            None,
            torn_gap_detail,
            None,
        ),
        (
            K::Unparsable,
            Some(s2),
            Some(3),
            None,
            "CorruptTrail: Unparsable: invalid audit v1 OTLP line".to_owned(),
            None,
        ),
    ];
    assert_eq!(
        rows(
            Verifier::new(policy_trail())
                .verify_dir(&d.0)
                .unwrap()
                .findings(),
        ),
        expected,
        "R15 (ruling 13-V4-d9) p01 full literal finding list: run 1 at S1 \
         with NO `span` entry (closer S2 excluded); run 2 at S2 with exactly \
         one `span seg 0 after 8 len 7` for S2's trailing `broken\\n`; \
         run 1 and run 2 digests pinned literally",
    );
}

// ============================================================
// R16 / R17 — M10 killers (last tuple's `is_live` forced `true`).
// M10 only perturbs the archive case (no native live file), so each
// killer is an archive whose closer is the last tuple.
//
// R16: the R7 archive with a torn `not json\n` fragment appended to
// its closer S2. Head: one run finding at S1 with A1's one-range
// detail and digest (ruling 13-V4-d9: the appended fragment lands
// in the closer and is excluded). Under M10 the walker takes the
// live arm on S2, breaks on the torn tail, and emits zero run
// findings; the assertion flips.
//
// R17: A8-as-archive (same A8 layout but no live file; the closer
// sits at S2). Head: one run finding at S1 with A8's digest. Under
// M10 the live arm on S2 changes the closer's classification and
// the row's count flips.
// ============================================================

#[test]
fn r16_m10_r7_archive_torn_closer_run_finding_unchanged() {
    let (_d, _s0, s1, s2) = build_archive_closed_inside();
    let dir = _s0.parent().unwrap().to_owned();
    fs::OpenOptions::new()
        .append(true)
        .open(&s2)
        .unwrap()
        .write_all(b"not json\n")
        .unwrap();
    let a1_digest = parse_digest(A1_DIGEST);
    let run_detail = make_run_detail(&[(4, 3, 1)], &[], &a1_digest);
    let per_seg_detail = "expected first complete record to be a checkpoint".to_owned();
    let resume_detail = "operator=operator reason=incident \
         head=5:blake3:4181d394847e4274645a1b39a8366b0217c32abc5ab45e4dbee9f064c25361aa \
         gap=none lost_records=0 structural=valid"
        .to_owned();
    let torn_gap_detail = "trailing gap lines 3..=3 (9 bytes), \
         digest blake3:8b78e71ce40a5c8ed68f53d8601ac823e803eb9366d24f963163e8524438ce8a"
        .to_owned();
    let expected = vec![
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            per_seg_detail,
            None,
        ),
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            run_detail,
            Some(digest_string(&a1_digest)),
        ),
        (
            K::SeqGap,
            Some(s1),
            Some(1),
            Some(4),
            "missing seq 3..=3".to_owned(),
            None,
        ),
        (
            K::Resumed,
            Some(s2.clone()),
            Some(2),
            Some(7),
            resume_detail,
            None,
        ),
        (
            K::UncoveredTail,
            None,
            None,
            None,
            "records seq 7..=7".to_owned(),
            None,
        ),
        (
            K::TornWrite,
            Some(s2.clone()),
            Some(3),
            None,
            torn_gap_detail,
            None,
        ),
        (
            K::Unparsable,
            Some(s2),
            Some(3),
            None,
            "CorruptTrail: Unparsable: invalid audit v1 OTLP line".to_owned(),
            None,
        ),
    ];
    assert_eq!(
        rows(&verify_dir(&dir)),
        expected,
        "R16 (M10 killer 1): R7-archive with torn closer still emits one run finding at head \
         (ruling 13-V4-d9 excludes closer bytes). M10 (last tuple is_live=true) flips this.",
    );
}

#[test]
fn r17_m10_a8_as_archive_torn_closer_run_finding_unchanged() {
    // A8-as-archive with a torn fragment appended to the closing
    // S2. This is a distinct layout from R16 (A8 has an EMPTY S1
    // mid-run; R7's S1 carries a headless + checkpoint). At head
    // the closer fires via the sealed arm, S2's `not json\n` lands
    // in the closer segment and is excluded (ruling 13-V4-d9), so
    // one run finding is emitted at S1 with A8's digest. Under M10
    // the live arm walks S2, breaks on the torn tail, and emits
    // zero run findings; the assertion flips.
    let d = Temp::new();
    let cp0 = signed_cp(
        0,
        crate::audit::Record::genesis(&TRAIL),
        &crate::audit::Mmr::new(),
    );
    crate::audit::runs_v4a_fixtures::put_segment(&d.0, 0, &[&cp0], &[]);
    crate::audit::runs_v4a_fixtures::put_segment(&d.0, 1, &[], &[]);
    let fold = seeded(&cp0);
    let cp_opening = signed_cp(1, cp0.hash(), &fold);
    let resume = resume_decl(&cp_opening, 0, cp0.hash(), 0);
    crate::audit::runs_v4a_fixtures::put_segment(&d.0, 2, &[&cp_opening, &resume], b"not json\n");
    let s1 = d.0.join("audit-20260101T000000.000000000Z_000001.jsonl");
    let s2 = d.0.join("audit-20260101T000000.000000000Z_000002.jsonl");
    let a8_digest = parse_digest(A8_DIGEST);
    let per_seg_detail = "expected first complete record to be a checkpoint".to_owned();
    let run_detail = make_run_detail(&[], &[], &a8_digest);
    let resume_detail = "operator=operator reason=incident \
         head=0:blake3:fc26c6f2bb830592aaaca5413da1599489d86ac6e240a4a7a010681e0d4c8e77 \
         gap=none lost_records=0 structural=valid"
        .to_owned();
    // The torn trailing bytes are the same 9 bytes as R16 (same
    // `not json\n`), so the TornWrite/Unparsable detail bytes-digest
    // and seq placement match.
    let torn_gap_detail = "trailing gap lines 3..=3 (9 bytes), \
         digest blake3:8b78e71ce40a5c8ed68f53d8601ac823e803eb9366d24f963163e8524438ce8a"
        .to_owned();
    let expected = vec![
        (
            K::Resumed,
            Some(s2.clone()),
            Some(2),
            Some(2),
            resume_detail,
            None,
        ),
        (
            K::UncoveredTail,
            None,
            None,
            None,
            "records seq 2..=2".to_owned(),
            None,
        ),
        (
            K::SegmentStructure,
            Some(s1.clone()),
            None,
            None,
            per_seg_detail,
            None,
        ),
        (
            K::SegmentStructure,
            Some(s1),
            None,
            None,
            run_detail,
            Some(digest_string(&a8_digest)),
        ),
        (
            K::TornWrite,
            Some(s2.clone()),
            Some(3),
            None,
            torn_gap_detail,
            None,
        ),
        (
            K::Unparsable,
            Some(s2),
            Some(3),
            None,
            "CorruptTrail: Unparsable: invalid audit v1 OTLP line".to_owned(),
            None,
        ),
    ];
    assert_eq!(
        rows(&verify_dir(&d.0)),
        expected,
        "R17 (M10 killer 2): A8-as-archive with torn closer emits one run finding at head \
         with A8's digest (closer bytes excluded, ruling 13-V4-d9). M10 flips this.",
    );
}

// ============================================================
// R18 / R19 — regression rows for M11 and MS. Each row's main
// assertion ("zero run findings" on an A1/A3 layout plus a torn
// tail appended to the live file) is already true on base, since
// on base there is no V4a code and no run findings exist for any
// layout. The regression is against the V4a code at head, where
// two distinct mutants flip the row:
//   * M11 (every `is_live` forced `false`): the live tuple is
//     treated as sealed, the walker accepts its closer, and one
//     run finding is emitted; the literal row count flips.
//   * MS (drop the "any violation empties `runs`" rule in
//     `runs::classify`): torn tail on the live closer fires
//     `Violation::InvalidLineOrOpeningCheckpoint` on segment 2 at
//     head and the walker still classifies Base/InRun/Closer; the
//     suppression rule is the only reason `runs` is empty here,
//     so MS flips the row to one run finding.
// Head behaviour: torn tail on the live file prevents the closer
// from firing (the walker's violation suppresses `runs`), so zero
// run findings are emitted. Each row is therefore a measured
// killer for both M11 and MS (exit 101).
// ============================================================

#[test]
fn r18_m11_a1_torn_live_no_run_finding() {
    let a = build_a1();
    fs::OpenOptions::new()
        .append(true)
        .open(a.dir_path.join("audit.jsonl"))
        .unwrap()
        .write_all(b"not json\n")
        .unwrap();
    let s1 = a
        .dir_path
        .join("audit-20260101T000000.000000000Z_000001.jsonl");
    let live = a.dir_path.join("audit.jsonl");
    let per_seg_detail = "expected first complete record to be a checkpoint".to_owned();
    let resume_detail = "operator=operator reason=incident \
         head=5:blake3:4181d394847e4274645a1b39a8366b0217c32abc5ab45e4dbee9f064c25361aa \
         gap=none lost_records=0 structural=valid"
        .to_owned();
    let torn_gap_detail = "trailing gap lines 3..=3 (9 bytes), \
         digest blake3:8b78e71ce40a5c8ed68f53d8601ac823e803eb9366d24f963163e8524438ce8a"
        .to_owned();
    let expected = vec![
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            per_seg_detail,
            None,
        ),
        (
            K::SeqGap,
            Some(s1),
            Some(1),
            Some(4),
            "missing seq 3..=3".to_owned(),
            None,
        ),
        (
            K::Resumed,
            Some(live.clone()),
            Some(2),
            Some(7),
            resume_detail,
            None,
        ),
        (
            K::UncoveredTail,
            None,
            None,
            None,
            "records seq 7..=7".to_owned(),
            None,
        ),
        (
            K::TornWrite,
            Some(live.clone()),
            Some(3),
            None,
            torn_gap_detail,
            None,
        ),
        (
            K::Unparsable,
            Some(live),
            Some(3),
            None,
            "CorruptTrail: Unparsable: invalid audit v1 OTLP line".to_owned(),
            None,
        ),
    ];
    assert_eq!(
        rows(&verify_dir(&a.dir_path)),
        expected,
        "R18 (M11 killer 1): A1+torn live emits ZERO run findings at head (the \
         torn tail prevents the live closer). M11 (every is_live=false) sends \
         live through the sealed arm and flips the row to one run finding.",
    );
}

#[test]
fn r19_m11_a3_torn_live_no_run_finding() {
    let a = build_a3();
    fs::OpenOptions::new()
        .append(true)
        .open(a.dir_path.join("audit.jsonl"))
        .unwrap()
        .write_all(b"not json\n")
        .unwrap();
    let s1 = a
        .dir_path
        .join("audit-20260101T000000.000000000Z_000001.jsonl");
    let s2 = a
        .dir_path
        .join("audit-20260101T000000.000000000Z_000002.jsonl");
    let live = a.dir_path.join("audit.jsonl");
    let per_seg_detail = "expected first complete record to be a checkpoint".to_owned();
    let resume_detail = "operator=operator reason=incident \
         head=8:blake3:436c1a38d9dd40b9880233500e5c4c97783f180fcc0eb9c8376bee20e791d2ce \
         gap=9..=9 lost_records=0 structural=valid"
        .to_owned();
    let torn_gap_detail = "trailing gap lines 3..=3 (9 bytes), \
         digest blake3:8b78e71ce40a5c8ed68f53d8601ac823e803eb9366d24f963163e8524438ce8a"
        .to_owned();
    let expected = vec![
        (
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            per_seg_detail.clone(),
            None,
        ),
        (
            K::SeqGap,
            Some(s1),
            Some(1),
            Some(4),
            "missing seq 3..=3".to_owned(),
            None,
        ),
        (
            K::SegmentStructure,
            Some(s2.clone()),
            Some(1),
            Some(7),
            per_seg_detail,
            None,
        ),
        (
            K::SeqGap,
            Some(s2),
            Some(1),
            Some(7),
            "missing seq 6..=6".to_owned(),
            None,
        ),
        (
            K::SeqGap,
            Some(live.clone()),
            Some(1),
            Some(10),
            "missing seq 9..=9".to_owned(),
            None,
        ),
        (
            K::Resumed,
            Some(live.clone()),
            Some(2),
            Some(11),
            resume_detail,
            None,
        ),
        (
            K::UncoveredTail,
            None,
            None,
            None,
            "records seq 11..=11".to_owned(),
            None,
        ),
        (
            K::TornWrite,
            Some(live.clone()),
            Some(3),
            None,
            torn_gap_detail,
            None,
        ),
        (
            K::Unparsable,
            Some(live),
            Some(3),
            None,
            "CorruptTrail: Unparsable: invalid audit v1 OTLP line".to_owned(),
            None,
        ),
    ];
    assert_eq!(
        rows(&verify_dir(&a.dir_path)),
        expected,
        "R19 (M11 killer 2): A3+torn live emits ZERO run findings at head; \
         M11 flips this to one run finding by treating live as sealed.",
    );
}

// ============================================================
// R20 — ruling 13-V4-d8 point 2 (one classify over the merged
// `Collection`): an A3-layout trail split into an archive directory
// (the sealed segments S0, S1, S2 — including the run's first
// segment S1) and a trail directory (the live file), verified in
// ONE `Verifier::verify_files` call with both directories. The run
// spans both directories, so the single classify pass must see them
// together; its one run finding falls at the archived first segment
// S1 with A3's pinned digest `78d50888…`.
//
// Second killer for the per-directory classification mutant (call
// `classify` once per `path.parent()` group of `natives` instead of
// once over all of them): neither the archive group (no live-file
// closer) nor the trail group (no run opener) emits the run finding
// under the mutant, so the literal list flips. R10 kills the same
// mutant with a different layout (archive-plus-trail split of the
// R7 archive, A1's digest `79d8cb1c…`); R20 is the distinct second
// killer. Regression row for the mutant: this row passes on base
// `origin/dev` because the classify pass at that head already runs
// once over the merged Collection.
// ============================================================

#[test]
fn r20_227_cross_dir_a3_archive_plus_trail_dir_one_classify() {
    /// Rebase each finding's file path onto `base_dir`, keeping only
    /// its basename (every A3 segment lives at its dir root).
    fn relative(got: Vec<Row>, base_dir: &Path) -> Vec<Row> {
        got.into_iter()
            .map(|r| {
                let rebased = r.1.map(|p| {
                    let name = p.file_name().expect("row file path has a basename");
                    base_dir.join(name)
                });
                (r.0, rebased, r.2, r.3, r.4, r.5)
            })
            .collect()
    }
    let common = Path::new("base");
    let a = build_a3();
    // Split A3: sealed S0, S1, S2 land in `archive_dir`; the live
    // `audit.jsonl` lands in `trail_dir`. Both directories pass
    // through the same `verify_files` call so the merged
    // `Collection` is classified once (ruling 13-V4-d8 point 2),
    // producing exactly one run finding at S1 with A3's digest.
    let s0_name = "audit-20260101T000000.000000000Z_000000.jsonl";
    let s1_name = "audit-20260101T000000.000000000Z_000001.jsonl";
    let s2_name = "audit-20260101T000000.000000000Z_000002.jsonl";
    let archive_dir = Temp::new();
    let trail_dir = Temp::new();
    for name in [s0_name, s1_name, s2_name] {
        fs::copy(a.dir_path.join(name), archive_dir.0.join(name)).unwrap();
    }
    fs::copy(
        a.dir_path.join("audit.jsonl"),
        trail_dir.0.join("audit.jsonl"),
    )
    .unwrap();
    let s1 = Path::new(s1_name);
    let s2 = Path::new(s2_name);
    let live = Path::new("audit.jsonl");
    let a3_digest = parse_digest(A3_DIGEST);
    // A3's two loss points and the full A3 digest: ruling 13-V4-d8
    // point 1 grammar; ADR-0005 decision 11 digest pin.
    let run_detail = make_run_detail(&[(4, 3, 1), (7, 6, 1)], &[], &a3_digest);
    let per_seg_detail = "expected first complete record to be a checkpoint".to_owned();
    // A3's `Resumed` head citation is `cp8.hash`, captured here as
    // a literal (same as R2's A3 row).
    let resume_detail = "operator=operator reason=incident \
         head=8:blake3:436c1a38d9dd40b9880233500e5c4c97783f180fcc0eb9c8376bee20e791d2ce \
         gap=9..=9 lost_records=0 structural=valid"
        .to_owned();
    let expected = vec![
        (
            K::SegmentStructure,
            Some(common.join(s1)),
            Some(1),
            Some(4),
            per_seg_detail.clone(),
            None,
        ),
        (
            K::SegmentStructure,
            Some(common.join(s1)),
            Some(1),
            Some(4),
            run_detail,
            Some(digest_string(&a3_digest)),
        ),
        (
            K::SeqGap,
            Some(common.join(s1)),
            Some(1),
            Some(4),
            "missing seq 3..=3".to_owned(),
            None,
        ),
        (
            K::SegmentStructure,
            Some(common.join(s2)),
            Some(1),
            Some(7),
            per_seg_detail,
            None,
        ),
        (
            K::SeqGap,
            Some(common.join(s2)),
            Some(1),
            Some(7),
            "missing seq 6..=6".to_owned(),
            None,
        ),
        (
            K::SeqGap,
            Some(common.join(live)),
            Some(1),
            Some(10),
            "missing seq 9..=9".to_owned(),
            None,
        ),
        (
            K::Resumed,
            Some(common.join(live)),
            Some(2),
            Some(11),
            resume_detail,
            None,
        ),
        (
            K::UncoveredTail,
            None,
            None,
            None,
            "records seq 11..=11".to_owned(),
            None,
        ),
    ];
    let split_rows = relative(
        rows(&verify_files([archive_dir.0.clone(), trail_dir.0.clone()])),
        common,
    );
    assert_eq!(
        split_rows, expected,
        "R20 (ruling 13-V4-d8 point 2): verify_files([archive_dir, trail_dir]) \
         on an A3 split (sealed S0/S1/S2 in archive_dir, live in trail_dir) \
         emits one run finding at the archived first segment S1 with A3's \
         pinned digest `78d50888…` (the full literal finding list, rebased)",
    );
}
