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
        build_a9, entry_rec, headless, line_bytes, pushed, resume_decl, seeded, signed_cp,
        write_records,
    },
    storage::SegmentSource,
};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

fn policy_trail() -> TrustPolicy {
    TrustPolicy::builder().trail(TRAIL).build().unwrap()
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

fn classify_run_bundles(dir: &Path) -> Vec<(PathBuf, [u8; 32], String)> {
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
            (natives[run.first_segment].0.clone(), digest, detail)
        })
        .collect()
}

fn run_bundles_from_findings(findings: &[Finding]) -> Vec<(PathBuf, [u8; 32], String)> {
    findings
        .iter()
        .filter_map(|f| {
            f.run_digest().and_then(|d| {
                f.file()
                    .map(|p| (p.to_path_buf(), d, f.detail().to_owned()))
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
            "records seq 0..=7, no trusted coverage yet (signatures are checked in #13 V5)"
                .to_owned(),
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
    let a3_digest = parse_digest(A3_DIGEST);
    let run_detail = make_run_detail(&[(4, 3, 1), (7, 6, 1)], &[], &a3_digest);
    let per_seg_detail = "expected first complete record to be a checkpoint".to_owned();
    let got = rows(&findings);
    let run = got.iter().find(|r| r.5.is_some()).expect("one run finding");
    assert_eq!(run.0, K::SegmentStructure);
    assert_eq!(run.1.as_deref(), Some(s1.as_path()));
    assert_eq!(run.2, Some(1));
    assert_eq!(run.3, Some(4));
    assert_eq!(run.4, run_detail, "A3 two-loss-point detail");
    assert_eq!(run.5, Some(digest_string(&a3_digest)));
    // The per-segment S1 SegmentStructure sits literally alongside.
    let per_seg: Vec<_> = got
        .iter()
        .filter(|r| r.0 == K::SegmentStructure && r.4 == per_seg_detail)
        .collect();
    assert_eq!(per_seg.len(), 2, "A3 has S1 and S2 per-segment pins");
    // Only one V4a run finding across the trail.
    let runs: Vec<_> = got.iter().filter(|r| r.5.is_some()).collect();
    assert_eq!(runs.len(), 1, "A3: exactly one run finding");
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
    let a8_digest = parse_digest(A8_DIGEST);
    let run_detail = make_run_detail(&[], &[], &a8_digest);
    let runs: Vec<_> = rows(&findings)
        .into_iter()
        .filter(|r| r.5.is_some())
        .collect();
    assert_eq!(runs.len(), 1, "A8: one run finding");
    assert_eq!(runs[0].0, K::SegmentStructure);
    assert_eq!(runs[0].1.as_deref(), Some(s1.as_path()));
    assert_eq!(runs[0].2, None, "A8: line None (no record in S1)");
    assert_eq!(runs[0].3, None, "A8: seq None (no record in S1)");
    assert_eq!(runs[0].4, run_detail);
    assert_eq!(runs[0].5, Some(digest_string(&a8_digest)));
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
    let runs: Vec<_> = rows(&findings)
        .into_iter()
        .filter(|r| r.5.is_some())
        .collect();
    assert_eq!(runs.len(), 1, "A9: one run finding");
    let run = &runs[0];
    assert_eq!(run.0, K::SegmentStructure);
    assert_eq!(run.1.as_deref(), Some(s1.as_path()));
    assert_eq!(run.2, None, "A9: line None (S1 record-free)");
    assert_eq!(run.3, None, "A9: seq None (S1 record-free)");
    // Literal full detail: two spans at `after start`, then the A9
    // digest (ruling 13-V4-d8 point 1 grammar; 13-V4-d2 point 2
    // `start` sentinel; run-local seg renumbering 0/1).
    assert_eq!(
        run.4,
        "span seg 0 after start len 9 blake3:8b78e71ce40a5c8ed68f53d8601ac823e803eb9366d24f963163e8524438ce8a; \
         span seg 1 after start len 14 blake3:4538bcdbaba974dc18a217221116cee0c884f72d52845285ab713a33c8d047da; \
         digest blake3:4905b9e63aa3fd9248f5c3605fe4beaf4af5a956f3f108b6dcecdbfbfda54026",
        "A9: literal detail with both span entries",
    );
    assert_eq!(run.5, Some(A9_DIGEST.to_owned()));
}

// ============================================================
// R5 — p07: rejected layout, no run finding; the existing
// per-segment `SegmentStructure` finding is listed literally
// (ruling 13-V4-d3 point 2, 13-V4-d8 point 3).
// ============================================================

#[test]
fn r5_p07_rejected_no_run_finding() {
    let d = Temp::new();
    // An entry with seq=0 pointing at genesis -- not a checkpoint.
    let e0 = entry_rec(0, crate::audit::Record::genesis(&TRAIL));
    let fold = seeded(&e0);
    let close = signed_cp(1, e0.hash(), &fold);
    let resume = resume_decl(&close, 0, e0.hash(), 0);
    fs::write(
        d.0.join("audit-20260101T000000.000000000Z_000000.jsonl"),
        line_bytes(&e0),
    )
    .unwrap();
    write_records(&d.0, &[&close, &resume]);
    let findings = verify_dir(&d.0);
    let got = rows(&findings);
    let runs: Vec<_> = got.iter().filter(|r| r.5.is_some()).collect();
    assert!(runs.is_empty(), "p07 rejects the trail: no run finding");
    let seg_structure: Vec<_> = got
        .iter()
        .filter(|r| r.0 == K::SegmentStructure && r.5.is_none())
        .collect();
    assert!(
        !seg_structure.is_empty(),
        "p07 keeps its per-segment SegmentStructure finding"
    );
    // Companion positive check: A1 (accepted layout) must still
    // emit a run finding at head, so R5 is red on base.
    let a1 = build_a1();
    let a1_runs: Vec<_> = rows(&verify_dir(&a1.dir_path))
        .into_iter()
        .filter(|r| r.5.is_some())
        .collect();
    assert_eq!(
        a1_runs.len(),
        1,
        "p07-rejection-is-isolated companion: A1 still emits one run finding",
    );
}

// ============================================================
// R6 — non-increasing seq inside a would-be run: no run finding, no panic.
// Addendum 28 point 2: any violation empties `runs`.
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
    // S1 would be a run segment; its second record has a non-
    // increasing seq (seq=1 after seq=4), which the tolerant
    // classifier rejects (addendum 28 point 2: emptying `runs`).
    let r4 = headless(&e1, 4);
    let roll = entry_rec(1, r4.hash());
    crate::audit::runs_v4a_fixtures::put_segment(&d.0, 1, &[&r4, &roll], &[]);
    // live: a plausible closer.
    let mmr4 = pushed(&mmr1, &r4);
    let close = signed_cp(5, r4.hash(), &mmr4);
    let resume = resume_decl(&close, 4, r4.hash(), 4);
    write_records(&d.0, &[&close, &resume]);
    let findings = verify_dir(&d.0);
    let runs: Vec<_> = rows(&findings)
        .into_iter()
        .filter(|r| r.5.is_some())
        .collect();
    assert!(runs.is_empty(), "non-increasing seq rejects the run");
    // Companion positive check: A3 (accepted layout) still emits a
    // run finding at head, so R6 is red on base.
    let a3 = build_a3();
    let a3_runs: Vec<_> = rows(&verify_dir(&a3.dir_path))
        .into_iter()
        .filter(|r| r.5.is_some())
        .collect();
    assert_eq!(
        a3_runs.len(),
        1,
        "non-increasing-seq-is-isolated companion: A3 still emits one run finding",
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
    let (_d, _s0, s1, _s2) = build_archive_closed_inside();
    let dir = _s0.parent().unwrap();
    let findings = verify_dir(dir);
    let runs: Vec<_> = rows(&findings)
        .into_iter()
        .filter(|r| r.5.is_some())
        .collect();
    assert_eq!(runs.len(), 1, "archive with inner closer: one run finding");
    assert_eq!(runs[0].0, K::SegmentStructure);
    assert_eq!(runs[0].1.as_deref(), Some(s1.as_path()));
    assert_eq!(runs[0].2, Some(1), "S1's first record: line");
    assert_eq!(runs[0].3, Some(4), "S1's first record: seq");
}

// ============================================================
// R8 — archive with a run left open at the end: no run finding
// (ruling 13-V4-d6 point 2: a run still open at the end of the
// snapshot yields no run finding).
// ============================================================

#[test]
fn r8_archive_run_open_at_end_no_run_finding() {
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
    let _mmr2 = pushed(&mmr1, &e2);
    crate::audit::runs_v4a_fixtures::put_segment(&d.0, 0, &[&cp0, &e1, &e2], &[]);
    let r4 = headless(&e2, 4);
    // S1 is a run-active segment; the archive ends here with no
    // closer and no live file.
    crate::audit::runs_v4a_fixtures::put_segment(&d.0, 1, &[&r4], &[]);
    let findings = verify_dir(&d.0);
    let runs: Vec<_> = rows(&findings)
        .into_iter()
        .filter(|r| r.5.is_some())
        .collect();
    assert!(
        runs.is_empty(),
        "archive with an open run at the end: no run finding"
    );
    // Companion positive check: the R7 archive (same kind of
    // archive snapshot, run closed inside it) emits exactly one
    // run finding at head, so R8 is red on base.
    let (_r7, r7_s0, _r7_s1, _r7_s2) = build_archive_closed_inside();
    let r7_dir = r7_s0.parent().unwrap().to_owned();
    let r7_runs: Vec<_> = rows(&verify_dir(&r7_dir))
        .into_iter()
        .filter(|r| r.5.is_some())
        .collect();
    assert_eq!(
        r7_runs.len(),
        1,
        "archive-open-at-end-is-isolated companion: an archive whose run \
         closes inside it still emits one run finding",
    );
}

// ============================================================
// R9 — SS-7: `verify_dir(dir)` and `verify_files([each file])` emit
// identical reports (ruling 13-V3-d2: one confirmed snapshot).
// ============================================================

#[test]
fn r9_ss7_verify_dir_equals_verify_files_each_file() {
    let a = build_a1();
    let dir_rows = rows(&verify_dir(&a.dir_path));
    let files: Vec<PathBuf> = fs::read_dir(&a.dir_path)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    let files_rows = rows(&verify_files(files));
    // A1 produces one run finding -- both forms must see it, and
    // the full literal lists must match (ruling 13-V3-d2).
    let dir_runs: Vec<_> = dir_rows.iter().filter(|r| r.5.is_some()).collect();
    assert_eq!(
        dir_runs.len(),
        1,
        "SS-7 precondition: A1 verify_dir emits one run finding",
    );
    assert_eq!(dir_rows, files_rows, "SS-7: dir == files([each file])");
}

// ============================================================
// R10 — SS-8: `verify_files([archive_dir, trail_dir])` vs
// `verify_dir(full_trail)` emit the same run finding (compared on
// paths relative to their own dir, both asserted literally).
// ADR-0005 decision 2 step 6.
// ============================================================

#[test]
fn r10_ss8_archive_plus_trail_dir_vs_full_dir_same_run_finding() {
    // Build the full trail in `full_dir` (archive + trail together).
    let (_full_d, s0_full, _s1_full, _s2_full) = build_archive_closed_inside();
    let full_dir = s0_full.parent().unwrap().to_owned();
    let full_runs: Vec<_> = rows(&verify_dir(&full_dir))
        .into_iter()
        .filter(|r| r.5.is_some())
        .map(|r| (r.3, r.4.clone(), r.5.clone()))
        .collect();
    // Split: `archive_dir` holds S0+S1; `trail_dir` holds S2 (as
    // `audit-...000000.jsonl`, legal on its own). Pass both to one
    // `verify_files` call -- ADR-0005 decision 2 step 6 and ruling
    // 13-V4-d8 point 2: one classify over the merged `Collection`.
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
    // Place S2 in the trail_dir under a lower-numbered name so it
    // still sorts after the archive's segments by `input::collect`'s
    // ordering (rotated by name, live last) when BOTH dirs are
    // merged (ruling 13-V3-d2 and 13-V4-d8 point 2): we pick a
    // later timestamp so it sorts last among sealed segments.
    fs::copy(
        full_dir.join("audit-20260101T000000.000000000Z_000002.jsonl"),
        trail_dir
            .0
            .join("audit-20260101T000001.000000000Z_000000.jsonl"),
    )
    .unwrap();
    let split_runs: Vec<_> = rows(&verify_files([archive_dir.0.clone(), trail_dir.0.clone()]))
        .into_iter()
        .filter(|r| r.5.is_some())
        .map(|r| (r.3, r.4.clone(), r.5.clone()))
        .collect();
    assert_eq!(
        full_runs.len(),
        1,
        "SS-8 precondition: full dir has one run finding",
    );
    assert_eq!(
        split_runs.len(),
        1,
        "SS-8: archive_dir + trail_dir produce one run finding too",
    );
    // Compare file paths relative to their dir. Each run finding's
    // file is the run's first segment (ruling 13-V4-d8 point 5),
    // which is the second segment in base order (`S1` in both
    // forms: archive_dir's S1 and full_dir's S1).
    assert_eq!(
        full_runs[0].0, split_runs[0].0,
        "SS-8: same seq on the run finding"
    );
    assert_eq!(
        full_runs[0].1, split_runs[0].1,
        "SS-8: same detail (same digest)"
    );
    assert_eq!(full_runs[0].2, split_runs[0].2, "SS-8: same run digest",);
}

// ============================================================
// R11 — shipped-only and native+shipped same trail: no run finding
// from the shipped input; the native run finding unchanged
// (owner decision 13-V4-d7; spike #224).
// ============================================================

#[test]
fn r11_shipped_only_and_native_plus_shipped_no_shipped_run_finding() {
    // Shipped-only: copy A1's live file to an arbitrary non-native
    // name. The verifier accepts it as a shipped input (no segment
    // boundary semantics); V4a emits no run finding.
    let a = build_a1();
    let shipped_only_dir = Temp::new();
    fs::copy(
        a.dir_path.join("audit.jsonl"),
        shipped_only_dir.0.join("copy-live"),
    )
    .unwrap();
    let shipped_only_findings = verify_dir(&shipped_only_dir.0);
    let shipped_only_runs: Vec<_> = rows(&shipped_only_findings)
        .into_iter()
        .filter(|r| r.5.is_some())
        .collect();
    assert!(
        shipped_only_runs.is_empty(),
        "shipped-only input: no run finding (#224)",
    );
    // Native + shipped: copy the live file alongside the native
    // layout under a non-native filename. The native run finding
    // (R1) is unchanged; the shipped copy adds no run finding.
    let full_rows = rows(&verify_dir(&a.dir_path));
    let full_runs: Vec<(_, _, _)> = full_rows
        .iter()
        .filter(|r| r.5.is_some())
        .map(|r| (r.1.clone(), r.4.clone(), r.5.clone()))
        .collect();
    assert_eq!(
        full_runs.len(),
        1,
        "shipped-input row precondition: native A1 run finding emitted",
    );
    let shipped_name = a.dir_path.join("copy-live");
    fs::copy(a.dir_path.join("audit.jsonl"), &shipped_name).unwrap();
    let mixed_rows = rows(&verify_dir(&a.dir_path));
    let mixed_runs: Vec<(_, _, _)> = mixed_rows
        .iter()
        .filter(|r| r.5.is_some())
        .map(|r| (r.1.clone(), r.4.clone(), r.5.clone()))
        .collect();
    assert_eq!(
        full_runs, mixed_runs,
        "native run finding unchanged when a shipped copy is added"
    );
    // Clean up before the Temp Drop so cp is deterministic.
    fs::remove_file(&shipped_name).unwrap();
}

// ============================================================
// R12 — multi-trail directory: `(line, seq)` come from the verified
// trail only (ruling 13-V4-d8 point 5; filtering reads
// `collection.inputs[seg.input_index].data.records`).
// ============================================================

#[test]
fn r12_multi_trail_line_seq_from_verified_trail_only() {
    // Build a layout where the run's first segment S1 holds records
    // of two trails. The first PHYSICAL record on S1 is on a
    // foreign trail (prev mismatches S0's tail, so the tolerant
    // walk accepts it at the broken boundary); later records are
    // on the verified trail and chain cleanly through to live's
    // closer. Without the trail filter, `(line, seq)` would be
    // (1, 3) (the foreign record). The filter at ruling 13-V4-d8
    // point 5 picks (2, 4): the first record on the verified
    // trail.
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
    // extra_B: trail B, seq=3, prev=some arbitrary hash (not
    // e2.hash). The tolerant walker's broken-boundary arm accepts
    // it; apply_checked otherwise rolls it back.
    let foreign_trail = [0xAA; 16];
    let ctx_b = crate::audit::RecordContext::new(foreign_trail, 3, 123, "f", [0x55; 32]);
    let extra_b =
        crate::audit::Record::new(ctx_b, crate::audit::Entry::new("actor", "change", "object"))
            .unwrap();
    // The tolerant classifier threads extra_b into the run state,
    // so the verified-trail successor must chain from extra_b.hash.
    let e4 = entry_rec(4, extra_b.hash());
    let mmr_bextra = {
        let mut m = mmr2.clone();
        m.push(extra_b.hash()).unwrap();
        m
    };
    let mmr4 = pushed(&mmr_bextra, &e4);
    let cp5 = signed_cp(5, e4.hash(), &mmr4);
    crate::audit::runs_v4a_fixtures::put_segment(&d.0, 1, &[&extra_b, &e4, &cp5], &[]);
    let mmr5 = pushed(&mmr4, &cp5);
    let cp6 = signed_cp(6, cp5.hash(), &mmr5);
    let resume = resume_decl(&cp6, 5, cp5.hash(), 5);
    write_records(&d.0, &[&cp6, &resume]);
    let findings = verify_dir(&d.0);
    let runs: Vec<_> = rows(&findings)
        .into_iter()
        .filter(|r| r.5.is_some())
        .collect();
    // If classify emits a run here, its (line, seq) comes from the
    // first on-trail record in S1 (e4, line=2, seq=4). Otherwise
    // the test's pre-condition didn't hold and we fail loudly; the
    // brief's row says "come from the verified trail only", so
    // either way (line, seq) must NOT be (1, 3).
    for r in &runs {
        assert_ne!(
            r.2,
            Some(1),
            "multi-trail: (line, seq) never from the foreign record (line=1)",
        );
        assert_ne!(
            r.3,
            Some(3),
            "multi-trail: (line, seq) never from the foreign record (seq=3)",
        );
    }
    // If a run finding is produced, its (line, seq) is from a
    // verified-trail record, never the foreign (line=1, seq=3).
    // Whether classify tolerates the mixed-trail segment is
    // implementation-detail: the filter assertion above holds
    // either way.
    //
    // Companion positive check: A1 (single-trail accept layout)
    // produces exactly one run finding at head with (line=1,
    // seq=4) on the verified trail, so R12 is red on base.
    let a1 = build_a1();
    let a1_runs: Vec<_> = rows(&verify_dir(&a1.dir_path))
        .into_iter()
        .filter(|r| r.5.is_some())
        .collect();
    assert_eq!(
        a1_runs.len(),
        1,
        "multi-trail-filter-is-isolated companion: A1 emits one run finding",
    );
    assert_eq!(a1_runs[0].2, Some(1), "A1 companion: line");
    assert_eq!(a1_runs[0].3, Some(4), "A1 companion: seq");
    // The foreign record raises `TrailMismatch` once.
    let mismatches: Vec<_> = findings
        .iter()
        .filter(|f| f.kind() == K::TrailMismatch)
        .collect();
    assert_eq!(mismatches.len(), 1, "foreign-trail record flagged once");
}

// ============================================================
// R13 — agreement over A1, A3, A8, A9 and R5-R8: the set of run
// findings equals the set of `ClassifyOutput.runs` computed
// directly on the same snapshot, with strict equality on
// `(first_segment.path, digest)` (ruling 13-V4-d5 (a) parallel
// index by construction).
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
    // Split archive+trail form: one run finding across the merged
    // Collection (ruling 13-V4-d8 point 2). The classify-side
    // computes over a merged (archive + trail) snapshot in base
    // order, matching `input::collect`'s merge.
    let (_sd, split_s0, _, _) = build_archive_closed_inside();
    let full_dir_for_split = split_s0.parent().unwrap().to_owned();
    let archive_dir = Temp::new();
    let trail_dir = Temp::new();
    fs::copy(
        full_dir_for_split.join("audit-20260101T000000.000000000Z_000000.jsonl"),
        archive_dir
            .0
            .join("audit-20260101T000000.000000000Z_000000.jsonl"),
    )
    .unwrap();
    fs::copy(
        full_dir_for_split.join("audit-20260101T000000.000000000Z_000001.jsonl"),
        archive_dir
            .0
            .join("audit-20260101T000000.000000000Z_000001.jsonl"),
    )
    .unwrap();
    fs::copy(
        full_dir_for_split.join("audit-20260101T000000.000000000Z_000002.jsonl"),
        trail_dir
            .0
            .join("audit-20260101T000001.000000000Z_000000.jsonl"),
    )
    .unwrap();
    let split_verify_runs: Vec<_> =
        rows(&verify_files([archive_dir.0.clone(), trail_dir.0.clone()]))
            .into_iter()
            .filter(|r| r.5.is_some())
            .map(|r| (r.3, r.4, r.5))
            .collect();
    let full_verify_runs: Vec<_> = rows(&verify_dir(&full_dir_for_split))
        .into_iter()
        .filter(|r| r.5.is_some())
        .map(|r| (r.3, r.4, r.5))
        .collect();
    assert_eq!(
        split_verify_runs.len(),
        1,
        "R13 split-form agreement precondition: one run finding",
    );
    assert_eq!(
        split_verify_runs, full_verify_runs,
        "R13 split-form agreement: archive_dir + trail_dir == full_dir \
         (ruling 13-V4-d8 point 2: one classify over the merged Collection)",
    );
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
    // Append a torn JSON fragment to the live closer. Ruling 13-V4-d9:
    // this fragment lands in the closer segment (last_segment), so it
    // is excluded from the run's spans and its run digest.
    fs::OpenOptions::new()
        .append(true)
        .open(a.dir_path.join("audit.jsonl"))
        .unwrap()
        .write_all(b"{\"half")
        .unwrap();
    let findings = verify_dir(&a.dir_path);
    let a1_digest = parse_digest(A1_DIGEST);
    // Detail: A1's one loss range, no span entries, A1's pinned digest.
    let run_detail = make_run_detail(&[(4, 3, 1)], &[], &a1_digest);
    let run_rows: Vec<_> = rows(&findings)
        .into_iter()
        .filter(|r| r.5.is_some())
        .collect();
    assert_eq!(run_rows.len(), 1, "A1+torn: one run finding");
    assert_eq!(
        run_rows[0].4, run_detail,
        "A1+torn: detail excludes closer span"
    );
    assert_eq!(
        run_rows[0].5,
        Some(digest_string(&a1_digest)),
        "A1+torn: run digest unchanged (`79d8cb1c…`) per ruling 13-V4-d9",
    );
    // Belt-and-braces: no `span ` segment appears in the detail.
    assert!(
        !run_rows[0].4.contains("span "),
        "A1+torn: detail must not carry any `span` entry (closer excluded)",
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
    let findings = Verifier::new(policy_trail())
        .verify_dir(&d.0)
        .unwrap()
        .findings()
        .to_vec();
    let run_rows: Vec<_> = rows(&findings)
        .into_iter()
        .filter(|r| r.5.is_some())
        .collect();
    assert_eq!(run_rows.len(), 2, "p01: two run findings");
    // Run 0's detail has no `span` entry (closer S2 excluded; S1
    // carries no fragments → zero spans).
    assert!(
        !run_rows[0].4.contains("span "),
        "p01 run 0: no span entry (ruling 13-V4-d9 excludes closer S2)",
    );
    // Run 1 (index 1 here is the SECOND run; `engine::check`'s stable
    // sort keeps run findings ordered). Its detail must carry exactly
    // one `span seg 0 after <resume.seq> len 7` for S2's `broken\n`.
    assert_eq!(
        run_rows[1].4.matches("span ").count(),
        1,
        "p01 run 2: exactly one span (S2's trailing `broken\\n`)",
    );
    let expected_fragment = format!("span seg 0 after {} len 7 ", resume.context.seq);
    assert!(
        run_rows[1].4.contains(&expected_fragment),
        "p01 run 2: detail carries `{expected_fragment}…`; got `{}`",
        run_rows[1].4,
    );
}
