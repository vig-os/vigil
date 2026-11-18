//! Rulings 13-V4-d5 (b), 13-V4-d6 points 1 and 2: snapshot segment
//! source over the verifier's confirmed bytes.
//!
//! One `#[cfg(test)]` submodule under `audit::storage::tests`. Every
//! row drives [`SegmentSource::for_snapshot`] + `runs::classify`
//! under [`Reaction::Collect`]; no row re-opens the trail directory
//! after bytes are captured (ruling 13-V3-d2's one-snapshot rule).
//!
//! Row index:
//! - `snapshot_equals_live_open_on_simple_run_collect`: live-file
//!   present, one closed run in the live file; pins every
//!   [`ClassifyOutput`] field the snapshot and the live-open paths
//!   must agree on (`violations`, `head_mismatch`, `segments.len()`,
//!   `runs.len()` + each pinned [`RunReport`] field, `found`,
//!   `final_state.run.head`).
//! - `snapshot_equals_live_open_on_empty_live_file_collect`: base
//!   segment + empty `audit.jsonl`. Pins that the snapshot path
//!   reaches the live arm exactly where the file-backed live-open
//!   does (ruling 13-V4-d6 point 2); live-only
//!   [`Violation::EmptyLiveFile`] fires on both and
//!   `final_state.run.head` matches.
//! - `snapshot_equals_live_open_on_torn_tail_live_file_collect`: base
//!   segment + `audit.jsonl` whose trailing bytes are an unterminated
//!   JSON fragment. The live-arm tolerant pass handles the torn tail;
//!   the snapshot path must do the same.
//! - `snapshot_archive_with_closer_emits_run_report`: real archive
//!   (no `audit.jsonl`), two sealed segments forming a closed run
//!   plus a sealed closer; pins the exact [`RunReport`] fields
//!   (`first_segment`, `last_segment`, `closing_opening`, exactly
//!   one `LossPoint`) and the per-segment
//!   [`SegmentClass`]/`damage` on every segment the walk yielded.
//! - `snapshot_archive_unclosed_run_emits_no_run_report`: archive
//!   with a headless run and no closer anywhere; pins
//!   `runs.is_empty()` and the per-segment [`SegmentClass`] on each
//!   of the two sealed segments.
//! - `snapshot_final_state_matches_live_open_head_seq`: literal
//!   assertion that the snapshot's `final_state.run.head.seq` equals
//!   the closer's own seq (and the live-open path's) on a
//!   live-present layout (ruling 13-V4-d6 point 2).
//! - `snapshot_archive_final_state_is_none`: literal assertion that
//!   `final_state.is_none()` on an archive snapshot (every entry
//!   `is_live = false`), since no live arm ever ran.

use super::runs::{close_run, signed};
use super::*;
use crate::audit::runs::{
    ClassifyArgs, ClassifyOutput, Reaction, ReaderPath, RunReport, SegmentClass, classify,
};
use crate::audit::storage::SegmentSource;
use std::{fs, io::Read, path::Path, rc::Rc};

// ---------------------------------------------------------------
// Local helpers (file:line-stable; these do not duplicate helpers
// that already live in `storage_tests` -- they just read bytes back
// from an on-disk fixture).
// ---------------------------------------------------------------

/// Reads `audit-STAMP_NNNNNN.jsonl` segments in base order from `dir`,
/// followed by `audit.jsonl` (if present), and returns the
/// `(bytes, is_live)` tuples [`SegmentSource::for_snapshot`] takes.
/// Order matches [`SegmentSource::for_live_open`] (rotated names
/// first, then the live file), which is the "equal plan shape on a
/// live-present layout" that ruling 13-V4-d5 (b) requires.
fn snapshot_tuples(dir: &Path) -> Vec<(Rc<[u8]>, bool)> {
    let mut rotated: Vec<(String, std::path::PathBuf)> = fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            (name != "audit.jsonl" && crate::rotate::parse_segment(&name, "audit").is_some())
                .then_some((name, e.path()))
        })
        .collect();
    rotated.sort_by(|a, b| a.0.cmp(&b.0));
    let mut tuples: Vec<(Rc<[u8]>, bool)> = rotated
        .into_iter()
        .map(|(_, path)| (read_rc(&path), false))
        .collect();
    let live = dir.join("audit.jsonl");
    if live.exists() {
        tuples.push((read_rc(&live), true));
    }
    tuples
}

fn read_rc(path: &Path) -> Rc<[u8]> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    Rc::from(bytes.into_boxed_slice())
}

fn classify_snapshot(tuples: &[(Rc<[u8]>, bool)]) -> ClassifyOutput {
    let mut source = SegmentSource::for_snapshot(tuples);
    classify(
        ClassifyArgs {
            trail: TRAIL,
            prior_state: None,
        },
        ReaderPath::LiveOpen { expected: None },
        &mut source,
        Reaction::Collect,
    )
    .unwrap()
}

fn classify_live_open(dir: &Path) -> ClassifyOutput {
    let file = fs::File::open(dir).unwrap();
    let mut source = SegmentSource::for_live_open(&file).unwrap();
    classify(
        ClassifyArgs {
            trail: TRAIL,
            prior_state: None,
        },
        ReaderPath::LiveOpen { expected: None },
        &mut source,
        Reaction::Collect,
    )
    .unwrap()
}

/// Field-by-field equality on the Collect-relevant parts of
/// [`ClassifyOutput`]. Compares `violations`, `head_mismatch`,
/// `segments.len()`, every pinned [`RunReport`] field, `found` (by
/// `(seq, hash)`), and `final_state.run.head` (`Head` already has
/// `PartialEq`/`Eq`): the fields that must agree on
/// `for_snapshot` and `for_live_open` over the same bytes (rulings
/// 13-V4-d5 (b), 13-V4-d6 point 2).
///
/// `live_file` is excluded by construction: a snapshot's live
/// segment reads from [`crate::audit::storage::ByteSource::Memory`]
/// which has no backing `File`, so `into_file` returns `None` there
/// by design.
fn assert_classify_equal(snap: &ClassifyOutput, live: &ClassifyOutput) {
    assert_eq!(
        snap.violations, live.violations,
        "violations differ: snapshot vs live-open",
    );
    assert_eq!(
        snap.head_mismatch, live.head_mismatch,
        "head_mismatch differs: snapshot vs live-open",
    );
    assert_eq!(
        snap.segments.len(),
        live.segments.len(),
        "segments.len differs",
    );
    assert_eq!(
        snap.segments
            .iter()
            .map(|s| (s.class, s.damage))
            .collect::<Vec<_>>(),
        live.segments
            .iter()
            .map(|s| (s.class, s.damage))
            .collect::<Vec<_>>(),
        "per-segment (class, damage) differ",
    );
    assert_eq!(
        snap.found.as_ref().map(|r| (r.context.seq, r.hash())),
        live.found.as_ref().map(|r| (r.context.seq, r.hash())),
        "found (seq, hash) differs",
    );
    assert_eq!(
        snap.final_state.as_ref().map(|s| s.run.head),
        live.final_state.as_ref().map(|s| s.run.head),
        "final_state.run.head differs",
    );
    assert_eq!(snap.runs.len(), live.runs.len(), "runs.len differs");
    for (i, (s, l)) in snap.runs.iter().zip(live.runs.iter()).enumerate() {
        assert_eq!(
            s.first_segment, l.first_segment,
            "runs[{i}].first_segment differs",
        );
        assert_eq!(
            s.last_segment, l.last_segment,
            "runs[{i}].last_segment differs",
        );
        assert_eq!(
            s.closing_opening, l.closing_opening,
            "runs[{i}].closing_opening differs",
        );
        assert_eq!(
            s.loss_points, l.loss_points,
            "runs[{i}].loss_points differs",
        );
        assert_eq!(s.spans, l.spans, "runs[{i}].spans differs");
    }
}

// ---------------------------------------------------------------
// Row: snapshot ≡ live-open on a one-range run (live present).
// Kills M-SNAP-1 (plan reorder: different `RunReport.first_segment`
// / `last_segment`); M-SNAP-9 (streaming through the original file
// after `read_to_end`: an empty span set changes `RunReport.spans`).
// Also kills the "native_segments is_live always false" probe
// because `final_state.run.head` is set by the live arm and left
// `None` by every sealed arm, so any mutant that stops the walker
// from entering the live arm changes `final_state`.
// ---------------------------------------------------------------

#[test]
fn snapshot_equals_live_open_on_simple_run_collect() {
    let d = Temp::new();
    // S0: base checkpoint (seq=0).
    let first = signed(0, Record::genesis(&TRAIL), &Mmr::new());
    super::runs::put(&d, 0, &[&first], &[]);
    // S1: headless record (opens a run).
    let r = super::runs::headless(&first, 5);
    let mut fold = seeded(&first);
    fold.push(r.hash()).unwrap();
    super::runs::put(&d, 1, &[&r], &[]);
    // live: closing checkpoint + resume (closes the run).
    close_run(&d, &r, &fold);
    let tuples = snapshot_tuples(&d.0);
    let snap = classify_snapshot(&tuples);
    let live = classify_live_open(&d.0);
    assert_classify_equal(&snap, &live);
    // Sanity: the fixture produced one closed run via live-open.
    assert_eq!(snap.runs.len(), 1, "fixture should produce one run");
}

// ---------------------------------------------------------------
// Row: snapshot ≡ live-open when the live file is empty (ruling
// 13-V4-d6 point 2). The live arm emits `Violation::EmptyLiveFile`
// at segment_index 1 on both paths. Under M-SNAP-3 the snapshot
// path walks `audit.jsonl` as sealed via `history_segment` instead
// of `scan_closing`, which emits no `EmptyLiveFile` and leaves
// `final_state.run.head` matching the base segment's, so both the
// `violations` and the `final_state` comparisons fire.
// ---------------------------------------------------------------

#[test]
fn snapshot_equals_live_open_on_empty_live_file_collect() {
    let d = Temp::new();
    // S0: base checkpoint.
    let first = signed(0, Record::genesis(&TRAIL), &Mmr::new());
    super::runs::put(&d, 0, &[&first], &[]);
    // Empty live file.
    fs::write(d.0.join("audit.jsonl"), b"").unwrap();
    let tuples = snapshot_tuples(&d.0);
    let snap = classify_snapshot(&tuples);
    let live = classify_live_open(&d.0);
    assert_classify_equal(&snap, &live);
    // Sanity: the live-arm-only `EmptyLiveFile` fired on both.
    assert!(
        snap.violations
            .iter()
            .any(|(_, v)| matches!(v, Violation::EmptyLiveFile)),
        "EmptyLiveFile should fire on the snapshot path too",
    );
}

// ---------------------------------------------------------------
// Row: snapshot ≡ live-open when the live file ends in an
// unterminated JSON fragment (ruling 13-V4-d6 point 2). The
// tolerant live-arm pass folds the complete records and treats
// the trailing fragment as a torn tail; `history_segment` on the
// same bytes (M-SNAP-3's mutation) would surface the fragment as
// a strict violation at the end of a sealed segment and emit a
// different `violations` list.
// ---------------------------------------------------------------

#[test]
fn snapshot_equals_live_open_on_torn_tail_live_file_collect() {
    let d = Temp::new();
    // S0 base + live with one complete record and a torn fragment.
    let first = signed(0, Record::genesis(&TRAIL), &Mmr::new());
    super::runs::put(&d, 0, &[&first], &[]);
    let second = signed(1, first.hash(), &seeded(&first));
    let mut live_bytes: Vec<u8> = line(&second);
    live_bytes.extend_from_slice(b"{\"torn\":");
    fs::write(d.0.join("audit.jsonl"), &live_bytes).unwrap();
    let tuples = snapshot_tuples(&d.0);
    let snap = classify_snapshot(&tuples);
    let live = classify_live_open(&d.0);
    assert_classify_equal(&snap, &live);
}

// ---------------------------------------------------------------
// Row: archive with closer -- `for_snapshot` with `is_live: false`
// on every entry walks every segment as sealed. The classifier's
// own `closed_run` latch (ruling 13-V4-d3 point 1) closes the run
// that started inside the archive. Kills M-SNAP-2 (snapshot always
// appends a synthetic `Live`: doubles the closer or trips
// scan_closing with no live file) and M-SNAP-6 (`Memory` reads EOF:
// no RunReport emerges).
// ---------------------------------------------------------------

#[test]
fn snapshot_archive_with_closer_emits_run_report() {
    let d = Temp::new();
    let first = signed(0, Record::genesis(&TRAIL), &Mmr::new());
    super::runs::put(&d, 0, &[&first], &[]);
    let r = super::runs::headless(&first, 5);
    let mut fold = seeded(&first);
    fold.push(r.hash()).unwrap();
    super::runs::put(&d, 1, &[&r], &[]);
    // Closer: a checkpoint linking back + a `vigil.audit.resume`
    // declaration. Mirror `close_run`'s shape, but write it to a
    // SEALED segment (no `audit.jsonl`): the archive case.
    let closer = signed(r.context.seq + 4, r.hash(), &fold);
    let decl = declaration(
        &closer,
        r.context.seq,
        r.hash(),
        closer.context.seq - 1,
        None,
    );
    super::runs::put(&d, 2, &[&closer, &decl], &[]);
    // Archive: no `audit.jsonl`.
    let tuples = snapshot_tuples(&d.0);
    assert!(
        tuples.iter().all(|(_, is_live)| !*is_live),
        "archive-case tuples must have is_live=false everywhere",
    );
    let out = classify_snapshot(&tuples);
    assert!(
        out.violations.is_empty(),
        "archive-with-closer should emit no violations, got {:?}",
        out.violations,
    );
    assert!(!out.head_mismatch, "head_mismatch should be false");
    // Per-segment (class, damage): S0 Base/no-damage, S1 InRun/
    // no-damage, S2 Closer/no-damage. Pinned as a literal row.
    let per_segment: Vec<(SegmentClass, bool)> =
        out.segments.iter().map(|s| (s.class, s.damage)).collect();
    assert_eq!(
        per_segment,
        vec![
            (SegmentClass::Base, false),
            (SegmentClass::InRun, false),
            (SegmentClass::Closer, false),
        ],
        "per-segment class+damage",
    );
    assert_eq!(out.runs.len(), 1, "exactly one RunReport expected");
    let report: &RunReport = &out.runs[0];
    // The run spans S0 (base; not a member) -> S1 (opens) -> S2
    // (closer). First/last match the run-member span.
    assert_eq!(report.first_segment, 1, "run first_segment");
    assert_eq!(report.last_segment, 2, "run last_segment");
    assert_eq!(
        report.closing_opening,
        Some(crate::audit::storage::Head::of(&closer)),
        "closing_opening is the closer's opening checkpoint head",
    );
    // S1's single headless record is the loss site. One loss point.
    assert_eq!(
        report.loss_points.len(),
        1,
        "exactly one loss point for the S1 headless",
    );
    assert_eq!(
        report.loss_points[0].loss_seq, r.context.seq,
        "loss_seq is the headless seq",
    );
}

// ---------------------------------------------------------------
// Row: archive with an unclosed run -- no RunReport is emitted
// (ruling 13-V4-d2 point 1 on an open run at end of plan). Pins
// `segments.len()` and the per-segment [`SegmentClass`] so the row
// catches a mutant that drops the per-segment report pass.
// ---------------------------------------------------------------

#[test]
fn snapshot_archive_unclosed_run_emits_no_run_report() {
    let d = Temp::new();
    let first = signed(0, Record::genesis(&TRAIL), &Mmr::new());
    super::runs::put(&d, 0, &[&first], &[]);
    // S1: a headless record (opens a run), no closer anywhere.
    let r = super::runs::headless(&first, 5);
    super::runs::put(&d, 1, &[&r], &[]);
    let tuples = snapshot_tuples(&d.0);
    assert!(
        tuples.iter().all(|(_, is_live)| !*is_live),
        "archive-case tuples must have is_live=false everywhere",
    );
    let out = classify_snapshot(&tuples);
    assert!(
        out.runs.is_empty(),
        "unclosed archive run must not emit a RunReport, got {} runs",
        out.runs.len(),
    );
    // S0 base + S1 run-opening (ruling 13-V4-d3 point 1: the
    // walker's own `run_out` makes the segment a run member even
    // without a closer).
    assert_eq!(out.segments.len(), 2, "two sealed segments");
    assert_eq!(
        out.segments
            .iter()
            .map(|s| (s.class, s.damage))
            .collect::<Vec<_>>(),
        vec![(SegmentClass::Base, false), (SegmentClass::InRun, false),],
        "per-segment class+damage on an unclosed-run archive",
    );
}

// ---------------------------------------------------------------
// Row: literal `final_state` assertion on a snapshot with a live
// file (ruling 13-V4-d6 point 2). The snapshot path must end with
// `final_state.run.head` equal to the live-open path's, since the
// live arm fires on both regardless of whether the source carries
// a `File` handle. Kills probes that leave `final_state` `None` on
// a live-present snapshot.
// ---------------------------------------------------------------

#[test]
fn snapshot_final_state_matches_live_open_head_seq() {
    let d = Temp::new();
    // S0 base + S1 headless + live closer, as in the simple-run
    // fixture: one closed run, final_state is the closer+resume's
    // tail state on both paths.
    let first = signed(0, Record::genesis(&TRAIL), &Mmr::new());
    super::runs::put(&d, 0, &[&first], &[]);
    let r = super::runs::headless(&first, 5);
    let mut fold = seeded(&first);
    fold.push(r.hash()).unwrap();
    super::runs::put(&d, 1, &[&r], &[]);
    let (_closer, resume) = close_run(&d, &r, &fold);
    let tuples = snapshot_tuples(&d.0);
    let snap = classify_snapshot(&tuples);
    let live = classify_live_open(&d.0);
    let snap_head = snap
        .final_state
        .as_ref()
        .expect("snapshot final_state is Some on a live-present layout")
        .run
        .head;
    let live_head = live
        .final_state
        .as_ref()
        .expect("live-open final_state is Some")
        .run
        .head;
    assert_eq!(snap_head, live_head, "final_state.run.head differs");
    // The run closer's resume is the last complete record; the
    // live walker's post-segment state carries its seq/hash.
    assert_eq!(
        snap_head.seq, resume.context.seq,
        "final_state tail seq is the resume seq",
    );
    assert_eq!(
        snap_head.hash,
        resume.hash(),
        "final_state tail hash is the resume hash",
    );
}

// ---------------------------------------------------------------
// Row: literal `final_state` assertion on an archive snapshot
// (ruling 13-V4-d6 point 2). Every entry has `is_live = false`;
// no live arm ever runs, so `final_state` stays `None` on `Ok`
// archive classifies, listed as a `None` case in
// [`ClassifyOutput::final_state`]'s rustdoc.
// ---------------------------------------------------------------

#[test]
fn snapshot_archive_final_state_is_none() {
    let d = Temp::new();
    let first = signed(0, Record::genesis(&TRAIL), &Mmr::new());
    super::runs::put(&d, 0, &[&first], &[]);
    let r = super::runs::headless(&first, 5);
    let mut fold = seeded(&first);
    fold.push(r.hash()).unwrap();
    super::runs::put(&d, 1, &[&r], &[]);
    let closer = signed(r.context.seq + 4, r.hash(), &fold);
    let decl = declaration(
        &closer,
        r.context.seq,
        r.hash(),
        closer.context.seq - 1,
        None,
    );
    super::runs::put(&d, 2, &[&closer, &decl], &[]);
    let tuples = snapshot_tuples(&d.0);
    assert!(
        tuples.iter().all(|(_, is_live)| !*is_live),
        "archive-case tuples must have is_live=false everywhere",
    );
    let out = classify_snapshot(&tuples);
    assert!(
        out.final_state.is_none(),
        "archive snapshot: final_state must be None on the Ok path, got Some",
    );
    assert!(
        out.live_file.is_none(),
        "archive snapshot: live_file must be None (no live arm ran)",
    );
}
