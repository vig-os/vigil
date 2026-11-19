//! V4a/V4b fold-finding emission over the verifier's confirmed
//! snapshot: one `SegmentStructure` finding per closed run (V4a), and
//! one `MmrMismatch` per checkpoint the shared classifier's fold
//! reports as differing (V4b, ADR-0005 decision 5 rule 2 and
//! amendment 6 (iii); ruling 13-V4-d10 points 2-3). The run detection
//! and the fold compare both live in the shared classifier
//! (`audit::runs::classify`, owner decision 13-V4-d4); this module
//! owns no run rule and no fold rule of its own, and does not re-walk
//! or re-fold the records (ruling 13-V4-d10 point 1).
//!
//! The snapshot source is [`storage::SegmentSource::for_snapshot`],
//! which opens nothing and writes nothing (rulings 13-V4-d5 (b),
//! 13-V4-d6 point 1); the verifier's confirmed bytes come from
//! [`Collection::native_segments`], which `input::collect` retained
//! on the one snapshot read (ruling 13-V3-d2). The classifier runs
//! once, under `Reaction::Collect` (rulings 13-V4-d5 (a), 13-V4-d8
//! point 2; ruling 13-V4-d10 point 1: one fold per verify call).
//!
//! Each `RunReport` in `ClassifyOutput::runs` becomes one
//! `SegmentStructure` finding carrying the run's digest per ADR-0005
//! decision 11, "accept-run". The finding's `(file, line, seq)` are
//! the run's first segment's path and the segment's first record on
//! the verified trail (ruling 13-V4-d8 point 5); the detail follows
//! the 13-V4-d8 point 1 grammar; the digest is
//! `lines::run_digest(ranges, spans)`.
//!
//! Each [`CheckpointFoldEntry`] in `ClassifyOutput::fold_entries`
//! with outcome [`CheckpointFoldOutcome::Differs`] or
//! [`CheckpointFoldOutcome::DiffersAfterLoss`] becomes one
//! `MmrMismatch` finding at the record's native file and line; the
//! detail follows `expected size <n> root <digest>, found size <n>
//! root <digest>` (ruling 13-V4-d10 point 2). A
//! `CheckpointFoldOutcome::Differs` entry pairs with a
//! `CheckpointMmrDiffers` violation (which empties every run per
//! 13-V4-d8 point 3); a `DiffersAfterLoss` entry is never a
//! violation and never empties a run (amendment 6 (iii) refined by
//! decision 11 `accept-run` item 3; ruling 13-V4-d10 point 3).
//!
//! **Shipped-copy limit (owner decision 13-V4-d7; spike #224):** the
//! classifier runs over native inputs only; a shipped (Collector)
//! input gets no run finding AND no fold compare at this head.
//! Shipped-only openings are therefore never confirmed as matched by
//! [`matched_opening_seqs`] -- which is what the engine's
//! resume-candidate filter requires (ruling 13-V4-d10 points 4-5).
//! Spike #224 decides whether run boundaries and rule 2 can be
//! recovered from a Collector record stream.
//!
//! **Known limit (ruling 13-V4-d10 point 6):** once a segment records
//! a violation the classifier stops checking the rest of that
//! segment, so a second mismatch inside the same segment is not
//! reported here. The first error is reported and the trail is
//! already rejected.

use std::collections::BTreeSet;

use super::{
    Finding,
    input::{Collection, NativeSegment},
    lines,
};
use crate::audit::{
    FindingKind as K, digest_string,
    runs::{
        self, CheckpointFoldEntry, CheckpointFoldOutcome, ClassifyArgs, ClassifyOutput, LossPoint,
        Reaction, ReaderPath, RunReport,
    },
    storage::SegmentSource,
};

/// Emits one `SegmentStructure` finding per closed run and one
/// `MmrMismatch` per differing fold-compare entry that
/// `runs::classify` returns under `Reaction::Collect` on the
/// verifier's confirmed snapshot (rulings 13-V4-d3-d8, 13-V4-d10).
/// Returns the set of opening `seq`s the classifier positively
/// recorded as compared and matched; the engine's resume-candidate
/// filter keeps only candidates whose opening `seq` is in this set
/// (ruling 13-V4-d10 point 4, fail-closed).
///
/// Native inputs only; a shipped (Collector) input gets no run
/// finding and no fold compare at this head (owner decision
/// 13-V4-d7; spike #224). A shipped-only opening is therefore never
/// returned here, which is the fail-closed guarantee (ruling
/// 13-V4-d10 point 5).
///
/// The classifier runs once over the merged `Collection`, in its
/// collection order (ruling 13-V4-d8 point 2, 13-V4-d10 point 1):
/// `verify_files` and `verify_dir` already build one `Collection`
/// across every directory and file (`verify/mod.rs` and
/// `input::collect`), so the archive-plus-trail case of ADR-0005
/// decision 2 step 6 flows through this single pass and never splits
/// per directory. No second fold.
pub(super) fn check_runs(
    collection: &Collection,
    trail: [u8; 16],
    findings: &mut Vec<Finding>,
) -> BTreeSet<u64> {
    let natives = collection.native_segments();
    // Ruling 13-V4-d6 point 1: build a crate-private, portable
    // `(Rc<[u8]>, is_live)` snapshot from the verifier's already-
    // retained native-input bytes. Opens nothing, writes nothing.
    let tuples: Vec<(std::rc::Rc<[u8]>, bool)> = natives
        .iter()
        .map(|seg| (std::rc::Rc::clone(&seg.bytes), seg.is_live))
        .collect();
    let mut source = SegmentSource::for_snapshot(&tuples);
    // Ruling 13-V4-d8 point 2: `verify_dir` / `verify_files`
    // classify the one native-segment snapshot once. No early return
    // on empty `natives`: an empty plan classifies to an empty
    // `ClassifyOutput::runs` (no segment, no closer).
    //
    // Ruling 13-V4-d8 point 4 (classifier `Err` audit on a
    // `for_snapshot` source under `Reaction::Collect`): the only `?`
    // in `runs::classify` that can surface an `Err` is
    // `runs::collect_segment_spans_and_records`, via
    // `u32::try_from(segment_index)`. Every other `?` goes through
    // `storage::ByteSource::Memory`, whose `try_clone` / `seek` /
    // `read` paths are all infallible on an in-memory cursor; the
    // walker's tolerant fallback in `runs::history_segment` catches
    // `CorruptTrail` for Collect; and `source.next_segment()` on a
    // `PlanStep::Snapshot` only returns `Ok`. The `u32::try_from`
    // path overflows only on a crafted `Collection` with more than
    // `u32::MAX` native segments (≥ 4 GiB of `Vec<Input>` and
    // `BTreeMap<Inode, …>` entries built in `input::collect` before
    // `check_runs` ever runs), unreachable from any crafted input
    // the verifier could actually produce. One `expect` therefore
    // documents the construction argument; every run-emitting row in
    // `src/audit/verify/runs_tests.rs` enters it on the Ok side.
    let out = runs::classify(
        ClassifyArgs {
            trail,
            prior_state: None,
        },
        ReaderPath::LiveOpen { expected: None },
        &mut source,
        Reaction::Collect,
    )
    .expect(
        "runs::classify on a SegmentSource::for_snapshot under Reaction::Collect \
         is Err only on `u32::try_from(segment_index)` inside \
         `runs::collect_segment_spans_and_records`, which overflows only above \
         u32::MAX native segments — unreachable from any Collection \
         `input::collect` could build. ByteSource::Memory's try_clone/seek/read \
         are infallible on an in-memory cursor.",
    );
    for run in &out.runs {
        emit_run_finding(&natives, collection, trail, run, findings);
    }
    emit_fold_findings(&natives, collection, trail, &out, findings)
}

/// #13 V4b (ruling 13-V4-d10 points 2-3): emit one `MmrMismatch`
/// finding per [`CheckpointFoldOutcome::Differs`] and per
/// [`CheckpointFoldOutcome::DiffersAfterLoss`] entry in
/// `out.fold_entries`, and collect the matched openings for the
/// engine's fail-closed candidate filter (ruling 13-V4-d10 point 4).
///
/// The per-finding `(file, line, seq)` comes from the record in the
/// classifier's native segment that matches the entry's `seq`, the
/// same mapping V4a uses (ruling 13-V4-d5 (a): the classifier's
/// per-segment index is parallel to `Collection::native_segments()`
/// by construction). No bounds arm: an out-of-range segment index
/// would be a construction bug in `classify`, not a crafted input.
fn emit_fold_findings(
    natives: &[NativeSegment],
    collection: &Collection,
    trail: [u8; 16],
    out: &ClassifyOutput,
    findings: &mut Vec<Finding>,
) -> BTreeSet<u64> {
    let mut matched_openings: BTreeSet<u64> = BTreeSet::new();
    for entry in &out.fold_entries {
        match entry.outcome {
            CheckpointFoldOutcome::Matched => {
                // Ruling 13-V4-d10 point 4: a positive, compare-and-
                // matched record of the opening. The filter in
                // `verify::engine::check` consumes this set.
                matched_openings.insert(entry.seq);
            }
            CheckpointFoldOutcome::Differs | CheckpointFoldOutcome::DiffersAfterLoss => {
                emit_mmr_mismatch(natives, collection, trail, entry, findings);
            }
        }
    }
    matched_openings
}

/// Build one `MmrMismatch` finding at the record's native file and
/// line. The detail grammar (ruling 13-V4-d10 point 2) is exactly
/// `expected size <n> root <digest>, found size <n> root <digest>`,
/// with `<digest>` through [`digest_string`] to match the rest of
/// the verifier. Looking up the record by `seq` on the trail keeps
/// the mapping identical to V4a's `(file, line, seq)` lookup (ruling
/// 13-V4-d8 point 5, point 3 for `records` filtered by trail).
fn emit_mmr_mismatch(
    natives: &[NativeSegment],
    collection: &Collection,
    trail: [u8; 16],
    entry: &CheckpointFoldEntry,
    findings: &mut Vec<Finding>,
) {
    // Ruling 13-V4-d5 (a): classify's segment_index is parallel to
    // `Collection::native_segments()`; no bounds arm.
    let seg = &natives[entry.pos.segment_index];
    let input = &collection.inputs[seg.input_index];
    // The record is identified by `(trail, seq)`. `input.data.records`
    // already filters by segment (via `input::collect`), so the match
    // walks at most that segment's records (ruling 13-V4-d10 point 1:
    // no re-walk of bytes).
    let line = input
        .data
        .records
        .iter()
        .find(|r| r.trail == trail && r.seq == entry.seq)
        .map(|r| r.line);
    let detail = format!(
        "expected size {} root {}, found size {} root {}",
        entry.expected_size,
        digest_string(&entry.expected_root),
        entry.declared_size,
        digest_string(&entry.declared_root),
    );
    findings.push(Finding::new(
        K::MmrMismatch,
        Some(seg.path.clone()),
        line,
        Some(entry.seq),
        detail,
    ));
}

fn emit_run_finding(
    natives: &[NativeSegment],
    collection: &Collection,
    trail: [u8; 16],
    run: &RunReport,
    findings: &mut Vec<Finding>,
) {
    // Ruling 13-V4-d5 (a): the classifier's per-segment index is
    // parallel to `collection.native_segments()` by construction --
    // both are driven by the same `Collection::inputs` order -- so
    // no bounds arm (13-V4-d5 (d), 13-V4-d8 point 4).
    let seg = &natives[run.first_segment];
    // Ruling 13-V4-d8 point 5: `(line, seq)` are the first complete
    // record on the verified trail in the run's first segment.
    // Both are `None` when the segment holds none on this trail.
    // `collection.inputs[seg.input_index].data.records` is the
    // already-decoded summary list; `input::collect` filters by
    // segment but not by trail, so a multi-trail directory shows
    // other trails' records here (R12).
    let input = &collection.inputs[seg.input_index];
    let (line, seq) = input
        .data
        .records
        .iter()
        .find(|r| r.trail == trail)
        .map_or((None, None), |r| (Some(r.line), Some(r.seq)));
    // Ruling 13-V4-d8 point 1: ranges then spans then digest. Ranges
    // in `seq` order come from `run.loss_points`'s own order (the
    // classifier pushes them in walk order, which is `seq` order;
    // 197-d1 addendum 28 point 2 drops the whole run on arithmetic
    // overflow before any range is pushed).
    let ranges: Vec<(u64, u64)> = run
        .loss_points
        .iter()
        .map(|lp| (lp.first, lp.count))
        .collect();
    let digest = lines::run_digest(&ranges, &run.spans);
    let detail = run_detail(&run.loss_points, &run.spans, &digest);
    findings.push(
        Finding::new(
            K::SegmentStructure,
            Some(seg.path.clone()),
            line,
            seq,
            detail,
        )
        .with_run_digest(digest),
    );
}

/// Ruling 13-V4-d8 point 1 grammar: ranges (loss points) in `seq`
/// order, then spans in (segment, byte) order, then the run digest.
fn run_detail(loss_points: &[LossPoint], spans: &[lines::Span], digest: &[u8; 32]) -> String {
    let mut out = String::new();
    for lp in loss_points {
        use std::fmt::Write as _;
        let _ = write!(
            out,
            "loss seq {} first {} count {}; ",
            lp.loss_seq, lp.first, lp.count
        );
    }
    for sp in spans {
        use std::fmt::Write as _;
        // Ruling 13-V4-d8 point 1: the `u64::MAX` after-sentinel
        // prints as `start` (13-V4-d2 point 2).
        let after = if sp.after == u64::MAX {
            "start".to_owned()
        } else {
            sp.after.to_string()
        };
        let _ = write!(
            out,
            "span seg {} after {} len {} {}; ",
            sp.seg,
            after,
            sp.len,
            digest_string(&sp.digest),
        );
    }
    use std::fmt::Write as _;
    let _ = write!(out, "digest {}", digest_string(digest));
    out
}
