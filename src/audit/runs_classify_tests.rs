//! Classify tests (ruling 197-d1 addendum 25.3): Collect rows (CC1-...)
//! plus the multi-segment first-equality sweep that proves
//! `classify` under `Reaction::Collect`'s first violation equals the
//! reader's first violation at the same head.
//!
//! These are `#[cfg(test)]` under `src/audit/runs.rs`, so they do NOT
//! enter the `audit::storage::tests` filter (addendum 25.3).
use super::*;
use crate::audit::{
    AuditError, AuditErrorKind, CheckpointFields, Entry, Mmr, Record, RecordContext,
    storage::{Cache, Head, TrailReader},
};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

const TRAIL: [u8; 16] = [17; 16];
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "vigil-audit-classify-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn context(seq: u64, previous: [u8; 32]) -> RecordContext {
    RecordContext::new(TRAIL, seq, 100 + seq, "test", previous)
}
fn cp(seq: u64, previous: [u8; 32], mmr: &Mmr) -> Record {
    let fields = CheckpointFields::new(
        mmr.size(),
        mmr.root(),
        mmr.peaks().to_vec(),
        [1; 32],
        [0; 64],
    )
    .unwrap();
    Record::checkpoint(context(seq, previous), fields).unwrap()
}
fn line(record: &Record) -> Vec<u8> {
    use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
    let extra = AnyValue {
        value: Some(any_value::Value::StringValue("context".into())),
    };
    let mut l = crate::logs::encode_line(&crate::audit::format::request(record, extra).unwrap())
        .unwrap()
        .into_bytes();
    l.push(b'\n');
    l
}
fn entry(previous: &Record) -> Record {
    Record::new(
        context(previous.context.seq + 1, previous.hash()),
        Entry::new("actor", "change", "object"),
    )
    .unwrap()
}
fn fixture(path: &Path) -> Record {
    let first = cp(0, Record::genesis(&TRAIL), &Mmr::new());
    fs::write(path.join("audit.jsonl"), line(&first)).unwrap();
    first
}
fn append(path: &Path, record: &Record) {
    fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(&line(record))
        .unwrap();
}
fn seeded(first: &Record) -> Mmr {
    let mut mmr = Mmr::new();
    mmr.push(first.hash()).unwrap();
    mmr
}
fn segment(path: &Path, id: usize) -> PathBuf {
    path.join(format!("audit-20260101T000000.000000000Z_{id:06}.jsonl"))
}
fn rotated(path: &Path, last: &Record, mmr: &mut Mmr, id: usize) -> Record {
    let close = cp(last.context.seq + 1, last.hash(), mmr);
    append(&path.join("audit.jsonl"), &close);
    mmr.push(close.hash()).unwrap();
    fs::rename(path.join("audit.jsonl"), segment(path, id)).unwrap();
    let opening = cp(close.context.seq + 1, close.hash(), mmr);
    fs::write(path.join("audit.jsonl"), line(&opening)).unwrap();
    mmr.push(opening.hash()).unwrap();
    opening
}

/// Opens the dir as a File (for `SegmentSource::for_live_open`).
fn dirfile(path: &Path) -> fs::File {
    fs::File::open(path).unwrap()
}

/// Extracts the detail string from an [`AuditError`] via its `Display`
/// impl (format: `"{kind:?}: {detail}"`).
fn detail_of(err: &AuditError) -> String {
    let s = format!("{err}");
    s.split_once(": ").map_or(s.clone(), |(_, d)| d.to_string())
}

/// Serialises every reachable field of [`ClassifyOutput::final_state`] +
/// [`ClassifyOutput::found`] into a string. The first-equality sweep uses
/// this to compare the Stop and Collect Ok outcomes bit-for-bit
/// (#197 ruling addendum 27.1 Collect-vs-Stop Ok-path equality). Comparing
/// strings keeps the diagnostic readable when a mismatch fires.
fn ok_outcome(output: &ClassifyOutput) -> String {
    let state = output.final_state.as_ref().map(|s| {
        let run = &s.run;
        let predecessor = run.checkpoint_predecessor.map(|h| (h.seq, h.hash));
        format!(
            "head=({},{:x?}) checkpoint={} pending_resume={} run_loss={} predecessor={:?} \
             prev={:x?} mmr_size={} mmr_peaks={:x?} offset={} length={} cp_time={} \
             since_cp={} newline={} gap_digest={:x?}",
            run.head.seq,
            run.head.hash,
            run.checkpoint,
            run.pending_resume,
            run.run_loss,
            predecessor,
            run.checkpoint_previous,
            run.mmr.size(),
            run.mmr.peaks(),
            s.offset(),
            s.length,
            s.checkpoint_time,
            s.since_checkpoint,
            s.tail_newline(),
            s.gap_digest_raw(),
        )
    });
    let found = output.found.as_ref().map(|r| {
        format!(
            "head=({},{:x?}) seq={}",
            r.context.seq,
            r.hash(),
            r.context.seq
        )
    });
    format!(
        "state={:?} found={:?} sealed_before={:?} live_file_present={}",
        state,
        found,
        output.sealed_before,
        output.live_file.is_some(),
    )
}

/// Returns the `Cache` after a successful live-open, for use as the
/// starting state of a refresh row. Threads through the real reader so
/// the cache is byte-identical to what `TrailReader::open` would build.
/// Helper: append raw bytes to the given file path (test-only).
fn append_bytes(path: &Path, bytes: &[u8]) {
    fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

fn live_cache(path: &Path) -> Cache {
    let reader = TrailReader::open(path, TRAIL, None).unwrap();
    // `with_current` gives us the live file + state; we rebuild a Cache.
    let (state, file, sealed_before) = reader
        .with_current(
            |_| Ok(()),
            |_, file, s| {
                let f = file.try_clone().unwrap();
                Ok((s.clone(), f, None))
            },
        )
        .unwrap();
    // Grab `sealed_before` by reading the directory listing: the reader's
    // cache knows which sealed names existed at open time. For single-
    // segment layouts, sealed_before is None; for multi-segment it is
    // Some(segname(last)).
    let names = crate::rotate::rotated_names_at(&dirfile(path), "audit").unwrap();
    let sealed_before = names.last().cloned().or(sealed_before);
    Cache::new_for_test(state, file, sealed_before)
}

// ============================================================
// CC rows (addendum 25.3): exact literal lists.
// ============================================================

mod classify_collect_tests {
    use super::*;

    /// CC10-emit-head-mismatch-flag-false (refresh path, absent expected):
    /// Collect on RefreshAppend with no violation keeps `head_mismatch`
    /// false, because only `ReaderPath::LiveOpen { expected: Some(_) }`
    /// can set it (addendum 27.1 / M-C5 killer).
    ///
    /// Addendum 27.4 / ruling 197-d1 addendum 27.4: literal pin.
    #[test]
    fn cc10_refresh_append_never_sets_head_mismatch() {
        let d = Temp::new();
        let first = fixture(&d.0);
        let second = entry(&first);
        append(&d.0.join("audit.jsonl"), &second);
        let cache = live_cache(&d.0);
        // Append one more record: refresh-append path reaches classify.
        let third = entry(&second);
        append(&d.0.join("audit.jsonl"), &third);
        let dir = dirfile(&d.0);
        let out = classify_for_test(
            &dir,
            TRAIL,
            ReaderPath::RefreshAppend,
            Some(cache.state().clone()),
            Reaction::Collect,
            Some(&cache),
        )
        .unwrap();
        assert_eq!(
            out.violations,
            Vec::<(SegmentViolationPos, Violation)>::new(),
            "CC10: valid refresh-append records no violations"
        );
        assert!(
            !out.head_mismatch,
            "CC10: head_mismatch stays false on non-LiveOpen paths \
             (kills M-C5 'HeadMismatch leaked to refresh paths')"
        );
    }

    /// CC11-emit-head-mismatch-flag-true (liveopen path, expected absent
    /// from trail): under Collect the flag is recorded. Kills M-C4
    /// `LiveOpen` HeadMismatch suppressed.
    ///
    /// Addendum 27.4: literal pin — `violations` is the
    /// empty vec, `head_mismatch` is `true`, Stop returns the exact
    /// `AuditErrorKind::HeadMismatch` kind.
    #[test]
    fn cc11_liveopen_absent_expected_sets_head_mismatch_under_collect() {
        let d = Temp::new();
        let _first = fixture(&d.0);
        let absent = Head {
            seq: 999,
            hash: [0xee; 32],
        };
        let dir = dirfile(&d.0);
        let out = classify_for_test(
            &dir,
            TRAIL,
            ReaderPath::LiveOpen {
                expected: Some(absent),
            },
            None,
            Reaction::Collect,
            None,
        )
        .unwrap();
        assert_eq!(
            out.violations,
            Vec::<(SegmentViolationPos, Violation)>::new(),
            "CC11: valid-trail head-mismatch records no record violations"
        );
        assert!(
            out.head_mismatch,
            "CC11: under Collect, an absent expected head sets head_mismatch=true \
             (kills M-C4 suppressing head-mismatch)"
        );
        // And under Stop, the same layout returns Err(HeadMismatch).
        let dir2 = dirfile(&d.0);
        let err = classify_for_test(
            &dir2,
            TRAIL,
            ReaderPath::LiveOpen {
                expected: Some(absent),
            },
            None,
            Reaction::Stop,
            None,
        )
        .err()
        .expect("CC11/Stop: expected Err(HeadMismatch)");
        assert_eq!(err.kind(), AuditErrorKind::HeadMismatch);
    }

    /// CC5-refresh-append-single-segment-violation: refresh append over
    /// a layout where the appended bytes are an invalid continuation
    /// (`vigil.audit.*`-prefixed action which is reserved for internal
    /// records only). Under Collect, the RefreshAppend path through
    /// `classify_collect` records the exact violation list on
    /// `segment_index == 0` (the single segment of RefreshAppend) with
    /// `head_mismatch == false` (addendum 27.1). Kills M-C5
    /// (HeadMismatch leaked to refresh paths).
    ///
    /// Addendum 27.4: literal `vec![...]` pin.
    #[test]
    fn cc5_refresh_append_single_segment_violation() {
        let d = Temp::new();
        let first = fixture(&d.0);
        let cache = live_cache(&d.0);
        // Appending a record whose `seq` does not increase is detected
        // as a sealed-run rollback by the strict walk and surfaces the
        // same recorded violation under tolerant-mode Collect.
        let bad = Record::new(
            context(first.context.seq, first.hash()),
            Entry::new("actor", "change", "object"),
        )
        .unwrap();
        append(&d.0.join("audit.jsonl"), &bad);
        let dir = dirfile(&d.0);
        let out = classify_for_test(
            &dir,
            TRAIL,
            ReaderPath::RefreshAppend,
            Some(cache.state().clone()),
            Reaction::Collect,
            Some(&cache),
        )
        .unwrap();
        assert!(
            !out.head_mismatch,
            "CC5: RefreshAppend may NEVER set head_mismatch; got head_mismatch=true"
        );
        assert_eq!(
            out.violations,
            vec![(
                SegmentViolationPos {
                    segment_index: 0,
                    record_index_in_segment: 0,
                },
                Violation::RecordRolledBack,
            )],
            "CC5: refresh-append rollback is recorded at (seg=0, rec=0), RecordRolledBack"
        );
    }

    /// CC2-refresh-rotate-violation-in-rotated: a RefreshRotate layout
    /// with a valid prelude, a corrupt rotated_0 following it, and a
    /// valid new live. Under Collect, state threading (#197 ruling
    /// addendum 27.1) hands rotated_0's opening cp the prelude's
    /// folded state, so the strict first-violation surfaces on the
    /// prelude's duplicated record at `segment_index == 0`,
    /// `record_index_in_segment == 1`.
    ///
    /// Addendum 27.4: literal `vec![...]` pin.
    #[test]
    fn cc2_refresh_rotate_segment_index_above_zero() {
        let d = Temp::new();
        let first = fixture(&d.0);
        let cache = live_cache(&d.0);
        // Simulate a rotation by moving the live to segname(0) and
        // writing a new broken live.
        let mut mmr = seeded(&first);
        let close = cp(1, first.hash(), &mmr);
        append(&d.0.join("audit.jsonl"), &close);
        mmr.push(close.hash()).unwrap();
        fs::rename(d.0.join("audit.jsonl"), segment(&d.0, 0)).unwrap();
        // Corrupt rotated_0 by duplicating the first record so the
        // strict walk detects a rollback inside the sealed run.
        let seg0 = fs::read(segment(&d.0, 0)).unwrap();
        let bad_dup = line(&first);
        fs::write(segment(&d.0, 0), [seg0, bad_dup].concat()).unwrap();
        // Keep a valid new live.
        let opening = cp(close.context.seq + 1, close.hash(), &mmr);
        fs::write(d.0.join("audit.jsonl"), line(&opening)).unwrap();
        let dir = dirfile(&d.0);
        let out = classify_for_test(
            &dir,
            TRAIL,
            ReaderPath::RefreshRotate,
            Some(cache.state().clone()),
            Reaction::Collect,
            Some(&cache),
        )
        .unwrap();
        assert_eq!(
            out.violations,
            vec![(
                SegmentViolationPos {
                    segment_index: 0,
                    record_index_in_segment: 1,
                },
                Violation::SequenceDidNotIncrease,
            )],
            "CC2: refresh-rotate prelude hits SequenceDidNotIncrease at the duplicated record; \
             state threading (#197 ruling addendum 27.1) lets rotated_0's opening cp re-use the \
             prelude's folded state, so the rotated segment's strict pass does not re-record a \
             second violation"
        );
        assert!(
            !out.head_mismatch,
            "CC2: RefreshRotate never sets head_mismatch"
        );
    }

    /// CC1-liveopen-single-violation-on-rotated-0: LiveOpen with a
    /// corrupt rotated_0 (duplicated opening record) and a valid live.
    /// Under Collect, classify_collect records the exact violation list
    /// from the rotated_0 segment tagged at `segment_index == 0`.
    /// Addendum 27.4: literal `vec![...]` pin.
    #[test]
    fn cc1_liveopen_single_violation_on_rotated_0() {
        let d = Temp::new();
        let first = fixture(&d.0);
        // Rotate first to rotated_0 with a dup-first appended to make a
        // rollback inside the sealed run.
        let mut mmr = seeded(&first);
        let close = cp(1, first.hash(), &mmr);
        append(&d.0.join("audit.jsonl"), &close);
        mmr.push(close.hash()).unwrap();
        fs::rename(d.0.join("audit.jsonl"), segment(&d.0, 0)).unwrap();
        // Corrupt rotated_0 with a duplicated first record.
        let seg0 = fs::read(segment(&d.0, 0)).unwrap();
        let bad_dup = line(&first);
        fs::write(segment(&d.0, 0), [seg0, bad_dup].concat()).unwrap();
        // Keep a valid new live.
        let opening = cp(close.context.seq + 1, close.hash(), &mmr);
        fs::write(d.0.join("audit.jsonl"), line(&opening)).unwrap();

        let dir = dirfile(&d.0);
        let out = classify_for_test(
            &dir,
            TRAIL,
            ReaderPath::LiveOpen { expected: None },
            None,
            Reaction::Collect,
            None,
        )
        .unwrap();
        // Exact literal: single violation on segment_index 0 (rotated_0).
        assert_eq!(
            out.violations,
            vec![(
                SegmentViolationPos {
                    segment_index: 0,
                    record_index_in_segment: 2,
                },
                Violation::SequenceDidNotIncrease,
            )],
            "CC1 exact: rotated_0 glued duplicate record raises \
             SequenceDidNotIncrease at (seg=0, rec=2)"
        );
        assert!(!out.head_mismatch);
    }

    /// CC4-openfallback-order-matches-base: same layout as RP5 under
    /// Collect — rotated_0 has a duplicated opening. The collector does
    /// not short-circuit, so the violation appears exactly where the
    /// reader-side Stop would have exited (on segment 0). Addendum 27.4
    /// : literal pin.
    #[test]
    fn cc4_openfallback_order_matches_base() {
        let d = Temp::new();
        let first = fixture(&d.0);
        let mut mmr = seeded(&first);
        let _ = rotated(&d.0, &first, &mut mmr, 0);
        // Corrupt rotated_0 by duplicating the first record so sequence
        // doesn't strictly increase inside the sealed run.
        let bytes = fs::read(segment(&d.0, 0)).unwrap();
        let doubled = [bytes, line(&first)].concat();
        fs::write(segment(&d.0, 0), doubled).unwrap();

        let dir = dirfile(&d.0);
        let out = classify_for_test(
            &dir,
            TRAIL,
            ReaderPath::LiveOpen { expected: None },
            None,
            Reaction::Collect,
            None,
        )
        .unwrap();
        assert_eq!(
            out.violations,
            vec![(
                SegmentViolationPos {
                    segment_index: 0,
                    record_index_in_segment: 2,
                },
                Violation::SequenceDidNotIncrease,
            )],
            "CC4: open-fallback collect records exactly the rotated_0 duplicated-opening \
             violation (seg 0 rec 2 / SequenceDidNotIncrease), same first-violation as Stop",
        );
    }

    /// CC6-refresh-rotate-prelude-violation: RefreshRotate where the
    /// cached-live prelude (re-read as a sealed segment) carries a
    /// non-identical rollback after the cache offset: an `Entry` with
    /// `seq == first.seq` (the rollback the strict scan rejects before
    /// dedup logic can swallow it as an identical duplicate). Under
    /// Collect, classify_collect records a prelude-side
    /// `SequenceDidNotIncrease` at `segment_index == 0`
    /// (`record_index_in_segment == 0`) and continues into rotated_0
    /// where the broken hash link surfaces as a `RecordRolledBack`
    /// at `segment_index == 1`.
    #[test]
    fn cc6_refresh_rotate_prelude_violation() {
        let d = Temp::new();
        let first = fixture(&d.0);
        let cache = live_cache(&d.0);
        // Append a non-identical rollback (seq == first.seq) so the
        // dedup path does not swallow it as an identical duplicate.
        let bad = Record::new(
            context(first.context.seq, first.hash()),
            Entry::new("actor", "change", "object"),
        )
        .unwrap();
        append(&d.0.join("audit.jsonl"), &bad);
        // Close + rotate.
        let mut mmr = seeded(&first);
        let close = cp(first.context.seq + 1, first.hash(), &mmr);
        append(&d.0.join("audit.jsonl"), &close);
        mmr.push(close.hash()).unwrap();
        fs::rename(d.0.join("audit.jsonl"), segment(&d.0, 0)).unwrap();
        let opening = cp(close.context.seq + 1, close.hash(), &mmr);
        fs::write(d.0.join("audit.jsonl"), line(&opening)).unwrap();

        let dir = dirfile(&d.0);
        let out = classify_for_test(
            &dir,
            TRAIL,
            ReaderPath::RefreshRotate,
            Some(cache.state().clone()),
            Reaction::Collect,
            Some(&cache),
        )
        .unwrap();
        assert_eq!(
            out.violations,
            vec![
                (
                    SegmentViolationPos {
                        segment_index: 0,
                        record_index_in_segment: 0,
                    },
                    Violation::SequenceDidNotIncrease,
                ),
                (
                    SegmentViolationPos {
                        segment_index: 1,
                        record_index_in_segment: 0,
                    },
                    Violation::RecordRolledBack,
                ),
            ],
            "CC6: refresh-rotate collect records the prelude's SequenceDidNotIncrease at \
             the mid-segment append offset (seg 0 rec 0) and continues into the \
             rotated_0 segment where the opening checkpoint's hash link is now broken \
             (seg 1 rec 0 / RecordRolledBack)",
        );
        assert!(!out.head_mismatch);
    }

    /// CC7-refresh-rotate-rotated-violation: RefreshRotate with clean
    /// prelude, corrupt rotated_0, valid live. Under Collect the
    /// recorded violation is on `segment_index == 1`.
    #[test]
    fn cc7_refresh_rotate_rotated_violation() {
        let d = Temp::new();
        let first = fixture(&d.0);
        let cache = live_cache(&d.0);
        // Rotate first live to segname(0), with a clean close.
        let mut mmr = seeded(&first);
        let close = cp(1, first.hash(), &mmr);
        append(&d.0.join("audit.jsonl"), &close);
        mmr.push(close.hash()).unwrap();
        fs::rename(d.0.join("audit.jsonl"), segment(&d.0, 0)).unwrap();
        // Corrupt rotated_0 with a glued duplicate.
        let bytes = fs::read(segment(&d.0, 0)).unwrap();
        let bad_dup = line(&first);
        fs::write(segment(&d.0, 0), [bytes, bad_dup].concat()).unwrap();
        // Valid new live.
        let opening = cp(close.context.seq + 1, close.hash(), &mmr);
        fs::write(d.0.join("audit.jsonl"), line(&opening)).unwrap();

        let dir = dirfile(&d.0);
        let out = classify_for_test(
            &dir,
            TRAIL,
            ReaderPath::RefreshRotate,
            Some(cache.state().clone()),
            Reaction::Collect,
            Some(&cache),
        )
        .unwrap();
        // #197 ruling addendum 27.4: literal assert_eq on the full
        // vec. Under state threading (addendum 27.1) the prelude's
        // folded state is handed to rotated_0, so the strict
        // first-violation surfaces on the prelude's glued duplicate at
        // (seg=0, rec=1).
        assert_eq!(
            out.violations,
            vec![(
                SegmentViolationPos {
                    segment_index: 0,
                    record_index_in_segment: 1,
                },
                Violation::SequenceDidNotIncrease,
            )],
            "CC7: refresh-rotate exact literal list — prelude (seg 0) hits SequenceDidNotIncrease \
             on the duplicate; rotated_0 (seg 1) re-uses the threaded state and does not re-record"
        );
    }

    /// CC3-liveopen-two-violations-cross-segment: a LiveOpen layout
    /// where the rotated_0 segment contains an in-segment rollback AND
    /// the live segment contains a separate rollback. Under Collect,
    /// classify_collect records violations tagged with distinct
    /// `segment_index` values (0 for rotated_0, 1 for live). Addendum
    /// 17.4: the sealed-segment walk continues through end-of-segment
    /// checks under Collect, so both segment's records are captured.
    #[test]
    fn cc3_liveopen_two_violations_cross_segment() {
        let d = Temp::new();
        let first = fixture(&d.0);
        // Rotate first live to seg_0 + inject a glued rollback.
        let mut mmr = seeded(&first);
        let close = cp(first.context.seq + 1, first.hash(), &mmr);
        append(&d.0.join("audit.jsonl"), &close);
        mmr.push(close.hash()).unwrap();
        fs::rename(d.0.join("audit.jsonl"), segment(&d.0, 0)).unwrap();
        let seg0 = fs::read(segment(&d.0, 0)).unwrap();
        let bad_rotated = line(&first);
        fs::write(segment(&d.0, 0), [seg0, bad_rotated].concat()).unwrap();
        // Write a live with a rollback: opening cp2 + rollback entry.
        let opening = cp(close.context.seq + 1, close.hash(), &mmr);
        let live_rollback = Record::new(
            context(opening.context.seq, opening.hash()),
            Entry::new("actor", "change", "object"),
        )
        .unwrap();
        fs::write(
            d.0.join("audit.jsonl"),
            [line(&opening), line(&live_rollback)].concat(),
        )
        .unwrap();

        let dir = dirfile(&d.0);
        let out = classify_for_test(
            &dir,
            TRAIL,
            ReaderPath::LiveOpen { expected: None },
            None,
            Reaction::Collect,
            None,
        )
        .unwrap();
        assert_eq!(
            out.violations,
            vec![
                (
                    SegmentViolationPos {
                        segment_index: 0,
                        record_index_in_segment: 2,
                    },
                    Violation::SequenceDidNotIncrease,
                ),
                (
                    SegmentViolationPos {
                        segment_index: 1,
                        record_index_in_segment: 1,
                    },
                    Violation::RecordRolledBack,
                ),
            ],
            "CC3: cross-segment collect records the rotated_0 duplicated opening \
             (seg 0 rec 2 / SequenceDidNotIncrease) followed by the live rollback \
             (seg 1 rec 1 / RecordRolledBack)",
        );
    }

    /// CC8-fold-iii-recorded-and-continues: a single-segment layout
    /// where a checkpoint's embedded MMR root disagrees with the fold
    /// the walker built from the preceding records. Under Collect the
    /// violation is recorded as `CheckpointMmrDiffers` and classify
    /// continues through subsequent records (addenda 17.3 / 19.2).
    #[test]
    fn cc8_fold_iii_recorded_and_continues() {
        let d = Temp::new();
        let first = fixture(&d.0);
        let e1 = entry(&first);
        append(&d.0.join("audit.jsonl"), &e1);
        // Build cp2 with the correct popcount/size but a wrong root
        // and wrong peaks, so the fold-iii comparison records a
        // CheckpointMmrDiffers while the record itself remains a
        // valid parseable checkpoint.
        let mut real_mmr = seeded(&first);
        real_mmr.push(e1.hash()).unwrap();
        let wrong_peaks: Vec<[u8; 32]> = real_mmr.peaks().iter().map(|_| [0x66; 32]).collect();
        let fake_fields =
            CheckpointFields::new(real_mmr.size(), [0x66; 32], wrong_peaks, [1; 32], [0; 64])
                .unwrap();
        let bad_cp2 =
            Record::checkpoint(context(e1.context.seq + 1, e1.hash()), fake_fields).unwrap();
        append(&d.0.join("audit.jsonl"), &bad_cp2);

        let dir = dirfile(&d.0);
        let out = classify_for_test(
            &dir,
            TRAIL,
            ReaderPath::LiveOpen { expected: None },
            None,
            Reaction::Collect,
            None,
        )
        .unwrap();
        assert_eq!(
            out.violations,
            vec![(
                SegmentViolationPos {
                    segment_index: 0,
                    record_index_in_segment: 2,
                },
                Violation::CheckpointMmrDiffers,
            )],
            "CC8: fold-iii salvage records exactly one CheckpointMmrDiffers at the \
             bad checkpoint's position (seg 0 rec 2); the segment is then marked \
             damaged so no derived InvalidUndamagedSegment follows (addendum 19.2)",
        );
    }

    /// CC9-collect-tags-record-index: a rotated_0 layout `[cp0, e1, e2,
    /// e3, bad_e3]` where the rollback sits at record index 4. Under
    /// Collect the recorded violation's `record_index_in_segment` is
    /// exactly 4 on `segment_index == 0`. Kills M-C8 (Collect
    /// `record_index_in_segment` not bumped: would be 0 instead).
    #[test]
    fn cc9_collect_tags_record_index() {
        let d = Temp::new();
        let first = fixture(&d.0);
        // Append e1, e2, e3, then rollback (re-append e3). Then rotate.
        let e1 = entry(&first);
        append(&d.0.join("audit.jsonl"), &e1);
        let e2 = entry(&e1);
        append(&d.0.join("audit.jsonl"), &e2);
        let e3 = entry(&e2);
        append(&d.0.join("audit.jsonl"), &e3);
        // Rollback: re-append e3 with a mutated hash link.
        append(&d.0.join("audit.jsonl"), &e3);
        // Rotate.
        let mut mmr = seeded(&first);
        mmr.push(e1.hash()).unwrap();
        mmr.push(e2.hash()).unwrap();
        mmr.push(e3.hash()).unwrap();
        mmr.push(e3.hash()).unwrap();
        let close = cp(5, e3.hash(), &mmr);
        append(&d.0.join("audit.jsonl"), &close);
        mmr.push(close.hash()).unwrap();
        fs::rename(d.0.join("audit.jsonl"), segment(&d.0, 0)).unwrap();
        let opening = cp(close.context.seq + 1, close.hash(), &mmr);
        fs::write(d.0.join("audit.jsonl"), line(&opening)).unwrap();

        let dir = dirfile(&d.0);
        let out = classify_for_test(
            &dir,
            TRAIL,
            ReaderPath::LiveOpen { expected: None },
            None,
            Reaction::Collect,
            None,
        )
        .unwrap();
        assert_eq!(
            out.violations,
            vec![
                (
                    SegmentViolationPos {
                        segment_index: 0,
                        record_index_in_segment: 5,
                    },
                    Violation::SequenceGapInSealedRun,
                ),
                (
                    SegmentViolationPos {
                        segment_index: 1,
                        record_index_in_segment: 0,
                    },
                    Violation::RecordRolledBack,
                ),
            ],
            "CC9: rotated_0 records the rollback at record index 5 (kills M-C8 which \
             would tag it 0), then the live opening checkpoint inherits the damaged \
             run and the walk records a RecordRolledBack at seg 1 rec 0",
        );
    }

    /// M-C3 killer: classify drops `found` writeback on the live-close
    /// walker → under Stop with `expected=Some(H_live)`, the Cache's
    /// `found` field must be `Some(H_live)` after a successful scan.
    ///
    /// Ruling 197-d1 addendum 27.4: literal pin — `found.hash()` equals
    /// the exact live tail record's hash.
    #[test]
    fn mc3_found_writeback_on_live_close() {
        let d = Temp::new();
        let first = fixture(&d.0);
        let second = entry(&first);
        append(&d.0.join("audit.jsonl"), &second);
        let dir = dirfile(&d.0);
        let out = classify_for_test(
            &dir,
            TRAIL,
            ReaderPath::LiveOpen {
                expected: Some(Head::of(&second)),
            },
            None,
            Reaction::Stop,
            None,
        )
        .unwrap();
        let found = out.found.as_ref().expect(
            "M-C3: classify must populate `found` when `expected` matches a record on the live close",
        );
        assert_eq!(found.hash(), second.hash());
        assert_eq!(found.context.seq, second.context.seq);
    }

    /// MC3C-Collect-found-writeback-on-live-after-rotation: with the
    /// fixture plus one rotation (rotated_0 complete, live has the
    /// opening) and `expected = Head::of(&opening)`, Stop returns Ok
    /// with `found = Some(opening)`; Collect must give
    /// `head_mismatch == false` AND `found = Some(opening)` on the
    /// same layout (ruling 197-d1 addendum 27.1). Kills the MC3C
    /// mutant "drop `found` after the Collect live close": under the
    /// mutant Collect's `found` would be `None`, so a literal pin on
    /// `found.hash() == opening.hash()` and `head_mismatch == false`
    /// is enough to flip the row. Ruling 197-d1 addendum 27.4:
    /// literal pin asserts the exact found hash.
    #[test]
    fn mc3c_collect_found_writeback_on_live_after_rotation() {
        let d = Temp::new();
        let first = fixture(&d.0);
        let mut mmr = seeded(&first);
        let opening = rotated(&d.0, &first, &mut mmr, 0);
        let dir = dirfile(&d.0);
        let out = classify_for_test(
            &dir,
            TRAIL,
            ReaderPath::LiveOpen {
                expected: Some(Head::of(&opening)),
            },
            None,
            Reaction::Collect,
            None,
        )
        .unwrap();
        assert_eq!(
            out.violations,
            Vec::<(SegmentViolationPos, Violation)>::new(),
            "MC3C: valid rotated+live layout records no violations"
        );
        assert!(
            !out.head_mismatch,
            "MC3C: expected head is present on the live segment, so head_mismatch is false"
        );
        let found = out.found.as_ref().expect(
            "MC3C: classify under Collect must populate `found` when `expected` matches a record on the live close",
        );
        assert_eq!(found.hash(), opening.hash());
        assert_eq!(found.context.seq, opening.context.seq);
    }

    /// CC12-liveopen-damaged-sealed-propagates-run-to-live-close:
    /// Under `Reaction::Collect`, the same layout as RP12 records an
    /// `UnclosedSegmentLacksResume` violation tagged at
    /// `segment_index == 1` (the live segment). rotated_0 is
    /// `[cp0, close1]` plus a complete `Line::Unparsable` payload, so
    /// the tolerant fallback latches `damaged = true` and promotes
    /// `run_flag = true` without updating `gap`; the returned State
    /// is sealed (gap=None, run.checkpoint=true). `classify_collect`
    /// threads `run = true` into `scan_closing` on the live, where
    /// `initial_boundary_resume = ctx.run || !sealed(prior) = true ||
    /// false = true` relies solely on the `run` arg. Kills M-C9
    /// ("run inheritance drops across live-close"): the mutant
    /// passes `run = false` to `scan_closing`, `initial_boundary_
    /// resume` collapses to false, and no violation is recorded on
    /// the live's non-resume second record. Ruling 197-d1 addendum
    /// 27.4: literal pin asserts the first recorded violation's exact
    /// (seg, rec, variant).
    #[test]
    fn cc12_liveopen_damaged_sealed_propagates_run_to_live_close() {
        let d = Temp::new();
        let first = fixture(&d.0);
        let mut mmr = seeded(&first);
        let opening = rotated(&d.0, &first, &mut mmr, 0);
        // Damage rotated_0 with a complete Unparsable line: the
        // tolerant fallback latches `damaged = true` (hence
        // `run_flag = true`) WITHOUT updating `gap`, so `*run` is the
        // only signal carried across the sealed->live boundary.
        append_bytes(&segment(&d.0, 0), b"garbage\n");
        // Non-resume second record on the live.
        let bad = entry(&opening);
        append(&d.0.join("audit.jsonl"), &bad);

        let dir = dirfile(&d.0);
        let out = classify_for_test(
            &dir,
            TRAIL,
            ReaderPath::LiveOpen { expected: None },
            None,
            Reaction::Collect,
            None,
        )
        .unwrap();
        // #197 ruling addendum 27.4: literal `vec![...]` assert_eq.
        // With state threading, the sealed rotated_0's folded `State`
        // reaches the live-close walker; the strict live-close pass
        // sees `run=true` through the `*run` arg,
        // `initial_boundary_resume = opening && (ctx.run ||
        // !sealed(prior)) = true && (true || false) = true`, so the
        // live's non-resume second record trips `boundary_resume &&
        // !first && !is_resume` and records
        // `UnclosedSegmentLacksResume` at (seg=1, rec=1). This is
        // byte-equal to the reader's RP12 `Err` detail
        // ("unclosed segment lacks matching immediate resume").
        // Kills M-C9 ("run inheritance drops across live-close"):
        // under the mutant `run=false` collapses
        // `initial_boundary_resume`, strict walks cleanly, and the
        // violation never fires.
        assert_eq!(
            out.violations,
            vec![(
                SegmentViolationPos {
                    segment_index: 1,
                    record_index_in_segment: 1,
                },
                Violation::UnclosedSegmentLacksResume,
            )],
            "CC12: exact literal list — run=true propagation into scan_closing records \
             UnclosedSegmentLacksResume on the live's non-resume second record (kills M-C9)"
        );
        assert!(
            !out.head_mismatch,
            "CC12: LiveOpen with expected=None never sets head_mismatch"
        );
    }

    /// CC13-liveopen-damaged-sealed-propagates-run-across-sealed:
    /// Under `Reaction::Collect`, the two-rotation layout records a
    /// `FirstSuccessorLacksImmediateResume` violation tagged at
    /// `segment_index == 1` (rotated_1). rotated_0 is `[cp0, close1]`
    /// plus a complete `Line::Unparsable` line, so the tolerant
    /// fallback latches `damaged` and promotes `run_flag = true`
    /// WITHOUT updating `gap`; the returned State is sealed
    /// (gap=None, run.checkpoint=true). `classify_collect` threads
    /// `run = true` into rotated_1's `history_segment` call, strict
    /// fails on the closing cp via `boundary_resume && !first &&
    /// !is_resume`, the tolerant Collect fallback runs with
    /// `inherited = run_in || unsealed_boundary = true || false =
    /// true`, and the closing cp at `count == 1` records
    /// `FirstSuccessorLacksImmediateResume`. Kills M-C2 ("classify
    /// threads `run = false` across sealed->sealed"): the mutant
    /// resets `run = false` between sealed segments, strict runs
    /// cleanly (initial_boundary_resume = false, no inherited run),
    /// and no violation on rotated_1 is recorded. Addendum 27.4:
    /// literal pin asserts the exact (seg, rec, variant) for seg 1.
    #[test]
    fn cc13_liveopen_damaged_sealed_propagates_run_across_sealed() {
        let d = Temp::new();
        let first = fixture(&d.0);
        let mut mmr = seeded(&first);
        let opening = rotated(&d.0, &first, &mut mmr, 0);
        // Damage rotated_0 with a complete Unparsable line: the
        // tolerant epilogue latches `run_flag = true` WITHOUT
        // updating `gap`, so `*run` is the only signal carried
        // across the sealed->sealed boundary.
        append_bytes(&segment(&d.0, 0), b"garbage\n");
        let opening2 = rotated(&d.0, &opening, &mut mmr, 1);
        // Close the live-side run so the layout is well-formed under
        // the mutant (no incidental live-side violation that would
        // confuse the assertion).
        let close3 = cp(opening2.context.seq + 1, opening2.hash(), &mmr);
        append(&d.0.join("audit.jsonl"), &close3);

        let dir = dirfile(&d.0);
        let out = classify_for_test(
            &dir,
            TRAIL,
            ReaderPath::LiveOpen { expected: None },
            None,
            Reaction::Collect,
            None,
        )
        .unwrap();
        // #197 ruling addendum 27.4: literal `vec![...]` assert_eq.
        // With state threading, the sealed rotated_0's folded state
        // reaches rotated_1's history_segment; strict detects the
        // closing cp at `count == 1` as
        // `FirstSuccessorLacksImmediateResume` via `boundary_resume &&
        // !is_resume`, and the following live records
        // `RecordRolledBack` because the state advance is halted by
        // `recovery_pending`. Byte-equal to the reader's RP13 `Err`
        // detail ("first successor lacks immediate resume"). Kills
        // M-C2 ("classify threads `run = false` across
        // sealed->sealed"): under the mutant `run_in=false` leaves
        // `boundary_resume=false`, strict walks cleanly, and the
        // resume violation never fires.
        assert_eq!(
            out.violations,
            vec![
                (
                    SegmentViolationPos {
                        segment_index: 1,
                        record_index_in_segment: 1,
                    },
                    Violation::FirstSuccessorLacksImmediateResume,
                ),
                (
                    SegmentViolationPos {
                        segment_index: 2,
                        record_index_in_segment: 0,
                    },
                    Violation::RecordRolledBack,
                ),
            ],
            "CC13: exact literal list — run=true propagation across sealed->sealed records \
             FirstSuccessorLacksImmediateResume on rotated_1's closing cp (kills M-C2), \
             followed by a RecordRolledBack on the live from the halted state advance"
        );
        assert!(
            !out.head_mismatch,
            "CC13: LiveOpen with expected=None never sets head_mismatch"
        );
    }

    /// CC14-liveopen-ok-expected-on-sealed-record: Collect counterpart
    /// of RP14. Layout sealed `[cp0, e1, cp2]`, live `[cp3]`, with
    /// `expected = Head(cp2)`. Under Collect, `out.violations` is
    /// empty (every record folds cleanly), `out.head_mismatch` is
    /// false (expected matches cp2 on the sealed segment), and
    /// `out.found` is `Some(cp2)`.
    ///
    /// Kills the "Collect sealed arm passes `expected = None`" and
    /// the "Collect clears `found` after each sealed segment"
    /// mutants: under either plant the sealed walker never writes
    /// `found`, the live walker never matches on cp3, `head_mismatch`
    /// flips to true, and the row's `assert_eq!(out.found, Some(..))`
    /// exits 101.
    #[test]
    fn cc14_liveopen_ok_expected_on_sealed_record() {
        let d = Temp::new();
        let first = fixture(&d.0);
        let second = entry(&first);
        append(&d.0.join("audit.jsonl"), &second);
        let mut mmr = seeded(&first);
        mmr.push(second.hash()).unwrap();
        let cp2 = cp(second.context.seq + 1, second.hash(), &mmr);
        append(&d.0.join("audit.jsonl"), &cp2);
        mmr.push(cp2.hash()).unwrap();
        fs::rename(d.0.join("audit.jsonl"), segment(&d.0, 0)).unwrap();
        let cp3 = cp(cp2.context.seq + 1, cp2.hash(), &mmr);
        fs::write(d.0.join("audit.jsonl"), line(&cp3)).unwrap();

        let dir = dirfile(&d.0);
        let out = classify_for_test(
            &dir,
            TRAIL,
            ReaderPath::LiveOpen {
                expected: Some(Head::of(&cp2)),
            },
            None,
            Reaction::Collect,
            None,
        )
        .unwrap();
        assert_eq!(
            out.violations,
            vec![],
            "CC14: a valid rotated+live trail with expected on the sealed cp records no \
             violations",
        );
        assert!(
            !out.head_mismatch,
            "CC14: expected matches cp2 on the sealed segment, so head_mismatch is false",
        );
        let found = out
            .found
            .as_ref()
            .expect("CC14: the sealed walker must write `found` when `expected` matches cp2");
        assert_eq!(
            (found.hash(), found.context.seq),
            (cp2.hash(), cp2.context.seq),
            "CC14: `found` is cp2 (the sealed segment's second checkpoint); no later \
             record overwrites it",
        );
    }

    /// CC15-liveopen-ok-duplicate-entry-in-live: a layout `[cp0, e1, e1]`
    /// in a single live file. Under `Reaction::Stop` the strict walker
    /// takes `Advance::Duplicate` on the second `e1` (state unchanged,
    /// `since_checkpoint` stays at 1). Under `Reaction::Collect` the
    /// (Strict, Collect) dispatch arm receives `Some(Advance::Duplicate)`
    /// from `feed_record_collect_strict` and emits
    /// `DispatchFed::Duplicate` through `on_feed`, so Collect's
    /// `final_state` matches Stop's bit-for-bit, with `violations == []`
    /// and `head_mismatch == false` (ruling 197-d1 addendum 27.1
    /// Collect-vs-Stop Ok-path equality).
    ///
    /// A mutant on the (Strict, Collect) arm that re-routes a duplicate
    /// as `DispatchFed::Record` re-enters `on_feed`'s Record branch and
    /// bumps `since_checkpoint` to 2 on the second `e1`, so Collect's
    /// `final_state.since_checkpoint` diverges from Stop's; this row's
    /// `assert_eq!` on the full `ok_outcome()` then exits 101.
    #[test]
    fn cc15_liveopen_ok_duplicate_entry_in_live() {
        let d = Temp::new();
        let first = fixture(&d.0);
        let second = entry(&first);
        append(&d.0.join("audit.jsonl"), &second);
        append(&d.0.join("audit.jsonl"), &second);
        let dir1 = dirfile(&d.0);
        let stop = classify_for_test(
            &dir1,
            TRAIL,
            ReaderPath::LiveOpen { expected: None },
            None,
            Reaction::Stop,
            None,
        )
        .expect("CC15/Stop: `[cp0, e1, e1]` is a valid live-only layout");
        let dir2 = dirfile(&d.0);
        let collect = classify_for_test(
            &dir2,
            TRAIL,
            ReaderPath::LiveOpen { expected: None },
            None,
            Reaction::Collect,
            None,
        )
        .expect("CC15/Collect: `[cp0, e1, e1]` is a valid live-only layout");
        assert_eq!(
            collect.violations,
            Vec::<(SegmentViolationPos, Violation)>::new(),
            "CC15: a duplicate line on a live-only layout records no violations under Collect",
        );
        assert!(
            !collect.head_mismatch,
            "CC15: LiveOpen with `expected=None` never sets `head_mismatch`",
        );
        assert_eq!(
            ok_outcome(&collect),
            ok_outcome(&stop),
            "CC15: Collect's `final_state` / `found` must equal Stop's bit-for-bit on \
             `[cp0, e1, e1]` (every State field, including `since_checkpoint == 1`)",
        );
        let finish = collect
            .final_state
            .as_ref()
            .expect("CC15: live arm yields a folded state");
        assert_eq!(
            finish.since_checkpoint, 1,
            "CC15: the duplicate branch must NOT call `next_cp_fields`, so \
             `since_checkpoint` stays at 1 (the count from the first `e1`)",
        );
    }

    /// CC16-liveopen-err-record-rolled-back-expected-on-prior-live:
    /// a layout `[cp0, e1, H]` where `H` is a distinct record with the
    /// same `context.seq` as `e1` (and the same `context.previous =
    /// cp0.hash`), so `apply_checked` returns
    /// `Violation::RecordRolledBack`. The `expected` head is `e1`, so
    /// when the Collect walker folds `e1` the on_feed Record branch
    /// writes `found = Some(e1)`. The Strict-Collect arm then rejects
    /// `H` through `feed_record_collect_strict` (returns `None`),
    /// `on_violation` records `(pos{0,2}, RecordRolledBack)` and
    /// latches `recovery_pending`, and the `None` dispatch branch runs
    /// nothing: `found` keeps its `Some(e1)` value.
    ///
    /// A mutant on the (Strict, Collect) arm that runs `on_feed` on
    /// the `None` branch feeds `DispatchFed::Record(H, rs=e1)`, so
    /// `expected == Some(rs.head)` matches and the `on_feed` Record
    /// branch overwrites `found` to `Some(H)`. This row's
    /// `assert_eq!` on `found` then exits 101.
    #[test]
    fn cc16_liveopen_err_record_rolled_back_expected_on_prior_live() {
        let d = Temp::new();
        let first = fixture(&d.0);
        let second = entry(&first);
        append(&d.0.join("audit.jsonl"), &second);
        // `H`: same seq as `second`, distinct payload (different
        // actor), same previous (points to cp0). `apply_checked`
        // returns `Violation::RecordRolledBack` because
        // `head.seq <= s.head.seq` (equal) and the hashes differ.
        let h = Record::new(
            RecordContext::new(
                TRAIL,
                second.context.seq,
                100 + second.context.seq,
                "other",
                first.hash(),
            ),
            Entry::new("other", "change", "object"),
        )
        .unwrap();
        append(&d.0.join("audit.jsonl"), &h);

        let dir = dirfile(&d.0);
        let out = classify_for_test(
            &dir,
            TRAIL,
            ReaderPath::LiveOpen {
                expected: Some(Head::of(&second)),
            },
            None,
            Reaction::Collect,
            None,
        )
        .expect("CC16: Collect finishes Ok with a rolled-back record recorded");
        assert_eq!(
            out.violations,
            vec![(
                SegmentViolationPos {
                    segment_index: 0,
                    record_index_in_segment: 2,
                },
                Violation::RecordRolledBack,
            )],
            "CC16: exact literal list — `H` rolls the stream back at (seg=0, rec=2), \
             nothing else records",
        );
        let found = out
            .found
            .as_ref()
            .expect("CC16: the Record-branch writeback must fire when `e1` folds");
        assert_eq!(
            (found.hash(), found.context.seq),
            (second.hash(), second.context.seq),
            "CC16: `found` is `e1` (the record whose head equals `expected`); the \
             rejected `H` must NOT overwrite `found` through the `None` dispatch branch",
        );
        assert!(
            !out.head_mismatch,
            "CC16: `expected` was found on the live segment before `H` rejected, so \
             `head_mismatch` stays false",
        );
    }

    /// CC17-refresh-rotate-damaged-prelude-requires-resume-on-live:
    /// Collect counterpart of `RP16`. Same RefreshRotate layout
    /// (cached prelude ends with a complete `Line::Unparsable`
    /// payload after rotation); under `Reaction::Collect` the live
    /// arm's Strict-Collect walker records `UnclosedSegmentLacksResume`
    /// at `segment_index == 1` (the live), tagged at
    /// `record_index_in_segment == 1`. The threaded `run=true` from
    /// the damaged sealed prelude is the sole signal driving
    /// `initial_boundary_resume`; a mutant that drops the live arm's
    /// `run` arg to `false` collapses it, strict walks the live
    /// cleanly, and the violation disappears — the row's
    /// `assert_eq!` on the exact `violations` list then exits 101.
    #[test]
    fn cc17_refresh_rotate_damaged_prelude_requires_resume_on_live() {
        let d = Temp::new();
        let first = fixture(&d.0);
        let cache = live_cache(&d.0);
        let mut mmr = seeded(&first);
        let opening = rotated(&d.0, &first, &mut mmr, 0);
        append_bytes(&segment(&d.0, 0), b"garbage\n");
        append(&d.0.join("audit.jsonl"), &entry(&opening));

        let dir = dirfile(&d.0);
        let out = classify_for_test(
            &dir,
            TRAIL,
            ReaderPath::RefreshRotate,
            Some(cache.state().clone()),
            Reaction::Collect,
            Some(&cache),
        )
        .expect("CC17: Collect finishes Ok with the live-side violation recorded");
        assert_eq!(
            out.violations,
            vec![(
                SegmentViolationPos {
                    segment_index: 1,
                    record_index_in_segment: 1,
                },
                Violation::UnclosedSegmentLacksResume,
            )],
            "CC17: exact literal list — the threaded `run=true` from the damaged \
             prelude makes the live's non-resume second record trip \
             `UnclosedSegmentLacksResume` at (seg=1, rec=1)",
        );
        assert!(
            !out.head_mismatch,
            "CC17: `RefreshRotate` never passes an `expected` head, so `head_mismatch` \
             stays false",
        );
    }
}

// ============================================================
// First-equality sweep (addendum 25.3): across multiple layouts and
// reader paths, classify-Collect-first == reader-first.
// ============================================================
mod classify_first_equality {
    use super::*;

    /// One layout run under one path-builder, producing a directory on
    /// disk and the [`ReaderPath`] + optional [`Cache`] the sweep
    /// drives through `classify_stop` / `classify_collect`.
    struct Row {
        name: &'static str,
        build: fn(&Path) -> (ReaderPath, Option<Cache>),
    }

    /// Build a set of multi-segment layouts and compare the reader's
    /// first-violation outcome against classify under Collect's first
    /// violation. Covers all five reader paths (ruling 197-d1
    /// addendum 25.3): live open, open fallback, refresh append,
    /// refresh rotate, refresh append+rotate. #197 ruling addendum
    /// 27.1: the sweep also covers damaged multi-segment layouts on
    /// every path (a garbage tail after a valid sealed, a non-resume
    /// successor, and a broken prelude), expected-head-present
    /// layouts on live open and open fallback, and duplicate-line
    /// layouts, so Ok-path full equality pins the state-threading
    /// and `found` writeback behaviour.
    ///
    /// 0 mismatches, 0 exclusions required.
    #[test]
    fn multi_segment_first_equality_sweep() {
        let layouts: &[Row] = &[
            // ----- Live open -----
            Row {
                name: "liveopen-ok-single",
                build: |p| {
                    let _ = fixture(p);
                    (ReaderPath::LiveOpen { expected: None }, None)
                },
            },
            Row {
                name: "liveopen-err-headmismatch",
                build: |p| {
                    let _ = fixture(p);
                    (
                        ReaderPath::LiveOpen {
                            expected: Some(Head {
                                seq: 42,
                                hash: [0xee; 32],
                            }),
                        },
                        None,
                    )
                },
            },
            // ----- Open fallback (rotated + live listed at open) -----
            Row {
                name: "openfallback-ok-rotated-plus-live",
                build: |p| {
                    let first = fixture(p);
                    let mut mmr = seeded(&first);
                    let _ = rotated(p, &first, &mut mmr, 0);
                    (ReaderPath::LiveOpen { expected: None }, None)
                },
            },
            Row {
                name: "openfallback-multi-rotate-chain",
                build: |p| {
                    let first = fixture(p);
                    let mut mmr = seeded(&first);
                    let r1 = rotated(p, &first, &mut mmr, 0);
                    let _ = rotated(p, &r1, &mut mmr, 1);
                    (ReaderPath::LiveOpen { expected: None }, None)
                },
            },
            // ----- Refresh append (same-inode) -----
            Row {
                name: "refresh-append-ok",
                build: |p| {
                    let first = fixture(p);
                    let cache = live_cache(p);
                    let second = entry(&first);
                    append(&p.join("audit.jsonl"), &second);
                    (ReaderPath::RefreshAppend, Some(cache_for_path(cache)))
                },
            },
            Row {
                name: "refresh-append-err-rollback",
                build: |p| {
                    let first = fixture(p);
                    let cache = live_cache(p);
                    let bad = Record::new(
                        context(first.context.seq, first.hash()),
                        Entry::new("actor", "change", "object"),
                    )
                    .unwrap();
                    append(&p.join("audit.jsonl"), &bad);
                    (ReaderPath::RefreshAppend, Some(cache_for_path(cache)))
                },
            },
            // ----- Refresh rotate (different-inode; cached live
            //       becomes a prelude) -----
            Row {
                name: "refresh-rotate-ok",
                build: |p| {
                    let first = fixture(p);
                    let cache = live_cache(p);
                    let mut mmr = seeded(&first);
                    let _ = rotated(p, &first, &mut mmr, 0);
                    (ReaderPath::RefreshRotate, Some(cache_for_path(cache)))
                },
            },
            // ----- Refresh append + rotate (cache appended then rotated) -----
            Row {
                name: "refresh-append-then-rotate",
                build: |p| {
                    let first = fixture(p);
                    let cache = live_cache(p);
                    let second = entry(&first);
                    append(&p.join("audit.jsonl"), &second);
                    let mut mmr = seeded(&first);
                    mmr.push(second.hash()).unwrap();
                    let _ = rotated(p, &second, &mut mmr, 0);
                    (ReaderPath::RefreshRotate, Some(cache_for_path(cache)))
                },
            },
            // ----- Damaged multi-segment layouts that exercise
            //       state threading and the `found` writeback across
            //       the sealed->live boundary (#197 ruling addendum
            //       27.1 Collect-vs-Stop Ok-path equality). -----
            // Garbage tail after a valid sealed segment (LiveOpen).
            Row {
                name: "liveopen-damaged-rotated-plus-non-resume-live",
                build: |p| {
                    let first = fixture(p);
                    let mut mmr = seeded(&first);
                    let opening = rotated(p, &first, &mut mmr, 0);
                    append_bytes(&segment(p, 0), b"garbage\n");
                    append(&p.join("audit.jsonl"), &entry(&opening));
                    (ReaderPath::LiveOpen { expected: None }, None)
                },
            },
            // Garbage tail across two sealed segments (LiveOpen, open
            // fallback with expected=None).
            Row {
                name: "liveopen-damaged-rotated-plus-rotated-plus-live",
                build: |p| {
                    let first = fixture(p);
                    let mut mmr = seeded(&first);
                    let opening = rotated(p, &first, &mut mmr, 0);
                    append_bytes(&segment(p, 0), b"garbage\n");
                    let opening2 = rotated(p, &opening, &mut mmr, 1);
                    let close3 = cp(opening2.context.seq + 1, opening2.hash(), &mmr);
                    append(&p.join("audit.jsonl"), &close3);
                    (ReaderPath::LiveOpen { expected: None }, None)
                },
            },
            // Expected head present on LiveOpen's live segment.
            Row {
                name: "liveopen-expected-matches-live",
                build: |p| {
                    let first = fixture(p);
                    let second = entry(&first);
                    append(&p.join("audit.jsonl"), &second);
                    (
                        ReaderPath::LiveOpen {
                            expected: Some(Head::of(&second)),
                        },
                        None,
                    )
                },
            },
            // Expected head present on open fallback's live (post-
            // rotation).
            Row {
                name: "openfallback-expected-matches-live-opening",
                build: |p| {
                    let first = fixture(p);
                    let mut mmr = seeded(&first);
                    let opening = rotated(p, &first, &mut mmr, 0);
                    (
                        ReaderPath::LiveOpen {
                            expected: Some(Head::of(&opening)),
                        },
                        None,
                    )
                },
            },
            // Broken prelude on RefreshRotate (glued bytes before
            // rotation).
            Row {
                name: "refresh-rotate-broken-prelude",
                build: |p| {
                    let first = fixture(p);
                    let cache = live_cache(p);
                    let mut mmr = seeded(&first);
                    append_bytes(&p.join("audit.jsonl"), b"{\"torn\":");
                    let close = cp(first.context.seq + 1, first.hash(), &mmr);
                    append(&p.join("audit.jsonl"), &close);
                    mmr.push(close.hash()).unwrap();
                    fs::rename(p.join("audit.jsonl"), segment(p, 0)).unwrap();
                    let opening = cp(close.context.seq + 1, close.hash(), &mmr);
                    fs::write(p.join("audit.jsonl"), line(&opening)).unwrap();
                    (ReaderPath::RefreshRotate, Some(cache_for_path(cache)))
                },
            },
            // Refresh-append with a non-resume successor on same inode.
            Row {
                name: "refresh-append-non-resume-successor",
                build: |p| {
                    let _first = fixture(p);
                    let cache = live_cache(p);
                    append_bytes(&p.join("audit.jsonl"), b"garbage\n");
                    (ReaderPath::RefreshAppend, Some(cache_for_path(cache)))
                },
            },
            // #197 ruling addendum 27.1 Ok-path full-equality: layouts
            // that pin Collect's Advance routing on duplicates and
            // on expected-head threading. A duplicate line on a
            // live-only layout: Stop takes `Advance::Duplicate`,
            // which keeps `since_checkpoint` at 1; feeding the
            // duplicate as `Advance::Record` would raise it to 2.
            Row {
                name: "liveopen-ok-duplicate-entry",
                build: |p| {
                    let first = fixture(p);
                    let second = entry(&first);
                    append(&p.join("audit.jsonl"), &second);
                    append(&p.join("audit.jsonl"), &second);
                    (ReaderPath::LiveOpen { expected: None }, None)
                },
            },
            // Same duplicate layout driving open fallback: the sealed
            // segment carries the duplicated entry, so the strict pass
            // runs through the Collect-Strict arm of `dispatch_line`.
            // The strict walker treats the second `e1` as
            // `Advance::Duplicate` (state unchanged), so the closing
            // checkpoint rolls the MMR with the entry pushed exactly
            // once -- matching how the writer would seal this run.
            Row {
                name: "openfallback-ok-duplicate-entry-in-sealed",
                build: |p| {
                    let first = fixture(p);
                    let second = entry(&first);
                    append(&p.join("audit.jsonl"), &second);
                    append(&p.join("audit.jsonl"), &second);
                    let mut mmr = seeded(&first);
                    mmr.push(second.hash()).unwrap();
                    let close = cp(second.context.seq + 1, second.hash(), &mmr);
                    append(&p.join("audit.jsonl"), &close);
                    mmr.push(close.hash()).unwrap();
                    fs::rename(p.join("audit.jsonl"), segment(p, 0)).unwrap();
                    let opening = cp(close.context.seq + 1, close.hash(), &mmr);
                    fs::write(p.join("audit.jsonl"), line(&opening)).unwrap();
                    (ReaderPath::LiveOpen { expected: None }, None)
                },
            },
            // Expected head on a SEALED segment's record (open fallback
            // shape). Kills the RV6 mutant "Collect sealed arm passes
            // `expected = None`" and the OWN8 mutant "Collect clears
            // `found` after each sealed segment" through the Ok-path
            // full-equality branch: under either mutant Collect's final
            // `found` is `None` while the reader's is `Some(cp2)`, and
            // Collect's `head_mismatch` flips to true.
            Row {
                name: "openfallback-ok-expected-on-sealed-record",
                build: |p| {
                    let first = fixture(p);
                    let second = entry(&first);
                    append(&p.join("audit.jsonl"), &second);
                    let mut mmr = seeded(&first);
                    mmr.push(second.hash()).unwrap();
                    let cp2 = cp(second.context.seq + 1, second.hash(), &mmr);
                    append(&p.join("audit.jsonl"), &cp2);
                    mmr.push(cp2.hash()).unwrap();
                    fs::rename(p.join("audit.jsonl"), segment(p, 0)).unwrap();
                    let cp3 = cp(cp2.context.seq + 1, cp2.hash(), &mmr);
                    fs::write(p.join("audit.jsonl"), line(&cp3)).unwrap();
                    (
                        ReaderPath::LiveOpen {
                            expected: Some(Head::of(&cp2)),
                        },
                        None,
                    )
                },
            },
            // RefreshRotate with the cached live rotated under the
            // reader: the cached prelude holds `[cp0, e1]`, rotated_0
            // closes it with `[cp0, e1, close]`, and the new live
            // carries the opening. Exercises the sealed walker's
            // state threading across the RefreshRotate prelude →
            // rotated → live chain (`RefreshRotate` never passes an
            // `expected` head, so the row does not drive `found`).
            Row {
                name: "refresh-rotate-ok-cached-prelude-plus-close-plus-opening",
                build: |p| {
                    let first = fixture(p);
                    let second = entry(&first);
                    append(&p.join("audit.jsonl"), &second);
                    let cache = live_cache(p);
                    let mut mmr = seeded(&first);
                    mmr.push(second.hash()).unwrap();
                    let close = cp(second.context.seq + 1, second.hash(), &mmr);
                    append(&p.join("audit.jsonl"), &close);
                    mmr.push(close.hash()).unwrap();
                    fs::rename(p.join("audit.jsonl"), segment(p, 0)).unwrap();
                    let opening = cp(close.context.seq + 1, close.hash(), &mmr);
                    fs::write(p.join("audit.jsonl"), line(&opening)).unwrap();
                    (ReaderPath::RefreshRotate, Some(cache_for_path(cache)))
                },
            },
            // Expected head matches the single live record (live-open
            // single segment, expected present). Pairs with the other
            // expected-present rows so every reader path has one.
            Row {
                name: "liveopen-ok-expected-on-live-single",
                build: |p| {
                    let first = fixture(p);
                    let second = entry(&first);
                    append(&p.join("audit.jsonl"), &second);
                    (
                        ReaderPath::LiveOpen {
                            expected: Some(Head::of(&second)),
                        },
                        None,
                    )
                },
            },
        ];

        let mut mismatches: Vec<String> = Vec::new();
        for row in layouts {
            let d = Temp::new();
            let (path, cache) = (row.build)(&d.0);
            let prior = cache.as_ref().map(|c| c.state().clone());

            let dir = dirfile(&d.0);
            let reader_outcome = classify_for_test(
                &dir,
                TRAIL,
                path,
                prior.clone(),
                Reaction::Stop,
                cache.as_ref(),
            );

            let dir2 = dirfile(&d.0);
            let collect_outcome =
                classify_for_test(&dir2, TRAIL, path, prior, Reaction::Collect, cache.as_ref());

            match (reader_outcome, collect_outcome) {
                (Ok(r), Ok(c)) => {
                    // #197 ruling addendum 27.1: Ok-path full equality.
                    // Where the reader returns Ok, Collect's `final_state`
                    // (every field) and `found` must equal the reader's,
                    // with empty `violations` and `head_mismatch == false`.
                    if !c.violations.is_empty() || c.head_mismatch {
                        mismatches.push(format!(
                            "{}: reader Ok, Collect has violations {:?} or head_mismatch {}",
                            row.name, c.violations, c.head_mismatch
                        ));
                    }
                    let (want, got) = (ok_outcome(&r), ok_outcome(&c));
                    if want != got {
                        mismatches.push(format!(
                            "{}: reader Ok outcome differs from Collect Ok outcome\n  reader: {}\n  collect: {}",
                            row.name, want, got
                        ));
                    }
                }
                (Err(e), Ok(c)) => {
                    if e.kind() == AuditErrorKind::HeadMismatch {
                        if !c.head_mismatch {
                            mismatches.push(format!(
                                "{}: reader Err(HeadMismatch), Collect head_mismatch=false",
                                row.name
                            ));
                        }
                    } else if let Some((_, v)) = c.violations.first() {
                        let collect_err: AuditError = (*v).into();
                        if detail_of(&collect_err) != detail_of(&e) {
                            mismatches.push(format!(
                                "{}: reader detail {:?}, Collect first {:?}",
                                row.name,
                                detail_of(&e),
                                detail_of(&collect_err)
                            ));
                        }
                    } else {
                        mismatches.push(format!(
                            "{}: reader Err({:?}, {:?}), Collect no violation",
                            row.name,
                            e.kind(),
                            detail_of(&e)
                        ));
                    }
                }
                (Ok(_), Err(e)) => {
                    mismatches.push(format!("{}: reader Ok, Collect Err {e:?}", row.name));
                }
                (Err(er), Err(ec)) => {
                    if er.kind() != ec.kind() {
                        mismatches.push(format!(
                            "{}: reader Err kind {:?}, Collect Err kind {:?}",
                            row.name,
                            er.kind(),
                            ec.kind()
                        ));
                    }
                }
            }
        }
        assert!(
            mismatches.is_empty(),
            "first-equality sweep ({} rows) found mismatches: {mismatches:?}",
            layouts.len()
        );
        assert_eq!(
            layouts.len(),
            19,
            "sweep row count: expected 19 (every reader path with Ok and Err shapes, \
             damaged multi-segment layouts, expected-head-present on each LiveOpen \
             shape, duplicate-line layouts on live-open and open-fallback, and \
             expected on a sealed-prelude record for refresh rotate; #197 ruling \
             addendum 27.1 Ok-path full equality)",
        );
    }

    fn cache_for_path(c: Cache) -> Cache {
        c
    }
}
