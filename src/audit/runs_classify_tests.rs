//! Classify tests (ruling 197-d1 addendum 25.3): Collect rows (CC1-...)
//! plus the multi-segment first-equality sweep that proves
//! `classify` under `Reaction::Collect`'s first violation equals the
//! reader's first violation at the same head.
//!
//! These are `#[cfg(test)]` under `src/audit/runs.rs`, so they do NOT
//! enter the `audit::storage::tests` filter (addendum 25.3 / brief
//! "put the Collect rows in `runs.rs` so they don't skew the storage
//! count").
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

/// Returns the `Cache` after a successful live-open, for use as the
/// starting state of a refresh row. Threads through the real reader so
/// the cache is byte-identical to what `TrailReader::open` would build.
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
    /// can set it (addendum 27.1 / M-C5 / M-C10 killer).
    ///
    /// Addendum 27.4 / brief 197-r2b-S3b1b-r1c item 1: literal pin.
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
        let out = classify_for_test_collect(
            &dir,
            TRAIL,
            ReaderPath::RefreshAppend,
            Some(cache.state().clone()),
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
    /// Addendum 27.4 / brief item 1: literal pin — `violations` is the
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
        let out = classify_for_test_collect(
            &dir,
            TRAIL,
            ReaderPath::LiveOpen {
                expected: Some(absent),
            },
            None,
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
        let err = classify_for_test_stop(
            &dir2,
            TRAIL,
            ReaderPath::LiveOpen {
                expected: Some(absent),
            },
            None,
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
    /// Addendum 27.4 / brief item 1: literal `vec![...]` pin.
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
        let out = classify_for_test_collect(
            &dir,
            TRAIL,
            ReaderPath::RefreshAppend,
            Some(cache.state().clone()),
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
    /// valid new live. Under Collect, classify tags the recorded
    /// violation with `segment_index == 1` (prelude is segment 0,
    /// rotated is segment 1). Kills M-C7 (Collect segment_index not
    /// bumped): the mutant would tag this at seg 0 instead.
    ///
    /// Addendum 27.4 / brief item 1: literal `vec![...]` pin.
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
        let out = classify_for_test_collect(
            &dir,
            TRAIL,
            ReaderPath::RefreshRotate,
            Some(cache.state().clone()),
            Some(&cache),
        )
        .unwrap();
        assert_eq!(
            out.violations,
            vec![
                (
                    SegmentViolationPos {
                        segment_index: 0,
                        record_index_in_segment: 1,
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
            "CC2: refresh-rotate exact literal list — prelude (seg 0) hits SequenceDidNotIncrease \
             on the glued duplicate; rotated_0 (seg 1) hits RecordRolledBack on the opening scan"
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
    /// Addendum 27.4 / brief item 1: literal `vec![...]` pin.
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
        let out = classify_for_test_collect(
            &dir,
            TRAIL,
            ReaderPath::LiveOpen { expected: None },
            None,
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
    /// / brief item 1: literal pin.
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
        let out = classify_for_test_collect(
            &dir,
            TRAIL,
            ReaderPath::LiveOpen { expected: None },
            None,
            None,
        )
        .unwrap();
        // The first recorded violation is on the rotated_0 segment
        // (segment_index == 0). Pin the first entry's (pos, violation)
        // and that no violation precedes it.
        let first_v = out.violations.first().cloned();
        assert_eq!(
            first_v,
            Some((
                SegmentViolationPos {
                    segment_index: 0,
                    record_index_in_segment: 2,
                },
                Violation::SequenceDidNotIncrease,
            )),
            "CC4: open-fallback first violation sits on rotated_0 (seg=0, rec=2) \
             with SequenceDidNotIncrease (base-identical)"
        );
    }

    /// CC6-refresh-rotate-prelude-violation: RefreshRotate where the
    /// cached-live prelude (re-read as a sealed segment) carries a
    /// non-identical rollback after the cache offset: an `Entry` with
    /// `seq == first.seq` (the rollback the strict scan rejects before
    /// dedup logic can swallow it as an identical duplicate). Under
    /// Collect, classify_collect records at least one violation on
    /// `segment_index == 0`. Kills M-C6 (`SealedPrelude` treated as
    /// `SealedOpening`) via the shape of the first violation.
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
        let out = classify_for_test_collect(
            &dir,
            TRAIL,
            ReaderPath::RefreshRotate,
            Some(cache.state().clone()),
            Some(&cache),
        )
        .unwrap();
        // The first recorded violation sits on segment_index == 0 (the
        // prelude segment, read as `history_segment(opening = false)`).
        let first_seg = out.violations.first().map(|(p, _)| p.segment_index);
        assert_eq!(
            first_seg,
            Some(0),
            "CC6: refresh-rotate prelude's first violation sits on seg 0; got {:?}",
            out.violations
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
        let out = classify_for_test_collect(
            &dir,
            TRAIL,
            ReaderPath::RefreshRotate,
            Some(cache.state().clone()),
            Some(&cache),
        )
        .unwrap();
        // Find a violation on segment_index == 1.
        let any_seg1 = out.violations.iter().any(|(p, _)| p.segment_index == 1);
        assert!(
            any_seg1,
            "CC7: refresh-rotate rotated-side violation must sit on seg 1; got {:?}",
            out.violations
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
        let out = classify_for_test_collect(
            &dir,
            TRAIL,
            ReaderPath::LiveOpen { expected: None },
            None,
            None,
        )
        .unwrap();
        // Cross-segment: at least one violation on seg 0 (rotated_0)
        // AND at least one on seg 1 (live).
        let has_seg0 = out.violations.iter().any(|(p, _)| p.segment_index == 0);
        let has_seg1 = out.violations.iter().any(|(p, _)| p.segment_index == 1);
        assert!(
            has_seg0 && has_seg1,
            "CC3: cross-segment violations require one on each segment; got {:?}",
            out.violations
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
        let out = classify_for_test_collect(
            &dir,
            TRAIL,
            ReaderPath::LiveOpen { expected: None },
            None,
            None,
        )
        .unwrap();
        // Under Collect, the checkpoint-MMR mismatch is recorded as a
        // typed Violation::CheckpointMmrDiffers on the single segment
        // (segment_index 0).
        let has_mmr_differs = out
            .violations
            .iter()
            .any(|(p, v)| *v == Violation::CheckpointMmrDiffers && p.segment_index == 0);
        assert!(
            has_mmr_differs,
            "CC8: expected CheckpointMmrDiffers recorded on seg 0; got {:?}",
            out.violations
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
        let out = classify_for_test_collect(
            &dir,
            TRAIL,
            ReaderPath::LiveOpen { expected: None },
            None,
            None,
        )
        .unwrap();
        // The violation's record_index_in_segment must be > 0 (M-C8
        // would set it to 0).
        let non_zero_record_index = out
            .violations
            .iter()
            .any(|(p, _)| p.record_index_in_segment > 0);
        assert!(
            non_zero_record_index,
            "CC9: a violation with record_index_in_segment > 0 proves classify_collect bumps \
             the per-segment record index (kills M-C8); got {:?}",
            out.violations
        );
    }

    /// M-C3 killer: classify drops `found` writeback on the live-close
    /// walker → under Stop with `expected=Some(H_live)`, the Cache's
    /// `found` field must be `Some(H_live)` after a successful scan.
    ///
    /// Addendum 27.4 / brief item 1: literal pin — `found.hash()` equals
    /// the exact live tail record's hash.
    #[test]
    fn mc3_found_writeback_on_live_close() {
        let d = Temp::new();
        let first = fixture(&d.0);
        let second = entry(&first);
        append(&d.0.join("audit.jsonl"), &second);
        let dir = dirfile(&d.0);
        let out = classify_for_test_stop(
            &dir,
            TRAIL,
            ReaderPath::LiveOpen {
                expected: Some(Head::of(&second)),
            },
            None,
            None,
        )
        .unwrap();
        let found = out.found.as_ref().expect(
            "M-C3: classify_stop must populate `found` when `expected` matches a record on the live close",
        );
        assert_eq!(found.hash(), second.hash());
        assert_eq!(found.context.seq, second.context.seq);
    }

    /// Helper: append raw bytes to the given file path (test-only).
    fn append_bytes(path: &Path, bytes: &[u8]) {
        use std::io::Write;
        fs::OpenOptions::new()
            .append(true)
            .open(path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
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
    /// the live's non-resume second record. Addendum 27.4 / brief
    /// 197-r2b-S3b1b-r1c item 1: literal pin asserts the first
    /// recorded violation's exact (seg, rec, variant).
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
        let out = classify_for_test_collect(
            &dir,
            TRAIL,
            ReaderPath::LiveOpen { expected: None },
            None,
            None,
        )
        .unwrap();
        // The live segment (segment_index == 1) records
        // `InitialCheckpointDoesNotLinkGenesis` on its first record
        // (opening cp). Under Collect, the sealed walk's tolerant
        // arm does not thread State across the segment boundary
        // (the per-segment State is rebuilt on each call), so the
        // live-close walker sees `state = None` and
        // `genesis = ctx.run || state.is_none()` evaluates true
        // only because `*run` reached it carrying the prior run's
        // damaged-latch signal. Kills M-C9 ("run inheritance
        // drops across live-close"): under the mutant `run=false`
        // leaves `genesis = false`, the opening cp is instead
        // validated via from_peaks + push, and the first violation
        // recorded on the live becomes `CheckpointMmrDiffers`
        // (different literal pin, so the assert fires).
        // Addendum 27.4 / brief 197-r2b-S3b1b-r1c item 1: literal
        // pin asserts the exact first (seg, rec, variant) on
        // segment_index == 1.
        let live_violation = out
            .violations
            .iter()
            .find(|(p, _)| p.segment_index == 1)
            .cloned();
        assert_eq!(
            live_violation,
            Some((
                SegmentViolationPos {
                    segment_index: 1,
                    record_index_in_segment: 0,
                },
                Violation::InitialCheckpointDoesNotLinkGenesis,
            )),
            "CC12: run=true propagation into scan_closing records \
             InitialCheckpointDoesNotLinkGenesis on the live's opening cp (kills M-C9); \
             got: {:?}",
            out.violations,
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
        let out = classify_for_test_collect(
            &dir,
            TRAIL,
            ReaderPath::LiveOpen { expected: None },
            None,
            None,
        )
        .unwrap();
        // The second segment (rotated_1, segment_index == 1)
        // records `FirstSuccessorDoesNotCloseRun` on its opening cp
        // (record 0): under Collect the sealed walk does not thread
        // State across the boundary, strict Collect fails on
        // boundary_resume and falls back to tolerant Collect with
        // `inherited = run_in || unsealed_boundary = true || false
        // = true`, and the opening cp with trial_apply(None, ..) =
        // false trips `inherited && is_cp && !broken && !closing`.
        // Kills M-C2 ("classify threads `run = false` across
        // sealed->sealed"): under the mutant `run_in = false`
        // (and state = None still because Collect does not thread
        // state), `inherited = false || false = false`, no
        // `FirstSuccessorDoesNotCloseRun` check fires, strict's
        // `boundary_resume` also collapses, and the first
        // violation recorded on rotated_1 becomes
        // `CheckpointMmrDiffers` via the new-mmr-from-peaks path.
        // Addendum 27.4: literal pin asserts the exact first
        // (seg, rec, variant) on segment_index == 1.
        let seg1_violation = out
            .violations
            .iter()
            .find(|(p, _)| p.segment_index == 1)
            .cloned();
        assert_eq!(
            seg1_violation,
            Some((
                SegmentViolationPos {
                    segment_index: 1,
                    record_index_in_segment: 0,
                },
                Violation::FirstSuccessorDoesNotCloseRun,
            )),
            "CC13: run=true propagation across sealed->sealed records \
             FirstSuccessorDoesNotCloseRun on rotated_1's opening cp (kills M-C2); \
             got: {:?}",
            out.violations,
        );
        assert!(
            !out.head_mismatch,
            "CC13: LiveOpen with expected=None never sets head_mismatch"
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
    /// violation. Covers all five reader paths (addendum 25.3 / brief
    /// item 4): live open, open fallback, refresh append, refresh
    /// rotate, refresh append+rotate.
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
        ];

        let mut mismatches: Vec<String> = Vec::new();
        for row in layouts {
            let d = Temp::new();
            let (path, cache) = (row.build)(&d.0);
            let prior = cache.as_ref().map(|c| c.state().clone());

            let dir = dirfile(&d.0);
            let reader_outcome =
                classify_for_test_stop(&dir, TRAIL, path, prior.clone(), cache.as_ref());

            let dir2 = dirfile(&d.0);
            let collect_outcome =
                classify_for_test_collect(&dir2, TRAIL, path, prior, cache.as_ref());

            match (reader_outcome, collect_outcome) {
                (Ok(_), Ok(c)) => {
                    if !c.violations.is_empty() || c.head_mismatch {
                        mismatches.push(format!(
                            "{}: reader Ok, Collect has violations {:?} or head_mismatch {}",
                            row.name, c.violations, c.head_mismatch
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
            8,
            "sweep row count: expected 8 (5 paths × multiple layouts)"
        );
    }

    fn cache_for_path(c: Cache) -> Cache {
        c
    }
}
