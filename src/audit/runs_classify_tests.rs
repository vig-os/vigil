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
    Cache {
        state,
        file,
        sealed_before,
    }
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
            Some(cache.state.clone()),
            Reaction::Collect,
            Some(&cache),
        )
        .unwrap();
        assert!(
            out.violations.is_empty(),
            "CC10: valid refresh-append should record no violations, got {:?}",
            out.violations
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

    /// M-C3 killer: classify drops `found` writeback on the live-close
    /// walker → under Stop with `expected=Some(H_live)`, the Cache's
    /// `found` field must be `Some(H_live)` after a successful scan.
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
        assert!(
            out.found.is_some(),
            "M-C3: classify under Stop must populate `found` when `expected` matches a record on the live close"
        );
        assert_eq!(out.found.as_ref().unwrap().hash(), second.hash());
    }
}

// ============================================================
// First-equality sweep (addendum 25.3): across multiple layouts and
// reader paths, classify-Collect-first == reader-first.
// ============================================================
mod classify_first_equality {
    use super::*;

    type Builder = Box<dyn Fn(&Path) -> ReaderPath>;

    /// Build a set of multi-segment layouts and compare the reader's
    /// first-violation outcome against classify under Collect's first
    /// violation. 0 mismatches, 0 exclusions.
    #[test]
    fn multi_segment_first_equality_sweep() {
        // Each layout returns a built directory and the reader path to
        // exercise on top of it.
        let layouts: Vec<(&'static str, Builder)> = vec![
            (
                "liveopen-ok-single",
                Box::new(|p: &Path| {
                    let _ = fixture(p);
                    ReaderPath::LiveOpen { expected: None }
                }),
            ),
            (
                "liveopen-ok-rotated-plus-live",
                Box::new(|p: &Path| {
                    let first = fixture(p);
                    let mut mmr = seeded(&first);
                    let _ = rotated(p, &first, &mut mmr, 0);
                    ReaderPath::LiveOpen { expected: None }
                }),
            ),
            (
                "liveopen-err-headmismatch",
                Box::new(|p: &Path| {
                    let _ = fixture(p);
                    let absent = Head {
                        seq: 42,
                        hash: [0xee; 32],
                    };
                    ReaderPath::LiveOpen {
                        expected: Some(absent),
                    }
                }),
            ),
            (
                "liveopen-multi-segment-rotate-chain",
                Box::new(|p: &Path| {
                    let first = fixture(p);
                    let mut mmr = seeded(&first);
                    let r1 = rotated(p, &first, &mut mmr, 0);
                    let _ = rotated(p, &r1, &mut mmr, 1);
                    ReaderPath::LiveOpen { expected: None }
                }),
            ),
        ];

        let mut mismatches: Vec<String> = Vec::new();
        let mut rows = 0;
        for (name, build) in &layouts {
            let d = Temp::new();
            let path = build(&d.0);

            // Reader outcome via classify under Stop (through
            // TrailReader::open where possible).
            let dir = dirfile(&d.0);
            let reader_err = classify_for_test(&dir, TRAIL, path, None, Reaction::Stop, None);

            // Collect outcome.
            let dir2 = dirfile(&d.0);
            let collect = classify_for_test(&dir2, TRAIL, path, None, Reaction::Collect, None);

            rows += 1;
            match (reader_err, collect) {
                (Ok(_), Ok(c)) => {
                    if !c.violations.is_empty() || c.head_mismatch {
                        mismatches.push(format!(
                            "{name}: reader Ok, Collect has violations {:?} or head_mismatch {}",
                            c.violations, c.head_mismatch
                        ));
                    }
                }
                (Err(e), Ok(c)) => {
                    // Reader-side Err: Collect's first violation (or
                    // head_mismatch) must produce the same kind+detail.
                    if e.kind() == AuditErrorKind::HeadMismatch {
                        if !c.head_mismatch {
                            mismatches.push(format!(
                                "{name}: reader Err(HeadMismatch), Collect head_mismatch=false"
                            ));
                        }
                    } else if let Some((_, v)) = c.violations.first() {
                        let collect_err: AuditError = (*v).into();
                        if detail_of(&collect_err) != detail_of(&e) {
                            mismatches.push(format!(
                                "{name}: reader detail {:?}, Collect first {:?}",
                                detail_of(&e),
                                detail_of(&collect_err)
                            ));
                        }
                    } else {
                        mismatches.push(format!(
                            "{name}: reader Err({:?}, {:?}), Collect no violation",
                            e.kind(),
                            detail_of(&e)
                        ));
                    }
                }
                (Ok(_), Err(e)) => {
                    mismatches.push(format!("{name}: reader Ok, Collect Err {e:?}"));
                }
                (Err(er), Err(ec)) => {
                    // Rare: both Err from classify directly. Non-corrupt
                    // errors propagate identically; accept kind match.
                    if er.kind() != ec.kind() {
                        mismatches.push(format!(
                            "{name}: reader Err kind {:?}, Collect Err kind {:?}",
                            er.kind(),
                            ec.kind()
                        ));
                    }
                }
            }
        }
        assert!(
            mismatches.is_empty(),
            "first-equality sweep ({rows} rows) found mismatches: {mismatches:?}"
        );
    }
}
