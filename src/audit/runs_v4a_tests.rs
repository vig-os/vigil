//! V4a walk tests (ruling 197-d1 addendum 25.5 and 28): pin
//! `ClassifyOutput::segments` / `ClassifyOutput::runs` at this head.
//!
//! Each CV row builds a trail directory, (i) runs
//! `TrailReader::open` and records `Ok` or `Err(CorruptTrail: <detail>)`,
//! (ii) runs `classify` under `Reaction::Collect`, (iii) asserts the
//! full literal outcome.
//!
//! Row index:
//! - CV1-A1 / A3 / A8 / A9: the four digest subrows with literal
//!   captured `blake3:<hex>` constants.
//! - CV2 (p01..p13): reader-and-classify agreement sample.
//! - CV3 (p09, p10): digest-only (with and without spans).
//! - CV4: fold-(iii) mismatch records `CheckpointMmrDiffers`, runs empty.
//! - CV5: A1 run-structure detail pin (`first_segment`, `last_segment`,
//!   `closing_opening`, `loss_points`, `spans`).
//! - CV6: A8 empty-ranges digest.
//! - CV7: A9 span `seg` renumbering.
//! - CV8: non-increasing seq drops only this run.
//! - CV9: module doc lint (source-check via `include_str!`).
//! - CV11: reports built only under Collect.

use super::*;
use crate::audit::{
    AuditError, AuditErrorKind, CheckpointFields, Entry, KeyFileSigner, Mmr, Record, RecordContext,
    Signer, storage::TrailReader,
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
            "vigil-audit-v4a-{}-{}",
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
fn signed_cp(seq: u64, previous: [u8; 32], mmr: &Mmr) -> Record {
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
    let unsigned = Record::checkpoint(context(seq, previous), fields([0; 64])).unwrap();
    let signature = key.sign(&unsigned.signing_message().unwrap()).unwrap();
    Record::checkpoint(context(seq, previous), fields(signature)).unwrap()
}
fn entry_rec(seq: u64, previous: [u8; 32]) -> Record {
    Record::new(
        context(seq, previous),
        Entry::new("actor", "change", "object"),
    )
    .unwrap()
}
fn line_bytes(record: &Record) -> Vec<u8> {
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
fn write_bytes(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
}
fn append(path: &Path, bytes: &[u8]) {
    fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}
fn segment_path(dir: &Path, id: usize) -> PathBuf {
    dir.join(format!("audit-20260101T000000.000000000Z_{id:06}.jsonl"))
}
fn put_segment(dir: &Path, id: usize, records: &[&Record], suffix: &[u8]) {
    let mut bytes: Vec<u8> = records.iter().flat_map(|r| line_bytes(r)).collect();
    bytes.extend(suffix);
    fs::write(segment_path(dir, id), bytes).unwrap();
}
fn write_records(dir: &Path, records: &[&Record]) {
    let bytes: Vec<u8> = records.iter().flat_map(|r| line_bytes(r)).collect();
    write_bytes(&dir.join("audit.jsonl"), &bytes);
}
fn append_record(dir: &Path, record: &Record) {
    append(&dir.join("audit.jsonl"), &line_bytes(record));
}
fn dirfile(path: &Path) -> fs::File {
    fs::File::open(path).unwrap()
}
fn seeded(record: &Record) -> Mmr {
    let mut mmr = Mmr::new();
    mmr.push(record.hash()).unwrap();
    mmr
}
fn pushed(mmr: &Mmr, record: &Record) -> Mmr {
    let mut m = mmr.clone();
    m.push(record.hash()).unwrap();
    m
}

/// A "headless" record simulating a broken boundary after `last`: the
/// previous-hash is the hash of the hypothetical `entry(last.seq+1,
/// last.hash)` record that would have followed `last` on an honest
/// trail, so this record's `previous` matches no record actually
/// present on this trail. Matches `storage_tests::runs::headless`.
fn headless(last: &Record, seq: u64) -> Record {
    let ghost = entry_rec(last.context.seq + 1, last.hash());
    entry_rec(seq, ghost.hash())
}

/// Build a resume declaration record for the gap between `previous` and `checkpoint`.
/// Uses `Record::new_internal` to bypass the reserved-prefix check, as
/// the storage tests' own `declaration` helper does.
fn resume_decl(
    checkpoint: &Record,
    head_seq: u64,
    head_hash: [u8; 32],
    lost_through: u64,
) -> Record {
    let ctx = context(checkpoint.context.seq + 1, checkpoint.hash());
    Record::new_internal(
        ctx,
        Entry::new("operator", "vigil.audit.resume", "trail")
            .reason("incident")
            .details(format!(
                "head={head_seq}:{hex} lost_through={lost_through} file=-",
                hex = crate::audit::digest_string(&head_hash)
            )),
    )
    .unwrap()
}

// ============================================================
// A1 fixture (one-range run)
// Layout:
//   S0 = [cp0, e1, e2] (sealed)
//   S1 = [e4(prev=e2.hash), cp5(prev=e4.hash)] (headless, closes earlier)
//   live = [cp6(prev=cp5.hash, size matching fold), resume7(head=5:cp5, lost_through=5)]
// ============================================================
struct A1 {
    _dir: Temp,
    dir_path: PathBuf,
    /// The closer's opening checkpoint (cp6) — for CV5.
    cp6_head: Head,
}

fn build_a1() -> A1 {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    // Sealed S0:
    put_segment(&d.0, 0, &[&cp0, &e1, &e2], &[]);
    // S1 headless: broken-boundary entry at seq=4 (prev points to
    // the hypothetical lost record at seq=3). The reader's tolerant
    // fallback treats this as a run boundary.
    let r4 = headless(&e2, 4);
    // Honest fold for cp5 includes S0 fully (cp0, e1, e2) + r4.
    let fold = pushed(&mmr2, &r4);
    let cp5 = signed_cp(5, r4.hash(), &fold);
    put_segment(&d.0, 1, &[&r4, &cp5], &[]);
    // live: cp6 (closer opening) + resume7
    let fold6 = pushed(&fold, &cp5);
    let cp6 = signed_cp(6, cp5.hash(), &fold6);
    let resume = resume_decl(&cp6, 5, cp5.hash(), 5);
    write_records(&d.0, &[&cp6, &resume]);
    let cp6_head = Head::of(&cp6);
    A1 {
        dir_path: d.0.clone(),
        _dir: d,
        cp6_head,
    }
}

// ============================================================
// A8 fixture (closed run, zero records — empty S1)
//   S0 = [cp0], S1 = [] (empty), live = [cp_opening(seq=1, prev=cp0), resume]
// ============================================================
struct A8 {
    _dir: Temp,
    dir_path: PathBuf,
}

fn build_a8() -> A8 {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    put_segment(&d.0, 0, &[&cp0], &[]);
    // S1 empty:
    put_segment(&d.0, 1, &[], &[]);
    // live:
    let fold = seeded(&cp0);
    let cp_opening = signed_cp(1, cp0.hash(), &fold);
    let resume = resume_decl(&cp_opening, 0, cp0.hash(), 0);
    write_records(&d.0, &[&cp_opening, &resume]);
    A8 {
        dir_path: d.0.clone(),
        _dir: d,
    }
}

// ============================================================
// A9 fixture (multi-segment record-free)
//   S0 = [cp0], S1 = b"not json\n", S2 = b"also not json\n"
//   live = [cp_opening(seq=1, prev=cp0), resume]
// ============================================================
struct A9 {
    _dir: Temp,
    dir_path: PathBuf,
}

fn build_a9() -> A9 {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    put_segment(&d.0, 0, &[&cp0], &[]);
    put_segment(&d.0, 1, &[], b"not json\n");
    put_segment(&d.0, 2, &[], b"also not json\n");
    let fold = seeded(&cp0);
    let cp_opening = signed_cp(1, cp0.hash(), &fold);
    let resume = resume_decl(&cp_opening, 0, cp0.hash(), 0);
    write_records(&d.0, &[&cp_opening, &resume]);
    A9 {
        dir_path: d.0.clone(),
        _dir: d,
    }
}

// ============================================================
// A3 fixture (two headless segments two-range)
//   S0=[cp0, e1, cp2], S1=[e4(prev=cp2.hash), cp5], S2=[e7, cp8]
//   live=[cp10(prev=cp8.hash), resume11(head=8, lost_through=9)]
// ============================================================
struct A3 {
    _dir: Temp,
    dir_path: PathBuf,
}

fn build_a3() -> A3 {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let mmr2 = pushed(&mmr1, &cp2);
    let r4 = headless(&cp2, 4);
    let mmr4 = pushed(&mmr2, &r4);
    let cp5 = signed_cp(5, r4.hash(), &mmr4);
    put_segment(&d.0, 1, &[&r4, &cp5], &[]);
    let mmr5 = pushed(&mmr4, &cp5);
    let r7 = headless(&cp5, 7);
    let mmr7 = pushed(&mmr5, &r7);
    let cp8 = signed_cp(8, r7.hash(), &mmr7);
    put_segment(&d.0, 2, &[&r7, &cp8], &[]);
    let mmr8 = pushed(&mmr7, &cp8);
    let cp10 = signed_cp(10, cp8.hash(), &mmr8);
    let resume = resume_decl(&cp10, 8, cp8.hash(), 9);
    write_records(&d.0, &[&cp10, &resume]);
    A3 {
        dir_path: d.0.clone(),
        _dir: d,
    }
}

// ============================================================
// Common helpers
// ============================================================

fn classify_collect(path: &Path) -> super::ClassifyOutput {
    let dir = dirfile(path);
    super::classify_for_test(
        &dir,
        TRAIL,
        super::ReaderPath::LiveOpen { expected: None },
        None,
        super::Reaction::Collect,
        None,
    )
    .unwrap()
}

fn classify_stop(path: &Path) -> super::ClassifyOutput {
    let dir = dirfile(path);
    super::classify_for_test(
        &dir,
        TRAIL,
        super::ReaderPath::LiveOpen { expected: None },
        None,
        super::Reaction::Stop,
        None,
    )
    .unwrap()
}

fn digest_hex(digest: &[u8; 32]) -> String {
    crate::audit::digest_string(digest)
}

/// Pin the reader's exact `CorruptTrail` detail for a rejected trail
/// (ruling 197-d1 addendum 27.4: literal reader-detail pins at base
/// `ba7ef3e` for p06, p07, p12, p13a, p13b).
fn assert_reader_corrupt(dir: &Path, expected_detail: &str, label: &str) {
    let err: AuditError = TrailReader::open(dir, TRAIL, None)
        .err()
        .unwrap_or_else(|| panic!("{label}: expected Err(CorruptTrail), got Ok"));
    assert_eq!(
        err.kind(),
        AuditErrorKind::CorruptTrail,
        "{label}: wrong kind: {err}",
    );
    let got = format!("{err}")
        .strip_prefix("CorruptTrail: ")
        .map(ToString::to_string)
        .unwrap_or_default();
    assert_eq!(
        got, expected_detail,
        "{label}: reader detail mismatch at base ba7ef3e",
    );
}

// Captured at head on this slice (re-computed on every build by the
// CV1 rows; committed here as a literal per ruling 197-d1 addendum
// 27.4 so a drift in `run_digest`, span `seg` renumbering or
// loss-point arithmetic flips the pin).
const A1_DIGEST: &str = "blake3:79d8cb1c4dfc89a80a4911120280e63ed383108f3199f05291bcb51f625f3931";
const A3_DIGEST: &str = "blake3:78d5088883d54faa6aefe350948c217bb5ef3c32a468f22184bc07e56d84c63d";
const A8_DIGEST: &str = "blake3:1c02f080d9c70df74de0c13a4a30323f1b49ee624bab2c5d68fa5ee31c4400e4";
const A9_DIGEST: &str = "blake3:4905b9e63aa3fd9248f5c3605fe4beaf4af5a956f3f108b6dcecdbfbfda54026";

// ============================================================
// CV1: digest pins for A1 / A3 / A8 / A9 (captured at head).
// ============================================================

/// CV1-A1: one-range run under Collect. Reader returns `Ok`.
/// Loss point `(loss_seq=4, first=3, count=1)`, no spans.
#[test]
fn cv1_a1_digest_one_range() {
    let a = build_a1();
    // Reader is Ok.
    TrailReader::open(&a.dir_path, TRAIL, None).unwrap();
    let out = classify_collect(&a.dir_path);
    assert!(
        out.violations.is_empty(),
        "CV1-A1: Collect records no violations, got {:?}",
        out.violations
    );
    assert_eq!(
        out.runs.len(),
        1,
        "CV1-A1: one closed run expected (headless S1 closed by live)"
    );
    let rr = &out.runs[0];
    assert_eq!(rr.first_segment, 1);
    assert_eq!(rr.last_segment, 2);
    assert_eq!(rr.closing_opening, Some(a.cp6_head));
    assert_eq!(
        rr.loss_points,
        vec![super::LossPoint {
            loss_seq: 4,
            first: 3,
            count: 1,
        }],
        "CV1-A1: one loss point at (4, first=3, count=1)",
    );
    assert!(rr.spans.is_empty(), "CV1-A1: no spans");
    let ranges: Vec<(u64, u64)> = rr
        .loss_points
        .iter()
        .map(|lp| (lp.first, lp.count))
        .collect();
    let digest = crate::audit::verify::lines::run_digest(&ranges, &rr.spans);
    let got_hex = digest_hex(&digest);
    assert_eq!(got_hex, A1_DIGEST, "CV1-A1: captured digest pin");
}

/// CV1-A3: two-range two-headless run under Collect.
#[test]
fn cv1_a3_digest_two_ranges() {
    let a = build_a3();
    TrailReader::open(&a.dir_path, TRAIL, None).unwrap();
    let out = classify_collect(&a.dir_path);
    assert!(out.violations.is_empty(), "CV1-A3: no violations");
    assert_eq!(out.runs.len(), 1, "CV1-A3: one closed run");
    let rr = &out.runs[0];
    assert_eq!(
        rr.loss_points,
        vec![
            super::LossPoint {
                loss_seq: 4,
                first: 3,
                count: 1
            },
            super::LossPoint {
                loss_seq: 7,
                first: 6,
                count: 1
            },
        ],
        "CV1-A3: two loss points"
    );
    let ranges: Vec<(u64, u64)> = rr
        .loss_points
        .iter()
        .map(|lp| (lp.first, lp.count))
        .collect();
    let digest = crate::audit::verify::lines::run_digest(&ranges, &rr.spans);
    let got_hex = digest_hex(&digest);
    assert_eq!(got_hex, A3_DIGEST, "CV1-A3: captured digest pin");
}

/// CV1-A8: closed run with zero records (empty S1). Digest is the
/// empty-ranges, zero-spans digest.
#[test]
fn cv1_a8_digest_empty_ranges() {
    let a = build_a8();
    TrailReader::open(&a.dir_path, TRAIL, None).unwrap();
    let out = classify_collect(&a.dir_path);
    assert!(out.violations.is_empty(), "CV1-A8: no violations");
    assert_eq!(out.runs.len(), 1, "CV1-A8: one closed run");
    let rr = &out.runs[0];
    assert!(rr.loss_points.is_empty(), "CV1-A8: no loss points");
    assert!(rr.spans.is_empty(), "CV1-A8: no spans (S1 is empty)");
    let digest = crate::audit::verify::lines::run_digest(&[], &rr.spans);
    let got_hex = digest_hex(&digest);
    assert_eq!(
        got_hex, A8_DIGEST,
        "CV1-A8: captured digest pin (empty ranges, zero spans)"
    );
}

/// CV1-A9: multi-segment record-free. Two spans both with
/// `after == u64::MAX`, `seg == 0, 1` run-locally.
#[test]
fn cv1_a9_digest_multi_segment_record_free() {
    let a = build_a9();
    TrailReader::open(&a.dir_path, TRAIL, None).unwrap();
    let out = classify_collect(&a.dir_path);
    assert!(out.violations.is_empty(), "CV1-A9: no violations");
    assert_eq!(out.runs.len(), 1, "CV1-A9: one closed run");
    let rr = &out.runs[0];
    assert!(rr.loss_points.is_empty(), "CV1-A9: no loss points");
    assert_eq!(
        rr.spans.len(),
        2,
        "CV1-A9: two spans (one per record-free segment)"
    );
    assert_eq!(
        rr.spans[0].seg, 0,
        "CV1-A9: first span seg == 0 (run-local)"
    );
    assert_eq!(
        rr.spans[0].after,
        u64::MAX,
        "CV1-A9: first span after == u64::MAX"
    );
    assert_eq!(
        rr.spans[1].seg, 1,
        "CV1-A9: second span seg == 1 (run-local)"
    );
    assert_eq!(
        rr.spans[1].after,
        u64::MAX,
        "CV1-A9: second span after == u64::MAX"
    );
    let digest = crate::audit::verify::lines::run_digest(&[], &rr.spans);
    let got_hex = digest_hex(&digest);
    assert_eq!(got_hex, A9_DIGEST, "CV1-A9: captured digest pin");
}

// ============================================================
// CV4: fold-(iii) mismatch: `[cp0, e1, bad_cp2, e3, cp4]` layout
// Collect records exactly [(..., CheckpointMmrDiffers)] with bad
// checkpoint's segment marked damage == true. `out.runs` is EMPTY.
// ============================================================

#[test]
fn cv4_fold_iii_mismatch_records_and_runs_empty() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    // bad_cp2 claims the wrong fold: build from an MMR that does NOT include e1.
    let wrong_fold = seeded(&cp0);
    let bad_cp2 = signed_cp(2, e1.hash(), &wrong_fold);
    let e3 = entry_rec(3, bad_cp2.hash());
    // cp4 has to match the fold if the bad_cp2 were honest.
    // All records in one live file.
    write_records(&d.0, &[&cp0, &e1, &bad_cp2, &e3]);
    // Need to add cp4. Compute honest fold assuming bad_cp2 was accepted "as if matched":
    let mut fold = seeded(&cp0);
    fold.push(e1.hash()).unwrap();
    fold.push(bad_cp2.hash()).unwrap();
    fold.push(e3.hash()).unwrap();
    let cp4 = signed_cp(4, e3.hash(), &fold);
    append_record(&d.0, &cp4);
    let dir = dirfile(&d.0);
    let out = super::classify_for_test(
        &dir,
        TRAIL,
        super::ReaderPath::LiveOpen { expected: None },
        None,
        super::Reaction::Collect,
        None,
    )
    .unwrap();
    // Exactly one CheckpointMmrDiffers violation; runs is empty.
    assert_eq!(
        out.violations.len(),
        1,
        "CV4: one CheckpointMmrDiffers violation expected, got {:?}",
        out.violations
    );
    assert_eq!(
        out.violations[0].1,
        super::Violation::CheckpointMmrDiffers,
        "CV4: the one violation must be CheckpointMmrDiffers"
    );
    assert!(
        out.runs.is_empty(),
        "CV4: addendum 28 point 2: runs empty when violations non-empty (got {} runs)",
        out.runs.len()
    );
    // CV4 damage flag: the bad checkpoint's segment is marked damaged.
    let vp = out.violations[0].0;
    assert!(
        out.segments[vp.segment_index].damage,
        "CV4: bad checkpoint's segment has damage == true (seg {})",
        vp.segment_index
    );
}

// ============================================================
// CV4b (per C5 M-D4 second killer, also M-D9): a two-segment
// fold-(iii) mismatch row with a (i)+(ii) closer in live. Pins
// both the recorded CheckpointMmrDiffers and `runs.is_empty()`
// under addendum 28.2.
// ============================================================

#[test]
fn cv4b_fold_iii_mismatch_two_segment_layout() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    // bad_cp2 claims a wrong fold (empty MMR, not seeded with cp0+e1).
    let wrong_fold = seeded(&cp0);
    let bad_cp2 = signed_cp(2, e1.hash(), &wrong_fold);
    let e3 = entry_rec(3, bad_cp2.hash());
    put_segment(&d.0, 0, &[&cp0, &e1, &bad_cp2, &e3], &[]);
    // Live is a (i)+(ii) closer opening a next run (opening_cp links
    // e3.hash, immediate resume). Under addendum 28.2 the recorded
    // CheckpointMmrDiffers suppresses the run; a mutant that keeps
    // `runs` populated flips that pin.
    let mut fold_through = seeded(&cp0);
    fold_through.push(e1.hash()).unwrap();
    fold_through.push(bad_cp2.hash()).unwrap();
    fold_through.push(e3.hash()).unwrap();
    let cp_opening = signed_cp(4, e3.hash(), &fold_through);
    let resume = resume_decl(&cp_opening, e3.context.seq, e3.hash(), 3);
    write_records(&d.0, &[&cp_opening, &resume]);
    let dir = dirfile(&d.0);
    let out = super::classify_for_test(
        &dir,
        TRAIL,
        super::ReaderPath::LiveOpen { expected: None },
        None,
        super::Reaction::Collect,
        None,
    )
    .unwrap();
    let diffs = out
        .violations
        .iter()
        .filter(|(_, v)| matches!(v, super::Violation::CheckpointMmrDiffers))
        .count();
    assert!(
        diffs >= 1,
        "CV4b: at least one CheckpointMmrDiffers across the layout (got {:?})",
        out.violations,
    );
    assert!(out.runs.is_empty(), "CV4b: runs empty (addendum 28.2)");
}

// ============================================================
// CV4c (per C5 M-D9 second killer): fold-(iii) mismatch in a sealed
// segment with a live closer that would otherwise form a (i)+(ii)
// run. Addendum 28.2: `violations` non-empty keeps `runs` empty
// even though a `RunReport` would group the segments. A mutant that
// drops the `suppress_runs` guard on violations flips the pin.
// ============================================================

#[test]
fn cv4c_fold_iii_with_closer_suppress_runs() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let e1 = entry_rec(1, cp0.hash());
    let wrong_fold = seeded(&cp0);
    let bad_cp2 = signed_cp(2, e1.hash(), &wrong_fold);
    put_segment(&d.0, 0, &[&cp0, &e1, &bad_cp2], &[]);
    // Live: a (i)+(ii) closer after bad_cp2 (opening links bad_cp2's
    // hash, immediate resume). Under suppress_runs=true this yields
    // no run report; dropping the guard would emit a RunReport.
    let mut fold_through = seeded(&cp0);
    fold_through.push(e1.hash()).unwrap();
    fold_through.push(bad_cp2.hash()).unwrap();
    let cp_opening = signed_cp(3, bad_cp2.hash(), &fold_through);
    let resume = resume_decl(&cp_opening, bad_cp2.context.seq, bad_cp2.hash(), 2);
    write_records(&d.0, &[&cp_opening, &resume]);
    let dir = dirfile(&d.0);
    let out = super::classify_for_test(
        &dir,
        TRAIL,
        super::ReaderPath::LiveOpen { expected: None },
        None,
        super::Reaction::Collect,
        None,
    )
    .unwrap();
    assert!(
        !out.violations.is_empty(),
        "CV4c: fold-(iii) violation expected"
    );
    assert!(
        out.runs.is_empty(),
        "CV4c (addendum 28.2): runs empty when violations non-empty, even with a (i)+(ii) closer",
    );
}

// ============================================================
// CV8: non-increasing seq at a would-be loss point -- the reader
// rejects with `record sequence did not increase`; classify records
// the violation and runs is empty.
// ============================================================

#[test]
fn cv8_non_increasing_seq_drops_only_this_run() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let _mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    put_segment(&d.0, 0, &[&cp0, &e1, &e2], &[]);
    // S1 headless with non-increasing seq relative to prev's seq=2.
    // We want r.seq <= prev.seq. Use seq=1 (< 2).
    let bad = entry_rec(1, e2.hash());
    // cp closer (honest fold of actually-present records: cp0, e1, e2, bad)
    let mut fold = seeded(&cp0);
    fold.push(e1.hash()).unwrap();
    fold.push(e2.hash()).unwrap();
    fold.push(bad.hash()).unwrap();
    let cp_close = signed_cp(5, bad.hash(), &fold);
    put_segment(&d.0, 1, &[&bad, &cp_close], &[]);
    let fold6 = pushed(&fold, &cp_close);
    let cp_opening = signed_cp(6, cp_close.hash(), &fold6);
    let resume = resume_decl(&cp_opening, 5, cp_close.hash(), 5);
    write_records(&d.0, &[&cp_opening, &resume]);
    let dir = dirfile(&d.0);
    // Should not panic (never panics on a crafted trail, per d3 point 2).
    let out = super::classify_for_test(
        &dir,
        TRAIL,
        super::ReaderPath::LiveOpen { expected: None },
        None,
        super::Reaction::Collect,
        None,
    )
    .unwrap();
    // Violation is recorded (the reader would reject); runs is empty.
    assert!(
        !out.violations.is_empty(),
        "CV8: at least one violation expected"
    );
    assert!(
        out.runs.is_empty(),
        "CV8: runs empty when a violation records (addendum 28 point 2)"
    );
}

// ============================================================
// CV9 (per C3): source-check the module doc for banned history/round
// wording. No git subprocess, no env skip.
// ============================================================

#[test]
fn cv9_module_doc_has_no_history_wording() {
    let source = include_str!("runs.rs");
    // The forbidden substrings; a plain substring check is sufficient
    // (C3 allows that) and avoids a new dev-dependency.
    let banned: &[&str] = &[
        "today",
        "former",
        "no longer",
        "until that",
        "R2b S0",
        "R2b S1",
        "R2b S2",
        "R2b S3",
        "R2b S4",
        "R2b S5",
        "R2b S6",
        "R2b S7",
        "R2b S8",
        "R2b S9",
        "R2b1",
        "R2b2",
    ];
    let mut bad_lines: Vec<(usize, String, &str)> = Vec::new();
    for (lineno, line) in source.lines().enumerate() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("//!") {
            continue;
        }
        for &pat in banned {
            if trimmed.contains(pat) {
                bad_lines.push((lineno + 1, trimmed.to_string(), pat));
            }
        }
    }
    assert!(
        bad_lines.is_empty(),
        "CV9: module doc contains banned history/round wording: {:?}",
        bad_lines
    );
}

// ============================================================
// CV11 (per C1 / addendum 28 point 1): reports built only under
// Collect. Under Stop, both `segments` and `runs` stay empty.
// A1 and A3 under Stop give empty `segments` and `runs`.
// ============================================================

#[test]
fn cv11_classify_stop_builds_no_reports_a1() {
    let a = build_a1();
    TrailReader::open(&a.dir_path, TRAIL, None).unwrap();
    let out = classify_stop(&a.dir_path);
    assert!(
        out.segments.is_empty(),
        "CV11-A1: segments empty under Stop (addendum 28 point 1), got {} entries",
        out.segments.len()
    );
    assert!(
        out.runs.is_empty(),
        "CV11-A1: runs empty under Stop (addendum 28 point 1), got {} entries",
        out.runs.len()
    );
}

#[test]
fn cv11_classify_stop_builds_no_reports_a3() {
    let a = build_a3();
    TrailReader::open(&a.dir_path, TRAIL, None).unwrap();
    let out = classify_stop(&a.dir_path);
    assert!(
        out.segments.is_empty(),
        "CV11-A3: segments empty under Stop"
    );
    assert!(out.runs.is_empty(), "CV11-A3: runs empty under Stop");
}

// ============================================================
// CV5: A1 detail-level structure pin.
// ============================================================

#[test]
fn cv5_a1_run_structure_pin() {
    let a = build_a1();
    TrailReader::open(&a.dir_path, TRAIL, None).unwrap();
    let out = classify_collect(&a.dir_path);
    assert_eq!(out.runs.len(), 1);
    let rr = &out.runs[0];
    assert_eq!(rr.first_segment, 1, "CV5: A1 first_segment == 1");
    assert_eq!(rr.last_segment, 2, "CV5: A1 last_segment == 2");
    assert_eq!(
        rr.closing_opening,
        Some(a.cp6_head),
        "CV5: closing_opening == Head::of(&cp6)"
    );
    assert_eq!(
        rr.loss_points,
        vec![super::LossPoint {
            loss_seq: 4,
            first: 3,
            count: 1
        }],
        "CV5: A1 loss points"
    );
    assert!(rr.spans.is_empty(), "CV5: A1 spans empty");
}

// ============================================================
// CV6: A8's empty-ranges digest matches `run_digest(&[], &out.runs[0].spans)`.
// ============================================================

#[test]
fn cv6_a8_empty_ranges_digest_matches() {
    let a = build_a8();
    let _ = a; // reader validated below
    let a = build_a8();
    let out = classify_collect(&a.dir_path);
    assert_eq!(out.runs.len(), 1);
    let rr = &out.runs[0];
    let got = crate::audit::verify::lines::run_digest(&[], &rr.spans);
    // Compute reference inline: no ranges, no spans.
    let expected = crate::audit::verify::lines::run_digest(&[], &[]);
    assert_eq!(
        got, expected,
        "CV6: A8 digest equals empty-ranges-zero-spans digest"
    );
}

// ============================================================
// CV7: A9 span `seg` is run-local (0, 1), not segment-global.
// ============================================================

#[test]
fn cv7_a9_span_seg_renumbered_run_local() {
    let a = build_a9();
    let out = classify_collect(&a.dir_path);
    assert_eq!(out.runs.len(), 1);
    let rr = &out.runs[0];
    let segs: Vec<u32> = rr.spans.iter().map(|s| s.seg).collect();
    assert_eq!(
        segs,
        vec![0, 1],
        "CV7: A9 spans seg renumbered to 0, 1 (run-local)"
    );
}

// ============================================================
// CV2 (subset): the `cv2_sample_*` row covers A8 / p09 equivalence.
// The full `cv2_p01..cv2_p13` table lives below, constructed via
// the widened `storage::tests::runs` helpers (addendum 27.4).
// ============================================================

/// CV0 (addendum 25.5): every field the slice adds is READ and
/// ASSERTED at this head, so a drop or rewrite of a field cannot
/// leave this row green with nothing compared.
#[test]
fn cv0_every_field_is_read_here() {
    let a = build_a1();
    let out = classify_collect(&a.dir_path);
    assert_eq!(out.runs.len(), 1, "CV0: A1 has one closed run");
    let rr = &out.runs[0];
    // RunReport fields: assert concrete values for A1.
    assert_eq!(rr.first_segment, 1, "CV0: A1 run first_segment == 1");
    assert_eq!(rr.last_segment, 2, "CV0: A1 run last_segment == 2");
    assert_eq!(
        rr.closing_opening,
        Some(a.cp6_head),
        "CV0: A1 closing_opening == Head::of(&cp6)",
    );
    assert_eq!(
        rr.loss_points,
        vec![super::LossPoint {
            loss_seq: 4,
            first: 3,
            count: 1,
        }],
        "CV0: A1 loss_points literal",
    );
    assert!(rr.spans.is_empty(), "CV0: A1 spans empty");
    assert!(
        !out.segments.is_empty(),
        "CV0: A1 segments populated under Collect",
    );
    // SegmentReport fields: assert concrete expectations for A1.
    // A1 layout: S0=Base, S1=InRun, live=Closer.
    assert_eq!(out.segments.len(), 3, "CV0: A1 three segments");
    assert_eq!(
        out.segments[0].class,
        super::SegmentClass::Base,
        "CV0: A1 S0 class == Base",
    );
    assert_eq!(out.segments[0].run_membership, None);
    assert!(!out.segments[0].damage);
    assert!(!out.segments[0].boundary_resume);
    assert!(out.segments[0].final_state.is_some());
    assert_eq!(
        out.segments[1].class,
        super::SegmentClass::InRun,
        "CV0: A1 S1 class == InRun",
    );
    assert_eq!(out.segments[1].run_membership, Some(0));
    assert!(!out.segments[1].damage);
    assert_eq!(
        out.segments[2].class,
        super::SegmentClass::Closer,
        "CV0: A1 live class == Closer",
    );
    assert_eq!(out.segments[2].run_membership, Some(0));
    assert!(!out.segments[2].damage);
    // Count `boundary_resume=true` across A1's segments. Exactly ONE
    // segment latches it: the walker's own `boundary_resume` derived
    // from `role_opening && !storage::sealed(prior)`. A1 has:
    //   S0: prior=None  -> sealed-equivalent -> false
    //   S1: prior=cp0   -> sealed            -> false
    //   S2: prior=S1    -> unsealed (headless r4 forced pending_resume
    //                       on the tolerant walk's state)
    // -> count = 1. O2 kill rows (inverted sealed check) flip this.
    let br_true = out.segments.iter().filter(|s| s.boundary_resume).count();
    assert_eq!(
        br_true, 1,
        "CV0: A1 exactly one segment latches boundary_resume"
    );
    // Pin all three values are read (not just the sum) by binding
    // each field.
    let br_values: Vec<bool> = out.segments.iter().map(|s| s.boundary_resume).collect();
    assert_eq!(br_values.len(), 3, "CV0: A1 three boundary_resume reads");
    // LossPoint fields: destructure (assert loses would already fail above).
    for lp in &rr.loss_points {
        assert_eq!(lp.loss_seq, 4);
        assert_eq!(lp.first, 3);
        assert_eq!(lp.count, 1);
    }
}

#[test]
fn cv2_sample_p09_empty_segment_closed_run_equals_a8() {
    // p09 is isomorphic to A8: closed run with an empty S1.
    let a = build_a8();
    TrailReader::open(&a.dir_path, TRAIL, None).unwrap();
    let out = classify_collect(&a.dir_path);
    assert!(out.violations.is_empty());
    assert_eq!(out.runs.len(), 1, "p09 == A8: one closed run");
}

// ============================================================
// CV2: full p01..p13 agreement rows (ruling 13-V4-d3, 13-v4a.md §A6).
// Each row builds its directory via `storage_tests::runs` helpers
// (widened to `pub(crate)` for this slice), then (i) records
// `TrailReader::open`'s outcome, (ii) runs `classify` under
// `Reaction::Collect`, (iii) asserts the literal `out.runs` /
// `run_membership` for the layout. Addendum 28 point 2: a rejected
// trail gives `out.runs` empty.
// ============================================================

use crate::audit::storage::tests::{self as st, runs as st_runs};

fn membership(out: &super::ClassifyOutput) -> Vec<Option<usize>> {
    out.segments.iter().map(|s| s.run_membership).collect()
}

fn run_bounds(out: &super::ClassifyOutput) -> Vec<(usize, usize)> {
    out.runs
        .iter()
        .map(|r| (r.first_segment, r.last_segment))
        .collect()
}

/// p01 — closing segment starts second run.
/// Builds the `closing_segment_can_start_second_run` layout:
/// sealed `S0=[cp0]`, sealed `S1=[kept]` (headless), sealed
/// `S2=[close1, resume1, "broken\n"]`, live=`[close2, resume2]`.
/// Reader: `Ok`.
///
/// Ruling 197-d1 addendum 28 (B1): grouping uses the
/// walker's own closer signal, so S2 is both the Closer of run 0
/// (its `close1+resume1` pair closes the run opened by S1) AND
/// the first segment of run 1 (its trailing `"broken\n"` fragment
/// reopens a run that the live closer in S3 closes). Run 0's
/// `closing_opening` = the closer's opening checkpoint (seq 7, the
/// `close1` written by `close_run(kept)`, which uses `last.seq + 4
/// = 3 + 4 = 7`).
#[test]
fn cv2_p01_closing_segment_can_start_second_run() {
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
    TrailReader::open(&d.0, TRAIL, None).expect("p01: reader Ok");
    let out = classify_collect(&d.0);
    assert!(out.violations.is_empty(), "p01: no violations");
    // Two closed runs: S1..=S2 (closes kept's headless run) and
    // S2..=live (closes the run reopened by the "broken" tail).
    assert_eq!(
        run_bounds(&out),
        vec![(1, 2), (2, 3)],
        "p01: two closed runs ([1..=2] closed by S2, [2..=3] closed by live)",
    );
    // `closing_opening` of run 0 is the opening checkpoint of its
    // closer segment: S2's first record is `checkpoint` (seq 7).
    assert_eq!(
        out.runs[0].closing_opening.map(|h| h.seq),
        Some(7),
        "p01 run 0: closing_opening seq == 7 (close1 in S2)",
    );
}

/// R-honest-mid (ruling 197-d1 addendum 28): an honest segment
/// between the base and the run's start is NOT a run member.
/// Layout: `S0=[cp0]`, sealed `S1=[signed(1, cp0.hash)]`
/// (honest checkpoint-only middle), sealed `S2=[headless(cp1, 6)]`
/// (opens a run), live=`[close2, resume2]` (closes the run). The
/// walker leaves `*run==false` through S0 and S1 (no run activity),
/// then latches `run==true` in S2 (headless -> run opens), then
/// clears it in live (closer). Grouping places S1 OUTSIDE the run.
#[test]
fn cv2_r_honest_mid_honest_middle_is_not_a_run_member() {
    let d = st::Temp::new();
    let cp0 = st_runs::base(&d);
    st_runs::put(&d, 0, &[&cp0], &[]);
    let mmr0 = st::seeded(&cp0);
    // S1: a honest checkpoint-only segment (no run activity).
    let cp1 = st_runs::signed(1, cp0.hash(), &mmr0);
    st_runs::put(&d, 1, &[&cp1], &[]);
    let mmr1 = st::seeded_pair(&cp0, &cp1);
    // S2: a headless run segment linking from cp1 (opens run 0).
    let kept = st_runs::headless(&cp1, cp1.context.seq + 5);
    st_runs::put(&d, 2, &[&kept], &[]);
    let mut fold = mmr1;
    fold.push(kept.hash()).unwrap();
    // live: close the run.
    let _ = st_runs::close_run(&d, &kept, &fold);
    TrailReader::open(&d.0, TRAIL, None).expect("R-honest-mid: reader Ok");
    let out = classify_collect(&d.0);
    assert!(out.violations.is_empty(), "R-honest-mid: no violations");
    assert_eq!(
        run_bounds(&out),
        vec![(2, 3)],
        "R-honest-mid: run starts at S2 (headless), closes at live S3",
    );
    assert_eq!(
        membership(&out),
        vec![None, None, Some(0), Some(0)],
        "R-honest-mid: S1 (honest middle) is NOT a run member",
    );
}

/// R-honest-between (ruling 197-d1 addendum 28): two runs on the
/// same trail. The layout chains run 0 (closed by S2's close1+resume1)
/// directly into run 1's opening via a second headless in S3 (the
/// `second_loss_keeps_first_run_acceptable` storage-tests pattern):
///
///   S0=[cp0], S1=[kept1] (headless, run 0 opens),
///   S2=[close1, resume1] (closes run 0),
///   S3=[kept2] (headless off resume1, run 1 opens),
///   live=[close2, resume2] (closes run 1).
///
/// S0 is Base (not in any run); S3 is the first segment of run 1 so
/// S3 IS a run member. The "honest between" behaviour pinned here --
/// that classify's grouping does not extend run 0 past its closer
/// S2 -- is the real invariant: S2 is in run 0 only, S3 belongs to
/// run 1 only.
#[test]
fn cv2_r_honest_between_two_runs_on_same_trail() {
    let d = st::Temp::new();
    let cp0 = st_runs::base(&d);
    st_runs::put(&d, 0, &[&cp0], &[]);
    // S1: headless (run 0 opens).
    let kept1 = st_runs::headless(&cp0, 3);
    st_runs::put(&d, 1, &[&kept1], &[]);
    let mut fold = st::seeded_pair(&cp0, &kept1);
    // S2: closer for run 0.
    let close1_seq = kept1.context.seq + 4;
    let close1 = st_runs::signed(close1_seq, kept1.hash(), &fold);
    let resume1 = st::declaration(
        &close1,
        kept1.context.seq,
        kept1.hash(),
        close1.context.seq - 1,
        None,
    );
    st_runs::put(&d, 2, &[&close1, &resume1], &[]);
    fold.push(close1.hash()).unwrap();
    fold.push(resume1.hash()).unwrap();
    // S3: second headless, opens run 1 off resume1.
    let kept2 = st_runs::headless(&resume1, resume1.context.seq + 3);
    st_runs::put(&d, 3, &[&kept2], &[]);
    fold.push(kept2.hash()).unwrap();
    // live: close run 1.
    let _ = st_runs::close_run(&d, &kept2, &fold);
    TrailReader::open(&d.0, TRAIL, None).expect("R-honest-between: reader Ok");
    let out = classify_collect(&d.0);
    assert!(out.violations.is_empty(), "R-honest-between: no violations");
    assert_eq!(
        run_bounds(&out),
        vec![(1, 2), (3, 4)],
        "R-honest-between: two runs, S2 closes run 0 and does NOT bleed into run 1",
    );
    assert_eq!(
        membership(&out),
        vec![None, Some(0), Some(0), Some(1), Some(1)],
        "R-honest-between: S0 base; S1+S2 in run 0; S3+live in run 1",
    );
}

/// p02 — honest two-segment run (storage_tests::runs::run_lengths_one_and_two).
#[test]
fn cv2_p02_two_segment_run() {
    let d = st::Temp::new();
    let first = st_runs::base(&d);
    st_runs::put(&d, 0, &[&first], &[]);
    let mut fold = st::seeded(&first);
    let r_a = st_runs::headless(&first, first.context.seq + 5);
    st_runs::put(&d, 1, &[&r_a], &[]);
    fold.push(r_a.hash()).unwrap();
    let r_b = st_runs::headless(&r_a, r_a.context.seq + 5);
    st_runs::put(&d, 2, &[&r_b], &[]);
    fold.push(r_b.hash()).unwrap();
    let _ = st_runs::close_run(&d, &r_b, &fold);
    TrailReader::open(&d.0, TRAIL, None).expect("p02: reader Ok");
    let out = classify_collect(&d.0);
    assert!(out.violations.is_empty(), "p02: no violations");
    assert_eq!(
        run_bounds(&out),
        vec![(1, 3)],
        "p02: one run spans S1..=live (two headless segments + live closer)",
    );
    assert_eq!(
        membership(&out),
        vec![None, Some(0), Some(0), Some(0)],
        "p02: S0 base; S1, S2, live all in run 0",
    );
}

/// p03 — fragment-only segment belongs to run (storage_tests::runs::fragment_only_segment_belongs_to_run).
#[test]
fn cv2_p03_fragment_only_segment_belongs_to_run() {
    let d = st::Temp::new();
    let first = st_runs::base(&d);
    st_runs::put(&d, 0, &[&first], &[]);
    st_runs::put(&d, 1, &[], b"{\"torn\":");
    let _ = st_runs::close_run(&d, &first, &st::seeded(&first));
    TrailReader::open(&d.0, TRAIL, None).expect("p03: reader Ok");
    let out = classify_collect(&d.0);
    assert!(out.violations.is_empty(), "p03: no violations");
    assert_eq!(
        run_bounds(&out),
        vec![(1, 2)],
        "p03: one run covers S1 (fragment-only) and live closer",
    );
    assert_eq!(
        membership(&out),
        vec![None, Some(0), Some(0)],
        "p03: S0 base; S1 + live in run 0",
    );
}

/// p04 — unparsable last line is sealed evidence (storage_tests::runs::unparsable_last_line_is_sealed_evidence).
/// S0=[cp0, "not json\n"], live=[closer, resume]. The sealed segment
/// is run-triggering via its trailing Unparsable line.
#[test]
fn cv2_p04_unparsable_last_line_is_sealed_evidence() {
    let d = st::Temp::new();
    let first = st_runs::base(&d);
    st_runs::put(&d, 0, &[&first], b"not json\n");
    let _ = st_runs::close_run(&d, &first, &st::seeded(&first));
    TrailReader::open(&d.0, TRAIL, None).expect("p04: reader Ok");
    let out = classify_collect(&d.0);
    assert!(out.violations.is_empty(), "p04: no violations");
    assert_eq!(
        run_bounds(&out),
        vec![(0, 1)],
        "p04: one run covers S0 (unparsable tail) and live closer",
    );
    assert_eq!(
        membership(&out),
        vec![Some(0), Some(0)],
        "p04: S0 and live both in run 0",
    );
}

/// p05 — archived base (prev != genesis) followed by honest resume.
/// Reader `Ok`, no run (archived base alone is a valid base; not
/// run-triggering; ruling 107-d1). Mirrors
/// `storage_tests::classify_reader_pins::accepted_archived_base`.
#[test]
fn cv2_p05_archived_base_honest_resume_no_run() {
    let d = st::Temp::new();
    // Archived prefix: first checkpoint has `previous = [42; 32]`
    // (an opaque archived predecessor hash) and the genesis-seeded
    // fold the archived prefix implies.
    let genesis_fold = {
        let mut m = Mmr::new();
        m.push(Record::genesis(&TRAIL)).unwrap();
        m
    };
    let archived = st::cp(7, [42; 32], &genesis_fold);
    let r = st::declaration(&archived, 0, [42; 32], 6, None);
    st::write_records(&d.0, &[&archived, &r]);
    TrailReader::open(&d.0, TRAIL, None).expect("p05: archived base Ok");
    let out = classify_collect(&d.0);
    assert!(out.violations.is_empty(), "p05: no violations");
    assert!(
        out.runs.is_empty(),
        "p05: archived base alone is not run-triggering (0 runs)",
    );
}

/// p06 — p12-shape with headless run before it. S0 sealed=[cp0],
/// headless-run S0b=[kept], S1=[cp_linking(previous=kept.hash), e_next]
/// without immediate resume. Reader `Err(CorruptTrail: first successor
/// lacks immediate resume)`.
#[test]
fn cv2_p06_linking_after_headless_without_resume() {
    let d = st::Temp::new();
    let first = st_runs::base(&d);
    st_runs::put(&d, 0, &[&first], &[]);
    let kept = st_runs::headless(&first, 3);
    st_runs::put(&d, 1, &[&kept], &[]);
    let mut fold = st::seeded_pair(&first, &kept);
    let opening = st_runs::signed(4, kept.hash(), &fold);
    let not_resume = st::entry(&opening);
    fold.push(opening.hash()).unwrap();
    fold.push(not_resume.hash()).unwrap();
    let cp_live = st_runs::signed(not_resume.context.seq + 1, not_resume.hash(), &fold);
    let resume = st::declaration(
        &cp_live,
        not_resume.context.seq,
        not_resume.hash(),
        cp_live.context.seq - 1,
        None,
    );
    st_runs::put(&d, 2, &[&opening, &not_resume], &[]);
    st::write_records(&d.0, &[&cp_live, &resume]);
    // Ruling 197-d1 addendum 27.4: literal reader-detail pin at base
    // `ba7ef3e`, plus literal violation list.
    assert_reader_corrupt(&d.0, "first successor lacks immediate resume", "p06");
    let out = classify_collect(&d.0);
    assert_eq!(
        out.violations,
        vec![
            (
                super::SegmentViolationPos {
                    segment_index: 2,
                    record_index_in_segment: 1,
                },
                super::Violation::FirstSuccessorLacksImmediateResume,
            ),
            (
                super::SegmentViolationPos {
                    segment_index: 3,
                    record_index_in_segment: 0,
                },
                super::Violation::RecordRolledBack,
            ),
        ],
        "p06: literal violation list (addendum 27.4)",
    );
    assert!(
        out.runs.is_empty(),
        "p06 (C2): out.runs empty on rejected trail"
    );
}

/// p07 — non-checkpoint first record at base. S0=[entry(seq=0,
/// previous=genesis)] (not a checkpoint). Reader `Err(CorruptTrail:
/// missing initial checkpoint)`.
#[test]
fn cv2_p07_non_checkpoint_first_record_at_base() {
    let d = st::Temp::new();
    // An entry with seq=0 pointing at genesis -- not a checkpoint.
    let e0 = Record::new(
        st::context(0, Record::genesis(&TRAIL)),
        Entry::new("actor", "change", "object"),
    )
    .unwrap();
    st_runs::put(&d, 0, &[&e0], &[]);
    let fold = {
        let mut m = Mmr::new();
        m.push(e0.hash()).unwrap();
        m
    };
    let close = st_runs::signed(1, e0.hash(), &fold);
    let resume = st::declaration(&close, 0, e0.hash(), 0, None);
    st::write_records(&d.0, &[&close, &resume]);
    assert_reader_corrupt(&d.0, "missing initial checkpoint", "p07");
    let out = classify_collect(&d.0);
    assert_eq!(
        out.violations,
        vec![(
            super::SegmentViolationPos {
                segment_index: 0,
                record_index_in_segment: 0,
            },
            super::Violation::MissingInitialCheckpoint,
        )],
        "p07: literal violation list (addendum 27.4)",
    );
    assert!(
        out.runs.is_empty(),
        "p07 (C2): out.runs empty on rejected trail"
    );
}

/// p08 — archived base cp crashed, honest resume into live. The
/// archived prefix lives in sealed S0; the live file holds the
/// closer + resume. Reader `Ok`; classify emits no run (ruling
/// 13-V4-d3: the archived base alone is not run-triggering).
#[test]
fn cv2_p08_archived_base_crashed_honest_resume_no_run() {
    let d = st::Temp::new();
    let genesis_fold = {
        let mut m = Mmr::new();
        m.push(Record::genesis(&TRAIL)).unwrap();
        m
    };
    // Archived base cp at seq=5 with prev != genesis.
    let archived = st::cp(5, [42; 32], &genesis_fold);
    st_runs::put(&d, 0, &[&archived], &[]);
    let mut fold = genesis_fold;
    fold.push(archived.hash()).unwrap();
    let close = st::cp(6, archived.hash(), &fold);
    let resume = st::declaration(&close, 5, archived.hash(), 5, None);
    st::write_records(&d.0, &[&close, &resume]);
    TrailReader::open(&d.0, TRAIL, None).expect("p08: archived base Ok");
    let out = classify_collect(&d.0);
    assert!(out.violations.is_empty(), "p08: no violations");
    assert!(
        out.runs.is_empty(),
        "p08: archived-prefix-only (no run-triggering segment); 0 runs",
    );
}

/// p09 — closed run with no complete records (equal to A8).
/// Sealed S0=[cp0], S1=empty, live=[opening, resume]. Reader `Ok`.
#[test]
fn cv2_p09_closed_run_zero_records_equals_a8() {
    let a = build_a8();
    TrailReader::open(&a.dir_path, TRAIL, None).expect("p09: reader Ok");
    let out = classify_collect(&a.dir_path);
    assert!(out.violations.is_empty(), "p09: no violations");
    assert_eq!(
        run_bounds(&out),
        vec![(1, 2)],
        "p09: one run covers S1 (empty) and live closer",
    );
    assert_eq!(
        membership(&out),
        vec![None, Some(0), Some(0)],
        "p09: S0 base; S1 and live in run 0",
    );
}

/// p10 — fragment-only segment with predecessor cp0. Sealed S0=[cp0],
/// S1 fragment-only, live=[opening(prev=cp0), resume]. Reader `Ok`.
#[test]
fn cv2_p10_fragment_only_with_predecessor() {
    let d = st::Temp::new();
    let first = st_runs::base(&d);
    st_runs::put(&d, 0, &[&first], &[]);
    st_runs::put(&d, 1, &[], b"{\"torn\":");
    // Closer links cp0.hash (not the fragment-only segment's bytes).
    let fold = st::seeded(&first);
    let close = st_runs::signed(1, first.hash(), &fold);
    let resume = st::declaration(&close, 0, first.hash(), 0, None);
    st::write_records(&d.0, &[&close, &resume]);
    TrailReader::open(&d.0, TRAIL, None).expect("p10: reader Ok");
    let out = classify_collect(&d.0);
    assert!(out.violations.is_empty(), "p10: no violations");
    assert_eq!(
        run_bounds(&out),
        vec![(1, 2)],
        "p10: one run spans S1 (fragment-only) and live closer",
    );
    assert_eq!(
        membership(&out),
        vec![None, Some(0), Some(0)],
        "p10: S0 base; S1 and live in run 0",
    );
}

/// p11 — two consecutive record-free segments then closer. Sealed
/// S0=[cp0], S1 fragment-only, S2 Unparsable-only, live=[opening,
/// resume]. Reader `Ok`.
#[test]
fn cv2_p11_two_record_free_segments_then_closer() {
    let d = st::Temp::new();
    let first = st_runs::base(&d);
    st_runs::put(&d, 0, &[&first], &[]);
    st_runs::put(&d, 1, &[], b"{\"torn\":");
    st_runs::put(&d, 2, &[], b"not json\n");
    let fold = st::seeded(&first);
    let close = st_runs::signed(1, first.hash(), &fold);
    let resume = st::declaration(&close, 0, first.hash(), 0, None);
    st::write_records(&d.0, &[&close, &resume]);
    TrailReader::open(&d.0, TRAIL, None).expect("p11: reader Ok");
    let out = classify_collect(&d.0);
    assert!(out.violations.is_empty(), "p11: no violations");
    assert_eq!(
        run_bounds(&out),
        vec![(1, 3)],
        "p11: one run spans S1..=live (two record-free + closer)",
    );
    assert_eq!(
        membership(&out),
        vec![None, Some(0), Some(0), Some(0)],
        "p11: S0 base; S1, S2, live in run 0",
    );
}

/// p12 — linking opening after unsealed with no immediate resume.
/// Reader `Err(CorruptTrail: first successor lacks immediate resume)`.
#[test]
fn cv2_p12_linking_opening_after_unsealed_no_resume() {
    let d = st::Temp::new();
    let first = st_runs::base(&d);
    // S0 unsealed: [cp0, entry] with NO closing checkpoint nor LF
    // (the storage walker treats a closed segment without LF as
    // unclosed if it lacks an accompanying resume).
    let e1 = st::entry(&first);
    let bytes: Vec<u8> = [&first, &e1].iter().flat_map(|r| st::line(r)).collect();
    // Strip trailing LF so the segment is "unsealed".
    let bytes = if bytes.last() == Some(&b'\n') {
        bytes[..bytes.len() - 1].to_vec()
    } else {
        bytes
    };
    std::fs::write(st::segment(&d.0, 0), bytes).unwrap();
    let mut fold = st::seeded_pair(&first, &e1);
    // S1: opening links e1.hash, second record is NOT a resume.
    let opening = st_runs::signed(e1.context.seq + 1, e1.hash(), &fold);
    let not_resume = st::entry(&opening);
    st_runs::put(&d, 1, &[&opening, &not_resume], &[]);
    fold.push(opening.hash()).unwrap();
    fold.push(not_resume.hash()).unwrap();
    let cp_live = st_runs::signed(not_resume.context.seq + 1, not_resume.hash(), &fold);
    let resume = st::declaration(
        &cp_live,
        not_resume.context.seq,
        not_resume.hash(),
        cp_live.context.seq - 1,
        None,
    );
    st::write_records(&d.0, &[&cp_live, &resume]);
    assert_reader_corrupt(&d.0, "first successor lacks immediate resume", "p12");
    let out = classify_collect(&d.0);
    assert_eq!(
        out.violations,
        vec![
            (
                super::SegmentViolationPos {
                    segment_index: 1,
                    record_index_in_segment: 1,
                },
                super::Violation::FirstSuccessorLacksImmediateResume,
            ),
            (
                super::SegmentViolationPos {
                    segment_index: 2,
                    record_index_in_segment: 0,
                },
                super::Violation::RecordRolledBack,
            ),
        ],
        "p12: literal violation list (addendum 27.4)",
    );
    assert!(
        out.runs.is_empty(),
        "p12 (C2): out.runs empty on rejected trail"
    );
}

/// p13a — §19.2 S0 deleted. S1=[P5(prev != genesis), e6, C7],
/// old_live has an opening without an immediate resume. Reader
/// `Err(CorruptTrail)`; `out.runs` empty.
#[test]
fn cv2_p13a_section_19_2_s0_deleted() {
    let d = st::Temp::new();
    // P5: first present record, seq=5, previous != genesis.
    let p5 = st_runs::signed(5, [99u8; 32], &{
        let mut m = Mmr::new();
        m.push([99u8; 32]).unwrap();
        m
    });
    let e6 = st::entry(&p5);
    let mut fold = st::seeded_pair(&p5, &e6);
    let c7 = st_runs::signed(7, e6.hash(), &fold);
    fold.push(c7.hash()).unwrap();
    st_runs::put(&d, 0, &[&p5, &e6, &c7], &[]);
    // old_live: opening O8 + e9 (not a resume).
    let o8 = st_runs::signed(8, c7.hash(), &fold);
    let e9 = st::entry(&o8);
    fold.push(o8.hash()).unwrap();
    fold.push(e9.hash()).unwrap();
    let cp_live = st_runs::signed(e9.context.seq + 1, e9.hash(), &fold);
    let resume = st::declaration(
        &cp_live,
        e9.context.seq,
        e9.hash(),
        cp_live.context.seq - 1,
        None,
    );
    st_runs::put(&d, 1, &[&o8, &e9], &[]);
    st::write_records(&d.0, &[&cp_live, &resume]);
    assert_reader_corrupt(
        &d.0,
        "checkpoint MMR differs from preceding records",
        "p13a",
    );
    let out = classify_collect(&d.0);
    assert_eq!(
        out.violations,
        vec![
            (
                super::SegmentViolationPos {
                    segment_index: 0,
                    record_index_in_segment: 2,
                },
                super::Violation::CheckpointMmrDiffers,
            ),
            (
                super::SegmentViolationPos {
                    segment_index: 1,
                    record_index_in_segment: 0,
                },
                super::Violation::FirstSuccessorDoesNotCloseRun,
            ),
            (
                super::SegmentViolationPos {
                    segment_index: 2,
                    record_index_in_segment: 0,
                },
                super::Violation::RecordRolledBack,
            ),
        ],
        "p13a: literal violation list (addendum 27.4)",
    );
    assert!(
        out.runs.is_empty(),
        "p13a (C2): out.runs empty on rejected trail"
    );
}

/// p13b — §19.2 S0 kept, S1 cut to P5, honest resume. Storage still
/// rejects old_live because O8's successor e9 is not a resume.
#[test]
fn cv2_p13b_section_19_2_s0_kept() {
    let d = st::Temp::new();
    let first = st_runs::base(&d);
    st_runs::put(&d, 0, &[&first], &[]);
    // S1=[P5(prev != cp0.hash), e6, C7]
    let p5 = st_runs::signed(5, [99u8; 32], &{
        let mut m = Mmr::new();
        m.push([99u8; 32]).unwrap();
        m
    });
    let e6 = st::entry(&p5);
    let mut fold = st::seeded_pair(&p5, &e6);
    let c7 = st_runs::signed(7, e6.hash(), &fold);
    fold.push(c7.hash()).unwrap();
    st_runs::put(&d, 1, &[&p5, &e6, &c7], &[]);
    let o8 = st_runs::signed(8, c7.hash(), &fold);
    let e9 = st::entry(&o8);
    fold.push(o8.hash()).unwrap();
    fold.push(e9.hash()).unwrap();
    let cp_live = st_runs::signed(e9.context.seq + 1, e9.hash(), &fold);
    let resume = st::declaration(
        &cp_live,
        e9.context.seq,
        e9.hash(),
        cp_live.context.seq - 1,
        None,
    );
    st_runs::put(&d, 2, &[&o8, &e9], &[]);
    st::write_records(&d.0, &[&cp_live, &resume]);
    assert_reader_corrupt(&d.0, "first successor does not close sealed run", "p13b");
    let out = classify_collect(&d.0);
    assert_eq!(
        out.violations,
        vec![
            (
                super::SegmentViolationPos {
                    segment_index: 2,
                    record_index_in_segment: 0,
                },
                super::Violation::FirstSuccessorDoesNotCloseRun,
            ),
            (
                super::SegmentViolationPos {
                    segment_index: 3,
                    record_index_in_segment: 0,
                },
                super::Violation::RecordRolledBack,
            ),
        ],
        "p13b: literal violation list (addendum 27.4)",
    );
    assert!(
        out.runs.is_empty(),
        "p13b (C2): out.runs empty on rejected trail"
    );
}

// ============================================================
// CV3: p09 + p10 fragment-only agreement (digest-only runs, with
// and without spans). CV1-A8 already pins p09's digest; this row
// pins that p10 produces a digest-only run with exactly one span.
// ============================================================

#[test]
fn cv3_p09_and_p10_digest_only_with_and_without_spans() {
    // p09 (== A8): digest-only run, zero spans.
    let a = build_a8();
    let out_p09 = classify_collect(&a.dir_path);
    assert_eq!(out_p09.runs.len(), 1);
    let rr_p09 = &out_p09.runs[0];
    assert!(rr_p09.loss_points.is_empty(), "CV3 p09: no loss points");
    assert!(rr_p09.spans.is_empty(), "CV3 p09: no spans");

    // p10: digest-only run, exactly one span (S1 fragment-only).
    let d = st::Temp::new();
    let first = st_runs::base(&d);
    st_runs::put(&d, 0, &[&first], &[]);
    st_runs::put(&d, 1, &[], b"{\"torn\":");
    let fold = st::seeded(&first);
    let close = st_runs::signed(1, first.hash(), &fold);
    let resume = st::declaration(&close, 0, first.hash(), 0, None);
    st::write_records(&d.0, &[&close, &resume]);
    TrailReader::open(&d.0, TRAIL, None).expect("CV3 p10: reader Ok");
    let out_p10 = classify_collect(&d.0);
    assert_eq!(out_p10.runs.len(), 1, "CV3 p10: one run");
    let rr_p10 = &out_p10.runs[0];
    assert!(rr_p10.loss_points.is_empty(), "CV3 p10: no loss points");
    // Ruling 197-d1 addendum 27.4: literal span list and run_digest pin
    // (captured at head on this slice; a drift in `verify::lines::stream`,
    // span `seg` renumbering or the gap hash flips the pin).
    assert_eq!(
        rr_p10.spans.len(),
        1,
        "CV3 p10: one span (fragment-only S1)"
    );
    let span0 = &rr_p10.spans[0];
    assert_eq!(span0.seg, 0, "CV3 p10: span seg run-local 0");
    assert_eq!(
        span0.after,
        u64::MAX,
        "CV3 p10: span starts at segment first byte (after == u64::MAX)",
    );
    assert_eq!(
        span0.len, 8,
        "CV3 p10: span len == 8 (bytes of `{{\\\"torn\\\":`)",
    );
    assert_eq!(
        digest_hex(&span0.digest),
        "blake3:e06678ed944e90a6f28636da719dc9b8267f8fec6688720495123ec237d761a4",
        "CV3 p10: span digest literal pin",
    );
    let run_digest = crate::audit::verify::lines::run_digest(&[], &rr_p10.spans);
    assert_eq!(
        digest_hex(&run_digest),
        "blake3:83abd6e7c857e0660c5cc69ff6cf0966bddfce1c06d6d36fb4b010ea2aa329ed",
        "CV3 p10: run_digest literal pin",
    );
}

// ============================================================
// B2 / addendum 28.5: two distinct killer rows per report mutant
// for O2 (`boundary_resume` inverted), O4 (any membership-changing
// mutant on the class/grouping), O6 (`final_state: None`) and O8
// (a closer's spans dropped).
// ============================================================

/// O2 killer 1 — A1 per-segment `boundary_resume` literal.
/// With `boundary_resume = role_opening && !storage::sealed(prior)`,
/// A1's values are `[false, true, false]` (S0 prior=None, S1 prior=cp0-
/// sealed is-false-since-sealed inverted, S2 prior=S1-unsealed is-true,
/// live prior=cp5-sealed is-false). The O2 mutant inverts the sealed
/// check and flips the row to `[false, false, true]`.
#[test]
fn b2_o2_a1_boundary_resume_per_segment_literal() {
    let a = build_a1();
    TrailReader::open(&a.dir_path, TRAIL, None).unwrap();
    let out = classify_collect(&a.dir_path);
    let br: Vec<bool> = out.segments.iter().map(|s| s.boundary_resume).collect();
    assert_eq!(
        br,
        vec![false, true, false],
        "O2 kill: A1 boundary_resume literal (inverting storage::sealed flips this row)",
    );
}

/// O2 killer 2 — A3 per-segment `boundary_resume` literal.
/// A3's four segments are all at sealed boundaries (cp2 / cp5 / cp8
/// all seal), so every `boundary_resume` is `false`. Inverting the
/// sealed check turns every segment with a prior state into `true`.
#[test]
fn b2_o2_a3_boundary_resume_per_segment_literal() {
    let a = build_a3();
    TrailReader::open(&a.dir_path, TRAIL, None).unwrap();
    let out = classify_collect(&a.dir_path);
    let br: Vec<bool> = out.segments.iter().map(|s| s.boundary_resume).collect();
    assert_eq!(
        br,
        vec![false, false, false, false],
        "O2 kill: A3 boundary_resume literal (inverting storage::sealed flips three segments)",
    );
}

/// O4 killer 1 — A1 per-segment `SegmentClass` literal
/// (`[Base, InRun, Closer]`). Any mutant that reroutes the class
/// derivation changes this row.
#[test]
fn b2_o4_a1_segment_classes_literal() {
    let a = build_a1();
    TrailReader::open(&a.dir_path, TRAIL, None).unwrap();
    let out = classify_collect(&a.dir_path);
    let classes: Vec<super::SegmentClass> = out.segments.iter().map(|s| s.class).collect();
    use super::SegmentClass::{Base, Closer, InRun};
    assert_eq!(
        classes,
        vec![Base, InRun, Closer],
        "O4 kill: A1 class order (any membership-changing mutant flips one entry)",
    );
    let membership: Vec<Option<usize>> = out.segments.iter().map(|s| s.run_membership).collect();
    assert_eq!(
        membership,
        vec![None, Some(0), Some(0)],
        "O4 kill: A1 run_membership literal",
    );
}

/// O4 killer 2 — A3 per-segment `SegmentClass` literal
/// (`[Base, InRun, InRun, Closer]`).
#[test]
fn b2_o4_a3_segment_classes_literal() {
    let a = build_a3();
    TrailReader::open(&a.dir_path, TRAIL, None).unwrap();
    let out = classify_collect(&a.dir_path);
    let classes: Vec<super::SegmentClass> = out.segments.iter().map(|s| s.class).collect();
    use super::SegmentClass::{Base, Closer, InRun};
    assert_eq!(
        classes,
        vec![Base, InRun, InRun, Closer],
        "O4 kill: A3 class order (membership-changing mutants flip at least one entry)",
    );
    let membership: Vec<Option<usize>> = out.segments.iter().map(|s| s.run_membership).collect();
    assert_eq!(
        membership,
        vec![None, Some(0), Some(0), Some(0)],
        "O4 kill: A3 run_membership literal",
    );
}

/// O6 killer 1 — A1 per-segment `final_state.is_some()` literal
/// (all `true`). A mutant that forces `final_state: None` on any
/// segment flips an entry.
#[test]
fn b2_o6_a1_final_state_is_some_per_segment() {
    let a = build_a1();
    TrailReader::open(&a.dir_path, TRAIL, None).unwrap();
    let out = classify_collect(&a.dir_path);
    let states: Vec<bool> = out
        .segments
        .iter()
        .map(|s| s.final_state.is_some())
        .collect();
    assert_eq!(
        states,
        vec![true, true, true],
        "O6 kill: A1 final_state.is_some() literal",
    );
}

/// O6 killer 2 — A3 per-segment `final_state.is_some()` literal
/// (all four `true`).
#[test]
fn b2_o6_a3_final_state_is_some_per_segment() {
    let a = build_a3();
    TrailReader::open(&a.dir_path, TRAIL, None).unwrap();
    let out = classify_collect(&a.dir_path);
    let states: Vec<bool> = out
        .segments
        .iter()
        .map(|s| s.final_state.is_some())
        .collect();
    assert_eq!(
        states,
        vec![true, true, true, true],
        "O6 kill: A3 final_state.is_some() literal",
    );
}

/// O8 killer 1 — p10 plus a live torn tail `{"half`. Reader is `Ok`
/// (torn trailing fragment on the live file is tolerated). The run
/// has `first_segment=1` (fragment-only `S1`) and `last_segment=2`
/// (live, the closer) — both contribute one span each. Expected
/// span shapes: `[(0, u64::MAX, 8), (1, 5, 6)]`. A mutant that
/// drops the closer segment's spans flips this to `[(0, u64::MAX, 8)]`.
#[test]
fn b2_o8_p10_live_torn_tail_half_spans() {
    let d = st::Temp::new();
    let first = st_runs::base(&d);
    st_runs::put(&d, 0, &[&first], &[]);
    st_runs::put(&d, 1, &[], b"{\"torn\":");
    let fold = st::seeded(&first);
    let (_close, resume) = st_runs::close_run(&d, &first, &fold);
    st::append_bytes(&d.0.join("audit.jsonl"), b"{\"half");
    TrailReader::open(&d.0, TRAIL, None).expect("O8: reader Ok on p10 + torn tail");
    let out = classify_collect(&d.0);
    assert!(out.violations.is_empty(), "O8: no violations");
    assert_eq!(out.runs.len(), 1, "O8: one run");
    let rr = &out.runs[0];
    let shapes: Vec<(u32, u64, u64)> = rr.spans.iter().map(|s| (s.seg, s.after, s.len)).collect();
    assert_eq!(
        shapes,
        vec![(0, u64::MAX, 8), (1, resume.context.seq, 6)],
        "O8 kill: p10+torn-tail spans literal — closer (live) contributes `(1, 5, 6)`",
    );
    assert_eq!(resume.context.seq, 5, "O8: resume.seq pin (sanity)");
    // Pin the closer-span digest so even a mutant that preserves the
    // tuple shapes but reorders content flips the row.
    assert_eq!(
        digest_hex(&rr.spans[1].digest),
        "blake3:d9a5b587318eff723676e5ae0e4f95bc2b2617255722fea8409d547b4cb020cc",
        "O8 kill: closer span digest literal",
    );
}

/// O8 killer 2 — A9 (multi-segment record-free) run spans with the
/// closer's spans as the trailing pair. If an O8-style mutant drops
/// the closer segment or truncates the per-segment span concatenation,
/// the full `[(0, MAX, 9), (1, MAX, 14)]` pair collapses.
#[test]
fn b2_o8_a9_span_shapes_literal() {
    let a = build_a9();
    TrailReader::open(&a.dir_path, TRAIL, None).unwrap();
    let out = classify_collect(&a.dir_path);
    assert_eq!(out.runs.len(), 1, "O8/A9: one run");
    let rr = &out.runs[0];
    let shapes: Vec<(u32, u64, u64)> = rr.spans.iter().map(|s| (s.seg, s.after, s.len)).collect();
    assert_eq!(
        shapes,
        vec![(0, u64::MAX, 9), (1, u64::MAX, 14)],
        "O8 kill: A9 span shapes literal (dropping any run-segment's span changes the list)",
    );
}

// ============================================================
// B3 (addendum 28.5): meaningful rows for the new mutants N1 made
// available on the walker closer-fired signal. `closer_fired` is now
// the Classifier's own (i)+(ii) latch, no inference from `ctx.run`.
// ============================================================

/// M-N1a kill — `closer_fired` stuck `false`. Any run that closes
/// (A1) no longer has a Closer segment, `runs` becomes empty.
#[test]
fn b3_n1a_closer_fired_stuck_false_kill() {
    let a = build_a1();
    TrailReader::open(&a.dir_path, TRAIL, None).unwrap();
    let out = classify_collect(&a.dir_path);
    assert_eq!(out.runs.len(), 1, "M-N1a kill: A1 still has one closed run");
    assert_eq!(
        out.segments[2].class,
        super::SegmentClass::Closer,
        "M-N1a kill: A1 live is Closer (stuck-false mutant drops this)",
    );
}

/// M-N1b kill — `closer_fired = ctx.run` (inherited-run inference).
/// Needs a layout where `ctx.run` is true on a non-closing strict
/// pass: p02 S2 inherits the run opened by S1 and does NOT close
/// it (the live closer is a separate segment). Pinning `segments[2]
/// .class == InRun` kills the inferred mutant (which would latch
/// `Closer` on S2 because `run_in_before==true`), and would then
/// split `cv2_p02`'s single run `[(1,3)]` into `[(1,2),(2,3)]`.
#[test]
fn b3_n1b_closer_fired_from_ctx_run_kill() {
    let d = st::Temp::new();
    let first = st_runs::base(&d);
    st_runs::put(&d, 0, &[&first], &[]);
    let mut fold = st::seeded(&first);
    let r_a = st_runs::headless(&first, first.context.seq + 5);
    st_runs::put(&d, 1, &[&r_a], &[]);
    fold.push(r_a.hash()).unwrap();
    let r_b = st_runs::headless(&r_a, r_a.context.seq + 5);
    st_runs::put(&d, 2, &[&r_b], &[]);
    fold.push(r_b.hash()).unwrap();
    let _ = st_runs::close_run(&d, &r_b, &fold);
    TrailReader::open(&d.0, TRAIL, None).expect("M-N1b: reader Ok on p02 layout");
    let out = classify_collect(&d.0);
    assert_eq!(
        out.segments[2].class,
        super::SegmentClass::InRun,
        "M-N1b kill: p02 S2 stays InRun (mutant closer_fired=run_in_before would latch Closer here)",
    );
    assert_eq!(
        out.segments[2].run_membership,
        Some(0),
        "M-N1b kill: p02 S2 belongs to run 0",
    );
}
