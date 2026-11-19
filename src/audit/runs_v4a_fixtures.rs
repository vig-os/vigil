//! Shared `#[cfg(test)] pub(crate)` fixture seam for the V4a run
//! layouts (A1, A3, A8, A9) and their captured run-digest constants.
//! Consumed by:
//! - `crate::audit::runs::classify_v4a_walk` (classify-level pins at
//!   this head);
//! - `crate::audit::verify::runs_tests` (V4a verifier rows, through
//!   `Verifier::verify_dir` / `Verifier::verify_files`).
//!
//! Rulings: 13-V4-d3, 13-V4-d4, 13-V4-d5, 13-V4-d6, 13-V4-d8.
//!
//! Every builder writes a trail directory on disk whose
//! `Verifier::verify_*` entry points can read; the classify-level
//! consumer calls the shared `classify` through
//! `crate::audit::runs::classify_for_test` instead. The two
//! consumers must see byte-identical layouts, so the digest consts
//! are the same literal for both. A fresh capture at head drives
//! each build (the digest-pin tests in `classify_v4a_walk`); this
//! module only holds the literals.

use super::{
    AuditError, AuditErrorKind, CheckpointFields, Entry, KeyFileSigner, Mmr, Record, RecordContext,
    Signer,
    storage::{Head, TrailReader},
};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

pub(crate) const TRAIL: [u8; 16] = [17; 16];
static NEXT: AtomicUsize = AtomicUsize::new(0);

/// Public key of the shared fixture signing key (seed `0x27` repeated).
/// Consumed by every verifier test that lists the fixture key on a
/// `TrustPolicy` so a signed fixture checkpoint is trusted at verify time
/// (ruling 13-V5-d1 points 1-2).
pub(crate) fn fixture_pubkey() -> [u8; 32] {
    KeyFileSigner::from_hex(&"27".repeat(32))
        .unwrap()
        .public_key()
}

/// Per-process temporary directory for a V4a trail. Deleted on drop.
pub(crate) struct Temp(pub(crate) PathBuf);
impl Temp {
    pub(crate) fn new() -> Self {
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

pub(crate) fn context(seq: u64, previous: [u8; 32]) -> RecordContext {
    RecordContext::new(TRAIL, seq, 100 + seq, "test", previous)
}
pub(crate) fn signed_cp(seq: u64, previous: [u8; 32], mmr: &Mmr) -> Record {
    signed_cp_explicit(seq, previous, mmr.size(), mmr.root(), mmr.peaks().to_vec())
}

/// Signs a checkpoint with **explicit** `(size, root, peaks)` instead
/// of taking the honest `Mmr` fold. Used by the #13 V4b rule-2 rows
/// (ruling 13-V4-d10 point 2) to craft an opening checkpoint whose
/// declared fields do not match the walker's fold. `peaks.len()` must
/// equal `size.count_ones()` (a `CheckpointFields::new` invariant);
/// pass a crafted vector of that length.
pub(crate) fn signed_cp_explicit(
    seq: u64,
    previous: [u8; 32],
    size: u64,
    root: [u8; 32],
    peaks: Vec<[u8; 32]>,
) -> Record {
    let key = KeyFileSigner::from_hex(&"27".repeat(32)).unwrap();
    let fields =
        |sig| CheckpointFields::new(size, root, peaks.clone(), key.public_key(), sig).unwrap();
    let unsigned = Record::checkpoint(context(seq, previous), fields([0; 64])).unwrap();
    let signature = key.sign(&unsigned.signing_message().unwrap()).unwrap();
    Record::checkpoint(context(seq, previous), fields(signature)).unwrap()
}
pub(crate) fn entry_rec(seq: u64, previous: [u8; 32]) -> Record {
    Record::new(
        context(seq, previous),
        Entry::new("actor", "change", "object"),
    )
    .unwrap()
}
pub(crate) fn line_bytes(record: &Record) -> Vec<u8> {
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
pub(crate) fn write_bytes(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
}
pub(crate) fn append(path: &Path, bytes: &[u8]) {
    fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}
pub(crate) fn segment_path(dir: &Path, id: usize) -> PathBuf {
    dir.join(format!("audit-20260101T000000.000000000Z_{id:06}.jsonl"))
}
pub(crate) fn put_segment(dir: &Path, id: usize, records: &[&Record], suffix: &[u8]) {
    let mut bytes: Vec<u8> = records.iter().flat_map(|r| line_bytes(r)).collect();
    bytes.extend(suffix);
    fs::write(segment_path(dir, id), bytes).unwrap();
}
pub(crate) fn write_records(dir: &Path, records: &[&Record]) {
    let bytes: Vec<u8> = records.iter().flat_map(|r| line_bytes(r)).collect();
    write_bytes(&dir.join("audit.jsonl"), &bytes);
}
pub(crate) fn seeded(record: &Record) -> Mmr {
    let mut mmr = Mmr::new();
    mmr.push(record.hash()).unwrap();
    mmr
}
pub(crate) fn pushed(mmr: &Mmr, record: &Record) -> Mmr {
    let mut m = mmr.clone();
    m.push(record.hash()).unwrap();
    m
}

/// A "headless" record simulating a broken boundary after `last`: the
/// previous-hash is the hash of the hypothetical `entry(last.seq+1,
/// last.hash)` record that would have followed `last` on an honest
/// trail, so this record's `previous` matches no record actually
/// present on this trail. Matches `storage_tests::runs::headless`.
pub(crate) fn headless(last: &Record, seq: u64) -> Record {
    let ghost = entry_rec(last.context.seq + 1, last.hash());
    entry_rec(seq, ghost.hash())
}

/// Build a resume declaration record for the gap between `previous`
/// and `checkpoint`. Uses `Record::new_internal` to bypass the
/// reserved-prefix check, as the storage tests' own `declaration`
/// helper does.
pub(crate) fn resume_decl(
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

/// Shared assertion: the layout's `TrailReader::open` outcome.
/// Kept with the fixtures so every consumer (the classify-level
/// `classify_v4a_walk` rows and the verify-level `runs_tests` rows)
/// checks the base reader behaviour through the same probe.
pub(crate) fn assert_reader_corrupt(dir: &Path, expected_detail: &str, label: &str) {
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

// ============================================================
// A1 fixture (one-range run)
// Layout:
//   S0 = [cp0, e1, e2] (sealed)
//   S1 = [e4(prev=e2.hash), cp5(prev=e4.hash)] (headless, closes earlier)
//   live = [cp6(prev=cp5.hash, size matching fold), resume7(head=5:cp5, lost_through=5)]
// ============================================================
pub(crate) struct A1 {
    _dir: Temp,
    pub(crate) dir_path: PathBuf,
    /// The closer's opening checkpoint (cp6) — for A1 run-structure pin.
    pub(crate) cp6_head: Head,
}

pub(crate) fn build_a1() -> A1 {
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
pub(crate) struct A8 {
    _dir: Temp,
    pub(crate) dir_path: PathBuf,
}

pub(crate) fn build_a8() -> A8 {
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
pub(crate) struct A9 {
    _dir: Temp,
    pub(crate) dir_path: PathBuf,
}

pub(crate) fn build_a9() -> A9 {
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
pub(crate) struct A3 {
    _dir: Temp,
    pub(crate) dir_path: PathBuf,
}

pub(crate) fn build_a3() -> A3 {
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

// Captured at head on this slice (re-computed on every build by the
// digest pins rows; committed here as a literal per ruling 197-d1
// addendum 27.4 so a drift in `run_digest`, span `seg` renumbering
// or loss-point arithmetic flips the pin).
pub(crate) const A1_DIGEST: &str =
    "blake3:79d8cb1c4dfc89a80a4911120280e63ed383108f3199f05291bcb51f625f3931";
pub(crate) const A3_DIGEST: &str =
    "blake3:78d5088883d54faa6aefe350948c217bb5ef3c32a468f22184bc07e56d84c63d";
pub(crate) const A8_DIGEST: &str =
    "blake3:1c02f080d9c70df74de0c13a4a30323f1b49ee624bab2c5d68fa5ee31c4400e4";
pub(crate) const A9_DIGEST: &str =
    "blake3:4905b9e63aa3fd9248f5c3605fe4beaf4af5a956f3f108b6dcecdbfbfda54026";
