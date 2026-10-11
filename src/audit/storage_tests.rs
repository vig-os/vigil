use super::*;
use crate::audit::{CheckpointFields, Entry, RecordContext};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};
const TRAIL: [u8; 16] = [17; 16];
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "vigil-audit-reader-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn context(seq: u64, previous: [u8; 32]) -> RecordContext {
    RecordContext::new(TRAIL, seq, 100 + seq, "test", previous)
}
fn cp(seq: u64, previous: [u8; 32], mmr: &Mmr) -> Record {
    Record::checkpoint(
        context(seq, previous),
        CheckpointFields::new(
            mmr.size(),
            mmr.root(),
            mmr.peaks().to_vec(),
            [1; 32],
            [0; 64],
        )
        .unwrap(),
    )
    .unwrap()
}
fn line(record: &Record) -> Vec<u8> {
    use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
    let extra = AnyValue {
        value: Some(any_value::Value::StringValue("context".into())),
    };
    let mut line = crate::logs::encode_line(&super::super::request(record, extra).unwrap())
        .unwrap()
        .into_bytes();
    line.push(b'\n');
    line
}
fn append(path: &Path, record: &Record) {
    fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(&line(record))
        .unwrap();
}
fn fixture(path: &Path) -> Record {
    let first = cp(0, Record::genesis(&TRAIL), &Mmr::new());
    fs::write(path.join("audit.jsonl"), line(&first)).unwrap();
    first
}
fn open(path: &Path) -> TrailReader {
    TrailReader::open(path, TRAIL, None).unwrap()
}
fn head(reader: &TrailReader) -> Head {
    reader
        .with_current(|_| Ok(()), |_, _, s| Ok(s.head))
        .unwrap()
}
fn entry(previous: &Record) -> Record {
    Record::new(
        context(previous.context.seq + 1, previous.hash()),
        Entry::new("actor", "change", "object"),
    )
    .unwrap()
}
fn bad<T>(result: Result<T, AuditError>, kind: AuditErrorKind) {
    assert_eq!(result.err().unwrap().kind(), kind);
}
fn rotated(path: &Path, last: &Record, mmr: &mut Mmr, id: usize) -> Record {
    let close = cp(last.context.seq + 1, last.hash(), mmr);
    append(&path.join("audit.jsonl"), &close);
    mmr.push(close.hash()).unwrap();
    fs::rename(
        path.join("audit.jsonl"),
        path.join(format!("audit-20260101T000000.000000000Z_{id:06}.jsonl")),
    )
    .unwrap();
    let opening = cp(close.context.seq + 1, close.hash(), mmr);
    fs::write(path.join("audit.jsonl"), line(&opening)).unwrap();
    mmr.push(opening.hash()).unwrap();
    opening
}
#[test]
fn validates_chain_mmr_identity_structure_and_expected_head() {
    let d = Temp::new();
    let first = fixture(&d.0);
    let second = entry(&first);
    append(&d.0.join("audit.jsonl"), &second);
    assert_eq!(head(&open(&d.0)), Head::of(&second));
    assert!(TrailReader::open(&d.0, TRAIL, Some(Head::of(&first))).is_ok());
    bad(
        TrailReader::open(
            &d.0,
            TRAIL,
            Some(Head {
                seq: 1,
                hash: [0; 32],
            }),
        ),
        AuditErrorKind::HeadMismatch,
    );
    bad(
        TrailReader::open(&d.0, [0; 16], None),
        AuditErrorKind::CorruptTrail,
    );
    let wrong = Record::new(context(1, [0; 32]), Entry::new("actor", "change", "object")).unwrap();
    fs::write(
        d.0.join("audit.jsonl"),
        [line(&first), line(&wrong)].concat(),
    )
    .unwrap();
    bad(
        TrailReader::open(&d.0, TRAIL, None),
        AuditErrorKind::CorruptTrail,
    );
    let wrong = Record::checkpoint(
        context(2, second.hash()),
        CheckpointFields::new(2, [0; 32], vec![[0; 32]], [0; 32], [0; 64]).unwrap(),
    )
    .unwrap();
    fs::write(
        d.0.join("audit.jsonl"),
        [line(&first), line(&second), line(&wrong)].concat(),
    )
    .unwrap();
    bad(
        TrailReader::open(&d.0, TRAIL, None),
        AuditErrorKind::CorruptTrail,
    );
    for bytes in [
        Vec::new(),
        line(&second),
        b"{\"torn\":".to_vec(),
        b"\n".to_vec(),
    ] {
        fs::write(d.0.join("audit.jsonl"), bytes).unwrap();
        bad(
            TrailReader::open(&d.0, TRAIL, None),
            AuditErrorKind::CorruptTrail,
        );
    }
    fs::remove_file(d.0.join("audit.jsonl")).unwrap();
    bad(
        TrailReader::open(&d.0, TRAIL, None),
        AuditErrorKind::CorruptTrail,
    );
}
#[test]
fn incremental_scan_reads_only_new_bytes_and_refuses_shrink_or_broken_append() {
    let d = Temp::new();
    let first = fixture(&d.0);
    let reader = open(&d.0);
    let before = SCANNED.with(|n| n.get());
    assert_eq!(head(&reader), Head::of(&first));
    assert_eq!(SCANNED.with(|n| n.get()), before);
    let second = entry(&first);
    append(&d.0.join("audit.jsonl"), &second);
    assert_eq!(head(&reader), Head::of(&second));
    assert_eq!(SCANNED.with(|n| n.get()) - before, line(&second).len());
    let broken = entry(&first);
    append(&d.0.join("audit.jsonl"), &broken);
    // An exact duplicate is permitted and contributes no new leaf.
    assert_eq!(head(&reader), Head::of(&second));
    let wrong = Record::new(context(2, first.hash()), Entry::new("x", "y", "z")).unwrap();
    append(&d.0.join("audit.jsonl"), &wrong);
    bad(
        reader.with_current(|_| Ok(()), |_, _, _| Ok(())),
        AuditErrorKind::CorruptTrail,
    );
    fs::write(d.0.join("audit.jsonl"), line(&first)).unwrap();
    bad(
        reader.with_current(|_| Ok(()), |_, _, _| Ok(())),
        AuditErrorKind::CorruptTrail,
    );
}
#[test]
fn repaired_fragments_are_checked_and_complete_json_without_lf_is_not_a_gap() {
    let d = Temp::new();
    let first = fixture(&d.0);
    let gap = b"{\"first\":\"\xf0\x9f\n{\"second\":";
    fs::OpenOptions::new()
        .append(true)
        .open(d.0.join("audit.jsonl"))
        .unwrap()
        .write_all(gap)
        .unwrap();
    let reader = open(&d.0);
    let digest = reader
        .with_current(
            |_| Ok(()),
            |_, _, s| {
                assert!(s.needs_newline());
                Ok(s.repair_digest().unwrap())
            },
        )
        .unwrap();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"vigil.audit.v1.repaired\0");
    hasher.update(gap);
    hasher.update(b"\n");
    assert_eq!(digest, *hasher.finalize().as_bytes());
    let second = Record::new(
        context(1, first.hash()).repaired(digest),
        Entry::new("x", "y", "z"),
    )
    .unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(d.0.join("audit.jsonl"))
        .unwrap()
        .write_all(b"\n")
        .unwrap();
    append(&d.0.join("audit.jsonl"), &second);
    assert_eq!(head(&reader), Head::of(&second));
    let unattested = entry(&first);
    fs::write(
        d.0.join("audit.jsonl"),
        [
            line(&first),
            gap.to_vec(),
            b"\n".to_vec(),
            line(&unattested),
        ]
        .concat(),
    )
    .unwrap();
    bad(
        TrailReader::open(&d.0, TRAIL, None),
        AuditErrorKind::CorruptTrail,
    );
    let wrong = Record::new(
        context(1, first.hash()).repaired([0; 32]),
        Entry::new("x", "y", "z"),
    )
    .unwrap();
    fs::write(
        d.0.join("audit.jsonl"),
        [line(&first), gap.to_vec(), b"\n".to_vec(), line(&wrong)].concat(),
    )
    .unwrap();
    bad(
        TrailReader::open(&d.0, TRAIL, None),
        AuditErrorKind::CorruptTrail,
    );
    let mut bytes = line(&first);
    bytes.pop();
    fs::write(d.0.join("audit.jsonl"), bytes).unwrap();
    let reader = open(&d.0);
    reader
        .with_current(
            |_| Ok(()),
            |_, _, s| {
                assert!(s.needs_newline());
                assert!(s.repair_digest().is_none());
                Ok(())
            },
        )
        .unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(d.0.join("audit.jsonl"))
        .unwrap()
        .write_all(b"\n")
        .unwrap();
    append(&d.0.join("audit.jsonl"), &unattested);
    assert_eq!(head(&reader), Head::of(&unattested));
    for invalid in [
        b" ".as_slice(),
        b"{bad}",
        b"{\"a\":\x01",
        b"\xff",
        b"null",
        b"{}",
        &[b'x'; 1],
    ] {
        fs::write(
            d.0.join("audit.jsonl"),
            [line(&first), invalid.to_vec()].concat(),
        )
        .unwrap();
        bad(
            TrailReader::open(&d.0, TRAIL, None),
            AuditErrorKind::CorruptTrail,
        );
    }
    fs::write(
        d.0.join("audit.jsonl"),
        [line(&first), vec![b'{'; 1_000_001]].concat(),
    )
    .unwrap();
    bad(
        TrailReader::open(&d.0, TRAIL, None),
        AuditErrorKind::CorruptTrail,
    );
}
#[test]
fn rotations_follow_old_descriptor_and_every_intervening_segment() {
    let d = Temp::new();
    let first = fixture(&d.0);
    let reader = open(&d.0);
    let mut mmr = Mmr::new();
    mmr.push(first.hash()).unwrap();
    let mut last = first.clone();
    for id in 0..3 {
        last = rotated(&d.0, &last, &mut mmr, id);
    }
    // A sealing crash can leave every byte of its closing JSON except LF.
    let sealed_path = d.0.join("audit-20260101T000000.000000000Z_000000.jsonl");
    let length = fs::metadata(&sealed_path).unwrap().len();
    fs::OpenOptions::new()
        .write(true)
        .open(&sealed_path)
        .unwrap()
        .set_len(length - 1)
        .unwrap();
    assert_eq!(head(&reader), Head::of(&last));
    assert!(TrailReader::open(&d.0, TRAIL, Some(Head::of(&first))).is_ok());
    fs::remove_file(d.0.join("audit-20260101T000000.000000000Z_000000.jsonl")).unwrap();
    bad(
        TrailReader::open(&d.0, TRAIL, Some(Head::of(&first))),
        AuditErrorKind::HeadMismatch,
    );
    // An archived prefix is allowed: the oldest remaining opening is self-contained.
    assert_eq!(head(&open(&d.0)), Head::of(&last));
    let lagging = open(&d.0);
    last = rotated(&d.0, &last, &mut mmr, 3);
    let old_length = fs::metadata(d.0.join("audit-20260101T000000.000000000Z_000003.jsonl"))
        .unwrap()
        .len();
    last = rotated(&d.0, &last, &mut mmr, 4);
    fs::remove_file(d.0.join("audit-20260101T000000.000000000Z_000004.jsonl")).unwrap();
    bad(
        lagging.with_current(|_| Ok(()), |_, _, _| Ok(())),
        AuditErrorKind::CorruptTrail,
    );
    assert!(old_length > 0);
    assert!(last.context.seq > 0);
}
#[test]
fn gap_requires_matching_resume_declaration() {
    let d = Temp::new();
    let first = fixture(&d.0);
    let mut mmr = Mmr::new();
    mmr.push(first.hash()).unwrap();
    let opening = cp(7, first.hash(), &mmr);
    let resume = Record::new(
        context(8, opening.hash()),
        Entry::new("operator", "vigil.audit.resume", "trail")
            .reason("incident")
            .details(format!(
                "head=0:{} lost_through=6 file=-",
                crate::audit::digest_string(&first.hash())
            )),
    )
    .unwrap();
    fs::write(
        d.0.join("audit.jsonl"),
        [line(&first), line(&opening)].concat(),
    )
    .unwrap();
    bad(
        TrailReader::open(&d.0, TRAIL, None),
        AuditErrorKind::CorruptTrail,
    );
    append(&d.0.join("audit.jsonl"), &entry(&opening));
    bad(
        TrailReader::open(&d.0, TRAIL, None),
        AuditErrorKind::CorruptTrail,
    );
    fs::write(
        d.0.join("audit.jsonl"),
        [line(&first), line(&opening), line(&resume)].concat(),
    )
    .unwrap();
    assert_eq!(head(&open(&d.0)), Head::of(&resume));
    let wrong = Record::new(
        context(8, opening.hash()),
        Entry::new("operator", "vigil.audit.resume", "trail")
            .details("head=0:blake3:00 lost_through=6 file=-"),
    )
    .unwrap();
    fs::write(
        d.0.join("audit.jsonl"),
        [line(&first), line(&opening), line(&wrong)].concat(),
    )
    .unwrap();
    bad(
        TrailReader::open(&d.0, TRAIL, None),
        AuditErrorKind::CorruptTrail,
    );
}
fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !path.exists() {
        assert!(Instant::now() < deadline, "missing {}", path.display());
        std::thread::yield_now();
    }
}
fn child(path: &Path, role: &str) -> std::process::Child {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "audit::format::storage::tests::child_role",
            "--nocapture",
        ])
        .env("VIGIL_READER_TEST_DIR", path)
        .env("VIGIL_READER_TEST_ROLE", role)
        .stdout(Stdio::null())
        .spawn()
        .unwrap()
}
fn finish(child: &mut std::process::Child) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "child: {status}");
            return;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("child timed out");
        }
        std::thread::yield_now();
    }
}
#[test]
fn child_role() {
    let Ok(path) = std::env::var("VIGIL_READER_TEST_DIR") else {
        return;
    };
    let path = PathBuf::from(path);
    let role = std::env::var("VIGIL_READER_TEST_ROLE").unwrap();
    let reader = open(&path);
    if role == "stress" {
        for _ in 0..60 {
            reader
                .with_current(
                    |_| Ok(()),
                    |_, file, s| {
                        let record = Record::new(
                            context(s.head.seq + 1, s.head.hash),
                            Entry::new(std::process::id().to_string(), "stress", "test"),
                        )
                        .unwrap();
                        let mut file = file;
                        file.write_all(&line(&record)).unwrap();
                        Ok(())
                    },
                )
                .unwrap();
        }
    } else {
        fs::write(path.join("ready"), b"").unwrap();
        wait_for(&path.join("go"));
        fs::write(path.join("waiting"), b"").unwrap();
        let result = reader.with_current(
            |_| Ok(()),
            |_, file, s| {
                let record = Record::new(
                    context(s.head.seq + 1, s.head.hash),
                    Entry::new("child", "replace", "test"),
                )
                .unwrap();
                let mut file = file;
                file.write_all(&line(&record)).unwrap();
                Ok(())
            },
        );
        if role == "directory" || role == "delete" {
            bad(result, AuditErrorKind::CorruptTrail);
        } else {
            result.unwrap();
        }
    }
}
#[test]
fn six_processes_serialize_one_trail() {
    let d = Temp::new();
    fixture(&d.0);
    let mut children: Vec<_> = (0..6).map(|_| child(&d.0, "stress")).collect();
    for child in &mut children {
        finish(child);
    }
    let start = Instant::now();
    let reader = open(&d.0);
    let scanned = start.elapsed();
    let start = Instant::now();
    assert_eq!(head(&reader).seq, 360);
    eprintln!(
        "B2a host scan of 361 records: {scanned:?}; unchanged refresh: {:?}",
        start.elapsed()
    );
}
#[test]
fn waiting_process_rechecks_replaced_file_and_directory_and_deleted_live() {
    for role in ["file", "directory", "delete"] {
        let d = Temp::new();
        let first = fixture(&d.0);
        let mut child = child(&d.0, role);
        wait_for(&d.0.join("ready"));
        let held = File::open(&d.0).unwrap();
        held.lock().unwrap();
        fs::write(d.0.join("go"), b"").unwrap();
        wait_for(&d.0.join("waiting"));
        let stale;
        if role == "file" {
            let mut mmr = Mmr::new();
            mmr.push(first.hash()).unwrap();
            rotated(&d.0, &first, &mut mmr, 0);
            stale = d.0.join("audit-20260101T000000.000000000Z_000000.jsonl");
        } else if role == "directory" {
            let old = d.0.join("old");
            // Swap the whole directory while retaining a bounded cleanup owner.
            let moved = d.0.with_extension("old");
            fs::rename(&d.0, &moved).unwrap();
            fs::create_dir(&d.0).unwrap();
            fixture(&d.0);
            fs::rename(moved, &old).unwrap();
            stale = old.join("audit.jsonl");
        } else {
            stale = d.0.join("deleted.jsonl");
            fs::rename(d.0.join("audit.jsonl"), &stale).unwrap();
        }
        let bytes = fs::read(&stale).unwrap();
        held.unlock().unwrap();
        finish(&mut child);
        assert_eq!(fs::read(stale).unwrap(), bytes);
        if role == "file" {
            assert_eq!(head(&open(&d.0)).seq, 3);
        }
    }
}
#[test]
fn audit_and_logs_share_handle_without_nesting_locks() {
    let d = Temp::new();
    fixture(&d.0);
    let logs =
        crate::rotate::RotatingFile::open(&d.0, "logs", crate::rotate::RotationConfig::default())
            .unwrap();
    let reader = open(&d.0);
    let duplicate = open(&d.0);
    for _ in 0..10 {
        logs.append(b"{}").unwrap();
        assert_eq!(head(&reader), head(&duplicate));
    }
    let locked = Directory::open(&d.0).unwrap();
    assert!(locked.shares_lock(&reader.directory));
    assert!(reader.directory.shares_lock(&duplicate.directory));
    locked.with_lock(|_| ()).unwrap();
}
