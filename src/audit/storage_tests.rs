use super::*;
use crate::{
    audit::{CheckpointFields, Entry, RecordContext},
    rotate::{RotatingFile, RotationConfig},
};
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
    let peaks = mmr.peaks().to_vec();
    let fields = CheckpointFields::new(mmr.size(), mmr.root(), peaks, [1; 32], [0; 64]).unwrap();
    Record::checkpoint(context(seq, previous), fields).unwrap()
}
fn line(record: &Record) -> Vec<u8> {
    use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
    let extra = AnyValue {
        value: Some(any_value::Value::StringValue("context".into())),
    };
    let mut line = crate::logs::encode_line(&crate::audit::format::request(record, extra).unwrap())
        .unwrap()
        .into_bytes();
    line.push(b'\n');
    line
}
fn seeded(first: &Record) -> Mmr {
    let mut mmr = Mmr::new();
    mmr.push(first.hash()).unwrap();
    mmr
}
fn append(path: &Path, record: &Record) {
    append_bytes(path, &line(record));
}
fn append_bytes(path: &Path, bytes: &[u8]) {
    fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(bytes)
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
fn reject<T>(result: Result<T, AuditError>) {
    bad(result, AuditErrorKind::CorruptTrail);
}
fn corrupt_open(path: &Path) {
    reject(TrailReader::open(path, TRAIL, None));
}
fn write_records(path: &Path, records: &[&Record]) {
    write(
        path,
        records.iter().flat_map(|r| line(r)).collect::<Vec<_>>(),
    );
}
fn write(path: &Path, bytes: impl AsRef<[u8]>) {
    fs::write(path.join("audit.jsonl"), bytes).unwrap();
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
#[test]
fn validates_chain_mmr_identity_structure_and_expected_head() {
    let d = Temp::new();
    let first = fixture(&d.0);
    let second = entry(&first);
    append(&d.0.join("audit.jsonl"), &second);
    assert_eq!(head(&open(&d.0)), Head::of(&second));
    assert!(TrailReader::open(&d.0, TRAIL, Some(Head::of(&first))).is_ok());
    let absent = Head {
        seq: 1,
        hash: [0; 32],
    };
    bad(
        TrailReader::open(&d.0, TRAIL, Some(absent)),
        AuditErrorKind::HeadMismatch,
    );
    reject(TrailReader::open(&d.0, [0; 16], None));
    let wrong = Record::new(context(1, [0; 32]), Entry::new("actor", "change", "object")).unwrap();
    write_records(&d.0, &[&first, &wrong]);
    corrupt_open(&d.0);
    let wrong = Record::checkpoint(
        context(2, second.hash()),
        CheckpointFields::new(2, [0; 32], vec![[0; 32]], [0; 32], [0; 64]).unwrap(),
    )
    .unwrap();
    write_records(&d.0, &[&first, &second, &wrong]);
    corrupt_open(&d.0);
    for bytes in [
        Vec::new(),
        line(&second),
        b"{\"torn\":".to_vec(),
        b"\n".to_vec(),
    ] {
        write(&d.0, bytes);
        corrupt_open(&d.0);
    }
    fs::remove_file(d.0.join("audit.jsonl")).unwrap();
    corrupt_open(&d.0);
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
    reject(reader.with_current(|_| Ok(()), |_, _, _| Ok(())));
    write(&d.0, line(&first));
    reject(reader.with_current(|_| Ok(()), |_, _, _| Ok(())));
}
#[test]
fn repaired_fragments_are_checked_and_complete_json_without_lf_is_not_a_gap() {
    let d = Temp::new();
    let first = fixture(&d.0);
    let gap = b"{\"first\":\"\xf0\x9f\n{\"second\":";
    append_bytes(&d.0.join("audit.jsonl"), gap);
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
    append_bytes(&d.0.join("audit.jsonl"), b"\n");
    append(&d.0.join("audit.jsonl"), &second);
    assert_eq!(head(&reader), Head::of(&second));
    let unattested = entry(&first);
    let wrong = Record::new(
        context(1, first.hash()).repaired([0; 32]),
        Entry::new("x", "y", "z"),
    )
    .unwrap();
    for record in [&unattested, &wrong] {
        write(
            &d.0,
            [line(&first), gap.to_vec(), b"\n".to_vec(), line(record)].concat(),
        );
        corrupt_open(&d.0);
    }
    let mut bytes = line(&first);
    bytes.pop();
    write(&d.0, bytes);
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
    append_bytes(&d.0.join("audit.jsonl"), b"\n");
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
        write(&d.0, [line(&first), invalid.to_vec()].concat());
        corrupt_open(&d.0);
    }
    write(
        &d.0,
        [line(&first), vec![b'{'; MAX_PAYLOAD_BYTES + 1]].concat(),
    );
    corrupt_open(&d.0);
}
#[test]
fn rotations_follow_old_descriptor_and_every_intervening_segment() {
    let d = Temp::new();
    let first = fixture(&d.0);
    let reader = open(&d.0);
    let mut mmr = seeded(&first);
    let mut last = first.clone();
    for id in 0..3 {
        last = rotated(&d.0, &last, &mut mmr, id);
    }
    // A sealing crash can leave every byte of its closing JSON except LF.
    let sealed_path = segment(&d.0, 0);
    let length = fs::metadata(&sealed_path).unwrap().len();
    fs::OpenOptions::new()
        .write(true)
        .open(&sealed_path)
        .unwrap()
        .set_len(length - 1)
        .unwrap();
    assert_eq!(head(&reader), Head::of(&last));
    assert!(TrailReader::open(&d.0, TRAIL, Some(Head::of(&first))).is_ok());
    fs::remove_file(segment(&d.0, 0)).unwrap();
    bad(
        TrailReader::open(&d.0, TRAIL, Some(Head::of(&first))),
        AuditErrorKind::HeadMismatch,
    );
    // An archived prefix is allowed: the oldest remaining opening is self-contained.
    assert_eq!(head(&open(&d.0)), Head::of(&last));
    let archived = open(&d.0);
    last = rotated(&d.0, &last, &mut mmr, 3);
    let lagging = open(&d.0);
    fs::remove_file(segment(&d.0, 3)).unwrap();
    assert_eq!(head(&archived), Head::of(&last));
    last = rotated(&d.0, &last, &mut mmr, 4);
    rotated(&d.0, &last, &mut mmr, 5);
    fs::remove_file(segment(&d.0, 5)).unwrap();
    reject(lagging.with_current(|_| Ok(()), |_, _, _| Ok(())));
}
#[test]
fn gap_requires_matching_resume_declaration() {
    let d = Temp::new();
    let first = fixture(&d.0);
    let mmr = seeded(&first);
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
    write_records(&d.0, &[&first, &opening]);
    corrupt_open(&d.0);
    append(&d.0.join("audit.jsonl"), &entry(&opening));
    corrupt_open(&d.0);
    write_records(&d.0, &[&first, &opening, &resume]);
    assert_eq!(head(&open(&d.0)), Head::of(&resume));
    let wrong = Record::new(
        context(8, opening.hash()),
        Entry::new("operator", "vigil.audit.resume", "trail")
            .details("head=0:blake3:00 lost_through=6 file=-"),
    )
    .unwrap();
    write_records(&d.0, &[&first, &opening, &wrong]);
    corrupt_open(&d.0);
}
fn write_child(file: &File, s: &State) -> Result<(), AuditError> {
    let record = Record::new(
        context(s.head.seq + 1, s.head.hash),
        Entry::new(std::process::id().to_string(), "child", "test"),
    )
    .unwrap();
    let mut file = file;
    file.write_all(&line(&record)).unwrap();
    Ok(())
}
fn would_block<T>(result: io::Result<T>) {
    assert_eq!(result.err().unwrap().kind(), io::ErrorKind::WouldBlock);
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
            "audit::storage::tests::child_role",
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
    if role == "reentrant" {
        let logs = RotatingFile::open(&path, "logs", RotationConfig::default()).unwrap();
        reader
            .with_current(
                |_| Ok(()),
                |_, _, _| {
                    would_block(logs.append(b"{}"));
                    Ok(())
                },
            )
            .unwrap();
        let directory = Directory::open(&path).unwrap();
        directory
            .with_lock(|_| {
                would_block(directory.with_lock(|_| ()));
            })
            .unwrap();
        logs.append(b"{}").unwrap();
    } else if role == "stress" {
        for _ in 0..60 {
            reader
                .with_current(|_| Ok(()), |_, file, s| write_child(file, s))
                .unwrap();
        }
    } else {
        fs::write(path.join("ready"), b"").unwrap();
        wait_for(&path.join("go"));
        fs::write(path.join("waiting"), b"").unwrap();
        let result = reader.with_current(|_| Ok(()), |_, file, s| write_child(file, s));
        if ["symlink", "directory", "delete"].contains(&role.as_str()) {
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
    assert_eq!(head(&open(&d.0)).seq, 360);
}
#[test]
fn waiting_process_rechecks_replaced_file_and_directory_and_deleted_live() {
    for role in ["file", "directory", "delete", "symlink"] {
        let d = Temp::new();
        let first = fixture(&d.0);
        let mut child = child(&d.0, role);
        wait_for(&d.0.join("ready"));
        let held = File::open(&d.0).unwrap();
        held.lock().unwrap();
        fs::write(d.0.join("go"), b"").unwrap();
        wait_for(&d.0.join("waiting"));
        let stale;
        if role == "file" || role == "symlink" {
            let mut mmr = Mmr::new();
            mmr.push(first.hash()).unwrap();
            rotated(&d.0, &first, &mut mmr, 0);
            stale = segment(&d.0, 0);
            if role == "symlink" {
                fs::remove_file(d.0.join("audit.jsonl")).unwrap();
                std::os::unix::fs::symlink(&stale, d.0.join("audit.jsonl")).unwrap();
            }
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
    let logs = RotatingFile::open(&d.0, "logs", RotationConfig::default()).unwrap();
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

#[test]
fn rotation_reads_only_new_data() {
    let d = Temp::new();
    let mut last = fixture(&d.0);
    let mut mmr = seeded(&last);
    for id in 0..20 {
        for _ in 0..200 {
            last = entry(&last);
            append(&d.0.join("audit.jsonl"), &last);
            mmr.push(last.hash()).unwrap();
        }
        last = rotated(&d.0, &last, &mut mmr, id);
    }
    let reader = open(&d.0);
    let before = fs::metadata(d.0.join("audit.jsonl")).unwrap().len();
    last = rotated(&d.0, &last, &mut mmr, 20);
    let added = fs::metadata(segment(&d.0, 20)).unwrap().len() - before
        + fs::metadata(d.0.join("audit.jsonl")).unwrap().len();
    SCANNED.with(|n| n.set(0));
    assert_eq!(head(&reader), Head::of(&last));
    let scanned = SCANNED.with(|n| n.get());
    let total: u64 = fs::read_dir(&d.0)
        .unwrap()
        .map(|p| p.unwrap().metadata().unwrap().len())
        .sum();
    eprintln!("rotation bytes scanned={scanned}, new={added}, trail={total}");
    assert_eq!(scanned as u64, added);
}
#[test]
fn newer_fork_is_rejected_by_cached_and_fresh_readers() {
    let d = Temp::new();
    let first = fixture(&d.0);
    let reader = open(&d.0);
    let mut mmr = seeded(&first);
    rotated(&d.0, &first, &mut mmr, 0);
    fs::write(segment(&d.0, 1), line(&first)).unwrap();
    reject(reader.with_current(|_| Ok(()), |_, _, _| Ok(())));
    corrupt_open(&d.0);
}
#[test]
fn nonregular_segments_are_structural_corruption() {
    for kind in ["symlink", "directory", "fifo"] {
        let d = Temp::new();
        fixture(&d.0);
        let path = segment(&d.0, 0);
        match kind {
            "symlink" => std::os::unix::fs::symlink(d.0.join("audit.jsonl"), &path).unwrap(),
            "directory" => fs::create_dir(&path).unwrap(),
            _ => assert!(
                Command::new("mkfifo")
                    .arg(&path)
                    .status()
                    .unwrap()
                    .success()
            ),
        }
        corrupt_open(&d.0);
    }
}
#[test]
fn callback_lock_reentry_returns_would_block() {
    let d = Temp::new();
    fixture(&d.0);
    finish(&mut child(&d.0, "reentrant"));
}
