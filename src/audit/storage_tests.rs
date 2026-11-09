use super::*;
use crate::{
    audit::{CheckpointFields, Entry, Mmr, RecordContext, runs::RunState},
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
        .with_current(|_| Ok(()), |_, _, s| Ok(s.run.head))
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
    let resume = Record::new_internal(
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
    let wrong = Record::new_internal(
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
        context(s.run.head.seq + 1, s.run.head.hash),
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
    use std::io::Write;
    let _ = writeln!(
        std::io::stderr().lock(),
        "rotation bytes scanned={scanned}, new={added}, trail={total}"
    );
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

fn resumed(path: &Path, last: &Record, mmr: &mut Mmr, id: usize, lost: u64) -> Record {
    fs::rename(path.join("audit.jsonl"), segment(path, id)).unwrap();
    let opening = cp(lost + 1, last.hash(), mmr);
    let resume = Record::new_internal(
        context(lost + 2, opening.hash()),
        Entry::new("operator", "vigil.audit.resume", "trail")
            .reason("incident")
            .details(format!(
                "head={}:{} lost_through={lost} file={}",
                last.context.seq,
                crate::audit::digest_string(&last.hash()),
                segment(path, id).file_name().unwrap().to_str().unwrap()
            )),
    )
    .unwrap();
    write_records(path, &[&opening, &resume]);
    mmr.push(opening.hash()).unwrap();
    mmr.push(resume.hash()).unwrap();
    resume
}
fn resume_layout(torn: bool, lost: u64) {
    let d = Temp::new();
    let first = fixture(&d.0);
    let last = entry(&first);
    append(&d.0.join("audit.jsonl"), &last);
    let reader = open(&d.0);
    let lagging = open(&d.0);
    let mut mmr = seeded(&first);
    mmr.push(last.hash()).unwrap();
    if torn {
        append_bytes(&d.0.join("audit.jsonl"), b"{\"torn\":");
    }
    let bytes = fs::read(d.0.join("audit.jsonl")).unwrap();
    let resume = resumed(&d.0, &last, &mut mmr, 0, lost);
    assert_eq!(head(&reader), Head::of(&resume));
    assert_eq!(
        head(&TrailReader::open(&d.0, TRAIL, Some(Head::of(&resume))).unwrap()),
        Head::of(&resume)
    );
    assert_eq!(fs::read(segment(&d.0, 0)).unwrap(), bytes);
    let next = rotated(&d.0, &resume, &mut mmr, 1);
    assert_eq!(head(&lagging), Head::of(&next));
    assert_eq!(head(&open(&d.0)), Head::of(&next));
}
#[test]
fn resume_after_rollback_accepts_unclosed_segment() {
    resume_layout(false, 7);
}
#[test]
fn resume_after_torn_tail_accepts_unchanged_segment() {
    resume_layout(true, 1);
}
#[test]
fn missing_closure_requires_matching_immediate_resume() {
    let d = Temp::new();
    let first = fixture(&d.0);
    let last = entry(&first);
    append(&d.0.join("audit.jsonl"), &last);
    let reader = open(&d.0);
    let mut mmr = seeded(&first);
    mmr.push(last.hash()).unwrap();
    let resume = resumed(&d.0, &last, &mut mmr, 0, 1);
    assert_eq!(head(&open(&d.0)), Head::of(&resume));
    let opening = cp(2, last.hash(), &seeded_pair(&first, &last));
    for records in [vec![&opening], vec![&opening, &entry(&opening)]] {
        write_records(&d.0, &records);
        reject(reader.with_current(|_| Ok(()), |_, _, _| Ok(())));
        corrupt_open(&d.0);
    }
    let wrong = Record::new_internal(
        context(3, opening.hash()),
        Entry::new("operator", "vigil.audit.resume", "trail")
            .details("head=1:blake3:00 lost_through=1 file=-"),
    )
    .unwrap();
    write_records(&d.0, &[&opening, &wrong]);
    reject(reader.with_current(|_| Ok(()), |_, _, _| Ok(())));
    corrupt_open(&d.0);
}
fn seeded_pair(first: &Record, last: &Record) -> Mmr {
    let mut mmr = seeded(first);
    mmr.push(last.hash()).unwrap();
    mmr
}
#[test]
fn older_named_fork_is_outside_cached_history_validation() {
    let d = Temp::new();
    let first = fixture(&d.0);
    let reader = open(&d.0);
    let mut mmr = seeded(&first);
    let last = rotated(&d.0, &first, &mut mmr, 1);
    fs::write(segment(&d.0, 0), line(&first)).unwrap();
    assert_eq!(head(&reader), Head::of(&last));
    corrupt_open(&d.0);
}
#[test]
fn sealed_segment_is_read_only_even_when_live_is_writable() {
    use std::os::unix::fs::PermissionsExt;
    let d = Temp::new();
    let first = fixture(&d.0);
    let reader = open(&d.0);
    let mut mmr = seeded(&first);
    let last = rotated(&d.0, &first, &mut mmr, 0);
    fs::set_permissions(segment(&d.0, 0), fs::Permissions::from_mode(0o400)).unwrap();
    assert_eq!(head(&reader), Head::of(&last));
    assert_eq!(head(&open(&d.0)), Head::of(&last));
}
#[test]
fn intervening_segment_without_closure_or_resume_is_rejected() {
    let d = Temp::new();
    let first = fixture(&d.0);
    let reader = open(&d.0);
    let mut mmr = seeded(&first);
    let opening = rotated(&d.0, &first, &mut mmr, 0);
    let last = entry(&opening);
    append(&d.0.join("audit.jsonl"), &last);
    mmr.push(last.hash()).unwrap();
    fs::rename(d.0.join("audit.jsonl"), segment(&d.0, 1)).unwrap();
    let next = cp(last.context.seq + 1, last.hash(), &mmr);
    write_records(&d.0, &[&next, &entry(&next)]);
    reject(reader.with_current(|_| Ok(()), |_, _, _| Ok(())));
    corrupt_open(&d.0);
}

fn declaration(
    opening: &Record,
    seq: u64,
    hash: [u8; 32],
    lost: u64,
    repaired: Option<[u8; 32]>,
) -> Record {
    let mut ctx = context(opening.context.seq + 1, opening.hash());
    if let Some(digest) = repaired {
        ctx = ctx.repaired(digest);
    }
    Record::new_internal(
        ctx,
        Entry::new("operator", "vigil.audit.resume", "trail")
            .reason("incident")
            .details(format!(
                "head={seq}:{} lost_through={lost} file=-",
                crate::audit::digest_string(&hash)
            )),
    )
    .unwrap()
}
#[test]
fn resume_rejects_wrong_loss_bound() {
    let d = Temp::new();
    let first = fixture(&d.0);
    let opening = cp(7, first.hash(), &seeded(&first));
    let wrong = declaration(&opening, 0, first.hash(), 5, None);
    write_records(&d.0, &[&first, &opening, &wrong]);
    corrupt_open(&d.0);
}
#[test]
fn resume_rejects_predecessor_sequence_mismatch_with_right_hash() {
    let d = Temp::new();
    let first = fixture(&d.0);
    let opening = cp(7, first.hash(), &seeded(&first));
    let wrong = declaration(&opening, 1, first.hash(), 6, None);
    write_records(&d.0, &[&first, &opening, &wrong]);
    corrupt_open(&d.0);
}
#[test]
fn archived_resume_rejects_head_sequence_at_opening_with_right_hash() {
    let d = Temp::new();
    let first = fixture(&d.0);
    // An archived prefix has no checkpoint_predecessor; the upper bound is
    // independently necessary even when the previous hash and loss bound match.
    let opening = cp(7, first.hash(), &seeded(&first));
    let wrong = declaration(&opening, 7, first.hash(), 6, None);
    write_records(&d.0, &[&opening, &wrong]);
    corrupt_open(&d.0);
}
fn reject_both(reader: &TrailReader, path: &Path) {
    let running = reader
        .with_current(|_| Ok(()), |_, _, _| Ok(()))
        .err()
        .map(|e| e.kind());
    let fresh = TrailReader::open(path, TRAIL, None).err().map(|e| e.kind());
    assert_eq!(
        (running, fresh),
        (
            Some(AuditErrorKind::CorruptTrail),
            Some(AuditErrorKind::CorruptTrail)
        )
    );
}
#[test]
fn closed_segment_with_fragment_requires_resume_in_fresh_and_running_readers() {
    let d = Temp::new();
    let first = fixture(&d.0);
    let reader = open(&d.0);
    let mut mmr = seeded(&first);
    let opening = rotated(&d.0, &first, &mut mmr, 0);
    append_bytes(&segment(&d.0, 0), b"{\"torn\":");
    append(&d.0.join("audit.jsonl"), &entry(&opening));
    reject_both(&reader, &d.0);
}
#[test]
fn resume_rejects_attested_fragment_between_opening_and_declaration() {
    let d = Temp::new();
    let first = fixture(&d.0);
    let last = entry(&first);
    append(&d.0.join("audit.jsonl"), &last);
    let reader = open(&d.0);
    fs::rename(d.0.join("audit.jsonl"), segment(&d.0, 0)).unwrap();
    let opening = cp(2, last.hash(), &seeded_pair(&first, &last));
    let gap = b"{\"torn\":\n";
    let mut digest = blake3::Hasher::new();
    digest.update(b"vigil.audit.v1.repaired\0");
    digest.update(gap);
    let resume = declaration(
        &opening,
        1,
        last.hash(),
        1,
        Some(*digest.finalize().as_bytes()),
    );
    write(&d.0, [line(&opening), gap.to_vec(), line(&resume)].concat());
    reject_both(&reader, &d.0);
}

#[test]
fn resume_rejects_loss_bound_above_opening_bound() {
    let d = Temp::new();
    let first = fixture(&d.0);
    let opening = cp(7, first.hash(), &seeded(&first));
    let wrong = declaration(&opening, 0, first.hash(), 7, None);
    write_records(&d.0, &[&first, &opening, &wrong]);
    corrupt_open(&d.0);
}
#[test]
fn resume_rejects_head_sequence_below_predecessor_with_right_hash() {
    let d = Temp::new();
    let first = fixture(&d.0);
    let predecessor = entry(&first);
    let opening = cp(7, predecessor.hash(), &seeded_pair(&first, &predecessor));
    let wrong = declaration(&opening, 0, predecessor.hash(), 6, None);
    write_records(&d.0, &[&first, &predecessor, &opening, &wrong]);
    corrupt_open(&d.0);
}
#[test]
fn archived_resume_rejects_head_sequence_above_opening_with_right_hash() {
    let d = Temp::new();
    let first = fixture(&d.0);
    let opening = cp(7, first.hash(), &seeded(&first));
    let wrong = declaration(&opening, 8, first.hash(), 6, None);
    write_records(&d.0, &[&opening, &wrong]);
    corrupt_open(&d.0);
}

#[test]
fn genesis_resume_requires_immediate_matching_declaration() {
    let d = Temp::new();
    fixture(&d.0);
    let genesis = Record::genesis(&TRAIL);
    let mut fold = Mmr::new();
    fold.push(genesis).unwrap();
    let opening = cp(5, genesis, &fold);
    // Leaf validation is exercised by genesis_resume_checks_fold_leaf_in_both_reader_paths.
    let resume = declaration(&opening, 0, genesis, 4, None);
    write_records(&d.0, &[&opening]);
    corrupt_open(&d.0);
    write_records(&d.0, &[&opening, &entry(&opening)]);
    corrupt_open(&d.0);
    let wrong = declaration(&opening, 0, [42; 32], 4, None);
    write_records(&d.0, &[&opening, &wrong]);
    corrupt_open(&d.0);
    write_records(&d.0, &[&opening, &resume]);
    assert_eq!(head(&open(&d.0)), Head::of(&resume));
}

mod runs {
    use super::*;
    use crate::audit::{KeyFileSigner, Signer};

    // All checkpoints here have real signatures from the test-only constructor.
    fn signed(seq: u64, previous: [u8; 32], mmr: &Mmr) -> Record {
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
        let record = Record::checkpoint(context(seq, previous), fields(signature)).unwrap();
        crate::audit::verify_signature(
            &key.public_key(),
            &record.signing_message().unwrap(),
            &signature,
        )
        .unwrap();
        record
    }
    fn base(d: &Temp) -> Record {
        let first = signed(0, Record::genesis(&TRAIL), &Mmr::new());
        write_records(&d.0, &[&first]);
        first
    }
    fn put(d: &Temp, id: usize, records: &[&Record], suffix: &[u8]) {
        let mut bytes: Vec<_> = records.iter().flat_map(|r| line(r)).collect();
        bytes.extend(suffix);
        fs::write(segment(&d.0, id), bytes).unwrap();
    }
    fn close_run(d: &Temp, last: &Record, fold: &Mmr) -> (Record, Record) {
        let checkpoint = signed(last.context.seq + 4, last.hash(), fold);
        let resume = declaration(
            &checkpoint,
            last.context.seq,
            last.hash(),
            checkpoint.context.seq - 1,
            None,
        );
        write_records(&d.0, &[&checkpoint, &resume]);
        (checkpoint, resume)
    }
    fn headless(first: &Record, seq: u64) -> Record {
        Record::new(
            context(seq, entry(first).hash()),
            Entry::new("actor", "change", "object"),
        )
        .unwrap()
    }
    #[test]
    fn run_lengths_one_and_two_fold_every_present_record() {
        for length in [1, 2] {
            let d = Temp::new();
            let first = base(&d);
            put(&d, 0, &[&first], &[]);
            let mut fold = seeded(&first);
            let mut last = first.clone();
            for id in 1..=length {
                // Lost opening checkpoint and earlier records: the segment's
                // first surviving hash link and sequence both jump.
                last = headless(&last, last.context.seq + 5);
                put(&d, id, &[&last], &[]);
                fold.push(last.hash()).unwrap();
            }
            let (_, resume) = close_run(&d, &last, &fold);
            assert_eq!(head(&open(&d.0)), Head::of(&resume));
        }
    }
    #[test]
    fn fragment_only_segment_belongs_to_run() {
        let d = Temp::new();
        let first = base(&d);
        put(&d, 0, &[&first], &[]);
        put(&d, 1, &[], b"{\"torn\":");
        let (_, resume) = close_run(&d, &first, &seeded(&first));
        assert_eq!(head(&open(&d.0)), Head::of(&resume));
    }
    #[test]
    fn unparsable_last_line_is_sealed_evidence() {
        let d = Temp::new();
        let first = base(&d);
        put(&d, 0, &[&first], b"not json\n");
        let (_, resume) = close_run(&d, &first, &seeded(&first));
        assert_eq!(head(&open(&d.0)), Head::of(&resume));
    }
    #[test]
    fn honest_periodic_checkpoint_inside_headless_segment_is_only_a_leaf() {
        let d = Temp::new();
        let first = base(&d);
        put(&d, 0, &[&first], &[]);
        let missing = entry(&first);
        let kept = entry(&missing);
        let mut honest = seeded_pair(&first, &missing);
        honest.push(kept.hash()).unwrap();
        let periodic = signed(3, kept.hash(), &honest);
        put(&d, 1, &[&kept, &periodic], &[]);
        let mut fold = seeded_pair(&first, &kept);
        fold.push(periodic.hash()).unwrap();
        let (_, resume) = close_run(&d, &periodic, &fold);
        assert_eq!(head(&open(&d.0)), Head::of(&resume));
    }
    #[test]
    fn first_present_record_must_be_checkpoint_even_if_checkpoint_follows() {
        let d = Temp::new();
        let first = base(&d);
        let kept = entry(&first);
        let periodic = signed(2, kept.hash(), &seeded_pair(&first, &kept));
        put(&d, 0, &[&kept, &periodic], &[]);
        let Kind::Checkpoint(cp) = &periodic.kind else {
            panic!("checkpoint");
        };
        let mut alternative_base = Mmr::from_peaks(cp.size, cp.peaks.clone()).unwrap();
        alternative_base.push(periodic.hash()).unwrap();
        close_run(&d, &periodic, &alternative_base);
        corrupt_open(&d.0);
    }
    #[test]
    fn genesis_resume_after_fragment_only_first_segment_keeps_creation_leaf() {
        let d = Temp::new();
        base(&d);
        put(&d, 0, &[], b"{\"torn\":");
        let mut fold = Mmr::new();
        fold.push(Record::genesis(&TRAIL)).unwrap();
        let checkpoint = signed(5, Record::genesis(&TRAIL), &fold);
        // Leaf validation is exercised by genesis_resume_checks_fold_leaf_in_both_reader_paths.
        let resume = declaration(&checkpoint, 0, Record::genesis(&TRAIL), 4, None);
        write_records(&d.0, &[&checkpoint, &resume]);
        assert_eq!(head(&open(&d.0)), Head::of(&resume));
        assert_eq!(open(&d.0).cache.lock().unwrap().state.run.mmr.size(), 3);
    }
    #[test]
    fn closing_segment_can_start_second_run() {
        let d = Temp::new();
        let first = base(&d);
        put(&d, 0, &[&first], &[]);
        let kept = headless(&first, 3);
        put(&d, 1, &[&kept], &[]);
        let mut fold = seeded_pair(&first, &kept);
        let (checkpoint, resume) = close_run(&d, &kept, &fold);
        put(&d, 2, &[&checkpoint, &resume], b"broken\n");
        fold.push(checkpoint.hash()).unwrap();
        fold.push(resume.hash()).unwrap();
        let (_, last) = close_run(&d, &resume, &fold);
        assert_eq!(head(&open(&d.0)), Head::of(&last));
    }
    #[test]
    fn second_loss_keeps_first_run_acceptable() {
        let d = Temp::new();
        let first = base(&d);
        put(&d, 0, &[&first], &[]);
        let kept = headless(&first, 3);
        put(&d, 1, &[&kept], &[]);
        let mut fold = seeded_pair(&first, &kept);
        let (checkpoint, resume) = close_run(&d, &kept, &fold);
        assert_eq!(head(&open(&d.0)), Head::of(&resume));
        put(&d, 2, &[&checkpoint, &resume], &[]);
        fold.push(checkpoint.hash()).unwrap();
        fold.push(resume.hash()).unwrap();
        let second = headless(&resume, resume.context.seq + 3);
        put(&d, 3, &[&second], &[]);
        fold.push(second.hash()).unwrap();
        let (_, last) = close_run(&d, &second, &fold);
        assert_eq!(head(&open(&d.0)), Head::of(&last));
    }
    fn attack_fixture() -> (Temp, Record, Record, Record, Mmr) {
        let d = Temp::new();
        let first = base(&d);
        put(&d, 0, &[&first], &[]);
        let lost = entry(&first);
        let kept = entry(&lost);
        let last = entry(&kept);
        put(&d, 1, &[&kept, &last], &[]);
        let mut fold = seeded_pair(&first, &kept);
        fold.push(last.hash()).unwrap();
        close_run(&d, &last, &fold);
        (d, first, kept, last, fold)
    }
    #[test]
    fn prefix_deletion_changes_fold_condition_iii() {
        let (d, _, _, last, _) = attack_fixture();
        put(&d, 1, &[&last], &[]);
        corrupt_open(&d.0);
    }
    #[test]
    fn middle_segment_deletion_changes_fold_condition_iii() {
        let (d, _, kept, last, _) = attack_fixture();
        put(&d, 1, &[&kept], &[]);
        put(&d, 2, &[&last], &[]);
        fs::remove_file(segment(&d.0, 1)).unwrap();
        corrupt_open(&d.0);
    }
    #[test]
    fn middle_gap_in_run_segment_is_corrupt_even_with_intact_link() {
        let (d, first, kept, _, _) = attack_fixture();
        let gap = Record::new(
            context(kept.context.seq + 2, kept.hash()),
            Entry::new("actor", "change", "object"),
        )
        .unwrap();
        put(&d, 1, &[&kept, &gap], &[]);
        let fold = {
            let mut f = seeded_pair(&first, &kept);
            f.push(gap.hash()).unwrap();
            f
        };
        close_run(&d, &gap, &fold);
        corrupt_open(&d.0);
    }
    #[test]
    fn opening_must_link_last_present_head_condition_i() {
        let (d, _, _, last, fold) = attack_fixture();
        let checkpoint = signed(last.context.seq + 4, [91; 32], &fold);
        let resume = declaration(
            &checkpoint,
            last.context.seq,
            [91; 32],
            checkpoint.context.seq - 1,
            None,
        );
        write_records(&d.0, &[&checkpoint, &resume]);
        corrupt_open(&d.0);
    }
    #[test]
    fn opening_requires_immediate_resume_condition_ii() {
        let (d, _, _, last, fold) = attack_fixture();
        let checkpoint = signed(last.context.seq + 1, last.hash(), &fold);
        write_records(&d.0, &[&checkpoint, &entry(&checkpoint)]);
        corrupt_open(&d.0);
    }
    #[test]
    fn wrong_head_two_resumes_and_delayed_resume_are_corrupt() {
        let (d, _, _, last, fold) = attack_fixture();
        let (checkpoint, resume) = close_run(&d, &last, &fold);
        let wrong = declaration(
            &checkpoint,
            last.context.seq - 1,
            last.hash(),
            checkpoint.context.seq - 1,
            None,
        );
        write_records(&d.0, &[&checkpoint, &wrong]);
        corrupt_open(&d.0);
        let twice = Record::new_internal(
            context(resume.context.seq + 1, resume.hash()),
            Entry::new("operator", "vigil.audit.resume", "trail")
                .details("head=0:blake3:00 lost_through=0 file=-"),
        )
        .unwrap();
        write_records(&d.0, &[&checkpoint, &resume, &twice]);
        corrupt_open(&d.0);
        let intervening = entry(&checkpoint);
        let delayed = Record::new_internal(
            context(intervening.context.seq + 1, intervening.hash()),
            Entry::new("operator", "vigil.audit.resume", "trail")
                .details("head=0:blake3:00 lost_through=0 file=-"),
        )
        .unwrap();
        write_records(&d.0, &[&checkpoint, &intervening, &delayed]);
        corrupt_open(&d.0);
    }
    #[test]
    fn never_rotated_creation_loss_requires_moving_evidence_then_settles_resume() {
        use crate::audit::sink::{Config, Sink};
        use std::sync::Arc;
        let d = Temp::new();
        let creation = base(&d);
        let kept = entry(&creation);
        fs::write(
            d.0.join("audit.trail"),
            format!("{}\n", crate::audit::hex(&TRAIL)),
        )
        .unwrap();
        write_records(&d.0, &[&kept]);
        corrupt_open(&d.0);
        fs::rename(d.0.join("audit.jsonl"), d.0.join("incident.evidence")).unwrap();
        let mut fold = Mmr::new();
        fold.push(Record::genesis(&TRAIL)).unwrap();
        let checkpoint = signed(5, Record::genesis(&TRAIL), &fold);
        // Leaf validation is exercised by genesis_resume_checks_fold_leaf_in_both_reader_paths.
        let resume = declaration(&checkpoint, 0, Record::genesis(&TRAIL), 4, None);
        let staged = [line(&checkpoint), line(&resume)].concat();
        fs::write(d.0.join(".audit-resume.jsonl"), &staged).unwrap();
        let sink = Sink::open(
            &d.0,
            Arc::new(KeyFileSigner::from_hex(&"27".repeat(32)).unwrap()),
            Config::default(),
            Some(Head::of(&resume)),
        )
        .unwrap();
        assert_eq!(fs::read(d.0.join("audit.jsonl")).unwrap(), staged);
        assert!(!d.0.join(".audit-resume.jsonl").exists());
        assert_eq!(head(&open(&d.0)), Head::of(&resume));
        sink.close().unwrap();
        assert_eq!(
            fs::read(d.0.join("incident.evidence")).unwrap(),
            line(&kept)
        );
    }
    #[test]
    fn cached_reader_observes_unparsable_tail_and_new_headless_segments() {
        let d = Temp::new();
        let first = base(&d);
        let reader = open(&d.0);
        // Keep the inode that the reader holds, as an actual resume does.
        fs::rename(d.0.join("audit.jsonl"), segment(&d.0, 0)).unwrap();
        append_bytes(&segment(&d.0, 0), b"broken\n");
        let kept = headless(&first, 4);
        put(&d, 1, &[&kept], &[]);
        let (_, resume) = close_run(&d, &kept, &seeded_pair(&first, &kept));
        assert_eq!(head(&reader), Head::of(&resume));
        assert_eq!(head(&open(&d.0)), Head::of(&resume));
    }
    #[test]
    fn ordinary_gap_rules_resume_after_a_closed_run() {
        let (d, _, _, last, mut fold) = attack_fixture();
        let (opening, resume) = close_run(&d, &last, &fold);
        fold.push(opening.hash()).unwrap();
        fold.push(resume.hash()).unwrap();
        let next = signed(resume.context.seq + 3, resume.hash(), &fold);
        let declaration = declaration(
            &next,
            resume.context.seq,
            resume.hash(),
            next.context.seq - 1,
            None,
        );
        fold.push(next.hash()).unwrap();
        fold.push(declaration.hash()).unwrap();
        let closing = signed(declaration.context.seq + 1, declaration.hash(), &fold);
        put(
            &d,
            2,
            &[&opening, &resume, &next, &declaration, &closing],
            &[],
        );
        fold.push(closing.hash()).unwrap();
        let live = signed(closing.context.seq + 1, closing.hash(), &fold);
        write_records(&d.0, &[&live]);
        assert_eq!(head(&open(&d.0)), Head::of(&live));
    }
    #[test]
    fn checkpoint_after_run_closure_still_checks_mmr_outside_runs() {
        let (d, _, _, last, mut fold) = attack_fixture();
        let (opening, resume) = close_run(&d, &last, &fold);
        let wrong = signed(resume.context.seq + 1, resume.hash(), &fold);
        put(&d, 2, &[&opening, &resume, &wrong], &[]);
        fold.push(opening.hash()).unwrap();
        fold.push(resume.hash()).unwrap();
        fold.push(wrong.hash()).unwrap();
        let live = signed(wrong.context.seq + 1, wrong.hash(), &fold);
        write_records(&d.0, &[&live]);
        corrupt_open(&d.0);
    }
    #[test]
    fn staging_settlement_uses_the_same_run_fold() {
        use crate::audit::sink::{Config, Sink};
        use std::sync::Arc;
        for resume_stage in [false, true] {
            let (d, _, _, last, mut fold) = attack_fixture();
            fs::write(
                d.0.join("audit.trail"),
                format!("{}\n", crate::audit::hex(&TRAIL)),
            )
            .unwrap();
            let (opening, resume) = close_run(&d, &last, &fold);
            let expected = if resume_stage {
                fs::rename(d.0.join("audit.jsonl"), d.0.join(".audit-resume.jsonl")).unwrap();
                resume
            } else {
                fold.push(opening.hash()).unwrap();
                fold.push(resume.hash()).unwrap();
                let closing = signed(resume.context.seq + 1, resume.hash(), &fold);
                write_records(&d.0, &[&opening, &resume, &closing]);
                fold.push(closing.hash()).unwrap();
                let next = signed(closing.context.seq + 1, closing.hash(), &fold);
                fs::write(d.0.join(".audit-next.jsonl"), line(&next)).unwrap();
                next
            };
            let sink = Sink::open(
                &d.0,
                Arc::new(KeyFileSigner::from_hex(&"27".repeat(32)).unwrap()),
                Config::default(),
                Some(Head::of(&expected)),
            )
            .unwrap();
            assert_eq!(head(&open(&d.0)), Head::of(&expected));
            assert!(!d.0.join(".audit-next.jsonl").exists());
            assert!(!d.0.join(".audit-resume.jsonl").exists());
            sink.close().unwrap();
        }
    }
    #[test]
    fn record_free_first_run_requires_genesis_link_at_its_own_base() {
        let d = Temp::new();
        let creation = base(&d);
        put(&d, 0, &[], b"{\"torn\":");
        let opening = signed(7, [42; 32], &seeded(&creation));
        let resume = declaration(&opening, 0, [42; 32], 6, None);
        write_records(&d.0, &[&opening, &resume]);
        corrupt_open(&d.0);
    }
    fn successor_probe(wrong_mmr: bool) {
        {
            let d = Temp::new();
            let first = base(&d);
            put(&d, 0, &[&first], &[]);
            let kept = headless(&first, 3);
            put(&d, 1, &[&kept], &[]);
            let mut fold = seeded_pair(&first, &kept);
            let wrong_fold = seeded(&first);
            let checkpoint = signed(
                if wrong_mmr { 7 } else { 4 },
                kept.hash(),
                if wrong_mmr { &wrong_fold } else { &fold },
            );
            let next = if wrong_mmr {
                declaration(&checkpoint, 3, kept.hash(), 6, None)
            } else {
                entry(&checkpoint)
            };
            put(&d, 2, &[&checkpoint, &next], &[]);
            fold.push(checkpoint.hash()).unwrap();
            fold.push(next.hash()).unwrap();
            let live = signed(9, next.hash(), &fold);
            let resume = declaration(&live, next.context.seq, next.hash(), 8, None);
            write_records(&d.0, &[&live, &resume]);
            corrupt_open(&d.0);
        }
    }
    #[test]
    fn first_successor_cannot_defer_missing_resume() {
        successor_probe(false);
    }
    #[test]
    fn first_successor_cannot_defer_wrong_mmr() {
        successor_probe(true);
    }
    fn checkpoint_ended_run(d: &Temp) -> (Record, Mmr) {
        let first = base(d);
        put(d, 0, &[&first], &[]);
        let kept = headless(&first, 3);
        let fold = seeded_pair(&first, &kept);
        let periodic = signed(4, kept.hash(), &fold);
        put(d, 1, &[&kept, &periodic], &[]);
        let mut fold = fold;
        fold.push(periodic.hash()).unwrap();
        (periodic, fold)
    }
    #[test]
    fn checkpoint_ended_run_requires_resume_on_open() {
        let d = Temp::new();
        let (last, fold) = checkpoint_ended_run(&d);
        let opening = signed(5, last.hash(), &fold);
        write_records(&d.0, &[&opening, &entry(&opening)]);
        corrupt_open(&d.0);
    }
    #[test]
    fn checkpoint_ended_run_requires_resume_on_refresh() {
        let d = Temp::new();
        let first = base(&d);
        let reader = open(&d.0);
        fs::rename(d.0.join("audit.jsonl"), segment(&d.0, 0)).unwrap();
        let kept = headless(&first, 3);
        let mut fold = seeded_pair(&first, &kept);
        let periodic = signed(4, kept.hash(), &fold);
        put(&d, 1, &[&kept, &periodic], &[]);
        fold.push(periodic.hash()).unwrap();
        let opening = signed(5, periodic.hash(), &fold);
        write_records(&d.0, &[&opening, &entry(&opening)]);
        assert_eq!(
            reader
                .with_current(|_| Ok(()), |_, _, _| Ok(()))
                .unwrap_err()
                .kind(),
            AuditErrorKind::CorruptTrail
        );
    }
    #[test]
    fn checkpoint_ended_run_rejects_single_checkpoint_staging() {
        use crate::audit::sink::{Config, Sink};
        use std::sync::Arc;
        let d = Temp::new();
        let (last, fold) = checkpoint_ended_run(&d);
        fs::write(
            d.0.join("audit.trail"),
            format!("{}\n", crate::audit::hex(&TRAIL)),
        )
        .unwrap();
        fs::remove_file(d.0.join("audit.jsonl")).unwrap();
        let opening = signed(5, last.hash(), &fold);
        fs::write(d.0.join(".audit-next.jsonl"), line(&opening)).unwrap();
        assert!(
            Sink::open(
                &d.0,
                Arc::new(KeyFileSigner::from_hex(&"27".repeat(32)).unwrap()),
                Config::default(),
                None
            )
            .is_err()
        );
        assert!(!d.0.join("audit.jsonl").exists());
    }
    #[test]
    fn internal_checkpoint_gap_and_resume_are_corrupt() {
        let d = Temp::new();
        let first = base(&d);
        put(&d, 0, &[&first], &[]);
        let kept = headless(&first, 3);
        let mut fold = seeded_pair(&first, &kept);
        let gap = signed(7, kept.hash(), &fold);
        let resume = declaration(&gap, 3, kept.hash(), 6, None);
        put(&d, 1, &[&kept, &gap, &resume], &[]);
        fold.push(gap.hash()).unwrap();
        fold.push(resume.hash()).unwrap();
        close_run(&d, &resume, &fold);
        corrupt_open(&d.0);
    }
    #[test]
    fn fallback_requires_fragment_attestation() {
        let d = Temp::new();
        let first = base(&d);
        put(&d, 0, &[&first], &[]);
        let kept = headless(&first, 3);
        let next = entry(&kept);
        let bytes = [line(&kept), b"{\"torn\":\n".to_vec(), line(&next)].concat();
        fs::write(segment(&d.0, 1), bytes).unwrap();
        let mut fold = seeded_pair(&first, &kept);
        fold.push(next.hash()).unwrap();
        close_run(&d, &next, &fold);
        corrupt_open(&d.0);
    }
    #[test]
    fn identical_duplicate_inside_run_adds_no_leaf() {
        let (d, _, kept, last, _) = attack_fixture();
        put(&d, 1, &[&kept, &kept, &last], &[]);
        open(&d.0);
    }
    fn genesis_size_probe(record_free: bool) {
        {
            let d = Temp::new();
            let first = base(&d);
            if record_free {
                put(&d, 0, &[], b"{\"torn\":");
            }
            let checkpoint = signed(
                5,
                Record::genesis(&TRAIL),
                &seeded_pair(&first, &entry(&first)),
            );
            let resume = declaration(&checkpoint, 0, Record::genesis(&TRAIL), 4, None);
            write_records(&d.0, &[&checkpoint, &resume]);
            corrupt_open(&d.0);
        }
    }
    #[test]
    fn genesis_resume_rejects_two_creation_leaves_without_history() {
        genesis_size_probe(false);
    }
    #[test]
    fn genesis_resume_rejects_two_creation_leaves_after_record_free_run() {
        genesis_size_probe(true);
    }
    #[test]
    fn interior_non_fragment_is_corrupt_inside_and_outside_run() {
        for run in [false, true] {
            let d = Temp::new();
            let first = base(&d);
            let kept = if run {
                headless(&first, 3)
            } else {
                entry(&first)
            };
            let next = entry(&kept);
            if run {
                put(&d, 0, &[&first], &[]);
            }
            let bytes = [
                if run { Vec::new() } else { line(&first) },
                line(&kept),
                b"not json\n".to_vec(),
                line(&next),
            ]
            .concat();
            if run {
                fs::write(segment(&d.0, 1), bytes).unwrap();
                let mut fold = seeded_pair(&first, &kept);
                fold.push(next.hash()).unwrap();
                close_run(&d, &next, &fold);
            } else {
                fs::write(d.0.join("audit.jsonl"), bytes).unwrap();
            }
            corrupt_open(&d.0);
        }
    }
    fn successor_obligation_probe(kind: u8) {
        let d = Temp::new();
        let first = base(&d);
        put(&d, 0, &[&first], &[]);
        let kept = headless(&first, 3);
        put(&d, 1, &[&kept], &[]);
        let mut fold = seeded_pair(&first, &kept);
        let wrong_fold = seeded(&first);
        let cp = signed(
            if kind == 1 { 7 } else { 4 },
            kept.hash(),
            if kind == 1 { &wrong_fold } else { &fold },
        );
        let next = if kind == 1 {
            declaration(&cp, 3, kept.hash(), 6, None)
        } else {
            entry(&cp)
        };
        if kind == 0 {
            // Falsifier: the first successor is only cp@4; a later live pair
            // cannot discharge its missing declaration.
            put(&d, 2, &[&cp], &[]);
        } else {
            put(&d, 2, &[&cp, &next], b"junk\n");
        }
        fold.push(cp.hash()).unwrap();
        let last = if kind == 0 {
            &cp
        } else {
            fold.push(next.hash()).unwrap();
            &next
        };
        close_run(&d, last, &fold);
        corrupt_open(&d.0);
    }
    #[test]
    fn successor_checkpoint_alone_cannot_defer_resume() {
        successor_obligation_probe(0);
    }
    #[test]
    fn successor_wrong_fold_with_suffix_cannot_defer_resume() {
        successor_obligation_probe(1);
    }
    #[test]
    fn successor_wrong_action_with_suffix_cannot_defer_resume() {
        successor_obligation_probe(2);
    }

    fn unsealed_successor_probe(path: u8) {
        use crate::audit::sink::{Config, Sink};
        use std::sync::Arc;
        for suffix in [b"".as_slice(), b"junk\n".as_slice()] {
            for resumed in [false, true] {
                let d = Temp::new();
                let first = base(&d);
                let e1 = entry(&first);
                write_records(&d.0, &[&first, &e1]);
                let cached = (path == 1).then(|| open(&d.0));
                // Keep the cached descriptor, matching actual rotation/resume.
                fs::rename(d.0.join("audit.jsonl"), segment(&d.0, 0)).unwrap();
                let mut fold = seeded_pair(&first, &e1);
                let cp2 = signed(2, e1.hash(), &fold);
                let e3 = if resumed {
                    declaration(&cp2, 1, e1.hash(), 1, None)
                } else {
                    entry(&cp2)
                };
                put(&d, 1, &[&cp2, &e3], suffix);
                fold.push(cp2.hash()).unwrap();
                fold.push(e3.hash()).unwrap();
                let (_, resume) = close_run(&d, &e3, &fold);
                if path == 2 {
                    fs::write(
                        d.0.join("audit.trail"),
                        format!("{}\n", crate::audit::hex(&TRAIL)),
                    )
                    .unwrap();
                    fs::rename(d.0.join("audit.jsonl"), d.0.join(".audit-resume.jsonl")).unwrap();
                    let result = Sink::open(
                        &d.0,
                        Arc::new(KeyFileSigner::from_hex(&"27".repeat(32)).unwrap()),
                        Config::default(),
                        None,
                    );
                    if resumed {
                        let sink = result.unwrap();
                        assert_eq!(head(&open(&d.0)), Head::of(&resume));
                        sink.close().unwrap();
                    } else {
                        assert_eq!(result.err().unwrap().kind(), AuditErrorKind::CorruptTrail);
                    }
                } else if let Some(reader) = cached {
                    let result = reader.with_current(|_| Ok(()), |_, _, s| Ok(s.run.head));
                    if resumed {
                        assert_eq!(result.unwrap(), Head::of(&resume));
                    } else {
                        assert_eq!(result.unwrap_err().kind(), AuditErrorKind::CorruptTrail);
                    }
                } else if resumed {
                    assert_eq!(head(&open(&d.0)), Head::of(&resume));
                } else {
                    corrupt_open(&d.0);
                }
            }
        }
    }
    #[test]
    fn unsealed_predecessor_requires_resume_even_with_junk_on_open() {
        unsealed_successor_probe(0);
    }
    #[test]
    fn unsealed_predecessor_requires_resume_even_with_junk_on_refresh() {
        unsealed_successor_probe(1);
    }
    #[test]
    fn unsealed_predecessor_requires_resume_even_with_junk_on_settlement() {
        unsealed_successor_probe(2);
    }
    fn before_loss_probe(path: u8, headless: bool) {
        use crate::audit::sink::{Config, Sink};
        use std::sync::Arc;
        for junk in [false, true] {
            for wrong in [false, true] {
                if headless && wrong {
                    continue;
                }
                let d = Temp::new();
                let first = base(&d);
                let cached = (path == 1).then(|| open(&d.0));
                fs::rename(d.0.join("audit.jsonl"), segment(&d.0, 0)).unwrap();
                let mut fold = seeded(&first);
                let last;
                if headless {
                    let missing = entry(&first);
                    let kept = entry(&missing);
                    let next = entry(&kept);
                    let mut honest = seeded_pair(&first, &missing);
                    honest.push(kept.hash()).unwrap();
                    honest.push(next.hash()).unwrap();
                    last = signed(4, next.hash(), &honest);
                    put(&d, 1, &[&kept], &[]);
                    // This segment's first hash link is intact: the loss flag
                    // must survive from the preceding headless segment.
                    put(&d, 2, &[&next, &last], if junk { b"junk\n" } else { b"" });
                    fold.push(kept.hash()).unwrap();
                    fold.push(next.hash()).unwrap();
                    fold.push(last.hash()).unwrap();
                } else {
                    let wrong_fold = seeded(&entry(&first));
                    let cp1 = signed(1, first.hash(), if wrong { &wrong_fold } else { &fold });
                    last = entry(&cp1);
                    put(&d, 1, &[&cp1, &last], if junk { b"junk\n" } else { b"" });
                    fold.push(cp1.hash()).unwrap();
                    fold.push(last.hash()).unwrap();
                }
                let (_, resume) = close_run(&d, &last, &fold);
                if path == 2 {
                    fs::write(
                        d.0.join("audit.trail"),
                        format!("{}\n", crate::audit::hex(&TRAIL)),
                    )
                    .unwrap();
                    fs::rename(d.0.join("audit.jsonl"), d.0.join(".audit-resume.jsonl")).unwrap();
                    let result = Sink::open(
                        &d.0,
                        Arc::new(KeyFileSigner::from_hex(&"27".repeat(32)).unwrap()),
                        Config::default(),
                        None,
                    );
                    if wrong {
                        assert_eq!(result.err().unwrap().kind(), AuditErrorKind::CorruptTrail);
                    } else {
                        let sink = result.unwrap();
                        assert_eq!(head(&open(&d.0)), Head::of(&resume));
                        sink.close().unwrap();
                    }
                } else if let Some(reader) = cached {
                    let result = reader.with_current(|_| Ok(()), |_, _, s| Ok(s.run.head));
                    if wrong {
                        assert_eq!(result.unwrap_err().kind(), AuditErrorKind::CorruptTrail);
                    } else {
                        assert_eq!(result.unwrap(), Head::of(&resume));
                    }
                } else if wrong {
                    corrupt_open(&d.0);
                } else {
                    assert_eq!(head(&open(&d.0)), Head::of(&resume));
                }
            }
        }
    }
    #[test]
    fn before_loss_checkpoint_mmr_is_checked_on_open() {
        before_loss_probe(0, false);
    }
    #[test]
    fn before_loss_checkpoint_mmr_is_checked_on_refresh() {
        before_loss_probe(1, false);
    }
    #[test]
    fn before_loss_checkpoint_mmr_is_checked_on_settlement() {
        before_loss_probe(2, false);
    }
    #[test]
    fn after_loss_periodic_checkpoint_is_only_a_leaf_on_open() {
        before_loss_probe(0, true);
    }
    #[test]
    fn after_loss_periodic_checkpoint_is_only_a_leaf_on_refresh() {
        before_loss_probe(1, true);
    }
    #[test]
    fn after_loss_periodic_checkpoint_is_only_a_leaf_on_settlement() {
        before_loss_probe(2, true);
    }
    #[test]
    fn archived_forged_pair_is_documented_reader_residual() {
        let d = Temp::new();
        let first = base(&d);
        let genuine = signed(7, first.hash(), &seeded(&first));
        let Kind::Checkpoint(cp) = &genuine.kind else {
            panic!("checkpoint");
        };
        let forged = Record::checkpoint(
            genuine.context.clone(),
            CheckpointFields::new(
                cp.size,
                cp.root,
                cp.peaks.clone(),
                KeyFileSigner::from_hex(&"27".repeat(32))
                    .unwrap()
                    .public_key(),
                [0; 64],
            )
            .unwrap(),
        )
        .unwrap();
        let resume = declaration(&forged, 0, first.hash(), 6, None);
        write_records(&d.0, &[&forged, &resume]);
        // Documented residual: after archiving the prefix the reader checks no
        // signature; verify must report BadSignature/NoReceipt. This test is
        // exempt from the fails-without-change requirement.
        assert_eq!(head(&open(&d.0)), Head::of(&resume));
    }
}

#[test]
fn genesis_resume_checks_fold_leaf_in_both_reader_paths() {
    for fragment in [false, true] {
        for correct in [false, true] {
            let d = Temp::new();
            fixture(&d.0);
            let genesis = Record::genesis(&TRAIL);
            let mut fold = Mmr::new();
            fold.push(if correct { genesis } else { [42; 32] }).unwrap();
            let opening = cp(5, genesis, &fold);
            let resume = declaration(&opening, 0, genesis, 4, None);
            if fragment {
                fs::write(
                    d.0.join("audit-20000101T000000.000000000Z.jsonl"),
                    b"{\"torn\":",
                )
                .unwrap();
            }
            write_records(&d.0, &[&opening, &resume]);
            if correct {
                assert_eq!(head(&open(&d.0)), Head::of(&resume));
            } else {
                corrupt_open(&d.0);
            }
        }
    }
}

#[test]
fn resume_base_refuses_non_checkpoint_without_archived_predecessor() {
    let d = Temp::new();
    let creation = fixture(&d.0);
    let kept = entry(&creation);
    write_records(&d.0, &[&kept]);
    let file = File::open(d.0.join("audit.jsonl")).unwrap();
    let result = history_segment(
        crate::audit::runs::Reaction::Stop,
        &file,
        TRAIL,
        None,
        true,
        None,
        &mut None,
        &mut false,
    );
    assert!(matches!(result, Err(e) if e.kind() == AuditErrorKind::CorruptTrail));
}

#[test]
fn inherited_run_reaches_first_strict_scan_of_later_history() {
    let d = Temp::new();
    let first = fixture(&d.0);
    append_bytes(&d.0.join("audit.jsonl"), b"xyz\n");
    let file = File::open(d.0.join("audit.jsonl")).unwrap();
    let mut run = false;
    let state = history_segment(
        crate::audit::runs::Reaction::Stop,
        &file,
        TRAIL,
        None,
        true,
        None,
        &mut None,
        &mut run,
    )
    .unwrap()
    .0;
    assert!(run);
    // An otherwise strict-valid segment must close the inherited run with an
    // immediate resume; a normal entry cannot silently erase that obligation.
    let opening = cp(1, first.hash(), &seeded(&first));
    write_records(&d.0, &[&opening, &entry(&opening)]);
    let file = File::open(d.0.join("audit.jsonl")).unwrap();
    bad(
        history_segment(
            crate::audit::runs::Reaction::Stop,
            &file,
            TRAIL,
            state,
            true,
            None,
            &mut None,
            &mut run,
        ),
        AuditErrorKind::CorruptTrail,
    );
}

// ------------------------------------------------------------
// Pins every reader CorruptTrail detail per site (#197 R0a), with a
// coverage gate keyed per call site in storage.rs and runs.rs. Tests
// only. Each test body has a literal `assert_corrupt(result, "detail",
// site)` call so the gate's static scan of storage_tests.rs sees every
// pin.
// ------------------------------------------------------------
mod details {
    use super::*;
    use std::collections::{HashMap, HashSet};

    // The gate parses `storage.rs` and `runs.rs` separately with
    // `syn::parse_file` and collects sites across both in a fixed file
    // order (storage.rs first, then runs.rs), so the
    // `(detail, occurrence)` keys stay stable. From R2b S3a onward the
    // gate is re-keyed per ruling 197-d1 addendum 16 point 4: it
    // counts every `corrupt("literal")` in `storage.rs` and every
    // `Violation::<Variant>` construction expression in `runs.rs`,
    // mapping each variant to its `detail()` string.
    //
    // The pure classifier (`runs::Classifier`) owns 42 of the 49 sites:
    // every `apply_checked` detail (ruling 197-d1 point 2, R1), the
    // strict-mode per-segment checks driven by `feed_record` / `finish`
    // / `invalid_opening_line`, the tolerant-mode checks driven by
    // `feed_record_prepare_tolerant` / `feed_record_apply_tolerant` /
    // `finish_tolerant` / `feed_record_err_tolerant`, the finish-time
    // records inside `finish_collect` (addendum 16 point 5), and the
    // shared-walk `missing head` invariant that moved out of
    // `storage.rs` with the addendum-20.1 orchestration (UNREACHABLE
    // for `apply_checked`'s Ok case leaves `classifier.state()=Some`,
    // matched by the UNREACHABLE table row below). The reader shim in
    // `storage.rs` keeps the remaining 7 sites: the byte-level and
    // file-open checks. `check_attestation` is the single site for
    // `missing or mismatched repair attestation` (ruling 197-d1
    // addendum 7); the reader orders it per path at the position
    // ruling 197-d1 addendum 12 fixes. The total sits at
    // 49 = 7 in `storage.rs` + 42 in `runs.rs`. The one net extra
    // site over the 39+9=48 base is the balance of three S3a-era
    // adds against one S3b1a-round-2 merge: the fold (iii) salvage
    // push adds one `Violation::CheckpointMmrDiffers` construction
    // site inside `feed_record_apply_tolerant` (UNREACHABLE for the
    // reader-side pin gate: exercised by `collector_tests`, no
    // `assert_corrupt`); `apply_checked`'s fresh-Mmr genesis fold
    // carries an explicit `.map_err(|_| Violation::MmrOverflow)?`
    // (UNREACHABLE: `Mmr::new()` + push of one leaf cannot overflow);
    // and the glue-byte LF check — strict `SegmentBytes::
    // check_glue_byte_strict` and tolerant `SegmentBytes::next_event`
    // — behaves identically on the Err path, so the two copies of
    // `corrupt("bytes glued to complete unterminated record")` merge
    // into one shared helper `consume_glue_byte` (50 → 49). The
    // `missing head` occurrence 0 is the shared-walk invariant
    // described above; occurrence 1 is `Classifier::finish`'s own
    // construction, pinned by `pin_sc_missing_head_opening_false_*`.
    // A renamed variant whose `detail()` is not updated, or a new
    // `Violation::<X>` variant without a pin, fails the gate
    // (addendum 16 point 4).
    const STORAGE_SRC: &str = include_str!("storage.rs");
    const RUNS_SRC: &str = include_str!("runs.rs");
    const STORAGE_TESTS_SRC: &str = include_str!("storage_tests.rs");

    fn assert_corrupt<T>(result: Result<T, AuditError>, detail: &str, _site: usize) {
        let err = match result {
            Ok(_) => panic!("expected CorruptTrail, got Ok"),
            Err(e) => e,
        };
        assert_eq!(
            err.kind(),
            AuditErrorKind::CorruptTrail,
            "wrong kind: {err}"
        );
        assert_eq!(
            format!("{err}")
                .strip_prefix("CorruptTrail: ")
                .map(ToString::to_string)
                .unwrap_or_default(),
            detail,
            "detail mismatch",
        );
    }
    fn w(d: &Temp, bytes: &[u8]) {
        fs::write(d.0.join("audit.jsonl"), bytes).unwrap();
    }
    fn o(d: &Temp) -> File {
        File::open(d.0.join("audit.jsonl")).unwrap()
    }
    fn cp0() -> Record {
        cp(0, Record::genesis(&TRAIL), &Mmr::new())
    }
    fn genesis_fold() -> Mmr {
        let mut fold = Mmr::new();
        fold.push(Record::genesis(&TRAIL)).unwrap();
        fold
    }
    fn cp_root(seq: u64) -> Record {
        cp(seq, Record::genesis(&TRAIL), &genesis_fold())
    }
    fn alt_fold() -> Mmr {
        let mut m = Mmr::new();
        m.push([42; 32]).unwrap();
        m
    }
    fn resume_rec(prev: &Record, seq: u64, details: &str) -> Record {
        Record::new_internal(
            context(seq, prev.hash()),
            Entry::new("operator", "vigil.audit.resume", "trail")
                .reason("incident")
                .details(details.to_string()),
        )
        .unwrap()
    }
    fn multi_record_line(record: &Record) -> Vec<u8> {
        let b = line(record);
        let s = std::str::from_utf8(b.strip_suffix(b"\n").unwrap()).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(s).unwrap();
        let log = v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0].clone();
        v["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
            .as_array_mut()
            .unwrap()
            .push(log);
        let mut out = v.to_string().into_bytes();
        out.push(b'\n');
        out
    }
    fn cp0_other_trail() -> Record {
        let other = [5u8; 16];
        let fields =
            CheckpointFields::new(0, Mmr::new().root(), Vec::new(), [1; 32], [0; 64]).unwrap();
        Record::checkpoint(
            RecordContext::new(other, 0, 100, "test", Record::genesis(&other)),
            fields,
        )
        .unwrap()
    }
    fn hsc(
        f: &File,
        state: Option<State>,
        opening: bool,
        run: bool,
    ) -> Result<Option<State>, AuditError> {
        let mut r = run;
        history_segment(
            crate::audit::runs::Reaction::Stop,
            f,
            TRAIL,
            state,
            opening,
            None,
            &mut None,
            &mut r,
        )
        .map(|(s, _)| s)
    }
    /// Addendum 22.1/22.2: history_segment with `expected` + a `found`
    /// out-parameter, so pins can observe both the returned state and
    /// the strict-pass partial writes that must survive on the Err path.
    fn hsc_found(
        f: &File,
        state: Option<State>,
        opening: bool,
        run: bool,
        expected: Head,
    ) -> (Result<Option<State>, AuditError>, Option<Record>) {
        let mut r = run;
        let mut found = None;
        let res = history_segment(
            crate::audit::runs::Reaction::Stop,
            f,
            TRAIL,
            state,
            opening,
            Some(expected),
            &mut found,
            &mut r,
        )
        .map(|(s, _)| s);
        (res, found)
    }
    fn scc(f: &File, state: Option<State>, opening: bool) -> Result<State, AuditError> {
        scan(
            crate::audit::runs::Reaction::Stop,
            f,
            TRAIL,
            state,
            opening,
            None,
            &mut None,
            false,
        )
        .map(|(s, _)| s.unwrap())
    }
    fn state_from(bytes: &[u8]) -> (Temp, State) {
        let d = Temp::new();
        w(&d, bytes);
        let s = scc(&o(&d), None, true).unwrap();
        (d, s)
    }
    fn state_at_cp0() -> (Temp, State, Record) {
        let f = cp0();
        let (d, s) = state_from(&line(&f));
        (d, s, f)
    }
    fn state_unterminated() -> (Temp, State, Record) {
        let f = cp0();
        let mut b = line(&f);
        b.pop();
        let (d, s) = state_from(&b);
        assert!(!s.newline && s.gap.is_none());
        (d, s, f)
    }
    fn state_with_gap() -> (Temp, State, Record) {
        let f = cp0();
        let mut b = line(&f);
        b.extend_from_slice(b"{\"torn\":");
        let (d, s) = state_from(&b);
        assert!(s.gap.is_some());
        (d, s, f)
    }
    fn concat(records: &[&Record], suffix: &[u8]) -> Vec<u8> {
        let mut b: Vec<u8> = records.iter().flat_map(|r| line(r)).collect();
        b.extend_from_slice(suffix);
        b
    }

    // ---- Pins: live-open and existing() ---------------------------------

    #[test]
    fn pin_existing_missing() {
        let d = Temp::new();
        assert_corrupt(
            TrailReader::open(&d.0, TRAIL, None),
            "missing or nonregular trail file",
            0,
        );
    }
    #[test]
    fn pin_existing_fifo() {
        let d = Temp::new();
        assert!(
            Command::new("mkfifo")
                .arg(d.0.join("audit.jsonl"))
                .status()
                .unwrap()
                .success()
        );
        assert_corrupt(
            TrailReader::open(&d.0, TRAIL, None),
            "nonregular trail file",
            0,
        );
    }

    // ---- Pins: history_segment direct calls -----------------------------

    #[test]
    fn pin_hs_glued_byte() {
        let (d, s, _) = state_unterminated();
        append_bytes(&d.0.join("audit.jsonl"), b"x");
        assert_corrupt(
            hsc(&o(&d), Some(s), false, false),
            "bytes glued to complete unterminated record",
            0,
        );
    }
    #[test]
    fn pin_hs_invalid_record_in_sealed_run() {
        let d = Temp::new();
        w(&d, &concat(&[&cp0()], b"{}\n"));
        assert_corrupt(
            hsc(&o(&d), None, true, false),
            "invalid audit record in sealed run",
            0,
        );
    }
    #[test]
    fn pin_hs_multiple_records() {
        let d = Temp::new();
        w(&d, &multi_record_line(&cp0()));
        assert_corrupt(
            hsc(&o(&d), None, true, false),
            "multiple records in native audit line",
            0,
        );
    }
    #[test]
    fn pin_hs_trail_identity() {
        let d = Temp::new();
        w(&d, &line(&cp0_other_trail()));
        assert_corrupt(
            hsc(&o(&d), None, true, false),
            "trail identity differs from marker",
            0,
        );
    }
    #[test]
    fn pin_hs_unparsable_before_complete() {
        let d = Temp::new();
        let f = cp0();
        w(
            &d,
            &[line(&f), b"not json\n".to_vec(), line(&entry(&f))].concat(),
        );
        assert_corrupt(
            hsc(&o(&d), None, true, false),
            "unparsable line before complete record",
            0,
        );
    }
    #[test]
    fn pin_hs_attestation_duplicate_branch() {
        let d = Temp::new();
        let f = cp0();
        w(&d, &[line(&f), b"{\"torn\":\n".to_vec(), line(&f)].concat());
        assert_corrupt(
            hsc(&o(&d), None, true, false),
            "missing or mismatched repair attestation",
            0,
        );
    }
    #[test]
    fn pin_hs_fallback_duplicate_advances_length_through_feed_callback() {
        // Addendum 22.1: a trailing duplicate flows through the shared
        // `on_feed` callback as `FeedEvent::Duplicate`, which advances
        // the `SegmentBytes` offset cursor (so `s.length` is base-
        // identical) while leaving `state.offset` and `state.newline`
        // untouched. Repro: predecessor `scan([cp0, e1, cp2])`,
        // segment file `[e3, e3]`,
        // `history_segment(opening=true, run=false)`. Strict fails
        // with `MissingOpeningCheckpoint` (e3 is an entry on an
        // opening segment), so the tolerant fallback walks both
        // copies. A mutant that skips `on_feed` on the duplicate arm
        // leaves the `SegmentBytes` offset cursor at the first copy,
        // so `s.length` equals the single-record byte count (base
        // gives 2×, head's bug gave 1×).
        let cp0_rec = cp0();
        let e1 = entry(&cp0_rec);
        let mut mmr = seeded(&cp0_rec);
        mmr.push(e1.hash()).unwrap();
        let cp2 = cp(2, e1.hash(), &mmr);
        let pre = Temp::new();
        w(&pre, &[line(&cp0_rec), line(&e1), line(&cp2)].concat());
        let pre_state = scc(&o(&pre), None, true).unwrap();
        assert_eq!(pre_state.run.head.seq, 2);
        let e3 = Record::new(context(3, cp2.hash()), Entry::new("a", "c", "o")).unwrap();
        let seg = Temp::new();
        let seg_bytes = [line(&e3), line(&e3)].concat();
        let expected_length = seg_bytes.len() as u64;
        w(&seg, &seg_bytes);
        let state = hsc(&o(&seg), Some(pre_state), true, false)
            .unwrap()
            .unwrap();
        assert_eq!(
            state.length, expected_length,
            "duplicate arm must advance the walk cursor past both copies via on_feed",
        );
    }
    #[test]
    fn pin_hs_found_persists_on_strict_write_before_tolerant_duplicate() {
        // Addendum 22.2: on the Ok path through the tolerant fallback,
        // strict's partial `*found` write survives because the two
        // passes share one buffer (base-identical: a single `&mut found`
        // was threaded through both passes). Layout: predecessor at e1
        // (continuation, opening=false); the live file holds
        // `[cp0, e1, e1_duplicate, unparsable]`. Strict scans from
        // pred.offset: the duplicate e1 is `Advance::Duplicate`, so
        // `*found` is set to the duplicate; the trailing unparsable
        // trips `invalid audit line or opening checkpoint`, so strict
        // fails with CorruptTrail. The tolerant fallback walks the
        // same two records: e1 takes the duplicate arm (saved_prior's
        // head already matches), so `on_feed` is `FeedEvent::Duplicate`
        // and `found` is NOT re-written; the trailing unparsable
        // latches `damaged` and the segment finishes Ok. With the
        // previous two-buffer design, strict's write lived only in a
        // local that was dropped on `CorruptTrail`, and `found`
        // returned to the caller as `None` (base gave Some).
        let cp0_rec = cp0();
        let e1 = entry(&cp0_rec);
        let d = Temp::new();
        w(&d, &[line(&cp0_rec), line(&e1)].concat());
        let pre_state = scc(&o(&d), None, true).unwrap();
        append_bytes(&d.0.join("audit.jsonl"), &line(&e1));
        append_bytes(&d.0.join("audit.jsonl"), b"not json\n");
        let expected = Head::of(&e1);
        let (res, found) = hsc_found(&o(&d), Some(pre_state), false, false, expected);
        assert!(
            res.is_ok(),
            "tolerant must finish Ok on fragment-only continuation past e1",
        );
        assert_eq!(
            found.map(|r| r.context.seq),
            Some(e1.context.seq),
            "strict's `*found` write must persist across CorruptTrail into tolerant Ok",
        );
    }
    #[test]
    fn pin_hs_found_persists_on_err_after_strict_partial_write() {
        // Addendum 22.2: on the Err path, strict's partial `*found`
        // writes survive. Layout: no predecessor (`opening=true`), the
        // file holds `[cp0, e1, broken_e2]` where broken_e2 has a
        // wrong `previous`. Strict folds cp0 (not a match), then e1
        // (matches; `*found = Some(e1)`), then broken_e2 trips the
        // hash-link check and strict returns CorruptTrail. The
        // tolerant fallback walks from the start, hits the same broken
        // link, and the method returns Err. With the previous
        // two-buffer design, strict's `*found = Some(e1)` lived only
        // in the local inside the strict closure and was dropped; now
        // the shared buffer writes back before the `?` propagates.
        let cp0_rec = cp0();
        let e1 = entry(&cp0_rec);
        let broken = Record::new(context(2, [42; 32]), Entry::new("a", "c", "o")).unwrap();
        let d = Temp::new();
        w(&d, &[line(&cp0_rec), line(&e1), line(&broken)].concat());
        let expected = Head::of(&e1);
        let (res, found) = hsc_found(&o(&d), None, true, false, expected);
        assert_eq!(
            res.err().expect("broken link must propagate").kind(),
            AuditErrorKind::CorruptTrail,
        );
        assert_eq!(
            found.map(|r| r.context.seq),
            Some(e1.context.seq),
            "strict's partial `*found` write must survive on the Err path",
        );
    }
    #[test]
    fn pin_hs_on_feed_writes_found_on_opening_tolerant_walk_at_seq_max() {
        // Addendum 22.2 (round-7): on `history_segment(opening=true, *)`
        // the tolerant fallback's `on_feed(FeedEvent::Record, …)` must
        // write the matching head back into the shared `found` buffer
        // when `expected == Some(head)`, including the saturated
        // `head.seq` end of addendum 15's range. Repro: no predecessor
        // state, the live file holds a leading JSON fragment
        // (incomplete object -> `Line::Fragment`) and then an
        // archived-prefix checkpoint with `context.seq` pinned to the
        // record builder's ceiling (`i64::MAX as u64`; `Record::build`
        // rejects anything above that as "sequence exceeds OTLP int64",
        // so this is the largest `head.seq` the on-disk wire format
        // admits in the sense of addendum 15's saturated-seq branch)
        // and `context.previous == genesis` (root-link + pending). The
        // strict pass fails at the opening fragment with
        // `invalid audit line or opening checkpoint`, so `scan_inner`
        // never reaches any record and writes nothing into `found`.
        // The tolerant fallback restarts at offset 0, folds the
        // fragment as `FeedEvent::NonRecord` (no `found` write), then
        // folds the checkpoint; `on_feed` fires as
        // `FeedEvent::Record(cp_max, rs)` and the storage closure runs
        // the writeback `*fc.borrow_mut() = Some(record.clone())`.
        // The segment still finishes with `invalid undamaged segment`
        // (no damage latched, count=1) so the method returns Err; the
        // writeback must land before the `?` propagates (addendum 22.2
        // moves the `found_cell.into_inner()` back to the caller
        // ahead of `match walk?`). A mutant deleting the writeback,
        // or negating the `expected == Some(head)` guard, leaves the
        // shared buffer empty and `found` returns to the caller as
        // `None`; base's `history_segment` fallback wrote `found`
        // directly in the same loop, so it stayed `Some(cp_max)`.
        //
        // Build the archived-prefix checkpoint directly: the shared
        // `cp` helper derives `time = 100 + seq`, which overflows at
        // the saturated-seq ceiling; the storage flow depends on
        // `context.seq`, not `context.time`.
        let max_seq = i64::MAX as u64;
        let fold = genesis_fold();
        let fields = CheckpointFields::new(
            fold.size(),
            fold.root(),
            fold.peaks().to_vec(),
            [1; 32],
            [0; 64],
        )
        .unwrap();
        let cp_max = Record::checkpoint(
            RecordContext::new(TRAIL, max_seq, 0, "test", Record::genesis(&TRAIL)),
            fields,
        )
        .unwrap();
        let d = Temp::new();
        let mut bytes: Vec<u8> = Vec::new();
        // Line::Fragment: an incomplete JSON object is an EOF parse
        // error, which `super::lines::classify` reports as `Fragment`.
        bytes.extend_from_slice(b"{\"torn\":\n");
        bytes.extend_from_slice(&line(&cp_max));
        w(&d, &bytes);
        let expected = Head::of(&cp_max);
        let (res, found) = hsc_found(&o(&d), None, true, false, expected);
        assert_eq!(
            res.err()
                .expect("opening fragment + undamaged singleton must still propagate")
                .kind(),
            AuditErrorKind::CorruptTrail,
        );
        assert_eq!(
            cp_max.context.seq, max_seq,
            "sanity: the expected head is the saturated-seq branch",
        );
        assert_eq!(
            found.as_ref().map(|r| r.context.seq),
            Some(max_seq),
            "`on_feed` must write `found` for `expected == head` at the saturated \
             seq ceiling on an opening-only tolerant walk (no strict partial write)",
        );
        assert_eq!(
            found.map(|r| Head::of(&r)),
            Some(expected),
            "writeback must carry the exact record, not just its seq",
        );
    }
    #[test]
    fn pin_hs_fallback_duplicate_leaves_offset_at_first_copy() {
        // A complete identical duplicate takes `history_segment`'s
        // duplicate branch and `continue`s without updating
        // `s.offset`/`s.newline`. A trailing `not json` line trips
        // strict `scan_inner` so the fallback body runs. After the
        // duplicate, `s.offset` stays at the end of the first copy;
        // a mutant that sets `s.offset` before the duplicate
        // `continue` would push it past the second copy. The newline
        // half of the quirk is not observable here: the trailing
        // `not json\n` line hits the fragment/invalid branch, which
        // unconditionally overwrites `s.newline` with its own
        // trailing-newline flag.
        let d = Temp::new();
        let f = cp0();
        let first = line(&f);
        let expected_offset = first.len() as u64;
        let bytes = [first.clone(), first, b"not json\n".to_vec()].concat();
        w(&d, &bytes);
        let state = hsc(&o(&d), None, true, false).unwrap().unwrap();
        assert_eq!(
            state.offset, expected_offset,
            "duplicate `continue` must not advance the walk cursor past the first copy",
        );
    }
    #[test]
    fn pin_hs_fallback_fragment_only_opening_updates_state_newline() {
        // Fragment-only opening segment (opening=true) after a
        // predecessor state whose `newline=false` (an unterminated
        // prior record). Strict scan rejects the fragment with
        // `invalid audit line or opening checkpoint`; the fallback
        // walks the single Fragment line, whose branch writes
        // `s.newline = newline` so the outcome reflects the fragment's
        // trailing LF. Catches a mutant that skips the `s.newline`
        // update on the Fragment branch.
        let (_pre, prev_state, _) = state_unterminated();
        assert!(!prev_state.newline);
        let d2 = Temp::new();
        w(&d2, b"{\"torn\":\n");
        let state = hsc(&o(&d2), Some(prev_state), true, false)
            .unwrap()
            .unwrap();
        assert!(
            state.newline,
            "Fragment branch must write the trailing LF into `s.newline`",
        );
    }
    #[test]
    fn pin_hs_attestation_general_branch_broken_link_pair() {
        // Attestation-order pair, next=seq 6 broken link.
        let (_pre, s, _) = state_at_cp0();
        let h5 = Record::new(context(5, [0; 32]), Entry::new("actor", "change", "object")).unwrap();
        let broken = Record::new(
            context(6, [42; 32]),
            Entry::new("actor", "change", "object"),
        )
        .unwrap();
        let d = Temp::new();
        w(
            &d,
            &[line(&h5), b"{\"torn\":\n".to_vec(), line(&broken)].concat(),
        );
        assert_corrupt(
            hsc(&o(&d), Some(s), true, true),
            "missing or mismatched repair attestation",
            0,
        );
    }
    #[test]
    fn pin_hs_attestation_consumes_gap() {
        // Pins that the strict `scan_inner` consumes the gap digest when
        // the attested successor passes `check_attestation`. On
        // `[cp0, e1, fragment, e2(attested)]`, `history_segment`'s outer
        // `scan_inner` succeeds and never enters the fallback body, so
        // this pin reaches only `scan_inner`'s `gap.take()`. A mutant
        // that replaces that `gap.take()` with `gap.as_ref().cloned()`
        // keeps the gap in the returned state. The fallback body's own
        // `gap.take()` sites are pinned separately
        // (`pin_hs_fallback_duplicate_branch_consumes_gap` and
        // `pin_hs_fallback_general_branch_consumes_gap`).
        let f = cp0();
        let e1 = entry(&f);
        let fragment = b"{\"torn\":\n";
        let mut digest = blake3::Hasher::new();
        digest.update(b"vigil.audit.v1.repaired\0");
        digest.update(fragment);
        let e2 = Record::new(
            context(2, e1.hash()).repaired(*digest.finalize().as_bytes()),
            Entry::new("a", "b", "c"),
        )
        .unwrap();
        let d = Temp::new();
        w(
            &d,
            &[line(&f), line(&e1), fragment.to_vec(), line(&e2)].concat(),
        );
        let state = hsc(&o(&d), None, true, false).unwrap().unwrap();
        assert!(
            state.gap.is_none(),
            "attestation must consume the gap on scan_inner's take site",
        );
    }
    #[test]
    fn pin_hs_fallback_duplicate_branch_consumes_gap() {
        // Pins that the fallback body's duplicate branch consumes the
        // gap digest. A mutant that replaces `gap.take()` with
        // `gap.as_ref().cloned()` on that branch leaves the fragment
        // digest in `gap` across the `continue`. A later non-duplicate
        // record whose `repaired` is `None` then trips the
        // general-branch attestation, swapping the observable
        // `first successor lacks resume` detail for `missing or
        // mismatched repair attestation`. The duplicate carries the
        // attestation itself (same record hash, same `repaired`), so
        // the duplicate-branch attestation passes.
        let (_pre, s, first) = state_at_cp0();
        let fragment = b"{\"torn\":\n";
        let mut digest = blake3::Hasher::new();
        digest.update(b"vigil.audit.v1.repaired\0");
        digest.update(fragment);
        let digest = *digest.finalize().as_bytes();
        let mmr = seeded(&first);
        let cp1 = Record::checkpoint(
            context(1, first.hash()).repaired(digest),
            CheckpointFields::new(
                mmr.size(),
                mmr.root(),
                mmr.peaks().to_vec(),
                [1; 32],
                [0; 64],
            )
            .unwrap(),
        )
        .unwrap();
        let successor = Record::new(
            context(2, cp1.hash()),
            Entry::new("actor", "change", "object"),
        )
        .unwrap();
        let d = Temp::new();
        w(
            &d,
            &[line(&cp1), fragment.to_vec(), line(&cp1), line(&successor)].concat(),
        );
        assert_corrupt(
            hsc(&o(&d), Some(s), true, true),
            "first successor lacks resume",
            0,
        );
    }
    #[test]
    fn pin_hs_fallback_general_branch_consumes_gap() {
        // Pins that the fallback body's general branch consumes the gap
        // digest when an attested successor passes
        // `check_attestation`. On
        // `[cp0, e1, fragment, e2(attested), e3, "not json\n"]` the
        // trailing unparsable line fails the strict `scan_inner`, so
        // `history_segment`'s fallback body runs. There the
        // mid-segment general branch's `gap.take()` consumes the
        // fragment digest when e2 attests it; e3's subsequent
        // (unattested) attestation check then finds `gap` empty and
        // passes. A mutant that replaces that `gap.take()` with
        // `gap.as_ref().cloned()` leaves the digest in `gap` across
        // e2, so e3's attestation call fires `missing or mismatched
        // repair attestation` instead. The call returns `Ok` with no
        // pending gap in the returned state.
        let f = cp0();
        let e1 = entry(&f);
        let fragment = b"{\"torn\":\n";
        let mut digest = blake3::Hasher::new();
        digest.update(b"vigil.audit.v1.repaired\0");
        digest.update(fragment);
        let e2 = Record::new(
            context(2, e1.hash()).repaired(*digest.finalize().as_bytes()),
            Entry::new("a", "b", "c"),
        )
        .unwrap();
        let e3 = entry(&e2);
        let d = Temp::new();
        w(
            &d,
            &[
                line(&f),
                line(&e1),
                fragment.to_vec(),
                line(&e2),
                line(&e3),
                b"not json\n".to_vec(),
            ]
            .concat(),
        );
        let state = hsc(&o(&d), None, true, false).unwrap().unwrap();
        assert!(
            state.gap.is_none(),
            "attestation must consume the gap on history_segment's fallback general branch",
        );
    }
    #[test]
    fn pin_hs_fallback_rebuild_increments_since_checkpoint() {
        // Pins that the fallback body rebuilds the writer-only fields
        // (`checkpoint_time`, `since_checkpoint`) through the shared
        // `next_cp_fields` helper, same as `scan_inner` and
        // `apply_checked`. A fallback that folds a record after its
        // opening checkpoint must leave `since_checkpoint == 1` and
        // `checkpoint_time == cp0.context.time`. A trailing
        // `not json\n` line trips strict `scan_inner` so the fallback
        // body runs. Kills mutant O2 (the fallback rebuild skipping
        // the `since_checkpoint` increment).
        let d = Temp::new();
        let f = cp0();
        let e1 = entry(&f);
        let bytes = [line(&f), line(&e1), b"not json\n".to_vec()].concat();
        w(&d, &bytes);
        let state = hsc(&o(&d), None, true, false).unwrap().unwrap();
        assert_eq!(
            state.checkpoint_time, 100,
            "fallback rebuild must preserve the opening checkpoint's time",
        );
        assert_eq!(
            state.since_checkpoint, 1,
            "fallback rebuild must increment since_checkpoint on the first non-checkpoint record",
        );
    }
    #[test]
    fn pin_strict_since_checkpoint_saturates_at_u64_max() {
        // Pins that `next_cp_fields` saturates `since_checkpoint` at
        // `u64::MAX` on the strict path (per ruling 197-d1 addendum 15:
        // the increment uses `saturating_add(1)` on every path so the
        // strict and apply_checked/fallback paths cannot drift at the
        // bound). From a predecessor state with
        // `since_checkpoint = u64::MAX`, one more non-checkpoint record
        // on `scan(opening=false)` must leave `since_checkpoint` at
        // `u64::MAX`, without panic or wrap. A `+ 1` mutant panics in
        // debug and wraps to 0 in release.
        let (d, s, first) = state_at_cp0();
        let saturated = State {
            since_checkpoint: u64::MAX,
            ..s
        };
        let e1 = entry(&first);
        append_bytes(&d.0.join("audit.jsonl"), &line(&e1));
        let state =
            scc(&o(&d), Some(saturated), false).expect("strict path must not panic at u64::MAX");
        assert_eq!(
            state.since_checkpoint,
            u64::MAX,
            "strict path must saturate since_checkpoint at u64::MAX",
        );
    }
    #[test]
    fn pin_fallback_since_checkpoint_saturates_at_u64_max() {
        // Pins that `next_cp_fields` saturates `since_checkpoint` at
        // `u64::MAX` on the `apply_checked`/fallback path too (per
        // ruling 197-d1 addendum 15). From a predecessor state with
        // `since_checkpoint = u64::MAX`, one more non-checkpoint record
        // on `history_segment`'s fallback body (tripped by a trailing
        // unparsable line) must leave `since_checkpoint` at `u64::MAX`,
        // without panic or wrap. A `+ 1` mutant panics in debug and
        // wraps to 0 in release.
        let (d, s, first) = state_at_cp0();
        let saturated = State {
            since_checkpoint: u64::MAX,
            ..s
        };
        let e1 = entry(&first);
        append_bytes(
            &d.0.join("audit.jsonl"),
            &[line(&e1), b"not json\n".to_vec()].concat(),
        );
        let state = hsc(&o(&d), Some(saturated), false, false)
            .expect("fallback path must not panic at u64::MAX")
            .expect("fallback must return a state after folding the successor");
        assert_eq!(
            state.since_checkpoint,
            u64::MAX,
            "fallback path must saturate since_checkpoint at u64::MAX",
        );
    }
    #[test]
    fn pin_hs_record_sequence_did_not_increase() {
        let d = Temp::new();
        let first = cp0();
        let mut mmr = seeded(&first);
        let second = cp(1, first.hash(), &mmr);
        mmr.push(second.hash()).unwrap();
        w(&d, &[line(&first), line(&second), line(&first)].concat());
        assert_corrupt(
            hsc(&o(&d), None, true, false),
            "record sequence did not increase inside sealed run",
            0,
        );
    }
    #[test]
    fn pin_hs_missing_initial_checkpoint() {
        let d = Temp::new();
        w(&d, &line(&entry(&cp0())));
        assert_corrupt(
            hsc(&o(&d), None, true, false),
            "missing initial checkpoint",
            0,
        );
    }
    #[test]
    fn pin_hs_sequence_gap_inside_sealed_run_segment() {
        // Attestation-order pair, next=seq 7 linked.
        let (_pre, s, _) = state_at_cp0();
        let h5 = Record::new(context(5, [0; 32]), Entry::new("actor", "change", "object")).unwrap();
        let next = Record::new(
            context(7, h5.hash()),
            Entry::new("actor", "change", "object"),
        )
        .unwrap();
        let d = Temp::new();
        w(
            &d,
            &[line(&h5), b"{\"torn\":\n".to_vec(), line(&next)].concat(),
        );
        assert_corrupt(
            hsc(&o(&d), Some(s), true, true),
            "sequence gap inside sealed run segment",
            0,
        );
    }
    #[test]
    fn pin_hs_first_successor_does_not_close() {
        let (_pre, s, first) = state_at_cp0();
        let d = Temp::new();
        w(&d, &line(&cp(1, first.hash(), &alt_fold())));
        assert_corrupt(
            hsc(&o(&d), Some(s), true, true),
            "first successor does not close sealed run",
            0,
        );
    }
    #[test]
    fn pin_hs_first_successor_lacks_immediate_resume() {
        let (_pre, s, first) = state_at_cp0();
        let d = Temp::new();
        let cp1 = cp(1, first.hash(), &seeded(&first));
        w(&d, &concat(&[&cp1, &entry(&cp1)], &[]));
        assert_corrupt(
            hsc(&o(&d), Some(s), true, true),
            "first successor lacks immediate resume",
            0,
        );
    }
    #[test]
    fn pin_hs_first_successor_lacks_resume() {
        let (_pre, s, first) = state_at_cp0();
        let d = Temp::new();
        w(&d, &line(&cp(1, first.hash(), &seeded(&first))));
        assert_corrupt(
            hsc(&o(&d), Some(s), true, true),
            "first successor lacks resume",
            0,
        );
    }
    #[test]
    fn pin_hs_invalid_undamaged_segment() {
        let d = Temp::new();
        w(&d, &line(&cp_root(7)));
        assert_corrupt(
            hsc(&o(&d), None, true, false),
            "invalid undamaged segment",
            0,
        );
    }
    #[test]
    fn pin_hs_resume_lacks_declaration() {
        // Hand-crafted State{pending_resume=true} + fragment-only segment
        // reaches `finish_tolerant`'s pending-resume check
        // (`resume checkpoint lacks its declaration`) without the
        // duplicate-branch head-match or the `invalid undamaged segment`
        // guard intervening.
        let state_pending = State {
            run: RunState {
                head: Head {
                    seq: 7,
                    hash: [9; 32],
                },
                mmr: genesis_fold(),
                checkpoint: true,
                pending_resume: true,
                run_loss: false,
                checkpoint_predecessor: None,
                checkpoint_previous: [0; 32],
            },
            offset: 0,
            length: 0,
            checkpoint_time: 100,
            since_checkpoint: 0,
            newline: true,
            gap: None,
        };
        let d = Temp::new();
        w(&d, b"{\"torn\":");
        assert_corrupt(
            hsc(&o(&d), Some(state_pending), true, false),
            "resume checkpoint lacks its declaration",
            0,
        );
    }

    // ---- Pins: scan direct calls ----------------------------------------

    #[test]
    fn pin_sc_glued_byte() {
        let (d, s, _) = state_unterminated();
        append_bytes(&d.0.join("audit.jsonl"), b"x");
        assert_corrupt(
            scc(&o(&d), Some(s), false),
            "bytes glued to complete unterminated record",
            0,
        );
    }
    #[test]
    fn pin_sc_invalid_audit_line_or_opening_checkpoint() {
        let d = Temp::new();
        w(&d, b"{\n");
        assert_corrupt(
            scc(&o(&d), None, true),
            "invalid audit line or opening checkpoint",
            0,
        );
    }
    #[test]
    fn pin_sc_multiple_records() {
        let d = Temp::new();
        w(&d, &multi_record_line(&cp0()));
        assert_corrupt(
            scc(&o(&d), None, true),
            "multiple records in native audit line",
            1,
        );
    }
    #[test]
    fn pin_sc_trail_identity() {
        let d = Temp::new();
        w(&d, &line(&cp0_other_trail()));
        assert_corrupt(
            scc(&o(&d), None, true),
            "trail identity differs from marker",
            1,
        );
    }
    #[test]
    fn pin_sc_opening_duplicates_predecessor() {
        let (d, s, first) = state_at_cp0();
        w(&d, &line(&first));
        assert_corrupt(
            scc(&o(&d), Some(s), true),
            "opening checkpoint duplicates predecessor",
            0,
        );
    }
    #[test]
    fn pin_sc_missing_opening_checkpoint() {
        let d = Temp::new();
        w(&d, &line(&entry(&cp0())));
        assert_corrupt(scc(&o(&d), None, true), "missing opening checkpoint", 0);
    }
    #[test]
    fn pin_sc_attestation_consumes_gap() {
        // Pins that the strict `scan` consumes the gap digest when an
        // attested successor passes `check_attestation`. On
        // `[cp0, e1, fragment, e2(attested)]` the strict scan reaches
        // the attested successor and takes the gap. A mutant that
        // replaces `gap.take()` with `gap.as_ref().cloned()` leaves
        // the fragment digest in the returned state.
        let f = cp0();
        let e1 = entry(&f);
        let fragment = b"{\"torn\":\n";
        let mut digest = blake3::Hasher::new();
        digest.update(b"vigil.audit.v1.repaired\0");
        digest.update(fragment);
        let e2 = Record::new(
            context(2, e1.hash()).repaired(*digest.finalize().as_bytes()),
            Entry::new("a", "b", "c"),
        )
        .unwrap();
        let d = Temp::new();
        w(
            &d,
            &[line(&f), line(&e1), fragment.to_vec(), line(&e2)].concat(),
        );
        let state = scc(&o(&d), None, true).unwrap();
        assert!(
            state.gap.is_none(),
            "attestation must consume the gap on the strict scan path",
        );
    }
    #[test]
    fn pin_sc_repair_attestation() {
        let d = Temp::new();
        let f = cp0();
        w(
            &d,
            &[line(&f), b"{\"torn\":\n".to_vec(), line(&entry(&f))].concat(),
        );
        assert_corrupt(
            scc(&o(&d), None, true),
            "missing or mismatched repair attestation",
            0,
        );
    }
    // ---- Pins on the strict `scan` per-path order (ruling 197-d1 addendum 12) -
    #[test]
    fn pin_sc_trail_identity_after_pending_fragment() {
        // Pins the reader's per-path order on `scan(opening=false)`
        // (ruling 197-d1 addendum 12: multi / trail / dup /
        // missing-opening run BEFORE `check_attestation`). Layout:
        // `[cp0, e1, "{\"torn\":\n"]` cached, then a record from
        // another trail appended; `scan(opening=false)` must emit
        // `trail identity differs from marker`, not `missing or
        // mismatched repair attestation`.
        let f = cp0();
        let e1 = entry(&f);
        let fragment = b"{\"torn\":\n";
        let (d, s) = state_from(&[line(&f), line(&e1), fragment.to_vec()].concat());
        assert!(s.gap.is_some(), "setup: gap must be pending");
        append_bytes(&d.0.join("audit.jsonl"), &line(&cp0_other_trail()));
        assert_corrupt(
            scc(&o(&d), Some(s), false),
            "trail identity differs from marker",
            1,
        );
    }
    #[test]
    fn pin_sc_multiple_records_fails_apply_checked_first() {
        // Pins that `multiple records in native audit line` runs ahead
        // of `apply_checked`'s per-record checks (ruling 197-d1
        // addendum 12). The first record in the batch has a broken
        // hash link so `apply_checked` would error with `record rolled
        // back, changed or broke its hash link`; the classifier emits
        // `multiple records in native audit line` first.
        let f = cp0();
        let bad = Record::new(
            context(1, [42; 32]),
            Entry::new("actor", "change", "object"),
        )
        .unwrap();
        let d = Temp::new();
        let mut bytes = line(&f);
        bytes.extend_from_slice(&multi_record_line(&bad));
        w(&d, &bytes);
        assert_corrupt(
            scc(&o(&d), None, true),
            "multiple records in native audit line",
            1,
        );
    }
    #[test]
    fn pin_sc_duplicate_does_not_bump_since_checkpoint() {
        // Pins the duplicate semantic on the strict path: a complete
        // identical duplicate must leave the writer-only
        // `since_checkpoint` in place (ruling 13-V4-d4 point 1).
        // Layout `[cp0, e1, e1]` on live open gives
        // `since_checkpoint == 1` (from e1); a mutant that bumps on
        // `Advance::Duplicate` would give 2.
        let f = cp0();
        let e1 = entry(&f);
        let d = Temp::new();
        w(&d, &concat(&[&f, &e1, &e1], &[]));
        let state = scc(&o(&d), None, true).expect("scan should accept the duplicate");
        assert_eq!(
            state.since_checkpoint, 1,
            "a duplicate must not bump since_checkpoint",
        );
        // The duplicate branch of `Classifier::feed_record` also clears
        // `run_loss` on the preserved state (matching the strict
        // `apply` wrapper semantic), but that clear is not observable
        // on strict paths: every strict scan reaches a duplicate only
        // through a prior `Record` outcome that already set
        // `run_loss = false`. Dropping the clear still leaves this
        // scan returning `run_loss = false` here, so no assertion is
        // pinned.
    }
    #[test]
    fn pin_sc_attestation_between_missing_opening_and_apply() {
        // Pins the reader's per-path position for `check_attestation`
        // on the strict path (ruling 197-d1 addendum 12: between
        // `missing opening checkpoint` and `apply_checked`'s
        // per-record checks). Layout:
        // `[cp0, fragment, record_with_broken_link]`. Both attestation
        // and `apply_checked` would error. Attestation runs first ->
        // `missing or mismatched repair attestation`; a mutant that
        // moves attestation after `apply_checked` fires the hash-link
        // error instead.
        let f = cp0();
        let bad = Record::new(
            context(1, [42; 32]),
            Entry::new("actor", "change", "object"),
        )
        .unwrap();
        let d = Temp::new();
        w(
            &d,
            &[line(&f), b"{\"torn\":\n".to_vec(), line(&bad)].concat(),
        );
        assert_corrupt(
            scc(&o(&d), None, true),
            "missing or mismatched repair attestation",
            0,
        );
    }
    #[test]
    fn pin_sc_unclosed_segment_lacks_matching_immediate_resume() {
        let (d, s, first) = state_with_gap();
        let cp1 = cp(1, first.hash(), &seeded(&first));
        w(&d, &concat(&[&cp1, &entry(&cp1)], &[]));
        assert_corrupt(
            scc(&o(&d), Some(s), true),
            "unclosed segment lacks matching immediate resume",
            0,
        );
    }
    #[test]
    fn pin_sc_empty_live_file() {
        let d = Temp::new();
        w(&d, b"");
        assert_corrupt(
            scc(&o(&d), None, true),
            "empty live file or missing opening checkpoint",
            0,
        );
    }
    #[test]
    fn pin_sc_resume_lacks_declaration() {
        let d = Temp::new();
        w(&d, &line(&cp_root(7)));
        assert_corrupt(
            scc(&o(&d), None, true),
            "resume checkpoint lacks its declaration",
            1,
        );
    }
    #[test]
    fn pin_sc_opening_duplicates_predecessor_non_checkpoint() {
        // State cached after `[cp0, e1]`; live file begins with `[e1]`,
        // whose head equals the predecessor's. The order of the two
        // first-record guards on scan_inner's live path matters here:
        // the head-equality check must fire before the non-checkpoint
        // check, so a mutant that swaps them trips this pin.
        let f = cp0();
        let e1 = entry(&f);
        let (d, s) = state_from(&concat(&[&f, &e1], &[]));
        w(&d, &line(&e1));
        assert_corrupt(
            scc(&o(&d), Some(s), true),
            "opening checkpoint duplicates predecessor",
            0,
        );
    }
    #[test]
    fn pin_sc_missing_head_opening_false_empty() {
        // scan(opening=false, state=None) on an empty file: the loop
        // never runs, `first` stays false, so the "empty live file"
        // guard is skipped and the post-loop `state.ok_or_else` fires.
        let d = Temp::new();
        w(&d, b"");
        assert_corrupt(scc(&o(&d), None, false), "missing head", 1);
    }
    #[test]
    fn pin_sc_missing_head_opening_false_fragment_only() {
        // scan(opening=false, state=None) on a fragment-only file: the
        // fragment arm consumes the line because `first` is already
        // false, the loop then ends with no apply, and the post-loop
        // `state.ok_or_else` fires with "missing head".
        let d = Temp::new();
        w(&d, b"{\"torn\":");
        assert_corrupt(scc(&o(&d), None, false), "missing head", 1);
    }

    // ---- Pins: apply_checked via scan direct calls ----------------------

    #[test]
    fn pin_apply_missing_initial_checkpoint() {
        // scan(opening=false, state=None) reaches `feed_record`'s
        // `missing initial checkpoint` guard on the first non-Checkpoint
        // record.
        let d = Temp::new();
        w(&d, &line(&entry(&cp0())));
        assert_corrupt(scc(&o(&d), None, false), "missing initial checkpoint", 1);
    }
    #[test]
    fn pin_apply_initial_checkpoint_does_not_link_genesis() {
        let d = Temp::new();
        w(&d, &line(&cp(0, [42; 32], &Mmr::new())));
        assert_corrupt(
            scc(&o(&d), None, true),
            "initial checkpoint does not link genesis",
            0,
        );
    }
    #[test]
    fn pin_apply_record_rolled_back() {
        let d = Temp::new();
        let first = cp0();
        let bad = Record::new(
            context(1, [42; 32]),
            Entry::new("actor", "change", "object"),
        )
        .unwrap();
        w(&d, &concat(&[&first, &bad], &[]));
        assert_corrupt(
            scc(&o(&d), None, true),
            "record rolled back, changed or broke its hash link",
            0,
        );
    }
    #[test]
    fn pin_apply_sequence_gap_lacks_resume_declaration() {
        let d = Temp::new();
        let opening = cp_root(7);
        let e = Record::new(
            context(8, opening.hash()),
            Entry::new("actor", "change", "object"),
        )
        .unwrap();
        w(&d, &concat(&[&opening, &e], &[]));
        assert_corrupt(
            scc(&o(&d), None, true),
            "sequence gap lacks a resume declaration",
            0,
        );
    }
    #[test]
    fn pin_apply_sequence_gap_without_checkpoint() {
        let d = Temp::new();
        let first = cp0();
        let gap = Record::new(
            context(5, first.hash()),
            Entry::new("actor", "change", "object"),
        )
        .unwrap();
        w(&d, &concat(&[&first, &gap], &[]));
        assert_corrupt(
            scc(&o(&d), None, true),
            "sequence gap without checkpoint",
            0,
        );
    }
    #[test]
    fn pin_apply_checkpoint_mmr_differs() {
        let d = Temp::new();
        let first = cp0();
        let wrong = cp(1, first.hash(), &alt_fold());
        w(&d, &concat(&[&first, &wrong], &[]));
        assert_corrupt(
            scc(&o(&d), None, true),
            "checkpoint MMR differs from preceding records",
            0,
        );
    }
    #[test]
    fn pin_apply_resume_not_immediately_after_checkpoint() {
        let d = Temp::new();
        let first = cp0();
        let e = entry(&first);
        let r = resume_rec(&e, 2, "head=0:placeholder lost_through=0 file=-");
        w(&d, &concat(&[&first, &e, &r], &[]));
        assert_corrupt(
            scc(&o(&d), None, true),
            "resume not immediately after checkpoint",
            0,
        );
    }
    #[test]
    fn pin_apply_resume_without_details() {
        let d = Temp::new();
        let opening = cp_root(7);
        let r = Record::new_internal(
            context(8, opening.hash()),
            Entry::new("operator", "vigil.audit.resume", "trail").reason("incident"),
        )
        .unwrap();
        w(&d, &concat(&[&opening, &r], &[]));
        assert_corrupt(scc(&o(&d), None, true), "resume without details", 0);
    }
    #[test]
    fn pin_apply_invalid_resume_details() {
        let d = Temp::new();
        let opening = cp_root(7);
        w(
            &d,
            &concat(&[&opening, &resume_rec(&opening, 8, "no_file_marker")], &[]),
        );
        assert_corrupt(scc(&o(&d), None, true), "invalid resume details", 0);
    }
    #[test]
    fn pin_apply_invalid_resume_loss_bound() {
        let d = Temp::new();
        let opening = cp_root(7);
        w(
            &d,
            &concat(
                &[&opening, &resume_rec(&opening, 8, "head=0:x file=-")],
                &[],
            ),
        );
        assert_corrupt(scc(&o(&d), None, true), "invalid resume loss bound", 0);
    }
    #[test]
    fn pin_apply_invalid_resume_head() {
        let d = Temp::new();
        let opening = cp_root(7);
        w(
            &d,
            &concat(
                &[
                    &opening,
                    &resume_rec(&opening, 8, "bad lost_through=0 file=-"),
                ],
                &[],
            ),
        );
        assert_corrupt(scc(&o(&d), None, true), "invalid resume head", 0);
    }
    #[test]
    fn pin_apply_invalid_resume_head_sequence() {
        let d = Temp::new();
        let opening = cp_root(7);
        let r = resume_rec(&opening, 8, "head=xyz:placeholder lost_through=0 file=-");
        w(&d, &concat(&[&opening, &r], &[]));
        assert_corrupt(scc(&o(&d), None, true), "invalid resume head sequence", 0);
    }
    #[test]
    fn pin_apply_resume_after_creation_checkpoint() {
        let d = Temp::new();
        let first = cp0();
        let r = resume_rec(&first, 1, "head=0:placeholder lost_through=0 file=-");
        w(&d, &concat(&[&first, &r], &[]));
        assert_corrupt(
            scc(&o(&d), None, true),
            "resume after creation checkpoint",
            0,
        );
    }
    #[test]
    fn pin_apply_resume_declaration_does_not_describe_gap() {
        let d = Temp::new();
        let opening = cp_root(7);
        let wrong = declaration(&opening, 0, Record::genesis(&TRAIL), 5, None);
        w(&d, &concat(&[&opening, &wrong], &[]));
        assert_corrupt(
            scc(&o(&d), None, true),
            "resume declaration does not describe its gap",
            0,
        );
    }

    // ---- Accepted outcomes ----------------------------------------------

    #[test]
    fn accepted_archived_base() {
        // Archived base: the first checkpoint has prev != genesis. The
        // remaining accepted layouts (honest torn tail + resume, two-segment
        // run, closer + second run, genesis closer) are already pinned by
        // existing tests in `mod runs` and the top-level resume tests.
        let d = Temp::new();
        let archived = cp(7, [42; 32], &genesis_fold());
        let r = declaration(&archived, 0, [42; 32], 6, None);
        write_records(&d.0, &[&archived, &r]);
        assert_eq!(head(&open(&d.0)), Head::of(&r));
    }

    // ------------------------------------------------------------
    // #197 R0b: pin the paths and layouts R0a left out. Tests only.
    //
    // Section 1 covers the fallback rescan through `TrailReader::open`
    // for each fallback-reachable site (history_segment's post-strict
    // body). Section 2 pins the three refresh() sites, replacing the
    // R0a `PENDING_R0B` stubs (now empty). Section 3 pins the resume
    // path: predecessor_run errors surface through Sink::resume, and
    // Sink::open through settle() discards a bogus `.audit-resume.jsonl`
    // staging. Section 4 pins the path-dependent archived base
    // (`cp(7, [42;32], genesis_fold)`): `scan` is Ok but `scan_staged`
    // gives `initial checkpoint does not link genesis`. Section 5 pins
    // the named layouts: boundary_resume (sealed-run and fragment-only,
    // rotated and live), the opening MMR mismatch (closing opening),
    // the genesis closer after a fragment-only first segment, and the
    // hash-link boundary (197-d1 point 8) on live `open`, strict `scan`
    // and refresh. The gate hardening (stale-label check, strict
    // parsing with turbofish and non-literal guard) lives in
    // `parse_assertions` and `coverage_gate_pins_every_corrupt_site`.
    // ------------------------------------------------------------

    fn trail_marker(d: &Temp) {
        fs::write(
            d.0.join("audit.trail"),
            format!("{}\n", crate::audit::hex(&TRAIL)),
        )
        .unwrap();
    }

    // --- Section 1: fallback through TrailReader::open ----------------
    // Each test puts a rotated segment that fails the strict scan then
    // trips a specific fallback-body site. The live file is empty so if
    // the fallback did not fire we would still error on the live scan,
    // but each case here errors inside the rotated segment first.

    fn alt_cp0() -> Record {
        // Seq 0, prev != genesis: a different-hash duplicate opening.
        cp(0, [42; 32], &Mmr::new())
    }
    fn seg_only(bytes: Vec<u8>) -> Temp {
        let d = Temp::new();
        fs::write(segment(&d.0, 0), bytes).unwrap();
        fs::write(d.0.join("audit.jsonl"), b"").unwrap();
        d
    }
    fn two_segs(seg0: Vec<u8>, seg1: Vec<u8>) -> Temp {
        let d = Temp::new();
        fs::write(segment(&d.0, 0), seg0).unwrap();
        fs::write(segment(&d.0, 1), seg1).unwrap();
        fs::write(d.0.join("audit.jsonl"), b"").unwrap();
        d
    }

    #[test]
    fn pin_open_fallback_invalid_record_in_sealed_run() {
        let d = seg_only(concat(&[&cp0()], b"{}\n"));
        assert_corrupt(
            TrailReader::open(&d.0, TRAIL, None),
            "invalid audit record in sealed run",
            0,
        );
    }
    #[test]
    fn pin_open_fallback_multiple_records_sealed_run() {
        let d = seg_only([line(&cp0()), multi_record_line(&entry(&cp0()))].concat());
        assert_corrupt(
            TrailReader::open(&d.0, TRAIL, None),
            "multiple records in native audit line",
            0,
        );
    }
    #[test]
    fn pin_open_fallback_trail_identity_sealed_run() {
        let d = seg_only([line(&cp0()), line(&cp0_other_trail())].concat());
        assert_corrupt(
            TrailReader::open(&d.0, TRAIL, None),
            "trail identity differs from marker",
            0,
        );
    }
    #[test]
    fn pin_open_fallback_unparsable_before_complete_record() {
        let f = cp0();
        let d = seg_only([line(&f), b"not json\n".to_vec(), line(&entry(&f))].concat());
        assert_corrupt(
            TrailReader::open(&d.0, TRAIL, None),
            "unparsable line before complete record",
            0,
        );
    }
    #[test]
    fn pin_open_fallback_attestation_duplicate_branch() {
        // [cp0, fragment, cp0] on a sealed segment: the duplicate head
        // reaches the duplicate-branch `check_attestation` call.
        let f = cp0();
        let d = seg_only([line(&f), b"{\"torn\":\n".to_vec(), line(&f)].concat());
        assert_corrupt(
            TrailReader::open(&d.0, TRAIL, None),
            "missing or mismatched repair attestation",
            0,
        );
    }
    #[test]
    fn pin_open_fallback_sequence_did_not_increase_rotated_duplicate_opening() {
        // Brief's example: a rotated duplicate opening (different hash,
        // same seq=0) fires the sealed-seq check inside the fallback
        // body (feed_record_prepare_tolerant: `record sequence did not
        // increase inside sealed run`).
        let d = seg_only(concat(&[&cp0(), &alt_cp0()], &[]));
        assert_corrupt(
            TrailReader::open(&d.0, TRAIL, None),
            "record sequence did not increase inside sealed run",
            0,
        );
    }
    #[test]
    fn pin_open_fallback_missing_initial_checkpoint() {
        // A rotated segment whose first record is a non-Checkpoint
        // fires `feed_record_prepare_tolerant`'s `missing initial
        // checkpoint` guard (strict fires `missing opening checkpoint`
        // first through `feed_record`).
        let d = seg_only(line(&entry(&cp0())));
        assert_corrupt(
            TrailReader::open(&d.0, TRAIL, None),
            "missing initial checkpoint",
            0,
        );
    }
    #[test]
    fn pin_open_fallback_sequence_gap_inside_sealed_run_segment() {
        let f = cp0();
        let jumped = Record::new(context(5, f.hash()), Entry::new("a", "b", "c")).unwrap();
        let d = seg_only(concat(&[&f, &jumped], &[]));
        assert_corrupt(
            TrailReader::open(&d.0, TRAIL, None),
            "sequence gap inside sealed run segment",
            0,
        );
    }
    #[test]
    fn pin_open_fallback_attestation_general_branch_broken_link_pair() {
        // Two rotated segments: seg0 seals state at cp0; seg1 opens with
        // h5 (seq=5), then a fragment, then a broken-link seq=6. The
        // fragment+broken pair reaches the general-branch
        // `check_attestation` call in the fallback body on seg1.
        let f = cp0();
        let h5 = Record::new(context(5, [0; 32]), Entry::new("actor", "change", "object")).unwrap();
        let broken = Record::new(
            context(6, [42; 32]),
            Entry::new("actor", "change", "object"),
        )
        .unwrap();
        let d = two_segs(
            line(&f),
            [line(&h5), b"{\"torn\":\n".to_vec(), line(&broken)].concat(),
        );
        assert_corrupt(
            TrailReader::open(&d.0, TRAIL, None),
            "missing or mismatched repair attestation",
            0,
        );
    }
    #[test]
    fn pin_open_fallback_first_successor_does_not_close() {
        // seg0 ends with a trailing fragment (unsealed); seg1 opens with
        // a Checkpoint that correctly links cp0 but with the wrong fold.
        // The fallback trial fails on MMR mismatch → closing=false,
        // broken=false, Checkpoint → the `first successor does not close
        // sealed run` branch in feed_record_apply_tolerant.
        let f = cp0();
        let wrong_opening = cp(1, f.hash(), &alt_fold());
        let d = two_segs(
            [line(&f), b"{\"torn\":".to_vec()].concat(),
            line(&wrong_opening),
        );
        assert_corrupt(
            TrailReader::open(&d.0, TRAIL, None),
            "first successor does not close sealed run",
            0,
        );
    }
    #[test]
    fn boundary_resume_sealed_run_rotated_successor_lacks_immediate_resume() {
        // seg0 is a sealed-run segment (cp0 + trailing fragment); seg1
        // opens with a correct closing cp1, then a non-resume entry.
        // `feed_record_apply_tolerant`'s count==1 && closing &&
        // !is_resume branch fires `first successor lacks immediate
        // resume`.
        let f = cp0();
        let close = cp(1, f.hash(), &seeded(&f));
        let d = two_segs(
            [line(&f), b"{\"torn\":".to_vec()].concat(),
            concat(&[&close, &entry(&close)], &[]),
        );
        assert_corrupt(
            TrailReader::open(&d.0, TRAIL, None),
            "first successor lacks immediate resume",
            0,
        );
    }
    #[test]
    fn boundary_resume_fragment_only_rotated_successor_lacks_immediate_resume() {
        // seg0 is fragment-only (no records); seg1 opens with a
        // root-linked cp5 (closing the inherited run), then a non-resume
        // entry. `feed_record_apply_tolerant`'s count==1 && closing &&
        // !is_resume branch fires `first successor lacks immediate
        // resume`.
        let close = cp_root(5);
        let d = two_segs(
            b"{\"torn\":".to_vec(),
            concat(&[&close, &entry(&close)], &[]),
        );
        assert_corrupt(
            TrailReader::open(&d.0, TRAIL, None),
            "first successor lacks immediate resume",
            0,
        );
    }
    #[test]
    fn pin_open_fallback_first_successor_lacks_resume_eof() {
        // seg0 unsealed; seg1 is just a correct closing cp (no second
        // record), so `must_close && run_flag` in `finish_tolerant`
        // fires `first successor lacks resume`.
        let f = cp0();
        let close = cp(1, f.hash(), &seeded(&f));
        let d = two_segs([line(&f), b"{\"torn\":".to_vec()].concat(), line(&close));
        assert_corrupt(
            TrailReader::open(&d.0, TRAIL, None),
            "first successor lacks resume",
            0,
        );
    }
    #[test]
    fn pin_open_fallback_invalid_undamaged_segment() {
        // A rotated segment with a single root-linked cp(7) (prev==genesis
        // but seq>0) parses cleanly through the fallback body but is
        // neither damaged nor inside an inherited run, so `finish_tolerant`
        // fires `invalid undamaged segment` before the pending-resume
        // check.
        let d = seg_only(line(&cp_root(7)));
        assert_corrupt(
            TrailReader::open(&d.0, TRAIL, None),
            "invalid undamaged segment",
            0,
        );
    }
    #[test]
    fn pin_open_fallback_resume_checkpoint_lacks_declaration() {
        // cp(7) root-linked sets pending_resume; the trailing "not json\n"
        // marks the segment damaged (so the `invalid undamaged segment`
        // guard is skipped) and the state's pending_resume=true then
        // fires `resume checkpoint lacks its declaration` in
        // `finish_tolerant`.
        let d = seg_only([line(&cp_root(7)), b"not json\n".to_vec()].concat());
        assert_corrupt(
            TrailReader::open(&d.0, TRAIL, None),
            "resume checkpoint lacks its declaration",
            0,
        );
    }

    // --- Section 2: refresh() with opening=false ---------------------
    // The three sites previously held in `PENDING_R0B` are refresh's
    // own guards: the live file must exist, must not shrink below the
    // cached length, and the retained old descriptor must not have
    // been truncated below the cached length after a rotation.

    fn held_reader() -> (Temp, TrailReader, Record) {
        let d = Temp::new();
        let first = fixture(&d.0);
        let reader = open(&d.0);
        // Populate cache.state.length by reading the current head.
        assert_eq!(head(&reader), Head::of(&first));
        (d, reader, first)
    }

    #[test]
    fn refresh_missing_live_file() {
        let (d, reader, _) = held_reader();
        fs::remove_file(d.0.join("audit.jsonl")).unwrap();
        assert_corrupt(
            reader.with_current(|_| Ok(()), |_, _, _| Ok(())),
            "missing live file",
            0,
        );
    }
    #[test]
    fn refresh_live_file_shrank_below_cached_length() {
        let (d, reader, _) = held_reader();
        // Truncate in place: the inode is unchanged, so refresh takes
        // the same-inode branch and the cached-length guard fires.
        fs::OpenOptions::new()
            .write(true)
            .open(d.0.join("audit.jsonl"))
            .unwrap()
            .set_len(0)
            .unwrap();
        assert_corrupt(
            reader.with_current(|_| Ok(()), |_, _, _| Ok(())),
            "live file shrank below cached length",
            0,
        );
    }
    #[test]
    fn refresh_old_live_descriptor_was_truncated_after_rotation() {
        let (d, reader, first) = held_reader();
        let mut mmr = seeded(&first);
        rotated(&d.0, &first, &mut mmr, 0);
        // The reader still holds the fd of the renamed segment; truncate
        // that inode so refresh's different-inode branch sees old.len=0.
        fs::OpenOptions::new()
            .write(true)
            .open(segment(&d.0, 0))
            .unwrap()
            .set_len(0)
            .unwrap();
        assert_corrupt(
            reader.with_current(|_| Ok(()), |_, _, _| Ok(())),
            "old live descriptor was truncated",
            0,
        );
    }

    // --- Section 3: resume paths ------------------------------------
    // `predecessor_run` errors surface through `Sink::resume`; a bogus
    // `.audit-resume.jsonl` staging seen by `Sink::open` triggers the
    // Discarded outcome inside `promote_resume`, which unlinks the
    // staging without clobbering the live file.

    #[test]
    fn resume_surfaces_corrupt_predecessor_fallback() {
        use crate::audit::sink::{Config, Sink};
        use std::sync::Arc;
        let d = Temp::new();
        let first = cp0();
        // Rotated segment that fails strict scan and trips the fallback
        // body's `invalid audit record in sealed run` guard
        // (`feed_record_err_tolerant`).
        fs::write(segment(&d.0, 0), [line(&first), b"{}\n".to_vec()].concat()).unwrap();
        fs::write(d.0.join("audit.jsonl"), line(&first)).unwrap();
        trail_marker(&d);
        assert_corrupt(
            Sink::resume(
                &d.0,
                Arc::new(crate::audit::KeyFileSigner::from_hex(&"27".repeat(32)).unwrap()),
                Config::default(),
                Head::of(&first),
                0,
                "operator".into(),
                "incident".into(),
            )
            .map(|(sink, _, _)| drop(sink)),
            "invalid audit record in sealed run",
            0,
        );
    }
    #[test]
    fn settle_discards_bogus_resume_staging() {
        use crate::audit::sink::{ResumeOutcome, promote_resume};
        use std::sync::atomic::AtomicBool;
        // Staging that actually reaches `scan_staged`: two records,
        // Checkpoint + Entry with " file=-", so `valid_file` is true
        // and the short-circuit in
        //   `let valid = valid_file && scan_staged(..).is_ok();`
        // does invoke `scan_staged`. The opening is the Section 4
        // archived-base `cp(7, [42;32], genesis_fold)`, which
        // `scan_staged` rejects as "initial checkpoint does not link
        // genesis" (see `scan_staged_rejects_archived_base_without_root_link`).
        // `promote_resume` therefore takes the Discarded branch and
        // unlinks the staging. Dropping `scan_staged` from `valid`
        // leaves `valid = valid_file = true`, which flips `outcome`
        // to Promoted and renames the staging in place; swapping
        // Promoted/Discarded in the return flips the outcome without
        // the file-system side effect. Either mutant makes
        // `assert_eq!(outcome, Discarded)` or the staging-removal
        // assertion fail (exit 101).
        let d = Temp::new();
        trail_marker(&d);
        let archived = cp(7, [42; 32], &genesis_fold());
        let r = declaration(&archived, 0, [42; 32], 6, None);
        fs::write(
            d.0.join(".audit-resume.jsonl"),
            concat(&[&archived, &r], &[]),
        )
        .unwrap();
        let dir_f = File::open(&d.0).unwrap();
        let staged = File::open(d.0.join(".audit-resume.jsonl")).unwrap();
        let outcome = promote_resume(
            &staged,
            &dir_f,
            (None, false),
            TRAIL,
            &AtomicBool::new(false),
            false,
        )
        .unwrap();
        assert_eq!(outcome, ResumeOutcome::Discarded);
        assert!(!d.0.join(".audit-resume.jsonl").exists());
        // The error-string pin that stood here (`include_str!("sink.rs")
        // .contains("io_error(\"resume staging discarded after
        // validation\")")`) is dropped: no path reachable from this test
        // module surfaces that exact detail -- it is produced by
        // `Sink::resume` in `sink.rs`, not by `promote_resume`, and
        // `Sink::resume` runs full `initial(..)` validation beneath the
        // discard which this suite's layouts do not satisfy. Pinning
        // the behaviour we actually drive (`ResumeOutcome::Discarded`
        // and the staging unlink above) is proof enough for the mutants
        // listed in the PR body; a source-text contains() check is not.
    }

    // --- Section 4: scan_staged's archived-base rejection -----------
    // `cp(7, [42;32], genesis_fold)` is an archived prefix: ordinary
    // `scan` accepts it (see `accepted_archived_base`), but `scan_staged`
    // runs with genesis=true so the first checkpoint must link genesis.

    #[test]
    fn scan_staged_rejects_archived_base_without_root_link() {
        let d = Temp::new();
        let archived = cp(7, [42; 32], &genesis_fold());
        let r = declaration(&archived, 0, [42; 32], 6, None);
        w(&d, &concat(&[&archived, &r], &[]));
        // `scan` is Ok on this file (R0a's accepted_archived_base).
        assert!(scc(&o(&d), None, true).is_ok());
        assert_corrupt(
            scan_staged(&o(&d), TRAIL, None, false),
            "initial checkpoint does not link genesis",
            0,
        );
    }

    // --- Section 5: named layouts -----------------------------------

    #[test]
    fn boundary_resume_sealed_run_live_lacks_matching_immediate_resume() {
        // seg0 unsealed; the live file opens with a correct cp1, then
        // a non-resume entry. scan_inner's live-path hits `feed_record`'s
        // `unclosed segment lacks matching immediate resume` guard
        // before apply, which is a different site from the rotated-
        // successor `first successor lacks immediate resume` pin above.
        let d = Temp::new();
        let first = cp0();
        let close = cp(1, first.hash(), &seeded(&first));
        fs::write(
            segment(&d.0, 0),
            [line(&first), b"{\"torn\":".to_vec()].concat(),
        )
        .unwrap();
        write_records(&d.0, &[&close, &entry(&close)]);
        assert_corrupt(
            TrailReader::open(&d.0, TRAIL, None),
            "unclosed segment lacks matching immediate resume",
            0,
        );
    }
    #[test]
    fn boundary_resume_fragment_only_live_lacks_matching_immediate_resume() {
        // seg0 fragment-only; live opens with a root-linked cp5 then a
        // non-resume entry. scan_inner's `feed_record`
        // `unclosed segment lacks matching immediate resume` guard
        // fires before apply.
        let d = Temp::new();
        let close = cp_root(5);
        fs::write(segment(&d.0, 0), b"{\"torn\":").unwrap();
        write_records(&d.0, &[&close, &entry(&close)]);
        assert_corrupt(
            TrailReader::open(&d.0, TRAIL, None),
            "unclosed segment lacks matching immediate resume",
            0,
        );
    }
    #[test]
    fn opening_mmr_mismatch_closing_opening() {
        // Live-file layout where the second record is a sealed-run
        // close+open opening whose claimed MMR disagrees with the fold.
        // `apply_checked`'s MMR comparison fires `checkpoint MMR differs
        // from preceding records` before any boundary-handling branch.
        let d = Temp::new();
        let first = cp0();
        let wrong_close = cp(1, first.hash(), &alt_fold());
        w(&d, &concat(&[&first, &wrong_close], &[]));
        assert_corrupt(
            TrailReader::open(&d.0, TRAIL, None),
            "checkpoint MMR differs from preceding records",
            0,
        );
    }
    #[test]
    fn hash_link_boundary_rejected_on_live_open_strict_scan_and_refresh() {
        // 197-d1 point 8: [cp0, e1, x(seq=1, prev=e1.hash, other
        // content)]. The surviving `<=` → `<` mutant on the hash-link
        // check turns this into "sequence gap without checkpoint", so
        // detail-equality kills it. Pinned on live open, direct scan
        // and refresh.
        let first = cp0();
        let e1 = Record::new(
            context(1, first.hash()),
            Entry::new("actor", "change", "object"),
        )
        .unwrap();
        let x = Record::new(
            context(1, e1.hash()),
            Entry::new("other", "content", "here"),
        )
        .unwrap();

        // Live open: scan_closing hits `apply_checked`'s hash-link
        // check (`record rolled back, changed or broke its hash link`).
        let d_open = Temp::new();
        write_records(&d_open.0, &[&first, &e1, &x]);
        assert_corrupt(
            TrailReader::open(&d_open.0, TRAIL, None),
            "record rolled back, changed or broke its hash link",
            0,
        );

        // Direct strict scan: same bytes, same site through scc.
        assert_corrupt(
            scc(&o(&d_open), None, true),
            "record rolled back, changed or broke its hash link",
            0,
        );

        // Refresh: open on [cp0, e1], append x, with_current refreshes
        // through `scan` with opening=false and hits the same site.
        let d_refresh = Temp::new();
        write_records(&d_refresh.0, &[&first, &e1]);
        let reader = open(&d_refresh.0);
        assert_eq!(head(&reader), Head::of(&e1));
        append(&d_refresh.0.join("audit.jsonl"), &x);
        assert_corrupt(
            reader.with_current(|_| Ok(()), |_, _, _| Ok(())),
            "record rolled back, changed or broke its hash link",
            0,
        );
    }
    #[test]
    fn genesis_closer_accepted_after_fragment_only_first_segment() {
        // Section 5 named layout, accepted outcome: a fragment-only
        // first segment is closed by a genesis closer -- a cp that
        // links genesis plus an immediate resume declaration -- in the
        // live file. `TrailReader::open` accepts the trail, and
        // `history_segment` reports the fragment-only seg0 as a run
        // through its `&mut run` out parameter (the API that exposes
        // run membership to the readers).
        let d = Temp::new();
        fs::write(segment(&d.0, 0), b"{\"torn\":").unwrap();
        let opening = cp_root(5);
        let resume = declaration(&opening, 0, Record::genesis(&TRAIL), 4, None);
        write_records(&d.0, &[&opening, &resume]);
        let reader = TrailReader::open(&d.0, TRAIL, None).unwrap();
        assert_eq!(head(&reader), Head::of(&resume));
        // Which segments are runs: history_segment reports run=true on
        // the fragment-only seg0 (its unparsable tail cannot close the
        // chain). scan_closing then accepts the live file, so the
        // outer open succeeds.
        let seg0 = File::open(segment(&d.0, 0)).unwrap();
        let mut run = false;
        let state = history_segment(
            crate::audit::runs::Reaction::Stop,
            &seg0,
            TRAIL,
            None,
            true,
            None,
            &mut None,
            &mut run,
        )
        .unwrap()
        .0;
        assert!(run, "fragment-only seg0 belongs to a run");
        assert!(state.is_none(), "no complete record in seg0 to carry state");
    }

    /// S3a′ S2 (ruling 197-d1 addendum 17.1): strict Stop
    /// `Line::Record(Err(_))` preserves today's detail
    /// (`invalid audit line or opening checkpoint`), which is the
    /// same detail `feed_unparsable` emits via `invalid_opening_line()`.
    /// The refactor routes `Record(Err)` into
    /// `Classifier::feed_record_err_strict`, which reuses that helper;
    /// no new construction site is added.
    #[test]
    fn pin_sc_record_err_strict_reuses_invalid_opening_line_detail() {
        let d = Temp::new();
        let f = cp0();
        // Append a record-err: a line that parses as JSON but is not a
        // valid vigil record. `super::lines::classify` on such a
        // payload returns `Line::Record(Err(_))`.
        let bad = br#"{"resourceLogs":[{"scopeLogs":[{"logRecords":[{}]}]}]}"#;
        w(&d, &[line(&f), bad.to_vec(), b"\n".to_vec()].concat());
        assert_corrupt(
            scc(&o(&d), None, true),
            "invalid audit line or opening checkpoint",
            0,
        );
    }

    // ---- S3b1a: SegmentSource / SegmentBytes pins ----------------------
    // Ruling 197-d1 addendum 25.2 + S3b1a brief: byte-source properties
    // that S3b1b will rely on. Each row must pass at base `320a7d9` and
    // at head (this PR changes no behaviour). Together they pin the
    // laziness of `SegmentSource::next_segment`, the cross-segment glue
    // byte check, the `on_feed` offset bookkeeping across refresh-append,
    // and `decode_line_kind`'s Fragment-vs-Unparsable mapping.

    fn fifo_segment(d: &Temp, id: usize) {
        assert!(
            Command::new("mkfifo")
                .arg(segment(&d.0, id))
                .status()
                .unwrap()
                .success()
        );
    }

    /// SB1 live-open order: a corrupt rotated_0 (seg_only concat) plus a
    /// non-regular rotated_1 (FIFO) sits in the directory. `TrailReader
    /// ::open` must surface **seg_0's** `invalid audit record in sealed
    /// run`, not a `nonregular trail file` from eagerly probing seg_1.
    /// Kills MA1 (eager open-up-front) because eager would error on
    /// seg_1's open before seg_0's tolerant walk runs.
    #[test]
    fn sb1_liveopen_base_order_short_circuits_on_segment_0_error() {
        let d = seg_only(concat(&[&cp0()], b"{}\n"));
        fifo_segment(&d, 1);
        assert_corrupt(
            TrailReader::open(&d.0, TRAIL, None),
            "invalid audit record in sealed run",
            0,
        );
    }

    /// SB1 refresh-rotate order: the prelude walk surfaces its own
    /// `invalid audit record in sealed run` BEFORE `segments_after`
    /// runs its directory listing. Proves addendum 25.2: on
    /// `refresh-rotate`, the base order is "walk prelude first, then
    /// list newer segments". Kills MA5 (prelude skipped: refresh would
    /// reach the valid live and return Ok instead of the pinned Err)
    /// AND the B1 regression where `for_refresh_rotate` listed
    /// `segments_after` eagerly at construction time — because with
    /// `chmod 0300` the directory can't be listed, so eager listing
    /// would surface `Io Permission denied` before the prelude walk
    /// ever started.
    #[test]
    fn sb1_refresh_rotate_prelude_walks_before_segments_after() {
        use std::os::unix::fs::PermissionsExt;
        let d = Temp::new();
        let first = fixture(&d.0);
        let reader = open(&d.0);
        // Append corrupt bytes to the cached inode BEFORE rotating, so
        // the renamed file (soon-to-be prelude) carries them. The
        // reader's descriptor keeps pointing to the same inode.
        append_bytes(&d.0.join("audit.jsonl"), b"{}\n");
        fs::rename(d.0.join("audit.jsonl"), segment(&d.0, 0)).unwrap();
        // Fresh live with a cp1-based opening keeps refresh in the
        // rotate branch (different inode). Then `chmod 0300` on the
        // directory makes any later `rotated_names_at` / `statat` fail
        // with EACCES, so the two orderings surface distinct errors:
        // prelude-first → the corrupt-prelude's `CorruptTrail`;
        // segments_after-first → `Io Permission denied`.
        let opening = cp(1, first.hash(), &seeded(&first));
        fs::write(d.0.join("audit.jsonl"), line(&opening)).unwrap();
        fs::set_permissions(&d.0, fs::Permissions::from_mode(0o300)).unwrap();
        let r = reader.with_current(|_| Ok(()), |_, _, _| Ok(()));
        fs::set_permissions(&d.0, fs::Permissions::from_mode(0o700)).unwrap();
        assert_corrupt(r, "invalid audit record in sealed run", 0);
    }

    /// SB2 glue across segments, live open: an unterminated-last
    /// rotated segment followed by a terminated live file whose
    /// opening is a fresh checkpoint linking to rotated_0's head.
    /// Base-identical: `history_segment(opening=true)` and
    /// `scan_closing(opening=true)` both run with
    /// `needs_glue_check=false` at the segment boundary (opening=true
    /// forces a fresh offset), so live-open returns Ok with the
    /// cache's final `State` fully pinned. A SegmentBytes bookkeeping
    /// drift (MA3-style) that produced the wrong `offset` or
    /// `length` across the transition would move the pinned tuple.
    #[test]
    fn sb2_glue_across_segments_live_open_ok() {
        let d = Temp::new();
        let f = cp0();
        // rotated_0 ends without LF on cp0.
        let mut seg0 = line(&f);
        assert!(seg0.pop() == Some(b'\n'));
        fs::write(segment(&d.0, 0), &seg0).unwrap();
        // Live file: fresh opening checkpoint cp1 linked to cp0's
        // hash, so the opening check succeeds across the segment
        // transition.
        let opening = cp(1, f.hash(), &seeded(&f));
        fs::write(d.0.join("audit.jsonl"), line(&opening)).unwrap();
        let reader = TrailReader::open(&d.0, TRAIL, None).unwrap();
        let live_len = line(&opening).len() as u64;
        reader
            .with_current(
                |_| Ok(()),
                |_, _, s| {
                    assert_eq!(s.offset, live_len);
                    assert_eq!(s.length, live_len);
                    assert!(s.newline);
                    assert!(s.gap.is_none());
                    Ok(())
                },
            )
            .unwrap();
    }

    /// SB2 glue across segments, refresh rotate: the cached live
    /// ends without LF on cp0, and is rotated into seg_0 as-is. The
    /// fresh live carries a cp1 opening that links to cp0. On
    /// refresh, the rotate branch walks the prelude first (seg_0's
    /// unterminated cp0 bytes), which the shared `SegmentSource`
    /// yields before listing newer segments; the trailing live is
    /// then scanned as its own opening segment. Pins the FINAL
    /// `(offset, length, newline, gap)` tuple from the live scan,
    /// which must land exactly at the end of cp1 with a trailing LF.
    /// Kills the byte-bookkeeping mutants on the live-segment scan:
    /// `MA3` (`note_record_fed` offset off-by-one) and `MA3b`
    /// (`offset_cursor` off-by-one) move `offset` and `length` away
    /// from the pinned cp1 line length; `NRF2` (drops the
    /// `last_offset` write) leaves `offset = 1471` (the prelude
    /// cursor) instead of the cp1 record boundary.
    #[test]
    fn sb2_glue_across_segments_refresh_rotate_ok() {
        let d = Temp::new();
        // Seed cached state with an unterminated cp0.
        let f = cp0();
        let mut cached_bytes = line(&f);
        assert!(cached_bytes.pop() == Some(b'\n'));
        fs::write(d.0.join("audit.jsonl"), &cached_bytes).unwrap();
        let reader = TrailReader::open(&d.0, TRAIL, None).unwrap();
        // Rotate the unterminated cached file as-is; the prelude
        // intentionally ends without LF so the refresh-rotate walk
        // enters its glue-check branch on the prelude segment.
        fs::rename(d.0.join("audit.jsonl"), segment(&d.0, 0)).unwrap();
        let opening = cp(1, f.hash(), &seeded(&f));
        fs::write(d.0.join("audit.jsonl"), line(&opening)).unwrap();
        let live_len = line(&opening).len() as u64;
        reader
            .with_current(
                |_| Ok(()),
                |_, _, s| {
                    assert_eq!(s.offset, live_len);
                    assert_eq!(s.length, live_len);
                    assert!(s.newline);
                    assert!(s.gap.is_none());
                    Ok(())
                },
            )
            .unwrap();
    }

    /// SB3 refresh-append bookkeeping: after each refresh-append, pin
    /// the exact [`State`] field tuple (`offset`, `length`, `newline`,
    /// `gap`). An off-by-one in `SegmentBytes::note_record_fed` moves
    /// `offset` away from the record boundary; a wrong `offset_cursor`
    /// bump breaks `length`. Kills MA3.
    #[test]
    fn sb3_refresh_append_bookkeeping_pins_state() {
        let d = Temp::new();
        let first = fixture(&d.0);
        let reader = open(&d.0);
        let first_len = line(&first).len() as u64;
        reader
            .with_current(
                |_| Ok(()),
                |_, _, s| {
                    assert_eq!(s.offset, first_len);
                    assert_eq!(s.length, first_len);
                    assert!(s.newline);
                    assert!(s.gap.is_none());
                    Ok(())
                },
            )
            .unwrap();
        let e1 = entry(&first);
        let e1_len = line(&e1).len() as u64;
        append(&d.0.join("audit.jsonl"), &e1);
        reader
            .with_current(
                |_| Ok(()),
                |_, _, s| {
                    assert_eq!(s.offset, first_len + e1_len);
                    assert_eq!(s.length, first_len + e1_len);
                    assert!(s.newline);
                    assert!(s.gap.is_none());
                    Ok(())
                },
            )
            .unwrap();
        let e2 = entry(&e1);
        let e2_len = line(&e2).len() as u64;
        append(&d.0.join("audit.jsonl"), &e2);
        reader
            .with_current(
                |_| Ok(()),
                |_, _, s| {
                    assert_eq!(s.offset, first_len + e1_len + e2_len);
                    assert_eq!(s.length, first_len + e1_len + e2_len);
                    assert!(s.newline);
                    assert!(s.gap.is_none());
                    Ok(())
                },
            )
            .unwrap();
    }

    /// SB4 fragment at a segment END, exercised through a real
    /// multi-segment path: `seg_0 = [cp0, "{\"torn\":"]` (fragment
    /// without LF at the end of the sealed segment) plus a cp1 live.
    /// `TrailReader::open` walks seg_0 first through
    /// `history_segment`, which lands a repair gap with `newline=
    /// false`; the trailing live then enters its own scan with a
    /// pending resume from the unterminated boundary and no resume
    /// declaration follows. Pins the multi-segment open outcome.
    #[test]
    fn sb4_fragment_at_segment_end_multi_segment() {
        let f = cp0();
        let fragment = b"{\"torn\":";
        let d = Temp::new();
        fs::write(segment(&d.0, 0), [line(&f), fragment.to_vec()].concat()).unwrap();
        let cp1_rec = cp(1, f.hash(), &seeded(&f));
        fs::write(d.0.join("audit.jsonl"), line(&cp1_rec)).unwrap();
        assert_corrupt(
            TrailReader::open(&d.0, TRAIL, None),
            "resume checkpoint lacks its declaration",
            0,
        );
    }

    /// SB4 fragment at a segment START, exercised through the
    /// multi-segment `history_segment` tolerant fallback over a
    /// predecessor sealed-state: a fragment is the FIRST tolerant-
    /// decoded line of the second call. Layout: the first `hsc` on
    /// `[cp0]` yields a sealed state; the second `hsc` on
    /// `[fragment, cp0]` reads `{"torn":\n` as its first line,
    /// which must decode as Fragment and start a repair gap, so
    /// when the tolerant walk then folds a duplicate cp0 (seq=0)
    /// the sealed-run seq check fires and the pinned detail is
    /// `"record sequence did not increase inside sealed run"`
    /// (occurrence 0). Under MA4 the first line would decode as
    /// Unparsable and this layout's error would flip to
    /// `"unparsable line before complete record"`.
    #[test]
    fn sb4_fragment_at_segment_start_multi_segment() {
        let f = cp0();
        let d_a = Temp::new();
        w(&d_a, &line(&f));
        let state_a = hsc(&o(&d_a), None, true, false)
            .expect("seg a Ok")
            .expect("state=Some");
        let fragment = b"{\"torn\":\n";
        let d_b = Temp::new();
        w(&d_b, &[fragment.to_vec(), line(&f)].concat());
        assert_corrupt(
            hsc(&o(&d_b), Some(state_a), true, false),
            "record sequence did not increase inside sealed run",
            0,
        );
    }

    /// MX2 / MX3 killer: on a strict path, the glue byte must set
    /// BOTH `last_offset` and `last_newline` to `(offset_cursor,
    /// true)`. Pins `(offset, length, newline) = (1472, 1472, true)`
    /// (the head value for `state_unterminated` → append `"\n"` →
    /// `scan(opening=false)`), then appends an attested entry and
    /// confirms the next `scan` returns Ok. Mutants that drop the
    /// `last_newline = true` write (MX2) or the `last_offset =
    /// offset_cursor` write (MX3) would move the pinned tuple away
    /// from `(X+1, X+1, true)`.
    #[test]
    fn mx2_mx3_strict_glue_sets_last_offset_and_last_newline() {
        let (d, s, f) = state_unterminated();
        let unterm_len = s.offset;
        append_bytes(&d.0.join("audit.jsonl"), b"\n");
        let after = scc(&o(&d), Some(s.clone()), false).unwrap();
        assert_eq!(after.offset, unterm_len + 1);
        assert_eq!(after.length, unterm_len + 1);
        assert!(after.newline);
        let e1 = entry(&f);
        append_bytes(&d.0.join("audit.jsonl"), &line(&e1));
        let again = scc(&o(&d), Some(after), false).expect("scan continues Ok");
        assert_eq!(again.length, unterm_len + 1 + line(&e1).len() as u64);
    }

    /// MX4 killer: on a tolerant path, the lazy glue-byte branch of
    /// `SegmentBytes::next_event` must bump `offset_cursor` after a
    /// successful `\n`. Layout: an unterminated cp0, then append
    /// `"\nnot json\n"`, then `history_segment(opening=false, run=true)`.
    /// The glue byte `\n` consumes one byte, the unparsable
    /// `"not json\n"` consumes the rest. Pins
    /// `length = unterm_len + 10` (9 bytes of `not json\n` plus the
    /// glue byte). A mutant that drops the `offset_cursor += 1`
    /// after the tolerant glue-byte check (MX4) would record
    /// `length = unterm_len + 9`.
    #[test]
    fn mx4_tolerant_glue_bumps_offset_cursor() {
        let (d, s, _f) = state_unterminated();
        let unterm_len = s.offset;
        append_bytes(&d.0.join("audit.jsonl"), b"\nnot json\n");
        let res = hsc(&o(&d), Some(s), false, true).expect("history_segment Ok");
        let state = res.expect("Some(state) when the initial state was Some");
        assert_eq!(state.length, unterm_len + 10);
    }

    /// MH5 killer: on a strict refresh over an unterminated state
    /// with no new bytes, `consume_glue_byte` must return `Ok(false)`
    /// (count=0 at EOF), NOT `Ok(true)`. The merged helper's EOF
    /// branch feeds `check_glue_byte_strict`, so returning `true` on
    /// EOF would promote `last_newline` to `true` through the
    /// strict-side glue promotion while leaving `offset_cursor`
    /// unchanged; the state would appear terminated and a later
    /// refresh would stop checking for glue bytes. Pins
    /// `(offset, length, newline)` first with no new bytes, so the
    /// mutant's spurious `last_newline = true` flips the pinned
    /// `false`. Then appends an `x` byte and refreshes again: the
    /// base reader errors with `bytes glued to complete unterminated
    /// record` because the glue byte must be LF.
    #[test]
    fn mh5_strict_glue_eof_returns_false() {
        let (d, s, _f) = state_unterminated();
        let unterm_len = s.offset;
        let after = scc(&o(&d), Some(s.clone()), false).expect("scan Ok at EOF");
        assert_eq!(after.offset, unterm_len);
        assert_eq!(after.length, unterm_len);
        assert!(!after.newline);
        append_bytes(&d.0.join("audit.jsonl"), b"x");
        assert_corrupt(
            scc(&o(&d), Some(after), false),
            "bytes glued to complete unterminated record",
            0,
        );
    }

    /// SCN1 killer: on a strict path, `scan_inner` builds
    /// `State { length: bytes.offset_cursor() }`, not
    /// `bytes.last_offset()`. The two diverge when a Fragment is
    /// decoded on an opening segment: strict's `feed_fragment`
    /// extends the gap hasher and returns Ok (the fragment is NOT
    /// an opening-line violation here, because a complete record
    /// is in scope), so the walk finishes with `last_offset` at
    /// the record boundary but `offset_cursor` past the fragment
    /// bytes. Layout:
    /// `[cp0, "{\"torn\":"]` (fragment at end, no LF). Pins
    /// `offset = len(cp0)` (last_offset at the record boundary)
    /// and `length = len(cp0) + 8` (cursor past the fragment).
    /// Under SCN1 (`length: last_offset()`), length would collapse
    /// to `len(cp0)` and this test would fail.
    #[test]
    fn scn1_strict_fragment_length_is_offset_cursor() {
        let f = cp0();
        let fragment = b"{\"torn\":";
        let d = Temp::new();
        w(&d, &[line(&f), fragment.to_vec()].concat());
        let s = scc(&o(&d), None, true).expect("strict Ok with gap after fragment");
        let cp0_len = line(&f).len() as u64;
        assert_eq!(s.offset, cp0_len);
        assert_eq!(s.length, cp0_len + fragment.len() as u64);
        assert!(!s.newline);
        assert!(s.gap.is_some());
    }

    // ---- Coverage gate --------------------------------------------------

    const UNREACHABLE: &[(&str, usize, &str)] = &[
        (
            "checkpoint MMR differs from preceding records",
            1,
            "Addendum 16 point 2 (17.3 / 19.2): fold (iii) salvage push in feed_record_apply_tolerant records the Violation into the collector's vector without returning an AuditError; exercised by collector_tests::collector_fold_iii_mismatch_on_history_segment_opening_true_run_false (and its three per-path siblings) and collector_tests::collector_salvage_mmr_includes_the_checkpoint_leaf (no reader-side assert_corrupt).",
        ),
        (
            "missing written state",
            0,
            "State::after: apply always sets state=Some on Ok",
        ),
        (
            "missing head",
            0,
            "shared `runs::history_segment` walk: `feed_record_apply_tolerant` Ok leaves `classifier.state()=Some` so the defence-in-depth `Violation::MissingHead` construction after the apply is unreachable (addendum 20.1)",
        ),
        // `Classifier::feed_record` returns the new state from
        // `apply_checked` directly; its post-apply follow-up is a
        // classifier invariant with no inline `corrupt("missing head")`
        // call. The remaining `missing head` sites are both in
        // `runs.rs`: occ 0 is the shared `history_segment` walk's
        // UNREACHABLE defence-in-depth (above) and occ 1 is
        // `Classifier::finish`'s own construction (tested by
        // `pin_sc_missing_head_opening_false_*`).
        (
            "invalid opening peaks",
            0,
            "CheckpointFields::new rejects peaks.len() != popcount(size)",
        ),
        (
            "resume without predecessor",
            0,
            "state=None + non-Checkpoint fires 'missing initial checkpoint' first",
        ),
        (
            "MMR overflow",
            0,
            "apply_checked's fresh-Mmr genesis fold: Mmr::new() + push of one leaf cannot overflow size or miss peaks",
        ),
        (
            "MMR overflow",
            1,
            "apply_checked's main record fold: requires 2^64 leaves",
        ),
    ];

    // 197-d1 addendum 9: the gate parses Rust with `syn::parse_file`
    // instead of a hand-written lexer, so a bogus `assert_corrupt`
    // call cannot hide behind char literals (`'"'`, `'\''`, `'\u{22}'`,
    // `b'"'`, multi-byte chars like `'é'`), turbofish, a non-literal
    // detail/site arg, an alias (`let f = assert_corrupt;`) or any
    // other call shape. Each prior fix round closed one literal shape
    // and left the class open; parsing the real grammar closes the
    // class.
    //
    // 197-d1 addendum 10 threat model: this gate catches *drift* --
    // a `corrupt()` site added or renamed in `storage.rs` without a
    // matching pin in this file, or a pin whose `(detail, occurrence)`
    // label names no site. It does **not** defend against deliberate
    // sabotage by a test author who shadows, aliases, hides through a
    // macro or imports the helper under another name. Addendum 10's
    // round-4 fixes raise the bar against accidental shadowing so a
    // normal mistake cannot silently make an unpinned site look
    // covered:
    //   - exactly one `fn assert_corrupt` item is allowed, and it must
    //     live in `mod details`; any second `fn` item, or any
    //     `let`/binding/closure-arg pattern named `assert_corrupt`,
    //     fails the gate;
    //   - the identifier `assert_corrupt` anywhere inside a macro
    //     invocation's token stream (nested token groups recursively)
    //     fails the gate -- pins must be direct calls, not wrapped in
    //     `vec![...]`, `assert!({...})`, `proptest!`, etc.;
    //   - the identifier `assert_corrupt` anywhere in a `use` tree
    //     (plain import, group, rename as alias source or destination)
    //     fails the gate.
    //
    // Runtime exact-string asserts and per-site mutants remain the
    // proof that each pin fires. Known limit, stated on purpose:
    // reachability -- a static gate cannot prove a call is reached
    // (`if false { assert_corrupt(..) }`, an uncalled closure that
    // only ever appears as a direct call syntactically). Mutants are
    // the proof that each pin fires at runtime; see this module's
    // mutant proofs in the PR body.

    fn path_last_segment(path: &syn::Path) -> Option<&syn::Ident> {
        path.segments.last().map(|s| &s.ident)
    }

    fn parse_sites() -> Vec<(String, usize)> {
        // Addendum 16 point 4: the gate scans `storage.rs` for every
        // `corrupt("literal")` call (ExprCall whose callee ends in
        // `corrupt`, first arg is a string literal) and scans `runs.rs`
        // for every `Violation::<Variant>` construction expression
        // (ExprPath whose first segment is `Violation`), mapping each
        // variant to its `detail()` string via the single source of
        // truth [`runs::Violation::detail`]. Sites are collected in a
        // fixed file order (storage.rs first, then runs.rs) so the
        // `(detail, occurrence)` key stays stable across both files
        // -- the same key `assert_corrupt(result, "detail", site)` uses.
        // The pattern binding `v @ Violation::CheckpointMmrDiffers` in
        // `feed_record_apply_tolerant`'s salvage arm is NOT a
        // construction expression (patterns are not expressions), so
        // this scan does not double-count it.
        use crate::audit::runs::Violation;

        // Addendum 17.5: derive the variant set by syn-parsing
        // `enum Violation` from `runs.rs` (not from `Violation::ALL`),
        // and fail unless `ALL` equals it. A variant added to the enum
        // but missing from `ALL`, with a live construction site and no
        // pin, fails the gate: the site is counted and the pin is
        // missing.
        let parse_enum_variants = |file: &syn::File| -> HashSet<String> {
            let mut names = HashSet::new();
            for item in &file.items {
                if let syn::Item::Enum(e) = item
                    && e.ident == "Violation"
                {
                    for v in &e.variants {
                        names.insert(v.ident.to_string());
                    }
                }
            }
            names
        };
        let runs_pre: syn::File = syn::parse_file(RUNS_SRC)
            .expect("coverage gate: runs.rs is not valid Rust (parse_file failed)");
        let enum_variants: HashSet<String> = parse_enum_variants(&runs_pre);
        assert!(
            !enum_variants.is_empty(),
            "coverage gate: syn-parse of enum Violation yielded no variants",
        );
        let all_variants: HashSet<String> =
            Violation::ALL.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(
            enum_variants, all_variants,
            "coverage gate: enum Violation's variant set != Violation::ALL \
             (addendum 17.5: the ALL list must mirror the enum definition)",
        );

        // Variant-name → detail string. With the ALL==enum cross-check
        // above, every parsed enum variant also has a runtime detail().
        let name_to_detail: HashMap<String, &'static str> = Violation::ALL
            .iter()
            .map(|v| (format!("{v:?}"), v.detail()))
            .collect();

        struct CollectStorage {
            raw: Vec<String>,
        }
        impl<'ast> syn::visit::Visit<'ast> for CollectStorage {
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if let syn::Expr::Path(p) = &*call.func
                    && path_last_segment(&p.path).is_some_and(|i| i == "corrupt")
                    && let Some(syn::Expr::Lit(lit)) = call.args.first()
                    && let syn::Lit::Str(s) = &lit.lit
                {
                    self.raw.push(s.value());
                }
                syn::visit::visit_expr_call(self, call);
            }
        }

        // Addendum 17.5: exclude `#[cfg(test)]` code from site counting.
        // A `Violation::X` construction inside a `#[cfg(test)]` module or
        // item is a test, not a product site, and must not count.
        fn attrs_have_cfg_test(attrs: &[syn::Attribute]) -> bool {
            attrs.iter().any(|a| {
                a.path().is_ident("cfg")
                    && a.parse_args::<syn::Meta>().ok().is_some_and(|m| match m {
                        syn::Meta::Path(p) => p.is_ident("test"),
                        _ => false,
                    })
            })
        }

        struct CollectRuns<'a> {
            raw: Vec<String>,
            name_to_detail: &'a HashMap<String, &'static str>,
            in_pattern: usize,
            in_cfg_test: usize,
        }
        impl<'ast, 'a> syn::visit::Visit<'ast> for CollectRuns<'a> {
            fn visit_expr_path(&mut self, p: &'ast syn::ExprPath) {
                // Two-segment path `Violation::<Variant>`. `Self::X` paths
                // inside `impl Violation` have `Self` as the first segment
                // and are therefore skipped (the `const ALL` list and
                // `fn detail` are the enum's own definition, not call
                // sites). In syn 2.x `Pat::Path` wraps `ExprPath`, so a
                // pattern-position `Violation::<Variant>` (as in the fold
                // (iii) salvage arm `Err(Violation::CheckpointMmrDiffers)
                // if ... =>`) also reaches this visitor; the `in_pattern`
                // stack skips those — the salvage arm's pattern is NOT
                // a construction site (patterns match values, they do
                // not create them), the ONE construction for the salvage
                // is the explicit `self.collected.push((.., Violation::X))`
                // inside the arm body.
                if self.in_pattern == 0 && self.in_cfg_test == 0 {
                    let segs = &p.path.segments;
                    if segs.len() == 2
                        && segs[0].ident == "Violation"
                        && let Some(detail) = self.name_to_detail.get(&segs[1].ident.to_string())
                    {
                        self.raw.push((*detail).to_string());
                    }
                }
                syn::visit::visit_expr_path(self, p);
            }
            fn visit_pat(&mut self, p: &'ast syn::Pat) {
                self.in_pattern += 1;
                syn::visit::visit_pat(self, p);
                self.in_pattern -= 1;
            }
            fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
                let bump = attrs_have_cfg_test(&m.attrs);
                if bump {
                    self.in_cfg_test += 1;
                }
                syn::visit::visit_item_mod(self, m);
                if bump {
                    self.in_cfg_test -= 1;
                }
            }
            fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
                let bump = attrs_have_cfg_test(&f.attrs);
                if bump {
                    self.in_cfg_test += 1;
                }
                syn::visit::visit_item_fn(self, f);
                if bump {
                    self.in_cfg_test -= 1;
                }
            }
            fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
                let bump = attrs_have_cfg_test(&i.attrs);
                if bump {
                    self.in_cfg_test += 1;
                }
                syn::visit::visit_item_impl(self, i);
                if bump {
                    self.in_cfg_test -= 1;
                }
            }
            fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
                // Addendum 19.6: a `#[cfg(test)]` fn inside an `impl`
                // block is an `ImplItemFn`, not an `ItemFn`; without
                // this visit the gate would count its `Violation::X`
                // sites as product sites.
                let bump = attrs_have_cfg_test(&f.attrs);
                if bump {
                    self.in_cfg_test += 1;
                }
                syn::visit::visit_impl_item_fn(self, f);
                if bump {
                    self.in_cfg_test -= 1;
                }
            }
            fn visit_item_const(&mut self, c: &'ast syn::ItemConst) {
                let bump = attrs_have_cfg_test(&c.attrs);
                if bump {
                    self.in_cfg_test += 1;
                }
                syn::visit::visit_item_const(self, c);
                if bump {
                    self.in_cfg_test -= 1;
                }
            }
        }

        let mut raw: Vec<String> = Vec::new();
        let storage: syn::File = syn::parse_file(STORAGE_SRC)
            .expect("coverage gate: storage.rs is not valid Rust (parse_file failed)");
        let mut cs = CollectStorage { raw: Vec::new() };
        syn::visit::Visit::visit_file(&mut cs, &storage);
        raw.extend(cs.raw);
        let runs: syn::File = syn::parse_file(RUNS_SRC)
            .expect("coverage gate: runs.rs is not valid Rust (parse_file failed)");
        let mut cr = CollectRuns {
            raw: Vec::new(),
            name_to_detail: &name_to_detail,
            in_pattern: 0,
            in_cfg_test: 0,
        };
        syn::visit::Visit::visit_file(&mut cr, &runs);
        raw.extend(cr.raw);

        let mut counts: HashMap<String, usize> = HashMap::new();
        raw.into_iter()
            .map(|d| {
                let n = *counts.get(&d).unwrap_or(&0);
                counts.insert(d.clone(), n + 1);
                (d, n)
            })
            .collect()
    }

    fn parse_assertions(source: &str) -> Vec<(String, usize)> {
        // Every use of a path ending in `assert_corrupt` -- other than
        // the single helper `fn` item in `mod details` -- must be a
        // direct call whose detail argument is a string literal and
        // whose occurrence argument is an integer literal. Anything
        // else panics:
        //   - alias:        `let f = assert_corrupt;`
        //   - fn pointer:   `let f = assert_corrupt::<()>;`
        //   - non-literal:  `assert_corrupt(r, label, 0)`;
        //   - shadowing fn: a second `fn assert_corrupt<T>(...) {}` item;
        //   - binding pat:  `let assert_corrupt = ...;`, `|assert_corrupt| ...`;
        //   - macro-hidden: `vec![assert_corrupt::<()>(...)]`,
        //                   `assert!({ let f = assert_corrupt::<()>; ... })`;
        //   - use alias:    `use self::assert_corrupt as ac;`.
        // Dead-code calls (`if false { assert_corrupt(..); }`) still
        // register; see the known-limit note above.
        let file: syn::File = syn::parse_file(source)
            .expect("coverage gate: storage_tests.rs is not valid Rust (parse_file failed)");

        struct Visitor {
            found: Vec<(String, usize)>,
            // Addendum 10 fix 1: track every `fn assert_corrupt` item
            // we meet. Exactly one is allowed, and it must be in
            // `mod details` (the helper). Any other fails the gate.
            helper_count: usize,
            mod_stack: Vec<String>,
            helper_mod_stack: Option<Vec<String>>,
        }

        impl Visitor {
            fn record_call(&mut self, call: &syn::ExprCall) {
                // Direct call shape: `assert_corrupt(result, "detail", site)`
                // (3 args) or the same with a trailing `_site` placeholder
                // (4 args) if a caller ever adds one. Both detail (arg 1)
                // and site (arg 2) must be literal.
                assert!(
                    call.args.len() == 3 || call.args.len() == 4,
                    "coverage gate: assert_corrupt expects 3 or 4 args, got {}",
                    call.args.len(),
                );
                let detail = match &call.args[1] {
                    syn::Expr::Lit(l) => match &l.lit {
                        syn::Lit::Str(s) => s.value(),
                        _ => panic!(
                            "coverage gate: assert_corrupt detail arg is not a string literal \
                             (second arg must be a `\"...\"` literal)"
                        ),
                    },
                    _ => panic!(
                        "coverage gate: assert_corrupt detail arg is not a string literal \
                         (second arg must be a `\"...\"` literal, not a binding or expression)"
                    ),
                };
                let site = match &call.args[2] {
                    syn::Expr::Lit(l) => match &l.lit {
                        syn::Lit::Int(i) => i.base10_parse::<usize>().expect(
                            "coverage gate: assert_corrupt site arg does not parse as a usize",
                        ),
                        _ => panic!(
                            "coverage gate: assert_corrupt site arg is not an integer literal \
                             (third arg must be a `0`-style integer literal)"
                        ),
                    },
                    _ => panic!(
                        "coverage gate: assert_corrupt site arg is not an integer literal \
                         (third arg must be a `0`-style integer literal, not a binding)"
                    ),
                };
                self.found.push((detail, site));
            }

            // Addendum 10 fix 2: walk a macro's `TokenStream`, recursing
            // into nested `Group`s, and fail on any `Ident` equal to
            // `assert_corrupt`. `syn`'s `visit::Visit` stops at macro
            // boundaries, so `vec![assert_corrupt::<()>(...)]` and
            // `assert!({ let f = assert_corrupt::<()>; ... })` would be
            // invisible otherwise. String and char literals appear as
            // `TokenTree::Literal`, not `TokenTree::Ident`, so a panic
            // message that happens to contain the word "assert_corrupt"
            // does not trip this check.
            fn walk_macro_tokens(stream: proc_macro2::TokenStream) {
                use proc_macro2::TokenTree;
                for tt in stream {
                    match tt {
                        TokenTree::Group(g) => Self::walk_macro_tokens(g.stream()),
                        TokenTree::Ident(i) => assert!(
                            i != "assert_corrupt",
                            "coverage gate: `assert_corrupt` appears as an identifier \
                             inside a macro invocation's token stream; pins must be \
                             direct calls, not wrapped in `vec![...]`, \
                             `assert!({{ ... }})`, `proptest!`, etc."
                        ),
                        _ => {}
                    }
                }
            }
        }

        impl<'ast> syn::visit::Visit<'ast> for Visitor {
            fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
                self.mod_stack.push(m.ident.to_string());
                syn::visit::visit_item_mod(self, m);
                self.mod_stack.pop();
            }

            fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
                // The helper's own `fn assert_corrupt<T>(...)` definition
                // is not a use of the name -- walk its body but not its
                // signature. Any second such item is caught by
                // `helper_count` after the full traversal.
                if item.sig.ident == "assert_corrupt" {
                    self.helper_count += 1;
                    if self.helper_count == 1 {
                        self.helper_mod_stack = Some(self.mod_stack.clone());
                    }
                    syn::visit::visit_block(self, &item.block);
                    return;
                }
                syn::visit::visit_item_fn(self, item);
            }

            fn visit_pat_ident(&mut self, p: &'ast syn::PatIdent) {
                // Addendum 10 fix 1 (continued): a `let`/closure-arg/
                // match-arm/for-loop pattern binding the name
                // `assert_corrupt` would shadow the helper. Reject it.
                assert!(
                    p.ident != "assert_corrupt",
                    "coverage gate: `assert_corrupt` used as a binding pattern \
                     (let/closure-arg/match-arm/for-loop); the helper is a `fn` \
                     item and must not be shadowed"
                );
                syn::visit::visit_pat_ident(self, p);
            }

            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                // ExprCall::func may be an ExprPath (direct name) or an
                // ExprPath wrapped in generics (`assert_corrupt::<T>(..)`
                // still parses as ExprPath whose path has generic args
                // on the last segment). Either shape is a "direct call"
                // for addendum 9's purposes.
                let is_assert = matches!(
                    &*call.func,
                    syn::Expr::Path(p)
                        if path_last_segment(&p.path).is_some_and(|i| i == "assert_corrupt"),
                );
                if is_assert {
                    self.record_call(call);
                    // Walk the arguments so a nested `assert_corrupt`
                    // inside an arg is still inspected.
                    for arg in &call.args {
                        syn::visit::visit_expr(self, arg);
                    }
                    return;
                }
                syn::visit::visit_expr_call(self, call);
            }

            fn visit_expr_path(&mut self, p: &'ast syn::ExprPath) {
                // Any path-as-value reference to `assert_corrupt` that
                // did not get consumed by `visit_expr_call` above is an
                // alias, a fn-pointer coercion or some other non-call
                // use. Reject it.
                if path_last_segment(&p.path).is_some_and(|i| i == "assert_corrupt") {
                    panic!(
                        "coverage gate: `assert_corrupt` is referenced as a value \
                         (not a direct call); the gate only recognises \
                         `assert_corrupt(result, \"detail\", site)` call sites, \
                         not aliases (`let f = assert_corrupt;`) or fn pointers \
                         (`let f = assert_corrupt::<()>;`)"
                    );
                }
                syn::visit::visit_expr_path(self, p);
            }

            fn visit_macro(&mut self, mac: &'ast syn::Macro) {
                Self::walk_macro_tokens(mac.tokens.clone());
                syn::visit::visit_macro(self, mac);
            }

            fn visit_use_tree(&mut self, t: &'ast syn::UseTree) {
                // Addendum 10 fix 3: `use self::assert_corrupt as ac;`
                // and friends create an alias binding that the rest of
                // the visitor cannot recognise (the call site is `ac(..)`,
                // not `assert_corrupt(..)`). Reject `assert_corrupt`
                // anywhere in a `use` tree: as the imported name, as
                // the alias source and as the alias destination. Glob
                // imports (`use foo::*`) are allowed -- no binding is
                // named here.
                //
                // Note on recursion: we call `self.visit_use_tree(..)`
                // for children, not `syn::visit::visit_use_tree(..)`,
                // so nested `UseTree`s re-enter this override instead
                // of falling through to the default
                // `visit_use_name`/`visit_use_rename` which do not
                // check the ident.
                match t {
                    syn::UseTree::Path(p) => {
                        assert!(
                            p.ident != "assert_corrupt",
                            "coverage gate: `assert_corrupt` appears in a `use` tree; \
                             the helper must not be re-exported or routed through \
                             another path"
                        );
                        self.visit_use_tree(&p.tree);
                    }
                    syn::UseTree::Name(n) => assert!(
                        n.ident != "assert_corrupt",
                        "coverage gate: `assert_corrupt` is imported by a `use` tree; \
                         pins must call the in-scope helper directly, not reach it \
                         through a `use` import"
                    ),
                    syn::UseTree::Rename(r) => assert!(
                        r.ident != "assert_corrupt" && r.rename != "assert_corrupt",
                        "coverage gate: `assert_corrupt` appears in a `use` tree \
                         (as alias source or destination); the helper must not be \
                         aliased (`use self::assert_corrupt as ac`, \
                         `use foo::bar as assert_corrupt`)"
                    ),
                    syn::UseTree::Glob(_) => {}
                    syn::UseTree::Group(g) => {
                        for item in &g.items {
                            self.visit_use_tree(item);
                        }
                    }
                }
            }
        }

        let mut v = Visitor {
            found: Vec::new(),
            helper_count: 0,
            mod_stack: Vec::new(),
            helper_mod_stack: None,
        };
        syn::visit::Visit::visit_file(&mut v, &file);
        // Addendum 10 fix 1 (final): exactly one helper, in `mod details`.
        assert!(
            v.helper_count == 1,
            "coverage gate: expected exactly one `fn assert_corrupt` item, found {}",
            v.helper_count
        );
        let expected_path: &[String] = &[String::from("details")];
        assert!(
            v.helper_mod_stack.as_deref() == Some(expected_path),
            "coverage gate: the `fn assert_corrupt` helper is not in `mod details` \
             (module stack: {:?})",
            v.helper_mod_stack
        );
        v.found
    }

    #[test]
    fn coverage_gate_pins_every_corrupt_site() {
        // Fixed file order: storage.rs first (8 corrupt-literal sites),
        // then runs.rs (42 `Violation::<X>` construction sites, re-keyed
        // per addendum 16 point 4). Each source is parsed on its own
        // with `syn::parse_file`, so neither file needs to be
        // syntactically concatenable with the other.
        use crate::audit::runs::Violation;
        let sites = parse_sites();
        let site_set: HashSet<(String, usize)> = sites.iter().cloned().collect();
        let asserted: HashSet<(String, usize)> =
            parse_assertions(STORAGE_TESTS_SRC).into_iter().collect();
        let unreach: HashSet<(String, usize)> = UNREACHABLE
            .iter()
            .map(|(d, i, _)| ((*d).to_string(), *i))
            .collect();
        let mut missing = Vec::new();
        for key in &sites {
            if !asserted.contains(key) && !unreach.contains(key) {
                missing.push(key.clone());
            }
        }
        assert!(missing.is_empty(), "uncovered corrupt sites: {missing:?}");
        // Addendum 20.2: per-variant coverage. Every `Violation`
        // variant must have at least one construction site AND an
        // asserting pin (or at least one UNREACHABLE entry); a variant
        // added to `enum Violation`, `ALL` and `detail()` with no
        // site and no pin fails the gate here (G3).
        let site_details: HashSet<String> = site_set.iter().map(|(d, _)| d.clone()).collect();
        let pinned_details: HashSet<String> = asserted.iter().map(|(d, _)| d.clone()).collect();
        let unreach_details: HashSet<String> = unreach.iter().map(|(d, _)| d.clone()).collect();
        let mut variant_missing: Vec<&'static str> = Vec::new();
        for v in Violation::ALL.iter().copied() {
            let d = v.detail();
            let has_site = site_details.contains(d);
            let covered = pinned_details.contains(d) || unreach_details.contains(d);
            if !has_site || !covered {
                variant_missing.push(d);
            }
        }
        assert!(
            variant_missing.is_empty(),
            "per-variant coverage (addendum 20.2) failed: {variant_missing:?}"
        );
        // Stale-label check: any (detail, occurrence) pair that an
        // assert_corrupt names must exist in storage.rs or runs.rs, so
        // a pin left behind after a reader change cannot silently hide.
        let mut stale: Vec<(String, usize)> = asserted.difference(&site_set).cloned().collect();
        stale.sort();
        assert!(stale.is_empty(), "stale assert_corrupt labels: {stale:?}");
        for key in &unreach {
            assert!(site_set.contains(key), "stale UNREACHABLE {key:?}");
            assert!(
                !asserted.contains(key),
                "{key:?} is UNREACHABLE but a test asserts it"
            );
        }
        assert_eq!(
            sites.len(),
            49,
            "corrupt-site count changed; update gate explicitly"
        );
    }

    /// Addendum 27.3 structural gate: `storage.rs` must not contain any
    /// `for` / `while` / `loop` whose body calls a segment walker, and
    /// `initial_record` / `refresh` must each call `classify` and call
    /// no walker directly. Every remaining walker call in non-test
    /// `storage.rs` matches an explicit allowlist (fn → count) measured
    /// at head, with the reason documented. The static gate cannot
    /// prove dynamic reachability; the behavioural mutants prove
    /// runtime behaviour.
    #[test]
    fn coverage_gate_no_segment_loop_in_storage_rs() {
        /// Last segment of every path identifying a per-segment walk.
        /// If a loop body in `storage.rs` calls one of these, drift is
        /// back and this gate fails (addendum 27.3a).
        const WALKER_NAMES: &[&str] = &[
            "history_segment",
            "scan_segment",
            "scan_closing",
            "scan_staged",
            "scan",
        ];

        /// Allowed one-shot walker call sites in non-test `storage.rs`,
        /// measured at head (addendum 27.3c). Keyed by the enclosing
        /// fn and the walker name (the last path segment of the
        /// callee), with the count of unlooped call sites inside that
        /// fn. These are the storage shims composing into their inner
        /// `runs::*` counterparts.
        const ALLOWED: &[(&str, &str, usize, &str)] = &[
            (
                "history_segment",
                "history_segment",
                1,
                "storage::history_segment composes into runs::history_segment once; the strict-pass closure stays one call",
            ),
            (
                "scan_inner",
                "scan_segment",
                1,
                "scan_inner composes into runs::scan_segment once; the per-reader-path strict walk",
            ),
        ];

        fn path_last_ident(path: &syn::Path) -> Option<String> {
            path.segments.last().map(|s| s.ident.to_string())
        }

        fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
            attrs.iter().any(|a| {
                a.path().is_ident("cfg")
                    && a.parse_args::<syn::Meta>().ok().is_some_and(|m| match m {
                        syn::Meta::Path(p) => p.is_ident("test"),
                        _ => false,
                    })
            })
        }

        /// Collects a hit whenever an `ExprCall` targets a path whose
        /// last segment is a walker name. `inside_loop` says whether
        /// the containing walk is inside a for/while/loop body (so the
        /// gate fires), and also which enclosing fn we are in for the
        /// allowlist bookkeeping.
        struct WalkerVisitor<'a> {
            inside_loop_depth: usize,
            in_test_depth: usize,
            fn_stack: Vec<String>,
            /// (fn_name, walker, count) for every one-shot (non-loop)
            /// walker call outside `#[cfg(test)]`.
            allow_counts: std::collections::HashMap<(String, String), usize>,
            /// (fn_name, walker) for every call inside a for/while/loop
            /// body outside `#[cfg(test)]`. One hit here fails the gate.
            looped: Vec<(String, String)>,
            /// Set of fn names (outside `#[cfg(test)]`) that call
            /// `classify`. Used for (27.3b): `initial_record` /
            /// `refresh` must each call `classify`.
            classify_callers: std::collections::HashSet<String>,
            walker_names: &'a [&'a str],
        }

        impl<'a, 'ast> syn::visit::Visit<'ast> for WalkerVisitor<'a> {
            fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
                let bump = is_cfg_test(&m.attrs);
                if bump {
                    self.in_test_depth += 1;
                }
                syn::visit::visit_item_mod(self, m);
                if bump {
                    self.in_test_depth -= 1;
                }
            }
            fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
                let bump = is_cfg_test(&f.attrs);
                if bump {
                    self.in_test_depth += 1;
                }
                self.fn_stack.push(f.sig.ident.to_string());
                syn::visit::visit_item_fn(self, f);
                self.fn_stack.pop();
                if bump {
                    self.in_test_depth -= 1;
                }
            }
            fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
                let bump = is_cfg_test(&f.attrs);
                if bump {
                    self.in_test_depth += 1;
                }
                self.fn_stack.push(f.sig.ident.to_string());
                syn::visit::visit_impl_item_fn(self, f);
                self.fn_stack.pop();
                if bump {
                    self.in_test_depth -= 1;
                }
            }
            fn visit_expr_for_loop(&mut self, f: &'ast syn::ExprForLoop) {
                self.inside_loop_depth += 1;
                syn::visit::visit_expr_for_loop(self, f);
                self.inside_loop_depth -= 1;
            }
            fn visit_expr_while(&mut self, w: &'ast syn::ExprWhile) {
                self.inside_loop_depth += 1;
                syn::visit::visit_expr_while(self, w);
                self.inside_loop_depth -= 1;
            }
            fn visit_expr_loop(&mut self, l: &'ast syn::ExprLoop) {
                self.inside_loop_depth += 1;
                syn::visit::visit_expr_loop(self, l);
                self.inside_loop_depth -= 1;
            }
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if let syn::Expr::Path(path_expr) = &*call.func
                    && let Some(last) = path_last_ident(&path_expr.path)
                    && self.in_test_depth == 0
                {
                    let fn_name = self.fn_stack.last().cloned().unwrap_or_default();
                    if last == "classify" {
                        self.classify_callers.insert(fn_name.clone());
                    }
                    if self.walker_names.contains(&last.as_str()) {
                        if self.inside_loop_depth > 0 {
                            self.looped.push((fn_name, last));
                        } else {
                            *self.allow_counts.entry((fn_name, last)).or_insert(0) += 1;
                        }
                    }
                }
                syn::visit::visit_expr_call(self, call);
            }
            fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
                // Method calls like `foo.scan()` cannot be a walker
                // (walkers are free fns) but a `self.scan(...)` inside
                // an impl would read with the same identifier; be
                // defensive and still flag loop occurrences.
                let last = m.method.to_string();
                if self.in_test_depth == 0
                    && self.walker_names.contains(&last.as_str())
                    && self.inside_loop_depth > 0
                {
                    let fn_name = self.fn_stack.last().cloned().unwrap_or_default();
                    self.looped.push((fn_name, last));
                }
                syn::visit::visit_expr_method_call(self, m);
            }
        }

        let storage: syn::File = syn::parse_file(STORAGE_SRC)
            .expect("structural gate: storage.rs is not valid Rust (parse_file failed)");
        let mut v = WalkerVisitor {
            inside_loop_depth: 0,
            in_test_depth: 0,
            fn_stack: Vec::new(),
            allow_counts: std::collections::HashMap::new(),
            looped: Vec::new(),
            classify_callers: std::collections::HashSet::new(),
            walker_names: WALKER_NAMES,
        };
        syn::visit::Visit::visit_file(&mut v, &storage);

        // 27.3a: no walker call inside any for/while/loop body.
        assert!(
            v.looped.is_empty(),
            "storage.rs must not contain a `for`/`while`/`loop` whose body calls \
             `history_segment` / `scan_segment` / `scan_closing` / `scan_staged` / `scan`; \
             offenders: {:?}",
            v.looped
        );

        // 27.3b: `initial_record` and `refresh` each call `classify`.
        for caller in ["initial_record", "refresh"] {
            assert!(
                v.classify_callers.contains(caller),
                "storage.rs: fn `{caller}` must call `classify` (addendum 27.3b)"
            );
        }

        // 27.3b: `initial_record` and `refresh` must call no walker
        // directly outside a loop either.
        for caller in ["initial_record", "refresh"] {
            for walker in WALKER_NAMES {
                let count = v
                    .allow_counts
                    .get(&(caller.to_string(), (*walker).to_string()))
                    .copied()
                    .unwrap_or(0);
                assert_eq!(
                    count, 0,
                    "storage.rs: fn `{caller}` must not call walker `{walker}` directly \
                     (addendum 27.3b); every segment walk goes through `classify`"
                );
            }
        }

        // 27.3c: every remaining walker call site in non-test
        // storage.rs matches the allowlist exactly.
        let allowed_set: std::collections::HashMap<(String, String), usize> = ALLOWED
            .iter()
            .map(|(outer, walker, count, _)| {
                (((*outer).to_string(), (*walker).to_string()), *count)
            })
            .collect();
        for (key, count) in &v.allow_counts {
            let expected = allowed_set.get(key).copied();
            assert_eq!(
                expected,
                Some(*count),
                "storage.rs: unexpected walker call site (fn → walker → count): \
                 ({:?}, {}); update the allowlist with a documented reason \
                 (addendum 27.3c)",
                key,
                count
            );
        }
        for (key, expected_count) in &allowed_set {
            let found = v.allow_counts.get(key).copied().unwrap_or(0);
            assert_eq!(
                found, *expected_count,
                "storage.rs: allowlisted walker site ({:?}) expected count {} but found {}",
                key, expected_count, found
            );
        }
    }
}
