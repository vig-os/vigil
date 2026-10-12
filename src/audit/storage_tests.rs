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
    let first = fixture(&d.0);
    let genesis = Record::genesis(&TRAIL);
    let opening = cp(5, genesis, &seeded(&first));
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
    use crate::audit::{KeySeed, Signer};

    // KeySeed is the current B1 software signer; the planned KeyFileSigner
    // wrapper is not present yet. All checkpoints here have real signatures.
    fn signed(seq: u64, previous: [u8; 32], mmr: &Mmr) -> Record {
        let key = KeySeed::parse(&"27".repeat(32)).unwrap();
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
        let creation = base(&d);
        put(&d, 0, &[], b"{\"torn\":");
        let checkpoint = signed(5, Record::genesis(&TRAIL), &seeded(&creation));
        let resume = declaration(&checkpoint, 0, Record::genesis(&TRAIL), 4, None);
        write_records(&d.0, &[&checkpoint, &resume]);
        assert_eq!(head(&open(&d.0)), Head::of(&resume));
        assert_eq!(open(&d.0).cache.lock().unwrap().state.mmr.size(), 3);
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
        let checkpoint = signed(5, Record::genesis(&TRAIL), &seeded(&creation));
        let resume = declaration(&checkpoint, 0, Record::genesis(&TRAIL), 4, None);
        let staged = [line(&checkpoint), line(&resume)].concat();
        fs::write(d.0.join(".audit-resume.jsonl"), &staged).unwrap();
        let sink = Sink::open(
            &d.0,
            Arc::new(KeySeed::parse(&"27".repeat(32)).unwrap()),
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
                Arc::new(KeySeed::parse(&"27".repeat(32)).unwrap()),
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
                KeySeed::parse(&"27".repeat(32)).unwrap().public_key(),
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
