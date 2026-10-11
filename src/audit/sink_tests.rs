use super::*;
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, sync::atomic::AtomicUsize};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        hooks::CHECK_CLOCK.with(|check| *check.borrow_mut() = None);
        hooks::TIME.with(|t| t.set(Some(1_000_000_000)));
        hooks::FAIL.with(|f| f.borrow_mut().clear());
        hooks::SHORT.with(|s| s.set(None));
        hooks::EVENTS.with(|e| e.borrow_mut().clear());
        let path = std::env::temp_dir().join(format!(
            "vigil-sink-{}-{}",
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
fn signer() -> Arc<dyn Signer> {
    Arc::new(KeySeed::parse(&"11".repeat(32)).unwrap())
}
fn create(t: &Temp) -> Sink {
    Sink::create(&t.0, signer(), Config::default()).unwrap()
}
fn open(t: &Temp) -> Sink {
    Sink::open(&t.0, signer(), Config::default(), None).unwrap()
}
fn entry() -> Entry {
    Entry::new("actor", "change", "object")
}
fn bytes(t: &Temp) -> Vec<u8> {
    fs::read(t.0.join("audit.jsonl")).unwrap()
}
fn records(t: &Temp) -> Vec<Record> {
    bytes(t)
        .split(|b| *b == b'\n')
        .filter(|p| !p.is_empty())
        .flat_map(|p| Record::parse_line(p).unwrap())
        .collect()
}
fn bad<T>(r: Result<T, AuditError>, kind: AuditErrorKind) {
    assert_eq!(r.err().unwrap().kind(), kind);
}
fn bad_open(t: &Temp, expected: Option<Head>, kind: AuditErrorKind) {
    bad(
        Sink::open(&t.0, signer(), Config::default(), expected),
        kind,
    );
}
fn scan_head(s: &Sink) -> Head {
    s.reader
        .with_current(|d| s.prepare(d), |_, _, s| Ok(s.head))
        .unwrap()
}
#[test]
fn creation_marker_is_canonical() {
    let t = Temp::new();
    let s = create(&t);
    let marker = fs::read(t.0.join("audit.trail")).unwrap();
    assert_eq!(marker, format!("{}\n", hex(&s.trail)).as_bytes());
    assert_eq!(marker.len(), 33);
    assert_eq!(
        fs::metadata(t.0.join("audit.trail"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o400
    );
    assert_eq!(
        fs::metadata(t.0.join("audit.jsonl"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(records(&t)[0].context.seq, 0);
    assert_eq!(records(&t)[0].context.previous, Record::genesis(&s.trail));
    let events = hooks::EVENTS.with(|e| e.borrow().clone());
    assert_eq!(
        events,
        [
            "marker",
            "marker-dir",
            "clock",
            "staging",
            "staging-dir",
            "promote",
            "promote-dir"
        ]
    );
}
#[test]
fn malformed_markers_and_creation_refusal() {
    let t = Temp::new();
    let s = create(&t);
    let good = fs::read(t.0.join("audit.trail")).unwrap();
    fs::set_permissions(t.0.join("audit.trail"), fs::Permissions::from_mode(0o600)).unwrap();
    bad(
        Sink::create(&t.0, signer(), Config::default()),
        AuditErrorKind::TrailExists,
    );
    let mut uppercase = good.clone();
    uppercase[0] = b'A';
    for bad_marker in [
        uppercase,
        good[..32].to_vec(),
        [good.clone(), b"\n".to_vec()].concat(),
        [b" ".to_vec(), good.clone()].concat(),
        b"short\n".to_vec(),
    ] {
        fs::write(t.0.join("audit.trail"), bad_marker).unwrap();
        bad_open(&t, None, AuditErrorKind::CorruptTrail);
    }
    fs::write(t.0.join("audit.trail"), good).unwrap();
    drop(s);
}
#[test]
fn missing_marker_and_marker_without_trail() {
    let t = Temp::new();
    bad_open(&t, None, AuditErrorKind::MissingTrail);
    fs::write(t.0.join("audit.trail"), format!("{}\n", "11".repeat(16))).unwrap();
    bad_open(&t, None, AuditErrorKind::CorruptTrail);
}
#[test]
fn open_writes_and_signs_nothing() {
    let t = Temp::new();
    let s = create(&t);
    let before = bytes(&t);
    let failing = Arc::new(Failing::new());
    failing.fail.store(true, Ordering::Relaxed);
    let opened = Sink::open(&t.0, failing.clone(), Config::default(), None).unwrap();
    assert_eq!(failing.calls.load(Ordering::Relaxed), 0);
    assert_eq!(bytes(&t), before);
    assert_eq!(scan_head(&s), scan_head(&opened));
}
#[test]
fn reserved_prefix_size_and_one_write_checkpoint() {
    let t = Temp::new();
    let mut s = create(&t);
    s.config.checkpoint_every = 1;
    bad(
        s.record(&Entry::new("actor", "vigil.audit.something", "object")),
        AuditErrorKind::InvalidEntry,
    );
    let before = bytes(&t);
    bad(
        s.record(&entry().details("x".repeat(1_000_000))),
        AuditErrorKind::TooLarge,
    );
    assert_eq!(bytes(&t), before);
    hooks::EVENTS.with(|e| e.borrow_mut().clear());
    let h = s.record(&entry()).unwrap();
    assert_eq!(h.seq, 1);
    let events = hooks::EVENTS.with(|e| e.borrow().clone());
    assert_eq!(events, ["clock", "write", "record-data"]);
    assert_eq!(records(&t).len(), 3);
    let h = s
        .record_internal(&Entry::new("actor", "vigil.audit.test", "object"))
        .unwrap();
    assert_eq!(h.seq, 3);
}
#[test]
fn short_write_rolls_back() {
    let t = Temp::new();
    let s = create(&t);
    let before = bytes(&t);
    hooks::SHORT.with(|v| v.set(Some(13)));
    bad(s.record(&entry()), AuditErrorKind::Io);
    assert_eq!(bytes(&t), before);
    assert_eq!(s.record(&entry()).unwrap().seq, 1);
}
#[test]
fn shared_cadence_after_open_refresh_and_clock_step_back() {
    let t = Temp::new();
    let mut a = create(&t);
    a.config.checkpoint_every = 3;
    let mut b = open(&t);
    b.config.checkpoint_every = 3;
    a.record(&entry()).unwrap();
    b.record(&entry()).unwrap();
    a.record(&entry()).unwrap();
    assert_eq!(records(&t).len(), 5);
    hooks::TIME.with(|v| v.set(Some(2_000_000_000)));
    b.checkpoint().unwrap();
    hooks::TIME.with(|v| v.set(Some(2_100_000_000)));
    a.config.checkpoint_interval = Duration::from_secs(1);
    a.record(&entry()).unwrap();
    assert!(matches!(records(&t).last().unwrap().kind, Kind::Entry(_)));
    let mut c = open(&t);
    c.config.checkpoint_interval = Duration::from_secs(1);
    hooks::TIME.with(|v| v.set(Some(3_000_000_000)));
    c.record(&entry()).unwrap();
    assert!(matches!(
        records(&t).last().unwrap().kind,
        Kind::Checkpoint(_)
    ));
    hooks::TIME.with(|v| v.set(Some(1)));
    a.record(&entry()).unwrap();
    assert!(matches!(
        records(&t).last().unwrap().kind,
        Kind::Checkpoint(_)
    ));
}
#[derive(Debug)]
struct Failing {
    fail: AtomicBool,
    calls: AtomicUsize,
}
impl Failing {
    fn new() -> Self {
        Self {
            fail: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
        }
    }
}
impl Signer for Failing {
    fn public_key(&self) -> [u8; 32] {
        signer().public_key()
    }
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], SignerError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.fail.load(Ordering::Relaxed) {
            Err(SignerError::new("offline"))
        } else {
            signer().sign(message)
        }
    }
}
#[test]
fn signer_outage_grows_segment_retries_and_close_writes_nothing() {
    let t = Temp::new();
    let signer = Arc::new(Failing::new());
    let mut s = Sink::create(&t.0, signer.clone(), Config::default()).unwrap();
    s.config.checkpoint_every = 1;
    s.config.max_bytes = 1;
    signer.fail.store(true, Ordering::Relaxed);
    s.record(&entry()).unwrap();
    s.record(&entry()).unwrap();
    assert_eq!(s.unsigned_records.load(Ordering::Relaxed), 2);
    assert_eq!(records(&t).len(), 3);
    assert!(s.reported.load(Ordering::Relaxed));
    bad(s.checkpoint(), AuditErrorKind::Signer);
    let before = bytes(&t);
    let calls = signer.calls.load(Ordering::Relaxed);
    bad(s.close(), AuditErrorKind::Signer);
    assert_eq!(signer.calls.load(Ordering::Relaxed), calls + 1);
    assert_eq!(bytes(&t), before);
    let mut s = Sink::open(&t.0, signer.clone(), Config::default(), None).unwrap();
    s.config.max_bytes = 1;
    signer.fail.store(false, Ordering::Relaxed);
    s.record(&entry()).unwrap();
    assert_eq!(records(&t)[0].context.seq, 4);
    assert_eq!(scan_head(&s).seq, 5);
}
#[test]
fn drop_and_close_checkpoint() {
    let t = Temp::new();
    {
        let s = create(&t);
        s.record(&entry()).unwrap();
    }
    assert!(matches!(
        records(&t).last().unwrap().kind,
        Kind::Checkpoint(_)
    ));
    let c = open(&t).close().unwrap();
    assert_eq!(c.hash(), records(&t).last().unwrap().hash());
}
#[test]
fn repairs_attested_once_for_record_checkpoint_and_sealing() {
    for mode in 0..3 {
        let t = Temp::new();
        let mut s = create(&t);
        let gap = b"{\"resourceLogs\":\n{\"resourceLogs\":";
        fs::OpenOptions::new()
            .append(true)
            .open(t.0.join("audit.jsonl"))
            .unwrap()
            .write_all(gap)
            .unwrap();
        let mut h = blake3::Hasher::new();
        h.update(b"vigil.audit.v1.repaired\0");
        h.update(gap);
        h.update(b"\n");
        let digest = *h.finalize().as_bytes();
        match mode {
            0 => {
                s.record(&entry()).unwrap();
                s.checkpoint().unwrap();
            }
            1 => {
                s.close().unwrap();
            }
            _ => {
                s.config.max_bytes = 1;
                s.record(&entry()).unwrap();
                s.close().unwrap();
            }
        }
        let names = rotate::rotated_names_at(&File::open(&t.0).unwrap(), "audit").unwrap();
        let mut found = Vec::new();
        for name in names.into_iter().chain([PathBuf::from("audit.jsonl")]) {
            let bytes = fs::read(t.0.join(name)).unwrap();
            found.extend(
                bytes
                    .split(|b| *b == b'\n')
                    .filter_map(|p| Record::parse_line(p).ok())
                    .flatten(),
            );
        }
        assert_eq!(
            found
                .iter()
                .filter(|r| r.context.repaired.is_some())
                .count(),
            1
        );
        assert_eq!(found[1].context.repaired, Some(digest));
        assert!(matches!(found.last().unwrap().kind, Kind::Checkpoint(_)));
        let _ = open(&t);
    }
}
#[test]
fn complete_line_without_lf_is_not_a_gap() {
    let t = Temp::new();
    let s = create(&t);
    let mut before = bytes(&t);
    before.pop();
    fs::write(t.0.join("audit.jsonl"), &before).unwrap();
    // Fresh reader: the first handle correctly refuses a shortening below cached length.
    let mut reopened = open(&t);
    let state = predecessor(&File::open(&t.0).unwrap(), reopened.trail)
        .unwrap()
        .unwrap();
    let next = Record::new(reopened.context(&state, 1_000_000_000).unwrap(), entry()).unwrap();
    reopened.config.max_bytes = before.len() as u64 + line(&next).unwrap().len() as u64;
    reopened.record(&entry()).unwrap();
    assert_eq!(records(&t)[0].context.seq, 2);
    assert_eq!(records(&t)[1].context.repaired, None);
    drop(s);
}
#[test]
fn sealing_order_and_refresh() {
    let t = Temp::new();
    let mut a = create(&t);
    let b = open(&t);
    a.config.max_bytes = 1;
    hooks::EVENTS.with(|e| e.borrow_mut().clear());
    a.record(&entry()).unwrap();
    assert_eq!(
        hooks::EVENTS.with(|e| e.borrow().clone()),
        [
            "clock",
            "staging",
            "staging-dir",
            "write",
            "closing-data",
            "seal-rename",
            "promote",
            "promote-dir",
            "write",
            "record-data"
        ]
    );
    assert_eq!(scan_head(&b), scan_head(&a));
    b.record(&entry()).unwrap();
    assert_eq!(scan_head(&a), scan_head(&b));
}
#[test]
fn fsync_failure_sites_poison_handle_and_rollback() {
    for site in [
        "record-data",
        "checkpoint-data",
        "staging",
        "staging-dir",
        "closing-data",
        "promote-dir",
        "settle-discard-dir",
        "settle-promote-dir",
    ] {
        let t = Temp::new();
        let mut s = create(&t);
        let before = bytes(&t);
        if site.starts_with("settle-") {
            let content = if site == "settle-discard-dir" {
                b"{".to_vec()
            } else {
                s.checkpoint().unwrap();
                let state = predecessor(&File::open(&t.0).unwrap(), s.trail)
                    .unwrap()
                    .unwrap();
                line(&s.checkpoint_record(&state, 1_000_000_000).unwrap()).unwrap()
            };
            fs::write(t.0.join(".audit-next.jsonl"), content).unwrap();
        }
        hooks::FAIL.with(|f| *f.borrow_mut() = vec![site]);
        let result = if site == "checkpoint-data" {
            s.checkpoint().map(|_| Head {
                seq: 0,
                hash: [0; 32],
            })
        } else {
            if matches!(
                site,
                "staging" | "staging-dir" | "closing-data" | "promote-dir"
            ) {
                s.config.max_bytes = 1;
            }
            s.record(&entry())
        };
        bad(result, AuditErrorKind::Io);
        bad(s.record(&entry()), AuditErrorKind::Poisoned);
        if matches!(site, "record-data" | "checkpoint-data" | "closing-data") {
            assert_eq!(bytes(&t), before);
        }
        s.closed = true;
    }
}
#[test]
fn rollback_failure_sets_shared_poison_barrier() {
    let t = Temp::new();
    let s = create(&t);
    let other = open(&t);
    hooks::FAIL.with(|f| *f.borrow_mut() = vec!["record-data", "truncate"]);
    bad(s.record(&entry()), AuditErrorKind::Io);
    assert!(
        fs::read_to_string(t.0.join("audit.poison"))
            .unwrap()
            .contains("injected truncate")
    );
    assert_eq!(
        fs::metadata(t.0.join("audit.poison"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    bad(other.record(&entry()), AuditErrorKind::Poisoned);
    bad_open(&t, None, AuditErrorKind::Poisoned);
}

#[test]
fn resume_staging_every_prefix_with_and_without_gap() {
    for lost in [0, 7] {
        let t = Temp::new();
        let mut s = create(&t);
        s.closed = true;
        let live = bytes(&t);
        let state = predecessor(&File::open(&t.0).unwrap(), s.trail)
            .unwrap()
            .unwrap();
        let cp = Sink::signed(
            &*s.signer,
            RecordContext::new(s.trail, lost + 1, 2_000_000_000, "vigil", state.head.hash),
            &state.mmr,
        )
        .unwrap();
        let entry = Record::new_internal(
            RecordContext::new(s.trail, lost + 2, 2_000_000_000, "vigil", cp.hash()),
            Entry::new("operator", "vigil.audit.resume", "trail")
                .reason("reviewed")
                .details(format!(
                    "head=0:{} lost_through={lost} file=-",
                    digest_string(&state.head.hash)
                )),
        )
        .unwrap();
        let staged = [line(&cp).unwrap(), line(&entry).unwrap()].concat();
        for end in 0..staged.len() {
            fs::write(t.0.join(".audit-resume.jsonl"), &staged[..end]).unwrap();
            let mut reopened = open(&t);
            reopened.closed = true;
            assert_eq!(bytes(&t), live, "lost={lost}, prefix={end}");
            assert!(!t.0.join(".audit-resume.jsonl").exists());
        }
        fs::write(t.0.join(".audit-resume.jsonl"), &staged).unwrap();
        let mut reopened = open(&t);
        reopened.closed = true;
        assert_eq!(
            scan_head(&reopened),
            Head {
                seq: lost + 2,
                hash: entry.hash()
            }
        );
        assert_eq!(bytes(&t), staged);
        let names = rotate::rotated_names_at(&File::open(&t.0).unwrap(), "audit").unwrap();
        assert_eq!(names.len(), 1);
        assert_eq!(fs::read(t.0.join(&names[0])).unwrap(), live);
    }
}
#[test]
fn sealing_staging_rules_and_interrupted_creation() {
    for case in 0..9 {
        let t = Temp::new();
        let mut s = create(&t);
        s.closed = true;
        let dir = File::open(&t.0).unwrap();
        let state = predecessor(&dir, s.trail).unwrap().unwrap();
        let closing = s.checkpoint_record(&state, 2_000_000_000).unwrap();
        let mut mmr = state.mmr.clone();
        mmr.push(closing.hash()).unwrap();
        let opening = Sink::signed(
            &*s.signer,
            RecordContext::new(s.trail, 2, 2_000_000_000, "vigil", closing.hash()),
            &mmr,
        )
        .unwrap();
        let mut staged = line(&opening).unwrap();
        let promote = matches!(case, 0..=2 | 8);
        match case {
            0 | 1 | 8 => {
                fs::OpenOptions::new()
                    .append(true)
                    .open(t.0.join("audit.jsonl"))
                    .unwrap()
                    .write_all(&line(&closing).unwrap())
                    .unwrap();
                if case != 0 {
                    rotate::rotate(&dir, "audit", Path::new("audit.jsonl")).unwrap();
                }
                if case == 8 {
                    let segment = rotate::rotated_names_at(&dir, "audit").unwrap().remove(0);
                    fs::hard_link(t.0.join(segment), t.0.join("audit.jsonl")).unwrap();
                }
            }
            2 => {
                staged = bytes(&t);
                fs::remove_file(t.0.join("audit.jsonl")).unwrap();
            }
            3 => {} // Stage exists before the closing checkpoint was written.
            4 => {
                staged.pop();
            }
            5 => {
                staged = b"{".to_vec();
            }
            6 => {
                staged.extend(line(&opening).unwrap());
            }
            _ => {
                let record =
                    Record::new(s.context(&state, 2_000_000_000).unwrap(), entry()).unwrap();
                staged = line(&record).unwrap();
            }
        }
        fs::write(t.0.join(".audit-next.jsonl"), &staged).unwrap();
        let mut reopened = open(&t);
        reopened.closed = true;
        assert!(!t.0.join(".audit-next.jsonl").exists());
        if promote {
            assert_eq!(bytes(&t), staged);
        } else {
            assert_eq!(scan_head(&reopened), state.head);
        }
    }
}
#[test]
fn every_operation_settles_both_staging_names() {
    for op in 0..4 {
        let t = Temp::new();
        let s = create(&t);
        for name in [".audit-next.jsonl", ".audit-resume.jsonl"] {
            fs::write(t.0.join(name), b"{").unwrap();
        }
        match op {
            0 => {
                let _ = open(&t);
            }
            1 => {
                s.record(&entry()).unwrap();
            }
            2 => {
                s.checkpoint().unwrap();
            }
            _ => {
                s.close().unwrap();
            }
        }
        assert!(!t.0.join(".audit-next.jsonl").exists());
        assert!(!t.0.join(".audit-resume.jsonl").exists());
    }
}
#[test]
fn expect_head_structural_priority_and_running_rollback() {
    for attack in 0..5 {
        let t = Temp::new();
        let mut s = create(&t);
        let creation = bytes(&t);
        let h = s.record(&entry()).unwrap();
        let mut expected = h;
        let mut reopened = Sink::open(&t.0, signer(), Config::default(), Some(h)).unwrap();
        reopened.closed = true;
        bad_open(
            &t,
            Some(Head {
                seq: h.seq,
                hash: [0; 32],
            }),
            AuditErrorKind::HeadMismatch,
        );
        match attack {
            0 => fs::write(t.0.join("audit.jsonl"), creation).unwrap(),
            1 => fs::write(t.0.join("audit.jsonl"), b"").unwrap(),
            2 => fs::remove_file(t.0.join("audit.jsonl")).unwrap(),
            _ => {
                s.config.max_bytes = 1;
                let latest = s.record(&entry()).unwrap();
                let names = rotate::rotated_names_at(&File::open(&t.0).unwrap(), "audit").unwrap();
                if attack == 3 {
                    expected = latest;
                    fs::remove_file(t.0.join("audit.jsonl")).unwrap();
                    fs::rename(t.0.join(&names[0]), t.0.join("audit.jsonl")).unwrap();
                } else {
                    fs::remove_file(t.0.join(&names[0])).unwrap();
                }
            }
        }
        if attack != 4 {
            bad(s.record(&entry()), AuditErrorKind::CorruptTrail);
        }
        let kind = if matches!(attack, 1..=2) {
            AuditErrorKind::CorruptTrail
        } else {
            AuditErrorKind::HeadMismatch
        };
        bad_open(&t, Some(expected), kind);
        if matches!(attack, 0 | 3) {
            let mut unpinned = open(&t);
            unpinned.closed = true;
        }
        if matches!(attack, 1..=2) {
            bad_open(&t, None, AuditErrorKind::CorruptTrail);
        }
    }
}
#[test]
fn reading_writer_accepts_absent_fragment_and_refuses_changed_or_inserted_fragment() {
    for mode in 0..3 {
        let t = Temp::new();
        let s = create(&t);
        let initial = bytes(&t);
        let state = predecessor(&File::open(&t.0).unwrap(), s.trail)
            .unwrap()
            .unwrap();
        let gap = b"{\"resourceLogs\":\n";
        let mut h = blake3::Hasher::new();
        h.update(b"vigil.audit.v1.repaired\0");
        h.update(gap);
        let mut context = s.context(&state, 2_000_000_000).unwrap();
        if mode != 2 {
            context.repaired = Some(*h.finalize().as_bytes());
        }
        let record = Record::new(context, entry()).unwrap();
        let mut changed = initial;
        if mode == 1 {
            changed.extend_from_slice(b"{\"ResourceLogs\":\n");
        }
        if mode == 2 {
            changed.extend_from_slice(gap);
        }
        changed.extend(line(&record).unwrap());
        fs::write(t.0.join("audit.jsonl"), changed).unwrap();
        if mode == 0 {
            s.record(&entry()).unwrap();
            let _ = open(&t);
        } else {
            bad(s.record(&entry()), AuditErrorKind::CorruptTrail);
            bad_open(&t, None, AuditErrorKind::CorruptTrail);
        }
    }
}

#[test]
fn public_record_constructor_refuses_reserved_actions() {
    bad(
        Record::new(
            RecordContext::new([1; 16], 0, 1, "service", [0; 32]),
            Entry::new("actor", "vigil.audit.resume", "object"),
        ),
        AuditErrorKind::InvalidEntry,
    );
}

#[test]
fn cadence_child_role() {
    let Some(path) = std::env::var_os("VIGIL_SINK_CADENCE_DIR") else {
        return;
    };
    hooks::TIME.with(|v| v.set(Some(1_000_000_000)));
    let mut sink = Sink::open(
        Path::new(&path),
        signer(),
        Config {
            checkpoint_every: 3,
            ..Config::default()
        },
        None,
    )
    .unwrap();
    sink.record(&entry()).unwrap();
    sink.closed = true;
}
#[test]
fn processes_share_cadence() {
    let t = Temp::new();
    let mut s = create(&t);
    s.config.checkpoint_every = 3;
    s.record(&entry()).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "audit::sink::tests::cadence_child_role"])
        .env("VIGIL_SINK_CADENCE_DIR", &t.0)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    s.record(&entry()).unwrap();
    assert_eq!(records(&t).len(), 5);
}
#[test]
fn close_fsync_failure_is_io() {
    let t = Temp::new();
    let s = create(&t);
    let before = bytes(&t);
    hooks::FAIL.with(|v| *v.borrow_mut() = vec!["checkpoint-data"]);
    bad(s.close(), AuditErrorKind::Io);
    assert_eq!(bytes(&t), before);
}
#[test]
#[ignore = "host durability probe; run explicitly on a persistent filesystem"]
fn durable_append_probe() {
    let path = std::env::var_os("VIGIL_SINK_PROBE_DIR").unwrap();
    hooks::TIME.with(|v| v.set(None));
    let sink = Sink::create(Path::new(&path), signer(), Config::default()).unwrap();
    let start = std::time::Instant::now();
    sink.record(&entry()).unwrap();
    println!("durable append: {} us", start.elapsed().as_micros());
    sink.close().unwrap();
}

#[test]
fn timestamp_is_read_inside_directory_lock() {
    let t = Temp::new();
    let s = create(&t);
    let path = t.0.clone();
    hooks::CHECK_CLOCK.with(|check| {
        *check.borrow_mut() = Some(Box::new(move || {
            let dir = Directory::open(&path).unwrap();
            assert_eq!(
                dir.with_lock(|_| ()).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }))
    });
    s.record(&entry()).unwrap();
}
#[test]
fn creation_fsync_errors_return_io() {
    for site in [
        "marker",
        "marker-dir",
        "staging",
        "staging-dir",
        "promote-dir",
    ] {
        let t = Temp::new();
        hooks::FAIL.with(|f| *f.borrow_mut() = vec![site]);
        bad(
            Sink::create(&t.0, signer(), Config::default()),
            AuditErrorKind::Io,
        );
    }
}
