use super::*;
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, sync::atomic::AtomicUsize};
static NEXT: AtomicUsize = AtomicUsize::new(0);
pub(super) struct Temp(pub(super) PathBuf);
impl Temp {
    pub(super) fn new() -> Self {
        durability::stop();
        hooks::OBSERVE.with(|o| *o.borrow_mut() = None);
        hooks::STDERR.with(|lines| lines.borrow_mut().clear());
        hooks::CHECK_CLOCK.with(|check| *check.borrow_mut() = None);
        hooks::TIME.with(|t| t.set(Some(1_000_000_000)));
        hooks::FAIL.with(|f| f.borrow_mut().clear());
        hooks::SHORT.with(|s| s.set(None));
        hooks::HALF.with(|s| s.set(false));
        hooks::EVENTS.with(|e| e.borrow_mut().clear());
        hooks::SYNC_EVENTS.with(|e| e.borrow_mut().clear());
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
pub(super) fn signer() -> Arc<dyn Signer> {
    Arc::new(KeyFileSigner::from_hex(&"11".repeat(32)).unwrap())
}
pub(super) fn create(t: &Temp) -> Sink {
    Sink::create(&t.0, signer(), Config::default()).unwrap()
}
pub(super) fn open(t: &Temp) -> Sink {
    Sink::open(&t.0, signer(), Config::default(), None).unwrap()
}
pub(super) fn entry() -> Entry {
    Entry::new("actor", "change", "object")
}
pub(super) fn bytes(t: &Temp) -> Vec<u8> {
    fs::read(t.0.join("audit.jsonl")).unwrap()
}
pub(super) fn records(t: &Temp) -> Vec<Record> {
    bytes(t)
        .split(|b| *b == b'\n')
        .filter(|p| !p.is_empty())
        .flat_map(|p| Record::parse_line(p).unwrap())
        .collect()
}
pub(super) fn bad<T>(r: Result<T, AuditError>, kind: AuditErrorKind) {
    assert_eq!(r.err().unwrap().kind(), kind);
}
fn bad_open(t: &Temp, expected: Option<Head>, kind: AuditErrorKind) {
    bad(
        Sink::open(&t.0, signer(), Config::default(), expected),
        kind,
    );
}
pub(super) fn scan_head(s: &Sink) -> Head {
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
            "create-marker",
            "write",
            "marker",
            "marker-dir",
            "clock",
            "create-staging",
            "write",
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
        [good[..32].to_vec(), vec![b'\r']].concat(),
        [good[..32].to_vec(), vec![b'a']].concat(),
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
pub(super) struct Failing {
    pub(super) fail: AtomicBool,
    calls: AtomicUsize,
}
impl Failing {
    pub(super) fn new() -> Self {
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
            "create-staging",
            "write",
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
            s.record(&entry()).map(|r| r.head)
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
        let staged = resume_bytes(&s, &state, lost + 1, state.head.hash, "vigil.audit.resume");
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
        assert_eq!(scan_head(&reopened).seq, lost + 2);
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
        let mut reopened = Sink::open(&t.0, signer(), Config::default(), Some(h.head)).unwrap();
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
        bad_open(&t, Some(expected.head), kind);
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

fn resume_bytes(s: &Sink, state: &State, seq: u64, previous: [u8; 32], action: &str) -> Vec<u8> {
    let cp = Sink::signed(
        &*s.signer,
        RecordContext::new(s.trail, seq, 2_000_000_000, "vigil", previous),
        &state.mmr,
    )
    .unwrap();
    let entry = Record::new_internal(
        RecordContext::new(s.trail, seq + 1, 2_000_000_000, "vigil", cp.hash()),
        Entry::new("operator", action, "trail")
            .reason("reviewed")
            .details(format!(
                "head={}:{} lost_through={} file=-",
                state.head.seq,
                digest_string(&state.head.hash),
                seq - 1,
            )),
    )
    .unwrap();
    [line(&cp).unwrap(), line(&entry).unwrap()].concat()
}
#[test]
fn resume_promotes_over_live_opening_checkpoint() {
    let t = Temp::new();
    let mut s = create(&t);
    s.config.max_bytes = 1;
    s.record(&entry()).unwrap();
    s.closed = true;
    assert!(matches!(records(&t)[0].kind, Kind::Checkpoint(_)));
    assert_eq!(records(&t)[0].context.seq, 2);
    let dir = File::open(&t.0).unwrap();
    let state = predecessor(&dir, s.trail).unwrap().unwrap();
    let live = bytes(&t);
    let staged = resume_bytes(
        &s,
        &state,
        state.head.seq + 1,
        state.head.hash,
        "vigil.audit.resume",
    );
    fs::write(t.0.join(".audit-resume.jsonl"), &staged).unwrap();
    let mut reopened = open(&t);
    reopened.closed = true;
    assert_eq!(bytes(&t), staged);
    assert_eq!(scan_head(&reopened).seq, state.head.seq + 2);
    assert!(!t.0.join(".audit-resume.jsonl").exists());
    let names = rotate::rotated_names_at(&dir, "audit").unwrap();
    assert_eq!(names.len(), 2);
    assert_eq!(fs::read(t.0.join(names.last().unwrap())).unwrap(), live);
}
fn assert_resume_discard(rule: u8) {
    let t = Temp::new();
    let mut s = create(&t);
    s.closed = true;
    let dir = File::open(&t.0).unwrap();
    let state = predecessor(&dir, s.trail).unwrap().unwrap();
    // A declared gap permits a below-head checkpoint with a locally valid MMR count.
    let initial = resume_bytes(&s, &state, 8, state.head.hash, "vigil.audit.resume");
    fs::write(t.0.join(".audit-resume.jsonl"), initial).unwrap();
    let mut reopened = open(&t);
    reopened.closed = true;
    let state = predecessor(&dir, s.trail).unwrap().unwrap();
    let seq = state.head.seq + u64::from(rule != 2);
    let previous = if rule == 0 { [42; 32] } else { state.head.hash };
    let action = if rule == 1 {
        "change"
    } else {
        "vigil.audit.resume"
    };
    let staged = resume_bytes(&s, &state, seq, previous, action);
    let live = bytes(&t);
    let sealed = rotate::rotated_names_at(&dir, "audit").unwrap();
    fs::write(t.0.join(".audit-resume.jsonl"), staged).unwrap();
    let mut reopened = open(&t);
    reopened.closed = true;
    assert_eq!(scan_head(&reopened), state.head);
    assert_eq!(bytes(&t), live);
    assert_eq!(rotate::rotated_names_at(&dir, "audit").unwrap(), sealed);
    assert!(!t.0.join(".audit-resume.jsonl").exists());
}
#[test]
fn resume_discards_right_sequence_wrong_previous() {
    assert_resume_discard(0);
}
#[test]
fn resume_discards_wrong_action() {
    assert_resume_discard(1);
}
#[test]
fn resume_discards_sequence_below_next() {
    assert_resume_discard(2);
}
#[test]
fn record_at_rotation_limit_stays_in_live_file() {
    let t = Temp::new();
    let mut s = create(&t);
    let dir = File::open(&t.0).unwrap();
    let state = predecessor(&dir, s.trail).unwrap().unwrap();
    let record = Record::new(s.context(&state, 1_000_000_000).unwrap(), entry()).unwrap();
    let expected = [bytes(&t), line(&record).unwrap()].concat();
    s.config.max_bytes = expected.len() as u64;
    s.record(&entry()).unwrap();
    assert_eq!(bytes(&t), expected);
    assert!(rotate::rotated_names_at(&dir, "audit").unwrap().is_empty());
    s.closed = true;
}

#[test]
fn resume_without_predecessor_discards_non_genesis_link() {
    let t = Temp::new();
    let mut s = create(&t);
    s.closed = true;
    let mut state = predecessor(&File::open(&t.0).unwrap(), s.trail)
        .unwrap()
        .unwrap();
    state.head.hash = [42; 32];
    let staged = resume_bytes(&s, &state, 5, state.head.hash, "vigil.audit.resume");
    fs::remove_file(t.0.join("audit.jsonl")).unwrap();
    fs::write(t.0.join(".audit-resume.jsonl"), staged).unwrap();
    bad_open(&t, None, AuditErrorKind::CorruptTrail);
    assert!(!t.0.join(".audit-resume.jsonl").exists());
    assert!(!t.0.join("audit.jsonl").exists());
    assert!(t.0.join("audit.trail").exists());
}

#[test]
fn resume_without_predecessor_promotes_genesis_link() {
    let t = Temp::new();
    let mut s = create(&t);
    s.closed = true;
    let mut state = predecessor(&File::open(&t.0).unwrap(), s.trail)
        .unwrap()
        .unwrap();
    state.head.hash = Record::genesis(&s.trail);
    let staged = resume_bytes(&s, &state, 5, state.head.hash, "vigil.audit.resume");
    fs::remove_file(t.0.join("audit.jsonl")).unwrap();
    fs::write(t.0.join(".audit-resume.jsonl"), &staged).unwrap();
    let mut reopened = open(&t);
    reopened.closed = true;
    assert_eq!(bytes(&t), staged);
    assert_eq!(scan_head(&reopened).seq, 6);
    assert!(!t.0.join(".audit-resume.jsonl").exists());
}

#[test]
fn live_creation_checkpoint_rejects_non_genesis_link() {
    let t = Temp::new();
    let mut s = create(&t);
    s.closed = true;
    let forged = Sink::signed(
        &*s.signer,
        RecordContext::new(s.trail, 0, 1_000_000_000, "vigil", [42; 32]),
        &Mmr::new(),
    )
    .unwrap();
    fs::write(t.0.join("audit.jsonl"), line(&forged).unwrap()).unwrap();
    bad_open(&t, None, AuditErrorKind::CorruptTrail);
}
#[test]
fn resume_settlement_promotes_over_archived_live_prefix() {
    let t = Temp::new();
    let mut s = create(&t);
    s.config.max_bytes = 1;
    s.record(&entry()).unwrap();
    s.closed = true;
    let dir = File::open(&t.0).unwrap();
    let state = predecessor(&dir, s.trail).unwrap().unwrap();
    let live = bytes(&t);
    assert!(records(&t)[0].context.seq > 0);
    assert_ne!(records(&t)[0].context.previous, Record::genesis(&s.trail));
    for name in rotate::rotated_names_at(&dir, "audit").unwrap() {
        fs::remove_file(t.0.join(name)).unwrap();
    }
    let staged = resume_bytes(
        &s,
        &state,
        state.head.seq + 1,
        state.head.hash,
        "vigil.audit.resume",
    );
    fs::write(t.0.join(".audit-resume.jsonl"), &staged).unwrap();
    let mut reopened = open(&t);
    reopened.closed = true;
    assert_eq!(bytes(&t), staged);
    assert_eq!(scan_head(&reopened).seq, state.head.seq + 2);
    assert!(!t.0.join(".audit-resume.jsonl").exists());
    let sealed = rotate::rotated_names_at(&dir, "audit").unwrap();
    assert_eq!(sealed.len(), 1);
    assert_eq!(fs::read(t.0.join(&sealed[0])).unwrap(), live);
}
#[test]
fn sealing_settlement_promotes_after_archived_prefix_without_live() {
    let t = Temp::new();
    let mut s = create(&t);
    s.config.max_bytes = 1;
    s.record(&entry()).unwrap();
    s.closed = true;
    let dir = File::open(&t.0).unwrap();
    let state = predecessor(&dir, s.trail).unwrap().unwrap();
    let closing = s.checkpoint_record(&state, 2_000_000_000).unwrap();
    let mut mmr = state.mmr.clone();
    mmr.push(closing.hash()).unwrap();
    let opening = Sink::signed(
        &*s.signer,
        RecordContext::new(
            s.trail,
            closing.context.seq + 1,
            2_000_000_000,
            "vigil",
            closing.hash(),
        ),
        &mmr,
    )
    .unwrap();
    for name in rotate::rotated_names_at(&dir, "audit").unwrap() {
        fs::remove_file(t.0.join(name)).unwrap();
    }
    fs::write(
        t.0.join("audit.jsonl"),
        [bytes(&t), line(&closing).unwrap()].concat(),
    )
    .unwrap();
    let sealed_bytes = bytes(&t);
    assert!(records(&t)[0].context.seq > 0);
    assert_ne!(records(&t)[0].context.previous, Record::genesis(&s.trail));
    rotate::rotate(&dir, "audit", Path::new("audit.jsonl")).unwrap();
    let sealed = rotate::rotated_names_at(&dir, "audit").unwrap();
    let staged = line(&opening).unwrap();
    fs::write(t.0.join(".audit-next.jsonl"), &staged).unwrap();
    let mut reopened = open(&t);
    reopened.closed = true;
    assert_eq!(bytes(&t), staged);
    assert_eq!(scan_head(&reopened).seq, opening.context.seq);
    assert!(!t.0.join(".audit-next.jsonl").exists());
    assert_eq!(rotate::rotated_names_at(&dir, "audit").unwrap(), sealed);
    assert_eq!(fs::read(t.0.join(&sealed[0])).unwrap(), sealed_bytes);
}
#[test]
fn resume_without_predecessor_discards_nonzero_genesis_head() {
    let t = Temp::new();
    let mut s = create(&t);
    s.closed = true;
    let mut state = predecessor(&File::open(&t.0).unwrap(), s.trail)
        .unwrap()
        .unwrap();
    state.head.hash = Record::genesis(&s.trail);
    state.head.seq = 3;
    let staged = resume_bytes(&s, &state, 5, state.head.hash, "vigil.audit.resume");
    fs::remove_file(t.0.join("audit.jsonl")).unwrap();
    fs::write(t.0.join(".audit-resume.jsonl"), staged).unwrap();
    bad_open(&t, None, AuditErrorKind::CorruptTrail);
    assert!(!t.0.join(".audit-resume.jsonl").exists());
    assert!(!t.0.join("audit.jsonl").exists());
    assert!(t.0.join("audit.trail").exists());
}

// ADR-0005 amendment 3: each test below identifies its acceptance line.
fn fail(sites: &[&'static str]) {
    hooks::FAIL.with(|f| *f.borrow_mut() = sites.to_vec());
}
fn snapshot(t: &Temp) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    fs::read_dir(&t.0)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (PathBuf::from(e.file_name()), fs::read(e.path()).unwrap())
        })
        .collect()
}
fn silent(s: &mut Sink) {
    s.closed = true;
}
fn assert_inert(s: &Sink, t: &Temp) {
    let before = snapshot(t);
    bad(s.record(&entry()), AuditErrorKind::Poisoned);
    bad(s.checkpoint(), AuditErrorKind::Poisoned);
    assert_eq!(snapshot(t), before);
}
fn promotable(s: &Sink, t: &Temp, resume: bool) -> Vec<u8> {
    let state = predecessor(&File::open(&t.0).unwrap(), s.trail)
        .unwrap()
        .unwrap();
    if resume {
        resume_bytes(
            s,
            &state,
            state.head.seq + 1,
            state.head.hash,
            "vigil.audit.resume",
        )
    } else {
        line(&s.checkpoint_record(&state, 2_000_000_000).unwrap()).unwrap()
    }
}
fn replay_staging_outcome(t: &Temp, complete: bool) {
    durability::start(&t.0);
    let path = t.0.clone();
    hooks::OBSERVE.with(|o| {
        *o.borrow_mut() = Some(Box::new(move |site| {
            if site == "staging" {
                if complete {
                    durability::persist_staging(&path);
                } else {
                    // A durable name with no successfully flushed data replays empty.
                    let dir = File::open(&path).unwrap();
                    dir.sync_all().unwrap();
                    durability::sync(&dir).unwrap();
                }
            }
        }))
    });
}
#[test]
fn poison_831_staging_fsync() {
    for creating in [false, true] {
        let t = Temp::new();
        if creating {
            fail(&["staging"]);
            bad(
                Sink::create(&t.0, signer(), Config::default()),
                AuditErrorKind::Io,
            );
            assert_eq!(fs::read(t.0.join(".audit-next.jsonl")).unwrap(), b"");
            assert_eq!(fs::read(t.0.join("audit.trail")).unwrap().len(), 33);
            bad_open(&t, None, AuditErrorKind::CorruptTrail);
            bad(
                Sink::create(&t.0, signer(), Config::default()),
                AuditErrorKind::TrailExists,
            );
        } else {
            let mut a = create(&t);
            let mut b = open(&t);
            let before = bytes(&t);
            let head = scan_head(&b);
            a.config.max_bytes = 1;
            fail(&["staging"]);
            bad(a.record(&entry()), AuditErrorKind::Io);
            assert_eq!(bytes(&t), before);
            assert_eq!(fs::read(t.0.join(".audit-next.jsonl")).unwrap(), b"");
            assert_inert(&a, &t);
            hooks::EVENTS.with(|e| e.borrow_mut().clear());
            let receipt = b.record(&entry()).unwrap();
            assert_eq!(receipt.seq, head.seq + 1);
            assert!(!t.0.join(".audit-next.jsonl").exists());
            assert!(hooks::EVENTS.with(|e| e.borrow().contains(&"settle-discard-dir")));
            silent(&mut a);
            silent(&mut b);
        }
        assert!(!t.0.join("audit.poison").exists());
    }
}
#[test]
fn poison_832_failed_staging_truncate_restart() {
    for creating in [false, true] {
        for complete in [false, true] {
            let t = Temp::new();
            let mut writers = if creating {
                None
            } else {
                Some((create(&t), open(&t)))
            };
            replay_staging_outcome(&t, complete);
            fail(&["staging", "truncate"]);
            if let Some((a, _)) = writers.as_mut() {
                a.config.max_bytes = 1;
                bad(a.record(&entry()), AuditErrorKind::Io);
            } else {
                bad(
                    Sink::create(&t.0, signer(), Config::default()),
                    AuditErrorKind::Io,
                );
            }
            let stage = fs::read(t.0.join(".audit-next.jsonl")).unwrap();
            assert!(!stage.is_empty());
            assert!(
                fs::read_to_string(t.0.join("audit.poison"))
                    .unwrap()
                    .contains(".audit-next.jsonl")
            );
            let before = snapshot(&t);
            bad_open(&t, None, AuditErrorKind::Poisoned);
            if let Some((a, b)) = writers.as_mut() {
                assert_inert(a, &t);
                assert_inert(b, &t);
                silent(a);
                silent(b);
            }
            assert_eq!(snapshot(&t), before);
            drop(writers);
            hooks::OBSERVE.with(|o| *o.borrow_mut() = None);
            durability::replay();
            if t.0.join("audit.poison").exists() {
                fs::remove_file(t.0.join("audit.poison")).unwrap();
            }
            if creating && !complete {
                bad_open(&t, None, AuditErrorKind::CorruptTrail);
                bad(
                    Sink::create(&t.0, signer(), Config::default()),
                    AuditErrorKind::TrailExists,
                );
            } else {
                let mut reopened = open(&t);
                if creating {
                    assert_eq!(bytes(&t), stage);
                    assert_eq!(
                        fs::read(t.0.join("audit.trail")).unwrap(),
                        format!("{}\n", hex(&reopened.trail)).as_bytes()
                    );
                }
                reopened.record(&entry()).unwrap();
                assert!(!t.0.join(".audit-next.jsonl").exists());
                silent(&mut reopened);
            }
        }
    }
}
#[test]
fn poison_833_failed_staging_write() {
    for truncate_fails in [false, true] {
        let t = Temp::new();
        let mut s = create(&t);
        let before = bytes(&t);
        s.config.max_bytes = 1;
        hooks::SHORT.with(|cap| cap.set(Some(13)));
        if truncate_fails {
            fail(&["truncate"]);
        }
        bad(s.record(&entry()), AuditErrorKind::Io);
        assert!(!s.poisoned.load(Ordering::Relaxed));
        assert!(!t.0.join("audit.poison").exists());
        assert_eq!(bytes(&t), before);
        let stage = fs::read(t.0.join(".audit-next.jsonl")).unwrap();
        assert_eq!(stage.len(), if truncate_fails { 13 } else { 0 });
        s.record(&entry()).unwrap();
        silent(&mut s);
    }
    let t = Temp::new();
    fail(&["create-staging"]);
    bad(
        Sink::create(&t.0, signer(), Config::default()),
        AuditErrorKind::Io,
    );
    assert!(!t.0.join(".audit-next.jsonl").exists());
    assert!(!t.0.join("audit.poison").exists());
}
#[test]
fn poison_835_rename_directory_fsync() {
    // Sealing, creation, and running/open settlement of both staging names.
    for mode in 0..6 {
        let t = Temp::new();
        let mut writers = if mode == 2 {
            None
        } else {
            Some((create(&t), open(&t)))
        };
        let mut held = None;
        if let Some((a, _)) = writers.as_mut() {
            held = Some(a.record(&entry()).unwrap());
            if mode == 0 {
                a.config.max_bytes = 1;
            } else {
                a.checkpoint().unwrap();
                let staged = promotable(a, &t, mode >= 4);
                let name = if mode >= 4 {
                    ".audit-resume.jsonl"
                } else {
                    ".audit-next.jsonl"
                };
                fs::write(t.0.join(name), staged).unwrap();
            }
        }
        durability::start(&t.0);
        fail(&[if matches!(mode, 1 | 3 | 4 | 5) {
            "settle-promote-dir"
        } else {
            "promote-dir"
        }]);
        if mode == 2 {
            bad(
                Sink::create(&t.0, signer(), Config::default()),
                AuditErrorKind::Io,
            );
        } else if mode == 3 || mode == 5 {
            bad_open(&t, None, AuditErrorKind::Io);
        } else {
            bad(
                writers.as_ref().unwrap().0.record(&entry()),
                AuditErrorKind::Io,
            );
        }
        let poison = fs::read_to_string(t.0.join("audit.poison")).unwrap();
        assert!(poison.contains("directory fsync after rename"));
        assert!(poison.contains("audit.jsonl"));
        assert!(poison.contains(if mode >= 4 {
            ".audit-resume.jsonl"
        } else {
            ".audit-next.jsonl"
        }));
        let before = snapshot(&t);
        if let Some((a, b)) = writers.as_mut() {
            if mode != 3 && mode != 5 {
                assert!(a.poisoned.load(Ordering::Relaxed));
            }
            bad(b.record(&entry()), AuditErrorKind::Poisoned);
            assert_eq!(snapshot(&t), before);
            silent(a);
            silent(b);
        }
        bad_open(&t, None, AuditErrorKind::Poisoned);
        assert_eq!(snapshot(&t), before);
        drop(writers);
        durability::replay();
        if t.0.join("audit.poison").exists() {
            fs::remove_file(t.0.join("audit.poison")).unwrap();
        }
        if mode == 2 {
            // Step 2 persisted the complete creation checkpoint and marker.
            let mut recovered = open(&t);
            assert_eq!(scan_head(&recovered).seq, 0);
            silent(&mut recovered);
        } else {
            let mut recovered =
                Sink::open(&t.0, signer(), Config::default(), held.map(|r| r.head)).unwrap();
            recovered.record(&entry()).unwrap();
            silent(&mut recovered);
        }
    }
}
#[test]
fn poison_836_failed_poison_creation_residual() {
    let t = Temp::new();
    let mut a = create(&t);
    let mut b = open(&t);
    a.config.max_bytes = 1;
    fail(&["promote-dir", "create-poison"]);
    bad(a.record(&entry()), AuditErrorKind::Io);
    assert_inert(&a, &t);
    assert!(!t.0.join("audit.poison").exists());
    b.record(&entry()).unwrap();
    let mut reopened = open(&t);
    silent(&mut reopened);
    silent(&mut a);
    silent(&mut b);
}
#[test]
fn poison_837_other_directory_fsync() {
    for site in ["staging-dir", "settle-discard-dir"] {
        for opening in [false, true] {
            if opening && site == "staging-dir" {
                continue;
            }
            let t = Temp::new();
            let mut a = create(&t);
            let mut b = open(&t);
            let held = a.record(&entry()).unwrap();
            if site == "settle-discard-dir" {
                fs::write(t.0.join(".audit-next.jsonl"), b"{").unwrap();
            }
            durability::start(&t.0);
            let before = bytes(&t);
            a.config.max_bytes = 1;
            fail(&[site]);
            if opening {
                bad_open(&t, None, AuditErrorKind::Io);
            } else {
                bad(a.record(&entry()), AuditErrorKind::Io);
                assert!(a.poisoned.load(Ordering::Relaxed));
            }
            assert_eq!(bytes(&t), before);
            assert!(!t.0.join("audit.poison").exists());
            let acknowledged = b.record(&entry()).unwrap();
            silent(&mut a);
            silent(&mut b);
            drop(a);
            drop(b);
            durability::replay();
            if site == "settle-discard-dir" {
                assert!(t.0.join(".audit-next.jsonl").exists());
            }
            let mut recovered =
                Sink::open(&t.0, signer(), Config::default(), Some(acknowledged.head)).unwrap();
            assert!(!t.0.join(".audit-next.jsonl").exists());
            assert!(
                records(&t)
                    .iter()
                    .any(|r| r.context.seq == held.seq && r.hash() == held.hash)
            );
            silent(&mut recovered);
        }
    }
}
#[test]
fn poison_838_discard_then_seal_replay() {
    let t = Temp::new();
    let mut a = create(&t);
    let mut b = open(&t);
    fs::write(t.0.join(".audit-next.jsonl"), b"{").unwrap();
    durability::start(&t.0);
    fail(&["settle-discard-dir"]);
    bad(a.record(&entry()), AuditErrorKind::Io);
    b.config.max_bytes = 1;
    let acknowledged = b.record(&entry()).unwrap();
    silent(&mut a);
    silent(&mut b);
    drop(a);
    drop(b);
    durability::replay();
    let mut recovered =
        Sink::open(&t.0, signer(), Config::default(), Some(acknowledged.head)).unwrap();
    assert!(records(&t).iter().any(|r| r.hash() == acknowledged.hash));
    silent(&mut recovered);
}
#[test]
fn poison_839_create_final_failure() {
    let t = Temp::new();
    fail(&["promote-dir"]);
    bad(
        Sink::create(&t.0, signer(), Config::default()),
        AuditErrorKind::Io,
    );
    assert!(t.0.join("audit.poison").exists());
    let id = fs::read(t.0.join("audit.trail")).unwrap();
    assert_eq!(id.len(), 33);
    assert_eq!(
        records(&t)[0].context.trail.as_slice(),
        marker(&File::open(&t.0).unwrap()).unwrap()
    );
    // The operator's alternative is to remove the failed creation directory.
    fs::remove_dir_all(&t.0).unwrap();
    fs::create_dir(&t.0).unwrap();
    let mut fresh = create(&t);
    assert_ne!(fs::read(t.0.join("audit.trail")).unwrap(), id);
    silent(&mut fresh);
}
#[test]
fn poison_841_cause_and_clearing_rustdoc() {
    let t = Temp::new();
    let mut s = create(&t);
    s.config.max_bytes = 1;
    fail(&["promote-dir"]);
    bad(s.record(&entry()), AuditErrorKind::Io);
    let text = fs::read_to_string(t.0.join("audit.poison")).unwrap();
    assert!(text.contains("injected promote-dir"));
    assert!(text.contains("directory fsync after rename"));
    assert!(text.contains("audit.jsonl") && text.contains(".audit-next.jsonl"));
    let source = include_str!("mod.rs");
    let doc = source.split("    Poisoned,").next().unwrap();
    let restart = doc.find("first restart").unwrap();
    let verify = doc[restart..].find("vigil-audit verify").unwrap() + restart;
    let remove = doc[verify..].find("remove `audit.poison`").unwrap() + verify;
    assert!(restart < verify && verify < remove);
    silent(&mut s);
}
#[test]
fn poison_842_step7_does_not_run() {
    let t = Temp::new();
    let mut s = create(&t);
    s.config.max_bytes = 1;
    fail(&["promote-dir"]);
    hooks::EVENTS.with(|e| e.borrow_mut().clear());
    bad(s.record(&entry()), AuditErrorKind::Io);
    let events = hooks::EVENTS.with(|e| e.borrow().clone());
    assert!(!events.contains(&"record-data"));
    assert!(
        records(&t)
            .iter()
            .all(|r| matches!(r.kind, Kind::Checkpoint(_)))
    );
    silent(&mut s);
}
#[test]
fn poison_843_marker_failure() {
    for site in ["marker", "marker-dir"] {
        let t = Temp::new();
        let path = t.0.clone();
        let saved = Arc::new(std::sync::Mutex::new(Vec::new()));
        let capture = saved.clone();
        hooks::OBSERVE.with(|o| {
            *o.borrow_mut() = Some(Box::new(move |event| {
                if event == "marker" {
                    *capture.lock().unwrap() = fs::read(path.join("audit.trail")).unwrap();
                }
            }))
        });
        fail(&[site]);
        bad(
            Sink::create(&t.0, signer(), Config::default()),
            AuditErrorKind::Io,
        );
        hooks::OBSERVE.with(|o| *o.borrow_mut() = None);
        let id = fs::read(t.0.join("audit.trail")).unwrap();
        assert_eq!(id.len(), 33);
        assert_eq!(id, *saved.lock().unwrap());
        assert_eq!(snapshot(&t).len(), 1);
        bad_open(&t, None, AuditErrorKind::CorruptTrail);
        bad(
            Sink::create(&t.0, signer(), Config::default()),
            AuditErrorKind::TrailExists,
        );
        fs::remove_dir_all(&t.0).unwrap();
        fs::create_dir(&t.0).unwrap();
        let mut fresh = create(&t);
        assert_ne!(fs::read(t.0.join("audit.trail")).unwrap(), id);
        silent(&mut fresh);
    }
}
#[test]
fn poison_844_check_before_settlement() {
    for mode in 0..3 {
        for op in 0..4 {
            let t = Temp::new();
            let mut s = create(&t);
            let staged = if mode == 2 {
                bytes(&t)
            } else {
                promotable(&s, &t, mode == 1)
            };
            let name = if mode == 1 {
                ".audit-resume.jsonl"
            } else {
                ".audit-next.jsonl"
            };
            if mode == 2 {
                fs::remove_file(t.0.join("audit.jsonl")).unwrap();
            }
            fs::write(t.0.join(name), &staged).unwrap();
            fs::write(t.0.join("audit.poison"), b"another process").unwrap();
            let before = snapshot(&t);
            match op {
                0 => bad_open(&t, None, AuditErrorKind::Poisoned),
                1 => bad(s.record(&entry()), AuditErrorKind::Poisoned),
                2 => bad(s.checkpoint(), AuditErrorKind::Poisoned),
                _ => {
                    silent(&mut s);
                    bad(s.close(), AuditErrorKind::Poisoned);
                    assert_eq!(snapshot(&t), before);
                    fs::remove_file(t.0.join("audit.poison")).unwrap();
                    let mut recovered = open(&t);
                    assert_eq!(bytes(&t), staged);
                    silent(&mut recovered);
                    continue;
                }
            }
            assert_eq!(snapshot(&t), before);
            silent(&mut s);
            drop(s);
            fs::remove_file(t.0.join("audit.poison")).unwrap();
            let mut recovered = open(&t);
            assert_eq!(bytes(&t), staged);
            assert!(!t.0.join(name).exists());
            silent(&mut recovered);
        }
    }
}
#[derive(Debug)]
pub(super) struct CountingSigner {
    pub(super) calls: AtomicUsize,
    inner: Arc<dyn Signer>,
}
impl Signer for CountingSigner {
    fn public_key(&self) -> [u8; 32] {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.inner.public_key()
    }
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], SignerError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.inner.sign(message)
    }
}
pub(super) fn counting() -> Arc<CountingSigner> {
    Arc::new(CountingSigner {
        calls: AtomicUsize::new(0),
        inner: signer(),
    })
}
#[test]
fn poison_845_inert_handle_and_lock() {
    for drop_handle in [false, true] {
        let t = Temp::new();
        let key = counting();
        let s = Sink::create(&t.0, key.clone(), Config::default()).unwrap();
        let held = s.record(&entry()).unwrap();
        fail(&["record-data"]);
        bad(s.record(&entry()), AuditErrorKind::Io);
        fs::write(t.0.join(".audit-next.jsonl"), promotable(&s, &t, false)).unwrap();
        let before = snapshot(&t);
        let count = key.calls.load(Ordering::Relaxed);
        assert_inert(&s, &t);
        let lock = File::open(&t.0).unwrap();
        lock.lock().unwrap();
        // A watchdog releases the separate lock if a regression waits for it.
        let released = Arc::new(AtomicBool::new(false));
        let flag = released.clone();
        let worker = std::thread::spawn(move || {
            let start = std::time::Instant::now();
            while !flag.load(Ordering::Relaxed) && start.elapsed() < Duration::from_secs(2) {
                std::thread::sleep(Duration::from_millis(5));
            }
            lock.unlock().unwrap();
        });
        let start = std::time::Instant::now();
        if drop_handle {
            drop(s);
        } else {
            bad(s.close(), AuditErrorKind::Poisoned);
        }
        let elapsed = start.elapsed();
        released.store(true, Ordering::Relaxed);
        worker.join().unwrap();
        assert!(elapsed < Duration::from_secs(1));
        assert_eq!(key.calls.load(Ordering::Relaxed), count);
        assert_eq!(snapshot(&t), before);
        assert!(hooks::STDERR.with(|l| l.borrow().is_empty()));
        let fresh = Sink::open(&t.0, key.clone(), Config::default(), Some(held.head)).unwrap();
        let cp = fresh.close().unwrap();
        let disk = records(&t).pop().unwrap();
        assert_eq!(cp.hash(), disk.hash());
    }
}
#[test]
fn poison_846_checkpoint_close_drop_failure() {
    for op in 0..3 {
        for truncate_fails in [false, true] {
            let t = Temp::new();
            let s = create(&t);
            let before = bytes(&t);
            fail(if truncate_fails {
                &["checkpoint-data", "truncate"]
            } else {
                &["checkpoint-data"]
            });
            match op {
                0 => {
                    bad(s.checkpoint(), AuditErrorKind::Io);
                    assert_inert(&s, &t);
                    drop(s);
                }
                1 => bad(s.close(), AuditErrorKind::Io),
                _ => assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(s))).is_ok()
                ),
            }
            assert_eq!(t.0.join("audit.poison").exists(), truncate_fails);
            if !truncate_fails {
                assert_eq!(bytes(&t), before);
            }
            let lines = hooks::STDERR.with(|l| l.borrow().clone());
            assert_eq!(lines.len(), usize::from(op == 2));
            if op == 2 {
                assert!(lines[0].contains("injected checkpoint-data"));
            }
        }
    }
}
#[test]
fn poison_847_shared_poison_checkpoint_close_drop() {
    for op in 0..3 {
        let t = Temp::new();
        let key = counting();
        let s = Sink::create(&t.0, key.clone(), Config::default()).unwrap();
        let count = key.calls.load(Ordering::Relaxed);
        let path = t.0.clone();
        std::thread::spawn(move || fs::write(path.join("audit.poison"), b"second writer").unwrap())
            .join()
            .unwrap();
        let before = snapshot(&t);
        match op {
            0 => {
                bad(s.checkpoint(), AuditErrorKind::Poisoned);
                bad(s.close(), AuditErrorKind::Poisoned);
            }
            1 => bad(s.close(), AuditErrorKind::Poisoned),
            _ => drop(s),
        }
        assert_eq!(snapshot(&t), before);
        assert_eq!(key.calls.load(Ordering::Relaxed), count);
        assert_eq!(
            hooks::STDERR.with(|l| l.borrow().len()),
            usize::from(op == 2)
        );
        if op == 2 {
            assert!(hooks::STDERR.with(|l| l.borrow()[0].contains("audit.poison exists")));
        }
    }
}

#[test]
fn poison_832_staging_name_failure_and_failed_truncate() {
    for creating in [false, true] {
        let t = Temp::new();
        let mut a = if creating { None } else { Some(create(&t)) };
        let mut b = if creating { None } else { Some(open(&t)) };
        durability::start(&t.0);
        fail(&["staging-dir", "truncate"]);
        if let Some(a) = a.as_mut() {
            a.config.max_bytes = 1;
            bad(a.record(&entry()), AuditErrorKind::Io);
            assert_inert(a, &t);
            silent(a);
        } else {
            bad(
                Sink::create(&t.0, signer(), Config::default()),
                AuditErrorKind::Io,
            );
        }
        assert!(
            fs::read_to_string(t.0.join("audit.poison"))
                .unwrap()
                .contains(".audit-next.jsonl")
        );
        let before = snapshot(&t);
        if let Some(b) = b.as_mut() {
            assert_inert(b, &t);
            silent(b);
        }
        bad_open(&t, None, AuditErrorKind::Poisoned);
        assert_eq!(snapshot(&t), before);
        drop(a);
        drop(b);
        durability::replay();
        if t.0.join("audit.poison").exists() {
            fs::remove_file(t.0.join("audit.poison")).unwrap();
        }
        if creating {
            bad_open(&t, None, AuditErrorKind::CorruptTrail);
        } else {
            let mut recovered = open(&t);
            recovered.record(&entry()).unwrap();
            silent(&mut recovered);
        }
    }
}
#[test]
fn poison_836_no_handle_and_settlement_residuals() {
    for mode in 0..3 {
        let t = Temp::new();
        let mut writers = if mode == 0 {
            None
        } else {
            Some((create(&t), open(&t)))
        };
        if let Some((a, _)) = writers.as_ref() {
            fs::write(t.0.join(".audit-next.jsonl"), promotable(a, &t, false)).unwrap();
        }
        fail(&[
            if mode == 0 {
                "promote-dir"
            } else {
                "settle-promote-dir"
            },
            "create-poison",
        ]);
        match mode {
            0 => bad(
                Sink::create(&t.0, signer(), Config::default()),
                AuditErrorKind::Io,
            ),
            1 => bad_open(&t, None, AuditErrorKind::Io),
            _ => {
                let a = &writers.as_ref().unwrap().0;
                bad(a.record(&entry()), AuditErrorKind::Io);
                assert_inert(a, &t);
            }
        }
        assert!(!t.0.join("audit.poison").exists());
        if let Some((a, b)) = writers.as_mut() {
            b.record(&entry()).unwrap();
            silent(a);
            silent(b);
        }
        let mut reopened = open(&t);
        reopened.record(&entry()).unwrap();
        silent(&mut reopened);
    }
}
#[test]
fn durable_model_retains_last_success_and_inode_identity() {
    let t = Temp::new();
    let old = t.0.join("old");
    fs::write(&old, b"initial").unwrap();
    fs::hard_link(&old, t.0.join("alias")).unwrap();
    durability::start(&t.0);
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&old)
        .unwrap();
    file.set_len(0).unwrap();
    (&file).write_all(b"durable").unwrap();
    sync_io(&file, "record-data").unwrap();
    file.set_len(0).unwrap();
    (&file).write_all(b"not durable").unwrap();
    fail(&["record-data"]);
    assert!(sync_io(&file, "record-data").is_err());
    fs::rename(&old, t.0.join("moved")).unwrap();
    let dir = File::open(&t.0).unwrap();
    sync_io(&dir, "staging-dir").unwrap();
    durability::replay();
    assert_eq!(fs::read(t.0.join("moved")).unwrap(), b"durable");
    assert_eq!(fs::read(t.0.join("alias")).unwrap(), b"durable");
    durability::start(&t.0);
    fs::remove_file(t.0.join("alias")).unwrap();
    fs::remove_file(t.0.join("moved")).unwrap();
    fs::write(&old, b"new inode, never flushed").unwrap();
    sync_io(&dir, "staging-dir").unwrap();
    durability::replay();
    assert_eq!(fs::read(&old).unwrap(), b"");
    assert_eq!(snapshot(&t).len(), 1);
    // A distinct replay demonstrates durable contents and durable hard links.
    fs::write(&old, b"initial").unwrap();
    fs::hard_link(&old, t.0.join("alias")).unwrap();
    durability::start(&t.0);
    fs::write(&old, b"cache only").unwrap();
    durability::replay();
    assert_eq!(fs::read(&old).unwrap(), b"initial");
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        fs::metadata(&old).unwrap().ino(),
        fs::metadata(t.0.join("alias")).unwrap().ino()
    );
}

#[test]
fn poison_833_create_staging_write() {
    for truncate_fails in [false, true] {
        let t = Temp::new();
        hooks::OBSERVE.with(|o| {
            *o.borrow_mut() = Some(Box::new(move |site| {
                if site == "create-staging" {
                    hooks::SHORT.with(|short| short.set(Some(13)));
                    if truncate_fails {
                        fail(&["truncate"]);
                    }
                }
            }))
        });
        bad(
            Sink::create(&t.0, signer(), Config::default()),
            AuditErrorKind::Io,
        );
        hooks::OBSERVE.with(|o| *o.borrow_mut() = None);
        assert_eq!(
            fs::read(t.0.join(".audit-next.jsonl")).unwrap().len(),
            if truncate_fails { 13 } else { 0 }
        );
        assert!(!t.0.join("audit.poison").exists());
        bad_open(&t, None, AuditErrorKind::CorruptTrail);
        bad(
            Sink::create(&t.0, signer(), Config::default()),
            AuditErrorKind::TrailExists,
        );
    }
}
#[test]
fn poison_831_create_staging_name_fsync() {
    let t = Temp::new();
    fail(&["staging-dir"]);
    bad(
        Sink::create(&t.0, signer(), Config::default()),
        AuditErrorKind::Io,
    );
    assert_eq!(fs::read(t.0.join(".audit-next.jsonl")).unwrap(), b"");
    assert_eq!(fs::read(t.0.join("audit.trail")).unwrap().len(), 33);
    assert!(!t.0.join("audit.poison").exists());
    bad_open(&t, None, AuditErrorKind::CorruptTrail);
    bad(
        Sink::create(&t.0, signer(), Config::default()),
        AuditErrorKind::TrailExists,
    );
}

#[cfg(target_os = "linux")]
#[test]
fn drop_stderr_child_role() {
    let Some(path) = std::env::var_os("VIGIL_DROP_STDERR_DIR") else {
        return;
    };
    let s = Sink::open(Path::new(&path), signer(), Config::default(), None).unwrap();
    fail(&["checkpoint-data"]);
    drop(s);
}
#[cfg(target_os = "linux")]
#[test]
fn poison_846_drop_stderr_failure() {
    let t = Temp::new();
    let mut s = create(&t);
    silent(&mut s);
    let before = snapshot(&t);
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "audit::sink::tests::drop_stderr_child_role",
            "--nocapture",
        ])
        .env("VIGIL_DROP_STDERR_DIR", &t.0)
        .stderr(
            fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .unwrap(),
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    assert_eq!(snapshot(&t), before);
}
#[test]
fn poison_846_drop_signer_error_is_one_line() {
    #[derive(Debug)]
    struct Multiline;
    impl Signer for Multiline {
        fn public_key(&self) -> [u8; 32] {
            signer().public_key()
        }
        fn sign(&self, _: &[u8]) -> Result<[u8; 64], SignerError> {
            Err(SignerError::new("offline\nsecond line\rthird line"))
        }
    }
    let t = Temp::new();
    let mut s = create(&t);
    s.signer = Arc::new(Multiline);
    let before = snapshot(&t);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(s))).is_ok());
    let lines = hooks::STDERR.with(|lines| lines.borrow().clone());
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].lines().count(), 1);
    assert!(lines[0].contains("offline\\nsecond line\\rthird line"));
    assert_eq!(snapshot(&t), before);
}

// B3b: key custody and operator key generation (ADR-0005 d9).
#[test]
fn key_metadata_policy() {
    use crate::audit::signing::check_key_metadata;
    let path = std::path::Path::new("key.seed");
    for mode in [0o600, 0o400, 0o700] {
        check_key_metadata(path, mode, 12, 12).unwrap();
    }
    for mode in [0o640, 0o604, 0o660] {
        assert_eq!(
            check_key_metadata(path, mode, 12, 12)
                .unwrap_err()
                .to_string(),
            format!("key file has group or other permission bits: key.seed ({mode:o})")
        );
    }
    assert_eq!(
        check_key_metadata(path, 0o600, 12, 13)
            .unwrap_err()
            .to_string(),
        "key file owned by uid 12, not the current user 13: key.seed"
    );
}

#[test]
fn key_load_checks_descriptor() {
    let t = Temp::new();
    let path = t.0.join("key.seed");
    crate::audit::keygen(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    assert_eq!(
        KeyFileSigner::load(&path).unwrap_err().to_string(),
        format!(
            "key file has group or other permission bits: {} (640)",
            path.display()
        )
    );
    assert_eq!(
        KeyFileSigner::load(&t.0).unwrap_err().to_string(),
        format!("key file is not a regular file: {}", t.0.display())
    );
}

#[test]
fn key_load_fifo_without_blocking() {
    // Isolate a missing NONBLOCK mutant in a child so it cannot hang the suite.
    const CHILD: &str = "VIGIL_KEY_FIFO_CHILD";
    if let Some(path) = std::env::var_os(CHILD) {
        let path = PathBuf::from(path);
        assert_eq!(
            KeyFileSigner::load(&path).unwrap_err().to_string(),
            format!("key file is not a regular file: {}", path.display())
        );
        return;
    }
    let t = Temp::new();
    let fifo = t.0.join("fifo");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "audit::sink::tests::key_load_fifo_without_blocking",
        ])
        .env(CHILD, &fifo)
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("load blocked on FIFO");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn key_load_size_and_symlink() {
    let t = Temp::new();
    let path = t.0.join("key.seed");
    let key = crate::audit::keygen(&path).unwrap();
    let link = t.0.join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert_eq!(KeyFileSigner::load(&link).unwrap().public_key(), key);
    let mut bytes = fs::read(&path).unwrap();
    bytes.resize(1024, b' ');
    fs::write(&path, &bytes).unwrap();
    assert_eq!(KeyFileSigner::load(&path).unwrap().public_key(), key);
    bytes.push(b' ');
    fs::write(&path, &bytes).unwrap();
    assert_eq!(
        KeyFileSigner::load(&path).unwrap_err().to_string(),
        format!("key file too large: {}", path.display())
    );
    for bad in [b"00".as_slice(), &[0xff; 64], &[b'z'; 64]] {
        fs::write(&path, bad).unwrap();
        let error = KeyFileSigner::load(&path).unwrap_err().to_string();
        assert!(!error.contains(&"z".repeat(64)));
    }
}

#[test]
fn keygen_fresh_round_trip_and_never_overwrites() {
    const CHILD: &str = "VIGIL_KEYGEN_MODE_CHILD";
    let public_mode = match std::env::var(CHILD).as_deref() {
        Ok("022") => 0o644,
        Ok("077") => 0o600,
        Err(_) => {
            for mask in ["022", "077"] {
                assert!(
                    std::process::Command::new("sh")
                        .args([
                            "-c",
                            "umask \"$1\" && shift && exec \"$@\"",
                            "keygen-mode-child",
                            mask,
                        ])
                        .arg(std::env::current_exe().unwrap())
                        .args([
                            "--exact",
                            "audit::sink::tests::keygen_fresh_round_trip_and_never_overwrites",
                        ])
                        .env(CHILD, mask)
                        .status()
                        .unwrap()
                        .success()
                );
            }
            return;
        }
        Ok(mask) => panic!("unexpected child umask: {mask}"),
    };
    let t = Temp::new();
    let path = t.0.join("key.seed");
    let pub_path = t.0.join("key.seed.pub");
    let key = crate::audit::keygen(&path).unwrap();
    let seed = fs::read(&path).unwrap();
    let public = fs::read(&pub_path).unwrap();
    assert_eq!(seed.len(), 65);
    assert_eq!(seed[64], b'\n');
    assert!(
        seed[..64]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&pub_path).unwrap().permissions().mode() & 0o777,
        public_mode
    );
    assert_eq!(public, format!("{}\n", hex(&key)).as_bytes());
    assert!(!t.0.join("key.pub").exists());
    let signer = KeyFileSigner::load(&path).unwrap();
    assert_eq!(signer.public_key(), key);
    let message = b"key custody round trip";
    crate::audit::signing::verify_signature(&key, message, &signer.sign(message).unwrap()).unwrap();
    assert_eq!(
        crate::audit::keygen(&path).unwrap_err().to_string(),
        format!("key file exists: {}", path.display())
    );
    assert_eq!(fs::read(&path).unwrap(), seed);
    assert_eq!(fs::read(&pub_path).unwrap(), public);
}

#[test]
fn keygen_preexisting_public_and_dangling_symlink() {
    let t = Temp::new();
    let path = t.0.join("key.seed");
    let pub_path = t.0.join("key.seed.pub");
    fs::write(&pub_path, b"original").unwrap();
    assert_eq!(
        crate::audit::keygen(&path).unwrap_err().to_string(),
        format!("key file exists: {}", pub_path.display())
    );
    assert!(!path.exists());
    assert_eq!(fs::read(&pub_path).unwrap(), b"original");
    let target = t.0.join("absent");
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert_eq!(
        crate::audit::keygen(&path).unwrap_err().to_string(),
        format!("key file exists: {}", path.display())
    );
    assert!(!target.exists());
    assert!(
        fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn keygen_sync_order_and_cleanup() {
    let t = Temp::new();
    let path = t.0.join("key.seed");
    crate::audit::keygen(&path).unwrap();
    hooks::EVENTS.with(|events| {
        assert_eq!(
            *events.borrow(),
            ["keygen-seed", "keygen-pub", "keygen-dir"]
        )
    });
    use std::os::unix::fs::MetadataExt as _;
    let identity = |site, path: &std::path::Path| {
        let metadata = fs::metadata(path).unwrap();
        (site, metadata.dev(), metadata.ino())
    };
    hooks::SYNC_EVENTS.with(|events| {
        assert_eq!(
            *events.borrow(),
            [
                identity("keygen-seed", &path),
                identity("keygen-pub", &t.0.join("key.seed.pub")),
                identity("keygen-dir", &t.0),
            ]
        )
    });
    for site in ["keygen-seed", "keygen-pub", "keygen-dir"] {
        let path = t.0.join(site);
        hooks::FAIL.with(|fail| *fail.borrow_mut() = vec![site]);
        let error = crate::audit::keygen(&path).unwrap_err();
        assert!(error.to_string().contains(&format!("injected {site}")));
        assert!(!path.exists());
        assert!(!t.0.join(format!("{site}.pub")).exists());
        hooks::FAIL.with(|fail| assert!(fail.borrow().is_empty()));
    }
}

#[test]
fn keygen_bare_relative_name() {
    const CHILD: &str = "VIGIL_KEYGEN_RELATIVE_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let key = crate::audit::keygen("key.seed").unwrap();
        assert_eq!(KeyFileSigner::load("key.seed").unwrap().public_key(), key);
        assert!(std::path::Path::new("key.seed.pub").exists());
        return;
    }
    let t = Temp::new();
    assert!(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "audit::sink::tests::keygen_bare_relative_name"])
            .env(CHILD, "1")
            .current_dir(&t.0)
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn keygen_uses_entropy() {
    let first = Temp::new();
    let second = Temp::new();
    let first_path = first.0.join("key.seed");
    let second_path = second.0.join("key.seed");
    let first_key = crate::audit::keygen(&first_path).unwrap();
    let second_key = crate::audit::keygen(&second_path).unwrap();
    assert_ne!(first_key, second_key);
    assert_ne!(
        fs::read(first_path).unwrap(),
        fs::read(second_path).unwrap()
    );
}

#[test]
fn key_load_refuses_socket() {
    const CHILD: &str = "VIGIL_KEY_SOCKET_CHILD";
    if let Some(path) = std::env::var_os(CHILD) {
        let _listener = std::os::unix::net::UnixListener::bind("socket").unwrap();
        assert!(KeyFileSigner::load(path).is_err());
        return;
    }
    let t = Temp::new();
    assert!(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "audit::sink::tests::key_load_refuses_socket"])
            .env(CHILD, t.0.canonicalize().unwrap().join("socket"))
            .current_dir(&t.0)
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn key_load_ascii_whitespace_only() {
    let t = Temp::new();
    let path = t.0.join("key.seed");
    let key = crate::audit::keygen(&path).unwrap();
    let seed = fs::read_to_string(&path).unwrap();
    fs::write(&path, format!(" \t\r\n{}\r\n\t ", seed.trim_ascii())).unwrap();
    assert_eq!(KeyFileSigner::load(&path).unwrap().public_key(), key);
    fs::write(&path, format!("\u{00a0}{}\u{00a0}", seed.trim_ascii())).unwrap();
    assert_eq!(
        KeyFileSigner::load(&path).unwrap_err().to_string(),
        "seed contains non-hex characters"
    );
}
