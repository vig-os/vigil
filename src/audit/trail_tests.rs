use super::*;
use crate::rotate::Directory;
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tracing_subscriber::{Layer, layer::SubscriberExt};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "vigil-public-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(&self) -> AuditConfig {
        AuditConfig::new("svc").dir(&self.0)
    }
    fn records(&self) -> Vec<Record> {
        fs::read(self.0.join("audit.jsonl"))
            .unwrap()
            .split(|b| *b == b'\n')
            .filter(|b| !b.is_empty())
            .flat_map(|b| Record::parse_line(b).unwrap())
            .collect()
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
fn entry() -> Entry {
    Entry::new("actor", "change", "object")
        .before(Value::Text("secret-before".into()))
        .after(Value::Text("secret-after".into()))
}

#[test]
fn public_receipt_checkpoint_and_close_roundtrip() {
    let temp = Temp::new();
    let trail = temp.config().create(signer()).unwrap();
    assert_eq!(trail.dir(), temp.0);
    let receipt = trail.record(&entry()).unwrap();
    assert_eq!(receipt.trail(), trail.trail());
    assert_eq!(receipt.seq(), 1);
    assert_eq!(receipt.unsigned_records(), 0);
    assert_eq!(receipt.hash_string(), digest_string(&receipt.hash()));
    let mut found = false;
    let state = storage::scan(
        &fs::File::open(temp.0.join("audit.jsonl")).unwrap(),
        receipt.trail(),
        None,
        true,
        Some(storage::Head {
            seq: receipt.seq(),
            hash: receipt.hash(),
        }),
        &mut found,
        true,
    )
    .unwrap();
    assert!(found);
    assert_eq!(state.head.seq, receipt.seq());
    assert_eq!(state.head.hash, receipt.hash());
    let records = temp.records();
    assert_eq!(records.len(), 2);
    assert_eq!(records[1].context.seq, receipt.seq());
    assert_eq!(records[1].hash(), receipt.hash());
    let expected = format!(
        "{}\n",
        String::from_utf8(sink::line(&records[1]).unwrap())
            .unwrap()
            .trim_end_matches('\n')
    );
    let disk = fs::read_to_string(temp.0.join("audit.jsonl")).unwrap();
    assert!(disk.ends_with(&expected));
    let cp = trail.checkpoint().unwrap();
    assert_eq!(cp.seq(), 2);
    assert_eq!(Checkpoint::parse(cp.line()).unwrap().hash(), cp.hash());
    let cp = trail.close().unwrap();
    assert_eq!(cp.seq(), 3);
    assert_eq!(Checkpoint::parse(cp.line()).unwrap().line(), cp.line());
    assert_eq!(temp.records().last().unwrap().hash(), cp.hash());
    let reopened = temp
        .config()
        .expect_head(receipt.seq(), receipt.hash())
        .open(signer())
        .unwrap();
    assert_eq!(reopened.trail(), receipt.trail());
    assert_eq!(reopened.close().unwrap().seq(), 4);
}
#[test]
fn public_validation_and_reserved_action() {
    let temp = Temp::new();
    for create in [false, true] {
        for config in [
            temp.config().max_bytes(0),
            temp.config().checkpoint_every(0),
            temp.config().checkpoint_interval(Duration::ZERO),
        ] {
            let result = if create {
                config.create(signer())
            } else {
                config.open(signer())
            };
            assert_eq!(result.err().unwrap().kind(), AuditErrorKind::InvalidConfig);
        }
        for service in ["", ".", "..", "a/b", "é", "a b"] {
            let config = AuditConfig::new(service).dir(&temp.0);
            let result = if create {
                config.create(signer())
            } else {
                config.open(signer())
            };
            assert_eq!(result.err().unwrap().kind(), AuditErrorKind::InvalidConfig);
        }
    }
    assert_eq!(
        temp.config()
            .expect_head(0, [0; 32])
            .create(signer())
            .err()
            .unwrap()
            .kind(),
        AuditErrorKind::InvalidConfig
    );
    assert!(fs::read_dir(&temp.0).unwrap().next().is_none());
    let trail = temp.config().create(signer()).unwrap();
    let before = fs::read(temp.0.join("audit.jsonl")).unwrap();
    assert_eq!(
        trail
            .record(&Entry::new("actor", "vigil.audit.test", "object"))
            .err()
            .unwrap()
            .kind(),
        AuditErrorKind::InvalidEntry
    );
    assert_eq!(fs::read(temp.0.join("audit.jsonl")).unwrap(), before);
    trail.close().unwrap();
}
#[derive(Debug)]
struct Flaky {
    key: KeySeed,
    down: AtomicBool,
}
impl Signer for Flaky {
    fn public_key(&self) -> [u8; 32] {
        self.key.public_key()
    }
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], SignerError> {
        if self.down.load(Ordering::Relaxed) {
            Err(SignerError::new("offline"))
        } else {
            self.key.sign(message)
        }
    }
}
#[test]
fn unsigned_count_is_a_cumulative_per_handle_snapshot() {
    let temp = Temp::new();
    let signer = Arc::new(Flaky {
        key: KeySeed::parse(&"11".repeat(32)).unwrap(),
        down: AtomicBool::new(false),
    });
    let trail = temp
        .config()
        .checkpoint_every(1)
        .create(signer.clone())
        .unwrap();
    signer.down.store(true, Ordering::Relaxed);
    let first = trail.record(&entry()).unwrap();
    let second = trail.record(&entry()).unwrap();
    assert_eq!(first.unsigned_records(), 1);
    assert_eq!(second.unsigned_records(), 2);
    signer.down.store(false, Ordering::Relaxed);
    let third = trail.record(&entry()).unwrap();
    assert_eq!(third.unsigned_records(), 2);
    assert_eq!(first.unsigned_records(), 1);
    let other = temp.config().open(signer.clone()).unwrap();
    assert_eq!(other.record(&entry()).unwrap().unsigned_records(), 0);
    other.close().unwrap();
    trail.close().unwrap();
}
#[derive(Clone)]
struct Probe {
    dir: PathBuf,
    events: Arc<Mutex<Vec<BTreeMap<String, String>>>>,
}
impl<S: tracing::Subscriber> Layer<S> for Probe {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if event.metadata().target() != "vigil::audit" {
            return;
        }
        assert_eq!(*event.metadata().level(), tracing::Level::INFO);
        // Same-thread reentry is WouldBlock if the mirror still holds the lock.
        Directory::open(&self.dir)
            .unwrap()
            .with_lock(|_| ())
            .unwrap();
        #[derive(Default)]
        struct Fields(BTreeMap<String, String>);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.insert(field.name().into(), format!("{value:?}"));
            }
        }
        let mut fields = Fields::default();
        event.record(&mut fields);
        self.events.lock().unwrap().push(fields.0);
    }
}
#[test]
fn mirror_fires_after_directory_unlock_and_contains_only_four_fields() {
    let temp = Temp::new();
    let events = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_test_writer()
        .finish()
        .with(Probe {
            dir: temp.0.clone(),
            events: events.clone(),
        });
    tracing::subscriber::with_default(subscriber, || {
        let trail = temp.config().mirror_to_logs(true).create(signer()).unwrap();
        let receipt = trail.record(&entry()).unwrap();
        let captured = events.lock().unwrap();
        assert_eq!(captured.len(), 1);
        let fields = &captured[0];
        assert_eq!(
            fields.keys().map(String::as_str).collect::<Vec<_>>(),
            ["action", "hash", "object", "seq"]
        );
        assert_eq!(fields["action"], "\"change\"");
        assert_eq!(fields["object"], "\"object\"");
        assert_eq!(fields["seq"], receipt.seq().to_string());
        assert_eq!(fields["hash"].trim_matches('"'), receipt.hash_string());
        drop(captured);
        let error = trail
            .record(&Entry::new("actor", "vigil.audit.test", "object"))
            .err()
            .unwrap();
        assert_eq!(error.kind(), AuditErrorKind::InvalidEntry);
        assert_eq!(events.lock().unwrap().len(), 1);
        trail.checkpoint().unwrap();
        trail.close().unwrap();
        let off = temp.config().open(signer()).unwrap();
        off.record(&entry()).unwrap();
        assert!(
            off.record(&Entry::new("actor", "vigil.audit.test", "object"))
                .is_err()
        );
        off.close().unwrap();
        assert_eq!(events.lock().unwrap().len(), 1);
    });
}

#[test]
fn environment_directory_in_child() {
    const CHILD: &str = "VIGIL_AUDIT_DIRECTORY_CHILD";
    if let Ok(expected) = std::env::var(CHILD) {
        let result = AuditConfig::new("svc").create(signer());
        if expected == "missing" {
            let error = result.err().unwrap();
            assert_eq!(error.kind(), AuditErrorKind::InvalidConfig);
            assert!(error.to_string().contains("XDG_STATE_HOME and HOME"));
        } else {
            let trail = result.unwrap();
            assert_eq!(trail.dir(), PathBuf::from(expected));
            trail.close().unwrap();
        }
        return;
    }
    let temp = Temp::new();
    for (xdg, home, suffix) in [
        ("xdg", "home", "xdg/svc/audit"),
        ("relative", "home", "home/.local/state/svc/audit"),
        ("relative", "relative", "missing"),
    ] {
        let absolute = |s: &str| {
            if s == "relative" {
                PathBuf::from(s)
            } else {
                temp.0.join(s)
            }
        };
        let expected = if suffix == "missing" {
            PathBuf::from(suffix)
        } else {
            temp.0.join(suffix)
        };
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "audit::trail_tests::environment_directory_in_child",
                "--nocapture",
            ])
            .env(CHILD, expected)
            .env("VIGIL_DIR", temp.0.join("ignored"))
            .env("XDG_STATE_HOME", absolute(xdg))
            .env("HOME", absolute(home))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!temp.0.join("ignored").exists());
    }
}

#[test]
fn concurrent_receipts_snapshot_under_the_lock() {
    let temp = Temp::new();
    let signer = Arc::new(Flaky {
        key: KeySeed::parse(&"11".repeat(32)).unwrap(),
        down: AtomicBool::new(false),
    });
    let trail = temp
        .config()
        .checkpoint_every(1)
        .create(signer.clone())
        .unwrap();
    signer.down.store(true, Ordering::Relaxed);
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| trail.record(&entry()).unwrap()))
            .collect();
        for worker in workers {
            let receipt = worker.join().unwrap();
            assert_eq!(receipt.unsigned_records(), receipt.seq());
        }
    });
    signer.down.store(false, Ordering::Relaxed);
    trail.close().unwrap();
}
#[test]
fn failed_close_is_consumed_without_a_drop_retry() {
    let temp = Temp::new();
    let signer = Arc::new(Flaky {
        key: KeySeed::parse(&"11".repeat(32)).unwrap(),
        down: AtomicBool::new(false),
    });
    let trail = temp.config().create(signer.clone()).unwrap();
    let receipt = trail.record(&entry()).unwrap();
    let before = fs::read(temp.0.join("audit.jsonl")).unwrap();
    signer.down.store(true, Ordering::Relaxed);
    assert_eq!(trail.close().err().unwrap().kind(), AuditErrorKind::Signer);
    assert_eq!(fs::read(temp.0.join("audit.jsonl")).unwrap(), before);
    signer.down.store(false, Ordering::Relaxed);
    temp.config()
        .expect_head(receipt.seq(), receipt.hash())
        .open(signer)
        .unwrap()
        .close()
        .unwrap();
}
#[test]
fn missing_marker_recovery_and_expected_head_errors() {
    let temp = Temp::new();
    assert_eq!(
        temp.config().open(signer()).err().unwrap().kind(),
        AuditErrorKind::MissingTrail
    );
    fs::write(temp.0.join("audit.trail"), format!("{}\n", "11".repeat(16))).unwrap();
    assert_eq!(
        temp.config().open(signer()).err().unwrap().kind(),
        AuditErrorKind::CorruptTrail
    );
    assert_eq!(
        temp.config().create(signer()).err().unwrap().kind(),
        AuditErrorKind::TrailExists
    );
    let other = Temp::new();
    let cp = other.config().create(signer()).unwrap().close().unwrap();
    let before = fs::read(other.0.join("audit.jsonl")).unwrap();
    assert_eq!(
        other
            .config()
            .expect_head(cp.seq(), [0; 32])
            .open(signer())
            .err()
            .unwrap()
            .kind(),
        AuditErrorKind::HeadMismatch
    );
    assert_eq!(fs::read(other.0.join("audit.jsonl")).unwrap(), before);
}

#[test]
fn oversized_service_leaves_directory_reusable() {
    for length in [256, 1_000_100] {
        let temp = Temp::new();
        for create in [true, false] {
            let config = AuditConfig::new("a".repeat(length)).dir(&temp.0);
            let result = if create {
                config.create(signer())
            } else {
                config.open(signer())
            };
            assert_eq!(result.err().unwrap().kind(), AuditErrorKind::InvalidConfig);
            assert_eq!(fs::read_dir(&temp.0).unwrap().count(), 0);
        }
        AuditConfig::new("a".repeat(255))
            .dir(&temp.0)
            .create(signer())
            .unwrap()
            .close()
            .unwrap();
    }
}

#[test]
fn public_debug_and_value_traits() {
    fn receipt_traits<T: std::fmt::Debug + Clone + Copy + PartialEq + Eq + std::hash::Hash>() {}
    fn config_traits<T: std::fmt::Debug + Clone>() {}
    receipt_traits::<Receipt>();
    config_traits::<AuditConfig>();
    let temp = Temp::new();
    let config = temp.config();
    assert!(format!("{config:?}").contains("svc"));
    let trail = config.clone().create(signer()).unwrap();
    assert_eq!(
        format!("{trail:?}"),
        format!(
            "AuditTrail {{ dir: {:?}, trail: {:?}, service: {:?} }}",
            temp.0,
            trail.trail(),
            "svc"
        )
    );
    trail.close().unwrap();
}
