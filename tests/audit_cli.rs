//! Operator CLI acceptance tests.
#![cfg(feature = "audit")]

#[path = "common/child.rs"]
mod child;

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::Arc,
};
use vigil::audit::{AuditConfig, Checkpoint, Entry, KeyFileSigner, checkpoints};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "vigil-cli-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
    fn cli(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_vigil-audit"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .unwrap()
    }
    fn success(&self, args: &[&str]) -> Vec<String> {
        let output = self.cli(args);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }
    fn create(&self) -> Checkpoint {
        self.success(&["keygen", "old.key"]);
        let lines = self.success(&["create", "--key", "old.key", "--service", "svc", "trail"]);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].len(), 32);
        assert!(lines[0].bytes().all(|b| b.is_ascii_hexdigit()));
        let cp = Checkpoint::parse(&lines[1]).unwrap();
        assert_eq!(disk(&self.path("trail")).last().unwrap(), cp.line());
        cp
    }
}
static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn head(cp: &Checkpoint) -> String {
    format!("{} blake3:{}", cp.seq(), hex(&cp.hash()))
}
fn arg(cp: &Checkpoint) -> String {
    head(cp).replacen(' ', ":", 1)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn disk(dir: &Path) -> Vec<String> {
    vigil::rotate::segments(dir, "audit")
        .unwrap()
        .iter()
        .flat_map(|p| {
            fs::read_to_string(p)
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}
fn receipt(line: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(line).unwrap();
    let attrs = value["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"]
        .as_array()
        .unwrap();
    let get = |key| attrs.iter().find(|a| a["key"] == key).unwrap()["value"].clone();
    format!(
        "{} {}",
        get("audit.seq")["intValue"].as_str().unwrap(),
        get("audit.hash")["stringValue"].as_str().unwrap()
    )
}
fn service(line: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    v["resourceLogs"][0]["resource"]["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["key"] == "service.name")
        .unwrap()["value"]["stringValue"]
        .as_str()
        .unwrap()
        .into()
}
fn matches_pair(lines: &[String], records: &[String]) {
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], receipt(&records[records.len() - 2]));
    assert_eq!(lines[1], records[records.len() - 1]);
}

#[test]
fn lifecycle_and_checkpoint() {
    let f = Fixture::new();
    let cp = f.create();
    assert!(disk(&f.path("trail")).iter().all(|l| service(l) == "svc"));
    let public = f.success(&["keygen", "new.key"]);
    assert_eq!(public.len(), 1);
    assert_eq!(
        fs::read_to_string(f.path("new.key.pub")).unwrap().trim(),
        public[0]
    );
    let lines = f.success(&[
        "rotate",
        "--key",
        "new.key",
        "--actor",
        "operator",
        "--reason",
        "scheduled",
        "--bound",
        &arg(&cp),
        "--expect-head",
        &arg(&cp),
        "trail",
    ]);
    let records = disk(&f.path("trail"));
    matches_pair(&lines, &records);
    assert!(
        records[records.len() - 2..]
            .iter()
            .all(|l| service(l) == "vigil-audit")
    );
    let cp = Checkpoint::parse(&lines[1]).unwrap();
    let lines = f.success(&[
        "checkpoint",
        "--key",
        "new.key",
        "--expect-head",
        &arg(&cp),
        "trail",
    ]);
    assert_eq!(lines.len(), 2);
    let records = disk(&f.path("trail"));
    assert_eq!(lines[0], receipt(records.last().unwrap()));
    assert_eq!(lines[1], *records.last().unwrap());
}

#[test]
fn resume_prints_opening_receipt_and_explicit_close() {
    let f = Fixture::new();
    let cp = f.create();
    let lost = cp.seq() + 5;
    let lines = f.success(&[
        "resume",
        "--key",
        "old.key",
        "--actor",
        "operator",
        "--reason",
        "loss",
        "--head",
        &arg(&cp),
        "--lost-through",
        &lost.to_string(),
        "trail",
    ]);
    assert_eq!(lines.len(), 3);
    let records = disk(&f.path("trail"));
    let tail = &records[records.len() - 3..];
    assert_eq!(lines[0], tail[0]);
    assert_eq!(Checkpoint::parse(&lines[0]).unwrap().seq(), lost + 1);
    assert_eq!(lines[1], receipt(&tail[1]));
    assert!(lines[1].starts_with(&format!("{} ", lost + 2)));
    assert_eq!(lines[2], tail[2]);
    assert_eq!(Checkpoint::parse(&lines[2]).unwrap().seq(), lost + 3);
    assert!(tail.iter().all(|l| service(l) == "vigil-audit"));
    assert_eq!(
        records
            .iter()
            .filter_map(|l| Checkpoint::parse(l).ok())
            .map(|c| c.seq())
            .max(),
        Some(lost + 3)
    );
}

#[test]
fn checkpoints_include_sealed_and_live_in_order() {
    let f = Fixture::new();
    let cp = f.create();
    f.success(&[
        "checkpoint",
        "--key",
        "old.key",
        "--expect-head",
        &arg(&cp),
        "trail",
    ]);
    let dir = f.path("trail");
    let expected = disk(&dir);
    assert_eq!(expected.len(), 3);
    fs::write(
        dir.join("audit-20261013T120000.000000000Z_000010.jsonl"),
        format!("{}\n", expected[1]),
    )
    .unwrap();
    fs::write(
        dir.join("audit-20261013T120000.000000000Z_000002.jsonl"),
        format!("{}\n", expected[0]),
    )
    .unwrap();
    fs::write(dir.join("audit.jsonl"), format!("{}\n", expected[2])).unwrap();
    assert_eq!(
        checkpoints(&dir)
            .unwrap()
            .iter()
            .map(|c| c.line().to_owned())
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(f.success(&["checkpoints", "trail"]), expected);
    fs::write(dir.join("audit.jsonl"), b"not json\n\xff\n{}\n").unwrap();
    assert_eq!(checkpoints(&dir).unwrap().len(), 2);
}

#[test]
fn usage_and_signer_exit_codes() {
    let f = Fixture::new();
    for args in [
        vec!["verify"],
        vec!["unknown"],
        vec!["create"],
        vec![
            "checkpoint",
            "--key",
            "missing",
            "--expect-head",
            "5:sha256:0000",
            "trail",
        ],
        vec![
            "resume",
            "--key",
            "missing",
            "--actor",
            "a",
            "--reason",
            "r",
            "--head",
            "0:blake3:0000000000000000000000000000000000000000000000000000000000000000",
            "--lost-through",
            "x",
            "trail",
        ],
    ] {
        assert_eq!(f.cli(&args).status.code(), Some(2));
    }
    let output = f.cli(&["create", "--key", "missing", "--service", "svc", "trail"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .starts_with("error: Signer: ")
    );
    let cp = f.create();
    let output = f.cli(&[
        "resume",
        "--key",
        "old.key",
        "--actor",
        "a",
        "--reason",
        "r",
        "--head",
        &arg(&cp),
        "--lost-through",
        &(i64::MAX as u64 - 1).to_string(),
        "trail",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .starts_with("error: InvalidConfig: ")
    );
}

#[test]
fn writer_child() {
    let Some(dir) = std::env::var_os("VIGIL_CLI_WRITER_DIR") else {
        return;
    };
    let key = std::env::var_os("VIGIL_CLI_WRITER_KEY").unwrap();
    let trail = AuditConfig::new("svc")
        .dir(dir)
        .open(Arc::new(KeyFileSigner::load(key).unwrap()))
        .unwrap();
    let receipt = trail.record(&Entry::new("worker", "read", "file")).unwrap();
    println!("HEAD {} {}", receipt.seq(), receipt.hash_string());
    println!("HEAD {}", head(&trail.close().unwrap()));
}

#[test]
fn clean_stop_head_from_eight_processes() {
    let f = Fixture::new();
    let bound = f.create();
    let mut children = Vec::new();
    for _ in 0..8 {
        children.push(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "writer_child", "--nocapture"])
                .env("VIGIL_CLI_WRITER_DIR", f.path("trail"))
                .env("VIGIL_CLI_WRITER_KEY", f.path("old.key"))
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        );
    }
    let mut heads = Vec::new();
    for child in children {
        let output = child.wait_with_output().unwrap();
        let text = child::successful_test(output);
        heads.extend(
            text.lines()
                .filter_map(|l| l.strip_prefix("HEAD "))
                .map(str::to_owned),
        );
    }
    let highest = heads
        .iter()
        .max_by_key(|h| h.split_once(' ').unwrap().0.parse::<u64>().unwrap())
        .unwrap();
    assert_eq!(*highest, receipt(disk(&f.path("trail")).last().unwrap()));
    f.success(&["keygen", "new.key"]);
    f.success(&[
        "rotate",
        "--key",
        "new.key",
        "--actor",
        "a",
        "--reason",
        "r",
        "--bound",
        &arg(&bound),
        "--expect-head",
        &highest.replacen(' ', ":", 1),
        "trail",
    ]);
}

#[test]
fn tampered_heads_never_write() {
    for tamper in ["append", "truncate", "rewrite"] {
        let f = Fixture::new();
        let cp = f.create();
        f.success(&["keygen", "new.key"]);
        let path = f.path("trail/audit.jsonl");
        let original = fs::read(&path).unwrap();
        match tamper {
            "append" => {
                let trail = AuditConfig::new("svc")
                    .dir(f.path("trail"))
                    .open(Arc::new(KeyFileSigner::load(f.path("old.key")).unwrap()))
                    .unwrap();
                trail
                    .record(&Entry::new("attacker", "read", "object"))
                    .unwrap();
                trail.close().unwrap();
            }
            "truncate" => {
                let first = original.iter().position(|b| *b == b'\n').unwrap();
                fs::write(&path, &original[..=first]).unwrap();
            }
            _ => {
                // Replace the head with a valid, differently signed checkpoint.
                let first = original.iter().position(|b| *b == b'\n').unwrap();
                fs::write(&path, &original[..=first]).unwrap();
                let trail = AuditConfig::new("svc")
                    .dir(f.path("trail"))
                    .open(Arc::new(KeyFileSigner::load(f.path("new.key")).unwrap()))
                    .unwrap();
                trail.close().unwrap();
            }
        }
        let before = tree(&f.path("trail"));
        let output = f.cli(&[
            "rotate",
            "--key",
            "new.key",
            "--actor",
            "a",
            "--reason",
            "r",
            "--bound",
            &arg(&cp),
            "--expect-head",
            &arg(&cp),
            "trail",
        ]);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{tamper}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .starts_with("error: HeadMismatch: ")
        );
        assert!(output.stdout.is_empty());
        assert_eq!(tree(&f.path("trail")), before);
    }
}
fn tree(dir: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            let b = fs::read(&p).unwrap();
            (p, b)
        })
        .collect()
}

#[test]
fn stdout_failure_echoes_successful_lines() {
    use std::{io::Read, os::fd::OwnedFd, os::unix::net::UnixStream, process::Stdio};
    let f = Fixture::new();
    f.success(&["keygen", "old.key"]);
    let (writer, mut reader) = UnixStream::pair().unwrap();
    // Shutting down the peer read half deterministically makes every write fail.
    reader.shutdown(std::net::Shutdown::Read).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vigil-audit"))
        .current_dir(&f.0)
        .args(["create", "--key", "old.key", "--service", "svc", "trail"])
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    let lines = stderr.lines().collect::<Vec<_>>();
    assert_eq!(lines[0].len(), 32);
    assert_eq!(lines[1], disk(&f.path("trail")).last().unwrap());
    assert!(lines[2].starts_with("error: Io:"));
    let mut unused = Vec::new();
    reader.read_to_end(&mut unused).unwrap();
}

#[test]
fn close_invalid_config_keeps_successful_resume_output() {
    let f = Fixture::new();
    let cp = f.create();
    let lost = i64::MAX as u64 - 2;
    let output = f.cli(&[
        "resume",
        "--key",
        "old.key",
        "--actor",
        "a",
        "--reason",
        "r",
        "--head",
        &arg(&cp),
        "--lost-through",
        &lost.to_string(),
        "trail",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .starts_with("error: InvalidConfig:")
    );
    let lines = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), 2);
    let records = disk(&f.path("trail"));
    assert_eq!(lines[0], records[records.len() - 2]);
    assert_eq!(lines[1], receipt(records.last().unwrap()));
}

#[test]
fn global_help_lists_commands_and_exit_codes() {
    let f = Fixture::new();
    for alias in ["--help", "-h", "help"] {
        let output = f.cli(&[alias]);
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout).unwrap();
        for command in [
            "keygen",
            "create",
            "checkpoints",
            "checkpoint",
            "rotate",
            "resume",
        ] {
            assert!(text.contains(&format!("vigil-audit {command} ")), "{text}");
        }
        assert!(text.contains("verify: not yet available (#13)"));
        for code in [
            "0  Success",
            "1  AuditError or SignerError",
            "2  Usage, Io or InvalidConfig",
        ] {
            assert!(text.contains(code), "{text}");
        }
    }
}

#[test]
fn usage_errors_include_synopsis() {
    let f = Fixture::new();
    for args in [
        vec![],
        vec!["unknown"],
        vec!["create"],
        vec!["keygen", "--bad"],
        vec!["verify"],
    ] {
        let output = f.cli(&args);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let text = String::from_utf8(output.stderr).unwrap();
        assert!(text.starts_with("error: Usage: "), "{text}");
        assert!(text.contains("Usage:\n  vigil-audit "), "{text}");
    }
}

#[test]
fn command_help_matches_parser_commands() {
    let f = Fixture::new();
    // Read the dispatch arms independently of the shared argument/help table:
    // removing a help row must not silently remove this coverage.
    let source = include_str!("../src/bin/vigil-audit/args.rs");
    let parser: std::collections::BTreeSet<_> = source
        .lines()
        .filter_map(|line| {
            let line = line.trim().strip_prefix('"')?;
            let (name, rest) = line.split_once('"')?;
            rest.contains("=> Command::").then_some(name)
        })
        .collect();
    let output = f.cli(&["--help"]);
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    let help: std::collections::BTreeSet<_> = text
        .lines()
        .filter_map(|line| {
            line.strip_prefix("  vigil-audit ")?
                .split_whitespace()
                .next()
        })
        .collect();
    assert!(!parser.is_empty());
    assert_eq!(help, parser);
    for command in parser {
        let output = f.cli(&[command, "--help"]);
        assert_eq!(output.status.code(), Some(0), "{command}");
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.starts_with(&format!("Usage: vigil-audit {command} ")));
    }
}
