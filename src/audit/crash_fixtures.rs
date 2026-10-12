//! Reusable process crash fixtures for writer tests and verifier evidence (#13).
use super::*;
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::process::ExitStatusExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

pub(crate) fn command(path: &Path, role: &str) -> Command {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", "audit::sink::crashes::child_role", "--nocapture"])
        .env("VIGIL_CRASH_DIR", path)
        .env("VIGIL_CRASH_ROLE", role);
    cmd
}
pub(crate) fn knob(name: &str, default: usize) -> usize {
    std::env::var(name).map_or(default, |v| v.parse::<usize>().unwrap().max(1))
}
pub(crate) fn install_park(site: String) {
    hooks::OBSERVE.with(|v| {
        *v.borrow_mut() = Some(Box::new(move |event| {
            if event == site {
                println!("READY");
                std::io::stdout().flush().unwrap();
                loop {
                    std::thread::park();
                }
            }
        }))
    });
}
/// Kills and reaps even when an assertion unwinds, retaining no lock-holding child.
pub(crate) struct Process {
    child: Child,
    output: BufReader<std::process::ChildStdout>,
    pub(crate) receipts: Vec<(u64, String)>,
}
impl Process {
    pub(crate) fn spawn(path: &Path, role: &str, site: &str) -> Self {
        let mut child = command(path, role)
            .env("VIGIL_CRASH_SITE", site)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            output,
            receipts: Vec::new(),
        }
    }
    fn line(&mut self) -> String {
        let mut line = String::new();
        assert_ne!(
            self.output.read_line(&mut line).unwrap(),
            0,
            "child ended before handshake"
        );
        if let Some(rest) = line.strip_prefix("RECEIPT ") {
            let (seq, hash) = rest.trim().split_once(' ').unwrap();
            self.receipts.push((seq.parse().unwrap(), hash.into()));
        }
        line
    }
    pub(crate) fn ready(&mut self) {
        while self.line().trim() != "READY" {}
    }
    pub(crate) fn kill(&mut self) {
        self.child.kill().unwrap();
        assert_eq!(self.child.wait().unwrap().signal(), Some(9));
    }
    pub(crate) fn close(&mut self) {
        self.child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"close\n")
            .unwrap();
        let mut line = String::new();
        while self.output.read_line(&mut line).unwrap() != 0 {
            if let Some(rest) = line.strip_prefix("RECEIPT ") {
                let (seq, hash) = rest.trim().split_once(' ').unwrap();
                self.receipts.push((seq.parse().unwrap(), hash.into()));
            }
            line.clear();
        }
        assert!(self.child.wait().unwrap().success());
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
pub(crate) fn content(path: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    fs::read_dir(path)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (e.file_name().into(), fs::read(e.path()).unwrap())
        })
        .collect()
}
pub(crate) fn assert_recovery_bytes(
    before: &std::collections::BTreeMap<PathBuf, Vec<u8>>,
    after: &std::collections::BTreeMap<PathBuf, Vec<u8>>,
) {
    // Settlement may rename or discard staging; every resulting file must have
    // exactly the bytes of an input file. No record or signature is synthesized.
    let mut expected: Vec<_> = before.values().cloned().collect();
    expected.sort();
    let mut actual: Vec<_> = after.values().cloned().collect();
    actual.sort();
    if expected != actual {
        let staged = before.get(Path::new(".audit-next.jsonl")).unwrap();
        let index = expected.iter().position(|v| v == staged).unwrap();
        expected.remove(index);
        assert_eq!(expected, actual);
    }
    assert_eq!(
        before.get(Path::new("audit.trail")),
        after.get(Path::new("audit.trail"))
    );
}
pub(crate) fn chain(path: &Path) -> Vec<Record> {
    let dir = File::open(path).unwrap();
    let mut names = rotate::rotated_names_at(&dir, "audit").unwrap();
    names.push("audit.jsonl".into());
    let mut result = Vec::new();
    let mut gap = Vec::new();
    for name in names {
        for part in fs::read(path.join(name))
            .unwrap()
            .split_inclusive(|b| *b == b'\n')
        {
            let payload = part.strip_suffix(b"\n").unwrap_or(part);
            if let Ok(mut records) = Record::parse_line(payload) {
                assert_eq!(records.len(), 1);
                let r = records.remove(0);
                if !gap.is_empty() {
                    let mut h = blake3::Hasher::new();
                    h.update(b"vigil.audit.v1.repaired\0");
                    h.update(&gap);
                    assert_eq!(r.context.repaired, Some(*h.finalize().as_bytes()));
                    gap.clear();
                } else {
                    assert!(r.context.repaired.is_none());
                }
                if let Some(previous) = result.last() {
                    let previous: &Record = previous;
                    assert_eq!(r.context.seq, previous.context.seq + 1);
                    assert_eq!(r.context.previous, previous.hash());
                } else {
                    assert_eq!(r.context.seq, 0);
                    assert_eq!(r.context.previous, Record::genesis(&r.context.trail));
                }
                result.push(r);
            } else {
                gap.extend_from_slice(part);
            }
        }
    }
    assert!(gap.is_empty(), "final writer must attest every fragment");
    result
}
pub(crate) fn shuffled_indices(count: usize) -> Vec<usize> {
    let mut order: Vec<_> = (0..count).collect();
    for i in (1..count).rev() {
        let mut random = [0; 8];
        getrandom::fill(&mut random).unwrap();
        order.swap(i, (u64::from_le_bytes(random) % (i as u64 + 1)) as usize);
    }
    order
}
pub(crate) fn assert_receipts(all: &[Record], held: &[(u64, String)]) {
    for (seq, hash) in held {
        assert_eq!(
            all.iter()
                .filter(|r| r.context.seq == *seq && hex(&r.hash()) == *hash)
                .count(),
            1
        );
    }
}
