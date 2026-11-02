//! Public collecting verifier acceptance tests.
#![cfg(feature = "audit")]
use std::{
    error::Error,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use vigil::audit::{AuditErrorKind, FindingKind as K, Report, TrustPolicy, Verifier, verify};
const GOLDEN: &str = include_str!("fixtures/audit/codec.jsonl");
const TRAIL: [u8; 16] = [0x11; 16];
struct Dir(PathBuf);
impl Dir {
    fn new() -> Self {
        static ID: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "vigil-verify-engine-{}-{}",
            std::process::id(),
            ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn put(&self, name: &str, bytes: impl AsRef<[u8]>) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn policy() -> TrustPolicy {
    TrustPolicy::builder().trail(TRAIL).build().unwrap()
}
fn entry() -> &'static str {
    GOLDEN.lines().next().unwrap()
}
fn kinds(report: &Report, kind: K) -> Vec<&vigil::audit::Finding> {
    report
        .findings()
        .iter()
        .filter(|f| f.kind() == kind)
        .collect()
}
#[test]
fn pinned_empty_selection_and_narrowing_precede_reads() {
    let dir = Dir::new();
    let report = verify(&dir.0, &policy()).unwrap();
    assert_eq!(report.trail(), TRAIL);
    assert_eq!(report.records(), 0);
    assert_eq!(
        (
            report.first_seq(),
            report.last_seq(),
            report.covered_through()
        ),
        (None, None, None)
    );
    assert!(report.findings().is_empty());
    let multi = TrustPolicy::builder()
        .trail(TRAIL)
        .trail([2; 16])
        .build()
        .unwrap();
    let verifier = Verifier::new(multi);
    assert_eq!(
        verifier.verify_files([]).unwrap_err().kind(),
        AuditErrorKind::InvalidConfig
    );
    assert_eq!(
        verifier
            .verify_files([dir.0.join("missing")])
            .unwrap_err()
            .kind(),
        AuditErrorKind::InvalidConfig
    );
    assert_eq!(
        verifier.clone().trail([3; 16]).unwrap_err().kind(),
        AuditErrorKind::InvalidConfig
    );
    assert_eq!(
        verifier
            .trail([2; 16])
            .unwrap()
            .verify_files([])
            .unwrap()
            .trail(),
        [2; 16]
    );
}
#[test]
fn foreign_first_and_only_record_cannot_select_the_report_id() {
    let dir = Dir::new();
    let file = dir.put("copy", entry());
    let trust = TrustPolicy::builder().trail([2; 16]).build().unwrap();
    let report = Verifier::new(trust).verify_files([file.clone()]).unwrap();
    assert_eq!(report.trail(), [2; 16]);
    assert_eq!(report.records(), 0);
    assert_eq!((report.first_seq(), report.last_seq()), (None, None));
    let mismatch = kinds(&report, K::TrailMismatch);
    assert_eq!(mismatch.len(), 1);
    assert_eq!(mismatch[0].file(), Some(file.as_path()));
    assert_eq!(mismatch[0].line(), Some(1));
    assert!(mismatch[0].detail().contains("expected trail"));
    let multi = TrustPolicy::builder()
        .trail(TRAIL)
        .trail([2; 16])
        .build()
        .unwrap();
    let report = Verifier::new(multi)
        .trail([2; 16])
        .unwrap()
        .verify_files([file])
        .unwrap();
    assert_eq!(report.trail(), [2; 16]);
    assert_eq!(kinds(&report, K::TrailMismatch).len(), 1);
    assert_eq!(report.records(), 0);
}
#[test]
fn missing_explicit_file_is_io_with_source() {
    let dir = Dir::new();
    let error = Verifier::new(policy())
        .verify_files([dir.0.join("missing")])
        .unwrap_err();
    assert_eq!(error.kind(), AuditErrorKind::Io);
    assert!(error.source().is_some());
}
#[test]
fn decoder_kinds_collect_and_attribute_then_check_following_valid_line() {
    let valid = entry();
    let cases = [
        ("not json".to_owned(), K::Unparsable),
        (
            valid.replace("\"intValue\":\"1\"", "\"intValue\":\"2\""),
            K::UnknownVersion,
        ),
        ("{}".to_owned(), K::MissingField),
        (
            "{\"resourceLogs\":[],\"unknown\":1}".to_owned(),
            K::UnknownField,
        ),
        ("{\"a\":1,\"a\":1}".to_owned(), K::InvalidField),
        (
            valid.replace("sample.modify", "sample.forged"),
            K::HashMismatch,
        ),
    ];
    let dir = Dir::new();
    for (index, (bad, kind)) in cases.into_iter().enumerate() {
        let file = dir.put(&format!("copy-{index}"), format!("{bad}\n{valid}\n"));
        let report = Verifier::new(policy())
            .verify_files([file.clone()])
            .unwrap();
        assert_eq!(report.records(), 1, "{kind:?}");
        assert_eq!(report.first_seq(), Some(0));
        let findings = kinds(&report, kind);
        assert_eq!(findings.len(), 1, "{kind:?}: {:?}", report.findings());
        assert_eq!(findings[0].file(), Some(file.as_path()));
        assert_eq!(findings[0].line(), Some(1));
        assert!(kinds(&report, K::SegmentStructure).is_empty());
    }
}
#[test]
fn display_only_changes_are_one_authenticated_record_and_one_warning() {
    let dir = Dir::new();
    let edited = entry().replace("\"version\":\"0.0.0\"", "\"version\":\"9.0.0\"");
    assert_ne!(entry(), edited);
    let file = dir.put("copy", format!("{}\n{edited}\n{edited}\n", entry()));
    let report = Verifier::new(policy()).verify_files([file]).unwrap();
    assert!(report.is_valid(), "{:?}", report.findings());
    assert_eq!(report.records(), 1);
    assert_eq!(kinds(&report, K::DuplicateRecord).len(), 1);
    assert!(kinds(&report, K::SeqConflict).is_empty());
}
#[test]
fn native_boundaries_cannot_be_repaired_by_shipped_checkpoint() {
    let dir = Dir::new();
    let native = dir.put("audit.jsonl", entry());
    let shipped = dir.put("copy", GOLDEN.lines().nth(1).unwrap());
    let report = Verifier::new(policy())
        .verify_files([shipped, native.clone()])
        .unwrap();
    let structure = kinds(&report, K::SegmentStructure);
    assert_eq!(structure.len(), 1);
    assert_eq!(structure[0].file(), Some(native.as_path()));
    assert_eq!(structure[0].run_digest(), None);
    let empty = dir.put("audit-20261102T010203.000000000Z.jsonl", "");
    let report = Verifier::new(policy()).verify_files([empty]).unwrap();
    assert_eq!(kinds(&report, K::SegmentStructure).len(), 1);
}
#[test]
fn oversized_line_is_one_finding_and_following_record_survives() {
    let dir = Dir::new();
    let file = dir.put("copy", format!("{}\n{}\n", "x".repeat(1_100_000), entry()));
    let report = Verifier::new(policy()).verify_files([file]).unwrap();
    assert_eq!(report.records(), 1);
    assert_eq!(kinds(&report, K::Unparsable).len(), 1);
}
#[test]
fn reversed_shipped_files_and_batches_have_same_findings_and_physical_lines() {
    let dir = Dir::new();
    let mut batch: serde_json::Value = serde_json::from_str(entry()).unwrap();
    let logs = batch["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
        .as_array_mut()
        .unwrap();
    logs.push(logs[0].clone());
    let a = dir.put("a", format!("!\n{batch}\n"));
    let b = dir.put("b", entry());
    let verifier = Verifier::new(policy());
    let forward = verifier.verify_files([a.clone(), b.clone()]).unwrap();
    let reverse = verifier.verify_files([b, a.clone()]).unwrap();
    assert_eq!(forward.findings(), reverse.findings());
    assert_eq!(forward.records(), 1);
    assert_eq!(kinds(&forward, K::DuplicateRecord).len(), 1);
    assert_eq!(kinds(&forward, K::DuplicateRecord)[0].line(), Some(2));
    let bad = kinds(&forward, K::Unparsable);
    assert_eq!(bad[0].file(), Some(a.as_path()));
    assert_eq!(bad[0].line(), Some(1));
    batch["resourceLogs"][0]["scopeLogs"][0]["logRecords"][1]["attributes"][0]["value"]["intValue"] =
        "2".into();
    let invalid = dir.put("invalid-batch", format!("!\n{batch}\n{}\n", entry()));
    let report = verifier.verify_files([invalid]).unwrap();
    assert_eq!(kinds(&report, K::UnknownVersion)[0].line(), Some(2));
    assert_eq!(report.records(), 1); // The valid member in the failed batch never leaks.
    assert_eq!(kinds(&report, K::DuplicateRecord).len(), 0);
}
