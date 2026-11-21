//! Shared `#[cfg(test)]` helpers for the reconciliation rows
//! (ruling 13-V7-d1 points 2-6). One copy of `located`, `unlocated`,
//! `assert_findings`, `trust_with_key`, `report_of` and `parse_cp`
//! for both `receipts_tests` and `waivers_tests`.

use super::{Finding, Report, Verifier};
use crate::audit::{Checkpoint, FindingKind as K, Record, TrustPolicy, runs_v4a_fixtures::TRAIL};
use std::path::PathBuf;

pub(super) fn located(kind: K, file: PathBuf, line: u64, seq: u64, detail: String) -> Finding {
    Finding::new(kind, Some(file), Some(line), Some(seq), detail)
}
pub(super) fn unlocated(kind: K, seq: Option<u64>, detail: String) -> Finding {
    Finding::new(kind, None, None, seq, detail)
}
#[track_caller]
pub(super) fn assert_findings(actual: &[Finding], expected: &[Finding], label: &str) {
    assert_eq!(actual, expected, "{label} literal finding list");
}
pub(super) fn trust_with_key(key: [u8; 32]) -> TrustPolicy {
    TrustPolicy::builder()
        .trail(TRAIL)
        .key(key)
        .build()
        .unwrap()
}
pub(super) fn report_of(files: Vec<PathBuf>, verifier: Verifier) -> Report {
    verifier.verify_files(files).unwrap()
}
pub(super) fn parse_cp(record: &Record) -> Checkpoint {
    let mut bytes = crate::audit::runs_v4a_fixtures::line_bytes(record);
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    Checkpoint::parse(std::str::from_utf8(&bytes).unwrap()).unwrap()
}
