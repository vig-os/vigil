//! Offline verifier results. The engine and entry points follow in #13 V3.
use super::FindingKind;
use std::path::{Path, PathBuf};
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "consumed by the verifier engine, #13 V3a-2")
)]
mod input;
mod lines;

/// Severity of a finding produced by the offline verifier (#13).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Severity {
    /// Invalid history or evidence.
    Error,
    /// A condition requiring operator attention.
    Warning,
    /// Additional verification or review information.
    Info,
}

/// One diagnostic produced by the offline verifier (#13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    kind: FindingKind,
    file: Option<PathBuf>,
    line: Option<u64>,
    seq: Option<u64>,
    detail: String,
    accepted_kind: Option<FindingKind>,
    run_digest: Option<[u8; 32]>,
}
impl Finding {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "consumed by the verifier engine, #13 V3")
    )]
    pub(crate) fn new(
        kind: FindingKind,
        file: Option<PathBuf>,
        line: Option<u64>,
        seq: Option<u64>,
        detail: String,
    ) -> Self {
        Self {
            kind,
            file,
            line,
            seq,
            detail,
            accepted_kind: None,
            run_digest: None,
        }
    }
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "consumed by the verifier engine, #13 V3")
    )]
    pub(crate) fn accepted(mut self, kind: FindingKind) -> Self {
        assert_eq!(self.kind, FindingKind::Accepted);
        self.accepted_kind = Some(kind);
        self
    }
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "consumed by the verifier engine, #13 V3")
    )]
    pub(crate) fn with_run_digest(mut self, digest: [u8; 32]) -> Self {
        assert_eq!(self.kind, FindingKind::SegmentStructure);
        self.run_digest = Some(digest);
        self
    }
    /// Returns the diagnostic category.
    pub fn kind(&self) -> FindingKind {
        self.kind
    }
    /// Returns the severity assigned by ADR-0005 decision 11.
    pub fn severity(&self) -> Severity {
        severity(self.kind)
    }
    /// Returns the source file, when the finding concerns a file.
    pub fn file(&self) -> Option<&Path> {
        self.file.as_deref()
    }
    /// Returns the 1-based physical line number, when known.
    pub fn line(&self) -> Option<u64> {
        self.line
    }
    /// Returns the sequence number concerned, when known.
    pub fn seq(&self) -> Option<u64> {
        self.seq
    }
    /// Returns a diagnostic including expected and found values when applicable.
    pub fn detail(&self) -> &str {
        &self.detail
    }
    /// Returns the reviewed kind on an `Accepted` finding, and `None` otherwise.
    pub fn accepted_kind(&self) -> Option<FindingKind> {
        self.accepted_kind
    }
    /// Returns a run's digest on its `SegmentStructure` finding, and `None` otherwise.
    pub fn run_digest(&self) -> Option<[u8; 32]> {
        self.run_digest
    }
}

/// Results produced by the offline verifier (#13).
#[derive(Debug, Clone)]
pub struct Report {
    trail: [u8; 16],
    records: u64,
    first_seq: Option<u64>,
    last_seq: Option<u64>,
    covered_through: Option<u64>,
    findings: Vec<Finding>,
}
impl Report {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "consumed by the verifier engine, #13 V3")
    )]
    pub(crate) fn new(
        trail: [u8; 16],
        records: u64,
        first_seq: Option<u64>,
        last_seq: Option<u64>,
        covered_through: Option<u64>,
        findings: Vec<Finding>,
    ) -> Self {
        Self {
            trail,
            records,
            first_seq,
            last_seq,
            covered_through,
            findings,
        }
    }
    /// Returns the pinned trail identifier verified by this report.
    pub fn trail(&self) -> [u8; 16] {
        self.trail
    }
    /// Returns the number of verified records.
    pub fn records(&self) -> u64 {
        self.records
    }
    /// Returns the lowest verified sequence number, the start's when supplied.
    pub fn first_seq(&self) -> Option<u64> {
        self.first_seq
    }
    /// Returns the highest verified sequence number, or `None` for no records.
    pub fn last_seq(&self) -> Option<u64> {
        self.last_seq
    }
    /// Returns the highest sequence covered by a checkpoint signed with a trusted key.
    pub fn covered_through(&self) -> Option<u64> {
        self.covered_through
    }
    /// Returns all diagnostics collected during verification.
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }
    /// Returns true exactly when no finding has severity `Error`.
    pub fn is_valid(&self) -> bool {
        self.findings
            .iter()
            .all(|f| f.severity() != Severity::Error)
    }
}

fn severity(kind: FindingKind) -> Severity {
    use FindingKind::*;
    match kind {
        Unparsable
        | UnknownVersion
        | UnknownField
        | MissingField
        | InvalidField
        | HashMismatch
        | ChainBroken
        | SeqGap
        | SeqConflict
        | TrailMismatch
        | MmrMismatch
        | BadSignature
        | UntrustedKey
        | RevocationMismatch
        | RevocationUnconfirmed
        | SegmentStructure
        | AnchorMismatch
        | StartMismatch
        | UnanchoredStart
        | UnanchoredEnd
        | TrailEnded
        | StaleHead
        | NoReceipt
        | ReceiptMismatch
        | RepairMismatch
        | AcceptMismatch => Severity::Error,
        TornWrite | Resumed | ClockWentBackwards | DuplicateRecord => Severity::Warning,
        UncoveredTail | OutOfRange | Unreconciled | ReceiptWaived | TornWriteRepaired
        | Accepted | AcceptUnused | LostRecord => Severity::Info,
    }
}

#[cfg(test)]
mod mod_tests;
