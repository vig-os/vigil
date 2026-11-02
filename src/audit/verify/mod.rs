//! Offline collecting verifier and results (ADR-0005).
use super::{AuditError, AuditErrorKind, FindingKind, TrustPolicy};
use std::path::{Path, PathBuf};
mod engine;
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
    #[cfg_attr(not(test), expect(dead_code, reason = "review promotion, #13 V8"))]
    pub(crate) fn accepted(mut self, kind: FindingKind) -> Self {
        assert_eq!(self.kind, FindingKind::Accepted);
        self.accepted_kind = Some(kind);
        self
    }
    #[cfg_attr(not(test), expect(dead_code, reason = "run verification, #13 V4"))]
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

/// Verifies a directory using a cloned, validated trust policy.
///
/// **Incomplete (#13):** V3b supplies fragment/resume context and report
/// predicates; V4–V8/R10 supply folds, signatures, coverage, anchors, receipts,
/// review and archive rules. Native gaps are reported, never excused, until V5
/// supplies trusted coverage: a matching `audit.repaired` is a `TornWrite`, a
/// missing or different one is `RepairMismatch`, and a trailing gap is
/// `TornWrite` with the bytes-to-EOF digest. V5 then promotes a covered
/// `TornWrite` to `TornWriteRepaired`. No release from dev carries this
/// partial verifier before #13 through C1.
/// Open, or record once, before reviewing a crashed trail to settle staging.
/// Strict live review must target a stopped trail: an in-flight append can look
/// torn. Reads take no locks and offer per-directory snapshots, not global atomicity.
///
/// # Errors
/// Returns `Io` with its source for unreadable inputs or exhausted snapshot
/// retries, and `InvalidConfig` for ambiguous pins or duplicate native names.
/// Corruption is collected as findings.
///
/// ```no_run
/// use vigil::audit::{verify, TrustPolicy};
/// let trust = TrustPolicy::builder().trail([1; 16]).build()?;
/// let report = verify(std::path::Path::new("audit"), &trust)?;
/// assert_eq!(report.trail(), [1; 16]);
/// # Ok::<(), vigil::audit::AuditError>(())
/// ```
pub fn verify(dir: &Path, trust: &TrustPolicy) -> Result<Report, AuditError> {
    Verifier::new(trust.clone()).verify_dir(dir)
}

/// Collecting verifier with validated pins. See [`verify`] for staged #13
/// limitations and the settlement and stopped-trail review requirements.
#[derive(Debug, Clone)]
pub struct Verifier {
    trust: TrustPolicy,
    trail: Option<[u8; 16]>,
}
impl Verifier {
    /// Takes ownership of a validated policy. Multiple pins require [`Self::trail`].
    pub fn new(trust: TrustPolicy) -> Self {
        Self { trust, trail: None }
    }
    /// Narrows verification to a pinned trail, independently of input contents.
    ///
    /// # Errors
    /// Returns `InvalidConfig` immediately if the id is not pinned.
    pub fn trail(mut self, id: [u8; 16]) -> Result<Self, AuditError> {
        if !self.trust.pinned(&id) {
            return Err(AuditError::new(
                AuditErrorKind::InvalidConfig,
                "trail is not pinned",
            ));
        }
        self.trail = Some(id);
        Ok(self)
    }
    /// Expands a directory's vigil files and verifies its confirmed snapshot.
    /// See [`verify`] for review limitations and error semantics.
    ///
    /// # Errors
    /// Returns `Io` for read/retry failure or `InvalidConfig` for ambiguous input.
    pub fn verify_dir(&self, dir: &Path) -> Result<Report, AuditError> {
        self.verify_files([dir.to_owned()])
    }
    /// Verifies files or directories; arbitrary filenames are shipped copies
    /// merged by sequence, without native segment boundary semantics.
    /// Each inode is read once; native segments sort numerically, live last.
    /// See [`verify`] for staged limitations and per-directory snapshot scope.
    ///
    /// # Errors
    /// Returns `Io` with its source for unreadable explicit files or snapshot
    /// exhaustion, or `InvalidConfig` for ambiguous pins/duplicate native names.
    pub fn verify_files(
        &self,
        files: impl IntoIterator<Item = PathBuf>,
    ) -> Result<Report, AuditError> {
        let mut ids = self.trust.trail_ids();
        let trail = self
            .trail
            .or_else(|| {
                let first = *ids.next()?;
                ids.next().is_none().then_some(first)
            })
            .ok_or_else(|| {
                AuditError::new(AuditErrorKind::InvalidConfig, "select a pinned trail")
            })?;
        Ok(engine::check(input::collect(files)?, trail))
    }
}
