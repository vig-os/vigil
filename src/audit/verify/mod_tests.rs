use super::*;
fn finding(kind: FindingKind) -> Finding {
    Finding::new(
        kind,
        Some(PathBuf::from("trail")),
        Some(2),
        Some(3),
        "expected versus found".into(),
    )
}
#[test]
fn report_and_finding_accessors() {
    let f = finding(FindingKind::TornWrite);
    assert_eq!(f.kind(), FindingKind::TornWrite);
    assert_eq!(f.file(), Some(Path::new("trail")));
    assert_eq!(f.line(), Some(2));
    assert_eq!(f.seq(), Some(3));
    assert_eq!(f.detail(), "expected versus found");
    assert_eq!(f.accepted_kind(), None);
    assert_eq!(f.run_digest(), None);
    let f = finding(FindingKind::Accepted).accepted(FindingKind::TornWrite);
    assert_eq!(f.accepted_kind(), Some(FindingKind::TornWrite));
    assert_eq!(f.run_digest(), None);
    let f = finding(FindingKind::SegmentStructure).with_run_digest([7; 32]);
    assert_eq!(f.run_digest(), Some([7; 32]));
    assert_eq!(f.accepted_kind(), None);
    let r = Report::new([1; 16], 2, Some(3), Some(4), Some(3), vec![]);
    assert_eq!(r.trail(), [1; 16]);
    assert_eq!(r.records(), 2);
    assert_eq!(r.first_seq(), Some(3));
    assert_eq!(r.last_seq(), Some(4));
    assert_eq!(r.covered_through(), Some(3));
    assert!(r.findings().is_empty());
    assert!(r.is_valid());
    let empty = Report::new([1; 16], 0, None, None, None, vec![]);
    assert_eq!(
        (empty.first_seq(), empty.last_seq(), empty.covered_through()),
        (None, None, None)
    );
}
#[test]
#[should_panic]
fn accepted_requires_correct_kind() {
    finding(FindingKind::TornWrite).accepted(FindingKind::TornWrite);
}
#[test]
#[should_panic]
fn run_digest_requires_correct_kind() {
    finding(FindingKind::TornWrite).with_run_digest([0; 32]);
}
#[test]
fn trait_contracts() {
    fn scalar<T: Copy + Eq + std::fmt::Debug + Send + Sync>() {}
    fn threads<T: Send + Sync>() {}
    scalar::<Severity>();
    scalar::<FindingKind>();
    threads::<Finding>();
    threads::<Report>();
}

#[test]
fn adr_severity_table_and_validity() {
    use FindingKind::*;
    let groups: &[(Severity, &[FindingKind])] = &[
        (
            Severity::Error,
            &[
                Unparsable,
                UnknownVersion,
                UnknownField,
                MissingField,
                InvalidField,
                HashMismatch,
                ChainBroken,
                SeqGap,
                SeqConflict,
                TrailMismatch,
                MmrMismatch,
                BadSignature,
                UntrustedKey,
                RevocationMismatch,
                RevocationUnconfirmed,
                SegmentStructure,
                AnchorMismatch,
                StartMismatch,
                UnanchoredStart,
                UnanchoredEnd,
                TrailEnded,
                StaleHead,
                NoReceipt,
                ReceiptMismatch,
                RepairMismatch,
                AcceptMismatch,
            ],
        ),
        (
            Severity::Warning,
            &[TornWrite, Resumed, ClockWentBackwards, DuplicateRecord],
        ),
        (
            Severity::Info,
            &[
                UncoveredTail,
                OutOfRange,
                Unreconciled,
                ReceiptWaived,
                TornWriteRepaired,
                Accepted,
                AcceptUnused,
                LostRecord,
            ],
        ),
    ];
    for (severity, kinds) in groups {
        for &kind in *kinds {
            let f = finding(kind);
            assert_eq!(f.severity(), *severity, "{kind:?}");
            assert_eq!(f.accepted_kind(), None);
            assert_eq!(f.run_digest(), None);
            let r = Report::new(
                [0; 16],
                0,
                None,
                None,
                None,
                vec![finding(FindingKind::Accepted), f],
            );
            assert_eq!(r.is_valid(), *severity != Severity::Error);
        }
    }
}
