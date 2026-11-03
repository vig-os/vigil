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

#[test]
fn is_strict_valid_rejects_errors_warnings_uncovered_tail_and_unreconciled() {
    use FindingKind::*;
    // Pure info-only report with no UncoveredTail: strict valid.
    let r = Report::new([0; 16], 0, None, None, None, vec![finding(ReceiptWaived)]);
    assert!(r.is_strict_valid());
    // Any error: not strict valid.
    for k in [
        ChainBroken,
        SeqGap,
        HashMismatch,
        RepairMismatch,
        SegmentStructure,
        TrailMismatch,
    ] {
        let r = Report::new([0; 16], 0, None, None, None, vec![finding(k)]);
        assert!(!r.is_strict_valid(), "{k:?} should fail strict");
        assert!(!r.is_valid(), "{k:?} should fail is_valid too");
    }
    // Any warning: not strict valid.
    for k in [TornWrite, Resumed, ClockWentBackwards, DuplicateRecord] {
        let r = Report::new([0; 16], 0, None, None, None, vec![finding(k)]);
        assert!(!r.is_strict_valid(), "{k:?} should fail strict");
    }
    // UncoveredTail without exemption fails; with exemption passes.
    let r = Report::new([0; 16], 0, None, None, None, vec![finding(UncoveredTail)]);
    assert!(!r.is_strict_valid());
    assert!(r.clone().with_tail_exempt(true).is_strict_valid());
    // Unreconciled is never exempted.
    let r = Report::new([0; 16], 0, None, None, None, vec![finding(Unreconciled)])
        .with_tail_exempt(true);
    assert!(!r.is_strict_valid());
    // An Accepted info plus a surviving warning: still not strict.
    let r = Report::new(
        [0; 16],
        0,
        None,
        None,
        None,
        vec![finding(Accepted).accepted(TornWrite), finding(TornWrite)],
    );
    assert!(!r.is_strict_valid());
}

#[test]
fn first_broken_link_returns_first_error_in_ruled_order() {
    // #193: feed `engine::check` records plus a decoder-finding `LineItem`
    // whose natural emission order puts the higher-seq error first (file-
    // findings loop before chain loop). The engine's final `sort_by_key`
    // in `engine::check` is what moves the lower-seq ChainBroken to the
    // front, so `first_broken_link()` returns the seq-0 one. The in-test
    // sort has been dropped (#193); disabling the engine's sort makes
    // this test fail by returning the seq-10 InvalidField instead.
    use crate::audit::AuditError;
    use crate::audit::verify::input::{Collection, Data, Input, LineContent, LineItem, Summary};
    use std::rc::Rc;
    const TRAIL: [u8; 16] = [0x11; 16];
    fn located(seq: u64, hash: u8, previous: [u8; 32]) -> Summary {
        Summary {
            trail: TRAIL,
            seq,
            hash: [hash; 32],
            previous,
            time: seq,
            repaired: None,
            checkpoint: None,
            operator: None,
            line: seq + 1,
        }
    }
    // The chain loop emits one ChainBroken for the seq-0 record (its
    // `previous` is not genesis). The file-findings loop emits an
    // InvalidField at line 11, carrying seq=10 via `AuditError::with_seq`.
    // Natural insertion is [InvalidField(seq=10), ChainBroken(seq=0), …];
    // the engine's final sort reorders them by seq.
    let broken_record = located(0, 1, [8; 32]);
    let seq10_error = AuditError::decoding(
        crate::audit::AuditErrorKind::CorruptTrail,
        FindingKind::InvalidField,
    )
    .with_seq(10);
    let items = vec![
        LineItem {
            line: 11,
            content: LineContent::Invalid(seq10_error),
        },
        LineItem {
            line: 1,
            content: LineContent::Records(0..1),
        },
    ];
    let input = Input {
        path: PathBuf::from("copy"),
        native: false,
        data: Rc::new(Data {
            records: vec![broken_record],
            items,
            spans: vec![],
        }),
    };
    let collection = Collection {
        inputs: vec![input],
        shipped: vec![(0, 0)],
    };
    let report = super::engine::check(collection, TRAIL);
    // Confirm both error findings are present before asserting the order.
    let errors: Vec<_> = report
        .findings()
        .iter()
        .filter(|f| f.severity() == Severity::Error)
        .collect();
    assert!(
        errors
            .iter()
            .any(|f| f.kind() == FindingKind::ChainBroken && f.seq() == Some(0)),
        "{:?}",
        report.findings()
    );
    assert!(
        errors
            .iter()
            .any(|f| f.kind() == FindingKind::InvalidField && f.seq() == Some(10)),
        "{:?}",
        report.findings()
    );
    // Engine's `findings.sort_by_key` moves seq-0 to the front; the
    // predicate reports that one.
    let bl = report.first_broken_link().unwrap();
    assert_eq!(bl.kind(), FindingKind::ChainBroken);
    assert_eq!(
        bl.seq(),
        Some(0),
        "first_broken_link must return seq-0 ChainBroken after engine::check's sort"
    );
    // Warnings and infos are ignored.
    use FindingKind::*;
    let r = Report::new(
        [0; 16],
        0,
        None,
        None,
        None,
        vec![finding(TornWrite), finding(UncoveredTail), finding(Resumed)],
    );
    assert!(r.first_broken_link().is_none());
    // Every error kind qualifies: SegmentStructure, SeqConflict, etc.
    for k in [SegmentStructure, SeqConflict, RepairMismatch, TrailMismatch] {
        let r = Report::new([0; 16], 0, None, None, None, vec![finding(k)]);
        assert_eq!(r.first_broken_link().unwrap().kind(), k);
    }
}
