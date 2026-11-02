use super::*;
use crate::audit::verify::input::{Data, Input, LineItem};
use std::{path::PathBuf, rc::Rc};
const TRAIL: [u8; 16] = [1; 16];
fn record(seq: u64, hash: u8, previous: [u8; 32], time: u64) -> Summary {
    Summary {
        trail: TRAIL,
        seq,
        hash: [hash; 32],
        previous,
        time,
        repaired: None,
        checkpoint: None,
        operator: None,
        line: seq.saturating_add(1),
    }
}
fn run(records: Vec<Summary>) -> Report {
    check(
        Collection {
            shipped: (0..records.len()).map(|r| (0, r)).collect(),
            inputs: vec![Input {
                path: PathBuf::from("shipped"),
                native: false,
                data: Rc::new(Data {
                    records,
                    items: vec![],
                    spans: vec![],
                }),
            }],
        },
        TRAIL,
    )
}
fn kinds(report: &Report, kind: K) -> Vec<&Finding> {
    report
        .findings()
        .iter()
        .filter(|f| f.kind() == kind)
        .collect()
}
#[test]
fn genesis_and_every_later_error_are_collected() {
    let report = run(vec![
        record(0, 1, [9; 32], 10),
        record(2, 2, [1; 32], 9),
        record(3, 3, [8; 32], 8),
    ]);
    assert_eq!(kinds(&report, K::ChainBroken).len(), 2);
    assert_eq!(kinds(&report, K::SeqGap)[0].detail(), "missing seq 1..=1");
    assert_eq!(kinds(&report, K::ClockWentBackwards).len(), 2);
    for finding in kinds(&report, K::ChainBroken) {
        assert!(finding.detail().contains("expected previous blake3:"));
        assert!(finding.detail().contains("found blake3:"));
        assert_eq!(finding.file(), Some(Path::new("shipped")));
    }
}
#[test]
fn missing_prefix_does_not_hide_later_forgery() {
    let report = run(vec![record(3, 3, [1; 32], 1), record(4, 4, [8; 32], 2)]);
    assert_eq!(kinds(&report, K::SeqGap)[0].detail(), "missing seq 0..=2");
    assert_eq!(kinds(&report, K::ChainBroken).len(), 1);
}
#[test]
fn conflicts_check_all_candidates_and_link_through_either() {
    for successor in [2, 3] {
        let report = run(vec![
            record(0, 1, Record::genesis(&TRAIL), 10),
            record(1, 2, [1; 32], 9),
            record(1, 3, [8; 32], 8),
            record(2, 4, [successor; 32], 1),
        ]);
        assert_eq!(report.records(), 4);
        let broken = kinds(&report, K::ChainBroken);
        assert_eq!(broken.len(), 1); // The second conflicting candidate is checked.
        assert_eq!(broken[0].seq(), Some(1));
        let conflicts = kinds(&report, K::SeqConflict);
        assert_eq!(conflicts.len(), 1);
        for hash in [2, 3] {
            assert!(conflicts[0].detail().contains(&digest_string(&[hash; 32])));
        }
        assert!(kinds(&report, K::ClockWentBackwards).is_empty());
    }
}
#[test]
fn duplicates_warn_once_even_with_repeated_conflicting_candidates() {
    let report = run(vec![
        record(0, 1, Record::genesis(&TRAIL), 10),
        record(1, 2, [1; 32], 9),
        record(1, 2, [1; 32], 9),
        record(1, 2, [1; 32], 9),
        record(1, 3, [1; 32], 8),
        record(1, 3, [1; 32], 8),
    ]);
    assert_eq!(report.records(), 3);
    assert_eq!(kinds(&report, K::DuplicateRecord).len(), 1);
    assert_eq!(kinds(&report, K::SeqConflict).len(), 1);
    assert!(kinds(&report, K::ClockWentBackwards).is_empty());
}
#[test]
fn foreign_trail_never_advances_head() {
    let mut foreign = record(1, 2, [1; 32], 2);
    foreign.trail = [2; 16];
    let report = run(vec![
        record(0, 1, Record::genesis(&TRAIL), 1),
        foreign,
        record(2, 3, [2; 32], 3),
    ]);
    assert_eq!(report.trail(), TRAIL);
    assert_eq!(report.records(), 2);
    assert_eq!(kinds(&report, K::TrailMismatch).len(), 1);
    assert_eq!(kinds(&report, K::SeqGap).len(), 1);
}
#[test]
fn absent_resume_head_has_no_invented_clock_comparison_and_max_does_not_overflow() {
    let report = run(vec![record(u64::MAX, 1, [0; 32], 0)]);
    assert_eq!(report.last_seq(), Some(u64::MAX));
    assert_eq!(kinds(&report, K::SeqGap).len(), 1);
    assert!(kinds(&report, K::ClockWentBackwards).is_empty());
}
#[test]
fn duplicate_does_not_advance_clock() {
    let report = run(vec![
        record(0, 1, Record::genesis(&TRAIL), 10),
        record(0, 1, Record::genesis(&TRAIL), 10),
        record(1, 2, [1; 32], 9),
    ]);
    assert_eq!(kinds(&report, K::ClockWentBackwards).len(), 1);
    assert_eq!(kinds(&report, K::DuplicateRecord).len(), 1);
}
#[test]
fn ordering_is_seq_then_path_line_kind_with_unlocated_seq_last() {
    let error = || {
        crate::audit::AuditError::decoding(
            crate::audit::AuditErrorKind::CorruptTrail,
            K::InvalidField,
        )
    };
    let mut collection = Collection {
        inputs: vec![],
        shipped: vec![],
    };
    for name in ["z", "a"] {
        collection.inputs.push(Input {
            path: name.into(),
            native: false,
            data: Rc::new(Data {
                records: vec![record(0, 1, [9; 32], 0)],
                items: vec![
                    LineItem {
                        bytes: 0..1,
                        line: 2,
                        content: LineContent::Invalid(error()),
                    },
                    LineItem {
                        bytes: 1..2,
                        line: 1,
                        content: LineContent::Invalid(error()),
                    },
                ],
                spans: vec![],
            }),
        });
    }
    collection.shipped = vec![(0, 0), (1, 0)];
    let report = check(collection, TRAIL);
    let found: Vec<_> = report
        .findings()
        .iter()
        .map(|f| {
            (
                f.seq(),
                f.file().unwrap().to_str().unwrap(),
                f.line(),
                f.kind(),
            )
        })
        .collect();
    assert_eq!(
        found,
        vec![
            (Some(0), "a", Some(1), K::ChainBroken),
            (Some(0), "a", Some(1), K::DuplicateRecord),
            (None, "a", Some(1), K::InvalidField),
            (None, "a", Some(2), K::InvalidField),
            (None, "z", Some(1), K::InvalidField),
            (None, "z", Some(2), K::InvalidField)
        ]
    );
    assert_eq!(
        report
            .findings()
            .iter()
            .find(|f| f.severity() == super::super::Severity::Error)
            .unwrap()
            .kind(),
        K::ChainBroken
    );
}
