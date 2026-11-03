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
                        line: 2,
                        content: LineContent::Invalid(error()),
                    },
                    LineItem {
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
        .filter(|f| f.kind() != K::UncoveredTail)
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
    assert_eq!(report.first_broken_link().unwrap().kind(), K::ChainBroken);
}

/// Helpers for building synthetic native inputs with specific item sequences.
mod ctx {
    use super::*;
    use crate::audit::verify::input::{LineContent, Summary};
    use crate::audit::{CheckpointFields, Record};
    use std::ops::Range;
    pub(super) fn checkpoint(seq: u64, hash: u8, previous: [u8; 32]) -> Summary {
        let fields = CheckpointFields::new(0, [0; 32], vec![], [1; 32], [0; 64]).unwrap();
        Summary {
            trail: TRAIL,
            seq,
            hash: [hash; 32],
            previous,
            time: seq,
            repaired: None,
            checkpoint: Some(fields),
            operator: None,
            line: seq + 1,
        }
    }
    pub(super) fn resume_record(seq: u64, hash: u8, previous: [u8; 32], details: &str) -> Summary {
        Summary {
            trail: TRAIL,
            seq,
            hash: [hash; 32],
            previous,
            time: seq,
            repaired: None,
            checkpoint: None,
            operator: Some((
                "vigil.audit.resume".into(),
                "operator".into(),
                Some("reviewed".into()),
                Some(details.into()),
            )),
            line: seq + 1,
        }
    }
    pub(super) fn item_records(range: Range<usize>, line: u64) -> LineItem {
        LineItem {
            line,
            content: LineContent::Records(range),
        }
    }
    pub(super) fn fragment(line: u64) -> LineItem {
        LineItem {
            line,
            content: LineContent::Fragment,
        }
    }
    pub(super) fn invalid(line: u64) -> LineItem {
        LineItem {
            line,
            content: LineContent::Invalid(AuditError::decoding(
                crate::audit::AuditErrorKind::CorruptTrail,
                K::InvalidField,
            )),
        }
    }
    pub(super) fn native_input(
        path: &str,
        records: Vec<Summary>,
        items: Vec<LineItem>,
        spans: Vec<crate::audit::verify::lines::Span>,
    ) -> Input {
        Input {
            path: path.into(),
            native: true,
            data: Rc::new(Data {
                records,
                items,
                spans,
            }),
        }
    }
    pub(super) fn span(len: u64, digest: [u8; 32]) -> crate::audit::verify::lines::Span {
        crate::audit::verify::lines::Span {
            seg: 0,
            after: 0,
            len,
            digest,
        }
    }
    use crate::audit::AuditError;
    pub(super) const GENESIS: fn() -> [u8; 32] = || Record::genesis(&TRAIL);
}

#[test]
fn fragment_run_after_mismatch_is_unparsable_without_splitting_the_gap() {
    use ctx::*;
    // Records(1 line) -> Fragment -> Records (prev mismatch): condition 3 fails.
    let records = vec![
        checkpoint(0, 1, GENESIS()),
        record(1, 2, [9; 32], 1), // "after" record whose previous != checkpoint hash
    ];
    let items = vec![item_records(0..1, 1), fragment(2), item_records(1..2, 3)];
    let spans = vec![span(5, [0xaa; 32])];
    let input = native_input("audit.jsonl", records, items, spans);
    let collection = Collection {
        inputs: vec![input],
        shipped: vec![],
    };
    let report = check(collection, TRAIL);
    let unparsable = kinds(&report, K::Unparsable);
    assert_eq!(unparsable.len(), 1, "{:?}", report.findings());
    assert_eq!(unparsable[0].line(), Some(2));
    assert_eq!(unparsable[0].detail(), "fragment line failed context");
    // The gap-byte finding stays: span length unchanged (5 bytes), one gap.
    let gap = kinds(&report, K::RepairMismatch);
    assert_eq!(gap.len(), 1);
    assert!(gap[0].detail().contains("(5 bytes)"));
}

#[test]
fn consecutive_crashes_pass_condition_3_and_emit_no_unparsable() {
    use ctx::*;
    // Two fragments followed by a linking record: condition 3 holds for the run.
    let before = checkpoint(0, 1, GENESIS());
    let after = Summary {
        repaired: Some([7; 32]),
        ..record(1, 2, before.hash, 1)
    };
    let records = vec![before, after];
    let items = vec![
        item_records(0..1, 1),
        fragment(2),
        fragment(3),
        item_records(1..2, 4),
    ];
    let spans = vec![span(3, [7; 32])];
    let input = native_input("audit.jsonl", records, items, spans);
    let report = check(
        Collection {
            inputs: vec![input],
            shipped: vec![],
        },
        TRAIL,
    );
    assert!(
        kinds(&report, K::Unparsable).is_empty(),
        "{:?}",
        report.findings()
    );
    // The gap is a single TornWrite finding attested by the repair.
    let tw = kinds(&report, K::TornWrite);
    assert_eq!(tw.len(), 1);
    assert!(tw[0].detail().contains("lines 2..=3"));
}

#[test]
fn file_start_fragment_run_is_unparsable_plus_v3a2_gap() {
    use ctx::*;
    let after = record(0, 1, GENESIS(), 1);
    let records = vec![after];
    let items = vec![fragment(1), item_records(0..1, 2)];
    let spans = vec![span(4, [0; 32])];
    let input = native_input("audit.jsonl", records, items, spans);
    let report = check(
        Collection {
            inputs: vec![input],
            shipped: vec![],
        },
        TRAIL,
    );
    let unparsable = kinds(&report, K::Unparsable);
    assert_eq!(unparsable.len(), 1);
    assert_eq!(unparsable[0].line(), Some(1));
    assert_eq!(unparsable[0].detail(), "fragment line failed context");
    assert_eq!(kinds(&report, K::RepairMismatch).len(), 1);
}

#[test]
fn fragment_run_followed_by_invalid_line_is_unparsable() {
    use ctx::*;
    let before = checkpoint(0, 1, GENESIS());
    let items = vec![item_records(0..1, 1), fragment(2), invalid(3)];
    let spans = vec![span(2, [0; 32])];
    let input = native_input("audit.jsonl", vec![before], items, spans);
    let report = check(
        Collection {
            inputs: vec![input],
            shipped: vec![],
        },
        TRAIL,
    );
    let unparsable = kinds(&report, K::Unparsable)
        .into_iter()
        .filter(|f| f.detail() == "fragment line failed context")
        .collect::<Vec<_>>();
    assert_eq!(unparsable.len(), 1);
    assert_eq!(unparsable[0].line(), Some(2));
    // Gap still closes at the invalid line as a RepairMismatch.
    assert_eq!(kinds(&report, K::RepairMismatch).len(), 1);
}

#[test]
fn resume_at_genesis_with_no_opening_marks_structural_invalid_and_strict_fails() {
    // V3b-2 (ruling 13-V3-d5): with `L=0` and head=(0, genesis), `k=L+1=1`
    // and the record at seq 1 is the resume itself (not a checkpoint), so
    // S1a fails and the detail ends with `structural=invalid(no-opening)`.
    // The gap text is the fixed genesis form `gap=0..=0` (d5 point 3), not
    // the base's `gap=none`.
    use ctx::*;
    let g = GENESIS();
    let open = checkpoint(0, 1, g);
    let resume_text = format!(
        "head=0:{} lost_through=0 file=sealed.jsonl",
        digest_string(&g)
    );
    let r = resume_record(1, 2, open.hash, &resume_text);
    let report = check(
        Collection {
            inputs: vec![Input {
                path: "audit.jsonl".into(),
                native: true,
                data: Rc::new(Data {
                    records: vec![open, r],
                    items: vec![],
                    spans: vec![],
                }),
            }],
            shipped: vec![],
        },
        TRAIL,
    );
    let resumed = kinds(&report, K::Resumed);
    assert_eq!(resumed.len(), 1);
    assert!(
        resumed[0]
            .detail()
            .contains("gap=0..=0 lost_records=0 structural=invalid(no-opening)"),
        "{}",
        resumed[0].detail()
    );
    assert_eq!(resumed[0].seq(), Some(1));
    assert!(!report.is_strict_valid());
    assert!(report.is_valid());
}

#[test]
fn malformed_resume_declaration_emits_resumed_and_keeps_seq_gap() {
    use ctx::*;
    let g = GENESIS();
    let open = checkpoint(5, 1, [8; 32]);
    let r = resume_record(6, 2, open.hash, "head=garbage file=x");
    let _ = g;
    let report = check(
        Collection {
            inputs: vec![],
            shipped: vec![(0, 0), (0, 1)],
        }
        .pipe(|mut c| {
            c.inputs.push(Input {
                path: "audit.jsonl".into(),
                native: true,
                data: Rc::new(Data {
                    records: vec![open, r],
                    items: vec![],
                    spans: vec![],
                }),
            });
            c
        }),
        TRAIL,
    );
    let resumed = kinds(&report, K::Resumed);
    assert_eq!(resumed.len(), 1);
    assert_eq!(resumed[0].detail(), "malformed declaration");
    // SeqGap for missing 0..=4 stays.
    assert_eq!(kinds(&report, K::SeqGap).len(), 1);
}

trait Pipe: Sized {
    fn pipe<R>(self, f: impl FnOnce(Self) -> R) -> R {
        f(self)
    }
}
impl<T> Pipe for T {}

#[test]
fn resume_in_native_and_shipped_emits_once_on_native() {
    use ctx::*;
    let g = GENESIS();
    let open = checkpoint(0, 1, g);
    let resume_text = format!("head=0:{} lost_through=0 file=-", digest_string(&g));
    let r = resume_record(1, 2, open.hash, &resume_text);
    let open2 = checkpoint(0, 1, g);
    let r2 = resume_record(1, 2, open.hash, &resume_text);
    let native_input = Input {
        path: "audit.jsonl".into(),
        native: true,
        data: Rc::new(Data {
            records: vec![open, r],
            items: vec![],
            spans: vec![],
        }),
    };
    let shipped_input = Input {
        path: "copy".into(),
        native: false,
        data: Rc::new(Data {
            records: vec![open2, r2],
            items: vec![],
            spans: vec![],
        }),
    };
    let collection = Collection {
        inputs: vec![native_input, shipped_input],
        shipped: vec![(1, 0), (1, 1)],
    };
    let report = check(collection, TRAIL);
    let resumed = kinds(&report, K::Resumed);
    assert_eq!(resumed.len(), 1, "{:?}", report.findings());
    assert_eq!(resumed[0].file(), Some(Path::new("audit.jsonl")));
}

#[test]
fn uncovered_tail_spans_first_through_last_for_non_empty_trail_only() {
    let g = Record::genesis(&TRAIL);
    let report = run(vec![record(0, 1, g, 1), record(1, 2, [1; 32], 2)]);
    let tails = kinds(&report, K::UncoveredTail);
    assert_eq!(tails.len(), 1);
    assert!(tails[0].detail().contains("records seq 0..=1"));
    assert!(
        tails[0]
            .detail()
            .contains("signatures are checked in #13 V5")
    );
    assert!(report.is_valid());
    assert!(!report.is_strict_valid());
    // Empty trail: no UncoveredTail.
    let empty = run(vec![]);
    assert!(kinds(&empty, K::UncoveredTail).is_empty());
}

#[test]
fn no_crash_mark_appends_when_successor_opens_without_resume() {
    use ctx::*;
    // Current file: closing checkpoint seq=5, then a trailing fragment.
    let closing = checkpoint(5, 7, [6; 32]);
    let closing_hash = closing.hash;
    let current = Input {
        path: "audit-0.jsonl".into(),
        native: true,
        data: Rc::new(Data {
            records: vec![closing],
            items: vec![item_records(0..1, 1), fragment(2)],
            spans: vec![span(4, [1; 32])],
        }),
    };
    // Successor native starts with an opening checkpoint seq=6 whose `previous`
    // is the real closing hash, no resume at second position.
    let opening = checkpoint(6, 8, closing_hash);
    let next_record = record(7, 9, opening.hash, 7);
    let successor = Input {
        path: "audit.jsonl".into(),
        native: true,
        data: Rc::new(Data {
            records: vec![opening, next_record],
            items: vec![item_records(0..1, 1), item_records(1..2, 2)],
            spans: vec![],
        }),
    };
    let report = check(
        Collection {
            inputs: vec![current, successor],
            shipped: vec![],
        },
        TRAIL,
    );
    let tw = kinds(&report, K::TornWrite);
    assert_eq!(tw.len(), 1, "{:?}", report.findings());
    assert!(tw[0].detail().contains("; no crash outcome"));
}

#[test]
fn no_crash_mark_absent_when_archive_last_record_is_not_a_checkpoint() {
    use ctx::*;
    // The archive's last complete record is a plain record (not a closing
    // checkpoint); the trailing fragment remains, but ADR condition 1 fails.
    let last = record(5, 7, [6; 32], 5);
    let last_hash = last.hash;
    let current = Input {
        path: "audit-0.jsonl".into(),
        native: true,
        data: Rc::new(Data {
            records: vec![last],
            items: vec![item_records(0..1, 1), fragment(2)],
            spans: vec![span(4, [1; 32])],
        }),
    };
    let opening = checkpoint(6, 8, last_hash);
    let successor = Input {
        path: "audit.jsonl".into(),
        native: true,
        data: Rc::new(Data {
            records: vec![opening],
            items: vec![item_records(0..1, 1)],
            spans: vec![],
        }),
    };
    let report = check(
        Collection {
            inputs: vec![current, successor],
            shipped: vec![],
        },
        TRAIL,
    );
    let tw: Vec<_> = kinds(&report, K::TornWrite)
        .into_iter()
        .filter(|f| f.file() == Some(Path::new("audit-0.jsonl")))
        .collect();
    assert_eq!(tw.len(), 1, "{:?}", report.findings());
    assert!(!tw[0].detail().contains("no crash outcome"));
}

#[test]
fn no_crash_mark_absent_when_opening_does_not_link_to_closing() {
    use ctx::*;
    // Opening's `previous` differs from the closing's hash: ADR link fails.
    let closing = checkpoint(5, 7, [6; 32]);
    let current = Input {
        path: "audit-0.jsonl".into(),
        native: true,
        data: Rc::new(Data {
            records: vec![closing],
            items: vec![item_records(0..1, 1), fragment(2)],
            spans: vec![span(4, [1; 32])],
        }),
    };
    // `[9; 32]` is not the closing's hash (`[7; 32]`).
    let opening = checkpoint(6, 8, [9; 32]);
    let successor = Input {
        path: "audit.jsonl".into(),
        native: true,
        data: Rc::new(Data {
            records: vec![opening],
            items: vec![item_records(0..1, 1)],
            spans: vec![],
        }),
    };
    let report = check(
        Collection {
            inputs: vec![current, successor],
            shipped: vec![],
        },
        TRAIL,
    );
    let tw: Vec<_> = kinds(&report, K::TornWrite)
        .into_iter()
        .filter(|f| f.file() == Some(Path::new("audit-0.jsonl")))
        .collect();
    assert_eq!(tw.len(), 1, "{:?}", report.findings());
    assert!(!tw[0].detail().contains("no crash outcome"));
}

#[test]
fn no_crash_mark_absent_when_opening_seq_is_not_closing_plus_one() {
    use ctx::*;
    let closing = checkpoint(5, 7, [6; 32]);
    let closing_hash = closing.hash;
    let current = Input {
        path: "audit-0.jsonl".into(),
        native: true,
        data: Rc::new(Data {
            records: vec![closing],
            items: vec![item_records(0..1, 1), fragment(2)],
            spans: vec![span(4, [1; 32])],
        }),
    };
    // Opening seq is 7, not closing.seq + 1 == 6.
    let opening = checkpoint(7, 8, closing_hash);
    let successor = Input {
        path: "audit.jsonl".into(),
        native: true,
        data: Rc::new(Data {
            records: vec![opening],
            items: vec![item_records(0..1, 1)],
            spans: vec![],
        }),
    };
    let report = check(
        Collection {
            inputs: vec![current, successor],
            shipped: vec![],
        },
        TRAIL,
    );
    let tw: Vec<_> = kinds(&report, K::TornWrite)
        .into_iter()
        .filter(|f| f.file() == Some(Path::new("audit-0.jsonl")))
        .collect();
    assert_eq!(tw.len(), 1, "{:?}", report.findings());
    assert!(!tw[0].detail().contains("no crash outcome"));
}

#[test]
fn no_crash_mark_absent_when_successor_first_record_is_not_a_checkpoint() {
    use ctx::*;
    let closing = checkpoint(5, 7, [6; 32]);
    let closing_hash = closing.hash;
    let current = Input {
        path: "audit-0.jsonl".into(),
        native: true,
        data: Rc::new(Data {
            records: vec![closing],
            items: vec![item_records(0..1, 1), fragment(2)],
            spans: vec![span(4, [1; 32])],
        }),
    };
    // First complete record of the successor is a plain record, not a checkpoint.
    let opening = record(6, 8, closing_hash, 6);
    let successor = Input {
        path: "audit.jsonl".into(),
        native: true,
        data: Rc::new(Data {
            records: vec![opening],
            items: vec![item_records(0..1, 1)],
            spans: vec![],
        }),
    };
    let report = check(
        Collection {
            inputs: vec![current, successor],
            shipped: vec![],
        },
        TRAIL,
    );
    let tw: Vec<_> = kinds(&report, K::TornWrite)
        .into_iter()
        .filter(|f| f.file() == Some(Path::new("audit-0.jsonl")))
        .collect();
    assert_eq!(tw.len(), 1, "{:?}", report.findings());
    assert!(!tw[0].detail().contains("no crash outcome"));
}

#[test]
fn no_crash_mark_absent_when_successor_second_record_is_resume() {
    use ctx::*;
    let closing = checkpoint(5, 7, [6; 32]);
    let current = Input {
        path: "audit-0.jsonl".into(),
        native: true,
        data: Rc::new(Data {
            records: vec![closing],
            items: vec![item_records(0..1, 1), fragment(2)],
            spans: vec![span(4, [1; 32])],
        }),
    };
    let opening = checkpoint(6, 8, [7; 32]);
    let r = resume_record(
        7,
        9,
        opening.hash,
        "head=5:blake3:0000 lost_through=5 file=-",
    );
    let successor = Input {
        path: "audit.jsonl".into(),
        native: true,
        data: Rc::new(Data {
            records: vec![opening, r],
            items: vec![item_records(0..1, 1), item_records(1..2, 2)],
            spans: vec![],
        }),
    };
    let report = check(
        Collection {
            inputs: vec![current, successor],
            shipped: vec![],
        },
        TRAIL,
    );
    let tw = kinds(&report, K::TornWrite);
    assert_eq!(tw.len(), 1);
    assert!(!tw[0].detail().contains("no crash outcome"));
}

#[test]
fn no_crash_mark_absent_for_archive_verified_alone() {
    use ctx::*;
    let closing = checkpoint(5, 7, [6; 32]);
    let input = Input {
        path: "audit-0.jsonl".into(),
        native: true,
        data: Rc::new(Data {
            records: vec![closing],
            items: vec![item_records(0..1, 1), fragment(2)],
            spans: vec![span(4, [1; 32])],
        }),
    };
    let report = check(
        Collection {
            inputs: vec![input],
            shipped: vec![],
        },
        TRAIL,
    );
    let tw = kinds(&report, K::TornWrite);
    assert_eq!(tw.len(), 1);
    assert!(!tw[0].detail().contains("no crash outcome"));
}

#[test]
fn no_crash_mark_takes_next_native_input_not_a_shipped_copy() {
    // #193: a shipped copy sits in `collection.inputs` **between** the
    // archive and its native successor. `mark_no_crash` must look at
    // the next NATIVE input, not merely the next input in order; the
    // mutant `.find(|i| i.native)` → `.next()` would attribute the mark
    // against the shipped copy and either set or omit it incorrectly.
    // Here the shipped copy has NO opening checkpoint at seq=6, so the
    // mutant turns the mark OFF (the shipped `data.items.first()` is a
    // `Records(0..1)` whose record is the plain seq-6 copy with no
    // checkpoint; the branch `opening.checkpoint.is_none()` returns
    // false). The real next native does meet the condition.
    use ctx::*;
    let closing = checkpoint(5, 7, [6; 32]);
    let closing_hash = closing.hash;
    let archive = Input {
        path: "audit-0.jsonl".into(),
        native: true,
        data: Rc::new(Data {
            records: vec![closing],
            items: vec![item_records(0..1, 1), fragment(2)],
            spans: vec![span(4, [1; 32])],
        }),
    };
    // Shipped copy inserted between archive and successor native. Its
    // first (and only) record is a non-checkpoint, so the mutant would
    // fail `opening.checkpoint.is_none()` and omit the mark.
    let shipped_record = record(6, 8, closing_hash, 6);
    let shipped = Input {
        path: "copy".into(),
        native: false,
        data: Rc::new(Data {
            records: vec![shipped_record],
            items: vec![item_records(0..1, 1)],
            spans: vec![],
        }),
    };
    // Next NATIVE input: starts with an opening checkpoint linking back.
    let opening = checkpoint(6, 9, closing_hash);
    let next_record = record(7, 10, opening.hash, 7);
    let successor = Input {
        path: "audit.jsonl".into(),
        native: true,
        data: Rc::new(Data {
            records: vec![opening, next_record],
            items: vec![item_records(0..1, 1), item_records(1..2, 2)],
            spans: vec![],
        }),
    };
    let report = check(
        Collection {
            inputs: vec![archive, shipped, successor],
            // Shipped list enumerates the shipped record at inputs[1].
            shipped: vec![(1, 0)],
        },
        TRAIL,
    );
    // The archive's trailing TornWrite must carry the mark; a mutant
    // taking the shipped copy would omit it.
    let archive_tw: Vec<_> = kinds(&report, K::TornWrite)
        .into_iter()
        .filter(|f| f.file() == Some(Path::new("audit-0.jsonl")))
        .collect();
    assert_eq!(archive_tw.len(), 1, "{:?}", report.findings());
    assert!(
        archive_tw[0].detail().contains("; no crash outcome"),
        "{}",
        archive_tw[0].detail()
    );
}

#[test]
fn no_crash_mark_absent_when_successor_starts_with_fragment() {
    use ctx::*;
    let closing = checkpoint(5, 7, [6; 32]);
    let current = Input {
        path: "audit-0.jsonl".into(),
        native: true,
        data: Rc::new(Data {
            records: vec![closing],
            items: vec![item_records(0..1, 1), fragment(2)],
            spans: vec![span(4, [1; 32])],
        }),
    };
    let opening = checkpoint(6, 8, [7; 32]);
    let successor = Input {
        path: "audit.jsonl".into(),
        native: true,
        data: Rc::new(Data {
            records: vec![opening],
            items: vec![fragment(1), item_records(0..1, 2)],
            spans: vec![span(3, [2; 32])],
        }),
    };
    let report = check(
        Collection {
            inputs: vec![current, successor],
            shipped: vec![],
        },
        TRAIL,
    );
    let tw: Vec<_> = kinds(&report, K::TornWrite)
        .into_iter()
        .filter(|f| f.file() == Some(Path::new("audit-0.jsonl")))
        .collect();
    assert_eq!(tw.len(), 1);
    assert!(!tw[0].detail().contains("no crash outcome"));
}

#[test]
fn two_record_native_line_is_accepted_without_any_finding_on_that_line() {
    use ctx::*;
    // Native file whose first "line" (items[0]) carries two valid records.
    // ADR §3 (ruling 13-V3-d4 point 4): the verifier accepts such a line and
    // raises *no* finding attributed to it. Both records still count in
    // records().
    let g = GENESIS();
    let first = checkpoint(0, 1, g);
    let second = record(1, 2, first.hash, 1);
    let records = vec![first, second];
    let items = vec![item_records(0..2, 1)];
    let input = native_input("audit.jsonl", records, items, vec![]);
    let report = check(
        Collection {
            inputs: vec![input],
            shipped: vec![],
        },
        TRAIL,
    );
    assert_eq!(report.records(), 2);
    assert!(kinds(&report, K::SegmentStructure).is_empty());
    // Not a single finding is attributed to the native batch line.
    for f in report.findings() {
        assert_ne!(
            f.line(),
            Some(1),
            "no finding may attach to the batch line: {f:?}",
        );
    }
}

#[test]
fn two_record_native_line_with_repaired_on_second_record_is_silent() {
    use ctx::*;
    // Native two-record line where the SECOND record carries `audit.repaired`.
    // Ruling 13-V3-d4 point 4: `audit.repaired` is read only from the first
    // record of the line, so a later record's `repaired` is deliberately
    // ignored. No TornWriteRepaired / RepairMismatch is raised for it, and no
    // finding at all is attributed to that line.
    let g = GENESIS();
    let first = checkpoint(0, 1, g);
    let mut second = record(1, 2, first.hash, 1);
    second.repaired = Some([0xab; 32]);
    let records = vec![first, second];
    let items = vec![item_records(0..2, 1)];
    let input = native_input("audit.jsonl", records, items, vec![]);
    let report = check(
        Collection {
            inputs: vec![input],
            shipped: vec![],
        },
        TRAIL,
    );
    assert_eq!(report.records(), 2);
    assert!(kinds(&report, K::TornWriteRepaired).is_empty());
    assert!(kinds(&report, K::RepairMismatch).is_empty());
    assert!(kinds(&report, K::TornWrite).is_empty());
    for f in report.findings() {
        assert_ne!(
            f.line(),
            Some(1),
            "no finding may attach to the batch line: {f:?}",
        );
    }
}

#[test]
fn foreign_trail_resume_is_trail_mismatch_without_resumed() {
    use ctx::*;
    // A `vigil.audit.resume` record whose trail is NOT the selected one must
    // produce TrailMismatch and no Resumed warning (ruling 13-V3-d4 add. 8).
    // This kills the mutant "Resumed without the trail filter".
    let g = GENESIS();
    let open = checkpoint(0, 1, g);
    let resume_text = format!(
        "head=0:{} lost_through=0 file=sealed.jsonl",
        digest_string(&g)
    );
    let mut foreign_resume = resume_record(1, 2, open.hash, &resume_text);
    foreign_resume.trail = [2; 16]; // not TRAIL
    let input = Input {
        path: "audit.jsonl".into(),
        native: true,
        data: Rc::new(Data {
            records: vec![open, foreign_resume],
            items: vec![],
            spans: vec![],
        }),
    };
    let report = check(
        Collection {
            inputs: vec![input],
            shipped: vec![],
        },
        TRAIL,
    );
    assert_eq!(kinds(&report, K::TrailMismatch).len(), 1);
    assert!(
        kinds(&report, K::Resumed).is_empty(),
        "{:?}",
        report.findings()
    );
}

// ---------- #13 V3b-2 structural resume validation (ruling 13-V3-d5) ----------

/// Helper for V3b-2 rows: builds a single-input native `Collection`.
fn one_native(records: Vec<Summary>) -> Collection {
    Collection {
        inputs: vec![Input {
            path: "audit.jsonl".into(),
            native: true,
            data: Rc::new(Data {
                records,
                items: vec![],
                spans: vec![],
            }),
        }],
        shipped: vec![],
    }
}

#[test]
fn v3b2_hand_built_jump_marks_structural_valid_and_keeps_seq_gap() {
    // A2: non-genesis valid jump; the SeqGap for 2..=4 stays (d5 point 1
    // S2b: `SeqGap` and `Resumed` stay).
    use ctx::*;
    let g = GENESIS();
    let records = vec![
        checkpoint(0, 1, g),
        checkpoint(1, 2, [1; 32]),
        checkpoint(5, 3, [2; 32]),
        resume_record(
            6,
            4,
            [3; 32],
            &format!(
                "head=1:{} lost_through=4 file=sealed.jsonl",
                digest_string(&[2; 32])
            ),
        ),
    ];
    let report = check(one_native(records), TRAIL);
    let resumed = kinds(&report, K::Resumed);
    assert_eq!(resumed.len(), 1);
    assert!(
        resumed[0]
            .detail()
            .ends_with(" gap=2..=4 lost_records=0 structural=valid"),
        "{}",
        resumed[0].detail()
    );
    let gaps = kinds(&report, K::SeqGap);
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].detail(), "missing seq 2..=4");
}

#[test]
fn v3b2_head_not_present_non_genesis_marks_structural_invalid() {
    // A3: drop the record at seq 1; S2a fails. SeqGap for `1..=4` stays.
    use ctx::*;
    let g = GENESIS();
    let records = vec![
        checkpoint(0, 1, g),
        checkpoint(5, 3, [2; 32]),
        resume_record(
            6,
            4,
            [3; 32],
            &format!(
                "head=1:{} lost_through=4 file=sealed.jsonl",
                digest_string(&[2; 32])
            ),
        ),
    ];
    let report = check(one_native(records), TRAIL);
    let resumed = kinds(&report, K::Resumed);
    assert_eq!(resumed.len(), 1);
    assert!(
        resumed[0]
            .detail()
            .ends_with(" structural=invalid(head-not-present)"),
        "{}",
        resumed[0].detail()
    );
    assert_eq!(kinds(&report, K::SeqGap).len(), 1);
}

#[test]
fn v3b2_head_present_wrong_hash_marks_structural_invalid() {
    // A4: record at seq 1 has hash [7;32]; declaration names a different
    // head hash. S2a (`head-not-present`) fires because no candidate at
    // seq=h matches `head_hash` (13-V1-d1 point 1: match with any
    // candidate).
    use ctx::*;
    let g = GENESIS();
    let records = vec![
        checkpoint(0, 1, g),
        record(1, 7, [1; 32], 1),
        checkpoint(5, 3, [8; 32]),
        resume_record(
            6,
            4,
            [3; 32],
            &format!(
                "head=1:{} lost_through=4 file=sealed.jsonl",
                digest_string(&[8; 32])
            ),
        ),
    ];
    let report = check(one_native(records), TRAIL);
    let resumed = kinds(&report, K::Resumed);
    assert_eq!(resumed.len(), 1);
    assert!(
        resumed[0]
            .detail()
            .ends_with(" structural=invalid(head-not-present)"),
        "{}",
        resumed[0].detail()
    );
}

#[test]
fn v3b2_opening_not_checkpoint_marks_structural_invalid_no_opening() {
    // A5: the only candidate at k=5 is a plain record. S1a fails. Avoid
    // `ctx::resume_record` for the opening-slot record (that would add a
    // second `Resumed` finding and break the length check).
    use ctx::*;
    let g = GENESIS();
    let records = vec![
        checkpoint(0, 1, g),
        record(1, 2, [1; 32], 1),
        record(5, 3, [2; 32], 5),
        resume_record(
            6,
            4,
            [3; 32],
            &format!(
                "head=1:{} lost_through=4 file=sealed.jsonl",
                digest_string(&[2; 32])
            ),
        ),
    ];
    let report = check(one_native(records), TRAIL);
    let resumed = kinds(&report, K::Resumed);
    assert_eq!(resumed.len(), 1);
    assert!(
        resumed[0]
            .detail()
            .ends_with(" structural=invalid(no-opening)"),
        "{}",
        resumed[0].detail()
    );
}

#[test]
fn v3b2_link_mismatch_non_genesis_marks_structural_invalid() {
    // A6: head and non-head records present and in order, but the opening
    // checkpoint's `previous` points at an unrelated hash. S2c fires.
    use ctx::*;
    let g = GENESIS();
    let records = vec![
        checkpoint(0, 1, g),
        record(1, 2, [1; 32], 1),
        checkpoint(5, 3, [9; 32]), // prev != head's hash
        resume_record(
            6,
            4,
            [3; 32],
            &format!(
                "head=1:{} lost_through=4 file=sealed.jsonl",
                digest_string(&[2; 32])
            ),
        ),
    ];
    let report = check(one_native(records), TRAIL);
    let resumed = kinds(&report, K::Resumed);
    assert_eq!(resumed.len(), 1);
    assert!(
        resumed[0]
            .detail()
            .ends_with(" structural=invalid(link-mismatch)"),
        "{}",
        resumed[0].detail()
    );
}

#[test]
fn v3b2_genesis_valid_marks_structural_valid_and_emits_genesis_gap() {
    // A7: genesis-shaped resume. Opening at seq 3 whose `previous` is the
    // genesis value; nothing below seq 3 present. V3a-2's SeqGap for
    // 0..=2 still fires (§19.6 stays Proposed; 13-V3-d1 point 3).
    use ctx::*;
    let g = GENESIS();
    let records = vec![
        checkpoint(3, 1, g),
        resume_record(
            4,
            2,
            [1; 32],
            &format!("head=0:{} lost_through=2 file=-", digest_string(&g)),
        ),
    ];
    let report = check(one_native(records), TRAIL);
    let resumed = kinds(&report, K::Resumed);
    assert_eq!(resumed.len(), 1);
    assert!(
        resumed[0]
            .detail()
            .ends_with(" gap=0..=2 lost_records=0 structural=valid"),
        "{}",
        resumed[0].detail()
    );
    let gaps = kinds(&report, K::SeqGap);
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].detail(), "missing seq 0..=2");
}

#[test]
fn v3b2_link_mismatch_genesis_marks_structural_invalid() {
    // A8: declaration says genesis head but opening's `previous` is not
    // the genesis value. S3 "O.prev == genesis" fails → `link-mismatch`.
    use ctx::*;
    let g = GENESIS();
    let records = vec![
        checkpoint(3, 1, [1; 32]), // prev != genesis
        resume_record(
            4,
            2,
            [1; 32],
            &format!("head=0:{} lost_through=2 file=-", digest_string(&g)),
        ),
    ];
    let report = check(one_native(records), TRAIL);
    let resumed = kinds(&report, K::Resumed);
    assert_eq!(resumed.len(), 1);
    assert!(
        resumed[0]
            .detail()
            .ends_with(" structural=invalid(link-mismatch)"),
        "{}",
        resumed[0].detail()
    );
}

#[test]
fn v3b2_resume_not_at_k_plus_1_marks_structural_invalid() {
    // A9: opening at seq 5 (prev = genesis), a second record at seq 6,
    // and the resume at seq 7 (declared L=4 → k=5, expected k+1=6).
    // d5 point 4 priority: S1a passes (checkpoint at k=5), S1b fails.
    // The l.388 shape (opening at seq 0, resume at seq 1, L=0) resolves
    // to `no-opening`, not `resume-not-at-k+1`, so this row uses a
    // different shape to isolate the reason.
    use ctx::*;
    let g = GENESIS();
    let records = vec![
        checkpoint(5, 1, g),
        checkpoint(6, 6, [1; 32]),
        resume_record(
            7,
            2,
            [6; 32],
            &format!("head=0:{} lost_through=4 file=-", digest_string(&g)),
        ),
    ];
    let report = check(one_native(records), TRAIL);
    let resumed = kinds(&report, K::Resumed);
    assert_eq!(resumed.len(), 1);
    assert!(
        resumed[0]
            .detail()
            .ends_with(" structural=invalid(resume-not-at-k+1)"),
        "{}",
        resumed[0].detail()
    );
}

#[test]
fn v3b2_head_not_last_marks_structural_invalid() {
    // A10: a plain record at seq 3 sits between the head (seq 1) and
    // the opening (seq 5). S2b fails → `head-not-last`.
    use ctx::*;
    let g = GENESIS();
    let records = vec![
        checkpoint(0, 1, g),
        record(1, 2, [1; 32], 1),
        record(3, 3, [2; 32], 3),
        checkpoint(5, 4, [2; 32]),
        resume_record(
            6,
            5,
            [4; 32],
            &format!(
                "head=1:{} lost_through=4 file=sealed.jsonl",
                digest_string(&[2; 32])
            ),
        ),
    ];
    let report = check(one_native(records), TRAIL);
    let resumed = kinds(&report, K::Resumed);
    assert_eq!(resumed.len(), 1);
    assert!(
        resumed[0]
            .detail()
            .ends_with(" structural=invalid(head-not-last)"),
        "{}",
        resumed[0].detail()
    );
    // Chain [0, 1, 3, 5, 6] gives SeqGaps missing seq 2..=2 and 4..=4;
    // f91e714 emits two gaps here, kept on top of the structural suffix.
    let mut gaps: Vec<_> = kinds(&report, K::SeqGap)
        .into_iter()
        .map(|f| f.detail().to_owned())
        .collect();
    gaps.sort();
    assert_eq!(gaps, vec!["missing seq 2..=2", "missing seq 4..=4"]);
}

#[test]
fn v3b2_head_not_last_at_k_minus_1_marks_structural_invalid() {
    // A10 extension (#195): the extra record sits at **exactly** k−1=4,
    // so a mutant that changes `r.seq < k` to `r.seq + 1 < k` would
    // silently miss it (4+1=5 is NOT < 5) and the row would flip to
    // `structural=valid`. A10 already covers seq=3 (far from the
    // boundary); this row isolates the boundary.
    use ctx::*;
    let g = GENESIS();
    let records = vec![
        checkpoint(0, 1, g),
        record(1, 2, [1; 32], 1),
        record(4, 3, [2; 32], 4),
        checkpoint(5, 4, [2; 32]),
        resume_record(
            6,
            5,
            [4; 32],
            &format!(
                "head=1:{} lost_through=4 file=sealed.jsonl",
                digest_string(&[2; 32])
            ),
        ),
    ];
    let report = check(one_native(records), TRAIL);
    let resumed = kinds(&report, K::Resumed);
    assert_eq!(resumed.len(), 1);
    assert!(
        resumed[0]
            .detail()
            .ends_with(" structural=invalid(head-not-last)"),
        "{}",
        resumed[0].detail()
    );
}

#[test]
fn v3b2_genesis_not_first_marks_structural_invalid() {
    // A11: a record at seq 0 is present, so a genesis resume is not the
    // first of the verified set (S3b fails).
    use ctx::*;
    let g = GENESIS();
    let records = vec![
        record(0, 1, [9; 32], 0),
        checkpoint(3, 2, g),
        resume_record(
            4,
            3,
            [2; 32],
            &format!("head=0:{} lost_through=2 file=-", digest_string(&g)),
        ),
    ];
    let report = check(one_native(records), TRAIL);
    let resumed = kinds(&report, K::Resumed);
    assert_eq!(resumed.len(), 1);
    assert!(
        resumed[0]
            .detail()
            .ends_with(" structural=invalid(genesis-not-first)"),
        "{}",
        resumed[0].detail()
    );
}

#[test]
fn v3b2_genesis_not_first_at_k_minus_1_marks_structural_invalid() {
    // A11 extension (#195): the extra record sits at **exactly** k−1=2
    // (declared lost_through=2 → k=3), so a mutant that changes
    // `r.seq < k` to `r.seq + 1 < k` would silently miss it (2+1=3 is
    // NOT < 3) and the row would flip to `structural=valid`. A11 covers
    // seq=0 (far from the boundary); this row isolates it.
    use ctx::*;
    let g = GENESIS();
    let records = vec![
        record(2, 7, [8; 32], 2),
        checkpoint(3, 2, g),
        resume_record(
            4,
            3,
            [2; 32],
            &format!("head=0:{} lost_through=2 file=-", digest_string(&g)),
        ),
    ];
    let report = check(one_native(records), TRAIL);
    let resumed = kinds(&report, K::Resumed);
    assert_eq!(resumed.len(), 1);
    assert!(
        resumed[0]
            .detail()
            .ends_with(" structural=invalid(genesis-not-first)"),
        "{}",
        resumed[0].detail()
    );
}

#[test]
fn v3b2_foreign_trail_resume_does_not_affect_own_trail_candidate() {
    // A13 (#195): a foreign-trail resume whose declaration *would* be
    // structurally valid on the selected trail must still be excluded
    // by the trail filter in `declarations`. Shape: a valid own-trail
    // jump (head=1:[2;32], lost_through=4, k=5), plus a foreign resume
    // at the SAME declared shape and the same resume `seq`, whose
    // trail differs, so the mutant "remove the trail check in
    // `declarations::is_resume`" would promote it to a Valid candidate.
    //
    // Mutant observability (brief point 3). Both mutants are killed by
    // this one row, which pins `on_trail` with a foreign-trail record
    // at `seq=3` ∈ (h=1, k=5):
    //   M-f1  remove `is_resume` trail check   → candidates.len() == 2
    //                                            (both own and foreign
    //                                            resumes become Valid).
    //   M-f2  remove `.filter(|r| r.trail ==
    //         trail)` in `structural_check`     → S2b
    //         (`on_trail().any(|r| r.seq > head_seq && r.seq < k)`)
    //         sees the foreign record at `seq=3`, so the own-trail
    //         declaration flips from `structural=valid` to
    //         `structural=invalid(head-not-last)`.
    use ctx::*;
    let g = GENESIS();
    let resume_text = format!(
        "head=1:{} lost_through=4 file=sealed.jsonl",
        digest_string(&[2; 32])
    );
    // Same (resume_seq, declaration) as the own-trail resume, but a
    // DIFFERENT resume_hash and a foreign trail. Without the trail
    // filter in `declarations::is_resume`, dedup by (seq, hash) keeps
    // both: the foreign would then run through `structural_check` and
    // reach `Outcome::Valid` on the same records as the own one.
    let mut foreign_resume = resume_record(6, 9, [3; 32], &resume_text);
    foreign_resume.trail = [2; 16];
    // Foreign-trail record at a seq inside (h=1, k=5). Not a
    // checkpoint, so S1a (opening at k) is unaffected; its only effect
    // is through `on_trail`'s S2b (`head-not-last`), which the trail
    // filter must exclude.
    let mut foreign_mid = record(3, 10, [50; 32], 3);
    foreign_mid.trail = [2; 16];
    let records = vec![
        checkpoint(0, 1, g),
        record(1, 2, [1; 32], 1),
        foreign_mid,
        checkpoint(5, 3, [2; 32]),
        resume_record(6, 4, [3; 32], &resume_text),
        foreign_resume,
    ];
    // Gather candidates BEFORE moving the collection into `check`.
    let collection = one_native(records);
    let candidates = resume::collect_candidates(&collection, TRAIL);
    let report = check(collection, TRAIL);
    // Both foreign records (mid-interval record and foreign resume)
    // are TrailMismatch, as any foreign record is.
    assert_eq!(kinds(&report, K::TrailMismatch).len(), 2);
    // Exactly one Resumed warning: the own-trail resume, structural=valid.
    let resumed = kinds(&report, K::Resumed);
    assert_eq!(resumed.len(), 1, "{:?}", report.findings());
    assert!(
        resumed[0].detail().ends_with(" structural=valid"),
        "{}",
        resumed[0].detail()
    );
    // Exactly one candidate — the own-trail resume. M-f1 flips this to 2;
    // M-f2 flips the detail suffix and drops this to 0.
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].resume_seq, 6);
    assert_eq!(candidates[0].resume_hash, [4; 32]);
}

#[test]
fn v3b2_native_and_shipped_same_resume_show_same_suffix_once() {
    // A14: native and shipped copies of the same (seq, hash) must share
    // one suffix (d5 point 10). Shape adapted to be structurally valid
    // (genesis resume at seq 4, opening at seq 3).
    use ctx::*;
    let g = GENESIS();
    let open = checkpoint(3, 1, g);
    let resume_text = format!("head=0:{} lost_through=2 file=-", digest_string(&g));
    let r = resume_record(4, 2, open.hash, &resume_text);
    let open2 = checkpoint(3, 1, g);
    let r2 = resume_record(4, 2, open.hash, &resume_text);
    let native_input = Input {
        path: "audit.jsonl".into(),
        native: true,
        data: Rc::new(Data {
            records: vec![open, r],
            items: vec![],
            spans: vec![],
        }),
    };
    let shipped_input = Input {
        path: "copy".into(),
        native: false,
        data: Rc::new(Data {
            records: vec![open2, r2],
            items: vec![],
            spans: vec![],
        }),
    };
    let collection = Collection {
        inputs: vec![native_input, shipped_input],
        shipped: vec![(1, 0), (1, 1)],
    };
    let report = check(collection, TRAIL);
    let resumed = kinds(&report, K::Resumed);
    assert_eq!(resumed.len(), 1);
    assert!(
        resumed[0].detail().contains("gap=0..=2"),
        "{}",
        resumed[0].detail()
    );
    assert!(
        resumed[0].detail().ends_with(" structural=valid"),
        "{}",
        resumed[0].detail()
    );
}

#[test]
fn v3b2_non_genesis_head_with_genesis_hash_marks_head_not_present() {
    // A15: `h = 2` (not 0) with the genesis hash. d5 addendum 9: this is
    // a non-genesis declaration, so S2a fires because no candidate at
    // seq=2 exists. Non-genesis `lost == head_seq` → `gap=none`. This
    // also kills M12 (dropping the `h == 0` guard would route this to
    // the genesis path and return `structural=valid` with `gap=0..=2`).
    use ctx::*;
    let g = GENESIS();
    let records = vec![
        checkpoint(3, 1, g),
        resume_record(
            4,
            2,
            [1; 32],
            &format!("head=2:{} lost_through=2 file=-", digest_string(&g)),
        ),
    ];
    let report = check(one_native(records), TRAIL);
    let resumed = kinds(&report, K::Resumed);
    assert_eq!(resumed.len(), 1);
    assert!(
        resumed[0]
            .detail()
            .ends_with(" gap=none lost_records=0 structural=invalid(head-not-present)"),
        "{}",
        resumed[0].detail()
    );
}

#[test]
fn v3b2_several_candidates_at_k_valid_regardless_of_order() {
    // A16: two candidates at seq 5 — a plain non-checkpoint and a
    // qualifying checkpoint. Run `check` twice with the two in opposite
    // order; both must mark `structural=valid` (d5 addendum 8). This
    // kills M11 ("first candidate at k only"), which the native-first
    // run alone cannot catch.
    use ctx::*;
    let g = GENESIS();
    let resume_text = format!(
        "head=1:{} lost_through=4 file=sealed.jsonl",
        digest_string(&[2; 32])
    );
    // Build the full record set in both orderings; the two candidates at
    // seq 5 (plain, checkpoint) swap places.
    let forward = || {
        vec![
            checkpoint(0, 1, g),
            record(1, 2, [1; 32], 1),
            record(5, 7, [2; 32], 5),  // plain first
            checkpoint(5, 3, [2; 32]), // checkpoint second
            resume_record(6, 4, [3; 32], &resume_text),
        ]
    };
    let reversed = || {
        vec![
            checkpoint(0, 1, g),
            record(1, 2, [1; 32], 1),
            checkpoint(5, 3, [2; 32]), // checkpoint first
            record(5, 7, [2; 32], 5),  // plain second
            resume_record(6, 4, [3; 32], &resume_text),
        ]
    };
    let fwd_report = check(one_native(forward()), TRAIL);
    let rev_report = check(one_native(reversed()), TRAIL);
    // #195 A16: byte-identical findings across the two input orders.
    // The engine's final `sort_by_key` normalises every finding's
    // position, and the per-declaration outcome is shared (d5 point 10),
    // so Finding's `(kind, file, line, seq, detail, accepted_kind,
    // run_digest)` tuple must be identical. `Finding: PartialEq` compares
    // every field.
    assert_eq!(
        fwd_report.findings(),
        rev_report.findings(),
        "forward: {:?}\nreversed: {:?}",
        fwd_report.findings(),
        rev_report.findings()
    );
    // Preserved sanity checks on either run.
    let resumed = kinds(&fwd_report, K::Resumed);
    assert_eq!(resumed.len(), 1);
    assert!(
        resumed[0].detail().ends_with(" structural=valid"),
        "{}",
        resumed[0].detail()
    );
    let conflicts = kinds(&fwd_report, K::SeqConflict);
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].seq(), Some(5));
}

#[test]
fn v3b2_collect_candidates_records_validated_tuple() {
    // A17: collect_candidates emits a candidate for each structurally
    // valid resume, deduped per (resume_seq, resume_hash). Reads every
    // field so the per-field `#[cfg_attr(not(test), expect(dead_code))]`
    // is fulfilled under `clippy --all-targets -- -D warnings`. Also
    // kills M13 ("candidate pushed for invalid outcome"): the invalid
    // shape yields no candidate.
    use ctx::*;
    let g = GENESIS();
    // A1-like non-genesis valid.
    let valid_non_genesis = one_native(vec![
        checkpoint(0, 1, g),
        checkpoint(1, 2, [1; 32]),
        checkpoint(5, 3, [2; 32]),
        resume_record(
            6,
            4,
            [3; 32],
            &format!(
                "head=1:{} lost_through=4 file=sealed.jsonl",
                digest_string(&[2; 32])
            ),
        ),
    ]);
    let c = resume::collect_candidates(&valid_non_genesis, TRAIL);
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].resume_seq, 6);
    assert_eq!(c[0].resume_hash, [4; 32]);
    assert_eq!(c[0].opening_seq, 5);
    assert_eq!(c[0].opening_hash, [3; 32]);
    assert_eq!(c[0].head_seq, 1);
    assert_eq!(c[0].head_hash, [2; 32]);
    assert_eq!(c[0].lost_through, 4);
    assert!(!c[0].is_genesis);

    // A7-like genesis valid.
    let valid_genesis = one_native(vec![
        checkpoint(3, 1, g),
        resume_record(
            4,
            2,
            [1; 32],
            &format!("head=0:{} lost_through=2 file=-", digest_string(&g)),
        ),
    ]);
    let c = resume::collect_candidates(&valid_genesis, TRAIL);
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].resume_seq, 4);
    assert_eq!(c[0].resume_hash, [2; 32]);
    assert_eq!(c[0].opening_seq, 3);
    assert_eq!(c[0].opening_hash, [1; 32]);
    assert_eq!(c[0].head_seq, 0);
    assert_eq!(c[0].head_hash, g);
    assert_eq!(c[0].lost_through, 2);
    assert!(c[0].is_genesis);

    // A6-like invalid (link-mismatch) — no candidate.
    let invalid = one_native(vec![
        checkpoint(0, 1, g),
        record(1, 2, [1; 32], 1),
        checkpoint(5, 3, [9; 32]),
        resume_record(
            6,
            4,
            [3; 32],
            &format!(
                "head=1:{} lost_through=4 file=sealed.jsonl",
                digest_string(&[2; 32])
            ),
        ),
    ]);
    assert!(resume::collect_candidates(&invalid, TRAIL).is_empty());

    // Native plus a shipped copy of the valid non-genesis resume: one
    // candidate (d5 point 10, deduped by (resume_seq, resume_hash)).
    let native_copy = Input {
        path: "audit.jsonl".into(),
        native: true,
        data: Rc::new(Data {
            records: vec![
                checkpoint(0, 1, g),
                checkpoint(1, 2, [1; 32]),
                checkpoint(5, 3, [2; 32]),
                resume_record(
                    6,
                    4,
                    [3; 32],
                    &format!(
                        "head=1:{} lost_through=4 file=sealed.jsonl",
                        digest_string(&[2; 32])
                    ),
                ),
            ],
            items: vec![],
            spans: vec![],
        }),
    };
    let shipped_copy = Input {
        path: "copy".into(),
        native: false,
        data: Rc::new(Data {
            records: vec![resume_record(
                6,
                4,
                [3; 32],
                &format!(
                    "head=1:{} lost_through=4 file=sealed.jsonl",
                    digest_string(&[2; 32])
                ),
            )],
            items: vec![],
            spans: vec![],
        }),
    };
    let collection = Collection {
        inputs: vec![native_copy, shipped_copy],
        shipped: vec![(1, 0)],
    };
    let c = resume::collect_candidates(&collection, TRAIL);
    assert_eq!(c.len(), 1);
}
