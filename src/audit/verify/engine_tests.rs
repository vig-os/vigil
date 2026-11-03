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
fn resume_nothing_lost_emits_resumed_with_gap_none_and_strict_fails() {
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
    assert!(resumed[0].detail().contains("gap=none"));
    assert!(resumed[0].detail().contains("lost_records=0"));
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
