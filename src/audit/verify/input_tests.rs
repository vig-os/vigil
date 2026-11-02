use super::*;
use crate::audit::{Entry, FindingKind, RecordContext};
use std::{
    error::Error,
    sync::atomic::{AtomicU64, Ordering},
};
const GOLDEN: &str = include_str!("../../../tests/fixtures/audit/codec.jsonl");
const STAMP: &str = "audit-20261102T010203.000000000Z";
struct Dir(PathBuf);
impl Dir {
    fn new() -> Self {
        static ID: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "vigil-verify-input-{}-{}",
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
fn load(paths: Vec<PathBuf>) -> Collection {
    collect(paths).unwrap_or_else(|e| panic!("{e}"))
}
fn error(result: Result<Collection, AuditError>, kind: AuditErrorKind) {
    let Err(error) = result else {
        panic!("expected {kind:?}")
    };
    assert_eq!(error.kind(), kind);
    assert_eq!(error.source().is_some(), kind == AuditErrorKind::Io);
}
#[test]
fn native_numeric_order_across_directories_and_live_last() {
    let a = Dir::new();
    let b = Dir::new();
    let million = a.put(&format!("{STAMP}_1000000.jsonl"), b"");
    let smaller = b.put(&format!("{STAMP}_999999.jsonl"), b"");
    let bare = a.put(&format!("{STAMP}.jsonl"), b"");
    let live = b.put("audit.jsonl", b"");
    let paths = vec![live.clone(), million.clone(), bare.clone(), smaller.clone()];
    let expanded = load(vec![b.0.clone(), a.0.clone()]);
    let explicit = load(paths);
    let expected = vec![bare, smaller, million, live];
    assert_eq!(
        expanded
            .inputs
            .iter()
            .map(|i| i.path.clone())
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(
        explicit
            .inputs
            .iter()
            .map(|i| i.path.clone())
            .collect::<Vec<_>>(),
        expected
    );
    assert!(
        expanded
            .inputs
            .iter()
            .all(|i| i.native && i.data.items.is_empty())
    );
}
#[test]
fn inode_alias_precedence_and_duplicate_names() {
    let a = Dir::new();
    let b = Dir::new();
    let segment = a.put(&format!("{STAMP}.jsonl"), GOLDEN.lines().next().unwrap());
    let live = a.0.join("audit.jsonl");
    fs::hard_link(&segment, &live).unwrap();
    let shipped = b.0.join("copy");
    fs::hard_link(&segment, &shipped).unwrap();
    let result = load(vec![
        shipped.clone(),
        live.clone(),
        a.0.clone(),
        segment.clone(),
        live,
    ]);
    assert_eq!(result.inputs.len(), 1);
    assert_eq!(result.inputs[0].path, segment);
    assert_eq!(result.inputs[0].data.records.len(), 1);
    assert!(result.shipped.is_empty());
    b.put(&format!("{STAMP}.jsonl"), GOLDEN.lines().next().unwrap());
    error(
        collect(vec![a.0.clone(), b.0.clone()]),
        AuditErrorKind::InvalidConfig,
    );
    let c = Dir::new();
    let d = Dir::new();
    c.put("audit.jsonl", b"");
    d.put("audit.jsonl", b"");
    error(
        collect(vec![c.0.clone(), d.0.clone()]),
        AuditErrorKind::InvalidConfig,
    );
}
#[test]
fn missing_and_unreadable_inputs_keep_io_source() {
    let dir = Dir::new();
    error(collect(vec![dir.0.join("missing")]), AuditErrorKind::Io);
    // A vigil-named directory opens but cannot be read as a file, even as root.
    fs::create_dir(dir.0.join("audit.jsonl")).unwrap();
    error(collect(vec![dir.0.clone()]), AuditErrorKind::Io);
}
#[test]
fn retry_discards_old_decode_items_and_reads_live_tail() {
    let dir = Dir::new();
    dir.put("audit.jsonl", b"not json\n");
    let mut attempts = 0;
    let result = collect_with(
        vec![dir.0.clone()],
        |_, _| Ok(()),
        |path, attempt| {
            attempts = attempt;
            if attempt == 1 {
                // A changed segment listing retries while the same live inode is
                // completed in place. Tentative decoder errors must be discarded.
                fs::write(path.join(format!("{STAMP}.jsonl")), b"")?;
                fs::write(path.join("audit.jsonl"), GOLDEN.lines().next().unwrap())?;
            }
            Ok(())
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(attempts, 2);
    assert_eq!(result.inputs.len(), 2);
    assert_eq!(result.inputs[1].data.records.len(), 1);
    assert!(matches!(
        result.inputs[1].data.items[0].content,
        LineContent::Records(_)
    ));
    assert!(result.inputs[1].data.spans.is_empty());
}
#[test]
fn eight_races_are_io_not_success() {
    let dir = Dir::new();
    dir.put("audit.jsonl", b"");
    let mut attempts = 0;
    let result = collect_with(
        vec![dir.0.clone()],
        |_, _| Ok(()),
        |path, attempt| {
            attempts = attempt;
            fs::rename(
                path.join("audit.jsonl"),
                path.join(format!("{STAMP}_{attempt:06}.jsonl")),
            )?;
            fs::write(path.join("audit.jsonl"), b"")
        },
        |_| Ok(()),
    );
    assert_eq!(attempts, 8);
    error(result, AuditErrorKind::Io);
}
#[test]
fn retention_after_copy_returns_only_confirmed_snapshot() {
    let dir = Dir::new();
    let segment = dir.put(&format!("{STAMP}.jsonl"), line(1));
    let live = dir.put("audit.jsonl", line(2));
    let mut attempts = 0;
    let result = collect_with(
        vec![dir.0.clone()],
        |_, attempt| {
            attempts = attempt;
            Ok(())
        },
        |_, attempt| {
            if attempt == 1 {
                fs::remove_file(&segment)?;
            }
            Ok(())
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(attempts, 2);
    assert_eq!(
        result
            .inputs
            .iter()
            .map(|i| i.path.clone())
            .collect::<Vec<_>>(),
        vec![live]
    );
    assert_eq!(
        result
            .inputs
            .iter()
            .flat_map(|i| &i.data.records)
            .map(|r| r.seq)
            .collect::<Vec<_>>(),
        vec![2]
    );
}
#[test]
fn ignores_control_files_without_mutating_or_locking() {
    let dir = Dir::new();
    for name in [
        ".audit-resume.jsonl",
        ".audit-create.jsonl",
        "audit.poison",
        ".audit.lock",
        "random.jsonl",
    ] {
        dir.put(name, b"not a record");
    }
    let before: BTreeSet<_> = fs::read_dir(&dir.0)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(load(vec![dir.0.clone()]).inputs.is_empty());
    let after: BTreeSet<_> = fs::read_dir(&dir.0)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(before, after);
    assert_eq!(load(vec![dir.0.join("random.jsonl")]).inputs.len(), 1);
}
fn line(seq: u64) -> String {
    let record = Record::new(
        RecordContext::new([3; 16], seq, 77, "service", [4; 32]).repaired([5; 32]),
        Entry::new("actor", "change", "object"),
    )
    .unwrap();
    String::from_utf8(crate::audit::sink::line(&record).unwrap()).unwrap()
}
fn batch(lines: &[String]) -> String {
    let mut first: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    let records: Vec<_> = lines
        .iter()
        .flat_map(|s| {
            let v: serde_json::Value = serde_json::from_str(s).unwrap();
            v["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
                .as_array()
                .unwrap()
                .clone()
        })
        .collect();
    first["resourceLogs"][0]["scopeLogs"][0]["logRecords"] = records.into();
    first.to_string()
}
#[test]
fn shipped_unordered_batches_sort_by_seq_keep_physical_lines() {
    let dir = Dir::new();
    let a = dir.put("a", format!("not json\n{}\n", batch(&[line(9), line(2)])));
    let b = dir.put("b", format!("{}{}", line(7), line(1)));
    for paths in [vec![a.clone(), b.clone()], vec![b.clone(), a.clone()]] {
        let result = load(paths);
        assert_eq!(
            result
                .shipped
                .iter()
                .map(|&(i, r)| result.inputs[i].data.records[r].seq)
                .collect::<Vec<_>>(),
            vec![1, 2, 7, 9]
        );
        for input in &result.inputs {
            assert!(!input.native);
            assert!(input.data.spans.is_empty());
        }
        let input = &result.inputs[0];
        assert_eq!(input.path, a);
        let LineContent::Records(range) = &input.data.items[1].content else {
            panic!("batch")
        };
        assert_eq!(range.clone(), 0..2);
        for record in &input.data.records {
            assert_eq!(record.line, 2);
            assert_eq!(record.trail, [3; 16]);
            assert_eq!(record.previous, [4; 32]);
            assert_eq!(record.time, 77);
            assert_eq!(record.repaired, Some([5; 32]));
            assert!(record.checkpoint.is_none());
            assert!(record.operator.is_none());
        }
        assert_eq!(input.data.items[0].bytes, 0..9);
        assert_eq!(input.data.items[0].line, 1);
        let LineContent::Unparsable(e) = &input.data.items[0].content else {
            panic!("unparsable")
        };
        assert_eq!(e.finding_kind(), Some(FindingKind::Unparsable));
    }
}
#[test]
fn oversized_line_is_one_item_then_valid_line() {
    let dir = Dir::new();
    let mut bytes = vec![b'x'; 3_000_000];
    bytes.push(b'\n');
    bytes.extend(line(4).as_bytes());
    let path = dir.put("audit.jsonl", &bytes);
    let result = load(vec![path]);
    let data = &result.inputs[0].data;
    assert_eq!(data.items.len(), 2);
    assert_eq!(data.items[0].bytes, 0..3_000_001);
    assert_eq!(data.records.len(), 1);
    assert_eq!(data.records[0].line, 2);
    let LineContent::Unparsable(e) = &data.items[0].content else {
        panic!("over cap")
    };
    assert_eq!(e.kind(), AuditErrorKind::TooLarge);
    assert_eq!(data.spans[0].len, 3_000_001);
    let mut hash = crate::audit::gap_hasher();
    hash.update(&bytes[..3_000_001]);
    assert_eq!(data.spans[0].digest, *hash.finalize().as_bytes());
}
#[test]
fn decoder_errors_and_fragments_remain_located() {
    let dir = Dir::new();
    let path = dir.put("audit.jsonl", format!("{{}}\n{{\"seq\":\n{}", line(1)));
    let result = load(vec![path]);
    let data = &result.inputs[0].data;
    let LineContent::Invalid(e) = &data.items[0].content else {
        panic!("invalid")
    };
    assert_eq!(e.finding_kind(), Some(FindingKind::MissingField));
    assert!(matches!(data.items[1].content, LineContent::Fragment));
    assert_eq!(data.items[1].line, 2);
    assert_eq!(data.records[0].line, 3);
}

#[test]
fn whole_batch_failure_is_one_located_decoder_item() {
    let dir = Dir::new();
    let bad = batch(&[line(9), line(2)]).replace("\"actor\"", "\"edited\"");
    let path = dir.put("collector", format!("\n{bad}\n{}", line(10)));
    let result = load(vec![path.clone()]);
    assert_eq!(result.inputs[0].path, path);
    let data = &result.inputs[0].data;
    assert_eq!(data.items[1].line, 2);
    let LineContent::Invalid(error) = &data.items[1].content else {
        panic!("whole batch invalid")
    };
    assert_eq!(error.finding_kind(), Some(FindingKind::HashMismatch));
    assert_eq!(data.records.len(), 1);
    assert_eq!(data.records[0].seq, 10);
    assert_eq!(data.records[0].line, 3);
}

#[test]
fn checkpoint_operator_and_native_span_context_survives_compaction() {
    let dir = Dir::new();
    let fields = CheckpointFields::new(0, [6; 32], vec![], [7; 32], [8; 64]).unwrap();
    let checkpoint = Record::checkpoint(
        RecordContext::new([3; 16], 0, 55, "service", Record::genesis(&[3; 16])),
        fields,
    )
    .unwrap();
    let operator = Record::new_internal(
        RecordContext::new([3; 16], 1, 56, "service", checkpoint.hash()),
        Entry::new("operator", "vigil.audit.resume", "trail")
            .reason("crash")
            .details("pending resume context"),
    )
    .unwrap();
    let bytes = [
        crate::audit::sink::line(&checkpoint).unwrap(),
        b"{\"seq\":\n".to_vec(),
        crate::audit::sink::line(&operator).unwrap(),
    ]
    .concat();
    dir.put(&format!("{STAMP}.jsonl"), &bytes);
    dir.put("audit.jsonl", &bytes);
    let result = load(vec![dir.0.clone()]);
    for (index, input) in result.inputs.iter().enumerate() {
        assert_eq!(input.data.spans[0].seg, index as u32);
        assert_eq!(input.data.spans[0].after, 0);
        let first = &input.data.records[0];
        assert_eq!(first.hash, checkpoint.hash());
        assert_eq!(first.checkpoint.as_ref().unwrap().key, [7; 32]);
        assert_eq!(
            input.data.records[1].operator.as_ref().unwrap(),
            &(
                "vigil.audit.resume".into(),
                "operator".into(),
                Some("crash".into()),
                Some("pending resume context".into())
            )
        );
    }
}

#[test]
fn rotation_between_listing_and_open_retries() {
    let dir = Dir::new();
    let live = dir.put("audit.jsonl", line(4));
    let inode = fs::metadata(&live).unwrap().ino();
    let segment = dir.0.join(format!("{STAMP}.jsonl"));
    let mut attempts = 0;
    let result = collect_with(
        vec![dir.0.clone()],
        |_, attempt| {
            attempts = attempt;
            if attempt == 1 {
                fs::rename(&live, &segment)?;
            }
            Ok(())
        },
        |_, _| Ok(()),
        |_| Ok(()),
    )
    .unwrap_or_else(|e| {
        panic!("rotation retained the inode under its segment name, but collect returned {e:?}")
    });
    assert_eq!(attempts, 2);
    assert_eq!(result.inputs.len(), 1);
    assert_eq!(result.inputs[0].path, segment);
    assert_eq!(fs::metadata(&result.inputs[0].path).unwrap().ino(), inode);
    assert_eq!(result.inputs[0].data.records.len(), 1);
    assert_eq!(result.inputs[0].data.records[0].seq, 4);
}

#[test]
fn deletion_between_listing_and_open_retries() {
    let dir = Dir::new();
    let live = dir.put("audit.jsonl", line(4));
    let mut attempts = 0;
    let result = collect_with(
        vec![dir.0.clone()],
        |_, attempt| {
            attempts = attempt;
            if attempt == 1 {
                fs::remove_file(&live)?;
            }
            Ok(())
        },
        |_, _| Ok(()),
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(attempts, 2);
    assert!(result.inputs.is_empty());
}

#[test]
fn stable_unreadable_listing_keeps_original_source() {
    let dir = Dir::new();
    fs::create_dir(dir.0.join("audit.jsonl")).unwrap();
    let mut attempts = 0;
    let mut tentative_copies = 0;
    let result = collect_with(
        vec![dir.0.clone()],
        |_, attempt| {
            attempts = attempt;
            Ok(())
        },
        |_, _| {
            tentative_copies += 1;
            Ok(())
        },
        |_| Ok(()),
    );
    let Err(error) = result else {
        panic!("unreadable file succeeded")
    };
    assert_eq!(attempts, 1);
    assert_eq!(tentative_copies, 1);
    assert_eq!(error.kind(), AuditErrorKind::Io);
    let source = error.source().unwrap().downcast_ref::<io::Error>().unwrap();
    assert_eq!(source.kind(), io::ErrorKind::IsADirectory);
}

#[test]
fn open_races_exhaust_after_eight_attempts() {
    let dir = Dir::new();
    dir.put("audit.jsonl", line(4));
    let mut attempts = 0;
    let result = collect_with(
        vec![dir.0.clone()],
        |path, attempt| {
            attempts = attempt;
            // Replace the selected path before open with a differently named segment.
            // Every attempt changes the listing and makes the selected path unreadable.
            if attempt == 1 {
                fs::remove_file(path.join("audit.jsonl"))?;
            } else {
                fs::remove_file(path.join(format!("{STAMP}_{:06}.jsonl", attempt - 1)))?;
            }
            fs::write(path.join(format!("{STAMP}_{attempt:06}.jsonl")), line(4))
        },
        |_, _| Ok(()),
        |_| Ok(()),
    );
    assert_eq!(attempts, 8);
    error(result, AuditErrorKind::Io);
}

#[test]
fn pruning_already_read_segment_during_later_open_error() {
    let dir = Dir::new();
    let first = dir.put(&format!("{STAMP}.jsonl"), line(1));
    let live = dir.put("audit.jsonl", line(2));
    let rotated = dir.0.join(format!("{STAMP}_000001.jsonl"));
    let mut attempts = 0;
    let mut listings = Vec::new();
    let mut opened = Vec::new();
    let result = collect_with(
        vec![dir.0.clone()],
        |path, attempt| {
            attempts = attempt;
            let mut listing: Vec<_> = fs::read_dir(path)?
                .map(|e| e.map(|e| e.path()))
                .collect::<io::Result<_>>()?;
            listing.sort_by_key(|p| key(p));
            listings.push(listing);
            Ok(())
        },
        |_, _| Ok(()),
        |path| {
            opened.push(path.to_owned());
            if path == live {
                // Numeric segment order means seq 1 was already decoded.
                fs::remove_file(&first)?;
                fs::rename(&live, &rotated)?;
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(attempts, 2);
    assert_eq!(opened, vec![first, live, rotated.clone()]);
    assert_eq!(listings[1], vec![rotated]);
    assert_eq!(
        result
            .inputs
            .iter()
            .map(|i| i.path.clone())
            .collect::<Vec<_>>(),
        listings[1]
    );
    assert_eq!(
        result
            .inputs
            .iter()
            .flat_map(|i| &i.data.records)
            .map(|r| r.seq)
            .collect::<Vec<_>>(),
        vec![2]
    );
}
