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
        assert_eq!(first.checkpoint.as_ref().unwrap().fields.key, [7; 32]);
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

// ---------------------------------------------------------------
// Rulings 13-V4-d5 (a), (b), 13-V4-d6 points 1 and 2: the verifier's
// one classify pass drives `SegmentSource::for_snapshot` over the
// native inputs that `collect` already read and retained.
// ---------------------------------------------------------------

/// Reusable: a single-record base checkpoint for trail
/// `[17; 16]`. Golden line 2 is `audit.checkpoint seq=0` on that
/// trail, so a fixture built from it is a valid one-segment trail.
fn checkpoint_line() -> &'static str {
    GOLDEN.lines().nth(1).unwrap()
}

fn classify_snapshot(segments: &[super::NativeSegment]) -> crate::audit::runs::ClassifyOutput {
    let tuples: Vec<(std::rc::Rc<[u8]>, bool)> = segments
        .iter()
        .map(|seg| (std::rc::Rc::clone(&seg.bytes), seg.is_live))
        .collect();
    let mut source = crate::audit::storage::SegmentSource::for_snapshot(&tuples);
    crate::audit::runs::classify(
        crate::audit::runs::ClassifyArgs {
            trail: [17; 16],
            prior_state: None,
        },
        crate::audit::runs::ReaderPath::LiveOpen { expected: None },
        &mut source,
        crate::audit::runs::Reaction::Collect,
    )
    .unwrap()
}

fn segment_bytes_vec(c: &Collection) -> Vec<(PathBuf, Vec<u8>, bool)> {
    c.native_segments()
        .into_iter()
        .map(|s| (s.path, s.bytes.to_vec(), s.is_live))
        .collect()
}

#[test]
fn snapshot_collect_dir_matches_collect_explicit_paths() {
    // Ruling 13-V4-d5 (a), (b): a real archive -- no live file,
    // and a closed run entirely inside the archive. `collect([dir])`
    // and `collect([explicit seg paths])` must produce the same
    // `native_segments` sequence (sort + live-last by `key`), the
    // same `ClassifyOutput` through `for_snapshot`, and exactly
    // one `RunReport` whose fields are pinned here (ruling 197-d1
    // addendum 27.4).
    use crate::audit::Mmr;
    use crate::audit::storage::tests as st;
    let dir = st::Temp::new();
    // S0 = base checkpoint, S1 = headless (opens run), S2 =
    // closer (opening cp + resume closes it). No `audit.jsonl`.
    let base = st::runs::signed(
        0,
        crate::audit::format::Record::genesis(&[17; 16]),
        &Mmr::new(),
    );
    st::runs::put(&dir, 0, &[&base], &[]);
    let r = st::runs::headless(&base, 5);
    let mut fold = st::seeded(&base);
    fold.push(r.hash()).unwrap();
    st::runs::put(&dir, 1, &[&r], &[]);
    let closer = st::runs::signed(r.context.seq + 4, r.hash(), &fold);
    let decl = st::declaration(
        &closer,
        r.context.seq,
        r.hash(),
        closer.context.seq - 1,
        None,
    );
    st::runs::put(&dir, 2, &[&closer, &decl], &[]);
    let seg0 = st::segment(&dir.0, 0);
    let seg1 = st::segment(&dir.0, 1);
    let seg2 = st::segment(&dir.0, 2);
    let via_dir = load(vec![dir.0.clone()]);
    let via_paths = load(vec![seg0, seg1, seg2]);
    let dir_segments = via_dir.native_segments();
    let path_segments = via_paths.native_segments();
    // Equal shape: paths, bytes, is_live, input_index all match.
    assert_eq!(
        segment_bytes_vec(&via_dir),
        segment_bytes_vec(&via_paths),
        "native_segments should match across collect variants",
    );
    // Literal pin: `input_index` is the position in
    // `Collection::inputs`, and natives sort to the front; on this
    // three-sealed-segment fixture that is [0, 1, 2]. Pinning the
    // exact sequence kills a mutant that sets `input_index := 0`
    // on every entry, because the `1` and `2` rows no longer match.
    assert_eq!(
        dir_segments
            .iter()
            .map(|s| (s.input_index, s.is_live))
            .collect::<Vec<_>>(),
        vec![(0, false), (1, false), (2, false)],
        "input_index [0, 1, 2]; is_live=false on every sealed segment",
    );
    assert_eq!(
        path_segments
            .iter()
            .map(|s| (s.input_index, s.is_live))
            .collect::<Vec<_>>(),
        vec![(0, false), (1, false), (2, false)],
        "explicit-paths collect yields the same literal (input_index, is_live)",
    );
    // Snapshot-driven classify: full `ClassifyOutput` equality.
    let dir_out = classify_snapshot(&dir_segments);
    let path_out = classify_snapshot(&path_segments);
    assert_eq!(
        dir_out.violations,
        vec![],
        "clean closed-run archive: no violations",
    );
    assert_eq!(
        path_out.violations,
        vec![],
        "same via explicit paths: no violations",
    );
    assert_eq!(dir_out.head_mismatch, path_out.head_mismatch);
    assert_eq!(
        dir_out
            .segments
            .iter()
            .map(|s| (s.class, s.damage))
            .collect::<Vec<_>>(),
        path_out
            .segments
            .iter()
            .map(|s| (s.class, s.damage))
            .collect::<Vec<_>>(),
    );
    assert_eq!(
        dir_out.final_state.as_ref().map(|s| s.run.head),
        path_out.final_state.as_ref().map(|s| s.run.head),
    );
    assert_eq!(
        dir_out.found.as_ref().map(|r| (r.context.seq, r.hash())),
        path_out.found.as_ref().map(|r| (r.context.seq, r.hash())),
    );
    assert_eq!(dir_out.runs.len(), path_out.runs.len());
    for (a, b) in dir_out.runs.iter().zip(path_out.runs.iter()) {
        assert_eq!(a.first_segment, b.first_segment);
        assert_eq!(a.last_segment, b.last_segment);
        assert_eq!(a.closing_opening, b.closing_opening);
        assert_eq!(a.loss_points, b.loss_points);
        assert_eq!(a.spans, b.spans);
    }
    // Literal pin: one `RunReport` with the exact closed-run shape
    // (ruling 13-V4-d3 point 1 + addendum 25.5): S0 Base, S1
    // opens, S2 closes.
    assert_eq!(dir_out.runs.len(), 1, "exactly one RunReport");
    let report = &dir_out.runs[0];
    assert_eq!(report.first_segment, 1, "first_segment pins to S1");
    assert_eq!(report.last_segment, 2, "last_segment pins to S2");
    assert_eq!(
        report.closing_opening,
        Some(crate::audit::storage::Head::of(&closer)),
        "closing_opening is the closer's Head",
    );
    assert_eq!(
        report.loss_points.len(),
        1,
        "exactly one loss point for the S1 headless",
    );
    assert_eq!(
        report.loss_points[0].loss_seq, r.context.seq,
        "loss_seq is the headless record seq",
    );
}

#[test]
fn snapshot_native_segments_filters_shipped_siblings_and_retains_none() {
    // Ruling 13-V4-d5 (a): shipped inputs are out of the classifier's
    // scope and keep `Data::bytes` as `None` (ruling 13-V4-d6 point 1).
    // `native_segments` filters shipped inputs out. A second,
    // independent killer for M-SNAP-7 beyond
    // `snapshot_native_segments_excludes_shipped_inputs`: a mutant
    // that lifts the filter and emits shipped entries would trip the
    // `expect("native input retained bytes ...")` the moment any
    // Collection with a non-inode-aliased shipped input calls the
    // method, because `decode(keep_bytes=false)` on the shipped path
    // leaves `data.bytes = None`.
    let dir = Dir::new();
    let line_cp = checkpoint_line();
    dir.put(&format!("{STAMP}_000000.jsonl"), line_cp);
    let shipped = dir.0.join("extra-copy");
    fs::write(&shipped, line_cp).unwrap();
    let c = load(vec![dir.0.clone(), shipped.clone()]);
    // Natives are retained; this shipped path is a distinct inode,
    // so it is decoded with `keep_bytes=false` and keeps `bytes=None`.
    let natives: Vec<_> = c.inputs.iter().filter(|i| i.native).collect();
    let shipped_inputs: Vec<_> = c.inputs.iter().filter(|i| !i.native).collect();
    assert!(!natives.is_empty(), "fixture: at least one native");
    assert!(
        !shipped_inputs.is_empty(),
        "fixture: at least one shipped input",
    );
    for s in shipped_inputs {
        assert!(
            s.data.bytes.is_none(),
            "shipped inputs on distinct inodes must not retain bytes",
        );
    }
    // Correct behaviour: exactly the native inputs are returned.
    let segs = c.native_segments();
    assert_eq!(
        segs.len(),
        natives.len(),
        "native_segments returns exactly the native inputs",
    );
    for seg in &segs {
        assert!(super::native(&seg.path));
    }
}

#[test]
fn snapshot_native_segments_shipped_hardlinked_to_native_dedups_to_native() {
    // `Data` rustdoc (and `inode_alias_precedence_and_duplicate_names`
    // shape, applied to the `data.bytes` claim): a shipped path that
    // hard-links to an already-decoded native path (same inode)
    // shares the native's `Rc<Data>` through the inode cache; the
    // `collect` merge then keeps the lower-keyed (native) `Input`
    // per inode, so the survivor's `bytes` is `Some(...)` -- the
    // one `Rc<[u8]>` the native path brought in, which no shipped
    // alias ever duplicates. Exactly the retention the `Data`
    // rustdoc documents.
    let a = Dir::new();
    let b = Dir::new();
    let native_path = a.put(&format!("{STAMP}_000000.jsonl"), checkpoint_line());
    // Hard-linked shipped alias under a different dir, under a
    // non-native name: same inode as the native.
    let shipped = b.0.join("shipped-copy");
    fs::hard_link(&native_path, &shipped).unwrap();
    let c = load(vec![a.0.clone(), shipped.clone()]);
    // Inode dedup: exactly one Input survives per inode, and it is
    // the native (rank 0 < shipped rank 2 under the `key` order).
    assert_eq!(c.inputs.len(), 1, "same inode -> one Input");
    let only = &c.inputs[0];
    assert_eq!(only.path, native_path, "native wins over shipped alias");
    assert!(only.native, "surviving Input is marked native");
    assert!(
        only.data.bytes.is_some(),
        "native retains bytes under keep_bytes=true",
    );
    assert!(
        c.shipped.is_empty(),
        "shipped list is empty: the alias deduped into the native",
    );
    // `native_segments` yields exactly one entry whose bytes are the
    // retained `Rc<[u8]>` on the surviving native Input.
    let segs = c.native_segments();
    assert_eq!(segs.len(), 1);
    assert_eq!(segs[0].path, native_path);
    assert_eq!(
        segs[0].bytes.as_ref(),
        only.data.bytes.as_ref().unwrap().as_ref(),
    );
}

#[test]
fn snapshot_collect_archive_plus_trail_dir_matches_full_single_dir() {
    // Ruling 13-V4-d5 (b), 13-V3-d2 decision 2 step 6: a split
    // archive -- archive part (base checkpoint + run opener) in
    // one directory, trail part (closer: opening cp + resume) in
    // another. `collect([arch, trail])` and `collect([full])`
    // (same segments under one roof) must produce the same
    // `native_segments` order and the same `ClassifyOutput`
    // through `for_snapshot`, with exactly one closed `RunReport`
    // whose fields are pinned here. A row with corrupt
    // equal-on-both-sides outputs (e.g.
    // `OpeningCheckpointDuplicatesPredecessor`) is specifically
    // avoided.
    use crate::audit::Mmr;
    use crate::audit::storage::tests as st;
    let arch = st::Temp::new();
    let trail = st::Temp::new();
    let full = st::Temp::new();
    // Build the records once.
    let base = st::runs::signed(
        0,
        crate::audit::format::Record::genesis(&[17; 16]),
        &Mmr::new(),
    );
    let r = st::runs::headless(&base, 5);
    let mut fold = st::seeded(&base);
    fold.push(r.hash()).unwrap();
    let closer = st::runs::signed(r.context.seq + 4, r.hash(), &fold);
    let decl = st::declaration(
        &closer,
        r.context.seq,
        r.hash(),
        closer.context.seq - 1,
        None,
    );
    // Archive part: S0, S1.
    st::runs::put(&arch, 0, &[&base], &[]);
    st::runs::put(&arch, 1, &[&r], &[]);
    // Trail part: S2. Different counter so the file name does
    // not collide with the archive's (both dirs share the test
    // helpers' fixed stamp).
    st::runs::put(&trail, 2, &[&closer, &decl], &[]);
    // Full: all three in one directory.
    st::runs::put(&full, 0, &[&base], &[]);
    st::runs::put(&full, 1, &[&r], &[]);
    st::runs::put(&full, 2, &[&closer, &decl], &[]);
    let via_split = load(vec![arch.0.clone(), trail.0.clone()]);
    let via_full = load(vec![full.0.clone()]);
    // Paths differ by dir; compare bytes and is_live (order).
    let split_bytes_live: Vec<(Vec<u8>, bool)> = via_split
        .native_segments()
        .into_iter()
        .map(|s| (s.bytes.to_vec(), s.is_live))
        .collect();
    let full_bytes_live: Vec<(Vec<u8>, bool)> = via_full
        .native_segments()
        .into_iter()
        .map(|s| (s.bytes.to_vec(), s.is_live))
        .collect();
    assert_eq!(
        split_bytes_live, full_bytes_live,
        "archive+trail-dir native_segments must match full single-dir",
    );
    // Literal `input_index` pin on both variants: natives sort to
    // the front of `Collection::inputs`, so the three sealed
    // segments carry (0, 1, 2) in both the split and single-dir
    // runs. Kills a mutant that sets `input_index := 0` on every
    // `NativeSegment` (the (1, _) and (2, _) rows stop matching).
    assert_eq!(
        via_split
            .native_segments()
            .iter()
            .map(|s| (s.input_index, s.is_live))
            .collect::<Vec<_>>(),
        vec![(0, false), (1, false), (2, false)],
        "split archive+trail: input_index [0, 1, 2]",
    );
    assert_eq!(
        via_full
            .native_segments()
            .iter()
            .map(|s| (s.input_index, s.is_live))
            .collect::<Vec<_>>(),
        vec![(0, false), (1, false), (2, false)],
        "full single-dir: input_index [0, 1, 2]",
    );
    let split_out = classify_snapshot(&via_split.native_segments());
    let full_out = classify_snapshot(&via_full.native_segments());
    assert_eq!(
        split_out.violations,
        vec![],
        "split: clean closed-run has no violations",
    );
    assert_eq!(
        full_out.violations,
        vec![],
        "full: clean closed-run has no violations",
    );
    assert_eq!(split_out.head_mismatch, full_out.head_mismatch);
    assert_eq!(
        split_out
            .segments
            .iter()
            .map(|s| (s.class, s.damage))
            .collect::<Vec<_>>(),
        full_out
            .segments
            .iter()
            .map(|s| (s.class, s.damage))
            .collect::<Vec<_>>(),
    );
    assert_eq!(
        split_out.final_state.as_ref().map(|s| s.run.head),
        full_out.final_state.as_ref().map(|s| s.run.head),
    );
    assert_eq!(
        split_out.found.as_ref().map(|r| (r.context.seq, r.hash())),
        full_out.found.as_ref().map(|r| (r.context.seq, r.hash())),
    );
    assert_eq!(split_out.runs.len(), full_out.runs.len());
    for (a, b) in split_out.runs.iter().zip(full_out.runs.iter()) {
        assert_eq!(a.first_segment, b.first_segment);
        assert_eq!(a.last_segment, b.last_segment);
        assert_eq!(a.closing_opening, b.closing_opening);
        assert_eq!(a.loss_points, b.loss_points);
        assert_eq!(a.spans, b.spans);
    }
    // Literal pin: the closer in the trail part closes the run
    // that opened in the archive part.
    assert_eq!(split_out.runs.len(), 1, "exactly one RunReport");
    let report = &split_out.runs[0];
    assert_eq!(report.first_segment, 1, "first_segment pins to S1 (arch)");
    assert_eq!(report.last_segment, 2, "last_segment pins to S2 (trail)");
    assert_eq!(
        report.closing_opening,
        Some(crate::audit::storage::Head::of(&closer)),
    );
    assert_eq!(report.loss_points.len(), 1);
    assert_eq!(report.loss_points[0].loss_seq, r.context.seq);
}

#[test]
fn snapshot_native_segments_excludes_shipped_inputs() {
    // Ruling 13-V4-d5 (a): V4a classifies only native segments;
    // `native_segments` filters shipped inputs out. Kills
    // M-SNAP-7: emitting shipped inputs would change the vec.
    let dir = Dir::new();
    let line_cp = checkpoint_line();
    let _seg = dir.put(&format!("{STAMP}_000000.jsonl"), line_cp);
    let shipped = dir.0.join("extra-copy");
    fs::write(&shipped, line_cp).unwrap();
    let c = load(vec![dir.0.clone(), shipped.clone()]);
    let natives = c.native_segments();
    assert!(
        !natives.is_empty(),
        "fixture should expose at least one native segment",
    );
    for seg in &natives {
        assert!(
            super::native(&seg.path),
            "native_segments must only hold native-named paths; got {}",
            seg.path.display(),
        );
    }
    // Every retained-byte input shows up; nothing extra does.
    let retained = c.inputs.iter().filter(|i| i.data.bytes.is_some()).count();
    assert_eq!(
        natives.len(),
        retained,
        "exactly one NativeSegment per native (retained-bytes) input",
    );
}

#[test]
fn snapshot_native_segments_is_live_true_only_on_audit_jsonl() {
    // Ruling 13-V4-d5 (b): a native segment is the live input iff
    // its file name is `audit.jsonl`. Literal row: assert the
    // per-segment `(path file name, is_live)` on a layout with
    // rotated sealed segments and the live file, so a mutant that
    // sets `is_live = false` (or always `true`) on
    // `NativeSegment` fails on the `is_live` assertion directly.
    let dir = Dir::new();
    let line_cp = checkpoint_line();
    dir.put(&format!("{STAMP}_000000.jsonl"), line_cp);
    dir.put("audit.jsonl", line_cp);
    let c = load(vec![dir.0.clone()]);
    let segs = c.native_segments();
    let names_live: Vec<(String, bool)> = segs
        .iter()
        .map(|s| {
            (
                s.path.file_name().unwrap().to_string_lossy().into_owned(),
                s.is_live,
            )
        })
        .collect();
    assert_eq!(
        names_live,
        vec![
            (format!("{STAMP}_000000.jsonl"), false),
            ("audit.jsonl".to_owned(), true),
        ],
        "is_live=true only on audit.jsonl; sealed segments stay \
         is_live=false",
    );
}

#[test]
fn snapshot_native_segments_order_is_sort_live_last_literal() {
    // Ruling 13-V4-d5 (a): `native_segments` returns native inputs
    // in `Collection::inputs` order, which is (stamp, counter)
    // sorted with the live file last. Literal row: assert the
    // exact sequence of path file names so a reversed or shuffled
    // order fails here directly (independent of any classify run).
    let dir = Dir::new();
    let line_cp = checkpoint_line();
    dir.put(&format!("{STAMP}_000000.jsonl"), line_cp);
    dir.put(&format!("{STAMP}_000001.jsonl"), line_cp);
    dir.put("audit.jsonl", line_cp);
    let c = load(vec![dir.0.clone()]);
    let segs = c.native_segments();
    let names: Vec<String> = segs
        .iter()
        .map(|s| s.path.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        names,
        vec![
            format!("{STAMP}_000000.jsonl"),
            format!("{STAMP}_000001.jsonl"),
            "audit.jsonl".to_owned(),
        ],
        "sealed segments come first in (stamp, counter) order; live last",
    );
}

#[test]
fn snapshot_native_segments_bytes_equal_file_contents() {
    // Ruling 13-V4-d5 (b): a native segment's `bytes` is the
    // whole file exactly as it was on disk when `collect` ran
    // (the one-snapshot rule, 13-V3-d2). Literal row: write
    // fixtures with known byte contents and assert
    // `native_segments().bytes` matches byte for byte, and pin
    // `is_live` on each entry so this row is also a killer for
    // a mutation that drops the `is_live` discrimination (a
    // second one beyond
    // `snapshot_native_segments_is_live_true_only_on_audit_jsonl`).
    // Any retention path that drops bytes (e.g. an off-by-one
    // truncation) also fails on the bytes comparison.
    let dir = Dir::new();
    let sealed_bytes = b"line-one\nline-two\n";
    let live_bytes = b"live-only\n";
    dir.put(&format!("{STAMP}_000000.jsonl"), sealed_bytes);
    dir.put("audit.jsonl", live_bytes);
    let c = load(vec![dir.0.clone()]);
    let segs = c.native_segments();
    let got: Vec<(Vec<u8>, bool)> = segs.iter().map(|s| (s.bytes.to_vec(), s.is_live)).collect();
    assert_eq!(
        got,
        vec![(sealed_bytes.to_vec(), false), (live_bytes.to_vec(), true),],
        "native_segments bytes must equal the file contents on \
         disk and is_live must pin per segment",
    );
}

#[test]
fn snapshot_native_segments_input_index_pins_order_on_multi_native_dir() {
    // Ruling 13-V4-d5 (a): `NativeSegment.input_index` is the
    // position in [`Collection::inputs`] of the backing native
    // `Input`. Literal row: a directory with two sealed segments
    // and the live file yields three natives, whose `input_index`
    // must be 0, 1, 2 (natives sort to the front of `Collection::
    // inputs`). Kills a mutant that sets `input_index := 0` on
    // every emitted `NativeSegment` (the `1` and `2` rows no
    // longer match).
    let dir = Dir::new();
    let line_cp = checkpoint_line();
    dir.put(&format!("{STAMP}_000000.jsonl"), line_cp);
    dir.put(&format!("{STAMP}_000001.jsonl"), line_cp);
    dir.put("audit.jsonl", line_cp);
    let c = load(vec![dir.0.clone()]);
    let segs = c.native_segments();
    let indices: Vec<usize> = segs.iter().map(|s| s.input_index).collect();
    assert_eq!(
        indices,
        vec![0, 1, 2],
        "input_index tracks `Collection::inputs` order for natives",
    );
    // Cross-check: each `NativeSegment.input_index` resolves to
    // the native `Input` of the same path.
    for seg in &segs {
        assert_eq!(c.inputs[seg.input_index].path, seg.path);
        assert!(c.inputs[seg.input_index].native);
    }
}

#[test]
fn snapshot_native_segments_input_index_literal_with_shipped_siblings() {
    // Ruling 13-V4-d5 (a): shipped inputs are filtered out of the
    // emitted `NativeSegment` vec, but the retained `input_index`
    // is the index into the (unfiltered) `Collection::inputs`.
    // Literal row: two native sealed segments plus two shipped
    // paths; `input_index` is pinned to [0, 1] on the natives,
    // and `c.inputs` at those indices resolves to the natives.
    // Independently of
    // `snapshot_native_segments_input_index_pins_order_on_multi_native_dir`
    // because this one runs through the `copy` explicit-paths arm
    // and `collect`'s merge over directories + files.
    let a = Dir::new();
    let b = Dir::new();
    a.put(&format!("{STAMP}_000000.jsonl"), checkpoint_line());
    a.put(&format!("{STAMP}_000001.jsonl"), checkpoint_line());
    let shipped_one = b.0.join("shipped-one");
    fs::write(&shipped_one, checkpoint_line()).unwrap();
    let shipped_two = b.0.join("shipped-two");
    fs::write(&shipped_two, checkpoint_line()).unwrap();
    let c = load(vec![a.0.clone(), shipped_one.clone(), shipped_two.clone()]);
    // Inputs ordered: natives (rank 0) first, then shipped (rank 2).
    assert_eq!(c.inputs.len(), 4, "two natives + two shipped survive");
    let natives_and_flags: Vec<(bool, bool)> = c
        .inputs
        .iter()
        .map(|i| (i.native, i.data.bytes.is_some()))
        .collect();
    assert_eq!(
        natives_and_flags,
        vec![(true, true), (true, true), (false, false), (false, false)],
        "natives retain bytes; distinct-inode shipped paths do not",
    );
    let segs = c.native_segments();
    assert_eq!(
        segs.iter()
            .map(|s| (s.input_index, s.is_live))
            .collect::<Vec<_>>(),
        vec![(0, false), (1, false)],
        "native_segments emits input_index [0, 1] after the filter",
    );
    for seg in &segs {
        assert_eq!(c.inputs[seg.input_index].path, seg.path);
    }
}

#[test]
fn snapshot_collect_live_closed_run_pins_final_state_length_byte_exact() {
    // A second, distinct killer for a retained-bytes truncation
    // mutant on [`decode`] (beyond
    // `snapshot_native_segments_bytes_equal_file_contents`): a
    // live-present closed-run snapshot whose `final_state.length`
    // is pinned to the live file's byte count as measured on
    // disk. The live arm's `scan_closing` builds
    // `State.length = SegmentBytes.offset_cursor`, which is the
    // byte count consumed from the live segment's
    // `ByteSource::Memory` wrapper over the retained `Rc<[u8]>`.
    // Any retention path that drops bytes (e.g. an off-by-one
    // truncation) makes `offset_cursor` end one byte short, so
    // this literal `final_state.length == live_len` assertion
    // fires. The row also pins the clean-run invariants on this
    // fixture: `violations` empty, `head_mismatch` false, the
    // per-segment `(class, damage)` sequence, and the one
    // `RunReport`'s fields.
    use crate::audit::Mmr;
    use crate::audit::format::Record;
    use crate::audit::runs::SegmentClass;
    use crate::audit::storage::Head;
    use crate::audit::storage::tests as st;
    let dir = st::Temp::new();
    // S0 base + S1 headless (archive), live: closer + resume.
    let base = st::runs::signed(0, Record::genesis(&[17; 16]), &Mmr::new());
    st::runs::put(&dir, 0, &[&base], &[]);
    let r = st::runs::headless(&base, 5);
    let mut fold = st::seeded(&base);
    fold.push(r.hash()).unwrap();
    st::runs::put(&dir, 1, &[&r], &[]);
    let (closer, _resume) = st::runs::close_run(&dir, &r, &fold);
    let live_path = dir.0.join("audit.jsonl");
    let live_len = fs::metadata(&live_path).unwrap().len();
    let c = load(vec![dir.0.clone()]);
    let segs = c.native_segments();
    assert_eq!(
        segs.iter()
            .map(|s| (s.input_index, s.is_live))
            .collect::<Vec<_>>(),
        vec![(0, false), (1, false), (2, true)],
        "two sealed natives + live, in Collection::inputs order",
    );
    let out = classify_snapshot(&segs);
    // Clean closed run: no violations, no head mismatch.
    assert_eq!(out.violations, vec![], "clean closed run");
    assert!(!out.head_mismatch);
    // Per-segment (class, damage): S0 Base, S1 InRun, live Closer.
    let classes: Vec<(SegmentClass, bool)> =
        out.segments.iter().map(|s| (s.class, s.damage)).collect();
    assert_eq!(
        classes,
        vec![
            (SegmentClass::Base, false),
            (SegmentClass::InRun, false),
            (SegmentClass::Closer, false),
        ],
    );
    // Exactly one RunReport, closing at the live closer.
    assert_eq!(out.runs.len(), 1);
    let report = &out.runs[0];
    assert_eq!(report.first_segment, 1);
    assert_eq!(report.last_segment, 2);
    assert_eq!(report.closing_opening, Some(Head::of(&closer)));
    assert_eq!(report.loss_points.len(), 1);
    assert_eq!(report.loss_points[0].loss_seq, r.context.seq);
    // Byte-exact pin: `final_state.length` equals the live file's
    // on-disk byte count. A retained-bytes truncation mutant makes
    // this length one short.
    let final_state = out
        .final_state
        .as_ref()
        .expect("live-present snapshot has final_state");
    assert_eq!(
        final_state.length, live_len,
        "final_state.length equals the live file's byte count on disk",
    );
    assert!(
        final_state.tail_newline(),
        "live file ends with LF; a truncated last byte would flip this",
    );
}
