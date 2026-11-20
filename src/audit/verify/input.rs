//! Private, collecting input pipeline for #13 V3a-2.
//! Per ruling 13-V3-d2, each directory returns exactly its confirmed snapshot;
//! discarded attempts leave no data or obligations. No global atomicity, settlement or locks:
//! open or record once before reviewing a crashed trail; strict live review
//! must target a stopped trail because an in-flight append can look torn.
use super::lines::{self, Content, Span};
use crate::{
    audit::{AuditError, AuditErrorKind, CheckpointFields, Record, format::Kind},
    rotate,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, BufReader},
    ops::Range,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    rc::Rc,
};

type Inode = (u64, u64);
type Operator = (String, String, Option<String>, Option<String>);

/// A checkpoint record's signed body as the verifier retains it: the
/// checkpoint fields plus `checkpoint_message(unsigned_fields)`,
/// pre-computed from the one snapshot so `verify::signatures` never
/// re-reads or re-parses the trail bytes (ruling 13-V4-d5). Carrying
/// both in one struct makes the invariant structural: the signing
/// message is present iff the summary is for a checkpoint.
pub(super) struct SignedCheckpoint {
    pub(super) fields: CheckpointFields,
    pub(super) signing_message: Vec<u8>,
}

/// Authenticated identity and bounded context, never the full entry payload.
pub(super) struct Summary {
    pub(super) trail: [u8; 16],
    pub(super) seq: u64,
    pub(super) hash: [u8; 32],
    pub(super) previous: [u8; 32],
    pub(super) time: u64,
    pub(super) repaired: Option<[u8; 32]>,
    pub(super) checkpoint: Option<SignedCheckpoint>,
    // Only reserved records need text for #13 V3b resume/fragment context.
    pub(super) operator: Option<Operator>,
    pub(super) line: u64,
    /// `true` iff this record belongs to the in-memory end-record
    /// segment the verifier appended after the files (ruling 13-V6-d4
    /// points 1, 3 and 6). Written where the end-record input is
    /// built ([`end_record_input`]) and nowhere else; the engine and
    /// [`super::first_copy`] read it as the primary sort key so file
    /// copies always sort before the end-record copy at a shared
    /// `seq`, and [`super::end_before::check`] reads it to pick the
    /// first file copy for [`FindingKind::TrailEnded`].
    pub(super) is_end_record: bool,
}
impl Summary {
    fn new(record: Record, line: u64) -> Self {
        let hash = record.hash();
        let signing_message = record.signing_message();
        let (checkpoint, operator) = match record.kind {
            Kind::Checkpoint(fields) => (
                Some(SignedCheckpoint {
                    fields,
                    signing_message: signing_message
                        .expect("checkpoint record exposes its signing message"),
                }),
                None,
            ),
            Kind::Entry(entry) => (
                None,
                entry.action.starts_with("vigil.audit.").then_some((
                    entry.action,
                    entry.actor,
                    entry.reason,
                    entry.details,
                )),
            ),
        };
        Self {
            trail: record.context.trail,
            seq: record.context.seq,
            hash,
            previous: record.context.previous,
            time: record.context.time,
            repaired: record.context.repaired,
            checkpoint,
            operator,
            line,
            is_end_record: false,
        }
    }
}

pub(super) enum LineContent {
    /// Indices into physical-order summaries, for native neighbour context.
    Records(Range<usize>),
    Invalid(AuditError),
    Unparsable(AuditError),
    /// Native fragment line; condition 3 is decided per run in `engine::check`.
    Fragment,
}
pub(super) struct LineItem {
    pub(super) line: u64,
    pub(super) content: LineContent,
}
pub(super) struct Data {
    pub(super) records: Vec<Summary>,
    pub(super) items: Vec<LineItem>,
    pub(super) spans: Vec<Span>,
    /// Rulings 13-V3-d2 and 13-V4-d5 (b): the verifier's confirmed
    /// snapshot is read once. On native inputs the raw bytes are
    /// retained here so V4a's one classify pass drives
    /// [`crate::audit::storage::SegmentSource::for_snapshot`] over
    /// them without re-opening the file. Shipped inputs are out of
    /// the classifier's scope and `decode` would set `bytes` to
    /// `None` on them if decoded in isolation; a shipped path that
    /// hard-links to an already-decoded native path (same inode)
    /// shares the native's `Rc<Data>` through the inode cache, so it
    /// also sees `bytes = Some(...)` here. That is fine: only
    /// `native_segments` reads `bytes`, and it filters to
    /// `input.native` paths. Known cost: one `Rc<[u8]>` of segment
    /// size per native segment stays alive for the verification
    /// (the price of the one-snapshot rule).
    pub(super) bytes: Option<Rc<[u8]>>,
}
pub(super) struct Input {
    pub(super) path: PathBuf,
    pub(super) native: bool,
    /// `true` iff this input is the in-memory end-record segment
    /// [`end_record_input`] built. The engine reads this to find the
    /// end-record input in [`Collection::inputs`] when unlocating
    /// end-record findings (ruling 13-V6-d4 point 6), and
    /// [`Summary::is_end_record`] mirrors it on each record.
    pub(super) is_end_record: bool,
    pub(super) data: Rc<Data>,
}
pub(super) struct Collection {
    /// Native segment order, live last, then shipped paths.
    pub(super) inputs: Vec<Input>,
    /// (input index, summary index), sorted across shipped files and batches.
    pub(super) shipped: Vec<(usize, usize)>,
}

/// Rulings 13-V4-d5 (a) and (b): one native segment the V4a classify
/// pass walks, in `Collection::inputs` order. V4a feeds a slice of
/// these into
/// [`crate::audit::storage::SegmentSource::for_snapshot`] so the
/// confirmed snapshot is classified in a single pass with no
/// re-listing and no re-open of the trail directory (ruling 13-V3-d2).
/// Shipped inputs are out of scope: the classifier's fold runs over
/// native segments only (ruling 13-V4-d5 (a)); shipped inputs feed
/// `engine::check`'s record-level cross-copy checks instead.
/// Consumed by [`super::fold::check_runs`] (#13 V4a).
pub(super) struct NativeSegment {
    /// The native input's path, for diagnostics. Not opened by
    /// `for_snapshot`; carried alongside the bytes.
    pub(super) path: PathBuf,
    /// Bytes retained by [`decode`] under `keep_bytes = native(path)`.
    pub(super) bytes: Rc<[u8]>,
    /// `true` iff this is the live input (file name `audit.jsonl`).
    /// Ruling 13-V4-d5 (b): a snapshot with no live file (`is_live`
    /// `false` on every entry) is the archive case.
    pub(super) is_live: bool,
    /// Index into [`Collection::inputs`]. [`super::fold::check_runs`]
    /// reads this to recover each segment's first complete record
    /// `(line, seq)` on the verified trail (ruling 13-V4-d5 (a),
    /// 13-V4-d8 point 5); the classifier's own per-segment outputs
    /// keep a parallel index by construction (both arrays are
    /// driven by this same `Vec`).
    pub(super) input_index: usize,
}

impl Collection {
    /// Rulings 13-V4-d5 (a) and (b): the V4a classify pass's input --
    /// native inputs only, in [`Collection::inputs`] order (per-trail
    /// filtering happens inside [`crate::audit::runs::classify`]).
    /// Shipped inputs are excluded (ruling 13-V4-d5 (a); they do not
    /// flow through the classifier). The returned vec drives
    /// [`crate::audit::storage::SegmentSource::for_snapshot`] from
    /// [`super::fold::check_runs`].
    pub(super) fn native_segments(&self) -> Vec<NativeSegment> {
        self.inputs
            .iter()
            .enumerate()
            .filter(|(_, input)| input.native)
            .map(|(input_index, input)| NativeSegment {
                path: input.path.clone(),
                // Invariant that makes the `expect` unreachable in
                // production: `copy` sorts paths by `key` before it
                // decodes them (shipped `rank = 2`, so every native
                // path is decoded first), and `decode` is called with
                // `keep_bytes = native(path)`, so every inode a
                // native path visits is first decoded with retention
                // on. A later shipped path that hard-links to the
                // same inode shares the native's `Rc<Data>` through
                // the inode cache, so its `data.bytes` is also
                // `Some` -- the only way an `Input` with `native =
                // true` can have `data.bytes = None` is if a mutant
                // bypassed the filter, which is exactly what this
                // `expect` catches for M-SNAP-7.
                bytes: input
                    .data
                    .bytes
                    .as_ref()
                    .map(Rc::clone)
                    .expect("native input retained bytes in decode(keep_bytes=true)"),
                is_live: input.path.file_name().is_some_and(|n| n == "audit.jsonl"),
                input_index,
            })
            .collect()
    }
}

fn native(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n == "audit.jsonl" || rotate::parse_segment(n, "audit").is_some())
}
fn key(path: &Path) -> (u8, (String, u64), PathBuf) {
    let rank = if !native(path) {
        2
    } else if path.file_name().is_some_and(|n| n == "audit.jsonl") {
        1
    } else {
        0
    };
    (rank, rotate::segment_key(path, "audit"), path.to_owned())
}
fn decode(file: File, keep_bytes: bool) -> io::Result<Data> {
    let bytes: Option<Rc<[u8]>> = if keep_bytes {
        let mut raw = Vec::new();
        {
            let mut handle = &file;
            io::Read::read_to_end(&mut handle, &mut raw)?;
        }
        Some(Rc::from(raw.into_boxed_slice()))
    } else {
        None
    };
    match &bytes {
        Some(buf) => stream_into_data(io::Cursor::new(Rc::clone(buf)), Some(Rc::clone(buf))),
        None => stream_into_data(BufReader::new(file), None),
    }
}

fn stream_into_data(reader: impl io::BufRead, retain: Option<Rc<[u8]>>) -> io::Result<Data> {
    let mut data = Data {
        records: Vec::new(),
        items: Vec::new(),
        spans: Vec::new(),
        bytes: None,
    };
    let mut emit = |item: lines::Item| {
        let content = match item.content {
            Content::Records(records) => {
                let start = data.records.len();
                data.records
                    .extend(records.into_iter().map(|r| Summary::new(r, item.line)));
                LineContent::Records(start..data.records.len())
            }
            Content::Invalid(e) => LineContent::Invalid(e),
            Content::Unparsable(e) => LineContent::Unparsable(e),
            Content::Fragment => LineContent::Fragment,
        };
        data.items.push(LineItem {
            line: item.line,
            content,
        });
    };
    data.spans = lines::stream(reader, 0, &mut emit)?;
    data.bytes = retain;
    Ok(data)
}

/// Builds an in-memory native [`Input`] for the `end_before`
/// archive record so the shared classifier walks it as the segment
/// that follows the files (ruling 13-V6-d4 point 1). The returned
/// [`Input`] and every [`Summary`] it carries are marked
/// [`Summary::is_end_record`]/[`Input::is_end_record`], so the
/// engine and [`super::first_copy`] sort file copies ahead of them
/// at any shared `seq` and [`super::end_before::check`] can pick a
/// file copy for [`FindingKind::TrailEnded`] without consulting the
/// path. The `file_name` of `path` is `None` so `native_segments`
/// picks it up as sealed (`is_live = false`).
pub(super) fn end_record_input(bytes: Vec<u8>, path: PathBuf) -> Input {
    let rc: Rc<[u8]> = Rc::from(bytes.into_boxed_slice());
    let mut data = stream_into_data(io::Cursor::new(Rc::clone(&rc)), Some(rc))
        .expect("in-memory Cursor reads are infallible");
    for record in &mut data.records {
        record.is_end_record = true;
    }
    Input {
        path,
        native: true,
        is_end_record: true,
        data: Rc::new(data),
    }
}

/// Appends an in-memory native input to an already-built
/// [`Collection`] and sets its spans' `seg` to its new position.
pub(super) fn append_native(collection: &mut Collection, mut input: Input) {
    let seg = u32::try_from(collection.inputs.len()).expect("too many native segments");
    let data = Rc::get_mut(&mut input.data).expect("appended end-record input owns its data");
    for span in &mut data.spans {
        span.seg = seg;
    }
    collection.inputs.push(input);
}

/// Reads each inode once within a successful snapshot. Failed attempts own all
/// tentative data; none enters the cache until the retry protocol succeeds.
fn copy(
    paths: &[PathBuf],
    cache: &BTreeMap<Inode, Rc<Data>>,
    #[cfg(test)] mut before_open: impl FnMut(&Path) -> io::Result<()>,
) -> io::Result<Vec<(Inode, Input)>> {
    let mut local = cache.clone();
    let mut inputs = Vec::new();
    let mut paths = paths.to_vec();
    paths.sort_by_key(|p| key(p));
    for path in paths {
        #[cfg(test)]
        before_open(&path)?;
        let file = File::open(&path)?;
        let meta = file.metadata()?;
        let inode = (meta.dev(), meta.ino());
        let data = match local.get(&inode) {
            Some(data) => data.clone(),
            None => {
                // Ruling 13-V4-d5 (a): V4a classifies only native
                // segments; retain bytes there and skip the extra
                // memory cost on shipped inputs.
                let keep_bytes = native(&path);
                let data = Rc::new(decode(file, keep_bytes)?);
                local.insert(inode, data.clone());
                data
            }
        };
        inputs.push((
            inode,
            Input {
                native: native(&path),
                is_end_record: false,
                path,
                data,
            },
        ));
    }
    Ok(inputs)
}

pub(super) fn collect(paths: impl IntoIterator<Item = PathBuf>) -> Result<Collection, AuditError> {
    collect_with(
        paths,
        #[cfg(test)]
        |_, _| Ok(()),
        #[cfg(test)]
        |_, _| Ok(()),
        #[cfg(test)]
        |_| Ok(()),
    )
}

// Deterministic per-attempt hook, private to this module and its tests.
fn collect_with(
    paths: impl IntoIterator<Item = PathBuf>,
    #[cfg(test)] mut before_copy: impl FnMut(&Path, usize) -> io::Result<()>,
    #[cfg(test)] mut after_copy: impl FnMut(&Path, usize) -> io::Result<()>,
    #[cfg(test)] mut before_open: impl FnMut(&Path) -> io::Result<()>,
) -> Result<Collection, AuditError> {
    let mut directories = BTreeSet::new();
    let mut files = BTreeSet::new();
    for path in paths {
        if fs::metadata(&path).map_err(AuditError::from_io)?.is_dir() {
            directories.insert(path);
        } else {
            files.insert(path);
        }
    }
    let mut cache = BTreeMap::new();
    let mut selected: BTreeMap<Inode, Input> = BTreeMap::new();
    for directory in directories {
        #[cfg(test)]
        let mut attempt = 0;
        let inputs = rotate::retry_snapshot(
            &directory,
            "audit",
            |paths| {
                #[cfg(test)]
                {
                    attempt += 1;
                    before_copy(&directory, attempt)?;
                }
                // Native read errors are tentative until retry_snapshot confirms
                // the listing. A rotation can move a listed inode before open.
                let result = copy(
                    paths,
                    &cache,
                    #[cfg(test)]
                    &mut before_open,
                );
                #[cfg(test)]
                {
                    after_copy(&directory, attempt)?;
                }
                Ok(result)
            },
            |_| {
                Err(io::Error::other(
                    "audit snapshot changed during all eight attempts",
                ))
            },
        )
        .and_then(|result| result)
        .map_err(AuditError::from_io)?;
        merge(inputs, &mut cache, &mut selected);
    }
    let explicit = copy(
        &files.into_iter().collect::<Vec<_>>(),
        &cache,
        #[cfg(test)]
        |_| Ok(()),
    )
    .map_err(AuditError::from_io)?;
    merge(explicit, &mut cache, &mut selected);
    drop(cache);
    let mut inputs: Vec<_> = selected.into_values().collect();
    inputs.sort_by_key(|input| key(&input.path));
    let mut names = BTreeSet::new();
    for input in &inputs {
        if input.native && !names.insert(input.path.file_name().unwrap()) {
            return Err(AuditError::new(
                AuditErrorKind::InvalidConfig,
                format!("duplicate vigil input name: {}", input.path.display()),
            ));
        }
    }
    let mut shipped = Vec::new();
    for (i, input) in inputs.iter_mut().enumerate() {
        let data = Rc::get_mut(&mut input.data).expect("deduplicated input owns its data");
        if input.native {
            for span in &mut data.spans {
                span.seg = u32::try_from(i).map_err(|_| {
                    AuditError::new(AuditErrorKind::InvalidConfig, "too many native segments")
                })?;
            }
        } else {
            data.spans.clear();
            shipped.extend((0..data.records.len()).map(|r| (i, r)));
        }
    }
    shipped.sort_by_key(|&(i, r)| {
        let record = &inputs[i].data.records[r];
        (record.seq, &inputs[i].path, record.line, record.hash)
    });
    Ok(Collection { inputs, shipped })
}
fn merge(
    inputs: Vec<(Inode, Input)>,
    cache: &mut BTreeMap<Inode, Rc<Data>>,
    selected: &mut BTreeMap<Inode, Input>,
) {
    for (inode, input) in inputs {
        cache.insert(inode, input.data.clone());
        if selected
            .get(&inode)
            .is_none_or(|old| key(&input.path) < key(&old.path))
        {
            selected.insert(inode, input);
        }
    }
}

#[cfg(test)]
#[path = "input_tests.rs"]
mod tests;
