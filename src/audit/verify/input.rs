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

/// Authenticated identity and bounded context, never the full entry payload.
pub(super) struct Summary {
    pub(super) trail: [u8; 16],
    pub(super) seq: u64,
    pub(super) hash: [u8; 32],
    pub(super) previous: [u8; 32],
    pub(super) time: u64,
    pub(super) repaired: Option<[u8; 32]>,
    pub(super) checkpoint: Option<CheckpointFields>,
    // Only reserved records need text for #13 V3b resume/fragment context.
    #[cfg_attr(not(test), expect(dead_code, reason = "located context for #13 V3b"))]
    pub(super) operator: Option<Operator>,
    pub(super) line: u64,
}
impl Summary {
    fn new(record: Record, line: u64) -> Self {
        let hash = record.hash();
        let (checkpoint, operator) = match record.kind {
            Kind::Checkpoint(fields) => (Some(fields), None),
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
        }
    }
}

pub(super) enum LineContent {
    /// Indices into physical-order summaries, for native neighbour context.
    Records(Range<usize>),
    Invalid(AuditError),
    Unparsable(AuditError),
    /// Provisional only: #13 V3b decides fragment conditions 1 and 3.
    Fragment,
}
pub(super) struct LineItem {
    #[cfg_attr(not(test), expect(dead_code, reason = "located context for #13 V3b"))]
    pub(super) bytes: Range<usize>,
    pub(super) line: u64,
    pub(super) content: LineContent,
}
pub(super) struct Data {
    pub(super) records: Vec<Summary>,
    pub(super) items: Vec<LineItem>,
    pub(super) spans: Vec<Span>,
}
pub(super) struct Input {
    pub(super) path: PathBuf,
    pub(super) native: bool,
    pub(super) data: Rc<Data>,
}
pub(super) struct Collection {
    /// Native segment order, live last, then shipped paths.
    pub(super) inputs: Vec<Input>,
    /// (input index, summary index), sorted across shipped files and batches.
    pub(super) shipped: Vec<(usize, usize)>,
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
fn decode(file: File) -> io::Result<Data> {
    let mut data = Data {
        records: Vec::new(),
        items: Vec::new(),
        spans: Vec::new(),
    };
    data.spans = lines::stream(BufReader::new(file), 0, |item| {
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
            bytes: item.bytes,
            line: item.line,
            content,
        });
    })?;
    Ok(data)
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
                let data = Rc::new(decode(file)?);
                local.insert(inode, data.clone());
                data
            }
        };
        inputs.push((
            inode,
            Input {
                native: native(&path),
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
