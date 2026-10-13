//! Read-side state for #11. B2b settles staging files and checks the marker
//! before invoking this boundary; it also owns repair writes and durability.
//! This module never creates a data file, writes bytes or checks signatures.
//! Cached records are not revalidated after same-length in-place rewrites
//! (ADR-0005 decision 8); offline verification (#13) detects such changes.
//! Refresh also skips segment contents named at or before the retained old live
//! inode (or its cached filename bound if archived). Inserting a forged older
//! segment can therefore pass refresh while fresh open rejects it; fresh open
//! scans all present history. The cache does not authenticate historical edits.
use super::{
    AuditError, AuditErrorKind, Record,
    format::{Kind, validation::MAX_PAYLOAD_BYTES},
};
use crate::{audit::Mmr, rotate::Directory};
use rustix::fs::{self as rfs, Mode, OFlags};
use std::{
    fs::File,
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Mutex,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Head {
    pub(crate) seq: u64,
    pub(crate) hash: [u8; 32],
}
impl Head {
    fn of(record: &Record) -> Self {
        Self {
            seq: record.context.seq,
            hash: record.hash(),
        }
    }
}

/// State after the last complete record. The offset precedes any torn gap,
/// so a later refresh re-reads the entire gap before checking its attestation.
#[derive(Clone)]
pub(crate) struct State {
    pub(crate) head: Head,
    pub(crate) mmr: Mmr,
    offset: u64,
    pub(crate) length: u64,
    checkpoint: bool,
    pub(crate) checkpoint_time: u64,
    pub(crate) since_checkpoint: u64,
    newline: bool,
    gap: Option<blake3::Hasher>,
    pending_resume: bool,
    // A broken hash link in the pending run, cleared by its closing resume.
    run_loss: bool,
    checkpoint_predecessor: Option<Head>,
    checkpoint_previous: [u8; 32],
}
impl State {
    /// Advances from known writer output, never from a reread of our own bytes.
    pub(crate) fn after(&self, record: &Record, length: u64) -> Result<Self, AuditError> {
        let mut next = Some(self.clone());
        apply(record, &mut next, false)?;
        let mut next = next.ok_or_else(|| corrupt("missing written state"))?;
        next.offset = length;
        next.length = length;
        Ok(next)
    }
    /// Includes the repair LF that B2b will prepend to an unterminated tail.
    pub(crate) fn repair_digest(&self) -> Option<[u8; 32]> {
        self.gap.as_ref().map(|gap| {
            let mut gap = gap.clone();
            if !self.newline {
                gap.update(b"\n");
            }
            *gap.finalize().as_bytes()
        })
    }
    pub(crate) fn needs_newline(&self) -> bool {
        !self.newline
    }
}
pub(crate) struct Cache {
    // Last sealed name observed when this live descriptor was acquired.
    sealed_before: Option<PathBuf>,
    file: File,
    state: State,
}

/// Retains the old live descriptor across rotations, preventing inode reuse.
/// Reader handles across a resume may error; reopen to validate the new trail.
/// Lock order: directory gate/flock, then cache; never acquire a telemetry
/// directory lock inside this section (ADR-0002 d3/d7/d13, ADR-0005 d2/d8).
pub(crate) struct TrailReader {
    directory: Directory,
    trail: [u8; 16],
    cache: Mutex<Cache>,
}
impl TrailReader {
    /// Reads the marker, settles staging and scans in one acquisition.
    /// Damaged sealed runs require the matching checkpoint/resume and cumulative
    /// fold of ADR-0005 amendment 6: an explicit writer/verifier exception.
    /// A forged archived checkpoint/resume pair can pass without signature trust;
    /// verification must detect BadSignature/NoReceipt. Empty segments can be
    /// inserted into a run, and record-free evidence removed, without changing
    /// the fold because file= is informational.
    pub(crate) fn open_marked(
        path: &Path,
        expected: Option<Head>,
        prepare: impl FnOnce(&File) -> Result<[u8; 16], AuditError>,
    ) -> Result<Self, AuditError> {
        let directory = Directory::open(path).map_err(io_error)?;
        let (trail, cache) = directory
            .with_lock(|dir| {
                let trail = prepare(dir)?;
                Ok::<_, AuditError>((trail, initial(dir, trail, expected)?))
            })
            .map_err(io_error)??;
        Ok(Self {
            directory,
            trail,
            cache: Mutex::new(cache),
        })
    }
    /// Scans an existing trail after B2b's staging settlement. `trail` comes
    /// from the checked marker. No signature trust is inferred from disk.
    /// ADR-0005 amendment 6 deliberately permits damaged sealed runs that the
    /// verifier reports, only when a matching immediate resume and the cumulative
    /// MMR fold close the run. State is never reset at a damaged boundary.
    /// A forged archived checkpoint/resume pair can still pass this reader;
    /// verification reports BadSignature/NoReceipt. Inserting empty segments into
    /// a run, or removing record-free segments or unparsable bytes, leaves the
    /// fold unchanged (file= is informational).
    pub(crate) fn open(
        path: &Path,
        trail: [u8; 16],
        expected: Option<Head>,
    ) -> Result<Self, AuditError> {
        Self::open_with(path, trail, expected, |_| Ok(()))
    }

    /// B2b supplies staging settlement under the acquisition used for scanning.
    pub(crate) fn open_with(
        path: &Path,
        trail: [u8; 16],
        expected: Option<Head>,
        settle: impl FnOnce(&File) -> Result<(), AuditError>,
    ) -> Result<Self, AuditError> {
        let directory = Directory::open(path).map_err(io_error)?;
        let cache = directory
            .with_lock(|dir| {
                settle(dir)?;
                initial(dir, trail, expected)
            })
            .map_err(io_error)??;
        Ok(Self {
            directory,
            trail,
            cache: Mutex::new(cache),
        })
    }

    /// Operator boundary: settlement and a full history scan under one lock.
    /// Unlike refresh, this observes same-length rewrites of cached records.
    pub(crate) fn with_initial<T>(
        &self,
        bound: Option<Head>,
        prepare: impl FnOnce(&File) -> Result<(), AuditError>,
        f: impl FnOnce(&File, &File, &State, Option<Record>) -> Result<T, AuditError>,
    ) -> Result<T, AuditError> {
        self.directory
            .with_lock(|dir| {
                prepare(dir)?;
                let (cache, record) = initial_record(dir, self.trail, bound)?;
                f(dir, &cache.file, &cache.state, record)
            })
            .map_err(io_error)?
    }

    /// B2b's append boundary: recheck the live inode and validate every newly
    /// observed record before handing the current descriptor to the writer.
    /// B2b must settle staging *inside this same directory lock*, before refresh;
    /// the callback provides that seam without nesting another flock. Reentering
    /// this directory lock fails with an I/O `WouldBlock` error.
    pub(crate) fn with_current<T>(
        &self,
        settle: impl FnOnce(&File) -> Result<(), AuditError>,
        f: impl FnOnce(&File, &mut File, &mut State) -> Result<T, AuditError>,
    ) -> Result<T, AuditError> {
        self.with_current_checked(
            settle,
            None::<fn(Option<u64>) -> Result<bool, AuditError>>,
            f,
        )
    }

    /// Writer boundary: discover declared loss before validating cached state.
    /// The sink decides whether discovery requires a full open-path rebuild.
    pub(crate) fn with_resumes<T>(
        &self,
        settle: impl FnOnce(&File) -> Result<(), AuditError>,
        decide: impl FnOnce(Option<u64>) -> Result<bool, AuditError>,
        f: impl FnOnce(&File, &mut File, &mut State) -> Result<T, AuditError>,
    ) -> Result<T, AuditError> {
        self.with_current_checked(settle, Some(decide), f)
    }

    fn with_current_checked<T>(
        &self,
        settle: impl FnOnce(&File) -> Result<(), AuditError>,
        decide: Option<impl FnOnce(Option<u64>) -> Result<bool, AuditError>>,
        f: impl FnOnce(&File, &mut File, &mut State) -> Result<T, AuditError>,
    ) -> Result<T, AuditError> {
        self.directory
            .with_lock(|dir| {
                settle(dir)?;
                let mut cache = self
                    .cache
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(decide) = decide
                    && decide(resumes_after(dir, self.trail, &cache)?)?
                {
                    *cache = initial(dir, self.trail, None)?;
                } else {
                    refresh(dir, self.trail, &mut cache)?;
                }
                let old = cache.file.metadata().map_err(io_error)?;
                let Cache { file, state, .. } = &mut *cache;
                let result = f(dir, file, state);
                let new = cache.file.metadata().map_err(io_error)?;
                if (old.dev(), old.ino()) != (new.dev(), new.ino()) {
                    cache.sealed_before = crate::rotate::rotated_names_at(dir, "audit")
                        .map_err(io_error)?
                        .pop();
                }
                let result = result?;
                // Writer callbacks retain known writes directly, including after a later
                // rename failure. This refresh also supports reader/test callbacks
                // that append without updating State; for writers it is a no-op.
                refresh(dir, self.trail, &mut cache)?;
                Ok(result)
            })
            .map_err(io_error)?
    }
}
fn corrupt(detail: &str) -> AuditError {
    AuditError::new(AuditErrorKind::CorruptTrail, detail)
}
fn io_error(error: io::Error) -> AuditError {
    AuditError::new(AuditErrorKind::Io, error.to_string())
}
pub(crate) fn existing(dir: &File, name: &Path, writable: bool) -> Result<File, AuditError> {
    let access = if writable {
        OFlags::RDWR | OFlags::APPEND
    } else {
        OFlags::RDONLY
    };
    rfs::openat(
        dir,
        name,
        access | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|e| {
        if matches!(
            e,
            rustix::io::Errno::NOENT | rustix::io::Errno::LOOP | rustix::io::Errno::ISDIR
        ) {
            corrupt("missing or nonregular trail file")
        } else {
            io_error(e.into())
        }
    })
    .and_then(|file| {
        if !file.metadata().map_err(io_error)?.is_file() {
            return Err(corrupt("nonregular trail file"));
        }
        Ok(file)
    })
}
fn initial(dir: &File, trail: [u8; 16], expected: Option<Head>) -> Result<Cache, AuditError> {
    initial_record(dir, trail, expected).map(|(cache, _)| cache)
}
fn initial_record(
    dir: &File,
    trail: [u8; 16],
    expected: Option<Head>,
) -> Result<(Cache, Option<Record>), AuditError> {
    #[cfg(test)]
    FULL_FOLDS.with(|count| count.set(count.get() + 1));
    let mut chain = None;
    let mut found = None;
    let mut run = false;
    let names = crate::rotate::rotated_names_at(dir, "audit").map_err(io_error)?;
    for name in &names {
        let file = existing(dir, name, false)?;
        chain = history_segment(&file, trail, chain, true, expected, &mut found, &mut run)?;
    }
    let file = existing(dir, Path::new("audit.jsonl"), true)?;
    let state = scan_closing(&file, trail, chain, expected, &mut found, run)?;
    if expected.is_some() && found.is_none() {
        return Err(AuditError::new(
            AuditErrorKind::HeadMismatch,
            "expected head absent or different",
        ));
    }
    Ok((
        Cache {
            file,
            state,
            sealed_before: names.last().cloned(),
        },
        found,
    ))
}
// Normal segments keep the single-pass strict path. Only damaged history, or
// history already inside a run, needs the amendment-6 exception. No records are
// buffered, and the cumulative MMR and cached head are never replaced by a later
// checkpoint's claimed peaks.
/// Folds a sealed predecessor without resetting state at damaged run boundaries.
/// The caller must validate a successor with `scan_staged` or `scan_closing`.
pub(crate) fn history_segment(
    file: &File,
    trail: [u8; 16],
    mut state: Option<State>,
    opening: bool,
    expected: Option<Head>,
    found: &mut Option<Record>,
    run: &mut bool,
) -> Result<Option<State>, AuditError> {
    // Decision 8 still applies when a malformed suffix makes the successor
    // enter the run fallback: a linking opening cannot defer its declaration.
    let unsealed_boundary = opening && state.as_ref().is_some_and(|s| !sealed(s));
    match scan_inner(
        file,
        trail,
        state.clone(),
        expected,
        found,
        SegmentContext {
            opening,
            genesis: false,
            run: *run,
        },
    ) {
        Ok(next) => {
            *run = false;
            return Ok(Some(next));
        }
        Err(error) if error.kind() == AuditErrorKind::CorruptTrail => {}
        Err(error) => return Err(error),
    }
    let inherited = *run || unsealed_boundary;
    *run = inherited;
    let mut damaged = false;
    let mut first = opening;
    let mut count = 0;
    let mut closing = false;
    let mut must_close = false;
    let mut prefix = false;
    let mut invalid_line = false;
    let mut gap = None::<blake3::Hasher>;
    let mut file = file.try_clone().map_err(io_error)?;
    let mut offset = if opening {
        0
    } else {
        state.as_ref().map_or(0, |s| s.offset)
    };
    file.seek(SeekFrom::Start(offset)).map_err(io_error)?;
    let mut reader = BufReader::new(file);
    if !opening
        && state
            .as_ref()
            .is_some_and(|s| !s.newline && s.gap.is_none())
    {
        let mut byte = [0];
        if reader.read(&mut byte).map_err(io_error)? == 1 {
            if byte != *b"\n" {
                return Err(corrupt("bytes glued to complete unterminated record"));
            }
            offset += 1;
        }
    }
    loop {
        let mut line = Vec::new();
        let bytes = reader
            .by_ref()
            .take(MAX_READ_BYTES)
            .read_until(b'\n', &mut line)
            .map_err(io_error)?;
        if bytes == 0 {
            break;
        }
        #[cfg(test)]
        SCANNED.with(|n| n.set(n.get() + bytes));
        offset += bytes as u64;
        let newline = line.ends_with(b"\n");
        let payload = line.strip_suffix(b"\n").unwrap_or(&line);
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(corrupt("audit line exceeds byte cap"));
        }
        let records = match Record::parse_line(payload) {
            Ok(records) => records,
            Err(error) if error.finding_kind() == Some(super::FindingKind::Unparsable) => {
                // A fragment-only segment and an Unparsable crash outcome are
                // retained evidence. Ordinary repair attestations still apply
                // to fragments between complete records in the same segment.
                if fragment(payload) {
                    if !first {
                        gap.get_or_insert_with(|| {
                            let mut hash = blake3::Hasher::new();
                            hash.update(b"vigil.audit.v1.repaired\0");
                            hash
                        })
                        .update(&line);
                    }
                } else {
                    damaged = true;
                    invalid_line = true;
                }
                if count == 0 {
                    prefix = true;
                }
                if count == 1 {
                    closing = false;
                }
                if let Some(s) = &mut state {
                    s.newline = newline;
                }
                continue;
            }
            Err(_) => return Err(corrupt("invalid audit record in sealed run")),
        };
        if records.len() != 1 {
            return Err(corrupt("multiple records in native audit line"));
        }
        let record = &records[0];
        if record.context.trail != trail {
            return Err(corrupt("trail identity differs from marker"));
        }
        if invalid_line {
            return Err(corrupt("unparsable line before complete record"));
        }
        if !(first || closing && count == 1)
            && state.as_ref().is_some_and(|s| s.head == Head::of(record))
        {
            if let Some(hash) = gap.take()
                && record.context.repaired != Some(*hash.finalize().as_bytes())
            {
                return Err(corrupt("missing or mismatched repair attestation"));
            }
            continue;
        }
        if state
            .as_ref()
            .is_some_and(|s| record.context.seq <= s.head.seq)
        {
            return Err(corrupt(
                "record sequence did not increase inside sealed run",
            ));
        }
        let broken = first
            && state
                .as_ref()
                .is_some_and(|s| record.context.previous != s.head.hash);
        if first && (!matches!(record.kind, Kind::Checkpoint(_)) || broken) {
            damaged = true;
        }
        // The first present complete record is the base, never the first
        // checkpoint found later in a headless segment.
        if state.is_none() && !matches!(record.kind, Kind::Checkpoint(_)) {
            return Err(corrupt("missing initial checkpoint"));
        }
        let outside_run = inherited && !*run;
        if !first
            && !outside_run
            && state
                .as_ref()
                .is_some_and(|s| record.context.seq != s.head.seq + 1)
        {
            return Err(corrupt("sequence gap inside sealed run segment"));
        }
        if let Some(hash) = gap.take()
            && record.context.repaired != Some(*hash.finalize().as_bytes())
        {
            return Err(corrupt("missing or mismatched repair attestation"));
        }
        if first {
            // A segment may close one run and, through damage later in the
            // same file, start another. Compare this checkpoint before treating
            // the remaining in-run checkpoints solely as leaves.
            let mut trial = state.clone();
            closing = inherited
                && !prefix
                && !damaged
                && apply(record, &mut trial, state.is_none()).is_ok();
            if inherited && matches!(record.kind, Kind::Checkpoint(_)) && !broken && !closing {
                return Err(corrupt("first successor does not close sealed run"));
            }
            must_close = closing;
        }
        let is_resume = matches!(&record.kind, Kind::Entry(e) if e.action == "vigil.audit.resume");
        if count == 1 && closing {
            // A complete second record resolves the EOF obligation; its kind
            // and declaration are checked independently before closing the run.
            must_close = false;
            if !is_resume {
                return Err(corrupt("first successor lacks immediate resume"));
            }
            *run = false;
        }
        let before_loss = !(broken || state.as_ref().is_some_and(|s| s.run_loss));
        apply_checked(
            record,
            &mut state,
            false,
            broken,
            outside_run || before_loss,
        )?;
        let s = state.as_mut().ok_or_else(|| corrupt("missing head"))?;
        if count == 1 && closing {
            s.run_loss = false;
        }
        if expected == Some(s.head) {
            *found = Some(record.clone());
        }
        s.offset = offset;
        s.newline = newline;
        first = false;
        count += 1;
    }
    if must_close && *run {
        return Err(corrupt("first successor lacks resume"));
    }
    if count == 0 {
        damaged = true;
    }
    if !damaged && !*run {
        return Err(corrupt("invalid undamaged segment"));
    }
    if damaged {
        *run = true;
    }
    if let Some(s) = &mut state {
        if s.pending_resume {
            return Err(corrupt("resume checkpoint lacks its declaration"));
        }
        s.length = offset;
        s.gap = gap;
    }
    Ok(state)
}
/// Validates a staging successor, requiring a genesis link without a predecessor
/// and an immediate resume when the predecessor history ends inside a run.
pub(crate) fn scan_staged(
    file: &File,
    trail: [u8; 16],
    state: Option<State>,
    run: bool,
) -> Result<State, AuditError> {
    scan_inner(
        file,
        trail,
        state,
        None,
        &mut None,
        SegmentContext {
            opening: true,
            genesis: true,
            run,
        },
    )
}
fn scan_closing(
    file: &File,
    trail: [u8; 16],
    state: Option<State>,
    expected: Option<Head>,
    found: &mut Option<Record>,
    run: bool,
) -> Result<State, AuditError> {
    scan_inner(
        file,
        trail,
        state,
        expected,
        found,
        SegmentContext {
            opening: true,
            genesis: false,
            run,
        },
    )
}
fn sealed(state: &State) -> bool {
    // A complete JSON checkpoint without LF is still a record (ADR-0005 d5).
    state.checkpoint && state.gap.is_none() && !state.pending_resume
}
/// Discovers the minimum declared loss bound using only two bounded header
/// records per file after the cached inode (or its retained sealed-name bound).
/// These records are not validated yet: a low bound can only fail closed, and
/// an accepted bound proceeds only through open's full validation (B3d2-d7).
/// Readers do not use this discovery path and retain refresh's strict checks.
pub(crate) fn resumes_after(
    dir: &File,
    trail: [u8; 16],
    cache: &Cache,
) -> Result<Option<u64>, AuditError> {
    let old = cache.file.metadata().map_err(io_error)?;
    let live = existing(dir, Path::new("audit.jsonl"), false)?;
    let current = live.metadata().map_err(io_error)?;
    // B3d2-d7: promotion gives live a new inode; the same inode has no
    // resume after our boundary and still goes through ordinary refresh.
    if (old.dev(), old.ino()) == (current.dev(), current.ino()) {
        return Ok(None);
    }
    let (names, _) = segments_after(dir, cache)?;
    let mut minimum = None;
    for name in &names {
        let file = existing(dir, name, false)?;
        if let Some(bound) = resume_header(&file, trail)? {
            minimum = Some(minimum.map_or(bound, |prior: u64| prior.min(bound)));
        }
    }
    if let Some(bound) = resume_header(&live, trail)? {
        minimum = Some(minimum.map_or(bound, |prior| prior.min(bound)));
    }
    Ok(minimum)
}

fn resume_details(details: &str) -> Result<(&str, &str, &str), AuditError> {
    let (named, file) = details
        .split_once(" file=")
        .ok_or_else(|| corrupt("invalid resume details"))?;
    let (named, lost) = named
        .split_once(" lost_through=")
        .ok_or_else(|| corrupt("invalid resume loss bound"))?;
    Ok((named, lost, file))
}

fn resume_header(file: &File, trail: [u8; 16]) -> Result<Option<u64>, AuditError> {
    let mut reader = BufReader::new(file);
    for index in 0..2 {
        let mut line = Vec::new();
        reader
            .by_ref()
            .take(MAX_READ_BYTES)
            .read_until(b'\n', &mut line)
            .map_err(io_error)?;
        let payload = line.strip_suffix(b"\n").unwrap_or(&line);
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Ok(None);
        }
        let Ok(records) = Record::parse_line(payload) else {
            return Ok(None);
        };
        let [record] = records.as_slice() else {
            return Ok(None);
        };
        if record.context.trail != trail {
            return Ok(None);
        }
        if index == 0 {
            if !matches!(record.kind, Kind::Checkpoint(_)) {
                return Ok(None);
            }
        } else if matches!(&record.kind, Kind::Entry(entry) if entry.action == "vigil.audit.resume")
        {
            // Validation binds lost_through to the immediately preceding
            // checkpoint's seq minus one. Parse the declared value here;
            // the full rebuild checks that equality and every other field.
            if let Kind::Entry(entry) = &record.kind {
                return Ok(entry
                    .details
                    .as_deref()
                    .and_then(|details| resume_details(details).ok())
                    .and_then(|(_, bound, _)| bound.parse().ok()));
            }
        }
    }
    Ok(None)
}

fn segments_after(
    dir: &File,
    cache: &Cache,
) -> Result<(Vec<PathBuf>, Option<PathBuf>), AuditError> {
    let old = cache.file.metadata().map_err(io_error)?;
    let names = crate::rotate::rotated_names_at(dir, "audit").map_err(io_error)?;
    let mut boundary = cache.sealed_before.clone();
    for name in &names {
        let metadata = rfs::statat(dir, name, rfs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| io_error(e.into()))?;
        if (metadata.st_dev as u64, metadata.st_ino as u64) == (old.dev(), old.ino()) {
            boundary = Some(name.clone());
            break;
        }
    }
    let newest = names.last().cloned();
    Ok((
        names
            .into_iter()
            .filter(|name| {
                boundary.as_ref().is_none_or(|b| {
                    crate::rotate::segment_key(name, "audit")
                        > crate::rotate::segment_key(b, "audit")
                })
            })
            .collect(),
        newest,
    ))
}

fn refresh(dir: &File, trail: [u8; 16], cache: &mut Cache) -> Result<(), AuditError> {
    let old = cache.file.metadata().map_err(io_error)?;
    let live = rfs::statat(dir, "audit.jsonl", rfs::AtFlags::SYMLINK_NOFOLLOW).map_err(|e| {
        if e == rustix::io::Errno::NOENT {
            corrupt("missing live file")
        } else {
            io_error(e.into())
        }
    })?;
    let mut found = None;
    if (old.dev(), old.ino()) == (live.st_dev as u64, live.st_ino as u64) {
        if old.len() < cache.state.length {
            return Err(corrupt("live file shrank below cached length"));
        }
        if old.len() > cache.state.length {
            cache.state = scan(
                &cache.file,
                trail,
                Some(cache.state.clone()),
                false,
                None,
                &mut found,
                false,
            )?;
        }
        return Ok(());
    }
    if old.len() < cache.state.length {
        return Err(corrupt("old live descriptor was truncated"));
    }
    let mut run = false;
    let mut state = history_segment(
        &cache.file,
        trail,
        Some(cache.state.clone()),
        false,
        None,
        &mut found,
        &mut run,
    )?;
    // Locate the old descriptor by metadata, never by rereading historical
    // contents. If archived, the previous sealed name remains a lower bound.
    let (names, newest) = segments_after(dir, cache)?;
    for name in &names {
        let file = existing(dir, name, false)?;
        state = history_segment(&file, trail, state, true, None, &mut found, &mut run)?;
    }
    let file = existing(dir, Path::new("audit.jsonl"), true)?;
    let state = scan_closing(&file, trail, state, None, &mut found, run)?;
    *cache = Cache {
        file,
        state,
        sealed_before: newest,
    };
    Ok(())
}

const MAX_READ_BYTES: u64 = MAX_PAYLOAD_BYTES as u64 + 2; // LF plus one excess byte.

/// Bounded reads: each payload is capped even when it is only a fragment.
/// `genesis` requires a root link when no predecessor exists (staging settlement).
/// Otherwise decision 2 permits a self-contained archived prefix checkpoint.
pub(crate) fn scan(
    file: &File,
    trail: [u8; 16],
    state: Option<State>,
    opening: bool,
    expected: Option<Head>,
    found: &mut Option<Record>,
    genesis: bool,
) -> Result<State, AuditError> {
    scan_inner(
        file,
        trail,
        state,
        expected,
        found,
        SegmentContext {
            opening,
            genesis,
            run: false,
        },
    )
}

/// Boundary policy for scanning one segment under ADR-0005 amendment 6.
struct SegmentContext {
    /// Whether scanning starts at the segment's opening checkpoint.
    opening: bool,
    /// Whether an absent predecessor requires a genesis link.
    genesis: bool,
    /// Whether predecessor history ends inside a run requiring immediate resume.
    run: bool,
}

fn scan_inner(
    file: &File,
    trail: [u8; 16],
    mut state: Option<State>,
    expected: Option<Head>,
    found: &mut Option<Record>,
    context: SegmentContext,
) -> Result<State, AuditError> {
    let SegmentContext {
        opening,
        genesis,
        run,
    } = context;
    let genesis = genesis || (run && state.is_none());
    let mut file = file.try_clone().map_err(io_error)?;
    let start = if opening {
        0
    } else {
        state.as_ref().map_or(0, |s| s.offset)
    };
    file.seek(SeekFrom::Start(start)).map_err(io_error)?;
    let mut reader = BufReader::new(file);
    let mut offset = start;
    let mut first = opening;
    // ADR-0005 lines 524–525: resume renames the old live file AS IS. Lines
    // 406/411/770 allow its trailing fragment and require writer/verifier parity.
    // Defer an unclosed predecessor's boundary until the successor's immediate
    // resume validates head/hash/lost_through below; file= is informational (525).
    let mut boundary_resume = opening && (run || state.as_ref().is_some_and(|s| !sealed(s)));
    let mut gap = None::<blake3::Hasher>;
    if !opening
        && let Some(s) = &state
        && !s.newline
        && s.gap.is_none()
    {
        // A complete JSON record lacking LF was already consumed. The next
        // writer terminates it; this LF is not a blank line or a repair gap.
        let mut byte = [0];
        if reader.read(&mut byte).map_err(io_error)? == 1 {
            if byte != *b"\n" {
                return Err(corrupt("bytes glued to complete unterminated record"));
            }
            offset += 1;
            if let Some(s) = &mut state {
                s.offset = offset;
                s.newline = true;
            }
        }
    }
    loop {
        let mut line = Vec::new();
        let count = reader
            .by_ref()
            .take(MAX_READ_BYTES)
            .read_until(b'\n', &mut line)
            .map_err(io_error)?;
        if count == 0 {
            break;
        }
        #[cfg(test)]
        SCANNED.with(|n| n.set(n.get() + count));
        offset += count as u64;
        let newline = line.ends_with(b"\n");
        let payload = line.strip_suffix(b"\n").unwrap_or(&line);
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(corrupt("audit line exceeds byte cap"));
        }
        let records = match Record::parse_line(payload) {
            Ok(records) => records,
            Err(_) if !first && !boundary_resume && fragment(payload) => {
                gap.get_or_insert_with(|| {
                    let mut h = blake3::Hasher::new();
                    h.update(b"vigil.audit.v1.repaired\0");
                    h
                })
                .update(&line);
                if let Some(s) = &mut state {
                    s.newline = newline;
                }
                continue;
            }
            Err(_) => return Err(corrupt("invalid audit line or opening checkpoint")),
        };
        // Native writer files contain one record per line. Collector batches
        // are a verifier input (#13), never a native storage representation.
        if records.len() != 1 {
            return Err(corrupt("multiple records in native audit line"));
        }
        let record = &records[0];
        if record.context.trail != trail {
            return Err(corrupt("trail identity differs from marker"));
        }
        if first && state.as_ref().is_some_and(|s| s.head == Head::of(record)) {
            return Err(corrupt("opening checkpoint duplicates predecessor"));
        }
        if first && !matches!(record.kind, Kind::Checkpoint(_)) {
            return Err(corrupt("missing opening checkpoint"));
        }
        if let Some(gap) = gap.take()
            && record.context.repaired != Some(*gap.finalize().as_bytes())
        {
            return Err(corrupt("missing or mismatched repair attestation"));
        }
        if boundary_resume
            && !first
            && !matches!(&record.kind, Kind::Entry(e) if e.action == "vigil.audit.resume")
        {
            return Err(corrupt("unclosed segment lacks matching immediate resume"));
        }
        apply(record, &mut state, genesis)?;
        if !first {
            boundary_resume = false;
        }
        let s = state.as_mut().ok_or_else(|| corrupt("missing head"))?;
        if expected == Some(s.head) {
            *found = Some(record.clone());
        }
        s.offset = offset;
        s.newline = newline;
        first = false;
    }
    if first {
        return Err(corrupt("empty live file or missing opening checkpoint"));
    }
    let mut state = state.ok_or_else(|| corrupt("missing head"))?;
    if state.pending_resume || boundary_resume {
        return Err(corrupt("resume checkpoint lacks its declaration"));
    }
    state.length = offset;
    state.gap = gap;
    Ok(state)
}
fn apply(record: &Record, state: &mut Option<State>, genesis: bool) -> Result<(), AuditError> {
    apply_checked(record, state, genesis, false, true)?;
    if let Some(s) = state {
        s.run_loss = false;
    }
    Ok(())
}
fn apply_checked(
    record: &Record,
    state: &mut Option<State>,
    genesis: bool,
    broken_boundary: bool,
    compare_mmr: bool,
) -> Result<(), AuditError> {
    let head = Head::of(record);
    let root_link =
        state.is_none() && record.context.previous == Record::genesis(&record.context.trail);
    // A root checkpoint above zero declares loss and needs an immediate resume;
    // an archived prefix instead carries its predecessor hash and MMR (d2/d8).
    let mut pending = state.is_none() && head.seq > 0 && root_link;
    let mut mmr = if let Some(s) = state.as_ref() {
        s.mmr.clone()
    } else {
        let Kind::Checkpoint(cp) = &record.kind else {
            return Err(corrupt("missing initial checkpoint"));
        };
        if (genesis || head.seq == 0) && !root_link {
            return Err(corrupt("initial checkpoint does not link genesis"));
        }
        if root_link && head.seq > 0 {
            // Amendment 9: the lost creation hash is unavailable. Both reader
            // paths authenticate the computable genesis leaf through this fold.
            let mut fold = Mmr::new();
            fold.push(Record::genesis(&record.context.trail))?;
            fold
        } else {
            Mmr::from_peaks(cp.size, cp.peaks.clone())
                .map_err(|_| corrupt("invalid opening peaks"))?
        }
    };
    let prior = state.as_ref().map(|s| s.head);
    if let Some(s) = state.as_ref() {
        if head == s.head {
            return Ok(());
        } // Collector-style identical duplicates add no leaf.
        if head.seq <= s.head.seq || (!broken_boundary && record.context.previous != s.head.hash) {
            return Err(corrupt(
                "record rolled back, changed or broke its hash link",
            ));
        }
        if s.pending_resume
            && !matches!(&record.kind, Kind::Entry(e) if e.action == "vigil.audit.resume")
        {
            return Err(corrupt("sequence gap lacks a resume declaration"));
        }
        if !broken_boundary && head.seq != s.head.seq + 1 {
            if !matches!(record.kind, Kind::Checkpoint(_)) {
                return Err(corrupt("sequence gap without checkpoint"));
            }
            pending = true;
        }
    }
    match &record.kind {
        Kind::Checkpoint(cp) => {
            if compare_mmr
                && (cp.size != mmr.size() || cp.root != mmr.root() || cp.peaks != mmr.peaks())
            {
                return Err(corrupt("checkpoint MMR differs from preceding records"));
            }
        }
        Kind::Entry(entry) if entry.action == "vigil.audit.resume" => {
            let s = state
                .as_ref()
                .ok_or_else(|| corrupt("resume without predecessor"))?;
            if !s.checkpoint {
                return Err(corrupt("resume not immediately after checkpoint"));
            }
            let details = entry
                .details
                .as_deref()
                .ok_or_else(|| corrupt("resume without details"))?;
            let (named, lost, file) = resume_details(details)?;
            let (seq_text, hash) = named
                .strip_prefix("head=")
                .and_then(|v| v.split_once(':'))
                .ok_or_else(|| corrupt("invalid resume head"))?;
            let seq = seq_text
                .parse::<u64>()
                .map_err(|_| corrupt("invalid resume head sequence"))?;
            let bound = s
                .head
                .seq
                .checked_sub(1)
                .ok_or_else(|| corrupt("resume after creation checkpoint"))?;
            if lost != bound.to_string()
                || seq.to_string() != seq_text
                || seq >= s.head.seq
                || hash != crate::audit::digest_string(&s.checkpoint_previous)
                || s.checkpoint_predecessor.is_some_and(|p| p.seq != seq)
                || (s.checkpoint_predecessor.is_none()
                    && s.checkpoint_previous == Record::genesis(&record.context.trail)
                    && seq != 0)
                || file.is_empty()
                || file.bytes().any(|b| b.is_ascii_whitespace())
            {
                return Err(corrupt("resume declaration does not describe its gap"));
            }
        }
        Kind::Entry(_) => {}
    }
    mmr.push(head.hash).map_err(|_| corrupt("MMR overflow"))?;
    *state = Some(State {
        head,
        mmr,
        offset: 0,
        length: 0,
        checkpoint: matches!(record.kind, Kind::Checkpoint(_)),
        checkpoint_time: if matches!(record.kind, Kind::Checkpoint(_)) {
            record.context.time
        } else {
            state.as_ref().map_or(0, |s| s.checkpoint_time)
        },
        since_checkpoint: if matches!(record.kind, Kind::Checkpoint(_)) {
            0
        } else {
            state.as_ref().map_or(1, |s| s.since_checkpoint + 1)
        },
        newline: true,
        gap: None,
        pending_resume: pending,
        run_loss: broken_boundary || state.as_ref().is_some_and(|s| s.run_loss),
        checkpoint_predecessor: prior,
        checkpoint_previous: record.context.previous,
    });
    Ok(())
}
fn fragment(bytes: &[u8]) -> bool {
    if bytes.is_empty()
        || bytes.iter().all(u8::is_ascii_whitespace)
        || bytes.iter().any(|b| *b < 0x20)
    {
        return false;
    }
    let valid = match std::str::from_utf8(bytes) {
        Ok(_) => bytes,
        Err(e) if e.error_len().is_none() && bytes.len() - e.valid_up_to() <= 3 => {
            &bytes[..e.valid_up_to()]
        }
        Err(_) => return false,
    };
    matches!(serde_json::from_slice::<serde_json::Value>(valid), Err(e) if e.is_eof())
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;

#[cfg(test)]
thread_local! { static SCANNED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

#[cfg(test)]
thread_local! { pub(crate) static FULL_FOLDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
