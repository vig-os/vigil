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
    runs::{
        self, Advance, Classifier, DecodedLine, HistorySegmentWalk, LineEventKind,
        Mode as ClassifierMode, Reaction, RunState, SegmentContext,
    },
};
use crate::rotate::Directory;
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
    pub(super) fn of(record: &Record) -> Self {
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
    /// The pure per-record run state (see [`super::runs::RunState`]).
    pub(crate) run: RunState,
    offset: u64,
    pub(crate) length: u64,
    pub(crate) checkpoint_time: u64,
    pub(crate) since_checkpoint: u64,
    newline: bool,
    gap: Option<blake3::Hasher>,
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
pub(super) fn corrupt(detail: &str) -> AuditError {
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
///
/// Ruling 197-d1 addenda 19.1 and 20.1: the strict-pass-then-tolerant-
/// fallback-from-saved-state sequence — including the saved-prior
/// restore, `inherited = *run || unsealed_boundary`, per-line feeding,
/// the duplicate-line arm and the end-of-segment epilogue — is ONE
/// function in `runs::history_segment`, parameterised by [`Reaction`].
/// This shim owns **only** byte-level I/O (seek, glued-byte / LF check,
/// physical `read_line`, [`super::lines::classify`]) plus the writer-
/// only `next_cp_fields` fold and the `found` out-parameter. The reader
/// calls it with [`Reaction::Stop`]; the collector's `history_segment`
/// entry (collector_tests in `runs.rs`, #197 R2b S3b beyond) calls the
/// same function with [`Reaction::Collect`].
pub(crate) fn history_segment(
    file: &File,
    trail: [u8; 16],
    state: Option<State>,
    opening: bool,
    expected: Option<Head>,
    found: &mut Option<Record>,
    run: &mut bool,
) -> Result<Option<State>, AuditError> {
    // Decision 8 still applies when a malformed suffix makes the successor
    // enter the run fallback: a linking opening cannot defer its declaration.
    let unsealed_boundary = opening && state.as_ref().is_some_and(|s| !sealed(s));
    let ctx = SegmentContext {
        opening,
        genesis: false,
        run: *run,
    };
    let prior_run = state.as_ref().map(|s| s.run.clone());
    let initial_offset = if opening {
        0
    } else {
        state.as_ref().map_or(0, |s| s.offset)
    };
    let initial_length = state.as_ref().map_or(0, |s| s.length);
    let initial_gap = state.as_ref().and_then(|s| s.gap.clone());
    let needs_glue_check = !opening
        && state
            .as_ref()
            .is_some_and(|s| !s.newline && s.gap.is_none());

    // Reader-side state threaded through `on_feed` and the strict
    // closure. Two separate `found` buffers (one for the strict pass,
    // one for the tolerant walk) keep the captures aliasing-free; the
    // walk result selects which to propagate to the out-parameter.
    let mut out_state: Option<State> = state.clone();
    let mut final_offset = initial_offset;
    let initial_found = found.clone();
    let strict_initial_found = initial_found.clone();
    let strict_state = state.clone();
    let strict = move || -> Result<(State, Option<Record>), AuditError> {
        let mut strict_found = strict_initial_found;
        let s = scan_inner(file, trail, strict_state, expected, &mut strict_found, ctx)?;
        Ok((s, strict_found))
    };
    // Lazy tolerant events iterator: the seek, the glued-byte / LF
    // check and physical `read_line` live only in this closure. The
    // decoded line event carries the file bytes + the terminating LF
    // flag and is consumed by `runs::history_segment`.
    let tolerant_file = file.try_clone().map_err(io_error)?;
    let mut tolerant_reader_opt: Option<BufReader<File>> = None;
    let mut tolerant_offset = initial_offset;
    let mut did_glue_check = false;
    let events = move || -> Result<Option<DecodedLine>, AuditError> {
        let reader = match tolerant_reader_opt.as_mut() {
            Some(r) => r,
            None => {
                let mut f = tolerant_file.try_clone().map_err(io_error)?;
                f.seek(SeekFrom::Start(initial_offset)).map_err(io_error)?;
                tolerant_reader_opt = Some(BufReader::new(f));
                tolerant_reader_opt
                    .as_mut()
                    .expect("just inserted BufReader")
            }
        };
        if !did_glue_check && needs_glue_check {
            did_glue_check = true;
            let mut byte = [0];
            if reader.read(&mut byte).map_err(io_error)? == 1 {
                if byte != *b"\n" {
                    return Err(corrupt("bytes glued to complete unterminated record"));
                }
                tolerant_offset += 1;
            }
        }
        let mut line = Vec::new();
        let (bytes, newline) = read_line(reader, &mut line)?;
        if bytes == 0 {
            return Ok(None);
        }
        #[cfg(test)]
        SCANNED.with(|n| n.set(n.get() + bytes));
        tolerant_offset += bytes as u64;
        let payload = line.strip_suffix(b"\n").unwrap_or(&line);
        let kind = match super::lines::classify(payload) {
            super::lines::Line::Record(Ok(records)) => LineEventKind::Record(records),
            super::lines::Line::Fragment => LineEventKind::Fragment(line),
            super::lines::Line::Unparsable(_) => LineEventKind::Unparsable,
            super::lines::Line::Record(Err(_)) => LineEventKind::RecordErr,
        };
        Ok(Some(DecodedLine {
            kind,
            offset_after: tolerant_offset,
            newline,
        }))
    };

    // Reader-side `on_feed`: rebuilds the reader's `State` on each
    // successful record fold (addendum 20.1), using the writer-only
    // `next_cp_fields` fold that stays on the storage side, and
    // updates `newline` only for a fragment/unparsable; duplicates
    // skip `on_feed` entirely so the reader's prior `continue`
    // semantic is preserved.
    let mut tol_found: Option<Record> = initial_found;
    let on_feed = |fed: Option<(&Record, &RunState)>, offset_after: u64, newline_after: bool| {
        final_offset = offset_after;
        if let Some((record, rs)) = fed {
            let (cp_time, since_cp) = next_cp_fields(
                out_state
                    .as_ref()
                    .map(|s| (s.checkpoint_time, s.since_checkpoint)),
                record,
            );
            let head = rs.head;
            out_state = Some(State {
                run: rs.clone(),
                offset: offset_after,
                length: initial_length,
                checkpoint_time: cp_time,
                since_checkpoint: since_cp,
                newline: newline_after,
                gap: initial_gap.clone(),
            });
            if expected == Some(head) {
                tol_found = Some(record.clone());
            }
        } else if let Some(s) = &mut out_state {
            s.newline = newline_after;
        }
    };

    let walk = runs::history_segment::<(State, Option<Record>), _, _, _>(
        Reaction::Stop,
        strict,
        events,
        prior_run,
        ctx,
        unsealed_boundary,
        *run,
        trail,
        on_feed,
    )?;

    match walk {
        HistorySegmentWalk::Strict((next, strict_found)) => {
            *run = false;
            *found = strict_found;
            Ok(Some(next))
        }
        HistorySegmentWalk::Tolerant(outcome) => {
            let outcome = *outcome;
            *run = outcome.run_flag;
            if let Some(s) = &mut out_state {
                s.length = final_offset;
                s.gap = outcome.gap;
            }
            *found = tol_found;
            Ok(out_state)
        }
    }
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
    state.run.checkpoint && state.gap.is_none() && !state.run.pending_resume
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

fn resume_header(file: &File, trail: [u8; 16]) -> Result<Option<u64>, AuditError> {
    let mut reader = BufReader::new(file);
    for index in 0..2 {
        let mut line = Vec::new();
        read_line(&mut reader, &mut line)?;
        let payload = line.strip_suffix(b"\n").unwrap_or(&line);
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
                    .and_then(|details| runs::resume_details(details).ok())
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

/// Reads through one physical LF while retaining a bounded classification prefix.
/// Oversized tails are one Unparsable line, never several lines or a repair gap.
fn read_line(reader: &mut impl BufRead, line: &mut Vec<u8>) -> Result<(usize, bool), AuditError> {
    let mut count = reader
        .by_ref()
        .take(MAX_READ_BYTES)
        .read_until(b'\n', line)
        .map_err(io_error)?;
    let mut newline = line.ends_with(b"\n");
    if count as u64 == MAX_READ_BYTES && !newline {
        loop {
            let bytes = reader.fill_buf().map_err(io_error)?;
            if bytes.is_empty() {
                break;
            }
            let take = bytes.iter().position(|b| *b == b'\n').map(|p| p + 1);
            let length = take.unwrap_or(bytes.len());
            reader.consume(length);
            count += length;
            if take.is_some() {
                newline = true;
                break;
            }
        }
    }
    Ok((count, newline))
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

fn scan_inner(
    file: &File,
    trail: [u8; 16],
    state: Option<State>,
    expected: Option<Head>,
    found: &mut Option<Record>,
    context: SegmentContext,
) -> Result<State, AuditError> {
    // Strict-mode `scan_inner` is a thin shim over `runs::Classifier`. The
    // shim performs byte-level I/O (reading a physical line, the byte-glue
    // check for an unterminated predecessor, `offset`/`newline`/`length`
    // bookkeeping, and the three writer-only State fields), threads a
    // `runs::Classifier` for every segment-level per-record check, and
    // hands the finalized gap digest to `runs::Classifier::feed_record`,
    // which itself calls `runs::check_attestation` at the reader's per-path
    // position (ruling 197-d1 addenda 7 and 12). The classifier's strict
    // path owns:
    //   - multiple records in native audit line
    //   - trail identity differs from marker
    //   - opening checkpoint duplicates predecessor
    //   - missing opening checkpoint
    //   - unclosed segment lacks matching immediate resume
    //   - invalid audit line or opening checkpoint (Fragment@first/boundary, Unparsable)
    //   - empty live file or missing opening checkpoint
    //   - resume checkpoint lacks its declaration
    //   - every `apply_checked` detail (R1).
    let mut file = file.try_clone().map_err(io_error)?;
    let start = if context.opening {
        0
    } else {
        state.as_ref().map_or(0, |s| s.offset)
    };
    file.seek(SeekFrom::Start(start)).map_err(io_error)?;
    let mut reader = BufReader::new(file);
    let mut offset = start;
    let mut last_offset = state.as_ref().map_or(start, |s| s.offset);
    let mut last_newline = state.as_ref().is_none_or(|s| s.newline);
    let mut cp_time = state.as_ref().map_or(0, |s| s.checkpoint_time);
    let mut since_cp = state.as_ref().map_or(0, |s| s.since_checkpoint);
    // `boundary_resume` starts set at an opening that either opens a run or
    // follows an unsealed predecessor; the first successor must then be an
    // immediate `vigil.audit.resume`.
    let initial_boundary =
        context.opening && (context.run || state.as_ref().is_some_and(|s| !sealed(s)));
    if !context.opening
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
            last_offset = offset;
            last_newline = true;
        }
    }
    let prior_run = state.map(|s| s.run);
    let mut classifier =
        Classifier::new(prior_run, context, ClassifierMode::Strict, initial_boundary);
    loop {
        let mut line = Vec::new();
        let (count, newline) = read_line(&mut reader, &mut line)?;
        if count == 0 {
            break;
        }
        #[cfg(test)]
        SCANNED.with(|n| n.set(n.get() + count));
        offset += count as u64;
        let payload = line.strip_suffix(b"\n").unwrap_or(&line);
        match super::lines::classify(payload) {
            super::lines::Line::Record(Ok(records)) => {
                let record_count = records.len();
                if record_count != 1 {
                    // The classifier returns `multiple records in native audit
                    // line` ahead of every other check; attestation is unused.
                    classifier.feed_record(&records[0], record_count, trail, None)?;
                    unreachable!("feed_record returns Err when count != 1");
                }
                let record = &records[0];
                // Pass the current gap digest into `feed_record`; the
                // classifier runs `check_attestation` at the reader's
                // per-path position (ruling 197-d1 addendum 12: between
                // `missing opening checkpoint` and `unclosed segment lacks
                // matching immediate resume`).
                let gap_digest = classifier.take_gap();
                let advance = classifier.feed_record(record, 1, trail, gap_digest)?;
                if expected == classifier.state().map(|s| s.head) {
                    *found = Some(record.clone());
                }
                // A Duplicate leaves the writer-only fields untouched; a
                // Record folds the record through `next_cp_fields`.
                // Offset/newline advance on both paths.
                if matches!(advance, Advance::Record) {
                    (cp_time, since_cp) = next_cp_fields(Some((cp_time, since_cp)), record);
                }
                last_offset = offset;
                last_newline = newline;
            }
            super::lines::Line::Fragment => {
                classifier.feed_fragment(&line)?;
                last_newline = newline;
            }
            super::lines::Line::Unparsable(_) | super::lines::Line::Record(Err(_)) => {
                classifier.feed_unparsable(&line)?;
                // feed_unparsable always returns Err in strict mode; unreachable.
                unreachable!("feed_unparsable returns Err in strict mode");
            }
        }
    }
    let finished = classifier.finish()?;
    Ok(State {
        run: finished.state,
        offset: last_offset,
        length: offset,
        checkpoint_time: cp_time,
        since_checkpoint: since_cp,
        newline: last_newline,
        gap: finished.gap,
    })
}
fn apply(record: &Record, state: &mut Option<State>, genesis: bool) -> Result<(), AuditError> {
    apply_checked(record, state, genesis, false, true)?;
    if let Some(s) = state {
        s.run.run_loss = false;
    }
    Ok(())
}
/// Applies one record to the reader's state; the per-record logic lives in
/// [`super::runs::apply_checked`], and this keeps the writer-only fields
/// (`checkpoint_time`, `since_checkpoint`) in `State`.
fn apply_checked(
    record: &Record,
    state: &mut Option<State>,
    genesis: bool,
    broken_boundary: bool,
    compare_mmr: bool,
) -> Result<(), AuditError> {
    let prior_run = state.as_ref().map(|s| &s.run);
    let Some(next_run) =
        runs::apply_checked(prior_run, record, genesis, broken_boundary, compare_mmr)?
    else {
        return Ok(()); // Collector-style identical duplicate: leave state in place.
    };
    let (cp_time, since_cp) = next_cp_fields(
        state
            .as_ref()
            .map(|s| (s.checkpoint_time, s.since_checkpoint)),
        record,
    );
    *state = Some(State {
        run: next_run,
        offset: 0,
        length: 0,
        checkpoint_time: cp_time,
        since_checkpoint: since_cp,
        newline: true,
        gap: None,
    });
    Ok(())
}

/// Next `(checkpoint_time, since_checkpoint)` after folding `record` onto
/// the predecessor's `(checkpoint_time, since_checkpoint)` in `prior`. A
/// `Kind::Checkpoint` resets to `(record.context.time, 0)`; any other kind
/// adds `1`, saturating at `u64::MAX` (per ruling 197-d1 addendum 15: the
/// bound counts records since a checkpoint and is unreachable in practice,
/// but the semantics must still be correct on every path).
///
/// Shared by `scan_inner`, `apply_checked` and `history_segment`'s
/// tolerant-mode fallback rebuild so the three stay identical on every
/// writer-only field update.
fn next_cp_fields(prior: Option<(u64, u64)>, record: &Record) -> (u64, u64) {
    if matches!(record.kind, Kind::Checkpoint(_)) {
        return (record.context.time, 0);
    }
    let (cp_time, since_cp) = prior.unwrap_or((0, 0));
    (cp_time, since_cp.saturating_add(1))
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;

#[cfg(test)]
thread_local! { static SCANNED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

#[cfg(test)]
thread_local! { pub(crate) static FULL_FOLDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
