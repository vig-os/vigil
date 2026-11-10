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
        self, CollectorPos, DecodedLine, FeedEvent, FeedEventStrict, HistorySegmentArgs,
        HistorySegmentWalk, LineEventKind, Reaction, RunState, ScanSegmentArgs, SegmentContext,
        Violation,
    },
};

/// Addendum 27.1: per-segment Collect return of the three shims
/// (`history_segment`, `scan`, `scan_closing`). Under
/// [`Reaction::Stop`] the vector is empty and the Option is always
/// `Some`; under [`Reaction::Collect`] the vector carries the inner
/// classifier's `(CollectorPos, Violation)` list and the Option may be
/// `None` when no record was folded. `classify` in `runs.rs` pairs the
/// positions with its own segment index to build
/// `(SegmentViolationPos, Violation)`.
pub(crate) type SegmentOutcome = (Option<State>, Vec<(CollectorPos, Violation)>);
use crate::rotate::Directory;
use rustix::fs::{self as rfs, Mode, OFlags};
use std::cell::RefCell;
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

impl Cache {
    /// Test-only accessor so cross-module test code
    /// (`runs::classify_tests`) can clone the cached `State` into a
    /// classify args struct without widening the field to
    /// `pub(crate)` (ruling 197-d1 addendum 27 continuation).
    #[cfg(test)]
    pub(crate) fn state(&self) -> &State {
        &self.state
    }

    /// Test-only constructor so the CC rows can assemble a `Cache`
    /// from a reader-produced `(state, file, sealed_before)` triple
    /// without widening the fields (ruling 197-d1 addendum 27
    /// continuation).
    #[cfg(test)]
    pub(crate) fn new_for_test(state: State, file: File, sealed_before: Option<PathBuf>) -> Self {
        Self {
            state,
            file,
            sealed_before,
        }
    }
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
/// Ruling 197-d1 addendum 24.3 / 20.1: the ONE `Line` -> `LineEventKind`
/// decode, used by both `history_segment`'s tolerant-fallback event
/// closure and `scan_inner`'s strict event closure. A mutant that
/// changes this mapping fails BOTH a tolerant `history_segment` reader
/// pin and a strict `scan` reader pin.
fn decode_line_kind(line: Vec<u8>) -> LineEventKind {
    let classified = {
        let payload = line.strip_suffix(b"\n").unwrap_or(&line);
        super::lines::classify(payload)
    };
    match classified {
        super::lines::Line::Record(Ok(records)) => LineEventKind::Record(records),
        super::lines::Line::Fragment => LineEventKind::Fragment(line),
        super::lines::Line::Unparsable(_) => LineEventKind::Unparsable,
        super::lines::Line::Record(Err(_)) => LineEventKind::RecordErr,
    }
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

/// Ruling 197-d1 addendum 20.1 / S3b1a: per-segment byte source. Owns
/// the seek, the glued-byte / LF check, the physical `read_line`, the
/// [`decode_line_kind`] step, and the offset/length/newline bookkeeping
/// that both `history_segment` and `scan_inner` used to inline through
/// separate closures. S3b1b moves the loops over these into
/// `runs::classify` (ruling 197-d1 addendum 25); this PR is a
/// behaviour-preserving extraction.
pub(crate) struct SegmentBytes {
    pending_file: Option<File>,
    reader: Option<BufReader<File>>,
    initial_offset: u64,
    needs_glue_check: bool,
    did_glue_check: bool,
    offset_cursor: u64,
    last_offset: u64,
    last_newline: bool,
}

impl SegmentBytes {
    pub(crate) fn new(
        file: &File,
        initial_offset: u64,
        needs_glue_check: bool,
        last_offset: u64,
        last_newline: bool,
    ) -> Result<Self, AuditError> {
        let pending_file = file.try_clone().map_err(io_error)?;
        Ok(Self {
            pending_file: Some(pending_file),
            reader: None,
            initial_offset,
            needs_glue_check,
            did_glue_check: false,
            offset_cursor: initial_offset,
            last_offset,
            last_newline,
        })
    }

    fn ensure_reader(&mut self) -> Result<&mut BufReader<File>, AuditError> {
        if self.reader.is_none() {
            let mut f = self
                .pending_file
                .take()
                .expect("SegmentBytes: reader seeded before new() or twice");
            f.seek(SeekFrom::Start(self.initial_offset))
                .map_err(io_error)?;
            self.reader = Some(BufReader::new(f));
        }
        Ok(self
            .reader
            .as_mut()
            .expect("SegmentBytes: reader just inserted"))
    }

    /// Reads and validates the glue byte, if one is expected and has
    /// not been consumed yet. The strict and tolerant walks share this
    /// one `corrupt("bytes glued…")` site; the strict-only
    /// `last_offset` / `last_newline` promotion lives in
    /// [`check_glue_byte_strict`]. Returns `true` if a `\n` was
    /// consumed; `false` if nothing was read (EOF) or no glue check
    /// was pending.
    fn consume_glue_byte(&mut self) -> Result<bool, AuditError> {
        if self.did_glue_check || !self.needs_glue_check {
            return Ok(false);
        }
        self.did_glue_check = true;
        let mut byte = [0];
        let count = {
            let reader = self.ensure_reader()?;
            reader.read(&mut byte).map_err(io_error)?
        };
        if count == 0 {
            return Ok(false);
        }
        if byte != *b"\n" {
            return Err(corrupt("bytes glued to complete unterminated record"));
        }
        self.offset_cursor += 1;
        Ok(true)
    }

    /// Eager strict-side glue check (matching `scan_inner`'s original
    /// pre-events-loop check). On a consumed `\n` the glue byte also
    /// advances `last_offset` / `last_newline` (base-identical: strict
    /// `scan_inner` set both to the post-glue cursor).
    pub(crate) fn check_glue_byte_strict(&mut self) -> Result<(), AuditError> {
        if self.consume_glue_byte()? {
            self.last_offset = self.offset_cursor;
            self.last_newline = true;
        }
        Ok(())
    }

    /// Reads one decoded line event. On the first call (and only once
    /// per segment), performs the lazy tolerant-side glue check if
    /// `needs_glue_check` is set and no eager check ran — matching
    /// `history_segment`'s original tolerant-closure behaviour, where
    /// the glue byte bumps `offset_cursor` but does not touch
    /// `last_offset` / `last_newline`.
    pub(crate) fn next_event(&mut self) -> Result<Option<DecodedLine>, AuditError> {
        self.consume_glue_byte()?;
        let mut line = Vec::new();
        let (bytes, newline) = {
            let reader = self.ensure_reader()?;
            read_line(reader, &mut line)?
        };
        if bytes == 0 {
            return Ok(None);
        }
        #[cfg(test)]
        SCANNED.with(|n| n.set(n.get() + bytes));
        self.offset_cursor += bytes as u64;
        Ok(Some(DecodedLine {
            kind: decode_line_kind(line),
            offset_after: self.offset_cursor,
            newline,
        }))
    }

    /// `on_feed` for a folded record (strict Record / strict Duplicate
    /// / tolerant Record): advances `last_offset` and `last_newline` to
    /// the post-line cursor. Tolerant `Duplicate` and tolerant
    /// `NonRecord` do NOT call this (base-identical: the tolerant walk
    /// left `state.offset` alone across duplicate lines and on fragment
    /// / unparsable lines).
    pub(crate) fn note_record_fed(&mut self, offset_after: u64, newline: bool) {
        self.last_offset = offset_after;
        self.last_newline = newline;
    }

    /// `on_feed` for a mid-segment fragment or unparsable line (strict
    /// `NonRecord` and tolerant `NonRecord`). Base-identical: only
    /// `state.newline` moved on these lines.
    pub(crate) fn note_newline(&mut self, newline: bool) {
        self.last_newline = newline;
    }

    pub(crate) fn offset_cursor(&self) -> u64 {
        self.offset_cursor
    }
    pub(crate) fn last_offset(&self) -> u64 {
        self.last_offset
    }
    pub(crate) fn last_newline(&self) -> bool {
        self.last_newline
    }
}

/// S3b1a: one lazy, base-order segment source (addendum 25.2). Lists
/// the segments for a given reader path up front without opening any
/// files; each `next_segment` call opens the next file, so the first
/// open error surfaces exactly where it does at base. The multi-segment
/// loops in `initial_record` and `refresh` drive it; S3b1b moves the
/// loops themselves into `runs::classify`.
pub(crate) struct SegmentSource<'dir> {
    dir: &'dir File,
    plan: Vec<PlanStep>,
    cursor: usize,
    cached: Option<File>,
    pending: Option<PendingRotateAfter>,
    newest: Option<PathBuf>,
}

enum PlanStep {
    /// Refresh-rotate prelude: the cached live file, re-read as a sealed
    /// history segment (`history_segment(opening = false)`).
    CachedPrelude,
    /// Refresh-append sole segment: the cached live file as the single
    /// segment (`scan(opening = false)`).
    CachedLive,
    /// A rotated name, opened writable = false (`history_segment(opening
    /// = true)`).
    Rotated(PathBuf),
    /// The live file (`audit.jsonl`), opened writable = true
    /// (`scan_closing`).
    ClosingLive,
}

/// Refresh-rotate: inputs captured at construction so `segments_after`
/// can be called **after** the prelude is yielded. Base walked the
/// prelude first and only then listed the newer segments, so any error
/// surfacing from the listing (`rotated_names_at`, `statat`, EACCES
/// from a `chmod 0300` directory) must come out of the second
/// `next_segment` call, not the first.
struct PendingRotateAfter {
    old: std::fs::Metadata,
    sealed_before: Option<PathBuf>,
}

/// A segment the source has just yielded. The caller's loop picks the
/// per-segment walk; the source only opens bytes.
pub(crate) enum SegmentRead {
    /// A rotated sealed segment. `prelude == true` is the refresh-rotate
    /// cached-file prelude (`history_segment(opening = false)`);
    /// otherwise this is a rotated name opened writable = false
    /// (`history_segment(opening = true)`).
    Sealed { file: File, prelude: bool },
    /// The live file (refresh-append same-inode, or the trailing live
    /// close in live-open / refresh-rotate).
    Live(File),
}

impl<'dir> SegmentSource<'dir> {
    /// `initial_record` (live open and open fallback): list the rotated
    /// names, then the live file. No files opened yet.
    pub(crate) fn for_live_open(dir: &'dir File) -> Result<Self, AuditError> {
        let names = crate::rotate::rotated_names_at(dir, "audit").map_err(io_error)?;
        let newest = names.last().cloned();
        let mut plan: Vec<PlanStep> = names.into_iter().map(PlanStep::Rotated).collect();
        plan.push(PlanStep::ClosingLive);
        Ok(Self {
            dir,
            plan,
            cursor: 0,
            cached: None,
            pending: None,
            newest,
        })
    }

    /// `refresh` same-inode branch: the cached live file is the only
    /// segment. No open calls happen.
    pub(crate) fn for_refresh_append(dir: &'dir File, cache: &Cache) -> Result<Self, AuditError> {
        let cached = cache.file.try_clone().map_err(io_error)?;
        Ok(Self {
            dir,
            plan: vec![PlanStep::CachedLive],
            cursor: 0,
            cached: Some(cached),
            pending: None,
            newest: None,
        })
    }

    /// `refresh` rotated branch: yield the cached-file prelude first,
    /// then call `segments_after` lazily (so a directory listing error
    /// surfaces AFTER the prelude's own walk, not before), then the
    /// live file. Base-identical: `fn refresh` ran
    /// `history_segment(&cache.file, …)` first and only then called
    /// `segments_after(dir, cache)`.
    pub(crate) fn for_refresh_rotate(dir: &'dir File, cache: &Cache) -> Result<Self, AuditError> {
        let cached = cache.file.try_clone().map_err(io_error)?;
        let old = cache.file.metadata().map_err(io_error)?;
        Ok(Self {
            dir,
            plan: vec![PlanStep::CachedPrelude],
            cursor: 0,
            cached: Some(cached),
            pending: Some(PendingRotateAfter {
                old,
                sealed_before: cache.sealed_before.clone(),
            }),
            newest: None,
        })
    }

    /// Lazy base-order open. Each file is opened only inside the
    /// matching `next_segment` call, so a corrupt rotated segment N
    /// aborts the walk before segment N+1 is opened (addendum 25.2).
    /// On refresh rotate the `segments_after` listing itself runs
    /// lazily — after the prelude has been yielded — so a listing
    /// error surfaces at the second call, not the first.
    pub(crate) fn next_segment(&mut self) -> Result<Option<SegmentRead>, AuditError> {
        if self.cursor >= self.plan.len()
            && let Some(pending) = self.pending.take()
        {
            self.expand_rotate_after(pending)?;
        }
        if self.cursor >= self.plan.len() {
            return Ok(None);
        }
        let idx = self.cursor;
        self.cursor = idx + 1;
        match &self.plan[idx] {
            PlanStep::CachedPrelude => {
                let file = self
                    .cached
                    .take()
                    .expect("SegmentSource: prelude slot already consumed");
                Ok(Some(SegmentRead::Sealed {
                    file,
                    prelude: true,
                }))
            }
            PlanStep::CachedLive => {
                let file = self
                    .cached
                    .take()
                    .expect("SegmentSource: append slot already consumed");
                Ok(Some(SegmentRead::Live(file)))
            }
            PlanStep::Rotated(name) => {
                let file = existing(self.dir, name, false)?;
                Ok(Some(SegmentRead::Sealed {
                    file,
                    prelude: false,
                }))
            }
            PlanStep::ClosingLive => {
                let file = existing(self.dir, Path::new("audit.jsonl"), true)?;
                Ok(Some(SegmentRead::Live(file)))
            }
        }
    }

    /// Append the rotated-name steps and the closing-live step to the
    /// plan, running `segments_after` lazily so its errors surface
    /// after the prelude's own walk (addendum 25.2: on refresh rotate
    /// the prelude walks first, then the newer segments are listed).
    fn expand_rotate_after(&mut self, pending: PendingRotateAfter) -> Result<(), AuditError> {
        let (names, newest) = segments_after_from(self.dir, &pending.old, &pending.sealed_before)?;
        self.plan.reserve(names.len() + 1);
        self.plan.extend(names.into_iter().map(PlanStep::Rotated));
        self.plan.push(PlanStep::ClosingLive);
        self.newest = newest;
        Ok(())
    }

    /// The newest rotated name observed when the plan was built; used
    /// by the caller to update `Cache::sealed_before` after a refresh
    /// rotate or at the end of live-open. Matches base's `names.last()`
    /// (live-open) and `segments_after`'s `newest` (refresh-rotate).
    pub(crate) fn newest(&self) -> Option<&Path> {
        self.newest.as_deref()
    }
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
    let mut source = SegmentSource::for_live_open(dir)?;
    let out = runs::classify(
        runs::ClassifyArgs {
            trail,
            prior_state: None,
        },
        runs::ReaderPath::LiveOpen { expected },
        &mut source,
        Reaction::Stop,
    )?;
    // Under `Reaction::Stop` the live walker's `scan_inner` invariant
    // guarantees `Some(state)` on every Ok return; `ok_or_else` is
    // defence-in-depth (no new corrupt site, no new Violation
    // variant; the syn gate stays at 49), proving the reader path
    // stays panic-free.
    let state = out.final_state.ok_or_else(|| {
        AuditError::new(
            AuditErrorKind::HeadMismatch,
            "expected head absent or different",
        )
    })?;
    let file = out.live_file.ok_or_else(|| {
        AuditError::new(
            AuditErrorKind::HeadMismatch,
            "expected head absent or different",
        )
    })?;
    Ok((
        Cache {
            file,
            state,
            sealed_before: out.sealed_before,
        },
        out.found,
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
#[expect(
    clippy::too_many_arguments,
    reason = "addendum 27.1 adds a Reaction parameter to the base-order shim; bundling into a struct for one call site adds churn without clarity"
)]
pub(crate) fn history_segment(
    reaction: Reaction,
    file: &File,
    trail: [u8; 16],
    state: Option<State>,
    opening: bool,
    expected: Option<Head>,
    found: &mut Option<Record>,
    run: &mut bool,
) -> Result<SegmentOutcome, AuditError> {
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
    let needs_glue_check = !opening
        && state
            .as_ref()
            .is_some_and(|s| !s.newline && s.gap.is_none());

    // Reader-side state threaded through `on_feed` and the strict
    // closure. Addendum 22.2: `found_cell` is the ONE shared buffer so
    // the strict pass's partial writes survive on `CorruptTrail` and
    // the tolerant walk's own writes land in the same place
    // (base-identical: a single `&mut found` was threaded through
    // both passes).
    let found_cell = RefCell::new(found.clone());
    let fc = &found_cell;
    let strict_state = state.clone();
    // Addendum 27.1: the strict pass runs under `Reaction::Stop` even
    // under outer Collect — base's strict pass short-circuits on any
    // violation and then the tolerant fallback records. Only the
    // tolerant fallback below sees the outer reaction.
    #[rustfmt::skip]
    let strict = move || scan_inner(Reaction::Stop, file, trail, strict_state, expected, &mut fc.borrow_mut(), ctx)
        .map(|(s, _)| s.expect("scan_inner Stop implies state=Some"));
    // Lazy tolerant byte source. The seek, the glued-byte / LF check,
    // `read_line`, `decode_line_kind` AND the tolerant-side byte
    // bookkeeping (`last_offset` / `last_newline` / `offset_cursor`,
    // addendum 20.1 / 25.2) all live inside [`SegmentBytes`]; the shim
    // holds no second copy of these fields.
    let initial_last_offset = state.as_ref().map_or(initial_offset, |s| s.offset);
    let initial_last_newline = state.as_ref().is_none_or(|s| s.newline);
    let bytes = RefCell::new(SegmentBytes::new(
        file,
        initial_offset,
        needs_glue_check,
        initial_last_offset,
        initial_last_newline,
    )?);
    let events = || -> Result<Option<DecodedLine>, AuditError> { bytes.borrow_mut().next_event() };

    // Reader-side bookkeeping: the writer-only `cp_time` / `since_cp`
    // fold and the `expected` / `found` writeback. Byte-level fields
    // (`last_offset` / `last_newline` and the walk's end-of-segment
    // byte cursor) live in [`SegmentBytes`]; the duplicate arm
    // (addendum 22.1) leaves `last_offset` / `last_newline` alone —
    // base-identical.
    //
    // The pure run state used to be tracked here as a separate
    // `last_run` Option updated from `on_feed(Record)`; ruling
    // 197-d1 addendum 27 continuation moves it to the classifier's
    // own `state` field, read out of the Tolerant arm's
    // `CollectorOutcome.state`. Under Stop the two Options were
    // identical byte-for-byte (every tolerant-Stop apply updated
    // both `classifier.state` AND `last_run` in lockstep); under
    // Collect the tolerant arm never routed through `on_feed`'s
    // Record branch (dispatch_line's `(Tolerant, Collect)` arm calls
    // `feed_record_collect` without the `on_feed(Record, rs)` call),
    // so a separate `last_run` stayed `None` where the classifier's
    // own state was `Some`. Threading via `CollectorOutcome.state`
    // makes Collect return the same `Ok(state)` Stop does on
    // `[cp0, close1, garbage\n]` and every analogous sealed layout.
    let mut running_state: Option<RunState> = state.as_ref().map(|s| s.run.clone());
    let mut cp_time = state.as_ref().map_or(0, |s| s.checkpoint_time);
    let mut since_cp = state.as_ref().map_or(0, |s| s.since_checkpoint);
    let on_feed = |fed: FeedEvent<'_>, offset_after: u64, newline_after: bool| match fed {
        FeedEvent::Record(record, rs) => {
            (cp_time, since_cp) = next_cp_fields(Some((cp_time, since_cp)), record);
            running_state = Some(rs.clone());
            bytes
                .borrow_mut()
                .note_record_fed(offset_after, newline_after);
            if expected == Some(rs.head) {
                *fc.borrow_mut() = Some(record.clone());
            }
        }
        FeedEvent::Duplicate => {}
        FeedEvent::NonRecord => {
            if running_state.is_some() {
                bytes.borrow_mut().note_newline(newline_after);
            }
        }
    };

    #[rustfmt::skip]
    let walk_args = HistorySegmentArgs { ctx, prior_run, unsealed_boundary, run_in: *run, trail };
    let walk =
        runs::history_segment::<State, _, _, _>(reaction, walk_args, strict, events, on_feed);
    // Addendum 22.2: writeback `found` BEFORE propagating Err, so the
    // strict pass's partial writes survive on `CorruptTrail` and on a
    // tolerant-side Err. Base threaded `&mut found` directly through
    // both passes, so a partial write at record N was visible to the
    // caller even when record N+1 broke the fold.
    *found = found_cell.into_inner();
    match walk? {
        HistorySegmentWalk::Strict(next) => {
            *run = false;
            Ok((Some(next), Vec::new()))
        }
        HistorySegmentWalk::Tolerant(outcome) => {
            let outcome = *outcome;
            *run = outcome.run_flag;
            let bytes = bytes.into_inner();
            let violations = outcome.violations;
            // Ruling 197-d1 addendum 27 continuation: thread the
            // classifier's own folded state (identical to
            // `running_state` under Stop, authoritative under
            // Collect). Under Collect the tolerant arm's `on_feed`
            // record branch does not fire (dispatch_line's
            // `(Tolerant, Collect)` arm calls `feed_record_collect`
            // without an `on_feed(Record, rs)` call), so a separate
            // `running_state` would stay `None` where the classifier
            // already has `Some`. Using `outcome.state` keeps Stop
            // byte-identical and gives Collect the same `Ok(state)`
            // Stop returns on `[cp0, close1, garbage\n]`.
            let final_run = outcome.state.clone().or(running_state);
            Ok((
                final_run.map(|run_state| State {
                    run: run_state,
                    offset: bytes.last_offset(),
                    length: bytes.offset_cursor(),
                    checkpoint_time: cp_time,
                    since_checkpoint: since_cp,
                    newline: bytes.last_newline(),
                    gap: outcome.gap,
                }),
                violations,
            ))
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
    let (state, _) = scan_inner(
        Reaction::Stop,
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
    )?;
    Ok(state.expect("scan_staged Stop implies state=Some"))
}
pub(crate) fn scan_closing(
    reaction: Reaction,
    file: &File,
    trail: [u8; 16],
    state: Option<State>,
    expected: Option<Head>,
    found: &mut Option<Record>,
    run: bool,
) -> Result<SegmentOutcome, AuditError> {
    scan_inner(
        reaction,
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
    segments_after_from(dir, &old, &cache.sealed_before)
}

/// `segments_after` with the cache's `(old, sealed_before)` passed
/// directly, so [`SegmentSource::for_refresh_rotate`] can capture them
/// at construction and defer the actual listing until after the
/// prelude has been yielded.
fn segments_after_from(
    dir: &File,
    old: &std::fs::Metadata,
    sealed_before: &Option<PathBuf>,
) -> Result<(Vec<PathBuf>, Option<PathBuf>), AuditError> {
    let names = crate::rotate::rotated_names_at(dir, "audit").map_err(io_error)?;
    let mut boundary = sealed_before.clone();
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
    if (old.dev(), old.ino()) == (live.st_dev as u64, live.st_ino as u64) {
        if old.len() < cache.state.length {
            return Err(corrupt("live file shrank below cached length"));
        }
        if old.len() > cache.state.length {
            let mut source = SegmentSource::for_refresh_append(dir, cache)?;
            let out = runs::classify(
                runs::ClassifyArgs {
                    trail,
                    prior_state: Some(cache.state.clone()),
                },
                runs::ReaderPath::RefreshAppend,
                &mut source,
                Reaction::Stop,
            )?;
            // Stop invariant: live arm yields `Some(state)` on Ok;
            // `ok_or_else` is defence-in-depth (no new corrupt site).
            cache.state = out.final_state.ok_or_else(|| {
                AuditError::new(
                    AuditErrorKind::HeadMismatch,
                    "expected head absent or different",
                )
            })?;
        }
        return Ok(());
    }
    if old.len() < cache.state.length {
        return Err(corrupt("old live descriptor was truncated"));
    }
    let mut source = SegmentSource::for_refresh_rotate(dir, cache)?;
    let out = runs::classify(
        runs::ClassifyArgs {
            trail,
            prior_state: Some(cache.state.clone()),
        },
        runs::ReaderPath::RefreshRotate,
        &mut source,
        Reaction::Stop,
    )?;
    // Stop invariant: live arm yields `Some(state)` / `Some(file)` on
    // Ok; `ok_or_else` is defence-in-depth (no new corrupt site).
    let state = out.final_state.ok_or_else(|| {
        AuditError::new(
            AuditErrorKind::HeadMismatch,
            "expected head absent or different",
        )
    })?;
    let file = out.live_file.ok_or_else(|| {
        AuditError::new(
            AuditErrorKind::HeadMismatch,
            "expected head absent or different",
        )
    })?;
    *cache = Cache {
        file,
        state,
        sealed_before: out.sealed_before,
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
#[expect(
    clippy::too_many_arguments,
    reason = "addendum 27.1 adds a Reaction parameter to the base-order shim"
)]
pub(crate) fn scan(
    reaction: Reaction,
    file: &File,
    trail: [u8; 16],
    state: Option<State>,
    opening: bool,
    expected: Option<Head>,
    found: &mut Option<Record>,
    genesis: bool,
) -> Result<SegmentOutcome, AuditError> {
    scan_inner(
        reaction,
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

/// Ruling 197-d1 addendum 24.1: `scan_inner` is now a thin shim over
/// [`runs::scan_segment`]. The shim performs byte-level I/O only (file
/// clone + seek + glued-byte / LF check + `BufReader` setup + physical
/// `read_line` + [`super::lines::classify`] into a [`DecodedLine`]),
/// computes `initial_boundary_resume` (opening && (ctx.run ||
/// predecessor-not-sealed)), and threads the writer-only State fields
/// through the strict `on_feed` callback. All strict segment-level and
/// per-record classification lives in `runs::scan_segment` (addendum
/// 24.2: "No second strict loop may exist anywhere"); `history_segment`
/// composes through this shim, so a single strict walk serves every
/// reader path (`scan` ×3, `scan_staged` ×2, `scan_closing` ×2,
/// `history_segment`'s strict pass).
fn scan_inner(
    reaction: Reaction,
    file: &File,
    trail: [u8; 16],
    state: Option<State>,
    expected: Option<Head>,
    found: &mut Option<Record>,
    context: SegmentContext,
) -> Result<SegmentOutcome, AuditError> {
    let start = if context.opening {
        0
    } else {
        state.as_ref().map_or(0, |s| s.offset)
    };
    let needs_glue = !context.opening
        && state
            .as_ref()
            .is_some_and(|s| !s.newline && s.gap.is_none());
    let initial_last_offset = state.as_ref().map_or(start, |s| s.offset);
    let initial_last_newline = state.as_ref().is_none_or(|s| s.newline);
    // `boundary_resume` starts set at an opening that either opens a run or
    // follows an unsealed predecessor; the first successor must then be an
    // immediate `vigil.audit.resume`.
    let initial_boundary_resume =
        context.opening && (context.run || state.as_ref().is_some_and(|s| !sealed(s)));
    let mut cp_time = state.as_ref().map_or(0, |s| s.checkpoint_time);
    let mut since_cp = state.as_ref().map_or(0, |s| s.since_checkpoint);
    let prior_run = state.map(|s| s.run);
    // Byte-level I/O: the strict-side pre-events-loop glue check, the
    // seek, `read_line` and `decode_line_kind` all live inside
    // [`SegmentBytes`]. A complete JSON record lacking LF was already
    // consumed by a prior walk; the first byte here terminates it and
    // is not a blank line or a repair gap.
    let bytes = RefCell::new(SegmentBytes::new(
        file,
        start,
        needs_glue,
        initial_last_offset,
        initial_last_newline,
    )?);
    bytes.borrow_mut().check_glue_byte_strict()?;
    let events = || -> Result<Option<DecodedLine>, AuditError> { bytes.borrow_mut().next_event() };
    // Reader-side `on_feed`: advances `last_offset`/`last_newline` via
    // [`SegmentBytes::note_record_fed`] / `note_newline`, the writer-
    // only `cp_time`/`since_cp` via `next_cp_fields`, and the
    // `expected`/`found` out-parameter. Duplicate leaves `cp_time`/
    // `since_cp` untouched (base-identical), but the `found` writeback
    // fires on BOTH advances.
    let on_feed = |fed: FeedEventStrict<'_>, offset_after: u64, newline: bool| match fed {
        FeedEventStrict::Record(record, rs) => {
            (cp_time, since_cp) = next_cp_fields(Some((cp_time, since_cp)), record);
            if expected == Some(rs.head) {
                *found = Some(record.clone());
            }
            bytes.borrow_mut().note_record_fed(offset_after, newline);
        }
        FeedEventStrict::Duplicate(record) => {
            // Base-identical: the duplicate branch still writes `found`
            // when the classifier's state head matches `expected`.
            if expected == Some(Head::of(record)) {
                *found = Some(record.clone());
            }
            bytes.borrow_mut().note_record_fed(offset_after, newline);
        }
        FeedEventStrict::NonRecord => {
            bytes.borrow_mut().note_newline(newline);
        }
    };
    let outcome = runs::scan_segment(
        reaction,
        ScanSegmentArgs {
            ctx: context,
            trail,
            prior_run,
            initial_boundary_resume,
        },
        events,
        on_feed,
    )?;
    // Invariant: under `Reaction::Stop` an Ok `scan_segment` returns
    // `state = Some(_)`. Proof: the Ok(Reaction::Stop) branch of
    // `scan_segment` wraps `classifier.finish()?` into
    // `ScanSegmentOutcome { state: Some(finished.state), .. }`
    // (runs.rs `scan_segment`), and `Classifier::finish`'s own invariant
    // rejects a `state = None` path with `Violation::MissingHead`. Under
    // `Reaction::Collect` the state may be `None` if the collector
    // recorded without folding a complete record (addendum 27.1).
    let bytes = bytes.into_inner();
    let state = outcome.state.map(|run| State {
        run,
        offset: bytes.last_offset(),
        length: bytes.offset_cursor(),
        checkpoint_time: cp_time,
        since_checkpoint: since_cp,
        newline: bytes.last_newline(),
        gap: outcome.gap,
    });
    Ok((state, outcome.violations))
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
