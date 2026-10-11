//! Read-side state for #11. B2b settles staging files and checks the marker
//! before invoking this boundary; it also owns repair writes and durability.
//! This module never creates a data file, writes bytes or checks signatures.
use super::{AuditError, AuditErrorKind, Kind, Record};
use crate::{audit::Mmr, rotate::Directory};
use rustix::fs::{self as rfs, Mode, OFlags};
use std::{
    fs::File,
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
    path::Path,
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
    length: u64,
    checkpoint: bool,
    newline: bool,
    gap: Option<blake3::Hasher>,
    pending_resume: bool,
    checkpoint_predecessor: Option<Head>,
    checkpoint_previous: [u8; 32],
}
impl State {
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
struct Cache {
    file: File,
    state: State,
}

/// Retains the old live descriptor across rotations, preventing inode reuse.
/// Lock order: directory gate/flock, then cache; never acquire a telemetry
/// directory lock inside this section (ADR-0002 d3/d7/d13, ADR-0005 d2/d8).
pub(crate) struct TrailReader {
    directory: Directory,
    trail: [u8; 16],
    cache: Mutex<Cache>,
}
impl TrailReader {
    /// Scans an existing trail after B2b's staging settlement. `trail` comes
    /// from the checked marker. No signature trust is inferred from disk.
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

    /// B2b's append boundary: recheck the live inode and validate every newly
    /// observed record before handing the current descriptor to the writer.
    /// B2b must settle staging *inside this same directory lock*, before refresh;
    /// the callback provides that seam without nesting another flock.
    pub(crate) fn with_current<T>(
        &self,
        settle: impl FnOnce(&File) -> Result<(), AuditError>,
        f: impl FnOnce(&File, &File, &State) -> Result<T, AuditError>,
    ) -> Result<T, AuditError> {
        self.directory
            .with_lock(|dir| {
                settle(dir)?;
                let mut cache = self
                    .cache
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                refresh(dir, self.trail, &mut cache)?;
                f(dir, &cache.file, &cache.state)
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
fn existing(dir: &File, name: &Path) -> Result<File, AuditError> {
    rfs::openat(
        dir,
        name,
        OFlags::RDWR | OFlags::APPEND | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|e| {
        if e == rustix::io::Errno::NOENT {
            corrupt("missing trail file")
        } else {
            io_error(e.into())
        }
    })
}
fn initial(dir: &File, trail: [u8; 16], expected: Option<Head>) -> Result<Cache, AuditError> {
    let mut chain = None;
    let mut found = false;
    for name in crate::rotate::rotated_names_at(dir, "audit").map_err(io_error)? {
        let file = existing(dir, &name)?;
        chain = Some(scan(&file, trail, chain, true, expected, &mut found)?);
        sealed(chain.as_ref().ok_or_else(|| corrupt("empty segment"))?)?;
    }
    let file = existing(dir, Path::new("audit.jsonl"))?;
    let state = scan(&file, trail, chain, true, expected, &mut found)?;
    if expected.is_some() && !found {
        return Err(AuditError::new(
            AuditErrorKind::HeadMismatch,
            "expected head absent or different",
        ));
    }
    Ok(Cache { file, state })
}
fn sealed(state: &State) -> Result<(), AuditError> {
    // A complete JSON checkpoint without LF is still a record (ADR-0005 d5).
    if !state.checkpoint || state.gap.is_some() || state.pending_resume {
        return Err(corrupt(
            "rotation segment lacks a complete closing checkpoint",
        ));
    }
    Ok(())
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
    let mut found = false;
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
            )?;
        }
        return Ok(());
    }
    if old.len() < cache.state.length {
        return Err(corrupt("old live descriptor was truncated"));
    }
    let mut state = scan(
        &cache.file,
        trail,
        Some(cache.state.clone()),
        false,
        None,
        &mut found,
    )?;
    sealed(&state)?;
    // A slow writer may miss several rotations. Follow every intervening
    // segment; never jump directly from its old descriptor to the live head.
    for name in crate::rotate::rotated_names_at(dir, "audit").map_err(io_error)? {
        let file = existing(dir, &name)?;
        let metadata = file.metadata().map_err(io_error)?;
        if (metadata.dev(), metadata.ino()) == (old.dev(), old.ino()) {
            continue;
        }
        let candidate = scan(&file, trail, None, true, None, &mut found)?;
        if candidate.head.seq <= state.head.seq {
            continue;
        }
        state = scan(&file, trail, Some(state), true, None, &mut found)?;
        sealed(&state)?;
    }
    let file = existing(dir, Path::new("audit.jsonl"))?;
    let state = scan(&file, trail, Some(state), true, None, &mut found)?;
    *cache = Cache { file, state };
    Ok(())
}

/// Bounded reads: each payload is capped even when it is only a fragment.
fn scan(
    file: &File,
    trail: [u8; 16],
    mut state: Option<State>,
    opening: bool,
    expected: Option<Head>,
    found: &mut bool,
) -> Result<State, AuditError> {
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
            .take(1_000_002)
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
        if payload.len() > 1_000_000 {
            return Err(corrupt("audit line exceeds byte cap"));
        }
        let records = match Record::parse_line(payload) {
            Ok(records) => records,
            Err(_) if !first && fragment(payload) => {
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
        apply(record, &mut state)?;
        let s = state.as_mut().ok_or_else(|| corrupt("missing head"))?;
        if expected == Some(s.head) {
            *found = true;
        }
        s.offset = offset;
        s.newline = newline;
        first = false;
    }
    if first {
        return Err(corrupt("empty live file or missing opening checkpoint"));
    }
    let mut state = state.ok_or_else(|| corrupt("missing head"))?;
    if state.pending_resume {
        return Err(corrupt("resume checkpoint lacks its declaration"));
    }
    state.length = offset;
    state.gap = gap;
    Ok(state)
}
fn apply(record: &Record, state: &mut Option<State>) -> Result<(), AuditError> {
    let head = Head::of(record);
    let mut mmr = if let Some(s) = state.as_ref() {
        s.mmr.clone()
    } else {
        let Kind::Checkpoint(cp) = &record.kind else {
            return Err(corrupt("missing initial checkpoint"));
        };
        if head.seq == 0 && record.context.previous != Record::genesis(&record.context.trail) {
            return Err(corrupt("creation checkpoint does not link genesis"));
        }
        Mmr::from_peaks(cp.size, cp.peaks.clone()).map_err(|_| corrupt("invalid opening peaks"))?
    };
    let prior = state.as_ref().map(|s| s.head);
    let mut pending = false;
    if let Some(s) = state.as_ref() {
        if head == s.head {
            return Ok(());
        } // Collector-style identical duplicates add no leaf.
        if head.seq <= s.head.seq || record.context.previous != s.head.hash {
            return Err(corrupt(
                "record rolled back, changed or broke its hash link",
            ));
        }
        if s.pending_resume
            && !matches!(&record.kind, Kind::Entry(e) if e.action == "vigil.audit.resume")
        {
            return Err(corrupt("sequence gap lacks a resume declaration"));
        }
        if head.seq != s.head.seq + 1 {
            if !matches!(record.kind, Kind::Checkpoint(_)) {
                return Err(corrupt("sequence gap without checkpoint"));
            }
            pending = true;
        }
    }
    match &record.kind {
        Kind::Checkpoint(cp) => {
            if cp.size != mmr.size() || cp.root != mmr.root() || cp.peaks != mmr.peaks() {
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
            let (named, file) = details
                .split_once(" file=")
                .ok_or_else(|| corrupt("invalid resume details"))?;
            let (named, lost) = named
                .split_once(" lost_through=")
                .ok_or_else(|| corrupt("invalid resume loss bound"))?;
            let (seq, hash) = named
                .strip_prefix("head=")
                .and_then(|v| v.split_once(':'))
                .ok_or_else(|| corrupt("invalid resume head"))?;
            let seq = seq
                .parse::<u64>()
                .map_err(|_| corrupt("invalid resume head sequence"))?;
            if lost
                != s.head
                    .seq
                    .checked_sub(1)
                    .ok_or_else(|| corrupt("resume after creation checkpoint"))?
                    .to_string()
                || seq.to_string()
                    != named
                        .strip_prefix("head=")
                        .and_then(|v| v.split_once(':'))
                        .map_or("", |p| p.0)
                || seq >= s.head.seq
                || hash != crate::audit::digest_string(&s.checkpoint_previous)
                || s.checkpoint_predecessor.is_some_and(|p| p.seq != seq)
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
        newline: true,
        gap: None,
        pending_resume: pending,
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
