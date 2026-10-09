//! Multi-process-safe size rotation and age retention for JSON Lines files.
//!
//! [`RotatingFile`] appends whole lines to `<dir>/<signal>.jsonl`. Once a line
//! would push the file past [`RotationConfig::max_bytes`], the file is renamed
//! to a rotated segment and a fresh one is started; rotated segments whose last
//! write is older than [`RotationConfig::retention`] are deleted.
//!
//! # Concurrency contract
//!
//! Every process of a host may append to the same signal at once; the size
//! check, the rotation and the write happen under one exclusive `flock(2)`
//! (`std::fs::File::lock`) on the **directory** itself. A lock *file* would be
//! open to a check-then-act race (one process verifies the lock file, it is
//! unlinked, another creates and locks a fresh one, and both enter the critical
//! section). After locking, the directory handle's `(dev, ino)` is checked
//! against the path; a replaced or missing directory is reopened (recreated
//! `0700` if needed), re-locked and checked again, with bounded retries. All
//! critical-section file operations are relative to that locked descriptor.
//! A swap during an append therefore leaves that append in the old directory;
//! the next lock acquisition moves the writer to the replacement directory.
//! Locking the live data file is no option either: it is renamed away
//! on rotation, and a waiter would lock the renamed inode. After taking the lock
//! the writer compares the live path's `(dev, ino)` with its cached handle and
//! reopens when another process rotated in the meantime, so a record never
//! lands in a rotated segment.
//!
//! All signals in one directory share that lock. That costs nothing that
//! matters: the critical section is one `write(2)` plus an occasional rotation.
//! A `<signal>.jsonl.lock` left by an older build is ignored.
//!
//! * Safe across processes and threads on **local filesystems**. NFS (and
//!   other filesystems with weak `flock` semantics) is **not supported**.
//! * Rotation uses an **atomic no-replace rename**, relative to the locked
//!   directory descriptor (Linux `RENAME_NOREPLACE`, macOS `RENAME_EXCL`). Only
//!   when unsupported (`EINVAL`, `ENOSYS`, `EOPNOTSUPP`) does it fall back to
//!   directory-relative link/unlink, which requires hard-link support. If
//!   linking fails, the live file stays intact and the append returns the error.
//!   If both the live unlink and its undo fail, the error reports both failures;
//!   the next lock acquisition heals the live file only if a segment of the
//!   same signal in the locked directory shares its device and inode. It then
//!   unlinks the live name and creates a fresh file, preserving the segment's
//!   data. External backup links alone never trigger healing.
//! * Open **one** [`RotatingFile`] per signal per process and share it (for
//!   example in an `Arc`). Two `flock`s taken through different file
//!   descriptors block each other even inside one process, so every
//!   `RotatingFile` opened in this process for one directory (any signals)
//!   shares one lock descriptor (each keeps its own [`RotationConfig`]); opening
//!   twice neither deadlocks nor errors.
//! * A failed or partial write is rolled back (`set_len` to the pre-write
//!   length) before the error is returned, so a half line never glues onto the
//!   next record. A short `write(2)` counts as a failure.
//! * A forked child shares its parent's lock *open file description*: the two
//!   do not exclude each other. Call `open` **after** `fork`, not before.
//! * Reaching the same directory through a bind mount (or any second path to
//!   it) gives two lock handles in one process, which block each other; that
//!   is unsupported. Use one canonical path.
//! * Segments whose mtime is in the future are not pruned until that time has
//!   passed.
//! * Readers need no lock: a line is written with a single `write(2)` to an
//!   `O_APPEND` file, and rotation never replaces an existing segment. Atomic
//!   rename publishes one name; the link/unlink fallback can briefly expose two
//!   names for the same inode, including after a reported undo failure until
//!   the next lock acquisition heals it.
//!
//! # Layout
//!
//! ```text
//! <dir>/<signal>.jsonl                           live file
//! <dir>/<signal>-20261009T120000.123456789Z.jsonl rotated segment
//! <dir>/<signal>-20261009T120000.123456789Z_000001.jsonl  same-nanosecond collision
//! ```
//!
//! Signal names are `[a-z0-9_]+`, so no signal's live file can look like another
//! signal's segment. Segments order by `(stamp, counter)`; the stamp is fixed
//! width, so plain string order is chronological too (up to 999 999 same-instant
//! collisions, after which the counter simply grows a digit). Even if the clock
//! goes backwards, a new segment sorts strictly after the newest existing one.
//! Directories are created `0700`, files `0600`; on `open`, an existing
//! directory or live file with looser permissions is tightened (never
//! loosened).

use rustix::fs::{self as rfs, AtFlags, Mode, OFlags};
use rustix::io::Errno;
use std::collections::HashMap;
use std::fs::{self, DirBuilder, File};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MIB: u64 = 1024 * 1024;
const DAY: u64 = 86_400;

/// When to rotate a [`RotatingFile`] and how long to keep rotated segments.
///
/// ```
/// use std::time::Duration;
/// let cfg = vigil::rotate::RotationConfig::default();
/// assert_eq!(cfg.max_bytes, 50 * 1024 * 1024);
/// assert_eq!(cfg.retention, Some(Duration::from_secs(90 * 86_400)));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationConfig {
    /// Rotate before a write that would make the live file larger than this.
    /// A single line bigger than the limit is still written, alone in a fresh
    /// file. Default: 50 MiB.
    pub max_bytes: u64,
    /// Delete rotated segments whose last write is older than this. `None`
    /// keeps every segment. Default: 90 days.
    pub retention: Option<Duration>,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            max_bytes: 50 * MIB,
            retention: Some(Duration::from_secs(90 * DAY)),
        }
    }
}

/// The cached live handle, replaced whenever the file at the live name changes.
struct Live {
    file: File,
}

impl Live {
    fn open(dir: &File, name: &Path, signal: &str) -> io::Result<Self> {
        let mut file = open_private(dir, name)?;
        // A failed fallback undo may have left both the live and segment names
        // on this inode. Verify that the extra name is our segment, rather
        // than an external backup link, before starting a fresh live file.
        if has_segment_link(dir, signal, &rfs::fstat(&file)?)? {
            unlink_name(dir, name)?;
            file = open_private(dir, name)?;
        }
        Ok(Self { file })
    }

    fn refresh(&mut self, dir: &File, name: &Path, signal: &str) -> io::Result<()> {
        let cached = rfs::fstat(&self.file)?;
        match rfs::statat(dir, name, AtFlags::empty()) {
            Ok(current)
                if (current.st_dev, current.st_ino) == (cached.st_dev, cached.st_ino)
                    && !has_segment_link(dir, signal, &current)? => {}
            Ok(_) | Err(Errno::NOENT) => *self = Self::open(dir, name, signal)?,
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }
}

/// Only an extra link under this signal's segment name proves that rotation
/// left a duplicate. External backups must keep their live name and records.
fn has_segment_link(dir: &File, signal: &str, live: &rfs::Stat) -> io::Result<bool> {
    if live.st_nlink <= 1 {
        return Ok(false);
    }
    for name in rotated_names_at(dir, signal)? {
        match rfs::statat(dir, name, AtFlags::empty()) {
            Ok(segment) if (segment.st_dev, segment.st_ino) == (live.st_dev, live.st_ino) => {
                return Ok(true);
            }
            Ok(_) | Err(Errno::NOENT) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(false)
}

/// The directory lock shared by every [`RotatingFile`] of one directory in
/// this process.
struct DirLock {
    /// Serialises threads and holds the current directory handle. Replacing
    /// it updates the registry entry and every writer sharing this lock.
    gate: Mutex<File>,
}

impl DirLock {
    fn open(dir: &Path) -> io::Result<Self> {
        Ok(Self {
            gate: Mutex::new(File::open(dir)?),
        })
    }

    fn lock_current(&self, path: &Path) -> io::Result<(MutexGuard<'_, File>, Unlock)> {
        let mut dir = lock_ignore_poison(&self.gate);
        // A directory can be renamed away while we wait for its lock. Retry
        // with the replacement, but do not spin forever under repeated swaps.
        for _ in 0..8 {
            let unlock = Unlock(dir.try_clone()?);
            dir.lock()?;
            let locked = dir.metadata()?;
            match fs::metadata(path) {
                Ok(current) if (locked.dev(), locked.ino()) == (current.dev(), current.ino()) => {
                    return Ok((dir, unlock));
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            drop(unlock);
            DirBuilder::new().recursive(true).mode(0o700).create(path)?;
            tighten(path, 0o700)?;
            match File::open(path) {
                Ok(current) => *dir = current,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::other(
            "state directory changed repeatedly while locking",
        ))
    }
}

static REGISTRY: LazyLock<Mutex<HashMap<PathBuf, Weak<DirLock>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Appends whole lines to `<dir>/<signal>.jsonl`, rotating by size and pruning
/// by age, correctly when many processes write the same file.
///
/// `RotatingFile` is `Send + Sync`; share it between threads with an `Arc`.
/// Open one per signal per process (see the [module docs](self) for the full
/// concurrency contract).
///
/// ```
/// use std::sync::Arc;
/// use vigil::rotate::{RotatingFile, RotationConfig, segments};
///
/// let dir = std::env::temp_dir().join(format!("vigil-doc-rotate-{}", std::process::id()));
/// let cfg = RotationConfig { max_bytes: 64, retention: None };
/// let log = Arc::new(RotatingFile::open(&dir, "logs", cfg)?);
/// for i in 0..10 {
///     log.append(format!(r#"{{"i":{i}}}"#).as_bytes())?;
/// }
/// // Ten 8-byte records at 64 bytes per segment: more than one file.
/// let files = segments(&dir, "logs")?;
/// assert!(files.len() > 1);
/// assert_eq!(files.last().unwrap(), &dir.join("logs.jsonl"));
/// # std::fs::remove_dir_all(&dir)?;
/// # Ok::<(), std::io::Error>(())
/// ```
pub struct RotatingFile {
    lock: Arc<DirLock>,
    dir: PathBuf,
    signal: String,
    live_path: PathBuf,
    live: Mutex<Live>,
    cfg: RotationConfig,
}

impl std::fmt::Debug for RotatingFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotatingFile")
            .field("path", &self.live_path)
            .field("cfg", &self.cfg)
            .finish()
    }
}

impl RotatingFile {
    /// Open (creating as needed) the signal's directory (`0700`) and live file
    /// (`0600`), and prune expired segments once.
    ///
    /// Opening the same directory again in this process (for this or another
    /// signal) shares the first open's directory lock instead of deadlocking on
    /// it.
    ///
    /// # Errors
    ///
    /// `InvalidInput` unless `signal` matches `[a-z0-9_]+`; otherwise any I/O
    /// error from creating the directory or file.
    pub fn open(dir: &Path, signal: &str, cfg: RotationConfig) -> io::Result<Self> {
        validate_signal(signal)?;
        DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        let dir = fs::canonicalize(dir)?;
        tighten(&dir, 0o700)?;
        let lock = {
            let mut registry = lock_ignore_poison(&REGISTRY);
            registry.retain(|_, w| w.strong_count() > 0);
            match registry.get(&dir).and_then(Weak::upgrade) {
                Some(lock) => lock,
                None => {
                    let lock = Arc::new(DirLock::open(&dir)?);
                    registry.insert(dir.clone(), Arc::downgrade(&lock));
                    lock
                }
            }
        };
        Self::with_lock(lock, dir, signal, cfg)
    }

    fn with_lock(
        lock: Arc<DirLock>,
        dir: PathBuf,
        signal: &str,
        cfg: RotationConfig,
    ) -> io::Result<Self> {
        let live_path = dir.join(format!("{signal}.jsonl"));
        let live = {
            let (handle, _unlock) = lock.lock_current(&dir)?;
            let live = Live::open(&handle, Path::new(&format!("{signal}.jsonl")), signal)?;
            if let Some(keep) = cfg.retention {
                prune_at(&handle, signal, keep);
            }
            live
        };
        Ok(Self {
            lock,
            dir,
            signal: signal.to_owned(),
            live_path,
            live: Mutex::new(live),
            cfg,
        })
    }

    /// Append `line` plus a trailing `\n` with one `write(2)`.
    ///
    /// `line` must not contain the trailing newline (an embedded one would
    /// split the record). Rotates first when the line would not fit. If the
    /// write fails part-way the file is truncated back to its pre-write length
    /// and the error is returned.
    ///
    /// # Errors
    ///
    /// Any I/O error from locking, rotating or writing; pruning errors are
    /// ignored.
    pub fn append(&self, line: &[u8]) -> io::Result<()> {
        self.append_with(line, write_once)
    }

    /// [`append`](Self::append) with the write step injectable, so tests can
    /// simulate a partial write.
    fn append_with(
        &self,
        line: &[u8],
        write: impl FnOnce(&mut File, &[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut buf = Vec::with_capacity(line.len().saturating_add(1));
        buf.extend_from_slice(line);
        buf.push(b'\n');
        let need = buf.len() as u64;

        let (dir, _unlock) = self.lock.lock_current(&self.dir)?;
        let name = PathBuf::from(format!("{}.jsonl", self.signal));
        let mut live = lock_ignore_poison(&self.live);

        live.refresh(&dir, &name, &self.signal)?;

        let len = live.file.metadata()?.len();
        if len > 0 && len.checked_add(need).is_none_or(|n| n > self.cfg.max_bytes) {
            rotate(&dir, &self.signal, &name)?;
            *live = Live::open(&dir, &name, &self.signal)?;
            if let Some(keep) = self.cfg.retention {
                prune_at(&dir, &self.signal, keep);
            }
        }

        let before = live.file.metadata()?.len();
        if let Err(e) = write(&mut live.file, &buf) {
            // Best effort: never leave a half line for the next record.
            let _ = live.file.set_len(before);
            return Err(e);
        }
        Ok(())
    }
}

/// Releases the `flock` on drop, including on early return and panic. Holds a
/// clone of the lock descriptor (same open file description).
struct Unlock(File);

impl Drop for Unlock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

fn lock_ignore_poison<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Signal names are `[a-z0-9_]+`: no `-`, `.` or `/`, so a live file name can
/// never parse as a segment of another signal.
fn validate_signal(signal: &str) -> io::Result<()> {
    let ok = !signal.is_empty()
        && signal
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid signal name {signal:?}: expected [a-z0-9_]+"),
        ))
    }
}

/// Open (creating as needed) an `O_APPEND` data file, `0600`.
fn open_private(dir: &File, name: &Path) -> io::Result<File> {
    let file = File::from(rfs::openat(
        dir,
        name,
        OFlags::CREATE | OFlags::APPEND | OFlags::WRONLY | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )?);
    let mode = rfs::fstat(&file)?.st_mode & 0o7777;
    if mode & !0o600 != 0 {
        rfs::fchmod(&file, Mode::from_bits_truncate(mode & 0o600))?;
    }
    Ok(file)
}

/// Tighten (never loosen) `path` to at most `mask` permission bits, so a
/// directory or file that pre-dates us with looser modes does not leak.
fn tighten(path: &Path, mask: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)?.permissions().mode() & 0o7777;
    if mode & !mask != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(mode & mask))?;
    }
    Ok(())
}

/// One `write(2)`; a short write is an error (the caller rolls back), so a
/// lock-free reader never sees a line completed by a second call.
fn write_once(w: &mut impl Write, buf: &[u8]) -> io::Result<()> {
    let n = loop {
        match w.write(buf) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            r => break r?,
        }
    };
    if n == buf.len() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("short write: {n} of {} bytes", buf.len()),
        ))
    }
}

/// `YYYYMMDDTHHMMSS.nnnnnnnnnZ`: fixed width, so it sorts chronologically.
fn stamp(now: SystemTime) -> String {
    let d = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    stamp_at(d.as_secs(), d.subsec_nanos())
}

fn stamp_at(secs: u64, nanos: u32) -> String {
    let (y, m, d) = civil_from_days(i64::try_from(secs / DAY).unwrap_or(i64::MAX / 2));
    let rem = secs % DAY;
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}.{nanos:09}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 → proleptic Gregorian (year, month, day).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month as u32, day as u32)
}

const STAMP_LEN: usize = "YYYYMMDDTHHMMSS.nnnnnnnnnZ".len();

/// Parse `<signal>-<stamp>[_NNNNNN].jsonl` into `(stamp, counter)`. Only this
/// exact shape counts, so `logs-2.jsonl` is not a segment of `logs`. The counter
/// has at least six digits (it grows a digit past 999 999).
fn parse_segment<'a>(name: &'a str, signal: &str) -> Option<(&'a str, u64)> {
    let rest = name
        .strip_prefix(signal)?
        .strip_prefix('-')?
        .strip_suffix(".jsonl")?;
    let stamp = rest.get(..STAMP_LEN)?;
    let digits = |s: &[u8]| s.iter().all(u8::is_ascii_digit);
    let b = stamp.as_bytes();
    let shaped = digits(&b[..8])
        && b[8] == b'T'
        && digits(&b[9..15])
        && b[15] == b'.'
        && digits(&b[16..25])
        && b[25] == b'Z';
    if !shaped {
        return None;
    }
    match &rest[STAMP_LEN..] {
        "" => Some((stamp, 0)),
        tail => {
            let n = tail.strip_prefix('_')?;
            if n.len() < 6 || !digits(n.as_bytes()) {
                return None;
            }
            Some((stamp, n.parse().ok()?))
        }
    }
}

/// The name for the next rotated segment: sorts strictly after `newest`, the
/// newest existing segment, even if the clock went backwards. The collision
/// suffix `_NNNNNN` sorts after the bare name (`_` > `.`) and counts up.
fn next_segment_name(signal: &str, now: &str, newest: Option<&str>) -> String {
    match newest.and_then(|n| parse_segment(n, signal)) {
        Some((stamp, counter)) if stamp >= now => {
            format!("{signal}-{stamp}_{:06}.jsonl", counter.saturating_add(1))
        }
        _ => format!("{signal}-{now}.jsonl"),
    }
}

/// Rotate relative to the locked directory, atomically and without replacing
/// an existing segment. Fall back only when the no-replace operation is absent.
fn rotate(dir: &File, signal: &str, live_name: &Path) -> io::Result<()> {
    rotate_with(dir, signal, live_name, rename_new, unlink_name)
}

fn rename_new(dir: &File, old: &Path, new: &Path) -> io::Result<()> {
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "redox"
    ))]
    {
        // On Apple targets rustix maps NOREPLACE to RENAME_EXCL.
        rfs::renameat_with(dir, old, dir, new, rfs::RenameFlags::NOREPLACE)?;
        Ok(())
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "redox"
    )))]
    {
        let _ = (dir, old, new);
        Err(Errno::NOSYS.into())
    }
}

fn unlink_name(dir: &File, name: &Path) -> io::Result<()> {
    rfs::unlinkat(dir, name, AtFlags::empty())?;
    Ok(())
}

/// Injectable rename/unlink steps, like the partial-write seam in `append_with`.
fn rotate_with(
    dir: &File,
    signal: &str,
    live_name: &Path,
    mut rename: impl FnMut(&File, &Path, &Path) -> io::Result<()>,
    mut unlink: impl FnMut(&File, &Path) -> io::Result<()>,
) -> io::Result<()> {
    let now = stamp(SystemTime::now());
    let mut newest = rotated_names_at(dir, signal)?
        .pop()
        .and_then(|p| p.to_str().map(str::to_owned));
    loop {
        let name = next_segment_name(signal, &now, newest.as_deref());
        let target = Path::new(&name);
        let result = match rename(dir, live_name, target) {
            Err(e)
                if [Errno::INVAL, Errno::NOSYS, Errno::OPNOTSUPP]
                    .iter()
                    .any(|code| e.raw_os_error() == Some(code.raw_os_error())) =>
            {
                match rfs::linkat(dir, live_name, dir, target, AtFlags::empty()) {
                    Ok(()) => {
                        if let Err(original) = unlink(dir, live_name) {
                            if let Err(undo) = unlink(dir, target) {
                                return Err(io::Error::other(format!(
                                    "unlink live {live_name:?} failed: {original}; undo segment {target:?} failed: {undo}"
                                )));
                            }
                            return Err(original);
                        }
                        Ok(())
                    }
                    Err(e) => Err(e.into()),
                }
            }
            result => result,
        };
        match result {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => newest = Some(name),
            Err(e) => return Err(e),
        }
    }
}

fn rotated_names_at(dir: &File, signal: &str) -> io::Result<Vec<PathBuf>> {
    let mut names = Vec::new();
    for entry in rfs::Dir::read_from(dir)? {
        let entry = entry?;
        if let Ok(name) = entry.file_name().to_str()
            && is_segment_name(name, signal)
        {
            names.push(PathBuf::from(name));
        }
    }
    names.sort_by_key(|p| segment_key(p, signal));
    Ok(names)
}

/// Whether `name` is a rotated segment of `signal`.
fn is_segment_name(name: &str, signal: &str) -> bool {
    parse_segment(name, signal).is_some()
}

/// Sort key `(stamp, counter)` of a segment path (chronological).
fn segment_key(path: &Path, signal: &str) -> (String, u64) {
    path.file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| parse_segment(n, signal))
        .map_or_else(Default::default, |(s, c)| (s.to_owned(), c))
}

fn rotated_segments(dir: &Path, signal: &str) -> io::Result<Vec<PathBuf>> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir)?
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| is_segment_name(n, signal))
        })
        .map(|e| e.path())
        .collect();
    v.sort_by_key(|p| segment_key(p, signal));
    Ok(v)
}

fn mtime(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Delete rotated segments last written more than `keep` ago. Never touches
/// the live or lock file; errors are ignored.
fn prune_at(dir: &File, signal: &str, keep: Duration) {
    let Ok(names) = rotated_names_at(dir, signal) else {
        return;
    };
    let now = SystemTime::now();
    for name in names {
        let expired = rfs::statat(dir, &name, AtFlags::empty())
            .ok()
            .and_then(|m| {
                let secs = Duration::from_secs(m.st_mtime.unsigned_abs());
                let base = if m.st_mtime >= 0 {
                    UNIX_EPOCH.checked_add(secs)
                } else {
                    UNIX_EPOCH.checked_sub(secs)
                }?;
                base.checked_add(Duration::new(0, u32::try_from(m.st_mtime_nsec).ok()?))
            })
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age > keep);
        if expired {
            let _ = unlink_name(dir, &name);
        }
    }
}

/// Every segment of `signal` in `dir`, oldest → newest: the rotated segments
/// in chronological order, then the live file (if it exists).
///
/// ```
/// let dir = std::env::temp_dir().join(format!("vigil-doc-segments-{}", std::process::id()));
/// assert!(vigil::rotate::segments(&dir, "metrics").is_err()); // no such dir
/// ```
///
/// # Errors
///
/// The error from reading `dir`.
pub fn segments(dir: &Path, signal: &str) -> io::Result<Vec<PathBuf>> {
    let mut v = rotated_segments(dir, signal)?;
    let live = dir.join(format!("{signal}.jsonl"));
    if live.exists() {
        v.push(live);
    }
    Ok(v)
}

/// Like [`segments`], keeping only segments last written at or after `since`
/// (all of them when `None`). A segment's mtime is its newest record, so this
/// never skips a segment that holds a record in the window.
///
/// ```
/// let dir = std::env::temp_dir().join(format!("vigil-doc-since-{}", std::process::id()));
/// let log = vigil::rotate::RotatingFile::open(&dir, "traces", Default::default())?;
/// log.append(b"{}")?;
/// let now = std::time::SystemTime::now();
/// let hour = std::time::Duration::from_secs(3600);
/// assert_eq!(vigil::rotate::segments_since(&dir, "traces", Some(now - hour))?.len(), 1);
/// assert!(vigil::rotate::segments_since(&dir, "traces", Some(now + hour))?.is_empty());
/// # std::fs::remove_dir_all(&dir)?;
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// # Errors
///
/// The error from reading `dir`.
pub fn segments_since(
    dir: &Path,
    signal: &str,
    since: Option<SystemTime>,
) -> io::Result<Vec<PathBuf>> {
    let mut v = segments(dir, signal)?;
    if let Some(cut) = since {
        v.retain(|p| mtime(p).is_none_or(|t| t >= cut));
    }
    Ok(v)
}

/// The lines of one segment (lossy UTF-8, no trailing newline). A segment that
/// was pruned in the meantime reads as empty.
fn read_segment(path: &Path) -> io::Result<Vec<String>> {
    match fs::read(path) {
        Ok(bytes) => Ok(bytes
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|l| String::from_utf8_lossy(l).into_owned())
            .collect()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// All lines of every segment last written at or after `since`, oldest first.
///
/// ```
/// use vigil::rotate::{RotatingFile, read_since};
/// let dir = std::env::temp_dir().join(format!("vigil-doc-read-{}", std::process::id()));
/// let log = RotatingFile::open(&dir, "logs", Default::default())?;
/// log.append(b"a")?;
/// log.append(b"b")?;
/// assert_eq!(read_since(&dir, "logs", None)?, ["a", "b"]);
/// # std::fs::remove_dir_all(&dir)?;
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// # Errors
///
/// Any I/O error from listing or reading the segments.
pub fn read_since(dir: &Path, signal: &str, since: Option<SystemTime>) -> io::Result<Vec<String>> {
    let mut out = Vec::new();
    for p in segments_since(dir, signal, since)? {
        out.extend(read_segment(&p)?);
    }
    Ok(out)
}

/// Search newest first (newest segment, newest line within it) and return the
/// first `Some` that `pick` yields. Use it for "find the record with this id",
/// which is usually near the end.
///
/// ```
/// use vigil::rotate::{RotatingFile, find_newest};
/// let dir = std::env::temp_dir().join(format!("vigil-doc-find-{}", std::process::id()));
/// let log = RotatingFile::open(&dir, "logs", Default::default())?;
/// log.append(b"id=1 old")?;
/// log.append(b"id=1 new")?;
/// let hit = find_newest(&dir, "logs", |l| l.starts_with("id=1").then(|| l.to_owned()))?;
/// assert_eq!(hit.as_deref(), Some("id=1 new"));
/// # std::fs::remove_dir_all(&dir)?;
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// # Errors
///
/// Any I/O error from listing or reading the segments.
pub fn find_newest<T>(
    dir: &Path,
    signal: &str,
    mut pick: impl FnMut(&str) -> Option<T>,
) -> io::Result<Option<T>> {
    for p in segments(dir, signal)?.iter().rev() {
        for line in read_segment(p)?.iter().rev() {
            if let Some(found) = pick(line) {
                return Ok(Some(found));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::process::Command;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn tmp(name: &str) -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let d = std::env::temp_dir().join(format!(
            "vigil-rotate-{name}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn cfg(max_bytes: u64) -> RotationConfig {
        RotationConfig {
            max_bytes,
            retention: None,
        }
    }

    fn all_lines(dir: &Path, signal: &str) -> Vec<String> {
        read_since(dir, signal, None).unwrap()
    }

    #[test]
    fn defaults() {
        let c = RotationConfig::default();
        assert_eq!(c.max_bytes, 50 * 1024 * 1024);
        assert_eq!(c.retention, Some(Duration::from_secs(90 * 86_400)));
    }

    #[test]
    fn creates_dir_and_files_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp("modes").join("nested");
        let log = RotatingFile::open(&d, "logs", cfg(1000)).unwrap();
        log.append(b"{}").unwrap();
        let mode = |p: PathBuf| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(d.clone()), 0o700);
        assert_eq!(mode(d.join("logs.jsonl")), 0o600);
        fs::remove_dir_all(d.parent().unwrap()).unwrap();
    }

    #[test]
    fn rejects_bad_signal_names() {
        let d = tmp("badsig");
        for s in [
            "",
            ".",
            "..",
            "a/b",
            "a\0b",
            "a-b",
            "a.b",
            "Logs",
            "logs-20000101T000000.000000000Z",
        ] {
            let e = RotatingFile::open(&d, s, cfg(10)).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{s:?}");
        }
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn rotates_past_the_limit_without_losing_records() {
        let d = tmp("rotate");
        let log = RotatingFile::open(&d, "calls", cfg(200)).unwrap();
        for i in 0..10 {
            log.append(format!(r#"{{"i":{i},"pad":"{}"}}"#, "x".repeat(60)).as_bytes())
                .unwrap();
        }
        let segs = segments(&d, "calls").unwrap();
        assert!(segs.len() >= 4, "expected several segments: {segs:?}");
        assert_eq!(all_lines(&d, "calls").len(), 10);
        for p in &segs {
            assert!(fs::metadata(p).unwrap().len() <= 200, "{p:?} over limit");
        }
        assert_eq!(segs.last().unwrap(), &d.join("calls.jsonl"));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn records_stay_in_order_across_segments() {
        let d = tmp("order");
        let log = RotatingFile::open(&d, "s", cfg(30)).unwrap();
        for i in 0..40 {
            log.append(format!("{i:05}").as_bytes()).unwrap();
        }
        let got = all_lines(&d, "s");
        let want: Vec<String> = (0..40).map(|i| format!("{i:05}")).collect();
        assert_eq!(got, want);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn exact_fit_does_not_rotate_but_one_more_byte_does() {
        let d = tmp("fit");
        let log = RotatingFile::open(&d, "s", cfg(10)).unwrap();
        log.append(b"1234").unwrap(); // 5 bytes
        log.append(b"1234").unwrap(); // 10 bytes: exactly the limit
        assert_eq!(segments(&d, "s").unwrap().len(), 1);
        log.append(b"1").unwrap(); // would make 12
        assert_eq!(segments(&d, "s").unwrap().len(), 2);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn oversize_line_is_written_alone_in_a_fresh_file() {
        let d = tmp("oversize");
        let log = RotatingFile::open(&d, "s", cfg(10)).unwrap();
        log.append(b"ab").unwrap();
        log.append(&[b'x'; 50]).unwrap();
        log.append(b"cd").unwrap();
        let segs = segments(&d, "s").unwrap();
        let contents: Vec<Vec<String>> = segs.iter().map(|p| read_segment(p).unwrap()).collect();
        assert_eq!(contents.len(), 3, "{segs:?}");
        assert_eq!(contents[0], ["ab"]);
        assert_eq!(contents[1], ["x".repeat(50)]);
        assert_eq!(contents[2], ["cd"]);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn size_arithmetic_does_not_overflow() {
        let d = tmp("overflow");
        let log = RotatingFile::open(&d, "s", cfg(u64::MAX)).unwrap();
        log.append(b"a").unwrap();
        log.append(b"b").unwrap();
        assert_eq!(all_lines(&d, "s"), ["a", "b"]);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn concurrent_threads_rotate_safely() {
        let d = tmp("threads");
        let log = Arc::new(RotatingFile::open(&d, "s", cfg(1_000)).unwrap());
        std::thread::scope(|sc| {
            for t in 0..8 {
                let log = Arc::clone(&log);
                sc.spawn(move || {
                    for i in 0..50 {
                        log.append(
                            format!(r#"{{"t":{t},"i":{i},"pad":"{}"}}"#, "y".repeat(40)).as_bytes(),
                        )
                        .unwrap();
                    }
                });
            }
        });
        let lines = all_lines(&d, "s");
        assert_eq!(lines.len(), 400, "every record survives rotation");
        let seen: HashSet<&String> = lines.iter().collect();
        assert_eq!(seen.len(), 400, "no duplicates");
        for p in segments(&d, "s").unwrap() {
            assert!(fs::metadata(&p).unwrap().len() <= 1_000);
        }
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn second_open_in_the_same_process_shares_and_does_not_deadlock() {
        let d = tmp("reopen");
        let a = RotatingFile::open(&d, "s", cfg(40)).unwrap();
        let b = RotatingFile::open(&d, "s", cfg(40)).unwrap();
        assert!(Arc::ptr_eq(&a.lock, &b.lock));
        let (a, b) = (Arc::new(a), Arc::new(b));
        let (tx, rx) = std::sync::mpsc::channel();
        for log in [a, b] {
            let tx = tx.clone();
            std::thread::spawn(move || {
                for i in 0..30 {
                    log.append(format!("{i:03}").as_bytes()).unwrap();
                }
                tx.send(()).unwrap();
            });
        }
        for _ in 0..2 {
            rx.recv_timeout(Duration::from_secs(30))
                .expect("appends deadlocked");
        }
        assert_eq!(all_lines(&d, "s").len(), 60);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn distinct_signals_in_one_dir_are_independent() {
        let d = tmp("signals");
        let a = RotatingFile::open(&d, "logs", cfg(20)).unwrap();
        let b = RotatingFile::open(&d, "logs_extra", cfg(20)).unwrap();
        for i in 0..6 {
            a.append(format!("a{i}").as_bytes()).unwrap();
            b.append(format!("b{i}").as_bytes()).unwrap();
        }
        assert!(all_lines(&d, "logs").iter().all(|l| l.starts_with('a')));
        assert_eq!(all_lines(&d, "logs").len(), 6);
        assert_eq!(all_lines(&d, "logs_extra").len(), 6);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn stale_inode_is_reopened_after_an_outside_rename() {
        let d = tmp("stale");
        let log = RotatingFile::open(&d, "s", cfg(1_000_000)).unwrap();
        log.append(b"before").unwrap();
        // Another process rotates the file behind our cached handle.
        fs::rename(
            d.join("s.jsonl"),
            d.join("s-20200101T000000.000000000Z.jsonl"),
        )
        .unwrap();
        log.append(b"after").unwrap();
        assert_eq!(
            fs::read_to_string(d.join("s-20200101T000000.000000000Z.jsonl")).unwrap(),
            "before\n"
        );
        assert_eq!(fs::read_to_string(d.join("s.jsonl")).unwrap(), "after\n");
        // Also when the live file was deleted outright.
        fs::remove_file(d.join("s.jsonl")).unwrap();
        log.append(b"again").unwrap();
        assert_eq!(fs::read_to_string(d.join("s.jsonl")).unwrap(), "again\n");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn same_instant_rotations_never_overwrite() {
        let d = tmp("collide");
        fs::create_dir_all(&d).unwrap();
        let st = "20261009T120000.123456789Z";
        let mut names: Vec<String> = Vec::new();
        for i in 0..12 {
            let n = next_segment_name("s", st, names.last().map(String::as_str));
            assert!(!d.join(&n).exists());
            fs::write(d.join(&n), i.to_string()).unwrap();
            names.push(n);
        }
        let unique: HashSet<_> = names.iter().collect();
        assert_eq!(unique.len(), 12);
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(sorted, names, "creation order == string order");
        for (i, n) in names.iter().enumerate() {
            assert_eq!(fs::read_to_string(d.join(n)).unwrap(), i.to_string());
        }
        assert!(names.iter().all(|n| is_segment_name(n, "s")));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn backwards_clock_still_orders_segments() {
        let d = tmp("clock");
        let log = RotatingFile::open(&d, "s", cfg(10)).unwrap();
        let future = d.join("s-29990101T000000.000000000Z.jsonl");
        fs::write(&future, "future\n").unwrap();
        for i in 0..3 {
            log.append(format!("rec{i}aaa").as_bytes()).unwrap();
        }
        let names: Vec<String> = segments(&d, "s")
            .unwrap()
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_owned())
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names[..names.len() - 1], sorted[..names.len() - 1]);
        assert_eq!(names.last().unwrap(), "s.jsonl");
        // The newest rotated segment is the one just rotated, not the planted one.
        let newest = &names[names.len() - 2];
        assert_ne!(newest, "s-29990101T000000.000000000Z.jsonl");
        assert!(
            newest.as_str() > "s-29990101T000000.000000000Z.jsonl",
            "{names:?}"
        );
        let hit = find_newest(&d, "s", |l| l.starts_with("rec").then(|| l.to_owned())).unwrap();
        assert_eq!(hit.as_deref(), Some("rec2aaa"));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn signals_sharing_a_prefix_do_not_see_each_others_files() {
        let d = tmp("prefix");
        let old = RotationConfig {
            max_bytes: 1000,
            retention: Some(Duration::from_secs(90 * 86_400)),
        };
        let sigs = ["logs", "logs_2", "logs_2024"];
        let handles: Vec<_> = sigs
            .iter()
            .map(|s| RotatingFile::open(&d, s, cfg(1000)).unwrap())
            .collect();
        for (h, s) in handles.iter().zip(sigs) {
            h.append(format!("{s}-record").as_bytes()).unwrap();
        }
        for s in sigs {
            assert_eq!(segments(&d, s).unwrap(), [d.join(format!("{s}.jsonl"))]);
            assert_eq!(all_lines(&d, s), [format!("{s}-record")]);
            age(&d.join(format!("{s}.jsonl")), 200);
        }
        // Opening `logs` with retention prunes only its own segments.
        let seg = d.join("logs-20250101T000000.000000000Z.jsonl");
        fs::write(&seg, "x\n").unwrap();
        age(&seg, 200);
        drop(handles);
        let _again = RotatingFile::open(&d, "logs", old).unwrap();
        assert!(!seg.exists());
        for s in sigs {
            assert!(
                d.join(format!("{s}.jsonl")).exists(),
                "{s} live file deleted"
            );
        }
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn segment_name_parser_is_strict() {
        let ok = "20261009T120000.123456789Z";
        assert_eq!(parse_segment(&format!("s-{ok}.jsonl"), "s"), Some((ok, 0)));
        assert_eq!(
            parse_segment(&format!("s-{ok}_000007.jsonl"), "s"),
            Some((ok, 7))
        );
        for bad in [
            "s-2.jsonl",
            "s-2024.jsonl",
            "s-20261009T120000.123456789Z_7.jsonl",
            "s-20261009T120000.123456789Z_00000x.jsonl",
            "s-20261009T120000.123456789.jsonl",
            "s-20261009T120000.123456789Zx.jsonl",
            "s-20261009x120000.123456789Z.jsonl",
            "s-2026100９T120000.123456789Z.jsonl",
            "s-.jsonl",
        ] {
            assert_eq!(parse_segment(bad, "s"), None, "{bad}");
        }
    }

    /// Open a handle that bypasses the per-process registry (so it gets its
    /// own directory descriptor), standing in for another process.
    fn open_independent(dir: &Path, signal: &str, cfg: RotationConfig) -> RotatingFile {
        let dir = fs::canonicalize(dir).unwrap();
        let lock = Arc::new(DirLock::open(&dir).unwrap());
        RotatingFile::with_lock(lock, dir, signal, cfg).unwrap()
    }

    /// Sets the flag when dropped, so a panicking test still stops its helper
    /// threads instead of hanging in `thread::scope`.
    struct StopOnDrop<'a>(&'a std::sync::atomic::AtomicBool);
    impl Drop for StopOnDrop<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    #[test]
    fn independent_handles_exclude_each_other_on_the_directory_lock() {
        let d = tmp("dirlock");
        fs::create_dir_all(&d).unwrap();
        std::thread::scope(|sc| {
            for t in 0..8 {
                let h = open_independent(&d, "s", cfg(300));
                sc.spawn(move || {
                    for i in 0..100 {
                        h.append(format!("{t:02}-{i:03}-pad-pad-pad").as_bytes())
                            .unwrap();
                    }
                });
            }
        });
        let lines = all_lines(&d, "s");
        assert_eq!(lines.len(), 800);
        assert_eq!(lines.iter().collect::<HashSet<_>>().len(), 800);
        // Within one writer, records stay in order.
        for t in 0..8 {
            let mine: Vec<_> = lines
                .iter()
                .filter(|l| l.starts_with(&format!("{t:02}-")))
                .collect();
            assert!(
                mine.windows(2).all(|w| w[0] < w[1]),
                "writer {t} out of order"
            );
        }
        for p in segments(&d, "s").unwrap() {
            assert!(fs::metadata(&p).unwrap().len() <= 300);
        }
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn leftover_lock_file_is_ignored_and_deleting_it_is_harmless() {
        let d = tmp("lockload");
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("s.jsonl.lock"), "").unwrap(); // from an older build
        let stop = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|sc| {
            let _guard = StopOnDrop(&stop);
            sc.spawn(|| {
                while !stop.load(Ordering::Relaxed) {
                    let _ = fs::remove_file(d.join("s.jsonl.lock"));
                    let _ = fs::write(d.join("s.jsonl.lock"), "");
                    std::thread::sleep(Duration::from_micros(200));
                }
            });
            let writers: Vec<_> = (0..8)
                .map(|t| {
                    let h = open_independent(&d, "s", cfg(300));
                    sc.spawn(move || {
                        for i in 0..100 {
                            h.append(format!("{t:02}-{i:03}-pad-pad-pad").as_bytes())
                                .unwrap();
                        }
                    })
                })
                .collect();
            for w in writers {
                w.join().unwrap();
            }
        });
        let lines = all_lines(&d, "s");
        assert_eq!(lines.len(), 800);
        assert_eq!(lines.iter().collect::<HashSet<_>>().len(), 800);
        assert!(
            !segments(&d, "s")
                .unwrap()
                .iter()
                .any(|p| p.to_str().unwrap().ends_with(".lock"))
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn all_signals_of_a_directory_share_one_lock_without_deadlock() {
        let d = tmp("sharedlock");
        let a = Arc::new(RotatingFile::open(&d, "aa", cfg(40)).unwrap());
        let b = Arc::new(RotatingFile::open(&d, "bb", cfg(40)).unwrap());
        assert!(Arc::ptr_eq(&a.lock, &b.lock));
        let (tx, rx) = std::sync::mpsc::channel();
        for log in [a, b] {
            let tx = tx.clone();
            std::thread::spawn(move || {
                for i in 0..30 {
                    log.append(format!("{i:03}").as_bytes()).unwrap();
                }
                tx.send(()).unwrap();
            });
        }
        for _ in 0..2 {
            rx.recv_timeout(Duration::from_secs(30))
                .expect("deadlocked");
        }
        assert_eq!(all_lines(&d, "aa").len(), 30);
        assert_eq!(all_lines(&d, "bb").len(), 30);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn counter_past_999999_neither_overwrites_nor_disappears() {
        let d = tmp("counter");
        fs::create_dir_all(&d).unwrap();
        let planted = "s-29990101T000000.000000000Z_999999.jsonl";
        fs::write(d.join(planted), "planted\n").unwrap();
        let log = RotatingFile::open(&d, "s", cfg(10)).unwrap();
        for i in 0..4 {
            log.append(format!("rec{i}aaa").as_bytes()).unwrap();
        }
        let names: Vec<String> = segments(&d, "s")
            .unwrap()
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_owned())
            .collect();
        assert_eq!(names[0], planted);
        assert_eq!(names[1], "s-29990101T000000.000000000Z_1000000.jsonl");
        assert_eq!(names[2], "s-29990101T000000.000000000Z_1000001.jsonl");
        assert_eq!(
            all_lines(&d, "s"),
            ["planted", "rec0aaa", "rec1aaa", "rec2aaa", "rec3aaa"]
        );
        let hit = find_newest(&d, "s", |l| l.starts_with("rec").then(|| l.to_owned())).unwrap();
        assert_eq!(hit.as_deref(), Some("rec3aaa"));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn failed_live_unlink_undoes_segment() {
        let d = tmp("unlink-failure");
        let log = RotatingFile::open(&d, "s", cfg(10)).unwrap();
        log.append(b"original").unwrap();
        let live = d.join("s.jsonl");
        let err = rotate_with(
            &File::open(&d).unwrap(),
            "s",
            Path::new("s.jsonl"),
            |_, _, _| Err(Errno::NOSYS.into()),
            |dir, name| {
                if name == Path::new("s.jsonl") {
                    Err(io::Error::from_raw_os_error(13))
                } else {
                    unlink_name(dir, name)
                }
            },
        )
        .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(13));
        assert_eq!(fs::read_to_string(&live).unwrap(), "original\n");
        assert_eq!(segments(&d, "s").unwrap(), [live]);
        log.append(b"next").unwrap();
        assert_eq!(all_lines(&d, "s"), ["original", "next"]);
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn atomic_rename_retries_collision_without_unlinking() {
        let d = tmp("atomic-collision");
        let log = RotatingFile::open(&d, "s", cfg(10)).unwrap();
        log.append(b"original").unwrap();
        let dir = File::open(&d).unwrap();
        let mut planted = false;
        rotate_with(
            &dir,
            "s",
            Path::new("s.jsonl"),
            |dir, old, new| {
                if !planted {
                    open_private(dir, new)?.write_all(b"squat\n")?;
                    planted = true;
                }
                rename_new(dir, old, new)
            },
            |_, _| panic!("atomic rename must not call unlink"),
        )
        .unwrap();
        assert_eq!(all_lines(&d, "s"), ["squat", "original"]);
        assert!(!d.join("s.jsonl").exists());
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn fallback_is_limited_to_unsupported_rename_errors() {
        for code in [
            Errno::INVAL,
            Errno::NOSYS,
            Errno::OPNOTSUPP,
            Errno::ACCESS,
            Errno::IO,
        ] {
            let d = tmp("fallback-errors");
            let log = RotatingFile::open(&d, "s", cfg(10)).unwrap();
            log.append(b"original").unwrap();
            let dir = File::open(&d).unwrap();
            let result = rotate_with(
                &dir,
                "s",
                Path::new("s.jsonl"),
                |_, _, _| Err(code.into()),
                unlink_name,
            );
            if [Errno::INVAL, Errno::NOSYS, Errno::OPNOTSUPP].contains(&code) {
                result.unwrap();
                assert!(!d.join("s.jsonl").exists());
            } else {
                assert_eq!(
                    result.unwrap_err().raw_os_error(),
                    Some(code.raw_os_error())
                );
                assert_eq!(segments(&d, "s").unwrap(), [d.join("s.jsonl")]);
            }
            assert_eq!(all_lines(&d, "s"), ["original"]);
            fs::remove_dir_all(d).unwrap();
        }
    }

    #[test]
    fn external_hard_links_preserve_live_records_on_refresh_and_open() {
        let root = tmp("external-links");
        let d = root.join("state");
        let backup = root.join("backup");
        fs::create_dir_all(&backup).unwrap();
        let log = RotatingFile::open(&d, "s", cfg(1000)).unwrap();
        for line in [b"one".as_slice(), b"two", b"three"] {
            log.append(line).unwrap();
        }
        let live = d.join("s.jsonl");
        let original = fs::metadata(&live).unwrap().ino();
        fs::hard_link(&live, backup.join("s.jsonl")).unwrap();
        // A segment-looking file of another signal must not justify healing.
        fs::hard_link(&live, d.join("other-20260101T000000.000000000Z.jsonl")).unwrap();
        // Nor may a segment of this signal on a different inode justify it.
        let unrelated = d.join("s-20260101T000000.000000000Z.jsonl");
        fs::write(&unrelated, "unrelated\n").unwrap();
        log.append(b"four").unwrap();
        assert_eq!(fs::metadata(&live).unwrap().ino(), original);
        assert_eq!(
            all_lines(&d, "s"),
            ["unrelated", "one", "two", "three", "four"]
        );
        let reopened = RotatingFile::open(&d, "s", cfg(1000)).unwrap();
        reopened.append(b"five").unwrap();
        assert_eq!(fs::metadata(&live).unwrap().ino(), original);
        assert_eq!(
            all_lines(&d, "s"),
            ["unrelated", "one", "two", "three", "four", "five"]
        );
        assert_eq!(
            fs::read_to_string(backup.join("s.jsonl")).unwrap(),
            "one\ntwo\nthree\nfour\nfive\n"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn matching_segment_link_is_healed_on_open() {
        let d = tmp("heal-on-open");
        let log = RotatingFile::open(&d, "s", cfg(1000)).unwrap();
        log.append(b"original").unwrap();
        let segment = d.join("s-20260101T000000.000000000Z.jsonl");
        fs::hard_link(d.join("s.jsonl"), &segment).unwrap();
        let reopened = RotatingFile::open(&d, "s", cfg(1000)).unwrap();
        reopened.append(b"next").unwrap();
        assert_eq!(all_lines(&d, "s"), ["original", "next"]);
        assert_eq!(fs::metadata(segment).unwrap().nlink(), 1);
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn failed_fallback_undo_reports_both_errors_and_next_append_heals() {
        let d = tmp("undo-failure");
        let a = RotatingFile::open(&d, "s", cfg(10)).unwrap();
        let b = RotatingFile::open(&d, "s", cfg(10)).unwrap();
        a.append(b"original").unwrap();
        let dir = File::open(&d).unwrap();
        let err = rotate_with(
            &dir,
            "s",
            Path::new("s.jsonl"),
            |_, _, _| Err(Errno::NOSYS.into()),
            |_, name| {
                Err(io::Error::other(if name == Path::new("s.jsonl") {
                    "live unlink denied"
                } else {
                    "undo denied"
                }))
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("live unlink denied"));
        assert!(err.to_string().contains("undo denied"));
        assert_eq!(fs::metadata(d.join("s.jsonl")).unwrap().nlink(), 2);
        b.append(b"next").unwrap();
        a.append(b"last").unwrap();
        assert_eq!(all_lines(&d, "s"), ["original", "next", "last"]);
        for path in segments(&d, "s").unwrap() {
            assert_eq!(fs::metadata(path).unwrap().nlink(), 1);
        }
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn read_only_directory_rotation_leaves_one_name_per_inode() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp("readonly-rotate");
        let log = RotatingFile::open(&d, "s", cfg(10)).unwrap();
        log.append(b"original").unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o500)).unwrap();
        let result = log.append(b"next");
        fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        let paths = segments(&d, "s").unwrap();
        assert_eq!(paths, [d.join("s.jsonl")]);
        assert_eq!(fs::metadata(&paths[0]).unwrap().nlink(), 1);
        assert_eq!(all_lines(&d, "s"), ["original"]);
        log.append(b"next").unwrap();
        assert_eq!(all_lines(&d, "s"), ["original", "next"]);
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn fallback_unlink_stays_relative_after_directory_swap() {
        let root = tmp("fallback-swap");
        let d = root.join("state");
        let old = root.join("old");
        let log = RotatingFile::open(&d, "s", cfg(10)).unwrap();
        log.append(b"original").unwrap();
        let dir = File::open(&d).unwrap();
        rotate_with(
            &dir,
            "s",
            Path::new("s.jsonl"),
            |_, _, _| Err(Errno::NOSYS.into()),
            |dir, name| {
                fs::rename(&d, &old)?;
                fs::create_dir(&d)?;
                unlink_name(dir, name)
            },
        )
        .unwrap();
        assert_eq!(all_lines(&old, "s"), ["original"]);
        assert!(!old.join("s.jsonl").exists());
        assert!(segments(&d, "s").unwrap().is_empty());
        log.append(b"next").unwrap();
        assert_eq!(all_lines(&d, "s"), ["next"]);
        for path in segments(&old, "s").unwrap() {
            assert_eq!(fs::metadata(path).unwrap().nlink(), 1);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn swap_storm_child_role() {
        let Some(root) = std::env::var_os("VIGIL_STORM_DIR") else {
            return;
        };
        let root = PathBuf::from(root);
        let id = std::env::var("VIGIL_STORM_ID").unwrap();
        let log = RotatingFile::open(&root.join("state"), "s", cfg(256)).unwrap();
        fs::write(root.join(format!("ready-{id}")), "").unwrap();
        wait_for(&root.join("go"));
        let mut outcomes = String::new();
        let mut i = 0;
        while !root.join("stop").exists() {
            let record = format!("{id}-{i:06}-{}", "z".repeat(100));
            let status = if log.append(record.as_bytes()).is_ok() {
                "ok"
            } else {
                "err"
            };
            outcomes.push_str(&format!("{status} {record}\n"));
            i += 1;
            std::thread::sleep(Duration::from_millis(1));
        }
        fs::write(root.join(format!("outcomes-{id}")), outcomes).unwrap();
    }

    #[test]
    fn swap_storm_has_no_duplicates_and_accounts_for_every_record() {
        let root = tmp("swap-storm");
        let d = root.join("state");
        fs::create_dir_all(&d).unwrap();
        let exe = std::env::current_exe().unwrap();
        let mut children: Vec<_> = (0..4)
            .map(|id| {
                Command::new(&exe)
                    .args([
                        "--exact",
                        "rotate::tests::swap_storm_child_role",
                        "--test-threads=1",
                    ])
                    .env("VIGIL_STORM_DIR", &root)
                    .env("VIGIL_STORM_ID", id.to_string())
                    .spawn()
                    .unwrap()
            })
            .collect();
        for id in 0..4 {
            wait_for(&root.join(format!("ready-{id}")));
        }
        fs::write(root.join("go"), "").unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let mut swaps = 0;
        while std::time::Instant::now() < deadline {
            fs::rename(&d, root.join(format!("old-{swaps}"))).unwrap();
            // Writers may recreate the missing directory before we do.
            fs::create_dir_all(&d).unwrap();
            swaps += 1;
            std::thread::sleep(Duration::from_millis(1));
        }
        fs::write(root.join("stop"), "").unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        for child in &mut children {
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                if std::time::Instant::now() > deadline {
                    for child in &mut children {
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                    panic!("storm child timed out");
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        assert!(swaps > 100, "insufficient swaps: {swaps}");
        let mut successes = HashSet::new();
        let mut errors = HashSet::new();
        for id in 0..4 {
            let outcomes = fs::read_to_string(root.join(format!("outcomes-{id}"))).unwrap();
            for line in outcomes.lines() {
                let (status, record) = line.split_once(' ').unwrap();
                if status == "ok" {
                    successes.insert(record.to_owned());
                } else {
                    errors.insert(record.to_owned());
                }
            }
        }
        assert!(successes.len() > 100, "insufficient successful writes");
        let mut seen = HashSet::new();
        let mut inodes = HashSet::new();
        for dir in std::iter::once(d).chain((0..swaps).map(|i| root.join(format!("old-{i}")))) {
            for path in segments(&dir, "s").unwrap() {
                let m = fs::metadata(&path).unwrap();
                assert_eq!(m.nlink(), 1, "duplicate inode names: {path:?}");
                assert!(
                    inodes.insert((m.dev(), m.ino())),
                    "duplicate inode: {path:?}"
                );
                let bytes = fs::read(&path).unwrap();
                assert!(
                    bytes.is_empty() || bytes.ends_with(b"\n"),
                    "torn line: {path:?}"
                );
                for line in String::from_utf8(bytes).unwrap().lines() {
                    assert!(seen.insert(line.to_owned()), "duplicate: {line}");
                }
            }
        }
        // Every missing attempt must have returned an error; successful writes
        // must survive in either the old or current directory exactly once.
        assert_eq!(seen, successes);
        assert!(errors.is_disjoint(&seen));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_directory_is_recreated_and_registry_stays_shared() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp("missing-dir");
        let a = RotatingFile::open(&d, "s", cfg(1000)).unwrap();
        let b = RotatingFile::open(&d, "s", cfg(1000)).unwrap();
        a.append(b"before").unwrap();
        fs::remove_dir_all(&d).unwrap();
        a.append(b"after-a").unwrap();
        b.append(b"after-b").unwrap();
        let c = RotatingFile::open(&d, "s", cfg(1000)).unwrap();
        assert!(Arc::ptr_eq(&a.lock, &b.lock));
        assert!(Arc::ptr_eq(&a.lock, &c.lock));
        c.append(b"after-c").unwrap();
        assert_eq!(
            fs::metadata(&d).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(all_lines(&d, "s"), ["after-a", "after-b", "after-c"]);
        fs::remove_dir_all(d).unwrap();
    }

    fn wait_for(path: &Path) {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !path.exists() {
            assert!(std::time::Instant::now() < deadline, "timed out: {path:?}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn replaced_directory_child_role() {
        let Some(root) = std::env::var_os("VIGIL_REPLACED_DIR") else {
            return;
        };
        let root = PathBuf::from(root);
        let id = std::env::var("VIGIL_REPLACED_ID").unwrap();
        let dir = root.join("state");
        let a = RotatingFile::open(&dir, "s", cfg(300)).unwrap();
        let b = RotatingFile::open(&dir, "s", cfg(300)).unwrap();
        a.append(format!("before-{id}").as_bytes()).unwrap();
        fs::write(root.join(format!("ready-{id}")), "").unwrap();
        wait_for(&root.join("go"));
        fs::write(root.join(format!("attempt-{id}")), "").unwrap();
        for i in 0..500 {
            let log = if i % 2 == 0 { &a } else { &b };
            log.append(format!("{id}-{i:03}-pad-pad-pad").as_bytes())
                .unwrap();
            if i == 0 {
                fs::write(root.join(format!("entered-{id}")), "").unwrap();
            }
        }
    }

    #[test]
    fn replaced_directory_processes_relock_and_preserve_records() {
        let root = tmp("replace-dir");
        fs::create_dir_all(&root).unwrap();
        let dir = root.join("state");
        let old = root.join("old");
        let exe = std::env::current_exe().unwrap();
        let mut children: Vec<_> = (0..4)
            .map(|id| {
                Command::new(&exe)
                    .args([
                        "--exact",
                        "rotate::tests::replaced_directory_child_role",
                        "--test-threads=1",
                    ])
                    .env("VIGIL_REPLACED_DIR", &root)
                    .env("VIGIL_REPLACED_ID", id.to_string())
                    .spawn()
                    .unwrap()
            })
            .collect();
        for id in 0..4 {
            wait_for(&root.join(format!("ready-{id}")));
        }
        fs::rename(&dir, &old).unwrap();
        fs::create_dir(&dir).unwrap();
        let lock = File::open(&dir).unwrap();
        lock.lock().unwrap();
        fs::write(root.join("go"), "").unwrap();
        for id in 0..4 {
            wait_for(&root.join(format!("attempt-{id}")));
        }
        std::thread::sleep(Duration::from_millis(200));
        let excluded = (0..4).all(|id| !root.join(format!("entered-{id}")).exists());
        lock.unlock().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        for child in &mut children {
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                if std::time::Instant::now() > deadline {
                    for child in &mut children {
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                    panic!("child timed out");
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        assert!(excluded, "writers bypassed the replacement directory lock");
        let before = all_lines(&old, "s");
        assert_eq!(before.len(), 4, "nothing appended to the old directory");
        assert_eq!(
            before.into_iter().collect::<HashSet<_>>(),
            (0..4).map(|id| format!("before-{id}")).collect()
        );
        for path in segments(&dir, "s").unwrap() {
            let bytes = fs::read(&path).unwrap();
            assert!(bytes.ends_with(b"\n"), "torn final line: {path:?}");
            assert!(bytes.len() <= 300, "segment exceeded size limit: {path:?}");
        }
        let lines = all_lines(&dir, "s");
        assert_eq!(lines.len(), 2000);
        let expected: HashSet<_> = (0..4)
            .flat_map(|id| (0..500).map(move |i| format!("{id}-{i:03}-pad-pad-pad")))
            .collect();
        assert_eq!(lines.into_iter().collect::<HashSet<_>>(), expected);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rotation_never_replaces_an_existing_file() {
        let d = tmp("norepl");
        fs::create_dir_all(&d).unwrap();
        let live = d.join("s.jsonl");
        fs::write(&live, "live\n").unwrap();
        // `rotate` picks a free name; a file squatting on a candidate survives.
        let squat = d.join("s-29990101T000000.000000000Z.jsonl");
        fs::write(&squat, "squat\n").unwrap();
        rotate(&File::open(&d).unwrap(), "s", Path::new("s.jsonl")).unwrap();
        assert_eq!(fs::read_to_string(&squat).unwrap(), "squat\n");
        assert!(!live.exists());
        let all = all_lines(&d, "s");
        assert_eq!(all, ["squat", "live"]);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn open_tightens_loose_modes_and_never_loosens() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp("tighten");
        fs::create_dir_all(&d).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let set = |p: &Path, m: u32| fs::set_permissions(p, fs::Permissions::from_mode(m)).unwrap();
        set(&d, 0o755);
        fs::write(d.join("s.jsonl"), "").unwrap();
        set(&d.join("s.jsonl"), 0o644);
        let log = RotatingFile::open(&d, "s", cfg(10)).unwrap();
        assert_eq!(mode(&d), 0o700);
        assert_eq!(mode(&d.join("s.jsonl")), 0o600);
        for _ in 0..3 {
            log.append(b"aaaaaaaa").unwrap(); // rotated segments inherit 0600
        }
        for p in segments(&d, "s").unwrap() {
            assert_eq!(mode(&p), 0o600, "{p:?}");
        }
        // Stricter than the target stays as it is.
        drop(log);
        set(&d, 0o500);
        set(&d.join("s.jsonl"), 0o400);
        let _again = RotatingFile::open(&d, "s", cfg(10));
        assert_eq!(mode(&d), 0o500);
        assert_eq!(mode(&d.join("s.jsonl")), 0o400);
        set(&d, 0o700);
        fs::remove_dir_all(&d).unwrap();
    }

    /// A writer that accepts at most `cap` bytes per call.
    struct Short {
        cap: usize,
        calls: usize,
        got: Vec<u8>,
    }
    impl Write for Short {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            let n = b.len().min(self.cap);
            self.got.extend_from_slice(&b[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn short_write_is_an_error_after_exactly_one_write_call() {
        let mut w = Short {
            cap: 3,
            calls: 0,
            got: vec![],
        };
        let e = write_once(&mut w, b"abcdef\n").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::WriteZero);
        assert_eq!(w.calls, 1, "no second write to finish the line");
        let mut w = Short {
            cap: 100,
            calls: 0,
            got: vec![],
        };
        write_once(&mut w, b"abc\n").unwrap();
        assert_eq!((w.calls, w.got.as_slice()), (1, &b"abc\n"[..]));
    }

    #[test]
    fn short_write_through_append_rolls_back() {
        let d = tmp("shortappend");
        let log = RotatingFile::open(&d, "s", cfg(1_000)).unwrap();
        log.append(b"good1").unwrap();
        let e = log
            .append_with(b"abcdefgh", |f, buf| {
                f.write_all(&buf[..4])?; // what a short write(2) leaves behind
                write_once(
                    &mut Short {
                        cap: 4,
                        calls: 0,
                        got: vec![],
                    },
                    buf,
                )
            })
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::WriteZero);
        log.append(b"good2").unwrap();
        assert_eq!(
            fs::read_to_string(d.join("s.jsonl")).unwrap(),
            "good1\ngood2\n"
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn rapid_rotations_lose_nothing() {
        // Every append rotates; names come from the real clock.
        let d = tmp("rapid");
        let log = RotatingFile::open(&d, "s", cfg(1)).unwrap();
        for i in 0..200 {
            log.append(format!("{i:04}").as_bytes()).unwrap();
        }
        let want: Vec<String> = (0..200).map(|i| format!("{i:04}")).collect();
        assert_eq!(all_lines(&d, "s"), want);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn stamp_is_utc_fixed_width_and_sorts() {
        assert_eq!(stamp_at(0, 0), "19700101T000000.000000000Z");
        assert_eq!(stamp_at(1_000_000_000, 5), "20010909T014640.000000005Z");
        assert_eq!(stamp_at(951_782_400, 0), "20000229T000000.000000000Z"); // leap day
        assert_eq!(
            stamp_at(1_791_547_200, 123_456_789),
            "20261009T120000.123456789Z"
        );
        assert!(stamp_at(99, 999_999_999) < stamp_at(100, 0));
        assert!(stamp_at(9, 0) < stamp_at(10, 0));
        assert_eq!(stamp_at(0, 0).len(), stamp_at(4_000_000_000, 1).len());
    }

    #[test]
    fn segment_names_sort_chronologically_and_filter_other_signals() {
        let d = tmp("names");
        fs::create_dir_all(&d).unwrap();
        for n in [
            "s-20260101T000000.000000009Z.jsonl",
            "s-20260101T000000.000000010Z.jsonl",
            "s-20260101T000000.000000010Z_000001.jsonl",
            "s-20260101T000000.000000010Z_000002.jsonl",
            "s-20260101T000000.000000010Z_000010.jsonl",
            "s.jsonl",
            "s.jsonl.lock",
            "s-extra-20260101T000000.000000001Z.jsonl",
            "s-notes.jsonl",
            "other-20260101T000000.000000001Z.jsonl",
        ] {
            fs::write(d.join(n), "").unwrap();
        }
        let got: Vec<String> = segments(&d, "s")
            .unwrap()
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            got,
            [
                "s-20260101T000000.000000009Z.jsonl",
                "s-20260101T000000.000000010Z.jsonl",
                "s-20260101T000000.000000010Z_000001.jsonl",
                "s-20260101T000000.000000010Z_000002.jsonl",
                "s-20260101T000000.000000010Z_000010.jsonl",
                "s.jsonl",
            ]
        );
        fs::remove_dir_all(&d).unwrap();
    }

    fn age(path: &Path, days: u64) {
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(days * 86_400))
            .unwrap();
    }

    fn seed_old_and_fresh(d: &Path) -> (PathBuf, PathBuf) {
        fs::create_dir_all(d).unwrap();
        let old = d.join("s-20250101T000000.000000000Z.jsonl");
        let fresh = d.join("s-20261001T000000.000000000Z.jsonl");
        for p in [&old, &fresh, &d.join("s.jsonl"), &d.join("s.jsonl.lock")] {
            fs::write(p, "{}\n").unwrap();
        }
        age(&old, 100);
        age(&d.join("s.jsonl"), 200); // the live file is never pruned
        age(&d.join("s.jsonl.lock"), 200);
        (old, fresh)
    }

    #[test]
    fn open_prunes_expired_segments_but_not_live_or_lock() {
        let d = tmp("prune-open");
        let (old, fresh) = seed_old_and_fresh(&d);
        let c = RotationConfig {
            max_bytes: 1000,
            retention: Some(Duration::from_secs(90 * 86_400)),
        };
        let _log = RotatingFile::open(&d, "s", c).unwrap();
        assert!(!old.exists());
        assert!(fresh.exists());
        assert!(d.join("s.jsonl").exists() && d.join("s.jsonl.lock").exists());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn directory_relative_pruning_handles_pre_epoch_mtime() {
        let d = tmp("prune-pre-epoch");
        fs::create_dir_all(&d).unwrap();
        let old = d.join("s-19600101T000000.000000000Z.jsonl");
        fs::write(&old, "old\n").unwrap();
        File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(UNIX_EPOCH - Duration::from_secs(1))
            .unwrap();
        let _log = RotatingFile::open(&d, "s", RotationConfig::default()).unwrap();
        assert!(!old.exists());
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn rotation_prunes_expired_segments() {
        let d = tmp("prune-rotate");
        let c = RotationConfig {
            max_bytes: 10,
            retention: Some(Duration::from_secs(90 * 86_400)),
        };
        let log = RotatingFile::open(&d, "s", c).unwrap();
        let (old, fresh) = seed_old_and_fresh(&d);
        assert!(old.exists());
        log.append(b"aaaaaaaa").unwrap();
        log.append(b"bbbbbbbb").unwrap(); // rotates
        assert!(!old.exists());
        assert!(fresh.exists());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn retention_none_keeps_everything() {
        let d = tmp("keep");
        let (old, fresh) = seed_old_and_fresh(&d);
        let log = RotatingFile::open(&d, "s", cfg(10)).unwrap();
        for _ in 0..5 {
            log.append(b"aaaaaaaa").unwrap();
        }
        assert!(old.exists() && fresh.exists());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn partial_write_is_rolled_back() {
        let d = tmp("partial");
        let log = RotatingFile::open(&d, "s", cfg(1_000)).unwrap();
        log.append(b"good1").unwrap();
        let err = log
            .append_with(b"half-written-record", |f, buf| {
                f.write_all(&buf[..7])?; // part of the line reaches the file…
                Err(io::Error::other("disk full"))
            })
            .unwrap_err();
        assert_eq!(err.to_string(), "disk full");
        assert_eq!(fs::read_to_string(d.join("s.jsonl")).unwrap(), "good1\n");
        // The lock was released and the next record is clean.
        log.append(b"good2").unwrap();
        assert_eq!(
            fs::read_to_string(d.join("s.jsonl")).unwrap(),
            "good1\ngood2\n"
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn readers_filter_by_mtime_and_search_newest_first() {
        let d = tmp("readers");
        let log = RotatingFile::open(&d, "s", cfg(30)).unwrap();
        for i in 0..12 {
            log.append(format!("id{} v{i}", i % 3).as_bytes()).unwrap();
        }
        // Newest line wins within a segment, newest segment wins across.
        let hit = find_newest(&d, "s", |l| l.starts_with("id0").then(|| l.to_owned())).unwrap();
        assert_eq!(hit.as_deref(), Some("id0 v9"));
        assert_eq!(
            find_newest(&d, "s", |l| (l == "nope").then_some(())).unwrap(),
            None
        );

        let segs = segments(&d, "s").unwrap();
        assert!(segs.len() > 2);
        age(&segs[0], 10);
        let cut = SystemTime::now() - Duration::from_secs(86_400);
        let recent = segments_since(&d, "s", Some(cut)).unwrap();
        assert_eq!(recent, segs[1..]);
        assert_eq!(segments_since(&d, "s", None).unwrap(), segs);
        assert!(read_since(&d, "s", Some(cut)).unwrap().len() < 12);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn readers_on_a_missing_dir_error_cleanly() {
        let d = tmp("missing");
        assert!(segments(&d, "s").is_err());
        assert!(find_newest(&d, "s", |_| Some(())).is_err());
    }

    // ---- multi-process --------------------------------------------------

    const CHILD_DIR: &str = "VIGIL_ROTATE_TEST_DIR";
    const CHILD_ID: &str = "VIGIL_ROTATE_TEST_ID";
    const CHILD_RECORDS: &str = "VIGIL_ROTATE_TEST_RECORDS";
    const CHILD_MAX: &str = "VIGIL_ROTATE_TEST_MAX";

    /// The child role: a no-op in a normal test run; when the parent test
    /// re-executes this binary with the env vars set, it is the writer.
    #[test]
    fn multiprocess_child_role() {
        let Some(dir) = std::env::var_os(CHILD_DIR) else {
            return;
        };
        let env = |k: &str| std::env::var(k).unwrap().parse::<u64>().unwrap();
        let (id, records, max) = (env(CHILD_ID), env(CHILD_RECORDS), env(CHILD_MAX));
        let log = RotatingFile::open(Path::new(&dir), "mp", cfg(max)).unwrap();
        for i in 0..records {
            log.append(format!(r#"{{"p":{id},"i":{i},"pad":"{}"}}"#, "z".repeat(20)).as_bytes())
                .unwrap();
        }
    }

    #[test]
    fn many_processes_rotate_safely() {
        if std::env::var_os(CHILD_DIR).is_some() {
            return; // we are a child; the role test does the work
        }
        const PROCS: u64 = 6;
        const RECORDS: u64 = 2000;
        const MAX: u64 = 400;
        let d = tmp("mp");
        fs::create_dir_all(&d).unwrap();
        let exe = std::env::current_exe().unwrap();
        let children: Vec<_> = (0..PROCS)
            .map(|id| {
                Command::new(&exe)
                    .args([
                        "--exact",
                        "rotate::tests::multiprocess_child_role",
                        "--test-threads=1",
                    ])
                    .env(CHILD_DIR, &d)
                    .env(CHILD_ID, id.to_string())
                    .env(CHILD_RECORDS, RECORDS.to_string())
                    .env(CHILD_MAX, MAX.to_string())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap()
            })
            .collect();
        // Bounded: a hung child fails the test instead of hanging it.
        let deadline = std::time::Instant::now() + Duration::from_secs(120);
        for mut c in children {
            let status = loop {
                if let Some(st) = c.try_wait().unwrap() {
                    break st;
                }
                if std::time::Instant::now() > deadline {
                    let _ = c.kill();
                    let _ = c.wait();
                    panic!("child timed out");
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            let mut out = String::new();
            let mut err = String::new();
            let _ = std::io::Read::read_to_string(&mut c.stdout.take().unwrap(), &mut out);
            let _ = std::io::Read::read_to_string(&mut c.stderr.take().unwrap(), &mut err);
            assert!(status.success(), "child failed: {out}{err}");
            // Guard against the child filter matching nothing.
            assert!(out.contains("1 passed"));
        }

        let segs = segments(&d, "mp").unwrap();
        assert!(
            segs.len() > 20,
            "expected many rotations, got {}",
            segs.len()
        );
        let names: HashSet<_> = segs.iter().collect();
        assert_eq!(names.len(), segs.len(), "no segment name collides");

        let mut seen = HashSet::new();
        for p in &segs {
            let bytes = fs::read(p).unwrap();
            assert!(
                bytes.is_empty() || bytes.ends_with(b"\n"),
                "{p:?} ends mid-line"
            );
            let text = String::from_utf8(bytes).unwrap();
            let n_lines = text.lines().count();
            if p != &d.join("mp.jsonl") {
                // Rotation only happens when the next line did not fit, so a
                // rotated segment is nearly full; a writer that rotated off a
                // stale handle would leave tiny or misplaced segments.
                assert!(
                    text.len() as u64 + 70 > MAX,
                    "{p:?} rotated early: {}",
                    text.len()
                );
            }
            if text.len() as u64 > MAX {
                assert_eq!(n_lines, 1, "{p:?} over the limit with several lines");
            }
            for line in text.lines() {
                assert!(
                    line.starts_with("{\"p\":") && line.ends_with('}'),
                    "torn: {line:?}"
                );
                let num = |key: &str| -> u64 {
                    let rest = &line[line.find(key).unwrap() + key.len()..];
                    rest[..rest.find([',', '}']).unwrap()].parse().unwrap()
                };
                assert!(
                    seen.insert((num("\"p\":"), num("\"i\":"))),
                    "duplicate {line}"
                );
            }
        }
        assert_eq!(seen.len() as u64, PROCS * RECORDS, "lost records");
        fs::remove_dir_all(&d).unwrap();
    }
}
