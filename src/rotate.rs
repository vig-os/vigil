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
//! check, the rename and the write happen under one exclusive `flock(2)`
//! (`std::fs::File::lock`) on a separate, never-renamed
//! `<signal>.jsonl.lock`. Locking the data file itself would let a waiter lock
//! an inode that has since been renamed away. After taking the lock the
//! writer compares the live path's `(dev, ino)` with its cached handle and
//! reopens when another process rotated in the meantime, so a record never
//! lands in a rotated segment.
//!
//! * Safe across processes and threads on **local filesystems**. NFS (and
//!   other filesystems with weak `flock` semantics) is **not supported**.
//! * Open **one** [`RotatingFile`] per signal per process and share it (for
//!   example in an `Arc`). Two `flock`s taken through different file
//!   descriptors block each other even inside one process, so opening the same
//!   path twice in a process returns handles that share one lock descriptor
//!   and one cached file handle (each keeps its own [`RotationConfig`]); it
//!   neither deadlocks nor errors.
//! * A failed or partial write is rolled back (`set_len` to the pre-write
//!   length) before the error is returned, so a half line never glues onto the
//!   next record.
//! * Readers need no lock: a line is written with a single `write(2)` to an
//!   `O_APPEND` file, and rotation is an atomic `rename`.
//!
//! # Layout
//!
//! ```text
//! <dir>/<signal>.jsonl                           live file
//! <dir>/<signal>.jsonl.lock                      lock file (never renamed, never pruned)
//! <dir>/<signal>-20261009T120000.123456789Z.jsonl rotated segment
//! <dir>/<signal>-20261009T120000.123456789Z_000001.jsonl  same-nanosecond collision
//! ```
//!
//! Segment names sort chronologically as plain strings, so [`segments`] simply
//! sorts them. Directories are created `0700`, files `0600`.

use std::collections::HashMap;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
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

/// `(dev, ino)` of an open file.
type FileId = (u64, u64);

/// The cached live handle, replaced whenever the file at the live path changes.
struct Live {
    file: File,
    id: FileId,
}

/// State shared by every [`RotatingFile`] of one path in this process.
struct Shared {
    dir: PathBuf,
    signal: String,
    live_path: PathBuf,
    /// Never renamed; `flock`ed for the duration of every append.
    lock: File,
    /// Serialises threads (a `flock` does not exclude threads sharing one
    /// descriptor) and owns the cached live handle.
    live: Mutex<Live>,
}

static REGISTRY: LazyLock<Mutex<HashMap<PathBuf, Weak<Shared>>>> =
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
    shared: Arc<Shared>,
    cfg: RotationConfig,
}

impl std::fmt::Debug for RotatingFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotatingFile")
            .field("path", &self.shared.live_path)
            .field("cfg", &self.cfg)
            .finish()
    }
}

impl RotatingFile {
    /// Open (creating as needed) the signal's directory (`0700`), live file and
    /// lock file (`0600`), and prune expired segments once.
    ///
    /// Opening the same `dir` + `signal` again in this process shares the lock
    /// and file handle of the first open instead of deadlocking on it.
    ///
    /// # Errors
    ///
    /// `InvalidInput` if `signal` is empty or contains a path separator or NUL;
    /// otherwise any I/O error from creating the directory or files.
    pub fn open(dir: &Path, signal: &str, cfg: RotationConfig) -> io::Result<Self> {
        validate_signal(signal)?;
        DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        let dir = fs::canonicalize(dir)?;
        let live_path = dir.join(format!("{signal}.jsonl"));

        let mut registry = lock_ignore_poison(&REGISTRY);
        registry.retain(|_, w| w.strong_count() > 0);
        let (shared, first) = match registry.get(&live_path).and_then(Weak::upgrade) {
            Some(shared) => (shared, false),
            None => {
                let lock = open_private(&dir.join(format!("{signal}.jsonl.lock")), false)?;
                let shared = Arc::new(Shared {
                    dir,
                    signal: signal.to_owned(),
                    live: Mutex::new(open_live(&live_path)?),
                    live_path: live_path.clone(),
                    lock,
                });
                registry.insert(live_path, Arc::downgrade(&shared));
                (shared, true)
            }
        };
        drop(registry);

        if first && let Some(keep) = cfg.retention {
            prune(&shared.dir, &shared.signal, keep);
        }
        Ok(Self { shared, cfg })
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
        self.append_with(line, |f, buf| f.write_all(buf))
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

        let s = &*self.shared;
        let mut live = lock_ignore_poison(&s.live);
        s.lock.lock()?;
        let _unlock = Unlock(&s.lock);

        // Another process may have rotated (or removed) the file since our
        // last append: the cached handle then points at a renamed inode.
        if disk_id(&s.live_path) != Some(live.id) {
            *live = open_live(&s.live_path)?;
        }

        let len = live.file.metadata()?.len();
        if len > 0 && len.checked_add(need).is_none_or(|n| n > self.cfg.max_bytes) {
            let target = unique_target(&s.dir, &s.signal, &stamp(SystemTime::now()));
            fs::rename(&s.live_path, &target)?;
            *live = open_live(&s.live_path)?;
            if let Some(keep) = self.cfg.retention {
                prune(&s.dir, &s.signal, keep);
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

/// Releases the `flock` on drop, including on early return and panic.
struct Unlock<'a>(&'a File);

impl Drop for Unlock<'_> {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

fn lock_ignore_poison<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn validate_signal(signal: &str) -> io::Result<()> {
    if signal.is_empty() || signal.contains(['/', '\0']) || signal == "." || signal == ".." {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid signal name {signal:?}"),
        ));
    }
    Ok(())
}

/// Open a file `0600`, either as an `O_APPEND` data file or a plain lock file.
fn open_private(path: &Path, append: bool) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).mode(0o600);
    if append {
        opts.append(true);
    } else {
        opts.write(true);
    }
    opts.open(path)
}

fn open_live(path: &Path) -> io::Result<Live> {
    let file = open_private(path, true)?;
    let m = file.metadata()?;
    Ok(Live {
        id: (m.dev(), m.ino()),
        file,
    })
}

fn disk_id(path: &Path) -> Option<FileId> {
    fs::metadata(path).ok().map(|m| (m.dev(), m.ino()))
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

/// A rotated-segment path that does not exist yet. Called under the lock, so
/// the existence check cannot race. The collision suffix `_NNNNNN` sorts after
/// the bare name (`_` > `.`) and, zero-padded, in counter order.
fn unique_target(dir: &Path, signal: &str, stamp: &str) -> PathBuf {
    let first = dir.join(format!("{signal}-{stamp}.jsonl"));
    if !first.exists() {
        return first;
    }
    (1u64..)
        .map(|n| dir.join(format!("{signal}-{stamp}_{n:06}.jsonl")))
        .find(|p| !p.exists())
        .unwrap_or(first)
}

/// Whether `name` is a rotated segment of `signal` (and not, say, of a signal
/// called `<signal>-x`).
fn is_segment_name(name: &str, signal: &str) -> bool {
    let Some(rest) = name
        .strip_prefix(signal)
        .and_then(|r| r.strip_prefix('-'))
        .and_then(|r| r.strip_suffix(".jsonl"))
    else {
        return false;
    };
    rest.starts_with(|c: char| c.is_ascii_digit())
        && rest
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, 'T' | 'Z' | '.' | '_'))
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
    v.sort();
    Ok(v)
}

fn mtime(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Delete rotated segments last written more than `keep` ago. Never touches
/// the live or lock file; errors are ignored.
fn prune(dir: &Path, signal: &str, keep: Duration) {
    let Ok(segs) = rotated_segments(dir, signal) else {
        return;
    };
    let now = SystemTime::now();
    for p in segs {
        let expired = mtime(&p)
            .and_then(|t| now.duration_since(t).ok())
            .is_some_and(|age| age > keep);
        if expired {
            let _ = fs::remove_file(&p);
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
        assert_eq!(mode(d.join("logs.jsonl.lock")), 0o600);
        fs::remove_dir_all(d.parent().unwrap()).unwrap();
    }

    #[test]
    fn rejects_bad_signal_names() {
        let d = tmp("badsig");
        for s in ["", ".", "..", "a/b", "a\0b"] {
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
        assert!(Arc::ptr_eq(&a.shared, &b.shared));
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
        let b = RotatingFile::open(&d, "logs-extra", cfg(20)).unwrap();
        for i in 0..6 {
            a.append(format!("a{i}").as_bytes()).unwrap();
            b.append(format!("b{i}").as_bytes()).unwrap();
        }
        assert!(all_lines(&d, "logs").iter().all(|l| l.starts_with('a')));
        assert_eq!(all_lines(&d, "logs").len(), 6);
        assert_eq!(all_lines(&d, "logs-extra").len(), 6);
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
        let mut names = Vec::new();
        for i in 0..12 {
            let t = unique_target(&d, "s", st);
            assert!(!t.exists());
            fs::write(&t, format!("{i}")).unwrap();
            names.push(t.file_name().unwrap().to_str().unwrap().to_owned());
        }
        let unique: HashSet<_> = names.iter().collect();
        assert_eq!(unique.len(), 12);
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(sorted, names, "creation order == string order");
        for (i, n) in names.iter().enumerate() {
            assert_eq!(fs::read_to_string(d.join(n)).unwrap(), i.to_string());
        }
        // The suffix keeps sorting past single and double digits.
        assert!(names.iter().all(|n| is_segment_name(n, "s")));
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
        for c in children {
            let out = c.wait_with_output().unwrap();
            assert!(
                out.status.success(),
                "child failed: {}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            // Guard against the child filter matching nothing.
            assert!(String::from_utf8_lossy(&out.stdout).contains("1 passed"));
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
