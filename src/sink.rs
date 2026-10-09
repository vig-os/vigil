//! The seam between serialization and storage: a [`LineSink`] takes one
//! complete line at a time.
//!
//! The exporter ([`crate::logs::OtlpJsonLogExporter`]) knows nothing about
//! files, rotation or locking; it hands finished lines to a sink. [`AppendFile`]
//! is the plain single-file sink, [`MemorySink`] is the in-memory one for tests.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

/// Receives finished lines, one per call.
pub trait LineSink: Send + Sync + fmt::Debug {
    /// Append one complete line; `line` has no trailing `'\n'`.
    ///
    /// Implementations must make the line (plus its newline) reach storage as
    /// a single `write(2)`, so concurrent writers cannot interleave.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error if the line could not be written.
    fn write_line(&self, line: &[u8]) -> io::Result<()>;

    /// Flush anything buffered. The default does nothing.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error if the flush failed.
    fn flush(&self) -> io::Result<()> {
        Ok(())
    }
}

impl<T: LineSink + ?Sized> LineSink for Arc<T> {
    fn write_line(&self, line: &[u8]) -> io::Result<()> {
        (**self).write_line(line)
    }

    fn flush(&self) -> io::Result<()> {
        (**self).flush()
    }
}

/// Appends lines to one file, each with a single `write(2)` on an `O_APPEND`
/// descriptor.
///
/// On a local filesystem the kernel positions each `O_APPEND` write at the end
/// of file atomically, so lines written by many threads (or processes) sharing
/// the file never interleave.
///
/// This is the **single-file** sink. It holds one open descriptor and does not
/// follow renames or unlinks: after an external `rename` it keeps writing to
/// the renamed file, and after an external `unlink` it writes to the orphaned
/// inode and still reports `Ok`. Rotation-safe writing is the job of
/// `rotate::RotatingFile` (#4). The mode `0600` applies only when this sink
/// creates the file; an existing file keeps its permissions.
///
/// # Short writes
///
/// If a write is cut short (disk full, a file-size limit) the file is left
/// ending in an unterminated fragment, and the error is returned. The sink does
/// not try to repair it afterwards (the repair write can fail for the same
/// reason). Instead every write first checks the file's last byte and, when it
/// is not `\n`, prefixes the line with a `\n` **in the same single `write`**,
/// so the fragment stays on its own line and the new line starts cleanly. Two
/// writers can both add that prefix, which leaves an empty line.
/// **Readers must skip empty and unparsable lines.**
///
/// ```
/// use vigil::sink::{AppendFile, LineSink};
///
/// let dir = std::env::temp_dir().join(format!("vigil-doc-{}", std::process::id()));
/// std::fs::create_dir_all(&dir)?;
/// let sink = AppendFile::open(dir.join("logs.jsonl"))?;
/// sink.write_line(br#"{"resourceLogs":[]}"#)?;
/// assert_eq!(
///     std::fs::read_to_string(dir.join("logs.jsonl"))?,
///     "{\"resourceLogs\":[]}\n"
/// );
/// std::fs::remove_dir_all(&dir)?;
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug)]
pub struct AppendFile {
    file: File,
    path: PathBuf,
}

impl AppendFile {
    /// Open (creating if needed) `path` for appending.
    ///
    /// # Errors
    ///
    /// Returns the I/O error from opening the file, for example a missing
    /// parent directory or insufficient permissions.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut options = OpenOptions::new();
        // `read` is only for the last-byte check; all writes are appends.
        options.read(true).append(true).create(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let file = options.open(&path)?;
        Ok(Self { file, path })
    }

    /// The path this sink appends to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl LineSink for AppendFile {
    fn write_line(&self, line: &[u8]) -> io::Result<()> {
        append_line(&self.file, line, &self.path)
    }
}

/// The two file operations `append_line` needs, so tests can substitute a
/// fake for a real file.
trait Appender {
    /// The last byte of the file, or `None` if it is empty.
    fn last_byte(&self) -> io::Result<Option<u8>>;
    /// One `write(2)`; returns the number of bytes accepted.
    fn append(&self, buf: &[u8]) -> io::Result<usize>;
}

impl Appender for File {
    fn last_byte(&self) -> io::Result<Option<u8>> {
        use std::os::unix::fs::FileExt;
        let len = self.metadata()?.len();
        if len == 0 {
            return Ok(None);
        }
        let mut byte = [0u8; 1];
        self.read_exact_at(&mut byte, len - 1)?;
        Ok(Some(byte[0]))
    }

    fn append(&self, buf: &[u8]) -> io::Result<usize> {
        // `&File` implements `Write`, so no lock is needed: the kernel orders
        // concurrent `O_APPEND` writes.
        (&*self).write(buf)
    }
}

/// One `write` of `[\n] + line + \n` to `out`, where the leading `\n` is only
/// present when the file does not already end in one (a fragment left by an
/// earlier short write, possibly by another process).
///
/// On a short write the tail is **not** retried (a second `write(2)` another
/// writer can slip in front of) and nothing else is appended (it would likely
/// fail for the same reason): the error says what happened, and the next
/// write's prefix terminates the fragment.
fn append_line(out: &impl Appender, line: &[u8], path: &Path) -> io::Result<()> {
    let needs_prefix = out.last_byte()?.is_some_and(|b| b != b'\n');
    let mut buf = Vec::with_capacity(line.len() + 2);
    if needs_prefix {
        buf.push(b'\n');
    }
    buf.extend_from_slice(line);
    buf.push(b'\n');
    let written = out.append(&buf)?;
    if written != buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!(
                "short write to {}: {written} of {} bytes; the file now ends in an \
                 unterminated fragment, which the next write will terminate",
                path.display(),
                buf.len()
            ),
        ));
    }
    Ok(())
}

/// Collects lines in memory. Cheap to clone; clones share the same buffer, so a
/// test can hand one clone to an exporter and read lines back from another.
#[derive(Debug, Clone, Default)]
pub struct MemorySink {
    lines: Arc<Mutex<Vec<String>>>,
}

impl MemorySink {
    /// An empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The lines written so far, without trailing newlines.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        self.lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl LineSink for MemorySink {
    fn write_line(&self, line: &[u8]) -> io::Result<()> {
        let line = std::str::from_utf8(line)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            .to_owned();
        self.lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(line);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_sink_shares_lines_between_clones() {
        let sink = MemorySink::new();
        let other = sink.clone();
        other.write_line(b"a").unwrap();
        sink.write_line(b"b").unwrap();
        assert_eq!(sink.lines(), ["a", "b"]);
    }

    #[test]
    fn memory_sink_rejects_invalid_utf8() {
        let err = MemorySink::new().write_line(&[0xff]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[test]
    fn append_file_is_created_0600_and_appends_across_opens() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let path = dir.join("x.jsonl");
        AppendFile::open(&path).unwrap().write_line(b"one").unwrap();
        AppendFile::open(&path).unwrap().write_line(b"two").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "one\ntwo\n");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// An in-memory file whose first `write` accepts only `limit` bytes.
    #[derive(Default)]
    struct Truncating {
        limit: usize,
        data: Mutex<Vec<u8>>,
        writes: Mutex<usize>,
    }

    impl Appender for Truncating {
        fn last_byte(&self) -> io::Result<Option<u8>> {
            Ok(self.data.lock().unwrap().last().copied())
        }

        fn append(&self, buf: &[u8]) -> io::Result<usize> {
            let mut writes = self.writes.lock().unwrap();
            let n = if *writes == 0 {
                buf.len().min(self.limit)
            } else {
                buf.len()
            };
            *writes += 1;
            self.data.lock().unwrap().extend_from_slice(&buf[..n]);
            Ok(n)
        }
    }

    #[test]
    fn short_write_errors_accurately_and_the_next_write_terminates_the_fragment() {
        let out = Truncating {
            limit: 4,
            ..Default::default()
        };
        let err = append_line(&out, b"0123456789", Path::new("x")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WriteZero);
        assert!(err.to_string().contains("4 of 11 bytes"), "{err}");
        // No repair write was attempted after the short write.
        assert_eq!(*out.writes.lock().unwrap(), 1);
        assert_eq!(*out.data.lock().unwrap(), b"0123");
        // The next line carries the prefix, in the same single write.
        append_line(&out, b"next", Path::new("x")).unwrap();
        assert_eq!(*out.writes.lock().unwrap(), 2);
        assert_eq!(*out.data.lock().unwrap(), b"0123\nnext\n");
        // A clean file gets no prefix.
        append_line(&out, b"more", Path::new("x")).unwrap();
        assert_eq!(*out.data.lock().unwrap(), b"0123\nnext\nmore\n");
    }

    #[cfg(unix)]
    #[test]
    fn append_file_terminates_a_foreign_fragment_in_one_write() {
        let dir = tempdir();
        let path = dir.join("x.jsonl");
        std::fs::write(&path, b"complete\nfragment").unwrap();
        AppendFile::open(&path)
            .unwrap()
            .write_line(b"next")
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "complete\nfragment\nnext\n"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn append_file_open_fails_without_parent_directory() {
        let dir = tempdir();
        assert!(AppendFile::open(dir.join("missing").join("x")).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "vigil-sink-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
