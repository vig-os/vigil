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
/// the file never interleave. The file is created with mode `0600` if missing.
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
        options.append(true).create(true);
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
        let mut buf = Vec::with_capacity(line.len() + 1);
        buf.extend_from_slice(line);
        buf.push(b'\n');
        // `&File` implements `Write`, so no lock is needed: the kernel orders
        // concurrent `O_APPEND` writes.
        let written = (&self.file).write(&buf)?;
        if written != buf.len() {
            // Retrying the tail would be a second write(2) that other writers
            // can slip in front of, producing an interleaved line. Fail loudly.
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!(
                    "short write to {}: {written} of {} bytes; the line may be truncated",
                    self.path.display(),
                    buf.len()
                ),
            ));
        }
        Ok(())
    }
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
