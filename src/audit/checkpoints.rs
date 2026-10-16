use super::Checkpoint;
use std::{fs, io, path::Path};

/// Reads all parseable checkpoints in segment order, with the live file last.
///
/// Takes no lock. Segment names and the live inode are checked around the read,
/// retrying up to eight times. Unparsable lines and ordinary records are ignored.
/// Checkpoint parsing checks structure and record hashes, but does not verify
/// signatures, trust or the chain; offline verification belongs to `verify` (#13).
///
/// # Errors
/// Returns filesystem errors or an error if all eight snapshots race with rotation.
/// An exhausted retry never silently omits the live tail.
pub fn checkpoints(dir: &Path) -> io::Result<Vec<Checkpoint>> {
    crate::rotate::retry_snapshot(
        dir,
        "audit",
        |paths| {
            let mut checkpoints = Vec::new();
            for path in paths {
                let bytes = match fs::read(path) {
                    Ok(bytes) => bytes,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e),
                };
                for line in bytes.split(|b| *b == b'\n') {
                    if let Ok(line) = std::str::from_utf8(line)
                        && let Ok(checkpoint) = Checkpoint::parse(line)
                    {
                        checkpoints.push(checkpoint);
                    }
                }
            }
            Ok(Ok(checkpoints))
        },
        |_| {
            Err(io::Error::other(
                "audit snapshot changed during all eight attempts",
            ))
        },
    )?
}
