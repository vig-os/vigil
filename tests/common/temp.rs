//! Shared unique temporary directory with cleanup during assertion unwinding.
use std::{
    fs,
    sync::atomic::{AtomicU64, Ordering},
};

pub(crate) struct TempDir(pub(crate) std::path::PathBuf);
impl TempDir {
    pub(crate) fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "vigil-prop-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        // Cleanup also runs during assertion unwinding; never double-panic.
        let _ = fs::remove_dir_all(&self.0);
    }
}
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
