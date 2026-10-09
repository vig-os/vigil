//! Golden-file test: the exact bytes for a fixed record set.
//!
//! Regenerate deliberately with `VIGIL_BLESS=1 cargo test --test golden`, then
//! review the diff of `tests/fixtures/`. A missing fixture fails the test
//! (unless blessing), so a build whose source filter drops the directory
//! cannot pass by skipping it.

mod common;

use common::{export, golden_records};
use vigil::sink::MemorySink;

fn fixture_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn assert_golden(name: &str, actual: &str) {
    let path = fixture_path(name);
    if std::env::var_os("VIGIL_BLESS").is_some_and(|v| v == "1") {
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing golden fixture {} ({e}); bless with VIGIL_BLESS=1",
            path.display()
        )
    });
    assert_eq!(
        actual, expected,
        "{name} differs from the golden bytes; if intended, rerun with VIGIL_BLESS=1"
    );
}

fn golden_output() -> String {
    let (resource, records) = golden_records();
    let sink = MemorySink::new();
    export(sink.clone(), &resource, &records);
    sink.lines().iter().map(|l| format!("{l}\n")).collect()
}

#[test]
fn golden_batch_bytes_are_pinned() {
    assert_golden("logs-golden.jsonl", &golden_output());
}

#[test]
fn golden_bytes_are_identical_across_repeated_runs() {
    let first = golden_output();
    for _ in 0..50 {
        assert_eq!(golden_output(), first);
    }
}
