//! Round trip against a real OpenTelemetry Collector.
//!
//! Ignored by default (needs the binary, and a few seconds). Run with
//!
//! ```text
//! nix shell nixpkgs#opentelemetry-collector-contrib -c \
//!     cargo test --test collector -- --ignored
//! ```
//!
//! It feeds the golden file to the contrib Collector's `otlpjsonfile` receiver
//! (`start_at: beginning`, `include_file_name: false`) and reads it back from a
//! `file` exporter. A line the receiver rejects is dropped silently, so the
//! assertion is that every record, including the non-finite doubles, comes out.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

#[test]
#[ignore = "needs otelcol-contrib on PATH"]
fn collector_ingests_the_golden_file() {
    let dir = std::env::temp_dir().join(format!("vigil-collector-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("in.jsonl");
    let output = dir.join("out.jsonl");
    let golden = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/logs-golden.jsonl"
    ))
    .unwrap();
    std::fs::write(&input, &golden).unwrap();
    let config = dir.join("config.yaml");
    std::fs::write(
        &config,
        format!(
            "receivers:\n  otlpjsonfile:\n    include: [{input}]\n    include_file_name: false\n    start_at: beginning\nexporters:\n  file:\n    path: {output}\nservice:\n  pipelines:\n    logs:\n      receivers: [otlpjsonfile]\n      exporters: [file]\n",
            input = input.display(),
            output = output.display()
        ),
    )
    .unwrap();

    let mut child = Command::new("otelcol-contrib")
        .arg("--config")
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("otelcol-contrib not found on PATH");

    let expected: usize = golden
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .map(|v| count_records(&v))
        .sum();
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut got = 0;
    let mut text = String::new();
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
        text = std::fs::read_to_string(&output).unwrap_or_default();
        got = text
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .map(|v| count_records(&v))
            .sum();
        if got >= expected {
            break;
        }
    }
    child.kill().unwrap();
    child.wait().unwrap();

    assert_eq!(got, expected, "Collector dropped records; output:\n{text}");
    for spelling in ["\"NaN\"", "\"Infinity\"", "\"-Infinity\""] {
        assert!(text.contains(spelling), "{spelling} lost in:\n{text}");
    }
    std::fs::remove_dir_all(dir).unwrap();
}

fn count_records(line: &Value) -> usize {
    line["resourceLogs"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|r| r["scopeLogs"].as_array().into_iter().flatten())
        .map(|s| s["logRecords"].as_array().map_or(0, Vec::len))
        .sum()
}
