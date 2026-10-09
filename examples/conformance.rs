//! Write fixed rich records in multiple rotated batches and an expected manifest.
#[path = "../tests/common/mod.rs"]
mod common;

use opentelemetry::{KeyValue, logs::LogRecord as _};
use std::{path::PathBuf, sync::Arc};
use vigil::{
    rotate::{RotatingFile, RotationConfig},
    sink::MemorySink,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .ok_or("expected output directory")?,
    );
    let file = Arc::new(RotatingFile::open(
        &dir,
        "logs",
        RotationConfig {
            max_bytes: 1,
            retention: None,
        },
    )?);
    let memory = MemorySink::new();
    let (resource, records) = common::golden_records();
    let second_resource = common::resource(vec![
        KeyValue::new("service.name", "vigil-golden"),
        KeyValue::new("process.pid", 2002_i64),
        KeyValue::new("service.version", "2.0.0"),
    ]);
    for (index, batch) in records.chunks(3).enumerate() {
        let resource = if index % 2 == 0 {
            &resource
        } else {
            &second_resource
        };
        common::export(memory.clone(), resource, batch);
        common::export(file.clone(), resource, batch);
    }
    // The reference reader delivers valid EOF fragments and drops garbage EOF
    // fragments. Include only the valid record in the expected manifest.
    let eof_record = common::rec(&common::scope("eof", "1"), |record| {
        record.set_body("unterminated valid record".into());
    });
    let eof = MemorySink::new();
    common::export(eof.clone(), &second_resource, &[eof_record]);
    let eof_line = eof.lines().pop().ok_or("missing EOF record")?;
    std::fs::write(dir.join("logs-unterminated-valid.jsonl"), &eof_line)?;
    std::fs::write(dir.join("logs-unterminated-garbage.jsonl"), "garbage")?;
    let mut lines = memory.lines();
    lines.push(eof_line);
    let manifest: Vec<serde_json::Value> = lines
        .iter()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(())
}
