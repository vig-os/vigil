//! Write fixed rich records in multiple rotated batches and an expected manifest.
#[path = "../tests/common/mod.rs"]
mod common;

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
    for batch in records.chunks(3) {
        common::export(memory.clone(), &resource, batch);
        common::export(file.clone(), &resource, batch);
    }
    let manifest: Vec<serde_json::Value> = memory
        .lines()
        .iter()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(())
}
