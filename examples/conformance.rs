//! Write fixed rich records in multiple rotated batches and an expected manifest.
#[cfg(vigil_unstable)]
#[path = "../tests/common/mod.rs"]
mod common;

#[cfg(vigil_unstable)]
use opentelemetry::{KeyValue, logs::LogRecord as _};
#[cfg(vigil_unstable)]
use std::{path::PathBuf, sync::Arc};
#[cfg(vigil_unstable)]
use vigil::{
    rotate::{RotatingFile, RotationConfig},
    sink::MemorySink,
};

#[cfg(vigil_unstable)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .ok_or("expected output directory")?,
    );
    #[cfg(feature = "metrics")]
    if let Some(mode) = std::env::args().nth(2) {
        return identity_fixture(&dir, mode == "identity-poisoned");
    }
    #[cfg(feature = "metrics")]
    metric_fixture(&dir)?;
    let file = Arc::new(RotatingFile::open(
        &dir,
        "logs",
        RotationConfig::default().max_bytes(1).retention(None),
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
    let unshrinkable = common::rec(&common::scope("dropped", "1"), |record| {
        record.set_body("unshrinkable integer attributes".into());
        for index in 0..60_000 {
            record.add_attribute(format!("integer-{index}"), 42_i64);
        }
    });
    common::export(
        memory.clone(),
        &second_resource,
        std::slice::from_ref(&unshrinkable),
    );
    common::export(file.clone(), &second_resource, &[unshrinkable]);
    // Exercise the public initialization path and tracing bridge as well as
    // the rich SDK fixtures. Read the resulting files into the same manifest.
    let bridge_dir = dir.join("bridge");
    // The driver sets VIGIL_DIR to this directory before starting us.
    let guard = vigil::init("vigil-conformance")?;
    let padding = "x".repeat(4096);
    for index in 0..1024 {
        tracing::info!(case = "large-batch", index, payload = %padding, "large batch record");
    }
    let huge = "z".repeat(3 * 1024 * 1024);
    tracing::info!(case = "oversized", "{}", huge);
    drop(guard);
    let bridge_lines = std::fs::read_to_string(bridge_dir.join("logs.jsonl"))?;
    std::fs::write(dir.join("logs-bridge.jsonl"), &bridge_lines)?;
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
    lines.extend(bridge_lines.lines().map(str::to_owned));
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

#[cfg(not(vigil_unstable))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err("conformance requires RUSTFLAGS=\"--cfg vigil_unstable\"".into())
}

#[cfg(all(vigil_unstable, feature = "metrics"))]
fn metric_fixture(dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    use opentelemetry::metrics::MeterProvider;
    use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
    let sink = MemorySink::new();
    let exporter =
        vigil::metric_export::OtlpJsonMetricExporter::new(sink.clone()).with_max_line_bytes(1400);
    let provider = SdkMeterProvider::builder()
        .with_reader(
            PeriodicReader::builder(exporter)
                .with_interval(std::time::Duration::from_secs(3600))
                .build(),
        )
        .build();
    let meter = provider.meter("conformance");
    let gauge = meter.f64_gauge("nonfinite").build();
    let histogram = meter.f64_histogram("histogram").build();
    for index in 0..20 {
        let attrs = [
            KeyValue::new("series", index),
            KeyValue::new("nonfinite", f64::NAN),
        ];
        gauge.record(f64::NAN, &attrs);
        histogram.record(f64::INFINITY, &attrs);
    }
    provider.shutdown()?;
    let lines = sink.lines();
    assert!(lines.len() > 2, "metrics must split");
    std::fs::write(dir.join("metrics.jsonl"), lines.join("\n") + "\n")?;
    Ok(())
}

#[cfg(all(vigil_unstable, feature = "metrics"))]
fn identity_fixture(dir: &std::path::Path, poison: bool) -> Result<(), Box<dyn std::error::Error>> {
    use vigil::metrics::Counter;
    static A: Counter = Counter::new(vigil::scope!(), "conformance.conflict").with_unit("ms");
    static B: Counter = Counter::new(vigil::scope!(), "conformance.conflict").with_unit("s");
    static OK: Counter = Counter::new(vigil::scope!(), "conformance.kept");
    let (_, guard) = vigil::Config::new("identity-conformance")
        .dir(dir)
        .metrics_interval(std::time::Duration::from_secs(3600))
        .layer::<tracing_subscriber::Registry>()?;
    A.add(1, &[]);
    OK.add(7, &[]);
    if poison {
        B.add(1, &[]);
    }
    match guard.shutdown() {
        Err(error) if poison && error.kind() == vigil::FlushErrorKind::DataLost => Ok(()),
        Ok(()) if !poison => Ok(()),
        result => Err(format!("unexpected identity shutdown: {result:?}").into()),
    }
}
