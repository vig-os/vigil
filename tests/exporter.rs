//! Format, determinism and concurrency tests for the OTLP/JSON Lines log
//! exporter. The assertions on the wire format work on parsed
//! `serde_json::Value`, not on a round trip through opentelemetry-proto, which
//! would hide encoding mistakes symmetric on both sides.

mod common;

use std::sync::Arc;
use std::thread;

use common::*;
use opentelemetry::KeyValue;
use opentelemetry::logs::{AnyValue, LogRecord as _, Severity};
use opentelemetry_proto::tonic::logs::v1::LogsData;
use serde_json::Value;
use vigil::sink::{AppendFile, MemorySink};

fn one_line(sink: &MemorySink) -> Value {
    let lines = sink.lines();
    assert_eq!(lines.len(), 1, "one batch must be one line: {lines:?}");
    serde_json::from_str(&lines[0]).unwrap()
}

fn all_records(line: &Value) -> Vec<&Value> {
    line["resourceLogs"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|r| r["scopeLogs"].as_array().unwrap())
        .flat_map(|s| s["logRecords"].as_array().unwrap())
        .collect()
}

/// Panic unless `value` is a decimal-digit string.
fn assert_decimal_string(value: &Value) {
    let s = value
        .as_str()
        .unwrap_or_else(|| panic!("not a string: {value}"));
    assert!(
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()),
        "not decimal: {s}"
    );
}

fn assert_lower_camel_keys(value: &Value) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                // Attribute keys are data, not field names.
                let is_attr_key = key.contains('.') || key.contains('_');
                assert!(
                    is_attr_key
                        || !key.contains('_')
                            && key.chars().next().is_some_and(|c| c.is_ascii_lowercase()),
                    "key not lowerCamelCase: {key}"
                );
                assert_lower_camel_keys(value);
            }
        }
        Value::Array(items) => items.iter().for_each(assert_lower_camel_keys),
        _ => {}
    }
}

#[test]
fn wire_format_matches_otlp_json() {
    let (resource, records) = {
        let (r, mut recs) = golden_records();
        // Drop the NaN-bearing kinds so the line also deserializes via proto.
        recs.retain(|r| r.record.severity_number() != Some(Severity::Error));
        recs.retain(|r| !matches!(r.record.body(), Some(AnyValue::Map(_))));
        recs.retain(|r| matches!(r.scope.name(), "alpha" | "beta"));
        let _ = r;
        (resource(vec![KeyValue::new("service.name", "wire")]), recs)
    };
    let sink = MemorySink::new();
    export(sink.clone(), &resource, &records);
    let line = one_line(&sink);

    // Loads as LogsData through opentelemetry-proto's serde support.
    let typed: LogsData = serde_json::from_value(line.clone()).unwrap();
    assert_eq!(typed.resource_logs.len(), 1);

    let all = all_records(&line);
    assert_eq!(all.len(), 3);
    for record in &all {
        assert_decimal_string(&record["timeUnixNano"]);
        assert_decimal_string(&record["observedTimeUnixNano"]);
        if let Some(severity) = record.get("severityNumber") {
            assert!(
                severity.is_u64(),
                "severityNumber must be an integer: {severity}"
            );
        }
    }
    assert_lower_camel_keys(&line);

    let traced = all
        .iter()
        .find(|r| r["body"]["stringValue"] == "traced")
        .unwrap();
    assert_eq!(traced["traceId"], "5b8efde700112233445566778899aabb");
    assert_eq!(traced["spanId"], "eee19b7ec3c1b174");
    assert_eq!(traced["flags"], 1);
    assert_eq!(traced["severityNumber"], 9);
    assert_eq!(traced["timeUnixNano"], "1700000001000000000");
    assert_eq!(traced["observedTimeUnixNano"], "1700000000123456789");

    // The bare record has no trace context: ids are absent or empty.
    let bare = all.iter().find(|r| r["body"].is_null()).unwrap();
    for id in ["traceId", "spanId"] {
        assert!(
            bare.get(id).is_none_or(|v| v == ""),
            "{id}: {:?}",
            bare.get(id)
        );
    }
}

#[test]
fn time_unix_nano_falls_back_to_observed_time() {
    let sink = MemorySink::new();
    let s = scope("s", "1");
    export(sink.clone(), &resource(vec![]), &[rec(&s, |_| {})]);
    let line = one_line(&sink);
    let record = all_records(&line)[0];
    assert_eq!(record["timeUnixNano"], "1700000000123456789");
    assert_eq!(record["observedTimeUnixNano"], "1700000000123456789");
}

#[test]
fn explicit_time_unix_nano_is_kept() {
    let sink = MemorySink::new();
    let s = scope("s", "1");
    export(
        sink.clone(),
        &resource(vec![]),
        &[rec(&s, |r| r.set_timestamp(at(5, 7)))],
    );
    assert_eq!(
        all_records(&one_line(&sink))[0]["timeUnixNano"],
        "5000000007"
    );
}

#[test]
fn any_value_kinds_and_non_finite_doubles() {
    let (resource, records) = golden_records();
    let sink = MemorySink::new();
    export(sink.clone(), &resource, &records);
    let line = one_line(&sink);
    let kinds = *all_records(&line)
        .iter()
        .find(|r| r["body"]["stringValue"] == "kinds")
        .unwrap();
    let attr = |key: &str| -> &Value {
        &kinds["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|kv| kv["key"] == key)
            .unwrap_or_else(|| panic!("no attribute {key}"))["value"]
    };
    assert_eq!(attr("string")["stringValue"], "text");
    assert_eq!(attr("bool")["boolValue"], true);
    assert_eq!(attr("int")["intValue"], "9007199254740993");
    assert_eq!(attr("double")["doubleValue"], 1.5);
    assert_eq!(attr("nan")["doubleValue"], "NaN");
    assert_eq!(attr("inf")["doubleValue"], "Infinity");
    assert_eq!(attr("neg_inf")["doubleValue"], "-Infinity");
    assert_eq!(attr("bytes")["bytesValue"], "AAEC/v8=");
    let array = &attr("array")["arrayValue"]["values"];
    assert_eq!(array[0]["intValue"], "1");
    assert_eq!(array[1]["doubleValue"], "NaN");
    assert_eq!(
        array[3]["arrayValue"]["values"][1]["doubleValue"],
        "-Infinity"
    );
    let kvlist = &attr("kvlist")["kvlistValue"]["values"];
    assert_eq!(kvlist[0]["key"], "alpha");
    assert_eq!(kvlist[0]["value"]["doubleValue"], "Infinity");
    assert_eq!(kvlist[1]["key"], "mid");
    assert_eq!(kvlist[1]["value"]["kvlistValue"]["values"][0]["key"], "a");
    assert_eq!(kvlist[2]["key"], "zeta");
    // No `null` doubles anywhere: the Collector would drop the whole line.
    assert!(
        !sink.lines()[0].contains(r#""doubleValue":null"#),
        "{}",
        sink.lines()[0]
    );
}

#[test]
fn output_is_sorted_and_stable_across_runs() {
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..25 {
        let (resource, records) = golden_records();
        let sink = MemorySink::new();
        export(sink.clone(), &resource, &records);
        seen.insert(sink.lines().remove(0));
    }
    assert_eq!(seen.len(), 1, "output differs between runs");

    let (resource, records) = golden_records();
    let sink = MemorySink::new();
    export(sink.clone(), &resource, &records);
    let line = one_line(&sink);
    let names: Vec<_> = line["resourceLogs"][0]["scopeLogs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["scope"]["name"].as_str().unwrap(),
                s["scope"]["version"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        names,
        [
            ("alpha", "1.0.0"),
            ("alpha", "1.1.0"),
            ("beta", "2.1.0"),
            ("gamma", "3.0.0"),
            ("ordered", "1.0.0"),
            ("zero", "1"),
            ("zero", "1")
        ]
    );
    let keys: Vec<_> = line["resourceLogs"][0]["resource"]["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|kv| kv["key"].as_str().unwrap())
        .collect();
    assert_eq!(
        keys,
        [
            "deployment.environment",
            "host.name",
            "res_inf",
            "res_nan",
            "service.name"
        ]
    );
}

#[test]
fn empty_batch_writes_nothing() {
    let sink = MemorySink::new();
    export(sink.clone(), &resource(vec![]), &[]);
    assert!(sink.lines().is_empty());
}

#[test]
fn resource_is_captured_through_the_provider() {
    use opentelemetry::logs::{Logger as _, LoggerProvider as _};
    use opentelemetry_sdk::logs::SdkLoggerProvider;
    use vigil::logs::OtlpJsonLogExporter;

    let sink = MemorySink::new();
    let provider = SdkLoggerProvider::builder()
        .with_resource(resource(vec![KeyValue::new("service.name", "svc")]))
        .with_simple_exporter(OtlpJsonLogExporter::new(sink.clone()))
        .build();
    let logger = provider.logger("lib");
    let mut record = logger.create_log_record();
    record.set_body("x".into());
    logger.emit(record);
    provider.shutdown().unwrap();
    let line = one_line(&sink);
    assert_eq!(
        line["resourceLogs"][0]["resource"]["attributes"][0],
        serde_json::json!({"key": "service.name", "value": {"stringValue": "svc"}})
    );
    // Emitting without an explicit timestamp: tracing-style, observed only.
    let record = all_records(&line)[0];
    assert_eq!(record["timeUnixNano"], record["observedTimeUnixNano"]);
}

#[test]
fn a_failing_sink_surfaces_an_error() {
    use opentelemetry_sdk::logs::{LogBatch, LogExporter};
    use vigil::logs::OtlpJsonLogExporter;
    use vigil::sink::LineSink;

    #[derive(Debug)]
    struct Broken;
    impl LineSink for Broken {
        fn write_line(&self, _: &[u8]) -> std::io::Result<()> {
            Err(std::io::Error::other("disk on fire"))
        }
    }

    let s = scope("s", "1");
    let r = rec(&s, |_| {});
    let exporter = OtlpJsonLogExporter::new(Broken);
    let pairs = [(&r.record, &r.scope)];
    let mut fut = std::pin::pin!(exporter.export(LogBatch::new(&pairs)));
    let std::task::Poll::Ready(result) = std::future::Future::poll(
        fut.as_mut(),
        &mut std::task::Context::from_waker(std::task::Waker::noop()),
    ) else {
        panic!("not ready")
    };
    let message = format!("{:?}", result.unwrap_err());
    assert!(message.contains("disk on fire"), "{message}");
}

#[test]
fn concurrent_batches_never_interleave() {
    const THREADS: usize = 8;
    const BATCHES: usize = 200;

    let dir = std::env::temp_dir().join(format!("vigil-append-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("logs.jsonl");
    let sink = Arc::new(AppendFile::open(&path).unwrap());

    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let sink = Arc::clone(&sink);
            thread::spawn(move || {
                let s = scope("concurrent", "1");
                let resource = resource(vec![KeyValue::new("thread", t as i64)]);
                for n in 0..BATCHES {
                    // Large-ish batches make a torn write likely if it could happen.
                    let records: Vec<_> = (0..20)
                        .map(|i| {
                            rec(&s, |r| {
                                r.set_body(format!("t{t} n{n} i{i} {}", "x".repeat(300)).into())
                            })
                        })
                        .collect();
                    export(Arc::clone(&sink), &resource, &records);
                }
            })
        })
        .collect();
    handles.into_iter().for_each(|h| h.join().unwrap());

    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.ends_with('\n'));
    let mut per_thread = vec![0usize; THREADS];
    let mut lines = 0;
    for line in content.lines() {
        // Readers skip empty lines: a writer that glimpsed another's write in
        // flight (no trailing newline yet) adds a repair prefix, which lands
        // after that complete line as an empty one.
        if line.is_empty() {
            continue;
        }
        lines += 1;
        let value: Value = serde_json::from_str(line).expect("interleaved or torn line");
        let records = all_records(&value);
        assert_eq!(records.len(), 20);
        let thread = value["resourceLogs"][0]["resource"]["attributes"][0]["value"]["intValue"]
            .as_str()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        for record in records {
            let body = record["body"]["stringValue"].as_str().unwrap();
            assert!(
                body.starts_with(&format!("t{thread} ")),
                "mixed batch: {body}"
            );
        }
        per_thread[thread] += 1;
    }
    assert_eq!(lines, THREADS * BATCHES);
    assert!(per_thread.iter().all(|&n| n == BATCHES), "{per_thread:?}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn non_finite_doubles_in_resource_and_scope_attributes_are_sanitized() {
    let (resource, records) = golden_records();
    let sink = MemorySink::new();
    export(sink.clone(), &resource, &records);
    let raw = &sink.lines()[0];
    assert!(!raw.contains(r#""doubleValue":null"#), "{raw}");
    let line = one_line(&sink);

    let res_attr = |key: &str| {
        line["resourceLogs"][0]["resource"]["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|kv| kv["key"] == key)
            .unwrap()["value"]["doubleValue"]
            .clone()
    };
    assert_eq!(res_attr("res_inf"), "Infinity");
    assert_eq!(res_attr("res_nan"), "NaN");

    let scopes = line["resourceLogs"][0]["scopeLogs"].as_array().unwrap();
    let gamma: Vec<_> = scopes
        .iter()
        .filter(|s| s["scope"]["name"] == "gamma")
        .collect();
    // Merged into one scope holding all four records, in a stable order.
    assert_eq!(gamma.len(), 1);
    let bodies: Vec<_> = gamma[0]["logRecords"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["body"]["stringValue"].as_str().unwrap())
        .collect();
    assert_eq!(
        bodies,
        ["nan scope 0", "nan scope 1", "nan scope 2", "nan scope 3"]
    );
    let attrs = &gamma[0]["scope"]["attributes"];
    assert_eq!(attrs[0]["key"], "scope_nan");
    assert_eq!(attrs[0]["value"]["doubleValue"], "NaN");
    assert_eq!(attrs[1]["value"]["doubleValue"], "-Infinity");
}

fn bodies_of_scope<'a>(line: &'a Value, name: &str) -> Vec<Vec<&'a str>> {
    line["resourceLogs"][0]["scopeLogs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["scope"]["name"] == name)
        .map(|s| {
            s["logRecords"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["body"]["stringValue"].as_str().unwrap())
                .collect()
        })
        .collect()
}

#[test]
fn signed_zero_scopes_stay_distinct_and_records_keep_batch_order() {
    let (resource, records) = golden_records();
    let sink = MemorySink::new();
    export(sink.clone(), &resource, &records);
    let line = one_line(&sink);

    // -0.0 and 0.0 are different scopes (faithful), -0.0 sorts first, and each
    // holds its own records in batch order.
    assert_eq!(
        bodies_of_scope(&line, "zero"),
        [vec!["zero 1", "zero 3"], vec!["zero 0", "zero 2"]]
    );
    let zero_scopes: Vec<_> = line["resourceLogs"][0]["scopeLogs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["scope"]["name"] == "zero")
        .map(|s| {
            s["scope"]["attributes"][0]["value"]["doubleValue"]
                .as_f64()
                .unwrap()
        })
        .collect();
    assert!(zero_scopes[0].is_sign_negative() && zero_scopes[1].is_sign_positive());

    // Records of an untouched scope are not re-sorted by time.
    assert_eq!(
        bodies_of_scope(&line, "ordered"),
        [vec!["ordered 0", "ordered 1", "ordered 2"]]
    );
}
