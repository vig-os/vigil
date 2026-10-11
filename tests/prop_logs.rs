//! Generated exporter inputs, checked against independent wire-level invariants.
mod common;
use common::*;
use opentelemetry::{
    KeyValue,
    logs::{AnyValue, LogRecord as _, Severity},
};
use opentelemetry_sdk::logs::{LogBatch, LogExporter};
use proptest::prelude::*;
use serde_json::{Value, json};
use vigil::{logs::OtlpJsonLogExporter, sink::MemorySink};

fn encode(records: &[Rec], cap: usize) -> Vec<String> {
    let sink = MemorySink::new();
    let mut exporter = OtlpJsonLogExporter::new(sink.clone()).with_max_line_bytes(cap);
    exporter.set_resource(&resource(vec![KeyValue::new("service.name", "immutable")]));
    let pairs: Vec<_> = records.iter().map(|r| (&r.record, &r.scope)).collect();
    let mut future = std::pin::pin!(exporter.export(LogBatch::new(&pairs)));
    use std::future::Future;
    match future
        .as_mut()
        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    {
        std::task::Poll::Ready(result) => result.unwrap(),
        _ => panic!("export must complete synchronously"),
    }
    sink.lines()
}
fn records(lines: &[String]) -> Vec<Value> {
    lines
        .iter()
        .flat_map(|line| {
            let v: Value = serde_json::from_str(line).unwrap();
            assert_eq!(
                v["resourceLogs"][0]["resource"]["attributes"][0]["value"]["stringValue"],
                "immutable"
            );
            v["resourceLogs"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|r| r["scopeLogs"].as_array().unwrap())
                .flat_map(|s| {
                    assert_eq!(s["scope"]["version"], "1");
                    s["logRecords"].as_array().unwrap().clone()
                })
                .collect::<Vec<_>>()
        })
        .collect()
}
fn attr<'a>(r: &'a Value, key: &str) -> &'a Value {
    &r["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["key"] == key)
        .unwrap()["value"]
}
fn envelopes(lines: &[String]) -> std::collections::BTreeSet<String> {
    let mut result = std::collections::BTreeSet::new();
    for line in lines {
        let value: Value = serde_json::from_str(line).unwrap();
        for resource in value["resourceLogs"].as_array().unwrap() {
            for scope in resource["scopeLogs"].as_array().unwrap() {
                result.insert(json!([resource["resource"], scope["scope"]]).to_string());
            }
        }
    }
    result
}
proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn bounding_split_and_determinism(bodies in prop::collection::vec(prop_oneof![Just(String::new()), ".{0,40}", ".{500,1800}"], 2..12), cap in 900usize..2200) {
        let batch: Vec<_> = bodies.iter().enumerate().map(|(i, body)| rec(&scope(if i % 2 == 0 {"a"} else {"b"}, "1"), |r| {
            r.set_timestamp(at(100 + i as u64, 0));
            r.set_event_name("immutable_event");
            r.set_body(body.clone().into());
            r.add_attribute("id", i as i64);
        })).collect();
        let lines = encode(&batch, cap);
        prop_assert_eq!(&lines, &encode(&batch, cap));
        for line in &lines { prop_assert!(line.len() <= cap); prop_assert!(!line.contains('\n')); }
        prop_assert_eq!(envelopes(&lines), envelopes(&encode(&batch, 100_000)));
        let output = records(&lines);
        prop_assert_eq!(output.len(), bodies.len());
        let mut ids = Vec::new();
        for r in output {
            prop_assert_eq!(&r["eventName"], "immutable_event");
            ids.push(attr(&r, "id")["intValue"].as_str().unwrap().parse::<usize>().unwrap());
        }
        ids.sort_unstable();
        prop_assert_eq!(ids, (0..bodies.len()).collect::<Vec<_>>());
    }
    #[test]
    fn largest_first_exact_overflow(big in 1400usize..2600, small in 1usize..100, overflow in 150usize..400) {
        let batch = [rec(&scope("a", "1"), |r| {
            r.set_body("m".repeat(small).into());
            r.set_event_name("event");
            r.add_attribute("payload", "x".repeat(big));
            r.add_attribute("number", 42i64);
        })];
        let full = encode(&batch, 100_000);
        let original = full[0].len();
        let mut marked: Value = serde_json::from_str(&full[0]).unwrap();
        let attrs = marked["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"].as_array_mut().unwrap();
        attrs.push(json!({"key":"vigil.truncated","value":{"boolValue":true}}));
        attrs.push(json!({"key":"vigil.original_size","value":{"intValue":original.to_string()}}));
        let cap = marked.to_string().len() - overflow;
        let lines = encode(&batch, cap);
        prop_assert_eq!(lines[0].len(), cap);
        let out = records(&lines);
        prop_assert_eq!(&out[0]["body"]["stringValue"], &"m".repeat(small));
        prop_assert_eq!(attr(&out[0], "payload")["stringValue"].as_str().unwrap().len(), big - overflow);
        prop_assert_eq!(&out[0]["eventName"], "event");
        prop_assert_eq!(attr(&out[0], "number"), &json!({"intValue":"42"}));
        prop_assert_eq!(attr(&out[0], "vigil.original_size")["intValue"].as_str().unwrap(), original.to_string());
        prop_assert_eq!(attr(&out[0], "vigil.truncated"), &json!({"boolValue":true}));
    }
    #[test]
    fn nested_escaped_values(unit in prop::sample::select(vec!["é", "🦀", "\\", "\"", "\n", "\u{0001}"]), count in 800usize..1200, overflow in 150usize..400) {
        let text = unit.repeat(count);
        let batch = [rec(&scope("a", "1"), |r| {
            r.set_body("message".into());
            r.add_attribute("nested/~key", any_map(vec![("inner/~key", AnyValue::ListAny(Box::new(vec![text.clone().into()])))]));
        })];
        let full = encode(&batch, 100_000);
        let original = full[0].len();
        let mut marked: Value = serde_json::from_str(&full[0]).unwrap();
        let attrs = marked["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"].as_array_mut().unwrap();
        attrs.push(json!({"key":"vigil.truncated","value":{"boolValue":true}}));
        attrs.push(json!({"key":"vigil.original_size","value":{"intValue":original.to_string()}}));
        let cap = marked.to_string().len() - overflow;
        let output = encode(&batch, cap);
        prop_assert!(output[0].len() <= cap);
        let out = records(&output);
        let value = &attr(&out[0], "nested/~key")["kvlistValue"]["values"][0];
        prop_assert_eq!(&value["key"], "inner/~key");
        let shortened = value["value"]["arrayValue"]["values"][0]["stringValue"].as_str().unwrap();
        let escaped_unit = serde_json::to_string(unit).unwrap().len() - 2;
        let removed_units = overflow.div_ceil(escaped_unit);
        prop_assert_eq!(shortened, unit.repeat(count - removed_units));
        prop_assert_eq!(&out[0]["body"]["stringValue"], "message");
        prop_assert_eq!(cap - output[0].len(), removed_units * escaped_unit - overflow);
    }
    #[test]
    fn base64_boundaries(count in 1200usize..2000, overflow in 150usize..400) {
        let batch = [rec(&scope("a", "1"), |r| r.set_body(AnyValue::Bytes(Box::new(vec![0; count]))))];
        let full = encode(&batch, 100_000);
        let original = full[0].len();
        let full_records = records(&full);
        let bytes = full_records[0]["body"]["bytesValue"].as_str().unwrap();
        let mut marked: Value = serde_json::from_str(&full[0]).unwrap();
        marked["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"] = json!([
            {"key":"vigil.truncated","value":{"boolValue":true}},
            {"key":"vigil.original_size","value":{"intValue":original.to_string()}}
        ]);
        let cap = marked.to_string().len() - overflow;
        let output = encode(&batch, cap);
        prop_assert!(output[0].len() <= cap);
        let out = records(&output);
        let shortened = out[0]["body"]["bytesValue"].as_str().unwrap();
        prop_assert_eq!(shortened.len() % 4, 0);
        prop_assert_eq!(shortened, &bytes[..(bytes.len() - overflow) / 4 * 4]);
    }
    #[test]
    fn unshrinkable_identity(extra in 2000usize..5000, cap in 1000usize..1800, oversized_event in any::<bool>()) {
        let batch = [rec(&scope("a", "1"), |r| {
            r.set_event_name("immutable_event");
            if oversized_event {
                static EVENT: [u8; 5000] = [b'e'; 5000];
                r.set_event_name(std::str::from_utf8(&EVENT).unwrap());
            } else {
                r.add_attribute("k".repeat(extra), 42i64);
            }
            r.set_timestamp(at(123, 456));
            r.set_severity_number(Severity::Error);
            r.set_severity_text("ERROR");
            let (t,s,f) = ids(); r.set_trace_context(t,s,Some(f));
            r.set_body("message".into());
        })];
        let full = encode(&batch, 100_000);
        let original = records(&full);
        let bounded = encode(&batch, cap);
        prop_assert!(bounded.iter().all(|l| l.len() <= cap));
        let out = records(&bounded);
        prop_assert_eq!(out.len(), 1);
        for key in ["timeUnixNano", "observedTimeUnixNano", "severityNumber", "severityText", "traceId", "spanId", "flags"] {
            prop_assert_eq!(&out[0][key], &original[0][key]);
        }
        prop_assert_eq!(attr(&out[0], "vigil.dropped"), &json!({"boolValue":true}));
        prop_assert_eq!(attr(&out[0], "vigil.truncated"), &json!({"boolValue":true}));
        prop_assert_eq!(attr(&out[0], "vigil.original_size")["intValue"].as_str().unwrap(), full[0].len().to_string());
    }
    #[test]
    fn non_finite_encoding(which in 0usize..3, nested in any::<bool>()) {
        let value = [f64::NAN, f64::INFINITY, f64::NEG_INFINITY][which];
        let batch = [rec(&scope("a", "1"), |r| {
            let v = AnyValue::Double(value);
            r.set_body(if nested { AnyValue::ListAny(Box::new(vec![v])) } else {v});
        })];
        let lines = encode(&batch, 1000);
        let out = records(&lines);
        let body = if nested { &out[0]["body"]["arrayValue"]["values"][0] } else { &out[0]["body"] };
        prop_assert_eq!(&body["doubleValue"], ["NaN", "Infinity", "-Infinity"][which]);
    }
}
