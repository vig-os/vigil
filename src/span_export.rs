//! **Unstable:** bounded OTLP/JSON span export. Enable `--cfg vigil_unstable`
//! and pin `=0.N.M` before 1.0; pin `~1.N` from 1.0.
use crate::{
    envelope::{self, Envelope},
    logs::{self, StringCandidate},
    sink::LineSink,
};
use opentelemetry_proto::{
    tonic::collector::trace::v1::ExportTraceServiceRequest,
    transform::{
        common::tonic::ResourceAttributesWithSchema,
        trace::tonic::group_spans_by_resource_and_scope,
    },
};
use opentelemetry_sdk::{
    Resource,
    error::{OTelSdkError, OTelSdkResult},
    trace::{SpanData, SpanExporter},
};
use serde_json::Value as Json;
use std::{
    future::{Future, ready},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

/// **Unstable:** writes spans as bounded OTLP/JSON lines.
/// Oversized spans are shortened or replaced with identity-preserving stubs.
/// The `vigil.truncated`, `vigil.dropped` and `vigil.original_size` attribute
/// names are reserved on spans; shortening replaces caller-supplied values.
/// Known limit: an SDK scope with a NaN-valued attribute never equals itself,
/// so each span has its own `scopeSpans` entry. Output remains deterministic.
/// Use `--cfg vigil_unstable` and pin `=0.N.M` before 1.0; pin `~1.N` from 1.0.
#[derive(Debug)]
#[cfg_attr(docsrs, doc(cfg(vigil_unstable)))]
pub struct OtlpJsonSpanExporter<S: LineSink> {
    sink: S,
    resource: Resource,
    limit: usize,
    dropped: AtomicUsize,
}
impl<S: LineSink> OtlpJsonSpanExporter<S> {
    /// Write to `sink`, with an empty resource and 1,000,000-byte payload limit.
    pub fn new(sink: S) -> Self {
        Self {
            sink,
            resource: Resource::builder_empty().build(),
            limit: 1_000_000,
            dropped: AtomicUsize::new(0),
        }
    }
    /// Set the payload limit, clamped to 1..=1,048,575 bytes, excluding newline.
    #[cfg(any(test, vigil_unstable))]
    pub fn with_max_line_bytes(mut self, limit: usize) -> Self {
        self.limit = limit.clamp(1, 1_048_575);
        self
    }
    /// The sink receiving complete lines.
    #[cfg(any(test, vigil_unstable))]
    pub fn sink(&self) -> &S {
        &self.sink
    }
    /// Consume the number of spans lost since the previous call.
    pub(crate) fn take_dropped_spans(&self) -> usize {
        self.dropped.swap(0, Ordering::Relaxed)
    }
    fn write(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        if batch.is_empty() {
            return Ok(());
        }
        let mut lost = batch.len();
        let result = (|| {
            let request = ExportTraceServiceRequest {
                resource_spans: group_spans_by_resource_and_scope(
                    batch,
                    &ResourceAttributesWithSchema::from(&self.resource),
                ),
            };
            let json = project(request).map_err(OTelSdkError::InternalFailure)?;
            let lines = envelope::bounded_lines(&json, self.limit, Envelope::Traces)
                .map_err(OTelSdkError::InternalFailure)?;
            for line in lines {
                self.sink.write_line(line.text().as_bytes()).map_err(|e| {
                    OTelSdkError::InternalFailure(format!("writing span batch: {e}"))
                })?;
                lost -= line.records() - line.stubs();
            }
            Ok(())
        })();
        self.dropped.fetch_add(lost, Ordering::Relaxed);
        result
    }
}
impl<S: LineSink + 'static> SpanExporter for OtlpJsonSpanExporter<S> {
    fn export(&self, batch: Vec<SpanData>) -> impl Future<Output = OTelSdkResult> + Send {
        ready(self.write(batch))
    }
    fn force_flush(&self) -> OTelSdkResult {
        self.sink
            .flush()
            .map_err(|e| OTelSdkError::InternalFailure(format!("flushing span sink: {e}")))
    }
    fn shutdown_with_timeout(&self, _: Duration) -> OTelSdkResult {
        self.force_flush()
    }
    fn set_resource(&mut self, resource: &Resource) {
        self.resource = resource.clone();
    }
}

fn project(mut request: ExportTraceServiceRequest) -> Result<Json, String> {
    for r in &mut request.resource_spans {
        if let Some(r) = &mut r.resource {
            envelope::sort_attributes(&mut r.attributes);
        }
        for s in &mut r.scope_spans {
            if let Some(s) = &mut s.scope {
                envelope::sort_attributes(&mut s.attributes);
            }
            for span in &mut s.spans {
                envelope::sort_attributes(&mut span.attributes);
                for event in &mut span.events {
                    envelope::sort_attributes(&mut event.attributes);
                }
                for link in &mut span.links {
                    envelope::sort_attributes(&mut link.attributes);
                }
            }
        }
    }
    let mut json = serde_json::to_value(&request).map_err(|e| e.to_string())?;
    for (r, j) in request
        .resource_spans
        .iter()
        .zip(json["resourceSpans"].as_array_mut().into_iter().flatten())
    {
        if let Some(r) = &r.resource {
            envelope::patch_key_values(&r.attributes, &mut j["resource"]["attributes"]);
        }
        for (s, j) in r
            .scope_spans
            .iter()
            .zip(j["scopeSpans"].as_array_mut().into_iter().flatten())
        {
            if let Some(s) = &s.scope {
                envelope::patch_key_values(&s.attributes, &mut j["scope"]["attributes"]);
            }
            for (span, j) in s
                .spans
                .iter()
                .zip(j["spans"].as_array_mut().into_iter().flatten())
            {
                envelope::patch_key_values(&span.attributes, &mut j["attributes"]);
                for (event, j) in span
                    .events
                    .iter()
                    .zip(j["events"].as_array_mut().into_iter().flatten())
                {
                    envelope::patch_key_values(&event.attributes, &mut j["attributes"]);
                }
                for (link, j) in span
                    .links
                    .iter()
                    .zip(j["links"].as_array_mut().into_iter().flatten())
                {
                    envelope::patch_key_values(&link.attributes, &mut j["attributes"]);
                }
            }
        }
    }
    envelope::normalize(&mut json, "", crate::ordered_json::TRACES)?;
    Ok(json)
}

// Candidates are values only; names, keys, ids and trace state are immutable.
fn candidates(value: &Json) -> Vec<StringCandidate> {
    let mut result = Vec::new();
    for key in ["attributes", "events", "links"] {
        logs::string_candidates(&value[key], &mut vec![key.into()], &mut result);
    }
    if let Some(message) = value["status"]["message"]
        .as_str()
        .filter(|s| !s.is_empty())
    {
        result.push(StringCandidate {
            pointer: "/status/message".into(),
            bytes: logs::string_bytes(message),
            base64: false,
        });
    }
    result.sort_by_key(|c| (std::cmp::Reverse(c.bytes), c.pointer.clone()));
    result
}
fn shorten(value: &mut Json, overhead: usize, limit: usize) -> Result<Option<String>, String> {
    let encode = |v: &Json| crate::ordered_json::encode(v, "spans", crate::ordered_json::TRACES);
    let mut size = overhead + encode(value)?.len();
    for candidate in candidates(value) {
        if size <= limit {
            break;
        }
        if let Some(Json::String(text)) = value.pointer_mut(&candidate.pointer) {
            let before = logs::string_bytes(text);
            logs::cut_string(text, size - limit, candidate.base64);
            size -= before - logs::string_bytes(text);
        }
    }
    logs::sort_json_attributes(value);
    (size <= limit).then(|| encode(value)).transpose()
}
pub(crate) fn fit_span(
    span: &Json,
    overhead: usize,
    limit: usize,
) -> Result<(String, bool), String> {
    let original = crate::ordered_json::encode(span, "spans", crate::ordered_json::TRACES)?;
    let original_size = overhead + original.len();
    if original_size <= limit {
        return Ok((original, false));
    }
    let mut shortened = span.clone();
    let mut attributes = shortened["attributes"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    attributes.retain(|a| {
        !matches!(
            a["key"].as_str(),
            Some("vigil.truncated" | "vigil.dropped" | "vigil.original_size")
        )
    });
    attributes.extend(logs::markers(original_size, false));
    shortened["attributes"] = Json::Array(attributes);
    if let Some(text) = shorten(&mut shortened, overhead, limit)? {
        return Ok((text, false));
    }
    let mut stub = serde_json::Map::new();
    for key in [
        "traceId",
        "spanId",
        "parentSpanId",
        "name",
        "kind",
        "startTimeUnixNano",
        "endTimeUnixNano",
        "status",
    ] {
        if let Some(value) = span.get(key) {
            stub.insert(key.into(), value.clone());
        }
    }
    stub.insert(
        "attributes".into(),
        Json::Array(logs::markers(original_size, true)),
    );
    shorten(&mut Json::Object(stub), overhead, limit)?
        .map(|text| (text, true))
        .ok_or_else(|| {
            format!("span envelope and diagnostic identity exceed max_line_bytes={limit}")
        })
}

#[cfg(test)]
#[path = "../tests/common/spans.rs"]
pub(crate) mod fixtures;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::MemorySink;

    fn output(batch: Vec<SpanData>, cap: usize) -> (OTelSdkResult, Vec<String>, usize) {
        let exporter = OtlpJsonSpanExporter::new(MemorySink::new()).with_max_line_bytes(cap);
        let result = fixtures::ready(exporter.export(batch));
        let lost = exporter.take_dropped_spans();
        assert_eq!(exporter.take_dropped_spans(), 0);
        (result, exporter.sink().lines(), lost)
    }
    fn records(lines: &[String]) -> Vec<Json> {
        lines
            .iter()
            .flat_map(|line| {
                let json: Json = serde_json::from_str(line).unwrap();
                json["resourceSpans"][0]["scopeSpans"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .flat_map(|scope| scope["spans"].as_array().unwrap().clone())
                    .collect::<Vec<_>>()
            })
            .collect()
    }
    #[test]
    fn ordered_spans_sort_scopes_and_attributes_keep_batch_order() {
        let batch_with_children = || {
            let mut batch = fixtures::batch();
            let span = &mut batch[0];
            let attributes = vec![
                opentelemetry::KeyValue::new("z", "last"),
                opentelemetry::KeyValue::new("a", "first"),
            ];
            span.events.events.push(opentelemetry::trace::Event::new(
                "event",
                span.start_time,
                attributes.clone(),
                0,
            ));
            span.links.links.push(opentelemetry::trace::Link::new(
                span.span_context.clone(),
                attributes,
                0,
            ));
            batch
        };
        let (_, expected, _) = output(batch_with_children(), 10000);
        let json: Json = serde_json::from_str(&expected[0]).unwrap();
        let scopes = json["resourceSpans"][0]["scopeSpans"].as_array().unwrap();
        assert_eq!(scopes[0]["scope"]["name"], "a");
        assert_eq!(scopes[1]["scope"]["name"], "b");
        assert_eq!(scopes[0]["spans"][0]["name"], "span-3");
        assert_eq!(scopes[0]["spans"][1]["name"], "span-1");
        for _ in 0..128 {
            let mut batch = batch_with_children();
            batch.swap(0, 1);
            batch.swap(2, 3);
            for span in &mut batch {
                span.attributes.reverse();
                for event in &mut span.events.events {
                    event.attributes.reverse();
                }
                for link in &mut span.links.links {
                    link.attributes.reverse();
                }
            }
            assert_eq!(output(batch, 10000).1, expected);
        }
    }
    #[test]
    fn ordered_span_fingerprint_and_encoding() {
        let mut span = fixtures::span("a", 0xabcdef);
        span.attributes.extend([
            opentelemetry::KeyValue::new("positive", f64::INFINITY),
            opentelemetry::KeyValue::new("negative", f64::NEG_INFINITY),
        ]);
        let (_, lines, _) = output(vec![span], 10000);
        let prefix = "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":[{\"spanId\":";
        for line in &lines {
            assert!(line.starts_with(prefix));
            let json: Json = serde_json::from_str(line).unwrap();
            let id = json["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["spanId"]
                .as_str()
                .unwrap();
            let written_id = format!("\"spanId\":\"{id}\"");
            assert!(line.find(&written_id).unwrap() + written_id.len() <= 128);
            assert!(line.contains("\"doubleValue\":\"NaN\""));
            assert!(line.contains("\"doubleValue\":\"Infinity\""));
            assert!(line.contains("\"doubleValue\":\"-Infinity\""));
        }
        let spans = records(&lines);
        assert_eq!(spans[0]["spanId"], "0000000000abcdef");
        assert_eq!(spans[0]["traceId"], "00000000000000000000000000abcdef");
        assert_eq!(spans[0]["kind"], 2);
        assert_eq!(spans[0]["status"]["code"], 2);
    }
    #[test]
    fn ordered_trace_children_precede_remaining_envelope_metadata() {
        use opentelemetry_proto::tonic::{
            common::v1::InstrumentationScope,
            resource::v1::Resource as ProtoResource,
            trace::v1::{ResourceSpans, ScopeSpans, Span},
        };
        // Valid OTLP messages at the shared envelope seam may carry dropped
        // attribute counts. These are remaining metadata, not primary keys;
        // child structure must decide ties before these counts (ADR-0001 d5).
        let resource = |name: &str, dropped| ResourceSpans {
            resource: Some(ProtoResource {
                dropped_attributes_count: dropped,
                ..Default::default()
            }),
            scope_spans: vec![ScopeSpans {
                scope: Some(InstrumentationScope {
                    name: "same".into(),
                    dropped_attributes_count: dropped,
                    ..Default::default()
                }),
                spans: vec![Span {
                    name: name.into(),
                    trace_id: vec![1; 16],
                    span_id: vec![1; 8],
                    start_time_unix_nano: 1,
                    end_time_unix_nano: 2,
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        // SDK scope identity distinguishes an absent version from an explicit
        // empty version, although both project to identical OTLP metadata.
        // These SDK scopes pin metadata ties, not the field_order arms.
        // The hand-built proto differs in droppedAttributesCount and
        // exercises those arms.
        let mut a = fixtures::span("same", 1);
        a.name = "a".into();
        let mut b = fixtures::span("same", 2);
        b.name = "b".into();
        b.instrumentation_scope = opentelemetry::InstrumentationScope::builder("same")
            .with_version("")
            .build();
        assert_ne!(a.instrumentation_scope, b.instrumentation_scope);
        let (result, lines, lost) = output(vec![b.clone(), a.clone()], 10000);
        result.unwrap();
        assert_eq!(lost, 0);
        let json: Json = serde_json::from_str(&lines[0]).unwrap();
        let scopes = json["resourceSpans"][0]["scopeSpans"].as_array().unwrap();
        assert_eq!(scopes.len(), 2);
        assert_eq!(scopes[0]["scope"], scopes[1]["scope"]);
        assert_eq!(scopes[0]["spans"][0]["name"], "a");
        assert_eq!(scopes[1]["spans"][0]["name"], "b");
        assert_eq!(output(vec![a, b], 10000).1, lines);
        // ResourceSpans: scopeSpans must precede resource metadata.
        let request = ExportTraceServiceRequest {
            resource_spans: vec![resource("b", 1), resource("a", 2)],
        };
        let json = project(request.clone()).unwrap();
        assert_eq!(
            json["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["name"],
            "a"
        );
        let mut reversed = request;
        reversed.resource_spans.reverse();
        assert_eq!(project(reversed).unwrap(), json);
        // ScopeSpans: spans must precede scope metadata.
        let mut first = resource("b", 1);
        first.scope_spans.extend(resource("a", 2).scope_spans);
        let request = ExportTraceServiceRequest {
            resource_spans: vec![first],
        };
        let json = project(request.clone()).unwrap();
        assert_eq!(
            json["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["name"],
            "a"
        );
        let mut reversed = request;
        reversed.resource_spans[0].scope_spans.reverse();
        assert_eq!(project(reversed).unwrap(), json);
    }
    #[test]
    fn ordered_nan_scope_keeps_separate_deterministic_entries() {
        let scope = opentelemetry::InstrumentationScope::builder("nan")
            .with_attributes([opentelemetry::KeyValue::new("value", f64::NAN)])
            .build();
        let mut a = fixtures::span("nan", 1);
        a.instrumentation_scope = scope.clone();
        let mut b = fixtures::span("nan", 2);
        b.instrumentation_scope = scope;
        let batch = vec![a, b];
        let (result, lines, lost) = output(batch.clone(), 10000);
        result.unwrap();
        assert_eq!(lost, 0);
        let json: Json = serde_json::from_str(&lines[0]).unwrap();
        let scopes = json["resourceSpans"][0]["scopeSpans"].as_array().unwrap();
        assert_eq!(scopes.len(), 2);
        assert!(
            scopes
                .iter()
                .all(|s| s["spans"].as_array().unwrap().len() == 1)
        );
        assert_eq!(output(batch, 10000).1, lines);
    }
    #[test]
    fn empty_batch_writes_nothing() {
        let (result, lines, lost) = output(Vec::new(), 1);
        result.unwrap();
        assert!(lines.is_empty());
        assert_eq!(lost, 0);
        let (result, lines, lost) = output(Vec::new(), 10000);
        result.unwrap();
        assert!(lines.is_empty());
        assert_eq!(lost, 0);
    }
    #[test]
    fn ordered_shortened_attributes_include_sorted_markers() {
        let mut span = fixtures::span("a", 2);
        span.attributes
            .push(opentelemetry::KeyValue::new("payload", "x".repeat(10000)));
        let (result, lines, lost) = output(vec![span], 1000);
        result.unwrap();
        assert_eq!(lost, 0);
        assert_eq!(lines.len(), 1);
        let spans = records(&lines);
        let keys: Vec<_> = spans[0]["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["key"].as_str().unwrap())
            .collect();
        assert_eq!(
            keys,
            [
                "a",
                "payload",
                "vigil.original_size",
                "vigil.truncated",
                "z"
            ]
        );
    }
    #[test]
    fn shortening_replaces_reserved_markers() {
        let mut span = fixtures::span("a", 2);
        span.attributes.extend([
            opentelemetry::KeyValue::new("payload", "x".repeat(10000)),
            opentelemetry::KeyValue::new("vigil.truncated", false),
            opentelemetry::KeyValue::new("vigil.dropped", true),
            opentelemetry::KeyValue::new("vigil.original_size", -1_i64),
        ]);
        let original_size = output(vec![span.clone()], 100000).1[0].len();
        let (result, lines, lost) = output(vec![span], 1000);
        result.unwrap();
        assert_eq!(lost, 0);
        let spans = records(&lines);
        let attributes = spans[0]["attributes"].as_array().unwrap();
        let named = |name| {
            attributes
                .iter()
                .filter(|a| a["key"] == name)
                .collect::<Vec<_>>()
        };
        let truncated = named("vigil.truncated");
        assert_eq!(truncated.len(), 1);
        assert_eq!(truncated[0]["value"]["boolValue"], true);
        let original = named("vigil.original_size");
        assert_eq!(original.len(), 1);
        assert_eq!(original[0]["value"]["intValue"], original_size.to_string());
        assert!(named("vigil.dropped").is_empty());
    }
    #[test]
    fn split_spans_repeat_metadata() {
        let (result, lines, lost) = output(fixtures::batch(), 800);
        result.unwrap();
        assert_eq!(lost, 0);
        assert!(lines.len() > 1);
        assert_eq!(records(&lines).len(), 4);
        for line in lines {
            assert!(line.len() <= 800);
            let json: Json = serde_json::from_str(&line).unwrap();
            assert!(json["resourceSpans"][0]["resource"].is_object());
            for scope in json["resourceSpans"][0]["scopeSpans"].as_array().unwrap() {
                assert!(scope["scope"]["name"].is_string());
            }
        }
    }
    #[test]
    fn shorten_values_preserve_identity() {
        let mut span = fixtures::span("a", 2);
        span.name = "n".repeat(100).into();
        span.attributes
            .push(opentelemetry::KeyValue::new("large", "x".repeat(10000)));
        let (result, lines, lost) = output(vec![span], 1000);
        result.unwrap();
        assert_eq!(lost, 0);
        let spans = records(&lines);
        let s = &spans[0];
        assert_eq!(s["name"], "n".repeat(100));
        assert_eq!(s["traceState"], "vendor=state");
        assert_eq!(s["spanId"], "0000000000000002");
        assert!(lines[0].contains("vigil.truncated"));
        assert!(lines[0].contains("vigil.original_size"));
        assert!(lines[0].len() <= 1000);
        // Immutable name alone forces a stub, never a shortened name.
        let mut span = fixtures::span("a", 2);
        span.name = "n".repeat(2000).into();
        let (result, lines, lost) = output(vec![span], 1000);
        assert!(result.is_err());
        assert!(lines.is_empty());
        assert_eq!(lost, 1);
    }
    #[test]
    fn stub_retains_exact_fields_and_neighbours() {
        let mut batch = fixtures::batch();
        batch[1].attributes.extend(
            (0..100).map(|i| opentelemetry::KeyValue::new(format!("key-{i}"), i64::from(i))),
        );
        batch[1].status = opentelemetry::trace::Status::error("s".repeat(4000));
        let (result, lines, lost) = output(batch, 800);
        result.unwrap();
        assert_eq!(lost, 1);
        let spans = records(&lines);
        assert_eq!(spans.len(), 4);
        let stub = spans.iter().find(|s| s["name"] == "span-3").unwrap();
        let mut keys: Vec<_> = stub
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "attributes",
                "endTimeUnixNano",
                "kind",
                "name",
                "parentSpanId",
                "spanId",
                "startTimeUnixNano",
                "status",
                "traceId"
            ]
        );
        assert_eq!(stub["attributes"].as_array().unwrap().len(), 3);
        assert_eq!(stub["attributes"][0]["key"], "vigil.dropped");
        assert_eq!(stub["attributes"][0]["value"]["boolValue"], true);
        assert!(
            spans
                .iter()
                .filter(|s| s["name"] != "span-3")
                .all(|s| s["traceState"] == "vendor=state")
        );
    }
    #[test]
    fn sanitizes_resource_scope_event_and_link_values() {
        use opentelemetry_proto::tonic::{
            common::v1::{AnyValue, KeyValue, any_value::Value},
            resource::v1::Resource as ProtoResource,
            trace::v1::{
                ResourceSpans, ScopeSpans, Span,
                span::{Event, Link},
            },
        };
        let attributes = vec![KeyValue {
            key: "nonfinite".into(),
            value: Some(AnyValue {
                value: Some(Value::DoubleValue(f64::NAN)),
            }),
            ..Default::default()
        }];
        let request = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(ProtoResource {
                    attributes: attributes.clone(),
                    ..Default::default()
                }),
                scope_spans: vec![ScopeSpans {
                    scope: Some(
                        opentelemetry_proto::tonic::common::v1::InstrumentationScope {
                            attributes: attributes.clone(),
                            ..Default::default()
                        },
                    ),
                    spans: vec![Span {
                        attributes: attributes.clone(),
                        events: vec![Event {
                            attributes: attributes.clone(),
                            ..Default::default()
                        }],
                        links: vec![Link {
                            attributes,
                            ..Default::default()
                        }],
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        let json = project(request).unwrap();
        let text = crate::ordered_json::encode(&json, "", crate::ordered_json::TRACES).unwrap();
        assert_eq!(text.matches("\"doubleValue\":\"NaN\"").count(), 5);
    }
    #[test]
    fn shortening_includes_event_link_bytes_and_status_only() {
        let span = serde_json::json!({"spanId": "0000000000000001", "name": "immutable", "status": {"code": 2, "message": "x".repeat(4000)}, "events": [{"name": "event", "attributes": [{"key":"key", "value":{"stringValue":"x".repeat(3000)}}]}], "links": [{"traceState": "vendor=immutable", "attributes": [{"key":"bytes", "value":{"bytesValue":"YWJj".repeat(500)}}]}]});
        let (text, stub) = fit_span(&span, 0, 800).unwrap();
        assert!(!stub);
        assert!(text.len() <= 800);
        let json: Json = serde_json::from_str(&text).unwrap();
        assert_eq!(json["name"], "immutable");
        assert_eq!(json["events"][0]["name"], "event");
        assert_eq!(json["links"][0]["traceState"], "vendor=immutable");
        assert_eq!(
            json["links"][0]["attributes"][0]["value"]["bytesValue"]
                .as_str()
                .unwrap()
                .len()
                % 4,
            0
        );
    }
    #[test]
    fn resource_replacement_flush_and_failed_write_accounting() {
        use crate::sink::LineSink;
        use std::sync::Mutex;
        #[derive(Debug, Default)]
        struct FailSecond(Mutex<usize>);
        impl LineSink for FailSecond {
            fn write_line(&self, _: &[u8]) -> std::io::Result<()> {
                let mut n = self.0.lock().unwrap();
                *n += 1;
                if *n == 2 {
                    Err(std::io::Error::other("write failure"))
                } else {
                    Ok(())
                }
            }
            fn flush(&self) -> std::io::Result<()> {
                Err(std::io::Error::other("flush failure"))
            }
        }
        let mut exporter =
            OtlpJsonSpanExporter::new(FailSecond::default()).with_max_line_bytes(800);
        exporter.set_resource(
            &Resource::builder_empty()
                .with_attribute(opentelemetry::KeyValue::new("service.name", "service"))
                .build(),
        );
        assert!(fixtures::ready(exporter.export(fixtures::batch())).is_err());
        assert_eq!(exporter.take_dropped_spans(), 3);
        assert!(
            exporter
                .force_flush()
                .unwrap_err()
                .to_string()
                .contains("flush failure")
        );
        assert!(exporter.shutdown_with_timeout(Duration::ZERO).is_err());
        let mut exporter = OtlpJsonSpanExporter::new(MemorySink::new());
        exporter.set_resource(
            &Resource::builder_empty()
                .with_attribute(opentelemetry::KeyValue::new("replace", "old"))
                .build(),
        );
        exporter.set_resource(
            &Resource::builder_empty()
                .with_attribute(opentelemetry::KeyValue::new("replace", "new"))
                .build(),
        );
        fixtures::ready(exporter.export(fixtures::batch())).unwrap();
        assert!(exporter.sink().lines()[0].contains("new"));
        assert!(!exporter.sink().lines()[0].contains("old"));
    }
    #[test]
    fn stub_too_big_is_atomic_and_counts_whole_batch() {
        let mut batch = fixtures::batch();
        batch[3].name = "n".repeat(2000).into();
        let (result, lines, lost) = output(batch, 800);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("span envelope and diagnostic identity exceed")
        );
        assert!(lines.is_empty());
        assert_eq!(lost, 4);
    }
}
