//! An OpenTelemetry [`LogExporter`] that writes OTLP/JSON Lines.
//!
//! Each export batch becomes bounded lines, each a `LogsData` message in the
//! [OTLP/JSON encoding] (the OTel [file exporter] format). Serialization is
//! done by `opentelemetry-proto`'s serde support, so 64-bit integers are
//! decimal strings, trace and span ids are hex, enums are integers and keys are
//! lowerCamelCase.
//!
//! On top of that encoding the exporter guarantees:
//!
//! * **Deterministic bytes.** The SDK groups records through a `HashMap`, so
//!   scope and attribute order would change from run to run. Resources, scopes
//!   and every attribute list (including `kvlistValue`s) are sorted before
//!   serializing, so identical input gives identical bytes.
//! * **`timeUnixNano` is filled.** The `tracing` bridge only sets the observed
//!   time; when `timeUnixNano` is `0` it is copied from `observedTimeUnixNano`.
//! * **Non-finite doubles survive.** See [`NON_FINITE`].
//!
//! [OTLP/JSON encoding]: https://opentelemetry.io/docs/specs/otlp/#json-protobuf-encoding
//! [file exporter]: https://opentelemetry.io/docs/specs/otel/protocol/file-exporter/
//!
//! ```
//! use opentelemetry::logs::{LogRecord as _, Logger as _, LoggerProvider as _, Severity};
//! use opentelemetry_sdk::logs::SdkLoggerProvider;
//! use vigil::logs::OtlpJsonLogExporter;
//! use vigil::sink::MemorySink;
//!
//! let sink = MemorySink::new();
//! let provider = SdkLoggerProvider::builder()
//!     .with_simple_exporter(OtlpJsonLogExporter::new(sink.clone()))
//!     .build();
//! let logger = provider.logger("example");
//! let mut record = logger.create_log_record();
//! record.set_severity_number(Severity::Info);
//! record.set_body("hello".into());
//! logger.emit(record);
//!
//! let lines = sink.lines();
//! assert_eq!(lines.len(), 1);
//! let value: serde_json::Value = serde_json::from_str(&lines[0])?;
//! let record = &value["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
//! assert_eq!(record["body"]["stringValue"], "hello");
//! assert_eq!(record["severityNumber"], 9);
//! # Ok::<(), serde_json::Error>(())
//! ```

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{
    AnyValue, InstrumentationScope, KeyValue, any_value::Value,
};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::resource::v1::Resource as ProtoResource;
use opentelemetry_proto::transform::common::tonic::ResourceAttributesWithSchema;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};
use opentelemetry_sdk::logs::{LogBatch, LogExporter};
use serde_json::Value as Json;

use crate::sink::LineSink;

/// How non-finite `doubleValue`s are spelled: `"NaN"`, `"Infinity"`,
/// `"-Infinity"`.
///
/// `opentelemetry-proto` serializes them as `{"doubleValue":null}`, which the
/// OpenTelemetry Collector rejects, silently dropping the **whole line** (every
/// record in the batch). The proto3 JSON mapping (which OTLP/JSON follows)
/// spells them as these strings. The Collector's `otlpjsonfile` receiver
/// accepts that spelling as a `doubleValue` (verified against
/// opentelemetry-collector-contrib 0.151.0, the version the flake pins, which
/// round-trips them back unchanged), so the exporter uses it and keeps the value a double. Note that
/// `opentelemetry-proto`'s own deserializer rejects these strings, so the
/// lines cannot be read back through its types; read them with `serde_json`
/// or the Collector.
pub const NON_FINITE: [&str; 3] = ["NaN", "Infinity", "-Infinity"];

/// Writes each log export batch as bounded OTLP/JSON `LogsData` lines to a
/// [`LineSink`].
///
/// See the [module documentation](self) for the format guarantees and an
/// example. Oversized records shorten their largest strings first, and carry `vigil.truncated` and `vigil.original_size`
/// (original single-record line bytes, including the envelope).
/// The exporter needs no async runtime: the SDK's batch processor
/// calls it from its own thread and the future it returns is already complete.
#[derive(Debug)]
pub struct OtlpJsonLogExporter<S: LineSink> {
    sink: S,
    resource: ResourceAttributesWithSchema,
    max_line_bytes: usize,
    dropped_records: AtomicUsize,
}

impl<S: LineSink> OtlpJsonLogExporter<S> {
    /// An exporter writing to `sink`. The resource is set by the SDK through
    /// [`LogExporter::set_resource`] when the exporter is added to a provider.
    #[must_use]
    pub fn new(sink: S) -> Self {
        Self {
            sink,
            resource: ResourceAttributesWithSchema::default(),
            max_line_bytes: 1_000_000,
            dropped_records: AtomicUsize::new(0),
        }
    }

    /// Maximum JSON payload bytes per line, excluding the newline (default
    /// 1,000,000). Clamped to 1..=1,048,575 for the Collector's 1 MiB limit.
    /// If the envelope alone cannot fit, export returns an explicit error.
    #[must_use]
    pub fn with_max_line_bytes(mut self, max_line_bytes: usize) -> Self {
        self.max_line_bytes = max_line_bytes.clamp(1, 1_048_575);
        self
    }

    /// The sink lines are written to.
    #[must_use]
    pub fn sink(&self) -> &S {
        &self.sink
    }

    // The initialization wrapper combines replacements and failed exports in
    // its bounded cumulative runtime-loss diagnostics.
    pub(crate) fn take_dropped_records(&self) -> usize {
        self.dropped_records.swap(0, Ordering::Relaxed)
    }

    fn export_batch(&self, batch: &LogBatch<'_>) -> OTelSdkResult {
        let Some(resource_logs) = group_batch(batch, &self.resource) else {
            return Ok(());
        };
        let line = encode_line(&ExportLogsServiceRequest {
            resource_logs: vec![resource_logs],
        })
        .map_err(|e| OTelSdkError::InternalFailure(format!("encoding log batch: {e}")))?;
        let mut dropped = 0;
        let lines = bounded_lines_counted(&line, self.max_line_bytes, &mut dropped)
            .map_err(OTelSdkError::InternalFailure)?;
        let _ = self
            .dropped_records
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                Some(count.saturating_add(dropped))
            });
        for line in lines {
            self.sink
                .write_line(line.as_bytes())
                .map_err(|e| OTelSdkError::InternalFailure(format!("writing log batch: {e}")))?;
        }
        Ok(())
    }
}

impl<S: LineSink + 'static> LogExporter for OtlpJsonLogExporter<S> {
    fn export(
        &self,
        batch: LogBatch<'_>,
    ) -> impl std::future::Future<Output = OTelSdkResult> + Send {
        // Everything is synchronous; the future is ready immediately.
        let result = self.export_batch(&batch);
        std::future::ready(result)
    }

    fn shutdown_with_timeout(&self, _timeout: Duration) -> OTelSdkResult {
        self.sink
            .flush()
            .map_err(|e| OTelSdkError::InternalFailure(format!("flushing log sink: {e}")))
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.resource = ResourceAttributesWithSchema::from(resource);
    }
}

/// Serialize a request as the single-line OTLP/JSON `LogsData` encoding.
///
/// `ExportLogsServiceRequest` and `LogsData` share their wire shape (a repeated
/// `resourceLogs` field 1), so the JSON is identical.
fn encode_line(request: &ExportLogsServiceRequest) -> Result<String, String> {
    let mut json = serde_json::to_value(request).map_err(|e| e.to_string())?;
    for (resource, json_resource) in request
        .resource_logs
        .iter()
        .zip(json["resourceLogs"].as_array_mut().into_iter().flatten())
    {
        patch_resource_logs(resource, json_resource);
    }
    let line = serde_json::to_string(&json).map_err(|e| e.to_string())?;
    // Safety net: a non-finite double the patching missed would serialize as
    // `null` and make the Collector drop the whole line. Refuse to write it.
    if line.contains(r#""doubleValue":null"#) {
        return Err("a non-finite doubleValue was not sanitized".to_owned());
    }
    Ok(line)
}

// Work on patched JSON: budgets include escaping and non-finite spellings.
// Small batches retain their original bytes, including the golden layout.
#[cfg(test)]
fn bounded_lines(line: &str, limit: usize) -> Result<Vec<String>, String> {
    bounded_lines_counted(line, limit, &mut 0)
}

fn bounded_lines_counted(
    line: &str,
    limit: usize,
    dropped: &mut usize,
) -> Result<Vec<String>, String> {
    if line.len() <= limit {
        return Ok(vec![line.to_owned()]);
    }
    let request: Json = serde_json::from_str(line).map_err(|e| e.to_string())?;
    let mut lines = Vec::new();
    for resource in request["resourceLogs"].as_array().into_iter().flatten() {
        let resource_prefix = format!(
            "{{\"resourceLogs\":[{}",
            array_prefix(resource, "scopeLogs")
        );
        let mut current = resource_prefix.clone();
        let mut has_scopes = false;
        for scope in resource["scopeLogs"].as_array().into_iter().flatten() {
            let scope_prefix = array_prefix(scope, "logRecords");
            // Closing the record array, scope, scope array, resource, resource
            // array and request takes exactly six ASCII bytes.
            let overhead = resource_prefix.len() + scope_prefix.len() + 6;
            let mut open = false;
            for record in scope["logRecords"].as_array().into_iter().flatten() {
                let (text, replaced) = fit_record(record, overhead, limit)?;
                *dropped = dropped.saturating_add(usize::from(replaced));
                let extra = if open {
                    1
                } else {
                    scope_prefix.len() + usize::from(has_scopes)
                };
                if current.len() + extra + text.len() + 6 > limit && has_scopes {
                    if open {
                        current.push_str("]}");
                    }
                    current.push_str("]}]}");
                    lines.push(current);
                    current = resource_prefix.clone();
                    has_scopes = false;
                    open = false;
                }
                if !open {
                    if has_scopes {
                        current.push(',');
                    }
                    current.push_str(&scope_prefix);
                    open = true;
                    has_scopes = true;
                } else {
                    current.push(',');
                }
                current.push_str(&text);
            }
            if open {
                current.push_str("]}");
            }
        }
        if has_scopes {
            current.push_str("]}]}");
            lines.push(current);
        }
    }
    Ok(lines)
}

// Copy only metadata, never the batch or a scope's records. Appending the
// array field also avoids serializing any growing output more than once.
fn array_prefix(value: &Json, field: &str) -> String {
    let metadata: serde_json::Map<String, Json> = value
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(key, _)| key.as_str() != field)
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let mut prefix = Json::Object(metadata).to_string();
    prefix.pop();
    if prefix.len() > 1 {
        prefix.push(',');
    }
    prefix.push_str(&format!("\"{field}\":["));
    prefix
}

fn markers(original_size: usize, dropped: bool) -> Vec<Json> {
    let mut attributes = vec![
        serde_json::json!({"key":"vigil.original_size","value":{"intValue":original_size.to_string()}}),
        serde_json::json!({"key":"vigil.truncated","value":{"boolValue":true}}),
    ];
    if dropped {
        attributes.push(serde_json::json!({"key":"vigil.dropped","value":{"boolValue":true}}));
    }
    attributes.sort_by_key(|a| a["key"].as_str().unwrap_or_default().to_owned());
    attributes
}

fn fit_record(record: &Json, overhead: usize, limit: usize) -> Result<(String, bool), String> {
    let original = record.to_string();
    let original_size = overhead + original.len();
    if original_size <= limit {
        return Ok((original, false));
    }
    let mut shortened = record.clone();
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
    attributes.extend(markers(original_size, false));
    attributes.sort_by_key(|a| a["key"].as_str().unwrap_or_default().to_owned());
    shortened["attributes"] = Json::Array(attributes);
    let mut size = overhead + shortened.to_string().len();
    let mut candidates = Vec::new();
    string_candidates(&shortened, &mut Vec::new(), &mut candidates);
    // Metadata and keys are immutable; only values contribute shrink capacity.
    candidates.sort_by_key(|c| std::cmp::Reverse(c.bytes));
    let capacity: usize = candidates.iter().map(|c| c.bytes).sum();
    if size.saturating_sub(capacity) <= limit {
        for candidate in candidates {
            if size <= limit {
                break;
            }
            if let Some(Json::String(text)) = shortened.pointer_mut(&candidate.pointer) {
                let before = string_bytes(text);
                cut_string(text, size - limit, candidate.base64);
                size -= before - string_bytes(text);
            }
        }
        if size <= limit {
            sort_json_attributes(&mut shortened);
            return Ok((shortened.to_string(), false));
        }
    }
    // A record with excessive structural/non-string data becomes one explicit
    // diagnostic, without discarding its healthy batch neighbors or identity.
    let mut stub = serde_json::Map::new();
    for key in [
        "timeUnixNano",
        "observedTimeUnixNano",
        "severityNumber",
        "severityText",
        "traceId",
        "spanId",
        "flags",
    ] {
        if let Some(value) = record.get(key) {
            stub.insert(key.to_owned(), value.clone());
        }
    }
    stub.insert("body".into(), serde_json::json!({"stringValue":format!("vigil: record dropped: {original_size} bytes exceeds max_line_bytes {limit}")}));
    stub.insert(
        "attributes".into(),
        Json::Array(markers(original_size, true)),
    );
    let mut stub = Json::Object(stub);
    let base_size = overhead + stub.to_string().len();
    if base_size > limit {
        return Err(format!(
            "log envelope and diagnostic identity exceed max_line_bytes={limit}"
        ));
    }
    // Preserve a small original message even when immutable record metadata
    // forces replacement. A large original body uses only the remaining budget.
    if let Some(body) = record["body"]["stringValue"]
        .as_str()
        .filter(|s| !s.is_empty())
    {
        let mut reason =
            serde_json::json!({"key":"vigil.dropped_reason","value":{"stringValue":""}});
        let extra = reason.to_string().len() + 1; // attribute plus comma
        if base_size + extra <= limit {
            let mut message = format!("unshrinkable record; original body: {body}");
            let available = limit - base_size - extra;
            let bytes = string_bytes(&message);
            if bytes > available {
                cut_string(&mut message, bytes - available, false);
            }
            reason["value"]["stringValue"] = Json::String(message);
            if let Some(attributes) = stub["attributes"].as_array_mut() {
                attributes.push(reason);
            }
            sort_json_attributes(&mut stub);
        }
    }
    let text = stub.to_string();
    Ok((text, true))
}

fn sort_json_attributes(value: &mut Json) {
    match value {
        Json::Object(values) => {
            for (key, value) in values {
                if matches!(key.as_str(), "attributes" | "values")
                    && let Json::Array(attributes) = value
                    && attributes.iter().all(|a| a.get("key").is_some())
                {
                    attributes.sort_by_key(|a| a["key"].as_str().unwrap_or_default().to_owned());
                }
                sort_json_attributes(value);
            }
        }
        Json::Array(values) => values.iter_mut().for_each(sort_json_attributes),
        _ => {}
    }
}

struct StringCandidate {
    pointer: String,
    bytes: usize,
    base64: bool,
}

fn string_candidates(value: &Json, path: &mut Vec<String>, result: &mut Vec<StringCandidate>) {
    match value {
        Json::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                path.push(index.to_string());
                string_candidates(value, path, result);
                path.pop();
            }
        }
        Json::Object(values) => {
            if matches!(
                value.get("key").and_then(Json::as_str),
                Some("vigil.truncated" | "vigil.dropped" | "vigil.original_size")
            ) {
                return;
            }
            for (key, value) in values {
                path.push(key.replace('~', "~0").replace('/', "~1"));
                if let Json::String(text) = value {
                    if matches!(key.as_str(), "stringValue" | "bytesValue") && !text.is_empty() {
                        result.push(StringCandidate {
                            pointer: format!("/{}", path.join("/")),
                            bytes: string_bytes(text),
                            base64: key == "bytesValue",
                        });
                    }
                } else {
                    string_candidates(value, path, result);
                }
                path.pop();
            }
        }
        _ => {}
    }
}

fn escaped_bytes(c: char) -> usize {
    match c {
        '\"' | '\\' | '\n' | '\r' | '\t' | '\u{08}' | '\u{0c}' => 2,
        c if c < '\u{20}' => 6,
        c => c.len_utf8(),
    }
}

fn string_bytes(text: &str) -> usize {
    text.chars().map(escaped_bytes).sum()
}

fn cut_string(text: &mut String, overflow: usize, base64: bool) {
    let mut removed = 0;
    let mut end = text.len();
    for (index, c) in text.char_indices().rev() {
        removed += escaped_bytes(c);
        end = index;
        if removed >= overflow {
            break;
        }
    }
    if base64 {
        end = end / 4 * 4;
    }
    text.truncate(end);
}

// ---- grouping and normalization -------------------------------------------

/// Group a batch by scope, deterministically, or `None` for an empty batch.
///
/// The SDK's `group_logs_by_resource_and_scope` is not used: it groups through
/// a `HashMap` keyed by `InstrumentationScope`, whose `PartialEq` and `Hash`
/// disagree for floats (`0.0 == -0.0` but their hashes differ; `NaN != NaN`), so
/// scopes with such attributes merge or split depending on the hash seed.
/// Here the key is the canonical text of the sanitized scope (attributes sorted
/// by key, floats printed so that `-0.0` and `NaN` stay distinct), in a
/// `BTreeMap`. Records keep the order the batch delivered them in within their
/// scope. The batch has one resource, so there is exactly one `ResourceLogs`.
fn group_batch(
    batch: &LogBatch<'_>,
    resource: &ResourceAttributesWithSchema,
) -> Option<ResourceLogs> {
    type Key = (String, String, String, String);
    let mut scopes: BTreeMap<Key, ScopeLogs> = BTreeMap::new();
    for (record, instrumentation) in batch.iter() {
        // The target overrides only the scope name.
        let name = record
            .target()
            .cloned()
            .unwrap_or_else(|| Cow::Owned(instrumentation.name().to_owned()));
        let exported = opentelemetry::InstrumentationScope::builder(name)
            .with_version(instrumentation.version().unwrap_or_default().to_owned())
            .with_schema_url(instrumentation.schema_url().unwrap_or_default().to_owned())
            .with_attributes(instrumentation.attributes().cloned())
            .build();
        let mut scope = InstrumentationScope::from((&exported, None));
        sort_attributes(&mut scope.attributes);
        let schema_url = exported.schema_url().unwrap_or_default().to_owned();
        // Debug, not JSON: JSON writes NaN and ±Inf all as `null`.
        let key = (
            scope.name.clone(),
            scope.version.clone(),
            schema_url.clone(),
            format!("{:?}", scope.attributes),
        );
        let mut record = LogRecord::from(record);
        normalize_record(&mut record);
        scopes
            .entry(key)
            .or_insert_with(|| ScopeLogs {
                scope: Some(scope),
                schema_url,
                log_records: Vec::new(),
            })
            .log_records
            .push(record);
    }
    if scopes.is_empty() {
        return None;
    }
    let mut attributes = resource.attributes.0.clone();
    sort_attributes(&mut attributes);
    Some(ResourceLogs {
        resource: Some(ProtoResource {
            attributes,
            dropped_attributes_count: 0,
            entity_refs: vec![],
        }),
        scope_logs: scopes.into_values().collect(),
        schema_url: resource.schema_url.clone().unwrap_or_default(),
    })
}

fn normalize_record(record: &mut LogRecord) {
    if record.time_unix_nano == 0 {
        record.time_unix_nano = record.observed_time_unix_nano;
    }
    sort_attributes(&mut record.attributes);
    if let Some(body) = &mut record.body {
        sort_any_value(body);
    }
}

/// Sort by key (stable, so duplicate keys keep their emission order) and
/// recurse into nested values.
fn sort_attributes(attributes: &mut [KeyValue]) {
    attributes.sort_by(|a, b| a.key.cmp(&b.key));
    for value in attributes.iter_mut().filter_map(|kv| kv.value.as_mut()) {
        sort_any_value(value);
    }
}

fn sort_any_value(value: &mut AnyValue) {
    match &mut value.value {
        Some(Value::ArrayValue(array)) => array.values.iter_mut().for_each(sort_any_value),
        Some(Value::KvlistValue(list)) => sort_attributes(&mut list.values),
        _ => {}
    }
}

// ---- non-finite doubles ----------------------------------------------------

/// Patch the serialized `json` of `resource_logs`, walking the typed tree and
/// the JSON in parallel, replacing the `null` that serde writes for a
/// non-finite `doubleValue` with its [`NON_FINITE`] spelling.
fn patch_resource_logs(resource_logs: &ResourceLogs, json: &mut Json) {
    if let Some(resource) = &resource_logs.resource {
        patch_key_values(&resource.attributes, &mut json["resource"]["attributes"]);
    }
    let scopes = json["scopeLogs"].as_array_mut().into_iter().flatten();
    for (scope_logs, json_scope) in resource_logs.scope_logs.iter().zip(scopes) {
        if let Some(scope) = &scope_logs.scope {
            patch_key_values(&scope.attributes, &mut json_scope["scope"]["attributes"]);
        }
        let records = json_scope["logRecords"]
            .as_array_mut()
            .into_iter()
            .flatten();
        for (record, json_record) in scope_logs.log_records.iter().zip(records) {
            patch_record(record, json_record);
        }
    }
}

fn patch_record(record: &LogRecord, json: &mut Json) {
    if let Some(body) = &record.body {
        patch_any_value(body, &mut json["body"]);
    }
    patch_key_values(&record.attributes, &mut json["attributes"]);
}

fn patch_key_values(key_values: &[KeyValue], json: &mut Json) {
    for (kv, json_kv) in key_values
        .iter()
        .zip(json.as_array_mut().into_iter().flatten())
    {
        if let Some(value) = &kv.value {
            patch_any_value(value, &mut json_kv["value"]);
        }
    }
}

fn patch_any_value(value: &AnyValue, json: &mut Json) {
    match &value.value {
        Some(Value::DoubleValue(d)) if !d.is_finite() => {
            let spelling = if d.is_nan() {
                NON_FINITE[0]
            } else if *d > 0.0 {
                NON_FINITE[1]
            } else {
                NON_FINITE[2]
            };
            json["doubleValue"] = Json::String(spelling.to_owned());
        }
        Some(Value::ArrayValue(array)) => {
            let items = json["arrayValue"]["values"].as_array_mut();
            for (value, json) in array.values.iter().zip(items.into_iter().flatten()) {
                patch_any_value(value, json);
            }
        }
        Some(Value::KvlistValue(list)) => {
            patch_key_values(&list.values, &mut json["kvlistValue"]["values"]);
        }
        _ => {}
    }
}

#[cfg(test)]
mod size_tests {
    use super::*;

    #[test]
    fn r2_many_scopes_pack_without_copying_batch() {
        let scopes: Vec<_> = (0..512).map(|i| {
            let records: Vec<_> = (0..20).map(|j| serde_json::json!({"body":{"stringValue":"x".repeat(128)},"attributes":[],"eventName":j.to_string()})).collect();
            serde_json::json!({"scope":{"name":format!("scope-{i:03}")},"logRecords":records})
        }).collect();
        let input =
            serde_json::json!({"resourceLogs":[{"resource":{},"scopeLogs":scopes}]}).to_string();
        let start = std::time::Instant::now();
        let lines = bounded_lines(&input, 1_000_000).unwrap();
        let elapsed = start.elapsed();
        assert!(
            lines.len() <= 3,
            "{} lines: scopes were not packed",
            lines.len()
        );
        assert!(elapsed < std::time::Duration::from_secs(3), "{elapsed:?}");
        assert!(lines.iter().all(|s| s.len() <= 1_000_000));
        let mut count = 0;
        for line in &lines {
            let value: Json = serde_json::from_str(line).unwrap();
            for scope in value["resourceLogs"][0]["scopeLogs"].as_array().unwrap() {
                assert!(
                    scope["scope"]["name"]
                        .as_str()
                        .unwrap()
                        .starts_with("scope-")
                );
                count += scope["logRecords"].as_array().unwrap().len();
            }
        }
        assert_eq!(count, 10_240);
        assert_eq!(lines, bounded_lines(&input, 1_000_000).unwrap());
    }

    fn fixture(records: Vec<Json>) -> String {
        serde_json::json!({"resourceLogs":[{"resource":{},"scopeLogs":[{"scope":{"name":"test"},"logRecords":records}]}]}).to_string()
    }

    fn output_records(lines: &[String]) -> Vec<Json> {
        lines
            .iter()
            .flat_map(|line| {
                let json: Json = serde_json::from_str(line).unwrap();
                json["resourceLogs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .flat_map(|r| {
                        r["scopeLogs"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .flat_map(|s| s["logRecords"].as_array().unwrap().clone())
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    #[test]
    fn review_unshrinkable_record_preserves_healthy_neighbors() {
        let attrs: Vec<_> = (0..60_000)
            .map(|n| serde_json::json!({"key":n.to_string(),"value":{"intValue":"1"}}))
            .collect();
        let bad = serde_json::json!({"attributes":attrs,"body":{"stringValue":"bad"},"timeUnixNano":"123","observedTimeUnixNano":"124","severityNumber":17,"severityText":"ERROR","traceId":"00112233445566778899aabbccddeeff","spanId":"0011223344556677","flags":1});
        let mut records =
            vec![serde_json::json!({"attributes":[],"body":{"stringValue":"healthy"}}); 511];
        records.insert(200, bad.clone());
        let input = fixture(records);
        let lines =
            bounded_lines(&input, 1_000_000).expect("one bad record must not fail the batch");
        assert!(lines.iter().all(|l| l.len() <= 1_000_000));
        let records = output_records(&lines);
        assert_eq!(records.len(), 512);
        assert_eq!(
            records
                .iter()
                .filter(|r| r["body"]["stringValue"] == "healthy")
                .count(),
            511
        );
        let stub = &records[200];
        for key in [
            "timeUnixNano",
            "observedTimeUnixNano",
            "severityNumber",
            "severityText",
            "traceId",
            "spanId",
            "flags",
        ] {
            assert_eq!(stub[key], bad[key]);
        }
        assert!(
            stub["body"]["stringValue"]
                .as_str()
                .unwrap()
                .starts_with("vigil: record dropped:")
        );
        for key in ["vigil.truncated", "vigil.dropped"] {
            assert!(
                stub["attributes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|a| a["key"] == key && a["value"]["boolValue"] == true)
            );
        }
        assert!(stub["attributes"].as_array().unwrap().iter().any(|a| {
            a["key"] == "vigil.original_size"
                && a["value"]["intValue"]
                    .as_str()
                    .unwrap()
                    .parse::<usize>()
                    .unwrap()
                    > 1_000_000
        }));
    }

    #[test]
    fn review_largest_string_preserves_message() {
        let input = fixture(vec![
            serde_json::json!({"body":{"stringValue":"the important message"},"attributes":[{"key":"payload","value":{"arrayValue":{"values":[{"kvlistValue":{"values":[{"key":"nested","value":{"stringValue":"x".repeat(2_000_000)}}]}}]}}} ]}),
        ]);
        let lines = bounded_lines(&input, 1_000_000).unwrap();
        assert_eq!(
            output_records(&lines)[0]["body"]["stringValue"],
            "the important message"
        );
    }

    #[test]
    fn review_truncation_uses_available_budget() {
        for text in ["x".repeat(7_800_000), "💣\n\"".repeat(1_000_000)] {
            let input = fixture(vec![
                serde_json::json!({"body":{"stringValue":text},"attributes":[]}),
            ]);
            let lines = bounded_lines(&input, 1_000_000).unwrap();
            assert_eq!(lines.len(), 1);
            assert!(
                (950_000..=1_000_000).contains(&lines[0].len()),
                "line size {}",
                lines[0].len()
            );
        }
    }

    #[test]
    fn review_base64_is_bounded() {
        let record =
            serde_json::json!({"body":{"bytesValue":"AQID".repeat(400_000)},"attributes":[]});
        let lines = bounded_lines(&fixture(vec![record]), 1_000_000).unwrap();
        assert_eq!(lines.len(), 1);
        assert!((950_000..=1_000_000).contains(&lines[0].len()));
        let records = output_records(&lines);
        let record = &records[0];
        assert!(
            !record["attributes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a["key"] == "vigil.dropped")
        );
        let bytes = record["body"]["bytesValue"].as_str().unwrap();
        assert_eq!(bytes.len() % 4, 0);
        assert!(
            bytes
                .as_bytes()
                .chunks_exact(4)
                .all(|chunk| chunk == b"AQID")
        );
    }

    fn assert_unique_keys(value: &Json) {
        match value {
            Json::Object(values) => {
                for (key, value) in values {
                    if matches!(key.as_str(), "attributes" | "values")
                        && let Json::Array(attributes) = value
                        && attributes.iter().all(|a| a.get("key").is_some())
                    {
                        let mut keys = std::collections::BTreeSet::new();
                        for attribute in attributes {
                            let key = attribute["key"].as_str().unwrap();
                            assert!(!key.is_empty(), "truncation must not create empty keys");
                            assert!(
                                keys.insert(key),
                                "truncation must not create duplicate keys"
                            );
                        }
                    }
                    assert_unique_keys(value);
                }
            }
            Json::Array(values) => values.iter().for_each(assert_unique_keys),
            _ => {}
        }
    }

    fn assert_structural_stub(record: Json, preserve_body: bool) {
        let healthy = serde_json::json!({"body":{"stringValue":"healthy"},"attributes":[]});
        let mut dropped = 0;
        let input = fixture(vec![healthy.clone(), record, healthy.clone()]);
        let lines = bounded_lines_counted(&input, 1_000_000, &mut dropped).unwrap();
        assert!(lines.iter().all(|l| l.len() <= 1_000_000));
        let records = output_records(&lines);
        assert_eq!(records.len(), 3);
        for record in &records {
            assert_unique_keys(record);
        }
        assert_eq!(records[0], healthy);
        assert_eq!(records[2], healthy);
        let stub = &records[1];
        assert!(
            stub["attributes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a["key"] == "vigil.dropped" && a["value"]["boolValue"] == true),
            "structural oversize must produce a stub"
        );
        assert_eq!(dropped, 1);
        if preserve_body {
            assert!(
                stub["body"]["stringValue"]
                    .as_str()
                    .unwrap()
                    .contains("bad")
                    || stub["attributes"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|a| a["key"] == "vigil.dropped_reason"
                            && a["value"]["stringValue"].as_str().unwrap().contains("bad")),
                "stub must preserve the small original message"
            );
        }
    }

    #[test]
    fn r3_oversized_key_becomes_stub_with_original_message() {
        assert_structural_stub(
            serde_json::json!({"body":{"stringValue":"bad"},"attributes":[{"key":"k".repeat(1_200_000),"value":{"intValue":"1"}}]}),
            true,
        );
    }

    #[test]
    fn r3_stub_reason_with_large_body_stays_bounded() {
        assert_structural_stub(
            serde_json::json!({"body":{"stringValue":format!("bad: {}", "💣\n\"".repeat(300_000))},"attributes":[{"key":"k".repeat(1_200_000),"value":{"intValue":"1"}}]}),
            true,
        );
    }

    #[test]
    fn r3_oversized_event_name_becomes_stub() {
        assert_structural_stub(
            serde_json::json!({"body":{"stringValue":"bad"},"attributes":[],"eventName":"e".repeat(1_200_000)}),
            true,
        );
    }

    #[test]
    fn r3_many_keys_become_stub_without_duplicate_keys() {
        let attributes: Vec<_> = (0..25_000).map(|index| serde_json::json!({"key":format!("key-{index:027}"),"value":{"intValue":"1"}})).collect();
        assert!(
            attributes
                .iter()
                .all(|a| a["key"].as_str().unwrap().len() == 31)
        );
        assert_structural_stub(
            serde_json::json!({"body":{"stringValue":"bad"},"attributes":attributes}),
            true,
        );
    }

    fn many_scopes() -> String {
        let scopes: Vec<_> = (0..512).map(|scope| {
            let records: Vec<_> = (0..(if scope < 272 {20} else {19})).map(|n| serde_json::json!({"body":{"stringValue":"x".repeat(256)},"attributes":[{"key":"index","value":{"intValue":n.to_string()}}]})).collect();
            serde_json::json!({"scope":{"name":format!("scope-{scope:03}")},"logRecords":records})
        }).collect();
        serde_json::json!({"resourceLogs":[{"resource":{},"scopeLogs":scopes}]}).to_string()
    }

    #[test]
    fn review_packs_scopes_without_copying_batch() {
        let input = many_scopes();
        let lines = bounded_lines(&input, 1_000_000).unwrap();
        assert!(lines.len() < 10, "must pack scopes: {} lines", lines.len());
        assert!(lines.iter().all(|l| l.len() <= 1_000_000));
        assert_eq!(output_records(&lines).len(), 10_000);
        assert_eq!(lines, bounded_lines(&input, 1_000_000).unwrap());
        let original: Json = serde_json::from_str(&input).unwrap();
        let mut grouped = BTreeMap::<String, Vec<Json>>::new();
        for line in &lines {
            let json: Json = serde_json::from_str(line).unwrap();
            for scope in json["resourceLogs"][0]["scopeLogs"].as_array().unwrap() {
                grouped
                    .entry(scope["scope"]["name"].as_str().unwrap().to_owned())
                    .or_default()
                    .extend(scope["logRecords"].as_array().unwrap().clone());
            }
        }
        for scope in original["resourceLogs"][0]["scopeLogs"].as_array().unwrap() {
            assert_eq!(
                &grouped[scope["scope"]["name"].as_str().unwrap()],
                scope["logRecords"].as_array().unwrap()
            );
        }
    }

    #[test]
    #[ignore = "run explicitly in release to measure 10k records across 512 scopes"]
    fn review_many_scopes_release_benchmark() {
        let input = many_scopes();
        let start = std::time::Instant::now();
        let lines = bounded_lines(&input, 1_000_000).unwrap();
        let elapsed = start.elapsed();
        eprintln!(
            "10k records / 512 scopes: {elapsed:?}, {} lines",
            lines.len()
        );
        assert!(elapsed < Duration::from_secs(1));
    }

    #[test]
    fn configured_limit_and_impossible_envelope() {
        let exporter =
            OtlpJsonLogExporter::new(crate::sink::MemorySink::new()).with_max_line_bytes(800);
        assert_eq!(exporter.max_line_bytes, 800);
        let record =
            serde_json::json!({"body":{"stringValue":"é\n\"".repeat(900)},"attributes":[]});
        let input = serde_json::json!({"resourceLogs":[{"resource":{},"scopeLogs":[{"scope":{"name":"test"},"logRecords":[record.clone(),record]}]}]}).to_string();
        let lines = bounded_lines(&input, exporter.max_line_bytes).unwrap();
        assert_eq!(lines, bounded_lines(&input, 800).unwrap());
        assert_eq!(lines.len(), 2);
        assert!(lines.iter().all(|line| line.len() <= 800));
        assert!(bounded_lines(&input, 1).is_err());
        assert_eq!(
            exporter.with_max_line_bytes(usize::MAX).max_line_bytes,
            1_048_575
        );
    }
}
