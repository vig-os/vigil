//! An OpenTelemetry [`LogExporter`] that writes OTLP/JSON Lines.
//!
//! Each export batch becomes **one line**: one `LogsData` message in the
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

use std::time::Duration;

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value::Value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::transform::common::tonic::ResourceAttributesWithSchema;
use opentelemetry_proto::transform::logs::tonic::group_logs_by_resource_and_scope;
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
/// opentelemetry-collector-contrib 0.155.0, which round-trips them back
/// unchanged), so the exporter uses it and keeps the value a double. Note that
/// `opentelemetry-proto`'s own deserializer rejects these strings, so the
/// lines cannot be read back through its types; read them with `serde_json`
/// or the Collector.
pub const NON_FINITE: [&str; 3] = ["NaN", "Infinity", "-Infinity"];

/// Writes each log export batch as one OTLP/JSON `LogsData` line to a
/// [`LineSink`].
///
/// See the [module documentation](self) for the format guarantees and an
/// example. The exporter needs no async runtime: the SDK's batch processor
/// calls it from its own thread and the future it returns is already complete.
#[derive(Debug)]
pub struct OtlpJsonLogExporter<S: LineSink> {
    sink: S,
    resource: ResourceAttributesWithSchema,
}

impl<S: LineSink> OtlpJsonLogExporter<S> {
    /// An exporter writing to `sink`. The resource is set by the SDK through
    /// [`LogExporter::set_resource`] when the exporter is added to a provider.
    #[must_use]
    pub fn new(sink: S) -> Self {
        Self {
            sink,
            resource: ResourceAttributesWithSchema::default(),
        }
    }

    /// The sink lines are written to.
    #[must_use]
    pub fn sink(&self) -> &S {
        &self.sink
    }

    fn export_batch(&self, batch: &LogBatch<'_>) -> OTelSdkResult {
        let mut resource_logs = group_logs_by_resource_and_scope(batch, &self.resource);
        resource_logs.iter_mut().for_each(normalize_resource_logs);
        resource_logs.retain(|r| r.scope_logs.iter().any(|s| !s.log_records.is_empty()));
        if resource_logs.is_empty() {
            return Ok(());
        }
        resource_logs.sort_by_cached_key(sort_key_resource);

        let line = encode_line(&ExportLogsServiceRequest { resource_logs })
            .map_err(|e| OTelSdkError::InternalFailure(format!("encoding log batch: {e}")))?;
        self.sink
            .write_line(line.as_bytes())
            .map_err(|e| OTelSdkError::InternalFailure(format!("writing log batch: {e}")))
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

// ---- normalization (deterministic order, timestamps) ----------------------

fn normalize_resource_logs(resource_logs: &mut ResourceLogs) {
    if let Some(resource) = &mut resource_logs.resource {
        sort_attributes(&mut resource.attributes);
    }
    for scope_logs in &mut resource_logs.scope_logs {
        if let Some(scope) = &mut scope_logs.scope {
            sort_attributes(&mut scope.attributes);
        }
        scope_logs.log_records.iter_mut().for_each(normalize_record);
    }
    resource_logs.scope_logs.sort_by_cached_key(sort_key_scope);
    merge_equal_scopes(&mut resource_logs.scope_logs);
}

/// Merge scope groups that describe the same scope.
///
/// The SDK groups by scope through a `HashMap`, and a scope attribute holding
/// NaN is never equal to itself, so every record of such a scope lands in its
/// own group, in `HashMap` order. Merging them gives one scope with many
/// records; the records are then sorted (their emission order is already lost)
/// so the output bytes do not depend on that order.
fn merge_equal_scopes(scope_logs: &mut Vec<ScopeLogs>) {
    let mut merged: Vec<ScopeLogs> = Vec::with_capacity(scope_logs.len());
    let mut combined = false;
    for next in scope_logs.drain(..) {
        match merged.last_mut() {
            Some(last) if sort_key_scope(last) == sort_key_scope(&next) => {
                last.log_records.extend(next.log_records);
                combined = true;
            }
            _ => merged.push(next),
        }
    }
    if combined {
        for group in &mut merged {
            group.log_records.sort_by_cached_key(|r| {
                (
                    r.time_unix_nano,
                    r.observed_time_unix_nano,
                    format!("{r:?}"),
                )
            });
        }
    }
    *scope_logs = merged;
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

fn sort_key_resource(resource_logs: &ResourceLogs) -> String {
    let attributes = resource_logs
        .resource
        .as_ref()
        .map(|r| format!("{:?}", r.attributes))
        .unwrap_or_default();
    format!("{attributes}\u{0}{}", resource_logs.schema_url)
}

fn sort_key_scope(scope_logs: &ScopeLogs) -> (String, String, String, String) {
    let (name, version, attributes) =
        scope_logs
            .scope
            .as_ref()
            .map_or_else(Default::default, |s| {
                (
                    s.name.clone(),
                    s.version.clone(),
                    // Debug, not JSON: JSON writes NaN and ±Inf all as `null`.
                    format!("{:?}", s.attributes),
                )
            });
    (name, version, scope_logs.schema_url.clone(), attributes)
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
