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

use std::borrow::Cow;
use std::collections::BTreeMap;
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
        let Some(resource_logs) = group_batch(batch, &self.resource) else {
            return Ok(());
        };
        let line = encode_line(&ExportLogsServiceRequest {
            resource_logs: vec![resource_logs],
        })
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
