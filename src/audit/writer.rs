//! Production audit projection; no sink I/O.
use super::*;
use opentelemetry_proto::tonic::{
    collector::logs::v1::ExportLogsServiceRequest,
    common::v1::{AnyValue, ArrayValue, InstrumentationScope, KeyValue, any_value},
    logs::v1::{LogRecord, ResourceLogs, ScopeLogs},
    resource::v1::Resource,
};
fn av(value: any_value::Value) -> AnyValue {
    AnyValue { value: Some(value) }
}
fn kv(key: &str, value: AnyValue) -> KeyValue {
    KeyValue {
        key: key.into(),
        value: Some(value),
        ..Default::default()
    }
}
fn text(value: &str) -> AnyValue {
    av(any_value::Value::StringValue(value.into()))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn digest(bytes: &[u8]) -> AnyValue {
    text(&format!("blake3:{}", hex(bytes)))
}
/// Maps one validated record to its audit OTLP request; B2/B3 MUST use this boundary.
///
/// # Errors
///
/// Rejects invalid context with InvalidConfig and oversized payloads with TooLarge
/// before any write. Uses the same domain validator as parse_line. Context is unhashed.
/// The shared JSON projection is validated before serialization, so excessive nesting
/// is refused before reaching a JSON parser's recursion limit. No truncation occurs.
pub(crate) fn request(
    record: &Record,
    extra: AnyValue,
) -> Result<ExportLogsServiceRequest, AuditError> {
    let refuse = |error: AuditError| {
        if error.kind() == AuditErrorKind::TooLarge {
            error
        } else {
            AuditError::new(
                AuditErrorKind::InvalidConfig,
                "audit context violates the canonical domain",
            )
        }
    };
    validation::typed_context_depth(&extra).map_err(refuse)?;
    let c = &record.context;
    let mut attributes = vec![
        kv("audit.v", av(any_value::Value::IntValue(1))),
        kv("audit.trail", text(&hex(&c.trail))),
        kv("audit.seq", av(any_value::Value::IntValue(c.seq as i64))),
        kv("audit.prev_hash", digest(&c.previous)),
        kv("audit.hash", digest(&record.hash())),
    ];
    let event_name = match &record.kind {
        Kind::Entry(entry) => {
            for (key, value) in [
                ("audit.actor", Some(&entry.actor)),
                ("audit.action", Some(&entry.action)),
                ("audit.object", Some(&entry.object)),
                ("audit.reason", entry.reason.as_ref()),
                ("audit.details", entry.details.as_ref()),
            ] {
                if let Some(value) = value {
                    attributes.push(kv(key, text(value)));
                }
            }
            for (key, value) in [
                ("audit.before", &entry.before),
                ("audit.after", &entry.after),
            ] {
                match value {
                    Some(Value::Text(value)) => attributes.push(kv(key, text(value))),
                    Some(Value::Digest(value)) => {
                        attributes.push(kv(&format!("{key}_digest"), digest(value)))
                    }
                    None => {}
                }
            }
            "audit.record"
        }
        Kind::Checkpoint(cp) => {
            attributes.extend([
                kv(
                    "audit.mmr_size",
                    av(any_value::Value::IntValue(cp.size as i64)),
                ),
                kv("audit.mmr_root", digest(&cp.root)),
                kv("audit.key_id", text(&hex(&cp.key))),
                kv("audit.sig", text(&hex(&cp.signature))),
            ]);
            if !cp.peaks.is_empty() {
                attributes.push(kv(
                    "audit.mmr_peaks",
                    av(any_value::Value::ArrayValue(ArrayValue {
                        values: cp.peaks.iter().map(|p| digest(p)).collect(),
                    })),
                ));
            }
            "audit.checkpoint"
        }
    };
    let mut resource_attributes = vec![
        kv("service.name", text(&c.service)),
        kv("context", extra.clone()),
    ];
    if let Some(host) = &c.host {
        resource_attributes.push(kv("host.name", text(host)));
    }
    let request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: resource_attributes,
                ..Default::default()
            }),
            scope_logs: vec![ScopeLogs {
                scope: Some(InstrumentationScope {
                    name: "vigil.audit".into(),
                    attributes: vec![kv("context", extra)],
                    ..Default::default()
                }),
                log_records: vec![LogRecord {
                    time_unix_nano: c.time,
                    observed_time_unix_nano: c.time,
                    severity_number: 9,
                    severity_text: "INFO".into(),
                    event_name: event_name.into(),
                    attributes,
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    let json = crate::logs::encode_json(&request)
        .map_err(|_| AuditError::new(AuditErrorKind::InvalidConfig, "OTLP projection failed"))?;
    validation::contexts(&json).map_err(refuse)?;
    let line = crate::logs::encode_line(&request)
        .map_err(|_| AuditError::new(AuditErrorKind::InvalidConfig, "OTLP encoding failed"))?;
    validation::payload(line.as_bytes()).map_err(refuse)?;
    Ok(request)
}
