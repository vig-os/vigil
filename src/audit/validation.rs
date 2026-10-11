//! Single accepted domain for audit construction and decoding.
use super::{AuditError, AuditErrorKind};
use crate::audit::FindingKind;
use base64::{
    Engine, alphabet,
    engine::{GeneralPurpose, GeneralPurposeConfig},
};
use serde_json::{Map, Value as Json};
use std::collections::BTreeMap;

/// Maximum AnyValue container edges from a top-level attribute (root depth zero).
/// Sixteen leaves ample room below serde's 128 JSON levels even for kvlists.
pub(super) const MAX_CONTEXT_DEPTH: usize = 16;
/// Maximum encoded payload bytes, excluding the optional final framing LF.
pub(super) const MAX_PAYLOAD_BYTES: usize = 1_000_000;
/// Constructs the canonical invalid-field finding.
pub(super) fn corrupt() -> AuditError {
    finding(FindingKind::InvalidField)
}
/// Constructs a typed reader finding.
pub(super) fn finding(kind: FindingKind) -> AuditError {
    AuditError::decoding(AuditErrorKind::CorruptTrail, kind)
}
/// Checks the closed field set of a JSON message.
pub(super) fn message(v: &Json, allowed: &[&str]) -> Result<(), AuditError> {
    if object(v)?
        .keys()
        .any(|key| !allowed.contains(&key.as_str()))
    {
        return Err(finding(FindingKind::UnknownField));
    }
    Ok(())
}
/// Requires a named message field.
pub(super) fn required<'a>(v: &'a Json, key: &str) -> Result<&'a Json, AuditError> {
    v.get(key).ok_or_else(|| finding(FindingKind::MissingField))
}
/// Maps typed constructor errors to invalid-field findings.
pub(super) fn mapped<T>(result: Result<T, AuditError>) -> Result<T, AuditError> {
    result.map_err(|_| corrupt())
}

/// Requires a JSON object.
pub(super) fn object(v: &Json) -> Result<&Map<String, Json>, AuditError> {
    v.as_object().ok_or_else(corrupt)
}
/// Requires a JSON array.
pub(super) fn array(v: &Json) -> Result<&Vec<Json>, AuditError> {
    v.as_array().ok_or_else(corrupt)
}
/// Requires authenticated/key text under the shared text policy.
pub(super) fn text(v: &Json) -> Result<&str, AuditError> {
    let s = v.as_str().ok_or_else(corrupt)?;
    mapped(valid_text(s))?;
    Ok(s)
}
/// Requires canonical unsigned decimal-string spelling.
pub(super) fn integer(v: &Json) -> Result<u64, AuditError> {
    let s = v.as_str().ok_or_else(corrupt)?;
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return Err(corrupt());
    }
    s.parse().map_err(|_| corrupt())
}
/// Unique validated attribute keys mapped to their AnyValue JSON.
pub(super) type Attributes<'a> = BTreeMap<&'a str, &'a Json>;
/// Validates keys and values and indexes one attribute list.
pub(super) fn attributes(v: &Json) -> Result<Attributes<'_>, AuditError> {
    attributes_at(v, 0)
}
fn attributes_at(v: &Json, depth: usize) -> Result<Attributes<'_>, AuditError> {
    let mut result = BTreeMap::new();
    for a in array(v)? {
        message(a, &["key", "value"])?;
        let fields = object(a)?;
        let key = text(required(a, "key")?)?;
        let value = fields
            .get("value")
            .ok_or_else(|| finding(FindingKind::MissingField))?;
        any_value_at(value, depth)?;
        if result.insert(key, value).is_some() {
            return Err(corrupt());
        }
    }
    Ok(result)
}
/// Checks the optional schema URL type.
pub(super) fn schema_url(v: &Json) -> Result<(), AuditError> {
    if v.get("schemaUrl").is_some_and(|v| !v.is_string()) {
        return Err(corrupt());
    }
    Ok(())
}
/// Checks a resource or scope message and its attribute domain.
pub(super) fn context_message(v: &Json, resource: bool) -> Result<(), AuditError> {
    message(
        v,
        if resource {
            &["attributes", "droppedAttributesCount", "entityRefs"]
        } else {
            &["name", "version", "attributes", "droppedAttributesCount"]
        },
    )?;
    for key in ["name", "version"] {
        if v.get(key).is_some_and(|v| !v.is_string()) {
            return Err(corrupt());
        }
    }
    if let Some(count) = v.get("droppedAttributesCount")
        && count.as_u64().is_none_or(|n| n > u32::MAX.into())
    {
        return Err(corrupt());
    }
    if let Some(attrs) = v.get("attributes") {
        attributes(attrs)?;
    }
    if let Some(refs) = v.get("entityRefs") {
        for entity in array(refs)? {
            message(entity, &["schemaUrl", "type", "idKeys", "descriptionKeys"])?;
            schema_url(entity)?;
            if entity.get("type").is_some_and(|v| !v.is_string()) {
                return Err(corrupt());
            }
            for key in ["idKeys", "descriptionKeys"] {
                if let Some(keys) = entity.get(key)
                    && array(keys)?.iter().any(|v| !v.is_string())
                {
                    return Err(corrupt());
                }
            }
        }
    }
    Ok(())
}
fn any_value_at(v: &Json, depth: usize) -> Result<(), AuditError> {
    nesting(depth)?;
    message(
        v,
        &[
            "stringValue",
            "boolValue",
            "intValue",
            "doubleValue",
            "bytesValue",
            "arrayValue",
            "kvlistValue",
        ],
    )?;
    if object(v)?.len() != 1 {
        return Err(corrupt());
    }
    for (key, val) in object(v)? {
        match key.as_str() {
            "arrayValue" | "kvlistValue" => {
                message(val, &["values"])?;
                if let Some(values) = val.get("values") {
                    if key == "arrayValue" {
                        for value in array(values)? {
                            any_value_at(value, depth + 1)?;
                        }
                    } else {
                        attributes_at(values, depth + 1)?;
                    }
                }
            }
            "stringValue" if val.is_string() => {}
            "bytesValue"
                if val.as_str().is_some_and(|s| {
                    let engine = GeneralPurpose::new(
                        &alphabet::STANDARD,
                        GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
                    );
                    engine.decode(s).is_ok()
                }) => {}
            "boolValue" if val.is_boolean() => {}
            "intValue"
                if val
                    .as_str()
                    .is_some_and(|s| s.parse::<i64>().is_ok_and(|n| n.to_string() == s)) => {}
            "doubleValue" if canonical_double(&val.to_string()).is_ok() => {}
            _ => return Err(corrupt()),
        }
    }
    Ok(())
}
/// Accepts exactly the shared encoder's finite-double spelling or nonfinite strings.
pub(super) fn canonical_double(raw: &str) -> Result<Json, AuditError> {
    if ["\"NaN\"", "\"Infinity\"", "\"-Infinity\""].contains(&raw) {
        return serde_json::from_str(raw).map_err(|_| corrupt());
    }
    let number: f64 = raw.parse().map_err(|_| corrupt())?;
    if !number.is_finite() || serde_json::to_string(&number).map_err(|_| corrupt())? != raw {
        return Err(corrupt());
    }
    Ok(Json::from(number))
}
/// Validates optional, unhashed correlation identifiers in the writer's lowercase form.
pub(super) fn correlation_ids(log: &Json) -> Result<(), AuditError> {
    for (key, width) in [("traceId", 32), ("spanId", 16)] {
        if let Some(value) = log.get(key) {
            let text = value.as_str().ok_or_else(corrupt)?;
            if !text.is_empty()
                && (text.len() != width
                    || !text
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            {
                return Err(corrupt());
            }
        }
    }
    Ok(())
}
/// Requires nonempty NUL-free text without Unicode normalization.
pub(super) fn valid_text(text: &str) -> Result<(), AuditError> {
    if text.is_empty() || text.contains('\0') {
        return Err(AuditError::new(
            AuditErrorKind::InvalidEntry,
            "strings must be nonempty and contain no NUL",
        ));
    }
    Ok(())
}

/// Checks line size and framing identically at both boundaries.
pub(super) fn payload(bytes: &[u8]) -> Result<(), AuditError> {
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(AuditError::decoding(
            AuditErrorKind::TooLarge,
            FindingKind::InvalidField,
        ));
    }
    if bytes.iter().any(|b| *b < 0x20) {
        return Err(corrupt());
    }
    Ok(())
}
/// Validates all resource/scope context and attribute trees before emission or decoding.
pub(super) fn contexts(json: &Json) -> Result<(), AuditError> {
    for resource in array(required(json, "resourceLogs")?)? {
        context_message(required(resource, "resource")?, true)?;
        for scope in array(required(resource, "scopeLogs")?)? {
            if let Some(context) = scope.get("scope") {
                context_message(context, false)?;
            }
            for log in array(required(scope, "logRecords")?)? {
                correlation_ids(log)?;
                attributes(required(log, "attributes")?)?;
            }
        }
    }
    Ok(())
}

/// Checks the shared nesting budget before descending in either representation.
fn nesting(depth: usize) -> Result<(), AuditError> {
    if depth > MAX_CONTEXT_DEPTH {
        return Err(corrupt());
    }
    Ok(())
}
/// Preflights typed context with the same budget before cloning or JSON projection.
/// This bounded traversal cannot recurse into arbitrarily deep caller input.
pub(super) fn typed_context_depth(
    value: &opentelemetry_proto::tonic::common::v1::AnyValue,
) -> Result<(), AuditError> {
    fn visit(
        value: &opentelemetry_proto::tonic::common::v1::AnyValue,
        depth: usize,
    ) -> Result<(), AuditError> {
        use opentelemetry_proto::tonic::common::v1::any_value::Value;
        nesting(depth)?;
        match &value.value {
            Some(Value::ArrayValue(array)) => {
                for value in &array.values {
                    visit(value, depth + 1)?;
                }
            }
            Some(Value::KvlistValue(list)) => {
                for pair in &list.values {
                    if let Some(value) = &pair.value {
                        visit(value, depth + 1)?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
    visit(value, 0)
}
