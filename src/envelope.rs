//! **Unstable:** shared OTLP envelope bounding. Enable `--cfg vigil_unstable`
//! and pin vigil with `~1.N`. Metadata is repeated without copying item arrays.
use crate::logs::NON_FINITE;
use crate::ordered_json::{self, Rules};
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value::Value};
use serde_json::Value as Json;

/// Signal hooks for the shared resource/scope/item pipeline.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
#[cfg_attr(docsrs, doc(cfg(vigil_unstable)))]
pub enum Envelope {
    /// Log records, with shortening and diagnostic stubs.
    Logs,
    /// Metrics, split into data points and dropped if still oversized.
    #[cfg(feature = "metrics")]
    Metrics,
}
impl Envelope {
    fn fields(self) -> [&'static str; 3] {
        match self {
            Self::Logs => ["resourceLogs", "scopeLogs", "logRecords"],
            #[cfg(feature = "metrics")]
            Self::Metrics => ["resourceMetrics", "scopeMetrics", "metrics"],
        }
    }
    pub(crate) fn rules(self) -> Rules {
        match self {
            Self::Logs => ordered_json::LOGS,
            #[cfg(feature = "metrics")]
            Self::Metrics => ordered_json::METRICS,
        }
    }
    fn fit(self, item: &Json, overhead: usize, limit: usize) -> Result<Vec<BoundedLine>, String> {
        match self {
            Self::Logs => crate::logs::fit_record(item, overhead, limit).map(|(text, stub)| {
                vec![BoundedLine {
                    text,
                    records: 1,
                    stubs: usize::from(stub),
                }]
            }),
            #[cfg(feature = "metrics")]
            Self::Metrics => crate::metric_export::fit_metric(item, overhead, limit),
        }
    }
}
/// One bounded payload and the number of signal units it contains.
#[derive(Debug)]
#[cfg_attr(docsrs, doc(cfg(vigil_unstable)))]
pub struct BoundedLine {
    /// JSON payload, excluding the newline.
    pub(crate) text: String,
    /// Log records or metric data points present in the line.
    pub(crate) records: usize,
    /// Diagnostic log stubs included in the record count.
    pub(crate) stubs: usize,
}
impl BoundedLine {
    /// JSON payload, excluding the newline.
    pub fn text(&self) -> &str {
        &self.text
    }
    /// Log records or metric data points present in the payload.
    pub fn records(&self) -> usize {
        self.records
    }
    /// Diagnostic log stubs included in the record count.
    pub fn stubs(&self) -> usize {
        self.stubs
    }
}
/// Bound an already sanitized and deterministically ordered OTLP projection.
///
/// # Errors
/// Returns an encoding error or an error when a log diagnostic cannot fit.
#[cfg_attr(docsrs, doc(cfg(vigil_unstable)))]
pub fn bounded_lines(
    request: &Json,
    limit: usize,
    envelope: Envelope,
) -> Result<Vec<BoundedLine>, String> {
    let line = ordered_json::encode(request, "", envelope.rules())?;
    let [resources, scopes, items] = envelope.fields();
    let records = request[resources]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|r| r[scopes].as_array().into_iter().flatten())
        .flat_map(|s| s[items].as_array().into_iter().flatten())
        .map(|_item| match envelope {
            Envelope::Logs => 1,
            #[cfg(feature = "metrics")]
            Envelope::Metrics => crate::metric_export::point_count(_item),
        })
        .sum();
    let limit = limit.clamp(1, 1_048_575);
    if line.len() <= limit {
        return Ok(vec![BoundedLine {
            text: line.to_owned(),
            records,
            stubs: 0,
        }]);
    }
    let mut lines = Vec::new();
    for resource in request[resources].as_array().into_iter().flatten() {
        let (resource_start, resource_end) = array_frame(resource, scopes, envelope.rules())?;
        let resource_prefix = format!("{{\"{resources}\":[{resource_start}");
        let mut current = resource_prefix.clone();
        let mut has_scopes = false;
        let mut records = 0;
        let mut stubs = 0;
        for scope in resource[scopes].as_array().into_iter().flatten() {
            let (scope_prefix, scope_end) = array_frame(scope, items, envelope.rules())?;
            let closing = scope_end.len() + resource_end.len() + 2;
            let overhead = resource_prefix.len() + scope_prefix.len() + closing;
            let mut open = false;
            for record in scope[items].as_array().into_iter().flatten() {
                for fragment in envelope.fit(record, overhead, limit)? {
                    let BoundedLine {
                        text,
                        records: count,
                        stubs: replaced,
                    } = fragment;
                    let extra = if open {
                        1
                    } else {
                        scope_prefix.len() + usize::from(has_scopes)
                    };
                    if current.len() + extra + text.len() + closing > limit && has_scopes {
                        if open {
                            current.push_str(&scope_end);
                        }
                        current.push_str(&resource_end);
                        current.push_str("]}");
                        lines.push(BoundedLine {
                            text: current,
                            records,
                            stubs,
                        });
                        records = 0;
                        stubs = 0;
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
                    records += count;
                    stubs += replaced;
                }
            }
            if open {
                current.push_str(&scope_end);
            }
        }
        if has_scopes {
            current.push_str(&resource_end);
            current.push_str("]}");
            lines.push(BoundedLine {
                text: current,
                records,
                stubs,
            });
        }
    }
    Ok(lines)
}

pub(crate) fn array_frame(
    value: &Json,
    field: &str,
    rules: Rules,
) -> Result<(String, String), String> {
    let metadata: serde_json::Map<String, Json> = value
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(key, _)| key.as_str() != field)
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let metadata = crate::ordered_json::encode(&Json::Object(metadata), "", rules)?;
    let suffix = if metadata == "{}" {
        "]}".to_owned()
    } else {
        format!("],{}", &metadata[1..])
    };
    Ok((format!("{{\"{field}\":["), suffix))
}

/// Sort by key (stable, so duplicate keys keep their emission order) and
/// recurse into nested values.
pub(crate) fn sort_attributes(attributes: &mut [KeyValue]) {
    attributes.sort_by(|a, b| a.key.cmp(&b.key));
    for value in attributes.iter_mut().filter_map(|kv| kv.value.as_mut()) {
        sort_any_value(value);
    }
}

pub(crate) fn sort_any_value(value: &mut AnyValue) {
    match &mut value.value {
        Some(Value::ArrayValue(array)) => array.values.iter_mut().for_each(sort_any_value),
        Some(Value::KvlistValue(list)) => sort_attributes(&mut list.values),
        _ => {}
    }
}

pub(crate) fn patch_key_values(key_values: &[KeyValue], json: &mut Json) {
    for (kv, json_kv) in key_values
        .iter()
        .zip(json.as_array_mut().into_iter().flatten())
    {
        if let Some(value) = &kv.value {
            patch_any_value(value, &mut json_kv["value"]);
        }
    }
}

pub(crate) fn patch_any_value(value: &AnyValue, json: &mut Json) {
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

// ADR-0001 decision 5: compare decoded OTLP values, not JSON spellings.
fn text(value: &Json) -> &str {
    value.as_str().unwrap_or_default()
}

fn compare_attributes(a: &Json, b: &Json) -> std::cmp::Ordering {
    let a = a.as_array().map(Vec::as_slice).unwrap_or_default();
    let b = b.as_array().map(Vec::as_slice).unwrap_or_default();
    a.iter()
        .zip(b)
        .map(|(a, b)| {
            text(&a["key"])
                .cmp(text(&b["key"]))
                .then_with(|| compare_any_value(&a["value"], &b["value"]))
        })
        .find(|order| !order.is_eq())
        .unwrap_or_else(|| a.len().cmp(&b.len()))
}

fn compare_any_value(a: &Json, b: &Json) -> std::cmp::Ordering {
    const TYPES: [&str; 7] = [
        "boolValue",
        "intValue",
        "doubleValue",
        "stringValue",
        "bytesValue",
        "arrayValue",
        "kvlistValue",
    ];
    let rank = |v: &Json| TYPES.iter().position(|key| !v[*key].is_null());
    let ra = rank(a);
    let rb = rank(b);
    if ra != rb {
        return ra.cmp(&rb);
    }
    match ra {
        Some(0) => a["boolValue"].as_bool().cmp(&b["boolValue"].as_bool()),
        Some(1) => {
            let integer = |v: &Json| {
                v.as_i64()
                    .or_else(|| text(v).parse::<i64>().ok())
                    .unwrap_or_default()
            };
            integer(&a["intValue"]).cmp(&integer(&b["intValue"]))
        }
        Some(2) => {
            let double = |v: &Json| {
                v.as_f64().unwrap_or_else(|| match text(v) {
                    "NaN" => f64::NAN,
                    "Infinity" => f64::INFINITY,
                    "-Infinity" => f64::NEG_INFINITY,
                    _ => 0.0,
                })
            };
            double(&a["doubleValue"]).total_cmp(&double(&b["doubleValue"]))
        }
        Some(3 | 4) => {
            let key = TYPES[ra.unwrap_or_default()];
            text(&a[key]).cmp(text(&b[key]))
        }
        Some(5) => {
            let a = a["arrayValue"]["values"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_default();
            let b = b["arrayValue"]["values"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_default();
            a.iter()
                .zip(b)
                .map(|(a, b)| compare_any_value(a, b))
                .find(|order| !order.is_eq())
                .unwrap_or_else(|| a.len().cmp(&b.len()))
        }
        Some(6) => compare_attributes(&a["kvlistValue"]["values"], &b["kvlistValue"]["values"]),
        _ => std::cmp::Ordering::Equal,
    }
}

fn compare_element(a: &Json, b: &Json, context: &str) -> std::cmp::Ordering {
    let key = match context {
        "scopeLogs" | "scopeMetrics" => "scope",
        "resourceLogs" | "resourceMetrics" => "resource",
        _ => "",
    };
    if context == "metrics" {
        return text(&a["name"]).cmp(text(&b["name"]));
    }
    if context == "dataPoints" {
        return compare_attributes(&a["attributes"], &b["attributes"]);
    }
    ["name", "version"]
        .into_iter()
        .map(|field| text(&a[key][field]).cmp(text(&b[key][field])))
        .chain(std::iter::once_with(|| {
            text(&a["schemaUrl"]).cmp(text(&b["schemaUrl"]))
        }))
        .find(|order| !order.is_eq())
        .unwrap_or_else(|| compare_attributes(&a[key]["attributes"], &b[key]["attributes"]))
}

// Traverse envelope containers only: records, attributes and point values have
// already been normalized by the typed hooks. Encode payloads only to resolve ties.
pub(crate) fn normalize(value: &mut Json, context: &str, rules: Rules) -> Result<(), String> {
    match value {
        Json::Object(fields) => {
            for (key, value) in fields {
                if matches!(
                    key.as_str(),
                    "resourceLogs"
                        | "resourceMetrics"
                        | "scopeLogs"
                        | "scopeMetrics"
                        | "metrics"
                        | "gauge"
                        | "sum"
                        | "histogram"
                        | "exponentialHistogram"
                        | "summary"
                        | "dataPoints"
                ) {
                    normalize(value, key, rules)?;
                }
            }
        }
        Json::Array(values) => {
            if context != "dataPoints" {
                for value in values.iter_mut() {
                    normalize(value, context, rules)?;
                }
            }
            if values.len() < 2 {
                return Ok(());
            }
            if matches!(
                context,
                "resourceLogs"
                    | "resourceMetrics"
                    | "scopeLogs"
                    | "scopeMetrics"
                    | "metrics"
                    | "dataPoints"
            ) {
                values.sort_by(|a, b| compare_element(a, b, context));
                let mut start = 0;
                while start < values.len() {
                    let mut end = start + 1;
                    while end < values.len()
                        && compare_element(&values[start], &values[end], context).is_eq()
                    {
                        end += 1;
                    }
                    if end - start > 1 {
                        // Encode once, and only inside equal-primary-key groups.
                        let mut tied = values[start..end]
                            .iter_mut()
                            .map(|value| {
                                let bytes = ordered_json::encode(value, context, rules)?;
                                Ok((bytes, value.take()))
                            })
                            .collect::<Result<Vec<_>, String>>()?;
                        tied.sort_by(|(a, _), (b, _)| a.cmp(b));
                        for (slot, (_, value)) in values[start..end].iter_mut().zip(tied) {
                            *slot = value;
                        }
                    }
                    start = end;
                }
            }
        }
        _ => {}
    }
    Ok(())
}
