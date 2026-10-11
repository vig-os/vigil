use super::*;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value as Json};
use std::{collections::BTreeMap, fmt};

fn corrupt() -> AuditError {
    AuditError::new(AuditErrorKind::CorruptTrail, "invalid audit v1 OTLP record")
}
fn mapped<T>(result: Result<T, AuditError>) -> Result<T, AuditError> {
    result.map_err(|_| corrupt())
}

// Preserve serde's error category at the seam for B2's torn-prefix recovery.
// Warning/strict policy belongs to #68, not the complete-record decoder.
fn decode_complete_json(bytes: &[u8]) -> Result<Json, serde_json::Error> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = Unique::deserialize(&mut decoder)?.0;
    decoder.end()?;
    Ok(value)
}
struct Unique(Json);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        decoder.deserialize_any(UniqueVisitor)
    }
}
struct UniqueVisitor;
impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Unique;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON without duplicate object keys")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Unique, E> {
        Ok(Unique(Json::Bool(v)))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Unique, E> {
        Ok(Unique(v.into()))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Unique, E> {
        Ok(Unique(v.into()))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Unique, E> {
        Number::from_f64(v)
            .map(|n| Unique(Json::Number(n)))
            .ok_or_else(|| E::custom("invalid number"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Unique, E> {
        Ok(Unique(v.into()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Unique, E> {
        Ok(Unique(v.into()))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Unique, E> {
        Ok(Unique(Json::Null))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Unique, A::Error> {
        let mut values = Vec::new();
        while let Some(Unique(value)) = seq.next_element()? {
            values.push(value);
        }
        Ok(Unique(Json::Array(values)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Unique, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate object key"));
            }
            let Unique(value) = map.next_value()?;
            values.insert(key, value);
        }
        Ok(Unique(Json::Object(values)))
    }
}
fn object(v: &Json) -> Result<&Map<String, Json>, AuditError> {
    v.as_object().ok_or_else(corrupt)
}
fn array(v: &Json) -> Result<&Vec<Json>, AuditError> {
    v.as_array().ok_or_else(corrupt)
}
fn text(v: &Json) -> Result<&str, AuditError> {
    let s = v.as_str().ok_or_else(corrupt)?;
    mapped(valid_text(s))?;
    Ok(s)
}
fn integer(v: &Json) -> Result<u64, AuditError> {
    let s = match v {
        Json::String(s) => s.to_owned(),
        Json::Number(n) if n.is_u64() => n.to_string(),
        _ => return Err(corrupt()),
    };
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return Err(corrupt());
    }
    s.parse().map_err(|_| corrupt())
}
fn scalar<'a>(v: &'a Json, key: &str) -> Result<&'a Json, AuditError> {
    let fields = object(v)?;
    if fields.len() != 1 {
        return Err(corrupt());
    }
    fields.get(key).ok_or_else(corrupt)
}
fn string(v: &Json) -> Result<&str, AuditError> {
    text(scalar(v, "stringValue")?)
}
fn hex_array<const N: usize>(s: &str) -> Result<[u8; N], AuditError> {
    if s.len() != N * 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(corrupt());
    }
    let mut bytes = [0; N];
    for (out, pair) in bytes.iter_mut().zip(s.as_bytes().chunks_exact(2)) {
        let digit = |b| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        *out = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(bytes)
}
fn digest(v: &Json) -> Result<[u8; 32], AuditError> {
    hex_array(string(v)?.strip_prefix("blake3:").ok_or_else(corrupt)?)
}
type Attributes<'a> = BTreeMap<&'a str, &'a Json>;
fn attributes(v: &Json) -> Result<Attributes<'_>, AuditError> {
    let mut result = BTreeMap::new();
    for a in array(v)? {
        let fields = object(a)?;
        if fields.len() != 2 {
            return Err(corrupt());
        }
        let key = text(&a["key"])?;
        let value = fields.get("value").ok_or_else(corrupt)?;
        if result.insert(key, value).is_some() {
            return Err(corrupt());
        }
    }
    Ok(result)
}
fn take<'a>(attrs: &mut Attributes<'a>, key: &str) -> Result<&'a Json, AuditError> {
    attrs.remove(key).ok_or_else(corrupt)
}
fn value(
    attrs: &mut Attributes<'_>,
    text_key: &str,
    digest_key: &str,
) -> Result<Option<Value>, AuditError> {
    match (attrs.remove(text_key), attrs.remove(digest_key)) {
        (Some(v), None) => Ok(Some(Value::Text(string(v)?.to_owned()))),
        (None, Some(v)) => Ok(Some(Value::Digest(digest(v)?))),
        (None, None) => Ok(None),
        _ => Err(corrupt()),
    }
}
fn parse_record(log: &Json, resource: &Attributes<'_>) -> Result<Record, AuditError> {
    for key in object(log)?.keys() {
        if ![
            "timeUnixNano",
            "observedTimeUnixNano",
            "eventName",
            "severityNumber",
            "severityText",
            "attributes",
            "traceId",
            "spanId",
            "flags",
            "droppedAttributesCount",
        ]
        .contains(&key.as_str())
        {
            return Err(corrupt());
        }
    }
    let time = integer(&log["timeUnixNano"])?;
    if integer(&log["observedTimeUnixNano"])? != time
        || log["severityNumber"].as_u64() != Some(9)
        || log["severityText"].as_str() != Some("INFO")
    {
        return Err(corrupt());
    }
    if let Some(v) = log.get("droppedAttributesCount")
        && v.as_u64() != Some(0)
    {
        return Err(corrupt());
    }
    // Correlation metadata is permitted, but is never authenticated record content.
    for (key, width) in [("traceId", 32), ("spanId", 16)] {
        if let Some(v) = log.get(key) {
            let s = v.as_str().ok_or_else(corrupt)?;
            if !s.is_empty() && (s.len() != width || !s.bytes().all(|b| b.is_ascii_hexdigit())) {
                return Err(corrupt());
            }
        }
    }
    if let Some(v) = log.get("flags")
        && v.as_u64().is_none_or(|n| n > u32::MAX.into())
    {
        return Err(corrupt());
    }
    let mut attrs = attributes(&log["attributes"])?;
    if integer(scalar(take(&mut attrs, "audit.v")?, "intValue")?)? != 1 {
        return Err(corrupt());
    }
    let trail = hex_array(string(take(&mut attrs, "audit.trail")?)?)?;
    let seq = integer(scalar(take(&mut attrs, "audit.seq")?, "intValue")?)?;
    let previous = digest(take(&mut attrs, "audit.prev_hash")?)?;
    let claimed = digest(take(&mut attrs, "audit.hash")?)?;
    let service = string(resource.get("service.name").ok_or_else(corrupt)?)?;
    let mut context = RecordContext::new(trail, seq, time, service, previous);
    if let Some(host) = resource.get("host.name") {
        context = context.host(string(host)?);
    }
    let record = match log["eventName"].as_str() {
        Some("audit.record") => {
            let mut entry = Entry::new(
                string(take(&mut attrs, "audit.actor")?)?,
                string(take(&mut attrs, "audit.action")?)?,
                string(take(&mut attrs, "audit.object")?)?,
            );
            if let Some(v) = attrs.remove("audit.reason") {
                entry = entry.reason(string(v)?);
            }
            if let Some(v) = attrs.remove("audit.details") {
                entry = entry.details(string(v)?);
            }
            if let Some(v) = value(&mut attrs, "audit.before", "audit.before_digest")? {
                entry = entry.before(v);
            }
            if let Some(v) = value(&mut attrs, "audit.after", "audit.after_digest")? {
                entry = entry.after(v);
            }
            mapped(Record::new(context, entry))?
        }
        Some("audit.checkpoint") => {
            let size = integer(scalar(take(&mut attrs, "audit.mmr_size")?, "intValue")?)?;
            let root = digest(take(&mut attrs, "audit.mmr_root")?)?;
            let key = hex_array(string(take(&mut attrs, "audit.key_id")?)?)?;
            let sig = hex_array(string(take(&mut attrs, "audit.sig")?)?)?;
            let peaks = match attrs.remove("audit.mmr_peaks") {
                Some(v) if size != 0 => array(scalar(scalar(v, "arrayValue")?, "values")?)?
                    .iter()
                    .map(digest)
                    .collect::<Result<Vec<_>, _>>()?,
                None if size == 0 => Vec::new(),
                _ => return Err(corrupt()),
            };
            mapped(Record::checkpoint(
                context,
                mapped(CheckpointFields::new(size, root, peaks, key, sig))?,
            ))?
        }
        _ => return Err(corrupt()),
    };
    if !attrs.is_empty() || record.hash() != claimed {
        return Err(corrupt());
    }
    Ok(record)
}
impl Record {
    /// Decodes one complete OTLP/JSON LogsData value, preserving nested record order.
    ///
    /// Rejects duplicate JSON keys after unescaping, unknown record attributes or
    /// fields, invalid v1 values, empty/whitespace input, and mismatching record
    /// hashes with CorruptTrail. Collector lines containing multiple resources,
    /// scopes and records are accepted. Resource/scope context other than service
    /// and host names, and correlation metadata, is unhashed.
    ///
    /// This checks individual structure and hashes, not chain links, MMR history,
    /// signatures or trust (#13). It does not classify incomplete input as a torn
    /// write: recovery needs file position and adjacent links (B2); strict warning
    /// policy remains deferred to #68. Receipt reconciliation across resume is
    /// separate and deferred to #70. Serde's default nesting limit applies.
    pub fn parse_line(bytes: &[u8]) -> Result<Vec<Self>, AuditError> {
        let json = decode_complete_json(bytes).map_err(|_| corrupt())?;
        let mut records = Vec::new();
        for resource in array(&json["resourceLogs"])? {
            let attrs = attributes(&resource["resource"]["attributes"])?;
            for scope in array(&resource["scopeLogs"])? {
                for log in array(&scope["logRecords"])? {
                    records.push(parse_record(log, &attrs)?);
                }
            }
        }
        if records.is_empty() {
            return Err(corrupt());
        }
        Ok(records)
    }
}

/// One structurally valid, hash-checked checkpoint and its original OTLP line.
///
/// Parsing does not establish signature validity, key trust, or consistency with
/// trail history. Keep anchors outside the trail directory; verification belongs
/// to #13. The sink's consuming close operation follows in B3.
#[derive(Clone, Debug)]
pub struct Checkpoint {
    seq: u64,
    hash: [u8; 32],
    fields: CheckpointFields,
    line: String,
}
impl Checkpoint {
    /// Parses exactly one checkpoint from a complete OTLP/JSON line.
    /// Ordinary actions or multiple records are CorruptTrail.
    /// No signature or trust verification is performed.
    pub fn parse(line: &str) -> Result<Self, AuditError> {
        let mut records = Record::parse_line(line.as_bytes())?;
        if records.len() != 1 {
            return Err(corrupt());
        }
        let record = records.remove(0);
        let hash = record.hash();
        let Kind::Checkpoint(fields) = record.kind else {
            return Err(corrupt());
        };
        Ok(Self {
            seq: record.context.seq,
            hash,
            fields,
            line: line.to_owned(),
        })
    }
    /// Returns the checkpoint's sequence number.
    pub fn seq(&self) -> u64 {
        self.seq
    }
    /// Returns its recomputed record hash, including the signature.
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }
    /// Returns the number of preceding leaves committed by this checkpoint.
    pub fn mmr_size(&self) -> u64 {
        self.fields.size
    }
    /// Returns its declared MMR root; history consistency is not checked.
    pub fn mmr_root(&self) -> [u8; 32] {
        self.fields.root
    }
    /// Returns the Ed25519 public key named by this checkpoint.
    pub fn key_id(&self) -> [u8; 32] {
        self.fields.key
    }
    /// Returns the original complete OTLP/JSON line, preserving its spelling.
    pub fn line(&self) -> &str {
        &self.line
    }
}
