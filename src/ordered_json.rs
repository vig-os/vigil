//! Feature-independent JSON emission. Signals declare priority keys by the
//! field containing an object (arrays retain that context); other keys sort
//! lexically. JSON maps are mutation storage only, never the output serializer.

use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};
use serde_json::Value;

pub(crate) type Rules = &'static [(&'static str, &'static [&'static str])];

pub(crate) const LOGS: Rules = &[
    ("resourceLogs", &["scopeLogs"]),
    ("scopeLogs", &["logRecords"]),
    ("logRecords", &["observedTimeUnixNano", "timeUnixNano"]),
];

pub(crate) fn encode(value: &Value, context: &str, rules: Rules) -> Result<String, String> {
    serde_json::to_string(&Ordered {
        value,
        context,
        rules,
        priority: None,
    })
    .map_err(|e| e.to_string())
}

struct Ordered<'a> {
    value: &'a Value,
    context: &'a str,
    rules: Rules,
    priority: Option<&'static [&'static str]>,
}

impl Ordered<'_> {
    fn priority(&self) -> &'static [&'static str] {
        self.priority.unwrap_or_else(|| {
            self.rules
                .iter()
                .find(|(name, _)| *name == self.context)
                .map_or(&[][..], |(_, keys)| *keys)
        })
    }
}

impl Serialize for Ordered<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.value {
            Value::Object(fields) => {
                let mut map = serializer.serialize_map(Some(fields.len()))?;
                let entry = |map: &mut S::SerializeMap, key: &String, value: &Value| {
                    map.serialize_entry(
                        key,
                        &Ordered {
                            value,
                            context: key,
                            rules: self.rules,
                            priority: None,
                        },
                    )
                };
                // AnyValue wrappers usually have one field: no ordering work.
                if fields.len() <= 1 {
                    for (key, value) in fields {
                        entry(&mut map, key, value)?;
                    }
                    return map.end();
                }
                let first = self.priority();
                // KeyValue and other two-field objects need one comparison.
                if first.is_empty() && fields.len() == 2 {
                    let mut fields = fields.iter();
                    if let (Some(a), Some(b)) = (fields.next(), fields.next()) {
                        let (a, b) = if a.0 <= b.0 { (a, b) } else { (b, a) };
                        entry(&mut map, a.0, a.1)?;
                        entry(&mut map, b.0, b.1)?;
                        return map.end();
                    }
                }
                // Priority lookup avoids collecting/sorting the envelope and
                // record fields. The remaining keys only need lexical order.
                for key in first {
                    if let Some((key, value)) = fields.get_key_value(*key) {
                        entry(&mut map, key, value)?;
                    }
                }
                let remaining = || {
                    fields
                        .iter()
                        .filter(|(key, _)| !first.contains(&key.as_str()))
                };
                if fields.keys().is_sorted() {
                    for (key, value) in remaining() {
                        entry(&mut map, key, value)?;
                    }
                } else {
                    let mut remaining: Vec<_> = remaining().collect();
                    remaining.sort_unstable_by_key(|(key, _)| key.as_str());
                    for (key, value) in remaining {
                        entry(&mut map, key, value)?;
                    }
                }
                map.end()
            }
            Value::Array(values) => {
                let mut seq = serializer.serialize_seq(Some(values.len()))?;
                // Every array element shares its containing field's rules.
                let priority = self.priority();
                for value in values {
                    seq.serialize_element(&Ordered {
                        value,
                        context: self.context,
                        rules: self.rules,
                        priority: Some(priority),
                    })?;
                }
                seq.end()
            }
            scalar => scalar.serialize(serializer),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_and_alphabetical_order_ignore_insertion_order() {
        let a: Value =
            serde_json::from_str(r#"{"z":0,"items":[{"b":2,"a":1,"t":"now"}],"a":3}"#).unwrap();
        let b: Value =
            serde_json::from_str(r#"{"a":3,"items":[{"t":"now","a":1,"b":2}],"z":0}"#).unwrap();
        let rules: Rules = &[("items", &["t"])];
        let expected = r#"{"a":3,"items":[{"t":"now","a":1,"b":2}],"z":0}"#;
        assert_eq!(encode(&a, "", rules).unwrap(), expected);
        assert_eq!(encode(&b, "", rules).unwrap(), expected);
    }
}
