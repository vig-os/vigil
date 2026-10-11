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
    })
    .map_err(|e| e.to_string())
}

struct Ordered<'a> {
    value: &'a Value,
    context: &'a str,
    rules: Rules,
}

impl Serialize for Ordered<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.value {
            Value::Object(fields) => {
                let first = self
                    .rules
                    .iter()
                    .find(|(name, _)| *name == self.context)
                    .map_or(&[][..], |(_, keys)| *keys);
                let mut fields: Vec<_> = fields.iter().collect();
                fields.sort_unstable_by_key(|(key, _)| {
                    (
                        first.iter().position(|k| k == key).unwrap_or(first.len()),
                        key.as_str(),
                    )
                });
                let mut map = serializer.serialize_map(Some(fields.len()))?;
                for (key, value) in fields {
                    map.serialize_entry(
                        key,
                        &Ordered {
                            value,
                            context: key,
                            rules: self.rules,
                        },
                    )?;
                }
                map.end()
            }
            Value::Array(values) => {
                let mut seq = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    seq.serialize_element(&Ordered {
                        value,
                        context: self.context,
                        rules: self.rules,
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
