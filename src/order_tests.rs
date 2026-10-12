//! Shared fixtures for the ADR-0001 total-order regressions.
use opentelemetry_proto::tonic::common::v1::{
    AnyValue, ArrayValue, InstrumentationScope, KeyValue, KeyValueList, any_value::Value,
};

fn attribute(value: Value) -> KeyValue {
    KeyValue {
        key: "key".into(),
        value: Some(AnyValue { value: Some(value) }),
        ..Default::default()
    }
}

pub(crate) fn scope(value: Value) -> InstrumentationScope {
    InstrumentationScope {
        name: "same".into(),
        attributes: vec![attribute(value)],
        ..Default::default()
    }
}

// Each family has two equal-primary NaN scopes with distinct payloads, plus
// nearby keys. Exhaust all 24 permutations of each four-element family.
pub(crate) fn families() -> Vec<Vec<InstrumentationScope>> {
    let nan = scope(Value::DoubleValue(f64::NAN));
    let short = scope(Value::StringValue("a".into()));
    let mut long = short.clone();
    long.attributes.push(KeyValue {
        key: "z".into(),
        ..Default::default()
    });
    vec![
        vec![
            nan.clone(),
            nan.clone(),
            scope(Value::DoubleValue(f64::NEG_INFINITY)),
            scope(Value::DoubleValue(f64::INFINITY)),
        ],
        vec![
            nan.clone(),
            nan.clone(),
            scope(Value::DoubleValue(-0.0)),
            scope(Value::DoubleValue(0.0)),
        ],
        vec![
            nan.clone(),
            nan.clone(),
            scope(Value::StringValue("a\n".into())),
            scope(Value::StringValue("a!".into())),
        ],
        vec![nan.clone(), nan, short, long],
    ]
}

pub(crate) fn permutations<T: Clone>(values: &[T], mut check: impl FnMut(Vec<T>)) {
    fn visit<T: Clone>(values: &mut [T], at: usize, check: &mut impl FnMut(Vec<T>)) {
        if at == values.len() {
            check(values.to_vec());
            return;
        }
        for i in at..values.len() {
            values.swap(at, i);
            visit(values, at + 1, check);
            values.swap(at, i);
        }
    }
    visit(&mut values.to_vec(), 0, &mut check);
}

pub(crate) fn ordered_scopes() -> Vec<InstrumentationScope> {
    let mut scopes = vec![InstrumentationScope {
        name: "same".into(),
        ..Default::default()
    }];
    scopes.push(InstrumentationScope {
        name: "same".into(),
        attributes: vec![KeyValue {
            key: "key".into(),
            ..Default::default()
        }],
        ..Default::default()
    });
    let scalar = |value| AnyValue { value: Some(value) };
    scopes.extend(
        [
            Value::BoolValue(false),
            Value::BoolValue(true),
            Value::IntValue(-10),
            Value::IntValue(9),
            Value::IntValue(10),
            Value::DoubleValue(f64::NEG_INFINITY),
            Value::DoubleValue(-0.0),
            Value::DoubleValue(0.0),
            Value::DoubleValue(9.0),
            Value::DoubleValue(10.0),
            Value::DoubleValue(f64::INFINITY),
            Value::DoubleValue(f64::NAN),
            Value::StringValue("a\n".into()),
            Value::StringValue("a!".into()),
            Value::BytesValue(vec![0]),
            Value::BytesValue(vec![1]),
            Value::ArrayValue(ArrayValue { values: vec![] }),
            Value::ArrayValue(ArrayValue {
                values: vec![scalar(Value::IntValue(9))],
            }),
            Value::ArrayValue(ArrayValue {
                values: vec![scalar(Value::IntValue(9)), scalar(Value::IntValue(10))],
            }),
            Value::ArrayValue(ArrayValue {
                values: vec![scalar(Value::IntValue(10))],
            }),
            Value::KvlistValue(KeyValueList { values: vec![] }),
            Value::KvlistValue(KeyValueList {
                values: vec![attribute(Value::IntValue(9))],
            }),
        ]
        .into_iter()
        .map(scope),
    );
    for (i, scope) in scopes.iter_mut().enumerate() {
        scope.dropped_attributes_count = i as u32;
    }
    scopes
}

#[test]
fn structural_ties_compare_children_before_numeric_time() {
    use serde_json::json;
    for (container, children, a, b) in [
        (
            "scopeMetrics",
            "metrics",
            json!({"name":"a", "sum":{"dataPoints":[{"timeUnixNano":"900", "startTimeUnixNano":"800", "customTimeUnixNano":"950", "asInt":"10"}]}}),
            json!({"name":"b", "sum":{"dataPoints":[{"timeUnixNano":"100", "startTimeUnixNano":"50", "customTimeUnixNano":"150", "asInt":"9"}]}}),
        ),
        (
            "scopeMetrics",
            "metrics",
            json!({"name":"same", "description":"a", "unit":"z", "sum":{"dataPoints":[{"timeUnixNano":"900"}]}}),
            json!({"name":"same", "description":"b", "unit":"a", "sum":{"dataPoints":[{"timeUnixNano":"100"}]}}),
        ),
        (
            "scopeMetrics",
            "metrics",
            json!({"name":"same", "unit":"a", "sum":{"dataPoints":[{"timeUnixNano":"900"}]}}),
            json!({"name":"same", "unit":"b", "sum":{"dataPoints":[{"timeUnixNano":"100"}]}}),
        ),
        (
            "scopeMetrics",
            "metrics",
            json!({"name":"same", "sum":{"dataPoints":[{"timeUnixNano":"900", "asDouble":9.0}]}}),
            json!({"name":"same", "sum":{"dataPoints":[{"timeUnixNano":"100", "asDouble":10.0}]}}),
        ),
        (
            "scopeLogs",
            "logRecords",
            json!({"timeUnixNano":"900", "observedTimeUnixNano":"901", "body":{"stringValue":"a\n"}}),
            json!({"timeUnixNano":"100", "observedTimeUnixNano":"101", "body":{"stringValue":"a!"}}),
        ),
        (
            "scopeLogs",
            "logRecords",
            json!({"timeUnixNano":"2", "observedTimeUnixNano":"3", "body":{"stringValue":"same"}}),
            json!({"timeUnixNano":"10", "observedTimeUnixNano":"11", "body":{"stringValue":"same"}}),
        ),
        (
            "scopeMetrics",
            "metrics",
            json!({"name":"same", "sum":{"dataPoints":[{"timeUnixNano":"2", "asInt":"1"}]}}),
            json!({"name":"same", "sum":{"dataPoints":[{"timeUnixNano":"10", "asInt":"1"}]}}),
        ),
    ] {
        let element = |child| json!({"scope":{"name":"same","attributes":[{"key":"nan","value":{"doubleValue":"NaN"}}]}, (children):[child]});
        let expected = element(a);
        let scopes = [expected.clone(), element(b)];
        permutations(&scopes, |scopes| {
            let mut value = json!({(container):scopes});
            crate::envelope::normalize(&mut value, "", crate::ordered_json::LOGS).unwrap();
            assert_eq!(value[container][0], expected);
        });
    }
}

#[test]
fn structural_ties_compare_typed_values_recursively() {
    use serde_json::json;
    let ordered = [
        json!({"boolValue":false}),
        json!({"boolValue":true}),
        json!({"intValue":"9"}),
        json!({"intValue":"10"}),
        json!({"doubleValue":"-Infinity"}),
        json!({"doubleValue":-0.0}),
        json!({"doubleValue":0.0}),
        json!({"doubleValue":"Infinity"}),
        json!({"doubleValue":"NaN"}),
        json!({"stringValue":"a\n"}),
        json!({"stringValue":"a!"}),
        json!({"bytesValue":"AA=="}),
        json!({"arrayValue":{"values":[]}}),
        json!({"arrayValue":{"values":[{"intValue":"9"}]}}),
        json!({"arrayValue":{"values":[{"intValue":"9"},{"intValue":"10"}]}}),
        json!({"arrayValue":{"values":[{"intValue":"10"}]}}),
        json!({"kvlistValue":{"values":[]}}),
        json!({"kvlistValue":{"values":[{"key":"key","value":{"intValue":"9"}}]}}),
        json!({"kvlistValue":{"values":[{"key":"key","value":{"intValue":"9"}},{"key":"z","value":{"intValue":"10"}}]}}),
        json!({"kvlistValue":{"values":[{"key":"key","value":{"intValue":"10"}}]}}),
    ];
    for values in ordered.windows(2) {
        let first = json!({"scope":{},"logRecords":[{"timeUnixNano":"900", "body":values[0]}]});
        let second = json!({"scope":{},"logRecords":[{"timeUnixNano":"100", "body":values[1]}]});
        permutations(&[first.clone(), second], |scopes| {
            let mut value = json!({"scopeLogs":scopes});
            crate::envelope::normalize(&mut value, "", crate::ordered_json::LOGS).unwrap();
            assert_eq!(value["scopeLogs"][0], first);
        });
    }
}

#[test]
fn structural_ties_retain_record_sequence_and_point_attribute_order() {
    use serde_json::json;
    let a = json!({"timeUnixNano":"2","body":{"stringValue":"a"}});
    let b = json!({"timeUnixNano":"2","body":{"stringValue":"b"}});
    let first = json!({"scope":{},"logRecords":[a,b]});
    let second = json!({"scope":{},"logRecords":[b,a]});
    permutations(&[first.clone(), second], |scopes| {
        let mut value = json!({"scopeLogs":scopes});
        crate::envelope::normalize(&mut value, "", crate::ordered_json::LOGS).unwrap();
        assert_eq!(value["scopeLogs"][0], first);
        assert_eq!(value["scopeLogs"][1]["logRecords"], json!([b, a]));
    });
    let first = json!({"scope":{},"metrics":[{"name":"same","sum":{"dataPoints":[{"timeUnixNano":"900","asInt":"100"}]}}]});
    let second = json!({"scope":{},"metrics":[{"name":"same","sum":{"dataPoints":[{"timeUnixNano":"100","attributes":[{"key":"key","value":{"intValue":"1"}}],"asInt":"1"}]}}]});
    permutations(&[first.clone(), second], |scopes| {
        let mut value = json!({"scopeMetrics":scopes});
        crate::envelope::normalize(&mut value, "", crate::ordered_json::LOGS).unwrap();
        assert_eq!(value["scopeMetrics"][0], first);
    });
}
