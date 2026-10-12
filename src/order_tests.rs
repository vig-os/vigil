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
