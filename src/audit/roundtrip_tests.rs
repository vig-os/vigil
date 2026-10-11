//! The B1 writer projection uses the production telemetry OTLP encoder; no sink I/O.
use super::*;
use opentelemetry_proto::tonic::{
    collector::logs::v1::ExportLogsServiceRequest,
    common::v1::{AnyValue, ArrayValue, InstrumentationScope, KeyValue, KeyValueList, any_value},
    logs::v1::{LogRecord, ResourceLogs, ScopeLogs},
    resource::v1::Resource,
};
use proptest::{
    prelude::*,
    strategy::ValueTree,
    test_runner::{Config, RngAlgorithm, TestRng, TestRunner},
};
use std::io::Write;

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
fn request(record: &Record, extra: AnyValue) -> ExportLogsServiceRequest {
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
    ExportLogsServiceRequest {
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
    }
}
fn unicode() -> BoxedStrategy<String> {
    prop::collection::vec(prop_oneof![3 => any::<char>().prop_filter("non-NUL", |c| *c != '\0'),
        2 => prop::sample::select(vec!['\u{7f}', '\u{1}', '\n', '\r', '\t', '\u{d7ff}', '\u{e000}', '\u{10000}', '\u{10ffff}'])], 1..40)
        .prop_map(|chars| chars.into_iter().collect()).boxed()
}
fn any_value() -> BoxedStrategy<AnyValue> {
    prop_oneof![
        unicode().prop_map(|s| text(&s)),
        any::<bool>().prop_map(|v| av(any_value::Value::BoolValue(v))),
        prop_oneof![any::<i64>(), Just(i64::MIN), Just(i64::MAX)]
            .prop_map(|v| av(any_value::Value::IntValue(v))),
        prop_oneof![
            any::<f64>(),
            Just(f64::NAN),
            Just(f64::INFINITY),
            Just(f64::NEG_INFINITY)
        ]
        .prop_map(|v| av(any_value::Value::DoubleValue(v))),
        prop::collection::vec(any::<u8>(), 0..64).prop_map(|v| av(any_value::Value::BytesValue(v)))
    ]
    .prop_recursive(3, 24, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4)
                .prop_map(|values| av(any_value::Value::ArrayValue(ArrayValue { values }))),
            prop::collection::vec(inner, 0..4).prop_map(|values| av(
                any_value::Value::KvlistValue(KeyValueList {
                    values: values
                        .into_iter()
                        .enumerate()
                        .map(|(i, v)| kv(&format!("key{i}"), v))
                        .collect()
                })
            ))
        ]
    })
    .boxed()
}
fn value() -> BoxedStrategy<Option<Value>> {
    prop::option::of(prop_oneof![
        unicode().prop_map(Value::Text),
        any::<[u8; 32]>().prop_map(Value::Digest)
    ])
    .boxed()
}
fn generated() -> impl Strategy<Value = (Record, AnyValue)> {
    (
        prop::collection::vec(unicode(), 6),
        (prop::option::of(unicode()), prop::option::of(unicode())),
        value(),
        value(),
        any::<[u8; 16]>(),
        prop_oneof![0u64..=i64::MAX as u64, Just(i64::MAX as u64)],
        prop_oneof![any::<u64>(), Just(u64::MAX)],
        (any::<[u8; 32]>(), any::<[u8; 32]>(), any::<[u8; 64]>()),
        any_value(),
        any::<bool>(),
        prop_oneof![15 => Just(0usize), 1 => 999_900usize..=1_000_000],
    )
        .prop_map(
            |(
                strings,
                (host, reason),
                before,
                after,
                trail,
                seq,
                time,
                (previous, key, signature),
                extra,
                checkpoint,
                target,
            )| {
                let mut context = RecordContext::new(trail, seq, time, &strings[0], previous);
                context.host = host;
                let kind = if checkpoint {
                    Kind::Checkpoint(
                        CheckpointFields::new(
                            seq,
                            previous,
                            vec![previous; seq.count_ones() as usize],
                            key,
                            signature,
                        )
                        .unwrap(),
                    )
                } else {
                    let mut entry =
                        Entry::new(&strings[1], &strings[2], &strings[3]).details(&strings[4]);
                    entry.reason = reason;
                    entry.before = before;
                    entry.after = after;
                    Kind::Entry(entry)
                };
                let mut record = Record::build(context, kind).unwrap();
                if target != 0 {
                    let line = crate::logs::encode_line(&request(&record, extra.clone())).unwrap();
                    assert!(line.len() < target);
                    record
                        .context
                        .service
                        .push_str(&"x".repeat(target - line.len()));
                }
                (record, extra)
            },
        )
}
fn roundtrip(record: &Record, extra: AnyValue) -> String {
    let line = crate::logs::encode_line(&request(record, extra)).unwrap();
    assert!(line.len() <= 1_000_000);
    let decoded = Record::parse_line(line.as_bytes()).unwrap();
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].canonical(), record.canonical());
    assert_eq!(decoded[0].hash(), record.hash());
    line
}
proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    #[test]
    fn writer_lines_always_verify((record, extra) in generated()) { roundtrip(&record, extra); }
}
fn corpus() -> Vec<String> {
    let mut runner = TestRunner::new_with_rng(
        Config::default(),
        TestRng::from_seed(RngAlgorithm::ChaCha, &[0x75; 32]),
    );
    let strategy = generated();
    (0..256)
        .map(|_| {
            let (record, extra) = strategy.new_tree(&mut runner).unwrap().current();
            roundtrip(&record, extra)
        })
        .collect()
}
#[test]
fn fixed_seed_corpus_matches_generator() {
    let bytes = corpus().join("\n") + "\n";
    assert_eq!(
        blake3::hash(bytes.as_bytes()).to_hex().as_str(),
        include_str!("../../tests/fixtures/audit/roundtrip.blake3").trim()
    );
}
#[test]
#[ignore = "explicit corpus regeneration; requires VIGIL_CORPUS_PATH"]
fn regenerate_writer_corpus() {
    let bytes = corpus().join("\n") + "\n";
    let path = std::env::var("VIGIL_CORPUS_PATH").unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap()
        .write_all(bytes.as_bytes())
        .unwrap();
    println!("corpus BLAKE3 {}", blake3::hash(bytes.as_bytes()).to_hex());
}
