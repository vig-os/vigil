//! The B1 writer projection uses the production telemetry OTLP encoder; no sink I/O.
use super::*;
use opentelemetry_proto::tonic::common::v1::{
    AnyValue, ArrayValue, KeyValue, KeyValueList, any_value,
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
fn unicode() -> BoxedStrategy<String> {
    prop::collection::vec(prop_oneof![3 => any::<char>().prop_filter("non-NUL", |c| *c != '\0'),
        2 => prop::sample::select(vec!['\u{2028}', '\u{2029}', '\u{7f}', '\u{1}', '\n', '\r', '\t', '\u{d7ff}', '\u{e000}', '\u{10000}', '\u{10ffff}'])], 1..40)
        .prop_map(|chars| chars.into_iter().collect()).boxed()
}
// Context values permit NUL; keys share this generator and may be refused by
// the validator's nonempty, NUL-free key rule. Authenticated text uses unicode().
fn context_unicode() -> BoxedStrategy<String> {
    prop_oneof![
        unicode(),
        Just("\0".into()),
        Just("before\0after".into()),
        Just(String::new())
    ]
    .boxed()
}
fn any_value() -> BoxedStrategy<AnyValue> {
    prop_oneof![
        context_unicode().prop_map(|s| text(&s)),
        Just(AnyValue { value: None }),
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
            prop::collection::vec(
                (
                    prop_oneof![context_unicode(), Just("duplicate".into())],
                    prop::option::of(inner)
                ),
                0..4
            )
            .prop_map(|pairs| av(any_value::Value::KvlistValue(KeyValueList {
                values: pairs
                    .into_iter()
                    .map(|(key, value)| KeyValue {
                        key,
                        value,
                        ..Default::default()
                    })
                    .collect()
            })))
        ]
    })
    .prop_flat_map(|leaf| {
        (
            Just(leaf),
            0usize..=validation::MAX_CONTEXT_DEPTH + 4,
            any::<bool>(),
        )
    })
    .prop_map(|(leaf, depth, kvlist)| nested(leaf, depth, kvlist))
    .boxed()
}
fn nested(mut leaf: AnyValue, depth: usize, kvlist: bool) -> AnyValue {
    for _ in 0..depth {
        leaf = if kvlist {
            av(any_value::Value::KvlistValue(KeyValueList {
                values: vec![kv("nested", leaf)],
            }))
        } else {
            av(any_value::Value::ArrayValue(ArrayValue {
                values: vec![leaf],
            }))
        };
    }
    leaf
}
fn value() -> BoxedStrategy<Option<Value>> {
    prop::option::of(prop_oneof![
        unicode().prop_map(Value::Text),
        any::<[u8; 32]>().prop_map(Value::Digest)
    ])
    .boxed()
}
pub(crate) fn generated() -> impl Strategy<Value = (Record, AnyValue)> {
    (
        prop::collection::vec(unicode(), 6),
        (
            prop::option::of(unicode()),
            prop::option::of(unicode()),
            prop::option::of(unicode()),
            prop::option::of(any::<[u8; 32]>()),
            prop_oneof![3 => Just(false), 1 => Just(true)],
        ),
        value(),
        value(),
        any::<[u8; 16]>(),
        prop_oneof![0u64..=i64::MAX as u64, Just(i64::MAX as u64)],
        prop_oneof![any::<u64>(), Just(u64::MAX)],
        (any::<[u8; 32]>(), any::<[u8; 32]>(), any::<[u8; 64]>()),
        any_value(),
        any::<bool>(),
        prop_oneof![15 => Just(0usize), 1 => 999_900usize..=1_000_100],
    )
        .prop_map(
            |(
                strings,
                (host, reason, details, repaired, resume),
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
                context.repaired = repaired;
                let size = if resume && seq > 1 {
                    (seq / 2).max(1)
                } else {
                    seq
                };
                let kind = if checkpoint {
                    Kind::Checkpoint(
                        CheckpointFields::new(
                            size,
                            previous,
                            vec![previous; size.count_ones() as usize],
                            key,
                            signature,
                        )
                        .unwrap(),
                    )
                } else {
                    let mut entry = Entry::new(&strings[1], &strings[2], &strings[3]);
                    entry.details = details;
                    entry.reason = reason;
                    entry.before = before;
                    entry.after = after;
                    Kind::Entry(entry)
                };
                let mut record = Record::build(context, kind).unwrap();
                if target != 0
                    && let Ok(request) = request(&record, extra.clone())
                {
                    let line = crate::logs::encode_line(&request).unwrap();
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
fn roundtrip(record: &Record, extra: AnyValue) -> Option<String> {
    let request = match request(record, extra) {
        Ok(request) => request,
        Err(error) => {
            assert!(matches!(
                error.kind(),
                AuditErrorKind::InvalidConfig | AuditErrorKind::TooLarge
            ));
            return None;
        }
    };
    let line = crate::logs::encode_line(&request).unwrap();
    assert!(line.len() <= 1_000_000);
    let decoded = Record::parse_line(line.as_bytes()).unwrap();
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].canonical(), record.canonical());
    assert_eq!(decoded[0].hash(), record.hash());
    Some(line)
}
proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    #[test]
    fn finite_context_doubles_are_accepted(number in any::<f64>().prop_filter("finite", |n| n.is_finite())) {
        for depth in [0, 1, 3] {
            for kvlist in [false, true] {
                prop_assert!(roundtrip(&record(), nested(av(any_value::Value::DoubleValue(number)), depth, kvlist)).is_some());
            }
        }
    }
    #[test]
    fn writer_lines_always_verify((record, extra) in generated()) { let _ = roundtrip(&record, extra); }
}
fn corpus() -> Vec<String> {
    let mut runner = TestRunner::new_with_rng(
        Config::default(),
        TestRng::from_seed(RngAlgorithm::ChaCha, &[0x75; 32]),
    );
    let strategy = generated();
    let mut lines = Vec::new();
    let mut refused = 0;
    while lines.len() < 256 {
        let (record, extra) = strategy.new_tree(&mut runner).unwrap().current();
        if let Some(line) = roundtrip(&record, extra) {
            lines.push(line);
        } else {
            refused += 1;
        }
        assert!(refused < 10_000, "generator must reach the accepted domain");
    }
    assert!(refused > 0, "fixed seed must exercise typed refusals");
    lines
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

fn record() -> Record {
    Record::new(
        RecordContext::new([0; 16], 0, 0, "service", [0; 32]),
        Entry::new("actor", "action", "object"),
    )
    .unwrap()
}
#[test]
fn context_domain_regression() {
    let record = record();
    let invalid = [
        vec![kv("", text("value"))],
        vec![kv("duplicate", text("a")), kv("duplicate", text("b"))],
        vec![KeyValue {
            key: "missing".into(),
            value: None,
            ..Default::default()
        }],
        vec![kv("none", AnyValue { value: None })],
    ];
    for values in invalid {
        let extra = av(any_value::Value::KvlistValue(KeyValueList { values }));
        assert_eq!(
            request(&record, extra).unwrap_err().kind(),
            AuditErrorKind::InvalidConfig
        );
    }
    for kvlist in [false, true] {
        assert!(
            roundtrip(
                &record,
                nested(text(""), validation::MAX_CONTEXT_DEPTH, kvlist)
            )
            .is_some()
        );
        assert_eq!(
            request(
                &record,
                nested(text(""), validation::MAX_CONTEXT_DEPTH + 1, kvlist)
            )
            .unwrap_err()
            .kind(),
            AuditErrorKind::InvalidConfig
        );
    }
    assert_eq!(
        request(&record, nested(text(""), 64, true))
            .unwrap_err()
            .kind(),
        AuditErrorKind::InvalidConfig
    );
    assert!(roundtrip(&record, text("\u{2028}\u{2029}")).is_some());
    let unicode_record = Record::new(
        RecordContext::new([0; 16], 0, 0, "\u{2028}\u{2029}", [0; 32]),
        Entry::new("\u{2028}", "\u{2029}", "object"),
    )
    .unwrap();
    assert!(roundtrip(&unicode_record, text("")).is_some());
}
#[test]
fn reader_uses_shared_context_domain() {
    let invalid = [
        serde_json::json!([{"key":"", "value":{"stringValue":"a"}}]),
        serde_json::json!([{"key":"duplicate", "value":{"stringValue":"a"}}, {"key":"duplicate", "value":{"stringValue":"b"}}]),
        serde_json::json!([{"key":"missing"}]),
        serde_json::json!([{"key":"null", "value":null}]),
        serde_json::json!([{"key":"empty", "value":{}}]),
    ];
    for attributes in invalid {
        for resource in [false, true] {
            let mut json =
                crate::logs::encode_json(&request(&record(), text("valid")).unwrap()).unwrap();
            if resource {
                json["resourceLogs"][0]["resource"]["attributes"] = attributes.clone();
            } else {
                json["resourceLogs"][0]["scopeLogs"][0]["scope"]["attributes"] = attributes.clone();
            }
            let error = Record::parse_line(&serde_json::to_vec(&json).unwrap()).unwrap_err();
            assert_eq!(error.kind(), AuditErrorKind::CorruptTrail);
            assert!(matches!(
                error.finding_kind(),
                Some(
                    crate::audit::FindingKind::InvalidField
                        | crate::audit::FindingKind::MissingField
                )
            ));
        }
    }
    for kvlist in [false, true] {
        let mut json =
            crate::logs::encode_json(&request(&record(), text("valid")).unwrap()).unwrap();
        json["resourceLogs"][0]["scopeLogs"][0]["scope"]["attributes"][0]["value"] =
            serde_json::to_value(nested(text(""), validation::MAX_CONTEXT_DEPTH + 1, kvlist))
                .unwrap();
        assert_eq!(
            Record::parse_line(&serde_json::to_vec(&json).unwrap())
                .unwrap_err()
                .finding_kind(),
            Some(crate::audit::FindingKind::InvalidField)
        );
    }
}
#[test]
fn writer_refuses_oversize_without_truncation() {
    let mut record = record();
    record.context.service = "x".repeat(validation::MAX_PAYLOAD_BYTES);
    assert_eq!(
        request(&record, text("valid")).unwrap_err().kind(),
        AuditErrorKind::TooLarge
    );
}

#[test]
fn context_numbers_and_ids_are_canonical() {
    for resource in [false, true] {
        for (field, spelling, accepted) in [
            ("intValue", "\"007\"", false),
            ("intValue", "\"+5\"", false),
            ("intValue", "\"7\"", true),
            ("doubleValue", "1", false),
            ("doubleValue", "1E2", false),
            ("doubleValue", "1.50", false),
            ("doubleValue", "1.0", true),
            ("doubleValue", "100.0", true),
            ("doubleValue", "1.5", true),
        ] {
            let mut json =
                crate::logs::encode_json(&request(&record(), text("valid")).unwrap()).unwrap();
            let attrs = if resource {
                &mut json["resourceLogs"][0]["resource"]["attributes"]
            } else {
                &mut json["resourceLogs"][0]["scopeLogs"][0]["scope"]["attributes"]
            };
            attrs
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({"key":"number", "value":{"stringValue":"NUMBER_TOKEN"}}));
            let line = serde_json::to_string(&json).unwrap().replace(
                "\"stringValue\":\"NUMBER_TOKEN\"",
                &format!("\"{field}\":{spelling}"),
            );
            assert_eq!(
                Record::parse_line(line.as_bytes()).is_ok(),
                accepted,
                "{field}: {spelling}, resource={resource}"
            );
        }
    }
    for (field, width) in [("traceId", 32), ("spanId", 16)] {
        for (digit, accepted) in [("a", true), ("A", false)] {
            let mut json =
                crate::logs::encode_json(&request(&record(), text("valid")).unwrap()).unwrap();
            json["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0][field] =
                digit.repeat(width).into();
            assert_eq!(
                Record::parse_line(&serde_json::to_vec(&json).unwrap()).is_ok(),
                accepted
            );
        }
    }
}

#[test]
fn r2_reserved_context_keys_are_rejected_at_both_boundaries() {
    for key in ["audit.repaired", "audit.seq", "audit.future"] {
        let extra = av(any_value::Value::KvlistValue(KeyValueList {
            values: vec![kv(key, text("misleading"))],
        }));
        assert_eq!(
            request(&record(), extra).unwrap_err().kind(),
            AuditErrorKind::InvalidConfig
        );
        for resource in [false, true] {
            for nested in [false, true] {
                let mut json =
                    crate::logs::encode_json(&request(&record(), text("valid")).unwrap()).unwrap();
                let attrs = if resource {
                    &mut json["resourceLogs"][0]["resource"]["attributes"]
                } else {
                    &mut json["resourceLogs"][0]["scopeLogs"][0]["scope"]["attributes"]
                };
                let reserved = serde_json::json!({"key":key,"value":{"stringValue":"misleading"}});
                attrs.as_array_mut().unwrap().push(if nested {
                    serde_json::json!({"key":"nested-context","value":{"kvlistValue":{"values":[reserved]}}})
                } else { reserved });
                assert_eq!(
                    Record::parse_line(&serde_json::to_vec(&json).unwrap())
                        .unwrap_err()
                        .finding_kind(),
                    Some(crate::audit::FindingKind::InvalidField)
                );
            }
        }
    }
}

#[test]
fn r2_zero_size_is_only_the_creation_checkpoint() {
    for seq in [1, 7, i64::MAX as u64] {
        let context = RecordContext::new([0; 16], seq, 0, "service", [0; 32]);
        let fields =
            CheckpointFields::new(0, crate::audit::Mmr::new().root(), vec![], [0; 32], [0; 64])
                .unwrap();
        // Assemble an invalid wire input without the checked constructor.
        let invalid = Record {
            context: context.clone(),
            kind: Kind::Checkpoint(fields.clone()),
        };
        let line = crate::logs::encode_line(&request(&invalid, text("context")).unwrap()).unwrap();
        assert_eq!(
            Record::checkpoint(context, fields).unwrap_err().kind(),
            AuditErrorKind::InvalidConfig
        );
        assert_eq!(
            Record::parse_line(line.as_bytes())
                .unwrap_err()
                .finding_kind(),
            Some(crate::audit::FindingKind::InvalidField)
        );
    }
}

#[test]
fn r2_corpus_contains_normal_and_resume_checkpoints() {
    let (mut normal, mut resume) = (0, 0);
    for line in corpus() {
        for record in Record::parse_line(line.as_bytes()).unwrap() {
            if let Kind::Checkpoint(fields) = record.kind {
                if fields.size == record.context.seq {
                    normal += 1;
                } else {
                    resume += 1;
                }
            }
        }
    }
    assert!(
        normal > resume && resume > 0,
        "normal={normal}, resume={resume}"
    );
}

#[test]
fn verify_committed_writer_corpus() {
    let compressed = include_bytes!("../../tests/fixtures/audit/roundtrip.jsonl.gz");
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(
        &mut flate2::read::GzDecoder::new(compressed.as_slice()),
        &mut bytes,
    )
    .unwrap();
    assert_eq!(
        blake3::hash(&bytes).to_hex().as_str(),
        include_str!("../../tests/fixtures/audit/roundtrip.blake3").trim()
    );
    let text = std::str::from_utf8(&bytes).unwrap();
    assert_eq!(text.lines().count(), 256);
    for line in text.lines() {
        let records = Record::parse_line(line.as_bytes()).unwrap();
        assert_eq!(records.len(), 1);
        assert!(line.starts_with(
            r#"{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"observedTimeUnixNano":"#
        ));
    }
}
