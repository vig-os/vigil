use super::*;
use serde_json::{Value as Json, json};
const GOLDEN: &str = include_str!("../../tests/fixtures/audit/codec.jsonl");
fn fixture(cp: bool) -> Json {
    serde_json::from_str(GOLDEN.lines().nth(usize::from(cp)).unwrap()).unwrap()
}
fn log(v: &mut Json) -> &mut Json {
    &mut v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
}
fn attrs(v: &mut Json) -> &mut Vec<Json> {
    log(v)["attributes"].as_array_mut().unwrap()
}
fn attr<'a>(v: &'a mut Json, key: &str) -> &'a mut Json {
    &mut attrs(v).iter_mut().find(|a| a["key"] == key).unwrap()["value"]
}
fn rejected(v: &Json) {
    let error = Record::parse_line(v.to_string().as_bytes()).unwrap_err();
    assert_eq!(error.kind(), AuditErrorKind::CorruptTrail);
}
#[test]
fn codec_golden_and_checkpoint_anchor() {
    for (line, name) in GOLDEN.lines().zip(["record_fields", "checkpoint_fields"]) {
        let records = Record::parse_line(line.as_bytes()).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].canonical(), super::tests::vector(name));
    }
    let line = GOLDEN.lines().nth(1).unwrap();
    let cp = Checkpoint::parse(line).unwrap();
    assert_eq!(cp.seq(), 0);
    assert_eq!(
        cp.hash().as_slice(),
        super::tests::vector("checkpoint_hash")
    );
    assert_eq!(cp.mmr_size(), 0);
    assert_eq!(cp.mmr_root(), Mmr::new().root());
    assert_eq!(
        cp.key_id(),
        KeyFileSigner::from_hex(&"07".repeat(32))
            .unwrap()
            .public_key()
    );
    assert_eq!(cp.line(), line);
    assert!(Checkpoint::parse(GOLDEN.lines().next().unwrap()).is_err());
}
#[test]
fn codec_collector_shape_and_context() {
    let mut v = fixture(false);
    let expected = Record::parse_line(v.to_string().as_bytes()).unwrap()[0].canonical();
    attrs(&mut v).reverse();
    for (key, value) in [
        ("traceId", json!("11".repeat(16))),
        ("spanId", json!("22".repeat(8))),
        ("flags", json!(1)),
        ("droppedAttributesCount", json!(0)),
    ] {
        log(&mut v)[key] = value;
    }
    v["resourceLogs"][0]["resource"]["attributes"]
        .as_array_mut()
        .unwrap()
        .push(json!({"key":"service.version","value":{"stringValue":"2"}}));
    v["resourceLogs"][0]["scopeLogs"][0]["scope"]["attributes"] = json!([]);
    let record = log(&mut v).clone();
    v["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
        .as_array_mut()
        .unwrap()
        .push(record);
    let scope = v["resourceLogs"][0]["scopeLogs"][0].clone();
    v["resourceLogs"][0]["scopeLogs"]
        .as_array_mut()
        .unwrap()
        .push(scope);
    let resource = v["resourceLogs"][0].clone();
    v["resourceLogs"].as_array_mut().unwrap().push(resource);
    let decoded = Record::parse_line(v.to_string().as_bytes()).unwrap();
    assert_eq!(decoded.len(), 8);
    assert!(decoded.iter().all(|r| r.canonical() == expected));
    assert!(Checkpoint::parse(&v.to_string()).is_err());
}
#[test]
fn codec_rejects_display_fields_and_duplicates() {
    for (key, value) in [
        ("body", json!({"stringValue":"forged"})),
        ("future", json!(0)),
        ("severityNumber", json!(10)),
        ("severityText", json!("WARN")),
        ("observedTimeUnixNano", json!(124)),
        ("droppedAttributesCount", json!(1)),
    ] {
        let mut v = fixture(false);
        log(&mut v)[key] = value;
        rejected(&v);
    }
    for key in [
        "timeUnixNano",
        "observedTimeUnixNano",
        "severityNumber",
        "severityText",
        "eventName",
    ] {
        let mut v = fixture(false);
        log(&mut v).as_object_mut().unwrap().remove(key);
        rejected(&v);
    }
    for key in ["audit.note", "audit.mmr_size", "audit.actor"] {
        let mut v = fixture(false);
        attrs(&mut v).push(json!({"key":key,"value":{"stringValue":"forged"}}));
        rejected(&v);
    }
    let raw = fixture(false).to_string();
    for (needle, replacement) in [
        (
            r#""stringValue":"α""#,
            r#""stringValue":"mallory","string\u0056alue":"α""#,
        ),
        (
            r#""severityNumber":9"#,
            r#""severityNumber":0,"severityNumber":9"#,
        ),
        (r#""resourceLogs":"#, r#""resourceLogs":[],"resourceLogs":"#),
        (
            r#""name":"vigil.audit""#,
            r#""name":"other","name":"vigil.audit""#,
        ),
    ] {
        let bad = raw.replacen(needle, replacement, 1);
        assert_ne!(bad, raw);
        assert_eq!(
            Record::parse_line(bad.as_bytes()).unwrap_err().kind(),
            AuditErrorKind::CorruptTrail
        );
    }
}
#[test]
fn codec_rejects_integer_spellings_and_invalid_values() {
    for spelling in [
        r#""+1""#,
        r#""01""#,
        r#"" 1""#,
        r#""١""#,
        r#""1e0""#,
        "-0",
        "-1",
        "1.0",
        "1e0",
        "18446744073709551616",
        "null",
        "true",
    ] {
        for needle in [
            r#""intValue":"1""#,
            r#""timeUnixNano":"123""#,
            r#""observedTimeUnixNano":"123""#,
        ] {
            let key = needle.split(':').next().unwrap();
            let raw = fixture(false)
                .to_string()
                .replacen(needle, &format!("{key}:{spelling}"), 1);
            assert!(Record::parse_line(raw.as_bytes()).is_err(), "{raw}");
        }
    }
    for key in [
        "audit.actor",
        "audit.action",
        "audit.object",
        "audit.reason",
        "audit.before",
        "audit.details",
    ] {
        for value in [
            json!({"stringValue":""}),
            json!({"stringValue":"x\u{0}y"}),
            json!({"intValue":"1"}),
            json!({"stringValue":"α","intValue":"1"}),
        ] {
            let mut v = fixture(false);
            *attr(&mut v, key) = value;
            rejected(&v);
        }
    }
    for key in [
        "audit.hash",
        "audit.prev_hash",
        "audit.trail",
        "audit.after_digest",
    ] {
        let mut v = fixture(false);
        attr(&mut v, key)["stringValue"] = json!("BLAKE3:AB");
        rejected(&v);
    }
    let mut v = fixture(false);
    attr(&mut v, "audit.actor")["stringValue"] = json!("mallory");
    rejected(&v);
    let mut v = fixture(false);
    attrs(&mut v).push(json!({"key":"audit.before_digest","value":{"stringValue":format!("blake3:{}", "00".repeat(32))}}));
    rejected(&v);
    for value in [json!(""), json!("x\u{0}")] {
        let mut v = fixture(false);
        v["resourceLogs"][0]["resource"]["attributes"][0]["value"]["stringValue"] = value;
        rejected(&v);
    }
}
#[test]
fn codec_rejects_checkpoint_shape_and_empty_lines() {
    for key in [
        "audit.mmr_size",
        "audit.mmr_root",
        "audit.key_id",
        "audit.sig",
    ] {
        let mut v = fixture(true);
        attrs(&mut v).retain(|a| a["key"] != key);
        rejected(&v);
    }
    for (key, value) in [
        ("audit.mmr_peaks", json!({"arrayValue":{"values":[]}})),
        ("audit.actor", json!({"stringValue":"forged"})),
    ] {
        let mut v = fixture(true);
        attrs(&mut v).push(json!({"key":key,"value":value}));
        rejected(&v);
    }
    let mut v = fixture(true);
    attr(&mut v, "audit.mmr_size")["intValue"] = json!("1");
    rejected(&v);
    for raw in [
        b"".as_slice(),
        b" \t\r\n",
        b"{}",
        b"null",
        b"[]",
        b"{",
        b"\xff",
        b"{}{}",
        b"{\"resourceLogs\":[]}",
    ] {
        assert!(Record::parse_line(raw).is_err());
    }
    let deep = format!("{}0{}", "[".repeat(200), "]".repeat(200));
    assert!(Record::parse_line(deep.as_bytes()).is_err());
}
#[test]
fn codec_short_fuzz_never_panics() {
    // Fixed-seed mutations, every prefix (including a cut UTF-8 actor), and raw bytes.
    let bytes = GOLDEN.lines().next().unwrap().as_bytes();
    for end in 0..bytes.len() {
        let _ = Record::parse_line(&bytes[..end]);
    }
    let mut state = 0x12345678u64;
    for n in 0..4096 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let mut input = if n % 2 == 0 {
            bytes.to_vec()
        } else {
            vec![0; n % 256]
        };
        if !input.is_empty() {
            let pos = state as usize % input.len();
            input[pos] = (state >> 32) as u8;
        }
        let _ = Record::parse_line(&input);
    }
}
#[test]
fn codec_optional_values_int64_boundary_and_nonzero_checkpoint() {
    let previous = Record::genesis(&[0x11; 16]);
    let record = Record::new(
        RecordContext::new([0x11; 16], i64::MAX as u64, u64::MAX, "svc", previous),
        Entry::new("α", "sample.modify", "id:1")
            .before(Value::Digest([0; 32]))
            .after(Value::Text("new".into())),
    )
    .unwrap();
    let mut v = fixture(false);
    v["resourceLogs"][0]["resource"]["attributes"]
        .as_array_mut()
        .unwrap()
        .retain(|a| a["key"] != "host.name");
    log(&mut v)["timeUnixNano"] = json!(u64::MAX.to_string());
    log(&mut v)["observedTimeUnixNano"] = json!(u64::MAX.to_string());
    attr(&mut v, "audit.seq")["intValue"] = json!(i64::MAX.to_string());
    attr(&mut v, "audit.hash")["stringValue"] = json!(digest_string(&record.hash()));
    attrs(&mut v).retain(|a| {
        !matches!(
            a["key"].as_str(),
            Some("audit.reason" | "audit.details" | "audit.before" | "audit.after_digest")
        )
    });
    for (key, value) in [
        ("audit.before_digest", digest_string(&[0; 32])),
        ("audit.after", "new".into()),
    ] {
        attrs(&mut v).push(json!({"key":key,"value":{"stringValue":value}}));
    }
    assert_eq!(
        Record::parse_line(v.to_string().as_bytes()).unwrap()[0].canonical(),
        record.canonical()
    );
    let mut mmr = Mmr::new();
    for i in 0..3 {
        mmr.push([i; 32]).unwrap();
    }
    let cp = Record::checkpoint(
        RecordContext::new([0x11; 16], 3, 123, "svc", previous).host("host"),
        CheckpointFields::new(3, mmr.root(), mmr.peaks().to_vec(), [0; 32], [0; 64]).unwrap(),
    )
    .unwrap();
    let mut v = fixture(true);
    for key in ["audit.seq", "audit.mmr_size"] {
        attr(&mut v, key)["intValue"] = json!("3");
    }
    for (key, value) in [
        ("audit.hash", digest_string(&cp.hash())),
        ("audit.mmr_root", digest_string(&mmr.root())),
        ("audit.key_id", "00".repeat(32)),
        ("audit.sig", "00".repeat(64)),
    ] {
        attr(&mut v, key)["stringValue"] = json!(value);
    }
    let peaks: Vec<_> = mmr
        .peaks()
        .iter()
        .map(|p| json!({"stringValue":digest_string(p)}))
        .collect();
    attrs(&mut v).push(json!({"key":"audit.mmr_peaks",
        "value":{"arrayValue":{"values":peaks}}}));
    let decoded = Checkpoint::parse(&v.to_string()).unwrap();
    assert_eq!(decoded.seq(), 3);
    assert_eq!(decoded.mmr_size(), 3);
    assert_eq!(decoded.mmr_root(), mmr.root());
    // A structurally valid zero signature parses: verification is explicitly #13.
    assert_eq!(decoded.key_id(), [0; 32]);
    let attrs = attrs(&mut v);
    attrs.last_mut().unwrap()["value"]["arrayValue"]["values"]
        .as_array_mut()
        .unwrap()
        .pop();
    rejected(&v);
}
#[test]
fn codec_rejects_collector_alias_forgery() {
    let mut v = fixture(false);
    let mut forged = log(&mut v).clone();
    forged["attributes"][4]["value"]["stringValue"] = json!("mallory");
    v["resourceLogs"][0]["scopeLogs"][0]["log_records"] = json!([forged]);
    assert!(
        Record::parse_line(v.to_string().as_bytes()).is_err(),
        "Collector alias forgery was silently accepted"
    );
}
#[test]
fn codec_closed_messages_and_nested_context() {
    let mut base = fixture(false);
    base["resourceLogs"][0]["resource"]["entityRefs"] =
        json!([{"schemaUrl":"s","type":"host","idKeys":["host.name"],"descriptionKeys":[]}]);
    base["resourceLogs"][0]["scopeLogs"][0]["scope"]["attributes"] = json!([
        {"key":"context","value":{"kvlistValue":{"values":[{"key":"nested","value":
            {"arrayValue":{"values":[{"stringValue":"context"}]}}}]}}}]);
    assert!(Record::parse_line(base.to_string().as_bytes()).is_ok());
    let cases = json!({
        "": ["resource_logs"],
        "/resourceLogs/0": ["scope_logs", "schema_url"],
        "/resourceLogs/0/scopeLogs/0": ["log_records", "schema_url"],
        "/resourceLogs/0/resource": ["dropped_attributes_count", "entity_refs"],
        "/resourceLogs/0/resource/entityRefs/0": ["schema_url", "id_keys", "description_keys"],
        "/resourceLogs/0/scopeLogs/0/scope": ["dropped_attributes_count"],
        "/resourceLogs/0/resource/attributes/0": ["key_strindex"],
        "/resourceLogs/0/resource/attributes/0/value": ["string_value", "int_value", "bool_value", "double_value", "bytes_value", "array_value", "kvlist_value"],
        "/resourceLogs/0/scopeLogs/0/scope/attributes/0/value/kvlistValue": [],
        "/resourceLogs/0/scopeLogs/0/scope/attributes/0/value/kvlistValue/values/0/value/arrayValue": [],
        "/resourceLogs/0/scopeLogs/0/logRecords/0": ["time_unix_nano", "observed_time_unix_nano", "severity_number", "severity_text", "event_name", "trace_id", "span_id", "dropped_attributes_count"]
    });
    for (pointer, aliases) in cases.as_object().unwrap() {
        for key in aliases
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .chain(["forged"])
        {
            let mut v = base.clone();
            v.pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(key.into(), json!([]));
            let error = Record::parse_line(v.to_string().as_bytes()).unwrap_err();
            assert_eq!(
                error.finding_kind(),
                Some(FindingKind::UnknownField),
                "{pointer}/{key}"
            );
        }
    }
}
#[test]
fn codec_decimal_strings_only() {
    for key in ["timeUnixNano", "observedTimeUnixNano"] {
        let mut v = fixture(false);
        log(&mut v)[key] = json!(123);
        rejected(&v);
    }
    for (cp, key) in [
        (false, "audit.v"),
        (false, "audit.seq"),
        (true, "audit.mmr_size"),
    ] {
        let mut v = fixture(cp);
        attr(&mut v, key)["intValue"] = json!(0);
        rejected(&v);
    }
}
#[test]
fn codec_cr_framing() {
    let line = GOLDEN.lines().nth(1).unwrap();
    for suffix in ["\r", "\r\n"] {
        assert!(Checkpoint::parse(&format!("{line}{suffix}")).is_err());
    }
    assert!(Checkpoint::parse(&format!("{line}\n")).is_ok());
    // JSON escapes are content, not framing CR bytes.
    let mut v = fixture(false);
    attr(&mut v, "audit.actor")["stringValue"] = json!("α\r\n\t");
    let record = Record::new(
        RecordContext::new([0x11; 16], 0, 123, "svc", Record::genesis(&[0x11; 16])).host("host"),
        Entry::new("α\r\n\t", "sample.modify", "id:1")
            .reason("reason")
            .before(Value::Text("old".into()))
            .after(Value::digest_of(b"new"))
            .details("{}"),
    )
    .unwrap();
    attr(&mut v, "audit.hash")["stringValue"] = json!(digest_string(&record.hash()));
    assert!(Record::parse_line(v.to_string().as_bytes()).is_ok());
}
#[test]
fn codec_line_size_bound() {
    let line = GOLDEN.lines().nth(1).unwrap();
    let mut bytes = line.as_bytes().to_vec();
    bytes.resize(1_000_000, b' ');
    assert!(Record::parse_line(&bytes).is_ok());
    bytes.push(b'\n');
    assert!(Record::parse_line(&bytes).is_ok());
    bytes.pop();
    bytes.push(b' ');
    let error = Record::parse_line(&bytes).unwrap_err();
    assert_eq!(error.kind(), AuditErrorKind::TooLarge);
    assert_eq!(error.finding_kind(), Some(FindingKind::Unparsable));
}
#[test]
fn codec_verifier_finding_kinds() {
    for (raw, kind) in [
        ("", FindingKind::Unparsable),
        ("{", FindingKind::Unparsable),
        ("{}", FindingKind::MissingField),
        ("[1]", FindingKind::Unparsable),
        ("1", FindingKind::Unparsable),
        ("\0", FindingKind::Unparsable),
        (
            r#"{"resourceLogs":[],"resourceLogs":[]}"#,
            FindingKind::InvalidField,
        ),
    ] {
        assert_eq!(
            Record::parse_line(raw.as_bytes())
                .unwrap_err()
                .finding_kind(),
            Some(kind)
        );
    }
    let mut v = fixture(false);
    attr(&mut v, "audit.v")["intValue"] = json!("2");
    assert_eq!(
        Record::parse_line(v.to_string().as_bytes())
            .unwrap_err()
            .finding_kind(),
        Some(FindingKind::UnknownVersion)
    );
    attr(&mut v, "audit.v")["intValue"] = json!("1");
    attr(&mut v, "audit.actor")["stringValue"] = json!("mallory");
    assert_eq!(
        Record::parse_line(v.to_string().as_bytes())
            .unwrap_err()
            .finding_kind(),
        Some(FindingKind::HashMismatch)
    );
    let error = Record::new(
        RecordContext::new([0; 16], 0, 0, "", [0; 32]),
        Entry::new("a", "b", "c"),
    )
    .unwrap_err();
    assert_eq!(error.finding_kind(), None);
}
#[test]
fn codec_line_controls_and_final_lf() {
    let line = GOLDEN.lines().nth(1).unwrap();
    let cases = [
        format!("{line}\n\n"),
        line.replacen('{', "{\n", 1),
        line.replacen('{', "{\t", 1),
        format!("{line}\n\t"),
    ];
    for bad in cases {
        assert!(Record::parse_line(bad.as_bytes()).is_err());
        assert!(Checkpoint::parse(&bad).is_err());
    }
    let cp = Checkpoint::parse(&format!("{line}\n")).unwrap();
    assert_eq!(cp.line(), line);
}
#[test]
fn codec_context_int64_and_base64() {
    let cases = json!([
        [false, {"intValue":"9223372036854775808"}], [false, {"intValue":"18446744073709551615"}],
        [false, {"intValue":"-9223372036854775809"}], [false, {"bytesValue":"!!!"}],
        [false, {"bytesValue":"YQ"}], [false, {"bytesValue":"YQ==="}], [false, {"bytesValue":"Y Q=="}],
        [false, {"bytesValue":"____"}], [true, {"bytesValue":""}], [true, {"bytesValue":"YQ=="}],
        [true, {"bytesValue":"YR=="}], [false, {"bytesValue":"Y\r\nQ=="}],
        [true, {"intValue":"9223372036854775807"}], [true, {"intValue":"-9223372036854775808"}]
    ]);
    for case in cases.as_array().unwrap() {
        let mut v = fixture(false);
        v["resourceLogs"][0]["scopeLogs"][0]["scope"] =
            json!({"attributes":[{"key":"context", "value":case[1]}]});
        assert_eq!(
            Record::parse_line(v.to_string().as_bytes()).is_ok(),
            case[0].as_bool().unwrap(),
            "{case}"
        );
    }
}
#[test]
fn codec_writer_int64_bounds() {
    for seq in [i64::MAX as u64 + 1, u64::MAX] {
        let context = RecordContext::new([0; 16], seq, 0, "svc", [0; 32]);
        assert_eq!(
            Record::new(context.clone(), Entry::new("a", "b", "c"))
                .unwrap_err()
                .kind(),
            AuditErrorKind::InvalidConfig
        );
        let peaks = vec![[0; 32]; seq.count_ones() as usize];
        let fields = CheckpointFields::new(seq, [0; 32], peaks, [0; 32], [0; 64]).unwrap();
        assert_eq!(
            Record::checkpoint(context, fields).unwrap_err().kind(),
            AuditErrorKind::InvalidConfig
        );
    }
}

#[test]
fn codec_raw_reader_parity() {
    let cases: Json =
        serde_json::from_str(include_str!("../../tests/fixtures/audit/raw-fields.json")).unwrap();
    let mut mismatches = Vec::new();
    for case in cases.as_array().unwrap() {
        let mut v = fixture(false);
        let field = case["field"].as_str().unwrap();
        if field == "bytesValue" {
            v["resourceLogs"][0]["resource"]["attributes"].as_array_mut().unwrap().push(json!({"key":"raw", "value":{"arrayValue":{"values":[{"kvlistValue":{"values":[{"key":"nested","value":{"bytesValue":"RAW"}}]}}]}}}));
        } else {
            log(&mut v)[field] = json!("RAW");
        }
        let line = v
            .to_string()
            .replace("\"RAW\"", case["raw"].as_str().unwrap());
        if Record::parse_line(line.as_bytes()).is_ok() != case["accepted"].as_bool().unwrap() {
            mismatches.push(case.clone());
        }
    }
    assert!(
        mismatches.is_empty(),
        "raw reader mismatches: {mismatches:?}"
    );
}
#[test]
fn codec_anchor_whitespace_is_preserved() {
    let line = GOLDEN.lines().nth(1).unwrap();
    let spaced = line.replacen('{', "{ ", 1) + " ";
    let cp = Checkpoint::parse(&(spaced.clone() + "\n")).unwrap();
    assert_eq!(cp.line(), spaced);
    assert_eq!(cp.hash(), Checkpoint::parse(line).unwrap().hash());
}

#[test]
fn repaired_digest_roundtrips_and_rejects_tampering() {
    use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
    let extra = || AnyValue {
        value: Some(any_value::Value::StringValue("context".into())),
    };
    for checkpoint in [false, true] {
        let context = RecordContext::new([0x11; 16], 7, 123, "svc", [0; 32]).repaired([0x42; 32]);
        let record = if checkpoint {
            Record::checkpoint(
                context,
                CheckpointFields::new(3, [0; 32], vec![[0; 32]; 2], [0; 32], [0; 64]).unwrap(),
            )
            .unwrap()
        } else {
            Record::new(context, Entry::new("actor", "action", "object")).unwrap()
        };
        let mut json =
            crate::logs::encode_json(&super::format::request(&record, extra()).unwrap()).unwrap();
        let decoded = Record::parse_line(&serde_json::to_vec(&json).unwrap()).unwrap();
        assert_eq!(decoded[0].canonical(), record.canonical());
        assert_eq!(
            attr(&mut json, "audit.repaired")["stringValue"],
            digest_string(&[0x42; 32])
        );
        for invalid in [
            json!("blake3:bad"),
            json!("blake3:".to_owned() + &"AB".repeat(32)),
            json!(42),
        ] {
            let mut altered = json.clone();
            attr(&mut altered, "audit.repaired")["stringValue"] = invalid;
            rejected(&altered);
        }
        let mut altered = json.clone();
        attr(&mut altered, "audit.repaired")["stringValue"] = json!(digest_string(&[0x43; 32]));
        assert_eq!(
            Record::parse_line(&serde_json::to_vec(&altered).unwrap())
                .unwrap_err()
                .finding_kind(),
            Some(FindingKind::HashMismatch)
        );
        attrs(&mut json).retain(|item| item["key"] != "audit.repaired");
        assert_eq!(
            Record::parse_line(&serde_json::to_vec(&json).unwrap())
                .unwrap_err()
                .finding_kind(),
            Some(FindingKind::HashMismatch)
        );
    }
}

#[test]
fn codec_shuffled_keys_preserve_canonical_hash() {
    fn reverse_keys(value: &Json) -> String {
        match value {
            Json::Object(map) => format!(
                "{{{}}}",
                map.iter()
                    .rev()
                    .map(|(key, value)| {
                        format!(
                            "{}:{}",
                            serde_json::to_string(key).unwrap(),
                            reverse_keys(value)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Json::Array(values) => format!(
                "[{}]",
                values
                    .iter()
                    .map(reverse_keys)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            scalar => scalar.to_string(),
        }
    }
    for line in GOLDEN.lines() {
        let original = Record::parse_line(line.as_bytes()).unwrap();
        let json: Json = serde_json::from_str(line).unwrap();
        let shuffled = reverse_keys(&json);
        assert_ne!(shuffled, line);
        let decoded = Record::parse_line(shuffled.as_bytes()).unwrap();
        assert_eq!(decoded.len(), original.len());
        for (before, after) in original.iter().zip(&decoded) {
            assert_eq!(before.canonical(), after.canonical());
            assert_eq!(before.hash(), after.hash());
        }
    }
}
