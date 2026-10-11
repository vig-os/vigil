use super::*;
use serde_json::{Value as Json, json};

const GOLDEN: &str = include_str!("../../tests/fixtures/audit/codec.jsonl");
fn fixture(cp: bool) -> Json {
    serde_json::from_str(GOLDEN.lines().nth(usize::from(cp)).unwrap()).unwrap()
}
fn log(v: &mut Json) -> &mut Json {
    &mut v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
}
fn attr<'a>(v: &'a mut Json, key: &str) -> &'a mut Json {
    &mut log(v)["attributes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|a| a["key"] == key)
        .unwrap()["value"]
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
        KeySeed::parse(&"07".repeat(32)).unwrap().public_key()
    );
    assert_eq!(cp.line(), line);
    assert!(Checkpoint::parse(GOLDEN.lines().next().unwrap()).is_err());
}
#[test]
fn codec_collector_shape_numbers_and_context() {
    let mut v = fixture(false);
    let expected = Record::parse_line(v.to_string().as_bytes()).unwrap()[0].canonical();
    for key in ["timeUnixNano", "observedTimeUnixNano"] {
        log(&mut v)[key] = json!(123);
    }
    for key in ["audit.v", "audit.seq"] {
        let n = attr(&mut v, key)["intValue"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        attr(&mut v, key)["intValue"] = json!(n);
    }
    log(&mut v)["attributes"].as_array_mut().unwrap().reverse();
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
        log(&mut v)["attributes"]
            .as_array_mut()
            .unwrap()
            .push(json!({"key":key,"value":{"stringValue":"forged"}}));
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
    log(&mut v)["attributes"].as_array_mut().unwrap().push(json!({"key":"audit.before_digest","value":{"stringValue":format!("blake3:{}", "00".repeat(32))}}));
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
        log(&mut v)["attributes"]
            .as_array_mut()
            .unwrap()
            .retain(|a| a["key"] != key);
        rejected(&v);
    }
    for (key, value) in [
        ("audit.mmr_peaks", json!({"arrayValue":{"values":[]}})),
        ("audit.actor", json!({"stringValue":"forged"})),
    ] {
        let mut v = fixture(true);
        log(&mut v)["attributes"]
            .as_array_mut()
            .unwrap()
            .push(json!({"key":key,"value":value}));
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
fn codec_optional_values_u64_boundary_and_nonzero_checkpoint() {
    let previous = Record::genesis(&[0x11; 16]);
    let record = Record::new(
        RecordContext::new([0x11; 16], u64::MAX, u64::MAX, "svc", previous),
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
    log(&mut v)["timeUnixNano"] = json!(u64::MAX);
    log(&mut v)["observedTimeUnixNano"] = json!(u64::MAX.to_string());
    attr(&mut v, "audit.seq")["intValue"] = json!(u64::MAX);
    attr(&mut v, "audit.hash")["stringValue"] = json!(digest_string(&record.hash()));
    log(&mut v)["attributes"]
        .as_array_mut()
        .unwrap()
        .retain(|a| {
            ![
                "audit.reason",
                "audit.details",
                "audit.before",
                "audit.after_digest",
            ]
            .contains(&a["key"].as_str().unwrap())
        });
    for (key, value) in [
        ("audit.before_digest", digest_string(&[0; 32])),
        ("audit.after", "new".into()),
    ] {
        log(&mut v)["attributes"]
            .as_array_mut()
            .unwrap()
            .push(json!({"key":key,"value":{"stringValue":value}}));
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
    log(&mut v)["attributes"]
        .as_array_mut()
        .unwrap()
        .push(json!({"key":"audit.mmr_peaks",
        "value":{"arrayValue":{"values":peaks}}}));
    let decoded = Checkpoint::parse(&v.to_string()).unwrap();
    assert_eq!(decoded.seq(), 3);
    assert_eq!(decoded.mmr_size(), 3);
    assert_eq!(decoded.mmr_root(), mmr.root());
    // A structurally valid zero signature parses: verification is explicitly #13.
    assert_eq!(decoded.key_id(), [0; 32]);
    let attrs = log(&mut v)["attributes"].as_array_mut().unwrap();
    attrs.last_mut().unwrap()["value"]["arrayValue"]["values"]
        .as_array_mut()
        .unwrap()
        .pop();
    rejected(&v);
}
