use super::*;
use crate::audit::{Entry, Record, RecordContext};

#[test]
fn id_boundaries_and_alphabet() {
    let kind = FieldKind::id();
    for text in [
        "a".into(),
        "x".repeat(128),
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-".into(),
    ] {
        assert!(kind.render(&AttrValue::Id(text)).is_ok());
    }
    for text in [
        "".into(),
        "x".repeat(129),
        "a/b".into(),
        "é".into(),
        "a\\n".into(),
    ] {
        assert!(kind.render(&AttrValue::Id(text)).is_err());
    }
    assert!(kind.render(&AttrValue::Token("a".into())).is_err());
}

#[test]
fn token_enum_and_integer_boundaries() {
    let kind = FieldKind::token();
    for text in [
        "a".into(),
        "x".repeat(64),
        "abcdefghijklmnopqrstuvwxyz0123456789._-".into(),
    ] {
        assert!(kind.parse(&text).is_ok());
    }
    for text in ["".into(), "x".repeat(65), "A".into(), ":".into()] {
        assert!(kind.parse(&text).is_err());
    }
    let kind = FieldKind::one_of(["yes", "no"]);
    assert!(kind.parse("yes").is_ok());
    assert!(kind.parse("no").is_ok());
    assert!(kind.parse("maybe").is_err());
    for kind in [
        FieldKind::one_of(Vec::<String>::new()),
        FieldKind::one_of(["x", "x"]),
        FieldKind::one_of(["X"]),
        FieldKind::one_of((0..65).map(|n| format!("v{n}"))),
        FieldKind::int(1, 0),
    ] {
        assert_eq!(
            kind.validate().unwrap_err().kind(),
            AuditErrorKind::InvalidConfig
        );
    }
    assert!(
        FieldKind::one_of((0..64).map(|n| format!("v{n}")))
            .validate()
            .is_ok()
    );
    let kind = FieldKind::int(-2, 2);
    for text in ["-2", "0", "2"] {
        assert!(kind.parse(text).is_ok());
    }
    for text in ["-3", "3", "-0", "+1", "01", " 1", "9223372036854775808"] {
        assert!(kind.parse(text).is_err());
    }
    let kind = FieldKind::int(i64::MIN, i64::MAX);
    for n in [i64::MIN, i64::MAX] {
        assert_eq!(kind.parse(&n.to_string()).unwrap(), AttrValue::Int(n));
    }
}

#[test]
fn digest_labels_and_text_boundaries() {
    for alg in ["a", "a123456789012345", "sha256", "blake3", "a-09"] {
        assert!(FieldKind::digest(alg).validate().is_ok());
    }
    for alg in ["", "a1234567890123456", "1sha", "SHA256", "a_b"] {
        assert!(FieldKind::digest(alg).validate().is_err());
    }
    let kinds = BTreeMap::from([("hash".into(), FieldKind::digest("sha256"))]);
    let header = format!("vigil.attrs.v1 blake3:{}\nhash=sha256:", "00".repeat(32));
    for hex in [
        "ab".repeat(31),
        "ab".repeat(33),
        "AB".repeat(32),
        "ag".repeat(32),
    ] {
        assert!(parse_block(&format!("{header}{hex}"), &kinds).is_err());
    }
    let text = format!("{header}{}", "ab".repeat(32));
    let (digest, values) = parse_block(&text, &kinds).unwrap();
    assert_eq!(values["hash"], AttrValue::Digest([0xab; 32]));
    assert_eq!(
        render_block(&digest, &kinds, values.iter().map(|(k, v)| (k.as_str(), v))).unwrap(),
        text
    );
    assert!(parse_block(&text.replace("hash=sha256:", "hash=blake3:"), &kinds).is_err());
}

#[test]
fn attribute_key_boundaries() {
    for key in ["a".into(), "x".repeat(64), "a0123456789_.z".into()] {
        assert!(validate_key(&key).is_ok());
    }
    for key in [
        "".into(),
        "x".repeat(65),
        "A".into(),
        "vigil.x".into(),
        "1x".into(),
        "a-b".into(),
    ] {
        assert!(validate_key(&key).is_err());
    }
}

fn fixture() -> (BTreeMap<String, FieldKind>, Vec<(&'static str, AttrValue)>) {
    (
        BTreeMap::from([
            ("a".into(), FieldKind::id()),
            ("b".into(), FieldKind::int(-1, 1)),
            ("c".into(), FieldKind::digest("sha256")),
        ]),
        vec![
            ("c", AttrValue::Digest([0xab; 32])),
            ("a", AttrValue::Id("ID:1".into())),
            ("b", AttrValue::Int(-1)),
        ],
    )
}
#[test]
fn canonical_block_permutations_and_roundtrip() {
    let (kinds, values) = fixture();
    let expected = format!(
        "vigil.attrs.v1 blake3:{}\na=ID:1\nb=-1\nc=sha256:{}",
        "11".repeat(32),
        "ab".repeat(32)
    );
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let text = render_block(
            &[0x11; 32],
            &kinds,
            order.map(|i| (values[i].0, &values[i].1)),
        )
        .unwrap();
        assert_eq!(text, expected);
        let (digest, parsed) = parse_block(&text, &kinds).unwrap();
        assert_eq!(digest, [0x11; 32]);
        assert_eq!(
            parsed,
            values
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect()
        );
        let json = serde_json::to_string(&text).unwrap();
        assert!(json.contains("\\n"));
        assert_eq!(serde_json::from_str::<String>(&json).unwrap(), text);
    }
    let empty = render_block(&[0; 32], &kinds, []).unwrap();
    assert_eq!(empty.len(), 86);
    assert!(parse_block(&empty, &kinds).unwrap().1.is_empty());
}
#[test]
fn noncanonical_blocks_are_refused() {
    let kinds = BTreeMap::from([("a".into(), FieldKind::id()), ("b".into(), FieldKind::id())]);
    let header = format!("vigil.attrs.v1 blake3:{}", "00".repeat(32));
    for suffix in [
        "\nb=x\na=y",
        "\na=x\na=x",
        "\na=x ",
        "\na=x\n",
        "\n\na=x",
        "a=x",
        "\\na=x",
        "\na=x\\n",
        "\na=x=b",
        "\r\na=x",
    ] {
        assert!(
            parse_block(&format!("{header}{suffix}"), &kinds).is_err(),
            "{suffix:?}"
        );
    }
    assert!(
        render_block(
            &[0; 32],
            &kinds,
            [
                ("a", &AttrValue::Id("x".into())),
                ("a", &AttrValue::Id("x".into()))
            ]
        )
        .is_err()
    );
}

#[test]
fn p4_public_internal_and_legacy_decode() {
    let context = || RecordContext::new([0x11; 16], 0, 123, "svc", Record::genesis(&[0x11; 16]));
    for details in ["vigil.attrs.", "vigil.attrs.v1 anything", "vigil.attrs.v2"] {
        let entry = Entry::new("actor", "sample.modify", "object").details(details);
        assert_eq!(
            Record::new(context(), entry.clone()).unwrap_err().kind(),
            AuditErrorKind::InvalidEntry
        );
        let legacy = Record::new_internal(context(), entry).unwrap();
        let bytes = crate::audit::sink::line(&legacy).unwrap();
        assert_eq!(
            Record::parse_line(&bytes).unwrap()[0].canonical(),
            legacy.canonical()
        );
    }
    assert!(
        Record::new(
            context(),
            Entry::new("actor", "sample.modify", "object").details("later vigil.attrs.v1")
        )
        .is_ok()
    );
}

#[test]
fn typed_record_golden_and_v010_encoding() {
    let (kinds, values) = fixture();
    let block = render_block(&[0x11; 32], &kinds, values.iter().map(|(k, v)| (*k, v))).unwrap();
    let record = Record::new_internal(
        RecordContext::new([0x11; 16], 0, 123, "svc", Record::genesis(&[0x11; 16])).host("host"),
        Entry::new("α", "sample.modify", "id:1")
            .reason("reason")
            .before(crate::audit::Value::Text("old".into()))
            .after(crate::audit::Value::digest_of(b"new"))
            .details(&block),
    )
    .unwrap();
    // The 0.1.0 fixture fixes every field and the TLV encoding. Substitute only
    // the details payload (tag 0x18); all other bytes remain frozen.
    let baseline = crate::audit::tests::vector("record_fields");
    let mut legacy = Vec::new();
    let mut offset = 0;
    while offset < baseline.len() {
        let tag = baseline[offset];
        let len = u32::from_be_bytes(baseline[offset + 1..offset + 5].try_into().unwrap()) as usize;
        if tag == 0x18 {
            legacy.push(tag);
            legacy.extend((block.len() as u32).to_be_bytes());
            legacy.extend(block.as_bytes());
        } else {
            legacy.extend(&baseline[offset..offset + 5 + len]);
        }
        offset += 5 + len;
    }
    assert_eq!(record.canonical(), legacy);
    assert_eq!(
        record.canonical(),
        crate::audit::tests::vector("typed_record_fields")
    );
    assert_eq!(
        record.hash().as_slice(),
        crate::audit::tests::vector("typed_record_hash")
    );
    assert_eq!(block.as_bytes(), crate::audit::tests::vector("typed_block"));
    let line = crate::audit::sink::line(&record).unwrap();
    assert_eq!(Record::parse_line(&line).unwrap()[0].canonical(), legacy);
}
