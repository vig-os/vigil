use super::*;

#[test]
fn default_object_and_both_builders() {
    assert_eq!(
        RecordSchema::builder("sample").build().unwrap_err().kind(),
        AuditErrorKind::InvalidConfig
    );
    let schema = RecordSchema::builder("sample")
        .action("read")
        .build()
        .unwrap();
    assert_eq!(schema.name(), "sample");
    assert_eq!(
        schema.text(),
        "vigil.schema.v1 sample\naction read object=id"
    );
    assert_eq!(RecordSchema::parse(schema.text()).unwrap(), schema);
}

fn refused(result: Result<RecordSchema, AuditError>) {
    assert_eq!(result.unwrap_err().kind(), AuditErrorKind::InvalidConfig);
}
#[test]
fn invalid_name() {
    for name in ["".into(), "X".into(), "x".repeat(65)] {
        refused(RecordSchema::builder(name).action("read").build());
    }
}
#[test]
fn invalid_action() {
    for action in ["".into(), "Read".into(), "x".repeat(129)] {
        refused(RecordSchema::builder("s").action(action).build());
    }
}
#[test]
fn duplicate_action() {
    refused(
        RecordSchema::builder("s")
            .action("read")
            .action("read")
            .build(),
    );
}
#[test]
fn reserved_action() {
    refused(
        RecordSchema::builder("s")
            .action("vigil.audit.read")
            .build(),
    );
}
#[test]
fn invalid_keys_required_and_optional() {
    for key in [
        "".into(),
        "x".repeat(65),
        "Upper".into(),
        "vigil.x".into(),
        "a-b".into(),
    ] {
        refused(
            RecordSchema::builder("s")
                .action("read")
                .required(&key, FieldKind::id())
                .build(),
        );
        refused(
            RecordSchema::builder("s")
                .action("read")
                .optional(&key, FieldKind::id())
                .build(),
        );
    }
}
#[test]
fn duplicate_keys() {
    for first_required in [true, false] {
        for second_required in [true, false] {
            let action = RecordSchema::builder("s").action("read");
            let action = if first_required {
                action.required("a", FieldKind::id())
            } else {
                action.optional("a", FieldKind::id())
            };
            let action = if second_required {
                action.required("a", FieldKind::id())
            } else {
                action.optional("a", FieldKind::id())
            };
            refused(action.build());
        }
    }
}
#[test]
fn invalid_object_kind() {
    refused(
        RecordSchema::builder("s")
            .action("read")
            .object(FieldKind::int(2, 1))
            .build(),
    );
}
#[test]
fn invalid_field_kind() {
    for kind in [
        FieldKind::int(2, 1),
        FieldKind::one_of(["x", "x"]),
        FieldKind::digest("BAD"),
    ] {
        refused(
            RecordSchema::builder("s")
                .action("read")
                .required("a", kind.clone())
                .build(),
        );
        refused(
            RecordSchema::builder("s")
                .action("read")
                .optional("a", kind)
                .build(),
        );
    }
}
const TEXT: &str = "vigil.schema.v1 sample\naction a object=id\nfield a required id\nfield b optional int:-1:1\nfield c required digest:sha256\naction b object=token\nfield x optional enum:no,yes\naction c object=int:-9223372036854775808:9223372036854775807";
const ORDERS: [[usize; 3]; 6] = [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
];
#[test]
fn canonical_permutations_and_roundtrip() {
    for actions in ORDERS {
        for keys in ORDERS {
            let mut builder = RecordSchema::builder("sample");
            for i in actions {
                let mut action = builder.action(["a", "b", "c"][i]);
                if i == 0 {
                    for k in keys {
                        action = match k {
                            0 => action.required("a", FieldKind::id()),
                            1 => action.optional("b", FieldKind::int(-1, 1)),
                            _ => action.required("c", FieldKind::digest("sha256")),
                        };
                    }
                } else if i == 1 {
                    action = action
                        .object(FieldKind::token())
                        .optional("x", FieldKind::one_of(["yes", "no"]));
                } else {
                    action = action.object(FieldKind::int(i64::MIN, i64::MAX));
                }
                builder = action.finish();
            }
            let schema = builder.build().unwrap();
            assert_eq!(schema.text(), TEXT);
            assert_eq!(RecordSchema::parse(schema.text()).unwrap(), schema);
        }
    }
}
macro_rules! parse_refusal {
    ($name:ident, $text:expr) => {
        #[test]
        fn $name() {
            refused(RecordSchema::parse(&$text));
        }
    };
}
parse_refusal!(
    unsorted_actions,
    "vigil.schema.v1 s\naction b object=id\naction a object=id"
);
parse_refusal!(
    unsorted_fields,
    "vigil.schema.v1 s\naction a object=id\nfield b required id\nfield a required id"
);
parse_refusal!(
    parse_duplicate_action,
    "vigil.schema.v1 s\naction a object=id\naction a object=id"
);
parse_refusal!(
    parse_duplicate_field,
    "vigil.schema.v1 s\naction a object=id\nfield a required id\nfield a optional id"
);
parse_refusal!(trailing_lf, format!("{TEXT}\n"));
parse_refusal!(crlf, TEXT.replace('\n', "\r\n"));
parse_refusal!(extra_whitespace, TEXT.replace("object=id", "object=id "));
parse_refusal!(blank_line, TEXT.replace("\naction b", "\n\naction b"));
parse_refusal!(malformed_grammar, TEXT.replace("required", "maybe"));
parse_refusal!(unknown_kind, TEXT.replace("object=id", "object=unknown"));
parse_refusal!(unsorted_enum, TEXT.replace("enum:no,yes", "enum:yes,no"));
parse_refusal!(noncanonical_integer, TEXT.replace("int:-1:1", "int:-1:+1"));
#[test]
fn digest_golden_and_kind_identity() {
    let text = &golden_text();
    assert_eq!(text, TEXT);
    let schema = RecordSchema::parse(text).unwrap();
    assert_eq!(
        schema.digest_string(),
        include_str!("../../tests/fixtures/audit/schema.digest").trim_end()
    );
    let mut input = b"vigil.audit.v1.schema\0".to_vec();
    input.extend(text.as_bytes());
    assert_eq!(schema.digest(), *blake3::hash(&input).as_bytes());
    assert_ne!(
        schema.digest(),
        RecordSchema::parse(&text.replace("field a required id", "field a required token"))
            .unwrap()
            .digest()
    );
}

#[test]
fn schema_linked_typed_record_golden() {
    use crate::audit::attributes::render_block;
    use crate::audit::{AttrValue, Entry, Record, RecordContext};
    use std::collections::BTreeMap;
    let schema = RecordSchema::parse(&golden_text()).unwrap();
    let kinds = BTreeMap::from([
        ("a".into(), FieldKind::id()),
        ("b".into(), FieldKind::int(-1, 1)),
        ("c".into(), FieldKind::digest("sha256")),
    ]);
    let values = [
        ("a", AttrValue::Id("ID:1".into())),
        ("b", AttrValue::Int(-1)),
        ("c", AttrValue::Digest([0xab; 32])),
    ];
    let block = render_block(
        &schema.digest(),
        &kinds,
        values.iter().map(|(k, v)| (*k, v)),
    )
    .unwrap();
    let record = Record::new_internal(
        RecordContext::new([0x11; 16], 0, 123, "svc", Record::genesis(&[0x11; 16])).host("host"),
        Entry::new("actor", "a", "id:1").details(&block),
    )
    .unwrap();
    assert_eq!(
        block.lines().next().unwrap(),
        format!("vigil.attrs.v1 {}", schema.digest_string())
    );
    assert_eq!(
        record.canonical(),
        include_bytes!("../../tests/fixtures/audit/schema-record.bin").as_slice()
    );
    assert_eq!(
        crate::audit::hex(&record.hash()),
        include_str!("../../tests/fixtures/audit/schema-record.hash").trim_end()
    );
    let line = crate::audit::sink::line(&record).unwrap();
    assert_eq!(
        line.as_slice(),
        include_bytes!("../../tests/fixtures/audit/schema-record.jsonl")
    );
    assert_eq!(
        Record::parse_line(&line).unwrap()[0].canonical(),
        record.canonical()
    );
}

fn golden_text() -> String {
    serde_json::from_str::<serde_json::Value>(include_str!(
        "../../tests/fixtures/audit/schema.json"
    ))
    .unwrap()["text"]
        .as_str()
        .unwrap()
        .to_owned()
}
