//! CP2 acceptance: every refusal observes the lock, bytes and sequence contract.
use super::*;
use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "vigil-schema-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn schema() -> RecordSchema {
    RecordSchema::builder("decisions")
        .action("approve")
        .required("tenant", FieldKind::id())
        .optional("commitment", FieldKind::digest("sha256"))
        .build()
        .unwrap()
}
fn entry() -> Entry {
    Entry::new("p_01", "approve", "o_01").attr("tenant", AttrValue::Id("t_01".into()))
}
fn signer() -> Arc<dyn Signer> {
    Arc::new(KeyFileSigner::from_hex(&"11".repeat(32)).unwrap())
}
fn config(t: &Temp) -> AuditConfig {
    AuditConfig::new("svc").dir(&t.0).schema(schema())
}
fn refused(entry: Entry) {
    let t = Temp::new();
    let trail = config(&t).create(signer()).unwrap();
    let path = t.0.join("audit.jsonl");
    let bytes = fs::read(&path).unwrap();
    let locks = crate::rotate::LOCK_ACQUISITIONS.with(|v| v.get());
    assert_eq!(
        trail.record(&entry).unwrap_err().kind(),
        AuditErrorKind::InvalidEntry
    );
    assert_eq!(crate::rotate::LOCK_ACQUISITIONS.with(|v| v.get()), locks);
    assert_eq!(fs::read(path).unwrap(), bytes);
    assert_eq!(trail.record(&self::entry()).unwrap().seq(), 1);
}
#[test]
fn p6_actor() {
    refused(Entry {
        actor: "Jane Doe".into(),
        ..entry()
    });
}
#[test]
fn p6_action() {
    refused(Entry {
        action: "unknown".into(),
        ..entry()
    });
}
#[test]
fn p6_object() {
    refused(Entry::new("p_01", "approve", "a sentence").attr("tenant", AttrValue::Id("t".into())));
}
#[test]
fn p6_reason() {
    // Valid v1 text: only the schema prohibition on a reason is violated.
    refused(entry().reason("change reason"));
}
#[test]
fn p6_text_values() {
    refused(entry().before(Value::Text("before".into())));
    refused(entry().after(Value::Text("after".into())));
}
#[test]
fn p6_details() {
    // Valid v1 text: only the schema prohibition on caller details is violated.
    refused(entry().details("application details"));
}
#[test]
fn p6_required_key() {
    refused(Entry::new("p_01", "approve", "o_01"));
}
#[test]
fn p6_unknown_key() {
    refused(entry().attr("unknown", AttrValue::Id("x".into())));
}
#[test]
fn p6_wrong_kind() {
    refused(entry().attr("tenant", AttrValue::Token("t".into())));
}
#[test]
fn p7_schema_required() {
    let t = Temp::new();
    let trail = AuditConfig::new("svc").dir(&t.0).create(signer()).unwrap();
    assert_eq!(
        trail.record(&entry()).unwrap_err().kind(),
        AuditErrorKind::InvalidEntry
    );
}
#[test]
fn p4_primitive_refuses_attributes() {
    let context = RecordContext::new([1; 16], 1, 1, "svc", [0; 32]);
    assert_eq!(
        Record::new(context, entry()).unwrap_err().kind(),
        AuditErrorKind::InvalidEntry
    );
}
#[test]
fn typed_roundtrip() {
    let t = Temp::new();
    let trail = config(&t).create(signer()).unwrap();
    let entry = entry()
        .attr("tenant", AttrValue::Id("replacement".into()))
        .attr("commitment", AttrValue::Digest([7; 32]))
        .before(Value::Digest([8; 32]))
        .after(Value::Digest([9; 32]));
    let receipt = trail.record(&entry).unwrap();
    let reader = storage::TrailReader::open(&t.0, trail.trail(), None).unwrap();
    // Use the existing line reader; decoded entries have only their v1 details.
    let bytes = fs::read(t.0.join("audit.jsonl")).unwrap();
    let record = bytes
        .split(|b| *b == b'\n')
        .filter(|b| !b.is_empty())
        .flat_map(|b| Record::parse_line(b).unwrap())
        .find(|r| r.context.seq == receipt.seq())
        .unwrap();
    assert_eq!(record.hash(), receipt.hash());
    let format::Kind::Entry(decoded) = &record.kind else {
        panic!("entry expected")
    };
    schema_validation::validate(&schema(), decoded).unwrap();
    let kinds = schema().actions[0]
        .fields
        .iter()
        .map(|(k, _, v)| (k.clone(), v.clone()))
        .collect();
    let (_, attrs) = attributes::parse_block(decoded.details.as_deref().unwrap(), &kinds).unwrap();
    assert_eq!(attrs, entry.attrs);
    drop(reader);
}
#[test]
fn p8_resume() {
    for (actor, reason, valid) in [
        ("Jane Doe", "ticket_1", false),
        ("op_1", "a sentence", false),
        ("op_1", "ticket_1", true),
    ] {
        let t = Temp::new();
        let closed = config(&t).create(signer()).unwrap().close().unwrap();
        let result = config(&t).resume(
            signer(),
            (closed.seq(), closed.hash()),
            closed.seq(),
            actor,
            reason,
        );
        if valid {
            result.unwrap().0.close().unwrap();
        } else {
            assert_eq!(result.unwrap_err().kind(), AuditErrorKind::InvalidEntry);
        }
    }
}
#[test]
fn p8_rotate() {
    for (actor, reason, valid) in [
        ("Jane Doe", "ticket_1", false),
        ("op_1", "a sentence", false),
        ("op_1", "ticket_1", true),
    ] {
        let t = Temp::new();
        let closed = config(&t).create(signer()).unwrap().close().unwrap();
        let new_key = Arc::new(KeyFileSigner::from_hex(&"22".repeat(32)).unwrap());
        let head = (closed.seq(), closed.hash());
        let result = config(&t).rotate(new_key, head, head, actor, reason);
        if valid {
            result.unwrap();
        } else {
            assert_eq!(result.unwrap_err().kind(), AuditErrorKind::InvalidEntry);
        }
    }
}

#[test]
fn object_kind_spellings() {
    for (kind, good, bad) in [
        (FieldKind::token(), "read", "READ".to_owned()),
        (FieldKind::one_of(["yes", "no"]), "yes", "maybe".to_owned()),
        (FieldKind::int(-2, 2), "-2", "-0".to_owned()),
        (
            FieldKind::digest("sha256"),
            &format!("sha256:{}", "ab".repeat(32)),
            format!("blake3:{}", "ab".repeat(32)),
        ),
    ] {
        let schema = RecordSchema::builder("objects")
            .action("read")
            .object(kind)
            .build()
            .unwrap();
        let t = Temp::new();
        let trail = AuditConfig::new("svc")
            .dir(&t.0)
            .schema(schema)
            .create(signer())
            .unwrap();
        assert_eq!(
            trail
                .record(&Entry::new("p", "read", bad))
                .unwrap_err()
                .kind(),
            AuditErrorKind::InvalidEntry
        );
        trail.record(&Entry::new("p", "read", good)).unwrap();
    }
}

#[test]
fn reopened_and_resumed_handles_keep_schema() {
    let t = Temp::new();
    let closed = config(&t).create(signer()).unwrap().close().unwrap();
    let trail = config(&t).open(signer()).unwrap();
    assert_eq!(
        trail
            .record(&entry().reason("forbidden"))
            .unwrap_err()
            .kind(),
        AuditErrorKind::InvalidEntry
    );
    drop(trail);
    // Drop may write a checkpoint; read the exact head rather than guessing it.
    let bytes = fs::read(t.0.join("audit.jsonl")).unwrap();
    let last = bytes
        .split(|b| *b == b'\n')
        .filter(|b| !b.is_empty())
        .flat_map(|b| Record::parse_line(b).unwrap())
        .last()
        .unwrap();
    assert!(last.context.seq >= closed.seq());
    let (trail, _, _) = config(&t)
        .resume(
            signer(),
            (last.context.seq, last.hash()),
            last.context.seq,
            "op_1",
            "ticket_1",
        )
        .unwrap();
    assert_eq!(
        trail
            .record(&entry().reason("forbidden"))
            .unwrap_err()
            .kind(),
        AuditErrorKind::InvalidEntry
    );
    trail.record(&entry()).unwrap();
}

#[test]
fn untyped_operator_text_remains_permitted() {
    let t = Temp::new();
    let untyped = || AuditConfig::new("svc").dir(&t.0);
    let closed = untyped().create(signer()).unwrap().close().unwrap();
    let head = (closed.seq(), closed.hash());
    let new_key = Arc::new(KeyFileSigner::from_hex(&"22".repeat(32)).unwrap());
    let (_, checkpoint) = untyped()
        .rotate(new_key.clone(), head, head, "Jane Doe", "a sentence")
        .unwrap();
    untyped()
        .resume(
            new_key,
            (checkpoint.seq(), checkpoint.hash()),
            checkpoint.seq(),
            "Jane Doe",
            "a sentence",
        )
        .unwrap()
        .0
        .close()
        .unwrap();
}
