//! Public record-schema API contract.
#![cfg(feature = "audit")]

use vigil::audit::{ActionFields, AuditErrorKind, FieldKind, RecordSchema, RecordSchemaBuilder};

#[test]
fn validated_schema_public_surface() {
    let builder: RecordSchemaBuilder = RecordSchema::builder("sample");
    assert_eq!(
        builder.clone().build().unwrap_err().kind(),
        AuditErrorKind::InvalidConfig
    );
    let fields: ActionFields = builder.action("read");
    let schema = fields
        .required("tenant", FieldKind::id())
        .optional("count", FieldKind::int(0, 10))
        .build()
        .unwrap();
    assert_eq!(RecordSchema::parse(schema.text()).unwrap(), schema);
    assert_eq!(schema.name(), "sample");
    assert_eq!(schema.digest_string().len(), 71);
    assert_eq!(schema.digest().len(), 32);
}
