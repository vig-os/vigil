//! Consumer compile check for the CP2 writer surface.
#![cfg(feature = "audit")]
use vigil::audit::{AttrValue, AuditConfig, Entry, FieldKind, RecordSchema};

#[test]
fn typed_writer_public_surface() {
    let schema = RecordSchema::builder("sample")
        .action("read")
        .required("tenant", FieldKind::id())
        .build()
        .unwrap();
    let config = AuditConfig::new("svc").schema(schema);
    let entry = Entry::new("p_1", "read", "o_1").attr("tenant", AttrValue::Id("t_1".into()));
    let _ = (config, entry);
}
