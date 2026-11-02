//! Consumer compile check for the typed attribute surface.
#![cfg(feature = "audit")]
use vigil::audit::{AttrValue, FieldKind};

#[test]
fn typed_attribute_public_surface() {
    let kinds = [
        FieldKind::id(),
        FieldKind::token(),
        FieldKind::one_of(["approved", "denied"]),
        FieldKind::int(-1, 1),
        FieldKind::digest("sha256"),
    ];
    assert_eq!(kinds[0], FieldKind::id());
    assert_eq!(AttrValue::Digest([0; 32]), AttrValue::Digest([0; 32]));
    assert_ne!(AttrValue::Id("x".into()), AttrValue::Token("x".into()));
    assert_eq!(AttrValue::Int(-1), AttrValue::Int(-1));
}
