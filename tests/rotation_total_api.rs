//! The total cap is an additive builder API with an explicit unlimited value.
use vigil::Config;
use vigil::rotate::RotationConfig;

#[test]
fn total_cap_builders_are_additive() {
    let _ = Config::new("api")
        .max_total_bytes(Some(0))
        .max_total_bytes(None);
    assert_eq!(
        RotationConfig::default().max_total_bytes(None),
        RotationConfig::default()
    );
    assert_ne!(
        RotationConfig::default().max_total_bytes(Some(0)),
        RotationConfig::default()
    );
}
