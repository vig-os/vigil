//! Additive rotation configuration is available to downstream callers.

use std::time::Duration;
use vigil::rotate::{RotationConfig, SignalRotation};
use vigil::{Config, Signal};

#[test]
fn additive_rotation_builders_are_public() {
    let signal = SignalRotation::new()
        .max_bytes(0)
        .max_segments(Some(0))
        .retention(Some(Duration::ZERO));
    let rotation = RotationConfig::default()
        .max_segments(None)
        .signal(Signal::Logs, signal.clone());
    assert_ne!(rotation, RotationConfig::default());
    let _config = Config::new("rotation-api")
        .max_segments(None)
        .signal_rotation(Signal::Logs, signal);
}
