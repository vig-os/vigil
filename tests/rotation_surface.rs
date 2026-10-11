use std::{fs, time::Duration};
use vigil::rotate::{RotatingFile, RotationConfig, segments};

#[test]
fn rotation_builder_clamps_zero_and_retention_none_keeps_segments() {
    let dir = std::env::temp_dir().join(format!("vigil-builder-{}", std::process::id()));
    let config = RotationConfig::default().max_bytes(0).retention(None);
    assert_eq!(
        config,
        RotationConfig::default().max_bytes(1).retention(None),
        "zero and one must produce the same configuration, not merely similar rotations"
    );
    let copy = config.clone();
    assert_eq!(config, copy);
    let file = RotatingFile::open(&dir, "logs", config).unwrap();
    file.append(b"first").unwrap();
    file.append(b"second").unwrap();
    assert_eq!(segments(&dir, "logs").unwrap().len(), 2);
    drop(file);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn explicit_zero_duration_prunes_rotated_segments() {
    let dir = std::env::temp_dir().join(format!("vigil-zero-retention-{}", std::process::id()));
    let file = RotatingFile::open(
        &dir,
        "logs",
        RotationConfig::default()
            .max_bytes(1)
            .retention(Some(Duration::ZERO)),
    )
    .unwrap();
    file.append(b"first").unwrap();
    file.append(b"second").unwrap();
    assert_eq!(segments(&dir, "logs").unwrap().len(), 1);
    drop(file);
    fs::remove_dir_all(dir).unwrap();
}
