//! Public operator rotation and exact-head checkpoint integration.
#![cfg(feature = "audit")]
use std::sync::Arc;
use vigil::audit::{AuditConfig, AuditErrorKind, Entry, KeyFileSigner, Signer, keygen};

#[test]
fn operator_public_paths() {
    let dir = std::env::temp_dir().join(format!("vigil-operator-public-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let old_path = dir.join("old.seed");
    let new_path = dir.join("new.seed");
    keygen(&old_path).unwrap();
    keygen(&new_path).unwrap();
    let old = Arc::new(KeyFileSigner::load(&old_path).unwrap());
    let new = Arc::new(KeyFileSigner::load(&new_path).unwrap());
    let config = AuditConfig::new("svc").dir(dir.join("trail"));
    let writer = config.clone().create(old).unwrap();
    writer.record(&Entry::new("a", "change", "o")).unwrap();
    let head = writer.close().unwrap();
    let bound = (head.seq(), head.hash());
    let (receipt, cp) = config
        .clone()
        .rotate(new.clone(), bound, bound, "operator", "scheduled")
        .unwrap();
    assert_eq!(receipt.seq(), head.seq() + 1);
    assert_eq!(receipt.unsigned_records(), 0);
    assert_eq!(cp.seq(), receipt.seq() + 1);
    assert_eq!(cp.key_id(), new.public_key());
    let next = config
        .clone()
        .checkpoint(new.clone(), (cp.seq(), cp.hash()))
        .unwrap();
    assert_eq!(next.seq(), cp.seq() + 1);
    assert_eq!(
        config
            .checkpoint(new, (cp.seq(), cp.hash()))
            .unwrap_err()
            .kind(),
        AuditErrorKind::HeadMismatch
    );
    std::fs::remove_dir_all(dir).unwrap();
}
