//! Process resource identity for both installation paths.
use serde_json::Value;
use std::{fs, process::Command};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

struct TempDir(std::path::PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        // Match the property tests' cleanup guard: never panic during unwinding.
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn temporary_directory_is_removed_when_an_assertion_fails() {
    let path = std::env::temp_dir().join(format!("vigil-resource-cleanup-{}", std::process::id()));
    let temp = TempDir(path.clone());
    fs::create_dir_all(&path).unwrap();
    let failure = std::panic::catch_unwind(move || {
        let _temp = temp;
        assert_eq!(1, 2, "exercise assertion failure cleanup");
    });
    assert!(failure.is_err());
    assert!(!path.exists());
}

#[test]
fn child() {
    let Ok(mode) = std::env::var("VIGIL_IDENTITY_MODE") else {
        return;
    };
    let dir = std::path::PathBuf::from(std::env::var_os("VIGIL_IDENTITY_DIR").unwrap());
    let config = vigil::Config::new("identity")
        .dir(&dir)
        .default_filter("info");
    let guard = if mode == "init" {
        config.init().unwrap()
    } else {
        let (layer, guard) = config.layer().unwrap();
        tracing_subscriber::registry().with(layer).init();
        guard
    };
    for _ in 0..2 {
        tracing::info!("identity");
        guard.flush().unwrap();
    }
    guard.shutdown().unwrap();
}

fn run(mode: &str, dir: &std::path::Path) -> String {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child", "--nocapture"])
        .env("VIGIL_IDENTITY_MODE", mode)
        .env("VIGIL_IDENTITY_DIR", dir)
        .env_remove("RUST_LOG")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let text = fs::read_to_string(dir.join("logs.jsonl")).unwrap();
    let mut ids = Vec::new();
    for line in text.lines() {
        let value: Value = serde_json::from_str(line).unwrap();
        let attrs = value["resourceLogs"][0]["resource"]["attributes"]
            .as_array()
            .unwrap();
        let id = attrs
            .iter()
            .find(|a| a["key"] == "service.instance.id")
            .expect("shared resource must have service.instance.id")["value"]["stringValue"]
            .as_str()
            .unwrap();
        assert_eq!(id.len(), 36);
        assert_eq!(id.as_bytes()[14], b'4'); // version nibble
        assert!(matches!(id.as_bytes()[19], b'8' | b'9' | b'a' | b'b')); // RFC variant bits 10
        for (index, byte) in id.bytes().enumerate() {
            if [8, 13, 18, 23].contains(&index) {
                assert_eq!(byte, b'-');
            } else {
                assert!(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
            }
        }
        ids.push(id.to_owned());
    }
    assert_eq!(ids.len(), 2);
    assert!(ids.iter().all(|id| id == &ids[0]));
    ids.remove(0)
}

#[test]
fn init_and_layer_generate_distinct_rfc9562_v4_resources() {
    let root = TempDir(
        std::env::temp_dir().join(format!("vigil-resource-identity-{}", std::process::id())),
    );
    fs::create_dir_all(&root.0).unwrap();
    let init = run("init", &root.0.join("init"));
    let second_init = run("init", &root.0.join("second-init"));
    let layer = run("layer", &root.0.join("layer"));
    assert_ne!(init, second_init);
    assert_ne!(init, layer);
    assert_ne!(second_init, layer);
}
