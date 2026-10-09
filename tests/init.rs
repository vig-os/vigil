use serde_json::Value;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::Command,
    time::{Duration, SystemTime},
};

#[test]
fn child() {
    let Ok(mode) = std::env::var("VIGIL_INIT_TEST") else {
        return;
    };
    let dir = std::path::PathBuf::from(std::env::var_os("VIGIL_TEST_DIR").unwrap());
    let cfg = vigil::Config::new("test-service")
        .version("1.2.3")
        .revision("abc123");
    let cfg = if matches!(mode.as_str(), "env" | "xdg" | "home") {
        cfg
    } else {
        cfg.dir(&dir).max_bytes(1_000_000).retention_days(0)
    };
    let guard = cfg.init().unwrap();
    assert!(
        vigil::init("again")
            .unwrap_err()
            .to_string()
            .contains("global tracing subscriber")
    );
    assert!(vigil::init("../bad").is_err());
    let span = tracing::info_span!("inside");
    let _entered = span.enter();
    tracing::debug!("hidden debug");
    tracing::trace!("hidden trace");
    tracing::info!(text = "hello", boolean = true, signed = -42i64, unsigned = 42u64, float = 1.25, debug = ?vec![1,2], display = %"shown", "visible info");
    tracing::warn!("visible warn");
    tracing::error!("visible error");
    tracing::info!(target: "opentelemetry_test", "sdk internal");
    if mode == "nan" {
        tracing::info!(nan = f64::NAN, "non-finite");
    }
    drop(guard);
}

fn run(mode: &str, dir: &std::path::Path, extra: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", "child", "--nocapture"])
        .env("VIGIL_INIT_TEST", mode)
        .env("VIGIL_TEST_DIR", dir)
        .env("RUST_LOG", "info")
        .env_remove("VIGIL_DIR")
        .env_remove("VIGIL_MAX_BYTES")
        .env_remove("VIGIL_RETENTION_DAYS");
    for (key, value) in extra {
        cmd.env(key, value);
    }
    if mode == "xdg" {
        cmd.env("XDG_STATE_HOME", dir);
    }
    if mode == "home" {
        cmd.env_remove("XDG_STATE_HOME").env("HOME", dir);
    }
    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
fn temp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("vigil-init-{}-{name}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}
#[test]
fn logging_and_builder_precedence() {
    let dir = temp("logs");
    let old = dir.join("logs-20200101T000000.000000000Z.jsonl");
    fs::write(&old, "{}\n").unwrap();
    fs::File::options()
        .write(true)
        .open(&old)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(200 * 86400))
        .unwrap();
    run(
        "builder",
        &dir,
        &[
            ("VIGIL_DIR", "/dev/null/impossible"),
            ("VIGIL_MAX_BYTES", "1"),
            ("VIGIL_RETENTION_DAYS", "1"),
        ],
    );
    assert!(old.exists());
    assert_eq!(
        fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let path = dir.join("logs.jsonl");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let text = fs::read_to_string(path).unwrap();
    let mut count = 0;
    for line in text.lines() {
        let _: opentelemetry_proto::tonic::logs::v1::LogsData = serde_json::from_str(line).unwrap();
        let data: Value = serde_json::from_str(line).unwrap();
        let resource = &data["resourceLogs"][0];
        let attrs = resource["resource"]["attributes"].as_array().unwrap();
        for (key, value) in [
            ("service.name", "test-service"),
            ("service.version", "1.2.3"),
            ("vcs.ref.head.revision", "abc123"),
        ] {
            assert!(
                attrs
                    .iter()
                    .any(|a| a["key"] == key && a["value"]["stringValue"] == value)
            );
        }
        for key in ["host.name", "process.pid"] {
            assert!(attrs.iter().any(|a| a["key"] == key));
        }
        for scope in resource["scopeLogs"].as_array().unwrap() {
            assert!(
                !scope["scope"]["name"]
                    .as_str()
                    .unwrap_or_default()
                    .starts_with("opentelemetry")
            );
            for record in scope["logRecords"].as_array().unwrap() {
                assert_ne!(record["timeUnixNano"], "0");
                assert!(record["severityNumber"].as_u64().unwrap() >= 9);
                assert!(record["traceId"].as_str().unwrap_or_default().is_empty());
                assert!(record["spanId"].as_str().unwrap_or_default().is_empty());
                count += 1;
            }
        }
    }
    assert_eq!(count, 3);
    assert!(!text.contains("hidden"));
    fs::remove_dir_all(dir).unwrap();
}
#[test]
fn storage_failure_warns_once_and_logs_to_stderr() {
    let dir = temp("fallback");
    let file = dir.join("file");
    fs::write(&file, "").unwrap();
    let output = run("fallback", &file.join("impossible"), &[]);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(stderr.matches("falling back to stderr").count(), 1);
    assert!(stderr.contains("visible info"));
    assert!(!stderr.contains("hidden debug"));
    fs::remove_dir_all(dir).unwrap();
}
#[test]
fn environment_overrides_and_zero_retention() {
    let dir = temp("env");
    let old = dir.join("logs-20200101T000000.000000000Z.jsonl");
    fs::write(&old, "{}\n").unwrap();
    fs::File::options()
        .write(true)
        .open(&old)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(200 * 86400))
        .unwrap();
    run(
        "env",
        &dir,
        &[
            ("VIGIL_DIR", dir.to_str().unwrap()),
            ("VIGIL_RETENTION_DAYS", "0"),
            ("VIGIL_MAX_BYTES", "1"),
        ],
    );
    assert!(old.exists());
    assert!(dir.join("logs.jsonl").exists());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn non_finite_field_survives() {
    let dir = temp("nan");
    run("nan", &dir, &[]);
    let text = fs::read_to_string(dir.join("logs.jsonl")).unwrap();
    let values: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(!values.is_empty());
    assert!(text.contains(r#""doubleValue":"NaN""#));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn xdg_and_home_paths() {
    for (mode, relative) in [
        ("xdg", "test-service"),
        ("home", ".local/state/test-service"),
    ] {
        let dir = temp(mode);
        run(mode, &dir, &[]);
        assert!(dir.join(relative).join("logs.jsonl").exists());
        fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn read_only_directory_falls_back() {
    let dir = temp("readonly");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
    let output = run("readonly", &dir.join("state"), &[]);
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        String::from_utf8(output.stderr)
            .unwrap()
            .matches("falling back to stderr")
            .count(),
        1
    );
    fs::remove_dir_all(dir).unwrap();
}
