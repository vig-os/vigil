use std::{
    fs,
    process::{Command, Stdio},
};

#[test]
fn child() {
    let Ok(mode) = std::env::var("REVIEW_MODE") else {
        return;
    };
    let dir = std::path::PathBuf::from(std::env::var_os("REVIEW_DIR").unwrap());
    if mode == "duplicate" {
        tracing::subscriber::set_global_default(tracing_subscriber::registry()).unwrap();
        assert!(
            vigil::Config::new("review")
                .dir(dir.join("untouched"))
                .init()
                .is_err()
        );
        assert!(!dir.join("untouched").exists());
        return;
    }
    let cfg = vigil::Config::new("review");
    let cfg = if mode == "path" {
        cfg
    } else {
        cfg.dir(if mode == "full" || mode == "failedpath" {
            dir.join("file/state")
        } else {
            dir.clone()
        })
    };
    let cfg = if mode == "tiny" {
        cfg.queue_size(16)
    } else {
        cfg
    };
    let guard = cfg.init().unwrap();
    if mode == "burst" || mode == "tiny" {
        for i in 0..10_000 {
            tracing::info!(i, "burst");
        }
    }
    tracing::warn!(target: "opentelemetry_test", "sdk warning probe");
    tracing::info!(target: "opentelemetry_test", "sdk info probe");
    if mode == "lock" {
        fs::write(dir.join("ready"), "").unwrap();
        let start = std::time::Instant::now();
        while !dir.join("go").exists() {
            assert!(start.elapsed().as_secs() < 10);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        tracing::info!("blocked export");
        let start = std::time::Instant::now();
        drop(guard);
        assert!(start.elapsed().as_secs_f64() >= 4.5 && start.elapsed().as_secs_f64() < 7.0);
    } else {
        drop(guard);
    }
}
fn run(mode: &str, envs: &[(&str, &str)]) -> (std::path::PathBuf, std::process::Output) {
    let dir = std::env::temp_dir().join(format!("vigil-review-{}-{mode}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("file"), "").unwrap();
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", "child", "--nocapture"])
        .env("REVIEW_MODE", mode)
        .env("REVIEW_DIR", &dir)
        .env("HOME", &dir)
        .env("RUST_LOG", "info");
    for key in [
        "VIGIL_DIR",
        "VIGIL_MAX_BYTES",
        "VIGIL_RETENTION_DAYS",
        "VIGIL_QUEUE_SIZE",
        "XDG_STATE_HOME",
    ] {
        cmd.env_remove(key);
    }
    for (k, v) in envs {
        cmd.env(k, v);
    }
    if mode == "full" {
        cmd.stderr(Stdio::from(
            fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .unwrap(),
        ));
    }
    let locker = (mode == "lock").then(|| {
        let dir = dir.clone();
        std::thread::spawn(move || {
            let start = std::time::Instant::now();
            while !dir.join("ready").exists() {
                assert!(start.elapsed().as_secs() < 15);
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            let lock = fs::File::open(&dir).unwrap();
            lock.lock().unwrap();
            fs::write(dir.join("go"), "").unwrap();
            std::thread::sleep(std::time::Duration::from_secs(7));
            lock.unlock().unwrap();
        })
    });
    let output = cmd.output().unwrap();
    if let Some(locker) = locker {
        locker.join().unwrap();
    }
    (dir, output)
}
#[test]
fn stderr_full_does_not_panic() {
    let (d, o) = run("full", &[]);
    assert!(o.status.success(), "{:?}", o);
    fs::remove_dir_all(d).unwrap();
}
#[test]
fn duplicate_has_no_filesystem_side_effects() {
    let (d, o) = run("duplicate", &[]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stdout));
    fs::remove_dir_all(d).unwrap();
}
#[test]
fn defaults_keep_ten_thousand_records() {
    let (d, o) = run("burst", &[]);
    assert!(o.status.success());
    let text = fs::read_to_string(d.join("logs.jsonl")).unwrap();
    let count: usize = text
        .lines()
        .map(|s| {
            let v: serde_json::Value = serde_json::from_str(s).unwrap();
            v["resourceLogs"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|r| r["scopeLogs"].as_array().unwrap())
                .map(|s| s["logRecords"].as_array().unwrap().len())
                .sum::<usize>()
        })
        .sum();
    assert_eq!(count, 10_000);
    assert!(!text.contains("sdk warning probe"));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("sdk warning probe"));
    assert!(!err.contains("sdk info probe"));
    fs::remove_dir_all(d).unwrap();
}
#[test]
fn tiny_queue_warns() {
    let (d, o) = run("tiny", &[("VIGIL_QUEUE_SIZE", "65536")]);
    assert!(o.status.success());
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("dropped") || err.contains("full"), "{err}");
    fs::remove_dir_all(d).unwrap();
}
#[test]
fn bad_environment_warns() {
    for (key, value) in [
        ("VIGIL_MAX_BYTES", "abc"),
        ("VIGIL_MAX_BYTES", "-5"),
        ("VIGIL_MAX_BYTES", "0"),
        ("VIGIL_RETENTION_DAYS", "x"),
        ("VIGIL_QUEUE_SIZE", "x"),
    ] {
        let (d, o) = run("badenv", &[(key, value)]);
        assert!(o.status.success());
        let err = String::from_utf8_lossy(&o.stderr);
        assert_eq!(err.matches(key).count(), 1, "{err}");
        assert!(err.contains(value));
        fs::remove_dir_all(d).unwrap();
    }
}
#[test]
fn empty_override_and_relative_xdg_use_home() {
    let (d, o) = run("path", &[("VIGIL_DIR", ""), ("XDG_STATE_HOME", "relative")]);
    assert!(o.status.success());
    assert!(d.join(".local/state/review/logs.jsonl").exists());
    fs::remove_dir_all(d).unwrap();
}
#[test]
fn fallback_names_failed_path() {
    let (d, o) = run("failedpath", &[]);
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains(d.join("file/state").to_str().unwrap()));
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn blocked_shutdown_warns_and_returns_within_bound() {
    let (d, o) = run("lock", &[]);
    assert!(
        o.status.success(),
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(String::from_utf8_lossy(&o.stderr).contains("remaining records may be lost"));
    fs::remove_dir_all(d).unwrap();
}
