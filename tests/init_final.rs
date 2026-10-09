use std::{fs, process::Command};
struct Logger;
impl log::Log for Logger {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, _: &log::Record<'_>) {}
    fn flush(&self) {}
}
static LOGGER: Logger = Logger;
#[test]
fn child() {
    let Ok(mode) = std::env::var("FINAL_MODE") else {
        return;
    };
    let dir = std::path::PathBuf::from(std::env::var_os("FINAL_DIR").unwrap());
    if mode == "race" {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let workers: Vec<_> = (0..2)
            .map(|i| {
                let barrier = barrier.clone();
                let path = dir.join(i.to_string());
                std::thread::spawn(move || {
                    barrier.wait();
                    let result = vigil::Config::new("race").dir(&path).init();
                    (path, result)
                })
            })
            .collect();
        let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|(_, r)| r.is_ok()).count(), 1);
        for (path, result) in &results {
            if result.is_err() {
                assert!(!path.exists(), "losing init created {}", path.display());
            }
        }
        return;
    }
    if mode == "logger" {
        log::set_logger(&LOGGER).unwrap();
    }
    let cfg = vigil::Config::new("final");
    let cfg = if mode == "builder" {
        cfg.queue_size(usize::MAX)
    } else {
        cfg
    };
    let cfg = if mode == "relative" {
        cfg
    } else {
        cfg.dir(&dir)
    };
    let guard = cfg.init().unwrap();
    tracing::info!("still alive");
    drop(guard);
}
fn run(mode: &str, envs: &[(&str, &str)]) -> (std::path::PathBuf, std::process::Output) {
    let dir = std::env::temp_dir().join(format!("vigil-final-{}-{mode}", std::process::id()));
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", "child", "--nocapture"])
        .env("FINAL_MODE", mode)
        .env("FINAL_DIR", &dir)
        .env("RUST_LOG", "info");
    for k in [
        "VIGIL_DIR",
        "VIGIL_MAX_BYTES",
        "VIGIL_QUEUE_SIZE",
        "VIGIL_RETENTION_DAYS",
        "VIGIL_VCS_REVISION",
        "XDG_STATE_HOME",
        "HOME",
    ] {
        cmd.env_remove(k);
    }
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    (dir, out)
}
#[test]
fn existing_log_logger_keeps_tracing_alive() {
    let (dir, out) = run("logger", &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        fs::read_to_string(dir.join("logs.jsonl"))
            .unwrap()
            .contains("still alive")
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stderr)
            .matches("a `log` logger is already installed")
            .count(),
        1
    );
    fs::remove_dir_all(dir).unwrap();
}
#[test]
fn huge_queues_are_capped() {
    for (mode, envs) in [
        ("env", vec![("VIGIL_QUEUE_SIZE", "18446744073709551615")]),
        ("builder", vec![]),
        ("trillion", vec![("VIGIL_QUEUE_SIZE", "1000000000000")]),
    ] {
        let (dir, out) = run(mode, &envs);
        assert!(out.status.success(), "{:?}", out);
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("1048576")
                && err.contains(if mode == "trillion" {
                    "1000000000000"
                } else {
                    "18446744073709551615"
                }),
            "{err}"
        );
        assert!(
            fs::read_to_string(dir.join("logs.jsonl"))
                .unwrap()
                .contains("still alive")
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
#[test]
fn empty_environment_is_unset() {
    let (dir, out) = run(
        "empty",
        &[
            ("VIGIL_DIR", ""),
            ("VIGIL_MAX_BYTES", ""),
            ("VIGIL_QUEUE_SIZE", ""),
            ("VIGIL_RETENTION_DAYS", ""),
            ("VIGIL_VCS_REVISION", ""),
        ],
    );
    assert!(out.status.success());
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !fs::read_to_string(dir.join("logs.jsonl"))
            .unwrap()
            .contains("vcs.ref.head.revision")
    );
    fs::remove_dir_all(dir).unwrap();
}
#[test]
fn relative_home_is_rejected_and_explained() {
    let (_, out) = run(
        "relative",
        &[
            ("HOME", "relative-final-home"),
            ("XDG_STATE_HOME", "relative-final-xdg"),
        ],
    );
    assert!(out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("neither")
            && err.contains("relative-final-home")
            && err.contains("relative-final-xdg"),
        "{err}"
    );
}
#[test]
fn relative_xdg_without_home_is_explained() {
    let (_, out) = run("relative", &[("XDG_STATE_HOME", "relative-final-xdg")]);
    assert!(out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("relative-final-xdg") && err.contains("rejected"),
        "{err}"
    );
}

#[test]
fn concurrent_initializers_only_create_winner_storage() {
    let (dir, out) = run("race", &[]);
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    fs::remove_dir_all(dir).unwrap();
}
