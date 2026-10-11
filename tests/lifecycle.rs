use std::{
    fs,
    process::Command,
    time::{Duration, Instant},
};
use tracing_subscriber::prelude::*;
use vigil::{Config, FlushErrorKind, Signal};

#[test]
fn child() {
    let Ok(mode) = std::env::var("VIGIL_LIFECYCLE_MODE") else {
        return;
    };
    let dir = std::path::PathBuf::from(std::env::var_os("VIGIL_LIFECYCLE_DIR").unwrap());
    if mode == "fallback" {
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("file"), "").unwrap();
        let guard = Config::new("fallback")
            .dir(dir.join("file/state"))
            .init()
            .unwrap();
        assert!(guard.dir().is_none());
        guard.flush().unwrap();
        guard.shutdown().unwrap();
        return;
    }
    let (layer, guard) = Config::new("lifecycle")
        .dir(&dir)
        .queue_size(4)
        .layer()
        .unwrap();
    tracing_subscriber::registry()
        .with(layer)
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    if mode.starts_with("overflow") {
        let lock = fs::File::open(&dir).unwrap();
        let mut lost = 0;
        for _ in 0..2 {
            lock.lock().unwrap();
            for _ in 0..50 {
                tracing::info!("overflow burst");
            }
            lock.unlock().unwrap();
            let error = guard.flush().unwrap_err();
            assert_eq!(error.kind(), FlushErrorKind::DataLost);
            assert!(error.lost(Signal::Logs) > 0);
            lost += error.lost(Signal::Logs);
        }
        let lines = fs::read_to_string(dir.join("logs.jsonl")).unwrap();
        assert_eq!(lost + lines.matches("overflow burst").count() as u64, 100);
        if mode == "overflow_twice" {
            drop(guard);
        } else {
            guard.shutdown().unwrap();
        }
        return;
    }
    if matches!(
        mode.as_str(),
        "timeout" | "flush_timeout" | "concurrent_flush"
    ) {
        let lock = fs::File::open(&dir).unwrap();
        lock.lock().unwrap();
        tracing::info!("blocked export");
        let started = Instant::now();
        if mode == "timeout" {
            let error = guard
                .shutdown_with_timeout(Duration::from_millis(25))
                .unwrap_err();
            assert_eq!(error.kind(), FlushErrorKind::Timeout);
            assert!(started.elapsed() < Duration::from_secs(2));
            assert_eq!(
                error.lost(Signal::Logs),
                0,
                "blocked records are not certainly lost"
            );
            lock.unlock().unwrap();
        } else if mode == "concurrent_flush" {
            std::thread::scope(|scope| {
                let first = scope.spawn(|| guard.flush().unwrap_err());
                let second = scope.spawn(|| guard.flush().unwrap_err());
                for error in [first.join().unwrap(), second.join().unwrap()] {
                    assert_eq!(error.kind(), FlushErrorKind::Timeout);
                    assert_eq!(error.lost(Signal::Logs), 0);
                }
            });
            assert!(started.elapsed() >= Duration::from_secs(5));
            assert!(
                started.elapsed() < Duration::from_secs(8),
                "flushes must not serialize their timeout budgets"
            );
            lock.unlock().unwrap();
            guard.flush().unwrap();
            guard.shutdown().unwrap();
        } else {
            let error = guard.flush().unwrap_err();
            assert_eq!(error.kind(), FlushErrorKind::Timeout);
            assert!(started.elapsed() >= Duration::from_secs(5));
            assert!(started.elapsed() < Duration::from_secs(8));
            lock.unlock().unwrap();
            guard.flush().unwrap();
            guard.shutdown().unwrap();
        }
        // A timed-out SDK worker may finish once the directory lock is released.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !fs::read_to_string(dir.join("logs.jsonl"))
            .unwrap()
            .contains("blocked export")
        {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        return;
    }
    tracing::info!("durable checkpoint");
    guard.flush().unwrap();
    assert!(
        fs::read_to_string(dir.join("logs.jsonl"))
            .unwrap()
            .contains("durable checkpoint")
    );
    if mode == "success" {
        tracing::info!("record after flush");
        guard.shutdown().unwrap();
        for _ in 0..10 {
            tracing::info!("rejected after explicit shutdown");
        }
        let lines = vigil::rotate::read_since(&dir, "logs", None)
            .unwrap()
            .join("\n");
        assert!(lines.contains("record after flush"));
        assert!(!lines.contains("rejected after explicit shutdown"));
        assert_eq!(
            Config::new("again").init().unwrap_err().kind(),
            vigil::InitErrorKind::AlreadyRunning
        );
        return;
    }
    fs::remove_file(dir.join("logs.jsonl")).unwrap();
    fs::create_dir(dir.join("logs.jsonl")).unwrap();
    tracing::info!("failed export");
    let error = guard.flush().unwrap_err();
    assert_eq!(error.kind(), FlushErrorKind::Failed);
    assert_eq!(error.lost(Signal::Logs), 1);
    assert_eq!(error.lost(Signal::Metrics), 0);
    assert_eq!(error.lost(Signal::Traces), 0);
    guard.flush().unwrap();
    tracing::info!("shutdown export failure");
    let error = guard.shutdown().unwrap_err();
    assert_eq!(error.kind(), FlushErrorKind::Failed);
    assert_eq!(error.lost(Signal::Logs), 1);
}

#[test]
fn lifecycle_reports_period_losses_and_stderr_fallback_succeeds() {
    for mode in [
        "loss",
        "fallback",
        "success",
        "timeout",
        "flush_timeout",
        "concurrent_flush",
    ] {
        let out = run(mode, "info");
        if mode == "loss" {
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(stderr.matches("runtime log export failed").count(), 1);
            assert!(!stderr.contains("vigil: log shutdown:"), "{stderr}");
            assert!(!stderr.contains("runtime log export losses"), "{stderr}");
        }
    }
}

fn run(mode: &str, filter: &str) -> std::process::Output {
    let dir = std::env::temp_dir().join(format!("vigil-{mode}-{}", std::process::id()));
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child", "--nocapture"])
        .env("VIGIL_LIFECYCLE_MODE", mode)
        .env("VIGIL_LIFECYCLE_DIR", &dir)
        .env("RUST_LOG", filter)
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("1 passed;"),
        "{out:?}"
    );
    fs::remove_dir_all(dir).unwrap();
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}
#[test]
fn overflow_twice() {
    let out = run("overflow_twice", "info");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("log shutdown: DataLost; dropped records:")
    );
}
#[test]
fn overflow_with_consumer_filter() {
    run("overflow_filtered", "info,opentelemetry=error");
}
