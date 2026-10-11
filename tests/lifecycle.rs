use std::{fs, process::Command};
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
    let guard = Config::new("lifecycle").dir(&dir).init().unwrap();
    if matches!(
        mode.as_str(),
        "timeout" | "flush_timeout" | "concurrent_flush"
    ) {
        let lock = fs::File::open(&dir).unwrap();
        lock.lock().unwrap();
        tracing::info!("blocked export");
        let started = std::time::Instant::now();
        if mode == "timeout" {
            let error = guard
                .shutdown_with_timeout(std::time::Duration::from_millis(25))
                .unwrap_err();
            assert_eq!(error.kind(), FlushErrorKind::Timeout);
            assert!(started.elapsed() < std::time::Duration::from_secs(2));
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
            assert!(started.elapsed() >= std::time::Duration::from_secs(5));
            assert!(
                started.elapsed() < std::time::Duration::from_secs(8),
                "flushes must not serialize their timeout budgets"
            );
            lock.unlock().unwrap();
            guard.flush().unwrap();
            guard.shutdown().unwrap();
        } else {
            let error = guard.flush().unwrap_err();
            assert_eq!(error.kind(), FlushErrorKind::Timeout);
            assert!(started.elapsed() >= std::time::Duration::from_secs(5));
            assert!(started.elapsed() < std::time::Duration::from_secs(8));
            lock.unlock().unwrap();
            guard.flush().unwrap();
            guard.shutdown().unwrap();
        }
        // A timed-out SDK worker may finish once the directory lock is released.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !fs::read_to_string(dir.join("logs.jsonl"))
            .unwrap()
            .contains("blocked export")
        {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(10));
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
        let dir =
            std::env::temp_dir().join(format!("vigil-lifecycle-{}-{mode}", std::process::id()));
        let out = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "child", "--nocapture"])
            .env("VIGIL_LIFECYCLE_MODE", mode)
            .env("VIGIL_LIFECYCLE_DIR", &dir)
            .env("RUST_LOG", "info")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if mode == "loss" {
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(
                stderr.matches("runtime log export failed").count(),
                1,
                "{stderr}"
            );
            assert!(
                !stderr.contains("log shutdown failed"),
                "explicit shutdown must not repeat losses: {stderr}"
            );
            assert!(
                !stderr.contains("runtime log export losses"),
                "explicit shutdown must return the pending summary: {stderr}"
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
