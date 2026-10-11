//! Consumer layer filters and process-wide pipeline reservation.
use std::{fs, process::Command};
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};
use vigil::{Config, Console, InitErrorKind};

#[test]
fn child() {
    let Ok(mode) = std::env::var("VIGIL_COMPOSE_MODE") else {
        return;
    };
    let dir = std::path::PathBuf::from(std::env::var_os("VIGIL_COMPOSE_DIR").unwrap());
    if matches!(mode.as_str(), "foreign" | "scoped") {
        if mode == "foreign" {
            tracing_subscriber::registry().init();
        } else {
            tracing::subscriber::with_default(tracing_subscriber::registry(), || {});
        }
        assert_eq!(
            Config::new("compose").dir(&dir).init().unwrap_err().kind(),
            InitErrorKind::ForeignSubscriber
        );
        assert!(!dir.exists());
        let (_, guard) = Config::new("compose")
            .dir(&dir)
            .layer::<tracing_subscriber::Registry>()
            .unwrap();
        assert_eq!(guard.dir(), Some(dir.as_path()));
        let error = Config::new("again").init().unwrap_err();
        assert_eq!(error.kind(), InitErrorKind::AlreadyRunning);
        assert!(!error.to_string().contains("global"));
        return;
    }
    assert_eq!(
        Config::new("../bad").init().unwrap_err().kind(),
        InitErrorKind::InvalidServiceName
    );
    assert_eq!(
        Config::new("compose")
            .default_filter("[")
            .init()
            .unwrap_err()
            .kind(),
        InitErrorKind::InvalidFilter
    );
    assert!(!dir.exists());
    let own_file = dir.with_extension("consumer");
    let output = fs::File::create(&own_file).unwrap();
    let own = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(output)
        .with_filter(tracing_subscriber::EnvFilter::new("consumer=debug"));
    let (layer, guard) = Config::new("compose")
        .dir(&dir)
        .filter_env("COMPOSE_LOG")
        .default_filter("app=info")
        .console(Console::Stderr)
        .layer()
        .unwrap();
    tracing_subscriber::registry().with(own).with(layer).init();
    assert_eq!(guard.dir(), Some(dir.as_path()));
    assert_eq!(
        Config::new("again").init().unwrap_err().kind(),
        InitErrorKind::AlreadyRunning
    );
    assert_eq!(
        Config::new("again")
            .layer::<tracing_subscriber::Registry>()
            .err()
            .unwrap()
            .kind(),
        InitErrorKind::AlreadyRunning
    );
    tracing::info!(target: "app", "vigil only");
    tracing::debug!(target: "app", "filtered debug");
    tracing::debug!(target: "consumer", "consumer only");
    tracing::warn!(target: "opentelemetry_test", "sdk diagnostic");
    drop(guard);
    assert_eq!(
        Config::new("again")
            .layer::<tracing_subscriber::Registry>()
            .err()
            .unwrap()
            .kind(),
        InitErrorKind::AlreadyRunning
    );
    tracing::info!(target: "app", "after shutdown");
    tracing::debug!(target: "consumer", "consumer survives shutdown");
    let logs = fs::read_to_string(dir.join("logs.jsonl")).unwrap();
    assert!(logs.contains("vigil only"));
    for excluded in [
        "consumer only",
        "filtered debug",
        "sdk diagnostic",
        "after shutdown",
    ] {
        assert!(!logs.contains(excluded), "{excluded}");
    }
    let own = fs::read_to_string(&own_file).unwrap();
    assert!(own.contains("consumer only") && own.contains("consumer survives shutdown"));
    assert!(!own.contains("vigil only"));
    fs::remove_file(own_file).unwrap();
}

#[test]
fn per_layer_filters_and_process_reservation() {
    for (mode, filter) in [
        ("compose", ""),
        ("invalid_env", "["),
        ("foreign", ""),
        ("scoped", ""),
    ] {
        let dir = std::env::temp_dir().join(format!("vigil-compose-{}-{mode}", std::process::id()));
        let out = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "child", "--nocapture"])
            .env("VIGIL_COMPOSE_MODE", mode)
            .env("VIGIL_COMPOSE_DIR", &dir)
            .env("COMPOSE_LOG", filter)
            .output()
            .unwrap();
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("1 passed;"),
            "{out:?}"
        );
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if !matches!(mode, "foreign" | "scoped") {
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(stderr.matches("vigil only").count(), 1, "{stderr}");
            assert_eq!(stderr.matches("sdk diagnostic").count(), 1, "{stderr}");
            assert_eq!(
                stderr.matches("event after shutdown").count(),
                1,
                "{stderr}"
            );
            assert_eq!(
                stderr.contains("invalid COMPOSE_LOG"),
                mode == "invalid_env"
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
