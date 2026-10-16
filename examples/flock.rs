//! Compose vigil with a consumer-owned Registry and a separate consumer filter.
use std::path::Path;
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

fn run(dir: &Path) -> Result<(), vigil::InitError> {
    let own = tracing_subscriber::fmt::layer()
        .with_filter(tracing_subscriber::EnvFilter::new("consumer=debug"));
    let (layer, guard) = vigil::Config::new("flock")
        .dir(dir)
        .filter_env("FLOCK_LOG")
        .default_filter("flk=info,flock=info")
        .console(vigil::Console::Stderr)
        .layer()?;
    tracing_subscriber::registry().with(own).with(layer).init();
    tracing::info!(target: "flk", "flock ready");
    tracing::debug!(target: "consumer", "consumer layer only");
    assert_eq!(guard.dir(), Some(dir));
    drop(guard);
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::args_os()
        .nth(1)
        .ok_or("expected state directory")?;
    run(Path::new(&dir))?;
    Ok(())
}

#[test]
fn flock_registry_writes_filtered_logs() {
    let dir = std::env::temp_dir().join(format!("vigil-flock-{}", std::process::id()));
    run(&dir).unwrap();
    let logs = std::fs::read_to_string(dir.join("logs.jsonl")).unwrap();
    assert!(logs.contains("flock ready"));
    assert!(!logs.contains("consumer layer only"));
    std::fs::remove_dir_all(dir).unwrap();
}
