//! Consumer-facing release documentation and package contract.

const README: &str = include_str!("../README.md");
const ADR: &str = include_str!("../docs/adr/0004-public-api-and-stability.md");
const MANIFEST: &str = include_str!("../Cargo.toml");
const CHANGELOG: &str = include_str!("../CHANGELOG.md");

#[test]
fn early_release_policy() {
    assert!(README.contains("a patch never does"));
    assert!(README.contains("`~0.N` (or `=0.N.M`)"));
    assert!(ADR.contains("[Amended: owner decision 2026-10-13, GOAL.v3.]"));
    assert!(!README.contains("publishes no 0.x"));
}

#[test]
fn metrics_configuration() {
    for setting in [
        "VIGIL_METRICS=0",
        "VIGIL_METRICS_INTERVAL",
        "Config::metrics(bool)",
        "Config::metrics_interval(Duration)",
        "default 60",
        "optional leading `+`, no whitespace",
    ] {
        assert!(README.contains(setting), "missing {setting}");
    }
}

#[test]
fn trace_status() {
    for status in [
        "exports spans to `traces.jsonl`",
        "#8 8d",
        "#8 8e",
        "#8 8f",
        "VIGIL_TRACES=0",
    ] {
        assert!(README.contains(status), "missing {status}");
    }
    assert!(!README.contains("only the unstable span exporter"));
}

#[test]
fn consumer_release_notes() {
    for item in [
        "span_export::OtlpJsonSpanExporter",
        "vigil::sink::{LineSink, AppendFile, MemorySink}",
        "vigil::logs::OtlpJsonLogExporter",
    ] {
        let line = CHANGELOG.lines().find(|line| line.contains(item)).unwrap();
        assert!(line.contains("requires `--cfg vigil_unstable`"));
    }
    assert!(!CHANGELOG.contains("**Breaking:**"));
    assert!(!CHANGELOG.contains("test-only fault-injection"));
    assert!(!CHANGELOG.contains("amendment 12 (Proposed)"));
}

#[test]
fn package_allowlist() {
    let include = MANIFEST
        .lines()
        .find(|line| line.starts_with("include = "))
        .unwrap();
    for required in [
        "src/**",
        "Cargo.lock",
        "README.md",
        "LICENSE",
        "docs/adr/**",
        "tests/**",
        "examples/**",
        "benches/**",
    ] {
        assert!(include.contains(required), "missing {required}");
    }
    for tooling in [".claude", ".github", ".githooks", ".vscode", "scripts/**"] {
        assert!(!include.contains(tooling), "ships {tooling}");
    }
}

#[test]
fn consumer_metadata() {
    for field in [
        "description = ",
        "license = ",
        "repository = ",
        "documentation = ",
        "readme = ",
        "keywords = ",
        "categories = ",
        "rust-version = ",
        "[package.metadata.docs.rs]",
        "all-features = true",
    ] {
        assert!(
            MANIFEST.lines().any(|line| line.starts_with(field)),
            "missing {field}"
        );
    }
    assert!(include_str!("../src/lib.rs").contains("cfg_attr(docsrs"));
}

#[test]
fn release_train_owns_version() {
    assert!(README.contains("Version changes are managed by the release train (#151)."));
}

#[test]
fn known_issues() {
    let issues = README
        .split("## Known issues")
        .nth(1)
        .unwrap()
        .split("## Traces")
        .next()
        .unwrap();
    for issue in [150, 112, 13, 89, 46] {
        assert!(
            issues.contains(&format!("/issues/{issue}")),
            "missing #{issue}"
        );
    }
}
