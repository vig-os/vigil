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
    // Cargo normalizes the published manifest to a multiline array.
    let include = MANIFEST
        .split_once("include = [")
        .unwrap()
        .1
        .split_once(']')
        .unwrap()
        .0;
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

#[path = "common/temp.rs"]
mod temp;

fn package_patterns() -> Vec<&'static str> {
    MANIFEST
        .split_once("include = [")
        .unwrap()
        .1
        .split_once(']')
        .unwrap()
        .0
        .split('"')
        .enumerate()
        .filter_map(|(index, pattern)| (index % 2 == 1).then_some(pattern))
        .collect()
}

#[test]
fn package_excludes_nested_tooling() {
    let dir = temp::TempDir::new();
    for path in [
        "src",
        ".claude/skills/inception_explore",
        ".github",
        ".githooks",
        ".vscode",
    ] {
        std::fs::create_dir_all(dir.0.join(path)).unwrap();
    }
    for path in [
        "src/lib.rs",
        "README.md",
        ".claude/skills/inception_explore/README.md",
        ".github/README.md",
        ".githooks/README.md",
        ".vscode/README.md",
    ] {
        std::fs::write(dir.0.join(path), "").unwrap();
    }
    let patterns = package_patterns();
    std::fs::write(
        dir.0.join("Cargo.toml"),
        format!("[package]\nname = \"release-docs-packaging-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\ninclude = {patterns:?}\n"),
    ).unwrap();
    let output = std::process::Command::new("cargo")
        .args(["package", "--list", "--allow-dirty", "--offline"])
        .current_dir(&dir.0)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let list = String::from_utf8(output.stdout).unwrap();
    for tooling in [".claude/", ".github/", ".githooks/", ".vscode/"] {
        assert!(!list.contains(tooling), "ships {tooling}: {list}");
    }
    assert!(patterns.iter().all(|pattern| pattern.starts_with('/')));
}

#[test]
fn unstable_pins_cover_both_release_phases() {
    let rustdoc = include_str!("../src/lib.rs");
    for text in [README, rustdoc] {
        assert!(text.contains("unstable items may change in any release"));
        assert!(text.contains("pin `=0.N.M` before 1.0"));
        assert!(text.contains("pin `~1.N` from 1.0"));
    }
    assert!(!README.contains("Applications that set the cfg should pin `~1.N`"));
}

#[test]
fn consumer_details_survive_changelog_curation() {
    for detail in [
        "not `Copy`",
        "`Display` text is outside",
        "validated `file=`",
        "genesis digest",
        "hard-link recovery",
        "clock rollback",
        "`CorruptTrail`",
        "`--start-from`",
        "`accept-run`",
        "batch-start anchor",
        "range digest",
        "owns its newline",
    ] {
        assert!(CHANGELOG.contains(detail), "missing {detail}");
    }
}

#[test]
fn readme_relative_links_are_packaged() {
    let inline = README
        .split("](")
        .skip(1)
        .map(|part| part.split(')').next().unwrap());
    let references = README
        .lines()
        .filter(|line| line.starts_with('['))
        .filter_map(|line| line.split_once("]: ").map(|(_, target)| target));
    for target in inline.chain(references) {
        if target.starts_with(['#', '/']) || target.contains("://") || target.starts_with("mailto:")
        {
            continue;
        }
        let path = target.split('#').next().unwrap();
        assert!(
            package_patterns().iter().any(|pattern| {
                let pattern = pattern.trim_start_matches('/');
                pattern == path
                    || pattern.strip_suffix("/**").is_some_and(|dir| {
                        path == format!("{dir}/") || path.starts_with(&format!("{dir}/"))
                    })
            }),
            "relative link omitted from package: {path}"
        );
    }
}
