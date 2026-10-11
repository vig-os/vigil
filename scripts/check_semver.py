#!/usr/bin/env python3
"""Check the pre-publish stable API without accepting a vacuous pass."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib


def checks_ran(output):
    """Require a recognized summary containing at least one executed check."""
    summaries = re.findall(r"\b(\d+) checks?:\s*(\d+) pass(?:,\s*(\d+) fail)?", output)
    return bool(summaries) and all(int(total) > 0 for total, _, _ in summaries)


def stable_environment():
    """Override every inherited Cargo compiler/documentation flag source."""
    env = os.environ.copy()
    for key in list(env):
        if key in ("RUSTFLAGS", "RUSTDOCFLAGS") or (
            key.startswith("CARGO_") and key.endswith(("RUSTFLAGS", "RUSTDOCFLAGS"))
        ):
            env.pop(key)
    # In pinned cargo-semver-checks 0.47.0 these take precedence over target
    # and user-level Cargo configuration. The tool appends its own JSON
    # options to RUSTDOCFLAGS for the child Cargo invocation. Encoded flags
    # must remain absent, or Cargo would ignore those required JSON options.
    env["CARGO_BUILD_RUSTFLAGS"] = ""
    env["CARGO_BUILD_RUSTDOCFLAGS"] = ""
    return env


def event_labels(path):
    """Read labels from the PR event; non-PR runs have no exception."""
    if not path:
        return set()
    event = json.loads(Path(path).read_text())
    return {label["name"] for label in event.get("pull_request", {}).get("labels", [])}


def evaluate(output, status, labels, version, summary=None):
    """Accept only complete, reviewed pre-publish major findings, never tool errors."""
    if not checks_ran(output):
        print("Semver gate failed: no positive check-count summary", file=sys.stderr)
        return 1
    if status == 0:
        return 0
    result = re.search(
        r"semver requires new major version: (\d+) major and (\d+) minor checks failed",
        output,
    )
    findings = re.findall(
        r"(?ms)^--- failure .+?(?=^--- failure |^     Summary|\Z)", output
    )
    if not result or status != 1:
        return status or 1
    major, minor = map(int, result.groups())
    reviewed = "semver:major" in labels and version.startswith("0.")
    complete = major > 0 and minor == 0 and len(findings) == major
    if summary:
        with Path(summary).open("a") as report:
            report.write("## Semver major findings\n\n")
            report.write(
                f"Pre-publish reviewed label present: {reviewed}. Major checks: {major}.\n\n"
            )
            for finding in findings:
                report.write("````text\n" + finding.rstrip() + "\n````\n\n")
            report.write(
                f"Exception accepted: {reviewed and complete}. ADR-0004 decision 12.\n"
            )
    if reviewed and complete:
        print(
            "Reviewed pre-publish semver:major exception accepted; findings retained in summary"
        )
        return 0
    return status


def main():
    """Use a full merge-base revision and keep unstable cfgs off both builds."""
    baseline = subprocess.check_output(
        ["git", "merge-base", "HEAD", "origin/dev"], text=True
    ).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", baseline):
        raise SystemExit("Expected a full merge-base SHA")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if baseline == head:
        print(
            "Semver gate failed: merge base equals HEAD; refusing self-comparison. "
            "Run on a feature PR into dev, not dev dispatch or dev-to-main.",
            file=sys.stderr,
        )
        return 1
    env = stable_environment()
    env["CARGO_TERM_COLOR"] = "never"
    print(f"Stable API baseline: {baseline}", flush=True)
    result = subprocess.run(
        [
            "cargo",
            "semver-checks",
            "--baseline-rev",
            baseline,
            "--release-type",
            "minor",
            "--all-features",
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    print(result.stdout, end="", flush=True)
    version = tomllib.loads(Path("Cargo.toml").read_text())["package"]["version"]
    return evaluate(
        result.stdout,
        result.returncode,
        event_labels(os.environ.get("GITHUB_EVENT_PATH")),
        version,
        os.environ.get("GITHUB_STEP_SUMMARY"),
    )


if __name__ == "__main__":
    sys.exit(main())
