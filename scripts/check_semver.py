#!/usr/bin/env python3
"""Check the pre-publish stable API without accepting a vacuous pass."""

import os
import re
import subprocess
import sys


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
    if not checks_ran(result.stdout):
        print("Semver gate failed: no positive check-count summary", file=sys.stderr)
        return 1
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
