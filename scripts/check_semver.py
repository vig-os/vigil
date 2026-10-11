#!/usr/bin/env python3
"""Check the pre-publish stable API without accepting a vacuous pass."""

import os
import re
import subprocess
import sys


def checks_ran(output):
    """Require a recognized summary containing at least one executed check."""
    summaries = re.findall(r"\b(\d+) checks:\s*(\d+) pass(?:,\s*(\d+) fail)?", output)
    return bool(summaries) and all(int(total) > 0 for total, _, _ in summaries)


def main():
    """Use a full merge-base revision and keep unstable cfgs off both builds."""
    baseline = subprocess.check_output(
        ["git", "merge-base", "HEAD", "origin/dev"], text=True
    ).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", baseline):
        raise SystemExit("Expected a full merge-base SHA")
    env = os.environ.copy()
    # Cargo prefers encoded flags; clear both forms and rustdoc flags so a
    # caller's unstable opt-in cannot change the surface being checked.
    for key in (
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTDOCFLAGS",
        "CARGO_ENCODED_RUSTDOCFLAGS",
    ):
        env.pop(key, None)
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
