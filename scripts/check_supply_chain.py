#!/usr/bin/env python3
"""Run the supply-chain policy, including OpenTelemetry compatibility checks."""

import json
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path


def conflicting_versions(packages):
    """Return OpenTelemetry crates with multiple semver compatibility lines.

    Before 1.0, each minor version is a separate compatibility line. Patch
    releases within a line remain allowed. Match the prefix so newly introduced
    OpenTelemetry crates automatically receive the same protection.
    """
    versions = defaultdict(set)
    for package in packages:
        if package["name"].startswith("opentelemetry"):
            versions[package["name"]].add(package["version"])
    conflicts = {}
    for name, releases in versions.items():
        lines = set()
        for release in releases:
            major, minor, _ = release.split(".", 2)
            lines.add((major, minor) if major == "0" else (major,))
        if len(lines) > 1:
            conflicts[name] = sorted(releases)
    return conflicts


def main():
    """Check locked metadata and pass the same graph to cargo-deny."""
    metadata = subprocess.run(
        ["cargo", "metadata", "--locked", "--all-features", "--format-version", "1"],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    conflicts = conflicting_versions(json.loads(metadata)["packages"])
    if conflicts:
        for name, versions in sorted(conflicts.items()):
            print(
                f"error: duplicate OpenTelemetry compatibility lines: {name}: {versions}"
            )
        return 1
    with tempfile.TemporaryDirectory(prefix="vigil-supply-chain-") as directory:
        path = Path(directory) / "metadata.json"
        path.write_bytes(metadata)
        return subprocess.run(
            ["cargo", "deny", "--locked", "check", "--metadata-path", str(path)],
            check=False,
        ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
