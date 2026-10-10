#!/usr/bin/env python3
"""Run the supply-chain policy, including OpenTelemetry compatibility checks."""

import json
import os
import tomllib
import subprocess
import tempfile
from collections import defaultdict
from datetime import datetime, timedelta, timezone
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


def advisory_database_errors(config_path=Path("deny.toml"), now=None):
    """Reject missing or stale configured DBs using their actual HEAD dates.

    cargo-deny 0.19.6 can silently retain stale data even with its staleness
    option enabled. Inspect matching origin URLs rather than assuming its
    internal hashed directory naming. Fetch timestamps are not evidence of
    fresh advisory content. A quiet DB also fails after seven days.
    """
    config = tomllib.loads(config_path.read_text())["advisories"]
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    root = Path(
        os.path.expandvars(config.get("db-path", str(cargo_home / "advisory-dbs")))
    ).expanduser()
    urls = config.get("db-urls", ["https://github.com/RustSec/advisory-db"])
    now = now or datetime.now(timezone.utc)
    oldest = now - timedelta(days=7)
    errors = []
    for url in urls:
        found = False
        for database in sorted(root.glob("*")):
            if not database.is_dir():
                continue
            origin = subprocess.run(
                ["git", "-C", str(database), "config", "--get", "remote.origin.url"],
                capture_output=True,
                text=True,
                check=False,
            )
            if (
                origin.returncode
                or origin.stdout.strip().rstrip("/").removesuffix(".git").lower()
                != url.rstrip("/").removesuffix(".git").lower()
            ):
                continue
            found = True
            head = subprocess.run(
                ["git", "-C", str(database), "show", "-s", "--format=%ct", "HEAD"],
                capture_output=True,
                text=True,
                check=False,
            )
            try:
                committed = datetime.fromtimestamp(
                    int(head.stdout.strip()), timezone.utc
                )
            except (ValueError, OverflowError, OSError):
                errors.append(f"cannot read advisory DB HEAD date: {database}")
                continue
            if head.returncode or committed < oldest or committed > now:
                errors.append(
                    f"advisory DB HEAD outside seven-day freshness window: {database}: {committed.isoformat()}"
                )
        if not found:
            errors.append(f"configured advisory DB missing: {url} in {root}")
    return errors


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
    # Fetch once, inspect actual content freshness, and prevent a second fetch
    # from changing the database between the freshness and policy checks.
    fetch_code = subprocess.run(
        ["cargo", "deny", "--locked", "fetch"], check=False
    ).returncode
    freshness_errors = advisory_database_errors()
    for error in freshness_errors:
        print(f"error: {error}", flush=True)
    with tempfile.TemporaryDirectory(prefix="vigil-supply-chain-") as directory:
        path = Path(directory) / "metadata.json"
        path.write_bytes(metadata)
        deny_code = subprocess.run(
            [
                "cargo",
                "deny",
                "--locked",
                "check",
                "--disable-fetch",
                "--metadata-path",
                str(path),
            ],
            check=False,
        ).returncode
    return deny_code or fetch_code or int(bool(conflicts or freshness_errors))


if __name__ == "__main__":
    raise SystemExit(main())
