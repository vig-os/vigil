"""Set the release version without changing dependencies or TOML formatting."""

import argparse
from pathlib import Path
import re
import tomllib


def replace_version(text, table, version):
    """Replace exactly one version assignment in the selected TOML table."""
    matches = list(re.finditer(r"(?m)^version\s*=\s*([\"\'])[\d.]+\1", table))
    if len(matches) != 1:
        raise ValueError("expected exactly one literal version field")
    match = matches[0]
    updated = table[: match.start()] + f'version = "{version}"' + table[match.end() :]
    return text.replace(table, updated, 1)


def set_version(directory, version, dry_run=False):
    """Validate both files, then update only the root package's version."""
    if (
        re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version)
        is None
    ):
        raise ValueError("release version must be X.Y.Z")
    manifest = directory / "Cargo.toml"
    lock = directory / "Cargo.lock"
    original = manifest.read_text()
    package = tomllib.loads(original)["package"]
    package["version"]  # A missing field must fail even in dry-run mode.
    table = re.search(r"(?ms)^\[package\][^\n]*\n.*?(?=^\[|\Z)", original)
    if table is None:
        raise ValueError("missing [package] table")
    updated = replace_version(original, table.group(), version)
    lock_original = lock.read_text()
    entries = list(
        re.finditer(
            r"(?ms)^\[\[package\]\][^\n]*\n.*?(?=^\[\[package\]\]|\Z)", lock_original
        )
    )
    roots = [
        entry.group()
        for entry in entries
        if tomllib.loads(entry.group())["package"][0]["name"] == package["name"]
        and "source" not in tomllib.loads(entry.group())["package"][0]
    ]
    if len(roots) != 1:
        raise ValueError("expected exactly one root package in Cargo.lock")
    lock_updated = replace_version(lock_original, roots[0], version)
    expected = tomllib.loads(original)
    expected["package"]["version"] = version
    if tomllib.loads(updated) != expected:
        raise ValueError("unexpected manifest changes")
    expected_lock = tomllib.loads(lock_original)
    for entry in expected_lock["package"]:
        if entry["name"] == package["name"] and "source" not in entry:
            entry["version"] = version
    if tomllib.loads(lock_updated) != expected_lock:
        raise ValueError("unexpected lockfile changes")
    if not dry_run:
        if updated != original:
            manifest.write_text(updated)
        if lock_updated != lock_original:
            lock.write_text(lock_updated)
    return updated != original or lock_updated != lock_original


def main():
    """Validate the release input and update the current checkout."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    set_version(Path.cwd(), args.version, args.dry_run)


if __name__ == "__main__":
    main()
