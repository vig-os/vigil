#!/usr/bin/env python3
"""Check the pre-publish stable API without accepting a vacuous pass."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from urllib.parse import quote
from urllib.request import Request, urlopen


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


def github_api(path):
    """Read repository metadata with the job's read-only token."""
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise ValueError("Semver review requires GITHUB_TOKEN")
    request = Request(
        "https://api.github.com/" + path,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urlopen(request, timeout=30) as response:
        return json.load(response)


def paginated(path, get=github_api, key=None):
    """Read all pages, so a later unauthorized reapplication cannot be missed."""
    items = []
    page = 1
    while True:
        separator = "&" if "?" in path else "?"
        batch = get(f"{path}{separator}per_page=100&page={page}")
        if key:
            batch = batch[key]
        items.extend(batch)
        if len(batch) < 100:
            return items
        page += 1


def current_labels(event, repository, get=github_api):
    """Verify live labels and the latest labeler's current admin/maintain role."""
    pr = event.get("pull_request")
    if not pr:
        return set()
    if not re.fullmatch(r"[A-Za-z_0-9.-]+/[A-Za-z_0-9.-]+", repository):
        raise ValueError("Invalid GITHUB_REPOSITORY")
    base = f"repos/{repository}"
    path = f"{base}/pulls/{int(pr['number'])}"
    live = get(path)
    if live["head"]["sha"] != pr["head"]["sha"]:
        raise ValueError("Semver review refuses a stale PR head")
    labels = {label["name"] for label in live["labels"]}
    if "semver:major" not in labels:
        return labels
    events = paginated(f"{base}/issues/{int(pr['number'])}/events", get)
    changes = [
        item
        for item in events
        if item.get("event") in {"labeled", "unlabeled"}
        and item.get("label", {}).get("name") == "semver:major"
    ]
    latest = max(changes, key=lambda item: item["id"], default=None)
    if not latest or latest["event"] != "labeled" or not latest.get("actor"):
        raise ValueError("semver:major has no verifiable latest labeled event")
    actor = latest["actor"]["login"]
    permission = get(f"{base}/collaborators/{quote(actor, safe='')}/permission")
    roles = permission.get("user", {}).get("permissions", {})
    if not (
        permission.get("permission") == "admin"
        or permission.get("role_name") in {"admin", "maintain"}
        or roles.get("admin") is True
        or roles.get("maintain") is True
    ):
        raise ValueError(
            f"semver:major latest labeler {actor} must have admin or maintain permission"
        )
    # Fail closed if a removal/reapplication raced the permission lookup.
    final = get(path)
    final_events = paginated(f"{base}/issues/{int(pr['number'])}/events", get)
    final_changes = [
        item
        for item in final_events
        if item.get("event") in {"labeled", "unlabeled"}
        and item.get("label", {}).get("name") == "semver:major"
    ]
    if (
        final["head"]["sha"] != live["head"]["sha"]
        or {label["name"] for label in final["labels"]} != labels
        or max(final_changes, key=lambda item: item["id"], default=None) != latest
    ):
        raise ValueError(
            "Semver review state changed during verification; rerun required"
        )
    print(f"Current semver:major label verified: {actor} has admin/maintain permission")
    return labels


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
    reviewed = "semver:major" in labels and version == "0.0.0"
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
    try:
        event_path = os.environ.get("GITHUB_EVENT_PATH")
        event = json.loads(Path(event_path).read_text()) if event_path else {}
        labels = current_labels(event, os.environ.get("GITHUB_REPOSITORY", ""))
    except (ValueError, KeyError, OSError) as error:
        message = f"Semver label review failed: {error}"
        print(message, file=sys.stderr)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with Path(summary).open("a") as report:
                report.write(message + "\n")
        # Retain every finding even when authorization fails.
        evaluate(result.stdout, result.returncode, set(), version, summary)
        return 1
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with Path(output_path).open("a") as output:
            output.write("labels=" + json.dumps(sorted(labels)) + "\n")
    return evaluate(
        result.stdout,
        result.returncode,
        labels,
        version,
        os.environ.get("GITHUB_STEP_SUMMARY"),
    )


if __name__ == "__main__":
    sys.exit(main())
