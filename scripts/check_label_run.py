"""Keep label-only CI summaries dependent on complete full-run evidence."""

import json
import os
from pathlib import Path

from check_semver import github_api, paginated

# This is the full CI contract. Label runs cannot replace missing/failed tests
# with skipped jobs, and only the semver finding may change after label review.
REQUIRED = {
    "Resolve toolchain",
    "Lint & Format",
    "Tests",
    "Commit Messages",
    "Scaffold Drift",
    "Dependency Review",
    "CI Extension / Rust checks (nix flake check)",
    "CI Extension / Collector conformance",
    "CI Extension / Supply chain (cargo-deny)",
    "CI Extension / MSRV (Linux and Apple target)",
    "CI Extension / Latest stable (Linux)",
    "CI Extension / Performance comparison",
}


def verify_evidence(event, repository, get=github_api):
    """Require the latest full run for this PR and head to have passed every heavy lane."""
    number = event["pull_request"]["number"]
    head = event["pull_request"]["head"]["sha"]
    runs = paginated(
        f"repos/{repository}/actions/workflows/ci.yml/runs?head_sha={head}&event=pull_request",
        get,
        "workflow_runs",
    )
    candidates = [
        run
        for run in runs
        if run["head_sha"] == head
        and run["event"] == "pull_request"
        and any(
            pr.get("number") == number and pr.get("head", {}).get("sha") == head
            for pr in run.get("pull_requests", [])
        )
    ]
    latest = max(candidates, key=lambda run: run["run_number"], default=None)
    if not latest or latest["status"] != "completed":
        raise ValueError(
            "Label-only summary requires a completed full CI run for this PR and head"
        )
    jobs = paginated(
        f"repos/{repository}/actions/runs/{latest['id']}/jobs", get, "jobs"
    )
    results = {job["name"]: job["conclusion"] for job in jobs}
    missing = sorted(name for name in REQUIRED if results.get(name) != "success")
    if missing:
        raise ValueError(f"Full CI evidence is missing or failed: {missing}")
    print(f"Full CI evidence verified: {latest['html_url']}")


if __name__ == "__main__":
    verify_evidence(
        json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text()),
        os.environ["GITHUB_REPOSITORY"],
    )
