#!/usr/bin/env python3
"""Measure merge-base and head sequentially on one runner with one harness."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib


def prepare_base(base, head):
    """Overlay the harness only when the base already pins its dependency.

    Historical commits without Criterion cannot provide a locked baseline.
    Return False without modifying them; never resolve additional dependencies.
    Other manifest/lock mismatches remain blocking Cargo --locked failures.
    """
    manifest = base / "Cargo.toml"
    original = manifest.read_text()
    config = tomllib.loads(original)
    lock = tomllib.loads((base / "Cargo.lock").read_text())
    if "criterion" not in config.get("dev-dependencies", {}) or not any(
        package.get("name") == "criterion" for package in lock.get("package", [])
    ):
        return False
    destination = base / "benches" / "performance.rs"
    destination.parent.mkdir(exist_ok=True)
    shutil.copyfile(head / "benches" / "performance.rs", destination)
    if not any(bench.get("name") == "performance" for bench in config.get("bench", [])):
        original += '\n[[bench]]\nname = "performance"\nharness = false\n'
        manifest.write_text(original)
    return True


def measure(base, head, env):
    """A failed build/run propagates; only the report's slowdown is advisory."""
    # Cargo fingerprints must never let one checkout reuse the other's binary.
    # Share the Criterion estimates and scratch disk, not compiled artifacts.
    target = Path(env["CARGO_TARGET_DIR"])
    base_env = {**env, "CARGO_TARGET_DIR": str(target / "performance-base")}
    head_env = {**env, "CARGO_TARGET_DIR": str(target / "performance-head")}
    subprocess.run(
        [
            "cargo",
            "bench",
            "--locked",
            "--bench",
            "performance",
            "--",
            "--save-baseline",
            "base",
        ],
        cwd=base,
        env=base_env,
        check=True,
    )
    subprocess.run(
        [
            "cargo",
            "bench",
            "--locked",
            "--bench",
            "performance",
            "--",
            "--baseline",
            "base",
        ],
        cwd=head,
        env=head_env,
        check=True,
    )
    subprocess.run(
        [
            "python3",
            str(head / "scripts" / "check_performance.py"),
            "--results",
            env["CRITERION_HOME"],
            "--baseline",
            env["CRITERION_HOME"],
        ],
        cwd=head,
        env=env,
        check=True,
    )


def main():
    """Use an isolated worktree and fresh estimates; clean up on any failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-ref", default="origin/dev")
    args = parser.parse_args()
    head = Path.cwd().resolve()
    target = Path(os.environ.get("CARGO_TARGET_DIR", "target")).resolve()
    target.mkdir(parents=True, exist_ok=True)
    merge_base = subprocess.check_output(
        ["git", "merge-base", "HEAD", args.base_ref],
        text=True,
    ).strip()
    print(
        f"Performance: merge-base {merge_base} vs head "
        + subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            text=True,
        ).strip(),
        flush=True,
    )
    with tempfile.TemporaryDirectory(
        prefix="performance-compare-", dir=target
    ) as directory:
        root = Path(directory)
        base = root / "base"
        subprocess.run(
            ["git", "worktree", "add", "--detach", str(base), merge_base], check=True
        )
        try:
            if not prepare_base(base, head):
                notice = (
                    "Performance comparison skipped: merge-base "
                    + merge_base
                    + " predates the locked Criterion benchmark dependency. "
                    "No timing comparison was made; benchmark correctness remains blocking."
                )
                print("::notice::" + notice, flush=True)
                if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
                    with open(summary, "a") as file:
                        file.write(
                            "## Performance comparison skipped\n\n" + notice + "\n"
                        )
                return
            scratch = root / "scratch"
            scratch.mkdir()
            env = {
                **os.environ,
                "CARGO_TARGET_DIR": str(target),
                "CRITERION_HOME": str(root / "criterion"),
                "VIGIL_BENCH_DIR": str(scratch),
            }
            for command in (
                ["uname", "-a"],
                ["lscpu"],
                ["df", "-T", str(scratch)],
                ["rustc", "-Vv"],
            ):
                subprocess.run(command, check=True)
            measure(base, head, env)
        finally:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(base)], check=True
            )


if __name__ == "__main__":
    main()
