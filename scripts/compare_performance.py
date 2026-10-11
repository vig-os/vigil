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
    """Overlay only the benchmark and its dev dependency on historical source.

    The merge-base may predate this suite. Preserve its runtime manifest and
    lockfile; Cargo resolves only the added benchmark dev dependency as needed.
    """
    destination = base / "benches" / "performance.rs"
    destination.parent.mkdir(exist_ok=True)
    shutil.copyfile(head / "benches" / "performance.rs", destination)
    manifest = base / "Cargo.toml"
    original = manifest.read_text()
    config = tomllib.loads(original)
    if "criterion" not in config.get("dev-dependencies", {}):
        original += (
            '\n[dev-dependencies.criterion]\nversion = "=0.8.2"\n'
            'default-features = false\nfeatures = ["cargo_bench_support"]\n'
        )
    if not any(bench.get("name") == "performance" for bench in config.get("bench", [])):
        original += '\n[[bench]]\nname = "performance"\nharness = false\n'
    manifest.write_text(original)


def measure(base, head, env):
    """A failed build/run propagates; only the report's slowdown is advisory."""
    # Cargo fingerprints must never let one checkout reuse the other's binary.
    # Share the Criterion estimates and scratch disk, not compiled artifacts.
    target = Path(env["CARGO_TARGET_DIR"])
    base_env = {**env, "CARGO_TARGET_DIR": str(target / "performance-base")}
    head_env = {**env, "CARGO_TARGET_DIR": str(target / "performance-head")}
    # Historical lockfiles lack the newly overlaid dev dependency. Cargo keeps
    # existing compatible pins and adds the missing entries in this disposable
    # checkout. Head must always respect its reviewed, committed lockfile.
    subprocess.run(
        [
            "cargo",
            "bench",
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
            prepare_base(base, head)
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
