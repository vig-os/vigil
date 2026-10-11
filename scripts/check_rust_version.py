"""Build and test ADR-0004's Rust lanes using flake-provided toolchains."""

import os
from pathlib import Path
import subprocess
import sys
import tomllib


def main():
    """Check the selected compiler before building every feature and testing."""
    lane = sys.argv[1]
    if lane not in {"msrv", "latest-stable"}:
        raise SystemExit(f"Unknown Rust lane: {lane}")
    env = os.environ.copy()
    # Host flags must not turn latest-stable deprecations into errors or
    # accidentally enable the explicitly unstable API surface.
    for key in list(env):
        if key in {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOCFLAGS"} or (
            key.startswith("CARGO_TARGET_") and key.endswith("_RUSTFLAGS")
        ):
            del env[key]
    env["RUSTFLAGS"] = ""
    env["RUSTDOCFLAGS"] = ""
    version = subprocess.check_output(
        ["rustc", "--version"], text=True, env=env
    ).split()[1]
    if lane == "msrv":
        declared = tomllib.loads(Path("Cargo.toml").read_text())["package"][
            "rust-version"
        ]
        expected = declared if declared.count(".") == 2 else f"{declared}.0"
        if version != expected or version != env["MSRV_VERSION"]:
            raise SystemExit(
                f"MSRV drift: rust-version={declared}, rustc={version}, "
                f"toolchain={env['MSRV_VERSION']}"
            )
    print(f"{lane}: rustc {version}", flush=True)
    for args in (["build", "--all-targets"], ["test"]):
        subprocess.run(
            ["cargo", *args, "--locked", "--all-features"], env=env, check=True
        )
    if lane == "msrv":
        subprocess.run(
            [
                "cargo",
                "check",
                "--locked",
                "--all-features",
                "--target",
                "aarch64-apple-darwin",
            ],
            env=env,
            check=True,
        )


if __name__ == "__main__":
    main()
