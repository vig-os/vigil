"""Exercise inherited flag sources with real rustdoc and semver checks."""

import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import check_semver


class SelfComparisonTests(unittest.TestCase):
    def test_rejects_self_comparison_before_running_cargo(self):
        output = io.StringIO()
        with (
            patch("check_semver.subprocess.check_output", return_value="a" * 40),
            patch("check_semver.subprocess.run") as cargo,
            contextlib.redirect_stderr(output),
        ):
            self.assertEqual(check_semver.main(), 1)
        cargo.assert_not_called()
        self.assertIn("refusing self-comparison", output.getvalue())


class RustdocFlagTests(unittest.TestCase):
    def test_unstable_removal_is_excluded_for_every_flag_source(self):
        """Removing a cfg-gated function must pass for every inherited source.

        The baseline has unstable_probe and the current tree removes it. If
        any flag leaks into rustdoc, function_missing makes the check fail.
        Also inspect the generated JSON: the gated item must be absent.
        No network or third-party Rust dependencies are needed by this crate.
        """
        script = Path(check_semver.__file__).resolve()
        with tempfile.TemporaryDirectory(prefix="vigil-semver-flags-") as scratch:
            root = Path(scratch)
            repo = root / "repo"
            repo.mkdir()
            env = os.environ.copy()
            env.update(
                GIT_AUTHOR_NAME="Semver fixture",
                GIT_AUTHOR_EMAIL="fixture@example.invalid",
                GIT_COMMITTER_NAME="Semver fixture",
                GIT_COMMITTER_EMAIL="fixture@example.invalid",
                CARGO_BUILD_JOBS="3",
                CARGO_TARGET_DIR=str(root / "target"),
            )

            def git(*args, data=None):
                return subprocess.check_output(
                    ["git", *args], cwd=repo, env=env, input=data, text=True
                ).strip()

            git("init", "--quiet")
            (repo / "Cargo.toml").write_text(
                '[package]\nname = "semver-flags-fixture"\nversion = "0.0.0"\n'
                'edition = "2024"\n[lib]\npath = "lib.rs"\n'
            )
            stable = "pub fn stable() {}\n"
            (repo / "lib.rs").write_text(
                stable + "#[cfg(vigil_unstable)]\npub fn unstable_probe() {}\n"
            )
            git("add", ".")
            baseline = git("commit-tree", git("write-tree"), data="Baseline\n")
            git("update-ref", "refs/remotes/origin/dev", baseline)
            (repo / "lib.rs").write_text(stable)
            git("add", ".")
            head = git(
                "commit-tree", git("write-tree"), "-p", baseline, data="Current\n"
            )
            git("update-ref", "HEAD", head)
            triple = subprocess.check_output(
                ["rustc", "--print", "host-tuple"], text=True
            ).strip()
            target_key = triple.upper().replace("-", "_")
            sources = {
                "RUSTDOCFLAGS": "--cfg vigil_unstable",
                "CARGO_ENCODED_RUSTDOCFLAGS": "--cfg\x1fvigil_unstable",
                "CARGO_BUILD_RUSTDOCFLAGS": "--cfg vigil_unstable",
                f"CARGO_TARGET_{target_key}_RUSTDOCFLAGS": "--cfg vigil_unstable",
                "RUSTFLAGS": "--cfg vigil_unstable",
                "CARGO_ENCODED_RUSTFLAGS": "--cfg\x1fvigil_unstable",
                "CARGO_BUILD_RUSTFLAGS": "--cfg vigil_unstable",
                f"CARGO_TARGET_{target_key}_RUSTFLAGS": "--cfg vigil_unstable",
                "user-build-config": '[build]\nrustdocflags = ["--cfg", "vigil_unstable"]\n',
                "user-target-config": f'[target.{triple}]\nrustdocflags = ["--cfg", "vigil_unstable"]\n',
            }
            for source, value in sources.items():
                with self.subTest(source=source):
                    cargo_home = root / source
                    cargo_home.mkdir()
                    case_env = env | {"CARGO_HOME": str(cargo_home)}
                    if source.startswith("user-"):
                        (cargo_home / "config.toml").write_text(value)
                    else:
                        case_env[source] = value
                    result = subprocess.run(
                        [sys.executable, str(script)],
                        cwd=repo,
                        env=case_env,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(
                        result.returncode, 0, result.stdout + result.stderr
                    )
                    self.assertTrue(check_semver.checks_ran(result.stdout))
                    json_path = root / "target/doc/semver_flags_fixture.json"
                    self.assertTrue(json_path.is_file(), result.stdout)
                    self.assertNotIn("unstable_probe", json_path.read_text())
