"""Regression checks for compiler drift and inherited warning flags."""

import os
import unittest
from unittest.mock import patch

import check_rust_version


class RustLaneTests(unittest.TestCase):
    """Exercise the lane's guard before Cargo can run."""

    def run_lane(self, lane, compiler, expected="1.95.0"):
        env = {
            "MSRV_VERSION": expected,
            "RUSTFLAGS": "-Dwarnings --cfg vigil_unstable",
            "CARGO_ENCODED_RUSTFLAGS": "-Dwarnings",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS": "-Dwarnings",
            "RUSTDOCFLAGS": "-Dwarnings",
        }
        with (
            patch.dict(os.environ, env, clear=True),
            patch("sys.argv", ["check_rust_version.py", lane]),
            patch("subprocess.check_output", return_value=f"rustc {compiler} (test)"),
            patch("subprocess.run") as cargo,
        ):
            try:
                check_rust_version.main()
            finally:
                self.cargo_calls = cargo.call_args_list

    def test_newer_compiler_is_rejected_before_build(self):
        with self.assertRaisesRegex(SystemExit, "MSRV drift"):
            self.run_lane("msrv", "1.99.0")
        self.assertEqual(self.cargo_calls, [])

    def test_job_pin_drift_is_rejected_before_build(self):
        with self.assertRaisesRegex(SystemExit, "MSRV drift"):
            self.run_lane("msrv", "1.95.0", "1.96.0")
        self.assertEqual(self.cargo_calls, [])

    def test_msrv_checks_apple_target_and_tests_all_features(self):
        self.run_lane("msrv", "1.95.0")
        commands = [call.args[0] for call in self.cargo_calls]
        self.assertEqual([cmd[1] for cmd in commands], ["build", "test", "check"])
        self.assertIn("aarch64-apple-darwin", commands[-1])
        for cmd in commands:
            self.assertIn("--all-features", cmd)
            self.assertIn("--locked", cmd)

    def test_latest_stable_allows_warnings_despite_host_flags(self):
        self.run_lane("latest-stable", "1.99.0")
        self.assertEqual(len(self.cargo_calls), 2)
        for call in self.cargo_calls:
            env = call.kwargs["env"]
            self.assertEqual(env["RUSTFLAGS"], "")
            self.assertEqual(env["RUSTDOCFLAGS"], "")
            self.assertNotIn("CARGO_ENCODED_RUSTFLAGS", env)
            self.assertNotIn("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS", env)
