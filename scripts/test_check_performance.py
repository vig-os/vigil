"""Proof that a 2x slowdown is visible and missing measurements fail closed."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from check_performance import BENCHMARKS, read_estimates, report


class PerformanceTests(unittest.TestCase):
    """Exercise the advisory policy with synthetic Criterion measurements."""

    def test_exactly_two_times_is_flagged(self):
        baseline = dict.fromkeys(BENCHMARKS, 100.0)
        current = dict(baseline)
        current["split/pipeline"] = 200.0
        text, flagged = report(current, baseline)
        self.assertTrue(flagged)
        self.assertIn("2.00x | REGRESSION", text)

    def test_below_threshold_is_not_flagged(self):
        text, flagged = report(
            dict.fromkeys(BENCHMARKS, 199.9), dict.fromkeys(BENCHMARKS, 100.0)
        )
        self.assertFalse(flagged)
        self.assertNotIn("REGRESSION", text)

    def test_all_workloads_required_and_means_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(FileNotFoundError):
                read_estimates(root)
            for name in BENCHMARKS:
                path = root / name / "new" / "estimates.json"
                path.parent.mkdir(parents=True)
                path.write_text(json.dumps({"mean": {"point_estimate": 100.0}}))
            self.assertEqual(read_estimates(root), dict.fromkeys(BENCHMARKS, 100.0))
            path.write_text('{"mean": {"point_estimate": 0}}')
            with self.assertRaises(ValueError):
                read_estimates(root)

    def test_invalid_baseline_rejected(self):
        for invalid in [0, -1, float("nan"), float("inf")]:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                report(
                    dict.fromkeys(BENCHMARKS, 100), dict.fromkeys(BENCHMARKS, invalid)
                )

    def test_ci_summary_and_warning_are_advisory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "baseline.json"
            baseline.write_text(json.dumps({"mean_ns": dict.fromkeys(BENCHMARKS, 100)}))
            summary = root / "summary.md"
            command = [
                sys.executable,
                str(Path(__file__).with_name("check_performance.py")),
                "--results",
                str(root),
                "--baseline",
                str(baseline),
            ]
            env = {**os.environ, "GITHUB_STEP_SUMMARY": str(summary)}
            missing = subprocess.run(
                command, env=env, capture_output=True, text=True, check=False
            )
            self.assertEqual(missing.returncode, 1)
            self.assertIn("Measurement unavailable", summary.read_text())
            summary.write_text("")
            for name in BENCHMARKS:
                path = root / name / "new" / "estimates.json"
                path.parent.mkdir(parents=True)
                path.write_text(json.dumps({"mean": {"point_estimate": 200}}))
            regression = subprocess.run(
                command, env=env, capture_output=True, text=True, check=False
            )
            self.assertEqual(regression.returncode, 0)
            self.assertIn("::warning::Performance >= 2x", regression.stdout)
            self.assertIn("2.00x | REGRESSION", summary.read_text())


if __name__ == "__main__":
    unittest.main()
