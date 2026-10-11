"""Prove identical harnesses, same-runner comparison and blocking failure policy."""

from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest
from unittest.mock import patch
import tomllib

from compare_performance import measure, prepare_base


class ComparisonTests(unittest.TestCase):
    """The old library gets the new harness without replacing runtime inputs."""

    def test_overlay_preserves_runtime_dependencies_and_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base, head = root / "base", root / "head"
            base.mkdir()
            (head / "benches").mkdir(parents=True)
            (head / "benches/performance.rs").write_text("new public API harness")
            (base / "Cargo.toml").write_text(
                '[package]\nname="example"\nversion="0.1.0"\n'
                '[dependencies]\nserde="1"\n'
            )
            (base / "Cargo.lock").write_text("version = 4\n")
            self.assertFalse(prepare_base(base, head))
            self.assertFalse((base / "benches").exists())
            self.assertEqual((base / "Cargo.lock").read_text(), "version = 4\n")
            self.assertEqual(
                (base / "Cargo.toml").read_text(),
                '[package]\nname="example"\nversion="0.1.0"\n'
                '[dependencies]\nserde="1"\n',
            )
            (base / "Cargo.toml").write_text(
                (base / "Cargo.toml").read_text()
                + '[dev-dependencies]\ncriterion="=0.8.2"\n'
            )
            self.assertFalse(prepare_base(base, head))
            self.assertFalse((base / "benches").exists())
            (base / "Cargo.lock").write_text(
                'version = 4\n[[package]]\nname="criterion"\nversion="0.8.2"\n'
            )
            locked = (base / "Cargo.lock").read_text()
            self.assertTrue(prepare_base(base, head))
            config = tomllib.loads((base / "Cargo.toml").read_text())
            self.assertEqual(config["dependencies"], {"serde": "1"})
            self.assertEqual(config["dev-dependencies"]["criterion"], "=0.8.2")
            self.assertEqual(
                config["bench"], [{"name": "performance", "harness": False}]
            )
            self.assertEqual((base / "Cargo.lock").read_text(), locked)
            self.assertEqual(
                (base / "benches/performance.rs").read_text(), "new public API harness"
            )
            prepare_base(base, head)
            self.assertEqual(
                len(tomllib.loads((base / "Cargo.toml").read_text())["bench"]), 1
            )

    @patch("compare_performance.subprocess.run")
    def test_base_then_head_share_estimates_and_environment(self, run):
        env = {
            "CRITERION_HOME": "/same/criterion",
            "VIGIL_BENCH_DIR": "/same/disk",
            "CARGO_TARGET_DIR": "/build",
        }
        measure(Path("/base"), Path("/head"), env)
        self.assertEqual(len(run.call_args_list), 3)
        base, head, report = run.call_args_list
        self.assertEqual(base.args[0][-2:], ["--save-baseline", "base"])
        self.assertEqual(head.args[0][-2:], ["--baseline", "base"])
        self.assertIn("--locked", base.args[0])
        self.assertIn("--locked", head.args[0])
        self.assertEqual(base.kwargs["cwd"], Path("/base"))
        self.assertEqual(head.kwargs["cwd"], Path("/head"))
        for call in [base, head, report]:
            self.assertEqual(
                call.kwargs["env"]["CRITERION_HOME"], env["CRITERION_HOME"]
            )
            self.assertEqual(
                call.kwargs["env"]["VIGIL_BENCH_DIR"], env["VIGIL_BENCH_DIR"]
            )
            self.assertTrue(call.kwargs["check"])
        self.assertNotEqual(
            base.kwargs["env"]["CARGO_TARGET_DIR"],
            head.kwargs["env"]["CARGO_TARGET_DIR"],
        )

    @patch("compare_performance.subprocess.run")
    def test_broken_benchmark_stops_comparison(self, run):
        run.side_effect = subprocess.CalledProcessError(101, "cargo bench")
        with self.assertRaises(subprocess.CalledProcessError):
            measure(
                Path("/base"),
                Path("/head"),
                {"CRITERION_HOME": "/same", "CARGO_TARGET_DIR": "/build"},
            )
        self.assertEqual(run.call_count, 1)

    def test_workflow_blocks_measurement_and_correctness_failures(self):
        workflow = Path(".github/workflows/ci-extension.yml").read_text()
        performance = workflow.split("\n  performance:\n", 1)[1]
        self.assertNotIn("continue-on-error:", performance)
        self.assertIn("compare_performance.py", performance)
        self.assertIn("fetch-depth: 0", performance)
        self.assertEqual(workflow.count("cargo test --locked --bench performance"), 1)
        self.assertNotIn("cargo test --locked --all-targets", workflow)
        self.assertEqual(
            workflow.count("cargo test --locked --lib --bins --tests --examples"), 3
        )

    def test_documented_append_headroom_distinguishes_vm_and_ci(self):
        readme = Path("README.md").read_text()
        for number in ("76.7k", "40.6k", "1.53×", "1.62×", "6.66×", "8.80×"):
            self.assertIn(number, readme)

    def test_ci_summary_blocks_extension_failures_and_cancellations(self):
        workflow = Path(".github/workflows/ci.yml").read_text()
        summary = workflow.split("\n  summary:\n", 1)[1]
        self.assertIn("extension,", summary)
        shell = textwrap.dedent(summary.split("        run: |\n", 1)[1])
        for status, expected in [("success", 0), ("failure", 1), ("cancelled", 1)]:
            with self.subTest(status=status):
                substituted = re.sub(
                    r"\$\{\{ needs\.(\S+)\.result \}\}",
                    lambda match: status if match[1] == "extension" else "success",
                    shell,
                )
                result = subprocess.run(
                    ["bash", "-c", substituted],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(
                    result.returncode, expected, result.stdout + result.stderr
                )


if __name__ == "__main__":
    unittest.main()
