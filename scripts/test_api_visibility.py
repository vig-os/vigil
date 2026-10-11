"""Compile a downstream application against both sides of the unstable cfg."""

from pathlib import Path
import subprocess
import tempfile
import unittest

from check_semver import stable_environment

ROOT = Path(__file__).resolve().parent.parent


class VisibilityTests(unittest.TestCase):
    def test_exporters_require_cfg_and_constant_is_always_private(self):
        with tempfile.TemporaryDirectory(prefix="vigil-consumer-") as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "Cargo.toml").write_text(
                '[package]\nname="visibility-probe"\nversion="0.0.0"\nedition="2024"\n'
                f'[dependencies]\nvigil-telemetry={{path="{ROOT}"}}\n'
            )
            (root / "Cargo.lock").write_text((ROOT / "Cargo.lock").read_text())
            source = root / "src/main.rs"
            source.write_text(
                "use vigil::{logs::OtlpJsonLogExporter, sink::MemorySink};\n"
                "fn main() { let _ = OtlpJsonLogExporter::new(MemorySink::new()); }\n"
            )
            env = stable_environment()
            command = [
                "cargo",
                "check",
                "--manifest-path",
                str(root / "Cargo.toml"),
            ]
            stable = subprocess.run(
                command, env=env, capture_output=True, text=True, check=False
            )
            self.assertNotEqual(stable.returncode, 0, stable.stderr)
            self.assertIn("private", stable.stderr)
            env["CARGO_ENCODED_RUSTFLAGS"] = "--cfg\x1fvigil_unstable"
            unstable = subprocess.run(
                command, env=env, capture_output=True, text=True, check=False
            )
            self.assertEqual(unstable.returncode, 0, unstable.stderr)
            source.write_text(
                "use vigil::logs::NON_FINITE;\nfn main() { let _ = NON_FINITE; }\n"
            )
            constant = subprocess.run(
                command, env=env, capture_output=True, text=True, check=False
            )
            self.assertNotEqual(constant.returncode, 0, constant.stderr)
            self.assertIn("private", constant.stderr)


if __name__ == "__main__":
    unittest.main()
