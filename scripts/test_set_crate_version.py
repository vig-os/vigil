"""Release version regression tests using isolated manifest/lock fixtures."""

from pathlib import Path
import tempfile
import unittest

from set_crate_version import set_version


class VersionTests(unittest.TestCase):
    """Prove release preparation preserves everything except root versions."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.manifest = self.directory / "Cargo.toml"
        self.lock = self.directory / "Cargo.lock"
        self.manifest.write_text(
            '[package]\nname = "vigil-telemetry"\nversion = "0.0.0"\n\n[dependencies]\nversion = "2.0.0"\n'
        )
        self.lock.write_text(
            'version = 4\n\n[[package]]\nname = "dependency"\nversion = "2.0.0"\n\n[[package]]\nname = "vigil-telemetry"\nversion = "0.0.0"\n'
        )

    def test_version_set(self):
        self.assertTrue(set_version(self.directory, "0.1.0"))
        self.assertIn('version = "0.1.0"', self.manifest.read_text())
        self.assertIn(
            'name = "vigil-telemetry"\nversion = "0.1.0"', self.lock.read_text()
        )

    def test_idempotence(self):
        set_version(self.directory, "0.1.0")
        before = [path.stat().st_mtime_ns for path in (self.manifest, self.lock)]
        self.assertFalse(set_version(self.directory, "0.1.0"))
        self.assertEqual(
            before, [path.stat().st_mtime_ns for path in (self.manifest, self.lock)]
        )

    def test_missing_field(self):
        self.manifest.write_text('[package]\nname = "vigil-telemetry"\n')
        with self.assertRaises(KeyError):
            set_version(self.directory, "0.1.0")

    def test_bad_version(self):
        for version in ("1.2", "v1.2.3", "1.2.3-rc1", "01.2.3", "1.2.3\n"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                set_version(self.directory, version)

    def test_other_versions_untouched(self):
        manifest = self.manifest.read_text()
        lock = self.lock.read_text()
        set_version(self.directory, "0.1.0")
        self.assertEqual(
            self.manifest.read_text(), manifest.replace('"0.0.0"', '"0.1.0"')
        )
        self.assertEqual(self.lock.read_text(), lock.replace('"0.0.0"', '"0.1.0"'))

    def test_dry_run(self):
        before = [path.read_bytes() for path in (self.manifest, self.lock)]
        self.assertTrue(set_version(self.directory, "0.1.0", dry_run=True))
        self.assertEqual(
            before, [path.read_bytes() for path in (self.manifest, self.lock)]
        )

    def test_missing_lock_root_does_not_write_manifest(self):
        self.lock.write_text("version = 4\n")
        before = self.manifest.read_bytes()
        with self.assertRaises(ValueError):
            set_version(self.directory, "0.1.0")
        self.assertEqual(before, self.manifest.read_bytes())
