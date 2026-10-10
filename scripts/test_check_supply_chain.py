"""Regression coverage for the OpenTelemetry semver compatibility gate."""

import unittest

from check_supply_chain import conflicting_versions


class CompatibilityTests(unittest.TestCase):
    """Check prefix coverage and pre-/post-1.0 compatibility semantics."""

    def test_compatibility_lines(self):
        """Reject incompatible majors, including future family members."""
        for name, versions, rejected in [
            ("opentelemetry", ["0.32.0", "0.33.0"], True),
            ("opentelemetry-future", ["1.0.0", "2.0.0"], True),
            ("opentelemetry_sdk", ["0.33.0", "0.33.1"], False),
            ("opentelemetry-proto", ["1.0.0", "1.2.0"], False),
            ("other", ["1.0.0", "2.0.0"], False),
        ]:
            with self.subTest(name=name, versions=versions):
                packages = [{"name": name, "version": v} for v in versions]
                self.assertEqual(bool(conflicting_versions(packages)), rejected)


if __name__ == "__main__":
    unittest.main()
