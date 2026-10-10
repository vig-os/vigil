"""Regression coverage for the OpenTelemetry semver compatibility gate."""

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from check_supply_chain import advisory_database_errors, conflicting_versions, main


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


class GateTests(unittest.TestCase):
    """Ensure independent failures never hide the remaining policy checks."""

    def test_all_checks_run(self):
        """Aggregate conflict, fetch and policy failures without early returns."""
        for conflict, fetch_code, deny_code in [
            (True, 0, 0),
            (True, 0, 4),
            (False, 1, 0),
            (False, 0, 8),
            (False, 0, 0),
        ]:
            with self.subTest(conflict=conflict, fetch=fetch_code, deny=deny_code):
                packages = [
                    {"name": "opentelemetry", "version": "0.33.0"},
                    {
                        "name": "opentelemetry",
                        "version": "0.32.0" if conflict else "0.33.1",
                    },
                ]
                metadata = json.dumps({"packages": packages}).encode()
                results = [
                    subprocess.CompletedProcess([], 0, stdout=metadata),
                    subprocess.CompletedProcess([], fetch_code),
                    subprocess.CompletedProcess([], deny_code),
                ]
                with (
                    patch(
                        "check_supply_chain.advisory_database_errors", return_value=[]
                    ),
                    patch(
                        "check_supply_chain.subprocess.run", side_effect=results
                    ) as run,
                ):
                    self.assertEqual(
                        bool(main()), bool(conflict or fetch_code or deny_code)
                    )
                self.assertEqual(run.call_count, 3)
                self.assertEqual(
                    run.call_args_list[1].args[0],
                    ["cargo", "deny", "--locked", "fetch"],
                )
                self.assertIn("--disable-fetch", run.call_args_list[2].args[0])


class FreshnessTests(unittest.TestCase):
    """Check content timestamps rather than filesystem or fetch timestamps."""

    def test_head_dates(self):
        """Reject stale/future/malformed/missing DBs; allow the exact boundary."""
        now = datetime(2026, 10, 11, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "dbs" / "arbitrary-hash").mkdir(parents=True)
            config = root / "deny.toml"
            config.write_text(f'[advisories]\ndb-path = "{root / "dbs"}"\n')
            for age, rejected in [(0, False), (7, False), (8, True), (-1, True)]:
                with self.subTest(age=age):
                    timestamp = str(int((now - timedelta(days=age)).timestamp()))
                    results = [
                        subprocess.CompletedProcess(
                            [], 0, stdout="https://github.com/RustSec/advisory-db\n"
                        ),
                        subprocess.CompletedProcess([], 0, stdout=timestamp),
                    ]
                    with patch(
                        "check_supply_chain.subprocess.run", side_effect=results
                    ):
                        self.assertEqual(
                            bool(advisory_database_errors(config, now)), rejected
                        )
            for origin, head in [
                ("", ""),
                ("https://github.com/RustSec/advisory-db", "invalid"),
            ]:
                results = [
                    subprocess.CompletedProcess([], 0, stdout=origin),
                    subprocess.CompletedProcess([], 0, stdout=head),
                ]
                with patch("check_supply_chain.subprocess.run", side_effect=results):
                    self.assertTrue(advisory_database_errors(config, now))

    def test_staleness_does_not_skip_policy(self):
        """A stale database still allows cargo-deny to report other findings."""
        results = [
            subprocess.CompletedProcess([], 0, stdout=b'{"packages": []}'),
            subprocess.CompletedProcess([], 0),
            subprocess.CompletedProcess([], 0),
        ]
        with (
            patch(
                "check_supply_chain.advisory_database_errors", return_value=["stale"]
            ),
            patch("check_supply_chain.subprocess.run", side_effect=results) as run,
        ):
            self.assertNotEqual(main(), 0)
            self.assertEqual(run.call_count, 3)


if __name__ == "__main__":
    unittest.main()
