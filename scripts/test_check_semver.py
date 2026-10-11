"""Regression coverage for vacuous semver output."""

import contextlib
import io
from pathlib import Path
import tempfile
import unittest

from check_semver import checks_ran, evaluate, event_labels


class CheckCountTests(unittest.TestCase):
    def test_positive_check_count(self):
        self.assertTrue(checks_ran("222 checks: 222 pass, 30 skip"))

    def test_breaking_check_still_counts(self):
        self.assertTrue(checks_ran("222 checks: 221 pass, 1 fail, 30 skip"))

    def test_vacuous_pass(self):
        self.assertFalse(checks_ran("0 checks: 0 pass, 252 skip"))

    def test_missing_or_changed_summary(self):
        self.assertFalse(checks_ran("Finished successfully"))
        self.assertFalse(checks_ran(""))

    def test_one_empty_summary_fails(self):
        self.assertFalse(checks_ran("222 checks: 222 pass\n0 checks: 0 pass"))

    def test_singular_summary(self):
        self.assertTrue(checks_ran("1 check: 1 pass, 0 skip"))
        self.assertFalse(checks_ran("0 check: 0 pass, 252 skip"))


class MajorExceptionTests(unittest.TestCase):
    output = (
        "196 checks: 192 pass, 4 fail, 56 skip\n"
        + "".join(
            f"--- failure finding_{i}: major break ---\nFailed in: item_{i}\n"
            for i in range(4)
        )
        + "     Summary semver requires new major version: 4 major and 0 minor checks failed\n"
    )

    def test_label_with_majors_passes_and_lists_every_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary"
            self.assertEqual(
                evaluate(self.output, 1, {"semver:major"}, "0.0.0", summary), 0
            )
            for i in range(4):
                self.assertIn(f"item_{i}", summary.read_text())
            self.assertIn("Exception accepted: True", summary.read_text())

    def test_majors_without_label_fail(self):
        self.assertEqual(evaluate(self.output, 1, set(), "0.0.0"), 1)

    def test_label_with_zero_checks_fails(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(
                evaluate("0 checks: 0 pass", 0, {"semver:major"}, "0.0.0"), 1
            )

    def test_label_never_accepts_tool_failure_or_incomplete_findings(self):
        for output, status in [
            ("compile failed", 1),
            (self.output, 101),
            (self.output.replace("--- failure finding_0", "unrecognized finding_0"), 1),
        ]:
            with (
                self.subTest(output=output, status=status),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertNotEqual(
                    evaluate(output, status, {"semver:major"}, "0.0.0"), 0
                )

    def test_published_version_has_no_exception(self):
        self.assertEqual(evaluate(self.output, 1, {"semver:major"}, "1.0.0"), 1)

    def test_event_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            event = Path(directory) / "event.json"
            event.write_text('{"pull_request":{"labels":[{"name":"semver:major"}]}}')
            self.assertEqual(event_labels(event), {"semver:major"})
            event.write_text("{}")
            self.assertEqual(event_labels(event), set())
        self.assertEqual(event_labels(None), set())
