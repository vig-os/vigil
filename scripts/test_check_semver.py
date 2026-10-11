"""Regression coverage for vacuous semver output."""

import unittest

from check_semver import checks_ran


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
