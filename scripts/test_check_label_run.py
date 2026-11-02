"""A label change cannot turn missing or failed full CI into a green summary."""

import unittest

from check_label_run import REQUIRED, verify_evidence


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.event = {"pull_request": {"number": 81, "head": {"sha": "abc"}}}
        self.runs = [
            {
                "head_sha": "abc",
                "pull_requests": [{"number": 81, "head": {"sha": "abc"}}],
                "event": "pull_request",
                "run_number": 1,
                "status": "completed",
                "id": 1,
                "html_url": "https://example.test/1",
            }
        ]
        self.jobs = [{"name": name, "conclusion": "success"} for name in REQUIRED]
        self.jobs.append(
            {"name": "CI Extension / Semver compatibility", "conclusion": "failure"}
        )

    def get(self, path):
        return {"jobs": self.jobs} if "/jobs?" in path else {"workflow_runs": self.runs}

    def test_complete_full_run_with_only_semver_failure_is_reusable(self):
        verify_evidence(self.event, "vig-os/vigil", self.get)

    def test_missing_failed_cancelled_and_skipped_heavy_jobs_fail(self):
        for conclusion in (None, "failure", "cancelled", "skipped"):
            self.jobs[0]["conclusion"] = conclusion
            with (
                self.subTest(conclusion=conclusion),
                self.assertRaisesRegex(ValueError, "missing or failed"),
            ):
                verify_evidence(self.event, "vig-os/vigil", self.get)
        self.jobs = []
        with self.assertRaises(ValueError):
            verify_evidence(self.event, "vig-os/vigil", self.get)

    def test_older_green_does_not_override_latest_unfinished_or_failed_run(self):
        self.runs.append(dict(self.runs[0], run_number=2, id=2, status="in_progress"))
        with self.assertRaisesRegex(ValueError, "completed full CI"):
            verify_evidence(self.event, "vig-os/vigil", self.get)

    def test_evidence_for_other_head_or_event_is_not_reusable(self):
        for field, value in (("head_sha", "other"), ("event", "workflow_dispatch")):
            with self.subTest(field=field):
                self.runs = [dict(self.runs[0], **{field: value})]
                with self.assertRaises(ValueError):
                    verify_evidence(self.event, "vig-os/vigil", self.get)

    def test_other_pr_with_same_head_and_missing_pr_metadata_fail(self):
        for prs in (
            [],
            [{"number": 82, "head": {"sha": "abc"}}],
            [{"number": 81, "head": {"sha": "other"}}],
        ):
            with self.subTest(prs=prs):
                self.runs[0]["pull_requests"] = prs
                with self.assertRaisesRegex(ValueError, "this PR and head"):
                    verify_evidence(self.event, "vig-os/vigil", self.get)

    def test_newer_other_pr_run_does_not_hide_this_pr_evidence(self):
        self.runs.append(
            dict(
                self.runs[0],
                run_number=2,
                id=2,
                status="in_progress",
                pull_requests=[{"number": 82, "head": {"sha": "abc"}}],
            )
        )
        verify_evidence(self.event, "vig-os/vigil", self.get)
