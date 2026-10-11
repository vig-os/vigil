"""Regression coverage for vacuous semver output."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from check_semver import checks_ran, evaluate, current_labels, paginated


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

    def test_other_zero_versions_have_no_exception(self):
        for version in ("0.1.0", "0.0.1", "0.0.0-alpha", "1.0.0"):
            with self.subTest(version=version):
                self.assertEqual(evaluate(self.output, 1, {"semver:major"}, version), 1)


class LiveReviewTests(unittest.TestCase):
    def setUp(self):
        self.event = {
            "pull_request": {
                "number": 81,
                "head": {"sha": "abc"},
                "labels": [{"name": "stale-payload"}],
            }
        }
        self.live = {"head": {"sha": "abc"}, "labels": [{"name": "semver:major"}]}
        self.events = [
            {
                "id": 1,
                "event": "labeled",
                "label": {"name": "semver:major"},
                "actor": {"login": "owner"},
            }
        ]
        self.permission = {"permission": "admin"}
        self.calls = []

    def get(self, path):
        self.calls.append(path)
        if "/events?" in path:
            return self.events
        if path.endswith("/permission"):
            return self.permission
        return self.live

    def test_live_addition_ignores_stale_payload(self):
        self.assertEqual(
            current_labels(self.event, "vig-os/vigil", self.get), {"semver:major"}
        )

    def test_live_removal_ignores_stale_green_payload(self):
        self.event["pull_request"]["labels"] = [{"name": "semver:major"}]
        self.live["labels"] = []
        self.assertEqual(current_labels(self.event, "vig-os/vigil", self.get), set())
        self.assertEqual(len(self.calls), 1)

    def test_admin_and_maintain_are_accepted(self):
        for permission in (
            {"permission": "admin"},
            {"permission": "write", "role_name": "maintain"},
            {"user": {"permissions": {"maintain": True}}},
        ):
            self.permission = permission
            self.assertIn(
                "semver:major", current_labels(self.event, "vig-os/vigil", self.get)
            )

    def test_write_triage_and_unknown_permissions_fail(self):
        for permission in (
            {
                "permission": "write",
                "role_name": "write",
                "user": {
                    "permissions": {"push": True, "admin": False, "maintain": False}
                },
            },
            {"role_name": "triage"},
            {},
        ):
            self.permission = permission
            with (
                self.subTest(permission=permission),
                self.assertRaisesRegex(ValueError, "admin or maintain"),
            ):
                current_labels(self.event, "vig-os/vigil", self.get)

    def test_latest_reapplication_must_be_authorized(self):
        self.events += [
            dict(self.events[0], id=2, event="unlabeled"),
            dict(self.events[0], id=3, actor={"login": "writer"}),
        ]
        self.permission = {"permission": "write"}
        with self.assertRaisesRegex(ValueError, "writer"):
            current_labels(self.event, "vig-os/vigil", self.get)
        self.assertTrue(any("/writer/permission" in path for path in self.calls))

    def test_missing_removed_and_actorless_events_fail(self):
        for events in (
            [],
            [dict(self.events[0], event="unlabeled")],
            [dict(self.events[0], actor=None)],
        ):
            self.events = events
            with (
                self.subTest(events=events),
                self.assertRaisesRegex(ValueError, "verifiable"),
            ):
                current_labels(self.event, "vig-os/vigil", self.get)

    def test_stale_head_fails(self):
        self.live["head"]["sha"] = "new"
        with self.assertRaisesRegex(ValueError, "stale PR head"):
            current_labels(self.event, "vig-os/vigil", self.get)

    def test_api_failure_is_not_an_approval(self):
        def unavailable(path):
            raise OSError("API unavailable")

        with self.assertRaises(OSError):
            current_labels(self.event, "vig-os/vigil", unavailable)

    def test_racing_removal_fails(self):
        def racing(path):
            if path.endswith("/permission"):
                self.live["labels"] = []
            # Model separate HTTP response objects.
            return json.loads(json.dumps(self.get(path)))

        with self.assertRaisesRegex(ValueError, "state changed"):
            current_labels(self.event, "vig-os/vigil", racing)

    def test_racing_reapplication_with_unchanged_labels_fails(self):
        def racing(path):
            if path.endswith("/permission"):
                self.events += [
                    dict(self.events[0], id=2, event="unlabeled"),
                    dict(self.events[0], id=3, actor={"login": "writer"}),
                ]
            # Separate HTTP snapshots: the visible label set stays unchanged.
            return json.loads(json.dumps(self.get(path)))

        with self.assertRaisesRegex(ValueError, "state changed"):
            current_labels(self.event, "vig-os/vigil", racing)

    def test_unrelated_label_renamed_into_major_has_no_approval(self):
        # REST events retain the apply-time name, verified on PR #81.
        self.events[0]["label"]["name"] = "previous-unrelated-name"
        with self.assertRaisesRegex(ValueError, "verifiable latest labeled event"):
            current_labels(self.event, "vig-os/vigil", self.get)
        self.assertFalse(any("/permission" in path for path in self.calls))

    def test_pagination_includes_later_events(self):
        calls = []

        def get(path):
            calls.append(path)
            return list(range(100)) if path.endswith("&page=1") else [100]

        self.assertEqual(paginated("events", get), list(range(101)))
        self.assertEqual(len(calls), 2)
