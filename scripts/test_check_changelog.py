"""Exercise union merges that are textually clean but semantically invalid."""

import subprocess
import tempfile
import unittest
from pathlib import Path

from check_changelog import check

ROOT = Path(__file__).resolve().parents[1]


class ChangelogTests(unittest.TestCase):
    def test_duplicate_headings(self):
        for text in (
            "## Unreleased\n## Unreleased\n",
            "## [0.2.0] - TBD\n## [0.2.0] - 2026-10-11\n",
            "## Unreleased\n## [Unreleased]\n",
        ):
            with self.subTest(text=text):
                self.assertEqual(len(check(text)), 1)
                self.assertIn("duplicate heading", check(text)[0])

    def test_bullets_are_scoped_to_sections(self):
        self.assertEqual(check("### Added\n- Same\n### Fixed\n- Same\n"), [])
        self.assertEqual(
            check("## [0.2.0]\n### Added\n- Same\n## [0.1.0]\n### Added\n- Same\n"),
            [],
        )
        for marker in ("-", "*", "+"):
            text = f"### Added\n{marker} Same\n\n{marker} Same\n"
            self.assertIn("duplicate bullet", check(text)[0])

    def test_duplicate_sections_within_version(self):
        text = "## Unreleased\n### Added\n- x\n### Added\n- y\n"
        self.assertIn("duplicate section 'Added'", check(text)[0])
        self.assertEqual(
            check("## Unreleased\n### Added\n- x\n## [0.1.0]\n### Added\n- y\n"),
            [],
        )

    def test_bullet_scope_survives_repeated_sections_and_subheadings(self):
        text = (
            "## Unreleased\n### Added\n- Same\n### Fixed\n- Other\n"
            "### Added\n#### Details\n- Same\n"
        )
        errors = check(text)
        self.assertTrue(any("duplicate section" in error for error in errors))
        self.assertTrue(any("duplicate bullet" in error for error in errors))
        self.assertEqual(len(check("### Added\n- Same\n#### Details\n- Same\n")), 1)

    def test_nested_items_under_distinct_parents_are_allowed(self):
        for marker in ("-", "*", "+", "1.", "2)"):
            with self.subTest(marker=marker):
                text = (
                    f"## Unreleased\n### Added\n{marker} A\n"
                    f"  {marker} Documented in README\n{marker} B\n"
                    f"  {marker} Documented in README\n"
                )
                self.assertEqual(check(text), [])

    def test_numbered_items_and_marker_changes(self):
        for first, second in (("1.", "2."), ("1)", "2)"), ("-", "*"), ("-", "1.")):
            with self.subTest(first=first, second=second):
                text = f"## Unreleased\n### Added\n{first} Same\n{second} Same\n"
                self.assertIn("duplicate bullet", check(text)[0])
        self.assertEqual(check("### Added\n1. Same\n### Fixed\n2. Same\n"), [])

    def test_fenced_examples_are_ignored(self):
        self.assertEqual(
            check("## Unreleased\n```md\n## Unreleased\n- Same\n- Same\n```\n"),
            [],
        )

    def test_cli_fails_for_duplicate_and_passes_clean_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "CHANGELOG.md"
            for text, expected in (("## Unreleased\n" * 2, 1), ("## Unreleased\n", 0)):
                path.write_text(text)
                result = subprocess.run(
                    ["python3", str(ROOT / "scripts/check_changelog.py"), str(path)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, expected)
                if expected:
                    self.assertIn("duplicate heading", result.stderr)

    def merge(self, base, ours, theirs, *, union=True):
        """Merge two fixture branches with the project's actual union rule."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args):
                return subprocess.run(
                    ["git", "-C", directory, *args],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout

            git("init", "-q")
            git("config", "user.name", "Changelog test")
            git("config", "user.email", "changelog-test@example.invalid")
            git("config", "commit.gpgsign", "false")
            if union:
                (root / ".gitattributes").write_text(
                    (ROOT / ".gitattributes").read_text()
                )
            path = root / "CHANGELOG.md"
            path.write_text(base)
            git("add", ".")
            git("commit", "-qm", "Fixture base")
            git("branch", "fixture-base")
            for branch, text in (("ours", ours), ("theirs", theirs)):
                git("checkout", "-qb", branch, "fixture-base")
                path.write_text(text)
                git("add", "CHANGELOG.md")
                git("commit", "-qm", branch)
            tree = git("merge-tree", "--write-tree", "ours", "theirs").strip()
            return git("show", f"{tree}:CHANGELOG.md")

    def test_release_sync_union_hides_duplicate_version(self):
        base = "# Changelog\n\n## [0.2.0] - TBD\n\n### Added\n\n- Feature\n"
        main = base.replace("TBD", "2026-10-11")
        dev = base.replace("## [0.2.0]", "### Security\n\n- Security fix\n\n## [0.2.0]")
        with self.assertRaises(subprocess.CalledProcessError) as conflict:
            self.merge(base, main, dev, union=False)
        self.assertEqual(conflict.exception.returncode, 1)
        self.assertIn("CONFLICT", conflict.exception.stdout)
        merged = self.merge(base, main, dev)
        self.assertIn("## [0.2.0] - TBD", merged)
        self.assertIn("## [0.2.0] - 2026-10-11", merged)
        self.assertIn("duplicate heading '0.2.0'", check(merged)[0])

    def test_parallel_new_sections_union_is_rejected(self):
        base = "# Changelog\n\n## Unreleased\n\n### Added\n\n- Existing\n"
        merged = self.merge(
            base,
            base + "- Added A\n\n### Security\n\n- Security A\n",
            base + "- Added B\n\n### Security\n\n- Security B\n",
        )
        self.assertEqual(merged.count("### Security"), 2)
        self.assertTrue(
            any("duplicate section 'Security'" in error for error in check(merged))
        )

    def test_parallel_unreleased_additions_merge_and_validate(self):
        base = "# Changelog\n\n## Unreleased\n\n### Added\n\n- Existing\n"
        merged = self.merge(
            base,
            base.replace("- Existing", "- Parallel A\n- Existing"),
            base.replace("- Existing", "- Parallel B\n- Existing"),
        )
        self.assertEqual(merged.count("- Parallel A"), 1)
        self.assertEqual(merged.count("- Parallel B"), 1)
        self.assertEqual(check(merged), [])


if __name__ == "__main__":
    unittest.main()
