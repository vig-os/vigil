"""Reject duplicate changelog headings and bullets hidden by union merges."""

import re
import sys
from pathlib import Path


def check(text: str) -> list[str]:
    """Return line-numbered duplicate diagnostics, scoped by Markdown headings.

    Version identity excludes the release date, so TBD and dated headings for
    the same version conflict. Each version may contain a section kind only once.
    Unindented list items are compared by text (ignoring markers and numbers)
    across the whole version and section kind, even if that section repeats or
    contains deeper headings. Different versions/kinds may repeat the same text.
    Indented items and fenced code blocks are ignored.
    """
    headings: dict[str, int] = {}
    sections: dict[str, int] = {}
    bullets: dict[tuple[str, str], int] = {}
    section = ""
    errors = []
    fence = None
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        marker = re.match(r"^(`{3,}|~{3,})", stripped)
        if fence is not None:
            if marker and marker[1][0] == fence[0] and len(marker[1]) >= len(fence):
                fence = None
            continue
        if marker:
            fence = marker[1]
            continue
        if re.match(r"^#{1,2}\s", line):
            sections = {}
            bullets = {}
            section = ""
        heading = re.match(r"^##\s+(?:\[([^\]]+)\]|(Unreleased)\b)", line)
        if heading:
            key = heading[1] or heading[2]
            if key in headings:
                errors.append(
                    f"line {number}: duplicate heading {key!r} "
                    f"(first at line {headings[key]})"
                )
            else:
                headings[key] = number
        subsection = re.match(r"^###\s+(.+?)(?:\s+#+)?\s*$", line)
        if subsection:
            section = subsection[1]
            if section in sections:
                errors.append(
                    f"line {number}: duplicate section {section!r} "
                    f"(first at line {sections[section]})"
                )
            else:
                sections[section] = number
        item = re.match(r"^(?:[-*+]|[0-9]+[.)])\s+(.+)", line)
        if item:
            content = item[1].rstrip()
            bullet_key = (section, content)
            if bullet_key in bullets:
                errors.append(
                    f"line {number}: duplicate bullet {content!r} "
                    f"(first at line {bullets[bullet_key]})"
                )
            else:
                bullets[bullet_key] = number
    return errors


def main() -> int:
    """Check supplied Markdown paths, defaulting to the project changelog."""
    failed = False
    for name in sys.argv[1:] or ["CHANGELOG.md"]:
        try:
            errors = check(Path(name).read_text(encoding="utf-8"))
        except OSError as error:
            errors = [str(error)]
        for error in errors:
            print(f"{name}: {error}", file=sys.stderr)
        failed |= bool(errors)
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
