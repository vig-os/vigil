"""Reject duplicate changelog headings and bullets hidden by union merges."""

import re
import sys
from pathlib import Path


def check(text: str) -> list[str]:
    """Return line-numbered duplicate diagnostics, scoped by Markdown headings.

    Version identity excludes the release date, so TBD and dated headings for
    the same version conflict. Bullets are compared after stripping indentation
    within each heading's section; distinct sections may repeat the same text.
    Fenced code blocks are ignored.
    """
    headings: dict[str, int] = {}
    bullets: dict[str, int] = {}
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
        if re.match(r"^#{1,6}\s", line):
            bullets = {}
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
        if re.match(r"^[-*+]\s", stripped):
            if stripped in bullets:
                errors.append(
                    f"line {number}: duplicate bullet {stripped!r} "
                    f"(first at line {bullets[stripped]})"
                )
            else:
                bullets[stripped] = number
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
