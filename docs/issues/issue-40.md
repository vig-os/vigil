---
type: issue
state: closed
created: 2026-10-10T22:18:12Z
updated: 2026-10-10T22:54:20Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/40
comments: 1
labels: chore, priority:high, effort:small
assignees: none
milestone: 0.2.0 — metrics + traces
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:37.074Z
---

# [Issue 40]: [chore: stop CHANGELOG merge conflicts (merge=union) and curate Unreleased to match the code](https://github.com/vig-os/vigil/issues/40)

**Confirmed (pre-mortem R11):** replaying the 8 dev→branch merges of 0.1.0 with `git merge-tree`, 6/8 conflicted on `CHANGELOG.md`, 3 of them *only* there. With `CHANGELOG.md merge=union` (via a gitattributes entry) all 6 changelog conflicts disappeared; the remaining conflicts were real (Cargo.*, lib.rs). devkit's `prepare_changelog.py` parses a single `## Unreleased` and has no fragments.
Its content has also drifted: "Added" still claims "flock on a separate `.lock` file" and "hard-link, then unlink" (superseded per ADR-0002 as amended) and "one `LogsData` line" per batch (#30 splits lines); "Fixed" lists fixes to never-released features.

**Do:** (1) add `CHANGELOG.md merge=union` to `.gitattributes`. Check first whether that file is devkit-managed: if so, use the project-owned mechanism devkit offers, or file a devkit issue and use the closest consumer-owned seam. Verify GitHub's server-side update-branch honours it, or document that it doesn't. (2) Curate `## Unreleased` so every line matches the code on dev, and fold fixes to unreleased features into the "Added" entries. (3) File a devkit feature request for changelog fragments.
**AC:** a replay of two parallel PRs that both add Unreleased entries merges without a CHANGELOG conflict (shown with `git merge-tree`); each Unreleased line has been checked against the code.

---

# [Comment #1]() by [gerchowl]()

_Posted on October 10, 2026 at 10:54 PM_

Done in #52: `CHANGELOG.md merge=union` (a consumer-owned `.gitattributes`), replayed on 10 real merges (6 conflicts → 0); a `scripts/check_changelog.py` structure guard (duplicate versions, Unreleased, sections, top-level items) wired into the commit hook and `nix flake check`; Unreleased curated against the code; GitHub update-branch and release-sync caveats documented. Fragments request: vig-os/devkit#1858. Verified across 3 review rounds.

