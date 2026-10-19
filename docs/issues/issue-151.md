---
type: issue
state: closed
created: 2026-10-16T14:36:59Z
updated: 2026-10-16T18:27:23Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/151
comments: 1
labels: bug
assignees: none
milestone: 0.2.0 — metrics + traces
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:20.192Z
---

# [Issue 151]: [ci(release): the release train never sets the crate version (Cargo.toml stays 0.0.0)](https://github.com/vig-os/vigil/issues/151)

Found by the 0.1.0 release-readiness review. `prepare-release.yml` only freezes the CHANGELOG (l.~320, l.~351), and the project-owned `prepare-release-extension.yml` is a no-op, so a v0.1.0 tag would ship a crate reporting 0.0.0. Fix: the extension hook sets `Cargo.toml` and `Cargo.lock` to the release version on `release/X.Y.Z`, using the COMMIT_APP token (docs/DOWNSTREAM_RELEASE.md, prepare-release extension hook). The logic lives in a tested script. The devkit Rust pack gap gets filed upstream. This blocks the v0.1.0 release.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 16, 2026 at 06:27 PM_

Proven by the first real train run. prepare-release 0.1.0 (run 38946591963) executed the extension job 'Set release crate version' (success), which committed a27c6ae `chore(release): set crate version to 0.1.0` on release/0.1.0; `Cargo.toml` there reads `version = "0.1.0"`. Fixed by #153. Upstream: vig-os/devkit#1899.

