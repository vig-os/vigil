---
type: issue
state: closed
created: 2026-10-17T23:50:19Z
updated: 2026-11-02T20:13:47Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/158
comments: 1
labels: bug
assignees: none
milestone: 0.2.0 — metrics + traces
projects: none
parent: none
children: none
synced: 2026-11-03T09:06:12.280Z
---

# [Issue 158]: [release/0.1.0: CHANGELOG.md ends with a blank line after the devkit freeze; Lint fails and blocks the final release](https://github.com/vig-os/vigil/issues/158)

The devkit freeze (322d80d) dropped an empty `### Security` heading and left `\n\n` at EOF, on release/0.1.0 and on dev. Lint & Format fails (`end-of-file-fixer`), so the final release.yml refuses: '#155 has failed CI checks'. Fix: a bugfix PR into release/0.1.0 that trims the trailing blank line (no CHANGELOG entry, since it isn't user-visible). Dev gets it back through sync-main-to-dev after promote. Upstream: https://github.com/vig-os/devkit/issues/1901
---

# [Comment #1]() by [gerchowl]()

_Posted on November 2, 2026 at 08:13 PM_

Fixed by #159 (a58be12, merged into release/0.1.0) and shipped in [0.1.0](https://github.com/vig-os/vigil/releases/tag/0.1.0). The PR used `Refs:`, so the issue did not close automatically. Closing at milestone triage.

