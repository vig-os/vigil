---
type: issue
state: closed
created: 2026-11-02T12:33:25Z
updated: 2026-11-02T15:04:31Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/182
comments: 1
labels: docs
assignees: none
milestone: none
projects: none
parent: none
children: none
synced: 2026-11-03T09:06:07.681Z
---

# [Issue 182]: [docs: consumer-facing docs for v0.2.0 on release/0.2.0](https://github.com/vig-os/vigil/issues/182)

Before release 0.2.0 is finalized (PR #181), the consumer docs on `release/0.2.0` must describe 0.2.0:
- the README banner, install and pin examples, and the vigil-audit install command use tag `0.2.0`;
- an upgrade note from 0.1.0 covers the `vigil.attrs.` details refusal (semver:major, #175);
- the known issues are current (the verifier schema checks wait on #13, plus #173 and #168);
- the CHANGELOG `[0.2.0]` section is written for consumers, without stale design statuses or stray blank lines.

These fixes land on the release branch before the final tag, so the tag carries them (see devkit#1986).
---

# [Comment #1]() by [gerchowl]()

_Posted on November 2, 2026 at 03:04 PM_

Done in #183 (merged into release/0.2.0 before the final tag), shipped in [0.2.0](https://github.com/vig-os/vigil/releases/tag/0.2.0) and synced to dev via #185.

