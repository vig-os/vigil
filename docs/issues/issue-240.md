---
type: issue
state: open
created: 2026-11-20T02:22:03Z
updated: 2026-11-20T02:22:03Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/240
comments: 0
labels: none
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-20T09:45:01.051Z
---

# [Issue 240]: [test(audit): correct the S6b comment on inherent ClockWentBackwards findings](https://github.com/vig-os/vigil/issues/240)

Follow-up from #239 (Refs: #13). Comment-only.

The S6b row comment (and the PR description) says both incidental `ClockWentBackwards` findings are inherent to any honest layout separating highest seq from latest time. Only one is forced: with the entry's time at or above cp0's, only cp2 fires. Either say exactly one is inherent, or pick the entry's time so only one fires.
