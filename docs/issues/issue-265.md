---
type: issue
state: open
created: 2026-11-22T15:47:55Z
updated: 2026-11-22T15:47:55Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/265
comments: 0
labels: none
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-23T10:23:50.818Z
---

# [Issue 265]: [test(audit): second killing rows for accept-run scoping and the start+1 opening check](https://github.com/vig-os/vigil/issues/265)

Follow-up to #263 (#13, rulings 13-V8-d1 and its clarification).

- Run scoping (the closer segment belongs to the next run, ruling 13-V4-d9) is pinned by `two_runs_accept_run_0_promotes_only_run_0` alone; on that fixture the mirror row's run has no items 1–3 findings past its closer. Add a layout (three runs, or items 1–3 findings in run 1's closer) where the mirror row also fails if the closer is included.
- The start+1 check that the resume's opening is the start is pinned by one hand-built row; add a second layout.

Refs: #13
