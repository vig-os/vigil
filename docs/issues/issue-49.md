---
type: issue
state: closed
created: 2026-10-10T22:19:00Z
updated: 2026-10-11T11:16:14Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/49
comments: 1
labels: feature, priority:medium, area:testing, effort:medium
assignees: none
milestone: 1.0.0 — stable
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:33.796Z
---

# [Issue 49]: [perf: benchmarks and documented budgets (append under dir lock, export, init)](https://github.com/vig-os/vigil/issues/49)

Benchmarks for append under the dir lock (1 and 8 processes), export throughput (records/s, with splitting), init cost and rotation cost vs segment count (known to slow with tens of thousands of segments at tiny max_bytes). Document budgets in the README; CI tracks regressions (non-blocking on shared runners, with a clear threshold). AC: numbers with the hardware in the README; a 2× regression is visible in the CI output.

---

# [Comment #1]() by [gerchowl]()

_Posted on October 11, 2026 at 11:16 AM_

Done in PR #80 (merged into dev): public-API benchmarks, budgets measured on ext4 with the CI-runner headroom stated, a non-blocking CI check comparing the merge-base and the head on the same runner, and a blocking benchmark correctness run.

