---
type: issue
state: open
created: 2026-11-19T22:44:50Z
updated: 2026-11-19T22:44:50Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/236
comments: 0
labels: none
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-20T09:45:01.842Z
---

# [Issue 236]: [test(audit): revocation rows — describe behaviour instead of mutant names; fix stale comments](https://github.com/vig-os/vigil/issues/236)

Follow-ups from #235 (Refs: #13). Comment-only, no behaviour change.

1. Comments in `revocation_tests.rs` refer to mutants by internal names (Q1R, M7, M8, M2r, R2). Describe the behaviour each row pins instead.
2. The V1 comment lists only two of its killing mutants, and the module doc says only V10 uses `AuditConfig::rotate`, but V1 uses it too.
