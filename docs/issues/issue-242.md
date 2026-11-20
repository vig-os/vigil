---
type: issue
state: open
created: 2026-11-20T04:41:21Z
updated: 2026-11-20T04:41:21Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/242
comments: 0
labels: none
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-20T09:45:00.733Z
---

# [Issue 242]: [test(audit): make in-process anchor rows fail on the whole finding list](https://github.com/vig-os/vigil/issues/242)

Follow-up to #241 (#13 V6a).

The rows that check anchors taken in process (from `AuditTrail::checkpoint()`, `close()` and `AuditConfig::resume`) detect a `Checkpoint` that lacks its trail only through their "carries its trail" assertion, not through the whole-list `assert_findings`. Two of them are also clean-match variants of earlier rows.

Add, as literal rows (whole `Vec<Finding>`):
- anchors from `checkpoint()` on a trail rewritten and re-signed above them: `AnchorMismatch … hash differs (record <hex>)` for each, so a missing trail would turn the list into `trail differs`;
- the opening checkpoint returned by `resume` used as an anchor against a trail whose opening record was altered.

Refs: #13
