---
type: issue
state: open
created: 2026-11-22T14:37:13Z
updated: 2026-11-22T14:37:13Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/264
comments: 0
labels: none
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-23T10:23:51.384Z
---

# [Issue 264]: [test(audit): build the accept-run rows with the real writer](https://github.com/vig-os/vigil/issues/264)

Follow-up to #263 (#13, ruling 13-V8-d1).

The rows in `src/audit/verify/accept_run_tests.rs` build their runs from hand-built segment files. Where the writer can produce the layout (`AuditConfig` with `max_bytes`, a crash, a cut segment, then `resume`), rebuild the rows with the real writer on a pre-seeded `audit.trail` so the fixtures cannot drift from what the writer emits; keep hand-built lines only for layouts the writer cannot produce (forged or forked records), and say so in each row's comment.

Refs: #13
