---
type: issue
state: open
created: 2026-10-09T16:02:46Z
updated: 2026-11-02T20:13:59Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/26
comments: 3
labels: feature
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-03T09:06:14.985Z
---

# [Issue 26]: [feat(traces): correlate tracing spans with OTLP log context](https://github.com/vig-os/vigil/issues/26)

An integration probe for #5 emits events inside an entered tracing::info_span. With the 0.33 tracing appender alone, OTLP traceId and spanId remain empty. Add tracing span context integration with the traces signal, and verify log correlation with non-empty IDs. The logs initialization API documents this limitation.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 9, 2026 at 04:15 PM_

Found while reviewing #28: besides the missing traceId/spanId, **span fields** (e.g. `outer.a` from `info_span!("outer", a = 1)`) aren't carried onto log records at all. Cover both in this issue.

---

# [Comment #2]() by [gerchowl]()

_Posted on October 10, 2026 at 10:19 PM_

Blocked on the design decisions: ADR-0004 public API and feature flags (#37) and ADR-0003 metrics and traces (#38), then the API refactor #42 (it touches `init.rs`). Implement only the accepted design.

---

# [Comment #3]() by [gerchowl]()

_Posted on November 2, 2026 at 08:13 PM_

Milestone triage: 0.2.0 was released on 2026-11-02 without this issue, so it moves to 0.3.0, the next release from `dev`.

