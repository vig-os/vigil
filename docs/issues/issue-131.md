---
type: issue
state: closed
created: 2026-10-13T00:18:06Z
updated: 2026-10-13T10:37:47Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/131
comments: 1
labels: bug
assignees: none
milestone: 1.0.0 — stable
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:22.556Z
---

# [Issue 131]: [lifecycle: FlushError Display hides a logs Timeout/Failed label when a log count is present](https://github.com/vig-os/vigil/issues/131)

Found by the #130 re-review (e4119bd, merged at fe9e46d). This was not new in #130.

When logs both lost records and timed out (or failed), the logs part of `FlushError`'s `Display` shows only the count. For example, `Timeout: at least 3 log records lost; metric data points dropped` does not say that logs is the signal that timed out. Metrics behaves the same way: its Failed/Timeout label hides `data_points_lost`. That case is a kind-precedence choice, but it is not documented.

Expected: each part renders its own outcome label and its count, following the per-part rule #130 established (`: ` before the first part, `; ` between parts, a source right after its own label). If precedence folding is kept anywhere, the rustdoc must say so. Add pinned Display tests for:
- a log count plus Timeout;
- a log count plus Failed;
- metrics Failed/Timeout with data points dropped.

Display text is not part of the stability promise (ADR-0004 decision 3, ruling 113-d1), so changing it is non-breaking.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 13, 2026 at 10:37 AM_

Fixed in #139 (780f349). Each `FlushError` part now renders its own count, then its own label and source (`<count>[; <label>[: <source>]]`) for logs, metrics and traces. The pinned Display tests cover each case.

