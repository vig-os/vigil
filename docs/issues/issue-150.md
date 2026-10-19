---
type: issue
state: open
created: 2026-10-16T14:30:32Z
updated: 2026-10-16T14:30:33Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/150
comments: 0
labels: bug
assignees: none
milestone: 0.2.0 — metrics + traces
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:20.827Z
---

# [Issue 150]: [bug(metrics): MetricStorage::close() blocks behind an in-flight write waiting on the directory lock](https://github.com/vig-os/vigil/issues/150)

Found by the #149 review (8c-2). The same flaw was fixed for traces in #149's non-blocking `TraceStorage::close()`.

## Defect
`MetricStorage::write_line` holds the storage mutex for the whole write (src/init.rs ~l.1314–1333). `RotatingFile` waits on the directory lock with no limit. If another process holds the lock while a metrics export is writing, `close()` blocks until the lock is released. Shutdown paths that call `close()` after a timed-out provider shutdown therefore overrun their deadline (ADR-0003 d4).

## Evidence
Probe by the #149 reviewer on ebf93bb, an external-process lock test: `METRIC_CLOSE blocked_until_external_lock_released=true`, while `TRACE_CLOSE timely=true later=BrokenPipe`.

## Fix
Mirror the #149 trace design. The Closed transition must not wait for an in-flight write: the state is checked before the write and set without taking the file mutex, an in-flight write completes or fails on its own, and later writes are refused (BrokenPipe) and counted (d23).

**Acceptance:** with the directory lock held by another process and a write in flight, `close()` returns promptly (a deadline-contract test), and a later write is refused and counted. Mutant: hold the file mutex in `close()` → exit 101.

Refs #7 #8.
