---
type: issue
state: open
created: 2026-10-09T13:22:10Z
updated: 2026-11-01T23:56:03Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/16
comments: 2
labels: chore, priority:medium, effort:medium
assignees: none
milestone: 0.4.0 — adoption
projects: none
parent: none
children: none
synced: 2026-11-02T13:59:43.209Z
---

# [Issue 16]: [chore: first consumers — s1-mcp, watcher-s1, flock](https://github.com/vig-os/vigil/issues/16)

Migrate gerchowl/s1-mcp (call log → OTLP: `tools/call s1_decide` spans + `gen_ai.evaluation.result` events; replaces its interim rotation), gerchowl/watcher-s1, and flock (already on `tracing`). Survey on 2026-10-09: only flock and forge use a logging framework; 11 other Rust repos have none.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 10, 2026 at 10:19 PM_

Sequencing (path-to-1.0 pre-mortem R2): consumers adopt **after** the API review and freeze (#37 ADR-0004, #42), because flock needs its own filter variable and default, a console layer and composition with its own Registry. Cross-repo PRs; owners merge. Findings become `bug` issues before the release-readiness review (#51).

---

# [Comment #2]() by [gerchowl]()

_Posted on November 1, 2026 at 11:56 PM_

**A flock adoption requirement for the "roles" work deferred here (ADR-0004 decision 10).**

flock supports live handoff, where a new server process takes over from the old one while both are still running. During that overlap, flock's ADR-0039 §2 needs the **old** server to close its `server` pipeline and keep running under a separate role (`server-<pid>`), so that the new server can own `server`.

vigil today returns `AlreadyRunning` on a second `init`, even after `shutdown` (README; ADR-0004 decision 2), so a process can't switch roles.

We need one of the following:
- re-initialisation after shutdown under a different role;
- per-role pipelines inside one process.

Either way, the old and new servers' segments must stay distinguishable (by `service.instance.id` and role), and directory locking must be safe while the two overlap.

I'm filing this as an adoption requirement rather than a best-practice gap, because no spec mandates it.


