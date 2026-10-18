---
type: issue
state: open
created: 2026-10-09T13:22:10Z
updated: 2026-10-10T22:19:26Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/16
comments: 1
labels: chore, priority:medium, effort:medium
assignees: none
milestone: 0.4.0 — adoption
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:41.605Z
---

# [Issue 16]: [chore: first consumers — s1-mcp, watcher-s1, flock](https://github.com/vig-os/vigil/issues/16)

Migrate gerchowl/s1-mcp (call log → OTLP: `tools/call s1_decide` spans + `gen_ai.evaluation.result` events; replaces its interim rotation), gerchowl/watcher-s1, and flock (already on `tracing`). Survey on 2026-10-09: only flock and forge use a logging framework; 11 other Rust repos have none.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 10, 2026 at 10:19 PM_

Sequencing (path-to-1.0 pre-mortem R2): consumers adopt **after** the API review and freeze (#37 ADR-0004, #42), because flock needs its own filter variable and default, a console layer and composition with its own Registry. Cross-repo PRs; owners merge. Findings become `bug` issues before the release-readiness review (#51).

