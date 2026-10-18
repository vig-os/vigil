---
type: issue
state: open
created: 2026-10-09T13:21:55Z
updated: 2026-10-11T03:45:21Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/9
comments: 2
labels: feature, priority:medium, effort:small
assignees: none
milestone: 0.2.0 — metrics + traces
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:44.197Z
---

# [Issue 9]: [feat: semantic-convention pinning via schemaUrl (incl. GenAI/MCP)](https://github.com/vig-os/vigil/issues/9)

Stamp `schemaUrl` on resource and scope from a pinned semconv version.
- The GenAI and MCP conventions live in `open-telemetry/semantic-conventions-genai` and are all *Development* (untagged as of 2026-07): pin a commit.
- Typed attribute-key helpers for what fleet tools need first: `mcp.method.name`, `gen_ai.tool.name`, `gen_ai.operation.name`, and the `gen_ai.evaluation.result` event (`gen_ai.evaluation.name` / `.score.value` / `.score.label` / `.explanation`, correlated by span parent or `gen_ai.response.id`). First consumer: gerchowl/s1-mcp.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 10, 2026 at 10:19 PM_

Blocked on the design decisions: ADR-0004 public API and feature flags (#37) and ADR-0003 metrics and traces (#38), then the API refactor #42 (it touches `init.rs`). Implement only the accepted design.

---

# [Comment #2]() by [gerchowl]()

_Posted on October 11, 2026 at 03:45 AM_

ADR-0001's new section "Versioning stance at 1.0" (PR #78, #50) states the principle: renaming, removing or changing the meaning of an attribute vigil emits is a major; a purely additive pin move (new revision, new attributes, a moved `schemaUrl` string) is a minor, with a changelog entry naming the old and new `schemaUrl`. This issue owns the pin-bump mechanics (how the commit is pinned, stamped and bumped).

