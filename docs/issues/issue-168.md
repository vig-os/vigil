---
type: issue
state: open
created: 2026-11-02T04:57:23Z
updated: 2026-11-02T04:57:23Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/168
comments: 0
labels: discussion, priority:medium, area:docs
assignees: none
milestone: none
projects: none
parent: none
children: none
synced: 2026-11-02T13:59:38.198Z
---

# [Issue 168]: [decision: default disk caps (max_segments, max_total_bytes) before 1.0](https://github.com/vig-os/vigil/issues/168)

Deferred from the ADR-0002 amendment for #163 (OQ1).

The amendment adds opt-in caps (`max_segments`, `max_total_bytes`, per-signal overrides) and keeps today's defaults (no count cap, no total cap, 50 MiB per file, 90 d), because a default cap would delete data users now keep (ADR-0002 decision 2 promise, constraint: additive and non-breaking).

Open: whether vigil 1.0 should ship a default total cap (OWASP: logging must not be able to fill the disk). Decide before the 1.0 API freeze (ADR-0004), with the consumer numbers from #163 (264 MiB worst case from per-signal caps; 512 MiB total) as input, and with the shipping story (ADR-0006: a down Collector plus a cap loses the oldest unshipped telemetry).

Options: keep unbounded (document only); default total cap (for example 1 GiB); default count cap per signal. A default needs an env spelling for "no limit" (the amendment's variables have minimum 1 and no off value).

Refs: #163
