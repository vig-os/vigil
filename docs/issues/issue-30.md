---
type: issue
state: closed
created: 2026-10-09T19:15:34Z
updated: 2026-10-09T21:03:14Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/30
comments: 1
labels: bug, priority:high, effort:small
assignees: none
milestone: 0.1.0 — logs core
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:39.496Z
---

# [Issue 30]: [fix(logs): keep every JSONL line under 1 MiB (the Collector silently drops longer lines)](https://github.com/vig-os/vigil/issues/30)

**Milestone review finding (blocker), confirmed:** otelcol-contrib's `otlpjsonfile` receiver (0.151.0, default config) has a **1 MiB line limit and drops longer lines without logging anything**. vigil writes one export batch (up to 512 records) as one line with no size cap:
- 2000 records × ~4 KB → 2.3 MB lines → **4 of 2000** records came through the Collector.
- 1500 B padding → 0.97 MB lines → 1024/1024; 2200 B padding → 1.3 MB lines → **13 of 1024**.
Any full batch averaging ≳2 KB/record (stack traces, JSON payloads), or any single record > 1 MiB, is silently lost downstream. The README and ADRs don't mention it, and the conformance test (16 tiny records) can't catch it.

**Fix**
1. The exporter splits a batch into several `LogsData` lines so that **every line is ≤ 1 MiB** (configurable `max_line_bytes`, default 1 MiB minus margin, e.g. 1_000_000). Keep deterministic output and grouping, and split at record boundaries, repeating the resource/scope envelope per line.
2. **A single record whose line would still exceed the limit:** truncate its body (then its largest string attributes) to fit, and add attributes `vigil.truncated = true` and `vigil.original_size = <bytes>`. Never emit a line over the limit; never drop the record silently.
3. **Conformance (#6):** add large-record cases (a batch of ~4 KB records; one 3 MiB record) to the fixture and assert they survive the Collector (the truncated one with its marker). Also make the conformance example go **through `vigil::init`** (the tracing bridge), not just the exporter directly (another review finding).
4. Docs: ADR-0001 gets the line-size decision (with this evidence) and records as an **accepted deviation** that lines containing `"NaN"`/`"Infinity"` don't deserialize with opentelemetry-proto's own reader (`src/logs.rs:65`), while the Collector accepts them.
Refs: #3, #6, ADR-0001.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 9, 2026 at 09:03 PM_

Done in #35: every JSONL line stays ≤ 1 MB (configurable cap). Batches split at record boundaries with scopes packed per line (10k × 512 scopes in ~52 ms). Only string values are truncated, largest first, by the exact overflow (`vigil.truncated`, `vigil.original_size`). Records that can't fit become identity-preserving stubs (`vigil.dropped`, body kept in `vigil.dropped_reason`). Keys, eventName, scope and resource are never altered. Conformance covers large records through `vigil::init` (1043/1043). ADR-0001 records the line limit and the accepted NaN reader deviation. Independently verified across three rounds.

