---
type: issue
state: open
created: 2026-11-08T08:52:37Z
updated: 2026-11-08T08:52:37Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/208
comments: 0
labels: feature
assignees: none
milestone: none
projects: none
parent: 207
children: none
synced: 2026-11-09T09:15:00.117Z
---

# [Issue 208]: [feat(cli): vigil ingest — structured JSONL on stdin for logs, metrics, spans and audit](https://github.com/vig-os/vigil/issues/208)

Part of #207 (feature-parity tracking).

### Description
A `vigil ingest` command that reads one JSON object per line from stdin, validates it against a versioned schema and writes it through the library: logs, metrics, spans and (with `audit`) audit records.

### Problem Statement
Programs that are not Rust (shell scripts, cron and launchd jobs, any language that can write to a pipe) cannot use vigil today. They either write ad-hoc logs or would have to re-implement the OTLP/JSONL format, the rotation and the audit chain.

### Proposed Solution
- **Input contract:** one JSON object per line, `"v": 1` required, `"signal"` one of `log`, `metric`, `span`, `audit`. For example
  `{"v":1,"signal":"log","level":"info","body":"run started","attrs":{"run":"2026-11-08-0900"}}`
  `{"v":1,"signal":"audit","actor":"agent","action":"price.changed","attrs":{"item":"x","from":135,"to":115}}`
  The schema is published (JSON Schema) and versioned; typed audit attributes reuse the existing record schemas (`--schema`).
- **Strict:** an invalid line is never written and never silently dropped. It goes to stderr (or `--reject <file>`) with its line number, and the exit code is non-zero.
- **Long-running process, not one call per record:** the audit trail needs a single writer and rotation needs state. `ingest` holds the guard and the trail lock for its lifetime; a second writer on the same trail fails fast with a clear error.
- **Spans:** `span` lines carry `trace_id`/`span_id`/`parent` plus start/end, or begin/end pairs, so a shell pipeline can express "step X took Y".
- **Shutdown:** EOF flushes, like dropping the guard.
- Same `VIGIL_*` environment and `--service`/`--dir` as the library.

### Alternatives Considered
- **`vigil emit` per record:** simpler, but it pays startup per line and races on the audit trail. It could be a thin client of `ingest` later.
- **Loose input (free text to log):** rejected. The point is structured, checkable records.

### Additional Context
The first consumer is a shell scheduler (git pull → unattended agent → commit/push, twice a day). It would run `… | vigil ingest --service <name>` and emit a span per step plus audit records for the actions it confirms. Its parity row: logs, spans and audit are needed; metrics are nice to have.

### Impact
Additive: a new binary and feature, no change to the library API. The input schema becomes a stable contract that the parity check in #207 covers.

### Changelog Category
Added

