---
type: issue
state: closed
created: 2026-10-09T13:21:49Z
updated: 2026-10-09T19:10:41Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/6
comments: 2
labels: feature, priority:high, area:ci, area:testing, effort:medium
assignees: none
milestone: 0.1.0 — logs core
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:45.223Z
---

# [Issue 6]: [test: Collector conformance — otlpjsonfile receiver ingests our files losslessly](https://github.com/vig-os/vigil/issues/6)

"Conformant" is proven by the **reference reader**, not by our own parser agreeing with itself.
- CI job: run OpenTelemetry Collector-contrib with the `otlpjsonfile` receiver on vigil-written files → `file` exporter; assert a lossless round trip (same records, attributes, timestamps, ids).
- Pin the Collector version (nixpkgs `opentelemetry-collector-contrib`); run it on `dev` PRs.
- Extend to metrics and traces when they land (#7, #8).
---

# [Comment #1]() by [gerchowl]()

_Posted on October 9, 2026 at 02:12 PM_

**Pre-mortem findings (probed 2026-10-09):** nixpkgs (via the devkit pin) has `otelcol-contrib` **0.151.0** with `otlpjsonfile` and `file`, from the binary cache (84.7 MiB). On the way through the Collector **drops zero/empty fields, turns `intValue: 42` into `"42"`, adds `log.file.name`, holds back an unterminated last line, and reorders records across a rotation**. Use `start_at: beginning`, `include_file_name: false`, wait ≥2 s, and **compare by meaning, not bytes**. Don't use opentelemetry-proto's own reader as the oracle: it accepted a 2-byte `traceId`.

---

# [Comment #2]() by [gerchowl]()

_Posted on October 9, 2026 at 07:10 PM_

Done in #29: CI job `Collector conformance` writes a rich, rotated, two-resource fixture through vigil, ingests it with the flake-pinned otelcol-contrib 0.151.0 (`otlpjsonfile` → `file`), and compares by meaning as multisets. 189/189 leaf mutations caught; sabotage run proven red. Metrics/traces legs: #7, #8.

