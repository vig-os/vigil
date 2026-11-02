---
type: issue
state: open
created: 2026-10-09T13:22:08Z
updated: 2026-10-10T22:19:24Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/15
comments: 1
labels: feature, priority:medium, effort:medium
assignees: none
milestone: 0.4.0 — adoption
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:41.972Z
---

# [Issue 15]: [feat: shipping to Loki and Prometheus via Alloy](https://github.com/vig-os/vigil/issues/15)

Decide with gerchowl/g-fleet#355: Grafana Alloy (one agent per host, ADR-0029) reads the OTLP files and forwards them as OTLP to Loki (`/otlp/v1/logs`) and Prometheus (`/api/v1/otlp/v1/metrics`, opt-in receiver). Open question: an Alloy OTLP-*file* receiver was not found (the upstream Collector has `otlpjsonfile`). The fallback is that vigil can also push OTLP/HTTP to the local Alloy, with the file as the durable copy.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 10, 2026 at 10:19 PM_

Owner decision (2026-10-11): the shipping design is decided in ADR-0006 (#39): the Collector-contrib `otlpjsonfile` reference file shipper plus an optional `push` feature (#41). This fleet rollout (g-fleet, ADR-029) **may land after 1.0**; it stays in 0.4.0 as a cross-repo PR, and owners merge.

