---
type: issue
state: closed
created: 2026-10-10T22:18:10Z
updated: 2026-10-11T00:57:06Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/39
comments: 1
labels: feature, priority:high, area:docs, effort:medium
assignees: none
milestone: 0.2.0 — metrics + traces
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:37.451Z
---

# [Issue 39]: [design: ADR-0006 shipping (Collector file shipper, optional push feature, the Alloy gap)](https://github.com/vig-os/vigil/issues/39)

Decide how vigil's files reach Loki/Prometheus. **Owner decision (2026-10-11):** (1) Collector-contrib `otlpjsonfile` is the **reference file shipper**, documented and conformance-tested; (2) an optional **`push` feature** (OTLP/HTTP to a local agent such as Alloy's `otelcol.receiver.otlp`) is wanted, and files stay the durable copy; (3) the fleet rollout (#15, g-fleet ADR-029: one agent per host) may land after 1.0.

Evidence (pre-mortem R8): Alloy `latest` lists 24 `otelcol.receiver.*` components, **none of them `otlpjsonfile`**. `filelog` would ingest lines as text bodies, which is wrong for metrics/traces. ADR-0001 decision 9 (no network exporter) contradicts the push fallback.

**Deliver `docs/adr/0006-shipping.md` (and an ADR-0001 decision-9 amendment):** the file-shipper path (an example Collector config with `start_at`, storage extension for restart/offset safety, `include_file_name: false`, the rotation interplay); the push feature's design (crate choice and deps behind the feature, retry/backpressure, its interaction with files: tee, not replace; what happens when the agent is down); the security stance (localhost by default, TLS/auth options). **Research and document why Alloy has no OTLP-file receiver**, citing Alloy's component policy, issues or PRs, and whether contributing one upstream is realistic. Report it; don't file upstream (the owner decides).

---

# [Comment #1]() by [gerchowl]()

_Posted on October 11, 2026 at 12:57 AM_

ADR-0006 (shipping) Accepted and merged in #63 after 3 adversarial review rounds plus a final re-run: Collector-contrib otlpjsonfile as the reference file shipper with a persistent sending queue, compaction and exact loss/duplicate bounds (verified: 1500/1500 on overflow + SIGTERM; forced-full losses ≤100 lines per signal with an operator signal; SIGKILL duplicates bounded by the queue); Prometheus promote_scope_metadata required; an optional `push` feature (#41) with files as the durable copy; the local port-squat limit documented (authenticated transport: #65); the Alloy otlpjsonfile gap researched (grafana/alloy#6752) and reported to the owner, nothing filed upstream.

