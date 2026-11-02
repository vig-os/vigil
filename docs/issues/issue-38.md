---
type: issue
state: closed
created: 2026-10-10T22:18:08Z
updated: 2026-10-11T00:45:01Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/38
comments: 1
labels: feature, priority:high, area:docs, effort:medium
assignees: none
milestone: 0.2.0 — metrics + traces
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:37.790Z
---

# [Issue 38]: [design: ADR-0003 metrics and traces (seam, cumulative-only, service.instance.id, span dedup)](https://github.com/vig-os/vigil/issues/38)

Decide the metrics and traces design before #7/#8/#26/#9 are implemented. Evidence from the path-to-1.0 pre-mortem (probed 2026-10-10, Rust 1.95, opentelemetry 0.33.1, otelcol-contrib 0.151.0, Prometheus 3.15):
- **Metrics (R5, R6):** cumulative metrics work end to end: `otlpjsonfile` ingested 24/24, Prometheus OTLP returned 200. **Delta → 500 for the whole request**, cumulative series in the same batch included. vigil's resource has **no `service.instance.id`**, so N processes of one service emit cumulative series with the same identity, which interleave as resets and out-of-order samples (seen as 400 + 5 out-of-order). `PushMetricExporter::export(&self, &ResourceMetrics)` needs no runtime (PeriodicReader thread). `From<&ResourceMetrics>` for the proto is public under `gen-tonic-messages`. `ResourceMetrics` fields are `pub(crate)`, so fixtures need the sdk's `testing` feature (dev-dep).
- **Traces (R7):** `tracing-opentelemetry` **0.34.0** is the only release on opentelemetry 0.33. Log records get the exported span's trace/span ids in any layer order. Edges: (a) `info!(parent: &span)` on an un-entered span gives no context; (b) span fields reach records only via the appender's **experimental** `experimental_span_attributes`; (c) tracing-opentelemetry turns every event into a span event, so logs would be written twice (logs.jsonl and traces.jsonl) unless deduped; (d) a span still open at shutdown is silently lost. `OpenTelemetryLayer` is typed to its subscriber position.

**Decide in `docs/adr/0003-metrics-and-traces.md`:** the exporter seam (reuse the logs line/rotation/cap machinery); cumulative-only, with temporality not exposed; `service.instance.id` (UUID v4 per process, also on logs: a format change now, cheap); the Prometheus name mapping (documented); the tracing-opentelemetry pin and its upgrade policy; span-event dedup; open-span-at-shutdown semantics; the stance on the experimental span-attributes feature; one `init` wiring all signals; how this fits ADR-0004's feature flags. A fresh reviewer reviews before acceptance.

---

# [Comment #1]() by [gerchowl]()

_Posted on October 11, 2026 at 12:45 AM_

ADR-0003 (metrics and traces) Accepted and merged in #53 after 3 independent review rounds plus a final check (probed on opentelemetry_sdk 0.33, tracing-opentelemetry 0.34, otelcol 0.151, Prometheus 3.12): cumulative-only; per-process service.instance.id; vigil::metrics with crate scope and deterministic poisoning on translated-name conflicts; Prometheus promote_scope_metadata required; span-event dedup; nearest-recorded-ancestor propagation; per-signal loss accounting (with ADR-0004 amendment notes); compile-time validation of names, units and boundaries; a key-order writer per #64.

