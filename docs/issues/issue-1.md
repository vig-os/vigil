---
type: issue
state: closed
created: 2026-10-09T13:21:38Z
updated: 2026-10-09T15:40:07Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/1
comments: 2
labels: feature, priority:high, area:docs, effort:medium
assignees: none
milestone: 0.1.0 — logs core
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:46.956Z
---

# [Issue 1]: [design: vigil architecture — OTLP/JSON Lines telemetry core + opt-in audit layer](https://github.com/vig-os/vigil/issues/1)

Epic and design anchor. Decisions already taken, with the evidence, in gerchowl/g-fleet#355 (comments 2026-10-09); the repo is declared in vig-os/org-config#327.

## Decided
- **API:** code uses `tracing`. vigil bridges it into OpenTelemetry (`opentelemetry` / `opentelemetry_sdk` 0.33; logs and metrics are Stable upstream, traces Beta).
- **On-disk format, conformant from day one:** the [OTel file-exporter spec](https://opentelemetry.io/docs/specs/otel/protocol/file-exporter/). JSON Lines; one `LogsData` / `MetricsData` / `TracesData` per line; **one signal per file**. Encoding per [OTLP/JSON](https://opentelemetry.io/docs/specs/otlp/#json-protobuf-encoding) (Stable): 64-bit ints as decimal strings, hex trace and span ids, integer enums, lowerCamelCase.
- **Serializer:** `opentelemetry-proto` (features `logs`/`metrics`/`trace` + `gen-tonic-messages` + `with-serde`, no tonic transport), the official encoder. Upstream has **no file exporter**; that is vigil's job.
- **Location:** `$XDG_STATE_HOME/<service>/{logs,metrics,traces}.jsonl`.
- **Rotation:** by size, with age retention, **safe across processes** (every rotating crate in the ecosystem is only thread-safe).
- **Shipping** stays outside the crate: Loki ≥3 and Prometheus ≥3 ingest OTLP natively.
- **Audit** is a *separate, lossless stream* behind `feature = "audit"`, built on `tessera-core` (blake3, MMR, ed25519).
- Name: crate `vigil-telemetry`, lib `vigil` (`vigil` is taken on crates.io).

## ADRs to write (docs/adr/)
- [x] ADR-0001 on-disk format (OTLP/JSONL, file-exporter conformance, versioning stance while the file-exporter spec is *Development*)
- [x] ADR-0002 multi-process rotation and retention
- [ ] ~~ADR-0003 audit trail~~ → moved to #10 (0.3.0)


---

# [Comment #1]() by [gerchowl]()

_Posted on October 9, 2026 at 02:05 PM_

Scope for closing this epic in **0.1.0**: ADR-0001 (on-disk format) and ADR-0002 (multi-process rotation and retention). **ADR-0003 (audit trail) moves to #10** (0.3.0 design: audit trail ADR), which is that ADR's natural owner; its checkbox here will be ticked by #10's PR. The decisions listed above stand.

---

# [Comment #2]() by [gerchowl]()

_Posted on October 9, 2026 at 03:40 PM_

ADR-0001 (on-disk format) and ADR-0002 (rotation and retention) landed in #21. ADR-0003 is owned by #10 (0.3.0).

