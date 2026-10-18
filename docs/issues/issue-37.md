---
type: issue
state: closed
created: 2026-10-10T22:18:06Z
updated: 2026-10-10T23:50:50Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/37
comments: 1
labels: feature, priority:high, area:docs, effort:medium
assignees: none
milestone: 0.2.0 — metrics + traces
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:38.137Z
---

# [Issue 37]: [design: ADR-0004 public API, stability, composition and feature flags (gates 0.2.0)](https://github.com/vig-os/vigil/issues/37)

Gate for 0.2.0: #7/#8 would add more public exporter types, so the API policy has to be decided first. Evidence from the path-to-1.0 pre-mortem (2026-10-10):
- **R1 (critical):** `src/logs.rs` publicly `impl LogExporter for OtlpJsonLogExporter`, where `LogExporter` comes from `opentelemetry_sdk` 0.33. That crate ships a breaking minor about twice a year (0.29→0.33 in 18 months). As soon as vigil is 1.0, every upstream bump becomes a vigil **major**, and cargo-semver-checks doesn't detect public-dependency bumps.
- **R2:** consumers don't fit `init`. flock needs its own filter variable and default (`FLOCK_LOG`, `flk=info`), a human/JSON console layer, and its own `Registry`. vigil has no `Config::filter`/env-var option, no console layer and no `vigil::layer()` to compose with.
- **R10:** `RotationConfig` has public fields and isn't `#[non_exhaustive]` (adding one field is a semver major, which cargo-semver-checks proved). `InitError(String)` has no error kinds. `Guard` has no fallible `shutdown`. Retention is `retention_days: u64` in `Config` but `Option<Duration>` in `RotationConfig`. `MemorySink` (a test helper) and `NON_FINITE` are in the stable surface. There is no feature-flag plan for metrics, traces, audit or push.

**Decide in `docs/adr/0004-public-api-and-stability.md`:** what stays public (exporters? behind which feature? how opentelemetry bumps are versioned: hidden behind vigil types, a `0.x`-tied feature, or major-per-bump); `#[non_exhaustive]` and sealed `LineSink`; error kinds; `Guard::shutdown(self) -> Result`; the composition API (`vigil::layer()` / `Config::filter`, env var name, an opt-in console layer); the feature-flag plan (`metrics`, `traces`, `audit`, `push`, `test-util`); MSRV policy (and how CI tests it); the semver-check baseline before the first publish. Every public item is justified. A fresh reviewer reviews the ADR before acceptance.

---

# [Comment #1]() by [gerchowl]()

_Posted on October 10, 2026 at 11:50 PM_

ADR-0004 Accepted and merged in #54 after 3 adversarial review rounds plus a final check. OpenTelemetry stays out of the stable API (vigil::metrics, vigil::propagation); `--cfg vigil_unstable` gates unstable items; one pipeline per process; matchable error kinds; Guard::flush/shutdown with per-signal loss counts; feature flags. The metric identity-conflict mechanism is split out to ADR-0003 (#38). The SDK-free metrics API crate is deferred to #61.

