# Architecture decision records

Decisions that shape vigil's on-disk contract, its concurrency behaviour and its public API. Each ADR records what was decided, the evidence behind it, and what was rejected, so a reviewer can challenge it before code depends on it.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-on-disk-format.md) | On-disk format: OTLP/JSON Lines | Accepted |
| [0002](0002-rotation-and-retention.md) | Multi-process rotation and retention | Accepted |
| [0003](0003-metrics-and-traces.md) | Metrics and traces | Accepted |
| [0004](0004-public-api-and-stability.md) | Public API, stability, composition and feature flags | Accepted |
| [0005](0005-audit-trail.md) | Audit trail | Accepted (2026-10-11), amended by [#66](https://github.com/vig-os/vigil/issues/66); amendment 2 ([#68](https://github.com/vig-os/vigil/issues/68), [#70](https://github.com/vig-os/vigil/issues/70)) Accepted (2026-10-11); amendment 3 ([#90](https://github.com/vig-os/vigil/issues/90)) Accepted (2026-10-12, [PR #91](https://github.com/vig-os/vigil/pull/91)); amendment 4 ([#11](https://github.com/vig-os/vigil/issues/11), marker form and trail-wide cadence) Accepted (2026-10-12, [PR #92](https://github.com/vig-os/vigil/pull/92)); amendment 5 ([#11](https://github.com/vig-os/vigil/issues/11), public writer validation and provisional primitives) Accepted (2026-10-12, [PR #105](https://github.com/vig-os/vigil/pull/105)); amendment 7 ([#11](https://github.com/vig-os/vigil/issues/11), [#12](https://github.com/vig-os/vigil/issues/12), file-backed signing and key generation) Accepted (2026-10-12, [PR #108](https://github.com/vig-os/vigil/pull/108)) |
| [0006](0006-shipping.md) | Shipping: the Collector file shipper, an optional `push` feature, and the Alloy gap | Accepted |

## Template

Files are named `NNNN-short-title.md`; numbers are never reused. Each ADR has these sections, in this order:

1. **Status** (Proposed, Accepted, or Superseded by ADR-NNNN) and **Date**
2. **Context**: the forces and the evidence, linked
3. **Decision**: what we do, stated so a test could check it
4. **Consequences**: what gets easier, what gets harder, what we now promise
5. **Alternatives considered**: and why each was rejected
6. **References**: issues, specs, probes

Where a detail is settled by an implementing issue, the ADR says "as implemented in #N" and links it; the ADR is updated when that issue lands. An accepted ADR is changed only by a new ADR that supersedes it, except for such details and typo fixes.
