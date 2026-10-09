# Architecture decision records

Decisions that shape vigil's on-disk contract and its concurrency behaviour. Each ADR records what was decided, the evidence behind it, and what was rejected, so a reviewer can challenge it before code depends on it.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-on-disk-format.md) | On-disk format: OTLP/JSON Lines | Accepted |
| [0002](0002-rotation-and-retention.md) | Multi-process rotation and retention | Accepted |

ADR-0003 (the audit trail) is owned by [#10](https://github.com/vig-os/vigil/issues/10) and lands with the 0.3.0 design.

## Template

Files are named `NNNN-short-title.md`; numbers are never reused. Each ADR has these sections, in this order:

1. **Status** (Proposed, Accepted, or Superseded by ADR-NNNN) and **Date**
2. **Context**: the forces and the evidence, linked
3. **Decision**: what we do, stated so a test could check it
4. **Consequences**: what gets easier, what gets harder, what we now promise
5. **Alternatives considered**: and why each was rejected
6. **References**: issues, specs, probes

Where a detail is settled by an implementing issue, the ADR says "as implemented in #N" and links it; the ADR is updated when that issue lands. An accepted ADR is changed only by a new ADR that supersedes it, except for such details and typo fixes.
