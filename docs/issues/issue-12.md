---
type: issue
state: closed
created: 2026-10-09T13:22:01Z
updated: 2026-10-13T06:00:08Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/12
comments: 2
labels: feature, security, priority:medium, effort:large
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:43.106Z
---

# [Issue 12]: [feat(audit): hash chain, trail-wide MMR and ed25519 checkpoints (vendored primitives, ADR-0005)](https://github.com/vig-os/vigil/issues/12)

> **Corrected at close (architect, 2026-10-13), as delivered and per ADR-0005:** there is one trail-wide MMR (decision 7), not per-segment roots. The primitives are vendored: `blake3` and `ed25519-dalek` behind the `audit` feature, plus vigil's own MMR, which is compatible with tessera. There is no `tessera-core` dependency (decisions 14–15, owner decision). The original text below is unchanged.

Implement the chain and checkpoints from the ADR (#10) using `tessera-core` (blake3, MMR, ed25519). `tessera-core` only, never `tessera-io`, so the default build stays light. Checkpoint cadence configurable (every N records or T seconds, plus on rotation).

---

# [Comment #1]() by [gerchowl]()

_Posted on October 11, 2026 at 12:58 AM_

Architect decision: ADR-0005 couples the sink to the cryptography (final `audit.hash`/`audit.prev_hash` per record; due and creation checkpoints signed in the same write and fsync). So #11 and #12 are **one implementation in two serial PRs**: (A) pure format primitives (encoding, chain, MMR, checkpoint signing, golden vectors; BSD-3-Clause added to deny.toml), then (B) the durable sink and record API. Verify stays in #13; the rules still open in #66 are not implemented yet.

---

# [Comment #2]() by [gerchowl]()

_Posted on October 13, 2026 at 06:00 AM_

Closing. A fresh acceptance audit at dev 89472d6 found every criterion met.

- **Met:** the hash chain (golden), the trail-wide MMR (decision 7), ed25519 checkpoints (golden and RFC 8032), the vendored primitives behind `audit` with a light default build, the N/T/rotation checkpoint cadence, and exactly three crate-scoped BSD-3-Clause exceptions in `deny.toml`.
- **Title and body corrected:** a trail-wide MMR instead of per-segment roots, and no tessera-core dependency (decisions 14–15).

