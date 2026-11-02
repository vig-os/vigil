---
type: issue
state: open
created: 2026-10-10T23:20:00Z
updated: 2026-10-11T01:10:53Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/57
comments: 1
labels: feature, security, priority:backlog, effort:large
assignees: none
milestone: none
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:32.316Z
---

# [Issue 57]: [feat(audit): external anchoring transports (RFC 3161 timestamps, transparency log) and consistency proofs for anchor holders](https://github.com/vig-os/vigil/issues/57)

Deferred from ADR-0005 (#10), decision 10.

In 1.0, an anchor is a checkpoint line copied to a place an attacker cannot rewrite. `vigil-audit checkpoints` exports these lines, and `vigil-audit verify --anchor` requires them to be present. With `push` (ADR-0006), checkpoints also ship to a backend like any other record.

**Not in 1.0, and the scope of this issue:**
- RFC 3161 time-stamp tokens over a checkpoint hash, from a hospital-internal TSA. This needs ASN.1/DER and an HTTP client.
- Submission to a (private) transparency log.
- A public `consistency_proof` API, so an anchor holder that keeps only checkpoint lines can check that a later checkpoint extends an earlier one. vigil's MMR is bit-identical to tessera-core's, so `tessera_core::hash::verify_consistency` already accepts these proofs.

**Constraint:** additive only. It must not change the v1 record or checkpoint encoding: a token rides in a new optional record kind, which needs an ADR-0005 amendment, or in a sidecar. A new ADR decides the transport.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 11, 2026 at 01:10 AM_

Scope note from the ADR-0005 amendment (#66, PR #71, decision 10): shipped and `push` copies of audit lines are **not anchors**. ADR-0006's shipping is best-effort (a full queue drops data, probes S4/Q), and a file shipper also ingests lines an attacker writes into the trail directory. In 1.0 an anchor is a checkpoint line taken from an in-process `Checkpoint` (`checkpoint()`/`close()`) or from a just-verified snapshot, copied out of band. **An audit-grade anchor feed** (lossless delivery of every in-process `Checkpoint` to an anchor holder, with backpressure instead of drops) is in this issue's scope, next to RFC 3161 and transparency logs.

Refs: #66

