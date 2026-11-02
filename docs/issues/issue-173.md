---
type: issue
state: open
created: 2026-11-02T05:54:03Z
updated: 2026-11-02T05:54:03Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/173
comments: 0
labels: feature, priority:backlog
assignees: none
milestone: none
projects: none
parent: none
children: none
synced: 2026-11-02T13:59:37.789Z
---

# [Issue 173]: [feat(audit): single-record inclusion proofs for auditors](https://github.com/vig-os/vigil/issues/173)

## Goal
Let an operator hand **one record** (or a small set) to an auditor together with a proof that it is included in a signed checkpoint. The auditor then verifies inclusion offline without receiving the whole trail.

## Context
- A consumer (#164) needs full-trail verification first, which already exists (#13). Single-record proofs are its stated next step.
- The trail already has one MMR over the whole trail (ADR-0005 §7) and signed checkpoints (§8), so an inclusion proof is a path from the record's leaf to a checkpointed MMR root.
- Consistency proofs for anchor holders are a different property and belong to #57. This issue covers inclusion only.
- ADR-0005 amendment 13 (#172, OQ4) defers inclusion proofs to this issue.

## Design first
An ADR-0005 amendment must decide the following before any code:
- the proof format (stable within 1.x);
- the library API, e.g. `prove_inclusion(dir, seq, checkpoint) -> InclusionProof` and `verify_inclusion(record_line, proof, &TrustPolicy)`;
- the CLI (`vigil-audit prove` and `vigil-audit verify-proof`);
- what the proof reveals about other records (only sibling digests);
- the interaction with archiving (amendment 10) and erasure (#165).

