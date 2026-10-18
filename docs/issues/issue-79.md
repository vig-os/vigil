---
type: issue
state: closed
created: 2026-10-11T03:54:52Z
updated: 2026-10-11T14:41:45Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/79
comments: 1
labels: feature, security, priority:high, effort:small
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:28.823Z
---

# [Issue 79]: [feat(audit): format support for ADR-0005 amendment 2 (tag 0x07, resume opening checkpoint with mmr_size ≠ seq)](https://github.com/vig-os/vigil/issues/79)

ADR-0005 amendment 2 (#68/#70, PR #77) changes the already-merged format layer (PR #73, `src/audit/format.rs`):
- `src/audit/format.rs:232` rejects a checkpoint unless `size == seq` (`if fields.size != context.seq { InvalidConfig }`), so a resume opening checkpoint whose `mmr_size` counts records can't be built. Change the guard exactly as amendment 2 specifies.
- Add the optional encoding tag **0x07** to `RecordContext` (omitted when absent, so the existing vectors 0x01–0x06 are unchanged: additive, pre-1.0, allowed by ADR-0005 decision 12).
- Add a golden vector with `0x07` to `tests/fixtures/audit/primitives.txt`, and a test that the old vectors are byte-identical.
Lands as part of the audit B-series (before B3 exposes resume), after #77 is accepted. Refs: #12, #68, #70, #77.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 11, 2026 at 02:41 PM_

Done in PR #85 (merged into dev). Checkpoints are rejected only when `size > seq`, tag 0x07 carries the authenticated `audit.repaired`, reserved `audit.*` names are rejected in the unhashed context, and a checkpoint with zero MMR size is allowed only at creation. The old vectors are byte-identical, and ADR-0005 amendment 2 is marked Accepted.

