---
type: issue
state: open
created: 2026-11-03T11:25:06Z
updated: 2026-11-03T11:25:06Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/198
comments: 0
labels: bug, priority:medium, effort:small
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-04T08:43:04.596Z
---

# [Issue 198]: [test(audit): two distinct resume records at one seq are untested in the verifier's declaration dedupe](https://github.com/vig-os/vigil/issues/198)

Found by the fresh re-review of #196 (pre-existing on dev a70e01c, not caused by #196).

The verifier dedupes resume declarations by `(seq, hash)` (`declarations` in `src/audit/verify/resume.rs` after #196; the old resume code on dev has the same key). The mutant that changes the key to `(seq, [0;32])` survives `cargo test --features audit verify` (exit 0): no test has two **different** resume records at one seq (a `SeqConflict` between two resume declarations).

**Ask:** add a row where two distinct `vigil.audit.resume` records share one seq, and assert that each gets its own `Resumed` and structural outcome (ruling 13-V3-d5 point 10: one outcome per (resume seq, resume hash)) and that the `SeqConflict` stands. Prove it with the mutant above (exit 101, then 0 after revert).

Refs: #13
