---
type: issue
state: closed
created: 2026-10-12T15:34:42Z
updated: 2026-10-13T12:55:20Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/118
comments: 1
labels: refactor, priority:low, effort:small
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:24.299Z
---

# [Issue 118]: [refactor(audit): history_segment argument struct; drop test-only predecessor wrapper](https://github.com/vig-os/vigil/issues/118)

Nits from the final falsifier review of PR #111 (merged at 75107d7). Both are code-shape issues, not behaviour.

- `src/audit/storage.rs` `history_segment` carries `#[allow(clippy::too_many_arguments)]`, placed before its doc comment and without a justification. This is the repo rule from the known traps: no unjustified `#[allow]`. Replace the long parameter list with a small context struct, such as the per-run state of `run`/`run_loss`/`must_close`, so the lint is satisfied, and drop the allow.
- `predecessor` only survives as a `#[cfg(test)]` wrapper. Either port its tests to `history_segment` or `predecessor_run` and remove it, or document why the test-only seam exists.

Acceptance:
- no `#[allow(clippy::too_many_arguments)]` is left in `src/audit/`;
- no `#[cfg(test)]`-only production wrapper remains without a doc reason;
- the 72 reader tests and all B3d1 mutants still behave the same;
- `nix flake check -L` passes.

---

# [Comment #1]() by [gerchowl]()

_Posted on October 13, 2026 at 12:55 PM_

Fixed by #146 (merged into dev at c4f6e06): both too_many_arguments allows removed (scan_inner gets SegmentContext; history_segment's was redundant), test-only predecessor wrapper removed, tests ported 1:1; 266 lib audit tests unchanged. Review found a pre-existing test gap (an inherited run passed into a later history segment's first strict scan survives as a mutant); folded into #13 slice 13-R.

