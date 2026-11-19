---
type: issue
state: open
created: 2026-11-15T19:24:12Z
updated: 2026-11-18T13:08:13Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/215
comments: 1
labels: priority:low, area:testing, effort:small
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-19T09:58:13.528Z
---

# [Issue 215]: [test(audit): classify follow-ups: second Collect killer for found routing, Collect found on reader-Err paths, gate aliasing](https://github.com/vig-os/vigil/issues/215)

Follow-up from the review of #212 (#197 R2b S3b1b). These are nits found by the independent review; none of them changes behaviour.

1. **A second Collect-side killer for the strict Collect arm's `found` routing.** A mutant where the strict Collect arm feeds a rejected record as `Record` is caught by exactly one Collect row (live `[cp0, e1, H]` with `expected = e1`). Ruling 197-d1 addendum 27.2 asks for two Collect-side killers for a Collect-only mutant. The multi-segment first-equality sweep cannot see it, because the reader returns `Err` on that layout and the sweep compares `found` only on `Ok` paths. Add a second Collect row with the same shape and the expected head in a sealed segment, and show the mutant fails it.
2. **Tolerant-Collect `found` on reader-`Err` rows is unpinned.** Several tolerant-Collect mutants survive with 0 first-violation and 0 Ok-path differences. A damaged sealed segment always makes the reader `Err` at the live segment, so these mutants change only Collect's `found` on rows where the reader errs. Decide whether Collect's `found` on reader-`Err` paths is part of the contract (S3b2 / V4a consume Collect). Pin it if so, or document that it is unspecified.
3. **Structural gate aliasing.** `coverage_gate_no_segment_loop_in_storage_rs` derives the walker set from call paths. A loop that calls a walker through `use self::history_segment as x` or `let w = history_segment;` is not detected. This is the sabotage class (addendum 10), not an accidental bypass; resolve aliases or document the limit in the test doc.
4. **`scan_inner`'s `expect`** moved from its old place to two sites in `storage.rs` (~812, ~940). Check whether that invariant can be expressed in the type instead.

Acceptance: each item is fixed with a row or test that fails without the change (shown once), or documented with its reason.

---

# [Comment #1]() by [gerchowl]()

_Posted on November 18, 2026 at 01:08 PM_

From the #216 review, a test doc nit: `strict_closer_without_open_run_live_is_base` says "an accepted strict-pass resume (gated by `ctx.run && boundary_resume && !first && is_resume`)". That condition gates the strict closer latch, not whether the resume is accepted. Suggested: "an accepted strict-pass resume, whose closer latch (`ctx.run && boundary_resume && !first && is_resume`) stays false because `ctx.run` is false".

