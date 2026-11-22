---
type: issue
state: open
created: 2026-11-21T00:46:57Z
updated: 2026-11-21T22:40:41Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/256
comments: 1
labels: none
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-22T09:27:08.075Z
---

# [Issue 256]: [test(audit): tidy the waiver rows and share the verifier test helpers](https://github.com/vig-os/vigil/issues/256)

Follow-up to #255 (#13, ruling 13-V7-d1 point 6).

- `src/audit/verify/waivers_tests.rs`: `w7_two_receipts_same_seq_different_hashes_are_not_invalid_config` carries an extra `.waive(1, …)` that makes it fail with waivers stubbed; drop the waiver so it pins only the two-receipts case (it overlaps `receipts_tests::two_receipts_one_seq_only_mismatch_fires`; merge if redundant).
- Add a `receipts_from(…, "   ")` accepted row, so trimming the reason before the emptiness check fails two rows (the rustdoc already promises whitespace-only reasons are accepted for both builders).
- Label the `InvalidConfig` group; rename `w7_second_receipts_from_same_values` (the reasons differ).
- Other `*_tests.rs` modules under `src/audit/verify/` still define their own `located`/`assert_findings`; move them to `tests_common.rs`.

Refs: #13
---

# [Comment #1]() by [gerchowl]()

_Posted on November 21, 2026 at 10:40 PM_

Also from #257 (live reconciliation rows in `src/audit/verify/live_tests.rs`): the L5 inline comment still says `highest_receipt` (the code uses `highest_evidence`); the L9c header comment talks about a mutation and should state the scenario only; the L8 group header should name L8a2, L8b2 and L8c2.

