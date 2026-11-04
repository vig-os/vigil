---
type: issue
state: closed
created: 2026-11-03T00:52:23Z
updated: 2026-11-03T13:22:12Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/193
comments: 1
labels: bug, priority:medium, effort:small
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-04T08:43:06.997Z
---

# [Issue 193]: [audit(verify): test the no-crash mark's native-successor condition and the engine's finding sort](https://github.com/vig-os/vigil/issues/193)

## Problem
The fresh re-review of #192 (#13 V3b-1, round 2) found two test-coverage gaps. The code is correct in both cases.

1. **The no-crash mark's "next native input" condition has no test.** Mutating `mark_no_crash` to take any next input (`.find(|i| i.native)` → `.next()`) passes both the lib and the integration tests. The mark is also tested only at unit level: none of the mark mutants fail an integration test.
2. **`first_broken_link_returns_first_error_in_ruled_order` (mod_tests) sorts its findings itself** (`findings.sort_by_key(|f| f.seq())`), so it doesn't exercise the engine's sort. With the engine's final sort in `engine::check` disabled, all 56 `audit::verify` lib tests still pass. Three integration tests catch it, so the ruled order is covered, but not by the test whose name claims it.

## Fix
- Add a test where a shipped copy sits between an archive and its native successor in the input order. The mark must come from the next native input only. Add an integration-level mark test on a real writer trail: rotation, then a trailing fragment appended to the archive.
- Rewrite the mod test so it calls the engine (or the shared sort) on findings in unsorted order, and drop the in-test sort.
- Prove each fix with a runtime mutant: exit 101, then revert, then exit 0.

Refs: #13 (V3b-1 review nits). Lands before C1.

---

# [Comment #1]() by [gerchowl]()

_Posted on November 3, 2026 at 01:22 PM_

Fixed by #196 (merged to dev at 6f8b953), reviewed by fresh reviewers over three rounds.

