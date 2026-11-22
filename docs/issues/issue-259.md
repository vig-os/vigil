---
type: issue
state: open
created: 2026-11-22T02:26:44Z
updated: 2026-11-22T09:03:22Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/259
comments: 3
labels: none
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-22T09:27:07.212Z
---

# [Issue 259]: [refactor(audit): derive resume-gap confirmation from the receipt match outcome](https://github.com/vig-os/vigil/issues/259)

Follow-up to #258 (#13, ruling 13-V7-d1 point 8).

Gap confirmation re-applies `Classifier::set_aside` on a classifier built without gaps, then `receipts::matches`, before the main receipt pass. It makes the same decision as `match_one` today (same start and end bounds; no resume receipt can sit inside a gap), but it rebuilds the predicate instead of reusing `match_one`'s outcome, so a future step added to `match_one` could make the two drift. Derive confirmation from the set of receipts `match_one` reports as matched, with one pass.

Refs: #13
---

# [Comment #1]() by [gerchowl]()

_Posted on November 22, 2026 at 02:54 AM_

Also from #258: G9 and G9c in `src/audit/verify/gaps_tests.rs` still compute `res1_digest` from hand-built deterministic fixtures instead of pinned constants; and the shipped-only opening limit is cited as 13-V4-d10 point 5 in one place and 13-V4-d7 in the `Verifier::receipts` rustdoc — align both on 13-V4-d10 point 5 (d7 is the shipped-copy run decision).

---

# [Comment #2]() by [gerchowl]()

_Posted on November 22, 2026 at 05:12 AM_

Also from #260 (`src/audit/verify/gap_anchors_tests.rs`): the A9 and A9b comments say ACCEPTANCE but they are regression rows; helper docs near l.70 and l.84 and on `line_without_lf` name rows (l.70 also misstates A1's anchors). In the rustdoc, write the gap rule once on `Verifier::anchor` and state there that the opening anchor must match under the anchor rule (not forked); link to it from `RevocationMismatch`, `LostRecord` and the `Gap` doc.

---

# [Comment #3]() by [gerchowl]()

_Posted on November 22, 2026 at 09:03 AM_

Also from #261: `src/audit/verify/review_tests.rs` r12 repeats five field assertions after its whole-list `assert_findings`; drop them so the row ends in one assertion.

