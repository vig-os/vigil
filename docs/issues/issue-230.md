---
type: issue
state: open
created: 2026-11-19T15:20:28Z
updated: 2026-11-19T15:20:28Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/230
comments: 0
labels: none
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-20T09:45:03.658Z
---

# [Issue 230]: [audit: doc and Stop-path follow-ups from rule-2 reporting](https://github.com/vig-os/vigil/issues/230)

Follow-ups from the review of #229 (rule-2 MMR mismatches from the shared fold). None of these changes behaviour.

1. **CHANGELOG wording overclaims.**
   - It says "every native … checkpoint whose fields differ is reported" and "records every checkpoint … in every segment".
   - Ruling 13-V4-d10 point 6 is a documented limit: once a segment has a violation, the rest of that segment is unchecked, so a second mismatch there is not reported.
   - Fix: state that limit.
2. **ADR-0005 §19.9 is out of date.**
   - It says fold entries are "dropped under outer Stop". They are now never computed under `Reaction::Stop`.
   - It does not state the 13-V4-d10 point 6 limit.
   - Fix: correct both.
3. **The reader's Stop path still does a little fold work.** `apply_checked` computes `mmr.root()` and builds the fold report unconditionally. On checkpoints after a loss point this is hashing the code before #229 skipped. Gate it on the same flag that decides whether fold entries are recorded.
4. **Test comment cleanup.**
   - Remove the stray `-- no wait, cp5 was a resume (r5).` in `build_sealed_two_mismatch`.
   - Replace the `0xafe9942` notation for a commit.
   - Fix the earlier-violation row's doc comment: cp2 has no fold entry because of `RecordRolledBack` in the live segment, not the sealed-segment latch.

Refs #13

