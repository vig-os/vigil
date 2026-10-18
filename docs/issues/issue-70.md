---
type: issue
state: closed
created: 2026-10-11T00:57:06Z
updated: 2026-10-11T10:25:00Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/70
comments: 1
labels: discussion
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:29.231Z
---

# [Issue 70]: [design: receipts across a resume — lost receipts, expect_head and the expected head after structural loss](https://github.com/vig-os/vigil/issues/70)

Split out of the ADR-0005 amendment (#66) after its review-round cap. The four #66 sub-decisions are decided there; this interaction between **receipts and `vigil-audit resume`** is not.

**The problem.** After structural loss (a deleted live file), `resume` continues `seq` from the named head (ADR-0005 decision 8), so new records reuse the `seq`s of lost, acknowledged records. Under #66's receipts rule (range = start through head, every receipt must match), the application's receipts for the lost records are `ReceiptMismatch` **for good**, and dropping them from the input hides the loss.

**A drafted mechanism, withdrawn from #66 because review round 3 broke it** (model probe at the #66 PR, tests `r4`, `r8`, `r9`, `r11`):
- `lost <seq> <hash> <resume seq> <reason>` lines → `ReceiptLost` (warning), accepted only if the named resume record is receipted, has the shape `resume` writes, and `seq` ∈ (named head, `lost_through`]; `resume --lost-through <seq>`; the `vigil.audit.` action prefix reserved in `Entry`.
- **M1 (major):** an old honest resume still covers a later rollback of the *new* records in (named head, lost_through], because receipts carry no time and the app holds two receipts per `seq` there. Fix direction: the resume record commits to the exact lost set (e.g. blake3 of the sorted lost receipt lines in `audit.details`), and `lost` lines must match it.
- **M2 (major):** after a resume, `expect_head` (decision 5) and the rotation's expected head (decision 9, "highest `seq` among receipts and close checkpoints") pick a lost receipt above the new head, so `open` is `HeadMismatch` and cannot recover; at a reused `seq` two hashes exist. Fix direction: the application replaces its receipts at a resume (stores the resume's receipt, marks lost ones), and both heads come only from receipts stored after the latest resume.
- Edge cases from review: a start equal to the resume's opening checkpoint (named head below the start); a crash orphan at a reused `seq` after a resume (two `waive` lines for one `seq`).

**Decide:** how receipts, `expect_head`, the expected head and waivers behave across a resume, with tests for #13. Must be decided before #13 implements receipts reconciliation for resumed trails. Until then, ADR-0005 says: the old receipts are `ReceiptMismatch`.

Refs: #10, #13, #66, #68

---

# [Comment #1]() by [gerchowl]()

_Posted on October 11, 2026 at 10:24 AM_

Resolved by ADR-0005 amendment 2, PR #77 (merged into dev).

