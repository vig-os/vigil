---
type: issue
state: closed
created: 2026-11-03T02:50:59Z
updated: 2026-11-03T13:22:17Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/195
comments: 1
labels: bug, priority:medium, effort:small
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-04T08:43:06.212Z
---

# [Issue 195]: [test(audit): V3b-2 follow-ups: k−1 boundary rows, single outcome computation, A13/A7w/A16 assertions](https://github.com/vig-os/vigil/issues/195)

Follow-up to #194 (#13 V3b-2), from the fresh review (verdict: nits). Behaviour is correct; these are test gaps and tidy-ups.

1. **Boundary at `k−1` is untested.** Two mutants survive both `cargo test --features audit verify` and `--test audit_verify` (exit 0):
   - `head-not-last` with the condition changed to `r.seq + 1 < k`, which ignores a record at exactly `k−1`;
   - `genesis-not-first`, changed the same way.

   A10 and A11 only place the extra record two or more seqs below `k`. Add rows with the extra record at `k−1`, one for each condition.
2. **The structural outcome is computed twice:** in `engine.rs` `resume_findings` (~l.283) and again in `resume.rs` `collect_candidates`. Both run `structural_check`, `hex_to_bytes` and the `is_genesis_head` expression. The results are identical, but ruling 13-V3-d5 point 10 says "computed once". Compute it once and share the result (DRY).
3. **A13 does not prove its trail-filter claim.** It fails on base at compile time (it calls `collect_candidates`), not at runtime. Its "no foreign candidate" assertion holds even without the trail filter, because the foreign resume is invalid anyway (`lost_through=5`, no opening). Use a foreign resume that would be valid on the selected trail.
4. **Weak assertions.**
   - A7w uses `contains`/`ends_with` where full-string equality was specified.
   - A16 checks the `SeqConflict` count and seq, not byte-identity across the two input orders.
5. **Tidy-ups.**
   - Two lines are over-long: `src/audit/verify/mod.rs:249` (105 chars) and `engine.rs:306` (115).
   - ADR-0005 §19.9 says "§19.6 stays Proposed" twice in a row.

Refs: #13

---

# [Comment #1]() by [gerchowl]()

_Posted on November 3, 2026 at 01:22 PM_

Fixed by #196 (merged to dev at 6f8b953), reviewed by fresh reviewers over three rounds.

