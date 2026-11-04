---
type: issue
state: open
created: 2026-11-03T10:18:01Z
updated: 2026-11-04T08:38:36Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/197
comments: 10
labels: priority:medium
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-04T08:43:05.301Z
---

# [Issue 197]: [refactor(audit): extract the reader's run classification into one shared pure module (#13 V4 prerequisite)](https://github.com/vig-os/vigil/issues/197)

Ruling 13-V4-d4 (owner decision, on #13): the reader's run rule (ADR-0005 amendment 6, B3d1-d1/d3/d4, ruling 107-d1) must have **one** implementation that both the storage reader and the verifier (#13 V4a/V4b) use.

## Scope
- Move the run classification that lives in `history_segment` and its callers in `src/audit/storage.rs` into a crate-private, pure module: per-segment `run`, `unsealed` and boundary-resume, base selection, run closure (i)+(ii), and the in-run seq and link rules.
  - No I/O, locks or writer state. It works on decoded segment summaries.
  - It returns the classification plus **every** violation, as typed values.
- The reader maps the first violation, in today's order, to the identical `CorruptTrail` and detail. No behaviour change: `audit::storage::tests` pass unchanged.
- No public API change.

## Why
Four verifier brief revisions restated the rule from the ADR and drifted from the reader each time (archived base, the immediate-resume boundary after a run segment, a genesis closer, rejected trails). Two copies of one ADR rule would drift again.

Refs: #13
---

# [Comment #1]() by [gerchowl]()

_Posted on November 3, 2026 at 10:38 AM_

## Ruling 197-d1 (architect): how #197 is staged

The pre-dispatch check of the #197 brief prototyped it against the reader on origin/dev 03ec68f. It found that the design cannot keep the reader's exact behaviour as written:
- The detail text depends on the path (live, rotated strict, rotated fallback).
- `history_segment` rescans a rotated segment on the fallback path after any strict `CorruptTrail`.
- The repair-attestation check sits between two classifier checks on the same record.
- No test anywhere asserts a `CorruptTrail` detail.
- The churn is ~520–570 lines.

#197 is therefore split into three PRs, merged in order.

1. **R0: pin the reader's behaviour (tests only, no product code).** For every `corrupt(…)` detail in `src/audit/storage.rs`, and on every path that can reach it (`open` on the live file, a rotated segment's strict pass, the fallback rescan, `scan`/`scan_closing`/`scan_staged`, refresh with `opening=false`, and `resume`), at least one test builds the layout and asserts the **exact** detail string and the error kind.
   - Include the run layouts the V4 checks used: archived base; `boundary_resume` after an unsealed or run segment; closer and second run; the genesis closer after a fragment-only segment; non-increasing seq; in-run gap; invalid record in a run; resume declaration mismatch; opening MMR mismatch; and the attestation order pair `[h5, fragment, next]` with seq 7 linked vs seq 6 broken.
   - A coverage test (or script run in CI) fails if a `corrupt("…")` detail in `storage.rs` has no asserting test, or is marked unreachable without a reason.
   - Every assertion is proven by a mutant: change the detail string or the check, and the named test exits 101.
2. **R1: the per-record state machine as a pure `RunState`.** This covers `apply_checked` with the resume-declaration validator and the fold (iii).
   - `State` embeds `RunState`. The writer's `State::after` keeps its behaviour, and `checkpoint_time`/`since_checkpoint` stay in `State` (writer state is not in the pure part).
   - The repair attestation goes into the classifier **as data** (the fragment-bytes digest and the record's `repaired` field), so the order is the reader's.
   - All R0 tests pass unchanged.
3. **R2: run, boundary and base classification** (strict pass, then fallback rescan from a saved segment-start state) in the pure module, plus the `classify` wrapper V4a uses.
   - It is a push API with resumable state, so the reader's lock and refresh paths keep streaming.
   - `classify` takes an iterator, not a slice, so it never buffers the trail.
   - All R0 tests pass unchanged.
4. **"Every violation"** (13-V4-d4 point 1) is defined as follows. After a fold (iii) mismatch, classification continues as if the checkpoint matched, and the mismatch is recorded. Any other violation ends the run under consideration, is recorded, and classification resumes at the next segment boundary. The reader still reports the first violation in its current order.
5. Only `pub(crate)` or narrower. `check_public_api.py` and `cargo semver-checks` show no change.


---

# [Comment #2]() by [gerchowl]()

_Posted on November 3, 2026 at 12:34 PM_

### Addendum to ruling 197-d1 (after the R0a review, PR #199)
6. **R0a scope is trimmed to fit size.** R0a is already 873 lines against a 700-line stop. Its fix round pins only the missing site ("missing head" occurrence 2, reachable via `scan(.., opening=false, ..)` on an empty or fragment-only file) and the live-path check order (state `[cp0,e1]` + live `[e1]` → `opening checkpoint duplicates predecessor`, which flips to `missing opening checkpoint` under a swap).
   - **R0b takes over:**
     - `scan_staged`, `scan_closing` and `TrailReader::open` on a live file, including the path-dependent archived-base case (`scan` Ok vs `scan_staged` `initial checkpoint does not link genesis`);
     - the named layouts `boundary_resume` after a run segment, the opening MMR mismatch, and the genesis closer;
     - fallback, refresh and resume, as before.
   - The gate's site labels are documentation only. R0b adds a per-path coverage list in the PR body, where each (site, path) pair names its test and its mutant.

---

# [Comment #3]() by [gerchowl]()

_Posted on November 3, 2026 at 02:09 PM_


### Addendum 7 to ruling 197-d1 (after the R1 check)
7. **The repair attestation moves to R2, not R1.** Carrying it in R1 merges the strict-path and fallback attestation sites, so the coverage gate reads 50 vs 51 and an R0 assertion changes, which point 2 forbids. It also pushes R1 past ~400 lines. The attestation is segment-level (it consumes the fragment gap), so it belongs with R2's segment classification. R2 therefore:
   - moves the attestation into the pure part as data (the fragment-bytes digest and the record's `repaired`), checked first, ahead of the record checks;
   - re-keys the coverage gate deliberately, with the merge stated in the PR;
   - makes the gate also fail on an assertion whose site no longer exists.
   
   Until R2 lands, R1's `apply_checked` alone is **not** a complete first-violation oracle for layouts with a fragment gap (e.g. `[cp0,e1,fragment,e2 prev≠e1]`: the reader says `missing or mismatched repair attestation`, `apply_checked` alone says `record rolled back, changed or broke its hash link`). Nothing outside the reader may call it as one before R2.
8. **R0b adds the hash-link boundary pin** that kills the surviving `<=` → `<` mutant: `[cp0, e1, x(seq=1, prev=e1.hash, other content)]` on live `open`, strict `scan` and refresh → `record rolled back, changed or broke its hash link` (the mutant gives `sequence gap without checkpoint`).


---

# [Comment #4]() by [gerchowl]()

_Posted on November 3, 2026 at 05:02 PM_


### Addendum 9 to ruling 197-d1 (after the R0b round-2 review)
9. **The coverage gate parses Rust with a real parser, not a hand-written lexer.**
   - Two review rounds in a row bypassed the hand-written scanner in `storage_tests.rs`: round 1 with turbofish calls, a fn-pointer alias and `'"'`; round 2 with a multi-byte char literal, where `['é','"']` hid a bogus call and produced false "uncovered" reports.
   - Each fix closes one literal shape and leaves the class open.
   - The gate therefore uses **`syn`** (already in `Cargo.lock` at 2.0.119 as a transitive dependency, so no new crate enters the supply chain). It is added as a **dev-dependency** with the `full` and `visit` features, and it parses `storage_tests.rs`. The gate:
     - walks every expression and path;
     - requires each use of the path segment `assert_corrupt`, other than the helper's own `fn` item, to be a direct call (`ExprCall` whose callee path ends in `assert_corrupt`, with or without generic arguments) whose second and third arguments are a string literal and an integer literal;
     - fails on any other use (an alias, a fn pointer, a non-literal label);
     - keeps the stale-label, uncovered-site and 51-site checks.
   - For storage sources (`storage.rs`, and in R1 `runs.rs`), sites are found the same way: every `ExprCall` whose callee path ends in `corrupt` with a string-literal argument. The hand-written lexer is deleted.
   - **Known limit, stated in the gate's doc comment:** a static gate cannot prove a call is reachable (`if false { assert_corrupt(…) }`). Mutants remain the proof that each pin fires.


---

# [Comment #5]() by [gerchowl]()

_Posted on November 4, 2026 at 01:57 AM_


### Addendum 10 to ruling 197-d1 (owner decision 2026-11-04, after the R0b round-3 review)
10. **The coverage gate's threat model, plus one owner-approved 4th round for R0b.** R0b (PR #201) used its three fix rounds. Each round's review found a new way to hide a call from the static gate. The owner approved one exceptional 4th round with a fixed scope.
    - **Threat model, stated in the gate's doc comment.** The gate catches **drift**: a `corrupt()` site added or renamed without a pin, or a pin whose label names no site. It does not defend against deliberate sabotage by a test author. Runtime exact-string asserts and per-site mutants remain the proof that each pin fires. Known limit: reachability (`if false { … }`, an uncalled closure).
    - **Round 4 fixes exactly these three, nothing else:**
      1. Exempt **only the single helper `fn assert_corrupt` in `mod details`**. Require exactly one such item, and fail on any other `fn` (or closure binding) named `assert_corrupt`. This closes the only hole that could make an unpinned site look covered.
      2. Fail on the identifier `assert_corrupt` anywhere inside a macro invocation's token stream (`visit_macro`, scanning nested token groups recursively). Pins must be direct calls.
      3. Fail on `assert_corrupt` in any `use` tree.
    - If round 4's review finds a blocker outside these three, the architect stops and reports to the owner. There is no 5th round.


---

# [Comment #6]() by [gerchowl]()

_Posted on November 4, 2026 at 02:32 AM_


### Addendum 11 to ruling 197-d1 (after the R0b round-4 review)
11. **R0b round 4 is accepted. The `proc-macro2` dev-dependency edge is waived, and the follow-ups go to #202.**
    - The round-4 review confirmed all three fixes of addendum 10 by probing: no shadowing `fn` or binding, no `assert_corrupt` inside macro tokens, none in `use` trees. Every round-3 bypass is still caught, the gates pass, and cargo-deny passes in CI.
    - Its only blocker was the brief's own scope line ("gate and PR body only"). Round 4 also added `proc-macro2` as a direct dev-dependency.
    - That edge implements fix 2 (walking macro token streams). It adds no new crate (1.0.107 was already locked), and cargo-deny passes. So it is not a defect outside the three fixes, and addendum 10 rules out a 5th round. The architect waives that scope line for this edge. The PR body's dependency claim has been corrected.
    - Dropping the direct edge (syn's `syn::buffer` can do the walk), and the out-of-scope shadowing shapes the review found (a `struct`, `const`, `static`, method, `extern` fn or `macro_rules!` named `assert_corrupt`, and `S::assert_corrupt(…)`), are deliberate sabotage under the addendum-10 threat model, not drift. They are filed as **#202** (0.3.0, priority:low).
    - #201 merges at its reviewed head once CI Summary is green.


---

# [Comment #7]() by [gerchowl]()

_Posted on November 4, 2026 at 03:12 AM_

R1 (#200) light re-check after the rebase onto R0b (head 81d3ae8): no blockers. The rebase delta is docs plus the syn gate extended to `runs.rs`. All 147 R0b pins pass on the refactor, the gate covers `runs.rs` (51 sites), and the `<=` hash-link and shim mutants die.

Two doc nits are **carried into R2** (it rewrites the same code), so no separate issue:
1. Restore the `///` rustdoc on `storage::State.run`.
2. Make the `storage::apply_checked` shim comment a `///` doc again.

The shim's inlined `checkpoint_time`/`since_checkpoint` lets are behaviour-neutral (the shim mutant still fails `audit::sink`), so that change is accepted as is.

---

# [Comment #8]() by [gerchowl]()

_Posted on November 4, 2026 at 04:05 AM_


### Addendum 12 to ruling 197-d1 (after the R2a pre-dispatch check)
12. **What "checked first" in addendum 7 means: the reader's per-path order binds.**
    - On dev the repair attestation is not literally first, and its position depends on the path:
      - In `history_segment` it follows the segment-level checks: multiple records, trail identity, an unparsable line before a complete record, a non-increasing seq inside a sealed run, a missing initial checkpoint, and a sequence gap inside a sealed run segment.
      - In `scan_inner` it precedes the immediate-resume check and `apply`.
      - Probe `[cp0, e1, fragment, x(seq=1, prev=cp0)]`: `history_segment` gives `record sequence did not increase inside sealed run`, while `scan` gives `missing or mismatched repair attestation`.
    - Addendum 7's "checked first, ahead of the record checks" therefore means **ahead of `apply_checked`'s per-record checks**. The binding order is the reader's actual order on each path, unchanged.
    - **R2a:** `check_attestation` plus `apply_checked` are **not** a complete first-violation oracle by themselves; the reader-side segment checks ahead of them remain in `storage.rs` until R2b. The rustdoc says exactly that.
    - **R2b** must move those segment-level checks while preserving each path's order, proven per path by the R0 pins.


---

# [Comment #9]() by [gerchowl]()

_Posted on November 4, 2026 at 06:45 AM_


### Addendum 13 to ruling 197-d1 (R2b slicing, after the prototype-first plan)
13. **R2b lands in three slices, each prototyped (compiled and tested) before dispatch.**
    - **S1: the `scan_inner` family on a strict-mode push-API `runs::Classifier`.** This covers `scan_inner` plus its thin `scan`/`scan_staged`/`scan_closing` wrappers; a separate wrapper slice would be empty. The prototype measured about 403 non-test lines, which is the ~400 target, not a raised limit. Gate re-key 49 → 48 is stated in its brief.
    - **S2: `history_segment`'s tolerant mode plus the fallback rescan from a saved segment-start state.**
    - **S3: the "every violation" collector, the iterator `classify`, the V4a walk over the 13-V4-d3 layouts, and the `runs.rs` caveat rewrite** (the module becomes the complete first-violation oracle).
    - **Typed violations** (13-V4-d4 point 1; this ruling's point 4) land in **S3**, where the collector consumes them. S1 and S2 keep each site's `corrupt("literal")` inline, so the syn gate keeps counting them.
    - Every slice keeps the reader's per-path order (addendum 12) and is proven by the R0 pins plus an independent base-vs-slice differential.


---

# [Comment #10]() by [gerchowl]()

_Posted on November 4, 2026 at 08:38 AM_

R2b S1 (#204) round 2 light re-review: comment-only delta, no behaviour change, all gates and CI green. One stale `//` comment is **carried into S2**, which rewrites this region of `storage.rs`: the `scan_inner` header comment (~`storage.rs:812`) still says the shim "calls `runs::check_attestation` at each record's reader-side position", but the strict `Classifier::feed_record` now makes that call internally. The PR-body `run_loss` overclaim was corrected by the architect.

