---
type: issue
state: open
created: 2026-11-03T10:18:01Z
updated: 2026-11-08T02:01:50Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/197
comments: 20
labels: priority:medium
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-08T08:41:14.218Z
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

---

# [Comment #11]() by [gerchowl]()

_Posted on November 5, 2026 at 12:08 AM_


### Addendum 14 to ruling 197-d1 (owner decision 2026-11-05: S2 lands as one PR)
14. **R2b S2 lands as one atomic PR of about 645 non-test lines, above the usual ~400 limit.**
    - The only safe cut the planner found was "dead code first": S2a would add the tolerant classifier unused, behind `#[allow(dead_code)]` with 12 temporary UNREACHABLE gate rows, and S2b would switch `history_segment` onto it. That split meets the size limit only on paper, because S2a can't be verified on its own. A cut by behaviour needs hybrid latch bookkeeping that the planner judged unsafe.
    - The owner chose a single PR: the two prototype slices (`S2a.patch` then `S2b.patch` on 3994b07) squashed. No dead code, no `#[allow]` and no carrier UNREACHABLE rows ever reach dev. The gate stays at 48 sites.
    - **The proof is not the pins.** An independent systematic base-vs-head differential (all short token layouts, as for #204), comparing error strings and Ok-state fields (including `since_checkpoint`, `run_loss`, `checkpoint_time`, offset, length, newline and gap), is mandatory in the pre-dispatch check, in the implementer's PR and in the fresh review. Each differential must be shown to detect a planted regression.
    - **Mutant M4** as specified (sealed-seq ↔ missing-checkpoint) is equivalent, because the two guards have disjoint preconditions. It is replaced by **M4′**: swap trail identity with the sealed-seq check, on a layout where both guards fire.


---

# [Comment #12]() by [gerchowl]()

_Posted on November 5, 2026 at 02:41 AM_


### Addendum 15 to ruling 197-d1 (R2b S2: the `since_checkpoint` increment at the u64 bound)
15. **The shared writer-field helper saturates. The refactor deliberately unifies two base expressions, and this is the only intended difference from base.**
    - On dev (3994b07), base was inconsistent:
      - `scan_inner` computed `since_checkpoint` with `saturating_add(1)` (plus a no-op `.max(1)`);
      - the `storage::apply_checked` wrapper, which the fallback also uses, computed it with plain `+ 1`. At `u64::MAX` that panics in debug and wraps to 0 in release. A wrap to 0 would falsely signal "just checkpointed" to the writer's cadence (`sink.rs`).
    - S2's single helper `next_cp_fields` (required by the S2 check, for DRY) cannot match both. It uses **`saturating_add(1)`** everywhere.
    - The only observable difference from base is on the `apply_checked`/fallback path when `since_checkpoint == u64::MAX`: saturate instead of panic or wrap. The bound counts records since a checkpoint, so it is unreachable in practice, but the semantics must still be the correct ones.
    - Pins lock this on a strict path and on the `apply_checked`/fallback path: a state with `since_checkpoint = u64::MAX` stays `u64::MAX` after one more record.
    - The PR body states this as the single intended deviation, with this addendum as the reason. Differentials against base must show identical results everywhere except rows with that predecessor context on the `apply_checked`/fallback path, where base panics or wraps.
    - The architect's round-2 brief wrongly called plain `+ 1` "base's expression" for `scan_inner`. That brief is superseded.


---

# [Comment #13]() by [gerchowl]()

_Posted on November 5, 2026 at 03:41 AM_

R2b S2 (#205) final review at feed1727: a 311,025-row base-vs-head differential. The only output differences are the documented addendum-15 saturation rows (4,874, all in `since_checkpoint = u64::MAX` contexts, where base panics and head saturates). One more internal difference is recorded for the record: on an `Err` from the fallback, head leaves `*run` at the caller's value where base had set `inherited`. It is unobservable, since all five callers propagate with `?` and drop `run`. The PR body now states it accurately (the architect corrected a false "pre-existing" claim).

---

# [Comment #14]() by [gerchowl]()

_Posted on November 5, 2026 at 04:33 AM_


### Addendum 16 to ruling 197-d1 (R2b S3a: one classifier with a Stop/Collect reaction)
16. **The every-violation collector is a reaction mode of the one classifier, never a second copy of the checks** (the owner's decision 13-V4-d4).
    - The S3a prototype's `Mode::Collector` copied the tolerant checks. Its pre-dispatch check showed three things:
      - a mutant changed in only the collector's copy survived every test;
      - the collector disagreed with the reader on strict paths, and 9 of 35 kinds could never be emitted;
      - its fold-(iii) splice left the MMR one leaf short and produced a spurious violation.
    - Binding design:
      1. **One classifier, two reactions.** Keep `Mode{Strict,Tolerant}` and add `Reaction{Stop,Collect}`. Every check site calls a single `on_violation(v)`. `Stop` returns `Err(v.into())`, which is today's reader behaviour, byte-identical. `Collect` records `(v, position)` and then continues as point 4 says. The collector therefore sees exactly the reader's per-path order. **Its first recorded violation equals the reader's first violation on the same layout and path (strict and tolerant)**, and a test proves this across a systematic layout sweep.
      2. **Fold (iii) "as if matched"** re-applies the record through the shared `apply_checked(..., compare_mmr = false)`. No hand-built `RunState`, no hand-built MMR.
      3. **Typed at the source.** Each check site constructs a `Violation` variant directly; `detail()` gives today's exact string. There is no `from_detail` string round-trip and no `panic!` fallback.
      4. **The coverage gate is re-keyed deliberately** (as in addendum 7) to count `Violation` construction sites instead of `corrupt("literal")` calls. The PR states the new count and mapping, and a renamed or added variant without a pin fails the gate. R0's per-site pins keep asserting today's exact detail strings.
      5. Tolerant finish-time checks (`invalid undamaged segment`, `first successor lacks resume`, …) are recorded in Collect mode too.
    - Proof: an independent systematic differential (reader unchanged), the reader-vs-collector-first equality sweep, collector rows, and mutants, including one that changes a check (one shared site, so both reactions see it).


---

# [Comment #15]() by [gerchowl]()

_Posted on November 5, 2026 at 05:49 AM_


### Addendum 17 to ruling 197-d1 (R2b S3a: the open points from the v3 full-proof check)
17. **Settled from the S3a v3 check (reader unchanged over 221,625 cases; four blockers):**
    1. **Collect covers both modes.** `Reaction::Collect` has entry points for **Strict and Tolerant**, plus an entry for a `Record(Err)` line. On every single-segment path, the collector's first recorded violation equals the reader's first violation, with zero mismatches. **Multi-segment paths** (live open, refresh, open fallback) are proven in **S3b** through `classify`, not here.
    2. **No copies, the duplicate arm included.** The duplicate-line handling is the reader's own code path, with only the reaction differing. Neither the collector nor anything else duplicates the reader's `Duplicate` arm.
    3. **"As if matched" (point 4, fold iii)** means the MMR continues as the **computed fold including the checkpoint's own leaf**: the state the trail would have if the checkpoint had been honest. The checkpoint's declared size, root and peaks are discarded. A later honest checkpoint then matches. The row `[cp0,e1,bad_cp2,e3,cp4]` pins the **exact full recorded list** this semantics yields on each path, with exactly one `CheckpointMmrDiffers`. The earlier `from_peaks(cp.size, cp.peaks)` expectation is void.
    4. **End-of-segment checks:**
       - they are **skipped while the run is already ended** by an earlier violation, since no second report comes from a run that is already dead;
       - they **run at every segment boundary otherwise**, including `reset_at_boundary`, not only on the last segment.
    5. **The gate derives the variant set from the `enum Violation` definition (syn)**, not from `ALL`. Every variant must have a site and a pin, or a proven UNREACHABLE entry. `ALL` must equal the parsed set. `#[cfg(test)]` code is excluded from site counting. Every UNREACHABLE reason cites a test or proof that exists.
    6. Every surviving mutant from the check gets a killing row:
       - fold ends the run;
       - salvage skipped;
       - boundary `saved_prior=None`;
       - Collect keeps only the first;
       - Collect skips attestation;
       - duplicate arm without `count += 1`;
       - sealed-seq `<=`→`<`, which must also fail a collector row.
    - **Size:** if the non-test code exceeds ~400 lines after these fixes, stop with `BLOCKED: size <N>` for an owner decision (as in addendum 14). Don't trim proof or behaviour to fit.


---

# [Comment #16]() by [gerchowl]()

_Posted on November 5, 2026 at 06:14 AM_


### Addendum 18 to ruling 197-d1 (S3a is split into S3a and S3a′)
18. **To stay at about 400 non-test lines per PR, S3a lands in two parts.** This is a split, not a size exception.
    - **S3a (branch `refactor/197-r2b-s3a-collector`, about 391 lines):**
      - the one-classifier `Reaction{Stop,Collect}` for **Tolerant** mode;
      - the duplicate arm on the reader's own code path (17.2);
      - fold "as if matched" with the computed fold including the checkpoint leaf (17.3);
      - end-of-segment checks skipped once the run is ended and run at every boundary otherwise (17.4);
      - the gate deriving variants from `enum Violation` and excluding `#[cfg(test)]` code (17.5);
      - the killing rows that tolerant mode can host.
      
      The collector is **documented as tolerant-only until S3a′**. It has no consumer before S3b's `classify`, so S3a is correct on its own.
    - **S3a′:** Strict×Collect and the `Record(Err)` Collect entry (17.1), the remaining killing rows (boundary `saved_prior=None`, Collect skips attestation, duplicate arm without `count += 1`, and sealed-seq `<=`→`<` failing a collector row), and the first-equality sweep over the strict single-segment paths.
    - **Proof for S3a, mandatory before merge:**
      - a base-vs-head reader differential over **every** reader path (the duplicate-arm rewiring touches the reader);
      - the collector-first-equals-reader-first sweep over the **tolerant** single-segment paths (`history_segment` ×4), with zero mismatches;
      - the S3a rows;
      - the gate's G1–G3, with G2 exiting 101.
      
      The fresh reviewer runs these independently.


---

# [Comment #17]() by [gerchowl]()

_Posted on November 5, 2026 at 06:56 AM_


### Addendum 19 to ruling 197-d1 (S3a: shared orchestration, and no derived violations)
19. **The reader's orchestration is one function parameterised by `Reaction`, and a fold mismatch produces no derived violation.**
    - The PR #206 review (reader unchanged over 467,483 cases) found that the collector still diverges from the reader. It skipped `history_segment`'s strict pass: 1,046 cases where the reader returns Ok but the collector records, D1 among them. It also re-implemented the finish epilogue and the duplicate-line arm, and a mutant in either copy survives.
    - Binding:
      1. **One orchestration.** `history_segment`'s strict-pass-then-tolerant-fallback-from-saved-state sequence, the duplicate-line arm and the end-of-segment epilogue each live in **one** function, parameterised by `Reaction`. The reader calls it with `Stop`; the collector calls it with `Collect`.
         - In particular, Collect on `history_segment` runs the strict pass first. If that passes, the collector records **nothing**, exactly as the reader returns Ok. Only a strict failure enters the tolerant fallback, in Collect.
         - This moves code out of `storage.rs` into the shared function. That is allowed and required. Behaviour is proven by the reader differential.
      2. **No derived violations.** When a fold-(iii) mismatch is recorded in a segment, that segment counts as **damaged** for its end-of-segment checks. So `[cp0,e1,bad_cp2,e3,cp4]` records **exactly** `[(2, CheckpointMmrDiffers)]` on every `history_segment` path, with no follow-on `InvalidUndamagedSegment`. (Under `Stop` the reader never reaches that point, so its behaviour is unchanged.)
      3. Every shared function gets a mutant that fails **both** a reader pin and a collector row.


---

# [Comment #18]() by [gerchowl]()

_Posted on November 5, 2026 at 08:15 AM_


### Addendum 20 to ruling 197-d1 (S3a: the I/O boundary of the shared walk, the gate, and 19.2 precedence)
20. **Settled from PR #206 review 2** (reader unchanged over 404,992 cases; first-equality 0 mismatches over 85,268):
    1. **The I/O boundary.** The `history_segment` walk is shared only up to I/O, and that boundary is fixed here:
       - `storage.rs` keeps **only byte-level I/O and byte checks**: the seek, reading lines, the glued-byte and LF checks. It turns a segment into a stream of decoded line events (record, fragment, unparsable, …).
       - **All orchestration** goes into **one** `runs.rs` function that takes that event stream, the prior state and the `Reaction`. That means the saved prior state and its restore for the fallback, the `inherited` computation (including `unsealed_boundary`), the strict pass → tolerant fallback decision, per-line feeding, and the epilogue.
       - The reader calls it with `Stop`, and the collector with `Collect` (S3b's `classify` will consume the same event stream). There is **no test-only copy** of the orchestration.
       - Mutants on `inherited`, on the `saved_prior` restore and on the fallback decision must fail **both** a reader pin and a collector row.
    2. **The gate requires coverage per variant.** Every `Violation` variant has at least one construction site **and** a pin, or a proven UNREACHABLE entry. A variant added to the enum, `ALL` and `detail()` with no site and no pin (G3) fails the gate with exit 101.
    3. **19.2 precedence.** First-equality (the collector's first equals the reader's first) takes precedence. "Exactly `[(2, CheckpointMmrDiffers)]`, no derived violation" applies on every path where no earlier violation precedes the bad checkpoint. On `history_segment(true,true)` the reader's earlier first violation (`FirstSuccessorLacksImmediateResume` at 1) stands, and is pinned.
    - **Size:** if moving the walk takes non-test code beyond ~400 lines, stop with `BLOCKED: size <N>` for an owner decision (as in addendum 14). Don't keep a partial share to fit.


---

# [Comment #19]() by [gerchowl]()

_Posted on November 8, 2026 at 12:46 AM_


### Addendum 21 to ruling 197-d1 (owner decision 2026-11-08: S3a may exceed ~400 lines)
21. **PR #206 (R2b S3a) may land at up to about 450 non-test code lines.**
    - The addendum-20 shared walk (I/O boundary in `storage.rs`, one orchestration function in `runs.rs`) came to +438 after aggressive trimming.
    - Splitting it would land a half-shared walk on dev, which is exactly the drift addendum 20 forbids. The owner accepted the larger PR, as for S2 (addendum 14).
    - Proof is unchanged: the implementer's own reader differential, the first-equality sweep through the shared function, the walk mutants failing both sides, the gate G1–G3, then a fresh review.


---

# [Comment #20]() by [gerchowl]()

_Posted on November 8, 2026 at 02:01 AM_


### Addendum 22 to ruling 197-d1 (owner decision 2026-11-08: an exceptional 4th fix round for PR #206)
22. **PR #206 (R2b S3a) gets one exceptional 4th fix round with a fixed list, and the size cap rises to about 480 non-test code lines.**
    - Review 3 at 5455114 found two reader changes in `history_segment`:
      - a trailing duplicate under-reports the segment length (1172 vs 2344): the duplicate arm skips the feed callback, so `final_offset` is not advanced;
      - `found` differs from base after a strict pass, on Ok paths (sealed `DU`) and on Err paths.
    - It also found that two walk mutants (`inherited`, `saved_prior`) survive the collector rows, because those rows pass empty prior state. And the PR body overclaimed: no real differential was run, mutant coverage was claimed for "both sides", and +468 was described as within ~450.
    - The collector first-equality held (0 mismatches over 40,992 cases), as did the gate and the precedence row.
    - Round 4 fixes exactly:
      1. the duplicate arm advances the offset through the shared feed callback, byte-identical to base;
      2. `found` matches base exactly on Ok and Err paths;
      3. collector rows exercise a non-empty prior and an unsealed boundary, so the `inherited` and `saved_prior` mutants fail a collector row too;
      4. an argument struct replaces `#[allow(clippy::too_many_arguments)]`;
      5. the implementer runs the reader differential and the first-equality sweep and posts the real numbers, and the PR body is corrected.
    - **No 5th round.** A blocker outside this list goes back to the owner.


