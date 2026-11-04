---
type: issue
state: open
created: 2026-11-04T02:32:47Z
updated: 2026-11-04T02:32:47Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/202
comments: 0
labels: priority:low, area:testing, effort:small
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-04T08:43:04.023Z
---

# [Issue 202]: [test(audit): storage coverage gate follow-ups: reject every item named assert_corrupt, drop the direct proc-macro2 dev-dependency](https://github.com/vig-os/vigil/issues/202)

Follow-up to #201 (#197 R0b), from its round-4 fresh review. The gate's threat model (ruling 197-d1 addendum 10, on #197) is **drift, not sabotage**, so neither item blocked #201.

1. **Other items named `assert_corrupt` still shadow the helper.** Round 4 rejects a second `fn` and a pattern binding. A `struct assert_corrupt<T>(…)`, a `const assert_corrupt: fn(…) = …`, a `static`, an `impl`/`trait` method, an `extern` fn or a `macro_rules!` with that name still pass. In that case a site counts as covered while its pin asserts nothing. The reviewer showed this with a real compile: exit 0, 147 passed, with two sites falsely covered. Also `S::assert_corrupt(…)` replacing a real pin counts as covered.
   **Ask:** the gate fails on **any** item, associated item, macro or binding named `assert_corrupt` other than the single helper `fn` in `mod details`, and only counts calls whose path resolves to that helper: a bare `assert_corrupt`, `details::assert_corrupt` or `self::…`, not `S::assert_corrupt`. Prove each shape with a probe (exit 101, then 0 after revert).
2. **Drop the direct `proc-macro2` dev-dependency.** Round 4 added it to walk macro token streams. syn 2's `syn::buffer::TokenBuffer::new2` with `Cursor::ident`/`any_group`/`token_tree` does the same walk without naming `proc_macro2`. It adds no new crate (1.0.107 is already locked), so this is minimalism, not supply-chain risk.

Refs: #197, #13
