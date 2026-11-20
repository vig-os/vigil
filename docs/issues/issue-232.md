---
type: issue
state: open
created: 2026-11-19T17:42:05Z
updated: 2026-11-19T17:42:06Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/232
comments: 0
labels: none
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-20T09:45:02.740Z
---

# [Issue 232]: [test(audit): pin Finding getters in signature rows; declare A1 digest locally](https://github.com/vig-os/vigil/issues/232)

Follow-ups from #231 (Refs: #13). Neither changes behaviour.

1. The signature rows build their expected findings through the same `Finding::new` the code under test uses, so a mutant inside that constructor (e.g. setting `accepted_kind`) changes both sides and survives. Production never sets `accepted_kind` until `accepted()` is used (#13 V8). Pin at least one row's `accepted_kind()` and `run_digest()` through the public getters against literal values, independent of the constructor.
2. The A9 and R2 rows use `A1_DIGEST` imported from `runs_v4a_fixtures.rs`. It is a written-out literal, but declare it in `signature_tests.rs` so each row's expected values are self-contained.
