---
type: issue
state: open
created: 2026-11-20T20:01:06Z
updated: 2026-11-20T20:01:06Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/251
comments: 0
labels: none
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-21T09:17:32.512Z
---

# [Issue 251]: [audit verify: decide how end_before treats an end record from another trail](https://github.com/vig-os/vigil/issues/251)

Follow-up to #250 (#13, rulings 13-V6-d4 and 13-V6-d7).

`Verifier::end_before` accepts an archive record whose checkpoint belongs to another trail: it parses, the line becomes `TrailMismatch`, and the end anchor fails with `trail differs`, so the end is unanchored and the run fails (fail-closed). Decide whether such a record should instead be `InvalidConfig` at parse time (ruling 13-V6-d4 point 4 lists the parse failures and does not name this case). Row X12b in `src/audit/verify/above_end_tests.rs` relies on the current behaviour and needs a new layout if it changes.

Also: the docs on `X13B_RESUME_DIGEST` and `X4D_RESUME_DIGEST` in that file name rows that do not use them; they are pinned only in `fixture_hashes_match_literals`.

Refs: #13
