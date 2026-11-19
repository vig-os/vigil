---
type: issue
state: open
created: 2026-11-18T15:36:18Z
updated: 2026-11-18T15:36:18Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/220
comments: 0
labels: bug
assignees: none
milestone: none
projects: none
parent: none
children: none
synced: 2026-11-19T09:58:12.190Z
---

# [Issue 220]: [sink: uncovered try_clone().ok() branch (mutant survives)](https://github.com/vig-os/vigil/issues/220)

In `src/audit/sink.rs` (around lines 443-446 and 508 after #219), the expression `.try_clone().ok().is_some_and(..)` keeps the base behaviour, but no test covers it. A mutant that flips it to `is_none_or(..)` survives the whole suite.

Two things are needed:

1. Decide whether a failed `try_clone` at these sites should be an error rather than a `false`, which would be the same class of problem as #218. Diagnose before fixing.
2. Add rows that pin the chosen behaviour. Each mutant needs two distinct killing rows.

Found while reviewing #219.

