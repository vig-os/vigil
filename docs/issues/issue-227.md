---
type: issue
state: closed
created: 2026-11-19T07:59:15Z
updated: 2026-11-19T08:40:20Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/227
comments: 1
labels: none
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-19T09:58:09.427Z
---

# [Issue 227]: [test(audit): second killer for the per-directory classification mutant](https://github.com/vig-os/vigil/issues/227)

## Gap

Verifier run detection (#225) classifies the native segments of one verify call together (ruling 13-V4-d8 point 2). The mutant "classify once per parent directory" is killed by one row only: R10, an archive directory plus the trail directory against the full trail. Our standard is two distinct killers per mutant.

## Fix (tests only)

Add a second, distinct literal row that dies under that mutant. For example, the A3 layout split as an archive directory plus the trail directory, verified in one `verify_files` call. Assert the full sorted literal finding list, with the run finding at the archived first segment. Show it red under the mutant (exit 101) and green without it.

Refs: #13

---

# [Comment #1]() by [gerchowl]()

_Posted on November 19, 2026 at 08:40 AM_

Fixed in #228 (afe9942): R20 is the second killer; the mutant fails R10 and R20.

