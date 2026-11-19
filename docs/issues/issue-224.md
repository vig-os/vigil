---
type: issue
state: open
created: 2026-11-18T21:03:03Z
updated: 2026-11-19T08:47:07Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/224
comments: 1
labels: none
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-19T09:58:10.491Z
---

# [Issue 224]: [spike(audit): run detection over Collector copies (shipped record streams)](https://github.com/vig-os/vigil/issues/224)

## Question

Can the verifier recover run boundaries from a shipped (Collector) record stream, so that `verify_files` over shipped copies reports the same run findings as over vigil's own files?

## Why it is open

- ADR-0005 defines a run by segments: "the consecutive segments right before the segment that begins with that resume's opening checkpoint" (decision 11, `accept-run`).
- The ADR also says a shipped copy has no file boundaries and must verify the same (decision 8, gap rule, item 1), and the Collector drops fragments and unparsable lines (decision 5).
- The decision-11 test list asks for "A Collector round trip of a resumed trail (`verify_files`): the gap verifies, same findings as the files."
- Segment starts are opening checkpoints (decision 2, archiving), so the boundaries may be recoverable from the records alone.

#13 V4a runs the shared classifier over native inputs only (rulings 13-V4-d5, 13-V4-d6). Shipped inputs get no run finding in V4a. That is correct for native files whatever this spike finds.

## Spike output

1. Whether every segment boundary that matters for a run (the run's first segment, each loss point, the closing segment) is identifiable from the shipped records, with the rule and a counter-example search over the classifier's layouts.
2. What spans become in a copy that holds no fragments or unparsable lines, and whether the run digest stays equal to the native one.
3. A recommendation:
   - (a) a V-step before 1.0 that adds shipped-copy runs, with its acceptance rows; or
   - (b) an ADR amendment that documents the limit and narrows the decision-11 Collector test.

Owner decision 13-V4-d7: spike first, then decide. Milestone: 1.0.0.

Refs: #13

---

# [Comment #1]() by [gerchowl]()

_Posted on November 19, 2026 at 08:46 AM_

Scope extended by ruling 13-V4-d10 point 5 (on #13): this spike also decides how decision 5 rule 2 (the opening checkpoint's MMR fold) applies to records that exist only in shipped copies, where the classifier sees no file boundaries. Until then, the verifier does not confirm a shipped-only resume (fail-closed candidate filter, 13-V4-d10 point 4), and #13 does not close while this stays open.

