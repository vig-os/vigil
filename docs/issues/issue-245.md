---
type: issue
state: open
created: 2026-11-20T08:09:08Z
updated: 2026-11-20T11:35:58Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/245
comments: 1
labels: none
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-21T09:17:33.695Z
---

# [Issue 245]: [test(audit): tidy the below-start rows](https://github.com/vig-os/vigil/issues/245)

Follow-up to #244 (#13, ruling 13-V6-d3).

- P12 in `src/audit/verify/position_tests.rs` is labelled REGRESSION but fails on base at its main assertion; label it ACCEPTANCE.
- P3 (the stolen-key cut of ADR-0005 decision 11) holds only the forged start in its kept segment; add at least one rewritten, re-signed record above the start so the row shows the whole attack, with the same expected findings.
- Pin P8 and P10 with a second measured killer each in the row comments' scenario terms (P8: the anchoring anchor must never be set aside; P10: pins and anchors each stay in range when the start is not accepted).

Refs: #13
---

# [Comment #1]() by [gerchowl]()

_Posted on November 20, 2026 at 11:35 AM_

Also in this cleanup: test comments in `src/audit/verify/start_tests.rs` and `position_tests.rs` that describe how a row was measured ("First failing line on base: …", "… two named kills") should state only the scenario and the ADR bullet or ruling it covers.

