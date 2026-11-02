---
type: issue
state: closed
created: 2026-10-12T18:29:45Z
updated: 2026-10-13T00:56:56Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/121
comments: 1
labels: refactor, priority:low, area:testing, effort:small
assignees: none
milestone: 0.2.0 — metrics + traces
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:23.974Z
---

# [Issue 121]: [test(metrics): pin Declaration Eq/Ord on raw signed zeros, not only canonical values](https://github.com/vig-os/vigil/issues/121)

Nit from the fresh re-review of #119 (c6ca019, ruling 7b2b-d3): `canonical_boundary_equality_and_order_agree` builds both declarations through a test helper that already canonicalizes, so it checks canonicalization plus Eq/Ord on canonical values rather than Eq/Ord fed raw -0.0/+0.0. Harmless today (both constructors, registry metrics.rs:178 and SDK builder metrics.rs:428, canonicalize; mutants that skip either are killed), but the test should construct through the constructors with raw -0.0 so it would catch a third constructor added later. Refs #7.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 13, 2026 at 12:56 AM_

Fixed in #133, merged into dev at a245632. Leftover nit: the test leaves its temp dir behind when it fails, which only matters for cleanup after a failed run. It will be folded into #116, the next test-hygiene PR.

