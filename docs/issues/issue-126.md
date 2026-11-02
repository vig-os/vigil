---
type: issue
state: closed
created: 2026-10-12T21:02:22Z
updated: 2026-10-13T04:48:28Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/126
comments: 1
labels: bug, priority:medium, area:docs, effort:small
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:23.293Z
---

# [Issue 126]: [docs(adr-0005): residual 7 still says 'routine verify with the recorded start'](https://github.com/vig-os/vigil/issues/126)

Found by the round-3 re-review of #124 (merged), after the round cap. 18.3 residual 7, 'Who catches it' column (l.1131 at 3c49b1f): 'routine `verify` with the recorded start' contradicts the 18.1 row (l.1192), which now says 'with its start from the anchor-store entry' (rulings 107-d2/123). Fix: 'with the start from the anchor-store entry (amended, #123)' + an 18.6 row. To be folded into the next ADR-0005 docs PR (B3e). Refs #123.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 13, 2026 at 04:48 AM_

Fixed in #137 (292ee3c): §18.3 residual 7 now cites the anchor-store start, with a new §18.6 row.

