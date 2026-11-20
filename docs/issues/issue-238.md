---
type: issue
state: open
created: 2026-11-20T00:33:16Z
updated: 2026-11-20T00:33:16Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/238
comments: 0
labels: none
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-20T09:45:01.529Z
---

# [Issue 238]: [test(audit): make the end= foreign-above bound row an honest fixture](https://github.com/vig-os/vigil/issues/238)

Follow-up from #237 (Refs: #13). Test-only.

The E2f row (foreign records above a matching `end=`, bound confirmed by the match) signs cp2 with the key bounded `through=0`, so its expected list carries an incidental `UntrustedKey` error. Use the clean layout `[cp0, e1, e2, foreign3, foreign4]` with the key bounded `through=0` and `end=2:<e2 hash>`: its list is only 2× `TrailMismatch` + `UncoveredTail`, it is still red on base (`RevocationUnconfirmed`), and it still catches a foreign record silently voiding the match.
