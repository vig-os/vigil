---
type: issue
state: open
created: 2026-11-19T20:02:33Z
updated: 2026-11-19T20:02:33Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/234
comments: 0
labels: none
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-20T09:45:02.186Z
---

# [Issue 234]: [test(audit): coverage rows — explain D2's attester layout; write fragment lengths as literals](https://github.com/vig-os/vigil/issues/234)

Follow-ups from #233 (Refs: #13). Neither changes behaviour.

1. D2 uses the native layout `[cp0, frag, cp1(repaired)]` plus a shipped copy of cp1, because a copy of a non-attesting checkpoint would not exercise the duplicate-attester rule (ruling 13-V5-d2). Say so in the row's comment.
2. Expected `TornWrite`/`TornWriteRepaired` details take the byte count from `frag.len()`. Write each length as a literal, pinned by the existing consistency test.
