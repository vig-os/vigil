---
type: issue
state: closed
created: 2026-10-11T00:33:16Z
updated: 2026-10-11T10:24:58Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/68
comments: 1
labels: discussion
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:29.559Z
---

# [Issue 68]: [design: let --strict accept reviewed warnings (TornWrite, Resumed) so an honest crash never fails strict verify forever](https://github.com/vig-os/vigil/issues/68)

Found while writing the ADR-0005 amendment (#66), against threat model (c): an honest crash must never make verification fail permanently.

**The gap (ADR-0005 core, decisions 5, 8 and 11):**
- A SIGKILL or power loss mid-write leaves a torn fragment, reported as `TornWrite`, a **warning**. The fragment stays in the file forever (vigil never rewrites a trail).
- `--strict` "turns every warning into a failure, and it is the mode for regulated review" (decision 5).
- So one honest crash makes `--strict` exit 1 on that trail **for good**. The same holds for `Resumed` (decision 8: "`--strict` fails until a reviewer has accepted it"), but no mechanism for that acceptance is specified.

**What #66 decides and this issue may reuse:** a waiver for one crash-orphaned record per line in the receipts input (`waive <seq> <blake3:hex> <reason>`; range waivers were rejected in ADR-0005): an operator decision kept outside the trail directory, pinned by the record's hash so it cannot be moved to another record, checked against the application's durable request log, and reported as `ReceiptWaived` (info). A reviewed-warnings input of the same shape (finding kind + file + line/seq + hash or byte length + reviewer + reason) would let `--strict` pass after a recorded human review without weakening plain verify.

**Decide:** whether `--strict` accepts reviewed warnings, through which input (receipts file, a separate review file, or the trust file), how it is pinned, how it is reported, and the tests for #13. Must be decided before #13 implements `--strict`.

Refs: #10, #13, #66


---

# [Comment #1]() by [gerchowl]()

_Posted on October 11, 2026 at 10:24 AM_

Resolved by ADR-0005 amendment 2, PR #77 (merged into dev).

