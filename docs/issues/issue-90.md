---
type: issue
state: closed
created: 2026-10-11T22:15:24Z
updated: 2026-10-12T03:32:34Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/90
comments: 5
labels: docs, security, priority:high, area:docs, effort:small
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:27.307Z
---

# [Issue 90]: [docs(adr): ADR-0005 amendment — scope of fsync poisoning (staging, directory, marker, check order)](https://github.com/vig-os/vigil/issues/90)

ADR-0005 decision 6, "A failed fsync poisons the handle" (l.434–435), specifies the live file's record write: truncate back, `Io`, then `Poisoned` on that handle, and `audit.poison` if the truncate fails. Five full-ADR checks of the audit B2b1 brief found that it leaves these write-side cases open. Each one is a durability hazard, and so far each attempt to rule on it inside a brief contradicted other ADR text. Design questions belong in the ADR, so this amendment settles them before they're implemented.

## Open cases
1. **A staging file whose fsync failed** (`.audit-next.jsonl`, `create`'s staging, `.audit-resume.jsonl`). The file still looks complete in the page cache, so the next writer would promote it (l.493–496) and chain onto bytes the kernel may drop, which is exactly l.435's hazard. Candidate: truncate it to 0 (an empty file is discarded by l.497), and create `audit.poison` if that fails.
2. **A failed directory fsync** (live-file creation l.424, sealing step 6, a settlement promotion, `create`). Truncating can't undo a rename. If another writer acknowledges records in a file whose name isn't durable, a power loss can bring back the old names and l.493 then discards an acknowledged record. Candidates: create `audit.poison` here, or have the next writer redo the directory fsync before any append. The case of `open`, which has no handle to poison, is included.
3. **The marker fsync in `create`**, before any handle exists. Candidate: `create` returns `Io` and leaves the marker in place (l.159: never delete); l.514 then applies.
4. **Check order.** l.492 says staging settlement runs "before anything else", while l.435 says every writer checks for `audit.poison` under the lock. Protecting staging files (case 1) requires the poison check to come first.
5. **A handle poisoned in memory:**
   - Do `checkpoint`/`close` fail `Poisoned` and write nothing (l.434 names only `record`)?
   - Does `Drop`'s best effort (l.469) write nothing?
   - Does a poisoned handle run settlement (unlink/rename) before returning `Poisoned`?
6. **`checkpoint`/`close` while `audit.poison` exists** (l.435 names `open` and `record`).

## Acceptance
- A docs PR adds "Amendment (2026-10-1x, #<this>): poisoning scope" to ADR-0005, keeping the original text, settling cases 1–6 with reasons. It is reviewed against the whole ADR, including settlement (l.492–498), "open writes nothing" (l.491), `close` consuming the handle (l.559) and never deleting (l.159), and Accepted.
- The implementation lands in audit B2b2, with a test per case (injected fsync/truncate failures).
- Until then, audit B2b1 implements exactly l.434–435's text. In the cases above it returns `Io` without further poisoning. It is crate-private and unreleased (version 0.0.0).

Refs: #11, ADR-0005 decision 6/8.

---

# [Comment #1]() by [gerchowl]()

_Posted on October 11, 2026 at 10:16 PM_

Architect, scope narrowed after a sixth brief check. ADR l.434 is unqualified: ANY failed fsync poisons the handle (`Io`, then `Poisoned` for later `record`). Audit B2b1 implements exactly that, for every fsync site, with a truncate where a pre-write length exists. #90 keeps only:
- (1) whether failures without a pre-write length (staging, directory, marker) also create `audit.poison` or truncate a staging file to 0;
- (2) the order of the poison check vs settlement (l.435 vs l.492);
- (3) `checkpoint`/`close`/`Drop`/settlement on a poisoned handle;
- (4) `checkpoint`/`close` while `audit.poison` exists;
- (5) `create`'s marker fsync, where no handle exists yet.
The amendment must not weaken l.434's unqualified rule.

---

# [Comment #2]() by [gerchowl]()

_Posted on October 12, 2026 at 12:05 AM_

Settled by PR #91 (merged 57e2b8d): ADR-0005 amendment 3 decides the six cases, each with a reason and acceptance tests, after 3 review rounds plus a final nits-only edit. The amendment is merged as Proposed; it is marked Accepted in the B2b1 PR (#92) after review. B2b2 implements it.

---

# [Comment #3]() by [gerchowl]()

_Posted on October 12, 2026 at 02:31 AM_

Implementation (B2b2a) dispatched: brief checked three times against the whole ADR-0005. Two cases (3, 4) already hold on dev and get named mutants (l.~1088/1090) as their failing baselines. Test-only durable-state model for the simulated restart and power-loss replay lines. resume/verify parts deferred to B3/#13 by test line.

---

# [Comment #4]() by [gerchowl]()

_Posted on October 12, 2026 at 02:32 AM_

Ruling 11b2b2-d1 (on a correct BLOCKED from the implementer): l.832's "does not apply to `create`" conflicted with l.462 and l.550. Settlement judges the disk content. After a restart, a complete creation staging file is an interrupted `create` and is promoted (l.550), the same as l.839. An empty or torn one is discarded, giving `CorruptTrail`/`TrailExists`. This is recorded as a one-sentence ADR-0005 amendment in the B2b2a PR.

---

# [Comment #5]() by [gerchowl]()

_Posted on October 12, 2026 at 03:32 AM_

Implemented by PR #99 (merged ab81238): amendment 3 rules 1–6 and the clearing-procedure rustdoc, plus ruling 11b2b2-d1 as an ADR sentence at l.832. A fresh falsifier killed every case mutant and found the durable-state model strict. Resume parts are deferred to B3 and the verifier parts to #13.

