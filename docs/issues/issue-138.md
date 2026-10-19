---
type: issue
state: closed
created: 2026-10-13T03:52:16Z
updated: 2026-10-13T07:30:20Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/138
comments: 2
labels: feature
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:21.852Z
---

# [Issue 138]: [audit: resume does not hand the opening checkpoint to the caller (anchoring duty has no library path)](https://github.com/vig-os/vigil/issues/138)

Found by the #137 (B3e-1) review. ADR-0005's resume procedure has the operator anchor the opening checkpoint at `lost_through + 1`. `AuditConfig::resume` returns `(AuditTrail, Receipt)`. The receipt covers the resume record at `lost_through + 2`, and no `Checkpoint` is returned. So a library user can't fulfil the anchoring duty without reading the trail files from disk, while the ADR says anchors and expected heads never come from the disk.

To decide before the 1.0 API freeze (with #13):
- (a) `resume` also returns the opening `Checkpoint` (a breaking change to the `resume` signature while it is still pre-1.0); or
- (b) the `vigil-audit resume` CLI (#13) prints it, and the library documents how a caller reads it, with the trust caveat.

Architect recommendation: (a), which matches `close`/`checkpoint`, both of which return what must be anchored. The README (B3e) states today's limit and points here. Refs #11 #13.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 13, 2026 at 06:01 AM_

## Ruling 138-d1 (architect): `AuditConfig::resume` returns the opening checkpoint

**The gap (#138).** The resume procedure (ADR-0005 decision 8, amendment 9) says to anchor the opening checkpoint at `lost_through + 1`. Two other rules stand against reading it back from the files: "anchors and expected heads never come from the disk", and "do not anchor a line read from the trail directory" (README, B3e-1). `AuditConfig::resume` returns `(AuditTrail, Receipt)`, so a library user cannot meet that duty.

**Ruling.** `resume` returns `Result<(AuditTrail, Receipt, Checkpoint), AuditError>`.
- The `Receipt` is for the resume record at `lost_through + 2`, as today.
- The `Checkpoint` is the signed opening checkpoint at `lost_through + 1`.
- The tuple order follows `rotate`'s `(Receipt, Checkpoint)`, with the trail first.

Every operator call then hands back exactly what the operator must store or anchor:
- `close` returns a `Checkpoint`;
- `checkpoint` returns a `Checkpoint`;
- `rotate` returns `(Receipt, Checkpoint)`;
- `resume` returns `(AuditTrail, Receipt, Checkpoint)`.

**Why not the alternatives.**
- **(b) The CLI prints it, and the library tells callers to read it from disk.** Rejected: this contradicts the never-from-disk rule, and the library would be less capable than its own CLI.
- **A `Resumed` struct.** Rejected: rotation already returns a tuple, and consistency wins. The surface is pre-1.0 and not yet published (no 0.x releases), so a breaking signature change now costs nothing downstream.

**ADR.** Amendment 11 to ADR-0005 changes decision 13's surface table, the amendment-9 part-2 sentence (~l.631) and the receipts bullet (~l.409, "`AuditConfig::resume` returns the `Receipt` with the trail"). It is Proposed in the PR and Accepted when the PR merges.


---

# [Comment #2]() by [gerchowl]()

_Posted on October 13, 2026 at 07:30 AM_

Fixed in #141 (12aaf2a). `AuditConfig::resume` now returns `(AuditTrail, Receipt, Checkpoint)`, and ADR-0005 amendment 11 is Accepted. Reviewed by a fresh falsifier: R16 holds, and the mutants are caught.

