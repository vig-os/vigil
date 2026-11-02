---
type: issue
state: closed
created: 2026-10-11T00:15:49Z
updated: 2026-10-11T01:18:04Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/66
comments: 1
labels: feature, security, priority:high, area:docs, effort:medium
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:29.904Z
---

# [Issue 66]: [design: ADR-0005 amendment — close the rotation, receipts and start_from gaps (stolen-key model)](https://github.com/vig-os/vigil/issues/66)

Split out of ADR-0005 (#10, PR #62) after its 3 review rounds (architect, per the review-round cap). ADR-0005's core (record schema, canonical encoding, hash chain, MMR, checkpoints, lossless sink, verify findings) is accepted; **these sub-decisions are marked open in ADR-0005 and must be decided here before #12/#13 implement rotation, receipts or archiving.** Confirmed findings from the round-3 final check (reasoned from the ADR's state machine):
1. **Clean-stop `--expect-head` has no source.** On a clean stop the head is the `close()` checkpoint (ADR l.353), but `Receipt` comes only from `record` and `close()` returns nothing (l.481); with N processes nothing says which `close()` is last. So operators will copy the head from disk, which the rule forbids. Direction: `close()` returns a `Checkpoint` the app stores or anchors, or `--expect-head` = the last receipt with only checkpoints allowed after it.
2. **Receipts loophole (blocker).** The receipts range is "first to last receipt seq" (l.204): chained records appended after the app's last action escape `NoReceipt`, and the honest `close()` signs them. Direction: report every non-checkpoint record above the last receipt.
3. **`start_from` with a stolen key (blocker).** A start is accepted if any key trusted at its seq signed it (l.385); anchors and receipts below drop to `OutOfRange` and `--strict` passes. With a stolen, not-yet-revoked key, rewrite from seq s above the newest anchor, sign a start at s, and live-only verify passes `--strict` with all anchors disabled, although anchors are the only defence against a stolen key (l.207). Direction: a start trusted by signature alone must not demote anchors (`OutOfRange` → error), or the start must equal an anchor or live on WORM storage; also specify live-only verify without a start (no seq 0: `SeqGap`?).
4. **Revocation scope (nit with an operational consequence):** a key revoked only on X still forges Y cleanly (at most `NoReceipt`). State that a compromised key must be revoked on every trail that lists it, and fix the self-contradictory test at l.449.
**Deliver:** an amendment to `docs/adr/0005-audit-trail.md` (or an ADR-0007 if cleaner), independently reviewed with the stolen-key and write-access attacker models, plus tests added to #13's plan. Refs: #10, #12, #13, #57.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 11, 2026 at 01:18 AM_

Decided in #71 (ADR-0005 amended, Accepted): the clean-stop head source (`close()` returns a Checkpoint; expect-head/start-from/end= never from disk), the receipts range including records after the last receipt, `start_from`/archiving with anchors never demoted by a signature-only start, revocation scope across trails, the power-loss waiver rule, and anchoring that doesn't rely on push. Reviewed under four threat models. Follow-ups: #68 (torn-write --strict, core) and #70 (receipts across resume).

