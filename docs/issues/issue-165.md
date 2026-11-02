---
type: issue
state: open
created: 2026-11-02T04:28:21Z
updated: 2026-11-02T05:04:25Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/165
comments: 1
labels: none
assignees: none
milestone: none
projects: none
parent: none
children: none
synced: 2026-11-02T13:59:39.511Z
---

# [Issue 165]: [design(audit): erasure-compatible trail — GDPR Art. 17 vs hash chain (pseudonymous refs / crypto-shred / redactable records)](https://github.com/vig-os/vigil/issues/165)

An append-only, hash-chained audit trail and GDPR Art. 17 erasure conflict as soon as a record holds personal data: a name, an email, a free-text reason or a subject id that is itself personal. Deleting such a record breaks the chain and the MMR, and keeping it may break the law.

It came up while a consumer studied its product against 14–15 regulated verticals: erasure inside immutable history blocked 11 of 15. That consumer needs the same answer for its own data, and the audit trail it uses (vigil, see the companion consumer issue #164) must not be the place where erasure fails.

## Options to decide (ADR-0005 amendment)
1. **No personal data in hashed fields.** Records carry only pseudonymous subject references (an opaque id), and the mapping lives outside the trail where it can be deleted. Cheapest, but it needs a lint or schema rule that stops PII from entering attributes.
2. **Crypto-shredding.** Personal fields are encrypted under a per-subject key, and the record hash covers the ciphertext. Deleting the key erases the data while the chain still verifies.
3. **Redactable records.** The hash covers a commitment such as a salted hash per field, so a field can be dropped and its commitment kept.

## Acceptance
- An ADR-0005 amendment picks one option, or a combination, and states what the verifier proves after an erasure.
- A test erases one subject and verifies the trail end to end.
- The interaction with archiving (Amendment 10) and with tessera export (#59) is addressed.



---
*Consumer names and private references were redacted by the maintainers; the requirements are unchanged.*

---

# [Comment #1]() by [gerchowl]()

_Posted on November 2, 2026 at 05:04 AM_

**Architect: erasure requirements, clarified with the consumer (2026-11-02).**

- **Principal ids are always opaque.** They are minted by the consumer's identity system. Names and emails live in a separate store that can be erased.
- **The risk is free text** (escalation reasons, break-glass justifications, review notes). The consumer keeps free text in its own erasable store, and the audit record carries **only its digest**. Read records never carry a subject id.
- **Option 1 (pseudonymous references) is sufficient**, combined with a **lint or schema rule** that rejects attributes shaped like personal data. If crypto-shredding is ever needed, an external custodian or KMS holds the keys, never vigil.
- **After an erasure, an auditor must still be able to prove:**
  - the chain is intact;
  - record N existed at time T, in this order;
  - its action kind, signature meaning, commit roots and verdict refs are unchanged;
  - it was made by "a principal", meaning an opaque id whose mapping may have been erased.

Design: an ADR-0005 amendment covering this issue and #164 (option 1, the attribute rule, and documenting what an erasure leaves provable), then implementation slices.


