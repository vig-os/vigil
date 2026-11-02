---
type: issue
state: open
created: 2026-11-02T04:28:20Z
updated: 2026-11-02T12:26:04Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/164
comments: 4
labels: none
assignees: none
milestone: none
projects: none
parent: none
children: none
synced: 2026-11-02T13:59:40.618Z
---

# [Issue 164]: [consumer: audit backend for a regulated workflow system — gate/merge decisions, leases, labelled-row reads, attested time](https://github.com/vig-os/vigil/issues/164)

A consumer, a multi-agent workflow system built as one versioned record graph, wants vigil's audit trail as its audit backend for the Part 11 and GDPR-class requirements below. A second consumer, an identity and principal service, plans the same thing.

## Context
The system models work as a versioned graph with claims, branches and a merge queue with gates. The consumer's studies of regulated verticals rank these among the top gaps:
- An audit trail of who did what, when, to which record, independent of the graph's own history. Part 11 §11.10(e) applies, and so do auditors who need offline verification.
- Auditable READS of labelled rows, for healthcare, HR and finance spaces.
- Attested time, which an agent cannot set.

ADR-0005 already covers most of this: hash-chained records, an MMR, signed checkpoints, offline verification, and anchoring in #57.

## What the consumer would consume
1. Audit records for its events: merge and publish decisions with gate verdicts, lease grants, reads of labelled rows, escalations, and break-glass. The record names the principal (from the identity service), the space, the commit root and the meaning.
2. Inclusion proofs for single records handed to an auditor, without the rest of the trail (ADR-0005 decision 7).
3. Attested time from external anchoring (#57) and hardware checkpoint signers (#58).

## Asks
- Does the ADR-0005 record shape fit the consumer's event records as they stand, or does it need a consumer semantic-convention namespace (#9)?
- How do many writer processes (agents and a central hub) share one trail? Group commit (#56) looks relevant.
- See the erasure issue filed alongside this one: an immutable audit trail that names people meets GDPR erasure.



---
*Consumer names and private references were redacted by the maintainers; the requirements are unchanged.*

---

# [Comment #1]() by [gerchowl]()

_Posted on November 2, 2026 at 04:28 AM_

Companion erasure design issue: #165.

---

# [Comment #2]() by [gerchowl]()

_Posted on November 2, 2026 at 05:04 AM_

**Architect: consumer requirements, clarified with the consumer (2026-11-02).** Numbers marked (est) are the consumer's design targets.

- **Volume (est):** under 10 records/s per host, peak about 100/s. Decision records arrive at about 1–10 per minute per tenant. A labelled-row read emits **one record per query** that carries a digest of the read set, never one per row.
- **Topology:** one trail per tenant, **one writer process per trail**, about 1–20 trails per host, and no trail spans hosts. Single-writer per trail is sufficient.
- **Durability, two classes:**
  - (a) Decisions (gate verdict, merge or publish, approval use, break-glass, lease grant) must be durable **before the action is acknowledged**: a synchronous `record()` that returns a receipt.
  - (b) Read-access records may use group commit (#56) with a bounded window of about 100 ms (est). A crash must surface any lost window as a reported gap, never lose it silently.
- **Record shape** (fixed, 300–600 B (est), mostly hashes):
  - an opaque principal id;
  - an on-behalf-of chain (the agent principal plus the grant id);
  - the tenant id and the action kind;
  - the target and parent commit roots (32-byte digests);
  - for decisions, a verdict ref and the gate-definition hash;
  - the signature meaning (authored, reviewed, approved or executed, per 21 CFR Part 11 §11.50) plus the digest of the approval statement;
  - for reads, the read-set digest and the query kind;
  - the time.
- **Verification:** the offline verifier proves integrity, order and existence, plus anchored time once #57 lands. It does not prove semantic truth. Verifying the full trail is enough for the first version. **Inclusion proofs** for handing single records to an auditor are wanted next, not first.
- **Timing:** not urgent (weeks). The minimum first slice is (a), the fixed field shape, and the erasure rule from #165. Group commit for reads, inclusion proofs and anchoring follow.

Next: an ADR-0005 amendment covering this issue and #165 (design before code), then implementation slices. I'll report back here when they land.


---

# [Comment #3]() by [gerchowl]()

_Posted on November 2, 2026 at 11:42 AM_

Progress: slice **CP2** (the schema-checked writer) merged in #179 (dev `b4cf81f`). With CP1 (#175, #177), a writer can now use a per-trail `RecordSchema` (`RecordSchema::builder`, `AuditConfig::schema`) and typed attributes (`Entry::attr`). P5–P8 of ADR-0005 §20 are enforced fail-closed at `record`, `rotate` and `resume`, before the directory lock. The README has a new section, **Personal data and erasure**, that covers the operator duties.

Remaining: CP3 (the `vigil-audit schema` command and `--schema` on the CLI operator commands) and CP4 (the verifier's schema checks, which depend on #13). Single-record inclusion proofs are tracked in #173. To try it before the next release, pin `rev = "b4cf81f1bb9d9ec3435c94e7accf442cab099afa"`.

---

# [Comment #4]() by [gerchowl]()

_Posted on November 2, 2026 at 12:26 PM_

Progress: slice **CP3** (the operator CLI) merged in #180 (dev `72091e6`). `vigil-audit schema <file>` prints a canonical schema's `blake3:` digest for the trust file. `vigil-audit rotate` and `vigil-audit resume` take `--schema <file>`, so P8 (an opaque actor and reason id) applies on the CLI too. Remaining: CP4 (verifier schema checks; depends on #13).

