---
type: issue
state: closed
created: 2026-10-09T13:21:57Z
updated: 2026-10-11T00:22:56Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/10
comments: 3
labels: feature, security, priority:high, area:docs, effort:large
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:43.869Z
---

# [Issue 10]: [design: audit trail ADR — record schema, lossless sink, hash chain, checkpoints, key custody, anchoring](https://github.com/vig-os/vigil/issues/10)

ADR-0003 before any audit code.

**Requirement framing:** 21 CFR Part 11 §11.10(e) / EU Annex 11 ask for secure, computer-generated, time-stamped audit trails of operator actions on regulated records, which must not obscure prior entries. That means **tamper-evidence + retention + attribution**, not a specific data structure. Operational telemetry is out of scope. Medical-device use puts this module under IEC 62304, so keep it small and heavily tested.

**Decide**
- Record schema as OTLP log records (`eventName` `audit.*`): actor (authenticated identity, from the app), action, object, before/after (or their digests), reason, timestamps.
- **Lossless sink:** fsync per record; the sink is fail-closed (the action fails if the record can't be written); no sampling; no auto-delete (archive policy instead of retention).
- Chain: `audit.prev_hash` / `audit.hash` attributes (blake3), stays OTLP-conformant.
- Per-segment **MMR root + ed25519-signed checkpoints** using `tessera-core`; a sealed segment can become a `.tsra`.
- **Key custody:** a local key alone lets an attacker rewrite the whole chain. Options: TPM / Secure Enclave, an off-device signer, **external anchoring** (RFC 3161 timestamps, or pushing checkpoints to a server).
- What it does *not* do: e-signatures (§11.50/.70), identity management.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 9, 2026 at 02:05 PM_

This issue now owns **ADR-0003 audit trail** (`docs/adr/0003-audit-trail.md`), moved from #1's checklist. #1 closes in 0.1.0 with ADR-0001 and ADR-0002.

---

# [Comment #2]() by [gerchowl]()

_Posted on October 10, 2026 at 10:19 PM_

**Owner decision (2026-10-11), path-to-1.0 pre-mortem R3.** tessera-core is not on crates.io (`cargo info tessera-core` → not found; tessera's `docs/CONSUMING.md`: git-only). It's `0.1.0-alpha.1`, a "spike" with an unfrozen format (tessera ADR-0052). A crate with a git dependency can't be published: `cargo package` fails without a version and exits 101 with one. API gap: no hash-chain primitive or checkpoint type; `sign_ed25519` signs a fixed JCS envelope over a `manifest_hash`; digests are hex `String`s. Present: MMR `MerkleAccumulator`, inclusion and consistency proofs.

→ **The ADR is now `docs/adr/0005-audit-trail.md`** (0003 is metrics/traces #38, 0004 is the API #37). It **vendors the primitives** (blake3, ed25519-dalek, vigil's own MMR) under a format frozen by vigil's ADR, with no git dependency. Its first section must answer the owner's question with evidence: *does tessera benefit vigil's audit trail, or did the coupling come from misreading the discussion (tessera is the data-product crate, not telemetry/audit)?* If tessera's sealing, hashing and schemas fit, document the mapping (cross-verification) and an adoption path to tessera-core once it's published and frozen; the owner is happy to adopt the core then. The ADR also defines the format-freeze and old-trails-still-verify promise for 1.0 (#13).

---

# [Comment #3]() by [gerchowl]()

_Posted on October 11, 2026 at 12:22 AM_

ADR-0005 (audit trail) core Accepted and merged in #62 after 3 adversarial security rounds plus a final check: vendored primitives (blake3, ed25519-dalek, vigil's own MMR, bit-for-bit compatible with tessera's), the record schema and canonical encoding, hash chain, checkpoints, lossless sink, verify findings, and the format-freeze promise. The owner's tessera question is answered in its first section. Open stolen-key sub-decisions (clean-stop expect-head source, the receipts range, start_from/archiving, revocation scope) are split to #66, which must be accepted before #12/#13 implement them. Deferred: #56–#59.

