---
type: issue
state: open
created: 2026-10-10T23:20:02Z
updated: 2026-11-10T11:20:17Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/58
comments: 2
labels: feature, security, priority:backlog, effort:large
assignees: none
milestone: none
projects: none
parent: none
children: none
synced: 2026-11-11T08:55:56.074Z
---

# [Issue 58]: [feat(audit): hardware and off-device checkpoint signers (TPM 2.0, Secure Enclave, PKCS#11, ssh-agent)](https://github.com/vig-os/vigil/issues/58)

Deferred from ADR-0005 (#10), decision 9.

In 1.0, vigil ships `KeyFileSigner`: a 0600 seed file, the same hex format as `tessera keygen`. It also ships the public, unsealed `Signer` trait (`public_key() -> [u8; 32]`, `sign(&[u8]) -> Result<[u8; 64], SignerError>`, pure Ed25519 per RFC 8032), which an application can implement over any device.

A key file on the same host lets an attacker who can read it rewrite and re-sign the whole trail. That is the reason this issue matters.

**Scope:** reference signers, each behind its own feature so the default `audit` build stays small:
- ssh-agent (Ed25519 keys)
- PKCS#11
- TPM 2.0. This needs Ed25519 support in the TPM; many TPMs only do ECDSA P-256, which would mean a new signature scheme and an ADR.
- Secure Enclave (P-256 only, so the same caveat applies).

Each new dependency is justified against ADR-0004's allowlist rule: none of its types may appear in the stable surface.
---

# [Comment #1]() by [gerchowl]()

_Posted on November 10, 2026 at 11:20 AM_

## TPM 2.0 signer, algorithm agility, and a shared signed-checkpoint format

Three threads for #58. Posting as a comment rather than a new issue because #58 already covers TPM 2.0 / Secure Enclave / PKCS#11 / ssh-agent and flags the Ed25519-vs-ECDSA-P-256 question.

## Fleet context (why both layers)

In the deployment motivating this, some hosts have TPM 2.0 + Secure Boot (lanzaboote), some expose no TPM, and microVM guests have none — the host signs for them. `KeyFileSigner`'s local seed "does not protect against an attacker who can read the key and write the trail" (ADR-0005 §9), and the operator's audit policy requires a key held off the audited host. A device-bound signer slows the keyless attacker; an off-box countersignature over frequent checkpoints (§10) is the real forward-integrity. #58 is layer one; both are needed.

## Stage 1 — TPM-sealed seed for `KeyFileSigner` (no vigil change)

Deliver the ed25519 seed `KeyFileSigner::load` reads (§9 amendment 7) via systemd-creds / `LoadCredentialEncrypted=` bound to PCR 7. Seed at rest is then only usable on a trusted-boot kernel/initrd. Runtime code-exec as the writer still reads it from process memory — the residual §9 names. README/runbook only.

## Stage 2 — `TpmSigner` and the algorithm-agility decision

A non-exportable TPM key under a PCR 7 policy closes "read the file, re-sign the trail" for good. The hard part is what #58 already flags:

- Intel PTT and common dTPMs expose **ECDSA P-256**, not Ed25519. Secure Enclave is P-256 only.
- v1 pins Ed25519: "Ed25519 (RFC 8032, pure, not prehashed) over `"vigil.audit.v1.checkpoint\0" ‖ blake3(...)`", `verify_strict` "part of v1" (§8). Trust file `ed25519 <64 hex>` (§9) and `audit.key_id` (`[u8; 32]`, §3) assume it.
- §12 freezes v1 at 1.0.0 with "deterministic RFC 8032 signatures for fixed seeds" vectors. Any writer change → v2 ADR. A minor may add v2 verification + opt-in v2 writing; default-v2 is a major.
- TPM signing latency (tens of ms) is fine at vigil's cadence — the signer runs inside the directory lock (§9), slowing only that trail's writers.

**Main design question (decide on #58 before the slice starts).**

- **(a) `audit.v=2`, additive algorithm field.** New `audit.key_alg` (default `ed25519`); new trust-file `ecdsa-p256 <hex>` line; per-algorithm domain string (`"vigil.audit.v2.checkpoint.p256\0"`); `Signer` scheme-dependent, sealed behind an algorithm enum so ADR-0004 §1's allowlist is unchanged. Format change; new ADR; v1 golden vectors untouched (§12).
- **(b) Keep v1, parametrise `Signer` only.** Sealed `KeyScheme { Ed25519 }` in 1.x, ECDSA deferred to v2. Keeps most hardware — #58's headline cases — out of reach. ADR-0004-minor trait change; format untouched.

I'd rank (a). (b) is cheap today but defeats the point of #58.

**Optional (no format change):** a `TPM2_Quote` per checkpoint, nonce = chain head hash, stored in `audit.details` of the next application record. Attests the PCR state the key is bound to; one extra `write(2)` per checkpoint.

## Shared signed-checkpoint format with tessera (relates #59, tessera #203)

vigil's MMR is already bit-identical to tessera-core (§7, §15). The *signed checkpoint record* — `{trail/stream id, seq, mmr_size, mmr_root, prev_hash, time, key_id, sig}` — is universal: tessera's streaming writer (#203) wants signed live checkpoints over the live MMR root so consumers can pull blocks and verify them via inclusion + consistency proofs before the final seal (tessera #794's live tap). Proposal: define that record in `tessera-core`, used verbatim by vigil trails and `StreamWriter`. #59's `export-tsra` becomes "same record, different frame". Needs a tessera-side issue first; the algorithm-agility decision above decides what the record contains.

## Acceptance criteria (for #58's TPM slice, assuming (a))

- `TpmSigner` behind `audit-tpm`, `tss-esapi`-based; no new types in the stable surface (ADR-0004 §1; dependency allowlist exception justified in-PR like #12 did for `curve25519-dalek`).
- v2 ADR records the algorithm choice; v1 fixtures still pass §12's CI freeze; writing opt-in in 1.x, verification always on.
- README restates the runtime-root residual and points to §10 anchors.

## Open questions

- (a) vs (b).
- No-TPM microVM guests: host signs via VSOCK, or host runs the trail on their behalf? (§9 single-writer invariant per trail.)
- `audit.key_id` stays 32 bytes, or becomes a length-prefixed digest so ECDSA public keys fit?
- Shared checkpoint record in `tessera-core` from the start, or in vigil first and migrate under #59?


---

# [Comment #2]() by [gerchowl]()

_Posted on November 10, 2026 at 11:20 AM_

Tessera side of the shared signed-checkpoint record is now vig-os/tessera#795 (signed live checkpoints over the streaming MMR root). Journald bridge: #214.

