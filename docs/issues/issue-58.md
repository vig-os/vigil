---
type: issue
state: open
created: 2026-10-10T23:20:02Z
updated: 2026-10-10T23:20:02Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/58
comments: 0
labels: feature, security, priority:backlog, effort:large
assignees: none
milestone: none
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:31.928Z
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
