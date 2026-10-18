---
type: issue
state: open
created: 2026-10-10T23:20:04Z
updated: 2026-10-10T23:20:04Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/59
comments: 0
labels: feature, priority:backlog, effort:medium
assignees: none
milestone: none
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:31.573Z
---

# [Issue 59]: [feat(audit): tessera adoption path — export sealed segments as tessera products, optionally use tessera-core's MMR](https://github.com/vig-os/vigil/issues/59)

Deferred from ADR-0005 (#10), decision 15. This is gated on tessera-core being published on crates.io with its format frozen (tessera ADR-0052 keeps the format at v0, and `docs/CONSUMING.md` is git-only).

ADR-0005 already makes vigil's MMR bit-identical to tessera-core's construction (`hash.rs`, ADR-0028/0049), which was probed against vig-os/tessera@f08255d. Its record hashes use tessera's `blake3:<hex>` spelling, and its key files are tessera keygen files.

**Scope, once the gate opens:**
1. `vigil-audit export-tsra <segment>`: one blob block per sealed segment. The vigil checkpoint (`mmr_size`, `mmr_root`, `key_id`, `sig`) goes in sealed metadata, and `producer` follows ADR-0058. tessera then signs the manifest with its own `ed25519-env-v1` envelope. This needs a tessera product schema for audit segments: a tessera-side issue, to be raised with the owner first.
2. Optionally replace vigil's private MMR implementation with tessera-core's. This needs an API that tessera-core lacks at f08255d: resume a `MerkleAccumulator` from stored peaks. It must not change any byte: the v1 golden vectors and the frozen fixtures must pass unchanged.

Neither changes the v1 format. A failing golden vector blocks the swap.
