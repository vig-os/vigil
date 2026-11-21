---
type: issue
state: open
created: 2026-11-20T23:54:42Z
updated: 2026-11-20T23:54:42Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/254
comments: 0
labels: none
assignees: none
milestone: none
projects: none
parent: none
children: none
synced: 2026-11-21T09:17:31.828Z
---

# [Issue 254]: [feat: compress rotated segments (OTLP JSON Lines stays the format)](https://github.com/vig-os/vigil/issues/254)

## Compress rotated segments

OTLP JSON Lines stays the format (per ADR-0001). Rotated segments are stored compressed on disk (for example zstd); readers handle both the compressed and the uncompressed form, so existing readers keep working during a rollout.

## Why

Logs about a system are vigil's territory ([per owner direction 2026-11-21 on nerdmachines/kit#42](https://github.com/nerdmachines/kit/issues/42#issuecomment-7053575589)). Keeping rotated segments compressed trims disk use on long-running hosts without changing the authoritative on-write format or the hash/audit chain. OTLP JSON is highly compressible.

## Proposed shape (sketch, not a decision)

- Compression is applied **at rotation**, not inline (the active segment stays uncompressed so writes are append-only without a codec in the hot path).
- Suffix names the codec (for example `*.jsonl.zst`); the uncompressed suffix keeps working.
- Codec default: zstd (level configurable); allow "none" for sites that compress at the filesystem or shipping layer.
- Readers autodetect by suffix, or by a magic-byte sniff for the chosen codec, and the audit/tamper tests pass equally against a compressed segment as an uncompressed one.
- Compression never changes the hash domain (what is signed/chained stays the uncompressed canonical bytes; the compressed file is a cold-storage representation).

## Not in scope here

- No change to the OTLP JSON Lines format itself.
- No change to the active segment encoding.
- Ingest of foreign compressed streams is a separate concern.

## References

- nerdmachines/kit#55 (vigil is the home for system logs in the kit)
- Owner answer recorded on [nerdmachines/kit#42 (2026-11-21)](https://github.com/nerdmachines/kit/issues/42#issuecomment-7053575589) and in [kit's `docs/architecture/data-and-stores.md`'s Keyed collections section](https://github.com/nerdmachines/kit/blob/main/docs/architecture/data-and-stores.md#keyed-collections-read-and-write-path-status-2026-11-18) ("vigil's ADR-0001 format is OTLP JSON Lines in rotated segments; compression of rotated segments is not in vigil's ADRs yet")
- Related: #59 (tessera adoption path for sealed segments).

