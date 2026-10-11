# Audit primitive vectors

`primitives.txt` is a pre-1.0 golden set, independent of the production encoder.
Record fields use trail `11` repeated 16 times, sequence 0, time 123, service
`svc`, host `host`, actor `α`, action `sample.modify`, object `id:1`, reason
`reason`, before text `old`, after digest of `new`, and details `{}`.
Checkpoint vectors use the same context, empty MMR, and seed `07` repeated
32 times. A separate scratch program encoded each tag explicitly in ADR order,
then hashed and signed with BLAKE3 and Ed25519. RFC 8032 test 1 is also asserted.

MMR vectors were generated with the unmodified `leaf_hash`, `node_hash`,
`push_peak`, `bag` and `merkle_root` functions extracted from tessera-core
at `f08255d`, `tessera/crates/tessera-core/src/hash.rs`. Leaf input i is
`blake3:<hex(blake3(u64_be(i)))>`, starting at 0. `mmr_0_64` and `mmr_0_2048`
are BLAKE3 of concatenated raw roots for all sizes in the inclusive range.
Tests compare every root through these aggregate goldens and resume at every
size. There is no tessera dependency or regeneration during tests.
