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

## OTLP decoder fixtures

`codec.jsonl` spells the primitive record and empty-MMR checkpoint above as
OTLP/JSON, with fixed time, trail and seed. The two lines are independent format
vectors, both at sequence zero, not a linked trail. Tests decode them and compare
canonical bytes against `primitives.txt`; the decoder does not regenerate either
fixture. Full sink trails follow in B3.

## Writer round-trip corpus

`roundtrip.jsonl.gz` contains 256 OTLP lines from the shrinking proptest strategy
in `src/audit/roundtrip_tests.rs`, encoded by the shared production `encode_line`.
The fixed ChaCha seed is `[0x75; 32]`; `roundtrip.blake3` commits to the
uncompressed lines including final LF. A normal test regenerates all 256 cases
and checks that digest, in addition to 256 randomized property cases. The
Collector conformance harness decompresses and ingests every committed line.
Gzip keeps the near-one-million-byte cases below the repository file-size cap.

To regenerate, set `VIGIL_CORPUS_PATH` to a fresh output path and run
`cargo test --lib --features audit regenerate_writer_corpus -- --ignored --nocapture`
in the dev shell. Compress that output with Python `gzip.compress(..., mtime=0)`
and update the digest from the printed BLAKE3. The ignored test is an explicit
fixture-writing utility; both verification tests run normally in CI.

The production mapping and reader share context validation. The generator now
includes empty/duplicate/random keys, absent KeyValue/AnyValue values, empty
strings, absent details, U+2028/U+2029, arrays/kvlist depths at and beyond 16,
and size refusals. Corpus generation exercises typed refusals and collects 256
accepted lines; it does not discard a successfully emitted unverifiable line.
Depth counts container edges from root AnyValue depth zero. Invalid context
returns InvalidConfig; oversized payloads return TooLarge before writing.
