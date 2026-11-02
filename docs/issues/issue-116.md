---
type: issue
state: open
created: 2026-10-12T15:09:37Z
updated: 2026-10-12T15:09:37Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/116
comments: 0
labels: priority:medium, area:testing, effort:medium
assignees: none
milestone: 1.0.0 — stable
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:24.643Z
---

# [Issue 116]: [test: replace performance wall-clock assertions with deterministic proofs](https://github.com/vig-os/vigil/issues/116)

Follow-up from #96 / PR #115 (ruling 96-d1 inventory, confirmed by the round-1 code-falsifier review at a26101a).

These tests assert a **wall-clock bound on a property that has no API deadline**. Like the `src/logs.rs` test #115 replaced, they can fail under host load (flaky) and they don't pin the property they stand for. Each needs a deterministic proof of the real property: an ordering or happens-before handshake, a counted seam, or an explicit `#[ignore]` measurement that never gates, as ruling 96-d2 did. Loosening or widening a timeout is not a fix.

Locations are at dev 3c6ddac:
- [ ] `src/audit/sink_tests.rs:1589`: close/drop on a poisoned sink must return in under 1 s while a lock is held. Prove "does not wait for the held lock" without a clock.
- [ ] `src/rotate.rs:1198/1201`: "the writer doesn't block" is inferred from a 1 s `recv_timeout` while a reader is held.
- [ ] `src/rotate.rs:1293`: writers must finish a fixed workload within 90 s.
- [ ] `src/rotate.rs:1302`: the slowest append under contention must take under 5 s.
- [ ] `src/rotate.rs:2102`: more than 100 swaps within a 3 s window (a throughput floor).
- [ ] `tests/exporter.rs:567`: the ignored full-export measurement still asserts `elapsed < 1s`. Apply 96-d2: keep it as a measurement and drop the assertion.

Deadline-contract tests (the ADR-0003 d4 timeouts, `tests/lifecycle.rs`, and `init.rs` 1903/2119/2126/2165/2367/2528/2634, plus the coordination wait at `init.rs:2590`) stay as they are under ruling 96-d1.

Acceptance:
- no listed assertion remains;
- each replacement has a mutant that fails at runtime (exit 101) and passes once reverted;
- `nix flake check -L` passes.

