---
type: issue
state: closed
created: 2026-10-10T22:18:58Z
updated: 2026-10-11T03:40:43Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/48
comments: 1
labels: feature, priority:medium, area:testing, effort:medium
assignees: none
milestone: 1.0.0 — stable
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:34.205Z
---

# [Issue 48]: [test: property tests for line bounding/truncation and segment ordering](https://github.com/vig-os/vigil/issues/48)

Add proptest (dev-dep) for `logs.rs` line bounding and truncation (UTF-8 and escape boundaries, base64 bytes, the ≤cap invariant, deterministic output, stubs keep identity) and for segment-name ordering ((stamp, integer counter) total order, round trip through parse). Fuzzing only if properties leave a gap (say why). AC: each property fails when the bound or ordering is mutated (shown once); runtime stays reasonable in CI.

---

# [Comment #1]() by [gerchowl]()

_Posted on October 11, 2026 at 03:40 AM_

Done in #76: proptest properties for logs line bounding/truncation (cap, valid UTF-8/JSON, healthy records byte-identical, value-only largest-first truncation by exact overflow with random positions and ties, identity-preserving stubs, determinism, no loss or duplication across splits, NaN/±Inf) and rotate segment naming (total order incl. nanos and counters ≥6 digits, round trip, signal validation, behavioural `segments()` order). 15 mutations caught in 2 rounds; runtime < 0.4 s.

