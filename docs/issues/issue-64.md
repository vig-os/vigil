---
type: issue
state: closed
created: 2026-10-10T23:45:44Z
updated: 2026-10-11T21:07:39Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/64
comments: 1
labels: bug, priority:high, effort:small
assignees: none
milestone: 0.2.0 — metrics + traces
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:30.604Z
---

# [Issue 64]: [fix(logs): output byte order depends on serde_json/preserve_order being enabled anywhere in the consumer's build](https://github.com/vig-os/vigil/issues/64)

**Confirmed (ADR-0006 review, probe 2026-10-11):** vigil serializes OTLP/JSON through `serde_json::to_value`, which yields **sorted** maps by default. Cargo unifies features across the whole build graph, so if *any* crate in a consumer's dependency graph enables `serde_json/preserve_order`, vigil's maps become insertion-ordered: `{"description":"d","name":"n","sum":1}` (default) vs `{"name":"n","description":"d","sum":1}` (with `preserve_order`). This silently breaks ADR-0001 decision 5 ("equal input gives equal bytes") and the golden-byte tests' meaning in consumer builds, and it affects the fingerprints planned for metrics/traces (#7/#8) and push (#41).

**Fix (root cause):** make vigil's line writer independent of that feature: an explicit ordered representation (e.g. `BTreeMap`-based building or a custom serializer with a fixed field order) instead of relying on `serde_json::Map`'s default. **Test:** run the golden/determinism tests with `serde_json/preserve_order` enabled (a dev-dependency feature or a dedicated test crate in the workspace) and show they fail before the fix and pass after. Document the guarantee in ADR-0001's amendment or ADR-0003, whichever lands first.
Refs: ADR-0001 d5, #39 (ADR-0006 review), #3.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 11, 2026 at 09:07 PM_

Closed by #84 (merged 8d1821d): ordered writer + ADR-0006 d3 logs key order, depth-16 bound (ADR-0001 d10 amendment) with counted loss, preserve-order lane, perf 1.058× recorded in README. Four review rounds (round 4 docs-only, exception recorded on the PR). Open style nit: README '#49 Measurement details' h3 now sits after the #64 section.

