---
type: issue
state: open
created: 2026-11-08T08:52:22Z
updated: 2026-11-08T08:53:05Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/207
comments: 0
labels: feature, area:workspace
assignees: none
milestone: none
projects: none
parent: none
children: 208, 209
synced: 2026-11-09T09:15:00.544Z
---

# [Issue 207]: [feat(bindings): feature-parity tracking across Rust, CLI and Python surfaces](https://github.com/vig-os/vigil/issues/207)

### Description
Track which stable vigil features are reachable from each surface: the Rust library (today), a CLI fed with structured input on stdin, and a Python binding. This issue groups the two surface issues and owns the parity check.

### Problem Statement
vigil's integrity guarantees hold only while there is **one** implementation of the record format, the rotation and the hash-chained audit trail. Consumers that are not Rust programs (shell schedulers, Python tools) must reach that implementation through thin surfaces rather than re-implement it. Each surface lags behind the library unless gaps are tracked; nobody should find out from a missing method that a feature never made it across.

### Proposed Solution
- A machine-readable parity table, e.g. `api/parity.toml`, with one row per stable item and one column per surface (`rust`, `cli`, `python`). Each cell is `done`, `planned` (with an issue) or `wontfix` (with a reason).
- A CI check, in the style of the existing public-API snapshot gate, that diffs `api/public-api.txt` and the CLI input schema against the table. A new stable item without a row, or a row naming an item that no longer exists, fails CI.
- Rows group at feature granularity where per-item is noise (for example "metric instruments" rather than every builder method), but the check stays exact.
- Both surfaces wrap only the stable API. `vigil_unstable` items and OpenTelemetry types stay out, so an OpenTelemetry upgrade remains a minor release (ADR-0004).

Surfaces:
- [ ] CLI with structured stdin input — #208
- [ ] Python binding — #209

### Alternatives Considered
- **A Python port:** rejected. A second implementation of the chain and the signing would have to stay byte-identical, and an auditor would have to trust both.
- **Untracked bindings:** they drift silently. The API snapshot already exists, so the check is cheap.

### Additional Context
A first consumer is waiting on both surfaces: a small personal automation, a Python CLI plus a shell scheduler driving an unattended agent twice a day. It wants (a) signed audit records for state changes that leave the machine (prices changed on an external marketplace, outbound messages sent after human approval), and (b) ordinary logs and spans for the scheduled run. See the two surface issues for its concrete calls.

### Impact
Additive; no change to the Rust API. Adds a CI gate and a table that new stable items must update.

### Changelog Category
Added

