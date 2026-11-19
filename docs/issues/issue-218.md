---
type: issue
state: closed
created: 2026-11-18T14:09:05Z
updated: 2026-11-18T16:25:02Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/218
comments: 1
labels: bug
assignees: none
milestone: none
projects: none
parent: none
children: none
synced: 2026-11-19T09:58:12.923Z
---

# [Issue 218]: [classify (Collect) silently drops spans and record heads on a read error in the report pass](https://github.com/vig-os/vigil/issues/218)

## What

Under `runs::Reaction::Collect`, `runs::classify` builds the per-segment spans and record heads that a `RunReport` carries (and that the verifier's run digest will be computed from) in a second pass over each segment. Every I/O failure in that pass is swallowed and replaced by an empty result, at `dc2daaa`:

- `src/audit/runs.rs` around line 1174: the handle for the second pass is `file.try_clone().ok()`; on `Err` the segment gets no spans and no record heads (`unwrap_or((Vec::new(), None))` around line 1281).
- `collect_segment_spans_and_records` (around line 1024): a failed `seek` to 0 returns `(Vec::new(), None)`, and an `Err` from `verify::lines::stream` returns empty spans.
- The same function maps the segment index with `u32::try_from(segment_index).unwrap_or(u32::MAX)`, a sentinel instead of an error.

## Why it matters

A run digest pins the run's ranges **and spans** (ADR-0005 decision 11; rulings 107-d2, 107-d3, 13-V4-d2). A transient read error would yield a well-formed but wrong digest, and a reviewer's `accept-run` line would pin it. ADR-0005 decision 11 says the verifier's `Err` is `Io` when it cannot read. A read it could not complete must not turn into a different, valid-looking answer.

`Reaction::Stop` (the reader) never builds reports, so reader behaviour is unaffected.

## Fix

Under Collect, every failure in the report pass propagates out of `classify` as an `AuditError` (`Io` with the `io::Error` as source), and the segment index conversion is checked, not saturated. This lands with the byte-source refactor of the walkers (#13 V4a prerequisite, rulings 13-V4-d5 and 13-V4-d6), which rewrites these lines. Acceptance: a test source whose second pass fails makes `classify` return `Err`, and no `RunReport` is produced from a partial pass.

---

# [Comment #1]() by [gerchowl]()

_Posted on November 18, 2026 at 04:25 PM_

Fixed by #219 (merged into dev).

