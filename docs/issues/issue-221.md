---
type: issue
state: open
created: 2026-11-18T16:24:51Z
updated: 2026-11-18T16:24:51Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/221
comments: 0
labels: bug
assignees: none
milestone: none
projects: none
parent: none
children: none
synced: 2026-11-19T09:58:11.439Z
---

# [Issue 221]: [audit: untested walker-side try_clone error paths; misplaced rustdoc after #219](https://github.com/vig-os/vigil/issues/221)

Follow-ups from the review of #219, measured at its merge head:

1. **Walker-side `try_clone` errors have no row.** Each of these sites can be turned into a panic (`.expect()` instead of `?`) and the audit suite still passes:
   - `src/audit/runs.rs` around lines 1209, 1227 and 1277;
   - `src/audit/storage.rs` around line 1087.

   The gap was already there at base. Turning the `storage.rs` error into a corruption error is caught only by the syn gate. Add rows built on the `#[cfg(test)]` failing byte source (for example, failing the second `try_clone` on the live arm). Each mutant needs two distinct killers.
2. **Misplaced rustdoc.** The doc comment for `collect_segment_spans_and_records` now sits on `type SegmentSpansAndHeads` (`src/audit/runs.rs` around lines 1012-1035). Move it back to the function.

