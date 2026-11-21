---
type: issue
state: open
created: 2026-11-20T22:58:34Z
updated: 2026-11-20T22:58:35Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/253
comments: 0
labels: none
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-21T09:17:32.172Z
---

# [Issue 253]: [test(audit): tidy the receipt reconciliation rows and route the end cut through one helper](https://github.com/vig-os/vigil/issues/253)

Follow-up to #252 (#13, rulings 13-V7-d1 and its clarification).

- `src/audit/verify/receipts_tests.rs`: the rows `end_before_file_records_in_end_band_…` and `end_before_fork_at_end_checkpoint_…` are commented ACCEPTANCE but pass with reconciliation stubbed; label them REGRESSION.
- Add a row where a receipt names a checkpoint-only end record and is matched, so treating end-record receipts as mismatched fails two rows.
- `Classifier::is_in_range` repeats `seq >= end_seq` instead of calling `end_before::covers`, and `first_per_hash` relies on the engine's sort order instead of `first_copy`; route both through the shared helpers.

Refs: #13
