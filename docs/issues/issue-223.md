---
type: issue
state: open
created: 2026-11-18T19:43:31Z
updated: 2026-11-19T08:40:14Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/223
comments: 1
labels: bug
assignees: none
milestone: none
projects: none
parent: none
children: none
synced: 2026-11-19T09:58:10.867Z
---

# [Issue 223]: [audit tests: tighten snapshot-source rows (hard-link bytes, shipped siblings, spans) after #222](https://github.com/vig-os/vigil/issues/223)

Follow-ups from the review of #222, which add tests only:

- **Hard-link test.** The row for a shipped copy hard-linked to a native file checks only `bytes.is_some()`. It then compares the bytes with the same shared buffer, which cannot fail. It should assert the retained bytes equal the file contents on disk.
- **Shipped-siblings row.** It asserts only `bytes.is_some()`. It should assert the literal bytes.
- **Live closed-run row** (`snapshot_collect_live_closed_run_pins_final_state_length_byte_exact`). It asserts `loss_seq` but not `spans`. It should pin the spans literally.

---

# [Comment #1]() by [gerchowl]()

_Posted on November 19, 2026 at 08:40 AM_

Also: `src/audit/verify/runs_tests.rs` defines the same small `relative` path helper inside R10 and R20 (added in #228). Move it to module level and share it.

