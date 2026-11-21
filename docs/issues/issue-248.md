---
type: issue
state: open
created: 2026-11-20T12:19:44Z
updated: 2026-11-20T16:10:37Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/248
comments: 1
labels: none
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-21T09:17:32.862Z
---

# [Issue 248]: [test(audit): harden the end_before rows (cwd guard, writer-built E3)](https://github.com/vig-os/vigil/issues/248)

Follow-up to #246 (#13, ruling 13-V6-d4).

- `with_cwd` in `src/audit/verify/end_before_tests.rs` restores the working directory only on the normal path. A panic inside the closure (an `unwrap` on `end_before`/`verify_files`) would leave the process in a temp directory that is then deleted, failing later tests in a cascade. Restore it through a `Drop` guard.
- E3a/E3b are hand-built. Build them with the real writer and a pre-seeded `audit.trail` (as E10 does), and correct the comment that says the writer always draws a random trail.
- The "end anchor does not join the anchors" case is pinned by E3a only; add a second literal row that fails when the end anchor is not checked as an anchor.

Refs: #13
---

# [Comment #1]() by [gerchowl]()

_Posted on November 20, 2026 at 04:10 PM_

Also from #249 (ruling 13-V6-d6): the H1 row L4 in `src/audit/verify/end_link_tests.rs` builds each sealed segment with a single checkpoint, but rotation writes a closing checkpoint into the old file and the opening checkpoint into the next (ADR-0005 decision 4), so a sealed segment holds at least two. Rebuild L4 with rotation-sealed segments; the finding kinds stay the same (measured), with one further `MmrMismatch` on each later checkpoint. Correct the `build_prefix_deletion_scenario` doc that calls the shape complete.

