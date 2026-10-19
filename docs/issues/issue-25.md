---
type: issue
state: closed
created: 2026-10-09T15:59:09Z
updated: 2026-10-09T16:55:52Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/25
comments: 1
labels: bug, priority:medium, effort:small
assignees: none
milestone: 0.1.0 — logs core
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:40.215Z
---

# [Issue 25]: [fix(rotate): re-check the state dir's identity after locking; handle hard_link-ok/remove-fail](https://github.com/vig-os/vigil/issues/25)

Confirmed by the final verification of #22 (head b8d467e):

1. **A state directory replaced under a live writer breaks exclusion.** The `flock` is held on the directory fd opened at `open`, but every file operation goes through the path. Repro: slow writer running, then `mv s s.old; mkdir s; flock -x s sleep 3`: the writer kept appending into the new `s` (30 ok, 0 errors; 24 lines in `s/`, 6 in `s.old/`), so a new process locking the new dir wouldn't be excluded. **Fix:** after acquiring the lock, compare the locked fd's `(dev, ino)` with `stat(dir)`; if they differ, reopen the dir, re-lock and retry (same pattern as the live-file inode recheck). Test: replace the dir between appends; assert the next append locks and writes the new dir, and two writers stay mutually exclusive.
2. **`hard_link` succeeds, then `remove_file(live)` fails:** the live file and the new segment are then the same inode, so readers see its lines twice and the next rotation links it again. **Fix:** on `remove_file` failure, `remove_file(target)` to undo the link and return the error. Test via a seam.
3. Docs: on a filesystem without hard links, every append past the size limit fails with the `hard_link` error (no data loss). Document that rotation needs hard-link support (local POSIX fs).

Refs: #4, ADR-0002.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 9, 2026 at 04:55 PM_

Done in #27: the state-dir identity is rechecked after locking; all critical-section ops are relative to the locked dir fd (rustix); rotation is an atomic no-replace rename (link+unlink only as fallback, with reported errors); self-heal applies only to same-signal leftovers; macOS ENOTSUP is handled. Verified by three independent rounds.

