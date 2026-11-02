---
type: issue
state: closed
created: 2026-10-09T13:21:45Z
updated: 2026-10-09T15:58:58Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/4
comments: 2
labels: feature, priority:high, effort:small
assignees: none
milestone: 0.1.0 — logs core
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:45.925Z
---

# [Issue 4]: [feat: multi-process-safe size rotation and age retention](https://github.com/vig-os/vigil/issues/4)

Port and generalise the rotation from gerchowl/s1-mcp#6 (built and tested there; 8 concurrent writers × 50 records, no loss or duplication):
- Rotate when the next record would push the file past the limit (default **50 MB**) → `<signal>-<UTC stamp>.jsonl`.
- Delete rotated segments last written more than the retention ago (default **90 days**, `0` = keep). Prune on rotation and once per process.
- Size check + rename + append run under one **inter-process file lock** (std `File::lock`, no new crate).
- Reader helper over segments: oldest→newest, newest-first search, mtime window.

**Acceptance:** the s1-mcp test suite ported (incl. the concurrency hammer), plus a multi-*process* test (spawned children, not threads).
---

# [Comment #1]() by [gerchowl]()

_Posted on October 9, 2026 at 02:12 PM_

**Pre-mortem findings (probed 2026-10-09, all confirmed with tests), added to acceptance:**
1. **Stale fd → writes land in rotated segments.** 8 procs × 500 records, 2000 B limit: 428–2529 records in rotated segments, segments overshot to 64 688 B. Fix: after taking the lock, compare the live path's `(dev, ino)` with the open handle and reopen if they differ; then size-check → rotate → write. (Fixed variant: 0 lost, 0 misplaced, 0 over limit.)
2. **Same-second rotations overwrite each other** (`rename` replaces): 3960–3979 of 4000 lost. Keep s1-mcp's collision suffix under the lock, but its sort is wrong (`…Z-1.jsonl` < `…Z.jsonl`, `-10` < `-2`). Use a sortable name (nanosecond stamp or zero-padded counter).
3. **Lock a separate never-renamed `<signal>.jsonl.lock`**: `File::lock` is `flock`, and locking the data file itself lets a waiter lock the renamed inode.
4. **Overflow checks are off in all Nix checks** (crane runs clippy/nextest/doctest with `--release`). Use checked arithmetic, or `overflow-checks = true` for the profile.
5. **Two lock handles in one process block each other** (second `try_lock` → WouldBlock). One lock handle per path per process.
6. **A failed write leaves a half line** (EFBIG mid-`write_all`), and the next record glues onto it. Truncate back to the pre-write length under the lock.

---

# [Comment #2]() by [gerchowl]()

_Posted on October 9, 2026 at 03:58 PM_

Done in #22: multi-process-safe size rotation and age retention. The flock is on the state directory, the inode is rechecked before each write, names are collision-free and sortable with never-replace rotation, partial writes roll back, and modes are tightened. Verified by three independent rounds (up to 32 processes, 192k records, 0 lost/dup/torn; a mutation check confirms the tests catch a missing lock). Follow-up: #25.

