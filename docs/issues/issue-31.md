---
type: issue
state: closed
created: 2026-10-09T19:15:36Z
updated: 2026-10-09T20:53:13Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/31
comments: 1
labels: bug, priority:high, effort:small
assignees: none
milestone: 0.1.0 — logs core
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:39.144Z
---

# [Issue 31]: [fix(rotate): repair a fragment left by a killed writer; consistent reads during rotation](https://github.com/vig-os/vigil/issues/31)

**Milestone review findings, confirmed:**
1. **Major: a SIGKILLed writer corrupts the next healthy process's batch.** A kill during `write(2)` leaves an unterminated fragment; `RotatingFile::append` (`src/rotate.rs:362`) appends the next line directly onto it. Probe: 15 SIGKILLs during 33 MB-line writes → 2 glued lines (19,277,691 B and 8,191 B fragments + a full batch) that fail JSON parsing; **512 records lost each** (tags k9, k14). The in-process rollback only helps if the process survives; OOM kills and systemd stop timeouts hit exactly this path. `AppendFile` already repairs (`src/sink.rs:159`), but the rotating sink `init` uses doesn't. **Fix:** under the lock, if the live file is non-empty and its last byte isn't `\n`, prefix this write with `\n` (same single write), as `AppendFile` does. Test: plant a fragment, append, then every complete line parses and the next record is intact; plus a SIGKILL-during-write child-process test (bounded, small lines).
2. **Minor: readers miss records during rotation.** `read_since`/`segments`/`find_newest` list segments, then read the live file; a rotation in between loses that segment (`src/bin/race.rs`: 2918 of 3000 `read_since` snapshots had gaps at a 200 B limit). The docs promise "all lines" and "readers need no lock". **Fix:** make reads consistent without the writer lock: list, read, re-list, and retry while the set changed (bounded), or take the dir lock in shared mode if that's cheaper and doesn't block writers badly. Test with a concurrent rotating writer: no gaps across 1000 snapshots.
3. Unverified (assess, and fix if real and cheap): a SIGSTOPped/hung writer holding the dir lock blocks all writers indefinitely (`flock` blocking, no timeout). Consider a bounded wait (e.g. `try_lock` with backoff up to N s, then an error) and document it.
Refs: #4, #25, ADR-0002.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 9, 2026 at 08:53 PM_

Done in #34: a fragment left by a killed writer is repaired (newline) before the next write; readers are lock-free with bounded re-list retries (0 gaps in 2000 snapshots); a blocking dir lock with a one-time warning after a >10 s wait (no timeout, no starvation: max append 2–3 ms with 3 writers); newest-first `find_newest`. Independently verified across two rounds.

