# ADR-0002: Multi-process rotation and retention

- **Status:** Accepted
- **Date:** 2026-10-09
- **Amended 2026-10-09:** decision 3 (lock moves from a lock file to the state directory), the segment-name counter and replace-free rotation (decision 5), and signal names (decision 11), per the re-verification of [PR #22](https://github.com/vig-os/vigil/pull/22); directory-relative atomic no-replace rotation and recoverable link/unlink fallback per [#25](https://github.com/vig-os/vigil/issues/25).
- **Issues:** [#1](https://github.com/vig-os/vigil/issues/1), [#4](https://github.com/vig-os/vigil/issues/4)

## Context

Several fleet tools run one process per agent session, all appending to the same `<signal>.jsonl`. The rotation in [gerchowl/s1-mcp#6](https://github.com/gerchowl/s1-mcp/pull/6) works for that (8 concurrent writers × 50 records, no loss) and is the starting point, but the pre-mortem on [#4](https://github.com/vig-os/vigil/issues/4) (probed 2026-10-09, all confirmed by tests) found six defects in the naive port. The numbers below are those probes.

No existing crate fits. `file-rotate`, `logroller`, `log2`, `flexi_logger`, `rolling-file` and `tracing-appender` keep in-process size counters and rename without cross-process coordination: they are thread-safe, not multi-process safe ([g-fleet#355](https://github.com/gerchowl/g-fleet/issues/355), ecosystem table).

## Decision

Rotation lives in the crate, using std (`File::lock`, stable since Rust 1.89) and safe `rustix` filesystem wrappers, Unix targets (Linux, macOS), `#![forbid(unsafe_code)]`.

1. **Size rotation, default 50 MiB.** Rotate when `len + line + 1 > max_bytes`. A single line larger than the limit is still written, alone in a fresh file. Size arithmetic is checked or saturating, because crane runs every Nix check with `--release` where overflow checks are off.
2. **Age retention, default 90 days; `None` keeps everything.** A rotated segment is deleted when its mtime is older than the retention. The live file is never deleted.
3. **Lock the state directory.** All writers take an exclusive `flock` (std `File::lock`) on the state directory itself. After locking, its device and inode are checked against the path; a replaced or missing directory is reopened (recreated 0700 if needed) with bounded retries, updating the shared lock handle. Critical-section operations are relative to the locked descriptor, so an in-flight append remains in that directory even if its path is swapped. A separate lock file was the first design and is superseded: the re-verification of [PR #22](https://github.com/vig-os/vigil/pull/22) showed that a lock file deleted under load (tmpfiles, cleaners) lets two writers into the critical section (a check-then-act race: 2 `NotFound` errors in 48 000 appends, misordered records), while a non-empty directory cannot be unlinked. Locking the data file itself is also wrong: a waiter can lock the inode that was just renamed away and write under a lock nobody else holds. All signals in one directory share the one lock; the critical section is one write plus an occasional rotation, so contention is acceptable.
4. **Inode recheck before every write.** With the lock held, compare the live path's `(dev, ino)` with the cached handle and reopen if they differ; then size-check, rotate if needed, write. Without it, a process holding an `O_APPEND` handle from before another process rotated keeps writing into the renamed segment. Probe: 8 processes × 500 records, 2000 B limit, **428–2529 of 4000 records landed in rotated segments** and segments grew to 64 688 B. Fixed variant: 0 lost, 0 misplaced, 0 over the limit.
5. **Collision-free, chronologically sortable segment names.** `<signal>-<UTC stamp with nanoseconds>.jsonl`, and if that name already exists a zero-padded counter is appended, so the lexicographic order is the chronological order. Format, as implemented in [PR #22](https://github.com/vig-os/vigil/pull/22) (`stamp_at`, `unique_target` in `src/rotate.rs`): `<signal>-YYYYMMDDTHHMMSS.<9-digit nanos>Z.jsonl`, and on collision `<signal>-<stamp>_NNNNNN.jsonl` with a zero-padded counter of at least 6 digits. Ordering is by (stamp, integer counter), so a counter wider than 6 digits still sorts correctly. Rotation never replaces an existing file: the live file is atomically renamed with no-replace semantics; directory-relative link/unlink is used only when the platform or filesystem lacks that operation. Example: `logs-20261009T141245.123456789Z.jsonl`, then `logs-20261009T141245.123456789Z_000001.jsonl`. The separator is `_` because it sorts after `.`, so the bare name comes first. The naive scheme was wrong twice: `rename` replaces, so two rotations in the same second overwrote each other (the reason for no-replace semantics) (**3960–3979 of 4000 records lost**); and s1-mcp's `-N` suffix sorts wrongly (`…Z-1.jsonl` < `…Z.jsonl`, `-10` < `-2`).
6. **Repair and rollback of partial writes.** Under the lock, record the length before writing; if the write fails part-way (for example `EFBIG`), `set_len` back to it and return the error. Otherwise the next record is glued onto a half line and both are unreadable. Each line is written as one `write(2)` of `line + '\n'`. Under the directory lock, an unterminated tail left by a killed writer is detected and a leading newline is included in that same write. The damaged record remains invalid, but subsequent records remain intact; the repair byte counts toward the rotation limit.
7. **One lock handle per directory per process.** `flock` locks belong to the open file description, so a second handle in the same process blocks on the first. The handle lives inside the shared writer (`Arc`); a second `open` of the same directory in the same process shares it or fails clearly, and never deadlocks.
8. **Pruning** runs after a rotation and once per process at open. Prune errors are ignored and never fail an append.
9. **Local filesystems only.** `flock` and `O_APPEND` atomicity are not reliable over NFS; a state directory on NFS is unsupported and documented as such.
10. **Files and directories** are created `0600` and `0700`.
11. **Signal names** are restricted to `[a-z0-9_]+`, so a signal can never contain the `-` or `.` separators the segment names rely on.
12. **Lock-free reader retries.** `read_since` and `find_newest` take no lock. They list segments, copy records, and re-list; changed segment paths or a changed live device/inode trigger a retry. After eight attempts, `read_since` returns only the final copy's rotated-file prefix, excluding the live tail so it cannot skip intervening segments. This best-effort prefix may omit recent records, and pruning may remove retained records during copying. `find_newest` returns its final best-effort candidate on exhaustion. `find_newest` searches newest-first and stops reading files at the first match; its callback may run again on the same line after a retry. `segments` and `segments_since` return listing snapshots whose paths may change after return. A stopped reader cannot hold up a writer.
13. **Blocking writer locks.** Writers use blocking `File::lock` (a kernel wait, without polling or a timeout) so healthy contenders are not starved by polling. After a wait over ten seconds, one stderr warning per process names the directory. A stopped or hung lock holder can block writers; the batch queue filling is already reported on stderr. Warnings do not abort writes, and failed stderr writes are ignored.
14. **Separate file boundaries.** A rotated segment may end with an unterminated fragment from a killed writer. Readers and shippers must process each file separately; naive `cat seg1 seg2` can glue that tail to the next segment's first record. The Collector processes files separately.
15. **Reader helpers** shipped with the writer (#4): `segments` (oldest to newest, live file last), `segments_since` (mtime window), `read_since`, and `find_newest` (newest-first search).

### Acceptance evidence

The acceptance test is a **multi-process** test, not a thread test: the test binary re-executes itself as N ≥ 4 children, each writing M records with a tiny `max_bytes` that forces many rotations. It asserts every record appears exactly once across all segments, every line is whole, no segment exceeds the limit except single oversize lines, and no segment name collides. It sits beside targeted tests for each probe above (same-second rotation, name order, stale-inode reopen, retention with set mtimes, `None` keeps, partial-write rollback via a test seam, second `open` not deadlocking). Tests write only under `std::env::temp_dir()`, since `HOME` is unwritable in the Nix sandbox.

## Consequences

- Rotation uses atomic no-replace rename relative to the locked directory descriptor (`RENAME_NOREPLACE` on Linux, `RENAME_EXCL` on macOS); all critical-section file operations use that descriptor, so directory swaps cannot redirect an in-flight append. Only `EINVAL`, `ENOSYS`, `EOPNOTSUPP` or `ENOTSUP` enables the directory-relative link/unlink fallback, which requires hard-link support. A failed link preserves the live file; if unlink and undo both fail, the returned error names both failures. On the next lock acquisition, a multiply linked live file is unlinked and recreated only if a segment of the same signal in the locked directory shares its device and inode, preserving the data under that segment name. External backup links alone never trigger healing.
- Any number of local processes may share a state directory safely; the cost is one `flock` plus directory and live-file inode checks per write, serialised across all signals in the directory.
- Every rotation lists and sorts the directory, so rotation cost is linear in the segment count. That is fine at the 50 MiB default; a tiny `max_bytes` with tens of thousands of segments is slow (a 48 000-segment stress run took about 10 minutes). Readers and shipping agents match only `<signal>.jsonl` and `<signal>-*.jsonl`.
- Timestamps in names are from the rotating process's clock; ordering by name is only as good as host clock monotonicity, and counters cover same-instant collisions.
- Retention is by file mtime, so a segment survives 90 days after its *last* write, not its first.
- Windows is out of scope.

## Alternatives considered

- **An existing rotating-file crate:** not multi-process safe (see Context).
- **A logging daemon or single writer process:** adds a service every tool must find and survive.
- **A separate lock file:** the first design; a cleaner deleting it breaks mutual exclusion (decision 3).
- **Per-process files** (`logs-<pid>.jsonl`): avoids locking but multiplies files, breaks "one live file per signal" and the shipping story.
- **Lock the data file:** races with rename (decision 3).
- **`logrotate`/`newsyslog` externally:** per-host configuration, no guarantee against a writer holding the old inode, and no portable story for the fleet.
- **Trust `O_APPEND` alone:** atomic appends do not protect against writing into a renamed file (decision 4).

## References

- [vig-os/vigil#4](https://github.com/vig-os/vigil/issues/4) (pre-mortem findings 1–6), [#1](https://github.com/vig-os/vigil/issues/1)
- [gerchowl/s1-mcp#6](https://github.com/gerchowl/s1-mcp/pull/6) (origin of the rotation)
- [gerchowl/g-fleet#355](https://github.com/gerchowl/g-fleet/issues/355) (ecosystem comparison)
- [ADR-0001](0001-on-disk-format.md) (file names and format)
