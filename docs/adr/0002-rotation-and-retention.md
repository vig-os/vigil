# ADR-0002: Multi-process rotation and retention

- **Status:** Accepted
- **Date:** 2026-10-09
- **Issues:** [#1](https://github.com/vig-os/vigil/issues/1), [#4](https://github.com/vig-os/vigil/issues/4)

## Context

Several fleet tools run one process per agent session, all appending to the same `<signal>.jsonl`. The rotation in [gerchowl/s1-mcp#6](https://github.com/gerchowl/s1-mcp/pull/6) works for that (8 concurrent writers × 50 records, no loss) and is the starting point, but the pre-mortem on [#4](https://github.com/vig-os/vigil/issues/4) (probed 2026-10-09, all confirmed by tests) found six defects in the naive port. The numbers below are those probes.

No existing crate fits. `file-rotate`, `logroller`, `log2`, `flexi_logger`, `rolling-file` and `tracing-appender` keep in-process size counters and rename without cross-process coordination: they are thread-safe, not multi-process safe ([g-fleet#355](https://github.com/gerchowl/g-fleet/issues/355), ecosystem table).

## Decision

Rotation lives in the crate, std only (`File::lock`, stable since Rust 1.89), Unix targets (Linux, macOS), `#![forbid(unsafe_code)]`.

1. **Size rotation, default 50 MiB.** Rotate when `len + line + 1 > max_bytes`. A single line larger than the limit is still written, alone in a fresh file. Size arithmetic is checked or saturating, because crane runs every Nix check with `--release` where overflow checks are off.
2. **Age retention, default 90 days; `None` keeps everything.** A rotated segment is deleted when its mtime is older than the retention. The live file and the lock file are never deleted.
3. **Separate lock file.** All writers take an exclusive `flock` (std `File::lock`) on `<signal>.jsonl.lock`, which is never renamed. Locking the data file itself lets a waiter lock the inode that was just renamed away and write under a lock nobody else holds.
4. **Inode recheck before every write.** With the lock held, compare the live path's `(dev, ino)` with the cached handle and reopen if they differ; then size-check, rotate if needed, write. Without it, a process holding an `O_APPEND` handle from before another process rotated keeps writing into the renamed segment. Probe: 8 processes × 500 records, 2000 B limit, **428–2529 of 4000 records landed in rotated segments** and segments grew to 64 688 B. Fixed variant: 0 lost, 0 misplaced, 0 over the limit.
5. **Collision-free, chronologically sortable segment names.** `<signal>-<UTC stamp with nanoseconds>.jsonl`, and if that name already exists a zero-padded counter is appended, so the lexicographic order is the chronological order. Format, as implemented in [PR #22](https://github.com/vig-os/vigil/pull/22) (`stamp_at`, `unique_target` in `src/rotate.rs`): `<signal>-YYYYMMDDTHHMMSS.<9-digit nanos>Z.jsonl`, and on collision `<signal>-<stamp>_NNNNNN.jsonl` with a 6-digit zero-padded counter. Example: `logs-20261009T141245.123456789Z.jsonl`, then `logs-20261009T141245.123456789Z_000001.jsonl`. The separator is `_` because it sorts after `.`, so the bare name comes first. The naive scheme was wrong twice: `rename` replaces, so two rotations in the same second overwrote each other (**3960–3979 of 4000 records lost**); and s1-mcp's `-N` suffix sorts wrongly (`…Z-1.jsonl` < `…Z.jsonl`, `-10` < `-2`).
6. **Rollback of partial writes.** Under the lock, record the length before writing; if the write fails part-way (for example `EFBIG`), `set_len` back to it and return the error. Otherwise the next record is glued onto a half line and both are unreadable. Each line is written as one `write(2)` of `line + '\n'`.
7. **One lock handle per path per process.** `flock` locks belong to the open file description, so a second handle in the same process blocks on the first. The handle lives inside the shared writer (`Arc`); a second `open` of the same path in the same process shares it or fails clearly, and never deadlocks.
8. **Pruning** runs after a rotation and once per process at open. Prune errors are ignored and never fail an append.
9. **Local filesystems only.** `flock` and `O_APPEND` atomicity are not reliable over NFS; a state directory on NFS is unsupported and documented as such.
10. **Files and directories** are created `0600` and `0700`.
11. **Reader helpers** shipped with the writer (#4): `segments` (oldest to newest, live file last), `segments_since` (mtime window), `read_since`, and `find_newest` (newest-first search).

### Acceptance evidence

The acceptance test is a **multi-process** test, not a thread test: the test binary re-executes itself as N ≥ 4 children, each writing M records with a tiny `max_bytes` that forces many rotations. It asserts every record appears exactly once across all segments, every line is whole, no segment exceeds the limit except single oversize lines, and no segment name collides. It sits beside targeted tests for each probe above (same-second rotation, name order, stale-inode reopen, retention with set mtimes, `None` keeps, partial-write rollback via a test seam, second `open` not deadlocking). Tests write only under `std::env::temp_dir()`, since `HOME` is unwritable in the Nix sandbox.

## Consequences

- Any number of local processes may share a state directory safely; the cost is one `flock` and one `stat` per write.
- The lock file (`<signal>.jsonl.lock`) sits beside the data and must be ignored by readers and shipping agents; segment listing matches only `<signal>.jsonl` and `<signal>-*.jsonl`.
- Timestamps in names are from the rotating process's clock; ordering by name is only as good as host clock monotonicity, and counters cover same-instant collisions.
- Retention is by file mtime, so a segment survives 90 days after its *last* write, not its first.
- Windows is out of scope.

## Alternatives considered

- **An existing rotating-file crate:** not multi-process safe (see Context).
- **A logging daemon or single writer process:** adds a service every tool must find and survive.
- **Per-process files** (`logs-<pid>.jsonl`): avoids locking but multiplies files, breaks "one live file per signal" and the shipping story.
- **Lock the data file:** races with rename (decision 3).
- **`logrotate`/`newsyslog` externally:** per-host configuration, no guarantee against a writer holding the old inode, and no portable story for the fleet.
- **Trust `O_APPEND` alone:** atomic appends do not protect against writing into a renamed file (decision 4).

## References

- [vig-os/vigil#4](https://github.com/vig-os/vigil/issues/4) (pre-mortem findings 1–6), [#1](https://github.com/vig-os/vigil/issues/1)
- [gerchowl/s1-mcp#6](https://github.com/gerchowl/s1-mcp/pull/6) (origin of the rotation)
- [gerchowl/g-fleet#355](https://github.com/gerchowl/g-fleet/issues/355) (ecosystem comparison)
- [ADR-0001](0001-on-disk-format.md) (file names and format)
