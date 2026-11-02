---
type: issue
state: closed
created: 2026-11-01T23:56:02Z
updated: 2026-11-02T10:19:27Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/163
comments: 1
labels: none
assignees: none
milestone: none
projects: none
parent: none
children: none
synced: 2026-11-02T13:59:41.095Z
---

# [Issue 163]: [feat(rotate): bound total disk use — rotated-segment count and/or total-bytes cap (optionally per signal)](https://github.com/vig-os/vigil/issues/163)

## Motivation

A consumer (a long-running multi-process CLI, part of vigil's planned adoption, #16) needs a firm upper bound on disk use.

- Today the consumer keeps 5 MiB × 2 rotated files in its own logger, so its footprint is bounded.
- The consumer's vigil integration contract (its own ADR) requires per-signal limits:

  | Signal | Size per file | Rotated files | Age |
  |---|---|---|---|
  | logs | 16 MiB | 4 | 14 d |
  | traces | 32 MiB | 4 | 7 d |
  | metrics | 8 MiB | 2 | 30 d |

- It also requires a total cap (`max_total_bytes`, default 512 MiB) that deletes the oldest rotated files first.
- vigil's current controls are one segment size (50 MiB) and one age (90 d), with no limit on the number of segments. A busy agent fleet can write many GiB inside 90 days.
- Consumers then have to delete segments themselves, outside vigil's directory lock. That races with rotation in other processes.

## Best-practice basis

- **OWASP Logging Cheat Sheet, Verification:** "Ensure logging cannot be used to deplete system resources, for example by filling up disk space". See also "Attacks on Logs > Availability". https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- **NIST SP 800-92, §5.1.2 Log Storage and Disposal:** rotate when a maximum size is reached, and define what happens when storage is full. §2.3.2 also covers this.
- **OTel prior art:** the Collector-contrib `fileexporter` offers `max_megabytes`, `max_days` and `max_backups` ("the maximum number of rotated telemetry files to retain").

## Why it isn't covered yet

- **ADR-0002 decisions 1, 2 and 8:** size rotation plus mtime-age retention only.
- **`RotationConfig`:** exposes `max_bytes` and `retention`, each a single value for all signals (ADR-0004).
- **#4:** scoped retention to age only.
- **Issue tracker:** no issue covers a segment count, a total size or a disk quota.
- **ADR-0002 also notes** that prune cost grows linearly with the number of segments (48 000 segments took about 10 min). A count cap would bound that as well.

## Acceptance criteria

- [ ] Additive options `max_segments(Option<usize>)` and/or `max_total_bytes(Option<u64>)`, plus `VIGIL_*` env equivalents. Enforced at the existing prune points under the directory lock: delete the oldest rotated segments first, never the live file.
- [ ] Optional per-signal overrides for size, count and age.
- [ ] A multi-process test proving the bound holds while N writers rotate at once.
- [ ] The README states the worst-case disk-use formula.
- [ ] An amendment to ADR-0002.



---
*Consumer names and private references were redacted by the maintainers; the requirements are unchanged.*

---

# [Comment #1]() by [gerchowl]()

_Posted on November 2, 2026 at 10:19 AM_

**Landed on `dev`, so this issue is closed.**

The design is ADR-0002 amendment 3 (#169, now **Accepted**). The implementation is #176 (count cap and per-signal overrides) and #178 (total-bytes cap and the disk-use bound). Both were reviewed by fresh reviewers who ran independent multi-process probes.

**How to adopt**
- **Pin.** Until the next release is tagged, pin the `dev` merge commit: `vigil-telemetry = { git = "https://github.com/vig-os/vigil", rev = "47778e1" }`. Then switch to the release tag (`0.2.0` or later) when it ships; I'll post here when it does.
- **Builders.** All caps are off by default, so existing behaviour is unchanged:
  - `Config::max_segments(Some(k))` caps the rotated segments per signal (`Some(0)` keeps none);
  - `Config::max_total_bytes(Some(t))` sets one budget over all telemetry signals, deleting oldest first;
  - `Config::signal_rotation(Signal::Logs, SignalRotation::new().max_bytes(…).max_segments(Some(…)))` sets per-signal overrides of size, count and age.
  
  The same methods exist on `RotationConfig`.
- **Environment.**
  - Global: `VIGIL_MAX_SEGMENTS`, `VIGIL_MAX_TOTAL_BYTES`.
  - Per signal: `VIGIL_{LOGS,METRICS,TRACES}_{MAX_BYTES,MAX_SEGMENTS,RETENTION_DAYS}`.
  - A builder value beats the environment. An invalid value warns once and falls back to the default.
- **The bound.** The README section "Rotation" states the worst-case formula: visible bytes ≤ `max(T, Σ V_s)`, plus `R = Σ_s W_s · max(M_s, l_s)` for segments that idle writers still hold open after a prune, counted **per writer instance** (`init` opens one per enabled signal per process). It is a bound on **logical** bytes; filesystem block rounding is noted separately.
- **Limits** (ADR-0002 decisions 17 and 22):
  - **Live files.** They are never deleted. If `T` is below the live files' reservations, every rotated segment is pruned and vigil warns once.
  - **Quiet signals.** Under total-cap pressure, a quiet signal's rotated history can be fully pruned; a count cap is a ceiling, not a floor.
  - **Audit trail files.** They are never counted or deleted.
- **Default caps.** A default cap before 1.0 is tracked in #168.

