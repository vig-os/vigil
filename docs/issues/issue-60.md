---
type: issue
state: open
created: 2026-10-10T23:21:54Z
updated: 2026-10-11T00:50:40Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/60
comments: 2
labels: priority:medium, area:testing, effort:medium
assignees: none
milestone: 0.2.0 — metrics + traces
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:31.258Z
---

# [Issue 60]: [test(shipping): reference Collector config and exactly-once conformance across restart and rotation](https://github.com/vig-os/vigil/issues/60)

Implements the file-shipper half of ADR-0006 (#39, decision 2): the Collector-contrib `otlpjsonfile` receiver is vigil's reference shipper. It is documented and conformance-tested, and its loss and duplicate bounds are proven, not described.

## Scope

**`docs/shipping/collector.yaml`**, the reference config from ADR-0006 decision 2, for logs, metrics and traces:
- **receiver:**
  - `include` lists each service by name: `${SHIPPER_STATE_ROOT}/<service>/<signal>.jsonl` and `<signal>-*.jsonl`. `SHIPPER_STATE_ROOT` and `SHIPPER_STORAGE_DIR` are absolute paths, the shipper's own variables; vigil does not read them;
  - `start_at: beginning`, `include_file_name: false`;
  - `storage: file_storage/vigil`, `max_concurrent_files: 2`.
- **`file_storage/vigil`:** on persistent storage, with `compaction: { on_start: true, on_rebound: true, rebound_needed_threshold_mib: 10, rebound_trigger_threshold_mib: 2 }`.
- **every `otlp_http` exporter:** `sending_queue: { enabled: true, storage: file_storage/vigil, block_on_overflow: true, sizer: bytes, queue_size: 268435456 }` and `retry_on_failure: { enabled: true, max_elapsed_time: 0 }`.
- no `batch` processor while the pin is below 0.162.0.

**README shipping section:**
- the rules and the remaining loss and duplicate modes table (ADR-0006 decision 2), and the queue sizing rule (`queue_size` ≥ data rate × longest outage a clean stop must survive);
- disk use: up to `queue_size` per exporter plus ~18% storage overhead (about 900 MiB for three), plus room for compaction's temporary copy;
- the operator signal: `otelcol_exporter_queue_size` reaching `otelcol_exporter_queue_capacity` in the shipper's telemetry means "do not stop the shipper"; and that "Exporting failed. Dropping data." at SIGTERM is **not** loss with this config, while "Rejecting data … context canceled" on a full queue is;
- the record identity used for deduplication;
- the required Prometheus setting `otlp.promote_scope_metadata: true`, and why (without it, same-named instruments of two crates collapse into one series);
- the backend acceptance windows (Loki `reject_old_samples_max_age`, default 1w, and its per-stream out-of-order window; Prometheus `out_of_order_time_window`, default 0);
- the permission rule (the shipper runs as the writing user, or as root);
- each new service must be added to `include` (an unlisted service is silently never shipped);
- "push or file shipper, not both" (`VIGIL_PUSH=off`), and push's port-squatting limit (ADR-0006 decision 5).

**Pin moves:** at 0.154.0 rename the receiver to `otlp_json_file`; at 0.162.0 re-evaluate the `batch` rule.

## Conformance tests

`#[ignore]`d unless `otelcol-contrib` is on PATH, like `tests/collector.rs`.
- **Harness:** a second Collector (`otlp` receiver → `file` exporter, **one output file per run**, because the `file` exporter truncates on start) is the backend.
- **Ports and directories:** unique per run, and wait for each process to exit before the next starts. A reused port or case directory produced false results in the ADR probes.

Each case below is shown failing once (on the named setting, or on today's code), then passing with the reference config.

1. **Restart and rotation** (Probe F): records before start, while running, and while stopped across rotations → **exactly once**. Fails without receiver `storage` (duplicates), with `start_at: end` (loss), and with the live file only (loss).
2. **Backend down + clean restart** (S1/F): 1500 records while the backend is down, then SIGTERM, backend up, restart → **1500/1500, no duplicates**. Fails with the exporter defaults (memory queue: everything lost) and with the default request-count queue of 1000 (Q1: ~100–150 lost).
3. **Retry cap:** backend down longer than a finite `max_elapsed_time` → loss with the cap (S6), none with `0`.
4. **Full queue + clean stop (bounded loss):** with a deliberately small `queue_size`, fill the queue, then SIGTERM, backend up, restart → **at most 100 lines lost per signal** (one reader batch, Q3b: 99). Each line is one export batch: up to 1 MiB, up to 512 log records. Use **multi-record lines** written through `vigil::init`, and assert in lines **and** report records. Fails the bound without `max_concurrent_files: 2` (Q3a: 215–298 one-record lines).
5. **SIGKILL, duplicate bound:** (a) mid-flow with a live backend and rotation; (b) with the queue full. Both → **no loss**. Duplicates, counted in lines: ≤ one poll's lines for (a) (Probe Q saw ≤ 35 of 3000 at `poll_interval: 100ms`), and ≤ queue contents + one 100-line batch for (b). Report records too.
6. **Overflow without blocking:** SIGKILL and restart with `block_on_overflow` off → loss ("sending queue is full", S4). The reference config shows none.
7. **Compaction:** after an outage backlog drains, with a backlog well above the 10 MiB `rebound_needed_threshold_mib`, the `file_storage` directory shrinks to ≤ 5% of its peak (Probe Q: 118 MB → 0.33 MB). It does not shrink without `compaction`.
8. **Fingerprints** (Probe K): the first lines of two segments differ within the first 1000 bytes, with fixtures using a 700-byte metric description and a 2 KiB log body. It runs **with `serde_json/preserve_order` enabled** (#64). It fails on today's alphabetical order and passes after #64 and #7.
9. **`otelcol-contrib validate`** accepts the shipped config in CI.
10. **Prometheus `otlp.promote_scope_metadata: true`** (required, ADR-0003 decision 12 and ADR-0006 decision 2): the shipped Prometheus config sets it. Two crates recording the same instrument name arrive through the reference shipper as two series with distinct `otel_scope_name` labels. Shown failing once without the setting: the series collapse and one crate's data is dropped silently.

Refs: #39


---

# [Comment #1]() by [gerchowl]()

_Posted on October 10, 2026 at 11:58 PM_

**Scope added by ADR-0006 round 2** (Probe S, reproduced 2026-10-11 on otelcol-contrib 0.151.0):

- **Reference config:** every `otlp_http` exporter gets `sending_queue: { enabled: true, storage: file_storage/vigil, block_on_overflow: true }` and `retry_on_failure: { enabled: true, max_elapsed_time: 0 }`. `include` lists each service by name (`${VIGIL_STATE_ROOT}/<service>/<signal>.jsonl` and `<signal>-*.jsonl`), not `*/`.
- **Case "backend down + restart":** a second Collector (`otlp` receiver → `file` exporter, one output file per run) is the backend. Write N records; backend down ≥ 8 s; SIGTERM the shipper; backend up; restart the shipper. Assert every record exactly once. Shown once to fail with the exporter defaults: S1, 0/20 delivered.
- **Case "SIGKILL mid-flow":** stream 3000 records with rotation (`max_bytes` ≈ 200 kB), SIGKILL the shipper after ~1.5 s, restart it, wait, then assert **no loss**. Duplicates are allowed but must be counted and stay small: S4/S5 saw 0–10. Shown once to fail without `block_on_overflow` (S4: 168–356 lost).
- **Case "outage longer than the retry cap":** with `max_elapsed_time: 5s` the backend-down case loses data (S6: 12/20). The shipped config must pass it with `0`.
- **Fingerprint test** with `serde_json/preserve_order` enabled (feature unification, #64); it must still pass after #64 and #7.
- **README:** the remaining loss and duplicate modes table from ADR-0006 decision 2, and the push security limit (decision 5) next to the "push or file shipper, not both" rule.


---

# [Comment #2]() by [gerchowl]()

_Posted on October 11, 2026 at 12:01 AM_

Naming fix from ADR-0006 review: the shipper config uses its own variables, `SHIPPER_STATE_ROOT` (absolute; the Collector does not expand `~`) and `SHIPPER_STORAGE_DIR`, not `VIGIL_*` names, which vigil itself does not read. The comment above that says `${VIGIL_STATE_ROOT}` means `${SHIPPER_STATE_ROOT}`. The README also documents that each new vigil service must be added to `include` (an unlisted service is silently never shipped).

