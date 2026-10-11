# ADR-0006: Shipping: the Collector file shipper, an optional `push` feature, and the Alloy gap

- **Status:** Accepted (2026-10-11)
- **Date:** 2026-10-11
- **Supersedes:** [ADR-0001](0001-on-disk-format.md) decision 9 ("shipping stays outside the crate… no network exporter") **for the optional `push` feature only**; the default build keeps decision 9 unchanged. **Extends** ADR-0001 decision 5 and amends its versioning stance with a promised time-first JSON key order (decision 3 below).
- **Issues:** [#39](https://github.com/vig-os/vigil/issues/39) (this decision); implemented by [#60](https://github.com/vig-os/vigil/issues/60) (reference shipper config and conformance), [#7](https://github.com/vig-os/vigil/issues/7) and [#8](https://github.com/vig-os/vigil/issues/8) (key order), [#64](https://github.com/vig-os/vigil/issues/64) (feature-independent writer), [#41](https://github.com/vig-os/vigil/issues/41) (`push`), [#65](https://github.com/vig-os/vigil/issues/65) (authenticated push transport, after 1.0); fleet rollout [#15](https://github.com/vig-os/vigil/issues/15)

## Context

vigil writes OTLP/JSON Lines files ([ADR-0001](0001-on-disk-format.md)) that rotate under a directory lock ([ADR-0002](0002-rotation-and-retention.md)). Loki ≥ 3 and Prometheus ≥ 3 ingest OTLP natively, so something has to carry the files' contents to them. The fleet plan ([gerchowl/g-fleet#355](https://github.com/gerchowl/g-fleet/issues/355), g-fleet ADR-029) runs one Grafana Alloy agent per host. The path-to-1.0 pre-mortem (R8, 2026-10-10) found that **Alloy cannot read vigil's files**: none of its `otelcol.receiver.*` components reads OTLP/JSON files, and `filelog` would ingest each line as a text body, which is wrong for metrics and traces. #15's fallback ("vigil pushes OTLP/HTTP") contradicts ADR-0001 decision 9.

**Owner decision (2026-10-11):**
1. The Collector-contrib `otlpjsonfile` receiver is the **reference file shipper**, documented and conformance-tested.
2. An optional **`push` feature** (OTLP/HTTP to a local agent such as Alloy's `otelcol.receiver.otlp`) is wanted, and the files stay the durable copy.
3. The fleet rollout (#15) may land after 1.0.

This ADR turns that into checkable decisions. Every claim below was probed on 2026-10-11 in scratch directories outside the repository, using the flake's pinned nixpkgs (`cf5e765`): Rust 1.95.0, otelcol-contrib 0.151.0, Grafana Alloy 1.16.0 and Loki 3.7.8. The writer was a scratch crate on this branch's vigil using `vigil::rotate::RotatingFile` (rotation at 4000 bytes) and `vigil::init`.

### Probe F: the file shipper under restart and rotation

Each run wrote 150 numbered records in three phases: 50 before the Collector started, 50 while it ran, and 50 while it was stopped (the stops crossed several rotations). The Collector was then restarted. Each Collector run wrote to its own `file` exporter output, because the `file` exporter truncates its output when it starts (the first attempt hid every duplicate that way).

| Case | `storage` | `start_at` | `include` | Delivered | Duplicates | Lost |
|---|---|---|---|---|---|---|
| F1 | none | `beginning` | live + segments | 250 | **100** | 0 |
| F2 | none | `end` | live + segments | 50 | 0 | **100** |
| F3 | `file_storage` | `beginning` | live + segments | **150** | **0** | **0** |
| F4 | `file_storage` | `beginning` | live only | 68 | 0 | **82** |
| F5 | `file_storage` | `beginning` | live + segments, metrics (19 segments) | 150 | 0 | 0 |

- **F1:** without storage, every restart re-reads every file. For metrics that re-sends old cumulative samples.
- **F2:** `start_at: end` skips both what existed before the first start and what was written while the Collector was down.
- **F4:** a record still unread when its file is rotated out of the pattern is lost.
- **`include_file_name`:** by default (`true`) the receiver adds `log.file.name` to every log record's attributes and to every metric's `metadata`. Its value changes on every rotation (`metrics.jsonl`, then `metrics-20261011T….jsonl`). With `include_file_name: false` neither appears (F3 with the option set: same 150/0/0, no extra keys).

### Probe S: the shipper when the backend is down, restarts and crashes

The architect's review of this ADR found that Probe F's config loses data when the backend is unavailable; reproduced and extended here. A second Collector (`otlp` receiver → `file` exporter) stood in for the backend; the shipper read vigil's files and sent with `otlp_http`. "Disk queue" means `sending_queue: { storage: file_storage/vigil }`, sharing the receiver's storage extension.

| Case | Shipper exporter | Scenario | Delivered | Lost | Duplicates |
|---|---|---|---|---|---|
| S1 | defaults (memory queue, 5 min retry cap) | 20 records; backend down 8 s; SIGTERM shipper ("Exporting failed. Dropping data."); backend up; restart | 0/20 | **20** | 0 |
| S2 | disk queue, `max_elapsed_time: 0` | same | 20/20 | 0 | 0 |
| S3 | disk queue, `max_elapsed_time: 0` | same, but SIGKILL instead of SIGTERM | 20/20 | 0 | 0 |
| S4 | disk queue (and, once, memory queue), `block_on_overflow` off | 3000 records at ~1/ms, rotating every ~670; SIGKILL after 1.5 s; restart while writing continues; 3 runs | 2644, 2832, 2828 | **356, 168, 172** | 2, 10, 0 |
| S5 | disk queue, `max_elapsed_time: 0`, `block_on_overflow: true` | as S4, 3 runs | 3000/3000 each | 0 | 0 |
| S6 | as S5 but `max_elapsed_time: 5s` (stand-in for the 5 min default) | backend down 8 s, no restart | 8/20 | **12** | 0 |
| S7 | as S5 | as S6 | 20/20 | 0 | 0 |
| S8 | S4's settings (disk and memory queue, `block_on_overflow` off) | 3000 records with rotation, **no** kill or restart, 4 variants | 3000/3000 each | 0 | 0 |

- **S1:** the receiver commits its offsets once a line is handed to the pipeline, and the default sending queue lives in memory, so whatever was queued or retrying at shutdown is gone. S2/S3 fix this with a disk queue and unbounded retry.
- **S4:** after a restart the receiver reads its backlog faster than the exporter sends; the full queue rejects data ("sending queue is full", `rejected_items`), the receiver does not retry rejected data, and its offsets move on. `block_on_overflow: true` turns that into backpressure (S5).
- **S6:** the retry cap drops data on a long outage even while the shipper keeps running. In one run with a 5 s cap followed by a restart, the dropped batches were delivered after all (with 1 duplicate); this is not relied on.
- **Duplicates:** a SIGKILL re-sends what was read since the receiver last saved its offsets. Probe Q measures how much that can be.

### Probe Q: queue capacity, clean stops while the queue is full, duplicates, disk

The second review found that S5's config still loses data when an outage backlog outgrows the queue. Same harness as Probe S, with S5's settings unless a row says otherwise. Each case was run 1–7 times on unique ports. Every probe line held one record; vigil's lines hold more (below).

| Case | Queue | Scenario | Delivered | Lost | Duplicates |
|---|---|---|---|---|---|
| Q1 | default `sizer: requests`, 1000 | 1500 records while the backend is down (queue full at stop); SIGTERM; backend up; restart | 1351/1500 | **149** | 0 |
| Q2 | `sizer: bytes`, 256 MiB | as Q1 (queue holds the backlog: 132 390 bytes) | 1500/1500 | 0 | 0 |
| Q3a | `sizer: bytes`, 50 000 (forced full) | as Q1; 3 runs | 1285, 1202, 1285 | **215, 298, 215** | 0 |
| Q3b | as Q3a, plus `max_concurrent_files: 2` | as Q1; 4 runs (Q3b ×3, QO) | 1401 each | **99 each** | 0 |
| Q4 | as Q3a | as Q1 but SIGKILL; 2 runs | 1500/1500 | 0 | **566 each** |
| QF | reference config (decision 2) | as Q1; 5 runs | 1500/1500 each | 0 | 0 |
| QFK | reference config | as Q1 but SIGKILL; 2 runs | 1500/1500 each | 0 | 0 |
| QM | reference config, live backend | 3000 records streaming with rotation; SIGKILL at 1.5 s; restart; 7 runs | 3000/3000 each | 0 | 0, 0, 35, 8, 0, 1, 0 |

- **Why a clean stop loses data when the queue is full** (Q1, Q3).
  - With `block_on_overflow`, the receiver's hand-off of a batch blocks while the queue is full.
  - On SIGTERM the Collector cancels it ("Rejecting data", `context canceled`), and the reader advances its offset anyway: `pkg/stanza/fileconsumer/internal/reader/reader.go:268-273` and `:289-293` at v0.151.0, unchanged on main.
  - A batch is at most 100 lines (`reader.DefaultMaxBatchSize`, not configurable), and every file read concurrently holds one, so Q3a lost two to three batches.
  - `max_concurrent_files: 2` makes the receiver read one file at a time, which bounds the loss at one batch (Q3b: 99 in 4/4 runs).
  - `otlpjsonfile` has no receiver-side retry option at v0.151.0 or on main, so no setting can keep the offset.
- **Why the queue must hold the outage** (Q2, QF). While the queue is not full, nothing blocks, so a clean stop loses nothing.
- **Sizing data.** `sizer: bytes` counts the exporter's encoded request size, not the JSON line:
  - ~100 KB log lines: 1000 lines held 100 099 890 queue bytes;
  - ~300-byte lines: 50 000 bytes held 566 records.
- **Operator signal.** The shipper's own metrics (`service.telemetry.metrics`) show `otelcol_exporter_queue_size` reaching `otelcol_exporter_queue_capacity` before the full state that a stop would turn into loss. On such a stop the shipper logs "Rejecting data" with `context canceled`.
- **Duplicates after SIGKILL.**
  - The receiver saves its offsets after each completed poll. While the queue is not full, a SIGKILL re-sends what one poll read: QM saw 0–35 of 3000 (probes ran with `poll_interval: 100ms`; the default of 200 ms reads more per poll), and the review saw 1, 7 and 91.
  - While the queue is full, the blocked poll never completes, so a SIGKILL re-sends everything queued since the last saved offset: Q4 re-sent the whole queue (566), and the review saw 1000 with the default 1000-item queue.
  - So the bound is the queue's contents plus one batch.
- **Backends absorb exact duplicates.** The same OTLP log record pushed twice to Loki 3.7.8 came back as **1** entry. The same cumulative sample pushed twice to Prometheus 3.12.0 counted **1** sample.
- **Disk** (100 KB lines; queue held 100 MB). The `file_storage` file grew to 118 MB and, **without compaction, stayed 118 MB after the queue drained and after a restart**. With `compaction: { on_start: true, on_rebound: true }` (thresholds 10/2 MiB as in the reference config; `check_interval: 1s` in the probe, default 5 s) it shrank to 0.33 MB after draining and 0.1 MB after a restart (K1 vs K2), with all 1000 records delivered.
- **A misleading log line.** "Exporting failed. Dropping data." is logged at SIGTERM for items that the disk queue keeps and delivers after the restart (S2, QF).

### Probe K: fingerprints and JSON key order

The receiver (stanza `fileconsumer`) identifies a file by its first `fingerprint_size` bytes (default 1000), not by inode. If two segments of one signal start with the same 1000 bytes, the receiver takes the second for the first, which it has already read, and **silently skips it**.

- **Reduced fingerprint** (`fingerprint_size: 100`, below the divergence point): 13/150 logs and 8/150 metric points delivered.
- **Default fingerprint, realistic content.** A cumulative sum whose description is 700 bytes: in today's alphabetical key order (`{"resourceMetrics":[{"resource":…,"scopeMetrics":[{"metrics":[{"description":…,"name":…,"sum":{"dataPoints":[{…,"timeUnixNano":…`), the first lines of two segments first differ at byte **1092**. Only **3/150** points were delivered, and the Collector logged no error.
- **The same data with the varying field first** (`{"resourceMetrics":[{"scopeMetrics":[{"metrics":[{"sum":{"dataPoints":[{"timeUnixNano":…`) first differs at byte **97**: **150/150**.
- **Real lines today:** real `vigil::init` log lines first differ at byte 342, so the default is safe today for short attributes and bodies. The order is decided by `serde_json`'s sorted maps, though, and anything long that sorts before the timestamps (attributes, `body`, metric descriptions, histogram bounds) pushes the first difference past 1000 bytes.
- **Key order is accepted everywhere:** both the `otlpjsonfile` receiver and the OTLP/HTTP receiver (HTTP 200) accepted the time-first order and returned the same data.

### Probe P: OTLP/HTTP with vigil's own bytes

- **Collector receiver.** vigil's file lines, POSTed verbatim with `Content-Type: application/json` to otelcol-contrib 0.151.0's `otlp` receiver (`/v1/logs`, `/v1/metrics`), got HTTP 200 and came out of a `file` exporter equal **by meaning** (ADR-0001 decision 8).
  - A `"doubleValue":"NaN"` attribute (ADR-0001 decision 6) was accepted and kept.
  - A 1 048 080-byte body was accepted.
  - Malformed JSON got 400.
- **Alloy.** The same lines through Alloy 1.16.0 (`otelcol.receiver.otlp` → `otelcol.exporter.otlphttp` → the Collector) got 200 and arrived equal by meaning, NaN included.
- **Prototype.** A push worker using `ureq` 3.4.2 ran on its own thread: append to `RotatingFile`, then a non-blocking enqueue into a bounded queue of 64 lines; 2 s per request, 2 s shutdown budget.

| Agent | Sent | Dropped | Worst append + enqueue | File |
|---|---|---|---|---|
| up | 300/300 | 0 | 2.6 ms | 300 |
| down (connection refused) | 0 | 300 | 6 ms | 300 |
| starts 1.5 s into the run | 228/400 | 172 (queue full) | 0.37 ms | 400 |
| accepts TCP, never answers, deadline checked between attempts only | 0 | 200 | 0.2 ms | 200; **shutdown took 18.9 s** |
| same, deadline-capped request timeout, queue dropped at the deadline | 0 | 200 | 0.07 ms | 200; shutdown 2.02 s |
| answers 404 | 0 | 3, no retries | — | 3 |

### Probe D: the HTTP client's weight and build

Candidates, built on Rust 1.95 in the dev shell (crate counts include the probe's root crate):

| Crate | Crates | Network-stack crates pulled in |
|---|---|---|
| `ureq` 3.4.2, no default features | 11 | `http` only |
| `ureq` with `rustls` | 23 | `ring`, `rustls`, `webpki-roots` |
| `minreq` 3.0.0 | 2 | none; its `https-rustls` feature pulls `aws-lc-sys` |
| `reqwest` 0.13.5 blocking | 74 | `tokio`, `hyper`, `tower` |
| `opentelemetry-otlp` 0.33.1 (`http-json`, `reqwest-blocking-client`) | 102 | `tokio`, `hyper`, `reqwest`, `tower` |

- **Added to vigil's tree:** an optional `ureq` (no default features) adds 6 crates to vigil's normal dependency tree (64 → 70): `ureq`, `ureq-proto`, `http`, `httparse`, `base64` 0.23 and `utf8-zero`. None of them is on `tests/deps.rs`'s forbidden list.
- **Crane build:** a scratch clone with `push = ["dep:ureq"]` turned on by default passed crane's `clippy` and `nextest` checks (`nix build .#checks.x86_64-linux.{clippy,nextest}`, exit 0, 126 tests passed).
- **Metadata:** `ureq` declares `rust-version = 1.85` and is MIT OR Apache-2.0.
- **Unsafe defaults:** `ureq` 3.4.2 reads a proxy from the environment by default (`Proxy::try_from_env()`) and follows up to 10 redirects (`src/config.rs:948-950`).

### Probe L: Loki and `service.instance.id`

ADR-0003 adds a per-process `service.instance.id` to every signal and leaves Loki's label cardinality to this ADR. Loki's docs list it among the resource attributes promoted to index labels by default, while saying it is "no longer recommended" as one ([Loki OTel docs](https://grafana.com/docs/loki/latest/send-data/otel/)). Loki 3.7.8:
- **Defaults:** `service_instance_id` is an index label (`/loki/api/v1/series`).
- **The obvious override does nothing:** adding `attributes_config: [{action: structured_metadata, attributes: [service.instance.id]}]` changed nothing. Loki's parsed config puts the default `index_label` rule ahead of the user's rule.
- **What works:** `resource_attributes.ignore_defaults: true` plus an explicit `index_label` list without it. The only index label was then `service_name`, and `{service_name="probe2"} | service_instance_id != ""` still found the record through structured metadata.

### Why Alloy has no OTLP-file receiver

- **It ships a curated subset.** Alloy deliberately bundles only part of Collector-contrib. Its inclusion policy ([`docs/developer/add-otel-component.md`](https://github.com/grafana/alloy/blob/a753fee7a10311a332edd18a05567c3fcf9c0bba/docs/developer/add-otel-component.md), 2026-09-10) weighs signals:
  - **For inclusion:** Grafana product compatibility, clear demand in a feature request, ecosystem adoption, and filling a genuine gap.
  - **Against inclusion:** low stability or unmaintained, a non-reputable source, a heavy dependency or security footprint, and an incompatible license.
  - **Possible outcomes:** bundled and maintained in both engines; a community component in the Default Engine only; or not bundled ("you can still use it in your own build through OCB").
- **Neither engine has it today.**
  - Default Engine: Alloy 1.16.0 rejects `otelcol.receiver.otlpjsonfile` with `cannot find the definition of component name`.
  - OTel Engine (`alloy otel`, experimental): 1.16.0 lists 25 receivers (`alloy otel components`) and rejects the reference config with `'receivers' unknown type: "otlpjsonfile"`. At v1.20.1 (latest, 2026-09-28) its [`collector/builder-config.yaml`](https://github.com/grafana/alloy/blob/v1.20.1/collector/builder-config.yaml) lists 27 receivers. It includes `filelogreceiver` and the `filestorage` extension, but not `otlpjsonfilereceiver`.
- **Nobody has asked.** On 2026-10-11, GitHub search found no grafana/alloy issue or PR requesting `otlpjsonfile`, so there is no rejection on record. Related threads:
  - [grafana/alloy#6752](https://github.com/grafana/alloy/issues/6752) (2026-07-23, open, `needs-triage`, 0 comments, 7 👍) asks for the upstream **`otlpjson` connector**, for OTLP-JSON logs written to stdout.
  - In [grafana/alloy#4262](https://github.com/grafana/alloy/issues/4262) a maintainer noted (2025-08-27) that `fileexporter` output "requires a specific receiver to be able to read it back [otlpjsonfilereceiver]".
- **Weighed against Alloy's policy, the receiver would struggle.** Upstream its stability is **alpha** for traces, metrics and logs. Its codeowners entry says `seeking_new: true`. It was renamed `otlp_json_file` in contrib v0.154.0. Its metrics and traces paths read counts after handing data to the next consumer, a race that panics with the `batch` processor ([contrib#50314](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/50314)); that was fixed only in v0.162.0, and the pinned 0.151.0 has it (`file.go:156-158`, `:205-207`). Its dependency cost is small: it is built on `pkg/stanza`, which Alloy already ships for `filelog`. So the realistic outcome of a feature request is a **community component** (Default Engine, best effort), not a bundled one. This is our inference from the policy; Alloy has not said so.
- **The smaller upstream ask is the `otlpjson` connector.** Alloy 1.16.0 already has `otelcol.receiver.filelog` and `otelcol.storage.file` (public-preview); only `otelcol.connector.otlpjson` is missing (`cannot find the definition of component name`). The connector (`otlp_json`, alpha) is in the contrib **and k8s** distributions. Probe: Collector 0.151.0 with `filelog` (`start_at: beginning`, `include_file_name: false`, `file_storage`) → `otlpjson` connector → logs and metrics pipelines read vigil's rotated files: **150/150 logs and 150/150 metric points**, no extra attributes. Supporting #6752 with this use case (one wrapper, demand already filed) is more likely to land than a new receiver request.

**Nothing has been filed or commented upstream; that is the owner's call** (see Consequences).

## Decision

### 1. Files are always written; shipping reads them or tees them

vigil writes `<signal>.jsonl` exactly as ADR-0001/0002 say, whatever is enabled. A host ships by **one** of two paths:
- **(a) a file shipper** that reads the files (the reference is the Collector-contrib `otlpjsonfile` receiver, decision 2);
- **(b) the `push` feature** (decision 4), which sends the same lines to a local agent while they are written.

A host uses one path, never both: both would deliver every record twice. Push is switched on in code (decision 6), so the operator's switch on a file-shipper host is `VIGIL_PUSH=off`. The file is the durable copy: catching up after an outage is the file shipper's job; push is a live, best-effort feed.

**Delivery guarantees end at the backend's acceptance window.** The file shipper re-sends records that are hours or days old after an outage, and backends refuse records that are too old:
- **Loki** (3.7.8 defaults: `reject_old_samples: true`, `reject_old_samples_max_age: 1w`). Loki also accepts out-of-order entries per stream only within `max_chunk_age / 2` (1h by default) of that stream's newest entry. A catch-up that reads old segments while the live file is also being read, or that merges processes into one stream (the label config below drops `service.instance.id` from the labels), can therefore get old entries refused even inside the week;
- **Prometheus**: samples older than the TSDB head are out of order unless `out_of_order_time_window` is set (default 0). The pre-mortem saw out-of-order rejections from Prometheus 3.15.

So within ADR-0002's 90-day retention, a catch-up longer than those windows needs backend configuration, or the old records stay only in the files. This is documented with the reference config (#60). It was not probed here beyond reading Loki's defaults.

### 2. The reference file shipper: Collector-contrib `otlpjsonfile`, with bounded and documented loss

The reference config (shipped and tested in [#60](https://github.com/vig-os/vigil/issues/60)) is this, and each setting is load-bearing:

```yaml
extensions:
  file_storage/vigil:
    directory: ${env:SHIPPER_STORAGE_DIR}   # persistent; holds read offsets and the sending queues
    create_directory: true
    compaction:                             # without it the file never shrinks after an outage (Probe Q)
      directory: ${env:SHIPPER_STORAGE_DIR}
      on_start: true
      on_rebound: true
      rebound_needed_threshold_mib: 10         # the thresholds Probe Q proved (10/2 MiB)
      rebound_trigger_threshold_mib: 2
receivers:
  otlpjsonfile/logs:                        # likewise /metrics and /traces
    include:                                # one pair per vigil service; SHIPPER_STATE_ROOT: absolute path, e.g. /home/u/.local/state
      - ${env:SHIPPER_STATE_ROOT}/flock/logs.jsonl
      - ${env:SHIPPER_STATE_ROOT}/flock/logs-*.jsonl
    start_at: beginning
    include_file_name: false
    storage: file_storage/vigil
    max_concurrent_files: 2                 # one file at a time: bounds the full-queue stop loss to one batch
exporters:
  otlp_http/loki:                           # likewise /prometheus and /traces
    endpoint: http://loki.example:3100/otlp # → /otlp/v1/logs; Prometheus: …:9090/api/v1/otlp; traces: …:4318
    sending_queue: { enabled: true, storage: file_storage/vigil, block_on_overflow: true,
                     sizer: bytes, queue_size: 268435456 }   # 256 MiB per exporter; size it (below)
    retry_on_failure: { enabled: true, max_elapsed_time: 0 }
service:
  extensions: [file_storage/vigil]
  pipelines:
    logs:    { receivers: [otlpjsonfile/logs],    exporters: [otlp_http/loki] }
    metrics: { receivers: [otlpjsonfile/metrics], exporters: [otlp_http/prometheus] }
    traces:  { receivers: [otlpjsonfile/traces],  exporters: [otlp_http/traces] }
```

The full form (three receivers, three exporters, three pipelines) passes `otelcol-contrib validate` (0.151.0). `SHIPPER_STATE_ROOT` and `SHIPPER_STORAGE_DIR` are the shipper's own variables, not ones vigil reads. The Collector does not expand `~`, so both are absolute paths. The rules:

- **The receiver's `storage` is required.** Without it a restart re-sends everything (F1: 100 duplicates). With it, restarts and rotations while the Collector is down lose and duplicate nothing (F3, F5).
- **Each exporter needs a disk `sending_queue` with `block_on_overflow: true`, a byte capacity, and `max_elapsed_time: 0`.** The memory queue loses everything queued or retrying at shutdown (S1: 20/20 lost). Without `block_on_overflow` a backlog overflows the queue and is rejected for good (S4: up to 356/3000 lost). Any finite retry cap drops data during an outage longer than it (S6: 12/20 lost with 5 s; the default is 5 min). With all of them: S2, S3, S5, S7, QF, QFK and QM lost nothing. While the backend stays down, the queue fills; then the receiver stops reading and the rest of the backlog waits in vigil's own files, bounded only by retention.
- **Size each queue for the longest outage that a clean shipper stop must survive.** `queue_size` (bytes) ≥ the signal's data rate × that outage. For scale: Probe Q's one-record lines of ~300 bytes took ~90 queue bytes each, so 256 MiB held about 3 million such lines. vigil's lines usually carry many records, so measure your own rate in queue bytes (`otelcol_exporter_queue_size`) rather than counting records. Beyond that capacity the queue is full, and **a clean stop while it is full loses up to 100 lines per signal**: one reader batch (Q3b, with `max_concurrent_files: 2`; without that setting several batches, Q3a). A vigil line is one export batch, at most 1 MiB (ADR-0001 decision 10); for logs that is up to 512 records (`src/init.rs:314`). So the bound is up to 100 MiB of telemetry per signal. For logs that is up to 51 200 records (512 per line, `src/init.rs:314`). Metrics and span lines are bounded only in bytes, not in records. Watch `otelcol_exporter_queue_size` against `otelcol_exporter_queue_capacity` in the shipper's own telemetry, and do not stop or restart the shipper while they are equal. The cause is upstream (Notes for the owner).
- **Disk.** Each queue can hold up to its `queue_size` on disk; the storage file runs ~18% above the queued bytes (Probe Q: 118 MB for 100 MB). So the three reference queues need about 900 MiB on the `file_storage` filesystem, plus free space for compaction's temporary copy (up to the file's size). `compaction` with `on_rebound` returns the space after the backlog drains (118 MB → 0.33 MB). Without it the file stays at its peak for good, including across restarts. Compaction needs free space for a temporary copy in its `directory`.
- **Operator note:** at SIGTERM the shipper logs "Exporting failed. Dropping data." for items the disk queue keeps and delivers after the restart (S2, QF). With this config that line is not data loss; the loss signal is "Rejecting data" with `context canceled` while the queue is full.
- **`start_at: beginning`.** With `end`, records written before the first start or during downtime are lost (F2: 100/150).
- **`include` lists each vigil service's live file and its segments.** `<service>/<signal>.jsonl` and `<service>/<signal>-*.jsonl`, the names ADR-0002 decision 5 fixes. Matching only the live file loses whatever was unread when it rotated (F4: 82/150). Services are listed by name rather than with `*/`, because `$XDG_STATE_HOME/*/logs.jsonl` also matches files other programs write, and the receiver would ingest or reject them. Adding a service is a config change, made by whatever deploys the services (g-fleet for the fleet, #15).
- **`include_file_name: false`.** Otherwise every record carries a `log.file.name` that changes on rotation (F3 vs default). Only the shipper's own diagnostics need it.
- **No `batch` processor below contrib 0.162.0.** The receiver's metrics and traces paths race with mutating consumers ([contrib#50314](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/50314)). vigil already batches, and the receiver forwards one line at a time.
- **Defaults that must not be lowered:** `fingerprint_size` (1000; decision 3 guarantees uniqueness within it) and `max_log_size` (1 MiB; ADR-0001 decision 10 keeps lines below it).
- **Never `delete_after_read`.** It would delete the live file while writers still append to it.
- **The receiver's name.** It follows the flake's Collector pin: `otlpjsonfile` up to 0.153, `otlp_json_file` from 0.154 (the old name stays as a deprecated alias). #60 switches the config and the conformance test in the PR that moves the pin past 0.154.
- **Permissions.** Files are `0600` in a `0700` directory (ADR-0002 decision 10), so the shipper runs **as the writing user** (for example a `systemd --user` unit) or as root. vigil does not loosen its permissions for a shipper.
- **Retention outlives shipping lag.** A segment pruned (default 90 days, ADR-0002 decision 2) before the shipper reads it is lost.
- **Remaining loss and duplicate modes with this config,** each with its mitigation (#60 tests the ones marked ✓):

| Mode | Effect | Mitigation |
|---|---|---|
| A vigil service missing from `include` | that service is silently never shipped | The deployment adds each service when it installs it (#15); #60's README lists the step. |
| Backend down longer than retention | loss | Alert on shipper backlog. Retention (90 days by default) is the buffer. |
| Backend rejects old or out-of-order records (decision 1) | loss, logged by the shipper as a permanent error | Backend acceptance windows. |
| Clean stop (SIGTERM) while a queue is full (outage backlog > `queue_size`) | **loss of up to 100 lines per signal** (one reader batch; each line ≤ 1 MiB; for logs ≤ 512 records) (Q3b) ✓ | Size `queue_size` for the longest outage. Alert on `otelcol_exporter_queue_size` reaching `otelcol_exporter_queue_capacity`; don't stop the shipper in that state. The upstream fix is in Notes for the owner. |
| SIGKILL, crash or power loss | **duplicates of everything read since the last saved offset**: one poll's worth of lines with room in the queue (0–35 of 3000 one-record lines in QM, 91 in the review); up to the whole queue plus one 100-line batch when it is full (566 lines in Q4, 1000 in the review); each line can hold many records ✓ | Stop with SIGTERM (systemd's default). Loki and Prometheus absorb exact duplicates (Probe Q). Record identity is below the table. |
| Power loss with `file_storage` `fsync: false` (the default) | recent queue items and offsets may be lost or replayed | `fsync: true` at a write-cost; not probed. |
| `file_storage` directory lost or not persistent | full re-read: duplicates of everything retained; queued items lost but re-read | Put it on persistent storage owned by the shipper's user. |
| Files that start with identical bytes (before decision 3 / #64 land) | silent loss (Probe K) ✓ | Decisions 3 and #64. |
| Push and the file shipper both active | everything twice | Decision 1, `VIGIL_PUSH=off`. |
| A hand-written config that drops a rule above | loss or duplicates (F1, F2, F4, S1, S4, S6, Q1, Q3a) ✓ | Use the reference config. |

**Record identity for deduplication.** vigil records carry **no record id**, and this ADR adds none.
- **Logs:** a re-sent record is byte-identical, so its natural key is the stream (resource attributes) plus `timeUnixNano`, `observedTimeUnixNano`, body and attributes. With `service.instance.id` (ADR-0003) and nanosecond timestamps, two distinct records collide only when one process emits identical records in the same nanosecond. Loki stores identical (stream, timestamp, line) entries once.
- **Metrics:** a data point is keyed by series plus `timeUnixNano`. Prometheus ignores a sample identical to one it has.
- **Spans:** `traceId` + `spanId` is a unique key, but backend handling of a re-sent span was not probed.

A consumer that needs exact-once downstream dedupes on these keys; the shipper cannot provide it.
- **Prometheus must run with `otlp.promote_scope_metadata: true`** (required, [ADR-0003](0003-metrics-and-traces.md) decision 12). Every series then carries `otel_scope_name` and `otel_scope_version`. Without it, same-named instruments of two crates collapse into one series and one crate's data is dropped silently (ADR-0003's probe: `app_x_total` kept crate-a's 5/10/10 and lost crate-b's 7/14/14). It is a Prometheus setting, not a shipper one, so it sits next to the shipper config in the operator docs:

```yaml
# prometheus.yml (Prometheus started with --web.enable-otlp-receiver)
otlp:
  promote_scope_metadata: true
```

- **Loki labels.** Deployments with many short-lived processes stop `service.instance.id` from becoming a Loki index label as follows; the default list's `k8s.*` and `cloud.*` entries can be added back as needed, and everything not listed becomes structured metadata (Probe L):

```yaml
limits_config:
  otlp_config:
    resource_attributes:
      ignore_defaults: true
      attributes_config:
        - action: index_label
          attributes: [service.name, service.namespace, deployment.environment.name]
```

### 3. Time-first JSON key order, so every file has its own fingerprint

Extends ADR-0001 decision 5. **Implementation note (2026-10-11, #64):** the shared declarative ordered writer and the logs rows (`scopeLogs`, `logRecords`, then observed/event time) land in #64. Metrics and traces apply their rows in #7 and #8; #41 reuses the writer. The upstream OTLP serializer projects directly into a `serde_json::Value` for non-finite patching; maps are mutation storage and only the explicit ordered writer determines emitted key order. Finite doubles retain their exact values without a JSON text round trip. The splitter reuses that projection rather than parsing emitted JSON. Encoding and splitting share the explicit 16-edge AnyValue limit in ADR-0001 decision 10: SDK values are checked before recursive conversion and typed requests before projection, with over-deep SDK records counted as lost while healthy neighbors survive. Recursive processing is therefore bounded rather than proportional to arbitrary input depth. Tests cover the limit, limit+1 and 10,000-edge inputs. No `float_roundtrip` or `unbounded_depth` features are enabled; `raw_value` remains required by the strict audit reader. CI runs golden and deterministic ordering tests as two blocking jobs, with default JSON maps and with the opt-in `test-preserve-order` test feature; the latter also runs the audit shuffle/hash and committed corpus tests. The ordered writer emits single-field objects directly, looks up priority fields, and checks map-key order before collecting, emits alphabetically ordered maps directly after priority lookup, and sorts only the remainder of unordered maps. Priority rules are resolved once per array, and two-field objects need only one key comparison. The splitter emits priority arrays first and serializes metadata suffixes and records through the same writer, without reserializing growing batches. PR #75 supplied the audit codec and PR #85 supplied amendment-2 format support before #64. The #64 rebase regenerates the shared logs golden and audit writer corpus, verifies the committed corpus with `Record::parse_line` and the Collector, and asserts shuffled-key verification with unchanged canonical-protobuf bytes and hashes.

Metrics follow in [#7](https://github.com/vig-os/vigil/issues/7) (which generalizes the exporter seam over the three envelopes, ADR-0003 decision 2) and traces in [#8](https://github.com/vig-os/vigil/issues/8). vigil writes object keys in a fixed order: the listed keys first, in the order given, then all other keys alphabetically.

| Object | Keys first |
|---|---|
| `ResourceLogs` / `ResourceMetrics` / `ResourceSpans` | `scopeLogs` / `scopeMetrics` / `scopeSpans` |
| `ScopeLogs` / `ScopeMetrics` / `ScopeSpans` | `logRecords` / `metrics` / `spans` |
| `LogRecord` | `observedTimeUnixNano`, `timeUnixNano` |
| `Metric` | its data field (`sum`, `gauge`, `histogram`, `exponentialHistogram`, `summary`) |
| `Sum`, `Gauge`, … | `dataPoints` |
| data point | `timeUnixNano` |
| `Span` | `spanId`, `endTimeUnixNano` |

- **What this guarantees:** every line has a per-line value (a timestamp, or for spans a span id that is exported exactly once) within its first 128 bytes. So the first lines of any two files of one signal, across all the directories a shipper's glob matches, differ within the receiver's default 1000-byte fingerprint (Probe K: byte 97 instead of 1092; 150/150 instead of 3/150).
- **Within ADR-0001's promises:** JSON readers ignore key order, which the Collector's file and HTTP receivers confirm (Probe K). ADR-0001 said field order is deterministic within a version and not promised across versions; this decision amends that stance (the amendment is marked in ADR-0001) so the time-first keys are promised, because a shipper's correctness depends on them. The order of the remaining keys stays unpromised.
- **The order must not depend on the consumer's build.** Today's writer gets its order from `serde_json`'s maps (`src/logs.rs:182` goes through `to_value`). Those maps are sorted by default but insertion-ordered when *any* crate in the consumer's graph enables `serde_json/preserve_order`, because Cargo unifies features (review probe, [#64](https://github.com/vig-os/vigil/issues/64)). So decision 3 requires a writer whose output order is fixed by vigil's code: an explicit ordered representation or a serializer with a fixed field order, never `serde_json::Map`'s default. #64 builds that writer; #7 and #8 apply the table above on top of it.
- **The test** ([#60](https://github.com/vig-os/vigil/issues/60)): segments whose first records have a 700-byte metric description and a 2 KiB log body must first differ within 1000 bytes. It runs **with `serde_json/preserve_order` enabled** (as #64's determinism tests do), so feature unification cannot hide a regression.

### 4. The `push` feature: a tee of the same lines to a loopback OTLP/HTTP agent

ADR-0004 decision 7 names the feature `push` and makes it off by default. This decision supersedes ADR-0001 decision 9 for that feature only: **without `push`, vigil contains no network code** (unchanged).

- **Encoding and transport.** Each line that goes to a file, already bounded by ADR-0001 decision 10 and ordered by decision 3, is also POSTed **byte-for-byte** as an OTLP/HTTP request body with `Content-Type: application/json`. Logs go to `<endpoint>/v1/logs`, metrics to `/v1/metrics`, traces to `/v1/traces`; per-signal endpoints are used as given ([OTLP/HTTP](https://opentelemetry.io/docs/specs/otlp/#otlphttp)). A `LogsData`/`MetricsData`/`TracesData` line is exactly an `Export*ServiceRequest` body. So the pushed payload is the file payload; there is no second encoder, and file and push cannot diverge (Probe P: Collector and Alloy, equal by meaning). No compression on loopback.
- **Client.** `ureq` 3 with `default-features = false`, as `dep:ureq` behind `push`: +6 crates, no async runtime, no TLS (Probe D). One `vigil-push` thread per pipeline (one pipeline per process, ADR-0004 decision 2) drains a queue shared by all signals, reusing one keep-alive connection. vigil configures the agent explicitly:
  - no proxy (overriding `ureq`'s environment default);
  - `max_redirects = 0`, so an agent cannot redirect vigil off the host;
  - a global per-request timeout.
- **Tee order.** The exporter writes the line to the file first, then enqueues it without blocking (Probe P: worst append plus enqueue 6 ms against a down or hung agent). The line is enqueued even if the file write failed: it may then be the only copy. A failed file write follows [ADR-0003](0003-metrics-and-traces.md) decision 23, whether or not the push copy was delivered, because the durable copy is missing. A lost **log or span** line counts its records in `FlushError::lost(Signal::Logs)` or its spans in `lost(Signal::Traces)`. A lost **metrics** line sets the `FlushError` kind `Failed` and is reported on stderr in data points. It is **not** added to `lost(Signal::Metrics)`, because the next cumulative export carries the totals again.
- **Backpressure.** The queue is bounded in bytes (`Push::queue_bytes`, default 16 MiB, enough for 16 maximum-size lines). When full, the **oldest** queued line is dropped (the line the worker is currently sending or retrying is not in the queue and is not evicted; it keeps its own 60 s limit): the newest data matters most to a live feed, a newer cumulative point supersedes an older one, and the file keeps everything.
- **Retry,** per the OTLP/HTTP spec:
  - Connection errors, timeouts, and HTTP 429/502/503/504 are retried with exponential backoff (500 ms initial, ×2, 30 s cap, full jitter), honouring `Retry-After` up to the cap.
  - A line still undelivered 60 s after its first attempt is dropped.
  - Any other status is dropped at once (Probe P: 404, no retry).
  - A 200 with `partialSuccess` counts the rejected items as not delivered.
- **When the agent is down,** the head line retries, the queue fills, the oldest lines drop, and the application is not slowed (Probe P). When the agent returns, delivery resumes with whatever is queued. Nothing is replayed from the files.
- **Shutdown.** `Guard::shutdown`/`shutdown_with_timeout` first flushes the SDK into the files. Then the push worker gets the rest of the same budget, and every request's timeout is capped by what remains of it. At the deadline the remaining queue is dropped. `Drop` behaves the same with the default 5 s budget. If the SDK flush uses the whole budget (ADR-0003's meter shutdown can), push gets none, and the final export (for metrics, the last cumulative point) reaches only the file. Probe P: 18.9 s for a 2 s budget without the cap, 2.02 s with it.
- **Reporting.** Undelivered pushes are **not** lost data (the files have them), so they are not counted in `FlushError::lost`. vigil reports them on stderr through the runtime-loss rate limiter (ADR-0001 decision 10), once more at shutdown with the count, the endpoint and the state directory, and once per process for each distinct non-retryable status. Header values are never printed.
- **Storage fallback.** If storage fell back to stderr (`Guard::dir()` is `None`), push still runs, and the stderr warning says it is then the only copy.

### 5. Security: loopback, plain HTTP, optional headers

- **Endpoints must be loopback IP literals:** `http://` with a host in `127.0.0.0/8` or `[::1]`. Host names (including `localhost`) are refused, because the client would resolve them again on every connection and a resolver change could send data off the host. IPv4-mapped forms (`[::ffff:127.0.0.1]`) are refused too. This makes the check purely syntactic, so a bad endpoint in code is always a caller mistake. `https://` is refused. The default is `http://127.0.0.1:4318`, the OTLP/HTTP default port, an IP literal so no resolver is involved.
- **Remote shipping and TLS are the agent's job.** Alloy and the Collector both have TLS and auth to Loki and Prometheus.
- **Headers** (`Push::header`, `VIGIL_PUSH_HEADERS`) carry a token for an agent that wants one. `Debug` for `Push` redacts their values.
- **On a multi-user host** any local user can reach a loopback listener. Whether the agent accepts unauthenticated pushes is the agent's configuration; the headers let it require a token.
- **Known 1.0 limit: the peer is not authenticated.** Plain HTTP to a loopback port proves nothing about who listens there. While the agent is not running, any local user can bind `127.0.0.1:4318` (ports from 1024 up need no privilege) and receive every pushed line and every header, including an `authorization` token. That sidesteps the `0600`/`0700` permissions that protect the files (ADR-0002 decision 10). Mitigations for 1.0, all documented in `push`'s rustdoc and the README (#41):
  - On hosts where other users must not read the telemetry, use the file shipper, not `push`.
  - Run the agent on a privileged loopback port (below 1024): on Linux with the default `net.ipv4.ip_unprivileged_port_start = 1024`, an unprivileged user cannot take it over. It is no mitigation on macOS, which lets unprivileged processes bind low ports.
  - Treat a push header token as disclosed to local users: scope it to the local agent, never a backend credential.
- **Fix after 1.0: [#65](https://github.com/vig-os/vigil/issues/65).** It covers a Unix-socket transport whose filesystem permissions and peer credentials authenticate the agent, or TLS to a pinned certificate. Headers are then sent only over a verified transport. It is additive, a minor.

### 6. Public surface and configuration

All items are behind `#[cfg(feature = "push")]` and name only vigil and std types, so ADR-0004's allowlist is unchanged and the items are in the stable surface (ADR-0004 decision 1):

```rust
let guard = vigil::Config::new("flock")
    .push(vigil::Push::local())                            // VIGIL_PUSH_ENDPOINT, else http://127.0.0.1:4318
    // or vigil::Push::endpoint("http://127.0.0.1:4318")
    //        .header("authorization", "Bearer …")
    //        .timeout(Duration::from_secs(10))            // per request, default 10 s
    //        .queue_bytes(16 << 20)
    .init()?;
```

- **`Push`** is a struct with private fields, built with methods (ADR-0004 decision 5), and is `Debug + Clone + Send + Sync`. **`Config::push(Push)`** turns push on; nothing else does.
- **`InitErrorKind::InvalidPushEndpoint`** (new variant; the enum is `#[non_exhaustive]`) covers an endpoint given in code that is not a loopback `http://` URL or does not parse. It is a caller mistake (ADR-0004 decision 3).
- **Environment variables.** They use vigil's own `VIGIL_*` names (ADR-0004), not the `OTEL_EXPORTER_OTLP_*` ones, which a host may set for other programs (see Alternatives). They are read only when push is configured in code. An empty value counts as unset.
  - `VIGIL_PUSH_ENDPOINT`: the base URL. It is used only with `Push::local()`, which sets no endpoint of its own; an endpoint given with `Push::endpoint(..)` beats it, like every builder value. The signal paths are appended; there are no per-signal endpoints, because one local agent takes all signals.
  - `VIGIL_PUSH_HEADERS`: `key=value` pairs separated by commas, values percent-decoded (the OTLP exporter format). Added to builder headers; a builder header with the same name wins.
  - `VIGIL_PUSH_TIMEOUT_MS`: the per-request timeout in milliseconds. A builder `timeout` beats it.
  - `VIGIL_PUSH=off` disables push. It is the **one deliberate exception** to builder-beats-environment: an operator's kill switch only ever removes network traffic, and it is the documented way to keep push off on a file-shipper host (decision 1). Any other value is ignored with a warning.
  - An invalid environment value (an endpoint that is not a loopback IP literal, a bad header or a bad number) warns once on stderr and disables push. The environment degrades; it does not fail `init` (ADR-0004 decision 3).
- **The dependency test** (#41) stays offline. `tests/deps.rs` keeps its forbidden list, which `push` must not touch either (Probe D: it doesn't). It adds a check, from `Cargo.toml`, that `ureq` is `optional`, enabled only by `push`, and that `default` does not contain `push`, because `Cargo.lock` lists optional dependencies too.
- **Conformance** (#41): a CI leg runs the Collector's `otlp` receiver with a `file` exporter, pushes from `vigil::init`, and compares the pushed records with the files by meaning.

## Consequences

- **Two supported paths, one format.**
  - **Hosts with the Collector** get shipping from the files with no loss across backend outages that fit the queue (`queue_size`, sized per decision 2) and across clean restarts. Beyond that capacity, a clean stop while the queue is full loses up to 100 lines (one reader batch, each line up to 1 MiB; for logs up to 512 records) per signal. A crash re-sends records, up to the queue's contents, and backends absorb exact duplicates. Old records are subject to the backend's acceptance window (decision 1). The config, its sizing and its signals are documented and tested (#60).
  - **Hosts with Alloy** (the fleet) use `push` until Alloy can read OTLP files; push is live but loses data while the agent is down, and the files keep it.
  - The fleet rollout (#15) chooses per host and may land after 1.0.
- **A shipper bug now costs data silently.** F2/F4 and Probe K lost records with no error anywhere, and S1/S4/S6/Q1 lost them with only shipper log lines; #60's conformance test is what keeps the reference config honest. Hand-written configs that drop a rule above will lose or duplicate data, so the README states the rules, not just the YAML.
- **Key order is a contract.** Decision 3 binds the serializer: changing which keys come first is a format change under ADR-0001's versioning stance. Implementing it needs a writer whose order vigil's code fixes, independent of `serde_json` features (#64), with the table applied in #7 and #8, paid once for all signals.
- **The `push` feature costs** 6 crates and one thread per process, and only in builds that enable it. The default build stays network-free. Moving to a `ureq` 4 later is internal (no `ureq` type is public), so it is a vigil minor.
- **What push cannot do:** reach a remote collector, authenticate its peer, use TLS, or backfill. The peer limit (decision 5) is a documented 1.0 limit. The fix ([#65](https://github.com/vig-os/vigil/issues/65): a Unix socket, or a `push-tls` feature pulling `rustls`, +12 crates in Probe D) is additive, through a new ADR, so a vigil minor.
- **Upstream (owner's decision, nothing filed).** Two realistic options, both "report first":
  - **(a)** Comment on [grafana/alloy#6752](https://github.com/grafana/alloy/issues/6752) with this use case and Probe K/F evidence, asking for `otelcol.connector.otlpjson`. Alloy already has `filelog` and `storage.file`, and the probe shows that pipeline works.
  - **(b)** Open a feature request for `otelcol.receiver.otlpjsonfile` per Alloy's inclusion criteria; likely a community component at best, given alpha stability and a codeowner search.
  - If either lands, Alloy hosts can drop `push` for the file path; vigil changes only its docs.
- **Collector pin moves.** At 0.154 the receiver name changes; at 0.162 the `batch` race is fixed and that rule can be relaxed. #60 owns both.

## Alternatives considered

- **Keep ADR-0001 decision 9 (files only, no push).** Alloy hosts could then not ship metrics or traces at all until upstream adds a reader, which the owner rejected (owner decision of 2026-10-11, point 2).
- **`filelog` receiver alone.** It ingests each line as a log body: metrics and traces become log text (R8). With the `otlpjson` connector it works (probed), but that connector is not in Alloy, and the Collector's own `otlpjsonfile` is the simpler reference there.
- **Push replays from the files** (an in-process shipper with offsets). It would need shared offset state across every process writing a directory (ADR-0002's premise) and would duplicate the Collector's job. Rejected; completeness comes from the file shipper.
- **Push instead of files when enabled** (no tee). It would lose everything while the agent is down and contradicts the owner's "files remain the durable copy".
- **`opentelemetry-otlp`'s HTTP exporter.** 102 crates with tokio, hyper and reqwest (Probe D), a second encoder whose bytes can diverge from the file, and another 0.x crate pair to track. Rejected.
- **`reqwest` blocking.** 74 crates and a hidden tokio runtime. Rejected.
- **`minreq`.** It would add 1 crate instead of `ureq`'s 6, but `ureq` (224 M downloads, 3.4.2 on 2026-09-13; `minreq` 7 M, 3.0.0 on 2026-06-15) is the more widely used maintained client, with explicit proxy, redirect and global-timeout configuration, all of which decision 4 needs. Rejected narrowly.
- **A hand-written HTTP/1.1 client on `std::net`.** Zero crates, but chunked responses, keep-alive and `Retry-After` parsing become vigil's code to get right. Rejected.
- **Protobuf bodies** (`application/x-protobuf`, via `prost`). Smaller on the wire, but a second serialization path; loopback makes size irrelevant, and JSON is proven on both receivers (Probe P). Rejected.
- **Drop-newest when the queue is full.** Keeps the start of an outage window, which the files already hold, and loses the live tail. Rejected for drop-oldest.
- **TLS and remote endpoints in 1.0.** The owner's target is a local agent (one per host, ADR-029). TLS adds `rustls` and `ring` (+12 crates), trust-root policy (bundled or platform roots for private CAs) and certificate configuration surface, all of which the agent already has. Deferred to [#65](https://github.com/vig-os/vigil/issues/65); additive later (Consequences).
- **Unix domain sockets to the agent in 1.0.** They would authenticate the peer (decision 5's limit), but `ureq` has no built-in UDS transport and agent support was not probed. Deferred to [#65](https://github.com/vig-os/vigil/issues/65), not rejected.
- **A bigger `fingerprint_size` in the shipper config instead of decision 3.** The fingerprint is read from the head of every matched file on every poll, so making it cover a whole first line (up to 1 MiB) multiplies I/O across 90 days of segments. It also leaves every other `fileconsumer`-based shipper (Alloy's `filelog`, Fluent Bit) exposed. Fixing the cause in the writer is cheaper and covers them all.
- **A `*/` glob over the state root, filtered by a marker file vigil writes into each state directory.** The receiver cannot filter by a sibling file, so this would need a new vigil file format and still a per-host shipper step. Listing services is what deployments already know. Rejected.
- **The Collector's defaults for the exporter queue and retry.** They lose data (S1, S4, S6). Rejected for decision 2's settings.
- **`delete_after_read` or shipper-side truncation.** Deletes or truncates files that writers append to under ADR-0002's lock protocol. Rejected.
- **Push enabled by environment alone.** An endpoint variable set for some other program would silently turn on network traffic in every vigil binary on the host. Rejected; push is opted into in code, and the environment only tunes or disables it.
- **Reading the standard `OTEL_EXPORTER_OTLP_*` variables.** They are often set host-wide or per session for other programs, including to remote collectors. Under decision 5 a remote value would disable vigil's push, and a loopback value meant for a different program would quietly redirect it. They also carry per-signal endpoints that vigil does not need. Rejected for `VIGIL_PUSH_*`, which only vigil reads.
- **Allowing `localhost` and resolving it once at init.** That needs a pinned resolver in the HTTP client and turns a configuration value into an environment check. An IP literal says the same thing without either. Rejected.

## Notes for the owner: upstream bug report (draft, not filed)

The full-queue stop loss is the Collector's, and no 0.151.0 setting removes it. An existing upstream issue covers the mechanism: [contrib#47908](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/47908) (open, `Stale`), "fileconsumer: `readContents` silently drops tokens when `emitFunc` returns an error". A maintainer answered there that advancing the offset is intended, because retries belong to the exporter or to stanza's receiver-side `consumerretry`. Its fix PR, [contrib#47934](https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/47934), was closed. Our case is the one that answer does not cover: the error is the Collector's own shutdown cancelling a hand-off that the exporter's `block_on_overflow` is holding. Neither retry layer can help then, and `otlpjsonfile` has no `consumerretry` anyway. Suggested comment on #47908, if the owner wants one:

> **`context.Canceled` at shutdown loses one batch per reader, with every loss-preventing option enabled.** otelcol-contrib 0.151.0: `otlpjsonfile` (`file_storage`, `start_at: beginning`) → `otlp_http` with a persistent `sending_queue` (`block_on_overflow: true`), `retry_on_failure.max_elapsed_time: 0`. Make the backend unavailable until the queue is full, then send SIGTERM. The blocked `emitFunc` returns `context canceled` ("Rejecting data"), `reader.go:268-273`/`:289-293` advance `r.Offset`, and the checkpoint written at shutdown persists it. After a restart, exactly one 100-line batch per concurrently read file is missing (99/1500 with `max_concurrent_files: 2`, 3/3 runs; 215–298 with the default). Proposal: when `emitFunc` fails because the receiver's context was cancelled, keep the offset at the batch start (at-least-once; the next start re-reads the batch), or give `otlpjsonfile` the same `consumerretry` option `filelog` has. A persistent queue can then only produce duplicates, not loss.

Filing and wording are the owner's decision; nothing has been posted.

## References

- [vig-os/vigil#39](https://github.com/vig-os/vigil/issues/39), [#60](https://github.com/vig-os/vigil/issues/60), [#41](https://github.com/vig-os/vigil/issues/41), [#64](https://github.com/vig-os/vigil/issues/64), [#65](https://github.com/vig-os/vigil/issues/65), [#15](https://github.com/vig-os/vigil/issues/15), [#7](https://github.com/vig-os/vigil/issues/7), [#8](https://github.com/vig-os/vigil/issues/8)
- [ADR-0001](0001-on-disk-format.md) (format; decisions 5, 6, 8, 9, 10), [ADR-0002](0002-rotation-and-retention.md) (segment names, permissions, retention), ADR-0003 ([#38](https://github.com/vig-os/vigil/issues/38): `service.instance.id`, exporter seam), [ADR-0004](0004-public-api-and-stability.md) ([#37](https://github.com/vig-os/vigil/issues/37): stable surface, errors, feature table)
- [OTLP/HTTP](https://opentelemetry.io/docs/specs/otlp/#otlphttp) (paths, JSON encoding, retryable statuses, `Retry-After`, partial success); [OTLP exporter configuration](https://opentelemetry.io/docs/specs/otel/protocol/exporter/) (environment variables)
- Collector-contrib: [`otlpjsonfilereceiver`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/otlpjsonfilereceiver) (alpha), [`otlpjsonconnector`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/connector/otlpjsonconnector) (alpha), [#50314](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/50314) (count-after-consume race, fixed v0.162.0), [#47908](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/47908) (offset advances when the hand-off fails), [#45339](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/45339) (rename to `otlp_json_file`, v0.154.0)
- Grafana Alloy: [component inclusion criteria](https://github.com/grafana/alloy/blob/a753fee7a10311a332edd18a05567c3fcf9c0bba/docs/developer/add-otel-component.md), [OTel Engine builder config v1.20.1](https://github.com/grafana/alloy/blob/v1.20.1/collector/builder-config.yaml), [#6752](https://github.com/grafana/alloy/issues/6752), [#4262](https://github.com/grafana/alloy/issues/4262)
- [Loki OTLP ingestion](https://grafana.com/docs/loki/latest/send-data/otel/) (default index labels, `otlp_config`)
- [gerchowl/g-fleet#355](https://github.com/gerchowl/g-fleet/issues/355) (fleet logging scheme, shipping addendum)
