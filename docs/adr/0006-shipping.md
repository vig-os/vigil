# ADR-0006: Shipping: the Collector file shipper, an optional `push` feature, and the Alloy gap

- **Status:** Proposed
- **Date:** 2026-10-11
- **Supersedes:** [ADR-0001](0001-on-disk-format.md) decision 9 ("shipping stays outside the crate… no network exporter"). **Extends** ADR-0001 decision 5 with a JSON key order (decision 3 below).
- **Issues:** [#39](https://github.com/vig-os/vigil/issues/39) (this decision); implemented by [#60](https://github.com/vig-os/vigil/issues/60) (reference shipper config and conformance), [#7](https://github.com/vig-os/vigil/issues/7) and [#8](https://github.com/vig-os/vigil/issues/8) (key order), [#41](https://github.com/vig-os/vigil/issues/41) (`push`); fleet rollout [#15](https://github.com/vig-os/vigil/issues/15)

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

vigil writes `<signal>.jsonl` exactly as ADR-0001/0002 say, whatever is enabled. A deployment ships each signal by **one** of two paths:
- **(a) a file shipper** that reads the files (the reference is the Collector-contrib `otlpjsonfile` receiver, decision 2);
- **(b) the `push` feature** (decision 4), which sends the same lines to a local agent while they are written.

A host uses one path per signal, never both: both would deliver every record twice. The file is the durable copy: completeness (backfill after an outage, replay) is the file shipper's job; push is a live, best-effort feed.

### 2. The reference file shipper: Collector-contrib `otlpjsonfile`, configured for exactly once

The reference config (shipped and tested in [#60](https://github.com/vig-os/vigil/issues/60)) is this, and each setting is load-bearing:

```yaml
extensions:
  file_storage/vigil:
    directory: ${env:VIGIL_SHIPPER_STATE}   # persistent; holds the read offsets
    create_directory: true
receivers:
  otlpjsonfile/logs:                        # likewise /metrics and /traces
    include: ["${env:XDG_STATE_HOME}/*/logs.jsonl", "${env:XDG_STATE_HOME}/*/logs-*.jsonl"]
    start_at: beginning
    include_file_name: false
    storage: file_storage/vigil
exporters:
  otlp_http/loki:       { endpoint: http://loki.example:3100/otlp }            # → /otlp/v1/logs
  otlp_http/prometheus: { endpoint: http://prometheus.example:9090/api/v1/otlp } # → /api/v1/otlp/v1/metrics
  otlp_http/traces:     { endpoint: http://tempo.example:4318 }                # → /v1/traces
service:
  extensions: [file_storage/vigil]
  pipelines:
    logs:    { receivers: [otlpjsonfile/logs],    exporters: [otlp_http/loki] }
    metrics: { receivers: [otlpjsonfile/metrics], exporters: [otlp_http/prometheus] }
    traces:  { receivers: [otlpjsonfile/traces],  exporters: [otlp_http/traces] }
```

The full form passes `otelcol-contrib validate` (0.151.0). The rules:

- **`storage` is required.** Without it a restart re-sends everything (F1: 100 duplicates). With it: exactly once across restarts and across rotations while the Collector is down (F3, F5).
- **`start_at: beginning`.** With `end`, records written before the first start or during downtime are lost (F2: 100/150).
- **`include` matches the live file and its segments.** `<signal>.jsonl` and `<signal>-*.jsonl`, the names ADR-0002 decision 5 fixes. Matching only the live file loses whatever was unread when it rotated (F4: 82/150).
- **`include_file_name: false`.** Otherwise every record carries a `log.file.name` that changes on rotation (F3 vs default). Only the shipper's own diagnostics need it.
- **No `batch` processor below contrib 0.162.0.** The receiver's metrics and traces paths race with mutating consumers ([contrib#50314](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/50314)). vigil already batches, and the receiver forwards one line at a time.
- **Defaults that must not be lowered:** `fingerprint_size` (1000; decision 3 guarantees uniqueness within it) and `max_log_size` (1 MiB; ADR-0001 decision 10 keeps lines below it).
- **Never `delete_after_read`.** It would delete the live file while writers still append to it.
- **The receiver's name.** It follows the flake's Collector pin: `otlpjsonfile` up to 0.153, `otlp_json_file` from 0.154 (the old name stays as a deprecated alias). #60 switches the config and the conformance test in the PR that moves the pin past 0.154.
- **Permissions.** Files are `0600` in a `0700` directory (ADR-0002 decision 10), so the shipper runs **as the writing user** (for example a `systemd --user` unit) or as root. vigil does not loosen its permissions for a shipper.
- **Retention outlives shipping lag.** A segment pruned (default 90 days, ADR-0002 decision 2) before the shipper reads it is lost. That is the only loss mode left with this config.
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

Extends ADR-0001 decision 5, implemented for logs and metrics in [#7](https://github.com/vig-os/vigil/issues/7) (which generalizes the exporter seam over the three envelopes, ADR-0003 decision 2) and for traces in [#8](https://github.com/vig-os/vigil/issues/8). vigil writes object keys in a fixed order: the listed keys first, in the order given, then all other keys alphabetically.

| Object | Keys first |
|---|---|
| `ResourceLogs` / `ResourceMetrics` / `ResourceSpans` | `scopeLogs` / `scopeMetrics` / `scopeSpans` |
| `ScopeLogs` / `ScopeMetrics` / `ScopeSpans` | `logRecords` / `metrics` / `spans` |
| `LogRecord` | `observedTimeUnixNano`, `timeUnixNano` |
| `Metric` | its data field (`sum`, `gauge`, `histogram`, `exponentialHistogram`, `summary`) |
| `Sum`, `Gauge`, … | `dataPoints` |
| data point | `timeUnixNano` |
| `Span` | `spanId`, `endTimeUnixNano` |

- **What this guarantees:** every line has a per-line value (a timestamp, or for spans a span id that is exported exactly once) within its first 128 bytes. So the first lines of two files of one signal in one directory differ within the receiver's default 1000-byte fingerprint (Probe K: byte 97 instead of 1092; 150/150 instead of 3/150).
- **Within ADR-0001's promises:** JSON readers ignore key order, which the Collector's file and HTTP receivers confirm (Probe K). ADR-0001 already says field order is deterministic within a version and not promised across versions; this decision makes it part of the contract, because a shipper's correctness now depends on it.
- **The test** ([#60](https://github.com/vig-os/vigil/issues/60)): segments whose first records have a 700-byte metric description and a 2 KiB log body must first differ within 1000 bytes.

### 4. The `push` feature: a tee of the same lines to a loopback OTLP/HTTP agent

ADR-0004 decision 7 names the feature `push` and makes it off by default. This decision supersedes ADR-0001 decision 9 for that feature only: **without `push`, vigil contains no network code** (unchanged).

- **Encoding and transport.** Each line that goes to a file, already bounded by ADR-0001 decision 10 and ordered by decision 3, is also POSTed **byte-for-byte** as an OTLP/HTTP request body with `Content-Type: application/json`. Logs go to `<endpoint>/v1/logs`, metrics to `/v1/metrics`, traces to `/v1/traces`; per-signal endpoints are used as given ([OTLP/HTTP](https://opentelemetry.io/docs/specs/otlp/#otlphttp)). A `LogsData`/`MetricsData`/`TracesData` line is exactly an `Export*ServiceRequest` body. So the pushed payload is the file payload; there is no second encoder, and file and push cannot diverge (Probe P: Collector and Alloy, equal by meaning). No compression on loopback.
- **Client.** `ureq` 3 with `default-features = false`, as `dep:ureq` behind `push`: +6 crates, no async runtime, no TLS (Probe D). One `vigil-push` thread per `Guard` drains a queue shared by all signals, reusing one keep-alive connection. vigil configures the agent explicitly:
  - no proxy (overriding `ureq`'s environment default);
  - `max_redirects = 0`, so an agent cannot redirect vigil off the host;
  - a global per-request timeout.
- **Tee order.** The exporter writes the line to the file first, then enqueues it without blocking (Probe P: worst append plus enqueue 6 ms against a down or hung agent). The line is enqueued even if the file write failed: it may then be the only copy. It still counts in `ShutdownError::lost_records` (ADR-0004 decision 3), because the durable copy is missing.
- **Backpressure.** The queue is bounded in bytes (`Push::queue_bytes`, default 16 MiB, enough for 16 maximum-size lines). When full, the **oldest** queued line is dropped: the newest data matters most to a live feed, a newer cumulative point supersedes an older one, and the file keeps everything.
- **Retry,** per the OTLP/HTTP spec:
  - Connection errors, timeouts, and HTTP 429/502/503/504 are retried with exponential backoff (500 ms initial, ×2, 30 s cap, full jitter), honouring `Retry-After` up to the cap.
  - A line still undelivered 60 s after its first attempt is dropped.
  - Any other status is dropped at once (Probe P: 404, no retry).
  - A 200 with `partialSuccess` counts the rejected items as not delivered.
- **When the agent is down,** the head line retries, the queue fills, the oldest lines drop, and the application is not slowed (Probe P). When the agent returns, delivery resumes with whatever is queued. Nothing is replayed from the files.
- **Shutdown.** `Guard::shutdown`/`shutdown_with_timeout` first flushes the SDK into the files. Then the push worker gets the rest of the same budget, and every request's timeout is capped by what remains of it. At the deadline the remaining queue is dropped. `Drop` behaves the same with the default 5 s budget. Probe P: 18.9 s for a 2 s budget without the cap, 2.02 s with it.
- **Reporting.** Undelivered pushes are **not** lost records (the files have them), so they are not in `lost_records`. vigil reports them on stderr through the runtime-loss rate limiter (ADR-0001 decision 10), once more at shutdown with the count, the endpoint and the state directory, and once per process for each distinct non-retryable status. Header values are never printed.
- **Storage fallback.** If storage fell back to stderr (`Guard::dir()` is `None`), push still runs, and the stderr warning says it is then the only copy.

### 5. Security: loopback, plain HTTP, optional headers

- **Endpoints must be loopback:** `http://` with a host that is a loopback IP literal (`127.0.0.0/8`, `::1`) or `localhost` resolving only to loopback addresses at init. `https://` and any other host are refused. The default is `http://127.0.0.1:4318`, the OTLP/HTTP default port, an IP literal so no resolver is involved.
- **Remote shipping and TLS are the agent's job.** Alloy and the Collector both have TLS and auth to Loki and Prometheus.
- **Headers** (`Push::header`, `OTEL_EXPORTER_OTLP_HEADERS`) carry a token for an agent that wants one. `Debug` for `Push` redacts their values.
- **On a multi-user host** any local user can reach a loopback listener. Whether the agent accepts unauthenticated pushes is the agent's configuration; the headers let it require a token.

### 6. Public surface and configuration

All items are behind `#[cfg(feature = "push")]` and name only vigil and std types, so ADR-0004's allowlist is unchanged and the items are in the stable surface (ADR-0004 decision 1):

```rust
let guard = vigil::Config::new("flock")
    .push(vigil::Push::local())                            // http://127.0.0.1:4318
    // or vigil::Push::endpoint("http://127.0.0.1:4318")
    //        .header("authorization", "Bearer …")
    //        .timeout(Duration::from_secs(10))            // per request, default 10 s
    //        .queue_bytes(16 << 20)
    .init()?;
```

- **`Push`** is a struct with private fields, built with methods (ADR-0004 decision 5), and is `Debug + Clone + Send + Sync`. **`Config::push(Push)`** turns push on; nothing else does.
- **`InitErrorKind::InvalidPushEndpoint`** (new variant; the enum is `#[non_exhaustive]`) covers an endpoint given in code that is not a loopback `http://` URL or does not parse. It is a caller mistake (ADR-0004 decision 3).
- **Environment variables,** read only when push is configured, as defaults that builder values beat:
  - `OTEL_EXPORTER_OTLP_ENDPOINT` and `OTEL_EXPORTER_OTLP_{LOGS,METRICS,TRACES}_ENDPOINT`;
  - `OTEL_EXPORTER_OTLP_HEADERS` and `OTEL_EXPORTER_OTLP_TIMEOUT`;
  - `VIGIL_PUSH=off`, which disables push without a rebuild.
  - An empty value counts as unset. An invalid or non-loopback value from the environment warns once on stderr and disables push for that signal; the environment degrades, it does not fail `init` (ADR-0004 decision 3).
- **The dependency test** (#41) stays offline. `tests/deps.rs` keeps its forbidden list, which `push` must not touch either (Probe D: it doesn't). It adds a check, from `Cargo.toml`, that `ureq` is `optional`, enabled only by `push`, and that `default` does not contain `push`, because `Cargo.lock` lists optional dependencies too.
- **Conformance** (#41): a CI leg runs the Collector's `otlp` receiver with a `file` exporter, pushes from `vigil::init`, and compares the pushed records with the files by meaning.

## Consequences

- **Two supported paths, one format.**
  - **Hosts with the Collector** get exactly-once shipping from the files with a documented, tested config.
  - **Hosts with Alloy** (the fleet) use `push` until Alloy can read OTLP files; push is live but loses data while the agent is down, and the files keep it.
  - The fleet rollout (#15) chooses per host and may land after 1.0.
- **A shipper bug now costs data silently.** F2/F4 and Probe K lost records with no error anywhere; #60's conformance test is what keeps the reference config honest. Hand-written configs that drop a rule above will lose or duplicate data, so the README states the rules, not just the YAML.
- **Key order is a contract.** Decision 3 binds the serializer: changing which keys come first is a format change under ADR-0001's versioning stance. Implementing it needs ordered maps or a custom writer in place of `serde_json`'s sorted maps. That is a cost in #7, paid once for all signals.
- **The `push` feature costs** 6 crates and one thread per `Guard`, and only in builds that enable it. The default build stays network-free. Moving to a `ureq` 4 later is internal (no `ureq` type is public), so it is a vigil minor.
- **What push cannot do:** reach a remote collector, use TLS, or backfill. Adding TLS later is additive: a new feature (for example `push-tls`, pulling `rustls`; +12 crates in Probe D) and a builder method, through a new ADR, so a vigil minor.
- **Upstream (owner's decision, nothing filed).** Two realistic options, both "report first":
  - **(a)** Comment on [grafana/alloy#6752](https://github.com/grafana/alloy/issues/6752) with this use case and Probe K/F evidence, asking for `otelcol.connector.otlpjson`. Alloy already has `filelog` and `storage.file`, and the probe shows that pipeline works.
  - **(b)** Open a feature request for `otelcol.receiver.otlpjsonfile` per Alloy's inclusion criteria; likely a community component at best, given alpha stability and a codeowner search.
  - If either lands, Alloy hosts can drop `push` for the file path; vigil changes only its docs.
- **Collector pin moves.** At 0.154 the receiver name changes; at 0.162 the `batch` race is fixed and that rule can be relaxed. #60 owns both.

## Alternatives considered

- **Keep ADR-0001 decision 9 (files only, no push).** Alloy hosts could then not ship metrics or traces at all until upstream adds a reader, which the owner rejected (decision v2).
- **`filelog` receiver alone.** It ingests each line as a log body: metrics and traces become log text (R8). With the `otlpjson` connector it works (probed), but that connector is not in Alloy, and the Collector's own `otlpjsonfile` is the simpler reference there.
- **Push replays from the files** (an in-process shipper with offsets). It would need shared offset state across every process writing a directory (ADR-0002's premise) and would duplicate the Collector's job. Rejected; completeness comes from the file shipper.
- **Push instead of files when enabled** (no tee). It would lose everything while the agent is down and contradicts the owner's "files remain the durable copy".
- **`opentelemetry-otlp`'s HTTP exporter.** 102 crates with tokio, hyper and reqwest (Probe D), a second encoder whose bytes can diverge from the file, and another 0.x crate pair to track. Rejected.
- **`reqwest` blocking.** 74 crates and a hidden tokio runtime. Rejected.
- **`minreq`.** It would add 1 crate instead of `ureq`'s 6, but `ureq` (224 M downloads, 3.4.2 on 2026-09-13; `minreq` 7 M, 3.0.0 on 2026-06-15) is the more widely used maintained client, with explicit proxy, redirect and global-timeout configuration, all of which decision 4 needs. Rejected narrowly.
- **A hand-written HTTP/1.1 client on `std::net`.** Zero crates, but chunked responses, keep-alive and `Retry-After` parsing become vigil's code to get right. Rejected.
- **Protobuf bodies** (`application/x-protobuf`, via `prost`). Smaller on the wire, but a second serialization path; loopback makes size irrelevant, and JSON is proven on both receivers (Probe P). Rejected.
- **Drop-newest when the queue is full.** Keeps the start of an outage window, which the files already hold, and loses the live tail. Rejected for drop-oldest.
- **TLS and remote endpoints in 1.0.** The owner's target is a local agent (one per host, ADR-029). TLS adds `rustls` and `ring` (+12 crates), trust-root policy (bundled or platform roots for private CAs) and certificate configuration surface, all of which the agent already has. Rejected for 1.0; additive later (Consequences).
- **Unix domain sockets to the agent.** Not probed here, `ureq` has no built-in UDS transport, and the OTLP/HTTP default every agent ships with is TCP on port 4318. Rejected; a later ADR can add it if an agent needs it.
- **A bigger `fingerprint_size` in the shipper config instead of decision 3.** The fingerprint is read from the head of every matched file on every poll, so making it cover a whole first line (up to 1 MiB) multiplies I/O across 90 days of segments. It also leaves every other `fileconsumer`-based shipper (Alloy's `filelog`, Fluent Bit) exposed. Fixing the cause in the writer is cheaper and covers them all.
- **`delete_after_read` or shipper-side truncation.** Deletes or truncates files that writers append to under ADR-0002's lock protocol. Rejected.
- **Push enabled by environment alone.** `OTEL_EXPORTER_OTLP_ENDPOINT` set for some other program would silently turn on network traffic in every vigil binary on the host. Rejected; push is opted into in code, and the environment only tunes or disables it.

## References

- [vig-os/vigil#39](https://github.com/vig-os/vigil/issues/39), [#60](https://github.com/vig-os/vigil/issues/60), [#41](https://github.com/vig-os/vigil/issues/41), [#15](https://github.com/vig-os/vigil/issues/15), [#7](https://github.com/vig-os/vigil/issues/7), [#8](https://github.com/vig-os/vigil/issues/8)
- [ADR-0001](0001-on-disk-format.md) (format; decisions 5, 6, 8, 9, 10), [ADR-0002](0002-rotation-and-retention.md) (segment names, permissions, retention), ADR-0003 ([#38](https://github.com/vig-os/vigil/issues/38): `service.instance.id`, exporter seam), ADR-0004 ([#37](https://github.com/vig-os/vigil/issues/37): stable surface, errors, feature table)
- [OTLP/HTTP](https://opentelemetry.io/docs/specs/otlp/#otlphttp) (paths, JSON encoding, retryable statuses, `Retry-After`, partial success); [OTLP exporter configuration](https://opentelemetry.io/docs/specs/otel/protocol/exporter/) (environment variables)
- Collector-contrib: [`otlpjsonfilereceiver`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/otlpjsonfilereceiver) (alpha), [`otlpjsonconnector`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/connector/otlpjsonconnector) (alpha), [#50314](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/50314) (count-after-consume race, fixed v0.162.0), [#45339](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/45339) (rename to `otlp_json_file`, v0.154.0)
- Grafana Alloy: [component inclusion criteria](https://github.com/grafana/alloy/blob/a753fee7a10311a332edd18a05567c3fcf9c0bba/docs/developer/add-otel-component.md), [OTel Engine builder config v1.20.1](https://github.com/grafana/alloy/blob/v1.20.1/collector/builder-config.yaml), [#6752](https://github.com/grafana/alloy/issues/6752), [#4262](https://github.com/grafana/alloy/issues/4262)
- [Loki OTLP ingestion](https://grafana.com/docs/loki/latest/send-data/otel/) (default index labels, `otlp_config`)
- [gerchowl/g-fleet#355](https://github.com/gerchowl/g-fleet/issues/355) (fleet logging scheme, shipping addendum)
