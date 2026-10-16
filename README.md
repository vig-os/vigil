# vigil

*Verifiable Integrity-Guarded Instrumentation & Logging* (V·I·G·I·L): the opinionated observability crate for vig-os Rust projects.

> **Pre-alpha.** The design is settled; the code is being built. Logs, metrics, traces and the audit writer (behind the `audit` feature) are implemented; the audit operator commands are implemented; the audit verifier (#13 C1) and trace propagation (#8 8e) are being built. Track progress in the milestones.

**Pre-1.0 caveats.** Logs, metrics and traces export today, but open spans at
shutdown (#8 8d), propagation (#8 8e), and the tracer globals opt-in (#8 8f)
remain open. End root spans before shutdown. Review the [known issues](#known-issues)
before adopting an early release.

## Stability

Early GitHub releases start with v0.1.0; crates.io publication comes later and
remains the owner's decision. Before 1.0, a minor bump may break compatibility;
a patch never does. Applications should pin `~0.N` (or `=0.N.M`). Every breaking
change is labelled `semver:major` and recorded in the CHANGELOG. The stability
promise below applies from 1.0.0. Version changes are managed by the release train (#151).

- **Not covered.** Error `Display` and `Debug` text may change even in a patch,
  with a CHANGELOG entry. Programs must not parse it; see
  [ADR-0004 decision 3](docs/adr/0004-public-api-and-stability.md#3-errors-are-for-the-callers-mistakes-the-environment-degrades).
- **Semver.** The stable API is every public item built without `--cfg vigil_unstable`,
  with any combination of Cargo features, and it names only vigil's own types, `std`
  and the `tracing` family. OpenTelemetry types never appear in it, so an
  OpenTelemetry upgrade inside vigil is a minor release.
  Moving to `tracing` 0.2 or `tracing-subscriber` 0.4 would be a major. Removing a
  feature or changing the default features is a major. See
  [ADR-0004](docs/adr/0004-public-api-and-stability.md) decisions 1, 5 and 7. CI checks the committed public API snapshot and the ADR allowlist, including
  hidden items and macro expansions, alongside the semver gate ([Semver](#semver)).
- **`vigil_unstable` is excluded.** Items behind `--cfg vigil_unstable` (the exporters,
  sinks and the re-exported OpenTelemetry crates; global-provider installation (meter only; the tracer in #8)) may
  change in any minor release. Applications that set the cfg should pin `~1.N`
  ([ADR-0004](docs/adr/0004-public-api-and-stability.md) decision 4).
- **On-disk format.** Every line is valid OTLP/JSON, one signal per file, with the
  field encoding and time-first key order of
  [ADR-0001](docs/adr/0001-on-disk-format.md) and [ADR-0006](docs/adr/0006-shipping.md)
  decision 3. A breaking on-disk change, a renamed, removed or re-meant attribute
  (the semantic-convention pin and `schemaUrl` are planned in
  [#9](https://github.com/vig-os/vigil/issues/9); a purely additive pin move is a
  minor) and an OpenTelemetry upgrade that changes stable behaviour are each a major
  release. The file-exporter
  spec is still *Development*; how vigil absorbs its changes is in
  [ADR-0001, "Versioning stance at 1.0"](docs/adr/0001-on-disk-format.md#versioning-stance-at-10).
- **Audit format.** Separately frozen: every vigil 1.x release verifies every trail written by
  any vigil ≥ 1.0.0 (`audit.v` = `1`), and writes v1 by default
  ([ADR-0005](docs/adr/0005-audit-trail.md) decision 12). From 1.0 the `vigil::audit` items in
  [decision 13](docs/adr/0005-audit-trail.md#13-public-surface-feature-audit-under-adr-0004s-rules)
  are stable and the low-level format primitives behind `--cfg vigil_unstable` may change
  in any minor release; see [Audit format](#audit-format-opt-in).
- **MSRV.** Rust 1.95; raised only in a minor release, to a release at least six
  months old, with a changelog entry. See [Rust version policy](#rust-version-policy).
- **Platforms.** Linux and macOS (Unix targets only; rotation relies on `flock` and
  atomic no-replace rename, [ADR-0002](docs/adr/0002-rotation-and-retention.md)).
  CI builds and tests on Linux and checks `aarch64-apple-darwin` at the MSRV. A macOS
  CI lane that runs the tests arrives with
  [#46](https://github.com/vig-os/vigil/issues/46), so macOS is supported but not yet
  tested in CI.
- **Not covered.** The text of the `Console::Stderr` output (do not parse it; the file is
  the machine-readable output); the order of JSON keys after the time-first ones,
  whitespace and attribute order across versions; line order across processes and
  batches; the concrete types behind `Error::source()`; numeric defaults no code names
  (default histogram boundaries, span and cardinality limits, batch sizes), which may
  change in a minor release with a changelog entry; and copies of files that a shipper
  has rewritten.

## Known issues

- [#150](https://github.com/vig-os/vigil/issues/150): metrics close can block behind the directory lock.
- [#112](https://github.com/vig-os/vigil/issues/112): metrics shutdown has a five-second floor.
- [#13](https://github.com/vig-os/vigil/issues/13): no offline audit verifier yet; `open` and operator commands do not verify a trail.
- [#89](https://github.com/vig-os/vigil/issues/89): crash guarantees remain unproven.
- [#46](https://github.com/vig-os/vigil/issues/46): no macOS CI test lane yet.

## Traces

The default `traces` feature exports spans to `traces.jsonl` beside logs and
metrics. Set `VIGIL_TRACES=0` or `Config::traces(false)` to disable it completely;
`1` enables it and explicit builder values win. Unset or empty values enable
traces; other values warn and use the default.

Enter the span for correlation: log records emitted while it is entered carry
its trace and span IDs. An explicit event parent on an unentered span does not
activate correlation. Each event is written to logs once. Span events are not
recorded: ERROR events set span status to Error and increment
`droppedEventsCount`, while the exported events array stays empty.

Sampling is `ParentBased(AlwaysOn)`: local roots and sampled traces are recorded,
and an upstream W3C sample-out is respected. No global tracer or propagator is
installed by default. End root spans before shutting down the guard.

The special fields `otel.name`, `otel.kind`, `otel.status_code` and
`otel.status_description` override span name, kind and status. ERROR events and
`#[instrument(err)]` set Error status; a message-less error supplies its status
description, while an error with a message leaves that description empty.
Typed error span fields populate `exception.message` and `exception.stacktrace`.
Location, thread and target attributes are recorded; inactivity is not tracked.

`OTEL_*` environment variables have no effect on vigil configuration, including
sampler, span limits and batch settings. `OTEL_BSP_EXPORT_TIMEOUT` and
`OTEL_BSP_MAX_CONCURRENT_EXPORTS` do not apply to the synchronous processor.

## Metrics

`VIGIL_METRICS=0` disables metrics and `1` enables them (enabled by default).
Unset or empty values use the default; any other value warns and uses the default.
`Config::metrics(bool)` overrides the environment. These switches have the same
grammar as `VIGIL_TRACES` and `Config::traces(bool)` above.

`VIGIL_METRICS_INTERVAL` sets collection in whole seconds (default 60).
It accepts an unsigned 64-bit integer of at least 1, using Rust's integer parsing
(optional leading `+`, no whitespace). Unset or empty values use the default;
invalid, zero, negative or overflowing values warn and use 60 seconds.
`Config::metrics_interval(Duration)` overrides it and clamps durations below one
second to one second. These options require the `metrics` feature.

With the default `metrics` feature, declare instruments in statics using the
scope of their declaring crate:

```rust
# #[cfg(feature = "metrics")]
# fn main() {
use vigil::metrics::{Counter, CounterF64, Histogram, Gauge, UpDownCounter};
static REQUESTS: Counter = Counter::new(vigil::scope!(), "app.requests").with_unit("{request}").with_description("Handled requests");
static CPU: CounterF64 = CounterF64::new(vigil::scope!(), "process.cpu.time").with_unit("s");
static LATENCY: Histogram = Histogram::new(vigil::scope!(), "app.latency").with_unit("ms").with_boundaries(&[5.0, 10.0, 50.0]);
static INFLIGHT: UpDownCounter = UpDownCounter::new(vigil::scope!(), "app.inflight");
static MEMORY: Gauge = Gauge::new(vigil::scope!(), "app.memory").with_unit("By");

REQUESTS.add(1, &[("route", "/x".into())]);
LATENCY.record(12.5, &[("route", "/x".into())]);
# }
# #[cfg(not(feature = "metrics"))]
# fn main() {}
```

Names, units and histogram boundaries are validated at compile time in statics.
Instruments bind on their first record after initialization; earlier records
are dropped and counted, with one report when the pipeline starts. Metrics use
`metrics.jsonl` and are flushed and shut down with the guard.

Conflicting declarations poison every name involved: future records are dropped,
and exports remove all streams under those names. Conflicts include incompatible
kinds, units or histogram boundaries, spelling or description differences within
one scope, and overlapping Prometheus series names within a scope or between
incompatible pairs across scopes (ADR-0003 d21). Compatible
sharing across scopes requires Prometheus `otlp.promote_scope_metadata: true`;
vigil prints a reminder once per shared name.

Binding is lazy. A conflict that only some runs reach, for example on an error
path, removes the metric only in those runs, with a diagnostic on stderr.
Add a test that records every instrument once to surface all conflicts in CI.
`lost(Signal::Metrics)` counts records dropped after poisoning; measurements
aggregated before the conflict are excluded. Poisoning itself marks its reporting
period as `DataLost`, even when no later record is dropped.

### Prometheus

Prometheus maps OTLP metrics using its default translation (ADR-0003 d12):

| OTLP input | Prometheus output |
| --- | --- |
| Runs of characters other than ASCII letters, digits and `:`, including `.` and `_` | One `_` between name tokens; `:` is preserved |
| Unit | Fixed unit words and per-unit suffixes as detailed below; no repeated suffix token |
| Monotonic counter | `_total`; inner `total` words are dropped (`app.total.x` → `app_x_total`) |
| Gauge with unit `1` | Drop inner `ratio` words and append `_ratio` (`app.ratio.x` → `app_x_ratio`) |
| Name starting with a digit | Prefix `_` (`1x` → `_1x`; translator only, the facade rejects these names) |
| Up-down counter with unit `1` | No suffix (`app.x` → `app_x`) |
| Monotonic counter with unit `1` | `_total` only (`app.x` → `app_x_total`) |
| Histogram | `_bucket`, `_sum`, `_count` after the unit suffix |
| Resource `service.name` | `job` label |
| Resource `service.instance.id` | `instance` label |

The fixed numerator unit table is:
`d` → `days`, `h` → `hours`, `min` → `minutes`, `s` → `seconds`,
`ms` → `milliseconds`, `us` → `microseconds`, `ns` → `nanoseconds`,
`By` → `bytes`, `KiBy` → `kibibytes`, `MiBy` → `mebibytes`,
`GiBy` → `gibibytes`, `TiBy` → `tibibytes`, `KBy` → `kilobytes`,
`MBy` → `megabytes`, `GBy` → `gigabytes`, `TBy` → `terabytes`,
`m` → `meters`, `V` → `volts`, `A` → `amperes`, `J` → `joules`,
`W` → `watts`, `g` → `grams`, `Cel` → `celsius`, `Hz` → `hertz`,
and `%` → `percent`. Unit `1` contributes no unit word; the instrument-kind
rules in the table above apply (histograms still get their three suffixes).

Units split at the first `/`: the denominator contributes `_per_<unit>`, with
`s`, `m`, `h`, `d`, `w`, `mo`, `y` mapped to `second`, `minute`, `hour`,
`day`, `week`, `month`, `year`. Thus `By/s` becomes `_bytes_per_second`.
Empty unit parts and annotation parts containing `{` or `}` are dropped.
Unknown unit parts are kept verbatim after trimming whitespace and sanitizing:
characters other than ASCII letters, digits and `:` become `_`, repeated `_`
collapse, and a leading `_` is removed. Already-present suffix tokens are
not added again. Up-down counters and gauges have no `_total` suffix.

The authoritative [shared translation fixture](tests/fixtures/prometheus_names.json)
checks these rules against Prometheus 3.12.0 / otlptranslator v1.0.0 for all
148 accepted declarations; its additional facade-rejected row is translator-only.

Prometheus must be configured with `otlp.promote_scope_metadata: true`
(ADR-0003 d12). Start it with `--web.enable-otlp-receiver` and include:

```yaml
otlp:
  promote_scope_metadata: true
```

The scope is the declaring crate's package name and version (ADR-0004 d8).
This preserves `otel_scope_name` and `otel_scope_version` as labels, keeping
compatible metrics from different crates distinct. A crate's version is a label,
so a dependency upgrade starts new series; aggregate with
`sum without (otel_scope_version)`. Other Prometheus-compatible backends need
the equivalent setting. Collector configurations use the `otlp_http` exporter.

The [Prometheus conformance script](scripts/prometheus_conformance.py) is the
mapping oracle: it checks exact series sets and values through the Collector and
Prometheus against [the shared fixture](tests/fixtures/prometheus_names.json).
Rows the facade rejects (d24) are checked against the translator only; a Rust
test guards these exclusions so every accepted fixture name runs end to end.

## Unstable SDK access

Exporters and sinks are crate-private by default. Applications composing their
own SDK pipeline can opt in with `RUSTFLAGS="--cfg vigil_unstable" cargo build`,
or set `[build] rustflags = ["--cfg", "vigil_unstable"]` in their own
`.cargo/config.toml`. Use `vigil::unstable::{opentelemetry, opentelemetry_sdk}`
for the exact versions linked by vigil. These APIs may change in any minor;
applications should pin vigil with `~0.N` (or `=0.N.M`) before 1.0, and `~1.N` from 1.0. A library using them forces its
applications to enable the cfg, must document that requirement, and should avoid
pinning `~1.N` itself because that constrains every dependent in the graph.
Global-provider installation is available for the meter provider through
`Config::install_opentelemetry_globals` (requires `--cfg vigil_unstable`). The tracer
provider opt-in and the tracing integration re-export remain open in #8 8f.

Cargo uses one rustflags source, in precedence order: `CARGO_ENCODED_RUSTFLAGS`,
`RUSTFLAGS`, matching target rustflags (including `CARGO_TARGET_<TRIPLE>_RUSTFLAGS`),
then build rustflags. Earlier sources replace later ones: add the cfg to whichever
source the application already uses. Changing flags rebuilds dependencies once.
Docs.rs labels the unstable surface; CI compiles and tests it separately from
the stable [API snapshot and ADR allowlist](api/README.md) and semver gate.

## Rust version policy

The MSRV is Rust 1.95 (`Cargo.toml`), independent of the devkit pin. Raises
require a minor release and a changelog entry; the new stable Rust release must
be at least six months old on the vigil release date. Linux CI builds and tests
all features at the MSRV and checks `aarch64-apple-darwin` at the same version.
A second Linux lane builds and tests the latest stable (currently 1.99.0) through locked fenix, allowing warnings;
advance its independent manifest pin in `flake.nix` on each stable release. The macOS lane
([#46](https://github.com/vig-os/vigil/issues/46), not yet in CI) will use the dev pin. Today MSRV and dev pin are both 1.95.0; the MSRV lane adds the
Apple-target check and diverges as soon as devkit advances past 1.95.
See [ADR-0004 decision 11](docs/adr/0004-public-api-and-stability.md#11-msrv-policy).

## What it is

One crate, two layers:

- **Telemetry core** (every project). Your code uses [`tracing`](https://docs.rs/tracing) as usual; vigil bridges it into OpenTelemetry and writes **OTLP/JSON Lines** files that conform to the [OTel file-exporter spec](https://opentelemetry.io/docs/specs/otel/protocol/file-exporter/): one `LogsData` / `MetricsData` / `TracesData` per line, one signal per file, in the [OTLP/JSON encoding](https://opentelemetry.io/docs/specs/otlp/#json-protobuf-encoding) (64-bit ints as decimal strings, hex trace and span ids, integer enums, lowerCamelCase keys). Files rotate by size with age-based retention, and the rotation is safe when many processes write the same file. Loki (logs) and Prometheus (metrics) ingest OTLP natively.
- **`audit` feature** (opt-in). A separate, **lossless** audit trail of user actions on a device (who did what, when, and why) in the spirit of 21 CFR Part 11 §11.10(e). Records are still OTLP log records, hash-chained, committed by one Merkle mountain range (MMR) over the whole trail and covered by **ed25519-signed checkpoints**. The MMR is built the way [`tessera-core`](https://github.com/vig-os/tessera) builds its own (same leaves, nodes and roots), so tessera-core can check vigil's roots and proofs; vigil does not depend on tessera-core ([ADR-0005](docs/adr/0005-audit-trail.md) decisions 7 and 15).

```rust,no_run
let guard = vigil::Config::new("my-service")
    .version(env!("CARGO_PKG_VERSION"))
    .init()?;
tracing::info!(user = "alice", "opened study");
guard.shutdown()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Logs, metrics and traces are available now, and the audit writer behind the `audit` feature ([Audit format](#audit-format-opt-in)). Keep the guard
alive until shutdown to flush queued logs. `let _ = vigil::init(..)` drops it immediately. The batch queue holds 65,536 records by default (512 per export, every second).
Memory is bounded by queue size times record size; overflow drops records with
a stderr warning. `VIGIL_QUEUE_SIZE` or `Config::queue_size` changes the bound
(minimum 1, cap 1,048,576). Oversized environment and builder values clamp to
that cap with a warning. Measured memory is approximately 16 B per reserved
slot (16 MiB at the cap), plus approximately 0.4 KB per queued small record;
larger fields need more memory. Guard drop waits up to five seconds, including directory-lock waits,
then warns that remaining records may be lost; the SDK worker may continue
until the lock is released. `std::process::exit` skips flushing. Enter spans to populate OTLP trace/span IDs on log records.

Use `vigil::init("my-service")` for defaults. `RUST_LOG` defaults to `info`.
`VIGIL_DIR` selects the full state directory; otherwise vigil uses
`$XDG_STATE_HOME/<service>` or `$HOME/.local/state/<service>`.
Invalid numeric environment values emit a warning naming the variable and value
and use the default, except queue values above the cap clamp to the cap.
Empty `VIGIL_*` values are unset without warnings; relative `XDG_STATE_HOME`
and `HOME` are ignored, with rejected values explained if no path is available. `VIGIL_MAX_BYTES` has a minimum of 1 byte and defaults to 50 MiB and `VIGIL_RETENTION_DAYS` to 90
(`0` keeps everything). `Config::retention(Option<Duration>)` uses durations:
`None` keeps everything, while `Some(Duration::ZERO)` prunes rotated segments
at the next prune. Explicit `retention(None)` overrides the environment.
Explicit `Config` values override environment values.
`Config::revision` or `VIGIL_VCS_REVISION` supplies the producer commit.
Log storage initialization failures make logs fall back to stderr; metrics and traces
storage initialization failures disable their signal with its own warning.
A second initialization returns an error before creating storage. An existing
`log` logger is preserved: initialization succeeds with one warning that `log`
records cannot reach vigil; tracing events continue to be written.

Call `init` **after forking**. A child forked after initialization inherits the
parent's directory lock and subscriber but has no batch worker; it cannot safely
continue using that logging instance.

Log storage-open failures fall back to stderr; metrics and traces storage failures disable
their signal with its own warning. Runtime export failures drop the affected
records: the first error is reported on stderr, followed by cumulative dropped-record
summaries at most once per minute during failing exports and at shutdown if needed.
After the guard drops, events are discarded with one stderr warning.
`VIGIL_DIR` must be absolute; relative values warn and use the default resolution.
Empty `RUST_LOG` values count as unset, so the default is `info` (or the configured
`default_filter`). Invalid values warn and use the default.
`Config::filter_env("FLOCK_LOG").default_filter("flk=info,flock=info")`
selects another variable and default; an invalid default returns `InvalidFilter`.
`Config::console(Console::Stderr)` adds human-readable stderr with the same
filter and terminal-only ANSI. Its format may change; do not parse it.
`Config::layer` composes into your own `tracing_subscriber::registry()` with
per-layer filters, so your other layers keep their own filtering.
See `examples/flock.rs`. `Guard::dir()` gives the actual directory, or `None`
when logs fell back to stderr; metrics and traces may still write `metrics.jsonl` and `traces.jsonl`.
One successful `init` or `layer` permanently occupies
the process slot; later attempts return `AlreadyRunning`, even after shutdown.
A previously set global or scoped default subscriber returns `ForeignSubscriber`,
even after the scope ends; compose a layer
into that subscriber's Registry instead. Failed attempts release the slot.

Each pipeline generates a random UUID v4 `service.instance.id`, shared by all
its resource records. It is not configurable; concurrent producers get distinct
identities. If OS randomness is unavailable, initialization falls back to stderr
with a warning naming the instance identity generation failure. The synchronous log processor
explicitly sets its queue size, batch size and delay; `OTEL_BLRP_*` variables do
not configure vigil.

`Guard::flush()` exports queued logs and spans and collects and exports metrics with a
five-second timeout; `shutdown()`
uses the same timeout and `shutdown_with_timeout(Duration)` accepts another.
A blocked metrics export can hold shutdown for the SDK reader's fixed five seconds
even with a shorter timeout, returning metrics `Timeout` (ADR-0003 decision 4;
[shorter-wait follow-up #112](https://github.com/vig-os/vigil/issues/112)).
They return
`FlushError` with `Timeout`, `Failed` or `DataLost` (in that precedence order).
`lost(Signal::Logs)` counts failed exports, diagnostic replacements and queue
overflow since the previous flush or startup, without counting them again at
shutdown. Overflow counting works on every flush, independently of SDK diagnostics
and consumer filters. Counts are exact with quiescent producers and a successful
drain; concurrent arrivals can reduce the overflow lower bound, and timed-out or
failed drains do not count records still queued or in flight. Concurrent records
during shutdown may arrive after its watermark/counter or worker has stopped.
More than 64 concurrent flush requests can fill the logs SDK control channel
and return
`Failed`. If creating the shutdown thread fails, shutdown runs inline.
A failed durable log line counts its records even if another copy was delivered;
records on earlier successful lines are excluded. Records emitted after shutdown
begins are rejected with one warning and are not counted. Logs falling back to
stderr contribute no error; metrics and traces still report their outcomes. Explicit shutdown
makes Drop a no-op and returns countable losses without
printing them again; Drop reports only losses not yet printed on stderr, naming the actual outcome.

## Testing consumers

With `cargo nextest run`, each process initializes, records, shuts down and
reads its files. The process slot and scoped-default restrictions above apply:

```rust,no_run
let dir = std::env::temp_dir().join(format!("vigil-test-{}", std::process::id()));
let guard = vigil::Config::new("tests").dir(&dir).init()?;
tracing::info!(test_case = "my_unique_test", "record under test");
guard.shutdown()?;
let lines = vigil::rotate::read_since(&dir, "logs", None)?;
assert!(lines.iter().any(|line| line.contains("my_unique_test")));
# Ok::<(), Box<dyn std::error::Error>>(())
```

Under `cargo test`, keep one shared pipeline per test binary instead.
A static guard never drops, so each test calls `flush` and selects only
records with a field unique to that test. No test calls shutdown:

```rust,no_run
use std::sync::LazyLock;
static GUARD: LazyLock<vigil::Guard> = LazyLock::new(|| {
    vigil::Config::new("tests")
        .dir(std::env::temp_dir().join(format!("vigil-tests-{}", std::process::id())))
        .init().expect("test pipeline")
});
let guard = &*GUARD;
tracing::info!(test_case = "my_unique_test", "record under test");
guard.flush()?;
let lines = vigil::rotate::read_since(guard.dir().expect("test storage"), "logs", None)?;
assert!(lines.iter().any(|line| line.contains("my_unique_test")));
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Why not an existing crate

`tracing`, `opentelemetry` and `opentelemetry-proto` are the foundation and are used as-is. What's missing upstream: opentelemetry-rust has **no OTLP file exporter**, and every rotating-file crate (`file-rotate`, `logroller`, `log2`, `flexi_logger`, …) is thread-safe but not **multi-process** safe.

## Design

Decisions and their evidence are recorded as ADRs in [`docs/adr/`](docs/adr/): [0001 on-disk format](docs/adr/0001-on-disk-format.md) and [0002 multi-process rotation and retention](docs/adr/0002-rotation-and-retention.md).

## Development

Enter the pinned environment with `direnv allow` (or `nix develop`). `nix flake check` runs fmt, clippy, tests, doctests and docs. Changes enter through PRs to `dev`; `main` only takes release PRs.

### Supply chain

CI runs `nix develop -c python3 scripts/check_supply_chain.py` with cargo-deny
0.19.x from flake-pinned nixpkgs. It checks the locked all-features graph,
including dev dependencies: vulnerabilities and unmaintained crates fail;
yanked releases warn for review because yanks can be packaging-only. Only
crates.io sources and the commented Apache-2.0-compatible license allow-list in
`deny.toml` are accepted. OpenTelemetry crates cannot span semver compatibility
lines (including distinct 0.x minors); other duplicates warn, with exact reviewed
skips recorded in `deny.toml`.

`nix flake check` includes only the offline cargo-deny subset: bans, licenses
and sources. The CI extension and `.github/workflows/supply-chain.yml` run the
full gate, including advisories and the OpenTelemetry compatibility rule.
The consumer-owned workflow checks `dev` weekly (Monday 06:23 UTC) and supports
manual dispatch. Failures remain visible as red Actions runs; maintainers should
subscribe to workflow failure notifications. Neither scheduled runs nor manual
`workflow_dispatch` runs work until this workflow file reaches the default branch,
`main`, in the 1.0 release ([GitHub trigger requirements](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)).
PR CI is the supply-chain gate until then. Once enabled, both triggers check `dev`.

The gate explicitly fetches RustSec and registry data, then checks with
`--disable-fetch`. The wrapper enforces a seven-day limit on the actual DB HEAD
commit date because cargo-deny 0.19.6 does not reliably enforce its staleness option. A fetch error
fails the gate while the other checks still run. The offline subset and advisory
checks run separately so a missing or corrupt DB cannot hide license or source findings. If cargo-deny silently retains
a cache during an offline fetch, the freshness check rejects a DB whose HEAD
commit is older than seven days; a recent cached DB can still pass. A quiet DB
with no commits for seven days also fails and needs maintainer investigation.
To refresh manually, run `nix develop -c cargo deny fetch` and rerun the full gate.
Review license terms and notice requirements before changing `[licenses].allow`,
justify each addition in a comment, and rerun the gate. Review and remove duplicate
skips as dependencies converge; no vulnerability exceptions are currently allowed.

### Changelog updates

Add entries under the existing `## Unreleased` heading. Fixes to features that
have never shipped belong in their `Added` entry. `.gitattributes` uses Git's
built-in union driver to retain concurrent additions; review the merged result
for ordering, duplicate entries and contradictory edits. Union merging joins
text and does not validate the changelog's meaning or structure.

Release sync uses `git merge-tree`, which honors union: a clean merge can still
retain both a release's `TBD` heading and its dated heading. The
`scripts/check_changelog.py` check rejects duplicate version headings (regardless
of date), duplicate Unreleased headings, repeated `###` section headings within
a version, and duplicate top-level list entries. List entries must be unindented;
indented sub-bullets are ignored so different parents may repeat explanatory
text. Unordered markers (`-`, `*`, `+`) and numbered markers (`1.`, `1)`, etc.)
are ignored when comparing entry text. Entries are deduplicated across the whole
version per section kind, including repeated sections and deeper headings;
the same text is allowed in different versions or kinds (such as Added and Fixed). It runs on every local commit and in `nix flake check` (and
therefore CI). Resolve reported duplicates before accepting a release-sync PR;
a conflict-free merge alone is insufficient. Run
`python3 scripts/check_changelog.py` to check a resolution locally. The check
ignores fenced examples and permits repeated bullet text in different sections;
editorial review is still needed for contradictory entries with different text.

GitHub's server-side **Update branch** does not honor this merge rule (see the
[GitHub support discussion](https://github.com/orgs/community/discussions/9288)).
Update locally with `git fetch origin` and `git rebase origin/dev`, review
`CHANGELOG.md`, then push the feature branch with `git push --force-with-lease`
if rebasing rewrote published commits. No custom driver configuration is needed.
The root `.gitattributes` is consumer-owned: devkit 1.18.0 ships no such template
path and its scaffold does not delete consumer files.
[Changelog fragments are requested upstream](https://github.com/vig-os/devkit/issues/1858)
to avoid shared-file edits during parallel work.

## License

Apache-2.0.

## Conformance

Run `nix develop -c python3 scripts/conformance.py` locally. The dev shell pins
Collector-contrib through `flake.lock` and prints its version. On every PR, the
Collector reads rich, rotated logs from `examples/conformance.rs`, skips empty
and garbage lines, and exports JSON for a multiset comparison with the manifest.
The comparison checks complete resources, scopes and records, including nested
attributes, bodies, severity, timestamps and trace/span IDs across two resources,
allowing protobuf
default omission and integer spelling changes. Valid unterminated final records
are delivered; unterminated garbage is dropped. Metrics include non-finite values,
line splitting and poisoned-name filtering. Run
`nix develop -c python3 scripts/prometheus_conformance.py` for the
[Prometheus oracle](scripts/prometheus_conformance.py), including cross-scope
sharing, collision poisoning and every valid shared translation fixture row.
Spans from the unstable span exporter make the same round trip through the Collector;
the `init` traces bridge exports to `traces.jsonl`.

## Semver

Before the first publish, CI compares the stable API against the full SHA of
its merge base with `origin/dev`, using `cargo-semver-checks --release-type minor`
even while both versions are 0.0.0. It fails if no checks run. All Cargo features
are checked with `vigil_unstable` off; unstable items have no semver protection.
Run locally with `git fetch origin` followed by
`nix develop -c python3 scripts/check_semver.py`.
The gate refuses to compare when the merge base equals HEAD, including a
workflow dispatch on `dev` or a release PR from `dev` to `main`; run it on a
feature PR into `dev`. Self-comparison cannot prove compatibility.
CI also checks the committed [API snapshot and ADR allowlist](api/README.md),
including hidden exports, without any exception.
See [ADR-0004](docs/adr/0004-public-api-and-stability.md) for the stability policy
and the `semver:major` exception before publication. Only the architect/owner
applies that label after reviewing every major finding and its ADR justification
in the PR body. The job runs the same minor-release check, lists every major
finding in its summary, and accepts them only with the label on a pre-publish
version exactly `0.0.0`. Zero checks, tool failures and missing labels still fail.
The gate reads current labels through the GitHub API after the heavy CI lanes,
and verifies that the most recent `semver:major` application was by an account
with current admin or maintain permission. API failures fail closed. Adding or
removing the label automatically reevaluates semver and CI Summary without
rebuilding the heavy lanes; that summary requires successful full-run evidence
for the same PR head. A pending or failed full run cannot become green through
a label change. Label changes cancel superseded CI runs; if heavy jobs were
unfinished, rerun full CI to supply the required evidence. Reruns read live state, so an old payload cannot retain approval.

## Audit format (opt-in)

The `audit` feature is the durable audit writer of [ADR-0005](docs/adr/0005-audit-trail.md):
`AuditConfig` (`create`, `open`, `rotate`, `checkpoint`, `resume`), the `AuditTrail`
handle (`record`, `checkpoint`, `close`), `Entry`, `Receipt`, `Checkpoint`, the `Signer`
trait, `KeyFileSigner` and `keygen`. Every call fails closed: an `Err` means the audited
action must not complete ([decision 1][d1]). This section is written so that an operator
of a regulated deployment can set up, run, rotate, resume and review a trail without
reading the ADR; each subsection names the ADR section it restates, and the ADR decides
where the two differ.

The `vigil-audit` operator commands are available with the `audit` feature. The
verifier remains [#13 C1](https://github.com/vig-os/vigil/issues/13). The procedures below use the library
calls that exist, and every step that needs the verifier, a waiver or an accept line is
marked "(#13)". The low-level primitives (`Record`, `Record::parse_line`, `Mmr`,
`checkpoint_message`, `verify_signature`) are public only under `--cfg vigil_unstable`
and crate-visible otherwise ([decision 13][d13]). They persist nothing and establish no
trust.

### Operator command line

Build with `cargo build --features audit --bin vigil-audit`. Run `vigil-audit --help`
for commands and exit codes, or `vigil-audit <command> --help` for command help. Arguments use the
following synopsis (`verify` follows in #13 C1):

```text
vigil-audit keygen <keyfile>
vigil-audit create --key <keyfile> --service <name> <dir>
vigil-audit checkpoints <dir>
vigil-audit checkpoint --key <keyfile> --expect-head <seq>:<hash> <dir>
vigil-audit rotate --key <keyfile> --actor <who> --reason <why> --bound <seq>:<hash> --expect-head <seq>:<hash> <dir>
vigil-audit resume --key <keyfile> --actor <who> --reason <why> --head <seq>:<hash> --lost-through <seq> <dir>
```

Hashes are `blake3:` followed by 64 lowercase hex digits. Keep expected heads
outside the trail directory; use the highest sequence among all held receipts and
close checkpoints. `resume` instead takes the head found after loss, plus the
highest sequence for which the deployment holds evidence.

`keygen` writes the secret file and its `.pub` companion, and prints the public
key. `create` prints the 32-hex trail id and its close checkpoint. `checkpoints`
prints parseable checkpoint JSON lines in segment order, including the live file;
it checks neither signatures nor chain history and ignores unparsable lines.
`checkpoint` prints its receipt and checkpoint; `rotate` prints its rotation
receipt and checkpoint. `resume` prints its opening checkpoint, resume receipt
and close checkpoint, in sequence order. Receipts are `<seq> blake3:<hex>`;
checkpoint lines preserve the on-disk JSON payload.

`create` uses `--service`; records from `rotate`, `checkpoint` and `resume` use
`service.name = "vigil-audit"`. `--actor` names the human. `create` and `resume`
explicitly close the handle before exit, so the printed close checkpoint is the
clean-stop head. Successful outputs remain available if a later close fails.
Exit codes are 0 for success, 2 for usage, `Io` or `InvalidConfig`, and 1 for other
audit errors and signer errors. If stdout fails, successful output lines are
repeated on stderr and the exit code is 2 (architect ruling 13-d3, clarified by
13C2-d1).

### Supported filesystems and durability

Restates [decision 6][d6]. `AuditTrail::record` returns a `Receipt` only after
`fdatasync` (Linux) or `F_FULLFSYNC` (macOS) has returned. That promise needs two things
that vigil cannot check:

- **Storage that honours flushes.** The disk, its controller and any hypervisor must pass
  a flush through to stable storage. A volatile write cache without power-loss protection,
  or a VM disk that ignores flushes (for example QEMU `cache=unsafe`), voids the promise
  without any error vigil could see.
- **A filesystem that never shows stale or zero-filled bytes after a crash**, so that a
  torn write is a byte prefix of its line. ext4 in its default `data=ordered` mode and
  APFS are the *candidates*, supported for regulated use "each once a crash test shows
  the prefix property". **Today neither is established:** that needs crash and power-loss
  tests on each (#89 and #46). ext4 `data=writeback` and network filesystems are
  unsupported; XFS, btrfs and ZFS document no guarantee; any other filesystem is
  unsupported until such a test passes on it.

On a filesystem that breaks the assumption, a crash leaves an `Unparsable` line. The
writer then refuses with `CorruptTrail`, and the only way to continue is `resume`.

### Trail directory and trail id

Restates [decision 8, "Creating a trail"][d8]. The trail lives in `<state dir>/audit/`
(`$XDG_STATE_HOME/<service>/audit`); `AuditConfig::dir` overrides it. It has its own
directory lock, and vigil never deletes or rewrites a file in it.

`AuditConfig::create` is explicit and runs once. It draws the **trail id** (16 random
bytes from `getrandom`, never derived from the directory, the key or the clock) and writes
the marker `audit.trail`: 32 lowercase hex characters and one LF, mode `0400`. The id is
available as `AuditTrail::trail()`. `create` fails with `TrailExists` if the marker or any
audit file exists. `open` never creates a trail: with no marker it fails with
`MissingTrail`, so a deleted or emptied directory stops the application instead of
starting a new trail.

Pin the id in the verifier's trust file, which is kept outside the trail directory; the
marker lives in the writable directory and is never a trust input. A trail re-created
after deletion has a new id, even with the same key, and fails verification
(`TrailMismatch`) until an operator pins the new id on purpose. If `create` fails after
writing the marker but before completing staging, `open` reports `CorruptTrail` and
`create` reports `TrailExists`: no record was acknowledged, so remove the directory, run
`create` again and pin the newly drawn id. If it fails after its final renames, the
trail is complete but `audit.poison` exists and `open` reports `Poisoned`; take the id
from the marker, or remove the directory and run `create` again, and pin the id you
keep (see the `audit.poison` procedure below).

### Key custody

Restates [decision 9][d9] and amendment 7. These are the rules, as the ADR and the
rustdoc of `KeyFileSigner` and `keygen` state them:

- `vigil::audit::keygen(path)` writes the seed (`0600`, 64 hex characters) and
  `<path>.pub`, and never overwrites an existing file. `KeyFileSigner::load` refuses a
  file with group or other permission bits and one owned by another user.
- **Use the secret seed file, never the public key or `.pub` file.** Both are 32 bytes in
  64 hex characters, so a public key given as a seed silently derives a different signing
  key. Compare `Signer::public_key()` with the trusted key id before use.
- **Use separate keys for vigil and tessera.** Domain separation already stops a signature
  crossing over; separate keys also keep one tool's compromise from forcing the other's
  revocation.
- A key held on the machine protects against accidental corruption and against anyone who
  cannot read it. It does not protect against an attacker who can read the key and write
  the trail: they can rewrite everything and sign it again. For regulated use, prefer a
  `Signer` that keeps the key out of the process (reference backends are
  [#58](https://github.com/vig-os/vigil/issues/58)), and keep receipts and anchors outside
  the trail directory.
- **Keys that must be revoked independently must be different keys.** Use one key per
  trail when you keep one trust file per trail (next subsection).
- The signer runs inside the directory lock, so a slow signer slows every writer of the
  trail.

### Trust file layout and the one-file rule

Restates [decision 9, "Trust file format"][d9]. The verifier that reads the file is
[#13](https://github.com/vig-os/vigil/issues/13); the layout is fixed now so that keys and
bounds can be recorded as they change. UTF-8 lines; blank lines and lines starting with
`#` are ignored:

```text
trail <32 hex> [end=<seq>:<blake3:hex>] [comment]
ed25519 <64 hex> [through=<seq>:<blake3:hex>] [comment]
```

A `trail` line starts a section and pins that trail id; a trail id may start only one
section. An `ed25519` line lists a key trusted for the trail of the section it is in, at
most once per section; a key line before the first `trail` line is a parse error.
`through=` revokes a key at a checkpoint the operator has verified as good. `end=` retires
a trail: it must end exactly at that record. Take both values from the application's
receipts and close checkpoints or from an anchor, never from a read of the trail
directory. Keep the file outside the trail directory, for example in a reviewed
repository.

- **A key revoked on one trail is revoked on every trail that lists it.** A key with
  `through=` in one section and none in another is a parse error. Bounds do not combine
  across trails, so revoking a shared key means running the rotation procedure on every
  trail that lists it and is still written to; a retired trail gets `end=` at its last
  record and the key's bound at the same record.
- **Every trail a key signs for belongs in one trust file.** The verifier sees only the
  file it is given, so a key revoked in one file and still trusted in another is not
  caught. A deployment that keeps one file per trail must use one key per trail.

### Receipts and the expected head

Restates [decision 5, "Receipt reconciliation"][d5] and [decision 9, step 1][d9].

- **Store every receipt.** Keep the `Receipt` of each `record` (and of `rotate` and
  `resume`, whose records need receipts too) with the application's own record, outside
  the trail directory, before the audited action completes. The receipts file is one
  `<seq> <blake3:hex>` line per record (`Receipt::hash_string` spells the hash); no action
  name is exempt, so a forged `vigil.audit.*` record is `NoReceipt` like any other.
- **Store every `close` and `resume` checkpoint.** `AuditTrail::close` consumes the
  handle and returns the `Checkpoint` it signed; `resume` returns its signed opening
  `Checkpoint`. Keep each checkpoint's `line` with the receipts. A `Drop` checkpoint
  is not returned and cannot serve.
- **The expected head** after every writer has stopped is the highest `seq` among all
  receipts and close checkpoints the application holds, across all its processes. After a
  `resume` nothing changes: every `seq` the resumed trail writes lies above `lost_through`.
- **It comes from receipts or anchors, never from the disk.** An attacker who can write
  the files chooses what the disk says. `AuditConfig::expect_head(seq, hash)` makes `open`
  fail with `HeadMismatch` unless the trail holds that record, linked by an unbroken chain
  to the head. It proves only that this record, and the records present back to the first
  present one, are unchanged; it proves nothing below the first present record, and is
  invalid on `create`. If the expected `seq` lies in an archived segment, `open` fails
  with `HeadMismatch` rather than skip the check. `open` is a structural check, not a
  verifier.

### Operator rotation and checkpoint

Restates [decision 9, "The rotation procedure"][d9] and amendment 8. For any number of
writer processes:

1. **Stop every process writing the trail** and `close` each handle: no old-key writer
   may run after the bound. Store the close checkpoints. A writer that returned no close
   checkpoint (killed, dropped, `close` failed, or a poisoned handle) may have left
   records above everything held: start the application once more with `expect_head`
   from the highest held receipt or checkpoint and `close` that handle.
2. **Verify the trail (#13)** against the anchors and the receipts, including the close
   checkpoints, and never with live-trail reconciliation. A record that a `close` signed
   but the application never stored is `NoReceipt` here, before the new key covers it; a
   crash orphan is waived here after review (the waive step is #13). Choose the bound,
   the last checkpoint known good: after a clean stop, the final close checkpoint; after
   a suspected compromise, the last checkpoint that matches an anchor.
3. **Generate the new key** with `keygen`, deploy it to every writer and remove the old
   key file.
4. **In the trust file,** add the new key and set `through=<seq>:<hash>` on the old one.
5. **Confirm the rotation** with `AuditConfig::rotate(new_signer, bound, expect_head,
   actor, reason)`, where `bound` and `expect_head` are `(seq, hash)` pairs and the call
   returns `(Receipt, Checkpoint)`. `rotate` refuses with `HeadMismatch` unless the trail's
   head on disk is exactly `expect_head`, so records appended between steps 2 and 5 are
   never covered by the new key. The bound must be a checkpoint with exactly that hash
   whose segment is still present (restore an archived one first). A bound above the
   expected head, a new key equal to the bound's key, or the builder's own `expect_head`
   is `InvalidConfig`; the reason is required. Store the receipt and anchor the
   checkpoint's `line`. `AuditConfig::checkpoint(signer, expect_head)` writes an operator
   checkpoint under the same exact-head rule. If a `rotate` returned `Io` or never
   returned, follow the crash outcomes in the rustdoc of `AuditConfig::rotate` before
   signing anything.
6. **Start the writers** with the new key.

After a clean stop the trail then verifies with no error. After a compromise, every
old-key checkpoint above the bound stays `UntrustedKey` for good: those are the
checkpoints an auditor must look at, and the report shows them next to the
`vigil.audit.key_rotated` record.

### Operator resume

Restates [decision 8, "An operator decides"][d8], [amendment 9, part 2][a9] and
[decision 6][d6]. `resume` is for structural loss only: `open` refuses with `CorruptTrail`
(a live file that is missing, empty or without its opening checkpoint) or with
`HeadMismatch` (a rollback). vigil never guesses which case is innocent, and an honest
crash never needs `resume`. An operator decides, with
`AuditConfig::resume(signer, head, lost_through, actor, reason)`, which returns the
`AuditTrail`, the `Receipt` of its `vigil.audit.resume` record and the signed opening
`Checkpoint`. The builder's
`expect_head` is `InvalidConfig` here.

- **The live file's state decides what is sealed.** A *headless* live file (present, but
  its first complete record is no linking checkpoint), an *empty* one, and a well-formed
  one whose head is behind what the deployment holds (a *rolled-back* file) are sealed
  unchanged under the next segment name and keep their `SegmentStructure` findings for
  good. A *deleted* live file needs no sealing.
- **The head (R2'').** `head` is the predecessor's head: exactly the sequence and hash of
  the last complete record found, or `(0, genesis digest)` only when no predecessor
  record exists. Anything else is `HeadMismatch`.
- **`lost_through`** is "the highest `seq` the deployment holds any evidence of outside
  the trail directory": the receipts and close checkpoints of every process, anchors and
  revocation pins. It is at least the head's `seq` and at most `i64::MAX - 2`
  (B3d2-d10; larger is `InvalidConfig`). At exactly that bound `resume` succeeds, but the
  next `record` returns `InvalidConfig`. Higher than needed costs only a wider gap, so add
  a margin when in doubt. Lower than a held `seq` fails closed: that receipt or anchor is
  `ReceiptMismatch` or `AnchorMismatch` for good.
- **Restore archived segments before resuming (R10).** vigil cannot detect the
  missing archive. If every segment was archived away and the live file is lost, only
  the marker remains, and `resume` accepts the genesis head `(0, genesis digest)` and
  succeeds, which restarts the MMR and breaks its link to the archive. Restoring the
  archived segments first is the operator's duty; the verifier's detection of a
  genesis-linked resume next to archived segments is #13.
- **On success,** store the returned receipt outside the trail directory before
  continuing, and anchor the `Checkpoint` that `resume` returns at `lost_through + 1`.
  Do not anchor a line read from the trail directory as if it were trusted.
  The verifier reports the `Resumed` warning until a
  reviewer accepts it (#13; see the review criteria below).
- **On `Io`, or a call that never returned,** the resume may still have taken effect. If
  `audit.poison` exists, run its clearing procedure first (below). Then `open` settles the
  staging file, and you read the resume entry from the trail. Verification then reports
  `NoReceipt` for that one record, which you waive (the waive step is #13). Waive only
  the resume entry at `lost_through + 2`, directly after the opening checkpoint at
  `lost_through + 1`; its content must match your recorded arguments field for field,
  its time must lie between the call's start and its observed end, and its `file=` must
  name the segment that call sealed, or be `-` when the live file was deleted. The waiver
  reason has exactly one of two forms: `operator resume started <UTC>: returned Io:
  <error>` or `operator resume started <UTC>: did not return (<killed|host stopped> at
  <UTC>)`. Any other record is tampering.
- **A limit (B3d2-d9).** A handle whose boundary segment was lost after the clock went
  backwards may not see a later resume, which sorts below its boundary. It then fails
  closed with `CorruptTrail` and writes nothing. Open the trail again.

### The `audit.poison` clearing procedure

Restates [decision 6, amendment 3][d6] and the rustdoc of `AuditErrorKind::Poisoned`
(`src/audit/mod.rs`). A failed fsync is never retried. When a failure cannot be undone,
the writer creates `audit.poison` in the trail directory, and `open`, `record`,
`checkpoint`, `close`, `resume`, `AuditConfig::rotate` and `AuditConfig::checkpoint` fail
with `Poisoned` while it exists, and `Drop` writes nothing and reports once on stderr. A
poisoned handle writes nothing; reopen the trail with `expect_head` from the highest held receipt. To
clear the file:

1. Restart the machine, or unmount and remount the filesystem, so that the page cache is
   gone.
2. Verify the trail (#13). It now reads what the disk holds.
3. Remove `audit.poison`, and nothing else: leave staging files for normal settlement.

The file itself is not fsynced. If a power loss drops it, the restart is step 1 and
steps 2 and 3 are silently skipped; run the verification anyway. Verifying before the
restart reads the page-cache view, which looks the same whether or not the kernel dropped
the bytes.

### Request-log review criterion

Restates [decision 5, "Waivers"][d5]. A writer killed after its fsync but before the
application stored the receipt leaves a durable record with no receipt, and it looks like
a forged append. vigil cannot decide; a reviewer does, and **vigil cannot apply this
criterion itself**, because it does not see the application's log. The criterion needs a
**durable request log**: the application writes each entry to its own log and fsyncs it
before calling `record`, and marks it done once the receipt is stored. A crash, including
a power loss that stops every writer, can then orphan only entries that are logged and not
marked done, and at most one record each. A record may be waived only if:

- its full hashed content (actor, action, object, reason, before and after values or
  digests, details) equals such an entry;
- no other waiver uses that entry; and
- its time lies between that log entry and the crash.

Any other unreceipted record, whether there are more of them than open entries or a field
differs, is tampering and not a crash. Matching on actor, action and object alone would
let an attacker who kills a writer append that call's record with a forged reason or
value. The operator's own `rotate` and `resume` calls are the one exception, bounded to
the one record the call wrote and judged on the operator's record of the call instead of a
request-log entry.

### Review criteria

Restates [decision 11, "Review file"][d11] and [decision 18.4][d184]. The review file
(#13) records a reviewer's acceptance of a warning that stays for good, so that `--strict`
can pass after a recorded review. It is kept outside the trail directory; each line names
the reviewer and the reason. Only these warnings can be accepted, each against the
evidence named:

- **`TornWrite`:** a trailing one only where no write can attest it any more (a retired
  trail, a file sealed by `resume`; anywhere else, open the trail and `close` once),
  against the time of the crash. **Never** after the closing checkpoint of a segment
  sealed by rotation, where no crash can leave one.
- **`Resumed`:** against the incident report and the list of `LostRecord` inputs. An
  `accept Resumed` line alone confirms the gap.
- **`ClockWentBackwards`:** against the host's time-synchronisation log.
- **`DuplicateRecord`:** in shipped copies, against the Collector's redelivery; in
  vigil's own files only after an investigation, since no vigil writer duplicates a line.

**Runs sealed by `resume` (`accept-run`, #13).** A run sealed by `resume` reports a
`SegmentStructure` error that names the missing `seq` range of every loss point and ends
with a *run digest*. An `accept-run` line pins that digest and turns exactly the run's
listed findings into `Accepted`; a plain `accept` line never accepts an error. It neither
accepts the `Resumed` warning nor confirms the gap, so a run needs both lines. The
reviewer reads each named range before copying the digest: a line copied without reading
the ranges is not a review.

Every named range and every resume gap means records were deleted, altered or damaged
after they were durable. Neither is ordinary crash loss: records are fsynced before they
are acknowledged (decision 6), a torn tail is attested (decision 5), and a crash never
needs `resume` (decision 8). A range with `count` 0 is an altered or replaced record. A
gap may be wider than the loss by the operator's margin (decision 8), but the declaration
is never a crash effect. The reviewer checks each range against the deployment's
evidence and records the reviewer and the reason. That evidence is the receipts, close
checkpoints, anchors, the application's request log and the incident report.

### What `accept-run` does not accept

Restates [decision 18.2][d182] and [residual 4 of decision 18.3][d183]. An `accept-run`
line (#13) accepts exactly one run's listed findings, as its digest pins them (see
[Review criteria](#review-criteria), which also says that a plain `accept` never accepts
an error). It never accepts:

- **A missing prefix.** A cut that removes the beginning of the trail is `SeqGap` from
  `seq 0` (or `StartMismatch`), not a loss point inside a run.
- **Anchors and revocation pins inside a named range** while the run's closing opening
  checkpoint is unanchored. They are accepted only when that checkpoint is anchored in the
  verification and the digest matches.
- **Every receipt outside the ranges.**
- **`MmrMismatch`** of the run's closing opening checkpoint.

For archiving this means: a run whose closing opening checkpoint is unanchored, with an
anchored checkpoint or pin inside a named range, cannot be archived by the procedure
below until that checkpoint is anchored in the verification, or the trail is restored
from an intact copy.

### Archiving sealed segments

Restates the Archiving bullet and Procedure of [decision 2][d2], and README duties 3 and 4
of [decision 18.4][d184]. Archiving moves sealed segments to WORM or off-host storage. It
is an operator action outside vigil, which never deletes or rewrites an audit file. Any
sealed segment may be moved, except that a run sealed by `resume` is archived together
with everything before it: the start is then the resume's opening checkpoint, never a
record inside the run. The live file and the trail marker must stay. **Batch *n*** is the
set of segments moved by the *n*-th archiving. The **start of batch *n*** is the opening
checkpoint of the oldest segment that stays after it, and the first record of batch *n*+1 (or of the trail directory).

`vigil-audit checkpoints` is available; `vigil-audit verify` remains #13 C1. The commands are
copied from the ADR.

1. **Snapshot and verify.** Take a snapshot (a copy of the trail files) and verify it
   with the anchors, the receipts and the review file: `vigil-audit verify <snapshot>`
   for batch 1, and `vigil-audit verify --start-from <batch-start anchor entry of batch
   n−1> <snapshot>` for batch *n* ≥ 2. The criterion: no error finding and no warning
   that a reviewer has not accepted.
2. **Choose the start:** the opening checkpoint of the oldest segment that stays (a file
   operation: nothing runs).
3. **Record and anchor the start.** Copy its line from the snapshot step 1 verified
   (`vigil-audit checkpoints <snapshot>`), never from a later read of the trail directory,
   into the archive record and into the anchor store, where it is the **batch-start anchor
   entry** of this batch. When the start is a resume's opening checkpoint, the archive
   record also holds the line of the `vigil.audit.resume` record that follows it.
4. **Copy** the older segments from the snapshot that step 1 verified, never from the
   trail directory, to the archive destination (a file operation).
5. **Remove** the older segments from the trail directory (a file operation). **Keep the
   snapshot until step 6 has passed**: a copy that fails there is repeated from it.
6. **Verify in place,** at the archive's destination, with the anchors, the receipts and
   the review file, against step 1's criterion:
   - batch 1: `vigil-audit verify <archive dir> <trail dir>`, with no start;
   - batch *n* ≥ 2: `vigil-audit verify --start-from <batch-start anchor entry of batch
     n−1> <archive dir n> <trail dir>`;
   - then the trail directory alone: `vigil-audit verify --start-from <batch-start anchor
     entry of this batch> <trail dir>`.
7. **Check the end of every batch on a schedule,** not only on restore or move:
   `vigil-audit verify [--start-from <batch-start anchor entry of batch n−1>]
   --end-before <archive record of batch n> --end-anchor <batch-start anchor entry of
   batch n> <archive dir n>`, with the trust file, the anchors (the starts of batches
   *n*−1 and *n* among them), the receipts and the review file. A mismatch (`AnchorMismatch`), a missing entry or an end checkpoint that is
   not that entry (`UnanchoredEnd`) is an error, never a warning.

The rules that make the steps hold:

- **Keep each archive record outside the trail directory, beside its archive,** and put its
  start line in the anchor store. Whoever can delete inside the archive can rewrite the
  record next to it; only the anchor-store entry is the trusted end.
- **`--start-from` and `--end-anchor` come from the anchor store's batch-start entries,
  `--end-before` from the archive record** (which must byte-equal its entry), never from
  the trail directory. A start read from the disk is likely to be "anchored" too, and an
  attacker who deleted kept segments would then make the anchors and receipts of the
  deleted records `OutOfRange`.
- **The schedule is the detection window** ([residual 1][d183]). A deletion or tail cut of
  an archive between two step-7 runs is found by the next run, so the interval is how long
  it can go unseen. Choose it from the deployment's evidence requirements.
- **The schedule must cover every anchored start** ([residual 10][d183]): step 7 runs
  only for the batches it is given. The inventory is the set of anchored starts.
- **The full verification** is batch 1's form of step 6 over every batch directory and the
  trail directory. Run it whenever archives are restored or moved again.
- **The anchor store must sit where the attacker cannot write** (WORM, another host):
  step 7 relies on its integrity ([residual 11][d183], [decision 10][d10]).

**Collector copies must also ship the archive record** and its anchor. A copy that
starts after `seq 0` without them (`verify_files`, #13) cannot be told from a deleted
prefix: `SeqGap` ([residual 8][d183]).

### `open` is not a verifier

Restates [decision 18.1][d181] and README duty 5 of [decision 18.4][d184]. `open` is a
structural check, as [Receipts and the expected head](#receipts-and-the-expected-head) and
[Known limits](#known-limits) say: it settles interrupted staging and scans the chain, and
it infers no signature trust from the disk. A process restarted on a trail whose prefix
was deleted opens it and writes, as it would after archiving. So **run `verify` (#13)
routinely on the live trail**: with the start from the anchor-store entry once something
has been archived (the first record must be that start), with no start before the first
archiving (`seq 0` must be present), and with the archive steps above. A restarting writer does not see a prefix deletion.

### `--strict`

Restates [decision 5][d5]. `--strict` is a flag of the `vigil-audit verify` command (#13). It turns every warning that no `accept` line has accepted into a failure, and it is
the mode for regulated review.

### Operator duties

[Decision 18.4][d184] and the [Consequences][cons] of the ADR assign these duties to the
operator. Each entry links to the subsection that describes it.

- [ ] **Pin each trail id and keep the trust file outside the trail directory** ([Trail
  directory and trail id](#trail-directory-and-trail-id), [Trust file layout and the
  one-file rule](#trust-file-layout-and-the-one-file-rule)).
- [ ] **Stop every writer before rotating a key** ([Operator rotation and
  checkpoint](#operator-rotation-and-checkpoint)).
- [ ] **Decide on `resume` after structural loss** ([Operator resume](#operator-resume)).
- [ ] **Run on storage that honours flushes** ([Supported filesystems and
  durability](#supported-filesystems-and-durability)).
- [ ] **Review `accept Resumed` and `accept-run` (#13) against the deployment's evidence**
  ([Review criteria](#review-criteria)).
- [ ] **Know what `accept-run` does not accept** and what it means for archiving ([What
  `accept-run` does not accept](#what-accept-run-does-not-accept)).
- [ ] **Archive by the procedure, with the schedule and the full verification** ([Archiving
  sealed segments](#archiving-sealed-segments)).
- [ ] **Ship the archive record and its anchor with Collector copies** ([Archiving sealed
  segments](#archiving-sealed-segments)).
- [ ] **Run `verify` (#13) routinely on the live trail; `open` is not a verifier** ([`open` is not
  a verifier](#open-is-not-a-verifier)).

### Known limits

- With no earlier segments present (an archived prefix), the reader accepts a lone
  forged checkpoint and resume pair, because `open` is structural and cannot tell it from
  an honest start. `verify` reports it: `BadSignature` or `NoReceipt`
  ([amendment 6][a6]), plus `SeqGap` without a start and `StartMismatch` with one
  ([decision 18.1][d181]). The verifier is #13.
- The B3d2-d9 limit above: a handle may fail closed with `CorruptTrail` after a resume
  and must reopen.
- [Decision 18.3][d183] tabulates every residual and who catches it.

### Stability of the audit surface

The `vigil::audit` items in the table of [decision 13][d13] are the stable 1.0 surface;
the format primitives are provisional. The on-disk format is frozen separately at 1.0.0
([decision 12][d12]). The low-level primitives behind `--cfg vigil_unstable` may change in
any minor release (ADR-0004 decisions 1 and 4), as the [Semver](#semver) section says of
every unstable item.

Use digests rather than personal data in entries, retaining the referenced values in the
application's own store.

[d1]: docs/adr/0005-audit-trail.md#1-scope-a-separate-synchronous-fail-closed-api-behind-feature-audit
[d2]: docs/adr/0005-audit-trail.md#2-files-adr-0002s-machinery-in-a-directory-of-its-own
[d5]: docs/adr/0005-audit-trail.md#5-hash-chain
[d6]: docs/adr/0005-audit-trail.md#6-the-lossless-sink-fsync-per-record-fail-closed-no-queue
[d8]: docs/adr/0005-audit-trail.md#8-signed-checkpoints-cadence-and-segment-sealing
[a6]: docs/adr/0005-audit-trail.md#amendment-6-reader-rule-for-runs-sealed-by-resume
[a9]: docs/adr/0005-audit-trail.md#amendment-9-part-2-operator-resume-surface
[d9]: docs/adr/0005-audit-trail.md#9-key-custody-and-rotation
[d11]: docs/adr/0005-audit-trail.md#11-verify-api-and-cli-contract-13
[d12]: docs/adr/0005-audit-trail.md#12-format-freeze-and-the-promise-that-old-trails-still-verify
[d13]: docs/adr/0005-audit-trail.md#13-public-surface-feature-audit-under-adr-0004s-rules
[d181]: docs/adr/0005-audit-trail.md#181-open-is-structural-verify-decides
[d182]: docs/adr/0005-audit-trail.md#182-why-accept-run-does-not-reopen-p1
[d183]: docs/adr/0005-audit-trail.md#183-residuals-and-who-catches-each
[d184]: docs/adr/0005-audit-trail.md#184-readme-duties-copied-by-b3e
[d10]: docs/adr/0005-audit-trail.md#10-anchoring-optional
[cons]: docs/adr/0005-audit-trail.md#consequences

## Performance

The public API benchmark suite measures directory-locked appends, the complete
`Config::init` → `tracing` → batch processor → OTLP/JSON → rotating file pipeline,
one-time initialization, and rotation with 100 / 1,000 / 10,000 existing segments.
It uses Criterion 0.8.2 as a dev dependency for statistical estimates and JSON
results. Default features are disabled to avoid plotting and parallel analysis
dependencies; its Apache-2.0/MIT dependency graph passes the existing `deny.toml`
policy without license exceptions.

Reference measurements (2026-10-11): shared KVM VM, AMD Ryzen 7 9800X3D,
12 exposed vCPUs, Linux 6.18.55 / NixOS, x86_64, Rust 1.95.0
(59807616e, LLVM 22.1.2), release profile with thin LTO and one codegen unit.
Scratch files are on the real local ext4 filesystem `/dev/vdd` mounted at
`$HOME` (virtual block device), selected with `VIGIL_BENCH_DIR`. This is a
warm-cache filesystem workload: neither append nor flush calls `fsync`, so the
numbers include kernel writes and metadata operations, not durable-storage
latency. Reference measurements are documentation, never a cross-machine CI
baseline.

| Workload | Ext4 reference mean | Consumer budget |
| --- | ---: | ---: |
| Append, 1 process (4,096 records) | 12.32 ms; 333k records/s | ≥50k records/s |
| Append, 8 processes (32,768 total) | 148.69 ms; 220k records/s aggregate | ≥25k records/s aggregate |
| Export, 256-byte bodies | 11.62 ms; 352k records/s | ≥100k records/s |
| Export with near-cap splitting, 4 KiB bodies | 118.75 ms; 34.5k records/s | ≥10k records/s |
| `Config::init`, fresh process/directory | 0.141 ms | ≤1 ms |
| Rotation, 100 existing segments | 0.150 ms | ≤1 ms |
| Rotation, 1,000 existing segments | 2.059 ms | ≤10 ms |
| Rotation, 10,000 existing segments | 35.708 ms | ≤100 ms |

Budgets are consumer capacity-planning targets on comparable hardware and a
Linux ext4 filesystem with cached writes, using the workloads above. They are
explicitly scoped to local dev/CI disks with available CPU and memory, not NFS,
synchronous durability or cold-cache workloads. The VM append references above
provide 6.66× headroom at one process (333k / 50k records/s) and 8.80× at eight
processes (220k / 25k aggregate records/s). CI run 38133079340 on an AMD EPYC
7763 runner with 4 vCPUs and ext4 measured 76.7k records/s at one process and
40.6k aggregate at eight: only 1.53× and 1.62× headroom, respectively. These
are measurements on two particular systems, not a guaranteed margin on other
hosts. Budgets are not per-record deadlines or p99 guarantees. Provision below these rates, measure
on your actual disk, and monitor queue losses. A shared directory serializes
all signals, so eight writers share the aggregate budget, not eight times it.
Slow disks, CPU contention, large attributes, retention scans and uncached
metadata can exceed these budgets. Initialization is a one-time cost per
process; initialize after fork.

### Ordered-writer instruction budget (#64)

Alongside the [#49](https://github.com/vig-os/vigil/issues/49) disk budgets,
[#64](https://github.com/vig-os/vigil/issues/64) targeted **≤1.05× base
instructions per golden-batch export**. On 2026-10-11, `perf stat -e
instructions:u` measured **629,241 base versus 665,921 head instructions/export
(1.058×)**, narrowly missing that target. Base was dev `cffecf0`; head was
`2eed87c`. Identical release harnesses constructed the fixed golden batch once,
then exported it 10,000 times to a discard sink per process; the numbers average
three runs per revision, amortizing initialization. These instruction counts
are separate from the disk elapsed-time budgets and CI timing advisory.

A scratch-only ablation without the SDK depth guard measured **629,063 base
versus 664,066 head instructions/export (1.056×)**, so most residual overhead
comes from explicit ordered emission. Fast paths emit single-field objects
directly, compare two-field objects once, resolve priority rules once per array,
and avoid collecting/sorting already alphabetically ordered maps after priority
lookup. The remaining work preserves explicit priority-key emission around the
upstream OTLP projection and the required depth validation. Further removal
would require duplicating the upstream OTLP serializer or bypassing the depth
guard; the shared serializer and bounded-input contract are retained. Both
builds and all six perf runs for each comparison exited 0.

### Measurement details

- Append: each fresh child opens its own `RotatingFile`, reports ready, then
  waits for the parent to release it. One or eight children each append 4,096
  256-byte payloads with rotation disabled. Timing includes lock waits, writes,
  release of the children and their exit, excluding process spawn/open and
  file cleanup. The parent checks the total persisted byte count.
- Export: 4,096 tracing events with 256-byte bodies, queue size 8,192, console
  off and explicit info filter. Timing includes event production, serialization,
  splitting, writes and `Guard::flush`; setup, shutdown and output verification
  are excluded. The splitting workload uses 4,096-byte bodies so 512-record SDK
  batches exceed the 1,000,000-byte line cap. It verifies that lines approach
  the cap (>900,000 bytes), every line is bounded and valid JSON, and all records
  survive. These are records/s, including the asynchronous worker's completion.
- Init: a fresh child times only `Config::init` with a new state directory;
  spawn, shutdown and cleanup are excluded. A successful pipeline permanently
  occupies its process slot, so reinitializing within a benchmark is invalid.
- Rotation: preseed valid segment names outside timing; `max_bytes(1)` forces
  each append to rotate. Retention is disabled to isolate the scan needed to
  select the next segment name. Remove the new segment outside timing to keep
  the existing count fixed. Default retention adds a separate metadata scan.
  Rotation is about 238× slower at 10,000 segments than at 100.
  The measured growth makes tiny segments unsuitable for sustained traffic:
  choose a larger size and keep segment counts bounded. At 10,000 segments the
  rotation cost alone already dominates the ordinary append cost.

Reproduce the disk reference inside the dev shell:

```sh
export CARGO_TARGET_DIR="$PWD/target"
export CARGO_BUILD_JOBS=3
export VIGIL_BENCH_DIR="$(mktemp -d "$HOME/.cache/vigil-performance.XXXXXX")"
df -T "$VIGIL_BENCH_DIR"
unset VIGIL_BENCH_QUICK CRITERION_HOME
nix develop -c cargo bench --locked --bench performance
nix develop -c cargo test --locked --bench performance
```

The full reference run uses 100 samples, a 3-second warmup, a 5-second
measurement target and Criterion's default 100,000 resamples per workload.
Child startup and fixture cleanup increase wall time beyond the timed work.
Set `VIGIL_BENCH_QUICK=1` for CI's 10 samples, 1-second warmup, 1-second
measurement target and `nresamples(1000)`; Criterion can extend sampling for
slower workloads. `cargo test --locked --bench performance` validates every
workload once without timing assertions. An explicit step in the blocking Rust
checks lane runs this command exactly once. Its broader Cargo test steps select
libraries, binaries, integration tests and examples, excluding benchmarks.
This correctness run is independent of performance timing. Scratch
cleanup deliberately ignores errors so unwinding cannot cause a second panic.

CI's **Performance comparison** job checks out the PR head with full history,
computes its merge-base with the target branch, and creates a disposable
merge-base worktree. If that base already declares and locks Criterion, it
overlays the exact head benchmark harness while preserving the base dependency
manifest and lockfile. A missing benchmark target declaration is added without
changing dependencies. Both base and head build with `--locked` against their
own lockfiles: no dependency resolution or lockfile updates are allowed. It
measures base with Criterion `--save-baseline base`, then head with
`--baseline base`, sequentially in the **same job on the same runner and
filesystem**, with a shared scratch root and fresh estimate directory. Separate
Cargo artifact directories prevent reuse of the other checkout's binary.
If the merge-base predates the locked Criterion dependency, the job explicitly
skips the timing comparison with a notice annotation and job summary; it does
not fabricate a baseline or resolve extra dependencies. Benchmark correctness
still runs in the blocking Rust lane. Other build/run/lockfile failures block.
Hardware, filesystem, compiler and both commit IDs appear in the job log.
There is no committed cross-machine CI baseline. Local comparisons use:

```sh
export VIGIL_BENCH_QUICK=1
nix develop -c python3 scripts/compare_performance.py --base-ref origin/dev
```

The report flags mean elapsed-time ratios **>=2.0×** versus that same-runner
merge-base (equivalently throughput at most half). A slowdown exits **0**,
adds a `REGRESSION` row to the summary and emits a warning annotation. In the
PR Checks UI, the performance job stays **green with a warning**, and CI
Summary stays green when all other checks pass. A build/run failure, missing or
invalid estimates, or broken correctness assertion exits nonzero: the
performance job is **red and blocking**, and CI Summary fails. There is no
`continue-on-error` on this job or its steps. CI has a 30-minute job timeout.
These exit-status and workflow contracts have automated tests.

A warning requires repeating the same-runner comparison before attributing it
to code. A confirmed regression must be fixed before merge, or receive an
explicit maintainer-approved budget change with an issue describing consumer
impact. The merge-base baseline is regenerated on every run, so there is no
baseline reset to clear warnings.

To refresh the documented disk reference, run the full suite on the stated
filesystem, review all means and update this table, its hardware/date notes and
budget rationale together. An optional local JSON snapshot can be exported:

```sh
nix develop -c python3 scripts/check_performance.py \
  --results "$CARGO_TARGET_DIR/criterion" \
  --baseline "$CARGO_TARGET_DIR/reference.json" --update \
  --environment 'date; CPU/vCPUs; OS/kernel; rustc/LLVM; filesystem; fsync policy'
```

`--update` refuses quick-mode results, even after `VIGIL_BENCH_QUICK` is unset:
the harness records the mode beside the estimates. Missing/unverified mode
metadata or fewer than 100 samples for any workload is also rejected, so a
filtered full run cannot relabel leftover quick estimates. This optional
snapshot is not used by CI.
