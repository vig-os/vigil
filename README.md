# vigil

*Verifiable Integrity-Guarded Instrumentation & Logging* (V·I·G·I·L): the opinionated observability crate for vig-os Rust projects.

> **Pre-alpha.** The design is settled; the code is being built. Logs and metrics are implemented; traces and audit are being built. Track progress in the milestones.

## Stability

vigil publishes no 0.x: the first release is 1.0.0, so what follows is the 1.0
promise. Logs and metrics are implemented today; the rest of the promised surface is still
being built, and the pre-1.0 `dev` branch may change it.

- **Semver.** The stable API is every public item built without `--cfg vigil_unstable`,
  with any combination of Cargo features, and it names only vigil's own types, `std`
  and the `tracing` family. OpenTelemetry types never appear in it, so an
  OpenTelemetry upgrade inside vigil is a minor release.
  Moving to `tracing` 0.2 or `tracing-subscriber` 0.4 would be a major. Removing a
  feature or changing the default features is a major. See
  [ADR-0004](docs/adr/0004-public-api-and-stability.md) decisions 1, 5 and 7. CI checks the committed public API snapshot and the ADR allowlist, including
  hidden items and macro expansions, alongside the semver gate ([Semver](#semver)).
- **`vigil_unstable` is excluded.** Items behind `--cfg vigil_unstable` (the exporters,
  sinks and the re-exported OpenTelemetry crates; global-provider installation
  remains deferred to #7/#8) may
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
  ([ADR-0005](docs/adr/0005-audit-trail.md) decision 12). Before 1.0 the low-level
  `audit` API is provisional, see [Audit format](#audit-format-opt-in).
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

## Metrics

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

## Unstable SDK access

Exporters and sinks are crate-private by default. Applications composing their
own SDK pipeline can opt in with `RUSTFLAGS="--cfg vigil_unstable" cargo build`,
or set `[build] rustflags = ["--cfg", "vigil_unstable"]` in their own
`.cargo/config.toml`. Use `vigil::unstable::{opentelemetry, opentelemetry_sdk}`
for the exact versions linked by vigil. These APIs may change in any minor;
applications should pin vigil with `~1.N`. A library using them forces its
applications to enable the cfg, must document that requirement, and should avoid
pinning `~1.N` itself because that constrains every dependent in the graph.
Global-provider installation and the tracing integration re-export follow in
#7/#8; neither is implemented today.

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
- **`audit` feature** (opt-in). A separate, **lossless** audit trail of user actions on a device (who did what, when, and why) in the spirit of 21 CFR Part 11 §11.10(e). Records are still OTLP log records, hash-chained, with Merkle roots per segment and **ed25519-signed checkpoints**. They're built on [`tessera-core`](https://github.com/vig-os/tessera) primitives, so data provenance and audit provenance share one proof system.

```rust,no_run
let guard = vigil::Config::new("my-service")
    .version(env!("CARGO_PKG_VERSION"))
    .init()?;
tracing::info!(user = "alice", "opened study");
guard.shutdown()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Logs and metrics are available now; traces and audit are planned. Keep the guard
alive until shutdown to flush queued logs. `let _ = vigil::init(..)` drops it immediately. The batch queue holds 65,536 records by default (512 per export, every second).
Memory is bounded by queue size times record size; overflow drops records with
a stderr warning. `VIGIL_QUEUE_SIZE` or `Config::queue_size` changes the bound
(minimum 1, cap 1,048,576). Oversized environment and builder values clamp to
that cap with a warning. Measured memory is approximately 16 B per reserved
slot (16 MiB at the cap), plus approximately 0.4 KB per queued small record;
larger fields need more memory. Guard drop waits up to five seconds, including directory-lock waits,
then warns that remaining records may be lost; the SDK worker may continue
until the lock is released. `std::process::exit` skips flushing. Tracing
spans alone do not currently populate OTLP trace/span IDs.

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
Log storage initialization failures make logs fall back to stderr; metrics
storage initialization failures disable metrics with their own warning.
A second initialization returns an error before creating storage. An existing
`log` logger is preserved: initialization succeeds with one warning that `log`
records cannot reach vigil; tracing events continue to be written.

Call `init` **after forking**. A child forked after initialization inherits the
parent's directory lock and subscriber but has no batch worker; it cannot safely
continue using that logging instance.

Log storage-open failures fall back to stderr; metrics storage failures disable
metrics with their own warning. Runtime export failures drop the affected
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
when logs fell back to stderr; metrics may still write `metrics.jsonl`.
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

`Guard::flush()` exports queued logs and collects and exports metrics with a
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
stderr contribute no error; metrics still report their outcome. Explicit shutdown
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
are delivered; unterminated garbage is dropped. Metrics (#7) and traces (#8) are
planned extensions.

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

Enable `audit` for the I/O-free ADR-0005 format primitives: entries, canonical
record encoding, hashes, MMR commitments, checkpoint signatures and strict
OTLP decoding. `Record::parse_line` accepts Collector multi-record lines and
checks closed camelCase messages at every level, duplicate keys after unescaping
and record hashes. Int64 values require canonical decimal strings; JSON numbers
are rejected to prevent rounding by other readers. Raw bytes below 0x20 (including interior LF and CRLF) are
rejected; escaped controls and DEL are content. OTLP intValue fits i64; timestamps fit u64.
Context bytes require standard base64. Checkpoint anchors exclude final LF. Payloads over 1,000,000 bytes (excluding an
optional final LF) are refused before parsing; nesting is limited to 128 levels.
`AuditError::finding_kind` retains verifier categories for malformed lines.
`Checkpoint::parse` retains one checkpoint line for an external anchor; parsing
does not check signatures, trust, chain links or MMR history. Empty/whitespace
lines are errors, not torn writes. Incomplete input also fails decoding; crash
recovery requires file context and follows in B2, while strict warning policy
(#68) and receipts across resume (#70) remain separate. The durable
`AuditTrail::record` API follows in #11; verification and the CLI follow in #13.
These primitives alone do not persist records or establish trust. Their low-level
API is provisional before 1.0.

A deployment must use storage that honours flushes. Keys held locally cannot
protect against an attacker who can read them and rewrite the trail. Pin trail
identities and keep trust policy and application receipts outside the writable
trail directory; stop all writers before rotating keys. Use digests rather than
personal data, retaining the referenced values in the application's own store.

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
