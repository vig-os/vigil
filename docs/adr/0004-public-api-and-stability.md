# ADR-0004: Public API, stability, composition and feature flags

- **Status:** Proposed
- **Date:** 2026-10-11
- **Issues:** [#37](https://github.com/vig-os/vigil/issues/37) (this decision); implemented by [#42](https://github.com/vig-os/vigil/issues/42) (surface), [#43](https://github.com/vig-os/vigil/issues/43) (semver gate), [#44](https://github.com/vig-os/vigil/issues/44) (missing docs), [#45](https://github.com/vig-os/vigil/issues/45) (MSRV lane)

## Context

vigil goes from version 0.0.0 on `dev` straight to a published 1.0.0; there is no public 0.x (owner decision of 2026-10-10). So the first published surface is the 1.0 promise, and the metrics ([#7](https://github.com/vig-os/vigil/issues/7)) and traces ([#8](https://github.com/vig-os/vigil/issues/8)) work would copy whatever pattern the logs surface has today. The path-to-1.0 pre-mortem (2026-10-10, origin/dev `3cf046d`) found three problems with that surface. Every load-bearing claim below was re-probed for this ADR on 2026-10-11 (Rust 1.95.0, opentelemetry 0.33, cargo-semver-checks 0.47.0, cargo-public-api 0.51.0, all from the flake's pinned nixpkgs) in scratch crates outside the repository.

### R1: 0.x upstream types sit in the surface

The current public surface has 80 items (`cargo public-api` over rustdoc JSON of `3cf046d`). Four of them name `opentelemetry_sdk` types, all through one impl: `impl<S: LineSink + 'static> LogExporter for OtlpJsonLogExporter<S>` (`src/logs.rs:156`) with its `export(LogBatch)`, `set_resource(&Resource)` and `shutdown_with_timeout(..) -> OTelSdkResult`.

- **Upstream churn.** `opentelemetry` and `opentelemetry_sdk` released a breaking minor 14 times between 0.20 (2023-07-29) and 0.33 (2026-09-18), 6 of them since 2025-02 (0.28 2025-02-10, 0.29 03-22, 0.30 05-23, 0.31 09-25, 0.32 2026-05-08, 0.33 09-18; crates.io API). `tracing-opentelemetry` follows in lock step (0.34 on 2026-09-23 is the only release on 0.33).
- **A bump breaks consumers.** Probe: a library exposing `pub fn take(_: opentelemetry::KeyValue)` built against 0.33, used by a consumer on 0.32, fails with `error[E0308]: mismatched types` and `note: there are multiple different versions of crate opentelemetry in the dependency graph` (exit 101).
- **The semver tool cannot see it.** Probe: the same library at 0.1.0 with opentelemetry `=0.32.0` as baseline and `=0.33.0` as current, `cargo semver-checks --baseline-root old --release-type minor` → `196 checks: 196 pass, 56 skip`, `no semver update required`, exit 0. A public-dependency bump passes the gate.

### R2: consumers do not fit `init`

`init` reads only `RUST_LOG` (default `info`, `src/init.rs:193`), owns the global subscriber and has no console output except the storage-failure fallback. flock, the most demanding 0.4.0 consumer ([#16](https://github.com/vig-os/vigil/issues/16)), needs:

- **its own filter variable and default.** The file-logging modes install a global `tracing_subscriber::fmt()` subscriber whose global filter is `EnvFilter::try_from_env("FLOCK_LOG").unwrap_or_else(|_| EnvFilter::new("flk=info,flock=info"))`, writing JSON lines to its own rotating file (`flock/src/logging.rs:30-50`).
- **a different setup per mode.** `flk web` instead installs a separate global human-readable subscriber filtered by `RUST_LOG` (default `info`), writing to stdout, `fmt()`'s default writer (`flock/src/web/mod.rs:154-158`). So flock uses two filter variables, one per mode, and has terminal output in one of them.
- **to read its own log back** (`tail_session_logs`, `merge_log_records`, `flock/src/logging.rs:227-248`). flock knows its directory (`crate::session::data_dir()`), but it must be able to tell whether vigil really writes there or fell back to stderr.
- **room to migrate.** flock owns the global subscriber today. Keeping its own layers next to vigil's during a migration means composing vigil into a `Registry` that flock builds. flock does not do this yet; the probe below tests that shape.

### R10: the surface is not future-proof

- `RotationConfig` has public fields and is not `#[non_exhaustive]`: the pre-mortem planted `pub probe: bool` and cargo-semver-checks reported `constructible_struct_adds_field … semver requires new major version`. It is also `Copy`, so a future non-`Copy` field would be breaking.
- `InitError(String)` cannot be matched: "a subscriber is already set" and "invalid service name" are indistinguishable.
- `Guard` reports loss only on stderr from `Drop`; there is no fallible `shutdown`.
- Retention is `retention_days: u64` on `Config` but `Option<Duration>` on `RotationConfig`.
- `MemorySink` (a test helper) and `NON_FINITE` (a documentation constant) are in the surface.
- There are no feature flags, yet metrics, traces, audit and push are coming.

### Tooling facts the decisions rely on

- **cargo-semver-checks skips `unstable-*` features.** Probe: removing a function gated by `#[cfg(feature = "unstable-exporters")]` → 196 pass, exit 0. Control: removing one gated by a plain feature `extra` (not a default feature) → `failure function_missing … semver requires new major version`, exit 1. So by default it checks every feature except the unstable-looking ones.
- **A versioned-feature precedent exists.** `serde_with` 3.24.0 has features `chrono_0_4`, `indexmap_1`, `indexmap_2`, `schemars_0_8`, `schemars_0_9`, `schemars_1`, `time_0_3` to keep 0.x crates out of its own promise.
- **Composition works with a boxed, per-layer-filtered layer.** Probe (scratch crate against `3cf046d`): a generic `fn vigil_layer<S>() -> Box<dyn Layer<S> + Send + Sync + 'static>` with `S: Subscriber + for<'a> LookupSpan<'a> + Send + Sync + 'static`, holding the OTel bridge (over `OtlpJsonLogExporter`) filtered by `FLOCK_LOG`/`flk=info,flock=info` plus an opt-in stderr fmt layer, composed as `registry().with(json_layer.with_filter("flock=debug")).with(vigil)`. Events: `info!(target: "flk::api")` reached vigil's file and the console only; `debug!(target: "flk::api")` reached nobody; `debug!(target: "flock::attach")` reached only flock's JSON layer; `info!(target: "other")` reached nobody. `PROBE OK`, exit 0. The type parameter `S` was inferred from `.with(..)`.
- **The public surface can be snapshotted on the pinned stable toolchain.** `cargo public-api` alone insists on a nightly toolchain (`toolchain 'nightly-…' is not installed`), but `RUSTC_BOOTSTRAP=1 cargo rustdoc --lib -- -Z unstable-options --output-format json` on 1.95.0 followed by `cargo public-api --rustdoc-json target/doc/vigil.json` works (exit 0, 80 items, 4 mention `opentelemetry`).
- **MSRV floors.** Dependencies need at most Rust 1.85 on Linux (`prost` 0.14, `cargo metadata`; `wasip2` 1.87 is wasm-only), and edition 2024 needs 1.85. With `rust-version` lowered to 1.85, `clippy::incompatible_msrv` flags only `File::lock` (stable since 1.89) at `src/rotate.rs:204`, `src/rotate.rs:415` and in `tests/init_review.rs`. `AtomicUsize::try_update` is rejected by 1.93.0 and accepted by 1.95.0, while rustc 1.99.0 deprecates `fetch_update` (used at `src/logs.rs:144`; 1.98.1 does not warn).
- **Feature weight.** Adding `metrics` to `opentelemetry_sdk`/`opentelemetry-proto` adds 0 crates to the normal dependency tree (64 → 64); adding `trace` plus `tracing-opentelemetry` 0.34 adds 1 (→ 65), with a single `opentelemetry` 0.33 in the tree.
- **Queue-overflow losses are not exposed by the SDK.** `opentelemetry_sdk` 0.33 keeps `dropped_logs_count` private (`src/logs/batch_log_processor.rs:158`) and reports it only as the internal `BatchLogProcessor.LogsDropped` warning at shutdown (`:308-316`), which reaches tracing under the default `internal-logs` feature that vigil leaves on. That warning is emitted synchronously on the thread that calls `SdkLoggerProvider::shutdown_with_timeout`, before the shutdown message goes to the worker (`:304-320`, `src/logs/logger_provider.rs:100-111`). Probe: a provider with a batch queue of 1 got 1000 records; the global subscriber filtered everything below ERROR, as a flock-style global filter would. `provider.shutdown()` ran inside `tracing::subscriber::with_default(<capture layer>, ..)`, and the capture read `dropped_logs_count=999` (`PROBE OK`, exit 0). The same `shutdown()` returned `Ok(())`: the SDK reports no loss in its return value.
- **What `cargo public-api` lists depends on its simplification flags.** `-s` omits blanket impls, `-ss` also auto-trait impls, `-sss` also auto-derived impls (`cargo public-api --help`, 0.51.0). The probe count of 80 items used `-sss`. Without `-s`, every vigil type would list foreign blanket impls such as `opentelemetry`'s `impl<T: Sized> FutureExt for T` (`opentelemetry-0.33.0/src/context/future_ext.rs:8`).

## Decision

### 1. The semver promise covers vigil's own types, std, and the `tracing` family only

From 1.0.0, the **stable surface** is every public item available with any combination of features whose names do not start with `unstable-`. Only these external crates may appear in it: `core`, `alloc`, `std`, `tracing`, `tracing_core` and `tracing_subscriber`.

- **No `opentelemetry*` type, trait or impl is in the stable surface.** Exporters and sinks move behind `unstable-exporters` (decision 4).
- **`tracing` 0.1 and `tracing-subscriber` 0.3 are accepted** because the composition API (decision 2) cannot exist without naming `tracing_subscriber::Layer` and the `Subscriber`/`LookupSpan` bounds. They are the crates every consumer already uses (flock, s1-mcp, watcher-s1), and they have not broken in years: `tracing` 0.1.0 shipped 2019-06-28 and `tracing-subscriber` 0.3.0 2021-10-22. If `tracing-subscriber` 0.4 or `tracing` 0.2 ships, moving to it is a vigil **major**.
- **Bumping the internal opentelemetry pin** (0.33 → 0.34) changes nothing in the stable surface, so it is a vigil **minor** (patch if upstream only shipped a patch). If the bump changes bytes on disk, ADR-0001's versioning stance decides whether that is a minor or a major ([#50](https://github.com/vig-os/vigil/issues/50) writes the README "Stability" section that combines both). The bump also changes `unstable-exporters` items (decision 4).
- Error `source()` values are type-erased `dyn Error`; their concrete types (including SDK error types) are not part of the promise, so downcasting is unsupported.
- **Enforcement** (implemented in [#43](https://github.com/vig-os/vigil/issues/43)): CI builds the rustdoc JSON on the pinned toolchain as probed above, with all non-`unstable-` features, and runs `cargo public-api --rustdoc-json … -sss`. It fails if any line of that listing names a crate outside the allowlist. This catches what cargo-semver-checks cannot (R1 probe). Blanket impls are omitted on purpose: a foreign blanket impl such as `impl<T> FutureExt for T` is not something vigil promises, and a consumer who imports that trait gets the impl from their own copy of the crate anyway. `-s` omits vigil-written blanket impls as well, which is harmless today: the stable surface defines no trait of its own (`LineSink` sits behind `unstable-exporters`). An ADR that adds a public vigil trait with a blanket impl must extend the check to list it.
- **Extending the allowlist** takes an ADR. It may add a crate only if that crate is at 1.0 or later, or (like `tracing` here) has gone at least three years without a breaking release, and the ADR has to say why the type cannot stay internal. ADR-0005 (audit) and ADR-0006 (push) follow this rule for any type they want to expose.

### 2. Composition: one `Config`, two ways to install

`Config` keeps its builder and gains the filter, console and composition options. The sketch, with the semantics #42 must implement:

```rust
let (layer, guard) = vigil::Config::new("flock")
    .version(env!("CARGO_PKG_VERSION"))
    .filter_env("FLOCK_LOG")              // default "RUST_LOG"
    .default_filter("flk=info,flock=info") // default "info"
    .console(vigil::Console::Stderr)       // default Console::Off
    .layer()?;                             // or .init()? for the global subscriber
// flk web: .filter_env("RUST_LOG").default_filter("info").console(Console::Stderr), moving its logs from stdout to stderr
tracing_subscriber::registry()
    .with(flock_json_layer)                // the consumer's own layers and filters
    .with(layer)
    .init();
let dir = guard.dir();                     // Some(state dir) unless storage fell back
```

- **`Config::filter_env(name)`** names the variable vigil reads its filter directives from (default `RUST_LOG`). **`Config::default_filter(directives)`** is used when that variable is unset or empty (default `info`). An empty variable counts as unset, like every `VIGIL_*` variable; this replaces today's surprise that an empty `RUST_LOG` records nothing ([#36](https://github.com/vig-os/vigil/issues/36)). An invalid variable value warns on stderr and falls back to the default filter, as today. An invalid `default_filter` is a programming error: `init`/`layer` return `InitErrorKind::InvalidFilter`.
- **`Config::console(Console)`** adds a human-readable stderr layer with the same filter. `Console` is a `#[non_exhaustive]` enum with `Off` (default) and `Stderr`. ANSI colours are used only when stderr is a terminal. When storage falls back to stderr (decision 3), the console layer is not added twice. There is no JSON console: vigil's file is the structured output. There is no stdout variant either: diagnostics belong on stderr, and stdout stays free for the program's own output. A consumer that logs to stdout today (`flk web`) moves to stderr when it adopts `Console::Stderr`; #16 notes this in flock's migration PR. A consumer who really needs stdout composes its own fmt layer next to `layer()`.
- **`Config::layer::<S>(self) -> Result<(Box<dyn Layer<S> + Send + Sync + 'static>, Guard), InitError>`**, where `S: Subscriber + for<'a> LookupSpan<'a> + Send + Sync + 'static`, builds the same pipeline `init` builds but installs nothing global: no global subscriber and no `LogTracer`. The returned layer contains vigil's filter as a **per-layer** filter, the opentelemetry-target exclusion that prevents recursion, the post-shutdown filter, the SDK-diagnostics stderr layer and the optional console layer. So it neither filters nor duplicates the consumer's other layers (composition probe). `log` records reach it when the consumer installs `LogTracer`; `tracing_subscriber`'s `SubscriberInitExt::init()` does this by default. Calling `layer` more than once is allowed: each call has its own provider, and writers to the same directory share one lock (ADR-0002 decision 7). Each returned layer carries its own diagnostics layer and, if asked, its own console layer, so two layers mean SDK diagnostics on stderr twice. That is documented on `layer`, not deduplicated: a consumer who wants one console asks for it on one `Config`.
- **`Config::init(self)`** and **`vigil::init(service)`** keep their meaning: install the global subscriber and `LogTracer`, using the same options.
- **`Config::retention(Option<Duration>)`** replaces `retention_days(u64)`; `None` keeps everything and `Some(Duration::ZERO)` deletes rotated segments at the next prune. The environment variable stays `VIGIL_RETENTION_DAYS` (whole days, `0` keeps everything), because a human sets it. The two "zeros" mean opposite things, and the rustdoc of `Config::retention` and of the variable say so side by side. An explicit `retention(None)` beats the environment variable, like every builder value, so `Config` stores "not set" separately from "set to `None`".
- **`Guard::dir(&self) -> Option<&Path>`** returns the state directory vigil writes to, or `None` when it fell back to stderr. A consumer that reads its log back (flock, with `vigil::rotate::read_since`) learns from it whether there is a file to read. A consumer that left the directory to vigil's XDG resolution learns where the file is without repeating that resolution.

### 3. Errors are for the caller's mistakes; the environment degrades

The rule: `InitError` is returned only for a mistake the caller can fix in code. Anything the environment causes (unwritable storage, a bad environment variable, a subscriber that cannot be reconfigured) degrades with one stderr warning and still returns a `Guard`, because telemetry must never stop the application (as `init` already does for storage, #5).

- **`InitError`** is a struct with `kind(&self) -> InitErrorKind`, `Display`, `Error` (with `source()` where there is one), `Send + Sync + 'static`. **`InitErrorKind`** is `#[non_exhaustive]`, `Copy + Eq + Debug`, with:
  - `AlreadyInitialized`: a global subscriber is already installed (from vigil or anyone else). The caller may carry on without vigil.
  - `InvalidServiceName`: the name breaks the rule in `Config::new`.
  - `InvalidFilter`: `default_filter` does not parse.
- The `reload` failure path in `Config::init` (`cannot configure tracing subscriber`) only happens if the reloadable layer has been dropped, which cannot happen to the global default subscriber. It becomes a degradation (stderr warning, `Guard::dir()` is `None`), not an error kind.
- **`Guard::shutdown(self) -> Result<(), ShutdownError>`** flushes and shuts down with the default 5-second timeout; **`Guard::shutdown_with_timeout(self, Duration)`** takes an explicit one (a CLI wants a short wait, a daemon under lock contention a longer one). `Drop` keeps today's behaviour (stderr warning, no error), and after `shutdown` it does nothing. A guard that fell back to stderr returns `Ok(())`.
- **`ShutdownError`**: `kind()`, `lost_records(&self) -> u64`, `Display`, `Error`, `Send + Sync + 'static`. **`ShutdownErrorKind`** is `#[non_exhaustive]` with `Timeout` (the flush did not finish; more records than counted may be lost), `Failed` (the SDK or sink reported an error) and `RecordsLost` (everything was flushed, but records were lost during the process's life). If several apply, `kind` is the first in that order. `lost_records` counts export failures, diagnostic-stub replacements (ADR-0001 decision 10) and batch-queue overflow. The SDK keeps the overflow counter private, so `shutdown` (and `Drop`) runs the provider's shutdown inside `tracing::subscriber::with_default` with a vigil-owned capture subscriber. The capture reads `dropped_logs_count` from the `BatchLogProcessor.LogsDropped` event, which the SDK emits synchronously on that thread (probe). Scoping the capture to the shutdown call ties the count to this guard's provider, so several guards cannot double-count, and the consumer's filters cannot hide the event. Every other event raised on that thread during the shutdown call (for example the SDK's `BatchLogProcessor.Shutdown.Timeout` error) is forwarded to the dispatcher that was current before the call, so the consumer and vigil's diagnostics layer still see it. Only `LogsDropped` is consumed; vigil reports its count itself. A unit test pins the event name and field, so an upstream rename fails at the bump instead of silently undercounting. `lost_records` is a lower bound, and its rustdoc names the two known gaps: (1) when the consumer compiles WARN out of every crate with `tracing`'s static `max_level_*`/`release_max_level_*` features, the event never exists; (2) records emitted on other threads while shutdown runs are lost but not counted, whether they overflow after the SDK has read its counter (`batch_log_processor.rs:308`) or arrive after the worker has disconnected (`:250`), because `Logger::emit` does not check for shutdown (`src/logs/logger.rs:53-80`). Once metrics and traces exist, `shutdown` covers every signal's provider and the counts add up.

### 4. `unstable-exporters`: the exporters stay available, outside the promise

- With feature **`unstable-exporters`** (off by default), `vigil::logs::OtlpJsonLogExporter` (`new`, `with_max_line_bytes`, `sink`, and its `LogExporter` impl) and the `vigil::sink` module (`LineSink`, `AppendFile`, `MemorySink`, and the `LineSink` impls for `Arc<T>` and `RotatingFile`) are public. Without it they are crate-private. The metrics and traces exporters from #7/#8 go behind the same feature.
- **These items are exempt from semver.** Any vigil minor may change them, including when vigil moves to a new opentelemetry release. Such a change gets a changelog entry naming the feature. The rustdoc of each item and the README say to pin vigil with `~1.N` when the feature is enabled. Only applications should pin like that: Cargo allows one semver-compatible vigil 1.x per dependency graph, so a library that pins `~1.N` holds every other dependent in the graph at 1.N. cargo-semver-checks skips the feature by default (probe), and the public-api allowlist check (decision 1) runs without it.
- `LineSink` stays unsealed: its purpose is custom storage. New methods get default implementations.
- **Graduation trigger:** these items can join the stable surface only after `opentelemetry_sdk` publishes 1.0 for the traits they implement, and only through a new ADR. Until then a consumer who wants vigil's files from their own SDK pipeline uses this feature, knowing it is unstable.
- `NON_FINITE` becomes crate-private. The spelling it names is documented in the `logs` module and ADR-0001 decision 6.

### 5. No public fields, every public enum non-exhaustive

- No public struct has a public field. Structs that callers configure (`Config`, `RotationConfig`) are built with methods; the others (`Guard`, `InitError`, `ShutdownError`, `RotatingFile`) are opaque. This makes `#[non_exhaustive]` unnecessary on structs, because nobody outside can construct them with a literal.
- **`RotationConfig`** gets private fields and builder methods in the `Config` style: `RotationConfig::default().max_bytes(u64).retention(Option<Duration>)`. `max_bytes` clamps 0 to 1, like `Config::max_bytes`. It derives `Debug + Clone + PartialEq + Eq + Default` and **drops `Copy`**, so adding a non-`Copy` field later is not breaking.
- Every public enum (`Console`, `InitErrorKind`, `ShutdownErrorKind`, and later ones) is `#[non_exhaustive]`.
- Auto traits are part of the promise: `Config`, `Guard`, `RotationConfig`, `RotatingFile`, `InitError` and `ShutdownError` are `Send + Sync` (cargo-semver-checks catches losing them). Builder methods and `Guard` stay `#[must_use]`.
- `missing_docs`, `clippy::missing_errors_doc` and `clippy::missing_panics_doc` become denied ([#44](https://github.com/vig-os/vigil/issues/44)).

### 6. The stable surface at 1.0, item by item

Each item exists because a named need requires it. Anything not listed is not public in 1.0 without the `unstable-exporters` feature.

| Item | Why it is public |
|---|---|
| `init(service)` | The one-line path for most consumers (s1-mcp, watcher-s1). |
| `Config::new`, `dir`, `max_bytes`, `queue_size`, `version`, `revision` | Existing options with users today (#5); unchanged. |
| `Config::retention` | Replaces `retention_days` (one unit, decision 2). |
| `Config::filter_env`, `default_filter`, `console` | flock's filter and console needs (R2). |
| `Config::init` | `init` with options. |
| `Config::layer` | Composition into a consumer-owned `Registry` (R2, probed). |
| `Console` (`Off`, `Stderr`) | Opt-in console (R2). |
| `Guard`, `Guard::shutdown`, `Guard::shutdown_with_timeout` | Keeps the pipeline alive; reports loss as a value (R10). |
| `Guard::dir` | Tells a consumer that reads its log back whether, and where, vigil writes (R2). |
| `InitError`, `InitErrorKind` | Matchable init failures (R10). |
| `ShutdownError`, `ShutdownErrorKind` | Matchable shutdown failures and loss count (R10). |
| `VERSION` | Lets consumers print which vigil version wrote their telemetry in diagnostics and bug reports; a `&str` constant costs nothing to keep stable. |
| `rotate::RotatingFile` (`open`, `append`, `Debug`) | The multi-process-safe rotating writer, which no other crate provides ([ADR-0002](0002-rotation-and-retention.md), Context); the audit sink (#11) and consumers with their own signal files use it. |
| `rotate::RotationConfig` (`Default`, `max_bytes`, `retention`) | Configures `RotatingFile`. |
| `rotate::segments`, `segments_since`, `read_since`, `find_newest` | Reading vigil's files back (ADR-0002 decision 15): flock's log tail, the audit verifier (#13). |

The metrics and traces options (#7, #8, under ADR-0003), audit (#10, ADR-0005) and push (#41, ADR-0006) add their items under their features; each of those ADRs justifies its items against this ADR's rules.

### 7. Feature flags

Name and default are decided here. What a feature's code does is deferred to the ADR named in the last column.

| Feature | Default | Adds | Behaviour deferred to |
|---|---|---|---|
| `metrics` | on | `opentelemetry_sdk`/`opentelemetry-proto` `metrics` features; 0 new crates (probe) | ADR-0003 ([#38](https://github.com/vig-os/vigil/issues/38)) |
| `traces` | on | `trace` features plus `tracing-opentelemetry` 0.34; 1 new crate (probe) | ADR-0003 ([#38](https://github.com/vig-os/vigil/issues/38)) |
| `audit` | off | blake3, ed25519-dalek, vigil's own MMR (owner decision v2) | ADR-0005 ([#10](https://github.com/vig-os/vigil/issues/10)) |
| `push` | off | an HTTP client for OTLP/HTTP to a local agent | ADR-0006 ([#39](https://github.com/vig-os/vigil/issues/39), [#41](https://github.com/vig-os/vigil/issues/41)), which must supersede ADR-0001 decision 9 first |
| `unstable-exporters` | off | no dependencies; makes exporters and sinks public | none (this ADR) |

- Logs are not a feature: they are the crate's core and always compiled.
- `metrics` and `traces` are on by default because the crate's promise is "logs, metrics and traces" and they cost at most one crate. "On" means compiled in; what `init` does with each signal is ADR-0003's decision.
- `audit` is off because it adds cryptographic dependencies only audit users need. `push` exists only once ADR-0006 supersedes ADR-0001 decision 9 ("vigil writes files only… No network exporter"), which the owner has asked for (owner decision v2, 2026-10-11: an optional `push` feature, with files staying the durable copy). This ADR reserves the name and fixes it as off by default, so the default build never contains network code.
- **There is no `test-util` feature.** Its only candidate, `MemorySink`, serves exporter tests and goes behind `unstable-exporters`. Consumers test vigil's output with `Config::dir(<temp dir>)` and `rotate::read_since`.
- Rules: every optional dependency is enabled with `dep:` syntax, so no implicit feature names leak into the surface. Features are additive: enabling one never removes or changes an item. Removing a feature, or changing the default set, is a major. To label gated items with their feature, #42 sets `[package.metadata.docs.rs] all-features = true` and `rustdoc-args = ["--cfg", "docsrs"]` in `Cargo.toml` and adds `#![cfg_attr(docsrs, feature(doc_cfg))]` to `lib.rs` (docs.rs builds only default features unless told otherwise).

### 8. MSRV policy

- **`rust-version` stays `1.95` for 1.0.0.** The measured floor is lower (1.89, set by `File::lock`; dependencies need 1.85), but every known consumer builds with the devkit-pinned toolchain, which is 1.95.0. Rust 1.95 was released 2026-04-16, so it turns six months old on 2026-10-16, before any realistic 1.0 date; the six-month rule below governs raises after 1.0. A lower MSRV would buy no known user and would rule out `AtomicUsize::try_update`, the replacement for `fetch_update`, which rustc 1.99 deprecates (probe).
- **Raising the MSRV** happens only in a minor release, never a patch, with a changelog entry. The new MSRV must be a stable release at least six months old on the vigil release date. The devkit toolchain pin and the MSRV move independently.
- **CI tests it** ([#45](https://github.com/vig-os/vigil/issues/45)): one job builds and tests with all features on exactly the `rust-version` toolchain, separate from the dev pin. A second job builds and tests on the latest stable release without `-D warnings`, so a deprecation (like `fetch_update` on 1.99) shows up as a warning before it becomes an error; a build or test failure there blocks. Switching `src/logs.rs:144` to `try_update` is part of #42.

### 9. Semver baseline before and after the first publish

- **Until 1.0.0 is published** (version stays 0.0.0 on `dev`): the semver job ([#43](https://github.com/vig-os/vigil/issues/43)) compares each PR with the full SHA of its merge base with `dev`, passes an explicit `--release-type minor` (without it, 0.0.0 → 0.0.0 runs 0 checks and passes, pre-mortem R9), and fails unless it reports more than 0 checks. A PR labelled `semver:major` (such as #42) may fail this job only if its body cites the ADR decision that requires the break; the architect checks that citation before merging. The public-api allowlist check (decision 1) has no exception.
- **When #42 lands**, a `cargo public-api` snapshot of the stable surface is committed (#42 picks the path). From then on every surface change shows up as a diff of that file in the PR that makes it.
- **From 1.0.0 on:** the baseline is the latest published version on crates.io (cargo-semver-checks' default). Feature PRs don't bump the version, so CI keeps passing `--release-type minor`: every PR must be minor-compatible. The release-preparation PR sets the new version and the job runs with the release type that version implies. The `semver:major` exception ends: a breaking change needs a superseding ADR and a 2.0.0.

## Consequences

- Consumers who use only `init`/`Config` never see an opentelemetry bump: vigil can track upstream's roughly two breaking releases a year in minor releases.
- flock-shaped consumers compose vigil into their own `Registry` with their own filter, console and other layers. #42's acceptance includes a flock-like example with a test.
- `shutdown` makes loss visible as a value. The price is coupling to the SDK's `BatchLogProcessor.LogsDropped` event, its name, its field and the fact that it is emitted on the calling thread, all guarded by a test. If upstream changes any of these, vigil cannot take that bump until it finds another source for the count. The count stays a lower bound (decision 3).
- Users of `unstable-exporters` get no semver protection: `cargo update` can pull in a minor that breaks their build unless they pin `~1.N`, and such a pin in a library holds every other dependent in the graph back. Today no consumer is known to need the exporters.
- vigil's own `init`/`layer` must provide everything consumers need, because the exporters are no longer a stable escape hatch. Every new consumer need becomes a `Config` option (a minor) or an ADR.
- A `tracing-subscriber` 0.4 or `tracing` 0.2 forces a vigil major. Since every consumer would have to migrate anyway, this is accepted.
- Every callback through the boxed layer is one dynamic dispatch, which is negligible next to the file I/O behind it.
- #42 breaks the logs surface on `dev` (`retention_days`, `RotationConfig` fields, `InitError`, the exporter module). Nothing is published, so no user is affected; this is the last cheap moment.
- CI grows by a rustdoc-JSON build on the pinned toolchain (#43) and two toolchain lanes (#45).

## Alternatives considered

- **Keep the exporters stable and make every opentelemetry bump a vigil major.** That is 14 majors since mid-2023, each forced on `init`-only consumers who never touch an exporter. Rejected.
- **Versioned features (`opentelemetry_0_33`, as in `serde_with`).** Honest semver, but staying minor-only means compiling the exporters against several SDK versions at once (one renamed dependency and one code path per version); dropping an old one is a major anyway. That cost buys nothing for zero known users. Rejected; a new ADR can adopt it if users appear.
- **Wrap the SDK traits in vigil-owned types.** A provider accepts only the SDK's `LogExporter`, so a wrapper cannot plug in without exposing the trait it wraps. Rejected.
- **A separate 0.x crate for the exporters.** Gives cargo-visible semver for the exporters, but needs a second published crate and turns vigil's line encoder into a public API of one of the two crates. Rejected for 1.0. It is the natural move if the exporters gain real users before upstream reaches 1.0.
- **Make the exporters fully private.** Almost the same as decision 4, but it would take away the only way for an existing SDK pipeline to write vigil's files. The feature costs only `cfg` attributes. Rejected.
- **A concrete `vigil::Layer` type implementing `Layer<S>` for every `S`.** Per-layer filters (`Filtered<L, F, S>`) are generic over `S`, so a non-generic type would have to reimplement tracing-subscriber's filter plumbing. Rejected for the probed `Box<dyn Layer<S>>`.
- **Return `impl Layer<S>` instead of a box.** Works too, but a consumer cannot name the type to store it in a struct. Rejected; the box costs one indirection.
- **Accept a `tracing_subscriber::EnvFilter` in `Config`.** Puts one more upstream type in the surface where a string works. Rejected.
- **A registry callback (`Config::with_layer(..)`).** Inverts control and multiplies generic bounds. Rejected; `layer()` hands control to the consumer.
- **`InitError` as a `#[non_exhaustive]` enum.** Workable, but data in variants freezes their fields. A struct with `kind()` (the `std::io::Error` shape users already know) can carry message and source freely. Rejected.
- **`RotationConfig` with `#[non_exhaustive]` and public fields.** Allows reading and mutating fields, but skips the `max_bytes ≥ 1` validation and keeps the `Copy` commitment. Rejected.
- **A `test-util` feature.** Nothing for consumers would go in it (decision 7). Rejected.
- **MSRV N-2 rolling, or MSRV = the measured 1.89.** N-2 would follow upstream every six weeks with no consumer asking for it; 1.89 buys no known user and rules out `try_update`. Rejected for the six-month rule.

## References

- [vig-os/vigil#37](https://github.com/vig-os/vigil/issues/37), [#42](https://github.com/vig-os/vigil/issues/42), [#43](https://github.com/vig-os/vigil/issues/43), [#44](https://github.com/vig-os/vigil/issues/44), [#45](https://github.com/vig-os/vigil/issues/45), [#50](https://github.com/vig-os/vigil/issues/50), [#16](https://github.com/vig-os/vigil/issues/16), [#36](https://github.com/vig-os/vigil/issues/36)
- Path-to-1.0 pre-mortem, 2026-10-10 (findings R1, R2, R9, R10)
- [ADR-0001](0001-on-disk-format.md) (format versioning stance, decision 9 no network exporter, decision 10 bounded lines), [ADR-0002](0002-rotation-and-retention.md) (rotation and readers)
- crates.io version histories of `opentelemetry`, `opentelemetry_sdk`, `tracing-opentelemetry`, `tracing`, `tracing-subscriber`, `serde_with` (fetched 2026-10-11)
- [cargo-semver-checks](https://github.com/obi1kenobi/cargo-semver-checks) 0.47.0, [cargo-public-api](https://github.com/cargo-public-api/cargo-public-api) 0.51.0
- flock `src/logging.rs`, `src/web/mod.rs` (the composition needs)
