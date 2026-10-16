# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- Early-release stability guidance, known issues and a package allowlist for consumers of v0.1.0 ([#151](https://github.com/vig-os/vigil/issues/151)).

- Trace export through `init` and `Config::layer`, `Config::traces`/`VIGIL_TRACES`, correlated logs and concurrent Guard lifecycle ([#8](https://github.com/vig-os/vigil/issues/8)).
- `vigil-audit` operator commands (`keygen`, `create`, `checkpoints`, `checkpoint`, `rotate`, `resume`) with usage and `--help` output, and stable `audit::checkpoints(dir)` ([#13](https://github.com/vig-os/vigil/issues/13)).

- Operator `resume` (`AuditConfig::resume`) returning the opening `Checkpoint`, with a receipt and signer-retaining writer handle ([#11](https://github.com/vig-os/vigil/issues/11)).
- Default `traces` feature and `span_export::OtlpJsonSpanExporter` (requires `--cfg vigil_unstable`) ([#8](https://github.com/vig-os/vigil/issues/8)).
- Prometheus conformance script, shared translation fixture and README Prometheus subsection ([#7](https://github.com/vig-os/vigil/issues/7)).
- Audit operator `rotate` and `checkpoint` require an exact expected head, with atomic new-key coverage and documented crash recovery ([#11](https://github.com/vig-os/vigil/issues/11), [#12](https://github.com/vig-os/vigil/issues/12)).
- Metric identity registry canonicalizes signed-zero histogram boundaries, poisons conflicting declarations and filters their exports; `Config::install_opentelemetry_globals` (requires `--cfg vigil_unstable`) installs the meter provider ([#7](https://github.com/vig-os/vigil/issues/7)).
- Audit `keygen` creates durable seed/public-key files without overwriting ([#11](https://github.com/vig-os/vigil/issues/11), [#12](https://github.com/vig-os/vigil/issues/12)).
- Audit reader support for damaged segment runs sealed by resume, with a cumulative MMR fold and explicit boundary declarations ([#11](https://github.com/vig-os/vigil/issues/11), [#87](https://github.com/vig-os/vigil/issues/87)).
- Stable `vigil::metrics` facade with five static instruments, crate scopes, compile-time validation, late binding and recording-side measurement loss accounting ([#7](https://github.com/vig-os/vigil/issues/7)).
- Public audit writer surface (`AuditConfig`, `AuditTrail`, `Receipt`) and optional log mirroring ([#11](https://github.com/vig-os/vigil/issues/11)).
- `Config::metrics` and `Config::metrics_interval` configure the metrics pipeline and periodic collection ([#7](https://github.com/vig-os/vigil/issues/7)).
- Audit fsync poisoning scope: staging rollback, shared barriers after renames, inert poisoned handles and Drop diagnostics, with restart-first poison clearing ([#11](https://github.com/vig-os/vigil/issues/11), [#90](https://github.com/vig-os/vigil/issues/90)).
- Durable audit writer with shared checkpoint cadence, staged segment sealing and recovery with genesis-link validation, repair attestations, signer-outage handling and fsync poisoning ([#11](https://github.com/vig-os/vigil/issues/11), [#12](https://github.com/vig-os/vigil/issues/12)).
- Cumulative metrics exporter (requires `--cfg vigil_unstable`) and shared OTLP envelope bounding, with deterministic time-first output, non-finite sanitizing, and reported data-point losses ([#7](https://github.com/vig-os/vigil/issues/7)).
- Audit trail scanning with shared directory locks, incremental state, stale-inode protection and resume-aware segment boundaries ([#11](https://github.com/vig-os/vigil/issues/11), [#12](https://github.com/vig-os/vigil/issues/12)).
- Random UUID v4 `service.instance.id` on the shared resource built by `init` and `layer`, keeping concurrent producers distinct; entropy failures degrade to stderr with a warning naming the cause, and explicit synchronous log batch settings ignore `OTEL_BLRP_*` overrides ([#7](https://github.com/vig-os/vigil/issues/7)).
- Audit format support: authenticated repair digests and checkpoint MMR counts independent of resume sequence gaps, with reserved context names and creation-only empty MMR validation ([#79](https://github.com/vig-os/vigil/issues/79)).
- Docs: README "Stability" section and ADR-0001 "Versioning stance at 1.0", covering the semver and on-disk format promises, what counts as a major, how upstream spec changes are absorbed, MSRV, platforms and the separately frozen audit format ([#50](https://github.com/vig-os/vigil/issues/50)).
- Strict audit v1 OTLP decoding and checkpoint anchors: closed messages, canonical numbers, hash checks, raw-field parity, framing/size bounds and typed findings; writer and reader validation agree on double and hex encoding, Unicode, NUL and nesting limits ([#11](https://github.com/vig-os/vigil/issues/11), [#12](https://github.com/vig-os/vigil/issues/12)).
- Opt-in `audit` v1 format primitives (requires `--cfg vigil_unstable`): validated entries, canonical encoding, domain-separated record hashes and checkpoint signatures, resumable tessera-compatible MMR, and raw-hex key parsing (seed/public-key ambiguity documented) ([#12](https://github.com/vig-os/vigil/issues/12), [#11](https://github.com/vig-os/vigil/issues/11)).
- Fallible `Guard::flush`, `shutdown` and `shutdown_with_timeout`, with `FlushError`, `FlushErrorKind` and `Signal` reporting period loss lower bounds, timeout precedence and queue overflow on every flush independently of consumer filters; Drop prints only unreported losses and shutdown falls back inline if thread creation fails (ADR-0004 decisions 2, 3 and 5; [#42](https://github.com/vig-os/vigil/issues/42)).
- Configuration and composition APIs: `Config::layer`, `Console`, `Config::filter_env`, `Config::default_filter`, `Guard::dir`, and typed `InitErrorKind` errors; duration-based `Config::retention` and validated `RotationConfig` builders with private fields; retention uses `Config::retention(Option<Duration>)` ([#42](https://github.com/vig-os/vigil/issues/42), [#36](https://github.com/vig-os/vigil/issues/36)).
- Collector reference-reader conformance in CI compares complete rich log records across two resources, rotation, empty lines, garbage input and unterminated valid/garbage lines; it also exercises large tracing records and diagnostic stubs ([#6](https://github.com/vig-os/vigil/issues/6), [#30](https://github.com/vig-os/vigil/issues/30)).
- `vigil::init` and `Config` bridge tracing into rotating OTLP/JSON logs, attach producer resources (including the host name from `uname`), honor XDG and environment settings, and fall back to stderr on storage-open failures ([#5](https://github.com/vig-os/vigil/issues/5), [#32](https://github.com/vig-os/vigil/issues/32)).
  - Retain the logging guard: drop drains and shuts down the batch processor with a five-second timeout and a warning on failure. The configurable queue defaults to 65,536 records and is capped at 1,048,576; overflow warns on stderr. Runtime export losses and diagnostic replacements are counted in rate-limited cumulative summaries, with remaining losses reported at shutdown. SDK warnings go to stderr, failed stderr writes are tolerated, and events after shutdown produce at most one warning.
  - Invalid directory, filter and numeric overrides warn; empty overrides are ignored and relative HOME paths are rejected. An existing global subscriber is rejected before storage side effects; an existing `log` logger does not prevent tracing initialization. Initialize after fork, as documented.
- **Multi-process-safe size rotation and age retention** on local Unix filesystems ([#4](https://github.com/vig-os/vigil/issues/4), [#25](https://github.com/vig-os/vigil/issues/25), [#31](https://github.com/vig-os/vigil/issues/31)).
  - `vigil::rotate::RotatingFile` appends whole lines to `<dir>/<signal>.jsonl` under a blocking `flock` on the state directory, refreshes replaced or missing directory locks, and reopens the live file after another writer rotates. Operations use the locked directory descriptor; waits over ten seconds produce one warning per process.
  - Rotation uses atomic no-replace rename, with directory-relative link/unlink only when unsupported. Both unlink and undo failures are reported; the next lock acquisition recovers live files sharing an inode with a matching signal segment while preserving external backup links.
  - Signal names are `[a-z0-9_]+` and segment matching is exact. Segments order by timestamp and integer counter, including counters wider than six digits and backwards clock changes. Directories and files are created with modes 0700 and 0600, and looser existing permissions are tightened on open. Each line uses one `write(2)`; partial writes roll back and killed-writer fragments are separated from the next record.
  - `segments`, `segments_since`, `read_since` and `find_newest` read segments back without locking writers. Reads retry across rotation with a bounded best-effort result; newest-first searches stop at the first matching file. Files must be read separately to avoid joining unterminated fragments across file boundaries.
- `vigil::logs::OtlpJsonLogExporter` (requires `--cfg vigil_unstable`), an `opentelemetry_sdk` `LogExporter`, writes batches as bounded OTLP/JSON `LogsData` lines to a `vigil::sink::LineSink`, with deterministic ordering, missing `timeUnixNano` backfilled from observed time, and non-finite doubles spelled `"NaN"`/`"Infinity"`/`"-Infinity"` ([#3](https://github.com/vig-os/vigil/issues/3), [#30](https://github.com/vig-os/vigil/issues/30)).
  - Lines default to at most 1,000,000 JSON payload bytes excluding the newline; the configurable cap is clamped to 1..=1,048,575 for the Collector's 1 MiB limit. Batches split at record boundaries and pack scopes while copying only resource/scope metadata. Oversized records shorten their largest strings by the escaped-byte overflow, preserving UTF-8 and base64 boundaries, and carry `vigil.truncated` and `vigil.original_size`.
  - Attribute keys, event names and resource/scope fields remain immutable. Unshrinkable records become counted diagnostic stubs preserving identity and small original messages when space permits; healthy neighbors remain intact. A cap too small for the envelope and diagnostic identity returns an explicit error.
- `vigil::sink::{LineSink, AppendFile, MemorySink}` (requires `--cfg vigil_unstable`): the line-sink seam, an `O_APPEND` single-`write(2)` file sink (mode 0600) and an in-memory test sink ([#3](https://github.com/vig-os/vigil/issues/3)).
- **ADR-0001 (on-disk format) and ADR-0002 (rotation and retention)** record the OTLP/JSON Lines format, versioning stance and multi-process rotation design, including directory locks, no-replace rotation and bounded reader retries ([#1](https://github.com/vig-os/vigil/issues/1)).

### Changed

- Audit deployment guidance covers operator duties (what `accept-run` does not accept, the archive procedure and schedule, Collector copies, `open` is not a verifier, `--strict`) and an operator checklist; the README conformance paragraph covers the span round trip ([#11](https://github.com/vig-os/vigil/issues/11), [#12](https://github.com/vig-os/vigil/issues/12)).
- Audit deployment guidance covers (filesystems, trail id, key custody, trust file, receipts, rotation, resume, `audit.poison`, review criteria and known limits) ([#126](https://github.com/vig-os/vigil/issues/126)). ([#11](https://github.com/vig-os/vigil/issues/11), [#12](https://github.com/vig-os/vigil/issues/12)).
- `FlushError` reports traces and renders each signal's own diagnostic label, including metrics-only failures and timeouts ([#131](https://github.com/vig-os/vigil/issues/131), [#113](https://github.com/vig-os/vigil/issues/113)).
- Audit writers discover crossed `vigil.audit.resume` loss bounds before cache validation, rebuild through open, and track their highest acknowledged `seq` to fail closed stickily on a contradictory resume ([#11](https://github.com/vig-os/vigil/issues/11)).
- Rename audit `KeySeed` to `KeyFileSigner`, loading only regular seed files with verified permissions and effective ownership ([#11](https://github.com/vig-os/vigil/issues/11), [#12](https://github.com/vig-os/vigil/issues/12)).
- `FlushError::Display` preserves source errors and describes losses per signal; `Guard` final summaries now cover metrics, with independent logs fallback, concurrent shutdown and bounded metrics flush ([#7](https://github.com/vig-os/vigil/issues/7)).
- Audit `Record::new` rejects actions starting with `vigil.audit.` with `InvalidEntry`, reserving that prefix for internal records ([#11](https://github.com/vig-os/vigil/issues/11), [#12](https://github.com/vig-os/vigil/issues/12)).
- Log scope order on attribute ties now follows the documented total order ([#7](https://github.com/vig-os/vigil/issues/7)).
- Apply ADR-0006 decision 3 time-first JSON key order to logs ([#64](https://github.com/vig-os/vigil/issues/64)).
- Drop log records whose body or attribute AnyValues nest deeper than 16 array/map edges and count them as lost log records ([#64](https://github.com/vig-os/vigil/issues/64)).
- Exact OpenTelemetry re-exports require `--cfg vigil_unstable`; docs.rs labels the unstable surface. Empty `RUST_LOG` uses the default filter and unnamed guards drop immediately ([#42](https://github.com/vig-os/vigil/issues/42)).
- Shutdown stops recording before draining; explicit shutdown reports losses to the caller without repeating them on stderr, and Drop reports them once. Failed durable log lines count only records not already written, plus diagnostic replacements (ADR-0003 decisions 3, 4 and 23; [#42](https://github.com/vig-os/vigil/issues/42)).
- One successful pipeline permanently occupies the process slot, including after shutdown. Filters apply per layer; empty filter variables count as unset, and explicit `retention(None)` overrides environment retention ([#42](https://github.com/vig-os/vigil/issues/42)).

### Deprecated

### Removed

### Fixed

- Release preparation sets the root crate version on the release branch ([#151](https://github.com/vig-os/vigil/issues/151)).

- **Audit tail classification** ([#143](https://github.com/vig-os/vigil/issues/143)): `resume` seals NUL-filled, control-byte and oversized tails. Reading raw controls, oversized payloads and JSON non-objects now reports `AuditError::finding_kind()` as `Unparsable` instead of record findings; writer validation is unchanged.

- Audit rustdoc no longer says resume is pending or that `vigil-audit verify` exists; it marks the command as #13 and states which head resume takes ([#136](https://github.com/vig-os/vigil/issues/136)).
- Complete README Prometheus unit mapping and conformance diagnostics for bind retries and transient query failures ([#7](https://github.com/vig-os/vigil/issues/7)).
- Reject audit service names over 255 bytes before disk access; log mirroring follows successful writes only ([#11](https://github.com/vig-os/vigil/issues/11)).
- Audit signer-outage reporting tolerates unwritable stderr without panicking or failing an acknowledged record ([#100](https://github.com/vig-os/vigil/issues/100)).
- Make OTLP/JSON output independent of consumer `serde_json/preserve_order` feature unification ([#64](https://github.com/vig-os/vigil/issues/64)).
- Omit absent log bodies from OTLP JSON instead of serializing null, so audit records produced by the shared encoder satisfy the required body absence ([#11](https://github.com/vig-os/vigil/issues/11)).

### Security
