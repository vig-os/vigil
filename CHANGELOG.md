# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- Operator `resume` (`AuditConfig::resume`) with a receipt and signer-retaining writer handle ([#11](https://github.com/vig-os/vigil/issues/11)).
- Default `traces` feature and unstable `span_export::OtlpJsonSpanExporter` ([#8](https://github.com/vig-os/vigil/issues/8)).
- ADR-0005 amendment 10: prefix deletion, archiving and run review. `open` is structural and `verify` decides; the archive procedure copies from the verified snapshot, verifies in place per batch and checks each batch's end on a schedule (`--end-before`); a run's `SegmentStructure` names every loss point's missing `seq` range, and an `accept-run` review line accepts exactly one run's findings by a ranges digest. Docs only; #13 implements it ([#107](https://github.com/vig-os/vigil/issues/107)).
- Prometheus conformance script, shared translation fixture and README Prometheus subsection ([#7](https://github.com/vig-os/vigil/issues/7)).
- Audit operator `rotate` and `checkpoint` require an exact expected head, with atomic new-key coverage and documented crash recovery ([#11](https://github.com/vig-os/vigil/issues/11), [#12](https://github.com/vig-os/vigil/issues/12)).
- Metric identity registry canonicalizes signed-zero histogram boundaries, poisons conflicting declarations and filters their exports; unstable `Config::install_opentelemetry_globals` installs the meter provider ([#7](https://github.com/vig-os/vigil/issues/7)).
- Audit `keygen` creates durable seed/public-key files without overwriting ([#11](https://github.com/vig-os/vigil/issues/11), [#12](https://github.com/vig-os/vigil/issues/12)).
- Audit reader support for damaged segment runs sealed by resume, with a cumulative MMR fold and explicit boundary declarations ([#11](https://github.com/vig-os/vigil/issues/11), [#87](https://github.com/vig-os/vigil/issues/87)).
- Stable `vigil::metrics` facade with five static instruments, crate scopes, compile-time validation, late binding and recording-side measurement loss accounting ([#7](https://github.com/vig-os/vigil/issues/7)).
- Public audit writer surface (`AuditConfig`, `AuditTrail`, `Receipt`) and optional log mirroring ([#11](https://github.com/vig-os/vigil/issues/11)).
- `Config::metrics` and `Config::metrics_interval` configure the metrics pipeline and periodic collection ([#7](https://github.com/vig-os/vigil/issues/7)).
- Audit writer crash evidence: sealing and creation matrices, concurrent SIGKILL repairs, clean-stop heads and generated truncation properties ([#11](https://github.com/vig-os/vigil/issues/11), [#12](https://github.com/vig-os/vigil/issues/12)).
- Audit fsync poisoning scope: staging rollback, shared barriers after renames, inert poisoned handles and Drop diagnostics, with durable-state replay tests and restart-first poison clearing ([#11](https://github.com/vig-os/vigil/issues/11), [#90](https://github.com/vig-os/vigil/issues/90)).
- Internal durable audit writer with shared checkpoint cadence, staged segment sealing and recovery with genesis-link validation, repair attestations, signer-outage handling and fsync poisoning ([#11](https://github.com/vig-os/vigil/issues/11), [#12](https://github.com/vig-os/vigil/issues/12)).
- Add the unstable cumulative metrics exporter and shared OTLP envelope bounding, with deterministic time-first output, non-finite sanitizing, and reported data-point losses ([#7](https://github.com/vig-os/vigil/issues/7)).
- Internal audit trail scanning with shared directory locks, incremental state, stale-inode protection and resume-aware segment boundaries ([#11](https://github.com/vig-os/vigil/issues/11), [#12](https://github.com/vig-os/vigil/issues/12)).
- Random UUID v4 `service.instance.id` on the shared resource built by `init` and `layer`, keeping concurrent producers distinct; entropy failures degrade to stderr with a warning naming the cause, and explicit synchronous log batch settings are tested against `OTEL_BLRP_*` overrides ([#7](https://github.com/vig-os/vigil/issues/7)).
- Audit amendment 2 format support: authenticated repair digests and checkpoint MMR counts independent of resume sequence gaps, with reserved context names and creation-only empty MMR validation ([#79](https://github.com/vig-os/vigil/issues/79)).
- Public API performance benchmarks, disk-based consumer budgets and same-runner CI regression reports ([#49](https://github.com/vig-os/vigil/issues/49)).
- Stable public API snapshot and ADR allowlist gates, including declaration kinds, hidden exports and expanded macros; reviewed pre-publish `semver:major` findings remain visible in CI summaries ([#42](https://github.com/vig-os/vigil/issues/42)).
- Docs: README "Stability" section and ADR-0001 "Versioning stance at 1.0", covering the semver and on-disk format promises, what counts as a major, how upstream spec changes are absorbed, MSRV, platforms and the separately frozen audit format ([#50](https://github.com/vig-os/vigil/issues/50)).
- Property tests cover log bounding, truncation, and segment naming and ordering ([#48](https://github.com/vig-os/vigil/issues/48)).
- Strict audit v1 OTLP decoding and checkpoint anchors: closed messages, canonical numbers, hash checks, raw-field parity, framing/size bounds and typed findings; a shared context validator and production record mapping enforce writer/reader agreement, with canonical double/hex checks and Unicode/NUL/depth/refusal properties and a fixed-seed Collector corpus ([#11](https://github.com/vig-os/vigil/issues/11), [#12](https://github.com/vig-os/vigil/issues/12)).
- Opt-in `audit` v1 format primitives: validated entries, canonical encoding, domain-separated record hashes and checkpoint signatures, resumable tessera-compatible MMR, and raw-hex key parsing (seed/public-key ambiguity documented); BSD-3-Clause exceptions are scoped to the three reviewed crypto crates ([#12](https://github.com/vig-os/vigil/issues/12), [#11](https://github.com/vig-os/vigil/issues/11)).
- Independent MSRV and latest-stable CI build and test all features, verify `rust-version`, and check the Apple target at the MSRV ([#45](https://github.com/vig-os/vigil/issues/45)).
- Fallible `Guard::flush`, `shutdown` and `shutdown_with_timeout`, with `FlushError`, `FlushErrorKind` and `Signal` reporting period loss lower bounds, timeout precedence and queue overflow on every flush independently of consumer filters; Drop prints only unreported losses and shutdown falls back inline if thread creation fails (ADR-0004 decisions 2, 3 and 5; [#42](https://github.com/vig-os/vigil/issues/42)).
- ADR-0004 configuration and composition APIs: `Config::layer`, `Console`, `Config::filter_env`, `Config::default_filter`, `Guard::dir`, and typed `InitErrorKind` errors; duration-based `Config::retention` and validated `RotationConfig` builders ([#42](https://github.com/vig-os/vigil/issues/42), [#36](https://github.com/vig-os/vigil/issues/36)).
- Semver CI compares the stable API against the merge base with `dev`, excludes unstable items despite inherited Cargo flags and rejects self-comparisons and zero-check passes ([#43](https://github.com/vig-os/vigil/issues/43)).
- Supply-chain CI gates vulnerabilities, unmaintained crates, licenses, OpenTelemetry compatibility lines and dependency sources with flake-pinned cargo-deny, enforce advisory DB freshness and run weekly on `dev` ([#47](https://github.com/vig-os/vigil/issues/47)).
- Collector reference-reader conformance in CI compares complete rich log records across two resources, rotation, empty lines, garbage input and unterminated valid/garbage lines; it also exercises large tracing records and diagnostic stubs ([#6](https://github.com/vig-os/vigil/issues/6), [#30](https://github.com/vig-os/vigil/issues/30)).
- `vigil::init` and `Config` bridge tracing into rotating OTLP/JSON logs, attach producer resources (including the host name from `uname`), honor XDG and environment settings, and fall back to stderr on storage-open failures ([#5](https://github.com/vig-os/vigil/issues/5), [#32](https://github.com/vig-os/vigil/issues/32)).
  - Retain the logging guard: drop drains and shuts down the batch processor with a five-second timeout and a warning on failure. The configurable queue defaults to 65,536 records and is capped at 1,048,576; overflow warns on stderr. Runtime export losses and diagnostic replacements are counted in rate-limited cumulative summaries, with remaining losses reported at shutdown. SDK warnings go to stderr, failed stderr writes are tolerated, and events after shutdown produce at most one warning.
  - Invalid directory, filter and numeric overrides warn; empty overrides are ignored and relative HOME paths are rejected. An existing global subscriber is rejected before storage side effects; an existing `log` logger does not prevent tracing initialization. Initialize after fork, as documented.
- **Multi-process-safe size rotation and age retention** on local Unix filesystems ([#4](https://github.com/vig-os/vigil/issues/4), [#25](https://github.com/vig-os/vigil/issues/25), [#31](https://github.com/vig-os/vigil/issues/31)).
  - `vigil::rotate::RotatingFile` appends whole lines to `<dir>/<signal>.jsonl` under a blocking `flock` on the state directory, refreshes replaced or missing directory locks, and reopens the live file after another writer rotates. Operations use the locked directory descriptor; waits over ten seconds produce one warning per process.
  - Rotation uses atomic no-replace rename, with directory-relative link/unlink only when unsupported. Both unlink and undo failures are reported; the next lock acquisition recovers live files sharing an inode with a matching signal segment while preserving external backup links.
  - Signal names are `[a-z0-9_]+` and segment matching is exact. Segments order by timestamp and integer counter, including counters wider than six digits and backwards clock changes. Directories and files are created with modes 0700 and 0600, and looser existing permissions are tightened on open. Each line uses one `write(2)`; partial writes roll back and killed-writer fragments are separated from the next record.
  - `segments`, `segments_since`, `read_since` and `find_newest` read segments back without locking writers. Reads retry across rotation with a bounded best-effort result; newest-first searches stop at the first matching file. Files must be read separately to avoid joining unterminated fragments across file boundaries.
- `vigil::logs::OtlpJsonLogExporter`, an `opentelemetry_sdk` `LogExporter`, writes batches as bounded OTLP/JSON `LogsData` lines to a `vigil::sink::LineSink`, with deterministic ordering, missing `timeUnixNano` backfilled from observed time, and non-finite doubles spelled `"NaN"`/`"Infinity"`/`"-Infinity"` ([#3](https://github.com/vig-os/vigil/issues/3), [#30](https://github.com/vig-os/vigil/issues/30)).
  - Lines default to at most 1,000,000 JSON payload bytes excluding the newline; the configurable cap is clamped to 1..=1,048,575 for the Collector's 1 MiB limit. Batches split at record boundaries and pack scopes while copying only resource/scope metadata. Oversized records shorten their largest strings by the escaped-byte overflow, preserving UTF-8 and base64 boundaries, and carry `vigil.truncated` and `vigil.original_size`.
  - Attribute keys, event names and resource/scope fields remain immutable. Unshrinkable records become counted diagnostic stubs preserving identity and small original messages when space permits; healthy neighbors remain intact. A cap too small for the envelope and diagnostic identity returns an explicit error.
- `vigil::sink::{LineSink, AppendFile, MemorySink}`: the line-sink seam, an `O_APPEND` single-`write(2)` file sink (mode 0600) and an in-memory test sink ([#3](https://github.com/vig-os/vigil/issues/3)).
- **ADR-0001 (on-disk format) and ADR-0002 (rotation and retention)** record the OTLP/JSON Lines format, versioning stance and multi-process rotation design, including directory locks, no-replace rotation and bounded reader retries ([#1](https://github.com/vig-os/vigil/issues/1)).
- CI extension runs `nix flake check -L` (clippy, fmt, nextest, doctests, docs) so `CI Summary` gates on the Rust checks; workaround for vig-os/devkit#1811 ([#18](https://github.com/vig-os/vigil/issues/18)).

### Changed

- `AuditConfig::resume` also returns the opening `Checkpoint` (breaking, pre-1.0) ([#138](https://github.com/vig-os/vigil/issues/138)).
- Docs: the README "Audit format (opt-in)" now lists the operator duties of ADR-0005 §18.4 (what `accept-run` does not accept, the archive procedure and schedule, Collector copies, `open` is not a verifier, `--strict`) and an operator checklist; the README conformance paragraph covers the span round trip; the ADR §18.6 table cites decision 2 steps by name, not line ([#11](https://github.com/vig-os/vigil/issues/11), [#12](https://github.com/vig-os/vigil/issues/12)).
- Docs: the README "Audit format (opt-in)" section now carries the deployment text for the audit trail (filesystems, trail id, key custody, trust file, receipts, rotation, resume, `audit.poison`, review criteria and known limits); ADR-0005 §18.3 residual 7 now says "the start from the anchor-store entry" ([#126](https://github.com/vig-os/vigil/issues/126)). No code change ([#11](https://github.com/vig-os/vigil/issues/11), [#12](https://github.com/vig-os/vigil/issues/12)).
- `FlushError` reports traces and renders each signal's own label (#131).
- Docs: ADR-0003 amendments for traces (decision 15 drops the span sink's pending state, decision 16 respects an upstream's sample-out, decision 23 counts span overflow per flush) and ADR-0004 decision 7's `traces` crate count ([#8](https://github.com/vig-os/vigil/issues/8)).
- ADR-0005 amendment 9 Accepted: operator resume surface and inline path; document the lost-boundary clock-rollback limit ([#11](https://github.com/vig-os/vigil/issues/11)).
- Audit writers discover crossed `vigil.audit.resume` loss bounds before cache validation, rebuild through open, and track their highest acknowledged `seq` to fail closed stickily on a contradictory resume (R7'', ADR-0005 amendment 9, Proposed; [#11](https://github.com/vig-os/vigil/issues/11)).
- Clarify the error diagnostic stability promise and strengthen Prometheus harness retry, deadline and attempt-log coverage; complete mapping documentation ([#128](https://github.com/vig-os/vigil/issues/128)).
- ADR-0005 amendment 9 part 1 ([#11](https://github.com/vig-os/vigil/issues/11); settle/reader rules for operator resume: R5'' promotion matches a validated `file=`, R6' genesis leaf is the genesis digest, R9 hard-link-first in settle; test-only fault-injection seam in `rotate::rename_with`).
- Rename audit `KeySeed` to `KeyFileSigner`, loading only regular seed files with verified permissions and effective ownership ([#11](https://github.com/vig-os/vigil/issues/11), [#12](https://github.com/vig-os/vigil/issues/12)).
- Provisional audit format primitives require `vigil_unstable` ([#11](https://github.com/vig-os/vigil/issues/11), [#12](https://github.com/vig-os/vigil/issues/12)).
- `FlushError::Display` preserves source errors and describes losses per signal; `Guard` final summaries now cover metrics, with independent logs fallback, concurrent shutdown and bounded metrics flush ([#7](https://github.com/vig-os/vigil/issues/7)).
- Audit `Record::new` rejects actions starting with `vigil.audit.` with `InvalidEntry`, reserving that prefix for internal records ([#11](https://github.com/vig-os/vigil/issues/11), [#12](https://github.com/vig-os/vigil/issues/12)).
- Log scope order on attribute ties now follows the documented total order ([#7](https://github.com/vig-os/vigil/issues/7)).
- Deny missing public documentation and missing error/panic sections across stable and unstable APIs with all features in flake and CI checks ([#44](https://github.com/vig-os/vigil/issues/44)).
- Apply ADR-0006 decision 3 time-first JSON key order to logs ([#64](https://github.com/vig-os/vigil/issues/64)).
- Drop log records whose body or attribute AnyValues nest deeper than 16 array/map edges and count them as lost log records; these records were previously exported ([#64](https://github.com/vig-os/vigil/issues/64)).
- **Breaking:** exporters, sinks and exact OpenTelemetry re-exports require `--cfg vigil_unstable`; `NON_FINITE` is crate-private. Docs.rs labels the unstable surface, which is compiled and tested separately; empty `RUST_LOG` uses the default filter and unnamed guards drop immediately ([#42](https://github.com/vig-os/vigil/issues/42)).
- Shutdown stops recording before draining; explicit shutdown reports losses to the caller without repeating them on stderr, and Drop reports them once. Failed durable log lines count only records not already written, plus diagnostic replacements (ADR-0003 decisions 3, 4 and 23; [#42](https://github.com/vig-os/vigil/issues/42)).
- **Breaking:** one successful pipeline permanently occupies the process slot, including after shutdown. Filters apply per layer; empty filter variables count as unset, and explicit `retention(None)` overrides environment retention ([#42](https://github.com/vig-os/vigil/issues/42)).
- **Breaking:** make `RotationConfig` fields private and remove `Copy` ([#42](https://github.com/vig-os/vigil/issues/42)).

### Deprecated

### Removed

- **Breaking:** remove `Config::retention_days`; use `Config::retention(Option<Duration>)` ([#42](https://github.com/vig-os/vigil/issues/42)).

### Fixed

- Give every `FlushError` signal part its own diagnostic label, including metrics-only failures and timeouts ([#113](https://github.com/vig-os/vigil/issues/113)).
- Complete README Prometheus unit mapping and conformance diagnostics for bind retries and transient query failures ([#7](https://github.com/vig-os/vigil/issues/7)).
- Remove the unreachable audit storage checkpoint guard clause and replace the ADR-0005 Genesis-base line-number cite with decision 7 'Leaves' ([#11](https://github.com/vig-os/vigil/issues/11)).
- Share audit resume boundary lookup and details parsing; cover honest sealed, archived, unchanged-inode and deleted-live handle continuations ([#11](https://github.com/vig-os/vigil/issues/11)).
- ADR-0005 amendment 10 leftovers: `--start-from` takes the previous batch's batch-start anchor entry from the anchor store everywhere, the `Unparsable` wording and a doubled parenthesis are fixed, and the `accept-run` span definition is exact (a record owns its newline, a malformed record is never span bytes) with a golden vector for #13. Docs only ([#123](https://github.com/vig-os/vigil/issues/123)).
- Reject audit service names over 255 bytes before disk access; verify success-only mirroring and complete public writer trait promises, plain-build auto-trait assertions and unstable rustdoc ([#11](https://github.com/vig-os/vigil/issues/11)).
- Audit signer-outage reporting tolerates unwritable stderr without panicking or failing an acknowledged record ([#100](https://github.com/vig-os/vigil/issues/100)).
- Make OTLP/JSON output independent of consumer `serde_json/preserve_order` feature unification ([#64](https://github.com/vig-os/vigil/issues/64)).
- Bind label-only semver approval to the PR number and head, grant explicit read permissions, and detect concurrent relabels and write-role approvals; document label rename behavior and the removal merge window ([#42](https://github.com/vig-os/vigil/issues/42)).
- Omit absent log bodies from OTLP JSON instead of serializing null, so audit records produced by the shared encoder satisfy the required body absence ([#11](https://github.com/vig-os/vigil/issues/11)).
- Isolate subscriber-installing library tests in child processes; CI also runs plain Cargo tests for all targets and features with default and single test threads ([#42](https://github.com/vig-os/vigil/issues/42)).

### Security
