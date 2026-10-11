# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- Docs: README "Stability" section and ADR-0001 "Versioning stance at 1.0", covering the semver and on-disk format promises, what counts as a major, how upstream spec changes are absorbed, MSRV, platforms and the separately frozen audit format ([#50](https://github.com/vig-os/vigil/issues/50)).

- Property tests cover log bounding, truncation, and segment naming and ordering ([#48](https://github.com/vig-os/vigil/issues/48)).

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

- Shutdown stops recording before draining; explicit shutdown reports losses to the caller without repeating them on stderr, and Drop reports them once. Failed durable log lines count only records not already written, plus diagnostic replacements (ADR-0003 decisions 3, 4 and 23; [#42](https://github.com/vig-os/vigil/issues/42)).

- **Breaking:** one successful pipeline permanently occupies the process slot, including after shutdown. Filters apply per layer; empty filter variables count as unset, and explicit `retention(None)` overrides environment retention ([#42](https://github.com/vig-os/vigil/issues/42)).
- **Breaking:** make `RotationConfig` fields private and remove `Copy` ([#42](https://github.com/vig-os/vigil/issues/42)).

### Deprecated

### Removed

- **Breaking:** remove `Config::retention_days`; use `Config::retention(Option<Duration>)` ([#42](https://github.com/vig-os/vigil/issues/42)).

### Fixed

- Isolate subscriber-installing library tests in child processes; CI also runs plain Cargo tests for all targets and features with default and single test threads ([#42](https://github.com/vig-os/vigil/issues/42)).

### Security
