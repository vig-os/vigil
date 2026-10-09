# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- **Multi-process-safe size rotation and age retention** ([#4](https://github.com/vig-os/vigil/issues/4))
  - `vigil::rotate::RotatingFile` appends whole lines to `<dir>/<signal>.jsonl` under an `flock` on a separate `.lock` file, reopens when another process rotated, rolls back partial writes, and names rotated segments so they sort chronologically
  - `segments`, `segments_since`, `read_since` and `find_newest` read them back
  - Writers lock the directory (`flock`) instead of a lock file, so deleting files cannot break exclusion; signal names are `[a-z0-9_]+`; segment counters grow past six digits and rotation never replaces an existing file (hard-link, then unlink). Segment matching is exact (signals such as `logs` and `logs_2` never see each other's files), new segment names stay ordered when the clock goes backwards, looser modes on an existing directory or file are tightened on `open`, and each line is written with exactly one `write(2)`
- `vigil::logs::OtlpJsonLogExporter`, an `opentelemetry_sdk` `LogExporter` that writes each export batch as one OTLP/JSON `LogsData` line to a `vigil::sink::LineSink`, with deterministic ordering, `timeUnixNano` backfilled from the observed time, and non-finite doubles spelled `"NaN"`/`"Infinity"`/`"-Infinity"` so the Collector keeps the line ([#3](https://github.com/vig-os/vigil/issues/3))
- `vigil::sink::{LineSink, AppendFile, MemorySink}`: the line-sink seam, an `O_APPEND` single-`write(2)` file sink (mode 0600) and an in-memory test sink ([#3](https://github.com/vig-os/vigil/issues/3))
- **ADR-0001 (on-disk format) and ADR-0002 (rotation and retention)** ([#1](https://github.com/vig-os/vigil/issues/1))
  - Records the OTLP/JSON Lines format, versioning stance, and the multi-process rotation design with its pre-mortem evidence
- CI extension runs `nix flake check -L` (clippy, fmt, nextest, doctests, docs) so `CI Summary` gates on the Rust checks; workaround for vig-os/devkit#1811 ([#18](https://github.com/vig-os/vigil/issues/18))

### Changed

### Deprecated

### Removed

### Fixed

### Security
