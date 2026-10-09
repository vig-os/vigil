# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- `vigil::logs::OtlpJsonLogExporter`, an `opentelemetry_sdk` `LogExporter` that writes each export batch as one OTLP/JSON `LogsData` line to a `vigil::sink::LineSink`, with deterministic ordering, `timeUnixNano` backfilled from the observed time, and non-finite doubles spelled `"NaN"`/`"Infinity"`/`"-Infinity"` so the Collector keeps the line ([#3](https://github.com/vig-os/vigil/issues/3))
- `vigil::sink::{LineSink, AppendFile, MemorySink}`: the line-sink seam, an `O_APPEND` single-`write(2)` file sink (mode 0600) and an in-memory test sink ([#3](https://github.com/vig-os/vigil/issues/3))

### Changed

### Deprecated

### Removed

### Fixed

### Security
