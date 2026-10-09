# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- **Multi-process-safe size rotation and age retention** ([#4](https://github.com/vig-os/vigil/issues/4))
  - `vigil::rotate::RotatingFile` appends whole lines to `<dir>/<signal>.jsonl` under an `flock` on a separate `.lock` file, reopens when another process rotated, rolls back partial writes, and names rotated segments so they sort chronologically
  - `segments`, `segments_since`, `read_since` and `find_newest` read them back

### Changed

### Deprecated

### Removed

### Fixed

### Security
