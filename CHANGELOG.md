# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- **ADR-0001 (on-disk format) and ADR-0002 (rotation and retention)** ([#1](https://github.com/vig-os/vigil/issues/1))
  - Records the OTLP/JSON Lines format, versioning stance, and the multi-process rotation design with its pre-mortem evidence
- CI extension runs `nix flake check -L` (clippy, fmt, nextest, doctests, docs) so `CI Summary` gates on the Rust checks; workaround for vig-os/devkit#1811 ([#18](https://github.com/vig-os/vigil/issues/18))

### Changed

### Deprecated

### Removed

### Fixed

### Security
