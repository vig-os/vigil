---
type: issue
state: open
created: 2026-11-08T08:52:51Z
updated: 2026-11-08T08:52:51Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/209
comments: 0
labels: feature
assignees: none
milestone: none
projects: none
parent: 207
children: none
synced: 2026-11-09T09:14:59.621Z
---

# [Issue 209]: [feat(python): PyO3 binding over the stable API — logging handler, spans, metrics, audit writer](https://github.com/vig-os/vigil/issues/209)

Part of #207 (feature-parity tracking). Companion to #208 (CLI).

### Description
A Python package over the stable vigil API, built with PyO3 and maturin, so Python programs write vigil logs, metrics, spans and audit records in process, through the same Rust implementation.

### Problem Statement
Python tools that change state outside the machine want a signed audit record at the exact point where the change happens, and ordinary logs and spans around it. Piping to a subprocess (#208) works, but loses in-process context: the current span, exceptions and the standard `logging` module.

### Proposed Solution
- `vigil.init("service", version=…)` returns the guard as a context manager; leaving it flushes, like `Guard::shutdown`.
- `vigil.LoggingHandler`, a `logging.Handler`, so existing `logging` calls become vigil log records carrying the current trace and span ids.
- `with vigil.span("name", **attrs):` for spans; exceptions inside are recorded on the span.
- `vigil.Counter`/`Histogram` mirroring the Rust instruments.
- Behind the `audit` extra: `vigil.audit.open(dir, key=…, schema=…)` and `writer.append(actor=…, action=…, **attrs)` with schema-checked typed attributes, raising on rejection.
- Only the stable API is wrapped: no `vigil_unstable` items and no OpenTelemetry types, per ADR-0004.
- Packaging: wheels via maturin for the platforms CI already builds, and a nix derivation (`buildPythonPackage` with maturin) in the flake.

### Alternatives Considered
- **A pure-Python port:** rejected in #207 (one implementation of the chain).
- **A pure-Python client of `vigil ingest` (#208):** no native build, and parity follows the CLI. A reasonable first step or fallback, but it keeps a subprocess and loses in-process span context.

### Additional Context
The first consumer is a small Python CLI managing items it sells on an online marketplace. Its audit-worthy events are already single commands: changing a listing's price, recording an outbound message sent after human approval, changing an item's status. Today they are only recorded as git commits. It would call `writer.append(...)` in exactly those commands and use `LoggingHandler` for the rest. Its parity row: audit and logs are needed; spans and metrics are nice to have.

### Impact
Additive: a new workspace crate/package, no change to the Rust API. CI gains a maturin build and a Python test step; the parity table in #207 gains the `python` column.

### Changelog Category
Added

