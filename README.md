# vigil

*Verifiable Integrity-Guarded Instrumentation & Logging* (V·I·G·I·L): the opinionated observability crate for vig-os Rust projects.

> **Pre-alpha.** The design is settled; the code is being built. Nothing here is usable yet. Track progress in the milestones.

## What it is

One crate, two layers:

- **Telemetry core** (every project). Your code uses [`tracing`](https://docs.rs/tracing) as usual; vigil bridges it into OpenTelemetry and writes **OTLP/JSON Lines** files that conform to the [OTel file-exporter spec](https://opentelemetry.io/docs/specs/otel/protocol/file-exporter/): one `LogsData` / `MetricsData` / `TracesData` per line, one signal per file, in the [OTLP/JSON encoding](https://opentelemetry.io/docs/specs/otlp/#json-protobuf-encoding) (64-bit ints as decimal strings, hex trace and span ids, integer enums, lowerCamelCase keys). Files rotate by size with age-based retention, and the rotation is safe when many processes write the same file. Loki (logs) and Prometheus (metrics) ingest OTLP natively.
- **`audit` feature** (opt-in). A separate, **lossless** audit trail of user actions on a device (who did what, when, and why) in the spirit of 21 CFR Part 11 §11.10(e). Records are still OTLP log records, hash-chained, with Merkle roots per segment and **ed25519-signed checkpoints**. They're built on [`tessera-core`](https://github.com/vig-os/tessera) primitives, so data provenance and audit provenance share one proof system.

```rust,ignore
// The target API (not implemented yet):
vigil::init("my-service")?;                  // logs + metrics + traces → $XDG_STATE_HOME/my-service/*.jsonl
tracing::info!(user = %id, "opened study");  // just tracing
vigil::audit::record(actor, "edit", &object, before, after, reason)?; // with feature = "audit"
```

## Why not an existing crate

`tracing`, `opentelemetry` and `opentelemetry-proto` are the foundation and are used as-is. What's missing upstream: opentelemetry-rust has **no OTLP file exporter**, and every rotating-file crate (`file-rotate`, `logroller`, `log2`, `flexi_logger`, …) is thread-safe but not **multi-process** safe.

## Development

Enter the pinned environment with `direnv allow` (or `nix develop`). `nix flake check` runs fmt, clippy, tests, doctests and docs. Changes enter through PRs to `dev`; `main` only takes release PRs.

## License

Apache-2.0.
