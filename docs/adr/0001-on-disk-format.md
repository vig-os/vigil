# ADR-0001: On-disk format: OTLP/JSON Lines

- **Status:** Accepted
- **Date:** 2026-10-09
- **Issues:** [#1](https://github.com/vig-os/vigil/issues/1), [#3](https://github.com/vig-os/vigil/issues/3), [#6](https://github.com/vig-os/vigil/issues/6)

## Context

Fleet tools need local, durable telemetry that a collector can ship later. The decision to adopt the OpenTelemetry file format rather than a home-grown envelope was taken in [gerchowl/g-fleet#355](https://github.com/gerchowl/g-fleet/issues/355). Facts checked against the live specs on 2026-10-09:

- The [file-exporter spec](https://opentelemetry.io/docs/specs/otel/protocol/file-exporter/) has status **Development**. It describes only the serialization: a JSON Lines file (UTF-8, `\n` separator, preferred extension `jsonl`); only the top-level `TracesData`, `MetricsData` and `LogsData` objects; "files must contain exactly one type of data"; no ordering guarantee, not even monotonic timestamps. It calls itself "the first version of the serialization scheme".
- [OTLP/JSON](https://opentelemetry.io/docs/specs/otlp/#json-protobuf-encoding) is **Stable** for traces, metrics and logs: proto3 JSON mapping, except that `traceId`/`spanId` are hex and enums are integers; keys are lowerCamelCase; 64-bit integers are decimal strings; receivers MUST ignore unknown fields.
- opentelemetry-rust has no file exporter (only the OTLP network exporter and a human-readable stdout one).

## Decision

1. **Format.** OTLP/JSON Lines. One line is one complete `LogsData`, `MetricsData` or `TracesData`, terminated by `\n`, containing no raw newline. One signal per file.
2. **Location.** `$XDG_STATE_HOME/<service>/logs.jsonl`, `metrics.jsonl`, `traces.jsonl` (fallback `~/.local/state/<service>/`, as implemented in #5). Rotated segments are described in [ADR-0002](0002-rotation-and-retention.md).
3. **Encoding.** Exactly OTLP/JSON: 64-bit integers as decimal strings, hex `traceId`/`spanId`, integer enums, lowerCamelCase keys, `bytesValue` as base64.
4. **Serializer.** `opentelemetry-proto` with features `logs`/`metrics`/`trace` + `gen-tonic-messages` + `with-serde`, without the tonic transport. It is the official encoder and has the SDK-to-proto transforms. Probed weight ([#3](https://github.com/vig-os/vigil/issues/3), 0.33): no tonic, tokio, hyper or prost-build; only `prost` 0.14; MSRV ≤ 1.85. We do not hand-roll an encoder.
5. **Deterministic output.** The transforms group through a `HashMap`, so scope and resource-attribute order varies per run. Before writing, vigil sorts scopes and attributes by key (and resources by their sorted attributes), so equal input gives equal bytes and golden-file tests are stable.
6. **Non-finite doubles.** `NaN` and `±Inf` serialize as `{"doubleValue":null}`, which the Collector rejects, dropping every record in the line. vigil sanitizes them before writing. The exact encoding is pinned by [#3](https://github.com/vig-os/vigil/issues/3) after testing it against the Collector ([#6](https://github.com/vig-os/vigil/issues/6)); the spec spelling (`"NaN"`, `"Infinity"`) is not readable by `opentelemetry-proto`'s own reader, so the choice needs that test.
7. **Fill `timeUnixNano`.** The tracing bridge sets only `observedTimeUnixNano`; vigil copies it into `timeUnixNano` when unset, so readers never see `"0"`.
8. **Conformance oracle.** "Conformant" means the Collector-contrib **`otlpjsonfile` receiver** ingests our files and a round trip through its `file` exporter is lossless **by meaning** ([#6](https://github.com/vig-os/vigil/issues/6)). Our own parser agreeing with our own writer proves nothing (the proto reader accepted a 2-byte `traceId`). The Collector drops zero/empty fields, renders `intValue: 42` as `"42"`, and reorders across rotation, so the comparison is semantic, not byte-wise.
9. **Shipping stays outside the crate.** vigil writes files only. Loki ≥ 3 and Prometheus ≥ 3 ingest OTLP natively; the local agent or Collector forwards. No network exporter, no tonic in the default feature set.

### Versioning stance while the file-exporter spec is Development

- **What we promise readers:** every line is valid OTLP/JSON as defined by the Stable OTLP spec, in the one-signal-per-file layout above. Readers should ignore unknown fields, as OTLP requires of them.
- **What we do not promise:** that the Development file-exporter spec stays as it is today, or that field order, whitespace or attribute order is stable across vigil versions (only that it is deterministic within one version).
- **Absorbing a spec change:** a change that is additive or only restricts the layout is taken in a minor release (pre-1.0: `0.x`), with a `### Changed` entry in `CHANGELOG.md` naming the spec revision. Files already on disk are not rewritten; readers cope because the line payload is OTLP/JSON, which is Stable. A change to the envelope itself (for example a different line framing) is a breaking release and bumps the minor in `0.x`, the major from 1.0, with a changelog entry and an ADR superseding this one.
- **Semconv pinning:** where we emit conventions that are themselves Development (GenAI), we pin a commit and stamp it as the scope's `schemaUrl`, so a reader can tell which revision a file follows.
- **After the spec stabilises:** we re-verify against the stable text, mark this ADR with the confirmed revision, and drop the caveat.

## Consequences

- Any OTLP-aware tool reads vigil files without a vigil-specific parser; the Collector is the test oracle.
- Output is larger than a bespoke compact envelope (resource and scope repeat on every line). Rotation bounds the cost.
- Line order is not chronological across processes or batches, per spec. Readers must not assume it; the segment-level reader in #4 orders segments, not records.
- vigil depends on a crate whose JSON edge cases (non-finite doubles, loose id lengths) it must guard itself.

## Alternatives considered

- **Home-grown JSONL envelope** (s1-mcp's `calls.jsonl`): no ecosystem, every consumer needs a bespoke parser. Rejected in g-fleet#355.
- **Hand-written serializer:** duplicates the official encoder and drifts from it. Rejected.
- **OTLP/protobuf files:** not line-oriented, not greppable, not covered by the file-exporter spec.
- **Several signals in one file:** forbidden by the spec and by the `otlpjsonfile` receiver's expectations.
- **A network exporter in the crate:** shipping is a deployment concern ([g-fleet#355](https://github.com/gerchowl/g-fleet/issues/355), addendum); the file is the durable local copy.

## References

- [OTel file-exporter spec](https://opentelemetry.io/docs/specs/otel/protocol/file-exporter/) (Development)
- [OTLP/JSON encoding](https://opentelemetry.io/docs/specs/otlp/#json-protobuf-encoding) (Stable)
- [vig-os/vigil#1](https://github.com/vig-os/vigil/issues/1), [#3](https://github.com/vig-os/vigil/issues/3) (pre-mortem: serde weight, NaN, ordering, `timeUnixNano`), [#6](https://github.com/vig-os/vigil/issues/6) (Collector conformance)
- [gerchowl/g-fleet#355](https://github.com/gerchowl/g-fleet/issues/355) (decision, ecosystem table, shipping addendum)
