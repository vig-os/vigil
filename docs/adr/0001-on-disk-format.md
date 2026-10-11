# ADR-0001: On-disk format: OTLP/JSON Lines

- **Status:** Accepted
- **Date:** 2026-10-09
- **Amended by [ADR-0006](0006-shipping.md)** (Accepted 2026-10-11): decision 9 is superseded for the optional `push` feature; decision 5 and the versioning stance gain a fixed time-first JSON key order.
- **Amended:** 2026-10-11, [#50](https://github.com/vig-os/vigil/issues/50): the new section "Versioning stance at 1.0" states what 1.0 promises readers and what counts as a vigil major. It collects existing decisions and newly states one principle (a major is a renamed, removed or re-meant attribute; a purely additive semconv pin move is a minor). It builds on the stance below, which stays the record of how the Development spec is absorbed.
- **Amended:** 2026-10-12, [#7](https://github.com/vig-os/vigil/issues/7): the 1.0 bounding promise distinguishes shortened log records and spans from dropped metric data points.
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
5. **Amendment (2026-10-11, #64):** equal input gives equal bytes regardless of consumer feature unification, including `serde_json/preserve_order`; final object ordering is owned by vigil’s shared writer. *(Extended by [ADR-0006](0006-shipping.md) decision 3: a fixed time-first JSON key order.)* **Deterministic output.** The transforms group through a `HashMap`, so scope and resource-attribute order varies per run. Before writing, vigil sorts scopes and attributes by key (and resources by their sorted attributes), so equal input gives equal bytes and golden-file tests are stable.
6. **Non-finite doubles.** `NaN` and `±Inf` serialize as `{"doubleValue":null}`, which the Collector rejects, dropping every record in the line. vigil sanitizes them before writing. The exact encoding is pinned by [#3](https://github.com/vig-os/vigil/issues/3) after testing it against the Collector ([#6](https://github.com/vig-os/vigil/issues/6)); the spec spelling (`"NaN"`, `"Infinity"`) is not readable by `opentelemetry-proto`'s own reader, this is an **accepted deviation** from round-trip compatibility with that reader. The Collector accepts these spellings, as the conformance test verifies.
7. **Fill `timeUnixNano`.** The tracing bridge sets only `observedTimeUnixNano`; vigil copies it into `timeUnixNano` when unset, so readers never see `"0"`.
8. **Conformance oracle.** "Conformant" means the Collector-contrib **`otlpjsonfile` receiver** ingests our files and a round trip through its `file` exporter is lossless **by meaning** ([#6](https://github.com/vig-os/vigil/issues/6)). Our own parser agreeing with our own writer proves nothing (the proto reader accepted a 2-byte `traceId`). The Collector drops zero/empty fields, renders `intValue: 42` as `"42"`, and reorders across rotation, so the comparison is semantic, not byte-wise.
9. *(Superseded for the `push` feature by [ADR-0006](0006-shipping.md); the default build is unchanged.)* **Shipping stays outside the crate.** vigil writes files only. Loki ≥ 3 and Prometheus ≥ 3 ingest OTLP natively; the local agent or Collector forwards. No network exporter, no tonic in the default feature set.

10. **Bounded log lines (#30).** Collector-contrib 0.151.0's default `otlpjsonfile` receiver silently drops lines longer than 1 MiB. Review reproduced only 4/2000 records arriving with ~4 KB records (2.3 MB lines), versus 1024/1024 with 1500-byte padding and 13/1024 with 2200-byte padding. The exporter defaults to `max_line_bytes = 1_000_000` JSON payload bytes, excluding the newline; `with_max_line_bytes` configures it, clamped to 1..=1,048,575. Batches split at record boundaries with repeated resource/scope envelopes and deterministic ordering. Oversized single records shorten the largest body or attribute string (including nested values), cutting only the escaped-byte overflow at UTF-8 boundaries. Attribute keys, `eventName`, scope and resource fields are never truncated; byte values retain valid base64 boundaries. Multiple scopes pack into each line, and only resource/scope metadata is copied while splitting. They carry `vigil.truncated = true` and `vigil.original_size` (the original single-record line size including its envelope). If immutable keys, `eventName`, attribute count or other non-string record data still exceeds the budget, that record alone becomes a diagnostic stub retaining timestamps, severity, trace/span IDs and scope, with body `vigil: record dropped: <N> bytes exceeds max_line_bytes <cap>` and attributes `vigil.truncated`, `vigil.dropped`, and `vigil.original_size`. A bounded `vigil.dropped_reason` preserves the original string body when space permits, including small messages on records with oversized keys or event names. Healthy neighbors are exported normally. Dropped stubs enter the same rate-limited cumulative runtime-loss summary as export failures. A budget too small for the resource/scope envelope and diagnostic identity still returns an explicit error without emitting an oversized line. Conformance includes 1024 ~4 KB tracing records and a 3 MiB tracing body through `vigil::init`, plus an unshrinkable record whose diagnostic stub must survive the Collector.

    **Amendment (2026-10-11, #64):** log AnyValues have a maximum of 16 array/map edges from a root value at depth zero (`MAX_LOG_VALUE_DEPTH`), keeping OTLP wrappers within the default JSON reader depth. A deeper body or record attribute causes that record to be omitted and counted in the cumulative runtime-loss diagnostics; healthy neighbors remain exportable. The depth check precedes recursive SDK conversion, cloning, normalization and JSON projection. Counted loss is chosen instead of a stub: discovering the original byte size or copying the deep value for a stub would itself require unbounded recursion. Direct typed audit/log encoding refuses over-deep values before projection; audit context retains its own depth-16 validation. The exporter borrows SDK input and does not own the caller’s SDK value destruction.

### Versioning stance while the file-exporter spec is Development

- **What we promise readers:** every line is valid OTLP/JSON as defined by the Stable OTLP spec, in the one-signal-per-file layout above. Readers should ignore unknown fields, as OTLP requires of them.
- **What we do not promise:** that the Development file-exporter spec stays as it is today, or that field order, whitespace or attribute order is stable across vigil versions (only that it is deterministic within one version). *Amended by [ADR-0006](0006-shipping.md) decision 3:* the time-first key order is promised (file shippers identify files by their first bytes); only the order of the remaining keys is not.
- **Absorbing a spec change:** a change that is additive or only restricts the layout is taken in a minor release (pre-1.0: `0.x`), with a `### Changed` entry in `CHANGELOG.md` naming the spec revision. Files already on disk are not rewritten; readers cope because the line payload is OTLP/JSON, which is Stable. A change to the envelope itself (for example a different line framing) is a breaking release and bumps the minor in `0.x`, the major from 1.0, with a changelog entry and an ADR superseding this one.
- **Semconv pinning:** where we emit conventions that are themselves Development (GenAI), we pin a commit and stamp it as the scope's `schemaUrl`, so a reader can tell which revision a file follows.
- **After the spec stabilises:** we re-verify against the stable text, mark this ADR with the confirmed revision, and drop the caveat.

### Versioning stance at 1.0

*Added 2026-10-11 ([#50](https://github.com/vig-os/vigil/issues/50)). This section collects decisions that already stand in ADR-0001, [ADR-0002](0002-rotation-and-retention.md), [ADR-0004](0004-public-api-and-stability.md), [ADR-0005](0005-audit-trail.md) and [ADR-0006](0006-shipping.md), with one exception: the principle in rule 2 (attribute renames, removals and changes of meaning are a major; a purely additive pin move is a minor) is **newly stated here by #50**, not an earlier decision. The README "Stability" section repeats it for users.*

vigil goes from 0.0.0 on `dev` straight to a published 1.0.0 ([ADR-0004](0004-public-api-and-stability.md) Context), so there is no 0.x: the first published file format is the one promised here, and the "minor in `0.x`" wording of the stance above does not apply to it. From 1.0.0 a breaking change is a **major**.

**What vigil promises readers of its files** (against the specs as checked on 2026-10-09, see Context):

- Every line is one complete `LogsData`, `MetricsData` or `TracesData` object in **OTLP/JSON**, as defined by the Stable OTLP spec, terminated by `\n`, one signal per file (decision 1).
- The field encoding is exactly OTLP/JSON: 64-bit integers as decimal strings, hex `traceId`/`spanId`, integer enums, lowerCamelCase keys, base64 `bytesValue` (decision 3). `NaN` and `±Inf` are written in the spellings of decision 6, `timeUnixNano` is never `"0"` (decision 7), and no line exceeds `max_line_bytes`, with oversized records shortened or replaced by a diagnostic stub as marked in decision 10.
  **Amendment (2026-10-12, #7):** the preceding shortening/stub promise applies to log records (decision 10) and spans (ADR-0003 decision 17). Metric data points are never shortened: oversized points are dropped and reported as specified by ADR-0003 decision 11's amendment, because their attributes are series identity.
- The JSON keys come in the fixed **time-first order** of [ADR-0006](0006-shipping.md) decision 3, because file shippers identify files by their first bytes.
- Readers ignore unknown fields, as OTLP requires of them. An additive change to the spec is taken in a minor release (see below).

**What vigil does not promise**: that the Development file-exporter spec stays as it is today; the order of the remaining keys, whitespace or attribute order across vigil versions (deterministic within one version only); that lines are in chronological order across processes or batches (see Consequences); the bytes of a Collector's copy of a file.

**What counts as a vigil major** (a vigil 2.0.0, with a changelog entry and an ADR that supersedes this one):

1. **A breaking on-disk change**: anything that makes a conforming reader of the 1.0 files misread, reject or lose data from later files. This covers a change to the envelope (line framing, the one-signal-per-file layout, a payload that is no longer OTLP/JSON), to the field encoding of decisions 3, 6, 7 and 10, and to the time-first key order of ADR-0006 decision 3, which that ADR makes a contract.
2. **Renaming, removing or changing the meaning of an attribute vigil emits** (newly stated by #50). This is rule 1's "misread … lose data" test applied to attributes: a dashboard or query on the old name or meaning breaks. It holds whether the change comes from vigil or from a semantic-convention revision vigil adopts under `schemaUrl` ([#9](https://github.com/vig-os/vigil/issues/9)). A purely additive move is not a major (see "Semantic conventions" below).
3. **An OpenTelemetry bump that changes stable behaviour** ([ADR-0004](0004-public-api-and-stability.md) decision 1). A bump that changes nothing stable is a minor, or a patch if upstream shipped only a patch. If a bump would change the behaviour users write code against (the special span fields `otel.name`, `otel.kind`, `otel.status_code` and `otel.status_description`, the span-status and error mapping, the span fields on log records, propagation semantics), vigil translates it in its own code, or the bump waits for a major. If it changes bytes on disk, rules 1 and 2 decide whether it is a minor or a major.

**How upstream spec changes are absorbed**:

- **The file-exporter spec** (Development): a change that is additive or only restricts the layout is taken in a **minor**, with a `### Changed` entry in `CHANGELOG.md` naming the spec revision. Files already on disk are not rewritten; readers cope because the payload is Stable OTLP/JSON. A change to the envelope is a **major** (rule 1).
- **OTLP/JSON** (Stable): an additive change is taken in a minor. A change that breaks the Stable encoding is a major (rule 1).
- **Semantic conventions**: where vigil emits conventions that are themselves Development (GenAI, MCP), it pins a commit and stamps it as `schemaUrl`, so a reader can tell from the file which revision it follows. The mechanics of the pin and its bumps are decided in [#9](https://github.com/vig-os/vigil/issues/9). By the principle of rule 2, a purely additive move (a new revision, new attributes, a moved `schemaUrl` string) is a **minor**, with a changelog entry naming the old and new `schemaUrl`; a revision that renames, removes or changes the meaning of an attribute vigil emits is a **major**. Before #9 lands vigil stamps no `schemaUrl`.
- **After the spec stabilises**: unchanged. We re-verify against the stable text, mark this ADR with the confirmed revision, and drop the caveat.

**The audit format is frozen separately** ([ADR-0005](0005-audit-trail.md) decision 12). Audit records are OTLP log lines, so this stance applies to their envelope. But their hashes cover a value-level canonical encoding, not the JSON bytes (ADR-0005, Alternatives considered), so a change in how the lines are serialized does not stop old trails from verifying. From 1.0.0 every vigil 1.x release verifies every trail written by any vigil ≥ 1.0.0 (`audit.v` = `1`) and writes v1 by default; any change to what is written is a v2 with its own ADR; making v2 the default is a major. A shipper that rewrites attribute values is outside that promise.

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
