---
type: issue
state: closed
created: 2026-10-09T13:21:43Z
updated: 2026-10-09T15:47:46Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/3
comments: 2
labels: feature, priority:high, effort:medium
assignees: none
milestone: 0.1.0 — logs core
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:46.302Z
---

# [Issue 3]: [feat: OTLP/JSON Lines file exporter for logs](https://github.com/vig-os/vigil/issues/3)

An `opentelemetry_sdk::logs::LogExporter` that writes each export batch as **one line = one `LogsData`** to `logs.jsonl`, encoded by `opentelemetry-proto`'s serde (`with-serde`).

**Acceptance**
- Each line deserializes as `LogsData`; 64-bit fields (`timeUnixNano`, `observedTimeUnixNano`) are decimal strings; `traceId`/`spanId` hex; `severityNumber` an integer; keys lowerCamelCase.
- A record is written with **one** `write(2)` on an `O_APPEND` fd, so lines from concurrent processes never interleave.
- Golden-file tests pin the exact bytes for a fixed record set.
- No tonic, prost-build or network dependency in the default feature set.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 9, 2026 at 02:12 PM_

**Pre-mortem findings (probed 2026-10-09), added to acceptance:**
- ✅ `opentelemetry-proto` 0.33 `logs`+`gen-tonic-messages`+`with-serde` pulls no tonic/tokio/hyper/prost-build (only prost 0.14). Field encoding is correct (string int64, hex ids, int enums, lowerCamelCase, `{"stringValue"}`, base64 bytes). The SDK→proto path is public: `transform::logs::tonic::group_logs_by_resource_and_scope` + `ResourceAttributesWithSchema: From<&Resource>`. MSRVs ≤ 1.85; one `write` per line up to 2 GiB on Linux.
- **NaN/±Inf serialize as `{"doubleValue":null}` → the Collector silently drops the whole line** (all records in that batch). Sanitize non-finite doubles (spec spelling would be `"NaN"`/`"Infinity"`, but opentelemetry-proto's own reader rejects that, so pick one and test it against the Collector in #6). Add a golden case.
- **Golden byte tests would flake**: grouping goes through a `HashMap` (transform/logs.rs:174), so scope and resource-attribute order changes per run. Sort deterministically before writing, or compare by meaning.
- **`timeUnixNano` is always `"0"`**: the tracing bridge sets only `observedTimeUnixNano`. Fill `timeUnixNano` from the observed time when unset.
- **Test fixtures are invisible in the Nix build**: crane's source filter drops `tests/fixtures`. Add it to `extraSrcFiles` in `flake.nix`, or `include_str!`.
- The SDK's own records (`scope=opentelemetry_sdk`) reach the exporter; no recursion (the SDK suppresses itself).

---

# [Comment #2]() by [gerchowl]()

_Posted on October 9, 2026 at 03:47 PM_

Done in #23: an OTLP/JSON Lines `LogExporter` with deterministic output, non-finite doubles sanitized everywhere (verified lossless through otelcol-contrib 0.151.0), single-write `AppendFile` with pre-write newline repair, golden tests, no tonic/tokio.

