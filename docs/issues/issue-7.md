---
type: issue
state: closed
created: 2026-10-09T13:21:51Z
updated: 2026-10-12T23:10:58Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/7
comments: 11
labels: feature, priority:medium, effort:medium
assignees: none
milestone: 0.2.0 — metrics + traces
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:44.892Z
---

# [Issue 7]: [feat: metrics to metrics.jsonl (cumulative, Prometheus-OTLP compatible)](https://github.com/vig-os/vigil/issues/7)

A periodic reader + `MetricExporter` writing **one `MetricsData` per line** to `metrics.jsonl`.
- **Cumulative** temporality by default (Prometheus' OTLP receiver needs it).
- Instrument names follow OTel semconv; document the Prometheus mapping (`.` → `_`, unit suffixes).
- **Acceptance:** CI pushes a fixture through Collector `otlpjsonfile` → Prometheus `--web.enable-otlp-receiver` and asserts the expected series names and values.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 10, 2026 at 10:19 PM_

Blocked on the design decisions: ADR-0004 public API and feature flags (#37) and ADR-0003 metrics and traces (#38), then the API refactor #42 (it touches `init.rs`). Implement only the accepted design.

---

# [Comment #2]() by [gerchowl]()

_Posted on October 10, 2026 at 11:58 PM_

**Work this issue carries from ADR-0006 decision 3 (proposed in #63):** a promised time-first JSON key order, so that every rotated file's first 1000 bytes differ. The Collector's `otlpjsonfile` receiver, and every `fileconsumer`-based shipper, identifies files by those bytes. With today's alphabetical order, a 700-byte metric description delivered 3/150 points, with no error anywhere.

- Build on #64's feature-independent writer: the output order is fixed by vigil's code, never by `serde_json::Map`, whose order flips under `serde_json/preserve_order`.
- Keys first, in this order, then the rest alphabetically:
  - `Resource*` → `scope*`
  - `Scope*` → `logRecords`/`metrics`/`spans`
  - `LogRecord` → `observedTimeUnixNano`, `timeUnixNano`
  - `Metric` → its data field (`sum`/`gauge`/`histogram`/`exponentialHistogram`/`summary`)
  - `Sum`/`Gauge`/… → `dataPoints`
  - data point → `timeUnixNano`
  - `Span` → `spanId`, `endTimeUnixNano`
- Every line then has a per-line value within its first 128 bytes. Golden files change accordingly.
- The fingerprint test lives in #60: a 700-byte description and a 2 KiB body; first difference within 1000 bytes; run with `preserve_order` enabled.

Refs: #39


---

# [Comment #3]() by [gerchowl]()

_Posted on October 11, 2026 at 12:01 AM_

Sequencing (architect, during #42): ADR-0004 decision 4's `Config::install_opentelemetry_globals` (a `vigil_unstable` opt-in that installs the global meter/tracer providers) lands with the metrics/traces providers in #7/#8, not in #42. Implement it in whichever of #7/#8 merges second, once both providers exist, or in each for its own provider, per ADR-0004.

---

# [Comment #4]() by [gerchowl]()

_Posted on October 11, 2026 at 10:45 PM_

7a1 (d6 logs batch pins, d7 `service.instance.id`) merged via PR #88 (7c8aad3). 7a2 (the generic envelope pipeline + metrics exporter, d2/d3-exporter/d8/d11/d22/d23-exporter, plus two ADR amendments) has been dispatched; 7b (lifecycle + the `vigil::metrics` API) follows.

---

# [Comment #5]() by [gerchowl]()

_Posted on October 12, 2026 at 04:12 AM_

7a2 (the metrics data path) merged in PR #93 (8f8f844): a generic envelope pipeline shared by logs and metrics, plus the metrics exporter. ADR amendments: oversized data points are dropped (ADR-0003 d11), non-finite attribute doubles are sanitized (ADR-0003 d2), and ADR-0001 d5 defines one documented structural total order where time decides only last, which fixes SDK HashMap order leaking through timestamps. The log scope order on attribute ties changed (CHANGELOG). Next: 7b (lifecycle and public API).

---

# [Comment #6]() by [gerchowl]()

_Posted on October 12, 2026 at 01:29 PM_

7b1 (metrics storage and bounded pipeline lifecycle) merged in #106 (e4239ac). The shutdown-floor follow-up is #112. Next: 7b2a (facade, slot, d24/d23 recording), then 7b2b, then 7b3 (Prometheus e2e).

---

# [Comment #7]() by [gerchowl]()

_Posted on October 12, 2026 at 03:29 PM_

## Ruling 7b2b-d1 (architect): answers your BLOCKED on item 7 vs ADR-0004 d4. Round 1 continues; the block is architect-caused.

You're right to stop: the brief deviated from an accepted ADR without citing the authority for it. Here is the ruling.

- **ADR-0004 d4 describes the end state, and it stays unchanged.** In 1.0, `install_opentelemetry_globals` installs every provider vigil's pipeline builds: the meter provider (#7) and the tracer provider (#8). The tracer provider doesn't exist in the code yet, because #8 builds it (ADR-0003 d15/d16). "Install the tracer provider" therefore has nothing to act on in this PR, so there is no conflict to amend. It is incremental delivery of one decision across two issues, and the commitment is tracked on #8.
- **This PR** installs the meter provider at d16's install point, exactly as item 7 says.
  - The rustdoc tells the truth about the current code: "installs vigil's meter provider as the OpenTelemetry global meter provider." Do not claim a tracer provider.
  - Add one line in the PR body: "ADR-0004 d4's tracer-provider half is delivered by #8 (ruling 7b2b-d1)."
- **The architect** adds to #8's acceptance criteria:
  - extend `install_opentelemetry_globals` to the tracer provider at the same install point;
  - update its rustdoc to d4's wording;
  - add a test that a span from `opentelemetry::global::tracer` lands in `traces.jsonl` with the method, and not without it.

The ruling is recorded on #7 and #8. Everything else in `briefs/7b2b.md` holds. Write the receipt `/home/larsgerchow/.local/state/architect/vigil/receipts/7b2b-1.json` again at the end, overwriting it. **Last line** `DONE: <PR url>` or `BLOCKED: <reason>`.


---

# [Comment #8]() by [gerchowl]()

_Posted on October 12, 2026 at 07:09 PM_

Slices 7b2a (stable recording facade) and 7b2b (identity registry, global meter wiring, determinism; rulings 7b2b-d1/d2/d3) landed via #114 (merge cd54d60, includes #119). Next slice: 7b3. Tracer-provider globals are deferred to #8 per ruling 7b2b-d1. Follow-up nit: #121.

---

# [Comment #9]() by [gerchowl]()

_Posted on October 12, 2026 at 07:21 PM_

## Ruling 7b3-d1 (architect): answers your BLOCKED (architect-caused; round 1 continues and doesn't count)

You're right. ADR-0003 d24 (l.154) rejects names that start with a digit at the facade, and d21 (l.133) acknowledges that such rows exist only for the translation port. The `1x` row can't go through the real binary, so brief item 3 contradicted the ADR.

### Ruling
- The `1x` row, and any other row whose name d24's `validate_name` rejects, is **translation-only**. It stays in the translation tests (`series_names` against the otlptranslator v1.0.0 rule) and is **excluded** from real-binary conformance.
- Make the exclusion structural, not a skip list typed by hand. The fixture marks such a row `translation_only` with a reason that cites d24.
- **Guard the exclusion** so it can never hide a valid name. One test asserts that:
  - every `translation_only` row is rejected by `validate_name`;
  - every row `validate_name` accepts goes through the real Collector → Prometheus path.

  Mutant: mark a valid row `translation_only` → exit 101.
- Document it in the conformance README/script docstring: "rows the facade rejects (d24) are checked against the translator only".

Everything else in `briefs/7b3.md`, including the Architect amendments section, holds. **Last line** `DONE: <PR url>` or `BLOCKED: <reason>`. Overwrite receipt 7b3-1.json at the end.


---

# [Comment #10]() by [gerchowl]()

_Posted on October 12, 2026 at 07:27 PM_

## Ruling 7b3-d2 (architect): answers your second BLOCKED (architect-caused; round 1 continues and doesn't count)

You're right again. ADR-0004 d8 (l.249) makes the scope the declaring crate: `vigil::scope!()` expands to `Scope::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))` in the calling crate. The package is named `vigil-telemetry` (Cargo.toml), so an instrument declared in this package's example has the scope name `vigil-telemetry`. The brief's literal `otel_scope_name="vigil"` was wrong.

### Ruling
- The example declares its instruments with `vigil::scope!()`, exactly as users do. Don't hand-build a `Scope`.
- The oracle **derives** the expected `otel_scope_name` and `otel_scope_version` from the package metadata, never from a literal:
  - the script reads them with `cargo metadata --no-deps --format-version 1` (the package's `name` and `version`);
  - or the example writes `env!("CARGO_PKG_NAME")`/`env!("CARGO_PKG_VERSION")` into the fixture output it already produces.

  Today that gives `vigil-telemetry` / `0.0.0`. A later rename of the package or a version bump must not break the test.
- Fix every place in the brief and in your docs that says `otel_scope_name=vigil`. The conformance README text says the scope is the declaring crate's package name (ADR-0004 d8).
- Add a mutant: hardcode the oracle's scope name to `vigil` → exit 101.

Everything else in `briefs/7b3.md` holds, together with its Architect amendments and ruling 7b3-d1. **Last line** `DONE: <PR url>` or `BLOCKED: <reason>`. Overwrite receipt 7b3-1.json at the end.


---

# [Comment #11]() by [gerchowl]()

_Posted on October 12, 2026 at 11:10 PM_

Closed by the last slice, #122 (Prometheus end-to-end conformance, merged into dev at 0c51c9a), after #114 (metrics facade 7b2a+7b2b) and the earlier 7b1 slices. The review nits on #122 are filed as #128, which will be folded into #113.

