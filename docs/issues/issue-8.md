---
type: issue
state: open
created: 2026-10-09T13:21:53Z
updated: 2026-10-16T15:05:01Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/8
comments: 14
labels: feature, priority:medium, effort:medium
assignees: none
milestone: 0.2.0 — metrics + traces
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:44.539Z
---

# [Issue 8]: [feat: traces to traces.jsonl (tracing-opentelemetry spans)](https://github.com/vig-os/vigil/issues/8)

`tracing-opentelemetry` layer + a `SpanExporter` writing **one `TracesData` per line** to `traces.jsonl`.
- Sampling default: parent-based, always-on locally (files are cheap; shipping decides volume).
- Log records emitted inside a span carry its `traceId`/`spanId`.
- Traces SDK is **Beta** upstream: pin the version and cover it in the conformance test.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 10, 2026 at 10:19 PM_

Blocked on the design decisions: ADR-0004 public API and feature flags (#37) and ADR-0003 metrics and traces (#38), then the API refactor #42 (it touches `init.rs`). Implement only the accepted design.

---

# [Comment #2]() by [gerchowl]()

_Posted on October 10, 2026 at 11:58 PM_

**Work this issue carries from ADR-0006 decision 3 (traces part: `ResourceSpans`, `ScopeSpans`, `Span`) (proposed in #63):** a promised time-first JSON key order, so that every rotated file's first 1000 bytes differ. The Collector's `otlpjsonfile` receiver, and every `fileconsumer`-based shipper, identifies files by those bytes. With today's alphabetical order, a 700-byte metric description delivered 3/150 points, with no error anywhere.

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

_Posted on October 11, 2026 at 09:17 PM_

Architect decision (#7 split, 7a brief): the span parts of ADR-0003 d6 — explicit pins making `OTEL_BSP_*`, `OTEL_SPAN_*_LIMIT` and `OTEL_TRACES_SAMPLER` ineffective, plus their env tests — are deferred from #7 to #8. ADR-0003 l.164 gives d6 to #7, but no tracer exists before #8. #8's brief must include them.

---

# [Comment #5]() by [gerchowl]()

_Posted on October 12, 2026 at 04:38 AM_

Architect note for #8 (traces), from 7b planning: `Config::install_opentelemetry_globals` (ADR-0004 l.~133/167, unstable cfg) lands in 7b2 and installs the **meter provider only**, because no tracer exists before #8. #8 extends the same method to install the tracer provider, and its brief must include that and the rustdoc update.

---

# [Comment #6]() by [gerchowl]()

_Posted on October 12, 2026 at 03:29 PM_

**Acceptance addition (architect ruling 7b2b-d1, from #7):** #7/7b2b ships `Config::install_opentelemetry_globals` (`--cfg vigil_unstable`) installing the **meter** provider only, because the tracer provider is built here. ADR-0004 d4 requires both. #8 must therefore:
- extend `install_opentelemetry_globals` to install the `SdkTracerProvider` at the same install point (ADR-0003 d16: after `set_global_default` succeeds, and at the end of `layer()` after commit; a no-op when traces are off or failed);
- update its rustdoc to d4's "meter and tracer providers" wording;
- test, under `vigil_unstable`, that a span from `opentelemetry::global::tracer` lands in `traces.jsonl` with the method and not without it, and that it gets d16's sampler, limits and loss reporting.

---

# [Comment #7]() by [gerchowl]()

_Posted on October 13, 2026 at 12:33 AM_

## Ruling 8-d1 (architect): #8 traces plan, open questions OQ1–OQ20

The full plan is `briefs/8-plan.draft.md`. It covers obligations O1–O19, P1–P9 and Q1–Q10, slices 8a–8f, and a pre-mortem, all checked against dev fe9e46d and the pinned crates (tracing-opentelemetry 0.34.0, opentelemetry_sdk 0.33.0). These rulings close its open questions. Three of them change ADR text, and those amendments land **first**, as slice **8-0** (docs only, ADR-0003 amendment, Proposed until 8c merges). Design comes before code.

### Rulings that amend ADRs (slice 8-0)
- **OQ1, the d15 pending state.** Rule: the construction order removes the pending state.
  - `init` and `layer` resolve trace storage (ready or disabled) **before** they build the `SdkTracerProvider`. No span can reach a provider whose sink is unresolved, so the slot has three states, all reachable and all testable: **Ready / Disabled / Closed**.
  - Amend d15. Drop "pending" and its Mutex+Condvar sentence, and state the order instead. The paragraph's guarantee (nothing lost, nothing confused with a failure) then holds by construction.
  - Rejected: a Condvar for a state no code path can enter. That is untestable dead code.
- **OQ3, span overflow accounting.** Rule: mirror the logs amendment (ADR-0004 l.170).
  - Accepted spans are counted after `inner.on_end`, and spans that reached the exporter are counted at the exporter. The difference is drained on every successful flush.
  - At shutdown, the count reconciles with `BatchSpanProcessor.SpansDropped`, without double counting.
  - Amend d23's "queue overflow captured at shutdown" to "queue overflow, counted at each flush boundary and reconciled at shutdown (as logs)".
- **OQ10, `ParentBased(AlwaysOn)` with an unsampled remote parent.** Rule: keep `ParentBased(AlwaysOn)` and the standard W3C semantics.
  - A trace that an upstream service explicitly sampled out (`traceparent` flags `00`) is respected. Its spans are not exported, but log records still carry its valid ids.
  - Amend d16's "every span is recorded locally" to: "every local root span and every span in a sampled trace is recorded locally; an upstream's explicit sample-out (W3C flags `00`) is respected, so vigil never turns another service's 'not sampled' into 'sampled' downstream".
  - The README states it, and 8e tests it (a remote parent with flags `00` → no exported span, while the log line carries the ids).
  - Rejected:
    - **`AlwaysOn`:** it records, but it propagates sampled=1 downstream, overriding other services' decisions.
    - **A custom sampler plus a processor exporting RecordOnly spans:** new machinery to defeat a standard the user's other services rely on.
  - The owner may overrule this before 1.0.

### Rulings that need no ADR change (they become brief text)
- **OQ2, scope.** The tracer scope is `"vigil"` without a version, matching logs. `target` stays an attribute, and #9 adds `schemaUrl`.
- **OQ4, flush budget.** The traces flush runs on a scoped thread concurrently with logs (metrics already overlaps), and keeps a typed `Timeout` through the thread-local pattern (lifecycle.rs ~l.396–411). The whole flush stays within 5 s.
- **OQ5, three-signal `FlushError`.**
  - Source precedence is logs → metrics → traces, and the Display parts appear in that order.
  - The new texts are "at least N spans lost", "span export timed out" and "span export failed".
  - Keep #130's per-part rule. #131 (a count hiding a Timeout) is folded into 8b.
- **OQ6, final lines.** Mirror logs:
  - `Drop`: `vigil: span shutdown: {kind:?}; dropped spans: N; remaining spans may be lost`;
  - explicit `shutdown`: only on `Timeout`;
  - nothing when traces are disabled.
- **OQ7, after shutdown.** `AfterShutdown::on_new_span` gets its own once-flag: `vigil: span after shutdown; further spans will be dropped silently`. The OTel layer adds no warning of its own.
- **OQ8, `Config::traces(false)`.** No storage, no provider, no thread and no layer. Propagation then returns `NotRecorded`, and logs carry no trace ids. d5's "layer stays" applies only to a storage failure.
- **OQ9, `set_parent` check order.**
  1. No id → `NotRecorded`.
  2. No vigil `Recorded` marker → `NotRecorded`.
  3. No `traceparent` → `Missing`.
  4. A parse failure or all-zero ids → `Invalid`.
  5. From upstream: `AlreadyStarted` → `AlreadyStarted`; `LayerNotFound`/`SpanDisabled` → `NotRecorded`.

  Document that a missing header on an already-started span reports `Missing`.
- **OQ11, d17.**
  - **What may be shortened:** non-empty `stringValue`/`bytesValue` in span, event and link attributes, plus `status.message`. Never `name`, ids, `traceState` or keys.
  - **The stub:** exactly d17's list plus `vigil.truncated`, `vigil.dropped` and `vigil.original_size`, with `status.message` cut to fit.
  - **If the stub itself does not fit:** an explicit error, as logs does; those spans count as lost.
- **OQ12, lockfile.** Two packages are added (`web-time 1.1.0` is wasm-only). Correct ADR-0004 d7's "1 new crate" to "1 new crate on supported targets; `web-time` is a wasm-only lock entry" in **8-0**, because docs must be true. The flake powerset comment is updated in 8a.
- **OQ13.** Pin the `Debug` output of `span_batch_config` with the two fields the sync processor ignores normalized, plus the behavioural child-process environment test.
- **OQ14.** `with_level(false)` is set explicitly and pinned.
- **OQ15.** #8 asserts that log records carry span ids in its d15 test, and removes the "spans do not populate IDs" text (init.rs, README). #26 keeps d20 and the edge-case correlation suite.
- **OQ16.** `vigil::span_export::OtlpJsonSpanExporter`, parallel to `metric_export`.
- **OQ17.** `install_opentelemetry_globals` does **not** set a global propagator, because ADR-0004 names only providers. The rustdoc says so.
- **OQ18.** `VIGIL_TRACES` follows the same grammar as `VIGIL_METRICS`.
- **OQ19.** The `Recorded` marker is inserted by the d18 `SpanTracker` (added in 8d, used in 8e), one layer behind the OTel filters.
- **OQ20.** The README notes that `OTEL_BSP_EXPORT_TIMEOUT`/`OTEL_BSP_MAX_CONCURRENT_EXPORTS` do not apply to the synchronous processor.

### Order
1. **8-0:** ADR-0003 amendment (d15 order, d16 sampled-out, d23 per-flush overflow) and the ADR-0004 d7 crate-count fix. Docs only, written by claude sonnet.
2. **8a → 8b → 8c → 8d → 8e → 8f**, serial, each with a fresh brief check against merged code before dispatch. 8f's Renovate and supply-chain half may run in parallel with 8a.


---

# [Comment #8]() by [gerchowl]()

_Posted on October 13, 2026 at 01:43 AM_

Slice 8-0 has merged as #134 into dev at de0f19c, after 2 rounds. ADR-0003 d4, d5, d15, d16 and d23 and ADR-0004 d7 are amended per ruling 8-d1. Next is slice 8a, the span data path, which gets a fresh brief check against the merged code before dispatch.

---

# [Comment #9]() by [gerchowl]()

_Posted on October 13, 2026 at 01:59 AM_

**Ruling 8-d2 (architect, from the 8a brief check against de0f19c):** spans retain batch order, like log records. ADR-0001 d5's amendment lists what is sorted (resources, scopes, metrics, data points) and says "Log records retain batch order", but it does not mention spans. The exporter sorts resources, scopes and attributes and leaves spans in batch order. Slice 8a amends that sentence to "Log records and spans retain batch order".

Also settled for 8a, with no ADR change:
- A stub that does not fit fails the whole batch, as logs does (`fit_record` → `bounded_lines`): nothing is written, and every span in the batch counts as dropped.
- The ordering CI lanes in ci-extension.yml gain the `traces` feature, so ADR-0003 d22's two-lane tests actually run.

---

# [Comment #10]() by [gerchowl]()

_Posted on October 13, 2026 at 04:01 AM_

Slice **8a** merged in #135 (9bc7682). It adds the `traces` feature (on by default) and `vigil::span_export::OtlpJsonSpanExporter` (unstable), with d17 bounding, the trace key order and determinism in both map lanes, and passes Collector conformance. ADR-0001 d5 is amended per 8-d2. Reviewed over 2 rounds by fresh falsifiers: about 25 runtime mutants, each made a test fail.

Carried into **8b** from the final review:
- the test comment at span_export.rs ~:394 implies the SDK-tied scopes exercise the `field_order` arms, but only the hand-built proto with a different `droppedAttributesCount` does;
- `shortened_attributes_include_sorted_markers` is not matched by the `--lib ordered` filter, so the preserve_order lane never runs it;
- a scope with a NaN-valued attribute never equals itself in the SDK, so each of its spans gets its own `scopeSpans`. The output stays deterministic, but the README/rustdoc should state it as a known limit, with a test.

Next: 8b, trace loss accounting (with #131).

---

# [Comment #11]() by [gerchowl]()

_Posted on October 13, 2026 at 05:42 AM_

**Ruling 8b-d1 (architect):** #139's size cap rises from 450 to 520 non-test lines. Don't split.

The overage (461 lines, mid fix round) comes from fix-round items the architect added: the two-variant queue-signal type, and un-folding metrics per #131. The PR is still one concern, per-signal loss accounting. Moving the `QueueCounts` seam into a preparatory PR would mean reviewing the same lines twice. Each round still gets a fresh falsifier, so the review stays tractable. Above 520, the PR splits.

---

# [Comment #12]() by [gerchowl]()

_Posted on October 13, 2026 at 10:37 AM_

Slice **8b** merged in #139 (780f349), after 3 fix rounds and ruling 8b-d1 (cap raised to 520; final size about 450 non-test lines). It adds per-signal trace loss accounting:
- one `QueueCounts` seam shared by logs and traces;
- per-flush overflow drain, reconciled with `BatchSpanProcessor.SpansDropped` at shutdown without double counting;
- each signal's event name and field defined once;
- typed `Timeout` through the generic flush;
- `ReportingSpanProcessor<P>`, plus `ReportingSpanExporter` in `trace_pipeline`.

Also in this PR: #131's per-part Display rule for every signal, and the three 8a carry-overs. #131 is closed. A fresh falsifier reviewed each round, and every mutant listed was caught at runtime.

Next: **8c**, the tracer provider and OTel layer wiring.

---

# [Comment #13]() by [gerchowl]()

_Posted on October 13, 2026 at 01:01 PM_

8c-1 merged: PR #144 at f1b2f6e. It adds the tracer pipeline builders (span_batch_config, span_limits, TraceStorage Ready/Disabled/Closed, build_tracer with ParentBased(AlwaysOn) and explicit limits), the OTel layer config (scope "vigil", with_level(false)) and the spans_or_error filter; 2 rounds. Disabled storage builds no counting wrappers at all (d15/d5). Next is 8c-2: init/Config/Guard wiring, flush and shutdown, README, end-to-end tests, and the d16 global-tracer test. Constraint for 8c-2: storage must resolve to Disabled before build_tracer (OQ1); nothing may switch it to Disabled afterwards.

---

# [Comment #14]() by [gerchowl]()

_Posted on October 16, 2026 at 03:05 PM_

8c-2 merged: #149, at a5b710f. `init` and `Config::layer` now export spans to `traces.jsonl`, behind `Config::traces`/`VIGIL_TRACES`. Guard flushes traces concurrently (a happens-before proof) and shuts down with the SpansDropped capture. `TraceStorage::close` never blocks. Log records carry span ids. 3 rounds. Follow-up #150 (the same close-blocking flaw in metrics). Next: 8d (open spans at shutdown; drop OQ7, which moved into 8c-2), 8e, 8f.

