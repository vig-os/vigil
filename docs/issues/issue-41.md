---
type: issue
state: open
created: 2026-10-10T22:18:14Z
updated: 2026-10-11T00:50:38Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/41
comments: 1
labels: feature, priority:medium, effort:medium
assignees: none
milestone: 0.4.0 — adoption
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:36.730Z
---

# [Issue 41]: [feat: optional push feature (OTLP/HTTP to a local agent), files stay the durable copy](https://github.com/vig-os/vigil/issues/41)

Implement the optional `push` feature as decided in ADR-0006 (#39). Behind a cargo feature: OTLP/HTTP export to a local agent (e.g. Alloy `otelcol.receiver.otlp`) for logs, metrics and traces. Files remain the durable copy (a tee). Backpressure, retry and "agent down" behaviour as the ADR specifies. No network dependencies in the default feature set (asserted by a test). Conformance: a CI leg that runs an OTLP/HTTP receiver (otelcol-contrib `otlp` receiver → `file` exporter) and compares the pushed data with the files by meaning.


## Specification (ADR-0006 decisions 4–6)

The full specification is in [this comment](https://github.com/vig-os/vigil/issues/41#issuecomment-6103532264) and ADR-0006. Acceptance additionally requires:
- **Port-squatting limit, documented** in `push`'s rustdoc (`Config::push`, `Push`) **and** the README: while the local agent is not listening, any local user can bind its loopback port (4318 is above 1024) and receive every pushed line and header, including an `authorization` token. That bypasses the files' `0600`/`0700` permissions. The documented mitigations:
  - use the file shipper on hosts where that matters;
  - on Linux, run the agent on a privileged loopback port (below 1024); this is no mitigation on macOS;
  - scope header tokens to the local agent, never a backend credential.

  The fix is #65.
- **Endpoint:** a loopback IP literal over `http://` only (`InitErrorKind::InvalidPushEndpoint` from code; one warning and push disabled from the environment).
- **No proxy and `max_redirects = 0`**, each with a test.
- **Configuration:** `VIGIL_PUSH_ENDPOINT`, `VIGIL_PUSH_HEADERS`, `VIGIL_PUSH_TIMEOUT_MS` and `VIGIL_PUSH=off`, with the precedence in ADR-0006 decision 6. `OTEL_EXPORTER_OTLP_*` is not read.
- **The `Cargo.toml` check in `tests/deps.rs`:** `ureq` is optional and only `push` enables it, and `default` has no `push`. Shown failing once.

---

# [Comment #1]() by [gerchowl]()

_Posted on October 10, 2026 at 11:58 PM_

**Specification from ADR-0006 decisions 4–6 (proposed in #63).** Implement exactly this; the ADR has the evidence.

**Dependencies and build**
- `ureq = { version = "3", default-features = false, optional = true }`, enabled only by `push = ["dep:ureq"]`. That is +6 crates (ureq, ureq-proto, http, httparse, base64 0.23, utf8-zero) and no TLS, tokio or hyper.
- `tests/deps.rs` keeps its forbidden list and adds an offline check of `Cargo.toml`:
  - `ureq` is `optional`;
  - only `push` enables it;
  - `default` does not contain `push`.

  This is needed because `Cargo.lock` lists optional dependencies too. Show it failing once with `push` in `default`.

**Transport**
- Each line written to a file is POSTed byte-for-byte, with `Content-Type: application/json`, to `<base>/v1/logs`, `/v1/metrics` or `/v1/traces`. No compression.
- One `vigil-push` thread per pipeline, with one keep-alive connection.
- `ureq` agent:
  - proxy explicitly `None` (ureq's default reads the environment);
  - `max_redirects = 0`;
  - a global per-request timeout (default 10 s).

**Tee, queue, retry, shutdown**
- **Tee:** the file write comes first, then a non-blocking enqueue. The line is enqueued even if the file write failed. Per ADR-0003 decision 23: a lost **log or span** line counts in `FlushError::lost(Signal::Logs)` or `lost(Signal::Traces)`; a lost **metrics** line sets kind `Failed`, is reported on stderr in data points, and is **not** counted in `lost(Signal::Metrics)`. *(Edited 2026-10-11 to align with accepted ADR-0003.)*
- **Queue:** bounded in bytes (`Push::queue_bytes`, default 16 MiB); when full, drop the **oldest** queued line. The in-flight line is not evicted.
- **Retry:**
  - connection errors, timeouts, 429/502/503/504: exponential backoff (500 ms, ×2, 30 s cap, full jitter), honouring `Retry-After` up to the cap;
  - a line is dropped 60 s after its first attempt;
  - any other status: dropped at once, warned once per status;
  - `partialSuccess`: rejected items count as undelivered.
- **Shutdown:** the SDK flush into the files comes first. The push worker then gets the rest of the same budget, every request timeout is capped by the remaining budget, and at the deadline the queue is dropped. Test: an agent that accepts TCP and never answers must not stretch a 2 s shutdown (the prototype took 18.9 s without the cap, 2.02 s with it).
- **Reporting:** undelivered pushes are not in `FlushError::lost` (the files hold them). They are reported on stderr through the runtime-loss rate limiter and once at shutdown (count, endpoint, state directory). Header values are never printed. `Debug` for `Push` redacts them.

**Security (decision 5)**
- The endpoint must be `http://` with a loopback **IP literal** (`127.0.0.0/8` or `[::1]`). Refuse host names, `localhost`, IPv4-mapped forms and `https://`. From code: `InitErrorKind::InvalidPushEndpoint`. From the environment: one warning, and push is disabled.
- The rustdoc and README state the 1.0 limit: any local user can bind the port while the agent is down and read lines and headers. Mitigations:
  - use the file shipper on hosts where that matters;
  - on Linux, run the agent on a privileged loopback port;
  - scope header tokens to the local agent.

  The fix is #65.

**API and environment (decision 6)**
- `Config::push(Push)`, with `Push::local()`, `Push::endpoint(&str)`, `.header(name, value)`, `.timeout(Duration)` and `.queue_bytes(usize)`. Only std types; private fields; `Debug + Clone + Send + Sync`.
- Environment variables are read only when push is configured in code, and an empty value counts as unset:
  - `VIGIL_PUSH_ENDPOINT`: used only with `Push::local()`;
  - `VIGIL_PUSH_HEADERS`: `k=v,…`, percent-decoded; a builder header with the same name wins;
  - `VIGIL_PUSH_TIMEOUT_MS`: a builder value wins;
  - `VIGIL_PUSH=off`: the only override of code; any other value warns.
- `OTEL_EXPORTER_OTLP_*` is deliberately not read.

**Conformance:** a CI leg runs otelcol-contrib's `otlp` receiver → `file` exporter, pushes from `vigil::init`, and compares the pushed records with the files by meaning. Add agent-down and hung-agent cases that assert the application is not slowed and the files are complete.

Refs: #39



