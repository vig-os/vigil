---
type: issue
state: closed
created: 2026-10-09T13:21:47Z
updated: 2026-10-09T16:43:38Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/5
comments: 2
labels: feature, priority:high, effort:medium
assignees: none
milestone: 0.1.0 — logs core
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:45.570Z
---

# [Issue 5]: [feat: vigil::init(service) — tracing bridge, resource attributes, XDG paths](https://github.com/vig-os/vigil/issues/5)

One call wires a tool:
```rust
let _guard = vigil::init("my-service")?; // flushes on drop
```
- `tracing-subscriber` registry + `opentelemetry-appender-tracing` → the file exporter.
- Resource attributes: `service.name`, `service.version`, `host.name`, `process.pid`, plus the producer's VCS commit when known (cf. tessera ADR-0058 `Producer`).
- Paths: `$XDG_STATE_HOME/<service>/` (fallback `~/.local/state/<service>/`), dir 0700, files 0600. Env overrides for dir, rotation and retention.
- Opinionated defaults (level from `RUST_LOG`, else `info`); never panics. If the file sink fails, logs degrade to stderr with a single warning.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 9, 2026 at 02:12 PM_

**Pre-mortem findings (probed 2026-10-09), added to acceptance:**
- **Nix sandbox: `HOME=/homeless-shelter` (unwritable), `XDG_STATE_HOME` unset**, so `create_dir_all` → PermissionDenied. `init` needs an injectable state dir (builder/env override); tests use `std::env::temp_dir()`; a missing or unwritable dir → error/stderr fallback, never a panic.
- Filter `opentelemetry*` targets off the bridge layer (the SDK's own records otherwise land in `logs.jsonl`).
- The batch processor drops silently once its 2048-record queue is full (it warns once), and exports on its own thread (no async runtime). `std::process::exit` skips the guard's drop (≤1 s of logs lost); document both.
- Unverified: `traceId`/`spanId` come out empty unless span context is wired (`tracing-opentelemetry` + the appender's span-context feature). Verify; if they're empty, either wire it or file a follow-up in 0.2.0 (traces).

---

# [Comment #2]() by [gerchowl]()

_Posted on October 9, 2026 at 04:43 PM_

Done in #28 (merged 5c6b8831): `vigil::init`/builder → tracing bridge → OTLP/JSONL exporter → rotating file. Never panics; the stderr fallback has exactly one warning; SDK warnings (WARN+) reach stderr, so drops are reported; queue 65 536 (cap 1 048 576); validated env with builder precedence; coexists with a `log` logger. Verified by three independent rounds. Trace/span correlation and span fields: #26 (0.2.0).

