---
type: issue
state: open
created: 2026-10-10T23:56:41Z
updated: 2026-10-10T23:56:41Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/65
comments: 0
labels: feature, security, priority:low, effort:medium
assignees: none
milestone: none
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:30.235Z
---

# [Issue 65]: [feat(push): authenticated transport to the local agent (Unix socket or TLS)](https://github.com/vig-os/vigil/issues/65)

ADR-0006 (#39) restricts the `push` feature to plain HTTP to a loopback IP literal for 1.0. That leaves a documented limit (ADR-0006 decision 5): while the local agent is not listening, any local user can bind the agent's port (4318 is above 1024) and receive every pushed line plus any `authorization` header. Pushed lines then bypass the `0600`/`0700` file permissions of ADR-0002 decision 10.

**Decide (new ADR, superseding ADR-0006 decision 5 for this part) and implement, additively, one or both of:**
- **Unix domain socket transport.** Filesystem permissions authenticate the peer, and Linux `SO_PEERCRED` / macOS `LOCAL_PEERCRED` can check the listener's uid. Needs a UDS-capable client path: `ureq` has no built-in UDS transport, so either a custom `ureq` transport or a minimal HTTP/1.1 client over `UnixStream`. Also needs an agent that listens on UDS; check Alloy `otelcol.receiver.otlp` and Collector `confighttp` UDS support.
- **TLS to a pinned certificate or CA** (a new feature such as `push-tls`, pulling `rustls`; Probe D in ADR-0006 measured +12 crates). Covers remote agents too. Requires a trust-root policy and certificate configuration.
- Either way: send `authorization`-style headers only over a transport whose peer is verified.

**Acceptance criteria**
- A test shows that an impostor listener (another uid on the socket, or a wrong certificate) receives no lines and no headers.
- The default build and `push` without the new feature are unchanged.

Not required for 1.0. The limit is documented in ADR-0006 decision 5 and in `push`'s rustdoc (#41).

Refs: #39, #41

