---
type: issue
state: open
created: 2026-10-10T23:26:52Z
updated: 2026-10-10T23:26:52Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/61
comments: 0
labels: feature
assignees: none
milestone: none
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:30.946Z
---

# [Issue 61]: [feat: metrics API for libraries without the SDK (post-1.0, additive)](https://github.com/vig-os/vigil/issues/61)

ADR-0004 (#37, decision 8) decides that in 1.0 **libraries record only through \`tracing\`** and do not depend on vigil; \`vigil::metrics\` is for applications that own the pipeline. Depending on vigil from a library would force the OpenTelemetry SDK, rotation and the exporters onto every application that uses the library, including applications that don't use vigil at all.

Scope (after 1.0): a small API-only crate (working name \`vigil-api\`) with the \`vigil::metrics\` instrument types and \`Value\`, no SDK dependency, no-op unless the application's vigil pipeline binds it, published at 1.0 from day one. \`vigil::metrics\` then becomes a re-export of it with identical paths and API, which is additive for vigil's users (ADR-0004 decision 8 keeps the facade shaped for that).

AC: a library depending only on the API crate records metrics that appear in an application's \`metrics.jsonl\` when the application runs vigil; an application without vigil compiles and runs with no SDK in its dependency tree and no stderr output from the API crate; cargo-semver-checks shows no break in \`vigil::metrics\` across the move.

Refs: #37
