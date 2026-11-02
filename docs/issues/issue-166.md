---
type: issue
state: open
created: 2026-11-02T04:45:40Z
updated: 2026-11-02T04:45:41Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/166
comments: 0
labels: bug
assignees: none
milestone: 0.2.0 — metrics + traces
projects: none
parent: none
children: none
synced: 2026-11-02T13:59:38.796Z
---

# [Issue 166]: [docs(readme): no Install / quick-start section, so consumers can't tell how to depend on v0.1.0](https://github.com/vig-os/vigil/issues/166)

The README (the crate root doc) never names the package `vigil-telemetry`, says nothing about depending on the GitHub release (git tag `0.1.0`; crates.io comes later), and has no minimal `init` example near the top. First consumers, human or agent, can't adopt the release without reading the source. Fix on release/0.1.0 before promotion, so main shows it, and dev gets it through sync.
