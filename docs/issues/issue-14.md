---
type: issue
state: open
created: 2026-10-09T13:22:06Z
updated: 2026-10-09T13:22:06Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/14
comments: 0
labels: chore, priority:medium, area:workspace, effort:medium
assignees: none
milestone: 0.4.0 — adoption
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:42.344Z
---

# [Issue 14]: [chore: wire vigil into devkit's Rust scaffold](https://github.com/vig-os/vigil/issues/14)

Upstream into vig-os/devkit (issue to file there): the Rust template depends on `vigil-telemetry` and calls `vigil::init` in generated binaries; optional checks that a project uses it. Opinions live in vigil; devkit only makes them the default.
