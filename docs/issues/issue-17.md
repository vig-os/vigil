---
type: issue
state: open
created: 2026-10-09T13:22:12Z
updated: 2026-10-10T22:19:07Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/17
comments: 1
labels: chore, area:ci, priority:medium, effort:small, semver:minor
assignees: none
milestone: 1.0.0 — stable
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:41.250Z
---

# [Issue 17]: [chore: first crates.io release](https://github.com/vig-os/vigil/issues/17)

Through the devkit release train. Needs the `crates-io` environment and `CARGO_REGISTRY_TOKEN` declared in vig-os/org-config (deliberately deferred in #327 until the first release).
---

# [Comment #1]() by [gerchowl]()

_Posted on October 10, 2026 at 10:19 PM_

Moved to 1.0.0: owner decision (2026-10-11), no public 0.x. This issue covers **release-train preparation** only: request the crates.io environment and token via org-config, `cargo publish --dry-run` green with **no git dependencies**, version set by the train. The human approves the release PR to main and the publish.

