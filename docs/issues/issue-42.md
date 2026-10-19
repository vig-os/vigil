---
type: issue
state: closed
created: 2026-10-10T22:18:47Z
updated: 2026-10-11T12:13:49Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/42
comments: 2
labels: feature, priority:high, effort:medium, semver:major
assignees: none
milestone: 0.2.0 — metrics + traces
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:36.399Z
---

# [Issue 42]: [feat: apply ADR-0004 to the existing surface (non_exhaustive, error kinds, Guard::shutdown, composition, features)](https://github.com/vig-os/vigil/issues/42)

Implement ADR-0004 (#37) on the existing logs surface (`init.rs`, `logs.rs`, `sink.rs`, `rotate.rs`) **before** #7/#8 add new signals, since it touches every module. Includes the folded docs nits from #36. AC: a `cargo public-api` snapshot is committed and every item is justified in the ADR; the composition API serves a flock-like consumer (its own filter env var + default, console layer, own Registry) in an example that compiles and has a test; error kinds are matchable; `Guard::shutdown` returns loss as an error; doc examples compile. Refs: #37, #36.

---

# [Comment #1]() by [gerchowl]()

_Posted on October 11, 2026 at 12:46 AM_

Scope note (architect): the ADR-0004 public-API **allowlist gate** (including hidden items, and no `opentelemetry` paths in the public API) is part of **#42 (3/3)** together with the API snapshot enforcement. #43 only adds the cargo-semver-checks job.

---

# [Comment #2]() by [gerchowl]()

_Posted on October 11, 2026 at 12:13 PM_

Part 3/3 landed in PR #81 (merged into dev). With parts 1 and 2 (#67, #72) this delivers the API freeze: exporters and sinks behind `--cfg vigil_unstable`, a public-API snapshot and a kind-aware ADR-0004 allowlist gate, and a live label-aware semver gate whose label applier must be admin or maintain. The four major API changes were reviewed by the architect.

