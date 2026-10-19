---
type: issue
state: closed
created: 2026-10-09T13:58:20Z
updated: 2026-10-09T15:37:03Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/18
comments: 1
labels: feature, priority:high, area:ci, effort:small
assignees: none
milestone: 0.1.0 — logs core
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:40.933Z
---

# [Issue 18]: [ci: run the Rust checks (nix flake check) in the CI extension](https://github.com/vig-os/vigil/issues/18)

The managed `ci.yml` runs `just lint` / `just test`, which are Python recipes: in this Rust repo both print "no pyproject.toml — skipping" and report green (vig-os/devkit#1811). Today **no CI lane compiles or tests the crate**, so `CI Summary` green says nothing about the code.

Until devkit fixes #1811, use the consumer-owned seam `.github/workflows/ci-extension.yml` (called unconditionally by `ci.yml` and aggregated by `CI Summary`).

**Acceptance**
- The extension job runs `nix flake check -L` (fmt, clippy, nextest, doctests, docs from `vigos.lib.mkRustProject`) on every PR, with a Nix cache (e.g. magic-nix-cache or cachix, whatever devkit's other lanes use) so the run stays reasonable.
- A deliberately failing test or clippy warning turns `CI Summary` red (show it once in the PR, then revert).
- The job's runner follows the `runner-json` input like the rest of ci.yml.
- Remove this workaround when devkit#1811 lands (note it in a comment in the file).

Prerequisite for every other 0.1.0 issue: their acceptance relies on CI actually running the tests.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 9, 2026 at 03:37 PM_

Done in #19 (merged 4de113b0): the CI extension runs `nix flake check -L`; red/green gating was proven on that PR.

