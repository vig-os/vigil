---
type: issue
state: closed
created: 2026-10-12T11:54:24Z
updated: 2026-10-12T14:04:25Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/109
comments: 1
labels: none
assignees: none
milestone: 1.0.0 — stable
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:25.747Z
---

# [Issue 109]: [ci: lint every supported feature set (clippy -D warnings for no-default-features, default, each feature, all-features)](https://github.com/vig-os/vigil/issues/109)

## Problem
CI runs clippy with only one feature set. A warning that exists only under another supported feature set goes through green CI.

Found by the code-falsifier review of #106: `src/init.rs:16` imports `OTelSdkResult`, which is unused under `--no-default-features`. Running `cargo clippy --no-default-features -- -D warnings` exits 101, yet CI was green. #106's fix round fixes that instance; this issue is the gate that stops it from coming back.

## Acceptance
- A CI job, or a step in `nix flake check`, runs `cargo clippy --locked --all-targets -D warnings` for each of these:
  - `--no-default-features`
  - the default features
  - each feature on its own (`metrics`, `audit`, and any others in `Cargo.toml`)
  - `--all-features`
- It does so with and without `--cfg vigil_unstable` where that cfg changes the code.
- The job is part of CI Summary.
- A deliberately unused import under one feature set makes the job fail; show this in the PR body.
- The feature list is not duplicated by hand: derive it from `Cargo.toml` (e.g. with `cargo metadata`) or use cargo-hack, if it's already in the devkit toolchain.

Refs: #106
---

# [Comment #1]() by [gerchowl]()

_Posted on October 12, 2026 at 02:04 PM_

Closed by #110: flake checks clippy-<set>[-unstable] over the powerset of user features (derived from Cargo.toml), with eval-time guards for >16 sets, name collisions and optional deps reachable only via implicit features. Architect re-verified the implicit-feature guard in a scratch worktree (default-only dep:libc → eval error; adding a user feature → 8 sets/16 checks).

