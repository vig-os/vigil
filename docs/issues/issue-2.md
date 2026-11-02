---
type: issue
state: closed
created: 2026-10-09T13:21:41Z
updated: 2026-10-09T13:25:18Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/2
comments: 1
labels: chore, priority:high, area:workspace, effort:small
assignees: none
milestone: 0.1.0 — logs core
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:46.633Z
---

# [Issue 2]: [chore: adopt devkit 1.18.0 (direnv, gitflow, Rust pack)](https://github.com/vig-os/vigil/issues/2)

Scaffold with vig-os/devkit **1.18.0**, **direnv mode only** (flake + `.envrc`, no `.devcontainer/`), **gitflow** (`dev` integrates, `main` takes release PRs), `DEVKIT_LANGUAGES=rust`.
- `flake.nix` pinned to `github:vig-os/devkit?ref=1.18.0`; `mkRustProject` (fenix toolchain from `rust-toolchain.toml`, crane checks: fmt, clippy, nextest, doctest, doc); `rust` capability module; `cargo fmt` / `cargo clippy -D warnings` pre-commit hooks.
- Crate skeleton `vigil-telemetry` (`[lib] name = "vigil"`).
- `.github/CODEOWNERS`: `* @gerchowl`.

**Acceptance:** `nix flake check` green locally, CI green on `dev`, `CI Summary` reported (required by the org-config rulesets once applied).
---

# [Comment #1]() by [gerchowl]()

_Posted on October 9, 2026 at 01:25 PM_

Landed as the one-off **bootstrap** commit `87ca93f` (signed), pushed directly to `main` and `dev`. An empty repo can't take a PR, and the org-config rulesets (#327 / vig-os/org-config#328) weren't applied yet; everything from here goes through PRs to `dev`.

- Scaffolded **without containers**: devkit 1.18.0's `init-workspace.sh` run on the host (`TEMPLATE_DIR`/`WORKSPACE_DIR` overrides, GNU tools via `nix shell`), `--mode direnv --workflow gitflow`, `DEVKIT_LANGUAGES=rust`. Re-run with `--force` once `Cargo.toml` existed, so the Rust `.gitignore` fragment rendered (flake, README and CODEOWNERS preserved).
- `flake.nix` pinned to devkit `1.18.0`; `mkRustProject` + the `rust` module + `cargo fmt` / `clippy -D warnings` hooks (same wiring as gerchowl/s1-mcp).
- `nix flake check`: all checks passed (fmt, clippy, nextest, doctest, doc). All pre-commit hooks passed on the commit.
- CODEOWNERS: `* @gerchowl`.

Known until the org-config apply + secret grants: no rulesets yet, and workflows that mint App tokens (sync-issues, release, devkit-upgrade) fail with empty credentials (vig-os/org-config#318).

