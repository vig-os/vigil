---
type: issue
state: closed
created: 2026-10-10T22:18:51Z
updated: 2026-10-11T12:41:14Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/44
comments: 1
labels: feature, priority:medium, area:docs, effort:small
assignees: none
milestone: 1.0.0 — stable
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:35.685Z
---

# [Issue 44]: [docs: deny missing_docs, missing_errors_doc and missing_panics_doc](https://github.com/vig-os/vigil/issues/44)

`missing_docs` is clean today (0 warnings) but not denied. Add `#![deny(missing_docs)]` plus clippy `missing_errors_doc`/`missing_panics_doc` in the crate and the flake's clippy check. AC: an undocumented pub item, or a pub fn returning Result without an Errors section, fails `nix flake check` (shown once).

---

# [Comment #1]() by [gerchowl]()

_Posted on October 11, 2026 at 12:41 PM_

Done in PR #83 (merged into dev). missing_docs, missing_errors_doc and missing_panics_doc are denied in Cargo.toml `[lints]` and enforced by clippy on stable, on all features and under `--cfg vigil_unstable`.

