---
type: issue
state: closed
created: 2026-10-09T20:21:04Z
updated: 2026-10-11T12:41:28Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/36
comments: 1
labels: priority:low, area:docs, effort:small
assignees: none
milestone: 0.2.0 — metrics + traces
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:38.461Z
---

# [Issue 36]: [docs(init): empty RUST_LOG records nothing; say that `let _ =` drops the guard at once](https://github.com/vig-os/vigil/issues/36)

Nits from the #33 review (both pre-existing behaviour, docs only):
- `RUST_LOG=` (empty) records nothing and gives no warning. That is `EnvFilter`'s behaviour (an empty directive set), but the README says an invalid `RUST_LOG` warns once and uses `info`. Either treat empty as unset (→ `info`) or document it.
- The docs show `let _guard = vigil::init(..)` but never say outright that `let _ = vigil::init(..)` drops the guard immediately (Rust semantics; `#[must_use]` doesn't fire for `let _`). Add one sentence to the README and `init` rustdoc.
Refs: #32
---

# [Comment #1]() by [gerchowl]()

_Posted on October 11, 2026 at 12:41 PM_

Covered on dev by #42 (PRs #72 and #81). An empty `RUST_LOG` now counts as unset and falls back to `info` (README:142, `src/init.rs:262`, :312), and the README (:105) and the `init` rustdoc (`src/init.rs:261`, :420) state that `let _ = vigil::init(..)` drops the guard immediately.

