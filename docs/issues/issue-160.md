---
type: issue
state: closed
created: 2026-10-18T23:41:13Z
updated: 2026-11-02T20:13:49Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/160
comments: 1
labels: bug
assignees: none
milestone: 0.2.0 — metrics + traces
projects: none
parent: none
children: none
synced: 2026-11-03T09:06:11.758Z
---

# [Issue 160]: [test(release_docs): pin-advice scan reads generated docs/issues and docs/pull-requests mirrors, so it fails after devkit's issue sync](https://github.com/vig-os/vigil/issues/160)

On release/0.1.0 the finalize step's 'chore: sync issues and PRs' (e82890c) committed generated mirrors under `docs/pull-requests/` and `docs/issues/`. `tests/release_docs.rs::all_unstable_pin_advice_is_phase_specific` (added in #154) walks those files too, and fails on `docs/pull-requests/pr-154.md:39`, which quotes the brief text verbatim. CI on release PR #155 is red (run 39084553862), which blocks the promotion of v0.1.0. Fix: scope the scan to the authored, consumer-facing sources (`src/`, `README.md`, `docs/adr/`, and anything else the package ships), never the generated mirrors. Add a test that a pin-advice-looking line under `docs/pull-requests/` is ignored. Fix it on release/0.1.0; dev gets it through sync.
---

# [Comment #1]() by [gerchowl]()

_Posted on November 2, 2026 at 08:13 PM_

Fixed by #161 (307b9d6: the pin-advice scan skips the generated `docs/issues` and `docs/pull-requests` mirrors, with a test). Shipped in [0.2.0](https://github.com/vig-os/vigil/releases/tag/0.2.0). The PR used `Refs:`, so the issue did not close automatically. Closing at milestone triage.

