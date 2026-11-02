---
type: issue
state: closed
created: 2026-10-10T22:18:53Z
updated: 2026-10-11T01:55:34Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/45
comments: 1
labels: feature, area:ci, priority:medium, effort:small
assignees: none
milestone: 1.0.0 — stable
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:35.333Z
---

# [Issue 45]: [ci: MSRV policy and a CI check against rust-version](https://github.com/vig-os/vigil/issues/45)

`rust-version = "1.95"` equals the pinned toolchain, so the MSRV has never been tested independently. Implement the MSRV policy from ADR-0004 (#37): a CI job builds and tests with the MSRV toolchain (a second fenix toolchain or cargo-msrv 0.19 verify from the pinned nixpkgs). AC: using a newer-std API fails the job (shown once); the policy is in the README.

---

# [Comment #1]() by [gerchowl]()

_Posted on October 11, 2026 at 01:55 AM_

Done in #74 per ADR-0004 d11: an MSRV lane on exactly the `rust-version` toolchain (1.95.0) with an aarch64-apple-darwin check, a latest-stable lane, both from the locked fenix input; drift guards (rust-version vs toolchain vs the flake assert, derived from one place); README policy. Red proof: E0658 under 1.95.0.

