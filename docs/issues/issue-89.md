---
type: issue
state: open
created: 2026-10-11T22:03:06Z
updated: 2026-10-11T22:03:06Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/89
comments: 0
labels: feature, security, priority:medium, area:testing, effort:medium
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:27.677Z
---

# [Issue 89]: [test(audit): power-loss test proving the prefix property on ext4 data=ordered](https://github.com/vig-os/vigil/issues/89)

ADR-0005 decision 7, "Assumption: a crash never exposes bytes that were not written" (amended, #68, l.~424–431), makes ext4 in its default `data=ordered` mode a supported filesystem for regulated use only once a test shows the prefix property on it:

> For ext4, that is #11's crash-injection tests on the Linux lane, plus a power-loss test (a VM disk cut off while a writer appends, with flushes honoured).

#11's SIGKILL tests (audit B2b) cover a process crash. They don't cover a power loss: a killed process leaves its data in the page cache. This issue owns the power-loss half, split out of #11 because it needs VM infrastructure, not crate code.

## Acceptance
- A reproducible harness boots a VM whose disk honours flushes (no `cache=unsafe`). A writer appends to an ext4 `data=ordered` trail, and the disk is cut off at random points (hard reset or kill of the VM process). The harness runs many iterations.
- After each cut, the trail reopens and passes verification (the #13 verifier, `--strict` once the next checkpoint covers the repair). In the tail it shows only byte prefixes of written lines: no zero-filled or stale range, and no line acknowledged with `Ok` before the cut is missing.
- The result (iterations, kernel, ext4 options, hypervisor and cache mode) is recorded where ADR-0005 / the README name the supported filesystems.
- Where it runs (CI or a documented manual gate before the release train #17) is decided in this issue.
- APFS is #46's scope, per the same ADR text.

Refs: ADR-0005 decision 7; #11; #13; #46; #17.

