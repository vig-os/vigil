---
type: issue
state: closed
created: 2026-10-10T22:18:49Z
updated: 2026-10-11T01:17:19Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/43
comments: 1
labels: feature, priority:high, area:ci, effort:small
assignees: none
milestone: 1.0.0 — stable
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:36.039Z
---

# [Issue 43]: [ci: semver gate with cargo-semver-checks that cannot pass vacuously](https://github.com/vig-os/vigil/issues/43)

Pre-mortem R9: in the pinned nixpkgs, cargo-semver-checks 0.47 with `--baseline-rev` and version 0.0.0→0.0.0 printed `(no change; assume major) 0 checks: 0 pass, 252 skip`, a silent pass. With `--release-type minor` it ran 196 checks, and a planted `pub probe: bool` on `RotationConfig` failed `constructible_struct_adds_field`. Abbreviated shas fail (`couldn't parse revision: 6d0b1c1^{tree}`). Do: a ci-extension job using the merge-base with dev (full sha) and an explicit `--release-type` until a published baseline exists, then the registry baseline. AC: a planted break fails the job (shown once); the job asserts N>0 checks ran; a public-dependency bump policy (ADR-0004) is enforced or documented as a manual gate.

---

# [Comment #1]() by [gerchowl]()

_Posted on October 11, 2026 at 01:17 AM_

Done in #69: a cargo-semver-checks 0.47 gate in the dev shell, full-sha merge-base baseline, explicit pre-publish release type, fails on 0 checks; every rustdoc-flag source is cleared so `vigil_unstable` can't leak into the checked surface; a dev→dev self-compare is handled. A planted break was proven red. The ADR-0004 allowlist gate lands with #42 (3/3).

