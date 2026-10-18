---
type: issue
state: open
created: 2026-10-10T22:18:55Z
updated: 2026-10-12T19:29:39Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/46
comments: 2
labels: feature, priority:high, area:ci, effort:medium
assignees: none
milestone: 1.0.0 — stable
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:34.948Z
---

# [Issue 46]: [ci: macOS lane (nix flake check + conformance on APFS), via a devkit macOS fix](https://github.com/vig-os/vigil/issues/46)

Owner decision: Linux + macOS are supported for 1.0. Pre-mortem R4: vigil's code cross-checks clean for aarch64-apple-darwin, and the flake evaluates `checks.aarch64-darwin.*`. otelcol-contrib 0.151.0 is cached for darwin, and macOS minutes are free for this public repo. **But** devkit's `setup-devkit-toolchain` uses `tac` (action.yml:263), `declare -A` (:349) and `env -0` (:290/296), which fail on the runners' bash 3.2 and lack GNU tac. `DEVKIT_CI_RUNNER` is one label set for all lanes, so the lane is its own job in `ci-extension.yml`. Do: an upstream devkit fix (an issue plus a PR to vig-os/devkit; its owners merge), then a job whose name contains `macOS` (check-1.0.0.sh greps for it) on `macos-15` running `nix flake check` plus the conformance script. AC: a successful macOS job on dev; rotation, multi-process and dir-flock tests pass on APFS (the ENOTSUP fallback and flock-on-directory are unproven there today).

---

# [Comment #1]() by [gerchowl]()

_Posted on October 11, 2026 at 03:59 AM_

**Scope addition from ADR-0005 amendment 2 (#68, PR #77), decision 6.** Recognising an honest torn write relies on a crash leaving only a byte prefix of the unacknowledged append: no stale or zero-filled range. ADR-0005 now lists APFS as a supported filesystem for regulated use **only once the macOS lane shows this**. So this lane also runs:

- #11's crash-injection tests on APFS: a writer process SIGKILLed mid-write, with other writers running. Each fragment must be a strict byte prefix of the line, the next writer must attest it (`audit.repaired`), and verify must report `TornWriteRepaired` and pass `--strict`.
- A power-loss test on APFS: a macOS VM whose disk is cut off while writers append, on a host that honours flushes (`F_FULLFSYNC`). After reboot, every acknowledged record must be present, and the tail must be either nothing or a byte prefix of the line (never zeros or stale bytes). If a VM power cut isn't feasible in CI, run it as a documented manual test on release candidates and record the result.

The Linux/ext4 (default `data=ordered`) counterpart belongs to #11's crash tests. Until a filesystem passes its test, the rustdoc and README call it unsupported for regulated use.

Refs: #46, #68, #11


---

# [Comment #2]() by [gerchowl]()

_Posted on October 12, 2026 at 07:29 PM_

The macOS conformance lane added by #46 must run `nix develop -c python3 scripts/prometheus_conformance.py` after `scripts/conformance.py`. This proves ADR-0003 d12/d21 against the pinned Collector and Prometheus, including scope metadata, collision poisoning and the shared translation fixture. Refs: #7.


