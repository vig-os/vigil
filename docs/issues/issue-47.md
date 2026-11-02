---
type: issue
state: closed
created: 2026-10-10T22:18:57Z
updated: 2026-10-10T23:59:38Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/47
comments: 1
labels: feature, security, area:ci, priority:medium, effort:small
assignees: none
milestone: 1.0.0 — stable
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:34.581Z
---

# [Issue 47]: [ci: supply-chain gate with cargo-deny (licenses, bans, advisories)](https://github.com/vig-os/vigil/issues/47)

`cargo audit` is clean today (86 crates) but nothing gates it. There's no `deny.toml`; cargo-deny 0.19.6 is in the pinned nixpkgs. Add a `deny.toml` (license allowlist compatible with Apache-2.0; ban duplicate opentelemetry majors; advisories deny) and a CI job. AC: a planted GPL dependency and a known-vulnerable version each fail the job (shown once).

---

# [Comment #1]() by [gerchowl]()

_Posted on October 10, 2026 at 11:59 PM_

Done in #55: cargo-deny 0.19.6 (flake-pinned). Licenses Apache-2.0/MIT/Unicode-3.0, crates.io-only sources, a single opentelemetry compatibility line, advisories with a 7-day DB freshness check, all findings reported together; a weekly/dispatch workflow (active once on main); the offline subset runs in `nix flake check`. Planted GPL, RUSTSEC, git-dependency and otel-split failures were proven red. 3 review rounds.

