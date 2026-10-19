---
type: issue
state: open
created: 2026-10-09T14:07:47Z
updated: 2026-10-16T15:08:21Z
author: renovate[bot]
author_url: https://github.com/renovate[bot]
url: https://github.com/vig-os/vigil/issues/20
comments: 0
labels: none
assignees: none
milestone: none
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:40.556Z
---

# [Issue 20]: [Dependency Dashboard](https://github.com/vig-os/vigil/issues/20)

This issue lists Renovate updates and detected dependencies. Read the [Dependency Dashboard](https://docs.renovatebot.com/key-concepts/dashboard/) docs to learn more.<br>[View this repository on the Mend.io Web Portal](https://developer.mend.io/github/vig-os/vigil).

## Awaiting Schedule

The following updates are awaiting their schedule. To get an update now, click on a checkbox below.

 - [ ] <!-- unschedule-branch=renovate/actions-create-github-app-token-digest -->chore(deps): update actions/create-github-app-token digest to 64ab729

## Open

The following updates have all been created. To force a retry/rebase of any, click on a checkbox below.

 - [ ] <!-- rebase-branch=renovate/opentelemetry-rust-monorepo -->[build(cargo): update opentelemetry-rust monorepo to v0.33.1](../pull/94) (`opentelemetry`, `opentelemetry-appender-tracing`, `opentelemetry-proto`, `opentelemetry_sdk`)
 - [ ] <!-- rebase-branch=renovate/serde_json-1.x-lockfile -->[build(cargo): update rust crate serde_json to v1.0.154](../pull/95)
 - [ ] <!-- rebase-branch=renovate/base64-0.x -->[build(cargo): update rust crate base64 to 0.23](../pull/97)
 - [ ] <!-- rebase-branch=renovate/getrandom-0.x -->[build(cargo): update rust crate getrandom to 0.4](../pull/98)
 - [ ] <!-- rebase-branch=renovate/proptest-1.x-lockfile -->[build(cargo): update rust crate proptest to v1.12.0](../pull/101)
 - [ ] <!-- rebase-branch=renovate/ed25519-dalek-3.x -->[build(cargo): update rust crate ed25519-dalek to v3](../pull/102)
 - [ ] <!-- rebase-branch=renovate/lock-file-maintenance -->[build(cargo): lock file maintenance](../pull/104)
 - [ ] <!-- rebase-all-open-prs -->**Click on this checkbox to rebase all open PRs at once**

## Detected Dependencies

<details><summary>cargo (1)</summary>
<blockquote>

<details><summary>Cargo.toml (23)</summary>

 - `getrandom 0.3` → [Updates: `0.4`]
 - `base64 0.22` → [Updates: `0.23`]
 - `blake3 1`
 - `ed25519-dalek 2` → [Updates: `3`]
 - `zeroize 1`
 - `opentelemetry 0.33` → [Updates: `0.33`]
 - `opentelemetry_sdk 0.33` → [Updates: `0.33`]
 - `opentelemetry-proto 0.33` → [Updates: `0.33`]
 - `serde 1`
 - `serde_json 1` → [Updates: `1`]
 - `rustix 1.1.5`
 - `opentelemetry-appender-tracing 0.33` → [Updates: `0.33`]
 - `tracing-opentelemetry 0.34`
 - `tracing 0.1`
 - `tracing-core 0.1`
 - `tracing-subscriber 0.3`
 - `tracing-log 0.2`
 - `rustix 1.1.5`
 - `allocation-counter 0.8.1`
 - `flate2 1`
 - `criterion 0.8.2`
 - `proptest 1` → [Updates: `1`]
 - `log 0.4`

</details>

</blockquote>
</details>

<details><summary>github-actions (20)</summary>
<blockquote>

<details><summary>.github/actions/setup-devkit-toolchain/action.yml</summary>


</details>

<details><summary>.github/workflows/abandon-release.yml</summary>


</details>

<details><summary>.github/workflows/ci-extension.yml (8)</summary>

 - `actions/checkout v7.0.1@3d3c42e5aac5ba805825da76410c181273ba90b1`
 - `actions/checkout v7.0.1@3d3c42e5aac5ba805825da76410c181273ba90b1`
 - `actions/checkout v7.0.1@3d3c42e5aac5ba805825da76410c181273ba90b1`
 - `actions/checkout v7.0.1@3d3c42e5aac5ba805825da76410c181273ba90b1`
 - `actions/checkout v7.0.1@3d3c42e5aac5ba805825da76410c181273ba90b1`
 - `actions/checkout v7.0.1@3d3c42e5aac5ba805825da76410c181273ba90b1`
 - `actions/checkout v7.0.1@3d3c42e5aac5ba805825da76410c181273ba90b1`
 - `actions/checkout v7.0.1@3d3c42e5aac5ba805825da76410c181273ba90b1`

</details>

<details><summary>.github/workflows/ci.yml</summary>


</details>

<details><summary>.github/workflows/codeql.yml</summary>


</details>

<details><summary>.github/workflows/devkit-upgrade.yml</summary>


</details>

<details><summary>.github/workflows/prepare-hotfix.yml</summary>


</details>

<details><summary>.github/workflows/prepare-release-extension.yml (4)</summary>

 - `actions/create-github-app-token v3@bcd2ba49218906704ab6c1aa796996da409d3eb1` → [Updates: `v3`]
 - `actions/checkout v7.0.1@3d3c42e5aac5ba805825da76410c181273ba90b1`
 - `vig-os/commit-action v0.3.3@7ba7e1ae17547813e708d4cc6a771a09f978f724`
 - `ubuntu 26.04`

</details>

<details><summary>.github/workflows/prepare-release.yml</summary>


</details>

<details><summary>.github/workflows/promote-release.yml</summary>


</details>

<details><summary>.github/workflows/publish-release-extension.yml (2)</summary>

 - `ubuntu 26.04`
 - `ubuntu 26.04`

</details>

<details><summary>.github/workflows/release-core.yml</summary>


</details>

<details><summary>.github/workflows/release-extension.yml (1)</summary>

 - `ubuntu 26.04`

</details>

<details><summary>.github/workflows/release-publish.yml</summary>


</details>

<details><summary>.github/workflows/release.yml</summary>


</details>

<details><summary>.github/workflows/scorecard.yml</summary>


</details>

<details><summary>.github/workflows/semver-labels.yml (2)</summary>

 - `actions/checkout v7.0.1@3d3c42e5aac5ba805825da76410c181273ba90b1`
 - `ubuntu 26.04`

</details>

<details><summary>.github/workflows/supply-chain.yml (2)</summary>

 - `actions/checkout v7.0.1@3d3c42e5aac5ba805825da76410c181273ba90b1`
 - `actions/checkout v7.0.1@3d3c42e5aac5ba805825da76410c181273ba90b1`

</details>

<details><summary>.github/workflows/sync-issues.yml</summary>


</details>

<details><summary>.github/workflows/sync-main-to-dev.yml</summary>


</details>

</blockquote>
</details>

---

- [ ] <!-- manual job -->Check this box to trigger a request for Renovate to run again on this repository


