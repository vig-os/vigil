---
type: issue
state: closed
created: 2026-10-10T22:19:02Z
updated: 2026-10-11T03:54:40Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/50
comments: 1
labels: feature, priority:medium, area:docs, effort:small
assignees: none
milestone: 1.0.0 — stable
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:33.382Z
---

# [Issue 50]: [docs: spec-versioning and stability stance for 1.0 (ADR-0001 update, README Stability section)](https://github.com/vig-os/vigil/issues/50)

The OTel file-exporter spec is still Development. Update ADR-0001 for 1.0: what vigil promises readers, what counts as a vigil major (format, semconv/schemaUrl pin from #9, opentelemetry bumps per ADR-0004), how spec changes are absorbed. AC: a README Stability section that matches ADR-0001/0004.

---

# [Comment #1]() by [gerchowl]()

_Posted on October 11, 2026 at 03:54 AM_

Done in #78: ADR-0001 amended with 'Versioning stance at 1.0' (what readers can rely on; majors = breaking on-disk/encoding changes and renaming/removing/redefining emitted attributes; additive semconv pin moves are minors, mechanics in #9) and a README Stability section (semver surface per ADR-0004, vigil_unstable excluded, on-disk and audit format promises, MSRV, platforms with macOS CI pending #46, what's not covered). Reviewed in 2 rounds.

