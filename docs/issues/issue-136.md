---
type: issue
state: closed
created: 2026-10-13T03:20:37Z
updated: 2026-10-13T11:49:11Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/136
comments: 1
labels: bug
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:22.232Z
---

# [Issue 136]: [docs(audit): stale rustdoc — crate doc says resume follows, Poisoned names vigil-audit verify](https://github.com/vig-os/vigil/issues/136)

The B3e brief check against dev 3d6be28 found two untrue rustdoc sentences:
- `src/audit/mod.rs` ~l.6, the module doc, says "resume follows in #11 B3d". `AuditConfig::resume` merged in #132.
- `AuditErrorKind::Poisoned` ~l.51 says "run `vigil-audit verify`". That binary does not exist yet (#13), and the sentence doesn't say so.

Fix: make both sentences true of dev, and mark the CLI step as #13's. These are code (rustdoc) changes, and B3e is prose only (README/ADR), so they go in their own PR or are folded into #13's first PR. Refs #11 #13.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 13, 2026 at 11:49 AM_

Fixed by #142 (merged into dev at abef957): module doc (resume takes the found head + lost_through; rotate/checkpoint the expected head), HeadMismatch, Poisoned (CLI marked #13), sink.rs l.1.

