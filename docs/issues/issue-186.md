---
type: issue
state: open
created: 2026-11-02T15:12:28Z
updated: 2026-11-02T20:14:19Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/186
comments: 1
labels: feature, priority:medium, effort:small
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-03T09:06:06.404Z
---

# [Issue 186]: [AuditError: attach io::Error as source() on every Io error](https://github.com/vig-os/vigil/issues/186)

`AuditError` has no error source today (`src/audit/mod.rs:115–122`: no source field; `impl Error` at l.152 has no `source()`). Every `AuditErrorKind::Io` error therefore flattens the underlying `io::Error` into its detail text, so callers cannot downcast to `io::Error` and read its `ErrorKind` (e.g. `NotFound` versus `PermissionDenied`).

ADR-0005 decision 13 (l.1050) already states the contract for the verifier: "`Err` is only `Io` (cannot read, the `io::Error` as source)". #13 V1 (`TrustPolicy::from_file`) adds the source plumbing (an optional boxed source, a crate-private constructor taking an `io::Error`, and `source()`) and uses it at that one site only, to stay in scope.

**Ask:** attach the `io::Error` as `source()` at every existing `AuditErrorKind::Io` site (writer, reader, lock, operator commands, `KeyFileSigner` file loading), with a test per site family that downcasts the source. This is additive (no public signature change).

Refs: #13

---

# [Comment #1]() by [gerchowl]()

_Posted on November 2, 2026 at 08:14 PM_

Milestone triage: 0.3.0. This is error plumbing on the audit paths that the verifier (#13) also uses.

