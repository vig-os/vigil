---
type: issue
state: closed
created: 2026-11-02T22:45:43Z
updated: 2026-11-03T13:22:09Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/191
comments: 3
labels: bug, priority:medium, effort:small
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-04T08:43:07.598Z
---

# [Issue 191]: [audit(verify): rule and pin decode-kind precedence for lines with several defects](https://github.com/vig-os/vigil/issues/191)

## Problem
In #190 (#13 V3a-2, round 3), the attribute-whitelist check in `src/audit/codec.rs` moved into a closure that runs after `audit.v`, `audit.trail` and `audit.seq` are read. The point was for decoder errors to carry `seq`. As a side effect, a line with **several** defects now reports a different `FindingKind` / `AuditError::finding_kind()`. A fresh reviewer probed the same three lines at both heads:

| line | 3ddbea5 (before) | 36fb6c5 (merged) |
|---|---|---|
| unknown attribute key | `UnknownField` | `UnknownField` (seq 90) |
| unknown key + `audit.v=2` | `UnknownField` | `UnknownVersion` |
| unknown key + missing `audit.seq` | `UnknownField` | `MissingField` |

Lines are still accepted and rejected exactly as before, and writers still see `CorruptTrail`. Only the reported kind differs. No ADR text or ruling pins the precedence between decode defects, and no test pins it.

## Decide, then pin
- Rule the precedence. Version first is arguably correct, since a newer-version line may legitimately carry fields this version doesn't know. Record it in ADR-0005 decision 11 next to the decode kinds.
- Add a test per multi-defect combination that pins the ruled kind and the `seq` it carries.
- Also tighten the honest-crash integration test in `tests/audit_verify.rs` to assert the exact gap byte count (today it only checks `"bytes)"`).

Refs: #13 (V3a-2 review nits). Lands before C1, so it ships with the verifier.

---

# [Comment #1]() by [gerchowl]()

_Posted on November 3, 2026 at 02:53 AM_

## Ruling 191-d1 (architect): precedence between decode defects on one line

ADR-0005 lists the record-level kinds `UnknownVersion`, `MissingField`, `InvalidField` and `UnknownField` (decision 11, "What is a record"; l.265–269 and l.787). It does not say which one a line with **several** defects reports. This ruling settles that. Acceptance and rejection do not change; only the reported kind is pinned.

1. **Version first.** If `audit.v` is present, parses and is not a supported version, the line is `UnknownVersion`, and nothing else in it is interpreted. A line of a newer version may legitimately carry fields or values that v1 doesn't know, so reporting those as `UnknownField` or `InvalidField` would misdiagnose a version mismatch. A *missing* or *malformed* `audit.v` is `MissingField` or `InvalidField` for `audit.v`, by step 2.
2. **Identity fields next, in this order:** `audit.v`, `audit.trail`, `audit.seq`. The first missing one is `MissingField`; the first present but malformed one is `InvalidField`. These fields come first so that every later finding on the line carries the `seq` (the reason for the #190 change).
3. **Then every other check, in the codec's existing decode order**, with the attribute whitelist (`UnknownField`, and a duplicate key as `InvalidField`) where it sits on dev today. The implementer records the full order, as it is in the code, as an ordered list in ADR-0005 decision 11 next to the record kinds, citing this ruling and #191.
4. **`HashMismatch`** comes only after a line decodes cleanly, as today.
5. **No behaviour change beyond pinning.** If the code on dev contradicts points 1–2 for any combination, the implementer stops with `BLOCKED: design question` and the probe output, rather than reordering on its own.

**Tests:** one test per pair of defects named in #191 (unknown key + bad version → `UnknownVersion`; unknown key + missing `audit.seq` → `MissingField`), plus the identity-order pairs (missing trail + missing seq → `MissingField` for `audit.trail`). Each pins the kind, and the `seq` where the line has one. The honest-crash integration test asserts the exact gap byte count.


---

# [Comment #2]() by [gerchowl]()

_Posted on November 3, 2026 at 03:03 AM_

### Addendum to ruling 191-d1 (after the pre-dispatch check)
6. **Point 1 is scoped to vigil's record schema; the OTLP envelope comes first.** `audit.v` versions vigil's record attributes, not the OTLP log-record envelope around them. `audit.v` is itself an attribute, so it can only be read once the attribute list decodes unambiguously; a duplicated `audit.v`, for example, has no single value to check. The full order is therefore:
   - **(0) the OTLP envelope:** the log-record fields, fixed severity, `body`, `droppedAttributesCount`, and the attribute-list decode, including duplicate keys. These checks run in the codec's existing order and report as they do on dev.
   - **(1) the version:** `UnknownVersion`.
   - **(2) the identity fields:** `audit.v`, `audit.trail`, `audit.seq`.
   - **(3) the remaining checks and the attribute whitelist,** as in point 3.

   A v=2 line with an envelope defect therefore reports the envelope defect. This matches dev today (probed: v=2 + duplicate key → `InvalidField`, v=2 + `droppedAttributesCount=1` → `UnknownField`), so nothing is reordered. Add one test pinning a v=2 + envelope-defect pair.
7. **`MissingField` carries no field name** (`AuditError` has none), so the trail-before-seq order can only be pinned by kind. The "missing trail + missing seq" test asserts `MissingField` and the `seq`, and claims nothing more. Adding a field name to findings is out of scope here.

---

# [Comment #3]() by [gerchowl]()

_Posted on November 3, 2026 at 01:22 PM_

Fixed by #196 (merged to dev at 6f8b953), reviewed by fresh reviewers over three rounds.

