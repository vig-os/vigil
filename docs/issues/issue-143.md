---
type: issue
state: closed
created: 2026-10-13T10:56:16Z
updated: 2026-10-16T13:29:16Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/143
comments: 1
labels: bug
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:21.443Z
---

# [Issue 143]: [bug(audit): resume refuses a zero-filled (NUL) live-file tail, so a power-loss trail can never be recovered](https://github.com/vig-os/vigil/issues/143)

## Defect
When `audit.jsonl` ends in zero-filled bytes, `AuditConfig::resume` refuses the trail with `CorruptTrail: invalid audit record in sealed run`. Delayed allocation produces exactly this tail after a power loss. With `resume` refused, the trail can never be opened or resumed again.

ADR-0005 §6 (supported filesystems) names zero-filled appended ranges as the failure mode and requires: "a crash leaves an `Unparsable` line. The writer refuses with `CorruptTrail` … **The only way to continue is `resume`, which seals the file as it is, error included.**" `open` refusing is conformant. `resume` refusing removes the only recovery path the ADR promises.

## Reproduction (probed on dev; the code is identical on 780f349)
The trail is genesis plus one entry, with the tail bytes appended to `audit.jsonl`:

| tail | `open` | `resume(head, lost_through)` |
|---|---|---|
| `00`×4096 | CorruptTrail | **CorruptTrail "invalid audit record in sealed run"** |
| `{"resourceLogs":[{"res` + `00`×64 | CorruptTrail | **CorruptTrail** |
| `00`×8 `0a` | CorruptTrail | **CorruptTrail** |
| `xyz\n` | CorruptTrail | Ok (sealed) |
| `7f 0a` | CorruptTrail | Ok |

## Root cause
- `validation::payload` (src/audit/validation.rs ~l.237) classifies any byte below 0x20 as `InvalidField`, not `Unparsable`.
- `storage::fragment` (storage.rs ~l.1034) also rejects such bytes.
- `history_segment` therefore takes its hard-error arm (storage.rs ~l.431) instead of the `Unparsable` arm.

ASCII garbage gets sealed; NUL garbage doesn't.

## Fix (ruling 13-d1 OQ9; implemented by #13 slice 13-R)
One shared line classifier, used by the reader and the verifier:
- a line is `Unparsable` iff its payload does not decode to a JSON object. This covers control bytes, over-cap lines and JSON non-objects;
- `UnknownField`/`HashMismatch` lines remain records.

`resume` then seals NUL tails like any other `Unparsable` line, and spans (ruling 123-d1) treat them as span bytes. ADR-0005 amendment 12 states the rule.

**Acceptance:** every row above resumes and reopens. Mutant: the old `< 0x20` → `InvalidField` mapping makes the NUL rows fail.

Found by the #13 pre-mortem (plan §4 item 1). The planner's mechanism (seal, then lockout) was refuted: `resume` refuses outright.

---

# [Comment #1]() by [gerchowl]()

_Posted on October 16, 2026 at 01:29 PM_

Fixed by #148, merged into dev at 1c8605d. A single line classifier is shared by the reader and the verifier, so resume now seals NUL, control-byte and over-cap tails, and an over-cap line is read through its LF as one Unparsable line. The ADR-0005 amendment 12 OQ9 part is Accepted. Reviewed by a fresh falsifier, with all mutants caught.

