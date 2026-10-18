---
type: issue
state: closed
created: 2026-10-11T10:42:53Z
updated: 2026-10-11T13:53:35Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/82
comments: 1
labels: bug
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:28.433Z
---

# [Issue 82]: [audit decoder: pdata parity for raw-byte JSON fields (bytesValue, traceId, spanId — no escapes, no CR/LF strip)](https://github.com/vig-os/vigil/issues/82)

Found in the round-3 verification of PR #75 (audit B1) at 6addf6f. Confirmed against the real Collector `pdata` v1.68.0 (`plog.JSONUnmarshaler`).

`pdata` reads `bytesValue` with `ReadBytes`, which takes the raw string bytes with no JSON unescaping, and decodes them with `base64.StdEncoding`. It reads `traceId` and `spanId` as raw hex the same way. vigil's decoder unescapes first, strips CR/LF and then validates (`src/audit/codec.rs:253-260`, `306-313`). So vigil accepts lines the Collector drops:

- `{"bytesValue":"Y\\r\\nQ=="}`: pdata fails with `illegal base64 data at input byte 1`; vigil returns OK.
- `"\\/w=="` and `"YQ==\\n"`: the same split.
- A `traceId` containing `\\u0030`: pdata rejects it; vigil accepts it.

The test `codec_context_int64_and_base64` asserts the wrong behaviour. The ADR-0005 sentence "CR/LF inside the decoded JSON string are ignored … like pdata" is factually wrong.

**Fix (systematic, not per field):** list every field in pdata's OTLP/JSON log reader that is read raw (not unescaped), and have the decoder reject any `\\` escape in exactly those fields, with no CR/LF stripping. Add a pdata-parity test for each. Correct the ADR wording. Fold this into PR #75 before it merges.

Refs: #11 #12 #75
---

# [Comment #1]() by [gerchowl]()

_Posted on October 11, 2026 at 01:53 PM_

Fixed in PR #75 (merged into dev): the fields pdata reads raw reject escapes; the field table is in ADR-0005; parity is checked against the pinned Collector in CI.

