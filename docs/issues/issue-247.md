---
type: issue
state: open
created: 2026-11-20T11:36:07Z
updated: 2026-11-20T11:36:07Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/247
comments: 0
labels: none
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-21T09:17:33.244Z
---

# [Issue 247]: [fix(audit): a shipped file named like the end record loses its finding locations](https://github.com/vig-os/vigil/issues/247)

Follow-up to #246 (#13, ruling 13-V6-d4 point 6).

`Verifier::end_before` adds the archive record as an in-memory segment whose findings carry no file and no line. The pass that strips those locations compares the input's file name after reading the end-record flag, so a real shipped file passed under the relative path `<end record>` also loses its locations (probe: a shipped copy holding a record above the end gave `TrailEnded` with `file: None, line: None`; the same file named `endrec.jsonl` stayed located).

Fix: strip locations by the input's end-record flag only, never by its name, and add a literal row with a shipped file named `<end record>`.

Refs: #13
