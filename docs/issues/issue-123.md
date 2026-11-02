---
type: issue
state: closed
created: 2026-10-12T19:44:20Z
updated: 2026-10-12T21:02:27Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/123
comments: 2
labels: bug, priority:high, area:docs, effort:small
assignees: none
milestone: none
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:23.639Z
---

# [Issue 123]: [docs(adr-0005): amendment 10 leftovers — --start-from source, l.464 wording, span definition for #13](https://github.com/vig-os/vigil/issues/123)

Found by the final re-review of #120 (merged 5c591d8, ruling 107-d3), after the 3-round cap; fixed through the normal path.

1. **Untrue normative text (N1):** several places still take `--start-from` from the archive record, contradicting l.199 (107-d2/d3: the start comes from the anchor store's batch-start entry of batch n−1): l.722 ("Where it comes from: the archive's own record"), l.733 ("The same file serves as --start-from of the next batch"), l.184 (step 1, batch n≥2), l.880 (test), l.1045, l.1102. The start's byte-equality with the archive record (l.199) has no enforcer since there is no `--start-anchor`: state that the operator passes the anchor-store entry.
2. **l.464 (N2):** opens with "verification reports an error for good, because no error can be accepted", which its own parenthetical now contradicts → "…an error unless an accept-run line commits its span".
3. **l.191 (N4):** doubled parenthesis.
4. **Span definition (N3) for the frozen digest:** l.793 "non-record bytes" leaves open (a) whether a line that parses but is InvalidField/UnknownVersion/MissingField is a record or span bytes, (b) which side owns a record's newline. Decide in the ADR and pin with a golden vector in #13.

Line numbers refer to 3e94cff. Refs #107.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 12, 2026 at 07:44 PM_

## Ruling 123-d1 (architect): span bytes for the run digest (ADR-0005 amendment 10, l.793)

The digest is frozen for 1.x (l.1228), so the span boundaries must be exact before #13 implements them.

- **(a) What is a record.** A complete line is a **record** for span purposes when it decodes as a JSON object far enough for the reader to attribute a record-level finding to it: `InvalidField`, `UnknownVersion`, `MissingField`, or a valid record. Such lines are never span bytes, and their findings stay errors that `accept-run` never accepts (l.803). Only lines the reader classifies as `Unparsable`, together with fragments and their repair newlines, are span bytes. **Why:** making a malformed record a span would let `accept-run` launder a record-level error. Keeping it a record keeps l.803 true.
- **(b) Who owns a newline.** A record's terminating LF belongs to the record. A span holds its own bytes, including the LF that ends an `Unparsable` line and a fragment's repair newline. It ends where the next record's first byte begins, or at end of file. A trailing fragment with no newline is part of the last span.
- **Golden vector.** The amendment gives one worked example with byte offsets: one segment containing a record, a fragment with its repair newline, an `Unparsable` line, a record, and a newline-less tail. It lists the resulting spans (`after`, `len`, D). #13's acceptance gets a test reproducing that vector byte for byte.


---

# [Comment #2]() by [gerchowl]()

_Posted on October 12, 2026 at 09:02 PM_

Fixed by #124 (merge 5d3978e; ruling 123-d1, golden vector verified independently). One leftover phrase tracked in #126.

