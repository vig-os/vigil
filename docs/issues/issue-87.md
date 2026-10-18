---
type: issue
state: closed
created: 2026-10-11T21:10:00Z
updated: 2026-10-12T15:34:40Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/87
comments: 2
labels: bug
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:28.098Z
---

# [Issue 87]: [audit: reader refuses a trail after resume seals a headless live file (ADR-0005 d8 vs B2a reader)](https://github.com/vig-os/vigil/issues/87)

Found by the round-3 falsifier of #86 (audit B2a, head d7e846f). Confirmed against the ADR text; this has to be settled before or in B3 (the operator `resume`).

**ADR-0005 decision 8 (the resume bullet):** "A **headless live file** (present, but its first complete record is no linking checkpoint) … is sealed as it is. It is renamed, unchanged, to the next segment name … and keeps its `SegmentStructure` findings forever as the record of the damage."

**B2a reader (#86, `src/audit/storage.rs`):** every segment must open with a checkpoint. After `resume` seals a headless live file, `open` would therefore refuse the trail for good. The resume declaration in the next file names the predecessor's head, but the sealed headless segment itself fails the opening-checkpoint requirement before that rule applies.

**Open question (an ADR question, not a code guess):** after a resume, must the writer (`open`/`expect_head`) accept a trail whose sealed segment has permanent `SegmentStructure` findings? Decision 5 (l.411) says "a crash never makes the writer refuse a trail the verifier accepts". So the answer depends on whether the verifier accepts that trail (with `Resumed`), and the ADR doesn't say this explicitly for the headless case.

**Done when:**
- an ADR-0005 amendment (or a clarification citing the lines) states the reader's rule for a segment that a matching resume declaration seals headless;
- the reader implements that rule, with positive and negative tests and a mutation check, as in #86's resume-boundary tests;
- B3's `resume` has an end-to-end test: headless live file → resume → `open` with `expect_head`.

Refs: #11
---

# [Comment #1]() by [gerchowl]()

_Posted on October 12, 2026 at 05:20 AM_

Architect note (2026-10-12): the amendment 5 text drafted in the B3 plan was broken by a falsifier pre-mortem. As written, it would let a keyless attacker rewrite a sealed segment so that it holds only its last record, or delete middle segments, and the reader would still accept the trail. The new damage would hide behind the `SegmentStructure` finding that is already permanent. Its justification was also wrong: decision 5 doesn't require it, because `SegmentStructure` is an error.

The adopted text, which lands in B3d:
- The reader accepts a *run* of damaged segments (headless, fragment-only, or containing `Unparsable`) only if both hold:
  - the following opening checkpoint links to the last complete record and is followed by the resume declaration;
  - that checkpoint's MMR size, root and peaks equal the fold over every complete record present before it.
- The reader state is never reset.
- The change is recorded as a deliberate exception to "the writer never accepts a line the verifier rejects".
- The keyless forgery of a whole archived-prefix trail stays the documented residual that only `verify` catches.

---

# [Comment #2]() by [gerchowl]()

_Posted on October 12, 2026 at 03:34 PM_

Fixed by PR #111 (merge 75107d7): the reader accepts a run of segments sealed by `resume` under ADR-0005 amendment 6, as clarified by architect rulings B3d1-d1 through B3d1-d4. The operator `resume` command itself is B3d2, tracked on #11.

