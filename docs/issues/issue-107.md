---
type: issue
state: closed
created: 2026-10-12T05:40:43Z
updated: 2026-10-12T19:44:30Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/107
comments: 3
labels: bug
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:26.145Z
---

# [Issue 107]: [audit reader accepts deletion of a live-file prefix down to any checkpoint when no sealed segment is present](https://github.com/vig-os/vigil/issues/107)

Found by a falsifier pre-mortem for B3d1 (#87) on 2026-10-12. It was confirmed with a probe test on `origin/feature/11-audit-public-surface` (B3a), which appended `probe_live_prefix`/`PROBE_A` to `src/audit/storage_tests.rs` and printed `ok=true`.

**What happens.** With no sealed segment present, a keyless attacker can rewrite `audit.jsonl` from `[cp0, e1, e2, C3, e4]` to `[C3, e4]`, and `TrailReader::open` accepts the result. This needs no forgery and works at sub-segment granularity: the reader cannot tell a periodic checkpoint at file start from the opening checkpoint of a trail whose earlier segments were archived.

**Spec conflict.** ADR-0005 decision 8 (~l.575) calls a first complete record that is "not a checkpoint that links … to the genesis value for the first segment" structural loss. That contradicts the archived-prefix acceptance.

**What is needed** (an ADR ruling first, then code and tests):
- Either the reader distinguishes an opening checkpoint from a periodic one (for example, an opening checkpoint at the trail's first file must link to genesis unless an archive marker or an anchored `start_from` says otherwise),
- or the ADR states this as a documented residual that only an anchored `start_from` (`StartMismatch`) catches, and README/B3e documents the anchoring duty.

Related: #87 (B3d1), #13 (verifier and `start_from`).
---

# [Comment #1]() by [gerchowl]()

_Posted on October 12, 2026 at 06:01 AM_

Scope widened by a second probe (B3d1 v2 check, 2026-10-12). Take a trail S0, S1=[O3,e4,P5,e6,C7], live=[O8,e9]. Delete S0 and cut S1 down to its periodic checkpoint P5: accepted (`PROBE_P5 ok=true`). Cut S1 down to C7 alone: also accepted (`PROBE_LASTONLY ok=true`). So the residual affects the **first present segment, sealed or live**, not only a trail with no sealed segment.

---

# [Comment #2]() by [gerchowl]()

_Posted on October 12, 2026 at 03:47 PM_

## Architect ruling 107-d1 (R3, after two pre-mortems): prefix deletion of an audit trail. This is design input for ADR-0005 amendment 10.

**Pre-mortem of R1 (code-falsifier, 2026-10-12): VERDICT blockers.**
- R1's live-side rule holds:
  - a cut of the live directory gives `SeqGap` with no start;
  - it gives `StartMismatch` with the recorded start.
- The pre-mortem found two problems.
  - **H1 (confirmed): the archive is never checked after the move.** The archive is verified as a snapshot (decision 2 step 1), but step 4 moves the segments out of the trail directory itself. A keyless attacker who deletes `S3..S4` in between leaves:
    - `verify --start-from O(S5) <live>` clean;
    - `verify <archive>` alone clean too, because a cut back to a checkpoint is undetectable without an expected end.
  - **P1 (plausible): laundering through a run.** A cut down to a periodic checkpoint can be laundered into an amendment-6 run by an honest operator `resume`. Two problems follow:
    - the records deleted below the head at a loss point are named by no finding;
    - decision 2 step 1 ("no error") can never pass for a trail that contains a run, because `SegmentStructure` is an error, so the "archive a run with everything before it" path cannot be followed.
- A role field (opening, periodic or closing) is not needed: no verify case depends on it.

### Ruling
1. **`TrailReader::open` is a structural check, not a verifier.** At `open`, the first present segment may begin at any checkpoint, because `open` cannot know about archiving. The guarantee against prefix deletion belongs to `verify`:
   - with no start, `seq 0` must be present, otherwise the result is `SeqGap`;
   - with the start from the archive record, the first record must be that start, otherwise `StartMismatch`;
   - the archive itself is checked by procedure step 6 below.

   `expect_head` proves nothing about history before the first present record.
2. **Archive procedure (decision 2, amended):**
   - Steps 1–3 stay.
   - Step 4: **copy the older segments from the snapshot verified in step 1**, never from the trail directory, to the archive destination.
   - Step 5: remove them from the trail directory.
   - Step 6: **verify the archive at its destination together with the trail directory**, with no start, using the anchors and receipts: `vigil-audit verify <archive dir> <trail dir>`. The criterion is the same as step 1's. Re-run it whenever the archive is restored or moved again.

   Step 6 binds the archive's last record to the start through the chain. Deleting any segment from the trail directory before step 5, or from the archive before step 6, becomes `SeqGap`, `ChainBroken` or `StartMismatch`.
3. **Run losses are named.** A run's `SegmentStructure` finding names, for every loss point, the missing `seq` range: from the `seq` after the last complete record that hash-links before it, up to the loss point's `seq` minus 1.

   Step 1's and step 6's criterion becomes: no error except the `SegmentStructure` findings of runs that are closed by a `Resumed` record. That `Resumed` must be accepted (`accept Resumed`), and the reviewer has checked each named range against the deployment's evidence. All warnings must be accepted. The README's review criteria tell the reviewer that a named range below the resume head means records deleted, not records lost in a crash.
4. **ADR-0005 wording**, in one amendment ("amended, #107, architect ruling 107-d1"):
   - l.378 "the history up to it has not been rewritten": limit it to the records present;
   - l.430 "the writer never accepts a line the verifier rejects": name the prefix exception (open vs `SeqGap` without start);
   - l.579 "…or to the genesis value for the first segment" and l.601 "(the creation checkpoint, or the first record kept after archiving)": "any checkpoint";
   - l.979(c): `SeqGap` from 0 may be a deletion, not only a forgotten `--start-from`;
   - l.706 "verified on its own" / "once before moving it": replace with step 6;
   - l.370: holds only for a verify without a start.
5. **Collector copies** (`verify_files`) that start after `seq 0` carry no archive record. They are named as a residual next to the existing one at l.981: the shipper must also ship the archive record.
6. **Where it lands:**
   - the ADR amendment and README text go with B3e (README deployment), or with #13 if that comes first;
   - item 3's finding detail is #13 (the verifier);
   - no change to the reader's code. B3d2's brief cites this ruling.

### Pre-mortem 2 on R2 (code-falsifier): VERDICT blockers. R3 = R2 plus these changes, all binding on the amendment
- **No keyless laundering inside an accepted run.** The run's closing opening checkpoint is signed and folds everything before it. Item 1 is safe for writers.
- **(R3-a) Archive tail and later batches.** Step 6 becomes:
  - batch 1: `verify` over every archive batch back to `seq 0` together with the trail directory;
  - batch n ≥ 2: `--start-from <batch n−1 record>` with its anchor, over archive n and the trail directory;
  - then the trail directory alone with `--start-from <this record>` and its anchor: no error.

  **New step 7, on a schedule (not only on restore or move):** verify each archive batch on its own against its end, `<archive dir>` plus a start-line file. That file holds the archive record's start line, plus the resume record line when the start is a resume opening checkpoint. The start's `prev_hash` pins the archive's last record. The amendment decides between this and an explicit `--expect-end`, and it documents any residual that remains.
- **(R3-b) Run review instead of tolerating an error.** Decision 11 l.750 says no error is ever accepted. So the amendment introduces an explicit review line, for example `accept-run <resume seq> <hash> <ranges digest> <reviewer> <reason>`, which turns every finding of one run into `Accepted`:
  - its `SegmentStructure`;
  - `MmrMismatch` on checkpoints at or after its loss points;
  - the findings at each loss point (specify them: `ChainBroken`/`SeqGap`);
  - receipt findings whose `seq` lies inside a named range.

  It works only when every named range matches the digest; otherwise it is an error, like `AcceptMismatch`. With that line, routine verify returns to exit 0, so a later deletion changes the exit code again (plausible finding 6).
- **(R3-c) README wording.** Every named range and every resume gap means records were deleted or damaged. Neither is ordinary crash loss (l.400: records are fsynced before they are acknowledged).

### Where it lands
#107 becomes the ADR-0005 **amendment 10** docs PR: Claude drafts it, a fresh code-falsifier reviews it, and it uses the pre-mortem findings above as acceptance input. It lands after B3c (#117), because both edit ADR-0005, and before #13 (the verifier) and B3e (README). B3d2 (operator resume) does not wait for it: the command's behaviour doesn't change, and its brief cites this ruling for the review wording.


---

# [Comment #3]() by [gerchowl]()

_Posted on October 12, 2026 at 07:44 PM_

Amendment 10 (archiving and run review; rulings 107-d1 R3, 107-d2, 107-d3) landed via #120 (merge 5c591d8). Leftover doc fixes are tracked in #123. Verifier and CLI implementation is in #13.

