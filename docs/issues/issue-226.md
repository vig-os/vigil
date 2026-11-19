---
type: issue
state: closed
created: 2026-11-18T23:24:30Z
updated: 2026-11-19T07:59:20Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/226
comments: 2
labels: bug
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-19T09:58:09.847Z
---

# [Issue 226]: [bug(audit): classify counts the closing segment's spans in the run digest](https://github.com/vig-os/vigil/issues/226)

## Defect

`runs::classify` assembles a run's spans over `first_segment..=last_segment`. `last_segment` is the closer, the segment that begins with the resume's opening checkpoint. So bytes in the closing segment *after* the resume enter the run's spans and its run digest.

ADR-0005 decision 11 says otherwise:
- A run is "the consecutive segments right before the segment that begins with that resume's opening checkpoint".
- A span is "a maximal run of non-record bytes inside a segment of the run".
- The closer "may itself be the first segment of the next run" (decision 8).

## Effects
- **The digest is unstable.** A crash that later tears the live file (the closer) changes the run digest of a run nobody touched. A1 plus the 9-byte fragment `{"seq":9,` moves the digest from `79d8cb1c…` to `aeca4d93…`. That breaks an `accept-run` pin.
- **Bytes are counted twice.** In the p01 layout, the closer's `Unparsable` span is in run 1 (`seg 1`) and in run 2 (`seg 0`). One set of bytes is then committed by two `accept-run` digests.
- **Scope.** The only consumer is the verifier's run digest (#13 V4a). The storage reader calls `classify` under `Reaction::Stop`, which builds no reports.

## Fix (ruling 13-V4-d9)
- Spans come only from `first_segment..last_segment`, the closer excluded.
- `loss_points` and `closing_opening` are unchanged.
- The pinned A1/A3/A8/A9 digests are unchanged.
- Two tests that pin the current behaviour become rows asserting the exclusion.

Refs: #13, #197

---

# [Comment #1]() by [gerchowl]()

_Posted on November 18, 2026 at 11:24 PM_

Ruled 13-V4-d9 on #13; fixed on PR #225 (the first consumer of run spans) as its own commit.

---

# [Comment #2]() by [gerchowl]()

_Posted on November 19, 2026 at 07:59 AM_

Fixed in #225 (b929f1f, commit e1fdcc0): a run's spans now exclude its closer (ruling 13-V4-d9).

