---
type: issue
state: closed
created: 2026-10-09T13:21:59Z
updated: 2026-10-13T06:00:05Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/11
comments: 29
labels: feature, security, priority:medium, effort:medium
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:43.468Z
---

# [Issue 11]: [feat(audit): lossless audit sink and record API](https://github.com/vig-os/vigil/issues/11)

> **Corrected at close (architect, 2026-10-13), as delivered and per ADR-0005:** the record API is `AuditTrail::record(&Entry)`, built with `Entry::new(actor, action, object)` plus `.reason/.before/.after`, not `vigil::audit::record(actor, …)`. Archiving is the operator archive procedure (ADR-0005 decision 2, steps 1–7), which runs outside vigil; there is no archive hook. The original text below is unchanged.

`vigil::audit::record(actor, action, object, before, after, reason)` per the ADR (#10): a separate `audit.jsonl`, fsync per record, fail-closed `Result`, never rotated away (archive hook instead). Optional mirror into `logs.jsonl` for observability.

---

# [Comment #1]() by [gerchowl]()

_Posted on October 11, 2026 at 12:58 AM_

Architect decision: ADR-0005 couples the sink to the cryptography (final `audit.hash`/`audit.prev_hash` per record; due and creation checkpoints signed in the same write and fsync). So #11 and #12 are **one implementation in two serial PRs**: (A) pure format primitives (encoding, chain, MMR, checkpoint signing, golden vectors; BSD-3-Clause added to deny.toml), then (B) the durable sink and record API. Verify stays in #13; the rules still open in #66 are not implemented yet.

---

# [Comment #2]() by [gerchowl]()

_Posted on October 11, 2026 at 03:59 AM_

**From ADR-0005 amendment 2 (#68, PR #77), decision 6:** ext4 in its default `data=ordered` mode counts as supported for regulated use only once a test shows that a crash leaves only a byte prefix of the unacknowledged append, with no zero-filled or stale range. That requires two tests on the Linux lane:

- #11's crash-injection test: writers SIGKILLed mid-write. Each fragment must be a strict prefix and must be attested by the next writer.
- A power-loss test: a VM disk cut off while writers append, with flushes honoured. Every acknowledged record must survive, and the tail must be nothing or a byte prefix. If CI can't run it, make it a documented manual release-candidate test.

The APFS counterpart is in #46's scope.

Refs: #11, #68


---

# [Comment #3]() by [gerchowl]()

_Posted on October 11, 2026 at 10:00 PM_

B2a (directory lock, recovery scan, reader resume-boundary rule) merged via PR #86 (b93ff8a), after 5 review rounds with mutation-tested boundaries. Next: B2b (durability, torn-tail repair via audit.repaired, SIGKILL matrix, truncation properties), then B3 (public sink API; #87 settled there).

---

# [Comment #4]() by [gerchowl]()

_Posted on October 11, 2026 at 10:19 PM_

Architect ruling (B2b1 BLOCKED, ADR-0005 l.486 gave no encoding): the marker `audit.trail` = exactly 32 lowercase hex + one LF (33 bytes), the spelling of the `audit.trail` attribute (l.310) and of the trust file's `trail` line (l.574). Any other form is `CorruptTrail`. It is recorded as an ADR-0005 amendment in the B2b1 PR.

---

# [Comment #5]() by [gerchowl]()

_Posted on October 11, 2026 at 10:21 PM_

Architect ruling (B2b1 BLOCKED, ADR-0005 l.467): checkpoint cadence is trail-wide. `checkpoint_interval` = the in-lock wall clock minus the `timeUnixNano` of the latest checkpoint on disk, whichever process wrote it; the baseline after open = the latest scanned checkpoint (there is always seq 0). A clock step back makes a checkpoint due now. `checkpoint_every` counts records since that checkpoint. Recorded as an ADR-0005 amendment in the B2b1 PR.

---

# [Comment #6]() by [gerchowl]()

_Posted on October 12, 2026 at 02:21 AM_

B2b1 (the durable writer core) merged in PR #92 (843fbcf) after a falsifier on every round. The PR also carries ADR-0005 amendment 4 (strict marker form, trail-wide checkpoint cadence, genesis resume head = 0), Accepted, and marks amendment 3 (#90) Accepted. Next: B2b2 (crash matrix, SIGKILL ≥8 writers, clean-stop writer parts, truncation properties, B1 carry-over, amendment 3 implementation), then B3.

---

# [Comment #7]() by [gerchowl]()

_Posted on October 12, 2026 at 03:32 AM_

B2b2a merged in PR #99 (ab81238): fsync poisoning scope, ADR-0005 amendment 3. Next: B2b2b (crash matrix, SIGKILL ≥8 writers, clean-stop writer parts, truncation properties), then B3. #100 was filed from its review: an eprintln! panic on the signer-failure path that predates this PR.

---

# [Comment #8]() by [gerchowl]()

_Posted on October 12, 2026 at 04:29 AM_

B2b2b merged in PR #103 (8591bcd). It covers the sealing and create crash matrix (each process killed at its step), 20 SIGKILL runs with 8 healthy and 3 killed writers, clean-stop/orphan heads, truncation properties and a reusable crash-fixture module for #13. A fresh falsifier caught 8 of 8 mutants, and runs at 10× scale and under load were green. Next: B3 (split before dispatch).

---

# [Comment #9]() by [gerchowl]()

_Posted on October 12, 2026 at 11:39 AM_

B3a (the public writer surface) merged in #105 (ce8afd4): `AuditConfig`, `AuditTrail` and `Receipt` are now stable; the low-level primitives moved under `--cfg vigil_unstable`; `mirror_to_logs` runs after the lock is released; amendment 5 is the d13 surface. Next: B3b (KeyFileSigner/keygen) and B3d1 (#87 reader rule, amendment 6), then B3c (operator rotate/checkpoint), B3d2 (resume) and B3e (README).

---

# [Comment #10]() by [gerchowl]()

_Posted on October 12, 2026 at 02:46 PM_

B3b (KeyFileSigner + `vigil-audit keygen`, ADR-0005 amendment 7) merged into dev via #108 (13f1b6b). Next slice: B3c (operator rotate/checkpoint with exact-head) is in progress.

---

# [Comment #11]() by [gerchowl]()

_Posted on October 12, 2026 at 02:47 PM_

Architect ruling B3c-d1 (B3c, ADR-0005 amendment 8): an operator-call waiver (resume, and now rotate) covers a call that returned `Io` **or never returned** (process killed, host stopped). The evidence is the operator's own record of the call: its exact arguments, start time, and how it ended. The waived record must be the one record that call writes directly after the named head, equal in full hashed content to the call's arguments, timed within the call window. Reason form: `operator <rotate|resume> started <UTC>: returned Io: <error>` / `… did not return (<killed|host stopped> at <UTC>)`.

---

# [Comment #12]() by [gerchowl]()

_Posted on October 12, 2026 at 02:49 PM_

## Ruling B3c-d2 (architect): answers your BLOCKED on B3c-d1's "directly after the named head"; round 1 continues (architect-caused wording)

Yes. "Directly after the named head" was rotate-shaped wording; each command's waived record sits where that command's documented layout puts it:
- **rotate:** the one record directly after the call's `--expect-head` (seq h+1), under brief 7(d)(ii)/(iii)'s conditions.
- **resume:** the resume record directly after the opening checkpoint the call wrote (ADR-0005 decision 8): the checkpoint at `seq` `lost_through + 1` that links to the call's named `--head`, and the resume record at `lost_through + 2`. Its full hashed content must equal the call: actor, reason, and `audit.details` `head=<seq>:<hash> lost_through=<seq>` from the arguments; `file=` must name the segment that call sealed, as found in the directory, or `-` when the live file was deleted.

Everything else in B3c-d1 holds (evidence = the operator's record of the call; window from start to observed end; fixed reason form; no other record gets the waiver). Write amendment 8 so the waiver sentence states both placements, citing "architect rulings B3c-d1 and B3c-d2". Don't edit `resume`'s rustdoc (B3d2).

Everything else in `briefs/B3c.md` v4 holds. **Last line** `DONE: <PR url>` or `BLOCKED: <reason>`.


---

# [Comment #13]() by [gerchowl]()

_Posted on October 12, 2026 at 05:52 PM_

B3c merged: PR #117 (b74300e). It adds operator `AuditConfig::rotate`/`checkpoint` with an exact-head check, makes ADR-0005 amendment 8 (rulings B3c-d1/d2/d3), and was approved after 2 review rounds. Remaining in #11: B3d2 (operator `resume`, amendment 9), then B3e (README deployment); amendment 10 (#107) goes before #13/B3e.

---

# [Comment #14]() by [gerchowl]()

_Posted on October 12, 2026 at 06:12 PM_

## Ruling B3d2-d1 (architect): operator `resume` design inputs for ADR-0005 amendment 9 (#11)

A full-ADR check of the draft B3d2 brief (code-falsifier, probes P1–P6 against origin/dev b74300e) found that the draft left design open and misread parts of the ADR. These rulings close it. Amendment 9 records them, citing "architect ruling B3d2-d1".

### R1. Write path: settle-style, not `operator_write`
`operator_write` needs an opened `Sink`, and `Sink::open`/`initial_record` return `CorruptTrail` for a deleted, empty or headless live file (P1). Those are exactly resume's states. So resume does not go through `operator_write`. Under the directory lock, held throughout (ADR l.587):
1. the poison check (`Poisoned` first), then the marker check;
2. `settle`, as every writer does, so a pending `.audit-next.jsonl`, an interrupted rotation (including a hard-linked live file, which settle unlinks) or a pending `.audit-resume.jsonl` is resolved first. Resume acts on the post-settle state;
3. `predecessor_run` (sink.rs ~l.314), the fold settle already uses, gives the last complete record found, under amendment 6's base rule. A base that is not a checkpoint returns `CorruptTrail` (ADR l.602: "`resume` refuses with `CorruptTrail`"). No predecessor at all requires `head=0:<genesis digest>` (l.560);
4. build both lines; one write and one fsync of `.audit-resume.jsonl`; directory fsync;
5. promote through **one shared helper extracted from settle's `.audit-resume.jsonl` promotion**: the same validity check and the same renames. The writer can then never produce a staging file that settle would discard. DRY: no second copy of the promote rule.

`OperatorOp`/`ReservedAction::Resume` and the reserved-action validation are reused wherever they apply to building the record.

### R2. Head check
ADR l.585 decides acceptance: "the named head … must be the last complete record found", and "vigil never guesses which case is innocent". The `--head` argument must equal `predecessor_run`'s head exactly (`seq` and hash) in every branch (well-formed, behind, headless, empty, deleted, none). A disk head that equals `head` is accepted: there is no "nothing to resume" refusal (l.872, a no-gap resume). A mismatch, including an older `seq`, the same `seq` with another hash, or a genesis head while segments exist, returns **`HeadMismatch`**, the exact-head rule of amendment 8 (l.656, l.663). `CorruptTrail` is kept for histories the fold rejects.

### R3. Builder `expect_head` on `AuditConfig::resume`
It returns **`InvalidConfig`**, through `validate_operator` with its message generalised. Resume's exact head is its `head` argument. `expect_head` means "present in the chain at open", which has no meaning on a headless, empty or deleted live file.

### R4. Empty live file
An empty live file is headless (it has no linking checkpoint, l.587). It is **sealed** to a segment like any headless file, and `file=` names that segment. Amendment 6 already reads a segment that holds no complete record as a run member. `file=-` means only "the live path was missing after settle" (l.587, B3c-d2).

### R5. `file=` is fixed under the lock, before the staging write
Today `rotate::rotate` picks the nanosecond-stamped name at rename time and doesn't return it. After a crash, the promoted record would then name a file that doesn't exist (P3), and B3c-d2's waiver condition (content equal including `file=`) could never be met. Ruling:
- `resume` picks the segment name under the lock **before** the staging write, with the same naming function and a no-replace existence check. It writes that name into `file=`. The seal rename uses exactly that name, no-replace.
- **Promotion (inline, and settle after a crash)** requires the directory to match the record:
  - `file=-` requires the live path to be missing;
  - `file=<name>` requires either the live file present (rename it to `<name>`, no-replace) or the live file missing with `<name>` present (the rename already happened before the crash).
  - Any other state discards the staging file under the ADR's existing rule ("Any other content … is discarded: nothing in it was acknowledged, and the operator runs `resume` again", l.560). The receipt is printed only after the final directory fsync, so nothing was acknowledged.
- The verifier still reads only `head=` and `lost_through=` (l.587). `file=` is truthful for the waiver and for humans.

### R6. Genesis leaf
The genesis-base ruling fixed `mmr_size` 1 but not the leaf, and the reader accepts any single peak (P5b). The creation record is lost, so its hash can't be the leaf. Ruling: in a genesis-linked resume (`head=0:<genesis digest>`), the single leaf is the **named head's hash, the genesis digest**, pushed exactly as the fold pushes any present record's hash. This is the general rule ("the fold covers the base and the named head"), applied to the genesis value. It is computable by every reader from the trail id, so it is checkable. The reader enforces it in the amendment-4 and amendment-6 paths (reuse the fold; no special-case copy). Anchors of the old creation root no longer match, which is expected after a declared loss and reported as such.

### R7. A writer handle open across a resume
The lock is taken per write, so another handle (in-process or in another process) can stay open across a resume. Its next `record`, under the lock, must refresh, observe the resume, and continue **after the resume record**: `seq` `lost_through + 3`, linked to the resume record. It must never write at a stale `seq` or link to the pre-resume head. P6 showed today's handle returning `Ok(4)` and `Ok(9)` for lost 0 and lost 5; pin the correct values with tests. If the existing refresh path can't do this without a design change, report `BLOCKED: design question` with the layout.

### R8. Drop
`Drop` of the returned `AuditTrail` follows decision 8 (d) (l.525), a best-effort checkpoint. Delete the draft's "Drop writes no checkpoint" criterion.

### Required pre-mortem (implementer, short, before code)
Look for an honest path that R1–R7 break:
- a crash at every point of the sequence (pick name → staging write → fsync → seal rename → staging rename → dir fsync), against R5's promotion rule;
- a hard link to the live file;
- a pending `.audit-next.jsonl`;
- a concurrent rotate, checkpoint or resume in another process;
- archiving (base) under a genesis resume.

If one breaks, stop with `BLOCKED:` and name the path, the layout and the test.


---

# [Comment #15]() by [gerchowl]()

_Posted on October 12, 2026 at 06:27 PM_

## Ruling B3d2-d2 (architect): amends B3d2-d1 after the pre-mortem of brief v2 (#11)

A second code-falsifier pre-mortem probed B3d2-d1 against origin/dev b74300e. It confirmed four defects in the ruling. R1–R4 and R8 of B3d2-d1 stand; this ruling amends R5, R6 and R7, adds R9 and R10, and splits the work.

### R5' The promotion rule replaces ADR l.560's "renames the live file, if present"
B3d2-d1 R5 stands: the name is fixed under the lock before the staging write, and promotion requires the directory to match `file=`. It changes merged ADR text, though, so amendment 9 must **replace** the l.560 sentence "Promotion renames the live file, if present, to its next segment name (no-replace)" with the R5 rule. Existing fixtures that write `file=-` beside a present live file must be migrated: parameterise `resume_bytes` with `file=`. The six known ones are:
- `resume_promotes_over_live_opening_checkpoint`
- `resume_staging_every_prefix_with_and_without_gap`
- `resume_discards_sequence_below_next`
- `resume_settlement_promotes_over_archived_live_prefix`
- `poison_835_rename_directory_fsync`
- `poison_844_check_before_settlement`

The shared promote helper names the segment from the record's `file=`. Settle's `.audit-resume.jsonl` arm stops calling `rotate::rotate`, which picks a fresh name. The naming function is the private `next_segment_name` in `src/rotate.rs` (~l.647–690); expose it `pub(crate)`, with no second copy.

### R6' The genesis leaf is the genesis digest, and l.604 and l.519 are amended
B3d2-d1 R6 stands. The creation record is lost in a genesis-linked resume, so `seeded(creation)` cannot be computed by any writer or reader. The leaf must be a value every reader derives from the trail id. Amendment 9 must **replace** these two passages:
- l.604's "seeded as `seeded()` does" becomes: the single leaf is the genesis digest, pushed as the fold pushes a record hash.
- l.519's "includes at least that creation leaf" becomes: at least one leaf, the creation record or, after a genesis-linked resume, the genesis digest.

Migrate these four fixtures, which build the leaf from a creation record the real writer would not have:
- `resume_without_predecessor_promotes_genesis_link`
- `genesis_resume_requires_immediate_matching_declaration`
- `runs::genesis_resume_after_fragment_only_first_segment_keeps_creation_leaf`
- `runs::never_rotated_creation_loss_requires_moving_evidence_then_settles_resume`

Rejected alternative: keeping `seeded(creation)`. No production writer can compute it, so it would only ever be written by tests.

### R7' A writer handle open across a resume rebuilds from the directory, and fails closed on contradicting evidence
`refresh` (storage.rs ~l.543) chains from the cached state on the old descriptor. A resume whose head is behind the handle's cache, or a deleted or headless resume, therefore errors on every later record. Ruling:
- When refresh finds that the live file was replaced by one that opens with an opening checkpoint plus `vigil.audit.resume`, and the named head is **not** the handle's cached head, the handle drops its cache and rebuilds it from the directory, through the same path `open` uses (`initial_record`/`open_marked`; no second fold).
- **Fail closed on contradicting evidence:** if the handle's own highest acknowledged `seq` (a receipt it returned) is above the resume's `lost_through`, the resume reused a `seq` this process acknowledged. `record` then returns `HeadMismatch` and writes nothing, on that call and every later one. This is the writer-side mirror of decision 5's "lower than a held `seq` fails closed".
- Otherwise, the next record continues at `lost_through + 3`, linked to the resume record.

Tests:
- the cases the pre-mortem found failing today, with lost 0 and lost 5: resume head behind the cache (rolled-back live), deleted live with a genesis resume, and a headless live;
- the fail-closed case;
- the case that already passes (head equals the disk head), kept as a regression test and not counted as a change proof.

### R9 Settle completes an interrupted rotation first
A live file that is a hard link to a segment name (the same inode, link count above 1) is the completed half of a no-replace rename. Settle unlinks the live name **first**, unconditionally, before any staging rule. The state that follows is then whatever it really is: if a valid staging file exists, it is promoted; otherwise the live path is missing and `open` reports structural loss, which `resume` handles with `file=-`.

Today settle unlinks only while promoting a valid staging file. A hard-linked live file with no staging file is then `CorruptTrail` forever, and a resume that seals it under a second name breaks `predecessor_run`. Add a crash fixture between `linkat` and `unlink`. Amendment 9 states the rule.

### R10 Archive plus genesis resume is an operator precondition, and the verifier detects it
If segments were archived and every present file is lost, `predecessor_run` finds no predecessor, so R2 requires `head=0:<genesis>`. That resume restarts the MMR and breaks the link to the archive; the writer cannot see the archive. So:
- `resume`'s rustdoc and amendment 9 state the precondition: restore archived segments before resuming. This matches l.602's "until the archived predecessor is restored".
- The verifier (#13) reports a genesis-linked resume whose trail id also has archived segments as an error. I will add this to #13's acceptance.

### Split (the scope exceeds the ~450-line limit)
- **B3d2a: settle and reader rules.**
  - R5' promotion rule, including the shared helper and `next_segment_name` made `pub(crate)`;
  - R9 hard-link-first;
  - R6' genesis leaf in the reader's amendment-4 and amendment-6 paths;
  - fixture migration;
  - amendment 9 part 1, which replaces l.519, l.560 and l.604 and states R9.
- **B3d2b: the `resume` surface.**
  - `AuditConfig::resume` per R1–R4 and R8;
  - R7' refresh rebuild and fail-closed;
  - rustdoc with B3c-d1/d2's waiver text and R10's precondition;
  - public-API files;
  - amendment 9 part 2.

  It is dispatched after B3d2a merges.

Both edit ADR-0005, so B3d2a waits for #107's PR to merge.


---

# [Comment #16]() by [gerchowl]()

_Posted on October 12, 2026 at 06:48 PM_

## Ruling B3d2-d3 (architect): amends B3d2-d2 after the B3d2a pre-mortem (#11)

A fresh pre-mortem of the B3d2a brief prototyped R5' and R6' on origin/dev b74300e. R6' breaks exactly the 4 named fixtures and R5' exactly the 10 named ones. It also found four defects. R5', R6', R7', R9 and R10 stand, amended as follows.

**R5'' `file=` must name a valid next segment.** The reader only requires `file=` to be non-empty with no whitespace. Under R5', settle would rename the live file to `foo.jsonl`, `../x`, `audit.poison` or a name that sorts before an existing segment, and the trail would stay `CorruptTrail` for good (probed). So the shared promote helper accepts `file=` only when it is one of:
- `-`;
- a name that `parse_segment(_, "audit")` accepts and that sorts after every other present segment.

When the live file is missing, the named segment must be the newest one present. Any other value is discarded under the ADR's discard rule. Amendment 9's l.560 replacement states this, and tests cover each rejected form.

**R9' hard-link-first is a defence that enables recovery, not an honest crash path.** Sealing step 2 (l.534) makes `.audit-next.jsonl` durable before the live file is renamed. An honest crash between `linkat` and `unlink` therefore always leaves a valid staging file, which today's settle already promotes. The only hard-linked state with no staging file is not honest.

R9 stays, because without it that state is `CorruptTrail: record rolled back` forever, and `resume` can't recover it: sealing the file under a second name breaks `predecessor_run`. After R9 it is "live path missing", which `resume` handles with `file=-`.

Tests:
- build the no-staging fixture by hand and label it non-honest (defence);
- keep the honest sealing crash, a hard-linked live file plus `.audit-next.jsonl`, as a regression test that must still promote;
- add a fault-injection seam in `rename_with`, so the crash between `linkat` and `unlink` is reachable in tests. `rotate::rotate` hardcodes `rename_new`, and Linux never takes the fallback.

**l.604 replacement:** replace the **whole** sentence "Its opening checkpoint carries the creation leaf exactly as amendment 4 and decision 8 already define it (…)" with the R6' statement: `mmr_size` 1, the single leaf is the genesis digest pushed as the fold pushes a record hash, and the reader enforces it. No sentence may survive that says otherwise.


---

# [Comment #17]() by [gerchowl]()

_Posted on October 12, 2026 at 07:46 PM_

## Ruling B3d2-d4 (architect): answers your BLOCKED on the fsync count (architect-caused; round 1 continues and doesn't count)

**One directory fsync after all of settle's directory mutations; criterion 4b is right.** Do 3, the R9 insertion and criterion 5 are wrong where they ask for a separate fsync right after the R9 unlink. Remove that fsync.

### Why
ADR-0005 sealing (l.547–549 on current dev) renames, renames again, and then fsyncs the directory once. That single fsync is what makes the new state durable before anything is acknowledged. The R9 unlink needs no durability of its own:
- if a crash makes the unlink revert, the next settle sees the hard link again and redoes it. R9 is idempotent;
- nothing is acknowledged between the unlink and the promotion.

A second fsync would add a durability point that the ADR doesn't define and that no test could distinguish.

### Rule (write it into amendment 9's R9 text)
Settle performs its directory mutations in order:
1. the R9 unlink;
2. then the staging promotion renames (R5'').

It issues **one** directory fsync after the last mutation and before it returns, whenever it changed the directory at all. That includes the non-honest no-staging case, where the R9 unlink is the only mutation. Recovery is idempotent at every crash point between those steps.

### Tests
- Through the `rename_with` seam and the existing fsync hook, crash after the unlink and before the promotion, then crash after the promotion and before the fsync. Settle again each time: same final state, exactly one directory fsync per settle that mutated.
- Mutant "fsync before the promotion instead of after" → exit 101 (the post-promotion state is not covered by an fsync).

Everything else in `briefs/B3d2a.md` holds. **Last line** `DONE: <PR url>` or `BLOCKED: <reason>`. Overwrite receipt B3d2a-1.json.


---

# [Comment #18]() by [gerchowl]()

_Posted on October 12, 2026 at 07:48 PM_

## Ruling B3d2-d5 (architect): answers your BLOCKED on R6' (architect-caused; round 1 continues and doesn't count)

**The single peak is the leaf hash the fold produces: `Mmr::new()` with the genesis digest pushed, exactly as the fold pushes any record hash.** That is `blake3(0x00 || "blake3:<hex of the genesis digest>")`, the leaf construction at ADR-0005 l.517. It is **not** the raw genesis digest. R6' already says "pushed as the fold pushes a record hash". Acceptance criteria 6, 7 and 9, where they demand the raw digest as the stored peak or root, are wrong.

### Do
- Writer side and fixtures: the genesis-resume opening checkpoint stores `mmr_size` 1, with peaks and root equal to the MMR from pushing the genesis digest through the **same** push function the reader's fold uses. Don't hand-hash it, and don't add a second leaf function.
- Reader: enforce it by comparing against that same fold result (one check point, no special-case copy).
- Criteria 6, 7 and 9 assert equality with that fold output.
  - Mutant "store the raw genesis digest as the peak" → exit 101.
  - Mutant "accept any single peak" → exit 101.
- Amendment 9's l.604 replacement sentence says "the single leaf is the genesis digest, hashed as a leaf like any record hash (l.517)", so no reader can take the raw digest for the peak.

Everything else in `briefs/B3d2a.md` and ruling B3d2-d4 holds. **Last line** `DONE: <PR url>` or `BLOCKED: <reason>`. Overwrite receipt B3d2a-1.json.


---

# [Comment #19]() by [gerchowl]()

_Posted on October 12, 2026 at 09:44 PM_

B3d2a (settle/reader rules for resume; amendment 9 part 1; rulings B3d2-d1..d5) landed via #125 (merge c060d94, 2 rounds). Two nits (stale '(l.517)' cite in the genesis-base paragraph; unreachable `|| (root_link && head.seq > 0)` at storage.rs ~l.825) are carried into B3d2b (resume surface, amendment 9 part 2), which is next.

---

# [Comment #20]() by [gerchowl]()

_Posted on October 12, 2026 at 09:52 PM_

## Ruling B3d2-d6 (architect): B3d2b design closure after the brief pre-mortem (#11)

A fresh pre-mortem read the B3d2b brief against dev c060d94 (B3d2a merged). R7' and the inline path need state and changes the brief did not name. Rulings:

**R7'' (a writer handle across a resume).**
- **State:** each handle tracks its **highest acknowledged `seq`**: one `AtomicU64`, raised with `fetch_max` by every returned `Receipt` (including signer-down acknowledgements) and by every `Checkpoint` that `checkpoint()` or `close()` returns. Its start value 0 is safe.
- **Trigger:** under the lock, before `history_segment` folds from the cache, the handle checks whether any `vigil.audit.resume` lies after its boundary, in a sealed segment **or** the live file. The trigger is wider than "the live file opens with a resume": a later rotation can seal the resume first. `TrailReader::refresh` reports the `lost_through` values it observed, and the sink decides.
- **Decision:**
  - If the minimum such `lost_through` is below the handle's highest acknowledged `seq`, the handle fails closed with `HeadMismatch`, sticky.
  - Otherwise it drops its cache and rebuilds through `open`'s path (no second fold).
  - Equality (acknowledged == `lost_through`) continues. That is the boundary case; test it so the `>`/`>=` mutant dies.
- **Gate:** the sticky fail-closed flag gates **every** write path in `with_current`: `record`, `checkpoint`, `close` and `Drop`'s best-effort checkpoint. A contradicted handle writes nothing ever again.
- **Tests:**
  - the rotation-after-resume sequence (handle H idle → resume behind H → another process records and rotates → H records);
  - the boundary equality case;
  - the fail-closed case on every write path, including Drop.
  - Expected `seq` values must account for R8: dropping resume's returned handle writes a checkpoint, so keep it alive or expect +1.
  - "behind, lost 0" and "headless, lost 0" are not honest states. Drop them.

**R11 (the inline path).**
- Resume runs steps (a)–(h) inside **one** lock acquisition, in `open_marked`'s `prepare` as `Sink::open` does, with the expected head set to resume's head. Then a receipt for a resume that took effect can never be lost to a second open.
- `promote_resume` returns an explicit outcome (`Promoted`/`Discarded`, a proper enum, no `Ok(())` on discard). The inline resume treats `Discarded` as an internal invariant violation, `Io`/`CorruptTrail`, and never hands out a receipt for it.
- `staged_records` reads from a **read** descriptor: reopen the staging file with `existing(dir, ".audit-resume.jsonl", false)`. The write descriptor is `WRONLY` (EBADF).
- The name pick uses a `pub(crate)` wrapper around rotate.rs's private `stamp()`/`next_segment_name`. Don't copy them.
- Resume gets its own fault seam before the lock, separate from `operator_write`'s `operator-before-lock`.

**R2' (genesis head).** A genesis head (`0:<genesis>`) is required **iff** `predecessor_run` finds no complete record. Otherwise it is `HeadMismatch`. Being literal about "segments exist" breaks one honest path: a resume seals an empty live file, then the new live file is lost. Add that layout as an Ok test.

**Split** (size is ~380–450 against the 450 cap):
- **B3d2b1:** R7''. Handle acknowledgement tracking, the widened trigger, fail-closed gating of every write path, rebuild through `open`. Tests build resume layouts with the existing settle/`resume_bytes` fixtures, so the public `resume` is not needed yet. ADR text: amendment 9's R7 paragraph. Also the two carried nits (stale "(l.517)" cite; the unreachable `root_link` condition at storage.rs:821).
- **B3d2b2:** the `AuditConfig::resume` surface, with R1–R4, R8, R11 and R2'. Rustdoc (waiver per B3c-d1/d2 at ADR l.409–411; R10 restore-archives precondition; run-review pointer to amendment 10, without editing it), public-API files, and amendment 9 flipped to Accepted (header l.12, inline marker l.574).

**Criteria hygiene.**
- A test of a new API fails before the change as a compile error. Runtime proofs come from mutants (exit 101), so say that.
- Drop criteria that already pass on dev: the settle half of criterion 8, criterion 13's count mutant, and criterion 6 duplicating criterion 5.
- Criterion 14: assert directly that the staging file is 0 bytes after a returned `Io`. Don't claim "the next writer promotes" as a failure (l.485 allows it).


---

# [Comment #21]() by [gerchowl]()

_Posted on October 12, 2026 at 10:04 PM_

## Ruling B3d2-d7 (architect): answers your BLOCKED on the equality boundary (#11). Round 1 continues; the block is architect-caused.

You are right. In your layout, H acknowledges A=3, the live inode is truncated to the valid predecessor B=1, and a resume declares lost_through=3. `refresh` returns `CorruptTrail("old live descriptor was truncated")` at storage.rs:578 before it can see the resume. My ruling B3d2-d6 put the trigger "before `history_segment` folds from the cache", but your brief's step 4 put the report inside the fold, after the truncation check. The two contradict, so the brief is wrong and the ruling is made precise here.

### R7''' Discover the resume before you validate the cache
1. **Discovery is a bounded header read, not a fold.** A resume is only ever written as the **second record of a file**: promotion makes the two-line staging file the live file, and a later rotation only renames that file. The sink therefore finds every resume after its boundary by reading **only the first two records** of each file after the boundary, under the lock and after `settle`:
   - the boundary is the segment whose (dev, ino) equals the cached descriptor, as `refresh` locates it today;
   - otherwise, if that inode was sealed under no name, archived or deleted, it is `cache.sealed_before`;
   - the files read are the segments sorting after the boundary, then `audit.jsonl`.

   Put this in one `pub(crate)` function in storage.rs, for example `resumes_after(dir, trail, &Cache) -> Result<Option<u64>, AuditError>`, which returns the minimum `lost_through`. It reuses the existing record parser, with no second parser and no second fold. A file that has an opening checkpoint followed by `vigil.audit.resume` counts; any other file contributes nothing.
2. **Order in the sink's write path:** settle → `resumes_after` → decide → only then either `refresh` or the rebuild.
   - **`None`:** run today's `refresh` unchanged. Its shrank/truncated `CorruptTrail` checks still guard every case without a declared loss. Keep a regression test: truncated live, no resume → `CorruptTrail`.
   - **`Some(L)` with `L < A`:** sticky `HeadMismatch`, nothing written (d6).
   - **`Some(L)` with `L >= A`:** discard the cache without validating it against the old descriptor, because the operator's resume declared that loss. Rebuild through `open`'s path, which folds and validates the whole trail, including the resume record. If that open fails, return its error.
3. **Same inode:** a promotion always gives the live path a new inode, so if (dev, ino) is unchanged, no resume lies after the boundary. The same-inode branch of `refresh` stays as it is. Say this in a comment that cites this ruling.
4. **Readers:** `TrailReader::refresh` keeps today's behaviour, and a reader handle across a resume still errors. Reopening it is the documented path; one rustdoc sentence says so. Your brief's step 4 (an out-param on the fold) is **replaced** by this ruling. Do not add it.
5. **Trust:** discovery reads `lost_through` from records that have not been validated yet. That is safe:
   - `L < A` only fails closed, and a closed handle writes nothing;
   - `L >= A` proceeds only through `open`'s full validation.

   State this in the rustdoc of `resumes_after`.

### Tests (each must fail before the change: a compile error, or a mutant with exit 101)
Keep every d6 test and add these:
- your `resume_boundary_equality_after_truncated_live` (A=3, B=1, L=3 → the next record has `seq` 6 and is linked to the resume record);
- the same layout with L=2 → sticky `HeadMismatch` on record, checkpoint, close and Drop, not `CorruptTrail`;
- truncated live with no resume → `CorruptTrail` (regression);
- a resume sealed by a later rotation (resume behind H → another handle records and rotates → H records). Discovery must find it in the segment, not in the live file.

### ADR text
Amendment 9's R7'' bullet also states the discovery rule ("a resume is only ever the second record of a file; the handle reads the first two records of each file after its boundary before it validates its cache") and cites "architect rulings B3d2-d6, B3d2-d7".

Everything else in `briefs/B3d2b1.md` holds. **Last line** `DONE: <PR url>` or `BLOCKED: <reason>`. Overwrite the receipt `/home/larsgerchow/.local/state/architect/vigil/receipts/B3d2b1-1.json`.


---

# [Comment #22]() by [gerchowl]()

_Posted on October 12, 2026 at 11:44 PM_

B3d2b1 (R7''/R7''': rulings B3d2-d6 and B3d2-d7) merged into dev as #127 at 9aed00b, after 2 review rounds. Its 2 nits (a CHANGELOG blank line, and a shared `segments_after` helper for the duplicated skip loops) are carried into B3d2b2, which is next: the `AuditConfig::resume` surface, with amendment 9 moving to Accepted.

---

# [Comment #23]() by [gerchowl]()

_Posted on October 12, 2026 at 11:49 PM_

## Ruling B3d2-d8 (architect): closes the B3d2b2 design gaps a brief check found against dev 9aed00b (#11)

A fresh code-falsifier checked the B3d2b2 brief against the merged B3d2b1 (#127, 9aed00b). It found decisions the brief left open or got wrong. The rulings:

**R2'' (head rule, replaces the brief's "`HeadMismatch` when `head.0 == 0` and a predecessor exists").**
`want = predecessor_run's head, or (0, genesis digest) when it finds no complete record`. Resume returns `HeadMismatch` **iff** `--head != want` (both `seq` and hash).
- A live file rolled back to just the creation checkpoint gives `want = (0, <creation hash>)`, and resuming from it is valid (ADR "must be the last complete record found").
- R2' (genesis iff no predecessor) is the special case of this rule where nothing is found.
- Add an Ok test for the creation-only rollback.

**R11' (one lock acquisition, no expected head).**
- Resume makes **one** `TrailReader::open_marked(path, None, prepare)` call. Its `prepare` closure runs the whole resume (poison check through the final directory fsync) and captures the receipt.
- The expected head is `None`, because R2'' has already been checked under that lock. `initial_record`'s expected-head check can never match the genesis head, which is not a record.
- No second open and no second lock.

**R12 (the returned handle's acknowledged `seq`).**
- The `AuditTrail` returned by `resume` starts with its acknowledged `seq` = `lost_through + 2`, the seq of the resume record's receipt (ADR R7'': "every returned receipt"). It is raised before return.
- If that raise is missing, a later resume declaring `lost_through + 1` would not trip `resume_check`, and the handle would rebuild over a `seq` the operator holds.
- `Sink::acknowledge` is private to `sink`, so the resume path lives in `sink.rs`, or the method widens to `pub(super)`. Never make it `pub`.
- Mutant proof: skip the raise; a second resume with `L' = lost_through + 1` must then make the first handle's next write return a sticky `HeadMismatch`.

**R13 (signer).** The signer passed to `resume` signs the opening checkpoint and **becomes the returned handle's signer**, as with `Sink::open`. It is used for `record`, `checkpoint`, `close` and R8's `Drop` checkpoint. Delete the brief's "the resume signer is not stored".

**R14 (resume entry fields).** The waiver (ADR l.411) needs every hashed field to be a function of the call, so:
- `object` = the trail id, as 32 lowercase hex, mirroring `vigil.audit.key_rotated` (ADR l.677).
- `actor`, `reason` and `details` are as the ADR states (l.602).
- Time and service come from exactly the same context that `operator_write` uses for `key_rotated`. Build the record with `ReservedAction::Resume.record(ctx, entry)`, as `KeyRotated` does (sink.rs:866). `record_internal` is `#[cfg(test)]`.
- The amendment-9 text states the object rule, citing this ruling.

**R15 (staging failures, ADR l.477–479, amendment 3 rule 1).**
- **Failed data or directory fsync of `.audit-resume.jsonl`:** truncate to 0 without an fsync. If that truncate fails, create `audit.poison` naming the staging file. Return `Io` and no handle.
- **Failed write:** truncate to 0 and return `Io` **without poisoning, even if the truncate fails** (settlement discards a torn prefix).
- Do not hand-roll this: generalise `Sink::stage` (sink.rs:649, which hardcodes `.audit-next.jsonl`) to take the staging name, and reuse it. Its existing fsync flag already gates the poison.

**R16 (`Discarded`).** An inline `promote_resume` that returns `Discarded` is an invariant violation. It returns `AuditErrorKind::Io` with a message naming it, and **no receipt**. By then `promote_resume` has already unlinked the staging file and fsynced the directory. Say so in a comment.

**Criteria hygiene.**
- Drop the count mutant `(".audit-resume.jsonl", 2) → 1`. It already fails on dev (`resume_staging_every_prefix_with_and_without_gap`, exit 101), so it proves nothing new.
- Drop the settle half of the every-byte-prefix criterion, which dev already tests. Keep only the inline API path.
- Drop "base not a checkpoint" from criterion 7, which duplicates criterion 6.
- Criterion 14, rule 2: assert that `audit.poison` exists, not "a second writer promotes stale state".

**ADR flip.** Amendment 9 → Accepted in **both** status places:
- l.3: "amendment 9 (… settle/reader rules for operator resume) Proposed (2026-10-12)";
- l.12: replace "Proposed" with "Accepted (2026-10-13, [PR #<n>])", and extend the cite to "B3d2-d1 … B3d2-d8".
- Un-mark the inline "(Proposed)" headings of R9 and R7'' (l.575).


---

# [Comment #24]() by [gerchowl]()

_Posted on October 12, 2026 at 11:56 PM_

**Addendum to ruling B3d2-d8, from the second brief check:**
- **R12 proof layout:** run resume 1 (L=5) and keep its handle H alive. Delete the live file, then run resume 2 with its head at the sealed predecessor, L'=6 and `file=-`. H's next write must return a sticky `HeadMismatch`.
- **R14 context:** `RecordContext::new(trail, L+2, clock, service, opening.hash())` builds the resume record, and `(trail, L+1, t, service, head.1)` builds the opening checkpoint.
- **Mirroring:** when `mirror_to_logs` is set, the resume record is mirrored after the lock is released.
- **Errors after a promote:** once the promote has happened, any error after it returns as `Io`, never `CorruptTrail` (ADR l.485).
- **Signature:** `actor` and `reason` take `impl Into<String>`, as `rotate` does.

---

# [Comment #25]() by [gerchowl]()

_Posted on October 13, 2026 at 12:02 AM_

## Ruling B3d2-d9 (architect): answers your BLOCKED on the lost future-dated boundary (#11). The block is architect-caused and doesn't count as a round.

You found a real limit of R7''' discovery. In your layout:
- handle H has acknowledged A;
- its `sealed_before` is a segment stamped 2099, because the clock was wrong when it rotated;
- that segment and the live file are then lost;
- an earlier base remains, and a resume with L = A succeeds;
- after the clock is corrected, a later rotation seals the resume file under a name that sorts *below* H's retained boundary.

Discovery skips it, and H returns `CorruptTrail` instead of continuing (`premortem_resume_after_lost_future_boundary_and_rotation`, exit 101).

### Ruling: fail closed with `CorruptTrail`, a documented limit; no new mechanism
- **Why this is safe.** A resume that discovery misses can never be continued past silently. H's `refresh` folds from its cached state, and the files after the missed resume link to the resume record, not to H's cached head. So the fold refuses (`CorruptTrail`) and nothing is written. The failure mode is "the handle must be reopened", never "a `seq` is reused".
- **Why not make it continue.** Segment names order by wall clock (ADR-0002 decision 5). Once the boundary segment is lost and the clock has gone backwards, no name-based rule can tell which resumes are newer than H. Scanning every segment would make older, honest resumes (L < A) fail closed as `HeadMismatch`. Scanning none would hide new ones. A trail-content rule would be a new design at this stage for a double-fault case (clock rollback *and* tail loss). ADR-0005's principle "vigil never guesses which case is innocent" applies.
- **Operator path.** `open` again. A fresh `open` folds the whole present trail and needs no boundary.

### Do (in this PR, B3d2b2)
1. Keep your fixture as a **test that pins the limit**. H's next `record`, `checkpoint` and `close` each return `CorruptTrail` and write nothing: the live file's bytes are unchanged and no staging file is left behind. A fresh `open` then continues at `L+3` (or `+1` after any record). Rename it to `resume_lost_future_boundary_fails_closed`.
2. **ADR-0005 amendment 9, R7'' bullet:** add one sentence. "Discovery relies on segment names sorting by time. If a handle's boundary segment is lost and the clock went backwards, a later resume may sort below the boundary and go undiscovered; the handle's fold then refuses with `CorruptTrail` and writes nothing, and the operator reopens the trail (architect ruling B3d2-d9)."
3. Add one line in the `AuditTrail` rustdoc's errors section (or wherever R7'' is documented in rustdoc) with the same limit and its remedy.
4. Continue with B3d2b2 as briefed. Every other pre-mortem item that passed stays as you found it.

Overwrite the receipt `/home/larsgerchow/.local/state/architect/vigil/receipts/B3d2b2-1.json` when you finish. **Last line** `DONE: <PR url>` or `BLOCKED: <reason>`.


---

# [Comment #26]() by [gerchowl]()

_Posted on October 13, 2026 at 01:43 AM_

## Ruling B3d2-d10 (architect): the lost_through bound is int64, and every resume input is validated before signing (#11)

The #132 review found that ADR-0005 (l.603, l.952) and the `resume` rustdoc bound `--lost-through` at `u64::MAX − 2`. But `seq` lives in OTLP's int64 domain (`validation.rs:309`), so:
- the documented bound is untrue;
- `L = i64::MAX − 1` is refused only after one `sign()`;
- a 1.1 MB `reason` is refused (`TooLarge`) only after one `sign()`.

That breaks the rule that a refused call signs nothing.

**Rule.**
1. **The bound is `lost_through ≤ i64::MAX − 2`**, so that both new `seq`s (`L+1` for the checkpoint and `L+2` for the resume record) fit the OTLP int64 domain. Any larger value returns `InvalidConfig` (exit 2 in the CLI). Amend ADR-0005 l.603 and l.952 from "`u64::MAX − 2`" to "`i64::MAX − 2` (`seq` is OTLP int64)", citing this ruling. Fix the rustdoc to match.
2. **A trail at the top of the seq domain.** With `L = i64::MAX − 2`, the resume succeeds. The returned handle's next `record` then returns `InvalidConfig` ("sequence exceeds OTLP int64"), the same as any trail that reaches `i64::MAX`. Document it in one sentence and pin it with a test.
3. **Validate everything before any `sign()`**, under the lock and before the staging write. That covers:
   - the seq bound;
   - actor/reason validation;
   - the reserved prefix;
   - the encoded size of both records against the record limit, which gives `TooLarge`.

   Build the two records and size-check them before signing, or derive the size bound without signing. A test asserts zero `sign()` calls for each refusal: `L = i64::MAX − 1`, `L = u64::MAX`, an oversized `reason`, and a reserved-prefix actor or reason if the API can carry one.


---

# [Comment #27]() by [gerchowl]()

_Posted on October 13, 2026 at 03:12 AM_

B3d2b2 merged in #132 (3d6be28): the operator `resume` surface, with ADR-0005 amendment 9 now **Accepted**. This completes the #11 write side. Rulings B3d2-d1 through B3d2-d10 are all implemented and pinned by tests, and the two d10 limit mutants and the R16/R2''/R12/R15 mutants are all caught.

Still open on this issue, carried into B3e:
- the README deployment section;
- the B3d1 residuals;
- the #107 duties;
- R10 restore-archives;
- #126;
- **a review nit from #132:** ADR-0005 l.631 says "Part 1 above defines promotion", but the R5'' promotion bullet (l.572) is not labelled part 1. B3e labels it.

The verifier and CLI halves remain in #13.

---

# [Comment #28]() by [gerchowl]()

_Posted on October 13, 2026 at 05:55 AM_

B3e is complete: B3e-1 (#137, 292ee3c) added the README deployment text, and B3e-2 (#140, 89472d6) added the operator duties for ADR-0005 §18.4 duties 2–5, `--strict`, and the operator-duty checklist. Every README duty the ADR assigns is now covered. Still open: #13 (verifier and CLI), #136 (stale rustdoc), #138 (`resume` returns no opening checkpoint) and #89 (power-loss test).

---

# [Comment #29]() by [gerchowl]()

_Posted on October 13, 2026 at 06:00 AM_

Closing. A fresh acceptance audit at dev 89472d6 found every criterion met or moved, with no NOT MET items. `cargo test --locked --features audit`: exit 0, 604 passed.

- **Met, with tests:** the record API; a separate directory and lock; fsync on every record; fail-closed results; segments never rotated away; the optional log mirror; the SIGKILL crash test (amendment 2).
- **Moved to open issues:** the power-loss test → #89; the APFS counterpart → #46; the verifier and CLI → #13; follow-ups → #136 (stale rustdoc), #138 (`resume` returns no opening checkpoint), #118 (refactor).

The body is corrected at the top to say what was delivered.

