---
type: issue
state: open
created: 2026-10-09T13:22:04Z
updated: 2026-11-03T10:18:00Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/13
comments: 29
labels: feature, security, priority:medium, area:testing, effort:medium
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-11-04T08:43:08.630Z
---

# [Issue 13]: [feat(audit): verify API/CLI and tamper tests](https://github.com/vig-os/vigil/issues/13)

`vigil::audit::verify(path, trust)` (+ a small CLI): recompute the chain, check MMR roots against signed checkpoints, report the first broken link precisely.
**Acceptance:** property tests for delete, reorder, edit and truncate at every position; a forged checkpoint is rejected; a valid trail from a previous version still verifies.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 11, 2026 at 12:59 AM_

**Test plan additions from the ADR-0005 amendment (#66, PR #71).** One test per decided rule. Each must fail against a verifier or writer that lacks the rule; the probe model in #71 shows the accepted rule failing the attack cases. The source of truth is ADR-0005 decision 11, "Tests for the attacks…". These are the #66 items, quoted from it (updated after the review of #71):

  - **Clean-stop head** (#66, decision 9).
    - N writer processes (at least 8) record and then `close()` in random order: the highest `seq` among the receipts and close checkpoints they returned is the disk head, and it is a checkpoint. `rotate --expect-head` with it succeeds.
    - After that clean stop, an attacker appends one chained record, or truncates back to an earlier checkpoint, or (with the old key) rewrites one record below the head and re-signs up to the same `seq`: `rotate` is `HeadMismatch` in each case, and nothing is signed.
    - Writer A closes, an attacker appends, writer B records and closes: `rotate` passes the exact-head check, and step 2's verify reports the forged record as `NoReceipt`.
    - A writer is SIGKILLed: the held maximum is below the disk head, `rotate` is `HeadMismatch`; one restarted writer's `close()` returns the disk head.
    - `close` consumes the handle and returns the checkpoint it wrote; with a failing signer it returns `Err` with kind `Signer` and writes nothing.
  - **Receipts range** (#66, decision 5).
    - Two forged records after the last receipt, then an honest `close()`: `NoReceipt` for both, exit 1. (Fails against the rule "first to last receipt".)
    - A forged record between `create` and the application's first record: `NoReceipt`.
    - A receipt above the head (rollback), or with a different hash: `ReceiptMismatch`.
    - A `rotate` or `resume` record without its printed receipt: `NoReceipt`; with it, no finding.
    - A crash orphan (the review criterion needs the application's request log fsynced before `record`; covered by a power-loss test that kills every writer at once with several calls in flight): `NoReceipt`; with a `waive` line naming it, `ReceiptWaived` (info) and `--strict` passes; the same waiver after the record at its `seq` is replaced, with no later receipt to mask it: `ReceiptMismatch`.
    - Late adoption: records before the first receipt are `NoReceipt`; with a `from` line, `ReceiptWaived` and `--strict` passes; a `from` line with a wrong hash: `ReceiptMismatch`.
    - Receipts for records lost before a `resume`: see "Receipts across a resume" below (amended by #70).
    - Records written after the receipts export: `NoReceipt` by default; with `--receipts-live`, one `Unreconciled` (info), exit 0 without `--strict` and 1 with it; a receipt above the head, or a receipt with a wrong hash between the reconciled prefix and the head, is still `ReceiptMismatch` with `--receipts-live`.
    - An in-flight record below the highest receipt (process A's receipt not stored, process B's stored): with `--receipts-live`, `Unreconciled` from A's `seq` and exit 0; a hole that stays open across later receipts keeps `Unreconciled` at the same `seq`, and is `NoReceipt` without `--receipts-live`. `--receipts-live` with no receipts: everything `Unreconciled`.
    - Receipts-file parsing: an unknown line, a `waive` or `from` line without a reason, two waivers for one `seq` and a second `from` line exit 2, and the library's second `waive` for one `seq` or second `receipts_from` returns `InvalidConfig`; two receipts with one `seq` and different hashes do not.
  - **Revocation scope** (#66, decision 9).
    - One key under trails X and Y, `through=` on X only: the trust file fails to parse (`InvalidConfig`), and so does the builder. (Against the accepted rule, Y forged with that key passes `--strict`.)
    - The same key listed twice in one section, or one trail id in two sections: parse error.
    - A different record at the `end=` `seq`: `TrailEnded`. A retired trail whose last writer crashed, `end=` on its last (non-checkpoint) record: `UncoveredTail` is reported and `--strict` passes; the same trail without `end=`: `--strict` fails.
    - A retired trail: with `end=` at its last record and the key's bound at the same record, it verifies clean with no confirming checkpoint; with the bound at an earlier anchored checkpoint, the bound is confirmed and the old key's later checkpoints are `UntrustedKey`; a record forged after it is `TrailEnded` (and `UntrustedKey` for a forged checkpoint); without `end=`, the bound is `RevocationUnconfirmed`.
    - The key revoked on both trails, each rotated to its own new key: both verify clean; a record and a checkpoint forged on Y with the old key above Y's bound: `UntrustedKey`; Y cut back to its bound and forged above it: `RevocationUnconfirmed` and `UntrustedKey`.
  - **Archiving and `start_from`** (#66, decision 11).
    - Archive and live verified together report the same findings as before the move.
    - Following decision 2's procedure (start anchored): anchors, revocation pins, receipts and waivers below the start are `OutOfRange` (info) and `--strict` passes; with an unanchored start, a waiver below it is `UnanchoredStart`.
    - Every checkpoint anchored, the start recorded at the archive boundary, then kept segments deleted up to a later opening checkpoint: `StartMismatch`.
    - The stolen-key attack: cut just above the newest anchor, sign a start there with the not yet revoked key, rewrite and re-sign above it, move the rest away, verify with every anchor and that start: `UnanchoredStart` for each anchor, exit 1. (Fails against the accepted rule, which passes `--strict`.)
    - An honest but unanchored start with an anchor, a receipt, a `from` line or a `through=` pin below it: `UnanchoredStart` for each; with nothing below it: no error.
    - Above an anchored start, the revocation rules still apply: an old-key checkpoint above the bound is `UntrustedKey`, and a bound with no confirmation above it is `RevocationUnconfirmed`.
    - A start whose hash differs from the first record, that is not the first record, that is not a checkpoint, or that is signed by a key not trusted at its `seq`: `StartMismatch`.
    - The live directory alone, with no start: `SeqGap` for `0..k−1`, and a forged record later in the file is still reported.

**Amendment 2 additions (#68, #70; ADR-0005 decision 11 is the source of truth).** One test per rule, each failing against a writer or verifier that lacks the rule. The probe in the amendment-2 PR shows the old rules failing the attack and honest cases. Changed core items:
  - **Resume.** On a deleted live file, `seq` continues above `--lost-through`; when `--lost-through` equals the head, it continues directly after it, with no `SeqGap`. `Resumed` is a warning, and `--strict` exits 1 until an `accept Resumed` line names it.
  - **Fake records.** Every strict prefix of a valid line's JSON text is a fragment, reported as `TornWrite` while trailing. The complete JSON text without its newline is a record, which the next writer terminates.
  - **Inserted fragments** (amended, #68). End-of-input fragments inserted between linked records → `RepairMismatch`, an error, reported by length only, and the CLI exits 1. (Against the core rule they were `TornWrite` warnings and plain verification passed.)
  - **Attested repairs** (#68, decision 5).
    - A writer SIGKILLed mid-write, then another process records and a checkpoint covers that record: the record carries `audit.repaired` over the fragment and the repair newline, the verifier reports one `TornWriteRepaired`, and `--strict` passes. (Fails against the core rule, where `TornWrite` fails `--strict` for good.) The same with N writer processes (at least 8) and several writers SIGKILLed mid-write: every gap attested by whichever process wrote next, `--strict` passes.
    - A crash during the repairing write: one gap holding both fragments, attested once by the next line.
    - The closing checkpoint of sealing step 3, and the checkpoint `close` writes, attest a torn tail like a record.
    - An attested fragment whose bytes are changed afterwards, and a fragment inserted before a line with no `audit.repaired`: `RepairMismatch`. The writer reading either is `CorruptTrail`.
    - An attesting line not yet covered: `TornWrite` until the next trusted checkpoint, then `TornWriteRepaired`.
    - A removed attested fragment, and a Collector round trip of a trail with a repaired torn write (`verify_files`): `TornWriteRepaired` with "fragment not present", no error.
    - A fragment appended at the live tail before an honest write: `TornWriteRepaired` (the documented limit, decision 17); a test asserts it so the limit stays visible.
    - A forged record carrying a valid attestation for an injected fragment, covered by an honest checkpoint: `NoReceipt` with `--receipts`.
    - Encoding: `audit.repaired` is tag `0x07`, absent on every line not written right after a repair; its value is the single hash `blake3("vigil.audit.v1.repaired\0" ‖ gap)` (a test fails if the bytes are hashed twice); a golden vector covers a record with it.
    - An attesting line in the uncovered tail of a retired trail whose `end=` matches it (a crash, a repair, then the last writer crashed before a checkpoint): `TornWriteRepaired`, because a matching `end=` pins it; without `end=`: `TornWrite`.
    - The writer reading a line that carries `audit.repaired` with no gap before it (a removed fragment): it accepts the line and appends, with no `CorruptTrail`.
  - **Reviewed warnings** (#68, decision 11, review file).
    - A trailing fragment on a stopped trail: `TornWrite` with its digest; with an `accept TornWrite` line naming the record before it and that digest, `Accepted` and `--strict` passes; with another digest, `AcceptUnused` and `--strict` fails; after opening the trail and calling `close`, `TornWriteRepaired`, and the old line is `AcceptUnused` with `--strict` passing.
    - `Resumed` and `ClockWentBackwards` accepted by pinned lines: `Accepted`, `--strict` passes. The same line after the record at its `seq` is replaced, or after the trail is rolled back below it: `AcceptMismatch`.
    - Review-file parsing: an error or info kind (for example `accept NoReceipt …`), a missing reviewer or reason, an unknown line and two lines for one kind and `seq` exit 2; the library's `accept` returns `InvalidConfig` for each.
    - An `accept` line below an anchored start: `OutOfRange`; below an unanchored one: `UnanchoredStart`.
    - `accept DuplicateRecord` for a line redelivered three times in a shipped copy: one `DuplicateRecord` for that `seq`, one line accepts it, `--strict` passes.
    - `accept TornWrite` naming a `seq` with no record: `AcceptMismatch`.
    - `accept TornWrite` for bytes appended after a rotation-sealed segment's closing checkpoint (the finding is marked "no crash outcome"): `AcceptMismatch`. The same fragment at the end of a file `resume` sealed with nothing lost: not marked, `Accepted`. The rotation-sealed segment verified alone, without the next file: not marked.
  - **Receipts across a resume** (#70, decisions 5, 8 and 9).
    - Honest resume after a deleted live file holding receipted records, `--lost-through` = the highest held `seq`: the opening checkpoint is at `lost_through + 1` with `mmr_size` = the records before it; each lost receipt is `LostRecord`, plain verify passes, `--strict` fails on `Resumed` and passes with an `accept Resumed` line. (Fails against the core rule: the lost receipts are `ReceiptMismatch`.)
    - Rollback of records written after the resume, then a restart without `expect_head`: `ReceiptMismatch`. (Fails against the withdrawn `lost`-line draft, #70's M1.)
    - After the resume, `open` with `expect_head` from the highest held receipt succeeds, and the rotation procedure with that expected head succeeds. (Fails under `seq` reuse, #70's M2.)
    - A gap forged with the trusted key but without the resume record's receipt: `NoReceipt` for the resume record, `ReceiptMismatch` for the lost receipts. A gap opened with an untrusted key: `UntrustedKey`. A signed jump without the resume record, or whose resume details name another head or `lost_through`, or whose `mmr_size` is wrong: `SeqGap` (and `MmrMismatch`). A `.audit-resume.jsonl` holding only an opening checkpoint (a crash prefix of `resume`'s write, with or without a gap) is discarded, never promoted; a `.audit-next.jsonl` whose lone checkpoint jumps is discarded; a complete `create` staging file (`seq 0` after the genesis value) is promoted.
    - Anchors, a revocation pin, a waiver and an `accept` line inside an unconfirmed gap keep their errors. Inside a gap confirmed by a receipt or an `accept Resumed` line, the waiver and the `accept` line are `LostRecord`, while the anchor and the pin keep `AnchorMismatch` and `RevocationMismatch`. With the gap's opening checkpoint also anchored, the anchor and the pin are `LostRecord` too. The stolen-key case: cut back over anchored checkpoints, sign an opening checkpoint and a resume record, add an `accept Resumed` line: every anchor inside stays `AnchorMismatch`, exit 1.
    - A start at the resume's opening checkpoint: inputs in the gap are below the start and follow the start rule.
    - `--lost-through` below the head: exit 2. Below a held receipt: that receipt is `ReceiptMismatch`, and `open` with it as `expect_head` is `HeadMismatch`.
    - Two resumes, each confirmed: both gaps' inputs are `LostRecord`. A resume with `--lost-through` equal to the head: no gap, no `LostRecord`.
    - `record` with an action starting with `vigil.audit.`: `InvalidEntry`.
    - `--lost-through` above `u64::MAX − 2`: exit 2, and `AuditConfig::resume` returns `InvalidConfig`.
    - A crash injected at each step of `resume` (after the staging write, after renaming the damaged file, after promoting): `.audit-resume.jsonl` is promoted with both lines or discarded, with and without a gap, over a deleted and over a torn live file, never an opening checkpoint without its resume record; re-running `resume` after a discard succeeds; verify reports no `SeqGap`.
    - A Collector round trip of a resumed trail (`verify_files`): the gap verifies, same findings as the files.
    - `resume` on a well-formed live file after a rollback: the file is sealed unchanged, the rolled-back receipts are `LostRecord` once confirmed.
    - A `from` line inside a confirmed gap: `LostRecord`, and records below it are still not `NoReceipt`. A redelivered duplicate line before a checkpoint: `DuplicateRecord`, no `MmrMismatch`.
    - Bytes appended after a rotation-sealed segment's closing checkpoint: `TornWrite` whose detail says no crash produces it, and `--strict` fails. A fragment at the end of a file sealed by `resume`: `TornWrite`, acceptable.

Refs: #66, #68, #70, #79


---

# [Comment #2]() by [gerchowl]()

_Posted on October 11, 2026 at 10:03 PM_

Architect, scope note from audit B2b. ADR-0005's crash tests (l.~682–686, l.~730–740: crash points with a second writer, attested repairs, 8 writers with SIGKILLs) are owned by "#11 and #13". #11's B2b writes the trails and asserts writer-side state: gaps are attested via `audit.repaired`, a later checkpoint covers the attesting line, and the B2a/writer read path accepts the trail. vigil has no verifier until #13. So #13's acceptance adds: re-run B2b's crash-matrix fixtures (or the same generators) through the verifier and assert the verifier-side outcomes — `TornWriteRepaired`, `--strict` exits 0, no `SeqConflict`, `TornWrite` until covered, and `RepairMismatch` for inserted or changed fragments. The power-loss test is #89.

---

# [Comment #3]() by [gerchowl]()

_Posted on October 11, 2026 at 10:09 PM_

Architect, scope (ownership from the audit B2b brief checks): #13 owns the whole `vigil-audit` CLI that ADR-0005 describes, not only `verify`: `verify`, `create`, `rotate`, `checkpoint --expect-head` (exact-head rule, l.545–546, l.565) and `keygen`. The library operations behind `rotate`/`checkpoint`/`keygen`, the `vigil.audit.key_rotated` record and `KeyFileSigner`'s file checks land in audit B3 (#11's public API); the CLI wraps them.

---

# [Comment #4]() by [gerchowl]()

_Posted on October 12, 2026 at 06:27 PM_

Acceptance addition (architect ruling B3d2-d2 R10, see #11): the verifier reports, as an error, a genesis-linked `vigil.audit.resume` (`head=0:<genesis digest>`) in a trail whose id also has archived segments (the resume restarted the MMR and broke the link to the archive). Test: archive, lose all present files, genesis resume, verify with the archive present → error.

---

# [Comment #5]() by [gerchowl]()

_Posted on October 12, 2026 at 07:44 PM_

Acceptance addition (ruling 123-d1 on #123): reproduce the amendment-10 span golden vector byte for byte (span boundaries, after, len, D), and test that a malformed-but-decodable record line (InvalidField/UnknownVersion/MissingField) is never span bytes and is never accepted by accept-run.

---

# [Comment #6]() by [gerchowl]()

_Posted on October 13, 2026 at 10:56 AM_

## Ruling 13-d1 (architect): the #13 plan, open questions OQ1–OQ15

The plan is `briefs/13-plan.draft.md`: obligations O1–O30, slices V1–V8, C1, C2, R10 and T1–T3, and a pre-mortem, all checked against dev 780f349. Seven of these rulings change ADR text (OQ9 also fixes merged code, #143): OQ1, OQ2, OQ6, OQ7, OQ9, OQ10 and OQ11. Those amendments land **first**, as slice **13-0**: docs only, ADR-0005 amendment 12, Proposed until the slice that implements each part merges. Design comes before code.

### Rulings that amend ADR-0005 (slice 13-0)
- **OQ1, the `TrustPolicy` shape: (b).** `TrustPolicy::builder() -> TrustPolicyBuilder`, `.trail(id) -> TrailTrust`, `.key/.key_through/.end/.trail`, and `.build() -> Result<TrustPolicy, AuditError>` (`InvalidConfig`), plus `TrustPolicy::from_file`.
  - Only a validated policy can exist.
  - Amend d9's "`TrustPolicy::new()` … at its build step" and the d13 table row.
  - Rejected: (a) `new()` returning a builder, which is unidiomatic (`clippy::new_ret_no_self`); and (c) lazy validation, which moves a config error into `Verifier::new` and makes it fallible for every caller.
- **OQ2, fallible `Verifier` configuration.** `trail`, `end_before`, `receipts_live`, `max_age`, `waive`, `receipts_from`, `accept` and `accept_run` return `Result<Self, AuditError>` (`InvalidConfig`).
  - A conflict (`end_before` combined with `receipts_live` or `max_age`) is detected by whichever call comes second.
  - `verify_dir`/`verify_files` still fail only with `io::Error`, keeping "findings, never errors".
  - `Verifier::new(TrustPolicy)` takes the policy by value, and `verify(dir, &TrustPolicy)` clones it.
  - Amend the d11 "Library" sketch and d13.
- **OQ6, `Report` extras.** Add:
  - `Report::is_strict_valid()`, so the `--strict` predicate lives in the library and the CLI stays thin;
  - `Report::first_broken_link()`;
  - `Finding::accepted_kind()`;
  - `Finding::run_digest()`.
  - Amend the d13 table.
- **OQ7, JSON output.** Exactly the planner's schema:
  - `{"version":1,"trail","valid","strict_valid","records","first_seq","last_seq","covered_through","findings":[{"kind","severity","file","line","seq","detail","accepted_kind","run_digest"}]}`;
  - kinds are the enum variant names, the same tokens the review file uses;
  - severity is lowercase;
  - absent values are `null`, never an omitted key.
  - Text output: `seq <first>..<m>`, and `signed through -` when nothing is covered.
  - The keys are stable within 1.x. Amend the d11 "JSON output" text.
- **OQ9, what is `Unparsable`: the planner's recommendation, plus a reader fix.**
  - A probe confirmed pre-mortem 1 as a defect in merged code, filed as **#143**: `resume` refuses a NUL-filled tail, which breaks §6's "the only way to continue is `resume`, which seals the file as it is".
  - **Rule:** one shared classifier, used by the reader and the verifier. A line is `Unparsable` iff its payload does not decode to a JSON object. That covers control bytes, over-cap lines, non-JSON and JSON non-objects.
  - `UnknownField` and `HashMismatch` lines remain records. A torn-write fragment keeps conditions 1–3.
  - Such lines are 123-d1 span bytes, so `resume` seals them and `accept-run` can review them.
  - Amend d11 "Finding" (the `Unparsable` definition), 123-d1 (a) and the §6 sentence, so that one definition is cited everywhere.
  - Rejected: keeping control bytes as `InvalidField`. That leaves a power-loss trail unrecoverable, which the ADR forbids.
- **OQ10, a genesis resume.**
  - **The gap** is `0..=lost_through`: the creation checkpoint is lost too, and there is no `SeqGap` inside a confirmed gap.
  - **R10 (genesis over archive)** is reported as `ChainBroken` at the genesis-linked opening checkpoint, whenever that opening is not the first record of the verified set or a start is given. The detail cites amendment 9 R10 and says "restore the archived segments, then resume". It is a real chain break, since the opening links to genesis, not to the archived predecessor, so no new kind is needed.
  - Amend amendment 9 R10 with the kind and the gap extent.
- **OQ11, `checkpoints(dir)`.** Add the public `fn checkpoints(dir: &Path) -> io::Result<Vec<Checkpoint>>` in vigil's segment order, so the CLI uses only the public API. Amend d13.
  - Receipts and review files are parsed in the binary. The library builder methods enforce the duplicate and kind rules.

### Rulings that need no ADR change (they become brief text)
- **OQ3.** `end_before(self, archive_record: &str, end_anchor: Option<Checkpoint>) -> Result<Self, AuditError>`. The record is one checkpoint line plus at most one resume record line. A missing anchor is the finding `UnanchoredEnd`, not an error.
- **OQ4.** `verify_files` is the general form.
  - Vigil-named segment files are ordered by `segment_key` across directories, with live files last.
  - Any other file is a shipped copy, merged by `seq`, with no segment semantics (no spans, runs or no-crash mark).
  - A directory expands to its vigil-named files, and `verify_dir(d)` is `verify_files(expand(d))`.
  - The same segment name in two inputs, or two `audit.jsonl` files, is a usage error: `InvalidConfig`, exit 2.
  - One inode reached under two names (a hard link left by an R9 crash) is read once.
- **OQ5.** With more than one pinned trail, `trail(id)` is required (`InvalidConfig`, exit 2). An attacker must never choose the verified trail by writing first.
- **OQ8, `ClockWentBackwards`.** A record whose `timeUnixNano` is below the preceding distinct present record's, in `seq` order, gets one finding at that `seq`, with the severity the ADR gives. When the head is not present, a resume opening is compared with nothing.
- **OQ12, operator output.**
  - Receipt lines are `<seq> blake3:<hex>`, one per written record, followed by the checkpoint line.
  - `create` prints the 32-hex id. `keygen` prints the public key and writes `<file>.pub`.
  - Exit codes: 0 success, 1 `AuditError` (stderr `error: <Kind>: <detail>`), 2 usage.
  - If writing stdout fails after `rotate`/`resume`/`checkpoint` succeeded, the same lines are repeated on stderr and the exit code is 1.
- **OQ13.** `--max-age <u64>(s|m|h|d)`, with no fractions and no combined units.
- **OQ14.** #13 ships the 7 synopsis commands. `export-tsra` stays in #59, which has no milestone (post-1.0, gated on tessera).
- **OQ15.** An anchor file holds one or more checkpoint lines. An anchor of another trail is `AnchorMismatch` ("trail differs"), never ignored. `Checkpoint` gains a private trail field (V6).

### Pre-mortem items adopted as brief text
- **(2) Hard links:** dedupe by `(dev, ino)`, as in OQ4.
- **(3) Unsettled staging:** the rustdoc and README say "open, or record once, before verifying a crashed trail". T3 verifies after settlement, plus one test pinning the outcome before settlement.
- **(4) Determinism:** T1 adds `cfg(test)` hooks for the trail id and the segment stamp.
- **(5) Memory:** V3 streams in vigil order, sorts only shipped copies, keeps a compact per-record summary and keeps receipts in a sorted `Vec`. A 1M-record bench is added in T2.
- **(9) Live races:** document that strict review targets stopped trails (d9 step 2).
- **(10):** the OQ12 stderr echo.
- **(11):** every slice runs `check_public_api.py` with an allowlist justification citing ADR-0005 amendment 12.

### Order
1. **13-0:** ADR-0005 amendment 12 (OQ1, OQ2, OQ6, OQ7, OQ9, OQ10, OQ11). Docs only, claude sonnet.
2. **13-R** (fixes #143): the shared line classifier (plan V2's `src/audit/lines.rs` extraction) and the reader fix. It lands before V1/V2, and V2 then reuses the classifier.
3. Then **V1 → V2 → V3 → V4 → V5 → V6 → V7 → V8 → R10 → C1 → T1 → T2 → T3**, serial.
   - **C2** (operator commands plus `checkpoints`) may run in parallel with V2–V8 on disjoint files, after 13-0 merges, and owns the bin skeleton.
   - Each slice gets a fresh brief check against merged code before dispatch.
4. #136 is handled separately (in flight), so V1 drops its mod.rs l.6 item.


---

# [Comment #7]() by [gerchowl]()

_Posted on October 13, 2026 at 11:01 AM_

## Ruling 13-d2 (architect): gaps in 13-d1 found by the 13-0 brief check

The pre-dispatch check of the 13-0 brief found ADR text that conflicts with 13-d1 but that 13-d1 did not rule on. These rulings close those gaps. They are part of amendment 12.

### A. The genesis resume (completes OQ10)
- **The gap.** A resume whose named head is the genesis head `(0, genesis digest)` (R2'') means that no record survived. Its gap is `0..=lost_through`, and its opening checkpoint's `prev_hash` is the genesis value. Amend these to state the genesis case explicitly:
  - decision 5 rule 1 (l.~397: `prev_hash` is the hash of the record at `h`);
  - l.~404 (the gap is `h+1..k−1`);
  - l.~126;
  - l.~384 (`seq 0` links to genesis).
- **`seq 0` missing.** l.~750 and §18.1 (l.~1128), "with no start, `seq 0` must be present, else `SeqGap`", gain the exception: "…unless `seq 0` lies in a confirmed genesis-resume gap".
- **R10.** A genesis-linked opening is legal only as the first record of the verified set with no start given. Anywhere else, it gets `ChainBroken` at the opening, with the R10 detail ("restore the archived segments, then resume"). The missing `seq`s are then **not** a resume gap and are `SeqGap` per rule 1. Both findings are reported.

### B. One `Unparsable` definition (completes OQ9)
Classification runs **in this order**, for every line, in the reader and the verifier:
1. **Fragment.** The torn-write fragment conditions 1–3 (decision 5, l.~422–425) are checked first. A line longer than the 1 000 000-byte cap is **never** a fragment, because the writer never writes an over-cap line, so no prefix of a written line exceeds it.
2. **Decode.** "Decode" means vigil's framed decoder, **including its pre-parse checks**: a raw byte below 0x20 anywhere in the payload, or a payload over the cap, fails decoding *before* JSON parsing. A line that fails decoding, or that parses to something other than a JSON object, is `Unparsable`.
3. **Record.** A line that decodes to a JSON object is a record. Its record-level findings stay record findings and are never span bytes: `InvalidField`, `UnknownVersion`, `MissingField`, `UnknownField`, `HashMismatch`.

**Amend decision 4:**
- l.~270–271: "Reject raw bytes below 0x20 … (`InvalidField`)" becomes `Unparsable` for the verifier finding. The writer still refuses to *write* them.
- l.~273–274 ("`TooLarge`, verifier `InvalidField`") becomes verifier `Unparsable`. The writer error `TooLarge` is unchanged.
- The decision-4 table rows (l.~322 tab between tokens, l.~331 over 1,000,000 bytes) change to match.
- State that changing a verifier finding kind writes no new byte, so the v1 format (d12) is unchanged.

**Rule (a), l.~814** (and its restatements at l.~908 and l.~1217): list the five record kinds above. Restate the reason as follows:
- A line that decodes to an object keeps its record-level finding, so `accept-run` can never accept a malformed record.
- Bytes that do not decode are span bytes. They are reviewed by digest and enter a run only through a reviewed `accept-run`.
- A record damaged so that it no longer decodes disappears from the chain. The resulting `SeqGap`, range or digest change is part of what the reviewer accepts or rejects.

### C. `Report::first_seq()` (completes OQ6/OQ7)
Add `Report::first_seq() -> Option<u64>`: the lowest `seq` verified (the start's, when a start is given). It backs the JSON `first_seq` key and the text `seq <first>..<m>`.

### D. Several pinned trails, and the error channel (completes OQ2/OQ5)
- **Signatures.** `verify(dir, &TrustPolicy)`, `Verifier::verify_dir` and `Verifier::verify_files` return `Result<Report, AuditError>`, not `io::Result`.
  - An unreadable input is `AuditErrorKind::Io`, with the `io::Error` as its source.
  - Verifying with a policy that pins several trails, without `trail(id)`, is `InvalidConfig`.
  - Tampering is still always a `Finding`, never an `Err`.
  - Amend d11 "Library" (l.~738) and "Errors versus findings" (l.~764): `Err` means "cannot read the input, or the configuration is invalid".
  - The CLI maps `Io` and `InvalidConfig` to exit 2.
- **Why.** The audit API keeps one error type (`AuditError`, which already has `Io`). An ambiguous policy fails closed at the call that verifies, and there is no "configuration error as a finding" hack and no `io::Error` carrying a non-I/O meaning.
- **Rejected:**
  - a fail-closed `Report` with a synthetic `TrailMismatch`, because `Report::trail()` would be undefined;
  - `io::ErrorKind::InvalidInput`, which breaks "io only when the verifier cannot read";
  - forbidding multi-trail policies, which d9 "Revocation scope" requires.

### E. Placement and bookkeeping (brief text)
- Amendment 12 is a new **`### 19. Verifier surface and line classification (amendment 12)`** after §18.7, in amendment 10's style, plus in-place `(amendment 12)` tags.
- Update:
  - the status summary (l.3);
  - the status-block entry (one sentence, like entries 9–11);
  - the Issues line (l.16, add #143);
  - the References;
  - the `docs/adr/README.md` index row;
  - a CHANGELOG entry, following #120's precedent.
- The d13 table: split the `verify`/`Verifier`/`Report`/`Finding` row as needed, and add a `checkpoints` row.


---

# [Comment #8]() by [gerchowl]()

_Posted on October 13, 2026 at 12:16 PM_

13-0 merged: PR #145 at 5be148a adds ADR-0005 amendment 12 (§19, Proposed), which records rulings 13-d1 and 13-d2. Review nits folded into 13-R: l.855 'exactly these keys' should be 'these keys' (1.x may add keys, per l.865); the §19.8 table and l.1331 should also list the d5 l.450 and §18.2 l.1168 genesis-gap exceptions.

---

# [Comment #9]() by [gerchowl]()

_Posted on October 13, 2026 at 12:21 PM_

## Ruling 13-d3 (architect): operator CLI details, from the C2 brief check

These rulings complete 13-d1 OQ12 for the operator commands. Where they differ from 13-d1, this ruling wins. The C2 PR records them in ADR-0005 §19 (amendment 12) and the README, so they are not undocumented.

1. **Exit codes follow ADR-0005 d11 "Exit codes" (l.~853), for every command.**
   - 0: success.
   - 1: any other `AuditError` (`HeadMismatch`, `CorruptTrail`, `Poisoned`, `Signer`, …) and any `SignerError`. For `verify` (C1), 1 also means findings.
   - 2: usage errors and the library's `Io`/`InvalidConfig`.
   - 13-d1 OQ12's "1 on any `AuditError`" is superseded. If writing stdout fails after a successful operation, the lines are repeated on stderr and the exit is **2** (an I/O error).
2. **Every command that obtains a handle closes it explicitly** (`create`, `resume`), because `Drop` would sign a checkpoint and report a failure only on stderr. A `close()` error is exit 1, after whatever lines were already printed.
   - Output is in `seq` order. A receipt line is `<seq> blake3:<hex>`, and a checkpoint line is the checkpoint's JSON line.
   - **`create`:** the 32-hex trail id, then the close checkpoint line. That checkpoint is the operator's next `--expect-head`.
   - **`resume`:** the opening checkpoint line (L+1), the resume receipt line (L+2), the close checkpoint line (L+3).
   - **`rotate`:** the receipt line, then the checkpoint line.
   - **`checkpoint`:** the checkpoint's receipt line, then its line.
3. **`service.name`** for records the CLI writes (`create`, `rotate`, `checkpoint`, `resume`) comes from `create --service <name>` (d11 synopsis). The other commands have no `--service`, so they use the constant `vigil-audit`, which names the tool that wrote the record. The human is named by `--actor`. This is documented in the README and §19.
4. **`SignerError`** (from `keygen` and `KeyFileSigner::load`) prints `error: Signer: <detail>` and exits 1.
5. **`checkpoints(dir)`** is stable (d13), not `vigil_unstable`. If the snapshot retry is exhausted, it returns an `io::Error` and never silently drops the live tail.


---

# [Comment #10]() by [gerchowl]()

_Posted on October 13, 2026 at 12:26 PM_

13-d3 clarification: item 2's 'A close() error is exit 1' contradicted item 1. A `close()` error exits with the item 1 mapping (`Io`/`InvalidConfig` → 2, any other kind → 1), after whatever lines were already printed. Item 1 governs every exit code.

---

# [Comment #11]() by [gerchowl]()

_Posted on October 16, 2026 at 01:54 PM_

C2 is merged: #147, at 3d22ec3. The `vigil-audit` binary has the operator commands (keygen, create, checkpoints, checkpoint, rotate, resume) under ruling 13-d3, and public `checkpoints(dir)` is in (amendment 12 OQ11 Accepted). 13-R (#148, 1c8605d) is also merged. Next for #13 is V1 (TrustPolicy), after the 0.1.0 release cut.

---

# [Comment #12]() by [gerchowl]()

_Posted on November 2, 2026 at 03:12 PM_

## Ruling 13-V1-d1 (architect): trust-file grammar details for V1 (`TrustPolicy`)

V1 implements ADR-0005 decision 9 ("Trust file format", "Revocation scope") and amendment 12 §19.1. Decision 9 leaves a few grammar details open; they are decided here and recorded in §19.1 by the V1 PR.

1. **The `schema` line stays with #164 CP4**, as amendment 13 allocates it. Until CP4, a `schema` line is a parse error that names #164 CP4. This fails closed on purpose: a policy that accepted a schema pin before the verifier could check it would let a typed trail verify without its schema claim.
2. **Anything outside the grammar fails closed.** A line that is not blank or a `#` comment must start with `trail` or `ed25519`. Fields are split on ASCII whitespace. After a line's required field, a token matching `^[a-z_]+=` is an option: `end=` belongs to `trail` and `through=` to `ed25519`. An unknown option, an option on the wrong kind of line, or an option given twice is a parse error. The first token that is not an option starts the free comment, which runs to the end of the line. This way a typo such as `thru=` can never quietly become a comment and leave a revoked key unbounded.
3. **Spellings.** All hex is lowercase. A trail id is exactly 32 hex characters and a key exactly 64. `end=` and `through=` take `<seq>:blake3:<64 hex>`, with a decimal `u64` seq; this is the same spelling as `vigil-audit --head`.
4. **The builder makes the same checks.** `build()` runs every semantic check that `from_file` runs: one section per trail id, a key at most once per section, consistent `through=` across sections, at least one section. A second `end` in one section is `InvalidConfig`. A key may carry different `through=` bounds in different sections, because bounds do not combine across trails.
5. **Errors.** A malformed line is `InvalidConfig` and names its line number. A whole-file error (not UTF-8, or no `trail` line) names no line. A file that cannot be read is `Io`, with the `io::Error` available as `source()`; making that hold for every other `Io` error is #186.


---

# [Comment #13]() by [gerchowl]()

_Posted on November 2, 2026 at 04:33 PM_

## Ruling 13-V2-d1 (architect): V2 scope, spans and the §19.3 accessors

1. **Spans do not depend on fragment context.** A fragment candidate that fails its file-position or following-link conditions is `Unparsable`. Both fragments and `Unparsable` lines are span bytes (decision 11 (a)/(b)), so the span layout, `after`, `len`, `D` and the run digest are the same either way. V2 builds spans from `lines::classify` alone. Deciding whether a candidate is a real fragment, and with it the `TornWrite`, `TornWriteRepaired`, `RepairMismatch` and `Unparsable` findings, is V3's work, which reuses the reader's context logic in `storage.rs`.
2. **One gap digest.** `blake3("vigil.audit.v1.repaired\0" ‖ bytes)` is extracted into one crate-private function. The reader and the span layer both use it, so nothing about the reader's behaviour changes.
3. **§19.3.** V2 declares the stored accessors `Report::first_seq`, `Finding::accepted_kind` and `Finding::run_digest` together with their types. V3 fills them, adds `is_strict_valid` and `first_broken_link`, and flips §19.3 to Accepted. Until then §19.3 stays Proposed.
4. The amendment-13 kinds `SchemaUnknown`, `SchemaViolation` and `OperatorText` arrive with #164 CP4.


---

# [Comment #14]() by [gerchowl]()

_Posted on November 2, 2026 at 05:34 PM_

## Ruling 13-V3-d1 (architect): V3 split and four engine questions

V3 is split into two PRs. **V3a** covers input handling and ordering, the `verify` / `Verifier` entry points and the chain rules. **V3b** covers fragment and resume context and the `Report` predicates. Each must stay at or under about 400 non-test lines.

1. **Conflicts at one `seq`.**
   - `Report::records()` counts distinct `(seq, record hash)` pairs among decoded records of the verified trail.
   - Every distinct candidate at a `seq` is kept and checked. A record at `seq + 1` links if its `prev_hash` matches **any** candidate at `seq`.
   - There is one `SeqConflict` per `seq`, naming every distinct hash, and at most one `DuplicateRecord` per `seq`.
   - Clock comparisons are skipped across a conflicting `seq`.
   - Duplicates are identified by the authenticated record hash, never by display-only bytes.
   - **Finding order:** findings with a `seq` come first, in ascending `seq` order; findings without one follow; ties break by source path, then line, then kind. `first_broken_link` is the first `Error` in this order.
   - Why: the result never depends on input order, and no alternative content is hidden. `SeqConflict` is an error in any case.
2. **Inputs that reach one file twice.** First, deduplicate by inode: one inode is read once, under its segment name when it also appears as `audit.jsonl` (amendment 9, R9). Second, after deduplication, two distinct files with the same vigil name are `InvalidConfig`, even when their bytes are identical. Listing a directory and also one of its files is therefore harmless.
3. **Staged completion; the verifier is pessimistic in between.**
   - Each slice reports what it can establish. It never excuses a finding whose excusing evidence a later slice checks: matching checkpoint folds (V4), trusted coverage and `end=` (V5), anchors (V6), receipts and confirmed gaps (V7), review (V8).
   - So until those land, an unconfirmed resume gap stays `SeqGap`, a repair without trusted coverage stays `TornWrite`, and so on.
   - V3b implements the §19.3 accessors and predicates and flips §19.3 to Accepted, with its rustdoc naming the later slices that feed it.
   - §19.6 (the genesis resume) stays Proposed until its confirmation path is testable (V7 or R10). The §19.9 table records this staging.
   - **No release from dev carries a partial verifier.** The next release waits until #13 has landed through C1. Until then the public `verify` rustdoc says it is incomplete and names #13.
4. **Mixed native and shipped input.** Only a native vigil file's own physical neighbours decide fragment context, no-crash marks and segment starts. The records merged by `seq` across all inputs decide chain links and duplicates. A shipped copy can never repair or erase damage in a native file.


---

# [Comment #15]() by [gerchowl]()

_Posted on November 2, 2026 at 05:37 PM_

**Addendum to ruling 13-V3-d1: V3a ships as two PRs.**
- **V3a-1** is a crate-private input layer. It expands directories, orders native segments, deduplicates inodes (point 2), reads under the snapshot retry, and streams files through the V2 line layer. It adds no public API and no chain findings.
- **V3a-2** adds the chain engine and the public `verify` / `Verifier` entry points.

Why: a public verifier that cannot yet detect a broken chain would pass broken trails on dev. The input layer on its own is invisible to users. V3b follows V3a-2.


---

# [Comment #16]() by [gerchowl]()

_Posted on November 2, 2026 at 07:20 PM_

## Ruling 13-V3-d2 (architect): what a directory snapshot guarantees

ADR-0005 decision 11 ("Locking and offline use") says the verifier "takes no lock and verifies a snapshot, using ADR-0002 decision 12's retry". A successful read of a directory therefore reflects **exactly one confirmed snapshot**: the attempt whose listing `retry_snapshot` confirmed as stable. Every attempt it discarded leaves no trace and no obligation.

- A segment that retention prunes during `verify` is treated exactly like a segment pruned just before `verify` started. It is absent from the snapshot, and the chain reports what is missing (`SeqGap`, or later V6's start handling). The verifier gains no security from requiring files that an earlier, discarded attempt saw: an attacker who can delete a file could have deleted it before the verifier started. Such a rule would make routine retention fail verifications, and it can never be made airtight.
- The V3a brief line "a disappearing selected input cannot silently disappear from a successful report" means only this: an explicitly given file that cannot be read is `Io`, and exhausting the retries is `Io`, never a partial success.
- Cross-directory consistency is per directory (unchanged).


---

# [Comment #17]() by [gerchowl]()

_Posted on November 2, 2026 at 08:59 PM_

## Ruling 13-V3-d3 (architect): V3a-2 reports every gap, pessimistically

A fresh review of PR #190 found that a line the classifier marks as a fragment produces no finding, and the line is lost. So junk inserted mid-file, or a cut-off last record, verifies as clean. The V3a-2 brief deferred all fragment handling to V3b. That was my error: it contradicts the reason for the split (no public verifier that fails open lands on dev) and ruling 13-V3-d1 point 3 ("each slice reports what it can establish"). Everything needed is already on dev: the gap spans and their digests (V2) and the `repaired` attestation in each record summary (V3a-1).

**V3a-2 therefore reports each gap once**, per ADR-0005 decision 11 ("Repairs are attested"), as far as it can be established without trusted coverage:

1. **A gap in a native file followed by a line in the same file.**
   - If that line's `audit.repaired` matches the gap digest, the gap is `TornWrite` (a warning). It is never `TornWriteRepaired` in V3: that needs trusted coverage or `end=`, which V5 checks.
   - If the line has no attestation, or another digest, the gap is `RepairMismatch` (an error).
2. **A trailing gap in a native file** (no line after it in that file) is `TornWrite`, with the gap digest over the bytes to the end of the file in its detail. The "no crash outcome" mark for a gap after a rotation-sealed closing checkpoint stays with V3b; until then that gap is a plain `TornWrite`.
3. **A line with `audit.repaired` and no gap before it** is `TornWriteRepaired`, with the detail "fragment not present". It is info and excuses nothing.
4. **Shipped input.** A fragment line in a shipped copy is `Unparsable` (an error): the Collector never ships fragments (ADR-0005 l.447), and a shipped copy can never repair damage (ruling 13-V3-d1 point 4).
5. **Attribution.** Each gap finding names its file and physical line(s), and carries the attesting line's `seq` where there is one.

**Decoder findings carry `seq` when it is known** (the ownership table: "V3 supplies … seq when known"). A line that decodes far enough to read `seq` (for example `HashMismatch`) carries it and sorts in `seq` order.

V3b keeps fragment context, no-crash marks and structural resume. V5 turns a covered `TornWrite` into `TornWriteRepaired`.


---

# [Comment #18]() by [gerchowl]()

_Posted on November 2, 2026 at 09:56 PM_

**PR #190, round 3 of 3 (architect).** The round-2 re-review found no fail-open path left: every gap now produces a finding. One defect remains. Gap findings point at the line after the gap instead of at the gap itself, and the detail omits the gap's byte length. ADR-0005 decision 11 and ruling 13-V3-d3 point 5 require both. Round 3 fixes that, makes decoder errors carry `seq` wherever it was read (not only `HashMismatch`), and corrects the CHANGELOG wording. **Size ruling:** the PR is already at about 400 added non-test lines, its hard stop, but this correctness fix is inside the ruled scope. So this round may add up to 25 net production lines, with no new scope.

---

# [Comment #19]() by [gerchowl]()

_Posted on November 2, 2026 at 10:45 PM_

Progress: slice **V3a-2** (the chain engine, plus the public `verify`, `Verifier::{new, trail, verify_dir, verify_files}`) merged in #190 (dev `81952b3`) after 3 rounds. Every gap is reported and never excused (ruling 13-V3-d3). Gap findings point at the gap's own line, with its byte length and the line that attests it. Decoder errors carry `seq` once it has been read. The review nits are in #191. Next: **V3b** (fragment context, no-crash marks, structural resume, the §19.3 accessors). The release gate stands: no release from dev until #13 lands through C1.

---

# [Comment #20]() by [gerchowl]()

_Posted on November 2, 2026 at 10:59 PM_

## Ruling 13-V3-d4 (architect): V3b fragment runs, resumes, native batch lines, and the split

A fresh pre-dispatch check of the V3b brief found four design errors in it. This ruling corrects them from the ADR-0005 text, settles one open question, and splits V3b.

1. **Fragment runs (decision 5, conditions 1 and 3; ADR l.430–438).**
   - Condition 1 holds for each line in a run of consecutive fragments: the next writer's repair newline ends each one ("Several crashes in a row leave one gap").
   - Condition 3 is checked once per run, against the **next complete record after the whole run**. That record must link to the last complete record before the run.
   - If condition 3 fails, each fragment in the run is `Unparsable` at its own line. **The bytes stay in the gap**: spans, gap lengths and digests never change (ruling 13-V2-d1 §1), and the gap is still reported by V3a-2's rules (`RepairMismatch` / `TornWrite`).
   - A rejected fragment never removes or splits a gap.
2. **Resume link (decision 5, l.402–403; amendment 12).**
   - The opening checkpoint at `k` links to the hash of the record at `h`, the last present record before it. The relation is `k ≥ h+1`: when `--lost-through` equals the head, `k = h+1` and nothing is lost (l.952).
   - For a genesis resume, the link is the genesis value and `k = lost_through + 1 ≥ 1`.
   - A structurally valid resume **does not remove its `SeqGap`** in V3. Rule 2 (the MMR fold) belongs to V4, and confirmation belongs to V7/V8 (ruling 13-V3-d1 point 3).
3. **Every resume record is `Resumed` (l.612).**
   - Every `vigil.audit.resume` record gives one `Resumed` warning, whether its declaration is well-formed or not, so `--strict` fails until a review accepts it.
   - If the declaration parses, the detail names the operator, the reason, the head, and the gap with `lost_records=0` until V7. If it doesn't, the detail says "malformed declaration" and any `SeqGap` stays.
4. **Several records on one native line.**
   - ADR §3 (l.207) says a reader "must accept them". The verifier is a reader, so in any input such a line is **accepted with no finding**: each record is decoded and chain-checked as usual.
   - `audit.repaired` is read from the line's first record, which is the line the writer wrote after the gap. That keeps V3a-2's behaviour.
   - The writer's own read (`storage.rs:892`) refuses such a line in a live file, because it needs one record per line to recover its state. The verifier's rustdoc documents this difference, and no new finding kind is added.
5. **No V5 work in V3b.** No private promotion to `TornWriteRepaired`: that upgrade is V5's.
6. **Split.**
   - **V3b-1:** fragment runs (1), the "no crash outcome" mark, plain `Resumed` for every resume record (3), the batch-line test (4), the §19.3 predicates `is_strict_valid` and `first_broken_link`, and §19.3 flipped to Accepted.
   - **V3b-2:** structural resume validation (2): head, `lost_through`, link and genesis checks, plus the private candidates kept for V4, V5 and V7.

   Neither part fails open. V3b-1 already makes every resume block `--strict`.


---

# [Comment #21]() by [gerchowl]()

_Posted on November 2, 2026 at 11:03 PM_

### Addendum to ruling 13-V3-d4 (after the re-check)
7. **Uncovered tail (ADR l.551 and l.857).** Until V5 checks signatures, no checkpoint is trusted, so every record is in the uncovered tail. V3b-1 emits one `UncoveredTail` (info) spanning `first_seq..=last_seq` whenever the selected trail has records. Its detail reads "no trusted coverage yet (signatures are checked in #13 V5)", and `covered_through` stays `None`. `is_strict_valid()` is therefore false for every non-empty trail until V5 narrows the tail. This is the pessimistic reading ruling 13-V3-d1 point 3 requires. An empty trail emits no `UncoveredTail`.
8. **`Resumed` once per `seq` (ADR l.822).** There is one `Resumed` per distinct `(seq, hash)`, attributed to the native copy when there is one (otherwise the first shipped copy in order). A resume record of a foreign trail is `TrailMismatch` only: no `Resumed`.
9. **"The declaration parses"** means all of these:
   - `storage.rs` `resume_details` succeeds;
   - `head=<seq>:blake3:<64 lowercase hex>` is canonical;
   - `lost_through` is a canonical decimal at least the head's `seq`;
   - `file=` is non-empty and contains no whitespace.

   Anything else is "malformed declaration". The gap text is `gap=<h+1>..=<lost_through>`, or `gap=none` when `lost_through == h`.
10. **Edges of a fragment run.**
    - **"Before"** is the last record of the last `Records` line before the run (`range.end-1`). **"After"** is the first record of the first line after the run (`range.start`).
    - **Condition 3 fails, so each fragment in the run is `Unparsable`, when any of these holds:**
      - the run starts the file. No honest crash produces this, since a new file always starts with its opening checkpoint written through the staging file;
      - the line after the run is not a `Records` line, for example an `Invalid` line;
      - the "after" record does not link to the "before" record.
    - Condition 3 holds trivially for a trailing run, with no line after it.
    - **The bytes always stay in the gap.** Existing tests that expect only the gap finding, such as `junk_as_first_line_attributes_gap_to_line_one`, gain the `Unparsable` finding(s).

---

# [Comment #22]() by [gerchowl]()

_Posted on November 3, 2026 at 12:52 AM_

Progress: slice **V3b-1** merged in #192 (dev `f91e714`) after 2 rounds. It adds:
- fragment-run context (ruling 13-V3-d4), where a rejected fragment is `Unparsable` and its bytes stay in the gap;
- the "no crash outcome" mark, with every ADR condition;
- `Resumed` for every resume record, once per `(seq, hash)`;
- `UncoveredTail` over the whole trail until V5;
- `Report::is_strict_valid` and `Report::first_broken_link`, with §19.3 Accepted.

Run on the same corrupted trails at dev and at the head, the verifier reports nothing less than before, and gap bytes and digests are byte-identical. The test-coverage nits are in #193. Next: **V3b-2** (structural resume validation). The release gate is unchanged.

---

# [Comment #23]() by [gerchowl]()

_Posted on November 3, 2026 at 01:08 AM_

## Ruling 13-V3-d5 (architect): V3b-2 structural resume validation

The pre-dispatch check of the V3b-2 brief (check-13v3b2, verdict blockers) found condition errors and two open questions. This ruling settles them from the ADR-0005 text on origin/dev f91e714 (decision 5 "Resume gaps", rules 1–3, l.402–411; amendment 12; §19.6). It refines 13-V3-d4 point 2 and addendum 9.

1. **The structural conditions** (rules 1 and 3, the ADR's own words). A resume record `R` of the selected trail, whose declaration parses (addendum 9) and names head `(h, H)` and `lost_through = L`, is **structurally valid** only if all of these hold:
   - (S1) The record at `k = L+1` is a checkpoint, the **opening**. `R` is the record at `k+1`. "At" means by `seq` in the verified set, not by file position: a shipped copy has no file boundaries and must verify the same (ADR l.403). No condition may require file boundaries.
   - (S2) **Non-genesis:** a record at `h` with hash `H` is present (in any candidate, ruling 13-V1-d1/d1 point 1: a match with **any** candidate suffices). It is the **last record present below `k`**: no record with `h < seq < k` is present. The opening's `prev_hash` is `H`. `k > h+1`, or `k = h+1` when `L = h` (nothing lost, l.952).
   - (S3) **Genesis** (`H` is the genesis value, `h = 0`, amendment 12, Proposed): the opening's `prev_hash` is the genesis value, `k = L+1 ≥ 1`, and **no record with `seq < k` is present** (the opening is the first record of the verified set; with a start given, that is V6's). Anything else is not valid. The `ChainBroken` for a genesis link elsewhere stays R10's (§19.6 stays Proposed); V3b-2 adds no finding for it.
   - The `audit.mmr_size` part of rule 2 stays V4's. Signatures stay V5's. Confirmation stays V7/V8's.
2. **The head is not present** (check item 6). If the record at `h` is absent from the files (archived, or deleted: the verifier cannot tell them apart, ADR "Collector copy", "`open` is structural"), the resume is **not** structurally valid. The reason is `head-not-present`. Its `SeqGap` and `Resumed` stay. How a start checkpoint (decision 11) covers an archived head is V6's start handling. A note goes on #13 for V6, and no new issue is needed.
3. **Gap text for a genesis resume** (check item 5). The ADR is explicit: "The gap is `0..=lost_through`" (l.407), and "for a genesis resume, `0` to `k−1`" (l.411).
   - Addendum 9's `gap=<h+1>..=<lost_through>` / `gap=none` covers the **non-genesis** case only.
   - For a genesis head, the text is `gap=0..=<lost_through>`. It is never `none`, because seq 0 is always lost.
   - V3b-2 corrects V3b-1's genesis text (today `gap=1..=2` for L=2, and `gap=none` for L=0). This is a bug fix within #13, with a test that fails on f91e714.
4. **The outcome is observable and mandatory.**
   - Every `Resumed` detail of a parsed declaration ends with exactly one suffix:
     - `structural=valid`, or
     - `structural=invalid(<reason>)`.
   - Reasons are fixed tokens, one per failed condition, the first in this order: `no-opening` (S1 checkpoint missing at k), `resume-not-at-k+1`, `head-not-present`, `head-not-last` (a record between h and k), `link-mismatch`, `genesis-not-first`.
   - A malformed declaration keeps "malformed declaration" and gets no suffix.
   - The suffix changes no severity and removes no finding. Every `SeqGap`, `ChainBroken` and `Resumed` stays as on f91e714.
   - No new `FindingKind`, no public API change.
5. **Candidates.** The validated `(h, H, L, k, resume seq, resume hash)` tuples are kept privately, **unique per `(resume seq, resume hash)`** (native copy first, as addendum 8), for V4 (rule 2 fold), V6 (start), V7 (confirmation).
   - `#[expect(dead_code, reason = "consumed by #13 V<n>")]` goes only on an item that is really dead in non-test builds: a struct field never read, or a fn never called. Never on a local binding. `just precommit` (clippy `-D warnings`) proves each expectation is fulfilled.
   - No helper may duplicate what `parse_resume` already enforces.
6. **Tests and mutants.**
   - Every acceptance row asserts the exact suffix (or the genesis gap text) and fails on f91e714.
   - Fixtures: use the real writer (`AuditConfig`, the storage resume path) in `tests/audit_verify.rs` where it can produce the shape. Otherwise use crate-private unit tests (`engine_tests`).
   - Each mutant runs on **both** `cargo test --features audit verify` and `--test audit_verify`. It counts as killed if **at least one** exits 101, and the brief names the killing test.
   - Drop the equivalent and gate-only mutants (old M2, M8, M9, and M6 unless it is observable).
   - Add one mutant per condition in point 1, including "head-not-last" and "resume-not-at-k+1", plus "genesis gap text reverted" and "suffix emitted for a malformed declaration".
7. **Size.** The revised estimate is to be restated. The hard stop is still ~400 added non-test lines → `BLOCKED: propose split`.


---

# [Comment #24]() by [gerchowl]()

_Posted on November 3, 2026 at 01:25 AM_

### Addendum to ruling 13-V3-d5 (after the re-check)
8. **Several candidates at one `seq`** (a `SeqConflict`). The conditions never depend on input order, consistent with ruling 13-V1-d1/d1 point 1 ("links if its `prev_hash` matches **any** candidate"):
   - S1 holds when **any** candidate at `k` is a checkpoint that satisfies the link condition (S2 or S3). Among the qualifying checkpoints, the opening is the first in input order (native first), and it is kept in the candidate tuple.
   - "`R` is the record at `k+1`" means `R` is among the candidates at `k+1`.
   - "No record with `h < seq < k`" (and genesis "`seq < k`") counts every candidate.
   - The `SeqConflict` itself stays exactly as on f91e714.
9. **The genesis head** is `(0, genesis value)`: `h == 0` **and** the hash is the genesis value. Any other `h` with the genesis hash is a non-genesis declaration, which normally ends in `head-not-present`.
10. **Same outcome for every copy.** The structural outcome belongs to the `(resume seq, resume hash)` pair and is computed once. Its native and shipped copies therefore always show the same suffix. There is no per-path outcome.


---

# [Comment #25]() by [gerchowl]()

_Posted on November 3, 2026 at 02:51 AM_

**V3b-2 merged:** #194 → dev a70e01c (structural resume validation, ruling 13-V3-d5 with its addendum 8–10). Each parsed `vigil.audit.resume` declaration now ends with `structural=valid` or `structural=invalid(<reason>)`. The genesis gap text is corrected to `0..=lost_through`. The validated tuples are kept privately for V4, V6 and V7. No finding is removed and no severity changes. The fresh review found no blockers, and its nits are in #195. Next: V4 (`run_digest` / the MMR fold of rule 2). Also for V6 (d5 point 2): an archived head currently reports `head-not-present`; the start handling decides how a start checkpoint covers it.

---

# [Comment #26]() by [gerchowl]()

_Posted on November 3, 2026 at 03:29 AM_

## Ruling 13-V4-d1 (architect): V4 runs, the opening's `mmr_size`, and loss-point ranges

The pre-dispatch check of the V4 brief (verdict blockers) probed its run rule against ADR-0005 on origin/dev a70e01c. The ADR's text settles it, and this ruling binds V4.

1. **A run is the ADR's layout rule, nothing else** (amendment 6): "one or more consecutive segments in which some segment's first complete record is no linking checkpoint, or which holds no complete record, or holds `Unparsable` lines".
   - The run is closed by the next segment whose first two records are an opening checkpoint that satisfies (i) (its `prev_hash` is the hash of the last complete record in or before the run) and a resume record that satisfies (ii).
   - **Membership never depends on the head or `lost_through` the resume declares.** A writer of resume details must not be able to choose which checkpoints are exempt from comparison.
   - The verifier's run set must be the set the storage side already derives for the same files (`history_segment` and its run rules in `src/audit/storage.rs`, from B3d1). V4 must not call storage internals (trap), so it implements the same ADR rule.
   - V4 adds a test proving that both sides agree on real-writer trails: honest crash, a two-segment run, and the laundering layout as the ADR states it in §19.2 (S1 = [O3, e4, P5, e6, C7] cut to P5).
   - Where they disagree, stop with `BLOCKED: design question` and the probe output.
2. **No empty runs.** A run has one or more segments. A resume with no run before its opening adds no run finding; its gap stays decision 5's `SeqGap` + `Resumed`. The n = m = 0 text (l.843) applies only to runs that have segments. Every run finding is pinned to the run's first segment (file, first record's line and seq; or line/seq `None` when the segment holds no complete record). There is no file-less run finding.
3. **The opening is always compared, and rule 2 binds the candidates.**
   - Decision 5 rule 2 (l.404): the opening's `mmr_size` is the size of the fold of the base and every record present before it. V4 compares every opening checkpoint (size, root, peaks) against the fold. A mismatch is an `MmrMismatch` and is never exempt, wherever the opening sits.
   - "Exempt after the first loss point" applies only to checkpoints **inside** a run (amendment 6). Nothing outside a run is exempt.
   - A resume candidate (13-V3-d5 point 5) whose opening fails rule 2 is removed from the private candidate list, so V6/V7 can never confirm or excuse its gap.
   - The `structural=…` suffix and its tokens stay as d5 defines them; rule 2 is reported by the `MmrMismatch`, not a new token.
4. **Ranges are one definition.**
   - A loss point's `first` and `count` follow ADR amendment 6 and ruling B3d1-d4: `count = loss.seq − first`, where `first` = the preceding complete record's seq + 1, and `count = 0` is legal.
   - The arithmetic is checked and can never panic.
   - For a non-increasing seq at a loss point, use the value the storage side gives for the same layout. If storage defines none, stop with `BLOCKED: design question` and the probe, and don't invent one.
   - The run digest for a real-writer trail must equal what the storage side computes for that trail wherever it computes one.
5. **Fixtures decode.** Every unit fixture must pass the decoder; for example, `size=0` at seq > 0 is rejected. Run each row on base and on the change, and state each row's base result and its killing mutant.


---

# [Comment #27]() by [gerchowl]()

_Posted on November 3, 2026 at 04:01 AM_

## Ruling 13-V4-d2 (architect): V4 brief v2 open points

Settled from ADR-0005 on origin/dev. This adds to 13-V4-d1.

1. **A run exists only when it is closed.**
   - Amendment 6: the reader "accepts a run … if and only if" (i)–(iii) hold, and "the first linking-checkpoint segment after a run must close it immediately" (B3d1-d3).
   - Decision 11: an `accept-run` line names the run's resume record, and one whose resume record is missing is `AcceptMismatch`.
   - So the verifier emits a **run** `SegmentStructure` (with a run digest) only for damaged segments closed by a segment whose first two records satisfy (i) and (ii). (iii) is checked by the fold, and its failure is the opening's `MmrMismatch`, 13-V4-d1 point 3.
   - Damaged segments that nothing closes keep only decision 8's per-segment `SegmentStructure`, and get no run digest. Otherwise a reviewer could `accept-run` a layout the reader rejects.
   - Brief v2's §0 change (`native_boundaries_cannot_be_repaired_by_shipped_checkpoint` going to 2 findings) is **retracted**, unless that fixture's empty segment is closed by (i)+(ii); state which with the probe.
   - Add a row: an unclosed empty or headless segment gives no run finding. Add a mutant: emit a run for an unclosed run.
2. **OQ-V4-new-1, `after` across segments:** accepted. `after` is `u64::MAX` for a span that starts at a segment's first byte, in every segment of the run (ADR l.830). The storage-agreement row covers a multi-segment run with spans.
3. **OQ-V4-new-2, no predecessor:** accepted. A run segment adds a loss point only when a complete record precedes it. A run with none lists no range (l.829, l.843). This holds only for closed runs, per point 1.
4. **Split approved:** V4a is run detection, ranges, spans, digest and the storage agreement. V4b is the fold, the opening and rule-2 comparison, and the candidate filter. They are separate brief files and separate PRs, merged in order. V4a dispatches after the #191/#193/#195 bundle merges.


---

# [Comment #28]() by [gerchowl]()

_Posted on November 3, 2026 at 04:22 AM_

## Ruling 13-V4-d3 (architect): the V4a run rule is the reader's, proven by an agreement table

The check of V4a brief (v3) probed 13 layouts with storage `open` and the brief's rule on the same directory. They disagreed in five places, and two of those fail open. This ruling binds V4a and adds to 13-V4-d1 and 13-V4-d2.

1. **The reader is the oracle.** For every layout, the verifier emits run findings **exactly** for the runs whose segments the storage reader accepts as a run (the per-segment `run` flag in `storage.rs` `history_segment` and its callers). Where the reader rejects the trail (`CorruptTrail`), the verifier emits **no** run finding and no run digest; its other findings stay.
   - V4a proves this with a crate-private **agreement table** in `storage::tests` (lib, `#[cfg(test)]`, so it may call storage internals). It runs storage `open` and `verify` over the same directory for every layout below and every V4a acceptance row, and asserts the same run segments, or none.
   - Verifier code never calls storage internals (trap).
2. **The layout cases, as the reader decides them** (ADR amendment 6 "Run boundaries", B3d1-d3, "Base"):
   - A linking opening after an unsealed segment with **no immediate resume** ends the candidate. That is no run (p12, p06: storage `first successor lacks immediate resume`).
   - **Any checkpoint first at the base** is the base (l.625), including an archived one with `prev ≠ genesis`, so an archived base alone is no run (p08). A non-checkpoint first record at the base means no run (p07, storage `missing initial checkpoint`).
   - **A closer ends run 1 and may start run 2** (p01, storage `closing_segment_can_start_second_run`).
   - **A non-increasing seq** gives no run finding (storage `record sequence did not increase`). The other findings stay, it never panics, and the row is tested. This settles the d1 point 4 non-increasing case.
3. **Rows.**
   - Replace A2 with §19.2 **as stated** (S0 deleted), with and without a later crash plus resume. Each row's expected run set is whatever the reader decides.
   - Use record-free segments for the `after = u64::MAX` spans (A9), and pin A9's digest.
   - Fix A3 (`L = 9`).
   - Give every mutant a killer that has actually run. M8 (rule drift) is killed by the agreement table.
4. **No field that nothing reads.** Cut `Run::first_loss_seq`; V4b adds what it needs. Remove the `expect`s on `run_digest`/`with_run_digest`.
5. **Escalation.** This is the V4 brief's fourth revision. If the next check finds a blocker in the run rule, the architect escalates to the owner instead of revising again.


---

# [Comment #29]() by [gerchowl]()

_Posted on November 3, 2026 at 10:18 AM_

## Ruling 13-V4-d4 (owner decision, 2026-11-03): one shared run classifier

Four V4a brief revisions restated the reader's run rule from the ADR prose, and each drifted from the reader. The last check found 11 layouts where storage `open` and the brief's verifier disagree: an archived base, the immediate-resume boundary after a run segment, a genesis closer after a fragment-only segment, and trails the reader rejects for other reasons. Following 13-V4-d3 point 5, this was escalated to the owner, who chose **one definition**.

1. **A refactor PR comes first** (its own issue, before V4a). It moves the reader's run classification into one pure, crate-private module: the per-segment `run`, `unsealed` and boundary-resume logic, base selection, run closure (i)+(ii), and the in-run sequence and link rules that today live in `history_segment` and its callers in `src/audit/storage.rs`.
   - **Pure:** no I/O, no locks, no writer state. It works on already-decoded segment summaries.
   - **Complete:** it returns the per-segment classification **and every violation** it finds, as typed values (an enum, not strings).
   - **The reader keeps its exact behaviour.** It maps the first violation, in its current order, to the same `CorruptTrail` it reports today, with the same detail text. All `audit::storage::tests` pass unchanged.
2. **V4a then calls that module.** A run finding is emitted exactly for the runs the classifier accepts. The fold condition (iii) stays V4b's: V4b uses the same module, or the shared fold, for the MMR comparison. The agreement table (13-V4-d3 point 1) remains as a regression test.
3. **The trap is narrowed.** The verifier still never calls `history_segment`, `scan_inner` or `apply_checked`. It may call the shared pure classifier.
4. The open point from the last check (which rejected trails may show a run) is settled by the classifier's typed violations. V4a emits no run for a run the classifier rejects, except for a fold-only violation (iii), which is V4b's `MmrMismatch`.


