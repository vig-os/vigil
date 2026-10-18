---
type: issue
state: open
created: 2026-10-09T13:22:04Z
updated: 2026-10-16T13:54:57Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/13
comments: 11
labels: feature, security, priority:medium, area:testing, effort:medium
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:42.779Z
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

