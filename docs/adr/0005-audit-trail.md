# ADR-0005: Audit trail

- **Status:** Accepted (2026-10-11), amended by [#66](https://github.com/vig-os/vigil/issues/66); amendment 2 ([#68](https://github.com/vig-os/vigil/issues/68), [#70](https://github.com/vig-os/vigil/issues/70)) Proposed.
- **Amended 2026-10-11 ([#66](https://github.com/vig-os/vigil/issues/66)), Accepted:** decides the four open sub-decisions: the clean-stop head (`close()` returns a `Checkpoint`, decision 9), the receipts range (seq 0 or the start through the head, with waivers and an explicit live mode, decision 5), `start_from` acceptance (only an anchored start demotes anything, decision 11) and revocation scope (a key revoked on one trail is revoked on every trail that lists it, decision 9). Decision 16 states what each rule detects under the four threat models. Receipts across a `resume` were deferred to [#70](https://github.com/vig-os/vigil/issues/70), and `--strict` with reviewed warnings to [#68](https://github.com/vig-os/vigil/issues/68); amendment 2 decides both.
- **Amended 2026-10-11 ([#68](https://github.com/vig-os/vigil/issues/68), [#70](https://github.com/vig-os/vigil/issues/70)), Proposed:** decides the two questions #66 deferred. **#68:** a writer that repairs a torn tail attests the fragment's bytes in the next line it writes (`audit.repaired`, decisions 3, 4 and 5), so an honest crash's fragment becomes `TornWriteRepaired` (info) once a trusted checkpoint covers that line, and a fragment no line attests is `RepairMismatch` (an error); warnings that stay for good (a trailing fragment no write can attest any more, `Resumed`, `ClockWentBackwards`, `DuplicateRecord`) pass `--strict` only through a hash-pinned `accept` line in a separate review file (decision 11). **#70:** `resume` never reuses a `seq`: it continues above `--lost-through`, the highest `seq` the deployment holds evidence of, so the chain may jump once at a declared resume gap; inputs inside a gap whose resume record is pinned from outside (a receipt or an `accept` line) are `LostRecord` (info), and `expect_head` and the rotation's expected head need no change (decisions 5, 7, 8 and 9). Decision 17 states what each rule detects under the four threat models. Format changes, before 1.0 (decision 12): one optional hashed attribute and `mmr_size` counting records instead of equalling `seq`.
- **Date:** 2026-10-11
- **Issues:** [#10](https://github.com/vig-os/vigil/issues/10) (this decision); implemented by [#11](https://github.com/vig-os/vigil/issues/11) (sink and record API), [#12](https://github.com/vig-os/vigil/issues/12) (chain, MMR, checkpoints), [#13](https://github.com/vig-os/vigil/issues/13) (verify API and CLI, tamper tests); amended by [#66](https://github.com/vig-os/vigil/issues/66), [#68](https://github.com/vig-os/vigil/issues/68) and [#70](https://github.com/vig-os/vigil/issues/70); deferred work in [#56](https://github.com/vig-os/vigil/issues/56), [#57](https://github.com/vig-os/vigil/issues/57), [#58](https://github.com/vig-os/vigil/issues/58), [#59](https://github.com/vig-os/vigil/issues/59)

## Context

### What the requirement is

21 CFR Part 11 §11.10(e) asks for "secure, computer-generated, time-stamped audit trails to independently record the date and time of operator entries and actions that create, modify, or delete electronic records. Record changes shall not obscure previously recorded information." The trail must be kept as long as the records it covers and be available for review and copying. EU GMP Annex 11 §9 adds the reason for a change. Read together, they ask for **attribution, tamper-evidence and retention**, not for a particular data structure. Operational telemetry (vigil's logs, metrics and traces) is out of scope: it may sample, batch and drop, which an audit trail must never do. Medical-device use places this module under IEC 62304, so it must stay small, closed and heavily tested.

### The owner's question: does tessera benefit vigil's audit trail?

The plan in #10 and #12 built the chain and checkpoints "on tessera-core". The owner asked whether that coupling is real or came from misreading the discussion, since tessera is the data-product crate and not telemetry. This section answers with evidence from vig-os/tessera at `f08255d` (`dev`, 2026-10-05): `docs/CONSUMING.md`, ADRs 0028, 0036, 0037, 0052 and 0058, and `tessera-core`'s `hash.rs`, `signing.rs` and `manifest.rs`.

**What tessera is.** A FAIR data-product format. A product (`.tsra`) is built, then **sealed once**: `manifest_hash` is blake3 over the RFC 8785 (JCS) canonical manifest, which commits to `content_hash`, the MMR root over the ordered block digests. A sealed product is immutable; a new version is a new product (ADR-0022/0036). Tessera's own "audit" is the version history of datasets: ADR-0036's `log/<lineage>.jsonl` is "a pure rebuildable cache, *not* canonical", and the RFC's "History — append-only manifest/hash chain" means chains of product versions. Nothing in tessera records operator actions.

**What vigil's audit trail is.** A live, append-only event log with many writer processes. Every record must be durable before the action it records is allowed to proceed. The log is never finished, so it cannot be sealed once.

**Concept-by-concept comparison:**

| tessera concept (where) | vigil audit need | Fit |
|---|---|---|
| blake3, digests spelled `"blake3:<hex>"` (`hash.rs` `digest`) | record hashes | **Fits.** vigil spells its record hashes the same way (decision 4). |
| MMR: leaf `blake3(0x00 ‖ digest string)`, node `blake3(0x01 ‖ l ‖ r)`, peaks bagged right to left, empty root `blake3("")` (`hash.rs`, ADR-0028/0049) | an append-only commitment with cheap proofs | **Fits exactly.** vigil adopts the construction bit for bit (decision 7). Probe: identical roots for every size 1..=2048 and for the empty trail. |
| inclusion and consistency proofs (`inclusion_proof`, `ConsistencyProof { old_peaks, appended }`) | proving one record to an auditor; proving that a later checkpoint extends an anchored one | **Fits.** Probe: tessera-core verifies proofs against vigil roots, including a consistency proof built from a vigil checkpoint's stored peaks. |
| `MerkleAccumulator` (streaming push, `root()`) | resuming the MMR from a checkpoint after a restart or in another process | **Gap.** Its peaks are private; it cannot be resumed from stored peaks. |
| sealing: `manifest_hash` over the JCS manifest, once | per-record integrity in a log that never ends | **Does not fit.** There is no hash-chain primitive and no checkpoint type; a product is sealed once and is immutable afterwards. |
| `ed25519-env-v1`: Ed25519 over the JCS `{alg, key_id, manifest_hash, signer, signed_at, key_format}` (`signing.rs`, ADR-0037) | signing checkpoints | **Partly fits.** Same curve, same raw 32-byte keys and hex key files (`tessera keygen` files are usable by vigil, decision 9). The envelope is bound to the meaning "manifest hash" and needs `serde_jcs`. Reusing it would make a vigil checkpoint signature a valid tessera product signature over the same string (a cross-protocol confusion), so vigil signs its own domain-separated message. |
| product schemas, embedded JSON Schema (`schema.rs`) | the audit record schema | **Does not fit.** They describe data products; an audit record is an OTLP log record (ADR-0001). |
| `Producer` `{tool, version, git_commit, git_repo, dirty}` (ADR-0058) | who wrote the trail | **Maps 1:1** to the resource vigil already writes (`service.name`, `service.version`, `vcs.ref.head.revision`), for the export in #59. |
| "non-deterministic bytes ride outside the seal; identity-bearing bytes are sealed" (ADR-0058) | what the record hash covers | **Same rule.** vigil hashes every field that carries meaning and leaves only correlation and transport fields outside (decision 4). |
| archival trust principle: verification depends only on bits in the product plus bits the verifier already holds (ADR-0037 §1) | verifying a trail in year 10, offline | **Adopted** (decision 11). |
| distribution: git-only, `0.1.0-alpha.1` unreleased, format `v0` "deliberately unfrozen", edition 2021, toolchain `stable` with no MSRV (ADR-0052, `CONSUMING.md`, `Cargo.toml`) | a crates.io release whose format is frozen at 1.0 | **Blocks a dependency.** A crate with a git dependency cannot be published (pre-mortem R3: `cargo package` exits 101), and an unfrozen format under the trail cannot carry decision 12's promise. |

**Answer.** The coupling came from shared vocabulary and shared primitives, not from a shared problem. Tessera seals finished artefacts, while vigil's audit trail is a live log. What tessera-core would contribute (blake3, an MMR, Ed25519) comes straight from `blake3` and `ed25519-dalek` plus an MMR whose push and root take under 50 lines (probe). Taking it as a dependency would add 41 crates (scratch crate on tessera-core: 41 normal dependencies, against 23 for `blake3` plus `ed25519-dalek`), and the two parts that do not fit (sealing and the envelope) would have to be worked around. Tessera does benefit vigil in two concrete ways, and this ADR takes both:

1. **A proven MMR construction, adopted bit for bit.** tessera-core can check vigil's roots and proofs today without either crate depending on the other (decision 7, probe below).
2. **An archival home.** A sealed audit segment can become a tessera product, for long-term FAIR archiving next to the data it audits. That export and an optional swap to tessera-core's MMR code are the adoption path (decision 15, [#59](https://github.com/vig-os/vigil/issues/59)). The owner is happy to adopt the core once it is published and frozen.

### Probes (2026-10-11, Rust 1.95.0 from the dev shell, scratch crates outside the repository)

- **MMR equivalence.** A scratch crate implements the MMR of decision 7 over 32-byte record hashes, with tessera-core (path dependency on the `f08255d` clone) as a dev-dependency.
  - Roots are equal to `MerkleAccumulator::root()` for every size 1..=2048, to `merkle_root` at sizes 1..=70 and every 97th size, and the empty root is equal too.
  - `verify_inclusion` accepts vigil-root proofs at indices 0, 1, 99, 100, 511, 512 and 776 of 777, and rejects a swapped leaf.
  - `verify_consistency` accepts a `ConsistencyProof` built from each stored checkpoint's peaks (every 100 records), and the proof equals tessera's own `consistency_proof`.
  - Resuming from stored peaks reproduces the final root.
  - `cargo test --release`: 2 passed. Mutation: bagging left to right instead fails both tests (`n=3`).
- **Cost per record** (release, thin LTO, vm-dev, 200 000 records of about 1.4 KB, each with reason, before and after):
  - canonical encoding, blake3, chain link and the OTLP/JSON line: **1.26 µs per record** (SIMD blake3), 2.67 µs with blake3's `pure` feature;
  - MMR push: 0.34 µs (0.45 µs pure);
  - Ed25519 sign: 11.1 µs; `verify_strict`: 24.1 µs.
- **fsync policy** (one process appending about 1.4 KB lines):

  | Policy | ext4 on virtio (`/home`) | tmpfs |
  |---|---|---|
  | no fsync | 0.77–1.6 M records/s | 2.1 M records/s |
  | `sync_data` each record | p50 23–34 ms, p99 57–84 ms, **30–37 records/s** | 1.8 M records/s (a no-op) |
  | `sync_all` each record | p50 28–35 ms, 30–34 records/s | 1.7 M records/s |
  | `sync_data` every 64 records | 1 961–1 982 records/s | — |

  Three runs on ext4. The host is shared, so these are orders of magnitude, not budgets ([#49](https://github.com/vig-os/vigil/issues/49) sets budgets).
- **Torn lines and duplicate keys** (`serde_json` 1, scratch test):
  - every UTF-8 prefix of a 1 271-byte record line fails with `Category::Eof`: 1 266 prefixes, plus 4 that cut a multibyte character;
  - a complete line with a duplicated `stringValue` key parses as `serde_json::Value`, keeping the last value.
- **Platform fsync.** In Rust 1.95.0 std (`library/std/src/sys/fs/unix.rs:1381-1430`), `File::sync_data` is `fdatasync` on Linux and `fcntl(F_FULLFSYNC)` on Apple targets, as is `sync_all`. Plain `fsync` on macOS does not flush the drive cache (`fsync(2)` on macOS); std already does the right thing.
- **Nix and crane build.** A scratch clone of vigil (`fc7d8d5`) adds `blake3 = { version = "1", default-features = false, features = ["std"] }` and `ed25519-dalek = { version = "2", default-features = false, features = ["std", "zeroize", "fast"] }`, plus a known-answer test (BLAKE3 of the empty input; RFC 8032 §7.1 TEST 1 signature with `verify_strict`).
  - `nix build .#checks.x86_64-linux.clippy .#checks.x86_64-linux.nextest`: exit 0, 127 tests passed, including the known-answer test, which crane runs in release mode.
  - The same build with blake3's `pure` feature (the configuration decision 14 chooses): exit 0, 127 passed. `pure` adds no crate (81 either way).
  - `#![forbid(unsafe_code)]` stays in vigil.
  - The normal dependency tree grows from 64 to 81 crates (arrayvec, blake3, block-buffer, constant_time_eq, cpufeatures, crypto-common, curve25519-dalek(-derive), digest, ed25519, ed25519-dalek, generic-array, sha2, signature, subtle, typenum, zeroize).
  - Licenses: MIT/Apache-2.0, `CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception` (blake3) and BSD-3-Clause (curve25519-dalek, ed25519-dalek, subtle). Declared MSRVs are at most 1.85.
  - `getrandom` 0.3.4 is already in the tree (through `opentelemetry_sdk` → `rand`), so using it adds no crate.

### Probes for the #66 amendment (2026-10-11, Rust 1.95.0 from the dev shell, a scratch crate outside the repository)

The four sub-decisions are rules about what the writer returns and what the verifier reports, so the probe is an executable model of those rules, run against both the accepted rule ("Old") and the amended one ("New").

- **The model.** `blake3` and `ed25519-dalek` with decision 14's features; records with `trail`, `seq`, kind, `prev_hash` and a domain-separated hash; checkpoints signed over a domain-separated message and checked with `verify_strict`; a trust policy with per-trail sections and `through=` bounds; and a verifier for chain, signatures, trust, revocation, anchors, receipts, waivers and `start_from`. MMR and OTLP encoding are left out, because none of the four rules depends on them. The model keeps one receipt per `seq`, so the rule for two receipts with one `seq` (decision 11, receipts file) is checked only by #13's tests.
- **24 attack tests** (`cargo test --release`, exit 0, three runs). Ten of them were added after two rounds of independent adversarial review. After round 1: in-flight records below the highest receipt, a start read from the disk, receipts lost with a `resume`, a retired trail, a waiver below the start, and late adoption. After round 2: a retired trail's bound below `end=`, plus three tests of the withdrawn `lost` mechanism (a forged resume, a resume-named record without the resume shape, and archiving past a resume), kept as input for [#70](https://github.com/vig-os/vigil/issues/70). Each attack runs against both rules:
  - forged records after the last receipt, signed by an honest `close()`: Old passes `--strict`, New reports `NoReceipt`;
  - a forged record before the first receipt: Old misses it, New reports it;
  - the stolen-key start: Old passes `--strict` with every anchor `OutOfRange`, New reports `UnanchoredStart`;
  - a key revoked on X only: under Old, Y forged with it passes `--strict`, under New the policy fails to load;
  - the honest cases (clean stop, waived crash orphan, anchored start, revocation on every trail) pass `--strict` under New.
- **Mutation.** Twelve mutants of the rules this amendment keeps, each killed by at least one test:
  - no cross-section revocation check;
  - an unanchored start demoting to info;
  - the range ending at the last receipt, or starting at the first;
  - no `SeqGap` without a start;
  - a waiver not pinned by its hash;
  - the live cut ignoring holes;
  - `end=` not confirming a bound, or not enforced;
  - waivers below the start not treated as inputs;
  - the `from` line ignored;
  - `end=` confirming only a bound equal to it.

  The last mutant first survived, because a later receipt masked it; the test was tightened until it failed.
- **Multi-process close** (real processes, `std::fs::File::lock`, `sync_data`):
  - 8 writer processes, 20 runs: the highest `seq` among the receipts and close checkpoints the processes printed was always the last line on disk, that line was always a close checkpoint, and every line was returned to exactly one process;
  - a writer SIGKILLed mid-run left records above everything held; one restarted writer's close returned exactly the disk head.

### Probes for amendment 2 (#68, #70; 2026-10-11, Rust 1.95.0 from the dev shell, a scratch crate outside the repository)

Like #66's, the probe is an executable model of the rules: what the writer writes and what the verifier reports. It runs three rule sets: the accepted core with #66 ("Old"), the `lost`-line draft withdrawn from #66 ("Withdrawn"), and this amendment ("New").

- **The model.** `blake3` and `ed25519-dalek` with decision 14's features, `serde_json` for the lines (so decision 5's end-of-input rule for fragments is the real parser's). Records carry `trail`, `seq`, kind, time, action, details, `audit.repaired`, `mmr_size`, key, signature, `prev_hash` and a domain-separated hash. The writer works on real file bytes: it finds the torn tail, writes the repair newline, attests the gap, seals segments and runs `resume`. The verifier checks chain, resume gaps, `mmr_size`, signatures, fragments and attestations, receipts, anchors, the start and `accept` lines. The MMR and the OTLP encoding are left out: no rule here depends on them, only on what `mmr_size` counts.
- **32 scenarios** (`cargo test --release`, exit 0, three runs), each asserting the amended rule. Eight were added after three rounds of independent adversarial review (below):
  - #68: an honest SIGKILL mid-write (`TornWriteRepaired`, `--strict` passes); a crash during the repairing write (one gap, one attestation); a fragment inserted between covered records, and an attested fragment edited afterwards (`RepairMismatch`); a fragment appended at the live tail before an honest write (the documented limit: info); a forged record carrying an attestation (`NoReceipt`); a trailing fragment (warning; accepted by a pinned line; a wrong digest accepts nothing; the next write attests it and the stale line is `AcceptUnused`); an attestation not yet covered by a checkpoint (warning until it is); a removed attested fragment (info); an accept line with another hash at its `seq`, or above the head (`AcceptMismatch`); an accept line naming an error (usage error); an honest clock step (warning, accepted).
  - #70: an honest resume after a deleted live file with six receipted records lost (six `LostRecord`, `--strict` passes once the resume is accepted); a rollback of the new records after the resume (`ReceiptMismatch`); `expect_head` from the highest held receipt after a resume (succeeds); a gap forged with a stolen key and no receipt for its resume record (`NoReceipt`, and the lost receipts stay `ReceiptMismatch`); a gap opened without a key (`UntrustedKey`); a signed jump without the resume record, or with details that do not match the jump (`SeqGap`); anchors inside an unconfirmed gap, and inside one confirmed only by an accept line (`AnchorMismatch` both: a text line never overrides an anchor), and with the gap's opening checkpoint anchored too (`LostRecord`); a start at the resume's opening checkpoint (inputs below it follow decision 11's start rule); a `--lost-through` below a held receipt (`ReceiptMismatch` and `HeadMismatch`: fails closed); two resumes; a resume with nothing lost.
  - Added after review: a Collector-style copy of a resumed trail with every line in one file (passes `--strict` once accepted; the first draft required the opening checkpoint to be the first record of its file and failed it); a resume after a rollback that left a well-formed live file (the rolled-back receipts are `LostRecord`, `expect_head` works); a complete line cut just before its newline (a record, `NoReceipt`, no fragment); an `accept TornWrite` line naming a missing record (`AcceptMismatch`). After rounds 2 and 3: every byte prefix of a resume's staging write, with and without a gap, over a deleted live file and over a live file ending in a checkpoint and a crash fragment, run through decision 8's settlement (each is discarded and `resume` re-run, or promoted with both lines: exactly one resume record, plain verification passes); the settlement of `.audit-next.jsonl` (a complete `create` or sealing staging file promoted, a torn one or a lone checkpoint whose `seq` jumps discarded); a fragment at the end of a file sealed by `resume`, and one appended after a rotation-sealed segment's closing checkpoint (both `TornWrite`; the second is marked "no crash outcome", an `accept` line for it is `AcceptMismatch`, and verified alone without the next file it is unmarked: the documented residual, decision 17).
- **Against the old rules** (each a test, exit 0):
  - Old: after one honest SIGKILL followed by five more records and a checkpoint, `TornWrite` stays and `--strict` fails, with nothing that could accept it; a fragment inserted between covered records is only a warning, so plain verification passes; the receipts of records lost with a `resume` are `ReceiptMismatch` for good.
  - Withdrawn, **#70's M1:** after an honest resume, new records are written, then rolled back, and a writer restarted without `expect_head` writes again at the same `seq`s. The receipts of the rolled-back records sit inside (named head, `lost_through`], next to the lost ones, so an operator labels them `lost`: every one is `ReceiptLost` and plain verification passes. New reports `ReceiptMismatch` for the same attack, because the new records sit above `lost_through`.
  - Old and Withdrawn, **#70's M2:** after a resume, the highest held receipt is a lost record's, above the new head at a reused `seq`, so `open` with `expect_head` is `HeadMismatch` and cannot recover. Under New the highest held receipt is the resume record's, and `open` succeeds.
- **Mutation.** Sixteen mutants of the amended rules, each killed by at least one scenario: a jump accepted without the resume record, or with details that do not match; a gap confirmed by its signature alone; inputs above `lost_through` treated as lost; an unconfirmed gap demoting anchors; `audit.repaired` checked for presence instead of value; an attestation counted before a checkpoint covers it; an unattested fragment reported as a warning; an accept line not pinned by its hash, accepting an error, or matching a fragment by `seq` alone; `mmr_size` required to equal `seq`; sealing settlement promoting a lone checkpoint without checking its `seq`; resume settlement promoting a lone opening checkpoint; anchors inside a gap set aside by a receipt or an `accept` line without an anchored opening checkpoint; an `accept` line accepting bytes after a rotation-sealed closing checkpoint.
- **Multi-process** (real processes, `std::fs::File::lock`, `sync_data`): 8 writer processes append 15 records each while three more writers are SIGKILLed after writing half a line, holding the lock; then one process closes. 20 runs: every completed write returned exactly one receipt (121), three fragments were on disk, every gap was attested by the next writer, whichever process took the lock (one to three gaps: back-to-back kills leave several fragments in one gap), and New passed `--strict` with the receipts and no `NoReceipt`. Old reported three `TornWrite` and failed `--strict` in every run.
- **Independent adversarial review** (a fresh reviewer with its own attack tests on the model). It found no way under threat models (a) or (b) to turn an error into info or a warning, or to pass `--strict` where the core and #66 rules would fail: reusing a confirmed resume's receipt for another gap, forged gaps with and without the key, a second forged gap to hide a rollback, revocation bounds inside a gap, inserted fragments and moved `accept` lines were all caught. It found two honest cases that failed for good and several underspecified rules; all are fixed in this text: a crash during `resume` (both lines now go into the staging file together, decision 8), a shipped copy of a resumed trail (the gap rule no longer depends on file boundaries), the effect of a `from` line or bound inside a gap, duplicates in `mmr_size`, which `TornWrite`s can be accepted, the writer's view of an attestation without a gap, a complete line without its newline, `resume` on a well-formed live file, and an overflow bound on `--lost-through`. A fresh round-2 reviewer confirmed those fixes and found one more honest failure: a power loss could leave a staging prefix ending right after the opening checkpoint, which the promote rule then accepted as a jump without its resume record; promotion now checks the `seq` (decision 8). A fresh round-3 reviewer found that a resume with nothing lost still had a crash prefix the sealing rule promoted (a lone checkpoint at the next `seq`), that the rule was undefined for `create`, and that an attempt to make bytes after a rotation-sealed closing checkpoint an error (round 1's minor finding) needed file names and misfired on honest copies. So `resume` now has its own staging file, `.audit-resume.jsonl`, promoted only with both lines; the sealing rule names `seq 0` after the genesis value; and bytes after a closing checkpoint stay a `TornWrite` warning that the review criteria forbid accepting (decision 17 lists the residual). `resume` holds the directory lock throughout. The architect's review of the PR then found that a receipt or an `accept Resumed` line set aside anchors and `through=` pins inside a gap, so a stolen key plus one accepted line could override anchors (#66 required an anchored start for that). Anchors and pins inside a gap now need the gap's opening checkpoint anchored, and the verifier itself refuses an `accept` line for bytes after a rotation-sealed closing checkpoint (probe: both, with mutants).
- **Not probed:** a real power loss. The rule rests on decision 5's premise that a torn write is a byte prefix of the line; decision 6 now states the filesystem requirement that makes this hold. Nor the writer's read-side checks, its cached-offset path ("Same file, longer"), or locking during `resume`: the model writer re-reads whole files and the settlement model is a single function, so #11's multi-process tests carry those.

### Constraints from earlier decisions

- **ADR-0001:** one complete OTLP/JSON `LogsData` per line; the Collector `otlpjsonfile` receiver is the conformance oracle; it drops lines over 1 MiB, and it drops zero and empty fields on a round trip.
- **ADR-0002:** the directory lock, inode recheck, segment names, no-replace rotation and partial-write repair are proven under multi-process load. Retention deletes old segments, which an audit trail must never do.
- **[ADR-0004](0004-public-api-and-stability.md)** (Accepted):
  - feature `audit`, off by default, adding blake3, ed25519-dalek and vigil's own MMR;
  - the stable surface may name only vigil's own types, std and the `tracing` family;
  - errors have a `kind()` with a `#[non_exhaustive]` kind enum;
  - every public enum is `#[non_exhaustive]` and no public struct has public fields;
  - `init` degrades instead of failing when the environment is at fault.

## Decision

### 1. Scope: a separate, synchronous, fail-closed API behind feature `audit`

- The feature **`audit`** (off by default, ADR-0004 decision 7) adds the module `vigil::audit` and the binary `vigil-audit`.
- Audit records are **not** `tracing` events. A filter, a sampler or a full batch queue can drop a `tracing` event, and an audit record must never be dropped. The application calls `AuditTrail::record` directly and gets a `Result`.
- The trail is opened on its own (`AuditConfig::open`), independent of `vigil::init`. An application can audit even when its telemetry has degraded to stderr.
- **Exception to ADR-0004 decision 3:** opening a trail and writing to it **fail closed**. An environment fault (unwritable directory, failed fsync, unusable key) is an `Err`, never a degradation. The caller must not complete the audited action without an `Ok`.
- **Out of scope:** electronic signatures (§11.50, §11.70, §11.100–300), identity management and authentication (the application passes an authenticated actor), access control beyond file modes (§11.10(d)), and making personal data erasable inside the trail (put a digest in the trail instead, decision 3).

### 2. Files: ADR-0002's machinery in a directory of its own

- The trail lives in **`<state dir>/audit/`**: `audit.jsonl` (live) and `audit-<stamp>[_NNNNNN].jsonl` (sealed segments, ADR-0002 decision 5 names). The state directory is the one `init` resolves (`$XDG_STATE_HOME/<service>/`); `AuditConfig::dir` overrides the audit directory itself.
- **Its own directory, so its own lock.** All signals in one directory share one lock (ADR-0002 decision 3). An audit fsync of tens of milliseconds (probe) must not hold up log appends, and audit files must never sit in a directory that retention prunes.
- **Reused from ADR-0002**, through a crate-internal locked-section API in `src/rotate.rs` (as implemented in #11):
  - the directory `flock` with device and inode recheck;
  - the live-file inode recheck before every write;
  - collision-free segment names;
  - atomic no-replace rotation;
  - rollback of partial writes and repair of unterminated tails;
  - modes `0600` and `0700`;
  - local filesystems only;
  - lock-free readers that retry.
- **Different from ADR-0002:**
  - Retention is always off: vigil never deletes or rewrites an audit file.
  - Rotation (at `max_bytes`, default 50 MiB) is preceded by a sealing checkpoint (decision 8).
  - Each write is followed by an fsync (decision 6).
  - Lines are never truncated (decision 6).
- **Sealing uses one staging file,** `.audit-next.jsonl`, and `resume` its own, `.audit-resume.jsonl` (amended, #70). Their leading dot keeps them out of the `audit.jsonl` / `audit-*.jsonl` patterns that readers and shippers match (ADR-0002 Consequences). Each exists only while a rotation, a `create` or a `resume` is in progress (decision 8).
- **Archiving** (moving sealed segments to WORM or off-host storage) is an operator action outside vigil. Any sealed segment may be moved: the live file always starts with a checkpoint that carries the state the writer needs (decision 8). The live file and the trail marker (decision 8, "Creating a trail") must stay. **Procedure** (amended, #66), so that the part that stays can be verified on its own (decision 11, `start_from`):
  1. Take a snapshot (a copy of the trail files) and verify it, archive and live together, with the anchors and receipts (`vigil-audit verify <snapshot>`): no error.
  2. Choose the start: the opening checkpoint of the oldest segment that stays.
  3. **Record and anchor the start:** copy its line **from the snapshot step 1 verified** (`vigil-audit checkpoints <snapshot>`), never from a later read of the trail directory, into the archive's own record (kept with the archive, outside the trail directory) and into the anchor store. Only an anchored start lets the verifier set aside the anchors, revocation pins, receipts and waivers below it (decision 11).
  4. Move the older segments.

  **`--start-from` comes from that archive record, never from the trail directory**, just as `--expect-head` never does (decision 9). Where many checkpoints are anchored, a checkpoint read from the disk is likely to be "anchored" too. An attacker who deletes kept segments up to a later opening checkpoint would then make the anchors and receipts of the deleted records `OutOfRange`. With the recorded start, the same deletion is `StartMismatch`, because the start is no longer the first record (probe).

### 3. Record schema: OTLP log records with `audit.*` attributes

Each line is one `LogsData` with one `ResourceLogs`, one `ScopeLogs` and one `LogRecord`, written by vigil's OTLP/JSON encoder (ADR-0001). A reader may also meet lines that contain several records, for example after a Collector round trip, and must accept them.

| OTLP field | Content | Hashed |
|---|---|---|
| resource `service.name` | the service the trail belongs to | yes (tag `0x05`) |
| resource `host.name` | the host, when vigil's resource has it | yes (`0x06`) |
| other resource attributes (`service.version`, `process.pid`, `vcs.ref.head.revision`, and whatever ADR-0003 adds) | context | no |
| scope | `name` `vigil.audit`, `version` = vigil's version | no |
| `timeUnixNano` | taken from the system clock by vigil inside the locked section; the API takes no timestamp | yes (`0x03`) |
| `observedTimeUnixNano` | equal to `timeUnixNano`; a v1 reader rejects a record where it differs or is missing (`InvalidField`), so no second, unhashed time can be shown | no (bound by equality) |
| `eventName` | `audit.record` or `audit.checkpoint` | yes, as the kind (`0x04`) |
| `severityNumber` / `severityText` | `9` / `INFO`, fixed; a v1 reader rejects any other value, or a missing one (`InvalidField`), since tools display them | no (bound by being fixed) |
| `traceId` / `spanId` / `flags` | the current span and its trace flags, if any; correlation only, never presented as record content | no |
| any other `LogRecord` field (`droppedAttributesCount` other than `0`, or a field a later OTLP adds) | a v1 reader rejects it (`UnknownField`), like `body`: nothing unhashed and displayable may sit on a record | — |
| `body` | absent; a v1 reader rejects a record that has one (`InvalidField`), so no unhashed text can sit next to hashed fields | — |

Attributes. Integers are OTLP `intValue`, `audit.mmr_peaks` is an `arrayValue` of `stringValue`s, and everything else is a `stringValue`. Strings are UTF-8, must not be empty, and must not contain a NUL.

**Integer decoding** (`intValue`, `timeUnixNano`, `observedTimeUnixNano`). OTLP/JSON writes 64-bit integers as decimal strings, and readers must accept JSON numbers too. vigil writes strings. A v1 reader accepts:

- a string of ASCII digits with no sign, no leading zeros (except `"0"`), no whitespace and no exponent;
- or a JSON integer number with the same restrictions.

The value must fit in u64. Anything else, including a negative value, a fraction, `1e3` or `"+1"`, is `InvalidField`. So every value has exactly one decoding, and the hash covers that value.

| Attribute | Kinds | Content | Tag |
|---|---|---|---|
| `audit.v` | both | format version, `1` | — (fixed by the domain string) |
| `audit.trail` | both | 32 lowercase hex characters (16 random bytes from `getrandom`), chosen when the trail is created (decision 8) | `0x01` |
| `audit.seq` | both | 0-based, contiguous across segments except at a declared resume gap (decision 5, amended by #70); the authoritative order | `0x02` |
| `audit.repaired` | both, optional (amended, #68) | the writer's attestation of the torn-tail bytes it repaired just before this line: `blake3:<hex>` (decision 5). Written only on the first line after a repair; never set from an `Entry` | `0x07` |
| `audit.actor` | record, required | the authenticated identity the application supplies (Part 11 "operator") | `0x10` |
| `audit.action` | record, required | what was done, convention `<domain>.<verb>` with verbs such as `create`, `modify`, `delete` (Part 11 "create, modify, or delete") | `0x11` |
| `audit.object` | record, required | the identifier of the regulated record acted on | `0x12` |
| `audit.reason` | record, optional | why (Annex 11 §9) | `0x13` |
| `audit.before` / `audit.before_digest` | record, optional, at most one of the pair | the prior value as text, or `blake3:<hex>` of it | `0x14` / `0x15` |
| `audit.after` / `audit.after_digest` | record, optional, at most one of the pair | the new value, same rule | `0x16` / `0x17` |
| `audit.details` | record, optional | free text (for example JSON) | `0x18` |
| `audit.mmr_size`, `audit.mmr_root`, `audit.key_id`, `audit.sig` | checkpoint, required | decision 8 | `0x20`, `0x21`, `0x23`, `0x24` |
| `audit.mmr_peaks` | checkpoint, present exactly when `audit.mmr_size` > 0, with exactly popcount(`mmr_size`) entries | decision 8; absent at size 0 because the Collector drops empty arrays | `0x22` |
| `audit.prev_hash` | both | the previous record's `audit.hash` | `0x7f` |
| `audit.hash` | both | this record's hash (decision 4) | — (it is the output) |

- **Empty strings are rejected, not dropped.** The Collector drops empty values (ADR-0001 decision 8), and an absent field and an empty one would then hash differently after a round trip.
- **A v1 reader rejects every log-record attribute outside the v1 set** (`UnknownField`), and any attribute key that appears twice in one record (`InvalidField`). Otherwise an unhashed attribute such as `audit.note` or `approved_by` could be added to a signed record and look authoritative, or two values for one key could make vigil hash one while another OTLP tool shows the other. vigil writes no other attributes.
- **Resource and scope attributes other than `service.name` and `host.name` are not authenticated.** They are context for shipping and debugging; `vigil-audit verify` never presents them as part of the record.
- **The before and after values** are what makes a change "not obscure previously recorded information". Where a value is large or personal, the application passes `Value::Digest`, keeping the trail small and free of the data itself. The application's own store must then keep the value the digest refers to.

### 4. Canonical encoding and record hash (frozen in v1)

The hash covers **values, not JSON bytes**. A verifier parses the OTLP/JSON line, extracts the fields and re-encodes them. So the hash survives anything that preserves attribute values: re-serialisation by a newer `opentelemetry-proto`, attribute reordering, or the Collector's `intValue` spelling.

```text
F(tag, v)    = tag (1 byte) ‖ len(v) (u32, big-endian) ‖ v
fields       = F(0x01, trail[16]) ‖ F(0x02, seq u64 BE) ‖ F(0x03, time u64 BE) ‖ F(0x04, kind: 0x01 record | 0x02 checkpoint)
               ‖ F(0x05, service.name) ‖ [F(0x06, host.name)] ‖ [F(0x07, repaired[32])]
               ‖ kind fields in ascending tag order, absent optional fields omitted
               ‖ F(0x7f, prev_hash[32])
hash         = blake3("vigil.audit.v1.record\0" ‖ fields)
```

- Strings are their UTF-8 bytes as written, with no normalisation.
- Integers (`0x02`, `0x03`, `0x20`) are u64 big-endian, 8 bytes.
- Digests (`0x07`, `0x15`, `0x17`, `0x21`), keys (`0x23`) and hashes are raw bytes: 32 each, signatures 64 bytes. `0x22` is the concatenated 32-byte peaks, left to right, and is omitted when `mmr_size` is 0.
- `audit.hash` and every digest attribute are spelled `blake3:<64 lowercase hex>`, tessera's spelling.
- A record hash is plain blake3 over bytes that begin with the domain string, so it really is "blake3 of something". tessera-core can therefore use it directly as an MMR leaf digest.

### 5. Hash chain

- `prev_hash` of `seq 0` is `blake3("vigil.audit.v1.genesis\0" ‖ trail)`. `prev_hash` of `seq n` is the `hash` of `seq n−1`, except for the opening checkpoint of a resume gap, whose `prev_hash` is the hash of the last record before the gap (below, amended by #70). No separate genesis record exists.
- **The chain has no key.** Against accidental damage (bit rot, a bad copy, a buggy tool), the chain alone detects editing any hashed field, deleting, inserting or reordering records (a `seq` gap, a duplicate or a broken link), splicing from another trail (`trail` mismatch) and losing the head (`seq 0` must link to the genesis value).
- **Against an attacker who can write the files but cannot use a trusted key**, only signed checkpoints protect, and only what they cover:
  - every record at or before the last checkpoint signed by a trusted key cannot be edited, removed, inserted or reordered without a finding;
  - the records after it can be rewritten freely, because the attacker can recompute every hash;
  - the attacker can also **roll the trail back** to any earlier checkpoint, deleting the later checkpoints, segments and live file. What remains is a valid trail that ends at that checkpoint and has no uncovered tail, so the loss is not bounded by the checkpoint cadence.
- **What detects a rollback or a rewritten tail**, and when:
  - **A running writer** never moves its head back. It refuses (`CorruptTrail`) to extend a trail whose head is behind its own cached head, or whose record at its cached `seq` has a different hash (decision 8, "Writer state"). So a rollback or a tail rewrite while any writer is running stops all writes. It is not signed over.
  - **A restarted writer** has no memory of the old head. It detects a rollback or rewrite only when it is given the head the application last saw: `AuditConfig::expect_head(seq, hash)`, taken from the highest `Receipt` the application has stored. `open` then fails with `HeadMismatch` unless the trail holds that `seq` with that hash, linked by an unbroken chain to the head on disk.
    - **What it proves.** Only that this one record is still there, unchanged, and that the history up to it has not been rewritten. Records after it can still be rewritten or rolled back, for example records acknowledged to processes whose receipts the application has not consolidated. So the application passes the highest receipt it holds across all its processes.
    - **Archived heads.** If the expected `seq` lies in a sealed segment that has been archived away, `open` cannot check it and fails with `HeadMismatch` rather than skip the check. The application's newest receipt is normally in the live file or a recent segment.
  - **Structural loss** is refused rather than repaired: a missing or empty live file, or a live file without its opening checkpoint (decision 8, "Crash recovery and structural loss"). Continuing then needs an operator decision (`vigil-audit resume`), and that decision is itself recorded in the trail.
  - **The verifier** detects a rollback through anchors (decision 10: a missing anchored checkpoint is `AnchorMismatch`) and through receipts the application compares against the report.
  - **`--max-age`** reports `StaleHead` when the newest trusted checkpoint is older than the given age. It detects a stopped writer, or a rollback after which **no** checkpoint was signed again. It does **not** detect a rollback once any writer has signed a fresh checkpoint on the shortened trail: for example, a writer restarted without `expect_head` on a live file truncated at a record boundary, or with a sealed segment renamed back to `audit.jsonl`.
- **Resume gaps** (amended, #70). `resume` never writes a `seq` twice: it continues above the highest `seq` the deployment holds evidence of (decision 8), so the chain jumps once over the `seq`s of the lost records, where the operator declared the loss. A jump from the record at `seq h` to a record at `seq k > h+1` is a **resume gap** only if all of these hold, and `SeqGap` (an error) otherwise:
  1. the record at `k` is a checkpoint whose `prev_hash` is the hash of the record at `h`. (In vigil's own files it is also the first record of its file, by construction through the staging file, but the gap rule does not require it: a shipped copy has no file boundaries and must verify the same, review probe. A gap forged inside a file gains nothing: it needs a trusted signature, and is unconfirmed without the resume's receipt or `accept` line);
  2. its `audit.mmr_size` is the number of records before it in the trail (decision 8; each `seq` counts once, so a duplicated line, `DuplicateRecord`, changes nothing), so the MMR, which counts records, has no hole;
  3. the record at `k+1` is a `vigil.audit.resume` record whose `audit.details` name exactly that head and `lost_through` = `k−1`, in the fixed form `resume` writes (decision 8).

  The opening checkpoint's signature is checked like any other (`BadSignature`, `UntrustedKey`). The `seq`s from `h+1` to `k−1` are the gap. A gap is **confirmed** when its resume record is pinned from outside the trail directory: a matching receipt (`--receipts`), or a matching `accept Resumed` line (`--reviewed`, decision 11). Only a confirmed gap demotes the inputs inside it (receipts, below); **a signature alone never demotes anything**, as for `start_from` (decision 11). **Anchors and `through=` pins inside a gap need more** (amended in review): they are set aside only when the gap's opening checkpoint is itself **anchored** (an anchor with its trail, `seq` and hash is given), exactly as an anchor below a start needs an anchored start. A receipt or an `accept` line is a text line, not an anchor, and must never override one: otherwise a stolen key could cut back over anchored checkpoints, sign a gap, and with one `accept Resumed` line turn every `AnchorMismatch` into info. For an honest operator it costs one step: anchor the opening checkpoint `resume` wrote, like any checkpoint (decision 10). An input below a start follows the start rule first. Probe: a signed jump without the resume record, or with details that name another jump, is `SeqGap`.
- **A checkpoint attests the trail as its signer found it, not who wrote each record.** A writer that finds records appended since its last read only checks that they link ("Same file, longer", decision 8). Its next checkpoint signs them, so anyone who can write the files can append correctly chained records that an honest key then covers. vigil cannot tell such records from those of another honest writer process. A deployment closes this in three ways:
  - **OS access control:** only the service account may write the audit directory. That is the first line, and outside vigil.
  - **Receipt reconciliation:** the verifier takes the application's receipts (`Verifier::receipts`, `--receipts <file>`, one `seq` and hash per line) and reports every record in the checked range that has no receipt as `NoReceipt`, and every receipt that does not match as `ReceiptMismatch`. Both are errors. **The checked range** (amended, #66):
    - **It runs from the start of what is verified to the head:** from `seq 0`, or from the start checkpoint (decision 11), through the last record in the files. It is **not** bounded by the receipts. Every record of kind `audit.record` in it that has no receipt is `NoReceipt`; checkpoints need none. Records after the last receipt are therefore reported, including those an honest `close()` signed (probe: the accepted rule "first to last receipt" passed `--strict` with two forged records after the last receipt; this rule reports both). So are records before the first receipt, for example ones appended right after `create`.
    - **Every receipt must match.** A receipt whose `seq` is not in the files, or whose hash differs, is `ReceiptMismatch`. A receipt above the head is how reconciliation sees a rollback. Receipts may include checkpoints, such as those `close()` and `checkpoint()` return (decision 9); they are checked like any receipt.
    - **Operator records need receipts too.** `vigil-audit rotate` and `resume` print a receipt line (`<seq> <blake3:hex>`) for the record they write, and the operator adds it to the receipts. `AuditConfig::resume` returns the `Receipt` with the trail. No action name is exempt, so a forged `vigil.audit.*` record is `NoReceipt` like any other.
    - **Waivers, for an honest crash.** A writer killed after its fsync but before the application stored the receipt leaves a durable record with no receipt. It looks exactly like a forged append, so vigil cannot decide; an operator does. The receipts input accepts `waive <seq> <blake3:hex> <reason>` (`Verifier::waive(seq, hash, reason)`), **one record per line**. The hash pins the record, so a waiver cannot be moved to another one: if the record at `<seq>` differs, it is `ReceiptMismatch`. Each waiver is reported as `ReceiptWaived` (info, naming the record and the reason), and the record is not `NoReceipt`.
      - **The review criterion**, written into the rustdoc and the README, because the attacker of threat model (a) can also kill a writer. It requires a **durable request log**: the application writes each entry to its own log and **fsyncs it before calling `record`**, and marks it done once the receipt is stored. Then a crash, including a power loss that stops every writer process at once, can orphan only entries that are logged and not marked done, across all processes, and at most one record each. A record may be waived only if its **full hashed content** (actor, action, object, reason, before and after values or digests, details) equals such an entry, no other waiver uses that entry, and its time lies between that log entry and the crash. Any other unreceipted record (more of them than open entries, or content that differs in any field) is tampering, not a crash. Matching on actor, action and object alone would let an attacker who kills a writer during a call append that call's record with a forged reason or value. vigil cannot apply this criterion itself, since it does not see the application's log.
    - **Late adoption.** A deployment that started storing receipts after the trail began gives one `from <seq> <blake3:hex> <reason>` line (`Verifier::receipts_from(seq, hash, reason)`): records up to and including that one are not reconciled. Its hash pins that history as it was when the decision was taken; a mismatch is `ReceiptMismatch`. It is reported once as `ReceiptWaived` (info).
    - **Receipts lost with a `resume`** (amended, #70). The `seq`s of records lost before a `resume` are never written again: they form the resume gap (above). A receipt whose `seq` lies inside a **confirmed** gap is **`LostRecord`** (info, naming the receipt and the resume record): the record it acknowledged was lost, and an operator decision pinned from outside the trail directory says so. Inside an unconfirmed gap it is `ReceiptMismatch`, like any receipt for a `seq` the files do not hold. The same holds for waivers, the `from` line and `accept` lines that name a `seq` inside a gap (decision 11). **Anchors and revocation pins** inside a gap are `LostRecord` only when, in addition, the gap's opening checkpoint is anchored (above); otherwise they keep `AnchorMismatch` and `RevocationMismatch`, errors, even in a confirmed gap. **A `LostRecord` input keeps every effect that does not need its record:** a `from` line inside a gap still exempts every record below its `seq` from reconciliation, and a `through=` bound inside a gap whose opening checkpoint is anchored still bounds the key (its *confirmed* and *bounded* checks use only records above it, decision 9); only the hash check, which needs the record, is replaced by the report. A receipt, waiver, anchor or `accept` line inside a gap has no other effect. The loss stays visible as the `Resumed` warning (decision 8), which names the gap and the number of `LostRecord` inputs, and `--strict` fails until a reviewer accepts it (decision 11). The application changes nothing in its store: it keeps the lost receipts and adds the resume's. This is structural loss after an operator incident, not an honest crash (threat model (c) never needs `resume`, decision 8). Probe: an honest resume with six receipted records lost gives six `LostRecord` and passes `--strict` once the resume is accepted. Under the withdrawn `lost`-line draft, which reused the `seq`s, the receipts of new records rolled back after the resume sat next to the lost ones, and an operator could not tell them apart (#70's M1): plain verification passed. Here the new records sit above the gap, so the same rollback is `ReceiptMismatch`.
    - **Live trails.** On a running trail, some records are in flight: `record` has returned `Ok` but the receipt is not stored yet, or not exported yet. They can sit **below** the highest receipt when another process or thread stored a later one first. By default the verifier treats the trail as stopped and reports every record without a receipt as `NoReceipt`. With `--receipts-live` (`Verifier::receipts_live(true)`), the range ends at the **longest fully reconciled prefix**: just before the first record without a receipt or waiver, and never above the highest receipt. Everything above it is reported once as `Unreconciled` (info, naming where it starts). With no receipts at all, the whole range is `Unreconciled`. `--strict` fails on `Unreconciled`, as on `UncoveredTail`.
      - An honest hole closes once its receipt is stored. A forged record is a hole that never closes: `Unreconciled` keeps starting at the same `seq` across reviews, and stopped-trail reconciliation reports it as `NoReceipt` (probe).
      - The export must be taken **before** the trail is read, so that every honest receipt is in the files and a receipt above the head still means a rollback. Receipts above the cut are still checked against their records.
      - The rotation procedure (decision 9) and any review of a stopped trail never use `--receipts-live`.
  - **Anchors** ([#57](https://github.com/vig-os/vigil/issues/57), decision 10), which bound what a later checkpoint may claim.
- **What cannot be detected without something kept outside the trail directory.** An attacker who can write the files can roll back or rewrite the uncovered tail, or roll back to any checkpoint. If afterwards a writer starts without `expect_head` and signs, the result is a consistent trail that verifies clean. Only anchors ([#57](https://github.com/vig-os/vigil/issues/57) and decision 10), receipts held by the application, or `expect_head` reveal it. The rustdoc of `AuditConfig::open` says so and recommends `expect_head` for regulated deployments.
- **Against an attacker who holds a trusted key,** only anchors, receipts and `expect_head` help (decision 9).
- **A torn write is not tampering, and nothing else is.** A killed writer can leave an unterminated fragment (ADR-0002 decision 6), and its `record` call never returned `Ok`. A torn fragment is always a strict byte prefix of a valid line (decision 6 states the storage requirement this rests on). A line is a **fragment** only if all of these hold:
  1. it is the last line of its file, or the next writer's repair newline ends it (ADR-0002 decision 6);
  2. it fails to parse in the way only a prefix can: after dropping at most 3 trailing bytes of a cut UTF-8 sequence, it is valid UTF-8, and the JSON parser stops with an end-of-input error (`serde_json::error::Category::Eof`);
  3. if a complete record follows, that record links to the last complete record before the fragment.

  Any other line that does not parse, or that parses but is not a valid v1 record, is an error (`Unparsable`, `InvalidField`, …), including a complete line in the middle of a file. Probe: every UTF-8 prefix of a 1 271-byte record line (1 266 of them; 4 more cut a multibyte character) is `Category::Eof`.

  **Repairs are attested** (amended, #68). A repair newline alone looks like any other newline. Under the core rule, anyone who can write the files could therefore insert end-of-input fragments between linked records and get only warnings, while an honest crash's fragment stayed a warning that failed `--strict` for good, because vigil never rewrites a file. So the writer records what it repaired:
  - **The gap** before a line is every byte between the end of the previous complete line in the same file (after its newline) and the first byte of that line: the fragments and their repair newlines.
  - A writer that finds a non-empty gap at the end of the live file (decision 8, "Writer state") sets `audit.repaired` on the first line it writes after it. The value is **one** BLAKE3 hash, `D = blake3("vigil.audit.v1.repaired\0" ‖ gap)` (32 bytes), where the gap includes the repair newline the writer writes itself; the attribute is spelled `blake3:<64 lowercase hex of D>`, and decision 4 encodes it as `F(0x07, D)`, the 32 raw bytes. Nothing hashes `D` again; `blake3:` is only the spelling, as for every digest in this ADR. No other line carries the attribute. The line may be a record or a checkpoint (the closing checkpoint of sealing step 3, or the one `close` writes). Several crashes in a row leave one gap, attested once (probe).
  - The writer applies the same check when it reads (decision 8): a gap before a line that does not attest it, or an attestation that does not match a non-empty gap, is `CorruptTrail`. A line with an attestation and no gap before it is accepted, as the verifier accepts it (below).
  - **A complete line without its newline is a record, not a fragment.** A writer killed after writing every byte of the line but the newline leaves valid JSON: the next writer's repair newline terminates it, there is no gap to attest, and the record is a crash orphan for the receipts (`NoReceipt` until waived, decision 5; review probe).

  The verifier reports **each gap once**:
  - **`TornWriteRepaired`** (info, naming the file, the lines, the byte length and the attesting `seq`): a line follows in the same file, its `audit.repaired` matches the gap, and that line is covered by a checkpoint signed with a trusted key, or pinned by a matching `end=` (decision 9). This is the honest crash after the next write: `--strict` passes (probe: 8 writer processes with three SIGKILLed mid-write, 20 runs).
  - **`TornWrite`** (a warning) while the attesting line is not yet covered. The next trusted checkpoint turns it into `TornWriteRepaired`.
  - **`RepairMismatch`** (an error): a line follows that does not attest the gap (no `audit.repaired`, or another digest). An honest writer always attests the gap it writes after, so the fragment was inserted or changed later (probe: both cases).
  - **`TornWrite`** (a warning) for a **trailing** gap, with no line after it in its file. Its detail carries the digest above, computed over the bytes up to the end of the file, for an `accept` line (decision 11). The next write to the live file attests it, so on a stopped trail, opening it and calling `close` once clears it. Where no write can follow (a retired trail on WORM storage, a file sealed by `resume`), only an `accept` line does. A trailing gap after the closing checkpoint of a segment sealed by rotation is also a `TornWrite`, but no crash produces it (sealing step 3 attests any earlier fragment, and nothing writes to a sealed file afterwards); the verifier marks the finding "no crash outcome" when the next file in the verified set starts with an opening checkpoint at the next `seq` that is not followed by a `vigil.audit.resume` record (a file `resume` sealed with nothing lost has the same adjacency, but its successor's second record is the resume record), and **an `accept` line naming a marked finding is `AcceptMismatch`**, an error (amended in review; the verifier enforces it, not only the review criteria). An archive verified alone, without the file after it, cannot set the mark: its trailing gap is an unmarked `TornWrite`, and the review criteria still forbid accepting it there. Verifying the archive together with the next file (decision 11) sets the mark again. Making it an error would need the verifier to know which files `resume` sealed, by file name, which copies and archives do not keep (review probe, round 3).
  - A line with `audit.repaired` but no gap before it is `TornWriteRepaired` with the detail "fragment not present". Shipped copies never contain fragments, because the Collector drops lines it cannot parse, and removing a fragment from vigil's own files removes no hashed content.

  The verifier reports each fragment with file, line and byte length, never its text: no JSON parser accepts a fragment as a record (condition 2), but its bytes can still be readable text (`cat` shows a fragment such as `{"resourceLogs":[…"user:mallory"`). It never presents a fragment as a record. An empty line, or one of only whitespace, also stops the parser at end of input. A torn write cannot produce one, because ADR-0002's repair writes one newline before the next record and vigil never writes whitespace, so such a line is `Unparsable`, an error. `--strict` turns every warning that no `accept` line has accepted into a failure, and it is the mode for regulated review. The rustdoc of `vigil-audit verify` and the README say so.
- **Duplicate JSON keys are rejected at every object level** (`InvalidField`), compared **after** unescaping, so `"stringValue"` and `"string\u0056alue"` are the same key. `serde_json::Value` silently keeps the last of two equal keys (probe: a line with `"stringValue":"user:jdoe","stringValue":"mallory"` parses, and other parsers such as Python's `json.loads` also keep the last). So vigil parses with a duplicate-rejecting deserializer, and its hash never covers a different value from the one another tool shows.
- **The writer applies exactly the verifier's rules** when it rebuilds its state (decision 8). So a crash never makes the writer refuse a trail the verifier accepts, and the writer never accepts a line the verifier rejects.

### 6. The lossless sink: fsync per record, fail-closed, no queue

`AuditTrail::record(&self, &Entry) -> Result<Receipt, AuditError>` does the following, all under the audit directory's lock:

1. Brings its cached chain state up to date (decision 8, "Writer state").
2. Checks that the entry is valid and that the encoded line is at most 1 000 000 bytes, the bound of ADR-0001 decision 10. An oversized entry is `AuditErrorKind::TooLarge`. Audit lines are **never truncated**, because truncation would change hashed content; use digests for large values.
3. Rotates if the line does not fit (decision 8).
4. Writes the record line, followed by a checkpoint line when one is due, with **one `write(2)`**.
5. Calls **`File::sync_data`**: `fdatasync` on Linux, `F_FULLFSYNC` on macOS (probe).
6. Returns `Ok(Receipt)` only after the fsync has returned.

- **Directory fsync.** When the live file is created (first write or rotation), the directory descriptor is fsynced before any record in that file is acknowledged, so the file name is durable as well. #11's tests on the macOS lane ([#46](https://github.com/vig-os/vigil/issues/46)) must show this works on APFS.
- **Assumption: the storage stack honours flushes.** "Durable after `Ok`" holds only if the disk, its controller and any hypervisor pass a flush through to stable storage. A volatile write cache without power-loss protection, or a VM disk in a mode that ignores flushes (for example QEMU `cache=unsafe`), voids the promise without any error vigil could see. The rustdoc and the README state this as a deployment requirement.
- **Assumption: a crash never exposes bytes that were not written** (amended, #68). Decision 5 recognises an honest torn write because it is a byte prefix of the line (or nothing). That needs a filesystem that, after a crash, never shows an appended range filled with stale or zero bytes. **This ADR claims no more than the evidence shows:**
  - ext4 in `data=writeback` mode is documented to break it: "a crash+recovery can cause incorrect data to appear in files which were written shortly before the crash", and it "can potentially leave stale data exposed in recently written files" (`Documentation/admin-guide/ext4.rst`). The unacknowledged append of a killed writer is exactly such a recent, unsynced write.
  - ext4's default `data=ordered` mode is documented to write data before the metadata that the journal commits ("all data are forced directly out to the main file system prior to its metadata being committed to the journal"). That is a statement about ordering. It is not a documented guarantee against zero-filled ranges after delayed allocation, and no vigil test has shown the prefix property there yet.
  - XFS, btrfs, ZFS and APFS document no guarantee this ADR could cite. Network filesystems are already excluded (decision 2).

  **Supported filesystems for regulated use are ext4 in its default mode (Linux) and APFS (macOS), each once a crash test shows the prefix property on it.** For ext4, that is #11's crash-injection tests on the Linux lane, plus a power-loss test (a VM disk cut off while a writer appends, with flushes honoured). For APFS, the same tests on the macOS lane, which this amendment adds to [#46](https://github.com/vig-os/vigil/issues/46)'s scope. Any other filesystem is unsupported until such a test passes on it. The rustdoc and the README list the supported filesystems next to the flush requirement and name ext4 `data=writeback` as unsupported.

  On a filesystem that breaks the assumption, a crash leaves an `Unparsable` line. The writer refuses with `CorruptTrail` (fail closed, decision 8), and verification reports an error for good, because no error can be accepted (decision 11). The only way to continue is `resume`, which seals the file as it is, error included.
- **A failed fsync poisons the handle.** After a failed fsync, Linux may have dropped the dirty pages and cleared the error ("fsyncgate", PostgreSQL 2018), so a retry could report success for data that is gone. vigil truncates back to the pre-write length (best effort) and returns `AuditErrorKind::Io`. Every later `record` on that handle fails with `AuditErrorKind::Poisoned`. Reopening rebuilds the state from what is actually on disk.
  - **If the truncate also fails,** the unacknowledged record stays visible, and other processes would chain onto bytes the kernel may later drop. The writer then creates `audit.poison` in the directory (holding the error text, `0600`) before releasing the lock. Every writer checks for that file under the lock, and `open` and `record` fail with `AuditErrorKind::Poisoned` while it exists. An operator removes it after `vigil-audit verify` has passed. If even that file cannot be created, the filesystem is failing and the other writers' own fsyncs fail too.
- **Backpressure, unlike telemetry.** Telemetry queues, batches and drops when full (ADR-0004 decision 3 counts the loss). Audit does none of that:
  - no queue, no batching across calls, no sampling and no drop;
  - no timeout: an expired timeout would not tell whether the record was written;
  - `record` blocks on the lock and the fsync.
- **Throughput.** The probe gives about 30 records/s per trail on vm-dev's ext4 and effectively unbounded throughput on tmpfs, which offers no durability. That fits operator actions at human rate, the purpose of this module. Bulk event streams belong in logs. Group commit and an atomic batch API keep `Ok`'s meaning and the format, and are deferred to [#56](https://github.com/vig-os/vigil/issues/56) as a post-1.0 minor.
- **Signer failure does not fail the record.** If a checkpoint is due and the signer fails:
  - the record is still written, chained and acknowledged;
  - the checkpoint is retried on the next append;
  - the failure is reported once on stderr, counted in `Receipt::unsigned_records()`, and returned as an error by an explicit `AuditTrail::checkpoint()`;
  - rotation waits for a successful checkpoint, so a segment can grow past `max_bytes` while the signer is down.

  A signer outage would otherwise stop every audited action.
- **Mirror into logs** (optional, `AuditConfig::mirror_to_logs(true)`, off by default). After the durable write, vigil emits a `tracing` event (target `vigil::audit`, INFO) with action, object, seq and hash, but never before or after values. It is observability only: filters may drop it, and it is not part of the trail.

### 7. One MMR over the whole trail, built the way tessera-core builds it

- **Leaves.** Every record is a leaf, checkpoints included, in `seq` order. The leaf for a record is `blake3(0x00 ‖ "blake3:<hex of its hash>")`. A record's leaf index is the number of records before it, which equals its `seq` unless a resume gap lies before it (decision 5, amended by #70): the MMR has no leaf for a lost `seq`.
- **Construction.** Interior nodes are `blake3(0x01 ‖ left ‖ right)`. Peaks are merged on the binary carry. The root bags the peaks right to left with the node hash; the empty root is `blake3("")`. This is tessera-core's construction (`hash.rs`, ADR-0028/0049, `f08255d`), and the probe shows they are equal.
- **Peak heights are not stored.** They are the set bits of `mmr_size`, left to right.
- **Why both a chain and an MMR.** The chain gives a sequential check and pinpoints the first broken link. The MMR gives an O(log n) inclusion proof for one record and a consistency proof between two checkpoints, without shipping the trail. An anchor holder that keeps only checkpoints needs exactly that.
- **One MMR over the whole trail, not one per segment.** It costs the same, because checkpoints carry the peaks. It also gives consistency proofs across segment boundaries, and one root commits to the entire history.
- **No write-path cost.** The MMR is advanced only when a checkpoint is built, from the leaves since the previous checkpoint. The probe puts a push at 0.34 µs.
- **Proof sizes.** An inclusion proof is O(log n) hashes. A consistency proof in tessera-compatible form is the old peaks plus every leaf appended since (`ConsistencyProof { old_peaks, appended }`), so its size grows with the gap: about 32 bytes per record between the two checkpoints. A minimal RFC 6962-style proof is O(log n), but tessera-core does not verify that form. [#57](https://github.com/vig-os/vigil/issues/57) decides which form the anchor-holder API exposes.

### 8. Signed checkpoints, cadence and segment sealing

- **What a checkpoint is.** A record of kind `audit.checkpoint` at `seq k`. It commits to the chain head (`prev_hash` = hash of the record before it) and to the MMR over the leaves of every record before it: `audit.mmr_size` = the number of those records (distinct `seq`s, so a redelivered duplicate line does not count), `audit.mmr_root`, and `audit.mmr_peaks`, an array of `blake3:<hex>` strings that is absent when `mmr_size` is 0. `mmr_size` equals `k` unless a resume gap lies before the checkpoint (amended, #70); the verifier recomputes it either way. It also carries `audit.key_id` (the 64-hex Ed25519 public key) and `audit.sig` (128 hex).
- **What is signed.** `sig` is Ed25519 (RFC 8032, pure, not prehashed) over `"vigil.audit.v1.checkpoint\0" ‖ blake3(fields without 0x24)`. That is a fixed 58-byte message, convenient for devices that sign short messages. The checkpoint's own record hash covers `sig` as well, so the chain covers the signature. Verification uses ed25519-dalek's `verify_strict`, which rejects non-canonical and small-order encodings. That choice is part of v1.
- **When one is written:**
  - (a) after a record, when `checkpoint_every` records (default 1 000) have been written since the last checkpoint;
  - (b) after a record, when `checkpoint_interval` (default 60 s) has passed since the last checkpoint;
  - (c) at rotation;
  - (d) on `AuditTrail::checkpoint()` and `close()`. `Drop` also tries, best effort.

  (a) and (b) are evaluated at append time: no background thread. A due checkpoint is written in the same `write(2)` and fsync as the record, so it costs no extra fsync.
- **What is never signed.** The records after the last checkpoint: at most `checkpoint_every`, or those since the interval elapsed, or more while a signer is down. They are chained but not signed, and the verifier reports them as `UncoveredTail` (decision 11).
- **Segment sealing.** When a record would not fit, the writer does the following under the lock. At every step, the live path either names a complete live file or is missing while a complete staging file exists:
  1. signs the **closing checkpoint** (`seq k`) and the **opening checkpoint** (`seq k+1`, which covers the closing one). If the signer fails, rotation is abandoned: nothing is written, the record goes into the current live file (which grows past `max_bytes`), and rotation is retried on the next append (decision 6);
  2. creates `.audit-next.jsonl`, writes the opening checkpoint into it, fsyncs it, and fsyncs the directory, so the staging file's name is durable before step 3 changes the live file. Otherwise a power loss after step 4 could leave neither file under its name on a filesystem that does not order metadata. A staging file left over from a crash has already been settled by the check below: promoted or discarded;
  3. appends the closing checkpoint to the live file and fsyncs;
  4. renames the live file to its segment name, no-replace;
  5. renames `.audit-next.jsonl` to `audit.jsonl`, no-replace;
  6. fsyncs the directory;
  7. writes the record into the new live file.

  The staging file is written before any rename, so the trail never has an empty or headless live file. Sealed segments may exceed `max_bytes` by the closing checkpoint, a few KB (its peaks list grows with the logarithm of the trail size). The closing checkpoint makes a sealed segment verifiable on its own, given the closing checkpoint of the segment before it. The opening checkpoint makes the live file self-sufficient for writers, so sealed segments can be archived away.
- **Every segment starts with a checkpoint.** The first segment starts with the creation checkpoint at `seq 0`; every later one starts with an opening checkpoint. Nothing may come before it, not even a torn fragment, because both are written through the staging file and fsynced before the rename. The verifier reports a segment that breaks this as `SegmentStructure`.
- **Creating a trail is explicit.** `AuditConfig::create(signer)` (or `vigil-audit create --key <keyfile> --service <name> <dir>`) creates a new trail:
  1. It draws the **trail id**: 16 bytes from `getrandom`, never derived from anything in the directory, the key or the clock. So a trail re-created after deletion always has a new id, even with the same key.
  2. It writes the marker file `audit.trail` (`0400`, holding the id) and fsyncs it and the directory.
  3. It writes the creation checkpoint at `seq 0` (`mmr_size` 0, `prev_hash` = the genesis value) through the staging file, as in sealing steps 2, 5 and 6.
  4. It returns the id (`AuditTrail::trail()`; the CLI prints it). The operator **pins** the id in the verifier's trust file, which is kept outside the trail directory (decision 9).

  `create` fails with `AuditErrorKind::TrailExists` if the marker or any audit file exists. `AuditConfig::open(signer)` never creates a trail: with no marker it fails with `AuditErrorKind::MissingTrail`. So a deleted or emptied directory stops the application (fail closed, decision 1) instead of starting a fresh trail. A re-created trail has an id that the trust file does not pin, so it fails verification (`TrailMismatch`) until an operator pins the new id on purpose.
- **`open` writes and signs nothing.** It rebuilds the state, completes an interrupted sealing (below, which writes no new bytes), and checks `expect_head`. The first byte it writes comes from the first `record`, `checkpoint` or `close`.
- **Every writer settles the staging file first.** Under the lock, before anything else and before every `record`, `checkpoint` or `close` (not only at `open`), a writer checks for `.audit-next.jsonl`, then for `.audit-resume.jsonl` (amended, #70). That costs two `fstatat`s. If one exists, it is the remains of a sealing, `create` or `resume` that crashed in another process. It is settled before any append:
  - **Promote** it when it is complete (not torn, by decision 5's rule, and ending with a newline) and its first and only record is a checkpoint linking to the last complete record of the predecessor at the next `seq`: the predecessor's `seq` + 1, or `seq 0` after the genesis value (amended, #70; a staging file that fails this is discarded, review probe):
    - with a live file: the live file's last complete record, which is then the closing checkpoint. Sealing finishes with steps 4–6;
    - with the live path missing: the newest sealed segment's last record. Steps 5–6 run;
    - with the live path missing and no sealed segment but the marker present: the genesis value. This is an interrupted `create`, and steps 5–6 run.
  - **Discard** it (unlink, then fsync the directory) in every other case: torn, not linking, or at another `seq`. In particular, a crash after step 2 leaves a live file whose last record is still `k−1`, so the staging file's opening checkpoint `k+1` does not link, and it is discarded. A discarded staging file never was part of the trail: its checkpoint covered a closing checkpoint that was never written. The next sealing signs both again.
  - **`.audit-resume.jsonl`** (amended, #70), the staging file of `resume`, is promoted only when it is complete and holds exactly two records: an opening checkpoint linking to the predecessor (by the same three cases) at a `seq` above it, and a `vigil.audit.resume` record linked to it whose details name the predecessor as head and `lost_through` = the checkpoint's `seq` − 1 (a resume gap, decision 5, or none when nothing was lost). Promotion renames the live file, if present, to its next segment name (no-replace), renames the staging file to `audit.jsonl`, and fsyncs the directory. Any other content, including a lone opening checkpoint (a crash prefix of `resume`'s single write), is discarded: nothing in it was acknowledged, and the operator runs `resume` again (review probe: every byte prefix, with and without a gap).

  Settling writes no record and no signature. Then the checks below run.
- **Writer state across processes.** Each writer keeps the live file's descriptor open, as `RotatingFile` does, so its cached `(dev, ino)` cannot be confused with a reused inode. It also caches its **head**: the highest `(seq, hash)` it has written or read. Under the lock, it compares the open descriptor and its cached length with the live path:
  - **Same file and length:** the cache is current.
  - **Same file, longer:** it reads and checks the records appended since its cached offset. The first must link to the cached head.
  - **Same file, shorter:** something truncated the trail: `CorruptTrail`.
  - **Another file** (another process rotated): it reads the rest of its old file through the descriptor it still holds, from the cached offset up to the closing checkpoint. Then it reads the new live file, whose opening checkpoint must link to that closing checkpoint. The chain from the cached head to the new head is therefore read in full, never assumed.

  **The head never moves back.** If the trail's head on disk is below the cached head, or its record at the cached `seq` has a different hash, the result is `CorruptTrail` and the handle refuses to write. While reading, the writer recomputes hashes and links and applies decision 5's rules for torn writes, repair attestations, resume gaps and duplicate keys; any other break is also `CorruptTrail`. The writer does not check signatures; it may not hold the other writers' keys. So anyone who can write the files can also stage a fake crash state, for example a staging file with a forged checkpoint, and a writer will promote it. That gains nothing beyond the documented restart gap (decision 5): the forged checkpoint fails `BadSignature` in `verify`.
- **Crash recovery and structural loss** (at `open`, or when the cache is unusable):
  - **Crash recovery is limited to two cases:**
    - **A torn fragment at the end of the live file** (decision 5's rule). It stays in place; the next write's repair newline ends it, and that write's first line attests it (`audit.repaired`, amended by #68).
    - **An interrupted sealing or `create`,** settled by the staging-file rule above, which runs in every writer, running or newly opened.

    Neither case writes a new record or signature at recovery; the attestation rides on the next line the application or an operator causes.
  - **`create` before its staging file is complete.** A crash after the marker is written, but before the staging file is complete (create step 3), leaves the marker and at most a torn staging file. `open` reports `CorruptTrail` ("marker without a trail"), and `create` reports `TrailExists`. No record was ever acknowledged, so the operator removes the directory and runs `create` again, which draws a new id that must be pinned. The rustdoc of `create` says so.
  - **Everything else is structural loss, refused with `CorruptTrail`:**
    - a live path missing without a staging file that can be promoted;
    - an empty live file;
    - a live file whose first complete record is not a checkpoint that links to the newest sealed segment, or to the genesis value for the first segment;
    - a missing head while the marker exists;
    - a head that does not match `expect_head`, which is `HeadMismatch`.

    vigil never guesses which case is innocent.
  - **An operator decides** with `vigil-audit resume --key <keyfile> --actor <who> --reason <why> --head <seq>:<hash> --lost-through <seq> <dir>`. It continues the trail from the named head, which must be the last complete record found and is typically the last one verified against anchors or receipts. vigil never rewrites or prepends, so:
    - **A headless live file** (present, but its first complete record is no linking checkpoint), or a **well-formed live file whose head is behind what the deployment holds** (a rollback, seen as `HeadMismatch` or through receipts; amended, #70), is sealed as it is. It is renamed, unchanged, to the next segment name, no-replace, and keeps its `SegmentStructure` findings forever as the record of the damage.
    - **A new live file** is then written through the staging file (sealing steps 2, 5 and 6), starting with an opening checkpoint at `seq` `lost_through + 1` that links to the named head. It is followed by a record with action `vigil.audit.resume`: the operator as actor, the reason, and in `audit.details` the fixed form `head=<seq>:<blake3:hex> lost_through=<seq> file=<segment name the sealed live file received, or - when it was deleted>` (amended, #70), which the verifier reads (decision 5, "Resume gaps"). **Both lines go into `.audit-resume.jsonl` in one write and one fsync** (amended, #70), before the damaged live file is renamed, and `resume` holds the directory lock from before that write until after the final directory fsync, like every writer. A crash at any point leaves either a staging file holding both (promoted by the rule above, which then finishes the renames) or a prefix of it, which the rule discards, including a prefix that ends exactly after the opening checkpoint's newline. A crash can therefore never leave an opening checkpoint without its resume record, which the verifier would report as `SeqGap` when it jumps (review probe, every prefix). `file=` is informational: the verifier reads only `head=` and `lost_through=`. The command prints the resume record's receipt after the final directory fsync (amended, #66, decision 5).
    - **`seq` continues above `--lost-through`, never from a `seq` already used** (amended, #70). `--lost-through` is mandatory, at least the head's `seq`, and at most `u64::MAX − 2` so the two new `seq`s fit (else a usage error, exit 2; `InvalidConfig` from `AuditConfig::resume`). It is **the highest `seq` the deployment holds any evidence of outside the trail directory**: the receipts and close checkpoints of every process (the expected head of decision 9), anchors and revocation pins. The trail cannot know how many records the deleted file held, so the operator takes it from that evidence. Equal to the head's `seq`, nothing was lost that anyone holds, and there is no gap: the core behaviour. **Higher than needed costs nothing** but a wider gap, so an operator in doubt adds a margin (for example `checkpoint_every`). **Lower than a held `seq` fails closed:** that receipt or anchor names a `seq` the new records reuse, so it is `ReceiptMismatch` or `AnchorMismatch` for good, and, if it is the highest held receipt, `open` with `expect_head` is `HeadMismatch` (probe). Records lost without any evidence held (written but never receipted) leave no trace in the trail; the application's durable request log (decision 5) is where they show.
    - **The verifier reports every `vigil.audit.resume` record as `Resumed`,** a warning that names the operator, the reason, the head, the gap and the number of `LostRecord` inputs in it. So plain verify passes with the decision visible, and `--strict` fails until a reviewer has accepted it with an `accept Resumed` line (decision 11, amended by #68).
    - **`vigil.audit.` is a reserved action prefix** (amended, #70). The verifier gives `vigil.audit.resume` records a meaning (the gap declaration and `Resumed`), so an `Entry` whose action starts with `vigil.audit.` is rejected with `AuditErrorKind::InvalidEntry`, wherever entries are validated: an application record can never be read as an operator's decision. A forged record with such an action is still `NoReceipt` like any other (decision 5).

### 9. Key custody and rotation

- **A signer is required to create or open a trail.** There is no unsigned mode, so there is one state space to test.
- **`Signer`** is a public, unsealed trait:

  ```rust
  pub trait Signer: Send + Sync + fmt::Debug {
      fn public_key(&self) -> [u8; 32];
      fn sign(&self, message: &[u8]) -> Result<[u8; 64], SignerError>;
  }
  ```

  It returns pure Ed25519 signatures and uses only std types (ADR-0004 decision 1). An application can implement it over any device or remote signer. Because it is unsealed, a method added in 1.x must have a default implementation; a new required method is a major. The signer is called inside the locked section, so a slow signer slows down the writers of that trail. A checkpoint is due at most every `checkpoint_every` records.
- **`KeyFileSigner`** is vigil's one implementation in 1.0. It loads a file holding the 32-byte seed as 64 hex characters, with surrounding whitespace allowed. That is the format `tessera keygen` writes (`signing_key_from_hex`), so tools are interoperable. **Use separate keys for vigil and tessera.** The domain-separated messages already prevent a signature from crossing over. Separate keys also keep a compromise of one tool's key from forcing the other's revocation, and let each be revoked on its own schedule.
  - **Use the secret seed file, never the public key or `.pub` file.** Both a seed and a public key are 32 bytes encoded as 64 hex characters. The parser cannot distinguish them: supplying a public key as a seed silently derives a different signing key. Check the derived public key against the trusted `key_id` before use. The v1 raw-hex format permits no header or prefix to disambiguate; only surrounding whitespace is allowed. A format change needs a separate decision.
  - Like OpenSSH, it refuses a file with group or other permission bits, or one owned by another user.
  - `vigil-audit keygen <file>` writes the seed (`0600`, never overwriting) and `<file>.pub` with the public key. The seed comes from `getrandom`.
  - The seed is held in `ed25519_dalek::SigningKey`, which zeroizes it on drop.
- **What a local key protects against, and what it does not.** It protects against accidental corruption and against tampering by anyone who cannot read the key. It does not protect against an attacker who can read the key and write the trail: they can rewrite everything and sign it again. Against that, use (1) a key the application process cannot read, through a `Signer` over an off-device or hardware signer (reference backends deferred to [#58](https://github.com/vig-os/vigil/issues/58)), or (2) anchors (decision 10). The rustdoc of `AuditTrail` and the README say this.
- **Rotation.** Checkpoints name their `key_id`, the chain fixes the order of keys, and the trust file lists every key valid for the trail.
- **Revocation is a pinned, confirmed bound.** A trust entry may carry `through=<seq>:<blake3:hex>`, naming a checkpoint the operator has verified as good. The verifier then requires:
  - **pinned:** the record at that `seq` exists and has exactly that hash, else `RevocationMismatch`. This fixes the history up to the bound, so an attacker holding the old key cannot cut the trail back and forge it below the bound;
  - **confirmed:** the trail contains, at a `seq` above the bound, a checkpoint signed by a **different** key that is trusted **at that `seq`** (listed for the same trail, and not itself bounded below that `seq`), else `RevocationUnconfirmed`. This pins the post-revocation head with a key the attacker does not hold, so a trail cut back to the bound, or forged above it with the old key, fails;
  - **bounded:** a checkpoint signed by the old key above the bound is `UntrustedKey`.
- **The rotation procedure,** for any number of writer processes:
  1. **Stop every process writing the trail.** `close()` signs a last checkpoint with the old key, and no old-key writer may run after the bound: its checkpoints would be `UntrustedKey` for good.

     **The expected head** (amended, #66). `AuditTrail::close(self) -> Result<Checkpoint, AuditError>` always writes a checkpoint signed by the handle's signer and returns it. The application stores that checkpoint (its `line`) with its receipts, as it stores every `Receipt`. Closes are serialised by the directory lock, so after every writer has stopped, **the expected head is the highest `seq` among all receipts and close checkpoints the application holds, across all its processes**. **After a `resume` nothing changes** (amended, #70): every `seq` the resumed trail writes lies above `--lost-through`, which is at least every `seq` the application held (decision 8), so the highest held receipt is the resume record's (returned by `AuditConfig::resume` and printed by the CLI) or a later one, never a lost record's. The same rule therefore gives `expect_head` and the expected head of a resumed trail, and a resumed trail is rotated like any other (probe: `open` with `expect_head` from the highest held receipt succeeds after a resume; under the `seq` reuse of the core and the withdrawn draft it was `HeadMismatch`, #70's M2). Probe: 8 real processes appending under `File::lock`, 20 runs: the highest returned `seq` was always the disk head, and that head was a close checkpoint.

     `close` consumes the handle even when it fails (for example with kind `Signer`; it then writes nothing), so an application retries by opening the trail again and closing that handle.

     **A writer that returned no close checkpoint** (killed, dropped without `close`, or `close` failed because the signer was down) may have left records above everything held; `Drop`'s best-effort checkpoint is not returned either. Then start the application once more with `expect_head` from its highest held receipt or checkpoint, and stop it cleanly: that `close()` returns the head. Probe: a SIGKILLed writer left records above every held receipt, and one restarted writer's `close()` returned exactly the disk head.
  2. Verify the trail against the anchors and the receipts, including the close checkpoints, without `--receipts-live` (decision 5). A record that a `close()` signed but the application never wrote is `NoReceipt` here, before any new key covers it; a crash orphan is waived here after review. Choose the bound: the last checkpoint known good. After a clean stop, that is the expected head of step 1, the final `close()` checkpoint. After a suspected compromise, it is the last checkpoint that matches an anchor.
  3. Generate the new key (`vigil-audit keygen`) and deploy it to every writer, removing the old key file.
  4. In the trust file, add the new key and set `through=<seq>:<hash>` on the old one.
  5. Confirm with `vigil-audit rotate --key <new keyfile> --actor <who> --reason <why> --bound <seq>:<hash> --expect-head <seq>:<hash> <dir>`. `--expect-head` is **mandatory**. It must come from the application's newest receipt or from an anchor, never from the disk. `rotate` refuses (`HeadMismatch`) unless the trail's head on disk is **exactly** that record, so records an attacker appended between steps 2 and 5 are never covered by the new key. After a clean stop, `--expect-head` is the expected head of step 1, never a line read from the trail directory. `vigil-audit checkpoint`, the other command an operator signs with, takes the same mandatory `--expect-head` with the same exact-head rule. After passing the check, `rotate` writes two things signed by the new key: a record with action `vigil.audit.key_rotated` (actor, reason, and `audit.details` naming the old key and the bound), and a checkpoint. vigil never removes records, so nothing after the bound is cut.
  6. Start the writers with the new key.

  **The outcome depends on the branch.**
  - **After a clean stop** (the bound is the last old-key checkpoint), the trail verifies with no error.
  - **After a compromise,** every old-key checkpoint above the bound stays `UntrustedKey`, an error, for good. Those checkpoints are exactly the ones an auditor must look at, and the report shows them next to the `vigil.audit.key_rotated` record that acknowledges them. The records between the bound and the confirming checkpoint are covered by the new key, and the operator vouches for them in step 2.

  A key that was never trusted, or one removed from the file, makes its checkpoints `UntrustedKey`.
- **Trust file format** (for `TrustPolicy::from_file` and `--trust`). UTF-8 lines; blank lines and lines starting with `#` are ignored:
  - `trail <32 hex> [end=<seq>:<blake3:hex>] [comment]` starts a section and pins that trail id (decision 8). At least one is required. A trail id that starts two sections is a parse error (amended, #66).
  - **`end=` retires a trail** (amended, #66): the trail must end exactly at that record. **Its value comes from the application's last close checkpoint or receipt for that trail, or from an anchor, never from `vigil-audit checkpoints` or any other read of the trail directory**, for the same reason as `--expect-head` (decision 9): an attacker who can write the files chooses what the disk says. A different record at that `seq`, or any record above it, is `TrailEnded` (an error). A retired trail on WORM storage cannot be written to, so `rotate` cannot write a confirming checkpoint there. Instead, any bound at or below the `end=` record counts as confirmed: `end=` pins the exact head, so no record, by any key, may follow it. After a suspected compromise the bound is still the last anchored checkpoint (step 2), and the old key's checkpoints between it and `end=` are `UntrustedKey`, as in the compromise branch (probe).
    - **`end=` on a crashed tail.** The two pins are different things. `end=` pins the trail's last record, which may be any record (a retired trail whose last writer crashed ends with records after its last checkpoint). A key's `through=` bound is always a checkpoint, at or below `end=`. The records between the last checkpoint and `end=` are signed by no key, so the verifier still reports them as `UncoveredTail` (info), and an auditor sees that they are unsigned. A matching `end=` pins them through the chain, from a source outside the trail directory, as a receipt does, so **`--strict` does not fail on the uncovered tail of a trail whose `end=` matches**. Without `end=`, or with a mismatch (`TrailEnded`), `--strict` fails on it as usual.
  - `ed25519 <64 hex> [through=<seq>:<blake3:hex>] [comment]` lists a key trusted **for the trail of the section it is in**. A key line before the first `trail` line is a parse error.
  - **Revocation scope** (amended, #66). **A key revoked on one trail is revoked on every trail that lists it.** A trust file in which a key carries `through=` in one section and no `through=` in another is a parse error (`TrustPolicy::from_file`, and the builder's build step, fail with `AuditErrorKind::InvalidConfig`, naming the key and the sections). Otherwise a stolen key revoked only on trail X still forges trail Y, which then verifies clean (probe: `--strict` passed on Y; at most `NoReceipt` with receipts).
    - **Bounds do not combine across trails.** A `seq` means something only within its trail, so each section carries its own bound, a checkpoint of that trail, and its own confirmation (the *pinned*, *confirmed* and *bounded* rules above, per trail). Revoking a shared key therefore means running the rotation procedure on every trail that lists it that is still written to. A retired trail gets `end=` at its last record and the key's bound at the same record (probe).
    - **The check covers one trust file.** The verifier sees only the trust file it is given, so a key revoked in X's file and still trusted in a separate file for Y is not caught. **Every trail a key signs for belongs in one trust file**, which the rustdoc of `TrustPolicy` and the README require. A deployment that keeps one file per trail must use one key per trail.
    - **A key appears at most once per section.** A second line for the same key in one section is a parse error, so a bound can never be silently overridden by a later line.
    - **Keys that must be revoked independently must be different keys.** A shared key has one lifecycle across its trails; that is the cost of the rule, and the rustdoc of `TrustPolicy` says so.
  - `TrustPolicy::new()` with `.trail(id)`, which returns a section builder with `.key(public_key)`, `.key_through(public_key, seq, hash)` and `.end(seq, hash)`, builds the same in code, with the same checks at its build step.
- **Keep the trust file outside the trail directory,** for example in the verifier's configuration or a reviewed repository. The marker `audit.trail` lives in the writable directory, so it is never a trust input.

### 10. Anchoring (optional)

- **What an anchor is.** A checkpoint line copied to a place the attacker cannot rewrite: another host, WORM storage, a ticket, a mail.
- **vigil 1.0 provides:**
  - `AuditTrail::checkpoint()`, which returns the `Checkpoint` just written, with its line;
  - `vigil-audit checkpoints <dir>`, which prints the checkpoint lines;
  - `vigil-audit verify --anchor <file>`, which requires every anchored checkpoint to be in the trail with the same `trail`, `seq` and `hash`. A missing or different checkpoint is `AnchorMismatch`.
- **Where an anchor comes from** (amended, #66). An anchor is a checkpoint line taken from a source the attacker cannot have written: a `Checkpoint` that `checkpoint()` or `close()` returned in process; the checkpoint line that `vigil-audit checkpoint`, `rotate` or `resume` prints for the checkpoint it wrote (for `resume`, the opening checkpoint, which decision 5 needs anchored to set aside the anchors and pins inside its gap; amended, #70); or `vigil-audit checkpoints` run on a snapshot that has just verified clean. It is copied to a store outside the trail directory. Only such anchors carry the guarantees this ADR states.
  - **"Verified clean"** (amended in review, #68, #70) means exactly this: `vigil-audit verify --strict` over the snapshot, with every anchor and the receipts the deployment holds (and its review file), exits 0. That is, no error, no warning that an `accept` line has not accepted (in particular no outstanding `Resumed`), no uncovered tail and no `Unreconciled`. A trail whose `Resumed` warning is not yet accepted is **not** clean, even if its gap is confirmed by a receipt: no checkpoint read from it may be anchored until a reviewer has accepted the resume. The checkpoint line `resume` prints is the exception, because it comes from the operator's command, not from a read of the directory.
- **Shipped copies are not anchors.** Shipping and `push` (ADR-0006, [#41](https://github.com/vig-os/vigil/issues/41)) are best-effort: a full queue drops data (ADR-0006, probes S4 and Q). The file shipper also ingests whatever lines an attacker writes into the directory. A backend copy is useful evidence, but a missing line proves nothing, and a present line was not necessarily written by vigil. No rule in this ADR relies on it. An audit-grade anchor feed, delivered without loss from the in-process `Checkpoint`, is in scope for [#57](https://github.com/vig-os/vigil/issues/57).
- **What anchoring adds.** A trail rewritten and re-signed with a stolen key no longer matches the anchors.
- **Deferred to [#57](https://github.com/vig-os/vigil/issues/57):** RFC 3161 timestamp tokens, transparency-log submission, and a public consistency-proof API for anchor holders. They need ASN.1/DER and HTTP, and none of them changes the v1 encoding.

### 11. Verify API and CLI contract (#13)

- **Library:**
  - `vigil::audit::verify(dir: &Path, trust: &TrustPolicy) -> io::Result<Report>`;
  - `Verifier::new(trust)` with:
    - `.anchor(Checkpoint)`;
    - `.start_from(Checkpoint)`, for a trail whose older segments are archived: a checkpoint supplies `seq`, `prev_hash` and peaks. Amended, #66:
      - **Where it comes from:** the archive's own record (decision 2's procedure), never the trail directory.
      - **Accepted** when the first record in the files is a checkpoint at the start's `seq` with exactly the start's hash, signed by a key trusted for the trail at that `seq`. Otherwise `StartMismatch` (an error), and the verifier does not use it.
      - **A signature alone never demotes anything.** Below the start, nothing can be checked against records. An anchor, a revocation pin (`through=<seq>:<hash>`), a receipt, a waiver, a `from` line or an `accept` line (amended, #68) below the start is:
        - **`OutOfRange` (info)** if the start is **anchored**: an anchor with the same trail, `seq` and hash is given (`.anchor`, `--anchor`). The anchor is the operator's out-of-band statement that the history below was verified before it was archived (decision 2's procedure), so `--strict` passes and archiving never makes verification fail for good;
        - **`UnanchoredStart` (an error)** otherwise, one finding per input, naming it.

        Probe: with the accepted rule, an attacker holding a stolen, not yet revoked key cut the trail just above the newest anchor, signed a start there, rewrote and re-signed everything above it and moved the rest away; verify passed `--strict` with every anchor `OutOfRange`. With this rule it fails with `UnanchoredStart`.
      - **An unanchored start with nothing below it** is accepted by its signature alone. That is no weaker than verifying without archiving: against a stolen key, only anchors and receipts above the start help (decision 5).
      - **Without a start, a trail whose `seq 0` is missing** (the live directory verified alone after archiving) is `SeqGap` for the missing range, an error. The verifier continues from the first checkpoint's `seq`, `prev_hash` and peaks, so later findings are still reported.
      - **The revocation rules above the start still apply:** a *confirmed* and *bounded* check needs only records above the bound.
      - **The archive is verified on its own.** `vigil-audit verify <archive dir> <live dir>`, or `verify_files` over both sets, checks everything in one run, with no start. The operator verifies the archive once before moving it, keeps the start checkpoint line with it, and anchors that line (decision 2's procedure).
    - `.receipts(impl IntoIterator<Item = (u64, [u8; 32])>)`: reconcile records against the application's receipts (decision 5);
    - `.waive(seq, hash, reason)`, `.receipts_from(seq, hash, reason)` and `.receipts_live(bool)`: an operator's waiver for one record, late adoption, and live reconciliation (decision 5). As in the receipts file, a second `waive` for the same `seq`, or a second `receipts_from`, is rejected: both methods return `Result<Self, AuditError>`, with kind `InvalidConfig` on the duplicate;
    - `.accept(kind, seq, hash, reviewer, reason)` (amended, #68): a reviewer's acceptance of one warning, pinned by a hash (the review file below). It returns `Result<Self, AuditError>`, with kind `InvalidConfig` for a kind that is not an acceptable warning, an empty reviewer or reason, or a second acceptance of the same kind at the same `seq`;
    - `.trail(id)`: narrow to one pinned trail;
    - `.max_age(Duration)`: report `StaleHead` (an error) when the newest trusted checkpoint is older than this, measured against the verifier's clock (decision 5);
    - `.verify_dir(&Path)` and `.verify_files(impl IntoIterator<Item = PathBuf>)`, the latter for copies shipped through a Collector.
- **Errors versus findings.** `io::Error` is only for not being able to read. Tampering is never an `Err`: it is a `Finding` in the `Report`.
- **The trail is always pinned.** Every record whose `audit.trail` is not pinned in the `TrustPolicy` is `TrailMismatch` (an error). `--trail <id>` (`Verifier::trail`) only **narrows**: it selects one trail already pinned in the policy, and an id the policy does not pin is a usage error, never a new pin. Without a pinned trail there is nothing to verify against: the CLI exits 2, and a `TrustPolicy` without a `trail` section fails to build. Another trail signed by the same key, including one re-created after deletion, therefore never verifies as the expected one.
- **Report.** `Report` exposes:
  - `trail()`, `records()`, `last_seq()`;
  - `covered_through()`: the highest `seq` covered by a checkpoint signed with a trusted key;
  - `findings()`;
  - `is_valid()`: no finding of severity `Error`.
- **Finding.** `Finding` exposes `kind()`, `severity()`, `file()`, `line()`, `seq()` and `detail()`, the last naming expected and found values. `FindingKind` is `#[non_exhaustive]`:
  - errors: `Unparsable`, `UnknownVersion`, `UnknownField`, `MissingField`, `InvalidField`, `HashMismatch`, `ChainBroken`, `SeqGap`, `SeqConflict` (two different records with one `seq`), `TrailMismatch`, `MmrMismatch`, `BadSignature`, `UntrustedKey`, `RevocationMismatch`, `RevocationUnconfirmed`, `SegmentStructure`, `AnchorMismatch`, `StartMismatch`, `UnanchoredStart` (an input below a start that is not anchored, decision 11), `TrailEnded` (a record at or above a retired trail's `end=` that does not match it, decision 9), `StaleHead`, `NoReceipt`, `ReceiptMismatch`, `RepairMismatch` (a gap of fragments that the line after it does not attest, decision 5, amended by #68), `AcceptMismatch` (an `accept` line whose record is missing or has another hash, or an `accept TornWrite` line naming a gap the verifier marked "no crash outcome": bytes after a rotation-sealed segment's closing checkpoint, decision 5; amended by #68);
  - warnings: `TornWrite` (a trailing gap, or one whose attesting line no trusted checkpoint covers yet), `Resumed`, `ClockWentBackwards`, `DuplicateRecord` (the same record twice: a Collector can redeliver a line, and in vigil's own files a duplicated line changes no content);
  - info: `UncoveredTail`, `OutOfRange` (an input below an anchored start), `Unreconciled` (records above the reconciled prefix with `--receipts-live`), `ReceiptWaived` (an operator's waiver or `from` line, decision 5), `TornWriteRepaired` (an attested and covered gap, decision 5, amended by #68), `Accepted` (a warning a reviewer accepted, naming its kind, the reviewer and the reason, amended by #68), `AcceptUnused` (an `accept` line that matched no warning, amended by #68), `LostRecord` (an input naming a `seq` inside a confirmed resume gap, decision 5, amended by #70).
- **How it verifies.** Records are ordered by `seq`, from vigil's segment order or from any order in shipped copies. Every record is checked; nothing stops at the first error. The first error in `seq` order is the **first broken link**, reported with file, line, `seq`, expected and found hash.
- **Locking and offline use.** The verifier takes no lock and verifies a snapshot, using ADR-0002 decision 12's retry. Following ADR-0037 §1, it needs only the trail files, the trust file and local anchors: no network.
- **CLI** (`vigil-audit`, std-only argument parsing, `required-features = ["audit"]`):

  ```text
  vigil-audit verify --trust <file> [--trail <id>] [--receipts <file> [--receipts-live]] [--reviewed <file>] [--anchor <file>]... [--start-from <file>] [--max-age <duration>] [--strict] [--json] <dir|file>...
  vigil-audit checkpoints <dir>
  vigil-audit checkpoint --key <keyfile> --expect-head <seq>:<hash> <dir>
  vigil-audit rotate --key <keyfile> --actor <who> --reason <why> --bound <seq>:<hash> --expect-head <seq>:<hash> <dir>
  vigil-audit create --key <keyfile> --service <name> <dir>
  vigil-audit resume --key <keyfile> --actor <who> --reason <why> --head <seq>:<hash> --lost-through <seq> <dir>
  vigil-audit keygen <keyfile>
  ```

- **Receipts file** (`--receipts`, amended, #66). UTF-8 lines; blank lines and lines starting with `#` are ignored:
  - `<seq> <blake3:hex>`: a receipt, a record's or a checkpoint's (decision 5);
  - `waive <seq> <blake3:hex> <reason>`: an operator's waiver for one record (decision 5);
  - `from <seq> <blake3:hex> <reason>`: late adoption, at most once (decision 5);
  - in each, the reason is required and is the rest of the line;
  - any other line, two `waive` lines for one `seq`, or a second `from` line is a usage error (exit 2).

  **Two receipts with one `seq` and different hashes are not a usage error** (amended, #66): an application holds exactly that after a rollback followed by a restart without `expect_head`, which is its strongest evidence of the rollback. (A `resume` no longer produces them: it never reuses a `seq`, amended by #70.) Each receipt is checked on its own, so the one that does not match is `ReceiptMismatch`. `Verifier::receipts` accepts such duplicates the same way.

  Like the trust file, it is kept outside the trail directory. `rotate`, `resume` and `checkpoint` print what the operator adds to it: a receipt line for each record written, and the checkpoint line.
- **Review file** (`--reviewed`, `Verifier::accept`, amended, #68). It records a reviewer's acceptance of a warning that stays for good, so that `--strict` can pass after a recorded human review without weakening plain verification. UTF-8 lines; blank lines and lines starting with `#` are ignored:
  - `accept <kind> <seq> <blake3:hex> <reviewer> <reason>`, where `<reviewer>` is one token naming who reviewed and the reason is the rest of the line, both required;
  - **acceptable kinds are the warnings, and only them:** `TornWrite`, `Resumed`, `ClockWentBackwards`, `DuplicateRecord`. An error can never be accepted, an info finding needs no acceptance, and `UncoveredTail` and `Unreconciled` clear by themselves (the next checkpoint, a matching `end=`, a stored receipt). Any other kind, a missing field, an unknown line, or two lines for the same kind and `seq` is a usage error (exit 2).
  - **What pins each kind.** For `Resumed`, `ClockWentBackwards` and `DuplicateRecord`: the `seq` and hash of the record the warning names; each of these is reported once per `seq` (a line delivered three times is one `DuplicateRecord`), so one line accepts it. For `TornWrite`: the `seq` of the last complete record before the gap in its file, and the gap digest the finding reports (decision 5), so the line accepts exactly those bytes at exactly that place. Only a **trailing** `TornWrite` can be accepted; one whose attesting line is not yet covered clears with the next trusted checkpoint, like `UncoveredTail`, and a line naming it is `AcceptUnused`.
  - **One file per trail**, like the receipts file: a verification covers one pinned trail (`Report::trail`), and every `seq` in the file is that trail's.
  - **Outcomes.** A line that matches a reported warning replaces it with `Accepted` (info). A line whose `seq` holds no record, or a record with another hash, is `AcceptMismatch` (an error): the reviewed record was changed or rolled back, and the line is an outside pin like a receipt. A line that matches its record but no warning (for example a trailing fragment that a later write has since attested) is `AcceptUnused` (info). Like every input, a line below a start follows the start rule, and one inside a confirmed resume gap is `LostRecord`.
  - **An `accept Resumed` line also confirms that resume's gap** (decision 5), for deployments without receipts. It sets aside receipts, waivers, the `from` line and `accept` lines inside the gap, never anchors or `through=` pins, which need the gap's opening checkpoint anchored.
  - **An `accept TornWrite` line for a gap the verifier marked "no crash outcome"** (bytes after a rotation-sealed segment's closing checkpoint, decision 5) is `AcceptMismatch`, an error.
  - **Why a separate file.** Reconciliation is opt-in through `--receipts`, and a receipts file means the application's acknowledgements; a deployment without receipts still needs to accept a `Resumed` or a clock step. The trust file is configuration shared by every trail, changed when keys change; a review is a per-incident record. The review file is kept outside the trail directory, like the other two, and is the place a reviewer's sign-off lives (in a reviewed repository, for example).
  - **Review criteria**, written into the rustdoc and the README: a trailing `TornWrite` is accepted only where no write can attest it any more (a retired trail, a file sealed by `resume`; anywhere else, open the trail and `close` once), against the time of the crash, and **never** after the closing checkpoint of a segment sealed by rotation (the finding's detail says so), where no crash can leave one; `Resumed` against the incident report and the `LostRecord` list; `ClockWentBackwards` against the host's time-synchronisation log; `DuplicateRecord` in shipped copies against the Collector's redelivery, and in vigil's own files only after an investigation, since no vigil writer duplicates a line.
- **Exit codes.** `0`: no error findings. With `--strict`, also no warnings (an accepted warning is reported as `Accepted`, info, amended by #68), no uncovered tail and no `Unreconciled`. `1`: at least one error finding (or, with `--strict`, a warning, an uncovered tail or `Unreconciled`). `2`: usage or I/O error.
- **Text output.** The first line reads `OK trail <id>: <n> records, seq 0..<m>, signed through <k>` or `FAIL trail <id>: …`. Then one line per finding: `<file>:<line>: seq <s>: <kind>: <detail>`.
- **JSON output.** `--json` prints the report as one JSON object.
- **Stability.** Within 1.x, the exit codes and the JSON keys are stable. New keys may be added; existing ones are not removed or renamed.
- **#13's acceptance includes:**
  - a round trip of a fixture trail through otelcol-contrib's `otlpjsonfile` → `file`, verified with `verify_files` (ADR-0001 decision 8);
  - property tests for delete, reorder, edit and truncate at every position, and for a forged checkpoint.
- **Tests for the attacks decisions 5, 8 and 9 close** (#11 and #13; each fails against a writer or verifier that lacks the rule):
  - **Rollback against a running writer.** With a writer open, an attacker truncates the live file at a record boundary, deletes it, or renames the newest sealed segment back to `audit.jsonl`. The next `record` is `CorruptTrail`, and nothing is signed.
  - **Rollback across a restart.** Structural loss is checked before `expect_head`, so it wins.
    - Deleting or emptying the live file (no staging file): `open` is `CorruptTrail`, with or without `expect_head`. `resume` then writes a `vigil.audit.resume` record.
    - Truncating the live file at a record boundary, or renaming the newest sealed segment back to `audit.jsonl`, then `open` with `expect_head` from the last receipt: `HeadMismatch`.
    - The same two edits without `expect_head`: the documented gap. A test asserts that `open` succeeds and verify then reports clean, so the limit stays visible.
    - `expect_head` naming a `seq` in an archived segment: `HeadMismatch`.
  - **Crash points, with a second writer running.**
    - A crash is injected after each sealing step 1–6 in process A while process B holds the trail open, and after a torn write at end of file. B's next `record` settles the staging file (promoted after steps 3 and 4; discarded after steps 1 and 2) and appends with the right `seq`.
    - The same crash points with `open` in a fresh process.
    - A crash after each `create` step: complete staging → promoted at `open`; earlier → `CorruptTrail` and `TrailExists`, as documented.
    - No case writes a new record or signature during recovery, and verify reports no error and no `SeqConflict`.
  - **Fake records.**
    - A complete but invalid line between two linked records is `Unparsable` or `InvalidField`: an error, and the CLI exits 1.
    - Every strict prefix of a valid line's JSON text (each cut point, including inside a multibyte character) is a fragment, `TornWrite` while trailing. The complete JSON text without its newline is a record, terminated by the next writer (amended, #68).
    - A line with a duplicate key at any level is `InvalidField`.
    - A non-canonical integer is `InvalidField`, as is an `observedTimeUnixNano` that differs from `timeUnixNano`.
  - **Wrong trail.** A second trail created with the same key, or the trail re-created after deletion, is `TrailMismatch` against the pinned id.
  - **Revocation.**
    - With the old key: cut back to the bound and forge records and a checkpoint above it → `RevocationUnconfirmed`; forge below the bound → `RevocationMismatch` or `HashMismatch`.
    - Following the procedure exactly after a clean stop → no error.
    - The compromise branch → `UntrustedKey` exactly for the old-key checkpoints above the bound, and the `vigil.audit.key_rotated` record present.
    - An old-key writer left running → `UntrustedKey`.
  - **Forged appends under an honest key.** An attacker appends correctly chained records between operator steps 2 and 5. `rotate` with `--expect-head` from the receipt gives `HeadMismatch`, and nothing is signed. Records appended under a running writer and then covered by its checkpoint are `NoReceipt` with `--receipts`.
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
    - Receipts for records lost before a `resume`: see "Receipts across a resume" below (amended by #70; they are no longer next to receipts for reused `seq`s).
    - Records written after the receipts export: `NoReceipt` by default; with `--receipts-live`, one `Unreconciled` (info), exit 0 without `--strict` and 1 with it; a receipt above the head, or a receipt with a wrong hash between the reconciled prefix and the head, is still `ReceiptMismatch` with `--receipts-live`.
    - An in-flight record below the highest receipt (process A's receipt not stored, process B's stored): with `--receipts-live`, `Unreconciled` from A's `seq` and exit 0; a hole that stays open across later receipts keeps `Unreconciled` at the same `seq`, and is `NoReceipt` without `--receipts-live`. `--receipts-live` with no receipts: everything `Unreconciled`.
    - Receipts-file parsing: an unknown line, a `waive` or `from` line without a reason, two waivers for one `seq` and a second `from` line exit 2, and the library's second `waive` for one `seq` or second `receipts_from` returns `InvalidConfig`; two receipts with one `seq` and different hashes do not.
  - **Trust scoping.** A key line before any `trail` line fails to parse. `--trail` with an unpinned id exits 2.
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
  - **Resume.** On a headless live file, the file is renamed unchanged and a new live file starts with an opening checkpoint. On a deleted live file, `seq` continues above `--lost-through` (with `--lost-through` equal to the head, directly after it, with no `SeqGap`). In both, `Resumed` is a warning and `--strict` exits 1 until an `accept Resumed` line names it.
  - **Display-only fields.** `severityNumber` other than 9, a different `severityText`, an extra `LogRecord` field, or a duplicate key that only differs by an escape → error.
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

### 12. Format freeze and the promise that old trails still verify

- **What v1 is.** Decisions 3 to 9 together: attribute names and types, the canonical encoding, the domain strings, the hash, the MMR, the checkpoint message, Ed25519 with `verify_strict`, and the file names. `audit.v` = `1`.
- **The promise from 1.0.0:**
  - every vigil 1.x release verifies every trail written by any vigil ≥ 1.0.0;
  - every 1.x release writes v1 by default;
  - v1 verification is never removed in 1.x. A 2.0 that drops it must say, in its ADR, how v1 trails are verified from then on (for example with a kept `vigil-audit` 1.x).

  `dev` before 1.0.0 is unpublished, so the format may still change there, with fixtures regenerated in the same PR.
- **How the format can change.** Any change to what is written is a v2 and needs a new ADR. A 1.x minor may add v2 *verification* and opt-in v2 writing. Making v2 the default is a major. A version change happens only at a segment boundary, after a closing checkpoint.
- **Enforcement** (in #13):
  - **Golden vectors**, committed as test data: canonical encodings and hashes of sample records; MMR roots for sizes 0..=64, recorded once from both vigil's code and tessera-core at `f08255d`, with no dependency kept; deterministic RFC 8032 signatures for fixed seeds.
  - **Fixture trails** under `tests/fixtures/audit/v1/`, generated with fixed seeds, a fixed trail id and an injected clock. They cover multi-segment, rotation, a key rotation, a torn write (trailing, and repaired with `audit.repaired`, amended by #68), a resume gap (amended by #70) and an uncovered tail. Tampered variants carry the findings they must produce.
  - **Frozen at 1.0.0.** Once the 1.0.0 tag exists, a CI step fails if any file under `tests/fixtures/audit/v1/` differs from the tag.
- **Dependency bumps cannot change the format.** BLAKE3 output is fixed by its specification and Ed25519 signatures by RFC 8032, so a bump of `blake3` or `ed25519-dalek` changes no byte; the golden vectors catch it if one ever does. Neither crate's types are public, so a major bump of either is invisible to users.
- **Collector copies.** The promise covers vigil's own files and copies whose attribute values are unchanged. A shipper that rewrites values is outside it.

### 13. Public surface (feature `audit`, under ADR-0004's rules)

Only vigil's own types and std appear. Hashes and keys are byte arrays, not `blake3` or `ed25519-dalek` types. Following ADR-0004 decision 5, configuration is by builder methods on structs with private fields.

**`audit` reads no `VIGIL_*` environment variable**, unlike telemetry. Its policy decides what is durable and what is signed, so it must be in reviewed code or the operator's deployment, not in an environment a process inherits.

| Item | Why it is public |
|---|---|
| `AuditConfig` (`new(service)`, `dir`, `max_bytes`, `checkpoint_every`, `checkpoint_interval`, `mirror_to_logs`, `expect_head(seq, hash)`, `create(self, signer)`, `open(self, signer)`, `resume(self, signer, head, lost_through, actor, reason)`, which returns the trail and the `Receipt` of its `vigil.audit.resume` record; `lost_through` amended by #70) | Creating (explicitly, once), opening with the head the application last saw, and the operator's resume decision (decision 8). |
| `AuditTrail` (`record`, `checkpoint`, `close(self) -> Result<Checkpoint, AuditError>`, `dir`, `trail`), `Send + Sync` | The trail handle, shared across threads. `close` consumes it, so nothing is written after the close checkpoint it returns (decision 9); an application that shares the handle through `Arc` closes it with `Arc::into_inner`. |
| `Entry` (`new(actor, action, object)`, `reason`, `before`, `after`, `details`) | One audited action (decision 3). |
| `Value` (`Text`, `Digest`; `Value::digest_of(&[u8])`), `#[non_exhaustive]` | A before or after value, or its digest. |
| `Receipt` (`trail`, `seq`, `hash`, `hash_string`, `unsigned_records`) | Stored by the application with its own record: an application-side anchor (decision 5), and the signal that signing is behind (decision 6). |
| `Checkpoint` (`seq`, `hash`, `mmr_size`, `mmr_root`, `key_id`, `line`, `parse`) | Anchors, verification start points and the expected head after a clean stop (decisions 9, 10, 11). |
| `Signer`, `SignerError`, `KeyFileSigner`, `keygen` | Key custody (decision 9). |
| `TrustPolicy` (`new`, `trail` → section with `key`, `key_through`, `end`; `from_file`) | The verifier's trust input: pinned trail ids, each with its own keys and revocation bounds (decision 9). |
| `verify`, `Verifier` (including `accept`, amended by #68), `Report`, `Finding`, `FindingKind` and `Severity` (both `#[non_exhaustive]`, `Copy + Eq + Debug`) | The verify contract (decision 11). |
| `AuditError`, `AuditErrorKind` (`Io`, `Poisoned`, `TooLarge`, `InvalidEntry`, `CorruptTrail`, `HeadMismatch`, `MissingTrail`, `TrailExists`, `Signer`, `InvalidConfig`), `#[non_exhaustive]`, `Copy + Eq + Debug` like ADR-0004's kinds | Matchable failures (ADR-0004 decision 3 shape). |

### 14. Dependencies (feature `audit` only)

- **`blake3` 1** with `default-features = false, features = ["std", "pure"]`.
  - `pure` compiles no C or assembly, which removes a C toolchain from every consumer build and from the IEC 62304 SOUP list.
  - It costs 1.4 µs per record (2.67 against 1.26 µs, probe), negligible next to a millisecond-scale fsync.
  - It keeps blake3's Rust SIMD paths.
- **`ed25519-dalek` 2** with `default-features = false, features = ["std", "zeroize", "fast"]`. No `rand_core`: keys come from `getrandom` bytes through `SigningKey::from_bytes`.
- **`getrandom` 0.3**, already in the tree.
- **The MMR** is vigil's own code (push, root and peaks; the probe's version is under 50 lines), with the golden vectors of decision 12. Proof generation is not needed by `verify`, which recomputes everything, and comes with the anchor-holder API in [#57](https://github.com/vig-os/vigil/issues/57).
- **Cost and licences.** 17 more crates in the normal tree (64 → 81, probe; `pure` adds none). **Licences.** [#47](https://github.com/vig-os/vigil/issues/47)'s `deny.toml` (merged in #55) allows Apache-2.0, MIT and Unicode-3.0.
  - `blake3` and `constant_time_eq` pass through their Apache-2.0 alternative.
  - `curve25519-dalek`, `ed25519-dalek` and `subtle` are BSD-3-Clause only, so the PR that adds them (#12) adds crate-scoped BSD-3-Clause license exceptions for exactly those three crates and justifies them there: permissive, notice-retaining, and compatible with Apache-2.0 distribution.

  **For #12:** `curve25519-dalek`, `ed25519-dalek` and `subtle` are BSD-3-Clause only. #12 must add crate-scoped BSD-3-Clause exceptions for exactly those three crates to `deny.toml`, with a justification in that PR.

  crates.io only; no git dependency.

### 15. Tessera mapping and adoption path

- **Now:**
  - vigil's MMR is tessera-core's construction (decision 7);
  - record hashes use tessera's digest spelling (decision 4);
  - key files are tessera keygen files (decision 9);
  - `Producer` maps to vigil's resource attributes.

  So tessera-core 0.1.0-alpha.1 can already recompute any vigil checkpoint root from the trail's record hashes, and check inclusion and consistency proofs against it, with no code on either side.
- **The adoption path** ([#59](https://github.com/vig-os/vigil/issues/59)) is gated on tessera-core being on crates.io with its format frozen:
  1. `vigil-audit export-tsra` packages a sealed segment as a tessera product: one blob block, the vigil checkpoint in sealed metadata, `producer` per ADR-0058. tessera then signs the product with its own envelope.
  2. Optionally, vigil replaces its private MMR code with tessera-core's. This needs a resume-from-peaks API, which tessera-core lacks at `f08255d`, and must leave every golden vector and fixture byte unchanged.

  Neither step changes v1.
- **What vigil does not adopt:** tessera's sealing model and its signature envelope (Context table), and its product schemas.

### 16. What the #66 rules detect, by threat model (amended, #66)

The four threat models: **(a)** an attacker who can write the trail files but holds no trusted key; **(b)** an attacker who holds a stolen, not yet revoked key and can write the files; **(c)** honest crashes (SIGKILL, power loss), which must never make plain verification fail for good; **(d)** several writer processes. None of the rules changes v1's encoding (decision 12); they change what the writer returns and what the verifier reports.

**Clean-stop head: `close()` returns a `Checkpoint` (decision 9, step 1).**
- (a) An append after the last close moves the head past the expected head; a rollback leaves it below, or with another hash: `rotate` and `vigil-audit checkpoint` refuse with `HeadMismatch`, and nothing is signed. An append between two closes is signed by the later close; step 2 reports it as `NoReceipt` before the new key covers anything.
- (b) The stolen key adds nothing here: the expected head's hash pins, through the chain, every record below it, so a rewrite and re-signing up to the same `seq` is `HeadMismatch` (probe).
- (c) A killed writer returns no close checkpoint, so `rotate` refuses until one restarted writer's `close()` returns the head. That blocks a rotation, never verification. A crash between fsync and the stored receipt leaves an orphan for a waiver (below).
- (d) Closes are serialised by the directory lock, so the highest `seq` held across processes is the head, whatever order they closed in (probe: 8 processes, 20 runs).
- **Not detectable without an external anchor ([#57](https://github.com/vig-os/vigil/issues/57)):** an attacker who controls the application's own store of receipts and checkpoints, or the writer process itself, chooses the expected head.

**Receipts range: start of the verified range through the head (decision 5).**
- (a) Every chained append is `NoReceipt` wherever it sits: before the first receipt, between receipts, or after the last one under an honest `close()`. A rollback is `ReceiptMismatch` for every receipt above the new head.
- (b) A rewrite of a receipted record is `ReceiptMismatch`, since the receipt's hash cannot be re-signed into agreement. A stolen key adds nothing against receipts.
- (c) A crash orphan, including one per open request-log entry when a power loss stops every writer at once, is `NoReceipt` until an operator reviews it against the application's durable request log and adds a hash-pinned `waive` line for it; then `ReceiptWaived` (info), so a crash never fails verification for good. With `--receipts-live`, in-flight records, including those below the highest receipt, are `Unreconciled` (info), never `NoReceipt`; `--strict` refuses to call that complete.
- (d) Receipts from all processes are merged; the range does not depend on which process wrote what.
- **Not detectable:** with `--receipts-live`, whether a record above the reconciled prefix is honest, until its hole closes or the trail stops (reported as `Unreconciled`); a forged record that an operator waives because it reproduces, field for field, an entry the application attempted, under a writer the attacker killed (the attacker then gains nothing the application did not try to record); and anything an attacker who can also write the receipts adds.

**`start_from`: only an anchored start demotes (decision 11).**
- (a) A forged start needs a trusted signature: `StartMismatch`. The start comes from the archive's record, never from the disk, so deleting kept segments up to a later checkpoint is `StartMismatch` too, even where every checkpoint is anchored (probe).
- (b) A start signed with the stolen key is accepted by signature, but every anchor, pin and receipt below it is `UnanchoredStart`, an error: the attack that passed `--strict` under the accepted rule now fails (probe). Anchors and receipts above the start are checked as usual.
- (c) A start is a sealed checkpoint, written through the staging file and settled after any crash (decision 8), so no crash changes it. Verifying the live directory alone without a start is `SeqGap`, an operator error rather than a crash effect, and the verifier still checks everything after the gap.
- (d) Not affected: the start is a property of the verified files, not of the writers.
- **Not detectable:** a stolen-key rewrite above an unanchored start with no anchor or receipt above it. This is the same limit as for a trail that was never archived (decision 9: against a stolen key, only anchors and receipts help). Nor an operator who takes the start from the disk against the rule.

**Revocation scope: revoked on one trail means revoked on all (decision 9).**
- (a) Not applicable: revocation concerns keys, and the trust file is kept outside the trail directory.
- (b) A trust file that revokes the stolen key on X but trusts it on Y no longer loads, so Y cannot verify clean with forged records signed by that key (probe). Once Y is bounded too, forged checkpoints above Y's bound are `UntrustedKey`, and a cut back to the bound is `RevocationUnconfirmed`. A retired trail is bounded at its `end=`, and anything appended to it is `TrailEnded` (probe).
- (c), (d) Not applicable: the rule is checked when the trust file is parsed.
- **Not detectable:** forgeries on any trail between the key's compromise and the bound chosen for that trail. Each bound must be the last checkpoint that matches an anchor on that trail (step 2), and only anchors date a compromise. Nor a trail kept in a separate trust file that still trusts the key: the rule holds within the one trust file the verifier is given.

### 17. What the amendment-2 rules detect, by threat model (amended, #68, #70)

The same four threat models as decision 16: **(a)** write access to the trail files without a trusted key; **(b)** a stolen, not yet revoked key plus write access; **(c)** honest crashes (SIGKILL, power loss), which must never make verification fail for good; **(d)** several writer processes. The format changes are one optional hashed attribute (`audit.repaired`, tag `0x07`) and `mmr_size` counting records; both land before 1.0 (decision 12).

**Attested repairs (decision 5, #68).**
- (a) A fragment inserted anywhere a line follows it, or an attested fragment whose bytes are changed, is `RepairMismatch`, an error (probe). Under the core rule both were warnings, so this closes most of a documented residual. Forging an attestation means rewriting the line after the fragment, which a covering checkpoint detects (`HashMismatch`, `ChainBroken`); in the uncovered tail the attestation is not counted (`TornWrite`, a warning, and `UncoveredTail` already fails `--strict`). A forged record that carries an attestation and is later covered by an honest checkpoint is `NoReceipt` with receipts (probe). Removing a fragment loses no hashed content and is info.
- (b) Nothing new: the stolen key can already rewrite and re-sign everything above the newest anchor, fragments included; anchors and receipts remain the defence (decision 9).
- (c) A SIGKILL mid-write leaves a fragment that the next write attests, whoever writes next; once a trusted checkpoint covers it, it is `TornWriteRepaired` and `--strict` passes (probe: 20 runs, 8 writers, three SIGKILLed mid-write). Several crashes in a row leave one gap with one attestation. A power loss behaves the same on storage that meets decision 6's two requirements. A trailing fragment on a stopped trail is a warning until the trail is opened and closed once; only where no write can follow does it need an `accept` line. So no honest crash fails verification for good.
- (d) The directory lock serialises writers, so the process that takes the lock next sees the gap and attests it; the rule does not depend on which process crashed.
- **Not detectable without something kept outside:** a fragment appended at the live tail while a writer runs, before that writer's next write. The writer attests what it finds, as it signs records it finds (decision 5, "A checkpoint attests the trail as its signer found it"). The gain is nil: a fragment is no record, carries no hashed content, is reported only by length (`TornWriteRepaired`, info), and is never presented as data. Nor, as an error, bytes appended after the closing checkpoint of a rotation-sealed segment: they stay a `TornWrite` warning (so `--strict` fails), marked "no crash outcome", and an `accept` line for them is `AcceptMismatch` whenever the next file is verified with them; verified alone, only the review criteria forbid accepting them.

**Reviewed warnings (decision 11, review file, #68).**
- (a) The review file lives outside the trail directory, like the trust file and the receipts. An `accept` line cannot be moved to another record or fragment: its hash pins one record, or one gap's bytes at one place. If the reviewed record is changed or rolled back, the line is `AcceptMismatch`, an error (probe).
- (b) A rewrite of a reviewed record with the stolen key is `AcceptMismatch`: like a receipt, an `accept` line is an outside pin the key cannot re-sign into agreement.
- (c) It is the route for the honest warnings no write can clear: a trailing fragment on a retired trail, an operator's `resume`, a clock step back, a Collector redelivery. Errors are never acceptable (probe: a usage error), so an attack that produces an error cannot be reviewed away.
- (d) Not affected: lines are checked against the files, whichever process wrote them.
- **Not detectable:** a reviewer who accepts tampering; the report shows every acceptance as `Accepted`, with the reviewer and the reason, so the decision is attributable. Anyone who can write the review file can accept warnings, but not errors.

**Resume gaps and lost receipts (decisions 5, 8 and 9, #70).**
- (a) Without a key, no opening checkpoint can be signed: `BadSignature` or `UntrustedKey` (probe). A jump without the full gap shape is `SeqGap`. A rollback of records written after a resume leaves receipts above `lost_through`, outside the gap: `ReceiptMismatch` (probe; #70's M1 closed). A rollback across the resume leaves the resume's receipt above the head: `ReceiptMismatch`.
- (b) The stolen key can sign an opening checkpoint and write a resume record, but cannot produce the resume record's receipt or an `accept Resumed` line. The forged gap stays unconfirmed: the resume record is `NoReceipt`, and every receipt, anchor and pin inside the gap keeps its error (probe). Even if a reviewer is talked into an `accept Resumed` line for it, anchors and pins inside stay errors, because only an anchor on the opening checkpoint sets them aside, and the stolen key cannot create one (probe). Without receipts and with no anchor inside it, a forged gap shows as a `Resumed` warning, so `--strict` fails; under the core rule the same attacker could cut the tail and re-sign it with no warning at all (decision 9).
- (c) Honest crashes never need `resume` (decision 8). A crash *during* `resume` is settled like an interrupted sealing: both new lines sit in one staging file, promoted together or discarded, so no crash leaves a jump without its resume record.
- (d) The expected head stays the highest `seq` held across processes: every new `seq` lies above `lost_through`, which is at least every held `seq` (probe: `open` with `expect_head` succeeds after a resume; #70's M2 closed).
- **Not detectable:** anyone who can also write the receipts or the review file, for the receipts, waivers and `from` lines inside a gap (anchors and pins need an anchored opening checkpoint, so writing those files does not set them aside); acknowledged records that no receipt, close checkpoint or anchor names (they leave no trace in the trail; the application's request log shows them). An operator who sets `--lost-through` below a held `seq` is not hidden: that input fails for good.

## Consequences

- **Regulated consumers get a trail they can show an auditor:**
  - attributable (actor), time-stamped by the system, with reason and before and after;
  - append-only and tamper-evident;
  - never deleted by vigil;
  - verifiable offline with one CLI, for as long as 1.x lasts.
- **The trail is plain OTLP/JSON.** Any OTLP tool reads it and the Collector ships it; integrity checks need only `vigil-audit`.
- **Throughput is bounded by fsync.** Tens of records per second on slow virtual disks (probe), more on local NVMe. A consumer that needs bulk audit waits for [#56](https://github.com/vig-os/vigil/issues/56) or batches at the application level.
- **Fail-closed means an audit outage stops the audited action.** That is the point, and the application must handle `Err` (for example, refuse the change and tell the operator). A signer outage does not stop it (decision 6), but it leaves records unsigned until the signer recovers.
- **What a local key does not stop.** An attacker who holds the key and can write the files can rewrite and re-sign the trail. Only an off-device signer ([#58](https://github.com/vig-os/vigil/issues/58)) or anchors ([#57](https://github.com/vig-os/vigil/issues/57) and decision 10) detect that. This is written in the rustdoc and the README, not left to be discovered.
- **What a writable trail does not stop without something kept elsewhere.** An attacker who can write the files but has no trusted key can rewrite everything after the last trusted checkpoint, or roll the trail back to any earlier checkpoint (decision 5). A running writer refuses to continue after that. A restarted writer refuses only with `expect_head`. Once any writer signs on the shortened trail, only anchors and the application's receipts reveal it; `--max-age` does not. A crash alone loses only unacknowledged records and is recovered without an operator. Any other loss stops the trail until an operator runs `resume`, which records the decision. The verifier reports the uncovered tail; `--strict` fails on it.
- **Operators carry real duties:**
  - pin each trail id and keep the trust file outside the trail directory;
  - stop every writer before rotating a key;
  - decide on `resume` after structural loss;
  - run on storage that honours flushes.

  The README's audit section lists them.
- **Creating a trail is a deployment step** (`create`), not something `open` does. An application whose audit directory was deleted stops until an operator acts, and a re-created trail fails verification until its new id is pinned.
- **Disk only grows.** Archiving is the operator's job; vigil only guarantees that any sealed segment can be moved.
- **The format is a long-term promise.** v1's encoding, domain strings and MMR can never change in 1.x. Every fix must be expressible as a v2, which costs an ADR and a second verifier path kept alive alongside v1.
- **Code that must stay small.** The audit sink adds a second writer to the crate's riskiest file (`src/rotate.rs`, a crate-internal locked-section API). It is shared code, so the multi-process tests of ADR-0002 must cover both callers.
- **Dependencies.** 17 more crates with `audit` on, and crate-scoped BSD-3-Clause licence exceptions for the three reviewed crypto crates.
- **Tessera.** Its interoperability costs vigil nothing now, and it keeps the adoption path open without making vigil's promise depend on tessera's release schedule.
- **What the #66 amendment costs** (decision 16):
  - **Applications store one more thing.** Each process stores the `Checkpoint` that `close()` returns next to its receipts, and a rotation needs every writer to have closed (or one restart and close). An application that drops the handle instead of closing it makes rotation take that extra step.
  - **`close` consumes the handle.** An application holding `Arc<AuditTrail>` must reach the last reference (`Arc::into_inner`) to close. A `close(&self)` that left the handle usable afterwards could not make the returned checkpoint the last thing written.
  - **Receipts cover everything, so a crash costs a review.** Every crash between a durable write and the stored receipt leaves a `NoReceipt` until an operator waives it, one line per record, against the application's request log. Operator records need their printed receipts added. A deployment that started storing receipts late adds one `from` line. Receipts lost with a `resume` are `LostRecord` once the resume is confirmed (amendment 2, below).
  - **Live reconciliation is a separate, explicitly weaker mode** (`--receipts-live`), which `--strict` never accepts, and it requires a fixed order: export receipts, then read the trail. It stops at the first open hole, so one slow or crashed writer holds back the reconciled prefix until its receipt is stored or waived.
  - **Archiving needs an anchor and a record.** The operator records and anchors the start before moving segments, and later verifications take the start from that record. A start that was not anchored cannot set aside the anchors, pins or receipts below it, so such a verification fails until the start is anchored (or the archive is verified together with the live files).
  - **A shared key has one lifecycle and one trust file.** Revoking it means rotating every live trail that lists it and pinning `end=` on every retired one, all in the same trust file. Deployments that want independent lifecycles, or one trust file per trail, use one key per trail.
  - **More surface to keep stable in 1.x:** `close`'s return type, `Verifier::waive`, `receipts_from` and `receipts_live`, the `waive` and `from` lines of the receipts file, the trust file's `end=` and the builder's `end`, `--receipts-live`, and the finding kinds `UnanchoredStart`, `TrailEnded`, `Unreconciled` and `ReceiptWaived`. `FindingKind` is `#[non_exhaustive]`, and no new `AuditErrorKind` is needed (the trust-file rule reuses `InvalidConfig`), so ADR-0004's rules hold.
  - **Decided in amendment 2 ([#68](https://github.com/vig-os/vigil/issues/68)):** an honest crash's `TornWrite`, and a `Resumed`, no longer make `--strict` fail for good (below).
- **What amendment 2 costs** (decision 17):
  - **Two format changes before 1.0** (decision 12 allows them on `dev`, with fixtures regenerated). `audit.repaired` adds tag `0x07` to the v1 encoding (decisions 3 and 4): the format layer merged with [#12](https://github.com/vig-os/vigil/issues/12) (PR #73) does not have it yet, and [#79](https://github.com/vig-os/vigil/issues/79) adds it to `RecordContext`; the writer in [#11](https://github.com/vig-os/vigil/issues/11) must set it. `mmr_size` counts records instead of equalling `seq` (decisions 7 and 8): identical on every trail without a resume gap. The merged code still rejects a checkpoint whose `mmr_size` differs from its `seq` (`src/audit/format.rs`, `InvalidConfig`), which contradicts this rule for a resume's opening checkpoint; #79 removes that check and the verifier and checkpoint builder count records. Nothing else in v1 changes: no new domain string for records or checkpoints (the attestation digest has its own, `vigil.audit.v1.repaired`), and the hash and signature constructions are unchanged.
  - **After a resume, `seq` is not the MMR leaf index.** The leaf index is the number of records before a record; it differs from `seq` by the size of every resume gap before it. The opening checkpoint's `mmr_size` gives the offset, so [#57](https://github.com/vig-os/vigil/issues/57)'s anchor-holder proof API maps `seq` to leaf index through it.
  - **The writer does a little more on a repair:** it hashes the bytes it already read to find the torn tail, and checks attestations when it reads lines other processes wrote. A crash costs no operator action any more, unless no write can follow it.
  - **Inserted fragments become errors.** A trail that a tool or a person "annotated" between lines no longer verifies; the core already called such lines tampering in spirit.
  - **`resume` takes a mandatory `--lost-through`** (`AuditConfig::resume` gains a `lost_through` argument). The operator must collect the highest held `seq` from every process, the anchors and the pins before resuming, as the rotation procedure already requires for the expected head. Overestimating is free; underestimating fails closed, for good, and cannot be repaired later.
  - **A reserved action prefix:** `vigil.audit.` is no longer available to applications.
  - **Operators review permanent warnings in writing:** one `accept` line each, with a reviewer and a reason, in a third file kept outside the trail directory. A trail with an unreviewed `Resumed` or clock step does not pass `--strict`.
  - **More surface to keep stable in 1.x:** `Verifier::accept`, `--reviewed` and the review-file format, `resume --lost-through` and `AuditConfig::resume`'s argument, the fixed `audit.details` form of a resume record, the `audit.repaired` attribute, and the finding kinds `RepairMismatch`, `AcceptMismatch`, `TornWriteRepaired`, `Accepted`, `AcceptUnused` and `LostRecord`. `FindingKind` is `#[non_exhaustive]` and `accept` reuses `InvalidConfig`, so ADR-0004's rules hold with no new `AuditErrorKind`.

## Alternatives considered

- **Build on `tessera-core` now** (the plan in #12). It is git-only, so vigil could not be published: `cargo package` exits 101 (pre-mortem R3). Its format is deliberately unfrozen (ADR-0052), so the promise of decision 12 would rest on another crate's moving format. It has no chain or checkpoint primitive and cannot resume an MMR. It would add 41 crates against 23. Rejected; its useful part is adopted as a construction (decision 7), and the rest is the adoption path (#59).
- **Wait for tessera-core 1.0 before shipping audit.** It would tie vigil 1.0 to another project's release, for primitives two mature crates already provide. Rejected.
- **Leave audit out of the 1.0 surface** (pre-mortem R3's third option). The 0.3.0 milestone and the owner want audit in 1.0, and nothing in the design needs an unstable dependency any more. Rejected.
- **Hash the JSON bytes of the line** (or a JCS canonicalisation of them). The bytes depend on `opentelemetry-proto`'s serialisation, which changes across bumps, and on the Collector's rewriting, so old trails would stop verifying after a bump. JCS adds `serde_jcs` and float canonicalisation for no gain. Rejected for a value-level encoding (decision 4).
- **Emit audit records through `tracing`.** Filters, sampling and the batch queue can drop them, and the caller cannot get a durable `Result`. Rejected (decision 1).
- **Share the telemetry directory and lock.** An audit fsync would block log appends, and retention would apply. Rejected (decision 2).
- **A separate rotation implementation for audit.** It would duplicate the most tested code in the crate. Rejected for a crate-internal locked-section API over ADR-0002's machinery.
- **fsync every N records, or on a timer.** An `Ok` would no longer mean durable, and a crash would lose acknowledged records. Rejected; group commit (#56) is the variant that keeps the meaning.
- **`sync_all` instead of `sync_data`.** Same cost (probe). It also flushes metadata the append does not need, and std maps both to `F_FULLFSYNC` on macOS. Rejected; directory metadata is fsynced explicitly when it changes.
- **Truncate oversized records like logs** (ADR-0001 decision 10). That would change hashed content and lose the record. Rejected for `TooLarge`.
- **Per-segment MMRs.** No consistency proof across segments, and a segment root alone does not bind segment order. A trail-wide MMR costs the same once checkpoints carry peaks. Rejected.
- **A hash chain without an MMR.** Proving one record or one extension would require the whole trail. Rejected; anchors need consistency proofs (#57).
- **Sign every record.** 11 µs and 64 bytes per record (probe), and a signer outage would stop every action. Checkpoints give the same tamper-evidence up to the uncovered tail. Rejected.
- **tessera's `ed25519-env-v1` envelope for checkpoints.** A checkpoint signature would then also verify as a tessera product signature over the same string. It needs `serde_jcs`, and its format is unfrozen. Rejected for a domain-separated message (decision 8).
- **Recover silently from a missing or empty live file** (the first draft: rebuild from the newest sealed segment and sign a new opening checkpoint). A crash and a rollback look the same from the directory, so the honest writer would sign over a shortened history. Rejected for the staging-file protocol, which makes every crash state recognisable, plus an operator `resume`.
- **A head file in the trail directory** to remember the last head across restarts. The attacker who rolls the trail back can roll that file back too. Rejected for `expect_head`, which comes from the application's own store.
- **Derive the trail id from the key or the creation checkpoint.** A re-created trail with the same key would get the same or a predictable id. A random id pinned out of band changes on re-creation. Rejected.
- **Revocation by `through=<seq>` alone** (the first draft). With the stolen key, an attacker cuts the trail back below the bound and forges a fresh trail there, which verifies clean. Rejected for a pinned hash plus a confirming checkpoint by another key.
- **Hash `observedTimeUnixNano` as a second field.** Two times with one meaning; requiring equality is simpler and shows one time. Rejected.
- **An unsigned mode.** A second state space to test, for users who could anchor instead. Rejected (decision 9).
- **A sidecar file for checkpoints.** Deleting the sidecar would not break the chain. Inline checkpoint records are covered by the chain themselves. Rejected.
- **A background checkpoint thread.** A thread in a regulated module, for little gain over checkpoints evaluated at append time and on `close`. Rejected; an idle trail's tail is covered on `close` or at the next append.
- **Ship TPM, Secure Enclave or PKCS#11 signers in 1.0.** Platform-specific dependencies, and many such devices do not support Ed25519. Deferred to #58 behind the `Signer` trait.
- **RFC 3161 in 1.0.** It needs ASN.1/DER and HTTP. Deferred to #57; anchoring by copying checkpoint lines works without them.
- **#66: `--expect-head` from the last receipt, with only checkpoints allowed after it** (the issue's second direction). It needs no API change, but a receipt does not pin the checkpoints after it, so any number of checkpoints could follow it, including a forged one that `rotate` (which checks the head, not signatures) would then cover with the new key. And with N processes, nothing tells the operator whether a close of another process happened after the last receipt. Rejected for `close()` returning the checkpoint it wrote.
- **#66: `--expect-head` read from the trail** (`vigil-audit checkpoints`, the last line). Exactly the head an attacker who can write the files controls. Rejected, as before.
- **#66: `close(&self)` returning `Option<Checkpoint>`, writing nothing when the head is already a checkpoint.** The head checkpoint may then be another process's, or a forged line the writer never checks (decision 8: writers do not verify signatures). Always writing a checkpoint signed by the handle's own signer costs one signature per close. Rejected.
- **#66: a receipts range from the first to the last receipt** (the accepted text). It misses appends before the first receipt and after the last, and the second is exactly what an honest `close()` signs (probe). Rejected.
- **#66: exempting `vigil.audit.*` actions from `NoReceipt`.** The attacker writes the action name, so a forged `vigil.audit.resume` record would escape. Printing receipts for operator records costs the operator one line per command. Rejected.
- **#66: treating records after the last receipt as a warning by default.** The common case of the attack, an honest close over a forged tail, would pass plain verification. The opt-in `--receipts-live` mode gives live reviews the weaker answer explicitly. Rejected.
- **#66: crash orphans as a permanent `NoReceipt`, or silently tolerated if they are the last record before a checkpoint.** The first breaks threat model (c); the second is the forged-append loophole again, since a forged record looks the same. Rejected for a hash-pinned waiver, reported as info.
- **#66: range waivers** (`waive <first>..<last>`). An attacker who can kill a writer can append any number of records before the restart, and one range line would waive them all. One line per record, checked against the application's request log, keeps the operator's decision as narrow as a crash. Rejected; the one legitimate range, late adoption, gets its own single `from` line.
- **#66: `--receipts-live` ending at the highest receipt.** A record in flight below it (one process's receipt stored before another's) would be `NoReceipt`, an error on an honest live trail (review probe). Rejected for the longest fully reconciled prefix.
- **#66: a `lost`-line mechanism for receipts lost with a `resume`** (drafted in review rounds 1 and 2). Round 2 showed that a chained `vigil.audit.resume` record appended without a key opened its gate; the fix (a receipted, correctly shaped resume and a `lost_through` bound) closed that, but round 3 showed that an old honest resume still covers a later rollback of the reused `seq`s, and that `expect_head` after a resume has no defined source. Withdrawn from #66 and deferred to [#70](https://github.com/vig-os/vigil/issues/70) with both findings; amendment 2 replaces it with resume gaps.
- **#66: requiring `rotate` on a retired trail.** It cannot write to WORM storage, so a shared key could then never be revoked cleanly on any trail that lists it. Rejected for `end=`, which is stronger: nothing at all may follow the retired head.
- **#66: checking revocation across several trust files.** The verifier would need every trust file in the deployment, which it cannot know it has. Rejected for one trust file per key, as a documented rule.
- **#66: a start trusted by its signature alone, with `OutOfRange` as info** (the accepted text before #66). It lets a stolen key disable every anchor (probe). Rejected.
- **#66: requiring the start to live on WORM storage.** The verifier cannot see where a file lives; a rule it cannot check is documentation, not verification. Anchoring the start gives the same assurance in a form the verifier checks. Rejected.
- **#66: always an error below a start, anchored or not.** Archiving would then fail verification for good, or force operators to drop their old anchors and receipts from the input, which hides them instead of reporting them. Rejected for the anchored-start rule.
- **#66: verifying the live directory alone without a start, reporting the missing history as info.** A rolled-back or deleted prefix would then verify clean. Rejected for `SeqGap`.
- **#66: per-trail revocation, documented as an operator duty** (the accepted text: "a revocation on trail X never affects trail Y"). A duty the verifier does not check is a trap: one forgotten section verifies a forged trail clean (probe). Rejected for a parse error.
- **#66: key-global revocation with one `revoked` flag and no bound.** `seq` is per trail, so a global bound has no meaning, and a bound-less revocation turns every honest checkpoint of the key on every trail into `UntrustedKey`, destroying history the operator vouched for. Rejected.

- **#68: an operator review line for every torn write, with no attestation** (the direction #68 suggested, reusing the waiver's shape). Every crash would cost a review, and a reviewer could not tell a crash's fragment from one inserted later: the writable directory holds no evidence of when a fragment appeared. The core's residual (inserted fragments pass plain verification) would stay. Rejected for attestation by the next writer, with review lines kept for the warnings no write can clear.
- **#68: `TornWrite` as info, or `--strict` ignoring it.** Inserted fragments, readable text included, would then pass `--strict`. Rejected.
- **#68: truncating the fragment at repair.** vigil never rewrites a trail; the fragment is evidence of the crash, and truncation looks the same as an attacker's edit. Rejected.
- **#68: a checkpoint forced after every repair, carrying the attestation.** A signer outage must not stop audited actions (decision 6), so the record after a repair would have to go out unattested and the rule would need a warning case for it again. Rejected for an attestation on whichever line comes next, record or checkpoint, counted once a trusted checkpoint covers it.
- **#68: acceptance lines in the receipts file or in the trust file.** The receipts file switches reconciliation on and holds the application's acknowledgements; deployments without receipts need acceptance too. The trust file is shared configuration of keys and trails, and a review is a per-incident record. Rejected for a separate review file.
- **#68: accepting by kind and `seq` only, or accepting errors.** An unpinned line could be moved to a different record or fragment, and an accepted error would let a reviewer, or anyone who can write the file, wave an attack through. Rejected: lines are hash-pinned and errors are never acceptable.
- **#68: one `accept` line confirming a `TornWrite` by its byte length.** Two fragments of equal length at one place are indistinguishable by length. Rejected for the digest.
- **#70: the withdrawn `lost` lines** (#66's draft). `seq` reuse let a later rollback of new records hide behind an old resume (M1), and gave `expect_head` a lost receipt above the new head (M2); both are reproduced in this amendment's probe. Rejected.
- **#70: the fix directions noted in #70** (the resume record commits to a hash of the lost receipt set, and the application replaces its receipts at each resume, taking both heads only from receipts stored after the latest one). Every application would have to rewrite its receipt store correctly at each resume and order receipts in time, and the verifier would still see two receipts per `seq`. Rejected for never reusing a `seq`, which needs nothing from the application beyond the evidence it already holds.
- **#70: an epoch counter in records and receipts.** It changes `Receipt`, the receipts-file format and `expect_head`, so that `(epoch, seq)` replaces `seq` everywhere. Rejected; skipping `seq`s keeps every existing rule.
- **#70: placeholder MMR leaves for the skipped `seq`s, keeping `mmr_size` = `seq`.** The verifier's work would grow with the declared gap, so a forged gap of 2^63 `seq`s signed with a stolen key is a denial of service unless capped, and any cap is arbitrary. Rejected for `mmr_size` counting records: a gap costs O(1).
- **#70: dropping the lost receipts from the input.** It hides the loss. Rejected (#70).
- **#70: lost receipts as warnings.** One incident would need a review line per lost record, and `Resumed` already carries the incident. Rejected for `LostRecord` (info) listed under one `Resumed` warning.
- **#70: a gap confirmed by its signature alone.** A stolen key could then disable every anchor and receipt inside a gap it declares, the attack #66 closed for `start_from`. Rejected for confirmation by a receipt or an `accept` line.
- **#70: `--lost-through` optional, defaulting to the head.** An operator who forgets it reuses `seq`s, and the core's permanent `ReceiptMismatch` returns. Rejected; equal to the head must be said explicitly.
## References

- [vig-os/vigil#10](https://github.com/vig-os/vigil/issues/10) (requirement framing; owner decision 2026-10-11), [#11](https://github.com/vig-os/vigil/issues/11), [#12](https://github.com/vig-os/vigil/issues/12), [#13](https://github.com/vig-os/vigil/issues/13), [#41](https://github.com/vig-os/vigil/issues/41), [#46](https://github.com/vig-os/vigil/issues/46), [#47](https://github.com/vig-os/vigil/issues/47), [#49](https://github.com/vig-os/vigil/issues/49), [#56](https://github.com/vig-os/vigil/issues/56), [#57](https://github.com/vig-os/vigil/issues/57), [#58](https://github.com/vig-os/vigil/issues/58), [#59](https://github.com/vig-os/vigil/issues/59)
- Path-to-1.0 pre-mortem, 2026-10-10 (finding R3)
- [vig-os/vigil#66](https://github.com/vig-os/vigil/issues/66) (this amendment: the four sub-decisions and the round-3 findings that opened them), [#68](https://github.com/vig-os/vigil/issues/68) (`--strict` and reviewed warnings) and [#70](https://github.com/vig-os/vigil/issues/70) (receipts across a `resume`), decided by amendment 2; [PR #71](https://github.com/vig-os/vigil/pull/71) (the withdrawn `lost`-line draft and its review findings M1 and M2); [PR #73](https://github.com/vig-os/vigil/pull/73) (#12's format layer, merged) and [#79](https://github.com/vig-os/vigil/issues/79) (its follow-up: tag `0x07` and `mmr_size` ≠ `seq` for a resume's opening checkpoint), [#46](https://github.com/vig-os/vigil/issues/46) (macOS lane, with the APFS crash test of decision 6)
- [ADR-0001](0001-on-disk-format.md) (format, bounded lines, conformance oracle), [ADR-0002](0002-rotation-and-retention.md) (rotation machinery), [ADR-0004](0004-public-api-and-stability.md) (public API and stability)
- [vig-os/tessera](https://github.com/vig-os/tessera) at `f08255d`: `docs/CONSUMING.md`, ADR-0028, ADR-0036, ADR-0037, ADR-0052, ADR-0058, `tessera-core/src/{hash,signing,manifest}.rs`
- 21 CFR Part 11 §11.10(e); EU GMP Annex 11 §9; IEC 62304
- [BLAKE3 specification](https://github.com/BLAKE3-team/BLAKE3-specs); [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) (Ed25519); [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) (Merkle tree hashing); [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) (time-stamp protocol)
- Rust 1.95.0 std `library/std/src/sys/fs/unix.rs` (`fsync`/`datasync` on Apple)
- Linux kernel `Documentation/admin-guide/ext4.rst` (`data=writeback` and `data=ordered`)
