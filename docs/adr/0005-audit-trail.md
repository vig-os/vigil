# ADR-0005: Audit trail

- **Status:** Accepted (2026-10-11). Core accepted; rotation/receipts/archiving sub-decisions open in [#66](https://github.com/vig-os/vigil/issues/66).
- **Date:** 2026-10-11
- **Issues:** [#10](https://github.com/vig-os/vigil/issues/10) (this decision); implemented by [#11](https://github.com/vig-os/vigil/issues/11) (sink and record API), [#12](https://github.com/vig-os/vigil/issues/12) (chain, MMR, checkpoints), [#13](https://github.com/vig-os/vigil/issues/13) (verify API and CLI, tamper tests); deferred work in [#56](https://github.com/vig-os/vigil/issues/56), [#57](https://github.com/vig-os/vigil/issues/57), [#58](https://github.com/vig-os/vigil/issues/58), [#59](https://github.com/vig-os/vigil/issues/59)

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
- **Sealing uses one staging file,** `.audit-next.jsonl`. Its leading dot keeps it out of the `audit.jsonl` / `audit-*.jsonl` patterns that readers and shippers match (ADR-0002 Consequences). It exists only while a rotation is in progress (decision 8).
- **Archiving** (moving sealed segments to WORM or off-host storage) is an operator action outside vigil. Verifying a trail whose older segments are gone (`start_from`) is open in [#66](https://github.com/vig-os/vigil/issues/66). Any sealed segment may be moved: the live file always starts with a checkpoint that carries the state the writer needs (decision 8). The live file and the trail marker (decision 8, "Creating a trail") must stay.

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
| `audit.seq` | both | 0-based, contiguous across segments; the authoritative order | `0x02` |
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
               ‖ F(0x05, service.name) ‖ [F(0x06, host.name)]
               ‖ kind fields in ascending tag order, absent optional fields omitted
               ‖ F(0x7f, prev_hash[32])
hash         = blake3("vigil.audit.v1.record\0" ‖ fields)
```

- Strings are their UTF-8 bytes as written, with no normalisation.
- Integers (`0x02`, `0x03`, `0x20`) are u64 big-endian, 8 bytes.
- Digests (`0x15`, `0x17`, `0x21`), keys (`0x23`) and hashes are raw bytes: 32 each, signatures 64 bytes. `0x22` is the concatenated 32-byte peaks, left to right, and is omitted when `mmr_size` is 0.
- `audit.hash` and every digest attribute are spelled `blake3:<64 lowercase hex>`, tessera's spelling.
- A record hash is plain blake3 over bytes that begin with the domain string, so it really is "blake3 of something". tessera-core can therefore use it directly as an MMR leaf digest.

### 5. Hash chain

- `prev_hash` of `seq 0` is `blake3("vigil.audit.v1.genesis\0" ‖ trail)`. `prev_hash` of `seq n` is the `hash` of `seq n−1`. No separate genesis record exists.
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
- **A checkpoint attests the trail as its signer found it, not who wrote each record.** A writer that finds records appended since its last read only checks that they link ("Same file, longer", decision 8). Its next checkpoint signs them, so anyone who can write the files can append correctly chained records that an honest key then covers. vigil cannot tell such records from those of another honest writer process. A deployment closes this in three ways:
  - **OS access control:** only the service account may write the audit directory. That is the first line, and outside vigil.
  - **Receipt reconciliation:** the verifier takes the application's receipts (`Verifier::receipts`, `--receipts <file>`, one `seq` and hash per line) and reports every record in the checked range that has no receipt as `NoReceipt`, and every receipt that does not match as `ReceiptMismatch`. Both are errors. *Which records the checked range covers* (in particular the records after the last receipt): **Open — decided in [#66](https://github.com/vig-os/vigil/issues/66); #12/#13 must not implement them before #66 is accepted.**
  - **Anchors** ([#57](https://github.com/vig-os/vigil/issues/57), decision 10), which bound what a later checkpoint may claim.
- **What cannot be detected without something kept outside the trail directory.** An attacker who can write the files can roll back or rewrite the uncovered tail, or roll back to any checkpoint. If afterwards a writer starts without `expect_head` and signs, the result is a consistent trail that verifies clean. Only anchors ([#57](https://github.com/vig-os/vigil/issues/57) and decision 10), receipts held by the application, or `expect_head` reveal it. The rustdoc of `AuditConfig::open` says so and recommends `expect_head` for regulated deployments.
- **Against an attacker who holds a trusted key,** only anchors, receipts and `expect_head` help (decision 9).
- **A torn write is not tampering, and nothing else is.** A killed writer can leave an unterminated fragment (ADR-0002 decision 6), and its `record` call never returned `Ok`. A torn fragment is always a strict byte prefix of a valid line. A line is **`TornWrite`** (a warning) only if all of these hold:
  1. it is the last line of its file, or the next writer's repair newline ends it (ADR-0002 decision 6);
  2. it fails to parse in the way only a prefix can: after dropping at most 3 trailing bytes of a cut UTF-8 sequence, it is valid UTF-8, and the JSON parser stops with an end-of-input error (`serde_json::error::Category::Eof`);
  3. if a complete record follows, that record links to the last complete record before the fragment.

  Any other line that does not parse, or that parses but is not a valid v1 record, is an error (`Unparsable`, `InvalidField`, …), including a complete line in the middle of a file. Probe: every UTF-8 prefix of a 1 271-byte record line (1 266 of them; 4 more cut a multibyte character) is `Category::Eof`.

  **A repair newline looks like any other newline,** so someone who can write the files can insert end-of-input fragments between linked records and get only warnings. No JSON parser accepts such a fragment as a record (condition 2), but its bytes can still be readable text: `cat` shows a fragment such as `{"resourceLogs":[…"user:mallory"`. The verifier reports each fragment with file, line and byte length, never its text, and it never presents a fragment as a record. An empty line, or one of only whitespace, also stops the parser at end of input. A torn write cannot produce one, because ADR-0002's repair writes one newline before the next record and vigil never writes whitespace, so such a line is `Unparsable`, an error. `--strict` turns every warning into a failure, and it is the mode for regulated review. The rustdoc of `vigil-audit verify` and the README say so.
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

- **Leaves.** Every record is a leaf, checkpoints included, in `seq` order. The leaf for `seq i` is `blake3(0x00 ‖ "blake3:<hex of hash_i>")`.
- **Construction.** Interior nodes are `blake3(0x01 ‖ left ‖ right)`. Peaks are merged on the binary carry. The root bags the peaks right to left with the node hash; the empty root is `blake3("")`. This is tessera-core's construction (`hash.rs`, ADR-0028/0049, `f08255d`), and the probe shows they are equal.
- **Peak heights are not stored.** They are the set bits of `mmr_size`, left to right.
- **Why both a chain and an MMR.** The chain gives a sequential check and pinpoints the first broken link. The MMR gives an O(log n) inclusion proof for one record and a consistency proof between two checkpoints, without shipping the trail. An anchor holder that keeps only checkpoints needs exactly that.
- **One MMR over the whole trail, not one per segment.** It costs the same, because checkpoints carry the peaks. It also gives consistency proofs across segment boundaries, and one root commits to the entire history.
- **No write-path cost.** The MMR is advanced only when a checkpoint is built, from the leaves since the previous checkpoint. The probe puts a push at 0.34 µs.
- **Proof sizes.** An inclusion proof is O(log n) hashes. A consistency proof in tessera-compatible form is the old peaks plus every leaf appended since (`ConsistencyProof { old_peaks, appended }`), so its size grows with the gap: about 32 bytes per record between the two checkpoints. A minimal RFC 6962-style proof is O(log n), but tessera-core does not verify that form. [#57](https://github.com/vig-os/vigil/issues/57) decides which form the anchor-holder API exposes.

### 8. Signed checkpoints, cadence and segment sealing

- **What a checkpoint is.** A record of kind `audit.checkpoint` at `seq k`. It commits to the chain head (`prev_hash` = hash of `seq k−1`) and to the MMR over leaves `0..k`: `audit.mmr_size` = `k`, `audit.mmr_root`, and `audit.mmr_peaks`, an array of `blake3:<hex>` strings that is absent when `k` is 0. It also carries `audit.key_id` (the 64-hex Ed25519 public key) and `audit.sig` (128 hex).
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
- **Every writer settles the staging file first.** Under the lock, before anything else and before every `record`, `checkpoint` or `close` (not only at `open`), a writer checks for `.audit-next.jsonl`. That costs one `fstatat`. If the file exists, it is the remains of a sealing that crashed in another process. It is settled before any append:
  - **Promote** it when it is complete (not torn, by decision 5's rule) and its first and only record is a checkpoint linking to the last complete record of the predecessor:
    - with a live file: the live file's last complete record, which is then the closing checkpoint. Sealing finishes with steps 4–6;
    - with the live path missing: the newest sealed segment's last record. Steps 5–6 run;
    - with the live path missing and no sealed segment but the marker present: the genesis value. This is an interrupted `create`, and steps 5–6 run.
  - **Discard** it (unlink, then fsync the directory) in every other case: torn, or not linking. In particular, a crash after step 2 leaves a live file whose last record is still `k−1`, so the staging file's opening checkpoint `k+1` does not link, and it is discarded. A discarded staging file never was part of the trail: its checkpoint covered a closing checkpoint that was never written. The next sealing signs both again.

  Settling writes no record and no signature. Then the checks below run.
- **Writer state across processes.** Each writer keeps the live file's descriptor open, as `RotatingFile` does, so its cached `(dev, ino)` cannot be confused with a reused inode. It also caches its **head**: the highest `(seq, hash)` it has written or read. Under the lock, it compares the open descriptor and its cached length with the live path:
  - **Same file and length:** the cache is current.
  - **Same file, longer:** it reads and checks the records appended since its cached offset. The first must link to the cached head.
  - **Same file, shorter:** something truncated the trail: `CorruptTrail`.
  - **Another file** (another process rotated): it reads the rest of its old file through the descriptor it still holds, from the cached offset up to the closing checkpoint. Then it reads the new live file, whose opening checkpoint must link to that closing checkpoint. The chain from the cached head to the new head is therefore read in full, never assumed.

  **The head never moves back.** If the trail's head on disk is below the cached head, or its record at the cached `seq` has a different hash, the result is `CorruptTrail` and the handle refuses to write. While reading, the writer recomputes hashes and links and applies decision 5's rules for torn writes and duplicate keys; any other break is also `CorruptTrail`. The writer does not check signatures; it may not hold the other writers' keys. So anyone who can write the files can also stage a fake crash state, for example a staging file with a forged checkpoint, and a writer will promote it. That gains nothing beyond the documented restart gap (decision 5): the forged checkpoint fails `BadSignature` in `verify`.
- **Crash recovery and structural loss** (at `open`, or when the cache is unusable):
  - **Crash recovery is limited to two cases:**
    - **A torn fragment at the end of the live file** (decision 5's rule). It stays in place, and the next write's repair newline ends it.
    - **An interrupted sealing or `create`,** settled by the staging-file rule above, which runs in every writer, running or newly opened.

    Neither case writes a new record or signature.
  - **`create` before its staging file is complete.** A crash after the marker is written, but before the staging file is complete (create step 3), leaves the marker and at most a torn staging file. `open` reports `CorruptTrail` ("marker without a trail"), and `create` reports `TrailExists`. No record was ever acknowledged, so the operator removes the directory and runs `create` again, which draws a new id that must be pinned. The rustdoc of `create` says so.
  - **Everything else is structural loss, refused with `CorruptTrail`:**
    - a live path missing without a staging file that can be promoted;
    - an empty live file;
    - a live file whose first complete record is not a checkpoint that links to the newest sealed segment, or to the genesis value for the first segment;
    - a missing head while the marker exists;
    - a head that does not match `expect_head`, which is `HeadMismatch`.

    vigil never guesses which case is innocent.
  - **An operator decides** with `vigil-audit resume --key <keyfile> --actor <who> --reason <why> --head <seq>:<hash> <dir>`. It continues the trail from the named head, which must be the last complete record found and is typically the last one verified against anchors or receipts. vigil never rewrites or prepends, so:
    - **A headless live file** (present, but its first complete record is no linking checkpoint) is sealed as it is. It is renamed, unchanged, to the next segment name, no-replace, and keeps its `SegmentStructure` findings forever as the record of the damage.
    - **A new live file** is then written through the staging file (sealing steps 2, 5 and 6), starting with an opening checkpoint that links to the named head. It is followed by a record with action `vigil.audit.resume`: the operator as actor, the reason, and the named head and the damaged file's name in `audit.details`.
    - **`seq` continues from the named head.** Records lost with a deleted live file therefore leave **no `SeqGap`**: the trail cannot know how many there were. The loss shows only through receipts, anchors, or `expect_head`.
    - **The verifier reports every `vigil.audit.resume` record as `Resumed`,** a warning that names the operator, the reason and the head. So plain verify passes with the decision visible, and `--strict` fails until a reviewer has accepted it.

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
  2. Verify the trail against the anchors and receipts, and choose the bound: the last checkpoint known good. After a clean stop, that is the final `close()` checkpoint. After a suspected compromise, it is the last checkpoint that matches an anchor.
  3. Generate the new key (`vigil-audit keygen`) and deploy it to every writer, removing the old key file.
  4. In the trust file, add the new key and set `through=<seq>:<hash>` on the old one.
  5. Confirm with `vigil-audit rotate --key <new keyfile> --actor <who> --reason <why> --bound <seq>:<hash> --expect-head <seq>:<hash> <dir>`. `--expect-head` is **mandatory**. It must come from the application's newest receipt or from an anchor, never from the disk. `rotate` refuses (`HeadMismatch`) unless the trail's head on disk is **exactly** that record, so records an attacker appended between steps 2 and 5 are never covered by the new key. *Where the expected head comes from after a clean stop* (`close()` returns nothing today): **Open — decided in [#66](https://github.com/vig-os/vigil/issues/66); #12/#13 must not implement them before #66 is accepted.** `vigil-audit checkpoint`, the other command an operator signs with, takes the same mandatory `--expect-head` with the same exact-head rule. After passing the check, `rotate` writes two things signed by the new key: a record with action `vigil.audit.key_rotated` (actor, reason, and `audit.details` naming the old key and the bound), and a checkpoint. vigil never removes records, so nothing after the bound is cut.
  6. Start the writers with the new key.

  **The outcome depends on the branch.**
  - **After a clean stop** (the bound is the last old-key checkpoint), the trail verifies with no error.
  - **After a compromise,** every old-key checkpoint above the bound stays `UntrustedKey`, an error, for good. Those checkpoints are exactly the ones an auditor must look at, and the report shows them next to the `vigil.audit.key_rotated` record that acknowledges them. The records between the bound and the confirming checkpoint are covered by the new key, and the operator vouches for them in step 2.

  A key that was never trusted, or one removed from the file, makes its checkpoints `UntrustedKey`.
- **Trust file format** (for `TrustPolicy::from_file` and `--trust`). UTF-8 lines; blank lines and lines starting with `#` are ignored:
  - `trail <32 hex> [comment]` starts a section and pins that trail id (decision 8). At least one is required.
  - `ed25519 <64 hex> [through=<seq>:<blake3:hex>] [comment]` lists a key trusted **for the trail of the section it is in**. A key line before the first `trail` line is a parse error.
  - **Revocation scope** (whether revoking a key on one trail revokes it on every trail that lists it, and how bounds combine): **Open — decided in [#66](https://github.com/vig-os/vigil/issues/66); #12/#13 must not implement them before #66 is accepted.**
  - `TrustPolicy::new()` with `.trail(id)`, which returns a section builder with `.key(public_key)` and `.key_through(public_key, seq, hash)`, builds the same in code.
- **Keep the trust file outside the trail directory,** for example in the verifier's configuration or a reviewed repository. The marker `audit.trail` lives in the writable directory, so it is never a trust input.

### 10. Anchoring (optional)

- **What an anchor is.** A checkpoint line copied to a place the attacker cannot rewrite: another host, WORM storage, a ticket, a mail.
- **vigil 1.0 provides:**
  - `AuditTrail::checkpoint()`, which returns the `Checkpoint` just written, with its line;
  - `vigil-audit checkpoints <dir>`, which prints the checkpoint lines;
  - `vigil-audit verify --anchor <file>`, which requires every anchored checkpoint to be in the trail with the same `trail`, `seq` and `hash`. A missing or different checkpoint is `AnchorMismatch`.
- **Push.** With `push` (ADR-0006, [#41](https://github.com/vig-os/vigil/issues/41)), audit lines can ship to a backend like any log, and that backend becomes an anchor.
- **What anchoring adds.** A trail rewritten and re-signed with a stolen key no longer matches the anchors.
- **Deferred to [#57](https://github.com/vig-os/vigil/issues/57):** RFC 3161 timestamp tokens, transparency-log submission, and a public consistency-proof API for anchor holders. They need ASN.1/DER and HTTP, and none of them changes the v1 encoding.

### 11. Verify API and CLI contract (#13)

- **Library:**
  - `vigil::audit::verify(dir: &Path, trust: &TrustPolicy) -> io::Result<Report>`;
  - `Verifier::new(trust)` with:
    - `.anchor(Checkpoint)`;
    - `.start_from(Checkpoint)`, for a trail whose older segments are archived: a checkpoint supplies `seq`, `prev_hash` and peaks.
      - **When a start checkpoint is accepted, and how anchors, revocation pins and receipts below it are reported** (including the `OutOfRange` finding and `--strict`'s behaviour): **Open — decided in [#66](https://github.com/vig-os/vigil/issues/66); #12/#13 must not implement them before #66 is accepted.** A start checkpoint signed by a stolen, not yet revoked key must not be able to demote anchors.
      - **The archive is verified on its own.** `vigil-audit verify <archive dir> <live dir>`, or `verify_files` over both sets, checks everything in one run, with no start. The operator verifies the archive once before moving it, and keeps the start checkpoint line with it.
    - `.receipts(impl IntoIterator<Item = (u64, [u8; 32])>)`: reconcile records against the application's receipts (decision 5);
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
  - errors: `Unparsable`, `UnknownVersion`, `UnknownField`, `MissingField`, `InvalidField`, `HashMismatch`, `ChainBroken`, `SeqGap`, `SeqConflict` (two different records with one `seq`), `TrailMismatch`, `MmrMismatch`, `BadSignature`, `UntrustedKey`, `RevocationMismatch`, `RevocationUnconfirmed`, `SegmentStructure`, `AnchorMismatch`, `StartMismatch`, `StaleHead`, `NoReceipt`, `ReceiptMismatch`;
  - warnings: `TornWrite`, `Resumed`, `ClockWentBackwards`, `DuplicateRecord` (the same record twice: a Collector can redeliver a line, and in vigil's own files a duplicated line changes no content);
  - info: `UncoveredTail` (and `OutOfRange`, whose rules are open in [#66](https://github.com/vig-os/vigil/issues/66)).
- **How it verifies.** Records are ordered by `seq`, from vigil's segment order or from any order in shipped copies. Every record is checked; nothing stops at the first error. The first error in `seq` order is the **first broken link**, reported with file, line, `seq`, expected and found hash.
- **Locking and offline use.** The verifier takes no lock and verifies a snapshot, using ADR-0002 decision 12's retry. Following ADR-0037 §1, it needs only the trail files, the trust file and local anchors: no network.
- **CLI** (`vigil-audit`, std-only argument parsing, `required-features = ["audit"]`):

  ```text
  vigil-audit verify --trust <file> [--trail <id>] [--receipts <file>] [--anchor <file>]... [--start-from <file>] [--max-age <duration>] [--strict] [--json] <dir|file>...
  vigil-audit checkpoints <dir>
  vigil-audit checkpoint --key <keyfile> --expect-head <seq>:<hash> <dir>
  vigil-audit rotate --key <keyfile> --actor <who> --reason <why> --bound <seq>:<hash> --expect-head <seq>:<hash> <dir>
  vigil-audit create --key <keyfile> --service <name> <dir>
  vigil-audit resume --key <keyfile> --actor <who> --reason <why> --head <seq>:<hash> <dir>
  vigil-audit keygen <keyfile>
  ```

- **Exit codes.** `0`: no error findings. With `--strict`, also no warnings and no uncovered tail. `1`: at least one error finding (or, with `--strict`, a warning or an uncovered tail). `2`: usage or I/O error.
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
    - Every strict prefix of a valid line (each cut point, including inside a multibyte character) is `TornWrite`.
    - A line with a duplicate key at any level is `InvalidField`.
    - A non-canonical integer is `InvalidField`, as is an `observedTimeUnixNano` that differs from `timeUnixNano`.
  - **Wrong trail.** A second trail created with the same key, or the trail re-created after deletion, is `TrailMismatch` against the pinned id.
  - **Revocation.**
    - With the old key: cut back to the bound and forge records and a checkpoint above it → `RevocationUnconfirmed`; forge below the bound → `RevocationMismatch` or `HashMismatch`.
    - Following the procedure exactly after a clean stop → no error.
    - The compromise branch → `UntrustedKey` exactly for the old-key checkpoints above the bound, and the `vigil.audit.key_rotated` record present.
    - An old-key writer left running → `UntrustedKey`.
  - **Forged appends under an honest key.** An attacker appends correctly chained records between operator steps 2 and 5. `rotate` with `--expect-head` from the receipt gives `HeadMismatch`, and nothing is signed. Records appended under a running writer and then covered by its checkpoint are `NoReceipt` with `--receipts`, within the range #66 decides.
  - **Trust scoping.** A key line before any `trail` line fails to parse. `--trail` with an unpinned id exits 2. The cross-trail revocation tests follow #66.
  - **Archiving.** Archive and live verified together report the same findings as before the move. The `--start-from` tests follow #66.
  - **Resume.** On a headless live file, the file is renamed unchanged and a new live file starts with an opening checkpoint. On a deleted live file, `seq` continues with no `SeqGap`. In both, `Resumed` is a warning and `--strict` exits 1.
  - **Display-only fields.** `severityNumber` other than 9, a different `severityText`, an extra `LogRecord` field, or a duplicate key that only differs by an escape → error.
  - **Inserted fragments.** End-of-input fragments inserted between linked records → `TornWrite` warnings, reported by length only, and `--strict` exits 1.

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
  - **Fixture trails** under `tests/fixtures/audit/v1/`, generated with fixed seeds, a fixed trail id and an injected clock. They cover multi-segment, rotation, a key rotation, a torn write and an uncovered tail. Tampered variants carry the findings they must produce.
  - **Frozen at 1.0.0.** Once the 1.0.0 tag exists, a CI step fails if any file under `tests/fixtures/audit/v1/` differs from the tag.
- **Dependency bumps cannot change the format.** BLAKE3 output is fixed by its specification and Ed25519 signatures by RFC 8032, so a bump of `blake3` or `ed25519-dalek` changes no byte; the golden vectors catch it if one ever does. Neither crate's types are public, so a major bump of either is invisible to users.
- **Collector copies.** The promise covers vigil's own files and copies whose attribute values are unchanged. A shipper that rewrites values is outside it.

### 13. Public surface (feature `audit`, under ADR-0004's rules)

Only vigil's own types and std appear. Hashes and keys are byte arrays, not `blake3` or `ed25519-dalek` types. Following ADR-0004 decision 5, configuration is by builder methods on structs with private fields.

**`audit` reads no `VIGIL_*` environment variable**, unlike telemetry. Its policy decides what is durable and what is signed, so it must be in reviewed code or the operator's deployment, not in an environment a process inherits.

| Item | Why it is public |
|---|---|
| `AuditConfig` (`new(service)`, `dir`, `max_bytes`, `checkpoint_every`, `checkpoint_interval`, `mirror_to_logs`, `expect_head(seq, hash)`, `create(self, signer)`, `open(self, signer)`, `resume(self, signer, head, actor, reason)`) | Creating (explicitly, once), opening with the head the application last saw, and the operator's resume decision (decision 8). |
| `AuditTrail` (`record`, `checkpoint`, `close`, `dir`, `trail`), `Send + Sync` | The trail handle, shared across threads. |
| `Entry` (`new(actor, action, object)`, `reason`, `before`, `after`, `details`) | One audited action (decision 3). |
| `Value` (`Text`, `Digest`; `Value::digest_of(&[u8])`), `#[non_exhaustive]` | A before or after value, or its digest. |
| `Receipt` (`trail`, `seq`, `hash`, `hash_string`, `unsigned_records`) | Stored by the application with its own record: an application-side anchor (decision 5), and the signal that signing is behind (decision 6). |
| `Checkpoint` (`seq`, `mmr_size`, `mmr_root`, `key_id`, `line`, `parse`) | Anchors and verification start points (decisions 10, 11). |
| `Signer`, `SignerError`, `KeyFileSigner`, `keygen` | Key custody (decision 9). |
| `TrustPolicy` (`new`, `trail` → section with `key`, `key_through`; `from_file`) | The verifier's trust input: pinned trail ids, each with its own keys and revocation bounds (decision 9). |
| `verify`, `Verifier`, `Report`, `Finding`, `FindingKind` and `Severity` (both `#[non_exhaustive]`, `Copy + Eq + Debug`) | The verify contract (decision 11). |
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
  - `curve25519-dalek`, `ed25519-dalek` and `subtle` are BSD-3-Clause only, so the PR that adds them (#12) adds BSD-3-Clause to the allowlist and justifies it there: permissive, notice-retaining, and compatible with Apache-2.0 distribution.

  **For #12:** `curve25519-dalek`, `ed25519-dalek` and `subtle` are BSD-3-Clause only. #12 must add BSD-3-Clause to `deny.toml` with a justification in that PR.

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
- **Dependencies.** 17 more crates with `audit` on, and BSD-3-Clause in the licence allowlist.
- **Tessera.** Its interoperability costs vigil nothing now, and it keeps the adoption path open without making vigil's promise depend on tessera's release schedule.

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

## References

- [vig-os/vigil#10](https://github.com/vig-os/vigil/issues/10) (requirement framing; owner decision 2026-10-11), [#11](https://github.com/vig-os/vigil/issues/11), [#12](https://github.com/vig-os/vigil/issues/12), [#13](https://github.com/vig-os/vigil/issues/13), [#41](https://github.com/vig-os/vigil/issues/41), [#46](https://github.com/vig-os/vigil/issues/46), [#47](https://github.com/vig-os/vigil/issues/47), [#49](https://github.com/vig-os/vigil/issues/49), [#56](https://github.com/vig-os/vigil/issues/56), [#57](https://github.com/vig-os/vigil/issues/57), [#58](https://github.com/vig-os/vigil/issues/58), [#59](https://github.com/vig-os/vigil/issues/59)
- Path-to-1.0 pre-mortem, 2026-10-10 (finding R3)
- [ADR-0001](0001-on-disk-format.md) (format, bounded lines, conformance oracle), [ADR-0002](0002-rotation-and-retention.md) (rotation machinery), [ADR-0004](0004-public-api-and-stability.md) (public API and stability)
- [vig-os/tessera](https://github.com/vig-os/tessera) at `f08255d`: `docs/CONSUMING.md`, ADR-0028, ADR-0036, ADR-0037, ADR-0052, ADR-0058, `tessera-core/src/{hash,signing,manifest}.rs`
- 21 CFR Part 11 §11.10(e); EU GMP Annex 11 §9; IEC 62304
- [BLAKE3 specification](https://github.com/BLAKE3-team/BLAKE3-specs); [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) (Ed25519); [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) (Merkle tree hashing); [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) (time-stamp protocol)
- Rust 1.95.0 std `library/std/src/sys/fs/unix.rs` (`fsync`/`datasync` on Apple)
