---
type: issue
state: open
created: 2026-11-10T11:20:07Z
updated: 2026-11-10T11:20:07Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/214
comments: 0
labels: feature, priority:medium, effort:large
assignees: none
milestone: none
projects: none
parent: none
children: none
synced: 2026-11-11T08:55:55.685Z
---

# [Issue 214]: [feat(audit): `vigil-journal` — journald cursor bridge for non-instrumented services](https://github.com/vig-os/vigil/issues/214)

### Description

A long-running `vigil-journal` bridge (sibling crate, matching the `vigil-audit` convention) reads `systemd-journald` by cursor and writes vigil records — log signal and/or audit trail — fail-closed, covering standard host services vigil cannot instrument: `sshd`, `sudo`, `systemd` unit state, `zfs`, auditd (via its journald bridge), `versitygw` access logs.

### Problem statement

Those services land in journald today. Loki is the usual escape hatch and it loses records silently: in one production fleet a Loki copy of guest journals was found missing ~3.6 % of every hour, with no counter or alert noticing. vigil's own stance is the opposite — lossless sink (ADR-0005 §6), fail-closed (§1), "the file is the durable copy" (ADR-0006 §1). Without a bridge, those services sit outside both the log signal's durability and the audit trail's integrity.

### Proposed solution

A separate long-lived writer, not a `vigil ingest` (#208) consumer: the audit trail needs a single writer holding the directory lock (ADR-0005 §9), and durable cursor state belongs inside the trail.

- **Read by cursor** (`sd_journal_seek_cursor` / `journalctl --show-cursor` semantics). Resume from the last written cursor; without one, `--start-at head|tail|boot` (`tail` default). `--follow` with a poll fallback.
- **Cursor inside every record.** Each vigil record carries `journal.cursor=<cursor>`, `journal.boot_id=<32 hex>`, `journal.seqnum=<int>` (as OTLP attributes or inside `audit.details`). A gap between two vigil records is a *provable* range of journal entries. The resume point is read off the trail's last record — not a side file (cf. #138, "resume checkpoint handed to the caller").
- **Fail-closed.** Writer refuses to advance on signer/disk failure (§6); the bridge stops reading, logs once, exits non-zero. Shape follows ADR-0006 §1 bounded-loss: journald buffers in its own files while the bridge is stopped, so no loss if the operator reacts before journald rotates.
- **Field mapping** (ADR-0005 §3):
  - `MESSAGE` → `body` (log) or `audit.details` (audit).
  - `_SYSTEMD_UNIT`, `_HOSTNAME`, `PRIORITY`, `SYSLOG_IDENTIFIER`, `_PID`, `_UID`, `_BOOT_ID` → OTLP attributes (`log.systemd.unit`, severity from `PRIORITY`).
  - `_AUDIT_TYPE_NAME`, `_AUDIT_SESSION`, `_AUDIT_LOGINUID` → `audit.action` / `audit.object` / `audit.actor` when routed to the audit trail (behind `--audit-match '_TRANSPORT=audit'`).
  - Binary `MESSAGE` → `Value::Digest` plus a sidecar blob the application keeps (§3 "before/after digest").
  - Line cap: 1 000 000 bytes (§3 framing); over-cap truncates with `journal.truncated=1`, never silently.
- **Routing.** `--route log` (default), `--route audit` (requires `--key`), `--route both`. One instance per trail per service.
- **Optional FSS verification.** When the journal has Forward Secure Sealing, `--verify-fss` runs `journalctl --verify` before vigil seals a segment and refuses to continue on failure; records the verdict.
- **Resume semantics.** Clean restart: zero duplicates, zero loss (cursor is exact). SIGKILL/power loss: at-least-once — up to one re-emitted entry since the last fsynced record (§6 fsync-per-record aligns).

### Alternatives considered

- **Pipe `journalctl -f --output=json` into `vigil ingest` (#208).** No durable cursor across restarts, no FSS hook. Workable for logs, not for the audit trail.
- **Loki-/Alloy-side rewriter.** Needs a second format and contradicts ADR-0006 §1.
- **Log signal only.** Fine for sshd/zfs; misses auditd where integrity matters.

### Additional context

Consumer side (pull into tessera, verify MMR, seal anchors) is fleet work, not vigil's — mentioned because it motivates the cursor-in-record rule: the consumer must prove nothing fell between two verified vigil records.

### Impact

Additive. New binary/crate; no change to `vigil-audit`'s stable surface. ADR-0005 v1 format unchanged (ordinary log and audit records). Stability-adjacent: a semantic-conventions namespace question (`log.systemd.*` or `journal.*`).

### Acceptance criteria

- `vigil-journal` runs non-root with CAP_DAC_READ_SEARCH over `/var/log/journal`, no setuid.
- Property test: for any replay offset in the cursor range, the trail verifies clean (§11) with no gap outside a declared restart.
- Runbook: "verify no journal gap between vigil records A and B" reads cursors out of the records and runs `journalctl --cursor` on both ends.
- A reference NixOS module so a host can enable it in one line.
- `--verify-fss` tested against trails with and without FSS enabled.

### Open questions

- Feature on `vigil-audit` (`journal`) or sibling crate `vigil-journal`? libsystemd is C, so a sibling keeps `vigil-audit`'s SOUP list clean (ADR-0005 §14 `pure` rationale).
- OTLP semantic conventions for systemd/kernel fields: adopt an upstream namespace or reserve `journal.*` under `audit.details`?
- Default routing: log, audit, or both?
- Does `_AUDIT_*` from auditd always route to the audit trail, or stay a routing choice?

