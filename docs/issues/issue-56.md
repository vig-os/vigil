---
type: issue
state: open
created: 2026-10-10T23:19:59Z
updated: 2026-10-10T23:19:59Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/56
comments: 0
labels: feature, priority:backlog, effort:medium
assignees: none
milestone: none
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:32.671Z
---

# [Issue 56]: [perf(audit): group commit and an atomic batch record API](https://github.com/vig-os/vigil/issues/56)

Deferred from ADR-0005 (#10), decision 6.

ADR-0005 makes `AuditTrail::record` write and fsync each record before it returns `Ok`. The probe on vm-dev (virtio ext4, 2026-10-11) measured write + `sync_data` at p50 23–34 ms, which is 30–37 records/s per trail. One fdatasync per 64 records reached about 1 970 records/s. That is enough for operator actions at human rate, which is the 1.0 scope. It is not enough for bulk imports.

**Scope:**
- Group commit inside one process. Concurrent `record` callers that are waiting on the trail share one write(2) and one fsync. Each caller still gets `Ok` only after the fsync that covers its record has returned.
- An additive `record_all(&[Entry])`: one write and one fsync, all-or-nothing.

Neither changes the v1 on-disk format or the meaning of `Ok`, so both are minor releases after 1.0.

**Acceptance:** a test shows N threads get no `Ok` before their record is durable (fault-injected fsync). A benchmark in the #49 harness shows the throughput gain. ADR-0005 decision 6 is updated as an implementing detail.
