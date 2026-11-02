---
type: issue
state: closed
created: 2026-10-12T01:21:50Z
updated: 2026-10-12T16:20:55Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/96
comments: 3
labels: bug
assignees: none
milestone: 0.2.0 — metrics + traces
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:26.944Z
---

# [Issue 96]: [test(logs): r2_many_scopes_pack_without_copying_batch asserts wall-clock < 3s and fails under host load](https://github.com/vig-os/vigil/issues/96)

## What
`src/logs.rs:691` `r2_many_scopes_pack_without_copying_batch` (from 5f17b75) asserts `elapsed < Duration::from_secs(3)` (l.~706). A reviewer of PR #93 saw it fail 4 times (3.8–4.1 s) at host load average 69 under `--cfg vigil_unstable`, and pass at 1.62 s once the load dropped. The code is not at fault: the failure comes from the test's wall-clock budget.

## Why it matters
A wall-clock assertion in the unit suite is a flaky gate: it fails on loaded CI runners and shared hosts with no regression in the code. The test's intent is "packing many scopes does not copy the batch" (a complexity property). That property should be pinned in a way that does not depend on timing.

## Proposed fix
Assert the property directly, not wall time. Options:
- count the copies or allocations, via a counting sink or an instrumented clone path behind `cfg(test)`;
- compare the scaling between N and 4N scopes (the ratio ≪ 16), still timing but robust to a uniform slowdown;
- move the absolute-time check to the existing performance-comparison CI job.

## Acceptance
- No unit test asserts absolute wall time.
- A mutant that copies the batch per scope still fails a test.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 12, 2026 at 02:05 PM_

Architect ruling 96-d1: the acceptance "no unit test asserts absolute wall time" applies to performance/complexity properties. Tests asserting that an API honours its own deadline (e.g. shutdown_with_timeout returns within timeout + slack) are contract tests and stay. This PR replaces the logs.rs packing test's wall-clock bound with a deterministic proof (mutant: copy the batch per scope → fails) and inventories every other absolute-time assertion; any classified as performance get their own follow-up issue.

---

# [Comment #2]() by [gerchowl]()

_Posted on October 12, 2026 at 02:10 PM_

Architect ruling 96-d2: `review_many_scopes_release_benchmark` (#[ignore], src/logs.rs) asserts elapsed < 1s, a performance assertion in the file this PR owns, so it is in scope. Its assertion is removed and the test stays as an explicit ignored measurement that prints elapsed. The deterministic counting test pins the property. (Inventory-only still applies to src/init.rs and src/audit/**.)

---

# [Comment #3]() by [gerchowl]()

_Posted on October 12, 2026 at 04:20 PM_

Fixed by PR #115 (merge cd4a6cc): the wall-clock packing test is replaced by a deterministic allocated-bytes bound (dev-only `allocation-counter`), and the ignored release benchmark is a measurement only (ruling 96-d2). The remaining performance-classified timing assertions are #116.

