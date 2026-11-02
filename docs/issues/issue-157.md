---
type: issue
state: closed
created: 2026-10-17T23:48:55Z
updated: 2026-11-02T04:53:45Z
author: vig-os-release-app[bot]
author_url: https://github.com/vig-os-release-app[bot]
url: https://github.com/vig-os/vigil/issues/157
comments: 1
labels: bug
assignees: none
milestone: none
projects: none
parent: none
children: none
synced: 2026-11-02T13:59:41.651Z
---

# [Issue 157]: [Release 0.1.0 failed — automatic rollback](https://github.com/vig-os/vigil/issues/157)

Release 0.1.0 failed during the automated release workflow.

**Workflow Run:** [View logs](https://github.com/vig-os/vigil/actions/runs/39080231720)
**Release PR:** #155

**Automatic rollback attempted:**
- Release branch: this run's finalize commit(s) reverted, but only when the branch tip matched exactly what the run wrote — otherwise the branch is left untouched and the rollback step fails loudly instead (vig-os/devkit#1462)

**Tag status (forward-fix policy):**
- Release tags are not deleted by automation (workflow choice; GitHub immutable-release lock-in applies only after a release is **published** when that setting is enabled). If a tag was pushed before the failure, it remains on the remote.
- Use a new release candidate to validate fixes, then re-run the final release when ready.
- If a draft GitHub Release exists, manage it from the Releases UI; **publishing** locks the linked tag and assets when **immutable releases** are enabled.
---

# [Comment #1]() by [gerchowl]()

_Posted on November 2, 2026 at 04:53 AM_

Resolved. The two refused final runs (draft release PR, then failed CI on #155) were rolled back automatically and fixed through #159 (#158) and the #155 ready transition. The later final run 39084085125 succeeded: tag 0.1.0 and the draft Release v0.1.0 exist. Promotion is tracked on #155.

