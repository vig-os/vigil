---
type: issue
state: closed
created: 2026-10-12T03:32:26Z
updated: 2026-10-12T04:29:27Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/100
comments: 1
labels: bug
assignees: none
milestone: 0.3.0 — audit trail
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:26.544Z
---

# [Issue 100]: [fix(audit): signer-failure report panics when stderr is unwritable (eprintln! on the record path)](https://github.com/vig-os/vigil/issues/100)

## What
`Sink::signer_failed` (`src/audit/sink.rs:~474` on dev ab81238, introduced earlier at 843fbcf l.427) reports a signer failure with `eprintln!`. `eprintln!` panics when the write to stderr fails. So with the signer down and stderr unwritable (full pipe, `/dev/full`, a closed fd), `record` panics instead of returning a result.

## Evidence
PR #99's falsifier ran a child process with stderr on `/dev/full`, a failing signer and `checkpoint_every=1`. It exited 101 (panic) and wrote nothing. A standalone `eprintln!` with `2>/dev/full` also exits 101.

## Why it matters
ADR-0005's signer-failure rule (decision 8, l.~441–446) says the record is still written and acknowledged and the failure is "reported once on stderr". Reporting must never turn into a panic on the audit write path, and ADR-0005 decision 1 (fail closed, typed errors) has no panic outcome. `Drop` already does this correctly (`let _ = writeln!(stderr().lock(), …)`).

## Fix
- Use the same non-panicking write as `Drop` for every stderr report in `src/audit/`.
- Grep `src/` for any other `eprintln!`/`println!` on library paths, and fix or justify each.
- Add a regression test: stderr unwritable plus a failing signer → `record` returns normally, through the `cfg(test)` stderr hook PR #99 added.

## Acceptance
- No `eprintln!` on library paths.
- The test fails before the fix (exit 101) and passes after.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 12, 2026 at 04:29 AM_

Fixed in PR #103 (merged 8591bcd). A child process with stderr on /dev/full exits 101 before the fix, and no library path prints any more.

