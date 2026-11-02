---
type: issue
state: closed
created: 2026-10-12T13:29:43Z
updated: 2026-10-13T00:17:42Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/113
comments: 2
labels: bug
assignees: none
milestone: 1.0.0 — stable
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:25.025Z
---

# [Issue 113]: [lifecycle: FlushError Display for a metrics-only failure omits the part wording and is untested](https://github.com/vig-os/vigil/issues/113)

Found by the final-round falsifier on #106 (e4239ac).

`src/lifecycle.rs:97-118`: when metrics fail or time out and no log records are lost, Display renders `Failed: <metrics text>`, without the `metric export failed` / `metric export timed out` part wording that the two-signal case uses (`Failed: at least 2 log records lost: <logs text>; metric export failed: <metrics text>`). No test covers this case.

Expected: every part carries its own wording, so the metrics-only case reads `Failed: metric export failed: <metrics text>` (and the same for `Timeout`). Add a Display unit test for metrics-only Failed and Timeout, plus logs-only with and without source text.

Open question, to be ruled when this is briefed: ADR-0004 (l.151 `InitError`, l.159 `FlushError`, l.262 `PropagationError`) lists `Display` but does not say whether its text is covered by the 1.0 stability promise. Proposed (Rust ecosystem convention): error Display text is not part of the promise; consumers match on `kind()` and `lost()`. Record the ruling as an ADR-0004 statement before 1.0.0, so this fix is non-breaking by contract rather than by assumption.

---

# [Comment #1]() by [gerchowl]()

_Posted on October 12, 2026 at 03:11 PM_

**Architect ruling 113-d1: error `Display` text is not part of the 1.0 stability promise.**

- **What is promised.** The programmatic surface of every public error type: the type, `kind()` and its `#[non_exhaustive]` kind enum, `lost()`, and `source()` chaining.
- **What is not promised.** `Display` and `Debug` text is human-readable diagnostics. It may change in any release, patch releases included. Every change is listed in the CHANGELOG. Programs must not parse it, and the rustdoc of each error type says so.
- **Why.** This is the Rust ecosystem convention, and it is what lets fixes like this issue land in a patch without breaking anyone. The alternative would freeze wording such as `Failed: <metrics text>` forever, including its bugs.
- **Where it is recorded.** As an ADR-0004 statement in the stability section. It covers `InitError` (l.151), `FlushError` (l.159), `PropagationError` (l.262) and the audit errors. The README's stability text links to it. This lands before 1.0.0, in the same PR as the Display fix.
- **Scheduling.** The fix touches `src/lifecycle.rs`, which #114 (7b2a) also edits, so it is briefed after #114 lands.

The owner can overrule this before 1.0.0. Nothing has been released, so changing the ruling costs nothing.


---

# [Comment #2]() by [gerchowl]()

_Posted on October 13, 2026 at 12:17 AM_

Fixed in #130, merged into dev at fe9e46d.

