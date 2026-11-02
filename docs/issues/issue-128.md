---
type: issue
state: closed
created: 2026-10-12T23:10:43Z
updated: 2026-10-13T00:17:45Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/128
comments: 2
labels: chore
assignees: none
milestone: 0.2.0 — metrics + traces
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:22.923Z
---

# [Issue 128]: [test(metrics): Prometheus conformance harness follow-ups from #122 review](https://github.com/vig-os/vigil/issues/128)

These are the review nits on #122 at 59c6d51, which was merged at 0c51c9a. None of them is a false pass. Fold them into the next metrics-touching PR (#113).

1. **The second-attempt log test is shallow.** `test_second_attempt_failure_reports_second_attempt_log` stubs out `start_servers`, the function that picks the attempt. So mutants that return `prometheus-0.log` from `start_servers`, or force `attempt = 0`, both survive. The fix is to test the attempt-to-log mapping where it is chosen.
2. **`query()` retry edge cases are untested.** Removing the deadline check before the request survives, and so does sleeping past the deadline. Add tests that kill both mutants.
3. **The retry classification is wrong.**
   - `HTTPError` is a subclass of `URLError`, so a malformed query (HTTP 400) is retried until the 60 s deadline instead of failing at once.
   - `http.client.IncompleteRead` and `JSONDecodeError` are not retried, and they end in a traceback.

   Retry only transient transport errors, fail fast on a 4xx, and treat a truncated or invalid response as transient within the deadline.
4. **The README mapping table leaves two rules out.**
   - Inner `ratio` words are dropped for a gauge with unit `1`: `app.ratio.x` → `app_x_ratio`.
   - A leading `_` is added before a name that starts with a digit.
5. **The scope test contradicts ruling 7b3-d2.** `oracle_scope_matches_declaring_package` pins the literal `"vigil-telemetry"`, so a package rename would break it. The architect's round brief asked for this, and that request conflicts with the ruling. Make it independent of the package name while still guarding against a hardcoded literal: the guard against `"vigil"` in `package_scope()` must remain. The e2e is the real oracle.
6. **CHANGELOG formatting.** The "Fixed" entry from #122 is followed by a stray blank line that splits the list.

---

# [Comment #1]() by [gerchowl]()

_Posted on October 12, 2026 at 11:12 PM_

**Architect ruling on item 5:** delete `oracle_scope_matches_declaring_package`. Pinning the literal contradicts ruling 7b3-d2, because a package rename must not break the tests. Comparing `env!` with `env!` proves nothing. The end-to-end run is the guard: the #122 review showed it fails when the scope is hardcoded to `vigil`. Add a one-line comment at `package_scope()` that says so. This issue is folded into #113's PR (briefs/113.md).

---

# [Comment #2]() by [gerchowl]()

_Posted on October 13, 2026 at 12:17 AM_

Fixed in #130, merged into dev at fe9e46d.

