---
type: issue
state: open
created: 2026-10-12T12:49:11Z
updated: 2026-10-12T12:49:11Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/112
comments: 0
labels: none
assignees: none
milestone: 1.0.0 — stable
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:25.368Z
---

# [Issue 112]: [metrics: honour a shutdown_with_timeout shorter than the SDK's fixed 5 s reader wait](https://github.com/vig-os/vigil/issues/112)

ADR-0003 decision 4 and architect ruling 7b1-d5 document that opentelemetry_sdk 0.33's periodic reader waits a fixed 5 seconds during shutdown. With a blocked metrics export, shutdown_with_timeout(100 ms) can therefore take about 5 seconds and reports metrics Timeout.

Make a shorter caller timeout bound the wait while preserving safe provider/storage cleanup and per-signal outcomes. This is non-breaking: it only shortens a wait.

References: ADR-0003 decision 4; ruling 7b1-d5; PR #106; #7.
