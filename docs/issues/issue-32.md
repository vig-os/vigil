---
type: issue
state: closed
created: 2026-10-09T19:15:38Z
updated: 2026-10-09T20:20:50Z
author: gerchowl
author_url: https://github.com/gerchowl
url: https://github.com/vig-os/vigil/issues/32
comments: 1
labels: bug, priority:high, effort:small
assignees: none
milestone: 0.1.0 — logs core
projects: none
parent: none
children: none
synced: 2026-10-18T00:53:38.804Z
---

# [Issue 32]: [fix(init): #[must_use] Guard, no stderr flood after shutdown, runtime-error and env consistency](https://github.com/vig-os/vigil/issues/32)

**Milestone review findings, confirmed:**
1. **Major: `Guard` lacks `#[must_use]`** (`src/init.rs:36`). `vigil::init("probe").unwrap();` compiles without a warning, drops the guard immediately and **loses 100% of logs** (0 records written). **Fix:** `#[must_use = "dropping the guard flushes and shuts down logging; bind it: let _guard = vigil::init(..)"]` on `Guard` (and on `init`/`Config::init` return values if needed). Doctest or compile-fail check.
2. **Major: stderr flood after shutdown.** After the guard drops, every event prints `WARN BatchLogProcessor.Emit.AfterShutdown` (1000 events → 1000 lines); logging in destructors/atexit floods stderr. **Fix:** after shutdown, drop events silently except for **one** stderr warning (e.g. a filter or atomic flag in the bridge layer, or rate-limit SDK warnings by name).
3. **Minor: runtime I/O errors.** The rustdoc (`src/init.rs:61`) says "I/O failures fall back to stderr with one warning", which is true only at open. At runtime (live file replaced by a dir), all records were lost and stderr got one `ExportError` per batch. **Fix:** make the docs accurate and rate-limit runtime export errors to stderr (first error + periodic summary with the count of dropped records), and test it.
4. **Minor: env consistency.** A relative `VIGIL_DIR=rel` is accepted silently (relative XDG/HOME are rejected): reject it with a warning and use the default resolution. An invalid `RUST_LOG` (`info,[`) silently falls back to `info`: warn once.
5. **Unverified, cheap:** on macOS `host.name` is probably missing (no `/proc`, `/etc/hostname`; `HOSTNAME` usually not exported). Use `rustix::system::uname().nodename()` (rustix is already a dependency) as the primary source.
6. Docs: the README notes that `fork` after `init` leaves the child sharing the parent's lock with no batch worker (call `init` after forking).
Refs: #5.
---

# [Comment #1]() by [gerchowl]()

_Posted on October 9, 2026 at 08:20 PM_

Done in #33: `#[must_use]` Guard (compile_fail doctest), exactly one stderr line after shutdown, runtime export errors rate-limited (first + per-minute + shutdown summary with drop counts), relative VIGIL_DIR rejected, invalid RUST_LOG warns once, host.name via uname, fork note. Independently verified.

