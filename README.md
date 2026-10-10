# vigil

*Verifiable Integrity-Guarded Instrumentation & Logging* (V·I·G·I·L): the opinionated observability crate for vig-os Rust projects.

> **Pre-alpha.** The design is settled; the code is being built. Logs are implemented; other signals and audit are being built. Track progress in the milestones.

## What it is

One crate, two layers:

- **Telemetry core** (every project). Your code uses [`tracing`](https://docs.rs/tracing) as usual; vigil bridges it into OpenTelemetry and writes **OTLP/JSON Lines** files that conform to the [OTel file-exporter spec](https://opentelemetry.io/docs/specs/otel/protocol/file-exporter/): one `LogsData` / `MetricsData` / `TracesData` per line, one signal per file, in the [OTLP/JSON encoding](https://opentelemetry.io/docs/specs/otlp/#json-protobuf-encoding) (64-bit ints as decimal strings, hex trace and span ids, integer enums, lowerCamelCase keys). Files rotate by size with age-based retention, and the rotation is safe when many processes write the same file. Loki (logs) and Prometheus (metrics) ingest OTLP natively.
- **`audit` feature** (opt-in). A separate, **lossless** audit trail of user actions on a device (who did what, when, and why) in the spirit of 21 CFR Part 11 §11.10(e). Records are still OTLP log records, hash-chained, with Merkle roots per segment and **ed25519-signed checkpoints**. They're built on [`tessera-core`](https://github.com/vig-os/tessera) primitives, so data provenance and audit provenance share one proof system.

```rust,no_run
let _guard = vigil::Config::new("my-service")
    .version(env!("CARGO_PKG_VERSION"))
    .init()?;
tracing::info!(user = "alice", "opened study");
# Ok::<(), vigil::InitError>(())
```

Logs are available now; metrics, traces and audit are planned. Keep the guard
alive until shutdown to flush queued logs. The batch queue holds 65,536 records by default (512 per export, every second).
Memory is bounded by queue size times record size; overflow drops records with
a stderr warning. `VIGIL_QUEUE_SIZE` or `Config::queue_size` changes the bound
(minimum 1, cap 1,048,576). Oversized environment and builder values clamp to
that cap with a warning. Measured memory is approximately 16 B per reserved
slot (16 MiB at the cap), plus approximately 0.4 KB per queued small record;
larger fields need more memory. Guard drop waits up to five seconds, including directory-lock waits,
then warns that remaining records may be lost; the SDK worker may continue
until the lock is released. `std::process::exit` skips flushing. Tracing
spans alone do not currently populate OTLP trace/span IDs.

Use `vigil::init("my-service")` for defaults. `RUST_LOG` defaults to `info`.
`VIGIL_DIR` selects the full state directory; otherwise vigil uses
`$XDG_STATE_HOME/<service>` or `$HOME/.local/state/<service>`.
Invalid numeric environment values emit a warning naming the variable and value
and use the default, except queue values above the cap clamp to the cap.
Empty `VIGIL_*` values are unset without warnings; relative `XDG_STATE_HOME`
and `HOME` are ignored, with rejected values explained if no path is available. `VIGIL_MAX_BYTES` has a minimum of 1 byte and defaults to 50 MiB and `VIGIL_RETENTION_DAYS` to 90
(`0` keeps everything). Explicit `Config` values override environment values.
`Config::revision` or `VIGIL_VCS_REVISION` supplies the producer commit.
Storage initialization failures emit one warning and fall back to stderr;
a second initialization returns an error before creating storage. An existing
`log` logger is preserved: initialization succeeds with one warning that `log`
records cannot reach vigil; tracing events continue to be written.

Call `init` **after forking**. A child forked after initialization inherits the
parent's directory lock and subscriber but has no batch worker; it cannot safely
continue using that logging instance.

Storage-open failures fall back to stderr. Runtime export failures drop the affected
records: the first error is reported on stderr, followed by cumulative dropped-record
summaries at most once per minute during failing exports and at shutdown if needed.
After the guard drops, events are discarded with one stderr warning.
`VIGIL_DIR` must be absolute; relative values warn and use the default resolution.
Invalid `RUST_LOG` values warn once and use `info`.

## Why not an existing crate

`tracing`, `opentelemetry` and `opentelemetry-proto` are the foundation and are used as-is. What's missing upstream: opentelemetry-rust has **no OTLP file exporter**, and every rotating-file crate (`file-rotate`, `logroller`, `log2`, `flexi_logger`, …) is thread-safe but not **multi-process** safe.

## Design

Decisions and their evidence are recorded as ADRs in [`docs/adr/`](docs/adr/): [0001 on-disk format](docs/adr/0001-on-disk-format.md) and [0002 multi-process rotation and retention](docs/adr/0002-rotation-and-retention.md).

## Development

Enter the pinned environment with `direnv allow` (or `nix develop`). `nix flake check` runs fmt, clippy, tests, doctests and docs. Changes enter through PRs to `dev`; `main` only takes release PRs.

### Changelog updates

Add entries under the existing `## Unreleased` heading. Fixes to features that
have never shipped belong in their `Added` entry. `.gitattributes` uses Git's
built-in union driver to retain concurrent additions; review the merged result
for ordering, duplicate entries and contradictory edits. Union merging joins
text and does not validate the changelog's meaning or structure.

Release sync uses `git merge-tree`, which honors union: a clean merge can still
retain both a release's `TBD` heading and its dated heading. The
`scripts/check_changelog.py` check rejects duplicate version headings (regardless
of date), duplicate Unreleased headings, repeated `###` section headings within
a version, and duplicate top-level list entries. List entries must be unindented;
indented sub-bullets are ignored so different parents may repeat explanatory
text. Unordered markers (`-`, `*`, `+`) and numbered markers (`1.`, `1)`, etc.)
are ignored when comparing entry text. Entries are deduplicated across the whole
version per section kind, including repeated sections and deeper headings;
the same text is allowed in different versions or kinds (such as Added and Fixed). It runs on every local commit and in `nix flake check` (and
therefore CI). Resolve reported duplicates before accepting a release-sync PR;
a conflict-free merge alone is insufficient. Run
`python3 scripts/check_changelog.py` to check a resolution locally. The check
ignores fenced examples and permits repeated bullet text in different sections;
editorial review is still needed for contradictory entries with different text.

GitHub's server-side **Update branch** does not honor this merge rule (see the
[GitHub support discussion](https://github.com/orgs/community/discussions/9288)).
Update locally with `git fetch origin` and `git rebase origin/dev`, review
`CHANGELOG.md`, then push the feature branch with `git push --force-with-lease`
if rebasing rewrote published commits. No custom driver configuration is needed.
The root `.gitattributes` is consumer-owned: devkit 1.18.0 ships no such template
path and its scaffold does not delete consumer files.
[Changelog fragments are requested upstream](https://github.com/vig-os/devkit/issues/1858)
to avoid shared-file edits during parallel work.

## License

Apache-2.0.

## Conformance

Run `nix develop -c python3 scripts/conformance.py` locally. The dev shell pins
Collector-contrib through `flake.lock` and prints its version. On every PR, the
Collector reads rich, rotated logs from `examples/conformance.rs`, skips empty
and garbage lines, and exports JSON for a multiset comparison with the manifest.
The comparison checks complete resources, scopes and records, including nested
attributes, bodies, severity, timestamps and trace/span IDs across two resources,
allowing protobuf
default omission and integer spelling changes. Valid unterminated final records
are delivered; unterminated garbage is dropped. Metrics (#7) and traces (#8) are
planned extensions.
