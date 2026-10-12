# Stable API review

`public-api.txt` is the all-features stable surface, including hidden items, on
the flake-pinned compiler.
`allowlist.json` names its justified item paths, required declaration kinds and accepted ADRs. Audit format
primitives are `vigil_unstable` only (ADR-0005 decision 13); the stable audit
writer joins ADR-0004's lifecycle,
composition and rotating-file surface. Standard trait implementations belong to
the listed type's contract. Exporters, sinks and OpenTelemetry re-exports require
`vigil_unstable` and must never enter this snapshot.

Run inside `nix develop`:

```sh
python3 scripts/check_public_api.py
# After reviewing the API change and its ADR justification:
python3 scripts/check_public_api.py --update
```

Both commands enforce the allowlist before writing anything. The check builds
rustdoc JSON with `RUSTC_BOOTSTRAP=1`, all features and controlled stable compiler
and rustdoc flags, then runs `cargo public-api --rustdoc-json … -sss`. It repeats
with `--document-hidden-items`, checks public re-export targets in JSON as well
as printed paths, explicitly rejects public `extern crate` items for forbidden
upstreams (including aliases and hidden items), and rejects empty/root-only
surfaces. Each public declaration must match its independently allowlisted kind:
a macro or extern crate cannot reuse an approved function or constant name.
`--update` only writes the snapshot; it never changes the kind allowlist. Rustdoc sees expanded
macros, so generated items and signatures receive the same checks. Hidden and
`__private` upstream re-exports are forbidden, rather than macro escape hatches.

As decided in ADR-0004, `-sss` omits blanket, auto-trait and derived impls; the
semver gate protects those contracts. A future public vigil trait with blanket
implementations needs an ADR extending this check. The snapshot pins signatures,
not runtime behavior or encoded bytes; tests and Collector conformance protect
those separately. Optional future features must remain additive and need their
ADRs and allowlist entries before adding stable items.
