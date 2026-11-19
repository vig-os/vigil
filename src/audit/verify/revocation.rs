//! Revocation pin and confirmation checks (ADR-0005 decision 9 and
//! amendment 8; rulings 13-V5-d1 point 4, 13-V5-d3 and 13-V5-d4).
//!
//! For each key in the verified trail's section carrying a
//! `through=<s>:<h>` bound, in key-byte order:
//!
//! - **pin:** exactly one distinct record exists at `s`, its hash is
//!   `h`, it is a checkpoint, and its `audit.key_id` is the bounded
//!   key. Amendment 8 defines a bound as a checkpoint whose `key_id`
//!   supplies the old key, so the trust file's `through=` must name a
//!   checkpoint the bounded key itself signed (ruling 13-V5-d4
//!   point 1). Otherwise emits `RevocationMismatch` with exactly one
//!   detail, chosen by the first failing condition in this order
//!   (ruling 13-V5-d4 point 3): no record, forked, other hash, not a
//!   checkpoint, signed by another key. A byte-identical duplicate
//!   counts as one record; the location is the first copy in the
//!   engine's merge order (the same copy `DuplicateRecord` treats as
//!   the original, ruling 13-V5-d4 point 4). A `SeqConflict` fork is
//!   not pinned (same fail-closed rule as ruling 13-V5-d2).
//! - **confirm:** a trusted checkpoint (ruling 13-V5-d1 point 3)
//!   strictly above `s` (`checked_add(1)`; ruling 13-V5-d4 point 2),
//!   signed by a key other than the bounded one. A shipped-only
//!   trusted checkpoint confirms (ruling 13-V5-d4 point 5; ruling
//!   13-V5-d1 point 1). Otherwise emits `RevocationUnconfirmed` at
//!   `s`.
//!
//! The two checks are independent (ruling 13-V5-d1 point 4): one
//! bound can carry both findings; neither suppresses the other.
//! Scope is a single section (ruling 13-V5-d3 point 3): the parse-time
//! rule that a revoked key is revoked in every section listing it is
//! already enforced by `TrustPolicy`.
//!
//! Reads only what [`super::engine::check`] already has from the one
//! snapshot (ruling 13-V4-d5): the merged records per `seq`, the
//! `SeqConflict` set, and the crate-private trusted predicate from
//! [`super::signatures::trusted`]. Never a second pass over files.
//!
//! Ruling 13-V5-d5 point 2.2: a matching `end=` confirms every
//! `through=` bound in the section whose `seq` is at or below the
//! matched end `seq`, so no `RevocationUnconfirmed` fires there. The
//! pin itself still runs (rulings 13-V5-d3 and 13-V5-d4). Threaded
//! as `matched_end` from [`super::end::check`], whose single call
//! `super::engine::check` owns.

use super::{Finding, input::Summary, signatures};
use crate::audit::{FindingKind as K, TrustPolicy, digest_string, hex};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

type Located<'a> = (&'a Path, &'a Summary);

/// Shared read-only context for the pin and confirmation passes.
struct Ctx<'a> {
    trail: [u8; 16],
    trust: &'a TrustPolicy,
    groups: &'a BTreeMap<u64, Vec<Located<'a>>>,
    conflicting_seqs: &'a BTreeSet<u64>,
    matched_end: Option<u64>,
}

pub(super) fn check(
    trail: [u8; 16],
    trust: &TrustPolicy,
    groups: &BTreeMap<u64, Vec<Located<'_>>>,
    conflicting_seqs: &BTreeSet<u64>,
    matched_end: Option<u64>,
    findings: &mut Vec<Finding>,
) {
    let ctx = Ctx {
        trail,
        trust,
        groups,
        conflicting_seqs,
        matched_end,
    };
    for (key, (s, h)) in trust.bounds_in(&trail) {
        let key_hex = hex(&key);
        let bound_prefix = format!("key {key_hex} through={s}:{}", digest_string(&h));
        let location = pin(&ctx, s, h, &key, &bound_prefix, findings);
        confirmation(&ctx, s, &key, &key_hex, location, findings);
    }
}

/// Emits `RevocationMismatch` for the first failing pin condition in
/// ruling 13-V5-d4 point 3's order: no record, forked, other hash, not
/// a checkpoint, signed by another key. Returns the single record's
/// `(path, line)` when any non-absent, non-forked record exists at
/// `s`, so the confirmation finding can share that location (ruling
/// 13-V5-d3 points 1 and 2: `RevocationUnconfirmed` is located like
/// the pin finding above). `None` on absent or forked, where the
/// finding itself is also unlocated. The chosen `(path, line)` is the
/// first copy in the engine's merge order (the one `DuplicateRecord`
/// treats as the original, ruling 13-V5-d4 point 4).
fn pin(
    ctx: &Ctx<'_>,
    s: u64,
    h: [u8; 32],
    bounded_key: &[u8; 32],
    bound_prefix: &str,
    findings: &mut Vec<Finding>,
) -> Option<(PathBuf, u64)> {
    let Some(copies) = ctx.groups.get(&s) else {
        findings.push(Finding::new(
            K::RevocationMismatch,
            None,
            None,
            Some(s),
            format!("{bound_prefix}: no record at seq {s}"),
        ));
        return None;
    };
    if ctx.conflicting_seqs.contains(&s) {
        findings.push(Finding::new(
            K::RevocationMismatch,
            None,
            None,
            Some(s),
            format!("{bound_prefix}: seq {s} is forked"),
        ));
        return None;
    }
    let (path, record) = copies[0];
    let location = (path.to_owned(), record.line);
    let located = |detail: String| {
        Finding::new(
            K::RevocationMismatch,
            Some(location.0.clone()),
            Some(location.1),
            Some(s),
            detail,
        )
    };
    if record.hash != h {
        findings.push(located(format!(
            "{bound_prefix}: record at seq {s} has hash {}",
            digest_string(&record.hash),
        )));
    } else if let Some(cp) = record.checkpoint.as_ref() {
        if cp.fields.key != *bounded_key {
            findings.push(located(format!(
                "{bound_prefix}: record at seq {s} is signed by key {}",
                hex(&cp.fields.key),
            )));
        }
    } else {
        findings.push(located(format!(
            "{bound_prefix}: record at seq {s} is not a checkpoint"
        )));
    }
    Some(location)
}

/// Emits `RevocationUnconfirmed` when no trusted checkpoint strictly
/// above `s` is signed by a key other than the bounded one
/// (ruling 13-V5-d1 point 3; ruling 13-V5-d3 point 2). Runs whether
/// the pin passed or failed: ruling 13-V5-d1 point 4 makes the two
/// checks independent so one bound can carry both findings. A
/// matching `end=` whose `seq` is at or above `s` also confirms the
/// bound (ruling 13-V5-d5 point 2.2).
fn confirmation(
    ctx: &Ctx<'_>,
    s: u64,
    bounded_key: &[u8; 32],
    key_hex: &str,
    location: Option<(PathBuf, u64)>,
    findings: &mut Vec<Finding>,
) {
    if ctx.matched_end.is_some_and(|e| s <= e) {
        return;
    }
    let confirmed = s.checked_add(1).is_some_and(|next| {
        ctx.groups.range(next..).any(|(_, copies)| {
            copies.iter().any(|(_, r)| {
                r.checkpoint
                    .as_ref()
                    .is_some_and(|cp| cp.fields.key != *bounded_key)
                    && signatures::trusted(ctx.trail, ctx.trust, r)
            })
        })
    });
    if confirmed {
        return;
    }
    let (file, line) = location.map_or((None, None), |(p, l)| (Some(p), Some(l)));
    findings.push(Finding::new(
        K::RevocationUnconfirmed,
        file,
        line,
        Some(s),
        format!("key {key_hex} through={s}: no trusted checkpoint by another key above the bound"),
    ));
}
