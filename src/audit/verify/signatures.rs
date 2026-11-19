//! Checkpoint signature and key-trust checks (ADR-0005 decisions 8 and 9,
//! ruling 13-V5-d1 points 1-3). Called by [`super::engine::check`] once
//! per distinct `(seq, hash)` checkpoint candidate the engine's merge
//! retains, at that candidate's own `(path, line)` -- native or
//! shipped, inside runs or outside. A byte-identical duplicate yields
//! one finding at the first-occurrence copy the engine keeps.
//!
//! `BadSignature` fires when `verify_strict` over the 58-byte checkpoint
//! signing message fails, which includes an undecodable key, a small-order
//! key and a non-canonical signature. `UntrustedKey` fires when the signing
//! key is not listed for the verified trail's section or the checkpoint's
//! `seq` exceeds the key's `through=` bound. The two are independent facts:
//! a checkpoint can carry both; neither suppresses the other. "Trusted"
//! per ruling 13-V5-d1 point 3 requires both to hold.
//!
//! Revocation pin consistency, `end=`, coverage and `max_age` belong to
//! later work in #13.

use super::{Finding, input::Summary};
use crate::audit::{FindingKind as K, TrustPolicy, hex, verify_signature};
use std::path::Path;

/// Whether `record` is a checkpoint whose signature verifies under
/// `verify_strict` over its signing message AND whose key is trusted at
/// its `seq` on `trail` (ruling 13-V5-d1 point 3).
///
/// Crate-private so later `#13 V5` work (revocation, `end=` and
/// `max_age`) reuses the same predicate rather than copying its logic.
/// `#13 V5b` consumes it for coverage (ruling 13-V5-d1 point 6).
pub(crate) fn trusted(trail: [u8; 16], trust: &TrustPolicy, record: &Summary) -> bool {
    let Some(cp) = record.checkpoint.as_ref() else {
        return false;
    };
    verify_signature(&cp.fields.key, &cp.signing_message, cp.fields.signature()).is_ok()
        && trust.trusted_at(&trail, &cp.fields.key, record.seq)
}

/// Appends `BadSignature` and/or `UntrustedKey` for one distinct `(seq, hash)`
/// checkpoint candidate (ruling 13-V5-d1 points 1-2). Called once per
/// candidate from `engine::check`; non-checkpoint candidates are a no-op.
pub(super) fn check(
    trail: [u8; 16],
    trust: &TrustPolicy,
    path: &Path,
    record: &Summary,
    findings: &mut Vec<Finding>,
) {
    let Some(cp) = record.checkpoint.as_ref() else {
        return;
    };
    let seq = record.seq;
    let key = cp.fields.key;
    let at = |detail: String, kind: K| {
        Finding::new(
            kind,
            Some(path.to_owned()),
            Some(record.line),
            Some(seq),
            detail,
        )
    };
    if verify_signature(&key, &cp.signing_message, cp.fields.signature()).is_err() {
        findings.push(at(format!("key {}", hex(&key)), K::BadSignature));
    }
    if !trust.trusted_at(&trail, &key, seq) {
        let detail = if trust.listed(&trail, &key) {
            let (through, _) = trust
                .bound(&trail, &key)
                .expect("key is listed and not trusted-at seq so it must be bounded");
            format!("key {} bounded through seq {through}", hex(&key))
        } else {
            format!("key {} not listed for trail {}", hex(&key), hex(&trail))
        };
        findings.push(at(detail, K::UntrustedKey));
    }
}

#[cfg(test)]
#[path = "signature_tests.rs"]
mod tests;
