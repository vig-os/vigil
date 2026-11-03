//! Structural resume validation (#13 V3b-2) per ADR-0005 decision 5
//! rules 1 and 3, amendment 12 and ruling 13-V3-d5 point 1.
//!
//! For every `vigil.audit.resume` record on the selected trail whose
//! declaration parses, the engine computes once (d5 point 10) the outcome
//! of six fixed conditions: the opening at `k = lost_through + 1` is a
//! checkpoint (S1a), the resume lands at `k + 1` (S1b), the declared head
//! is present as the last record below `k` (S2a and S2b, non-genesis),
//! the opening's `previous` links to the head (S2c non-genesis, S3a
//! genesis), and nothing precedes `k` for a genesis declaration (S3b).
//! Validated tuples are kept privately for #13 V4 (rule 2 fold), V6
//! (start) and V7 (confirmation).
use super::{
    engine::parse_resume,
    input::{Collection, Summary},
};
use crate::audit::Record;
use std::{collections::BTreeSet, fmt};

/// Outcome of a structural pass per rules 1 and 3 of ADR-0005 decision 5
/// (ruling 13-V3-d5 point 1).
pub(super) enum Outcome {
    /// All six conditions hold; the tuple feeds V4/V6/V7.
    Valid(ResumeCandidate),
    /// The first failed condition in d5 point 4's order.
    Invalid(Reason),
}

/// First failed condition, rendering through [`fmt::Display`] to the six
/// fixed tokens of ruling 13-V3-d5 point 4 in that exact order.
pub(super) enum Reason {
    NoOpening,
    ResumeNotAtKPlus1,
    HeadNotPresent,
    HeadNotLast,
    LinkMismatch,
    GenesisNotFirst,
}
impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoOpening => "no-opening",
            Self::ResumeNotAtKPlus1 => "resume-not-at-k+1",
            Self::HeadNotPresent => "head-not-present",
            Self::HeadNotLast => "head-not-last",
            Self::LinkMismatch => "link-mismatch",
            Self::GenesisNotFirst => "genesis-not-first",
        })
    }
}

/// Validated `(resume, opening, head)` triple consumed by #13 V4/V6/V7
/// (ruling 13-V3-d5 point 5). Deduped by `(resume_seq, resume_hash)`
/// native-first (d5 point 10, ADR amendment 8).
#[derive(Debug, Clone)]
pub(super) struct ResumeCandidate {
    #[cfg_attr(not(test), expect(dead_code, reason = "consumed by #13 V7"))]
    pub(super) resume_seq: u64,
    #[cfg_attr(not(test), expect(dead_code, reason = "consumed by #13 V7"))]
    pub(super) resume_hash: [u8; 32],
    #[cfg_attr(not(test), expect(dead_code, reason = "consumed by #13 V6"))]
    pub(super) opening_seq: u64,
    #[cfg_attr(not(test), expect(dead_code, reason = "consumed by #13 V6"))]
    pub(super) opening_hash: [u8; 32],
    #[cfg_attr(not(test), expect(dead_code, reason = "consumed by #13 V7"))]
    pub(super) head_seq: u64,
    #[cfg_attr(not(test), expect(dead_code, reason = "consumed by #13 V7"))]
    pub(super) head_hash: [u8; 32],
    #[cfg_attr(not(test), expect(dead_code, reason = "consumed by #13 V7"))]
    pub(super) lost_through: u64,
    #[cfg_attr(not(test), expect(dead_code, reason = "consumed by #13 V7"))]
    pub(super) is_genesis: bool,
}

/// Decodes a `blake3:<64 lowercase hex>` text, as validated by
/// [`parse_resume`], into its 32-byte digest. Panics on any other shape.
pub(super) fn hex_to_bytes(text: &str) -> [u8; 32] {
    let hex = text.strip_prefix("blake3:").expect("blake3 prefix");
    let mut out = [0u8; 32];
    for (i, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let n = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        out[i] = (n(pair[0]) << 4) | n(pair[1]);
    }
    out
}

/// Checks every structural condition of ADR-0005 decision 5 rules 1 and 3
/// (ruling 13-V3-d5 point 1) on `resume`'s declaration, reporting the
/// first failure in d5 point 4's order. "Any candidate" is applied per
/// d5 addendum 8: S1 holds if any candidate at `k` is a checkpoint that
/// links, with the opening chosen first in input order (native first).
pub(super) fn structural_check(
    collection: &Collection,
    trail: [u8; 16],
    resume: &Summary,
    head_seq: u64,
    head_hash: [u8; 32],
    lost_through: u64,
    is_genesis_head: bool,
) -> Outcome {
    let k = lost_through.saturating_add(1);
    let on_trail = || native_then_shipped(collection).filter(|r| r.trail == trail);
    // S1a: at least one candidate at seq=k is a checkpoint (d5 addendum 8).
    if !on_trail().any(|r| r.seq == k && r.checkpoint.is_some()) {
        return Outcome::Invalid(Reason::NoOpening);
    }
    // S1b: the resume lands at k+1.
    if resume.seq != k.saturating_add(1) {
        return Outcome::Invalid(Reason::ResumeNotAtKPlus1);
    }
    if !is_genesis_head {
        // S2a: a candidate at seq=h matches head_hash (13-V1-d1/d1 point 1).
        if !on_trail().any(|r| r.seq == head_seq && r.hash == head_hash) {
            return Outcome::Invalid(Reason::HeadNotPresent);
        }
        // S2b: no candidate with h < seq < k on this trail.
        if on_trail().any(|r| r.seq > head_seq && r.seq < k) {
            return Outcome::Invalid(Reason::HeadNotLast);
        }
    }
    // S2c / S3a: among checkpoints at k, pick the first (native first) that
    // links to the declared head (non-genesis) or to the genesis value.
    let expected_prev = if is_genesis_head {
        Record::genesis(&trail)
    } else {
        head_hash
    };
    let Some(opening) =
        on_trail().find(|r| r.seq == k && r.checkpoint.is_some() && r.previous == expected_prev)
    else {
        return Outcome::Invalid(Reason::LinkMismatch);
    };
    // S3b: for a genesis declaration, nothing precedes k on this trail.
    if is_genesis_head && on_trail().any(|r| r.seq < k) {
        return Outcome::Invalid(Reason::GenesisNotFirst);
    }
    Outcome::Valid(ResumeCandidate {
        resume_seq: resume.seq,
        resume_hash: resume.hash,
        opening_seq: opening.seq,
        opening_hash: opening.hash,
        head_seq,
        head_hash,
        lost_through,
        is_genesis: is_genesis_head,
    })
}

/// Walks resume records on `trail` native-first then shipped (ADR
/// amendment 8), deduped by `(resume_seq, resume_hash)` (d5 point 10),
/// and keeps only the structurally-valid tuples.
pub(super) fn collect_candidates(collection: &Collection, trail: [u8; 16]) -> Vec<ResumeCandidate> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let is_resume = |r: &Summary| {
        r.trail == trail
            && r.operator
                .as_ref()
                .is_some_and(|(action, ..)| action == "vigil.audit.resume")
    };
    let mut process = |r: &Summary| {
        if !seen.insert((r.seq, r.hash)) {
            return;
        }
        let details = r.operator.as_ref().and_then(|(_, _, _, d)| d.as_deref());
        let Some((head_seq, head_hash_text, lost)) = parse_resume(details) else {
            return;
        };
        let head_hash = hex_to_bytes(head_hash_text);
        let is_genesis_head = head_seq == 0 && head_hash == Record::genesis(&trail);
        if let Outcome::Valid(c) = structural_check(
            collection,
            trail,
            r,
            head_seq,
            head_hash,
            lost,
            is_genesis_head,
        ) {
            out.push(c);
        }
    };
    for input in collection.inputs.iter().filter(|i| i.native) {
        for r in input.data.records.iter().filter(|r| is_resume(r)) {
            process(r);
        }
    }
    for input in collection.inputs.iter().filter(|i| !i.native) {
        for r in input.data.records.iter().filter(|r| is_resume(r)) {
            process(r);
        }
    }
    out
}

/// Native inputs first (in `inputs` order), then shipped inputs (same
/// order), yielding every record. The caller filters by trail.
fn native_then_shipped(collection: &Collection) -> impl Iterator<Item = &Summary> {
    collection
        .inputs
        .iter()
        .filter(|i| i.native)
        .flat_map(|i| i.data.records.iter())
        .chain(
            collection
                .inputs
                .iter()
                .filter(|i| !i.native)
                .flat_map(|i| i.data.records.iter()),
        )
}
