//! `end_before` parsing, end-anchor byte equality and the
//! `TrailEnded` range for the files of a batch-end verification
//! (ADR-0005 decision 11 `.end_before`; ruling 13-V6-d4). The record
//! is walked in place as the segment that follows the files; this
//! module owns parsing of the archive record, the byte-equality rule
//! against the end anchor (each side without its LF; whitespace
//! counts), and the `TrailEnded` finding for file records at or
//! above the end checkpoint's `seq`. The `DuplicateRecord`
//! suppression at or above the end happens in exactly one place in
//! [`super::engine::check`]. The `UnanchoredEnd`, the end-record
//! `AnchorMismatch` and the `TrailEnded` grammars live on
//! [`crate::audit::Verifier::end_before`] and the finding kinds.

use super::{Finding, input::Summary};
use crate::audit::{
    AuditError, AuditErrorKind, Checkpoint, FindingKind as K, Record, format::Kind,
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

type Located<'a> = (&'a Path, &'a Summary);

/// The parsed archive record and the segment bytes the verifier
/// feeds to the shared classifier through the in-memory byte source.
pub(super) struct Parsed {
    pub(super) checkpoint: Checkpoint,
    pub(super) segment_bytes: Vec<u8>,
}

/// Parses the archive record per ruling 13-V6-d4 point 4. Returns
/// `InvalidConfig` naming the first failing rule; a trailing LF is
/// accepted.
pub(super) fn parse(end_record: &str) -> Result<Parsed, AuditError> {
    if end_record.is_empty() {
        return Err(invalid("end_record is empty"));
    }
    if end_record.as_bytes().contains(&b'\r') {
        return Err(invalid("end_record contains CR"));
    }
    let stripped = end_record.strip_suffix('\n').unwrap_or(end_record);
    let mut parts = stripped.split('\n');
    let first = parts.next().expect("split yields at least one part");
    let second = parts.next();
    if parts.next().is_some() {
        return Err(invalid("end_record has more than two lines"));
    }
    if first.is_empty() {
        return Err(invalid("end_record is empty"));
    }
    let checkpoint = Checkpoint::parse(first)
        .map_err(|_| invalid("end_record first line is not a checkpoint"))?;
    let mut segment_bytes = Vec::with_capacity(end_record.len() + 2);
    segment_bytes.extend_from_slice(first.as_bytes());
    segment_bytes.push(b'\n');
    if let Some(second) = second {
        if second.is_empty() {
            return Err(invalid("end_record has an empty second line"));
        }
        validate_resume(second, &checkpoint)?;
        segment_bytes.extend_from_slice(second.as_bytes());
        segment_bytes.push(b'\n');
    }
    Ok(Parsed {
        checkpoint,
        segment_bytes,
    })
}

fn validate_resume(line: &str, checkpoint: &Checkpoint) -> Result<(), AuditError> {
    let records = Record::parse_line(line.as_bytes())
        .map_err(|_| invalid("end_record second line is not a resume"))?;
    let [record] = <[Record; 1]>::try_from(records)
        .map_err(|_| invalid("end_record second line is not a single record"))?;
    let Kind::Entry(entry) = &record.kind else {
        return Err(invalid("end_record second line is not a resume"));
    };
    if entry.action != "vigil.audit.resume" {
        return Err(invalid("end_record second line is not a resume"));
    }
    let expected_seq = checkpoint
        .seq()
        .checked_add(1)
        .ok_or_else(|| invalid("end_record checkpoint seq overflows"))?;
    if record.context.seq != expected_seq {
        return Err(invalid("end_record resume line seq is not cp.seq + 1"));
    }
    if record.context.previous != checkpoint.hash() {
        return Err(invalid(
            "end_record resume line prev_hash does not equal cp.hash",
        ));
    }
    Ok(())
}

fn invalid(detail: impl Into<String>) -> AuditError {
    AuditError::new(AuditErrorKind::InvalidConfig, detail)
}

/// End-of-range inputs the engine reads once for a verify call.
pub(super) struct Context<'a> {
    pub(super) end_seq: u64,
    pub(super) first_line: &'a str,
    pub(super) anchor: Option<&'a Checkpoint>,
    pub(super) record_path: &'a Path,
}

/// `true` iff this `seq` is at or above the end checkpoint's `seq`
/// (ruling 13-V6-d4 point 3): the one place `DuplicateRecord` is
/// suppressed.
pub(super) fn covers(ctx: Option<&Context<'_>>, seq: u64) -> bool {
    ctx.is_some_and(|c| seq >= c.end_seq)
}

/// Emits the `TrailEnded` range for file records at or above the
/// end checkpoint's `seq`, and the `UnanchoredEnd` /
/// end-record-form `AnchorMismatch` from the byte-equality check
/// against the end anchor (ruling 13-V6-d4 points 3 and 5).
pub(super) fn check(
    ctx: &Context<'_>,
    groups: &BTreeMap<u64, Vec<Located<'_>>>,
    findings: &mut Vec<Finding>,
) {
    let mut in_files: Vec<(u64, Located<'_>)> = Vec::new();
    for (&seq, copies) in groups.range(ctx.end_seq..) {
        if let Some(located) = first_file_copy(copies, ctx.record_path) {
            in_files.push((seq, located));
        }
    }
    if let Some(&(a, (path, record))) = in_files.first() {
        let b = in_files.last().map(|&(s, _)| s).unwrap_or(a);
        findings.push(Finding::new(
            K::TrailEnded,
            Some(path.to_owned()),
            Some(record.line),
            Some(a),
            format!(
                "end_before seq {}: records seq {a}..={b} at or above the end",
                ctx.end_seq,
            ),
        ));
    }
    match ctx.anchor {
        None => findings.push(Finding::new(
            K::UnanchoredEnd,
            None,
            None,
            Some(ctx.end_seq),
            format!("end_before seq {}: no end anchor", ctx.end_seq),
        )),
        Some(anchor) if anchor.line() != ctx.first_line => findings.push(Finding::new(
            K::AnchorMismatch,
            None,
            None,
            Some(ctx.end_seq),
            "end record differs from end anchor".into(),
        )),
        Some(_) => {}
    }
}

/// The first file copy at this `seq` in the engine's merge order,
/// excluding the end-record segment; `None` when every copy sits on
/// the end-record. Shares the engine's input-position sort key so a
/// `TrailEnded` always locates at the same copy the main seq-loop
/// chose for `SeqConflict` and `DuplicateRecord` at that `seq`.
fn first_file_copy<'a>(copies: &[Located<'a>], end_path: &Path) -> Option<Located<'a>> {
    copies
        .iter()
        .filter(|(path, _)| *path != end_path)
        .min_by_key(|(_, r)| (r.input_pos, r.line, r.hash))
        .copied()
}

/// Sentinel path for the in-memory end-record segment. Findings
/// located on this path are unlocated by
/// [`super::engine::check`] before the sort (ruling 13-V6-d4 point 6).
pub(super) fn record_path() -> PathBuf {
    PathBuf::new()
}
