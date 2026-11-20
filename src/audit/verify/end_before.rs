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
use std::{collections::BTreeMap, path::Path};

type Located<'a> = (&'a Path, &'a Summary);

/// The parsed archive record and the segment bytes the verifier
/// feeds to the shared classifier through the in-memory byte source.
pub(super) struct Parsed {
    pub(super) checkpoint: Checkpoint,
    pub(super) segment_bytes: Vec<u8>,
    /// `seq` of the end record's last line: the resume line when one
    /// is present, otherwise the checkpoint (ruling 13-V6-d7 point 1).
    /// This is `E`, the end of the range for inputs above the end.
    pub(super) last_line_seq: u64,
}

/// Parses the archive record per ruling 13-V6-d4 point 4. Returns
/// `InvalidConfig` naming the first failing rule; a trailing LF is
/// accepted.
pub(super) fn parse(end_record: &str) -> Result<Parsed, AuditError> {
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
    let mut last_line_seq = checkpoint.seq();
    if let Some(second) = second {
        validate_resume(second, &checkpoint)?;
        segment_bytes.extend_from_slice(second.as_bytes());
        segment_bytes.push(b'\n');
        last_line_seq = checkpoint
            .seq()
            .checked_add(1)
            .ok_or_else(|| invalid("end_record checkpoint seq overflows"))?;
    }
    Ok(Parsed {
        checkpoint,
        segment_bytes,
        last_line_seq,
    })
}

/// One unified check for "the second line is a `vigil.audit.resume`
/// record": parsing it, demanding a single record, and demanding the
/// `vigil.audit.resume` action all funnel through the same filter
/// and the same error. Both an unparsable line and a parseable but
/// non-resume entry fail the same check, so a mutation that removes
/// the check fails on either kind of row.
fn validate_resume(line: &str, checkpoint: &Checkpoint) -> Result<(), AuditError> {
    let record = Record::parse_line(line.as_bytes())
        .ok()
        .filter(|records| records.len() == 1)
        .and_then(|mut records| records.pop())
        .filter(|record| {
            matches!(&record.kind, Kind::Entry(entry) if entry.action == "vigil.audit.resume")
        })
        .ok_or_else(|| invalid("end_record second line is not a resume"))?;
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
    /// `E`, the `seq` of the end record's last line (ruling 13-V6-d7
    /// point 1): the resume line when one is present, otherwise the
    /// checkpoint. The end of the range for inputs above the end.
    pub(super) last_line_seq: u64,
    pub(super) first_line: &'a str,
    pub(super) anchor: Option<&'a Checkpoint>,
    /// `true` iff the end anchor was given and passed the shared
    /// anchor rule (ruling 13-V6-d1 point 2). The result comes from
    /// [`super::anchors::match_only`] once per verify call, so
    /// [`Self::is_anchored`] reuses it rather than reimplementing
    /// the rule (ruling 13-V6-d7 clarification 13-V6-d7a point 2).
    /// Left `false` outside [`super::engine::check`].
    pub(super) end_anchor_matches: bool,
}

impl<'a> Context<'a> {
    /// `true` iff an end anchor was given and its line byte-equals
    /// the end record's first line (ruling 13-V6-d4 point 5: each
    /// side without its LF; whitespace counts). The one place the
    /// byte-equality check lives; [`Self::is_anchored`] and
    /// [`check`] both consume it so the comparison runs in exactly
    /// one place.
    pub(super) fn bytes_match(&self) -> bool {
        self.anchor.is_some_and(|a| a.line() == self.first_line)
    }

    /// `true` iff all three "anchored" conditions hold: the end
    /// anchor was given, its bytes match the record's first line,
    /// and the shared anchor rule produced no finding for it
    /// (ruling 13-V6-d4 point 5; ruling 13-V6-d7 clarification
    /// 13-V6-d7a point 2 — a fork at `e` leaves the end unanchored).
    /// The one place "anchored" is decided for the above-end
    /// set-aside; neither the byte-equality nor the anchor rule
    /// is re-checked here.
    pub(super) fn is_anchored(&self) -> bool {
        self.bytes_match() && self.end_anchor_matches
    }
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
        if let Some(located) = first_file_copy(copies) {
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
        // Ruling 13-V6-d4 point 5 (byte equality lives in one place,
        // `Context::bytes_match`): the end record's first line must
        // byte-equal the end anchor's line (each side without its LF;
        // whitespace counts).
        Some(_) if !ctx.bytes_match() => findings.push(Finding::new(
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
/// excluding the end-record segment. The filter reads
/// [`Summary::is_end_record`] so no path value is compared against a
/// sentinel; the sort key `(path, line, hash)` matches the file
/// copies the engine's main seq-loop would pick for `SeqConflict`
/// and `DuplicateRecord` at that `seq`.
fn first_file_copy<'a>(copies: &[Located<'a>]) -> Option<Located<'a>> {
    copies
        .iter()
        .filter(|(_, r)| !r.is_end_record)
        .min_by_key(|(path, r)| (*path, r.line, r.hash))
        .copied()
}

/// Emits one `ChainBroken` at `e` when the files hold no record
/// below the end checkpoint's `seq` and `e > 0` (ruling 13-V6-d6
/// point 3). In every other shape the chain loop in
/// [`super::engine::check`] checks the end record like any other,
/// so this is the only end-specific link finding. The finding has
/// no file and no line (end-record findings are unlocated, ruling
/// 13-V6-d4 point 6).
pub(super) fn no_record_precedes(
    ctx: &Context<'_>,
    groups: &BTreeMap<u64, Vec<Located<'_>>>,
    findings: &mut Vec<Finding>,
) {
    let e = ctx.end_seq;
    if e == 0 {
        return;
    }
    let has_file_record_below = groups
        .range(..e)
        .any(|(_, copies)| copies.iter().any(|(_, r)| !r.is_end_record));
    if has_file_record_below {
        return;
    }
    findings.push(Finding::new(
        K::ChainBroken,
        None,
        None,
        Some(e),
        format!("end_before seq {e}: no record precedes the end"),
    ));
}
