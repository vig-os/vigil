//! Physical lines and maximal non-record spans; fragment context follows in V3.
use super::super::{
    AuditError, Record, gap_hasher,
    lines::{Line, classify},
};
use std::ops::Range;

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "consumed by the verifier engine, #13 V3")
)]
pub(crate) enum Content {
    Records(Vec<Record>),
    Invalid(AuditError),
    Unparsable(AuditError),
    Fragment,
}
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "consumed by the verifier engine, #13 V3")
)]
pub(crate) struct Item {
    pub(crate) bytes: Range<usize>,
    pub(crate) line: u64,
    pub(crate) content: Content,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Span {
    pub(crate) seg: u32,
    pub(crate) after: u64,
    pub(crate) len: u64,
    pub(crate) digest: [u8; 32],
}

/// Reads one segment; offsets include each physical line's terminating LF.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "consumed by the verifier engine, #13 V3")
)]
pub(crate) fn read(bytes: &[u8], seg: u32) -> (Vec<Item>, Vec<Span>) {
    let mut offset = 0;
    let items: Vec<_> = bytes
        .split_inclusive(|b| *b == b'\n')
        .enumerate()
        .map(|(line, bytes)| {
            let start = offset;
            offset += bytes.len();
            let content = match classify(bytes) {
                Line::Record(Ok(records)) => Content::Records(records),
                Line::Record(Err(error)) => Content::Invalid(error),
                Line::Unparsable(error) => Content::Unparsable(error),
                Line::Fragment => Content::Fragment,
            };
            Item {
                bytes: start..offset,
                line: line as u64 + 1,
                content,
            }
        })
        .collect();
    let boundaries: Vec<_> = items
        .iter()
        .filter_map(|item| match &item.content {
            Content::Records(records) => {
                Some((item.bytes.clone(), records.last().map(|r| r.context.seq)))
            }
            Content::Invalid(_) => Some((item.bytes.clone(), None)),
            _ => None,
        })
        .collect();
    let spans = assemble(bytes, seg, &boundaries);
    (items, spans)
}

/// Shared assembly also supports the ADR's fixed-length record stand-ins.
fn assemble(bytes: &[u8], seg: u32, records: &[(Range<usize>, Option<u64>)]) -> Vec<Span> {
    let mut spans = Vec::new();
    let mut end = 0;
    let mut after = u64::MAX;
    for (range, seq) in records {
        append_span(&mut spans, bytes, seg, after, end..range.start);
        end = range.end;
        if let Some(seq) = seq {
            after = *seq;
        }
    }
    append_span(&mut spans, bytes, seg, after, end..bytes.len());
    spans
}
fn append_span(spans: &mut Vec<Span>, bytes: &[u8], seg: u32, after: u64, range: Range<usize>) {
    if range.is_empty() {
        return;
    }
    let mut hash = gap_hasher();
    hash.update(&bytes[range.clone()]);
    spans.push(Span {
        seg,
        after,
        len: range.len() as u64,
        digest: *hash.finalize().as_bytes(),
    });
}

/// Callers supply ranges in ascending sequence order and spans in segment/byte order.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "consumed by the verifier engine, #13 V3")
)]
pub(crate) fn run_digest(ranges: &[(u64, u64)], spans: &[Span]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"vigil.audit.v1.run-ranges\0");
    hash.update(
        &u32::try_from(ranges.len())
            .expect("range count exceeds u32")
            .to_be_bytes(),
    );
    for (first, count) in ranges {
        hash.update(&first.to_be_bytes());
        hash.update(&count.to_be_bytes());
    }
    hash.update(
        &u32::try_from(spans.len())
            .expect("span count exceeds u32")
            .to_be_bytes(),
    );
    for span in spans {
        hash.update(&span.seg.to_be_bytes());
        hash.update(&span.after.to_be_bytes());
        hash.update(&span.len.to_be_bytes());
        hash.update(&span.digest);
    }
    *hash.finalize().as_bytes()
}

#[cfg(test)]
#[path = "lines_tests.rs"]
mod tests;
