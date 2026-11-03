//! Physical lines and maximal non-record spans; fragment context follows in V3.
use super::super::format::validation::MAX_PAYLOAD_BYTES;
use super::super::{
    AuditError, Record, gap_hasher,
    lines::{Line, classify},
};
use std::io::{self, BufRead};
#[cfg(test)]
use std::ops::Range;

pub(crate) enum Content {
    Records(Vec<Record>),
    Invalid(AuditError),
    Unparsable(AuditError),
    Fragment,
}
pub(crate) struct Item {
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

/// Streams physical lines with bounded buffering, including over-cap lines.
/// The visitor consumes decoded records before the next line is read. Gap
/// bytes are hashed as they arrive; no raw file or oversized suffix is retained.
pub(crate) fn stream(
    mut reader: impl BufRead,
    seg: u32,
    mut visit: impl FnMut(Item),
) -> io::Result<Vec<Span>> {
    let mut spans = Vec::new();
    let (mut offset, mut line, mut after) = (0, 0, u64::MAX);
    let mut gap = gap_hasher();
    let mut gap_len = 0;
    loop {
        let mut bytes = Vec::new();
        let line_start = offset;
        let mut line_hash = gap.clone();
        loop {
            let available = reader.fill_buf()?;
            if available.is_empty() {
                break;
            }
            let take = available
                .iter()
                .position(|b| *b == b'\n')
                .map_or(available.len(), |i| i + 1);
            let chunk = &available[..take];
            line_hash.update(chunk);
            let keep = take.min((MAX_PAYLOAD_BYTES + 2).saturating_sub(bytes.len()));
            bytes.extend_from_slice(&chunk[..keep]);
            let ended = chunk.last() == Some(&b'\n');
            offset += take;
            reader.consume(take);
            if ended {
                break;
            }
        }
        if line_start == offset {
            break;
        }
        line += 1;
        let content = match classify(&bytes) {
            Line::Record(Ok(records)) => Content::Records(records),
            Line::Record(Err(error)) => Content::Invalid(error),
            Line::Unparsable(error) => Content::Unparsable(error),
            Line::Fragment => Content::Fragment,
        };
        if matches!(content, Content::Records(_) | Content::Invalid(_)) {
            if gap_len != 0 {
                spans.push(Span {
                    seg,
                    after,
                    len: gap_len,
                    digest: *gap.finalize().as_bytes(),
                });
            }
            gap = gap_hasher();
            gap_len = 0;
            if let Content::Records(records) = &content {
                after = records
                    .last()
                    .expect("decoded batch is nonempty")
                    .context
                    .seq;
            }
        } else {
            gap = line_hash;
            gap_len += (offset - line_start) as u64;
        }
        visit(Item { line, content });
    }
    if gap_len != 0 {
        spans.push(Span {
            seg,
            after,
            len: gap_len,
            digest: *gap.finalize().as_bytes(),
        });
    }
    Ok(spans)
}

/// In-memory adapter retained for the V2 golden vectors.
#[cfg(test)]
fn read(bytes: &[u8], seg: u32) -> (Vec<Item>, Vec<Span>) {
    let mut items = Vec::new();
    let spans = stream(bytes, seg, |item| items.push(item)).unwrap();
    (items, spans)
}

/// Shared assembly also supports the ADR's fixed-length record stand-ins.
#[cfg(test)]
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
#[cfg(test)]
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
    expect(dead_code, reason = "consumed by run verification, #13 V4")
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
