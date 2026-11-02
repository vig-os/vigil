use super::*;
use crate::audit::{FindingKind, digest_string, parse_hex};
const GOLDEN: &str = include_str!("../../../tests/fixtures/audit/codec.jsonl");
const D22: &str = "2409a78aa6ad2c5e32cac60ea818b20ea8c463f38f702d218ece3744a917a965";
const D9: &str = "9dee1892e67021871ac6a32b6380af5f85e7a864d24cb942d2221aa9cec907e0";
#[test]
fn span_golden_vector() {
    for (start, expected) in [
        (
            false,
            "e930812823378f6a1c296685c92bb448989e5b8156308109c9bb78f8218b39cb",
        ),
        (
            true,
            "97025044884292e8642f7cc819bf760c3c2f7c163478547f3bb656180c5ee302",
        ),
    ] {
        let mut bytes = Vec::new();
        let mut records = Vec::new();
        if !start {
            bytes.resize(210, b'r');
            bytes.push(b'\n');
            records.push((0..211, Some(4)));
        }
        bytes.extend_from_slice(b"{\"seq\":5,\"ki\nnot json\n");
        let offset = bytes.len();
        assert_eq!(offset, if start { 22 } else { 233 });
        bytes.resize(offset + 197, b'r');
        bytes.push(b'\n');
        records.push((offset..offset + 198, Some(5)));
        bytes.extend_from_slice(b"{\"seq\":6,");
        assert_eq!(bytes.len(), if start { 229 } else { 440 });
        let spans = assemble(&bytes, 0, &records);
        assert_eq!(
            spans,
            vec![
                Span {
                    seg: 0,
                    after: if start { u64::MAX } else { 4 },
                    len: 22,
                    digest: parse_hex(D22).unwrap()
                },
                Span {
                    seg: 0,
                    after: 5,
                    len: 9,
                    digest: parse_hex(D9).unwrap()
                }
            ]
        );
        assert_eq!(
            digest_string(&run_digest(&[], &spans)),
            format!("blake3:{expected}")
        );
    }
}
#[test]
fn classifier_integration() {
    let record = GOLDEN.lines().next().unwrap();
    let seq = Record::parse_line(record.as_bytes())
        .unwrap()
        .last()
        .unwrap()
        .context
        .seq;
    let bytes = format!("{record}\n{{\"seq\":5,\"ki\nnot json\n{record}\n{{\"seq\":6,");
    let (items, spans) = read(bytes.as_bytes(), 3);
    assert_eq!(items.len(), 5);
    assert_eq!(
        items.iter().map(|i| i.line).collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5]
    );
    assert_eq!(items[0].bytes, 0..record.len() + 1);
    assert!(matches!(items[0].content, Content::Records(_)));
    assert!(matches!(items[1].content, Content::Fragment));
    let Content::Unparsable(error) = &items[2].content else {
        panic!("expected Unparsable")
    };
    assert_eq!(error.finding_kind(), Some(FindingKind::Unparsable));
    assert_eq!(
        spans,
        vec![
            Span {
                seg: 3,
                after: seq,
                len: 22,
                digest: parse_hex(D22).unwrap()
            },
            Span {
                seg: 3,
                after: seq,
                len: 9,
                digest: parse_hex(D9).unwrap()
            }
        ]
    );
    // A new file always starts without a predecessor, regardless of prior files.
    assert_eq!(read(b"not json\n", 4).1[0].after, u64::MAX);
    assert!(read(b"", 0).0.is_empty());
}
#[test]
fn classification_boundaries() {
    let original = GOLDEN.lines().next().unwrap();
    let cases = [
        (
            original
                .replace("\"intValue\":\"1\"", "\"intValue\":\"2\"")
                .into_bytes(),
            FindingKind::UnknownVersion,
        ),
        (
            original
                .replace("55ba3e4f04b2fb65", "65ba3e4f04b2fb65")
                .into_bytes(),
            FindingKind::HashMismatch,
        ),
        (br#"{"a":1,"a":1}"#.to_vec(), FindingKind::InvalidField),
        (br#"{}"#.to_vec(), FindingKind::MissingField),
        (
            br#"{"resourceLogs":[],"extra":1}"#.to_vec(),
            FindingKind::UnknownField,
        ),
    ];
    for (bytes, kind) in cases {
        let (items, spans) = read(&bytes, 0);
        let Content::Invalid(error) = &items[0].content else {
            panic!("expected invalid record: {kind:?}")
        };
        assert_eq!(error.finding_kind(), Some(kind));
        assert!(spans.is_empty());
    }
    for bytes in [
        b"not json".to_vec(),
        b"[]".to_vec(),
        b"{\0}".to_vec(),
        vec![b'x'; 1_000_001],
        b"\n".to_vec(),
        b"  \n".to_vec(),
    ] {
        let (items, spans) = read(&bytes, 0);
        assert!(matches!(items[0].content, Content::Unparsable(_)));
        assert_eq!(spans[0].len, bytes.len() as u64);
    }
    assert!(read(original.as_bytes(), 0).1.is_empty());
    let parsed = Record::parse_line(original.as_bytes()).unwrap();
    let record = Record::new(
        parsed[0].context.clone(),
        crate::audit::Entry::new("acté😀r", "change", "object"),
    )
    .unwrap();
    let bytes = crate::audit::sink::line(&record).unwrap();
    for cut in 1..bytes.len() - 1 {
        let (items, spans) = read(&bytes[..cut], 0);
        assert!(matches!(items[0].content, Content::Fragment), "cut {cut}");
        assert_eq!(spans[0].len, cut as u64);
    }
}

#[test]
fn ranges_digest_vectors() {
    // Independently generated by scripts/audit/v2_digest_vectors.py using b3sum.
    for (ranges, expected) in [
        (
            vec![],
            "1c02f080d9c70df74de0c13a4a30323f1b49ee624bab2c5d68fa5ee31c4400e4",
        ),
        (
            vec![(4, 2)],
            "c65ce82ccb7c329d4811c4bc9bad0049ad71ed475604659769426ec3e19e5725",
        ),
        (
            vec![(4, 2), (9, 3)],
            "fa850e10e47f5a6aa0e85191ca856e525b033c6ba988e1ee46f13fbdbaac6215",
        ),
        (
            vec![(4, 0)],
            "3362c5a5c82adce3b633232975bfddb866f55d629a124a60e5c01db26c4b7e0a",
        ),
    ] {
        assert_eq!(run_digest(&ranges, &[]), parse_hex(expected).unwrap());
    }
    for (after, expected) in [
        (
            u64::MAX,
            "e8620f6c040ee0e8ba55a5496b9db7b1baf953aa7a90ef76df8fa489a3808ba9",
        ),
        (
            4,
            "3ff9b57858dc1358adca027346c31eda10f716bc8d0616a998561d8c5280b661",
        ),
    ] {
        let mut spans = read(b"not json\n", 0).1;
        spans[0].after = after;
        assert_eq!(run_digest(&[], &spans), parse_hex(expected).unwrap());
        let original = run_digest(&[], &spans);
        spans[0].seg = 1;
        assert_ne!(original, run_digest(&[], &spans));
        let mut repair = gap_hasher();
        repair.update(b"not json\n");
        assert_eq!(spans[0].digest, *repair.finalize().as_bytes());
    }
    assert_ne!(
        run_digest(&[(4, 2), (9, 3)], &[]),
        run_digest(&[(9, 3), (4, 2)], &[])
    );
}

#[test]
fn streaming_spans_ignore_buffer_boundaries_and_keep_over_cap_eof() {
    use std::io::BufReader;
    let record = GOLDEN.lines().next().unwrap();
    let bytes = format!("{record}\n{{\"seq\":\nnot json\n{record}\n{{\"seq\":");
    let expected = read(bytes.as_bytes(), 7).1;
    for capacity in [1, 2, 7, 4096] {
        let mut lines = Vec::new();
        let spans = stream(
            BufReader::with_capacity(capacity, bytes.as_bytes()),
            7,
            |item| lines.push(item.line),
        )
        .unwrap();
        assert_eq!(spans, expected);
        assert_eq!(lines, vec![1, 2, 3, 4, 5]);
    }
    for terminated in [false, true] {
        let mut bytes = vec![b'{'; MAX_PAYLOAD_BYTES + 1];
        if terminated {
            bytes.push(b'\n');
        }
        let mut count = 0;
        let spans = stream(BufReader::with_capacity(37, bytes.as_slice()), 2, |item| {
            count += 1;
            assert!(matches!(item.content, Content::Unparsable(_)));
            assert_eq!(item.bytes, 0..bytes.len());
        })
        .unwrap();
        assert_eq!(count, 1);
        let mut hash = gap_hasher();
        hash.update(&bytes);
        assert_eq!(
            spans,
            vec![Span {
                seg: 2,
                after: u64::MAX,
                len: bytes.len() as u64,
                digest: *hash.finalize().as_bytes()
            }]
        );
    }
}
