//! Shared line classification, in ADR-0005 §19.5 order.
use super::{AuditError, AuditErrorKind, FindingKind, Record, format};
use format::validation::MAX_PAYLOAD_BYTES;

/// A fragment candidate still needs file position and adjacent-link validation.
/// Record findings remain records so they can never become accepted span bytes.
pub(crate) enum Line {
    Fragment,
    Unparsable(AuditError),
    Record(Result<Vec<Record>, AuditError>),
}

/// Classifies one physical line, excluding at most its terminating LF.
/// Callers establish fragment conditions 1 and 3 from storage context.
pub(crate) fn classify(bytes: &[u8]) -> Line {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let unparsable = || AuditError::decoding(AuditErrorKind::CorruptTrail, FindingKind::Unparsable);
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Line::Unparsable(AuditError::decoding(
            AuditErrorKind::TooLarge,
            FindingKind::Unparsable,
        ));
    }
    if bytes.is_empty()
        || bytes.iter().all(u8::is_ascii_whitespace)
        || bytes.iter().any(|b| *b < 0x20)
    {
        return Line::Unparsable(unparsable());
    }
    let valid = match std::str::from_utf8(bytes) {
        Ok(_) => Some(bytes),
        Err(e) if e.error_len().is_none() && bytes.len() - e.valid_up_to() <= 3 => {
            Some(&bytes[..e.valid_up_to()])
        }
        Err(_) => None,
    };
    if valid.is_some_and(
        |v| matches!(serde_json::from_slice::<serde_json::Value>(v), Err(e) if e.is_eof()),
    ) {
        return Line::Fragment;
    }
    // Establish object framing independently of the record decoder's data
    // errors (notably duplicate keys inside a non-object).
    if !matches!(serde_json::from_slice::<serde_json::Value>(bytes), Ok(v) if v.is_object()) {
        return Line::Unparsable(unparsable());
    }
    Line::Record(
        format::codec::decode_complete_json(bytes)
            .map_err(|_| {
                AuditError::decoding(AuditErrorKind::CorruptTrail, FindingKind::InvalidField)
            })
            .and_then(Record::from_json),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    const GOLDEN: &str = include_str!("../../tests/fixtures/audit/codec.jsonl");
    fn kind(bytes: &[u8], expected: FindingKind) {
        let error = Record::parse_line(bytes).unwrap_err();
        assert_eq!(error.finding_kind(), Some(expected));
    }
    #[test]
    fn strict_prefixes_are_fragments() {
        let parsed = Record::parse_line(GOLDEN.lines().next().unwrap().as_bytes()).unwrap();
        let record = Record::new(
            parsed[0].context.clone(),
            super::super::Entry::new("acté😀r", "change", "object"),
        )
        .unwrap();
        let bytes = super::super::sink::line(&record).unwrap();
        let line = bytes.strip_suffix(b"\n").unwrap();
        assert!(matches!(classify(line), Line::Record(Ok(_))));
        // Empty input is explicitly Unparsable; a full JSON object is a record.
        for cut in 1..line.len() {
            assert!(
                matches!(classify(&line[..cut]), Line::Fragment),
                "cut {cut}"
            );
        }
    }
    #[test]
    fn complete_without_lf_is_record() {
        assert!(matches!(
            classify(GOLDEN.lines().next().unwrap().as_bytes()),
            Line::Record(Ok(_))
        ));
    }
    #[test]
    fn blank_is_unparsable() {
        for bytes in [b"".as_slice(), b" ", b"\t", b" \r\n"] {
            assert!(matches!(classify(bytes), Line::Unparsable(_)));
        }
    }
    #[test]
    fn non_objects_are_unparsable() {
        for bytes in [b"[1]".as_slice(), b"\"x\"", b"1", br#"[{"a":1,"a":1}]"#] {
            assert!(matches!(classify(bytes), Line::Unparsable(_)));
            kind(bytes, FindingKind::Unparsable);
        }
    }
    #[test]
    fn controls_between_tokens_are_unparsable() {
        for control in [b'\t', b'\r'] {
            let mut line = GOLDEN.lines().next().unwrap().as_bytes().to_vec();
            line.insert(1, control);
            assert!(matches!(classify(&line), Line::Unparsable(_)));
        }
    }
    #[test]
    fn control_at_eof_is_not_fragment() {
        assert!(matches!(
            classify(b"{\"resourceLogs\":\t"),
            Line::Unparsable(_)
        ));
    }
    #[test]
    fn over_cap_prefix_is_not_fragment() {
        let mut bytes = b"{\"resourceLogs\":[\"".to_vec();
        bytes.resize(MAX_PAYLOAD_BYTES + 1, b'x');
        assert!(matches!(classify(&bytes), Line::Unparsable(_)));
        let error = Record::parse_line(&bytes).unwrap_err();
        assert_eq!(error.kind(), AuditErrorKind::TooLarge);
        assert_eq!(error.finding_kind(), Some(FindingKind::Unparsable));
    }
    #[test]
    fn bad_fields_remain_records() {
        for (bytes, expected) in [
            (br#"{"a":1,"a":1}"#.as_slice(), FindingKind::InvalidField),
            (br#"{"resourceLogs":null}"#, FindingKind::InvalidField),
            (
                br#"{"resourceLogs":[],"unknown":1}"#,
                FindingKind::UnknownField,
            ),
        ] {
            assert!(matches!(classify(bytes), Line::Record(Err(_))));
            kind(bytes, expected);
        }
    }
    #[test]
    fn checkpoint_nul_finding_is_unparsable() {
        assert_eq!(
            super::super::Checkpoint::parse("\0")
                .unwrap_err()
                .finding_kind(),
            Some(FindingKind::Unparsable)
        );
    }
}
