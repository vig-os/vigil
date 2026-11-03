//! Public collecting verifier acceptance tests.
#![cfg(feature = "audit")]
use std::{
    error::Error,
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use vigil::audit::{
    AuditConfig, AuditErrorKind, Entry, FindingKind as K, KeyFileSigner, Report, TrustPolicy,
    Verifier, keygen, verify,
};
const GOLDEN: &str = include_str!("fixtures/audit/codec.jsonl");
const TRAIL: [u8; 16] = [0x11; 16];
struct Dir(PathBuf);
impl Dir {
    fn new() -> Self {
        static ID: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "vigil-verify-engine-{}-{}",
            std::process::id(),
            ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn put(&self, name: &str, bytes: impl AsRef<[u8]>) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn policy() -> TrustPolicy {
    TrustPolicy::builder().trail(TRAIL).build().unwrap()
}
fn entry() -> &'static str {
    GOLDEN.lines().next().unwrap()
}
fn kinds(report: &Report, kind: K) -> Vec<&vigil::audit::Finding> {
    report
        .findings()
        .iter()
        .filter(|f| f.kind() == kind)
        .collect()
}
#[test]
fn pinned_empty_selection_and_narrowing_precede_reads() {
    let dir = Dir::new();
    let report = verify(&dir.0, &policy()).unwrap();
    assert_eq!(report.trail(), TRAIL);
    assert_eq!(report.records(), 0);
    assert_eq!(
        (
            report.first_seq(),
            report.last_seq(),
            report.covered_through()
        ),
        (None, None, None)
    );
    assert!(report.findings().is_empty());
    let multi = TrustPolicy::builder()
        .trail(TRAIL)
        .trail([2; 16])
        .build()
        .unwrap();
    let verifier = Verifier::new(multi);
    assert_eq!(
        verifier.verify_files([]).unwrap_err().kind(),
        AuditErrorKind::InvalidConfig
    );
    assert_eq!(
        verifier
            .verify_files([dir.0.join("missing")])
            .unwrap_err()
            .kind(),
        AuditErrorKind::InvalidConfig
    );
    assert_eq!(
        verifier.clone().trail([3; 16]).unwrap_err().kind(),
        AuditErrorKind::InvalidConfig
    );
    assert_eq!(
        verifier
            .trail([2; 16])
            .unwrap()
            .verify_files([])
            .unwrap()
            .trail(),
        [2; 16]
    );
}
#[test]
fn foreign_first_and_only_record_cannot_select_the_report_id() {
    let dir = Dir::new();
    let file = dir.put("copy", entry());
    let trust = TrustPolicy::builder().trail([2; 16]).build().unwrap();
    let report = Verifier::new(trust).verify_files([file.clone()]).unwrap();
    assert_eq!(report.trail(), [2; 16]);
    assert_eq!(report.records(), 0);
    assert_eq!((report.first_seq(), report.last_seq()), (None, None));
    let mismatch = kinds(&report, K::TrailMismatch);
    assert_eq!(mismatch.len(), 1);
    assert_eq!(mismatch[0].file(), Some(file.as_path()));
    assert_eq!(mismatch[0].line(), Some(1));
    assert!(mismatch[0].detail().contains("expected trail"));
    let multi = TrustPolicy::builder()
        .trail(TRAIL)
        .trail([2; 16])
        .build()
        .unwrap();
    let report = Verifier::new(multi)
        .trail([2; 16])
        .unwrap()
        .verify_files([file])
        .unwrap();
    assert_eq!(report.trail(), [2; 16]);
    assert_eq!(kinds(&report, K::TrailMismatch).len(), 1);
    assert_eq!(report.records(), 0);
}
#[test]
fn missing_explicit_file_is_io_with_source() {
    let dir = Dir::new();
    let error = Verifier::new(policy())
        .verify_files([dir.0.join("missing")])
        .unwrap_err();
    assert_eq!(error.kind(), AuditErrorKind::Io);
    assert!(error.source().is_some());
}
#[test]
fn decoder_kinds_collect_and_attribute_then_check_following_valid_line() {
    let valid = entry();
    let cases = [
        ("not json".to_owned(), K::Unparsable),
        (
            valid.replace("\"intValue\":\"1\"", "\"intValue\":\"2\""),
            K::UnknownVersion,
        ),
        ("{}".to_owned(), K::MissingField),
        (
            "{\"resourceLogs\":[],\"unknown\":1}".to_owned(),
            K::UnknownField,
        ),
        ("{\"a\":1,\"a\":1}".to_owned(), K::InvalidField),
        (
            valid.replace("sample.modify", "sample.forged"),
            K::HashMismatch,
        ),
    ];
    let dir = Dir::new();
    for (index, (bad, kind)) in cases.into_iter().enumerate() {
        let file = dir.put(&format!("copy-{index}"), format!("{bad}\n{valid}\n"));
        let report = Verifier::new(policy())
            .verify_files([file.clone()])
            .unwrap();
        assert_eq!(report.records(), 1, "{kind:?}");
        assert_eq!(report.first_seq(), Some(0));
        let findings = kinds(&report, kind);
        assert_eq!(findings.len(), 1, "{kind:?}: {:?}", report.findings());
        assert_eq!(findings[0].file(), Some(file.as_path()));
        assert_eq!(findings[0].line(), Some(1));
        assert!(kinds(&report, K::SegmentStructure).is_empty());
    }
}
#[test]
fn display_only_changes_are_one_authenticated_record_and_one_warning() {
    let dir = Dir::new();
    let edited = entry().replace("\"version\":\"0.0.0\"", "\"version\":\"9.0.0\"");
    assert_ne!(entry(), edited);
    let file = dir.put("copy", format!("{}\n{edited}\n{edited}\n", entry()));
    let report = Verifier::new(policy()).verify_files([file]).unwrap();
    assert!(report.is_valid(), "{:?}", report.findings());
    assert_eq!(report.records(), 1);
    assert_eq!(kinds(&report, K::DuplicateRecord).len(), 1);
    assert!(kinds(&report, K::SeqConflict).is_empty());
}
#[test]
fn native_boundaries_cannot_be_repaired_by_shipped_checkpoint() {
    let dir = Dir::new();
    let native = dir.put("audit.jsonl", entry());
    let shipped = dir.put("copy", GOLDEN.lines().nth(1).unwrap());
    let report = Verifier::new(policy())
        .verify_files([shipped, native.clone()])
        .unwrap();
    let structure = kinds(&report, K::SegmentStructure);
    assert_eq!(structure.len(), 1);
    assert_eq!(structure[0].file(), Some(native.as_path()));
    assert_eq!(structure[0].run_digest(), None);
    let empty = dir.put("audit-20261102T010203.000000000Z.jsonl", "");
    let report = Verifier::new(policy()).verify_files([empty]).unwrap();
    assert_eq!(kinds(&report, K::SegmentStructure).len(), 1);
}
#[test]
fn oversized_line_is_one_finding_and_following_record_survives() {
    let dir = Dir::new();
    let file = dir.put("copy", format!("{}\n{}\n", "x".repeat(1_100_000), entry()));
    let report = Verifier::new(policy()).verify_files([file]).unwrap();
    assert_eq!(report.records(), 1);
    assert_eq!(kinds(&report, K::Unparsable).len(), 1);
}
#[test]
fn reversed_shipped_files_and_batches_have_same_findings_and_physical_lines() {
    let dir = Dir::new();
    let mut batch: serde_json::Value = serde_json::from_str(entry()).unwrap();
    let logs = batch["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
        .as_array_mut()
        .unwrap();
    logs.push(logs[0].clone());
    let a = dir.put("a", format!("!\n{batch}\n"));
    let b = dir.put("b", entry());
    let verifier = Verifier::new(policy());
    let forward = verifier.verify_files([a.clone(), b.clone()]).unwrap();
    let reverse = verifier.verify_files([b, a.clone()]).unwrap();
    assert_eq!(forward.findings(), reverse.findings());
    assert_eq!(forward.records(), 1);
    assert_eq!(kinds(&forward, K::DuplicateRecord).len(), 1);
    assert_eq!(kinds(&forward, K::DuplicateRecord)[0].line(), Some(2));
    let bad = kinds(&forward, K::Unparsable);
    assert_eq!(bad[0].file(), Some(a.as_path()));
    assert_eq!(bad[0].line(), Some(1));
    batch["resourceLogs"][0]["scopeLogs"][0]["logRecords"][1]["attributes"][0]["value"]["intValue"] =
        "2".into();
    let invalid = dir.put("invalid-batch", format!("!\n{batch}\n{}\n", entry()));
    let report = verifier.verify_files([invalid]).unwrap();
    assert_eq!(kinds(&report, K::UnknownVersion)[0].line(), Some(2));
    assert_eq!(report.records(), 1); // The valid member in the failed batch never leaks.
    assert_eq!(kinds(&report, K::DuplicateRecord).len(), 0);
}

struct Written {
    dir: PathBuf,
    trail: PathBuf,
    key: PathBuf,
    trust: TrustPolicy,
    seqs: Vec<u64>,
}
impl Written {
    fn new(records: usize) -> Self {
        static ID: AtomicU64 = AtomicU64::new(1 << 20);
        let dir = std::env::temp_dir().join(format!(
            "vigil-verify-writer-{}-{}",
            std::process::id(),
            ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let key = dir.join("key");
        keygen(&key).unwrap();
        let trail_dir = dir.join("trail");
        let signer = Arc::new(KeyFileSigner::load(&key).unwrap());
        let writer = AuditConfig::new("svc")
            .dir(&trail_dir)
            .create(signer)
            .unwrap();
        let trail_id = writer.trail();
        let mut seqs = Vec::new();
        for i in 0..records {
            let r = writer
                .record(&Entry::new("a", "change", format!("o{i}")))
                .unwrap();
            seqs.push(r.seq());
        }
        let head = writer.close().unwrap();
        seqs.push(head.seq());
        let trust = TrustPolicy::builder().trail(trail_id).build().unwrap();
        Self {
            dir,
            trail: trail_dir,
            key,
            trust,
            seqs,
        }
    }
    fn signer(&self) -> Arc<KeyFileSigner> {
        Arc::new(KeyFileSigner::load(&self.key).unwrap())
    }
    fn live(&self) -> PathBuf {
        self.trail.join("audit.jsonl")
    }
    fn read(&self) -> Vec<u8> {
        fs::read(self.live()).unwrap()
    }
    fn write(&self, bytes: &[u8]) {
        fs::write(self.live(), bytes).unwrap();
    }
}
impl Drop for Written {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn mid_file_fragment_without_attestation_is_repair_mismatch_and_not_valid() {
    let fx = Written::new(3);
    let before = fx.read();
    // Insert a fragment line between the first record line and the second.
    let first_lf = before.iter().position(|&b| b == b'\n').unwrap();
    let second_lf = before[first_lf + 1..]
        .iter()
        .position(|&b| b == b'\n')
        .unwrap()
        + first_lf
        + 1;
    let junk: &[u8] = b"{\"resourceLogs\":[\n";
    let mut after = Vec::new();
    after.extend_from_slice(&before[..=second_lf]);
    after.extend_from_slice(junk);
    after.extend_from_slice(&before[second_lf + 1..]);
    fx.write(&after);
    let report = verify(&fx.trail, &fx.trust).unwrap();
    assert!(!report.is_valid(), "{:?}", report.findings());
    let rm = kinds(&report, K::RepairMismatch);
    assert_eq!(rm.len(), 1, "{:?}", report.findings());
    assert!(
        kinds(&report, K::TornWrite).is_empty(),
        "{:?}",
        report.findings()
    );
    // The finding points at the gap's physical line, not the following record.
    assert_eq!(rm[0].line(), Some(3));
    let d = rm[0].detail();
    assert!(d.contains("lines 3..=3"), "{d}");
    assert!(d.contains(&format!("({} bytes)", junk.len())), "{d}");
    assert!(d.contains("attested at line 4"), "{d}");
}

#[test]
fn junk_as_first_line_attributes_gap_to_line_one() {
    let dir = Dir::new();
    let valid = entry();
    let junk = "{\"resourceLogs\":[\n";
    let native = dir.0.join("audit.jsonl");
    fs::write(&native, format!("{junk}{valid}\n")).unwrap();
    let report = verify(&dir.0, &policy()).unwrap();
    let rm = kinds(&report, K::RepairMismatch);
    assert_eq!(rm.len(), 1, "{:?}", report.findings());
    assert_eq!(rm[0].line(), Some(1));
    let d = rm[0].detail();
    assert!(d.contains("lines 1..=1"), "{d}");
    assert!(d.contains(&format!("({} bytes)", junk.len())), "{d}");
    assert!(d.contains("attested at line 2"), "{d}");
    // V3b-1: a file-start fragment run also raises Unparsable per fragment line.
    let unparsable: Vec<_> = kinds(&report, K::Unparsable)
        .into_iter()
        .filter(|f| f.detail() == "fragment line failed context")
        .collect();
    assert_eq!(unparsable.len(), 1);
    assert_eq!(unparsable[0].line(), Some(1));
}

#[test]
fn multi_line_gap_covers_every_junk_line_in_the_range() {
    let fx = Written::new(3);
    let before = fx.read();
    let first_lf = before.iter().position(|&b| b == b'\n').unwrap();
    let second_lf = before[first_lf + 1..]
        .iter()
        .position(|&b| b == b'\n')
        .unwrap()
        + first_lf
        + 1;
    let junk: &[u8] = b"{\"resourceLogs\":[\n{\"resourceLogs\":[\n";
    let mut after = Vec::new();
    after.extend_from_slice(&before[..=second_lf]);
    after.extend_from_slice(junk);
    after.extend_from_slice(&before[second_lf + 1..]);
    fx.write(&after);
    let report = verify(&fx.trail, &fx.trust).unwrap();
    let rm = kinds(&report, K::RepairMismatch);
    assert_eq!(rm.len(), 1, "{:?}", report.findings());
    assert_eq!(rm[0].line(), Some(3));
    let d = rm[0].detail();
    assert!(d.contains("lines 3..=4"), "{d}");
    assert!(d.contains(&format!("({} bytes)", junk.len())), "{d}");
    assert!(d.contains("attested at line 5"), "{d}");
}

#[test]
fn trailing_fragment_is_torn_write_and_reports_prior_last_seq() {
    let fx = Written::new(2);
    let before = fx.read();
    // Cut the final line (the close checkpoint) in half.
    let last_lf = before.iter().rposition(|&b| b == b'\n').unwrap();
    let prev_lf = before[..last_lf].iter().rposition(|&b| b == b'\n').unwrap();
    let cut = prev_lf + 1 + (last_lf - prev_lf - 1) / 2;
    let gap_bytes = (cut - (prev_lf + 1)) as u64;
    fx.write(&before[..cut]);
    let report = verify(&fx.trail, &fx.trust).unwrap();
    let tw = kinds(&report, K::TornWrite);
    assert_eq!(tw.len(), 1, "{:?}", report.findings());
    let d = tw[0].detail();
    assert!(d.contains("trailing gap"), "{d}");
    assert!(d.contains("digest blake3:"), "{d}");
    // Attribution points at the gap's own physical line, not past EOF.
    assert_eq!(tw[0].line(), Some(4));
    assert!(d.contains("lines 4..=4"), "{d}");
    assert!(d.contains(&format!("({gap_bytes} bytes)")), "{d}");
    let penultimate = fx.seqs[fx.seqs.len() - 2];
    assert_eq!(report.last_seq(), Some(penultimate));
    assert!(kinds(&report, K::RepairMismatch).is_empty());
}

#[test]
fn honest_crash_writer_attests_gap_and_mutating_a_byte_turns_it_into_repair_mismatch() {
    let fx = Written::new(2);
    let before = fx.read();
    // Truncate the closing checkpoint mid-line to simulate a crash.
    let last_lf = before.iter().rposition(|&b| b == b'\n').unwrap();
    let prev_lf = before[..last_lf].iter().rposition(|&b| b == b'\n').unwrap();
    let cut = prev_lf + 1 + (last_lf - prev_lf - 1) / 2;
    // The fragment on disk is `before[prev_lf + 1 .. cut]`; on reopen the
    // writer prepends a leading LF to its next record (`needs_newline`),
    // so the verifier's stream classifies the fragment line as
    // `<fragment_bytes> \n`. Hence the attested gap is one byte longer.
    let gap_bytes = (cut - (prev_lf + 1)) as u64 + 1;
    fx.write(&before[..cut]);
    // The writer reopens, settles the torn tail, and attests the gap on the next record.
    let reopened = AuditConfig::new("svc")
        .dir(&fx.trail)
        .open(fx.signer())
        .unwrap();
    let resumed = reopened
        .record(&Entry::new("a", "change", "resumed"))
        .unwrap();
    drop(reopened);
    let report = verify(&fx.trail, &fx.trust).unwrap();
    let tw = kinds(&report, K::TornWrite);
    assert_eq!(tw.len(), 1, "{:?}", report.findings());
    assert!(kinds(&report, K::RepairMismatch).is_empty());
    assert!(kinds(&report, K::TornWriteRepaired).is_empty());
    // The attested gap points at the gap line itself and names its exact byte
    // length (#193 / 191-d1 tightening: previously only `"bytes)"` was checked).
    assert_eq!(tw[0].line(), Some(4));
    let d = tw[0].detail();
    assert!(d.contains("lines 4..=4"), "{d}");
    assert!(d.contains(&format!("({gap_bytes} bytes)")), "{d}");
    assert!(
        d.contains(&format!("attested at line 5 seq {}", resumed.seq())),
        "{d}"
    );
    // Now flip one gap byte and re-verify: attestation no longer matches.
    let mut mutated = fs::read(fx.live()).unwrap();
    mutated[cut - 1] ^= 1; // flip a bit inside the torn fragment
    fx.write(&mutated);
    let report = verify(&fx.trail, &fx.trust).unwrap();
    assert!(
        kinds(&report, K::TornWrite).is_empty(),
        "{:?}",
        report.findings()
    );
    let rm = kinds(&report, K::RepairMismatch);
    assert_eq!(rm.len(), 1);
    assert_eq!(rm[0].line(), Some(4));
    let d = rm[0].detail();
    assert!(d.contains("lines 4..=4"), "{d}");
    assert!(d.contains(&format!("({gap_bytes} bytes)")), "{d}");
    assert!(
        d.contains(&format!("attested at line 5 seq {}", resumed.seq())),
        "{d}"
    );
    assert!(
        d.contains("expected blake3:") && d.contains("got blake3:"),
        "{d}"
    );
}

#[test]
fn shipped_repaired_record_without_preceding_gap_is_torn_write_repaired() {
    let fx = Written::new(2);
    let before = fx.read();
    // Produce an authentic torn-and-repaired native file.
    let last_lf = before.iter().rposition(|&b| b == b'\n').unwrap();
    let prev_lf = before[..last_lf].iter().rposition(|&b| b == b'\n').unwrap();
    let cut = prev_lf + 1 + (last_lf - prev_lf - 1) / 2;
    fx.write(&before[..cut]);
    let reopened = AuditConfig::new("svc")
        .dir(&fx.trail)
        .open(fx.signer())
        .unwrap();
    let receipt = reopened
        .record(&Entry::new("a", "change", "resumed"))
        .unwrap();
    drop(reopened);
    // Extract only the attesting record line into a shipped copy.
    let full = fx.read();
    let lines: Vec<&[u8]> = full
        .split_inclusive(|&b| b == b'\n')
        .filter(|l| {
            serde_json::from_slice::<serde_json::Value>(l.strip_suffix(b"\n").unwrap_or(l)).is_ok()
        })
        .collect();
    let repaired_line = lines
        .iter()
        .find(|l| l.windows(14).any(|w| w == b"audit.repaired"))
        .expect("the resumed record carries audit.repaired");
    let shipped_dir = Dir::new();
    let shipped = shipped_dir.put("copy", repaired_line);
    let report = Verifier::new(fx.trust.clone())
        .verify_files([shipped.clone()])
        .unwrap();
    let twr = kinds(&report, K::TornWriteRepaired);
    assert_eq!(twr.len(), 1, "{:?}", report.findings());
    assert_eq!(twr[0].file(), Some(shipped.as_path()));
    assert_eq!(twr[0].detail(), "fragment not present");
    assert_eq!(twr[0].seq(), Some(receipt.seq()));
}

#[test]
fn fragment_line_in_shipped_input_is_unparsable() {
    let dir = Dir::new();
    let valid = entry();
    let file = dir.put("copy", format!("{{\"resourceLogs\":[\n{valid}\n"));
    let report = Verifier::new(policy())
        .verify_files([file.clone()])
        .unwrap();
    let bad = kinds(&report, K::Unparsable);
    assert_eq!(bad.len(), 1, "{:?}", report.findings());
    assert_eq!(bad[0].file(), Some(file.as_path()));
    assert_eq!(bad[0].line(), Some(1));
    assert_eq!(report.records(), 1); // The following valid record is still checked.
}

#[test]
fn decoder_errors_after_seq_is_read_carry_the_seq_and_sort_by_it() {
    let dir = Dir::new();
    let valid = entry();
    // Each of these reads audit.seq (= 0) before failing.
    let missing = valid.replace(
        "{\"key\":\"audit.actor\",\"value\":{\"stringValue\":\"α\"}},",
        "",
    );
    assert_ne!(valid, missing);
    // Inject a brand-new attribute key so UnknownField fires after seq is read.
    let unknown = valid.replace(
        "{\"key\":\"audit.hash\"",
        "{\"key\":\"audit.unknownZ\",\"value\":{\"stringValue\":\"x\"}},{\"key\":\"audit.hash\"",
    );
    assert_ne!(valid, unknown);
    // Non-hex prev_hash is InvalidField, raised after audit.seq is read.
    let invalid = valid.replacen("blake3:a03c7c40", "blake3:zzzzzzzz", 1);
    assert!(invalid.contains("blake3:zzzz"));
    let not_json = "not json";
    let bytes = format!("{missing}\n{unknown}\n{invalid}\n{not_json}\n{valid}\n");
    let file = dir.put("copy", bytes);
    let report = Verifier::new(policy()).verify_files([file]).unwrap();
    for (kind, line) in [
        (K::MissingField, 1u64),
        (K::UnknownField, 2),
        (K::InvalidField, 3),
    ] {
        let fs = kinds(&report, kind);
        assert_eq!(fs.len(), 1, "{kind:?}: {:?}", report.findings());
        assert_eq!(fs[0].line(), Some(line), "{kind:?}");
        assert_eq!(fs[0].seq(), Some(0), "{kind:?}");
    }
    // Seqless Unparsable sorts after every seq-bearing finding.
    let order: Vec<_> = report.findings().iter().map(|f| f.kind()).collect();
    let unparsable = order.iter().position(|k| *k == K::Unparsable).unwrap();
    for k in [K::MissingField, K::UnknownField, K::InvalidField] {
        let pos = order.iter().position(|kk| *kk == k).unwrap();
        assert!(
            pos < unparsable,
            "{k:?} must sort before Unparsable; order: {order:?}"
        );
    }
}

#[test]
fn hash_mismatch_carries_seq_and_sorts_before_seqless_findings() {
    let dir = Dir::new();
    let valid = entry();
    let edited = valid.replace("sample.modify", "sample.forged");
    assert_ne!(valid, edited);
    let not_json = "not json";
    // Edited (HashMismatch, seq=0) must sort before the unparsable (no seq).
    let file = dir.put("copy", format!("{edited}\n{not_json}\n"));
    let report = Verifier::new(policy())
        .verify_files([file.clone()])
        .unwrap();
    let mismatches = kinds(&report, K::HashMismatch);
    assert_eq!(mismatches.len(), 1, "{:?}", report.findings());
    assert_eq!(mismatches[0].seq(), Some(0));
    let unparsable = kinds(&report, K::Unparsable);
    assert_eq!(unparsable.len(), 1);
    assert_eq!(unparsable[0].seq(), None);
    // Seq-bearing finding comes first.
    let order: Vec<_> = report.findings().iter().map(|f| f.kind()).collect();
    let hash_pos = order.iter().position(|k| *k == K::HashMismatch).unwrap();
    let unp_pos = order.iter().position(|k| *k == K::Unparsable).unwrap();
    assert!(hash_pos < unp_pos, "ordering: {order:?}");
}

/// V3b-1: uncovered tail (addendum 7).
#[test]
fn clean_writer_trail_emits_uncovered_tail_and_strict_is_false() {
    let fx = Written::new(2);
    let report = verify(&fx.trail, &fx.trust).unwrap();
    assert!(report.is_valid(), "{:?}", report.findings());
    assert!(!report.is_strict_valid());
    let tails = kinds(&report, K::UncoveredTail);
    assert_eq!(tails.len(), 1, "{:?}", report.findings());
    assert!(tails[0].detail().contains("records seq"));
    assert!(
        tails[0]
            .detail()
            .contains("signatures are checked in #13 V5")
    );
}

#[test]
fn empty_trail_emits_no_uncovered_tail() {
    let dir = Dir::new();
    let report = verify(&dir.0, &policy()).unwrap();
    assert!(kinds(&report, K::UncoveredTail).is_empty());
    assert_eq!(report.records(), 0);
}

/// V3b-1: honest crash with fragment run condition 3 holding (regression over base).
#[test]
fn consecutive_crashes_from_honest_writer_give_one_gap_no_unparsable() {
    let fx = Written::new(2);
    let before = fx.read();
    // Simulate two consecutive torn tails: cut the closing checkpoint in half,
    // then append another junk fragment that the writer later repairs.
    let last_lf = before.iter().rposition(|&b| b == b'\n').unwrap();
    let prev_lf = before[..last_lf].iter().rposition(|&b| b == b'\n').unwrap();
    let cut = prev_lf + 1 + (last_lf - prev_lf - 1) / 2;
    let mut after = before[..cut].to_vec();
    after.extend_from_slice(b"\n{\"resourceLogs\":[");
    fx.write(&after);
    let reopened = AuditConfig::new("svc")
        .dir(&fx.trail)
        .open(fx.signer())
        .unwrap();
    reopened
        .record(&Entry::new("a", "change", "resumed"))
        .unwrap();
    drop(reopened);
    let report = verify(&fx.trail, &fx.trust).unwrap();
    let tw = kinds(&report, K::TornWrite);
    assert_eq!(tw.len(), 1, "{:?}", report.findings());
    // No Unparsable "fragment line failed context": the run links.
    for u in kinds(&report, K::Unparsable) {
        assert!(
            !u.detail().contains("failed context"),
            "unexpected unparsable: {}",
            u.detail()
        );
    }
}

/// V3b-1: a file-start fragment run fails condition 3 (no "before" record):
/// each line is `Unparsable` AND V3a-2's gap finding stays.
#[test]
fn file_start_fragment_run_is_unparsable_with_unchanged_gap_digest() {
    let dir = Dir::new();
    let valid = entry();
    let junk = "{\"resourceLogs\":[\n{\"resourceLogs\":[\n";
    let native = dir.0.join("audit.jsonl");
    fs::write(&native, format!("{junk}{valid}\n")).unwrap();
    let report = verify(&dir.0, &policy()).unwrap();
    // V3a-2's gap finding is still a RepairMismatch.
    let rm = kinds(&report, K::RepairMismatch);
    assert_eq!(rm.len(), 1);
    // Each fragment line is now Unparsable with "fragment line failed context".
    let failed: Vec<_> = kinds(&report, K::Unparsable)
        .into_iter()
        .filter(|f| f.detail() == "fragment line failed context")
        .collect();
    assert_eq!(failed.len(), 2, "{:?}", report.findings());
    assert_eq!(failed[0].line(), Some(1));
    assert_eq!(failed[1].line(), Some(2));
    // Gap length unchanged (byte-for-byte V2 parity).
    assert!(rm[0].detail().contains(&format!("({} bytes)", junk.len())));
}

/// V3b-1: every resume record raises a Resumed warning via the public API.
#[test]
fn resume_record_from_writer_emits_one_resumed_with_parsed_detail() {
    use vigil::audit::{AuditConfig, checkpoints};
    let fx = Written::new(1); // Trail with the opening + one record + closing checkpoint.
    // Use the closing checkpoint as the resume head: nothing-lost resume.
    let cps = checkpoints(&fx.trail).unwrap();
    let closing = cps
        .iter()
        .max_by_key(|c| c.seq())
        .expect("closing checkpoint");
    let head = (closing.seq(), closing.hash());
    let (trail, _receipt, _opening) = AuditConfig::new("svc")
        .dir(&fx.trail)
        .resume(fx.signer(), head, head.0, "operator", "reviewed")
        .unwrap();
    drop(trail);
    let report = verify(&fx.trail, &fx.trust).unwrap();
    let resumed = kinds(&report, K::Resumed);
    assert_eq!(resumed.len(), 1, "{:?}", report.findings());
    assert!(resumed[0].detail().contains("operator=operator"));
    assert!(resumed[0].detail().contains("reason=reviewed"));
    assert!(resumed[0].detail().contains("gap=none"));
    assert!(resumed[0].detail().contains("lost_records=0"));
    assert!(!report.is_strict_valid());
}

// ---------- #13 V3b-2 writer-driven acceptance (ruling 13-V3-d5) ----------

/// A1: a writer-produced nothing-lost resume marks `structural=valid`.
#[test]
fn v3b2_writer_nothing_lost_resume_marks_structural_valid() {
    use vigil::audit::checkpoints;
    let fx = Written::new(1);
    let cps = checkpoints(&fx.trail).unwrap();
    let closing = cps
        .iter()
        .max_by_key(|c| c.seq())
        .expect("closing checkpoint");
    let head = (closing.seq(), closing.hash());
    let (trail, _receipt, _opening) = AuditConfig::new("svc")
        .dir(&fx.trail)
        .resume(fx.signer(), head, head.0, "operator", "reviewed")
        .unwrap();
    drop(trail);
    let report = verify(&fx.trail, &fx.trust).unwrap();
    let resumed = kinds(&report, K::Resumed);
    assert_eq!(resumed.len(), 1, "{:?}", report.findings());
    let detail = resumed[0].detail();
    assert!(
        detail.ends_with(" gap=none lost_records=0 structural=valid"),
        "{detail}"
    );
}

/// A12: the full detail string matches V3b-2's grammar byte-for-byte (the
/// head form is `head=<seq>:blake3:<hex>`, from `parse_resume`).
#[test]
fn v3b2_writer_resume_detail_matches_structural_valid_grammar() {
    use vigil::audit::checkpoints;
    let fx = Written::new(1);
    let cps = checkpoints(&fx.trail).unwrap();
    let closing = cps
        .iter()
        .max_by_key(|c| c.seq())
        .expect("closing checkpoint");
    let head = (closing.seq(), closing.hash());
    let (trail, _receipt, _opening) = AuditConfig::new("svc")
        .dir(&fx.trail)
        .resume(fx.signer(), head, head.0, "operator", "reviewed")
        .unwrap();
    drop(trail);
    let report = verify(&fx.trail, &fx.trust).unwrap();
    let resumed = kinds(&report, K::Resumed);
    assert_eq!(resumed.len(), 1, "{:?}", report.findings());
    let hex: String = closing.hash().iter().map(|b| format!("{b:02x}")).collect();
    let expected = format!(
        "operator=operator reason=reviewed head={}:blake3:{} gap=none lost_records=0 structural=valid",
        closing.seq(),
        hex
    );
    assert_eq!(resumed[0].detail(), expected);
}

/// #193: integration test for `mark_no_crash` on a real writer trail
/// that pins the NATIVE-successor condition against the mutant
/// `.find(|i| i.native)` → `.next()`. `verify::input::collect` orders
/// inputs by `(rank, segment_key, path)` with rank 0 for sealed native
/// segments, 1 for `audit.jsonl` and 2 for every non-native filename
/// (`src/audit/verify/input.rs:100-108`), so a shipped copy always
/// sorts AFTER every native input. The only layout at integration
/// level in which the mutant observably diverges from the production
/// code is therefore: a sealed native archive with a trailing fragment,
/// followed in `inputs` by a non-native shipped copy whose first
/// record happens to be the opening checkpoint the real successor
/// would carry (because it is a verbatim copy of the live file), and
/// NO native successor among the explicit inputs. Production code
/// returns `None` from `.find(|i| i.native)` → the archive's trailing
/// TornWrite stays unmarked (ADR-0005 §19.6: "An archive verified
/// alone, without the file after it, cannot set the mark"). The
/// mutant's `.next()` picks the shipped copy as the "successor"; its
/// opening checkpoint satisfies every structural condition
/// (`seq == closing.seq + 1`, `previous == closing.hash`, second
/// record not resume), so the mutant would incorrectly SET the mark.
#[test]
fn no_crash_mark_absent_when_only_successor_is_a_shipped_copy() {
    let dir = std::env::temp_dir().join(format!(
        "vigil-verify-mark-shipped-{}-{}",
        std::process::id(),
        std::sync::atomic::AtomicU64::new(1).fetch_add(1, Ordering::Relaxed) + 4096,
    ));
    fs::create_dir(&dir).unwrap();
    let key = dir.join("key");
    keygen(&key).unwrap();
    let signer = Arc::new(KeyFileSigner::load(&key).unwrap());
    let trail_dir = dir.join("trail");
    let config = AuditConfig::new("svc").dir(&trail_dir).max_bytes(1);
    let writer = config.clone().create(signer.clone()).unwrap();
    let trail_id = writer.trail();
    // Each `record()` with max_bytes=1 forces the sink to seal and open
    // a new segment; sealed segment filenames start with `audit-`.
    writer.record(&Entry::new("a", "change", "o1")).unwrap();
    writer.record(&Entry::new("a", "change", "o2")).unwrap();
    writer.close().unwrap();
    let trust = TrustPolicy::builder().trail(trail_id).build().unwrap();
    // Pick the LATEST sealed archive: its closing checkpoint links
    // forward to the live file's opening checkpoint, which is what the
    // shipped copy will hold. The sealed-segment timestamp in the
    // filename sorts lexicographically with physical seal order.
    let live_path = trail_dir.join("audit.jsonl");
    let mut archives: Vec<_> = fs::read_dir(&trail_dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with("audit-") && n.ends_with(".jsonl"))
        })
        .collect();
    assert!(
        !archives.is_empty(),
        "sealed archive segment missing; dir={:?}",
        fs::read_dir(&trail_dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
    );
    archives.sort_by_key(|e| e.file_name());
    let archive = archives.last().unwrap().path();
    // Copy the live file verbatim to a non-native filename (rank 2 in
    // `input::collect`), so that in `inputs` order it sits AFTER the
    // archive and no native successor exists. The copy's first record
    // is the live's opening checkpoint, which links back to `archive`'s
    // closing: every mutant-side structural check would therefore pass.
    let shipped_copy = dir.join("live-copy.audit");
    fs::copy(&live_path, &shipped_copy).unwrap();
    // Append a trailing fragment (incomplete JSON) to the archive.
    let before = fs::read(&archive).unwrap();
    let mut after = before.clone();
    after.extend_from_slice(b"{\"resourceLogs\":[");
    fs::write(&archive, &after).unwrap();
    // Verify ONLY [archive, shipped-copy] — explicitly NOT the trail
    // directory, so the live `audit.jsonl` is not picked up as a
    // native successor.
    let report = Verifier::new(trust)
        .verify_files([archive.clone(), shipped_copy.clone()])
        .unwrap();
    let archive_tw: Vec<_> = kinds(&report, K::TornWrite)
        .into_iter()
        .filter(|f| f.file() == Some(archive.as_path()))
        .collect();
    assert_eq!(archive_tw.len(), 1, "{:?}", report.findings());
    assert!(
        !archive_tw[0].detail().contains("no crash outcome"),
        "{}",
        archive_tw[0].detail()
    );
    fs::remove_dir_all(&dir).unwrap();
}

/// A7w: delete the live file after `Written::new(1)`, then resume with a
/// genesis-shaped declaration. Under d5 S3 with no record present below
/// `k=3` → `structural=valid`; if the writer rotated a segment below `k`
/// (not expected for Written::new(1) on origin/dev f91e714), S3b fires
/// `genesis-not-first` instead. The suffix is pinned from a real run.
#[test]
fn v3b2_writer_genesis_resume_after_live_delete_emits_genesis_gap_and_pinned_suffix() {
    let fx = Written::new(1);
    // Recover the trail's genesis value from the seq-0 line's
    // `audit.prev_hash` attribute, which the writer emits as
    // `"stringValue":"blake3:<hex>"` right after `"key":"audit.prev_hash"`.
    let bytes = fs::read(fx.live()).unwrap();
    let first_lf = bytes.iter().position(|&b| b == b'\n').unwrap();
    let line0 = std::str::from_utf8(&bytes[..first_lf]).unwrap();
    let key_marker = "\"key\":\"audit.prev_hash\"";
    let value_marker = "\"stringValue\":\"blake3:";
    let key_pos = line0.find(key_marker).unwrap();
    let after_key = &line0[key_pos..];
    let value_pos = after_key.find(value_marker).unwrap() + value_marker.len();
    let hex_start = key_pos + value_pos;
    let mut genesis = [0u8; 32];
    for i in 0..32 {
        genesis[i] =
            u8::from_str_radix(&line0[hex_start + 2 * i..hex_start + 2 * i + 2], 16).unwrap();
    }
    // Delete the live file so no records with seq < 3 remain visible.
    fs::remove_file(fx.live()).unwrap();
    let head = (0u64, genesis);
    let (trail, _receipt, _opening) = AuditConfig::new("svc")
        .dir(&fx.trail)
        .resume(fx.signer(), head, 2, "operator", "reviewed")
        .unwrap();
    drop(trail);
    let report = verify(&fx.trail, &fx.trust).unwrap();
    let resumed = kinds(&report, K::Resumed);
    assert_eq!(resumed.len(), 1, "{:?}", report.findings());
    // #195 A7w: full-string equality on the detail. Under d5 S3 with no
    // record present below k=3 → `structural=valid`; `Written::new(1)`
    // rotates nothing (one `record()` plus a `close()` keep everything
    // in the single live file), so after `remove_file(live)` no record
    // below `k=3` survives on disk and S3b passes.
    let hex: String = genesis.iter().map(|b| format!("{b:02x}")).collect();
    let expected = format!(
        "operator=operator reason=reviewed head=0:blake3:{hex} \
         gap=0..=2 lost_records=0 structural=valid"
    );
    assert_eq!(resumed[0].detail(), expected);
}
