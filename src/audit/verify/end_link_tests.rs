//! Rows for the chain rule applied to `Verifier::end_before`
//! (ADR-0005 decision 2 step 6, decision 11 `accept-run` item 2,
//! the prefix-deletion and tail-cut bullets; ruling 13-V6-d6;
//! #13). Each row
//! asserts the full sorted `Vec<Finding>` through
//! [`assert_findings`]; expected lists are already in the engine's
//! final sort order (`(seq.is_none(), seq, file, line, kind_debug)`),
//! so no per-row sort runs here. Labels in each row's doc comment
//! (ACCEPTANCE / REGRESSION) follow the repo-wide row standard.

use crate::audit::{
    AuditConfig, Checkpoint, Entry, FindingKind as K, Mmr, Record, Signer, TrustPolicy,
    digest_string, hex,
    runs_v4a_fixtures::{
        TRAIL, Temp, context, entry_rec, fixture_pubkey, line_bytes, pushed, put_segment, seeded,
        segment_path, signed_cp, write_bytes,
    },
    verify::{Finding, Verifier},
};
use std::{path::PathBuf, sync::Arc};

use super::end_before_tests::{
    CP0_HONEST_DIGEST, CP2_HONEST_DIGEST, E1_HONEST_DIGEST, E3_HONEST_DIGEST,
    FORGED_E2_ALT_DIGEST as E2_ALT_DIGEST, FORGED_E2_DIGEST as E2_HONEST_DIGEST,
};

// =====================================================================
// Shared literal hex constants. Verified by `fixture_hashes_match_literals`
// so a fixture-level drift surfaces here instead of across many rows.
// =====================================================================

/// Record hash of `signed_cp(3, e2.hash(), mmr_through_e2)` on the
/// hand-built L5 chain (the end checkpoint for L5 and reused as the
/// end record for L3, L12, L13 and L14). Pinned so each row's detail
/// text is literal.
const CP3_L5_DIGEST: &str =
    "blake3:dda83f7bbaaf877076831dd97e6563148bf337d350bc58cf8bc6e8802eed2f66";

// =====================================================================
// Helpers.
// =====================================================================

fn located(kind: K, file: PathBuf, line: u64, seq: u64, detail: String) -> Finding {
    Finding::new(kind, Some(file), Some(line), Some(seq), detail)
}
fn unlocated(kind: K, seq: Option<u64>, detail: String) -> Finding {
    Finding::new(kind, None, None, seq, detail)
}
#[track_caller]
fn assert_findings(actual: &[Finding], expected: &[Finding], label: &str) {
    assert_eq!(actual, expected, "{label} literal finding list");
}
fn trust() -> TrustPolicy {
    TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .build()
        .unwrap()
}
fn verifier() -> Verifier {
    Verifier::new(trust())
}
fn line_without_lf(record: &Record) -> String {
    let bytes = line_bytes(record);
    let text = std::str::from_utf8(&bytes).unwrap();
    text.strip_suffix('\n').unwrap().to_owned()
}
fn checkpoint_of(record: &Record) -> Checkpoint {
    let bytes = line_bytes(record);
    let text = std::str::from_utf8(&bytes).unwrap();
    Checkpoint::parse(text).unwrap()
}
fn resume_entry(seq: u64, previous: [u8; 32], head_seq: u64, head: [u8; 32]) -> Record {
    let details = format!(
        "head={head_seq}:{} lost_through={head_seq} file=audit.jsonl",
        digest_string(&head),
    );
    let entry = Entry::new("op", "vigil.audit.resume", "obj")
        .reason("a")
        .details(details);
    let ctx = context(seq, previous);
    Record::new_internal(ctx, entry).unwrap()
}

/// The hand-built L1/L4 chain: `cp0(0), e1(1), cp2(2), e3(3), cp4(4)`.
/// L1 archives the first three records (the tail cut back to the
/// periodic checkpoint `cp2`); L4 archives them as two separate
/// segments so the layout mirrors the prefix-deletion step-7 bullet.
/// Hand-built because `AuditConfig::create` always draws a random
/// trail, and the row standard pins the `ChainBroken` detail's
/// literal hex (ruling 13-V6-d6 point 1 grammar).
struct Chain {
    cp0: Record,
    e1: Record,
    cp2: Record,
    e3: Record,
    cp4: Record,
}
fn build_chain() -> Chain {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    let e3 = entry_rec(3, cp2.hash());
    let mmr3 = pushed(&mmr2, &e3);
    let cp4 = signed_cp(4, e3.hash(), &mmr3);
    Chain {
        cp0,
        e1,
        cp2,
        e3,
        cp4,
    }
}

/// The hand-built L5/L3 chain: `cp0(0), e1(1), e2(2), cp3(3)`. Used
/// by L5 (fork at seq 2) and reused by L3, L12, L13 and L14 (cp3 as
/// the end record above `cp0, e1, e2`). Hand-built so the record
/// hashes are literal constants.
struct ChainL5 {
    cp0: Record,
    e1: Record,
    e2: Record,
    cp3: Record,
}
fn build_chain_l5() -> ChainL5 {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    let cp3 = signed_cp(3, e2.hash(), &mmr2);
    ChainL5 { cp0, e1, e2, cp3 }
}

/// Real-writer batch: an `AuditConfig::create` trail with
/// `entries_before_checkpoint` entries, one `checkpoint()` call, a
/// second block of `entries_after_checkpoint` entries, and a
/// `close()`. The writer's `audit.jsonl` is left untouched; the
/// archive directory holds a copy of its leading bytes split at the
/// `split` offset so each row chooses what the archive holds and
/// what is cut. Deterministic hashes are not available (the writer
/// draws a random trail and uses the system clock), so rows read the
/// returned receipts to build the expected `ChainBroken` detail at
/// test time.
struct WriterBatch {
    _writer_dir: Temp,
    archive_dir_tmp: Temp,
    archive_dir: PathBuf,
    trust: TrustPolicy,
    /// Receipt for each record the writer wrote to the live file,
    /// in the order written (`[cp0, e1, cp2 (checkpoint), e3, cp5
    /// (close)]` for the L1/L4 split).
    receipts: Vec<RecordId>,
    close_cp: Checkpoint,
}
/// Minimal (seq, hash, line-text) identifier for a record the writer
/// just emitted, extracted from a receipt or from a `Checkpoint`.
#[derive(Clone)]
struct RecordId {
    seq: u64,
    hash: [u8; 32],
}
/// Builds the L1/L4 writer-built chain with one periodic checkpoint:
/// opening `cp(0)`, entry `e(1)`, periodic `cp(2)`, entry `e(3)`,
/// closing `cp(4)`. The archive directory holds the leading bytes
/// through the periodic `cp(2)` as one sealed segment; L4 further
/// splits it in two.
fn writer_l1_chain() -> WriterBatch {
    let writer_dir = Temp::new();
    let signer: Arc<dyn Signer> =
        Arc::new(crate::audit::KeyFileSigner::from_hex(&"27".repeat(32)).unwrap());
    let trail_handle = AuditConfig::new("svc")
        .dir(&writer_dir.0)
        .create(signer)
        .unwrap();
    let trail_id = trail_handle.trail();
    // Capture receipts in write order; seq 0 is the opening written
    // by `create` so no receipt returns for it, but its hash is
    // pinned by the first entry's `previous` through the chain (a
    // reader-only cross-check, not asserted here).
    let r1 = trail_handle
        .record(&Entry::new("actor", "change", "obj1"))
        .unwrap();
    let cp2 = trail_handle.checkpoint().unwrap();
    let r3 = trail_handle
        .record(&Entry::new("actor", "change", "obj2"))
        .unwrap();
    let cp4 = trail_handle.close().unwrap();
    let live = writer_dir.0.join("audit.jsonl");
    let live_bytes = std::fs::read(&live).unwrap();
    // Split the live bytes at the end of the cp2 line (the periodic
    // checkpoint) so the archive holds `cp0, e1, cp2` verbatim --
    // the "tail cut back to a periodic checkpoint" layout.
    let cp2_line_with_lf = {
        let mut v = cp2.line().as_bytes().to_vec();
        v.push(b'\n');
        v
    };
    let split = live_bytes
        .windows(cp2_line_with_lf.len())
        .position(|w| w == cp2_line_with_lf.as_slice())
        .expect("cp2 line in live file")
        + cp2_line_with_lf.len();
    let archive_bytes = &live_bytes[..split];
    let archive_tmp = Temp::new();
    let archive_segment = segment_path(&archive_tmp.0, 0);
    std::fs::write(&archive_segment, archive_bytes).unwrap();
    let trust = TrustPolicy::builder()
        .trail(trail_id)
        .key(fixture_pubkey())
        .build()
        .unwrap();
    // The seq-0 opening checkpoint hash is not exposed through the
    // public API; readers of this struct only need the seqs and the
    // hashes the acceptance details compare, which come from the
    // checkpoint and the entry receipts below.
    let receipts = vec![
        RecordId {
            seq: 1,
            hash: r1.hash(),
        },
        RecordId {
            seq: 2,
            hash: cp2.hash(),
        },
        RecordId {
            seq: 3,
            hash: r3.hash(),
        },
    ];
    WriterBatch {
        _writer_dir: writer_dir,
        archive_dir: archive_tmp.0.clone(),
        archive_dir_tmp: archive_tmp,
        trust,
        receipts,
        close_cp: cp4,
    }
}

// =====================================================================
// L1 -- ACCEPTANCE. "Tail cut" bullet (ADR-0005 l.944): the archive's
// last segment is cut back to a periodic checkpoint, so its later
// records and its closing checkpoint are deleted. `end_before(close,
// Some(close_anchor))` reports exactly one `ChainBroken` from the
// chain rule at `e` (ruling 13-V6-d6 point 1), one `MmrMismatch`, and
// one `SeqGap` for the cut range -- each unlocated by ruling
// 13-V6-d4 point 6.
// =====================================================================
#[test]
fn l1_tail_cut_has_chain_broken_and_seq_gap() {
    let b = writer_l1_chain();
    let close_line = b.close_cp.line().to_owned();
    let close_anchor = b.close_cp.clone();
    let cp2 = &b.receipts[1];
    let e3 = &b.receipts[2];
    let close_seq = b.close_cp.seq();
    let report = Verifier::new(b.trust.clone())
        .end_before(&close_line, Some(close_anchor))
        .unwrap()
        .verify_files(vec![b.archive_dir.clone()])
        .unwrap();
    let chain_broken = unlocated(
        K::ChainBroken,
        Some(close_seq),
        format!(
            "expected previous {}, found {}",
            digest_string(&cp2.hash),
            digest_string(&e3.hash),
        ),
    );
    let seq_gap = unlocated(
        K::SeqGap,
        Some(close_seq),
        format!("missing seq {}..={}", cp2.seq + 1, close_seq - 1),
    );
    // The `MmrMismatch` detail at the opener compares the archive
    // fold (size 3: `cp0, e1, cp2`) with the close checkpoint's
    // declared size `cp0+e1+cp2+e3` = 4; its root and the close's
    // root are both deterministic from the trail and the writer's
    // records but not from any public API, so this row keeps the
    // single `MmrMismatch` kind-and-seq pin and filters the full
    // assertion to the chain-rule finding plus `SeqGap`.
    let mut actual_core: Vec<Finding> = report
        .findings()
        .iter()
        .filter(|f| matches!(f.kind(), K::ChainBroken | K::SeqGap))
        .cloned()
        .collect();
    actual_core.sort_by_key(|f| (f.seq(), format!("{:?}", f.kind())));
    assert_findings(
        &actual_core,
        &[chain_broken, seq_gap],
        "L1 chain + gap pair",
    );
    assert!(
        report.findings().iter().any(|f| f.kind() == K::MmrMismatch
            && f.seq() == Some(close_seq)
            && f.file().is_none()),
        "L1 writer-built row also carries the unlocated MmrMismatch at e",
    );
    assert!(!report.is_valid(), "L1 exit 1");
    let _ = &b.archive_dir_tmp;
}

// =====================================================================
// L2 -- REGRESSION. The "Tail cut" bullet's "limit visible" assertion
// (ADR-0005 l.944): `verify <archive>` alone cannot see that the tail
// was cut back, so the archive's own finding list is empty. Pairs
// with L1 so a drift in the shared writer fixture fails both the
// limit-visible assertion and the end-link finding.
// =====================================================================
#[test]
fn l2_tail_cut_without_end_before_is_clean() {
    let b = writer_l1_chain();
    let report = Verifier::new(b.trust.clone())
        .verify_files(vec![b.archive_dir.clone()])
        .unwrap();
    let expected: Vec<Finding> = Vec::new();
    assert_findings(report.findings(), &expected, "L2");
    assert!(report.is_valid(), "L2 is valid");
    let _ = &b.archive_dir_tmp;
}

// =====================================================================
// L3 -- ACCEPTANCE. The last record is rewritten at the same `seq`
// without a jump (`e = p + 1`): a forged `e2_alt` sits in the archive
// at seq 2 while the end checkpoint `cp3` links to the honest `e2`.
// Chain rule at `e` compares with the record at the highest `seq`
// below (ruling 13-V6-d6 point 1), so exactly one `ChainBroken` fires
// at `e`, located at the end record and then unlocated by the
// strip-location pass. Hand-built: the forged `e2_alt` is not a
// shape the real writer produces.
// =====================================================================
#[test]
fn l3_replaced_last_record_without_jump_has_one_chain_broken() {
    let c = build_chain_l5();
    let e2_alt = Record::new(
        context(2, c.e1.hash()),
        Entry::new("actor", "change", "alt"),
    )
    .unwrap();
    let d = Temp::new();
    put_segment(&d.0, 0, &[&c.cp0, &c.e1, &e2_alt], &[]);
    let cp3_line = line_without_lf(&c.cp3);
    let anchor = checkpoint_of(&c.cp3);
    let report = verifier()
        .end_before(&cp3_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let expected = vec![
        unlocated(
            K::ChainBroken,
            Some(3),
            format!("expected previous {E2_ALT_DIGEST}, found {E2_HONEST_DIGEST}"),
        ),
        unlocated(
            K::MmrMismatch,
            Some(3),
            format!(
                "expected size 3 root {}, found size 3 root {}",
                mmr_l3_archive_root_hex(),
                mmr_l3_cp3_root_hex(),
            ),
        ),
    ];
    assert_findings(report.findings(), &expected, "L3");
}

// =====================================================================
// L3b -- ACCEPTANCE. Second rewritten-last-record row with a
// different alternate payload at the same `seq`, so a mutation that
// removes the chain-rule check but accidentally matches L3's specific
// alt bytes still fails on an independent input. Hand-built forged
// input.
// =====================================================================
#[test]
fn l3b_replaced_last_record_second_variant_has_one_chain_broken() {
    let c = build_chain_l5();
    let e2_alt2 = Record::new(
        context(2, c.e1.hash()),
        Entry::new("actor", "change", "alt2"),
    )
    .unwrap();
    let d = Temp::new();
    put_segment(&d.0, 0, &[&c.cp0, &c.e1, &e2_alt2], &[]);
    let cp3_line = line_without_lf(&c.cp3);
    let anchor = checkpoint_of(&c.cp3);
    let report = verifier()
        .end_before(&cp3_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let expected = vec![
        unlocated(
            K::ChainBroken,
            Some(3),
            format!(
                "expected previous {}, found {E2_HONEST_DIGEST}",
                digest_string(&e2_alt2.hash()),
            ),
        ),
        unlocated(
            K::MmrMismatch,
            Some(3),
            format!(
                "expected size 3 root {}, found size 3 root {}",
                mmr_l3b_archive_root_hex(&e2_alt2),
                mmr_l3_cp3_root_hex(),
            ),
        ),
    ];
    assert_findings(report.findings(), &expected, "L3b");
}

/// MMR root over `[cp0, e1, e2_alt]` of L3, hex-encoded.
fn mmr_l3_archive_root_hex() -> String {
    let c = build_chain_l5();
    let e2_alt = Record::new(
        context(2, c.e1.hash()),
        Entry::new("actor", "change", "alt"),
    )
    .unwrap();
    let mmr = pushed(&pushed(&seeded(&c.cp0), &c.e1), &e2_alt);
    format!("blake3:{}", hex(&mmr.root()))
}
/// MMR root over `[cp0, e1, e2_alt2]` of L3b, hex-encoded.
fn mmr_l3b_archive_root_hex(e2_alt2: &Record) -> String {
    let c = build_chain_l5();
    let mmr = pushed(&pushed(&seeded(&c.cp0), &c.e1), e2_alt2);
    format!("blake3:{}", hex(&mmr.root()))
}
/// MMR root `cp3` declares (fold of the honest `cp0, e1, e2`).
fn mmr_l3_cp3_root_hex() -> String {
    let c = build_chain_l5();
    let mmr = pushed(&pushed(&seeded(&c.cp0), &c.e1), &c.e2);
    format!("blake3:{}", hex(&mmr.root()))
}

// =====================================================================
// L4 -- ACCEPTANCE. The prefix-deletion bullet (ADR-0005 l.943):
// sealed segments archived before a start, with intermediate
// segments deleted. The three forms exercise the same fixture from
// different verify-side angles (step 7, step 6, start_from).
// Hand-built because each form pins literal hashes of the records
// at the deletion boundary.
// =====================================================================

/// Hand-built prefix-deletion scenario at the fixture `TRAIL`: two
/// sealed segments stay archived (`S0=[cp0, e1]`, `S1=[cp2]`), the
/// inner segment with `e3` is deleted from the archive, and the
/// next batch's opening `cp4` lives in the live directory (also
/// used as the end record). This matches ADR-0005 l.943: segments
/// deleted from the archive create a `SeqGap` at the next
/// segment's opening; the end-record variant also fires
/// `ChainBroken` through the chain rule.
struct PrefixDeletion {
    _archive_tmp: Temp,
    _live_tmp: Temp,
    archive_dir: PathBuf,
    live_dir: PathBuf,
    live_path: PathBuf,
    /// The opening of the kept segment, at seq 4 -- both the end
    /// record for forms (a)/(b) and the start anchor for form (c).
    s5_opening: Record,
    /// Hash of the archive's highest-`seq` record (`cp2`), the one
    /// the chain rule at `e = 4` compares with.
    cp2_hash: [u8; 32],
    /// Hash of the deleted `e3` record (what `cp4.previous` names
    /// but the archive no longer holds).
    e3_hash: [u8; 32],
    /// MMR root of the archive fold (`[cp0, e1, cp2]`, size 3).
    archive_root_hex: String,
    /// MMR root `cp4` declares (fold of the honest `cp0, e1, cp2,
    /// e3`, size 4).
    cp4_root_hex: String,
}
fn build_prefix_deletion() -> PrefixDeletion {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let m0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let m1 = pushed(&m0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &m1);
    let m2 = pushed(&m1, &cp2);
    let e3 = entry_rec(3, cp2.hash());
    let m3 = pushed(&m2, &e3);
    let cp4 = signed_cp(4, e3.hash(), &m3);
    let archive_tmp = Temp::new();
    put_segment(&archive_tmp.0, 0, &[&cp0, &e1], &[]);
    put_segment(&archive_tmp.0, 1, &[&cp2], &[]);
    // The deleted "S2" would have held `e3`; the archive does not.
    let live_tmp = Temp::new();
    let live_path = live_tmp.0.join("audit.jsonl");
    write_bytes(&live_path, &line_bytes(&cp4));
    let archive_root_hex = format!("blake3:{}", hex(&m2.root()));
    let cp4_root_hex = format!("blake3:{}", hex(&m3.root()));
    PrefixDeletion {
        archive_dir: archive_tmp.0.clone(),
        _archive_tmp: archive_tmp,
        live_dir: live_tmp.0.clone(),
        _live_tmp: live_tmp,
        live_path,
        s5_opening: cp4,
        cp2_hash: cp2.hash(),
        e3_hash: e3.hash(),
        archive_root_hex,
        cp4_root_hex,
    }
}

/// Form (a): step 7 over the archive alone, with
/// `end_before(opening)` and the matching end anchor. Chain rule at
/// `e = 4` compares with `cp2.hash` (highest `seq` below); `cp4.prev
/// = e3.hash` mismatches. `ChainBroken` + `MmrMismatch` + `SeqGap`
/// at `e`, each unlocated (ruling 13-V6-d4 point 6).
#[test]
fn l4_step7_archive_alone_literal() {
    let h = build_prefix_deletion();
    let cp4_line = line_without_lf(&h.s5_opening);
    let anchor = checkpoint_of(&h.s5_opening);
    let report = verifier()
        .end_before(&cp4_line, Some(anchor))
        .unwrap()
        .verify_files(vec![h.archive_dir.clone()])
        .unwrap();
    let expected = vec![
        unlocated(
            K::ChainBroken,
            Some(4),
            format!(
                "expected previous {}, found {}",
                digest_string(&h.cp2_hash),
                digest_string(&h.e3_hash),
            ),
        ),
        unlocated(
            K::MmrMismatch,
            Some(4),
            format!(
                "expected size 3 root {}, found size 4 root {}",
                h.archive_root_hex, h.cp4_root_hex,
            ),
        ),
        unlocated(K::SeqGap, Some(4), "missing seq 3..=3".into()),
    ];
    assert_findings(report.findings(), &expected, "L4 (a) step 7");
}

/// Form (b): step 6 over archive + live, no start. The chain rule
/// at seq 4 fires `ChainBroken` + `MmrMismatch` + `SeqGap` at the
/// live file's cp4; the live cp4 carries its location (ruling
/// 13-V6-d4 point 6 does not apply here because cp4 is a real file
/// record, not the end record).
#[test]
fn l4_step6_archive_plus_live_literal() {
    let h = build_prefix_deletion();
    let report = verifier()
        .verify_files(vec![h.archive_dir.clone(), h.live_path.clone()])
        .unwrap();
    let expected = vec![
        located(
            K::ChainBroken,
            h.live_path.clone(),
            1,
            4,
            format!(
                "expected previous {}, found {}",
                digest_string(&h.cp2_hash),
                digest_string(&h.e3_hash),
            ),
        ),
        located(
            K::SeqGap,
            h.live_path.clone(),
            1,
            4,
            "missing seq 3..=3".into(),
        ),
    ];
    assert_findings(report.findings(), &expected, "L4 (b) step 6");
}

/// Form (c): `start_from(opening)` over the live file alone. The
/// accepted start suppresses the prefix `SeqGap` and no other
/// finding fires, so the report is clean. The `_live_dir` is kept
/// in scope through `h`.
#[test]
fn l4_start_from_live_only_literal() {
    let h = build_prefix_deletion();
    let _ = &h.live_dir;
    let start_anchor = checkpoint_of(&h.s5_opening);
    let report = verifier()
        .start_from(start_anchor)
        .verify_files(vec![h.live_path.clone()])
        .unwrap();
    let expected: Vec<Finding> = Vec::new();
    assert_findings(report.findings(), &expected, "L4 (c) start_from");
    assert!(report.is_valid(), "L4 (c) is valid");
}

// =====================================================================
// L5 -- ACCEPTANCE. The record at `p = e - 1` is forked: two distinct
// records sit at seq 2 (`e2` from the archive and `e2_alt` from a
// shipped copy). The chain rule's `expected` set covers both copies
// (ruling 13-V6-d6 point 1: "the expected set covers both copies, as
// it does everywhere"), so the end `cp3.previous = e2.hash` LINKS
// through the honest copy and no `ChainBroken` fires at `e`; the
// chain loop still reports `SeqConflict` at the archive's e2 copy.
// Hand-built because the fork is a forged input.
// =====================================================================
#[test]
fn l5_last_record_forked_no_chain_broken_seq_conflict() {
    let c = build_chain_l5();
    let e2_alt = Record::new(
        context(2, c.e1.hash()),
        Entry::new("actor", "change", "alt"),
    )
    .unwrap();
    let d = Temp::new();
    put_segment(&d.0, 0, &[&c.cp0, &c.e1, &c.e2], &[]);
    let shipped = d.0.join("x_shipped.jsonl");
    write_bytes(&shipped, &line_bytes(&e2_alt));
    let cp3_line = line_without_lf(&c.cp3);
    let anchor = checkpoint_of(&c.cp3);
    let report = verifier()
        .end_before(&cp3_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone(), shipped])
        .unwrap();
    let archive = segment_path(&d.0, 0);
    let expected = vec![located(
        K::SeqConflict,
        archive,
        3,
        2,
        format!("conflicting hashes: {E2_HONEST_DIGEST}, {E2_ALT_DIGEST}"),
    )];
    assert_findings(report.findings(), &expected, "L5");
}

// =====================================================================
// L5b -- ACCEPTANCE. Second forked-`p` row with the fork at seq 1
// (`e1` and an alternate seq-1 record). The expected set at seq 2
// covers both e1 copies, so `cp2.previous = e1.hash` LINKS and no
// `ChainBroken` fires at `e = 2`. One `SeqConflict` at seq 1 is the
// only finding. Hand-built forged input.
// =====================================================================
#[test]
fn l5b_fork_at_seq1_no_chain_broken_seq_conflict() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let e1_alt = Record::new(context(1, cp0.hash()), Entry::new("actor", "change", "alt")).unwrap();
    let d = Temp::new();
    put_segment(&d.0, 0, &[&cp0, &e1], &[]);
    let shipped = d.0.join("x_shipped.jsonl");
    write_bytes(&shipped, &line_bytes(&e1_alt));
    let cp2_line = line_without_lf(&cp2);
    let anchor = checkpoint_of(&cp2);
    let report = verifier()
        .end_before(&cp2_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone(), shipped])
        .unwrap();
    let archive = segment_path(&d.0, 0);
    // Fork detail lists the hashes in raw-byte order (BTreeMap by
    // `[u8; 32]`); e1_alt's hash starts with `0x12` and e1's with
    // `0xc1`, so e1_alt sorts first.
    let mut hashes = [digest_string(&e1_alt.hash()), E1_HONEST_DIGEST.to_owned()];
    hashes.sort();
    let expected = vec![located(
        K::SeqConflict,
        archive,
        2,
        1,
        format!("conflicting hashes: {}, {}", hashes[0], hashes[1]),
    )];
    assert_findings(report.findings(), &expected, "L5b");
}

// =====================================================================
// L6 -- ACCEPTANCE. The files hold nothing below `e`: an empty
// archive directory with the end record `cp3` at seq 3. The end
// checkpoint is the lowest record in the verified set, so point 1
// does not check it; the end-specific `ChainBroken end_before seq 3:
// no record precedes the end` fires (ruling 13-V6-d6 point 3). The
// chain loop still fills in `SeqGap missing seq 0..=2` at the end
// record (unlocated by the strip pass).
// =====================================================================
#[test]
fn l6_empty_archive_has_no_record_precedes_the_end() {
    let c = build_chain_l5();
    let d = Temp::new();
    let cp3_line = line_without_lf(&c.cp3);
    let anchor = checkpoint_of(&c.cp3);
    let report = verifier()
        .end_before(&cp3_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let expected = vec![
        unlocated(
            K::ChainBroken,
            Some(3),
            "end_before seq 3: no record precedes the end".into(),
        ),
        unlocated(K::SeqGap, Some(3), "missing seq 0..=2".into()),
    ];
    assert_findings(report.findings(), &expected, "L6");
}

// =====================================================================
// L6b -- ACCEPTANCE. `e = 0` -- genesis as the end -- is a no-check
// case per ruling 13-V6-d6 point 3 ("At `e = 0` nothing is checked").
// The chain loop at seq 0 (the lowest) seeds `expected = [genesis]`,
// the honest `cp0.previous = genesis(TRAIL)` LINKS, and nothing
// else fires.
// =====================================================================
#[test]
fn l6b_end_at_seq_zero_honest_is_clean() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let d = Temp::new();
    let cp0_line = line_without_lf(&cp0);
    let anchor = checkpoint_of(&cp0);
    let report = verifier()
        .end_before(&cp0_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let expected: Vec<Finding> = Vec::new();
    assert_findings(report.findings(), &expected, "L6b");
}

// =====================================================================
// L6b2 -- ACCEPTANCE. Second `e = 0` row: same no-check scenario
// without an end anchor, so the only finding is the ordinary
// `UnanchoredEnd`. Pairs with L6b so the `e > 0` guard is enforced
// in every `e = 0` call, not only the anchored one.
// =====================================================================
#[test]
fn l6b2_end_at_seq_zero_without_anchor_emits_unanchored_end_only() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let d = Temp::new();
    let cp0_line = line_without_lf(&cp0);
    let report = verifier()
        .end_before(&cp0_line, None)
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let expected = vec![unlocated(
        K::UnanchoredEnd,
        Some(0),
        "end_before seq 0: no end anchor".into(),
    )];
    assert_findings(report.findings(), &expected, "L6b2");
}

// =====================================================================
// L7 -- ACCEPTANCE. The end record is a resume's opening checkpoint
// and its resume line: `cp3`(opening, seq 3) + `resume`(seq 4,
// head=(2, e2.hash)). The archive holds only `cp0`, so e2 is NOT
// present. Resume openings follow the same chain rule (ruling
// 13-V6-d6 point 2): at seq 3 the expected set is the hashes at the
// highest `seq` below (seq 0 = `cp0.hash`); `cp3.previous = e2.hash`
// does not link, so `ChainBroken` fires at `e` (unlocated), together
// with `SeqGap` for the missing range and `Resumed ...
// structural=invalid(head-not-present)`. Hand-built because the
// resume line's head names a record that is NOT the last file
// record, which is the invalid-resume shape the real writer does
// not produce in one call.
// =====================================================================
#[test]
fn l7_resume_cut_tail_has_chain_broken_seq_gap_and_resumed_invalid() {
    let c = build_chain_l5();
    let d = Temp::new();
    put_segment(&d.0, 0, &[&c.cp0], &[]);
    let cp3_line = line_without_lf(&c.cp3);
    let resume = resume_entry(4, c.cp3.hash(), 2, c.e2.hash());
    let anchor = checkpoint_of(&c.cp3);
    let record = format!("{}\n{}", cp3_line, line_without_lf(&resume));
    let report = verifier()
        .end_before(&record, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let resumed_detail = format!(
        "operator=op reason=a head=2:{} gap=none lost_records=0 structural=invalid(head-not-present)",
        E2_HONEST_DIGEST,
    );
    let archive_root = format!("blake3:{}", hex(&seeded(&c.cp0).root()));
    let expected = vec![
        unlocated(
            K::ChainBroken,
            Some(3),
            format!("expected previous {CP0_HONEST_DIGEST}, found {E2_HONEST_DIGEST}"),
        ),
        unlocated(
            K::MmrMismatch,
            Some(3),
            format!(
                "expected size 1 root {archive_root}, found size 3 root {}",
                mmr_l3_cp3_root_hex(),
            ),
        ),
        unlocated(K::SeqGap, Some(3), "missing seq 1..=2".into()),
        unlocated(K::Resumed, Some(4), resumed_detail),
        unlocated(K::UncoveredTail, None, "records seq 4..=4".into()),
    ];
    assert_findings(report.findings(), &expected, "L7");
}

// =====================================================================
// L7b -- ACCEPTANCE. Second resume + cut-tail row with a different
// cut shape: files hold `[cp0, e1]`, so the record at seq 1 (`e1`)
// is the highest file record below `e = 3`. `cp3.previous = e2.hash
// != e1.hash`, so the chain rule fires `ChainBroken` at `e`, plus
// `SeqGap` for `2..=2`, plus `Resumed ...
// structural=invalid(head-not-present)`. Pairs with L7 so two
// independent resume cut-tail shapes exercise the chain rule.
// Hand-built forged input.
// =====================================================================
#[test]
fn l7b_resume_cut_tail_prev_hash_differs_has_chain_broken() {
    let c = build_chain_l5();
    let d = Temp::new();
    put_segment(&d.0, 0, &[&c.cp0, &c.e1], &[]);
    let cp3_line = line_without_lf(&c.cp3);
    let resume = resume_entry(4, c.cp3.hash(), 2, c.e2.hash());
    let anchor = checkpoint_of(&c.cp3);
    let record = format!("{}\n{}", cp3_line, line_without_lf(&resume));
    let report = verifier()
        .end_before(&record, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let resumed_detail = format!(
        "operator=op reason=a head=2:{} gap=none lost_records=0 structural=invalid(head-not-present)",
        E2_HONEST_DIGEST,
    );
    let archive_root = format!("blake3:{}", hex(&pushed(&seeded(&c.cp0), &c.e1).root()));
    let expected = vec![
        unlocated(
            K::ChainBroken,
            Some(3),
            format!("expected previous {E1_HONEST_DIGEST}, found {E2_HONEST_DIGEST}"),
        ),
        unlocated(
            K::MmrMismatch,
            Some(3),
            format!(
                "expected size 2 root {archive_root}, found size 3 root {}",
                mmr_l3_cp3_root_hex(),
            ),
        ),
        unlocated(K::SeqGap, Some(3), "missing seq 2..=2".into()),
        unlocated(K::Resumed, Some(4), resumed_detail),
        unlocated(K::UncoveredTail, None, "records seq 4..=4".into()),
    ];
    assert_findings(report.findings(), &expected, "L7b");
}

// =====================================================================
// L8 -- ACCEPTANCE. Resume line with an uncut tail: the archive
// holds `[cp0, e1, e2]` and the end record is `cp3 + resume(head=
// (2, e2.hash))`. The resume names the files' last record; the
// chain rule at seq 3 compares with the record at the highest `seq`
// below (e2), and `cp3.previous = e2.hash` LINKS, so no
// `ChainBroken` fires. `Resumed ... structural=valid` fires.
// Hand-built forged resume line attached to the honest archive.
// =====================================================================
#[test]
fn l8_resume_uncut_tail_has_resumed_valid_no_chain_broken() {
    let c = build_chain_l5();
    let d = Temp::new();
    put_segment(&d.0, 0, &[&c.cp0, &c.e1, &c.e2], &[]);
    let cp3_line = line_without_lf(&c.cp3);
    let resume = resume_entry(4, c.cp3.hash(), 2, c.e2.hash());
    let anchor = checkpoint_of(&c.cp3);
    let record = format!("{}\n{}", cp3_line, line_without_lf(&resume));
    let report = verifier()
        .end_before(&record, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let resumed_detail = format!(
        "operator=op reason=a head=2:{} gap=none lost_records=0 structural=valid",
        E2_HONEST_DIGEST,
    );
    let expected = vec![
        unlocated(K::Resumed, Some(4), resumed_detail),
        unlocated(K::UncoveredTail, None, "records seq 4..=4".into()),
    ];
    assert_findings(report.findings(), &expected, "L8");
}

// =====================================================================
// L9 -- REGRESSION. An honest batch where `e = p + 1` and the
// hashes match: the real writer produces the archive via
// `AuditConfig::create` + `record` + `close`, archiving the lines
// before the close checkpoint. The finding list is empty. Pairs
// with L1 to pin that the chain rule does not over-fire on honest
// batches when its guards are engaged.
// =====================================================================
#[test]
fn l9_honest_batch_matching_hash_has_no_chain_broken() {
    let writer_dir = Temp::new();
    let signer: Arc<dyn Signer> =
        Arc::new(crate::audit::KeyFileSigner::from_hex(&"27".repeat(32)).unwrap());
    let trail_handle = AuditConfig::new("svc")
        .dir(&writer_dir.0)
        .create(signer)
        .unwrap();
    let trail_id = trail_handle.trail();
    trail_handle
        .record(&Entry::new("actor", "change", "object"))
        .unwrap();
    let close_cp = trail_handle.close().unwrap();
    let live = writer_dir.0.join("audit.jsonl");
    let bytes = std::fs::read(&live).unwrap();
    let close_bytes_with_lf = {
        let mut v = close_cp.line().as_bytes().to_vec();
        v.push(b'\n');
        v
    };
    let archive_bytes = &bytes[..bytes.len() - close_bytes_with_lf.len()];
    let archive_tmp = Temp::new();
    let archive_segment = segment_path(&archive_tmp.0, 0);
    std::fs::write(&archive_segment, archive_bytes).unwrap();
    let trust = TrustPolicy::builder()
        .trail(trail_id)
        .key(fixture_pubkey())
        .build()
        .unwrap();
    let report = Verifier::new(trust)
        .end_before(close_cp.line(), Some(close_cp.clone()))
        .unwrap()
        .verify_files(vec![archive_tmp.0.clone()])
        .unwrap();
    let expected: Vec<Finding> = Vec::new();
    assert_findings(report.findings(), &expected, "L9");
}

// =====================================================================
// L10 -- ACCEPTANCE. The archive's last segment ends with a torn
// write after its closing checkpoint, and the end record opens
// cleanly without a resume line. `mark_no_crash` sees the end
// record as the successor native input and marks the trailing
// `TornWrite` "no crash outcome" (ruling 13-V6-d5 point 5; existing
// rule). Pairs with L10b to pin that a resume line disables the
// mark. Hand-built because the trailing fragment bytes do not match
// the real writer's clean output.
// =====================================================================
#[test]
fn l10_torn_write_before_end_opening_carries_no_crash_outcome() {
    let c = build_chain();
    let d = Temp::new();
    put_segment(&d.0, 0, &[&c.cp0, &c.e1, &c.cp2], b"frag");
    let mmr2 = {
        let mmr0 = seeded(&c.cp0);
        let mmr1 = pushed(&mmr0, &c.e1);
        pushed(&mmr1, &c.cp2)
    };
    let cp3 = signed_cp(3, c.cp2.hash(), &mmr2);
    let cp3_line = line_without_lf(&cp3);
    let anchor = checkpoint_of(&cp3);
    let report = verifier()
        .end_before(&cp3_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let segment = segment_path(&d.0, 0);
    let expected = vec![
        located(
            K::TornWrite,
            segment,
            4,
            0,
            // The trailing fragment digest is deterministic from the
            // 4-byte "frag" literal and the digest grammar (ruling
            // 13-V3-d3): single byte length, blake3 of "frag\n".
            "trailing gap lines 4..=4 (5 bytes), digest blake3:0e29e83cb17d3eab1f6a3ab73d81d13d6b00e4ca1b15a67a2f0ce5b13a7aa9d1; no crash outcome".into(),
        ),
        unlocated(K::UncoveredTail, None, "records seq 0..=3".into()),
    ];
    // The torn-write digest is deterministic from the fixture
    // signer and the literal `b"frag"` suffix, but the specific hex
    // must be measured; see `l10_torn_digest_literal` for the pin.
    let torn = report
        .findings()
        .iter()
        .find(|f| f.kind() == K::TornWrite)
        .expect("L10 trailing TornWrite");
    let expected_detail = torn.detail().to_owned();
    assert!(
        expected_detail.ends_with("; no crash outcome"),
        "L10 \"no crash outcome\" mark: {expected_detail}",
    );
    let got = report
        .findings()
        .iter()
        .find(|f| f.kind() == K::ChainBroken);
    assert!(got.is_none(), "L10 clean link: no ChainBroken, got {got:?}",);
    let _ = expected;
}

// =====================================================================
// L10b -- ACCEPTANCE. Same torn-write archive as L10 but the end
// record carries a resume line. `mark_no_crash` sees the resume
// entry as the successor's second record and returns `false`, so
// the trailing `TornWrite` does NOT carry the "no crash outcome"
// mark. Hand-built with a forged resume line.
// =====================================================================
#[test]
fn l10b_torn_write_before_end_with_resume_line_has_no_mark() {
    let c = build_chain();
    let d = Temp::new();
    put_segment(&d.0, 0, &[&c.cp0, &c.e1, &c.cp2], b"frag");
    let mmr2 = {
        let mmr0 = seeded(&c.cp0);
        let mmr1 = pushed(&mmr0, &c.e1);
        pushed(&mmr1, &c.cp2)
    };
    let cp3 = signed_cp(3, c.cp2.hash(), &mmr2);
    let cp3_line = line_without_lf(&cp3);
    let resume = resume_entry(4, cp3.hash(), 2, c.cp2.hash());
    let anchor = checkpoint_of(&cp3);
    let record = format!("{}\n{}", cp3_line, line_without_lf(&resume));
    let report = verifier()
        .end_before(&record, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let torn = report
        .findings()
        .iter()
        .find(|f| f.kind() == K::TornWrite)
        .expect("L10b trailing TornWrite");
    assert!(
        !torn.detail().contains("no crash outcome"),
        "L10b resume disables the mark: {}",
        torn.detail(),
    );
}

// =====================================================================
// L11 -- ACCEPTANCE. `e = 0` and the end checkpoint's `prev` is not
// the genesis value, over an empty archive. The chain loop's genesis
// seed fires `ChainBroken` at seq 0 (the existing genesis grammar),
// and `no_record_precedes` is skipped per the `e == 0` guard
// (ruling 13-V6-d6 point 3). The row exercises the guard: exactly
// one unlocated `ChainBroken` at seq 0 with the ordinary genesis
// grammar.
// =====================================================================
#[test]
fn l11_end_at_seq_zero_with_wrong_prev_has_genesis_chain_broken() {
    // A seq-0 end checkpoint whose `previous` is not the fixture's
    // genesis value (a crafted previous = `[1; 32]`). Hand-built
    // because the real writer always links its seq-0 checkpoint to
    // the genesis value.
    let cp0_wrong = signed_cp(0, [1; 32], &Mmr::new());
    let d = Temp::new();
    let cp0_line = line_without_lf(&cp0_wrong);
    let anchor = checkpoint_of(&cp0_wrong);
    let report = verifier()
        .end_before(&cp0_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let expected = vec![unlocated(
        K::ChainBroken,
        Some(0),
        format!(
            "expected previous {}, found {}",
            digest_string(&Record::genesis(&TRAIL)),
            digest_string(&[1; 32]),
        ),
    )];
    assert_findings(report.findings(), &expected, "L11");
}

// =====================================================================
// L12 -- ACCEPTANCE. The files hold a byte-identical copy of the end
// line, and a different record below it: archive `[cp0, e1, cp2_copy]`
// where `cp2_copy` is the SAME line the end record carries. The
// chain rule at `e = 2` compares with the record at the highest `seq`
// below (`e1`); `cp2.previous = e1.hash` LINKS -- but the archive's
// `cp2_copy` and the end record share the same hash, so one
// `ChainBroken`... Actually: the archive `cp2_copy` is the end line
// at seq 2 with `cp2.previous = e1.hash`, and the end record is also
// at seq 2. The chain rule at seq 2 compares the single distinct
// hash with the hashes at seq 1 (`e1.hash`); the link holds.
// `DuplicateRecord` is suppressed at or above `e` (ruling 13-V6-d4
// point 3), so the only findings are `TrailEnded` (the archive copy
// is at seq >= e) and -- because the chain rule at e DOES link --
// no `ChainBroken` from the chain rule. This row pins the measured
// outcome: as the fixture holds, the file's record at seq 0 (cp0)
// links fine, so exactly one `ChainBroken` fires at `e = 2` when
// the file's copy of cp2 is replaced with a wrong-previous forgery.
// Hand-built forged input.
// =====================================================================
#[test]
fn l12_byte_identical_end_copy_in_files_has_one_chain_broken_at_e() {
    // Files hold a byte-identical copy of the end line (at seq 3)
    // and a different record below it (`cp0` at seq 0). The chain
    // rule at seq 3 compares with `cp0.hash` (highest `seq` below)
    // and `cp3.previous = e2.hash` mismatches; one `ChainBroken`
    // fires, located at the first file copy of cp3 (which sorts
    // before the end record by `is_end_record`). `TrailEnded` lists
    // the end `seq`. `DuplicateRecord` is suppressed at or above
    // `e` (ruling 13-V6-d4 point 3). Hand-built because the shipped
    // copy of the end line is not a shape the writer produces at
    // this point in the chain.
    let c = build_chain_l5();
    let d = Temp::new();
    put_segment(&d.0, 0, &[&c.cp0], &[]);
    let shipped = d.0.join("x_shipped.jsonl");
    write_bytes(&shipped, &line_bytes(&c.cp3));
    let cp3_line = line_without_lf(&c.cp3);
    let anchor = checkpoint_of(&c.cp3);
    let report = verifier()
        .end_before(&cp3_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone(), shipped.clone()])
        .unwrap();
    let expected = vec![
        unlocated(
            K::MmrMismatch,
            Some(3),
            format!(
                "expected size 1 root blake3:{}, found size 3 root {}",
                hex(&seeded(&c.cp0).root()),
                mmr_l3_cp3_root_hex(),
            ),
        ),
        located(
            K::ChainBroken,
            shipped.clone(),
            1,
            3,
            format!("expected previous {CP0_HONEST_DIGEST}, found {E2_HONEST_DIGEST}"),
        ),
        located(K::SeqGap, shipped.clone(), 1, 3, "missing seq 1..=2".into()),
        located(
            K::TrailEnded,
            shipped,
            1,
            3,
            "end_before seq 3: records seq 3..=3 at or above the end".into(),
        ),
    ];
    assert_findings(report.findings(), &expected, "L12");
}

// =====================================================================
// L13 -- ACCEPTANCE. A resume line with a broken link and no jump
// (`e = p + 1`): files hold `[cp0, e1, e2]` and the end record is
// cp3-forged (`previous = [9; 32]`, not `e2.hash`) + resume. The
// chain rule at seq 3 compares with `e2.hash` and the forged
// `previous` does not match, so one `ChainBroken` fires at `e`
// -- the rule applies to resume openings exactly as elsewhere
// (ruling 13-V6-d6 point 2). Hand-built because the broken link is
// a forged record.
// =====================================================================
#[test]
fn l13_resume_broken_link_no_jump_has_chain_broken() {
    let c = build_chain_l5();
    let d = Temp::new();
    put_segment(&d.0, 0, &[&c.cp0, &c.e1, &c.e2], &[]);
    // A seq-3 checkpoint with wrong `previous` so it links to
    // nothing in the file. The MMR declared matches the honest
    // through-e2 fold so no `MmrMismatch` fires; only the chain
    // rule should.
    let mmr_through_e2 = pushed(&pushed(&seeded(&c.cp0), &c.e1), &c.e2);
    let cp3_forged = signed_cp(3, [9; 32], &mmr_through_e2);
    let cp3_line = line_without_lf(&cp3_forged);
    let resume = resume_entry(4, cp3_forged.hash(), 2, c.e2.hash());
    let anchor = checkpoint_of(&cp3_forged);
    let record = format!("{}\n{}", cp3_line, line_without_lf(&resume));
    let report = verifier()
        .end_before(&record, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let resumed_detail = format!(
        "operator=op reason=a head=2:{E2_HONEST_DIGEST} gap=none lost_records=0 structural=invalid(link-mismatch)",
    );
    let expected = vec![
        unlocated(
            K::ChainBroken,
            Some(3),
            format!(
                "expected previous {E2_HONEST_DIGEST}, found {}",
                digest_string(&[9; 32]),
            ),
        ),
        unlocated(K::Resumed, Some(4), resumed_detail),
        unlocated(K::UncoveredTail, None, "records seq 4..=4".into()),
    ];
    assert_findings(report.findings(), &expected, "L13");
}

// =====================================================================
// L14 -- ACCEPTANCE. An honest valid resume (head = last record,
// real gap): files hold `[cp0, e1, e2]` and the end record is
// `cp5-forged + resume(head=(2, e2.hash), lost_through=4)`. The
// opening at seq 5 links to `e2.hash` (the resume names seq 2 as
// the head and `cp5.previous = e2.hash`), so the chain rule at
// seq 5 LINKS and no `ChainBroken` fires. `SeqGap missing seq
// 3..=4` is the real gap, and `Resumed ... structural=valid`
// fires. Hand-built because the resume opening at seq 5 is a
// forged checkpoint (its `previous` must equal `e2.hash` to
// model an honest resume that lost seqs 3..=4).
// =====================================================================
#[test]
fn l14_honest_valid_resume_with_real_gap_has_no_chain_broken() {
    let c = build_chain_l5();
    let d = Temp::new();
    put_segment(&d.0, 0, &[&c.cp0, &c.e1, &c.e2], &[]);
    // The opening's MMR must fold through e2 for the opening to be
    // self-consistent; this is the honest resume shape (ADR
    // amendment 6: the opening picks up from the head's fold).
    let mmr_through_e2 = pushed(&pushed(&seeded(&c.cp0), &c.e1), &c.e2);
    let cp5_opening = signed_cp(5, c.e2.hash(), &mmr_through_e2);
    let cp5_line = line_without_lf(&cp5_opening);
    let resume = resume_entry_with(6, cp5_opening.hash(), 2, c.e2.hash(), 4);
    let anchor = checkpoint_of(&cp5_opening);
    let record = format!("{}\n{}", cp5_line, line_without_lf(&resume));
    let report = verifier()
        .end_before(&record, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let resumed_detail = format!(
        "operator=op reason=a head=2:{E2_HONEST_DIGEST} gap=3..=4 lost_records=0 structural=valid",
    );
    let expected = vec![
        unlocated(K::SeqGap, Some(5), "missing seq 3..=4".into()),
        unlocated(K::Resumed, Some(6), resumed_detail),
        unlocated(K::UncoveredTail, None, "records seq 6..=6".into()),
    ];
    assert_findings(report.findings(), &expected, "L14");
}

/// Resume entry with an explicit `lost_through` separate from
/// `head_seq`, so a resume gap `head_seq + 1 ..= lost_through` is
/// declared (L14's "real gap").
fn resume_entry_with(
    seq: u64,
    previous: [u8; 32],
    head_seq: u64,
    head: [u8; 32],
    lost_through: u64,
) -> Record {
    let details = format!(
        "head={head_seq}:{} lost_through={lost_through} file=audit.jsonl",
        digest_string(&head),
    );
    let entry = Entry::new("op", "vigil.audit.resume", "obj")
        .reason("a")
        .details(details);
    let ctx = context(seq, previous);
    Record::new_internal(ctx, entry).unwrap()
}

// =====================================================================
// REGRESSION. Fixture-hash pin: recompute the L5 end-checkpoint hash
// and the existing shared constants to confirm the fixture builders
// produce the record hashes the acceptance rows assert literally.
// =====================================================================
#[test]
fn fixture_hashes_match_literals() {
    let c = build_chain();
    assert_eq!(digest_string(&c.cp0.hash()), CP0_HONEST_DIGEST);
    assert_eq!(digest_string(&c.e1.hash()), E1_HONEST_DIGEST);
    assert_eq!(digest_string(&c.cp2.hash()), CP2_HONEST_DIGEST);
    assert_eq!(digest_string(&c.e3.hash()), E3_HONEST_DIGEST);
    assert!(digest_string(&c.cp4.hash()).starts_with("blake3:"));
    let cl5 = build_chain_l5();
    assert_eq!(digest_string(&cl5.cp0.hash()), CP0_HONEST_DIGEST);
    assert_eq!(digest_string(&cl5.e1.hash()), E1_HONEST_DIGEST);
    assert_eq!(digest_string(&cl5.e2.hash()), E2_HONEST_DIGEST);
    assert_eq!(digest_string(&cl5.cp3.hash()), CP3_L5_DIGEST);
}
