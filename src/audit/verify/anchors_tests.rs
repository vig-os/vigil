//! Rows for the verifier's anchor check (ADR-0005 decision 10;
//! ruling 13-V6-d1 points 1-2).

use crate::audit::{
    AuditConfig, Checkpoint, Entry, FindingKind as K, KeyFileSigner, Mmr, Record, RecordContext,
    Signer, TrustPolicy, digest_string,
    format::CheckpointFields,
    runs_v4a_fixtures::{
        TRAIL, Temp, entry_rec, fixture_pubkey, line_bytes, pushed, put_segment, seeded,
        segment_path, signed_cp, signed_cp_explicit, write_bytes,
    },
    verify::{Finding, Report, Verifier},
};
use std::{path::PathBuf, sync::Arc};

// =====================================================================
// Shared literal hex constants (see `fixture_hashes_match_literals`).
// =====================================================================

const TRAIL_HEX: &str = "11111111111111111111111111111111";
const OTHER_TRAIL_HEX: &str = "01010101010101010101010101010101";
const FIXTURE_KEY_HEX: &str = "ee45ecb9aca01a0abd83ef56dd985c8c874e6e7f4aebcedf20bd8d88c2a0add7";
const CP0_HONEST_DIGEST: &str =
    "blake3:fc26c6f2bb830592aaaca5413da1599489d86ac6e240a4a7a010681e0d4c8e77";
const E1_HONEST_DIGEST: &str =
    "blake3:c121282b5135adfe7a17142cae6bfc4c9040c4aed26d74bddc923b8dafcdb6e8";
const CP2_HONEST_DIGEST: &str =
    "blake3:4164966a12a675e55eb6e133b9e50313907f164fe142d941447defcdfdb25d06";
const CP2_TWIN_V6A_DIGEST: &str =
    "blake3:aee5a47d9814a55594371fa3bb0bd34a48531533983898590ef72f511d42f45c";
const CP0_TWIN_A6B_DIGEST: &str =
    "blake3:1c2090cbf40864380a0bf92e4dc439c77146d8020e46fe172da7098a6b3077a7";
const SYNTH_HASH_5A_DIGEST: &str =
    "blake3:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
const SYNTH_HASH_77_DIGEST: &str =
    "blake3:7777777777777777777777777777777777777777777777777777777777777777";
// Shipped-only cp3 at seq=3 on TRAIL, prev=cp2_honest.hash, empty mmr root
// fold {cp0,e1,cp2}; pinned in `fixture_hashes_match_literals`.
const CP3_SHIPPED_DIGEST: &str =
    "blake3:dfbf4e5a7173125e6d43847fa1c1b05420adc1c09022566ebbb292b72cf0203c";
// cp0 on OTHER_TRAIL (seq=0, previous=genesis(OTHER_TRAIL), empty mmr).
const CP0_OTHER_DIGEST: &str =
    "blake3:b57a644cf07f1180908b840976740bf6624c17aab435a2d9f6b4e9b77aa177c0";
// Checkpoint on OTHER_TRAIL at seq=99 (previous=[0; 32], empty mmr).
const CP99_OTHER_DIGEST: &str =
    "blake3:0791a9c9430f91177360adae8628df07139451993563a00e654948b021aa676c";
// Rewritten e1 on TRAIL (actor differs from the honest fixture's "actor").
const E1_REWRITTEN_DIGEST: &str =
    "blake3:46fda744eb77f8cbc9f5a2a60266a6f79a4be949b5515146784bee95efb02bff";
// Rewritten cp2 on TRAIL (prev=rewritten e1, mmr fold over cp0 and e1').
const CP2_REWRITTEN_DIGEST: &str =
    "blake3:842e8fa455804ed56e1d6e6ea48a432a1de38c7d04fd00187b9605cc7e04509a";
// `signed_cp_explicit(2, e1.hash, 2, [0x5a; 32], vec![[0x22; 32]])` under
// the honest e1 chain head; used by A2, A8, A9.
const SYNTH_CP2_V6A_DIGEST: &str =
    "blake3:a4145e2e1465ae13c3afccdf696b8354b0a8620d167615d4ea72cbab57a5cf56";
// `signed_cp_explicit(1, cp0.hash, 1, [0x77; 32], vec![[0x55; 32]])`.
const SYNTH_CP1_V6A_DIGEST: &str =
    "blake3:6f29546e36b4f2e5563838f6a53d324832a27d0fb89ea9768459a028992bf915";
// `signed_cp(99, [0x88; 32], fold(cp0, e1, cp2))`.
const GHOST_CP99_DIGEST: &str =
    "blake3:1732cbb351492d4576b1e43cd12ec99180df1ba14093fe3b2447d7846dc818a5";
// `signed_cp_other(50, [0x11; 32], Mmr::push([0xbb; 32]))`.
const CP50_OTHER_DIGEST: &str =
    "blake3:e7258c673d92c4a5d5a21de38961bcb7316ad57e490e3d7420d3a3f389da4360";

const OTHER_TRAIL: [u8; 16] = [0x01; 16];

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

fn parse_anchor(record: &Record) -> Checkpoint {
    let mut bytes = line_bytes(record);
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    Checkpoint::parse(std::str::from_utf8(&bytes).unwrap()).unwrap()
}

fn trust_with_key() -> TrustPolicy {
    TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .build()
        .unwrap()
}

fn report_of(files: Vec<PathBuf>, verifier: Verifier) -> Report {
    verifier.verify_files(files).unwrap()
}

/// On OTHER_TRAIL: a signed checkpoint with the fixture key.
fn signed_cp_other(seq: u64, previous: [u8; 32], mmr: &Mmr) -> Record {
    let key = KeyFileSigner::from_hex(&"27".repeat(32)).unwrap();
    let ctx = RecordContext::new(OTHER_TRAIL, seq, 100 + seq, "test", previous);
    let fields = |sig| {
        CheckpointFields::new(
            mmr.size(),
            mmr.root(),
            mmr.peaks().to_vec(),
            key.public_key(),
            sig,
        )
        .unwrap()
    };
    let unsigned = Record::checkpoint(ctx.clone(), fields([0; 64])).unwrap();
    let signature = key.sign(&unsigned.signing_message().unwrap()).unwrap();
    Record::checkpoint(ctx, fields(signature)).unwrap()
}

/// Rewrites `e1` on TRAIL with a different actor so its hash differs.
fn entry_rewritten(seq: u64, previous: [u8; 32]) -> Record {
    Record::new(
        RecordContext::new(TRAIL, seq, 100 + seq, "test", previous),
        Entry::new("other-actor", "change", "object"),
    )
    .unwrap()
}

/// `[cp0, e1, cp2]` on TRAIL: the honest base used by rows A2-A12 unless noted.
struct TwoCheckpointLayout {
    _dir: Temp,
    path: PathBuf,
    cp0: Record,
    e1: Record,
    cp2: Record,
}
fn two_checkpoints() -> TwoCheckpointLayout {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let path = segment_path(&d.0, 0);
    TwoCheckpointLayout {
        _dir: d,
        path,
        cp0,
        e1,
        cp2,
    }
}

// =====================================================================
// A1 — REGRESSION. Every honest anchor matches, including one
// whose record is only in a shipped copy. Pins ruling 13-V5-d4's
// "shipped-only copies count as records in the trail" for anchors,
// and the quiet-on-match behavior on a clean trail.
// =====================================================================
#[test]
fn a1_every_anchor_matches_clean_trail() {
    let fx = two_checkpoints();
    let mut fold = pushed(&seeded(&fx.cp0), &fx.e1);
    fold = pushed(&fold, &fx.cp2);
    let cp3 = signed_cp(3, fx.cp2.hash(), &fold);
    let shipped = fx._dir.0.join("cp3.shipped");
    write_bytes(&shipped, &line_bytes(&cp3));
    let verifier = Verifier::new(trust_with_key())
        .anchor(parse_anchor(&fx.cp0))
        .anchor(parse_anchor(&fx.cp2))
        .anchor(parse_anchor(&cp3));
    let report = report_of(vec![fx.path.clone(), shipped], verifier);
    assert_findings(report.findings(), &[], "A1");
}

// =====================================================================
// A2 — ACCEPTANCE. An anchor at an existing checkpoint `seq` with
// another hash. Also pairs cp2 with a byte-identical shipped copy
// so the first-copy location (native, line 3) is pinned alongside
// the `hash differs` detail.
// =====================================================================
#[test]
fn a2_wrong_hash_at_existing_seq() {
    let fx = two_checkpoints();
    let dup = fx._dir.0.join("cp2.dup");
    write_bytes(&dup, &line_bytes(&fx.cp2));
    let synth = signed_cp_explicit(2, fx.e1.hash(), 2, [0x5a; 32], vec![[0x22; 32]]);
    let verifier = Verifier::new(trust_with_key()).anchor(parse_anchor(&synth));
    let report = report_of(vec![fx.path.clone(), dup], verifier);
    let _ = &synth;
    let expected = vec![
        located(
            K::AnchorMismatch,
            fx.path.clone(),
            3,
            2,
            format!(
                "anchor seq 2 hash {SYNTH_CP2_V6A_DIGEST}: hash differs (record {CP2_HONEST_DIGEST})",
            ),
        ),
        located(
            K::DuplicateRecord,
            fx.path,
            3,
            2,
            "2 copies of 1 distinct records".into(),
        ),
    ];
    assert_findings(report.findings(), &expected, "A2");
}

// =====================================================================
// A3 — ACCEPTANCE. An anchor above the head: no record at that
// `seq`, so the finding has no location.
// =====================================================================
#[test]
fn a3_anchor_above_head_no_record_no_location() {
    let fx = two_checkpoints();
    let fold = pushed(&seeded(&fx.cp0), &fx.e1);
    let mut fold2 = fold.clone();
    fold2.push(fx.cp2.hash()).unwrap();
    let ghost = signed_cp(99, [0x88; 32], &fold2);
    // Pass the same anchor twice: the distinct-anchor dedup still
    // emits exactly one finding.
    let anchor = parse_anchor(&ghost);
    let verifier = Verifier::new(trust_with_key())
        .anchor(anchor.clone())
        .anchor(anchor);
    let report = report_of(vec![fx.path], verifier);
    let _ = &ghost;
    let expected = vec![unlocated(
        K::AnchorMismatch,
        Some(99),
        format!("anchor seq 99 hash {GHOST_CP99_DIGEST}: no record"),
    )];
    assert_findings(report.findings(), &expected, "A3");
}

// =====================================================================
// A4 — ACCEPTANCE. An anchor from another trail, at a `seq` the
// verified trail holds. `trail differs` wins over any hash check.
// =====================================================================
#[test]
fn a4_other_trail_at_existing_seq() {
    let fx = two_checkpoints();
    let foreign = signed_cp_other(0, Record::genesis(&OTHER_TRAIL), &Mmr::new());
    let verifier = Verifier::new(trust_with_key()).anchor(parse_anchor(&foreign));
    let report = report_of(vec![fx.path], verifier);
    let _ = &foreign;
    let expected = vec![unlocated(
        K::AnchorMismatch,
        Some(0),
        format!("anchor seq 0 hash {CP0_OTHER_DIGEST}: trail differs"),
    )];
    assert_findings(report.findings(), &expected, "A4");
}

// =====================================================================
// A5 — ACCEPTANCE. Precedence row: another trail at an absent `seq`
// still reports `trail differs`, never `no record`.
// =====================================================================
#[test]
fn a5_other_trail_at_absent_seq_still_trail_differs() {
    let fx = two_checkpoints();
    let mut mmr_one = Mmr::new();
    mmr_one.push([0; 32]).unwrap();
    let foreign = signed_cp_other(99, [0; 32], &mmr_one);
    let verifier = Verifier::new(trust_with_key()).anchor(parse_anchor(&foreign));
    let report = report_of(vec![fx.path], verifier);
    let _ = &foreign;
    let expected = vec![unlocated(
        K::AnchorMismatch,
        Some(99),
        format!("anchor seq 99 hash {CP99_OTHER_DIGEST}: trail differs"),
    )];
    assert_findings(report.findings(), &expected, "A5");
}

// =====================================================================
// A5b — ACCEPTANCE. A second precedence row: a different absent
// `seq` on another trail. Pairs with A5 so the swap of
// `trail differs` and `no record` is pinned on two independent
// rows.
// =====================================================================
#[test]
fn a5b_other_trail_at_a_second_absent_seq_still_trail_differs() {
    let fx = two_checkpoints();
    let mut mmr_one = Mmr::new();
    mmr_one.push([0xbb; 32]).unwrap();
    let foreign = signed_cp_other(50, [0x11; 32], &mmr_one);
    let verifier = Verifier::new(trust_with_key()).anchor(parse_anchor(&foreign));
    let report = report_of(vec![fx.path], verifier);
    let _ = &foreign;
    let expected = vec![unlocated(
        K::AnchorMismatch,
        Some(50),
        format!("anchor seq 50 hash {CP50_OTHER_DIGEST}: trail differs"),
    )];
    assert_findings(report.findings(), &expected, "A5b");
}

// =====================================================================
// A6 — ACCEPTANCE. A forked `seq` with one copy matching the anchor
// is never a match; the detail is `seq is forked`, located at the
// first copy (native cp2, line 3). The engine's own `SeqConflict`
// sorts after by kind name.
// =====================================================================
#[test]
fn a6_forked_seq_with_one_matching_copy_stays_fork() {
    let fx = two_checkpoints();
    let twin = signed_cp_explicit(2, fx.e1.hash(), 2, [0xde; 32], vec![[0x22; 32]]);
    let twin_path = fx._dir.0.join("cp2.twin");
    write_bytes(&twin_path, &line_bytes(&twin));
    let verifier = Verifier::new(trust_with_key()).anchor(parse_anchor(&fx.cp2));
    let report = report_of(vec![fx.path.clone(), twin_path], verifier);
    let expected = vec![
        located(
            K::AnchorMismatch,
            fx.path.clone(),
            3,
            2,
            format!("anchor seq 2 hash {CP2_HONEST_DIGEST}: seq is forked"),
        ),
        located(
            K::SeqConflict,
            fx.path,
            3,
            2,
            format!("conflicting hashes: {CP2_HONEST_DIGEST}, {CP2_TWIN_V6A_DIGEST}"),
        ),
    ];
    assert_findings(report.findings(), &expected, "A6");
}

// =====================================================================
// A6b — ACCEPTANCE. Second forked-`seq` row at `seq=0`: pairs with
// A6 so the fork precedence (never match a forked `seq`) is pinned
// on two independent rows even when the anchor matches one copy's
// hash.
// =====================================================================
#[test]
fn a6b_forked_seq_zero_with_one_matching_copy_stays_fork() {
    let d = Temp::new();
    let honest = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    put_segment(&d.0, 0, &[&honest], &[]);
    let native = segment_path(&d.0, 0);
    let twin = signed_cp_explicit(0, Record::genesis(&TRAIL), 0, [0xaa; 32], vec![]);
    let twin_path = d.0.join("cp0.twin");
    write_bytes(&twin_path, &line_bytes(&twin));
    let verifier = Verifier::new(trust_with_key()).anchor(parse_anchor(&honest));
    let report = report_of(vec![native.clone(), twin_path], verifier);
    let expected = vec![
        located(
            K::AnchorMismatch,
            native.clone(),
            1,
            0,
            format!("anchor seq 0 hash {CP0_HONEST_DIGEST}: seq is forked"),
        ),
        located(
            K::SeqConflict,
            native,
            1,
            0,
            format!("conflicting hashes: {CP0_TWIN_A6B_DIGEST}, {CP0_HONEST_DIGEST}"),
        ),
    ];
    assert_findings(report.findings(), &expected, "A6b");
}

// =====================================================================
// A7 — ACCEPTANCE. A byte-identical native-plus-shipped duplicate
// of the anchored checkpoint still matches the anchor (one record
// in the trail). The only engine finding is the `DuplicateRecord`
// warning; no `AnchorMismatch`.
// =====================================================================
#[test]
fn a7_byte_identical_duplicate_still_matches() {
    let fx = two_checkpoints();
    let dup = fx._dir.0.join("cp2.dup");
    write_bytes(&dup, &line_bytes(&fx.cp2));
    let verifier = Verifier::new(trust_with_key()).anchor(parse_anchor(&fx.cp2));
    let report = report_of(vec![fx.path.clone(), dup], verifier);
    let expected = vec![located(
        K::DuplicateRecord,
        fx.path,
        3,
        2,
        "2 copies of 1 distinct records".into(),
    )];
    assert_findings(report.findings(), &expected, "A7");
}

// =====================================================================
// A8 — ACCEPTANCE. The anchored checkpoint is only in a shipped
// copy. It still counts as a record in the trail: the match variant
// emits no `AnchorMismatch`; the mismatch variant locates the
// finding at the shipped file's line. Native segment is `[cp0, e1]`
// (so its first-record-is-checkpoint rule holds).
// =====================================================================
#[test]
fn a8_shipped_only_copy_matches_and_mismatch_locates_there() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1], &[]);
    let native = segment_path(&d.0, 0);
    let shipped = d.0.join("cp2.shipped");
    write_bytes(&shipped, &line_bytes(&cp2));
    let matcher = Verifier::new(trust_with_key()).anchor(parse_anchor(&cp2));
    let matched = report_of(vec![native.clone(), shipped.clone()], matcher);
    assert_findings(matched.findings(), &[], "A8 match");

    // Mismatch variant with the same shipped-only record: wrong hash
    // on the same seq, located at the shipped file (line 1).
    let synth = signed_cp_explicit(2, e1.hash(), 2, [0x5a; 32], vec![[0x22; 32]]);
    let mismatch = Verifier::new(trust_with_key()).anchor(parse_anchor(&synth));
    let report = report_of(vec![native, shipped.clone()], mismatch);
    let _ = &synth;
    let expected = vec![located(
        K::AnchorMismatch,
        shipped,
        1,
        2,
        format!(
            "anchor seq 2 hash {SYNTH_CP2_V6A_DIGEST}: hash differs (record {CP2_HONEST_DIGEST})",
        ),
    )];
    assert_findings(report.findings(), &expected, "A8 mismatch");
}

// =====================================================================
// A9 — ACCEPTANCE. The same anchor passed twice collapses to one
// `(trail, seq, hash)`; a mismatch emits exactly one finding. Pins
// the mismatch form.
// =====================================================================
#[test]
fn a9_same_anchor_twice_collapses_to_one_finding() {
    let fx = two_checkpoints();
    let synth = signed_cp_explicit(2, fx.e1.hash(), 2, [0x5a; 32], vec![[0x22; 32]]);
    let anchor = parse_anchor(&synth);
    let verifier = Verifier::new(trust_with_key())
        .anchor(anchor.clone())
        .anchor(anchor);
    let report = report_of(vec![fx.path.clone()], verifier);
    let _ = &synth;
    let expected = vec![located(
        K::AnchorMismatch,
        fx.path,
        3,
        2,
        format!(
            "anchor seq 2 hash {SYNTH_CP2_V6A_DIGEST}: hash differs (record {CP2_HONEST_DIGEST})",
        ),
    )];
    assert_findings(report.findings(), &expected, "A9");
}

// =====================================================================
// A10 — ACCEPTANCE. An anchor taken in process (from
// `AuditTrail::checkpoint()`) matches the verified trail; and
// `Checkpoint::parse` of its line carries the same trail.
// =====================================================================
#[test]
fn a10_in_process_anchor_matches_and_parse_round_trips_trail() {
    let d = Temp::new();
    let signer: Arc<dyn Signer> = Arc::new(KeyFileSigner::from_hex(&"42".repeat(32)).unwrap());
    let pubkey = signer.public_key();
    let trail = AuditConfig::new("svc").dir(&d.0).create(signer).unwrap();
    let trail_id = trail.trail();
    trail
        .record(&Entry::new("actor", "change", "object"))
        .unwrap();
    let cp = trail.checkpoint().unwrap();
    assert_eq!(cp.trail(), trail_id, "A10: checkpoint() carries its trail");
    let round_trip = Checkpoint::parse(cp.line()).unwrap();
    assert_eq!(
        round_trip.trail(),
        trail_id,
        "A10: parse of the line carries the same trail",
    );
    let closed = trail.close().unwrap();
    assert_eq!(closed.trail(), trail_id, "A10: close() carries its trail");
    let trust = TrustPolicy::builder()
        .trail(trail_id)
        .key(pubkey)
        .build()
        .unwrap();
    let verifier = Verifier::new(trust).anchor(cp).anchor(closed);
    let report = verifier.verify_dir(&d.0).unwrap();
    let anchor_findings: Vec<_> = report
        .findings()
        .iter()
        .filter(|f| f.kind() == K::AnchorMismatch)
        .collect();
    assert!(
        anchor_findings.is_empty(),
        "A10: in-process anchors match, got {anchor_findings:?}",
    );
}

// =====================================================================
// A11 — ACCEPTANCE. "What anchoring adds" (ADR-0005 decision 10).
// The trail is rewritten above an anchored cp0 and re-signed with
// the same trusted key, so every other check passes. Each anchor
// above the rewrite point yields one `AnchorMismatch hash differs`.
// =====================================================================
#[test]
fn a11_rewritten_above_anchor_fires_hash_differs_each() {
    let fx_honest = two_checkpoints();
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rewritten(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let path = segment_path(&d.0, 0);
    let verifier = Verifier::new(trust_with_key())
        .anchor(parse_anchor(&fx_honest.cp0))
        .anchor(parse_anchor(&fx_honest.cp2));
    let report = report_of(vec![path.clone()], verifier);
    let _ = &cp2;
    let expected = vec![located(
        K::AnchorMismatch,
        path,
        3,
        2,
        format!(
            "anchor seq 2 hash {CP2_HONEST_DIGEST}: hash differs (record {CP2_REWRITTEN_DIGEST})",
        ),
    )];
    assert_findings(report.findings(), &expected, "A11");
}

// =====================================================================
// A12 — ACCEPTANCE. An anchor whose `seq` holds a non-checkpoint
// record (the entry e1) still runs through the hash check and
// reports `hash differs (record <hex>)` at that record.
// =====================================================================
#[test]
fn a12_anchor_at_non_checkpoint_record() {
    let fx = two_checkpoints();
    let synth = signed_cp_explicit(1, fx.cp0.hash(), 1, [0x77; 32], vec![[0x55; 32]]);
    let verifier = Verifier::new(trust_with_key()).anchor(parse_anchor(&synth));
    let report = report_of(vec![fx.path.clone()], verifier);
    let _ = &synth;
    let expected = vec![located(
        K::AnchorMismatch,
        fx.path,
        2,
        1,
        format!(
            "anchor seq 1 hash {SYNTH_CP1_V6A_DIGEST}: hash differs (record {E1_HONEST_DIGEST})",
        ),
    )];
    assert_findings(report.findings(), &expected, "A12");
}

// =====================================================================
// Pins every literal hex constant in this module to the fixture it
// names so a hash change in `runs_v4a_fixtures` or elsewhere never
// slips through the literal-row assertions.
// =====================================================================
#[test]
fn fixture_hashes_match_literals() {
    use crate::audit::hex;
    let fx = two_checkpoints();
    assert_eq!(hex(&TRAIL), TRAIL_HEX);
    assert_eq!(hex(&OTHER_TRAIL), OTHER_TRAIL_HEX);
    assert_eq!(hex(&fixture_pubkey()), FIXTURE_KEY_HEX);
    assert_eq!(digest_string(&fx.cp0.hash()), CP0_HONEST_DIGEST);
    assert_eq!(digest_string(&fx.e1.hash()), E1_HONEST_DIGEST);
    assert_eq!(digest_string(&fx.cp2.hash()), CP2_HONEST_DIGEST);
    let twin = signed_cp_explicit(2, fx.e1.hash(), 2, [0xde; 32], vec![[0x22; 32]]);
    assert_eq!(digest_string(&twin.hash()), CP2_TWIN_V6A_DIGEST);
    let twin0 = signed_cp_explicit(0, Record::genesis(&TRAIL), 0, [0xaa; 32], vec![]);
    assert_eq!(digest_string(&twin0.hash()), CP0_TWIN_A6B_DIGEST);
    assert_eq!(digest_string(&[0x5a; 32]), SYNTH_HASH_5A_DIGEST);
    assert_eq!(digest_string(&[0x77; 32]), SYNTH_HASH_77_DIGEST);
    let mut fold = pushed(&seeded(&fx.cp0), &fx.e1);
    fold = pushed(&fold, &fx.cp2);
    let cp3 = signed_cp(3, fx.cp2.hash(), &fold);
    assert_eq!(digest_string(&cp3.hash()), CP3_SHIPPED_DIGEST);
    let foreign0 = signed_cp_other(0, Record::genesis(&OTHER_TRAIL), &Mmr::new());
    assert_eq!(digest_string(&foreign0.hash()), CP0_OTHER_DIGEST);
    let mut mmr_one = Mmr::new();
    mmr_one.push([0; 32]).unwrap();
    let foreign99 = signed_cp_other(99, [0; 32], &mmr_one);
    assert_eq!(digest_string(&foreign99.hash()), CP99_OTHER_DIGEST);
    let e1r = entry_rewritten(1, fx.cp0.hash());
    assert_eq!(digest_string(&e1r.hash()), E1_REWRITTEN_DIGEST);
    let mmr1r = pushed(&seeded(&fx.cp0), &e1r);
    let cp2r = signed_cp(2, e1r.hash(), &mmr1r);
    assert_eq!(digest_string(&cp2r.hash()), CP2_REWRITTEN_DIGEST);
    let synth_cp2 = signed_cp_explicit(2, fx.e1.hash(), 2, [0x5a; 32], vec![[0x22; 32]]);
    assert_eq!(digest_string(&synth_cp2.hash()), SYNTH_CP2_V6A_DIGEST);
    let synth_cp1 = signed_cp_explicit(1, fx.cp0.hash(), 1, [0x77; 32], vec![[0x55; 32]]);
    assert_eq!(digest_string(&synth_cp1.hash()), SYNTH_CP1_V6A_DIGEST);
    let mut fold99 = pushed(&seeded(&fx.cp0), &fx.e1);
    fold99 = pushed(&fold99, &fx.cp2);
    let ghost99 = signed_cp(99, [0x88; 32], &fold99);
    assert_eq!(digest_string(&ghost99.hash()), GHOST_CP99_DIGEST);
    let mut mmr_bb = Mmr::new();
    mmr_bb.push([0xbb; 32]).unwrap();
    let foreign50 = signed_cp_other(50, [0x11; 32], &mmr_bb);
    assert_eq!(digest_string(&foreign50.hash()), CP50_OTHER_DIGEST);
}
