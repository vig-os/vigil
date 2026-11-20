//! Rows for `Verifier::end_before` (ADR-0005 decision 11
//! `.end_before`; ruling 13-V6-d4; #13).
//!
//! Row standard (repo-wide): every acceptance row asserts the FULL
//! sorted literal [`Finding`] list through [`assert_findings`] (a
//! thin wrapper around `assert_eq!` on `Vec<Finding>`). Regression
//! rows are labelled in their doc comments. Expected lists are
//! written in the engine's final sort order (`(seq.is_none(), seq,
//! file, line, kind_debug)`), so no per-row sort runs here.
//!
//! Fixture style: the honest-scenario batches E1 and E10 run the
//! real writer (`AuditConfig`/`AuditTrail`) and archive the batch
//! by moving its segment bytes to a new directory. E1 picks its
//! trail at `create`, so its expected details interpolate the drawn
//! trail id at test time; E10 pre-seeds `audit.trail` and calls
//! `AuditConfig::resume` so the run digest stays pinned across runs.
//! E3a/E3b are built at the fixture `TRAIL` with `signed_cp` and
//! `entry_rec` so P and S have literal record hashes pinned in
//! [`fixture_hashes_match_literals`]; `create` draws a random trail
//! and does not accept a pre-seeded `audit.trail`, so the writer
//! cannot produce the E3 layout with deterministic hashes without a
//! production-side clock and trail seam. Rows for scenarios the
//! real writer cannot produce (forged, foreign or parse-error) stay
//! hand-built with the fixture `TRAIL` and `signed_cp`/`put_segment`.

use crate::audit::{
    AuditConfig, AuditError, AuditErrorKind, Checkpoint, CheckpointFields, Entry, FindingKind as K,
    KeyFileSigner, Mmr, Record, Signer, TrustPolicy, digest_string, hex,
    runs_v4a_fixtures::{
        TRAIL, Temp, context, entry_rec, fixture_pubkey, line_bytes, pushed, put_segment, seeded,
        segment_path, signed_cp, write_bytes,
    },
    verify::{Finding, Verifier},
};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

// =====================================================================
// Shared literal hex constants pinned by `fixture_hashes_match_literals`.
// Trail-dependent values are only pinned where the fixture trail is
// fixed (`TRAIL` for hand-built rows and the resume-based E10 family);
// writer-built rows interpolate the drawn trail and record hashes at
// test time.
// =====================================================================

/// Hex of the fixture `TRAIL` = `[17; 16]`.
const TRAIL_HEX: &str = "11111111111111111111111111111111";
/// Public key of the shared fixture signer (seed `0x27` repeated).
const FIXTURE_KEY_HEX: &str = "ee45ecb9aca01a0abd83ef56dd985c8c874e6e7f4aebcedf20bd8d88c2a0add7";
/// Public key of `KeyFileSigner::from_hex(&"42".repeat(32))`, used
/// to sign the end-record checkpoint in E11 and NOT listed on the
/// trust policy, so the verifier reports `UntrustedKey`.
const UNTRUSTED_KEY_HEX: &str = "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";
/// Record hash of `signed_cp(0, Record::genesis(&TRAIL), &Mmr::new())`.
pub(super) const CP0_HONEST_DIGEST: &str =
    "blake3:fc26c6f2bb830592aaaca5413da1599489d86ac6e240a4a7a010681e0d4c8e77";
/// Record hash of `entry_rec(1, cp0.hash())` on the honest chain.
pub(super) const E1_HONEST_DIGEST: &str =
    "blake3:c121282b5135adfe7a17142cae6bfc4c9040c4aed26d74bddc923b8dafcdb6e8";
/// Record hash of `signed_cp(2, e1.hash(), &fold(cp0, e1))` on the
/// honest hand-built chain (used by E5-family, E6-family, E7-family
/// and E11).
pub(super) const CP2_HONEST_DIGEST: &str =
    "blake3:4164966a12a675e55eb6e133b9e50313907f164fe142d941447defcdfdb25d06";
/// Record hash of `entry_rec(2, e1.hash())`, the forged record at
/// the end `seq` in E7. Also reused as the honest `e2` hash in the
/// end-link rows' `ChainBroken` details.
pub(super) const FORGED_E2_DIGEST: &str =
    "blake3:8a5ea9c989aad7e89033b58ad6f59a6384af43dfe6df5bada042420c0040c306";
/// Record hash of `Record::new(context(2, e1.hash()), Entry::new(
/// "actor", "change", "alt"))`, the alternate forged record at the
/// end `seq` in E7c2.
pub(super) const FORGED_E2_ALT_DIGEST: &str =
    "blake3:b0a0082469a0a510874383b5c46630665a6952dd3e0ee8a05ed3eb3704f77287";
/// Record hash of `entry_rec(3, cp2.hash())` on the honest chain
/// past the end, used by E7b.
pub(super) const E3_HONEST_DIGEST: &str =
    "blake3:6dd21c1a65b14cff0eecfb0679a9da4a45cc6d5007071d250295342d454fb9b5";
/// Record hash of a second entry at seq 3 (`Entry::new("actor",
/// "change", "alt")` chaining the same `previous`) so E7b's two
/// shipped file copies at seq 3 fork.
const E3_ALT_DIGEST: &str =
    "blake3:4ce25936f5be0fe59ac6784f645b38397915b56d1d840aa99a31a9fa17ac9d1e";
/// Run digest the shared classifier emits for the E10 writer-built
/// A8-style archive (`S0=[]`, `S1=[]`) walked with the
/// resume-opening end record. Fixed because the fixture seeds
/// `audit.trail` with `TRAIL` and the run digest depends only on
/// the loss-point ranges and the (empty) gap spans. E10b uses the
/// same loss layout and reuses this constant for its own run finding.
const RUN_DIGEST_E10_HEX: &str = "1c02f080d9c70df74de0c13a4a30323f1b49ee624bab2c5d68fa5ee31c4400e4";
/// Record hash of `entry_rec(2, cp0.hash() chain)` on the honest
/// E3 chain, where seq 2's previous is `e1.hash()`. The same hash
/// also appears in E7 as the forged record at the end seq (same
/// context, same signer).
const E2_HONEST_DIGEST: &str = FORGED_E2_DIGEST;
/// Record hash of `signed_cp(3, e2.hash(), &mmr_through_e2)` on the
/// honest E3 chain -- the P checkpoint whose line the E3 archive
/// record replays.
const P_HONEST_DIGEST: &str =
    "blake3:dda83f7bbaaf877076831dd97e6563148bf337d350bc58cf8bc6e8802eed2f66";
/// Record hash of `entry_rec(4, p.hash())` on the honest E3 chain.
const E4_HONEST_DIGEST: &str =
    "blake3:c0d53ffca7d1358ec842a15694a00833b408e2a6d43f49f2f1de7225fabba4e6";
/// Record hash of `signed_cp(5, e4.hash(), &mmr_through_e4)` on the
/// honest E3 chain -- the S close checkpoint used as the end anchor
/// in E3a.
const S_HONEST_DIGEST: &str =
    "blake3:8c2a212152faa447de5f329dc79b90a503eec4ec0f18cfb9b6717a749d6a4cd0";

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
#[track_caller]
fn assert_invalid(result: Result<Verifier, AuditError>, reason: &str, label: &str) {
    match result {
        Ok(_) => panic!("{label}: expected InvalidConfig, got Ok"),
        Err(e) => {
            assert_eq!(
                e.kind(),
                AuditErrorKind::InvalidConfig,
                "{label}: expected InvalidConfig",
            );
            let text = e.to_string();
            assert!(
                text.contains(reason),
                "{label}: expected detail to contain {reason:?}, got {text:?}",
            );
        }
    }
}

/// Process-wide lock used by the relative-path rows so that at most
/// one test at a time changes `std::env::current_dir`. Other rows in
/// this module use absolute temp paths and do not read `cwd`.
fn cwd_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Runs `f` with `cwd` temporarily set to `dir`, restoring the
/// previous `cwd` on return. Used by [`e5d_byte_identical_copy_relative_paths_locate_trail_ended_at_file`]
/// and [`e7c_files_hold_different_record_at_end_seq_relative_paths`]:
/// relative paths starting with lowercase letters sort AFTER
/// `<end record>` (`<` = 0x3C, `a` = 0x61), so these rows would
/// locate `TrailEnded` at the end record if the engine sort dropped
/// `is_end_record`. Absolute `/tmp/...` paths sort BEFORE
/// `<end record>` (`/` = 0x2F) and do not stress that mutation.
fn with_cwd<T>(dir: &Path, f: impl FnOnce() -> T) -> T {
    let guard = cwd_lock().lock().unwrap_or_else(|p| p.into_inner());
    let previous = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir).unwrap();
    let out = f();
    std::env::set_current_dir(&previous).unwrap();
    drop(guard);
    out
}

/// Trust policy pinned to the fixture `TRAIL` and the fixture signer
/// key, for hand-built rows.
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

/// Hand-built batch at the fixture `TRAIL`, used by the rows whose
/// scenarios the real writer cannot produce (forged records in the
/// E7 family, parse-error second lines in E8, the untrusted end
/// checkpoint in E11). The archive directory holds one sealed
/// segment ending at `e1`; the archive record is `cp2`'s line (the
/// opening of the next batch).
struct HandBatch {
    _dir: Temp,
    archive_dir: PathBuf,
    cp0: Record,
    e1: Record,
    cp2: Record,
    cp2_line: String,
}
fn hand_built_batch() -> HandBatch {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1], &[]);
    let cp2_line = line_without_lf(&cp2);
    HandBatch {
        archive_dir: d.0.clone(),
        _dir: d,
        cp0,
        e1,
        cp2,
        cp2_line,
    }
}

fn line_without_lf(record: &Record) -> String {
    let bytes = line_bytes(record);
    let text = std::str::from_utf8(&bytes).unwrap();
    text.strip_suffix('\n').unwrap().to_owned()
}

/// Builds a signed `vigil.audit.resume` record at the fixture signer
/// for hand-built parse-error second lines.
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

fn checkpoint_of(record: &Record) -> Checkpoint {
    let bytes = line_bytes(record);
    let text = std::str::from_utf8(&bytes).unwrap();
    Checkpoint::parse(text).unwrap()
}

/// Signs a checkpoint with the UNTRUSTED key for E11.
fn signed_cp_other(seq: u64, previous: [u8; 32], mmr: &Mmr) -> Record {
    let key = KeyFileSigner::from_hex(&"42".repeat(32)).unwrap();
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
    let unsigned = Record::checkpoint(context(seq, previous), fields([0; 64])).unwrap();
    let signature = key.sign(&unsigned.signing_message().unwrap()).unwrap();
    Record::checkpoint(context(seq, previous), fields(signature)).unwrap()
}

// =====================================================================
// Writer-built fixtures (real `AuditConfig`/`AuditTrail`).
// =====================================================================

fn fixture_signer() -> Arc<dyn Signer> {
    Arc::new(KeyFileSigner::from_hex(&"27".repeat(32)).unwrap())
}

/// One real-writer batch archived by moving its `audit.jsonl`
/// records (minus the closing checkpoint) to a fresh sealed
/// segment. `close_cp` is the opening checkpoint of the next batch,
/// used as the `end_before` archive record.
struct WriterBatch {
    _writer_dir: Temp,
    archive_dir_tmp: Temp,
    archive_segment: PathBuf,
    trail_id: [u8; 16],
    close_cp: Checkpoint,
    close_cp_line: String,
    trust: TrustPolicy,
}
fn writer_honest_batch() -> WriterBatch {
    let writer_dir = Temp::new();
    let signer = fixture_signer();
    let trail = AuditConfig::new("svc")
        .dir(&writer_dir.0)
        .create(signer.clone())
        .unwrap();
    let trail_id = trail.trail();
    trail
        .record(&Entry::new("actor", "change", "object"))
        .unwrap();
    let close_cp = trail.close().unwrap();
    // Read the writer's live bytes and split off the close line so
    // the archive segment is exactly the lines before the close,
    // byte-for-byte what the writer produced.
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
    let close_cp_line = close_cp.line().to_owned();
    let trust = TrustPolicy::builder()
        .trail(trail_id)
        .key(fixture_pubkey())
        .build()
        .unwrap();
    WriterBatch {
        _writer_dir: writer_dir,
        archive_dir_tmp: archive_tmp,
        archive_segment,
        trail_id,
        close_cp,
        close_cp_line,
        trust,
    }
}

/// Hand-built E3 scenario at the fixture `TRAIL` and fixture
/// signer: cp0 (genesis checkpoint) at seq 0, entries at seq 1 and
/// 2, P (checkpoint) at seq 3, entry at seq 4, S (close checkpoint)
/// at seq 5. The archive holds the records strictly before P as one
/// sealed segment (`[cp0, e1, e2]`). Hand-built, not writer-built,
/// because `AuditConfig::create` always draws a random trail and the
/// writer's wall-clock timestamps vary per run; the hand-built
/// records at the fixed `context(seq, previous)` ensure every record
/// hash is a literal constant pinned in
/// [`fixture_hashes_match_literals`], as decision 11 "Step 7 takes
/// the end from the anchor store" requires the P-vs-S mismatch and
/// S's own anchor lookup to be assertable byte-for-byte.
struct HandE3 {
    _dir: Temp,
    archive_dir: PathBuf,
    p: Record,
    p_line: String,
    s: Record,
}
fn hand_built_e3() -> HandE3 {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    let p = signed_cp(3, e2.hash(), &mmr2);
    let mmr3 = pushed(&mmr2, &p);
    let e4 = entry_rec(4, p.hash());
    let mmr4 = pushed(&mmr3, &e4);
    let s = signed_cp(5, e4.hash(), &mmr4);
    put_segment(&d.0, 0, &[&cp0, &e1, &e2], &[]);
    let p_line = line_without_lf(&p);
    HandE3 {
        archive_dir: d.0.clone(),
        _dir: d,
        p,
        p_line,
        s,
    }
}

/// Real-writer E10 scenario: a trail archived at a `resume`
/// opening. Pre-seeds `audit.trail` with the fixture `TRAIL` so the
/// run digest the shared classifier emits stays pinned across runs.
/// Yields the A8-style layout (archive `S0=[]`, `S1=[]`, end record
/// `[cp_opening, resume_entry]`) under the fixture signer. Both
/// sealed segments are empty so the resume opens from genesis
/// without inviting a pre-opening chain finding (ruling 13-V3-d5's
/// genesis-not-first check).
struct WriterE10 {
    _writer_dir: Temp,
    _archive_dir_tmp: Temp,
    archive_dir: PathBuf,
    s1_path: PathBuf,
    cp_opening: Checkpoint,
    opening_line_bytes_with_lf: Vec<u8>,
    resume_line: String,
    resume_line_bytes_with_lf: Vec<u8>,
}
fn writer_e10_scenario() -> WriterE10 {
    writer_e10_scenario_with("operator", "incident")
}
fn writer_e10_scenario_with(operator: &str, reason: &str) -> WriterE10 {
    let writer_dir = Temp::new();
    // Pre-seed the trail marker so `resume` loads the fixture
    // `TRAIL` and the drawn record hashes stay stable.
    write_bytes(
        &writer_dir.0.join("audit.trail"),
        format!("{}\n", hex(&TRAIL)).as_bytes(),
    );
    let signer = fixture_signer();
    let (trail_handle, _receipt, opening) = AuditConfig::new("svc")
        .dir(&writer_dir.0)
        .resume(
            signer.clone(),
            (0, Record::genesis(&TRAIL)),
            0,
            operator,
            reason,
        )
        .unwrap();
    // Closing the handle writes an extra checkpoint line into the
    // live file, which the resume fixture discards: the fixture
    // consumes only the opening and the resume entry.
    let _ = trail_handle.close().unwrap();
    let live = writer_dir.0.join("audit.jsonl");
    let bytes = std::fs::read(&live).unwrap();
    let opening_line_bytes_with_lf = {
        let mut v = opening.line().as_bytes().to_vec();
        v.push(b'\n');
        v
    };
    let opening_len = opening_line_bytes_with_lf.len();
    assert!(
        bytes.starts_with(&opening_line_bytes_with_lf),
        "live file starts with the resume opening"
    );
    let rest = &bytes[opening_len..];
    let resume_end = rest
        .iter()
        .position(|&b| b == b'\n')
        .expect("resume entry ends with LF")
        + 1;
    let resume_line_bytes_with_lf = rest[..resume_end].to_vec();
    let resume_line = std::str::from_utf8(&resume_line_bytes_with_lf)
        .unwrap()
        .strip_suffix('\n')
        .unwrap()
        .to_owned();
    // Archive layout mirrors A8's empty-sealed-S1 shape, but with
    // S0 also empty: the resume opens from genesis, so no record
    // may sit below the opening (ruling 13-V3-d5's genesis-not-first
    // check). Two empty sealed segments drive the shared classifier
    // through the same A8 run digest without inviting a chain
    // finding at seq 0.
    let archive_tmp = Temp::new();
    put_segment(&archive_tmp.0, 0, &[], &[]);
    put_segment(&archive_tmp.0, 1, &[], &[]);
    let s1_path = segment_path(&archive_tmp.0, 1);
    WriterE10 {
        _writer_dir: writer_dir,
        archive_dir: archive_tmp.0.clone(),
        _archive_dir_tmp: archive_tmp,
        s1_path,
        cp_opening: opening,
        opening_line_bytes_with_lf,
        resume_line,
        resume_line_bytes_with_lf,
    }
}

fn trust_writer_e10() -> TrustPolicy {
    TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .build()
        .unwrap()
}

// =====================================================================
// E1 -- ACCEPTANCE. An honest batch produced by the real writer:
// `AuditConfig::create` + `record` + `close`. The archive holds the
// lines before the close checkpoint (which opens the next batch);
// the archive record is the close checkpoint's line and the end
// anchor equals it. Finding list is empty: the batch is clean.
// =====================================================================
#[test]
fn e1_honest_batch_equal_end_anchor_emits_no_findings() {
    let fx = writer_honest_batch();
    let report = Verifier::new(fx.trust.clone())
        .end_before(&fx.close_cp_line, Some(fx.close_cp.clone()))
        .unwrap()
        .verify_files(vec![fx.archive_dir_tmp.0.clone()])
        .unwrap();
    let expected: Vec<Finding> = Vec::new();
    assert_findings(report.findings(), &expected, "E1");
    assert!(report.is_valid(), "E1 is valid");
    assert_eq!(report.trail(), fx.trail_id);
    let _ = &fx.archive_segment;
}

// =====================================================================
// E2 -- ACCEPTANCE. Hand-built honest batch with no end anchor
// given: one unlocated `UnanchoredEnd` at the end checkpoint's `seq`
// with detail exactly `end_before seq <e>: no end anchor`, and
// nothing else.
// =====================================================================
#[test]
fn e2_no_end_anchor_emits_unanchored_end() {
    let fx = hand_built_batch();
    let report = verifier()
        .end_before(&fx.cp2_line, None)
        .unwrap()
        .verify_files(vec![fx.archive_dir.clone()])
        .unwrap();
    let expected = vec![unlocated(
        K::UnanchoredEnd,
        Some(2),
        "end_before seq 2: no end anchor".into(),
    )];
    assert_findings(report.findings(), &expected, "E2");
    assert!(!report.is_strict_valid(), "E2 fails on UnanchoredEnd");
}

// =====================================================================
// E3a -- ACCEPTANCE. Decision 11 bullet "Step 7 takes the end from
// the anchor store": at the hand-built E3 layout (cp0, e1, e2 in the
// archive; P at seq 3; S at seq 5 off to the side), the archive
// record is P's line and the end anchor is S from the anchor store.
// The record (P's line) differs from S's line, so `AnchorMismatch
// "end record differs from end anchor"` fires at P's seq. S also
// joins the anchors; S points at a seq the verified set does not
// hold, so the ordinary anchor rule emits
// `anchor seq 5 hash <S_HONEST_DIGEST>: no record`.
// =====================================================================
#[test]
fn e3a_record_replaced_with_p_line_has_anchor_mismatch_with_s() {
    let fx = hand_built_e3();
    let s_anchor = checkpoint_of(&fx.s);
    let report = verifier()
        .end_before(&fx.p_line, Some(s_anchor))
        .unwrap()
        .verify_files(vec![fx.archive_dir.clone()])
        .unwrap();
    let expected = vec![
        unlocated(
            K::AnchorMismatch,
            Some(3),
            "end record differs from end anchor".into(),
        ),
        unlocated(
            K::AnchorMismatch,
            Some(5),
            format!("anchor seq 5 hash {S_HONEST_DIGEST}: no record"),
        ),
    ];
    assert_findings(report.findings(), &expected, "E3a");
    assert!(!report.is_valid(), "E3a exit 1");
}

// =====================================================================
// E3b -- ACCEPTANCE. Same hand-built E3 layout as E3a but with no
// end anchor: one `UnanchoredEnd` at P's seq. Pairs with E3a to pin
// both bullets of decision 11 "Where the end comes from".
// =====================================================================
#[test]
fn e3b_record_replaced_with_p_line_no_anchor_is_unanchored_end() {
    let fx = hand_built_e3();
    let report = verifier()
        .end_before(&fx.p_line, None)
        .unwrap()
        .verify_files(vec![fx.archive_dir.clone()])
        .unwrap();
    let expected = vec![unlocated(
        K::UnanchoredEnd,
        Some(3),
        "end_before seq 3: no end anchor".into(),
    )];
    assert_findings(report.findings(), &expected, "E3b");
}

// =====================================================================
// E4 -- ACCEPTANCE. The record's first line differs from the end
// anchor only by trailing whitespace. Hand-built because the
// writer does not emit non-canonical whitespace variants of its
// lines. The end-anchor byte-equality rule (ruling 13-V6-d4 point
// 5: each side without its LF, whitespace counts) reports
// `AnchorMismatch` with detail `end record differs from end anchor`.
// The ordinary anchor check sees the matching hash at seq 2 and
// emits no second finding.
// =====================================================================
#[test]
fn e4_trailing_whitespace_still_anchor_mismatch_by_byte_equality() {
    let fx = hand_built_batch();
    let anchor = checkpoint_of(&fx.cp2);
    let record = format!("{} ", fx.cp2_line);
    let report = verifier()
        .end_before(&record, Some(anchor))
        .unwrap()
        .verify_files(vec![fx.archive_dir.clone()])
        .unwrap();
    let expected = vec![unlocated(
        K::AnchorMismatch,
        Some(2),
        "end record differs from end anchor".into(),
    )];
    assert_findings(report.findings(), &expected, "E4");
}

// =====================================================================
// E4b -- ACCEPTANCE. A second non-canonical variant: a leading
// space before the JSON object. Hand-built whitespace variant.
// =====================================================================
#[test]
fn e4b_leading_whitespace_still_anchor_mismatch_by_byte_equality() {
    let fx = hand_built_batch();
    let anchor = checkpoint_of(&fx.cp2);
    let record = format!(" {}", fx.cp2_line);
    let report = verifier()
        .end_before(&record, Some(anchor))
        .unwrap()
        .verify_files(vec![fx.archive_dir.clone()])
        .unwrap();
    let expected = vec![unlocated(
        K::AnchorMismatch,
        Some(2),
        "end record differs from end anchor".into(),
    )];
    assert_findings(report.findings(), &expected, "E4b");
}

// =====================================================================
// E5 -- ACCEPTANCE. The files already hold a byte-identical copy
// of the end line: `TrailEnded` fires at the shipped copy's path
// and line, and `DuplicateRecord` is suppressed (ruling 13-V6-d4
// point 3). The anchor equals the record's first line so no
// `AnchorMismatch` fires.
// =====================================================================
#[test]
fn e5_byte_identical_copy_of_end_line_is_trail_ended_not_duplicate() {
    let fx = hand_built_batch();
    let shipped = fx.archive_dir.join("x_shipped.jsonl");
    write_bytes(&shipped, &line_bytes(&fx.cp2));
    let anchor = checkpoint_of(&fx.cp2);
    let report = verifier()
        .end_before(&fx.cp2_line, Some(anchor))
        .unwrap()
        .verify_files(vec![fx.archive_dir.clone(), shipped.clone()])
        .unwrap();
    let expected = vec![located(
        K::TrailEnded,
        shipped.clone(),
        1,
        2,
        "end_before seq 2: records seq 2..=2 at or above the end".into(),
    )];
    assert_findings(report.findings(), &expected, "E5");
}

// =====================================================================
// E5b -- ACCEPTANCE. One duplicate strictly below the end: the
// archive holds `[cp0, e1]` and a shipped copy of `cp0` at seq 0
// lives alongside it, so seq 0 has two copies while seq 2 is the
// end. The expected list pins the `DuplicateRecord` at seq 0
// alone, so widening the suppression below the end makes this list
// empty and the assertion fails (ruling 13-V6-d4 point 3).
// =====================================================================
#[test]
fn e5b_duplicate_below_end_still_fires_at_or_above_is_suppressed() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1], &[]);
    let shipped = d.0.join("x_shipped.jsonl");
    write_bytes(&shipped, &line_bytes(&cp0));
    let cp2_line = line_without_lf(&cp2);
    let anchor = checkpoint_of(&cp2);
    let report = verifier()
        .end_before(&cp2_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone(), shipped])
        .unwrap();
    let archive = segment_path(&d.0, 0);
    let expected = vec![located(
        K::DuplicateRecord,
        archive,
        1,
        0,
        "2 copies of 1 distinct records".into(),
    )];
    assert_findings(report.findings(), &expected, "E5b");
}

// =====================================================================
// E5c -- ACCEPTANCE. A second byte-identical duplicate below the
// end, this time of `e1` at seq 1. Pairs with E5b so `DuplicateRecord`
// still fires for duplicates at two independent seqs strictly below
// the end (ruling 13-V6-d4 point 3).
// =====================================================================
#[test]
fn e5c_duplicate_of_e1_below_end_still_fires() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    put_segment(&d.0, 0, &[&cp0, &e1], &[]);
    let shipped = d.0.join("x_shipped.jsonl");
    write_bytes(&shipped, &line_bytes(&e1));
    let cp2_line = line_without_lf(&cp2);
    let anchor = checkpoint_of(&cp2);
    let report = verifier()
        .end_before(&cp2_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone(), shipped])
        .unwrap();
    let archive = segment_path(&d.0, 0);
    let expected = vec![located(
        K::DuplicateRecord,
        archive,
        2,
        1,
        "2 copies of 1 distinct records".into(),
    )];
    assert_findings(report.findings(), &expected, "E5c");
}

// =====================================================================
// E5d -- ACCEPTANCE. E5's byte-identical end-line scenario through
// RELATIVE paths: the archive segment (`audit.0.jsonl`) and the
// extra shipped copy (`x_shipped.jsonl`) both live in a tempdir,
// and the verify call runs with `cwd` set to that tempdir. The
// relative paths both sort AFTER `<end record>` (`<` = 0x3C, `a` =
// 0x61, `x` = 0x78), so if the engine drops `is_end_record` from
// its per-`seq` copy sort the end record becomes the first copy at
// seq 2 and `TrailEnded` locates at the end record (which the
// strip-location pass then unlocates). The expected list pins
// `TrailEnded` at the shipped copy's path and line, so dropping the
// flag turns the finding into an unlocated one and the assertion
// fails (ruling 13-V6-d4 point 3). Pairs with E5 (absolute paths)
// so that the test survives on hosts where `/tmp` sorts before `<`.
// =====================================================================
#[test]
fn e5d_byte_identical_copy_relative_paths_locate_trail_ended_at_file() {
    let fx = hand_built_batch();
    // Build the archive segment and the extra shipped copy inside a
    // fresh tempdir, then verify with `cwd` set to that tempdir and
    // only the file names in the paths list. Both file names start
    // with an ASCII letter >= `a` (0x61), so without the
    // `is_end_record` flag the end-record copy (`<end record>`,
    // 0x3C) would sort first and `TrailEnded` would locate at the
    // end record rather than at the shipped file copy.
    let d = Temp::new();
    put_segment(&d.0, 0, &[&fx.cp0, &fx.e1], &[]);
    let shipped_name = "x_shipped.jsonl";
    let shipped_absolute = d.0.join(shipped_name);
    write_bytes(&shipped_absolute, &line_bytes(&fx.cp2));
    let archive_relative: PathBuf = segment_path(&d.0, 0)
        .file_name()
        .expect("segment path has a file name")
        .into();
    let shipped_relative: PathBuf = shipped_name.into();
    let anchor = checkpoint_of(&fx.cp2);
    let report = with_cwd(&d.0, || {
        verifier()
            .end_before(&fx.cp2_line, Some(anchor))
            .unwrap()
            .verify_files(vec![archive_relative.clone(), shipped_relative.clone()])
            .unwrap()
    });
    let expected = vec![located(
        K::TrailEnded,
        shipped_relative,
        1,
        2,
        "end_before seq 2: records seq 2..=2 at or above the end".into(),
    )];
    assert_findings(report.findings(), &expected, "E5d");
}

// =====================================================================
// E6 -- ACCEPTANCE. The files hold two records above the end that
// were not cut: one `TrailEnded` at the FIRST such record with the
// `a..=b` seq range.
// =====================================================================
#[test]
fn e6_files_hold_records_above_end_emits_trail_ended_range() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let e3 = entry_rec(3, cp2.hash());
    let e4 = entry_rec(4, e3.hash());
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2, &e3, &e4], &[]);
    let path = segment_path(&d.0, 0);
    let cp2_line = line_without_lf(&cp2);
    let anchor = checkpoint_of(&cp2);
    let report = verifier()
        .end_before(&cp2_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let expected = vec![
        located(
            K::TrailEnded,
            path,
            3,
            2,
            "end_before seq 2: records seq 2..=4 at or above the end".into(),
        ),
        unlocated(K::UncoveredTail, None, "records seq 3..=4".into()),
    ];
    assert_findings(report.findings(), &expected, "E6");
}

// =====================================================================
// E6b -- ACCEPTANCE. A second layout with more than one record
// above the end, pinning that `TrailEnded` locates at the FIRST
// such record. The range differs from E6's so two rows together
// force both the FIRST-record location and the correct `a..=b`
// span (ruling 13-V6-d4 point 3).
// =====================================================================
#[test]
fn e6b_trail_ended_locates_at_first_record_above_end() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let e3 = entry_rec(3, cp2.hash());
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2, &e3], &[]);
    let path = segment_path(&d.0, 0);
    let cp2_line = line_without_lf(&cp2);
    let anchor = checkpoint_of(&cp2);
    let report = verifier()
        .end_before(&cp2_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let expected = vec![
        located(
            K::TrailEnded,
            path,
            3,
            2,
            "end_before seq 2: records seq 2..=3 at or above the end".into(),
        ),
        unlocated(K::UncoveredTail, None, "records seq 3..=3".into()),
    ];
    assert_findings(report.findings(), &expected, "E6b");
}

// =====================================================================
// E7 -- ACCEPTANCE. The files hold a DIFFERENT record at the end
// seq (hand-built because the real writer cannot sign a non-
// checkpoint record under its own key at a forked seq). The
// expected list pins `AnchorMismatch`, `SeqConflict` and
// `TrailEnded` at the archive copy, not at the end-record segment,
// which requires end copies to sort after the files
// (ruling 13-V6-d4 point 3).
// =====================================================================
#[test]
fn e7_files_hold_different_record_at_end_seq_is_trail_ended_plus_fork() {
    let fx = hand_built_batch();
    let forged = entry_rec(2, fx.e1.hash());
    let d = Temp::new();
    put_segment(&d.0, 0, &[&fx.cp0, &fx.e1, &forged], &[]);
    let anchor = checkpoint_of(&fx.cp2);
    let report = verifier()
        .end_before(&fx.cp2_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let path = segment_path(&d.0, 0);
    let expected = vec![
        located(
            K::AnchorMismatch,
            path.clone(),
            3,
            2,
            format!("anchor seq 2 hash {CP2_HONEST_DIGEST}: seq is forked"),
        ),
        located(
            K::SeqConflict,
            path.clone(),
            3,
            2,
            format!("conflicting hashes: {CP2_HONEST_DIGEST}, {FORGED_E2_DIGEST}"),
        ),
        located(
            K::TrailEnded,
            path,
            3,
            2,
            "end_before seq 2: records seq 2..=2 at or above the end".into(),
        ),
    ];
    assert_findings(report.findings(), &expected, "E7");
}

// =====================================================================
// E7b -- ACCEPTANCE. A fork strictly ABOVE the end seq in the
// files (hand-built: two distinct records at seq 3 forking above
// the end at seq 2). `TrailEnded` and `SeqConflict` must both fire
// at the first file record above the end: ruling 13-V6-d4 point 3
// suppresses only `DuplicateRecord` at or above the end, so a
// forked `seq` is still reported. Pairs with E7 which forks at
// the end seq; together they pin both the above-end and at-end
// cases of the suppression rule.
// =====================================================================
#[test]
fn e7b_fork_above_end_emits_seq_conflict_and_trail_ended() {
    let fx = hand_built_batch();
    let d = Temp::new();
    put_segment(&d.0, 0, &[&fx.cp0, &fx.e1], &[]);
    // Two distinct records at seq 3, both chaining to cp2 (so no
    // ChainBroken is in the way of the fork). The entries differ in
    // their object, so their hashes differ.
    let alt_seeded = {
        let ctx = context(3, fx.cp2.hash());
        Record::new(ctx, Entry::new("actor", "change", "alt")).unwrap()
    };
    let e3_regular = entry_rec(3, fx.cp2.hash());
    let shipped_a = d.0.join("x_shipped_a.jsonl");
    let shipped_b = d.0.join("y_shipped_b.jsonl");
    write_bytes(&shipped_a, &line_bytes(&e3_regular));
    write_bytes(&shipped_b, &line_bytes(&alt_seeded));
    let anchor = checkpoint_of(&fx.cp2);
    let report = verifier()
        .end_before(&fx.cp2_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone(), shipped_a.clone(), shipped_b.clone()])
        .unwrap();
    let expected = vec![
        located(
            K::SeqConflict,
            shipped_a.clone(),
            1,
            3,
            format!("conflicting hashes: {E3_ALT_DIGEST}, {E3_HONEST_DIGEST}"),
        ),
        located(
            K::TrailEnded,
            shipped_a,
            1,
            3,
            "end_before seq 2: records seq 3..=3 at or above the end".into(),
        ),
        unlocated(K::UncoveredTail, None, "records seq 3..=3".into()),
    ];
    assert_findings(report.findings(), &expected, "E7b");
}

// =====================================================================
// E7c -- ACCEPTANCE. E7's scenario reached through RELATIVE paths:
// the archive segment is `audit.0.jsonl` in a tempdir, and the
// verify call runs with `cwd` set to that tempdir. The relative
// path starts with `a` (0x61), which sorts AFTER `<end record>`
// (`<` = 0x3C), so if the engine drops `is_end_record` from its
// per-`seq` copy sort (or `verify::first_copy` drops it) the end
// record would become the first copy at seq 2 and the three
// findings would locate at the end record instead of the archive
// segment. The expected list pins the archive-copy location, so
// dropping the flag flips `AnchorMismatch`/`SeqConflict`/`TrailEnded`
// off the file path and the assertion fails (ruling 13-V6-d4 point
// 3). Pairs with E7 (absolute paths) so that the test survives on
// hosts where `/tmp` sorts before `<`.
// =====================================================================
#[test]
fn e7c_files_hold_different_record_at_end_seq_relative_paths() {
    let fx = hand_built_batch();
    let forged = entry_rec(2, fx.e1.hash());
    let d = Temp::new();
    put_segment(&d.0, 0, &[&fx.cp0, &fx.e1, &forged], &[]);
    let anchor = checkpoint_of(&fx.cp2);
    // The fixture segment file name is `audit-<stamp>_<id>.jsonl`;
    // keep just the file name so the path is relative to `cwd`.
    let relative_segment: PathBuf = segment_path(&d.0, 0)
        .file_name()
        .expect("segment path has a file name")
        .into();
    let report = with_cwd(&d.0, || {
        verifier()
            .end_before(&fx.cp2_line, Some(anchor))
            .unwrap()
            .verify_files(vec![relative_segment.clone()])
            .unwrap()
    });
    let expected = vec![
        located(
            K::AnchorMismatch,
            relative_segment.clone(),
            3,
            2,
            format!("anchor seq 2 hash {CP2_HONEST_DIGEST}: seq is forked"),
        ),
        located(
            K::SeqConflict,
            relative_segment.clone(),
            3,
            2,
            format!("conflicting hashes: {CP2_HONEST_DIGEST}, {FORGED_E2_DIGEST}"),
        ),
        located(
            K::TrailEnded,
            relative_segment,
            3,
            2,
            "end_before seq 2: records seq 2..=2 at or above the end".into(),
        ),
    ];
    assert_findings(report.findings(), &expected, "E7c");
}

// =====================================================================
// E7c2 -- ACCEPTANCE. Second relative-paths row for the end-record
// ordering flag: same relative-paths setup as E7c but the file's
// record at the end `seq` forks through a DIFFERENT hash (a
// `Record::new` with an unrelated entry object rather than
// `entry_rec`). Keeps the same expected locations so that dropping
// `is_end_record` from either `verify::first_copy` or the engine's
// per-`seq` copy sort fails on two independent file paths (E7c's
// forged record and E7c2's), not only one.
// =====================================================================
#[test]
fn e7c2_different_forged_record_at_end_seq_relative_paths() {
    let fx = hand_built_batch();
    let alt_forged = {
        let ctx = context(2, fx.e1.hash());
        Record::new(ctx, Entry::new("actor", "change", "alt")).unwrap()
    };
    let d = Temp::new();
    put_segment(&d.0, 0, &[&fx.cp0, &fx.e1, &alt_forged], &[]);
    let anchor = checkpoint_of(&fx.cp2);
    let relative_segment: PathBuf = segment_path(&d.0, 0)
        .file_name()
        .expect("segment path has a file name")
        .into();
    let report = with_cwd(&d.0, || {
        verifier()
            .end_before(&fx.cp2_line, Some(anchor))
            .unwrap()
            .verify_files(vec![relative_segment.clone()])
            .unwrap()
    });
    let expected = vec![
        located(
            K::AnchorMismatch,
            relative_segment.clone(),
            3,
            2,
            format!("anchor seq 2 hash {CP2_HONEST_DIGEST}: seq is forked"),
        ),
        located(
            K::SeqConflict,
            relative_segment.clone(),
            3,
            2,
            format!("conflicting hashes: {CP2_HONEST_DIGEST}, {FORGED_E2_ALT_DIGEST}"),
        ),
        located(
            K::TrailEnded,
            relative_segment,
            3,
            2,
            "end_before seq 2: records seq 2..=2 at or above the end".into(),
        ),
    ];
    assert_findings(report.findings(), &expected, "E7c2");
}

// =====================================================================
// E8 -- REGRESSION (parse-only). Each row below drives one line
// of ruling 13-V6-d4 point 4 ("anything else is `InvalidConfig`
// and names the reason"). Each check has two rows with distinct
// inputs so removing that check fails on two independent inputs
// at runtime. `assert_invalid` matches the full `InvalidConfig`
// message against a stable reason substring that names the check.
// =====================================================================

/// A record payload whose first line is an ordinary entry rather
/// than a checkpoint; shared by E8d/E8d2.
fn non_checkpoint_line(fx: &HandBatch) -> String {
    line_without_lf(&fx.e1)
}

#[test]
fn e8a_empty_record_rejected() {
    assert_invalid(verifier().end_before("", None), "empty", "E8a empty");
}
#[test]
fn e8a2_lone_lf_rejected() {
    // Distinct from E8a: a single LF strips to an empty remainder,
    // which the one empty-record check must reject with the same
    // reason.
    assert_invalid(verifier().end_before("\n", None), "empty", "E8a2 lone LF");
}
#[test]
fn e8b_three_lines_after_valid_resume_rejected() {
    let fx = hand_built_batch();
    let resume = resume_entry(
        fx.cp2.context.seq + 1,
        fx.cp2.hash(),
        fx.cp2.context.seq,
        fx.cp2.hash(),
    );
    let three = format!("{}\n{}\nextra", fx.cp2_line, line_without_lf(&resume));
    assert_invalid(
        verifier().end_before(&three, None),
        "more than two lines",
        "E8b three lines",
    );
}
#[test]
fn e8b2_three_lines_with_cp2_tail_rejected() {
    let fx = hand_built_batch();
    let resume = resume_entry(
        fx.cp2.context.seq + 1,
        fx.cp2.hash(),
        fx.cp2.context.seq,
        fx.cp2.hash(),
    );
    let three = format!(
        "{}\n{}\n{}",
        fx.cp2_line,
        line_without_lf(&resume),
        fx.cp2_line,
    );
    assert_invalid(
        verifier().end_before(&three, None),
        "more than two lines",
        "E8b2 three lines twin",
    );
}
#[test]
fn e8c_trailing_cr_rejected() {
    let fx = hand_built_batch();
    let cr = format!("{}\r", fx.cp2_line);
    assert_invalid(verifier().end_before(&cr, None), "CR", "E8c trailing CR");
}
#[test]
fn e8c2_cr_lf_pair_rejected() {
    let fx = hand_built_batch();
    let cr = format!("{}\r\n", fx.cp2_line);
    assert_invalid(verifier().end_before(&cr, None), "CR", "E8c2 CRLF");
}
#[test]
fn e8d_non_checkpoint_first_line_rejected() {
    let fx = hand_built_batch();
    assert_invalid(
        verifier().end_before(&non_checkpoint_line(&fx), None),
        "first line is not a checkpoint",
        "E8d non-cp",
    );
}
#[test]
fn e8d2_non_checkpoint_first_line_with_second_rejected() {
    let fx = hand_built_batch();
    let first = non_checkpoint_line(&fx);
    let body = format!("{first}\nanything");
    assert_invalid(
        verifier().end_before(&body, None),
        "first line is not a checkpoint",
        "E8d2 non-cp with 2nd",
    );
}
#[test]
fn e8e_second_line_not_a_record_rejected() {
    let fx = hand_built_batch();
    let both = format!("{}\nnot-a-record", fx.cp2_line);
    assert_invalid(
        verifier().end_before(&both, None),
        "second line is not a resume",
        "E8e non-record second",
    );
}
#[test]
fn e8e2_second_line_entry_not_resume_rejected() {
    let fx = hand_built_batch();
    let line2 = line_without_lf(&fx.e1);
    let both = format!("{}\n{line2}", fx.cp2_line);
    assert_invalid(
        verifier().end_before(&both, None),
        "second line is not a resume",
        "E8e2 entry second",
    );
}
#[test]
fn e8f_resume_line_with_wrong_seq_rejected() {
    let fx = hand_built_batch();
    let wrong = resume_entry(
        fx.cp2.context.seq + 2,
        fx.cp2.hash(),
        fx.cp2.context.seq,
        fx.cp2.hash(),
    );
    let both = format!("{}\n{}", fx.cp2_line, line_without_lf(&wrong));
    assert_invalid(
        verifier().end_before(&both, None),
        "resume line seq is not cp.seq + 1",
        "E8f wrong resume seq",
    );
}
#[test]
fn e8f2_resume_line_with_zero_seq_rejected() {
    let fx = hand_built_batch();
    let wrong = resume_entry(0, fx.cp2.hash(), fx.cp2.context.seq, fx.cp2.hash());
    let both = format!("{}\n{}", fx.cp2_line, line_without_lf(&wrong));
    assert_invalid(
        verifier().end_before(&both, None),
        "resume line seq is not cp.seq + 1",
        "E8f2 zero resume seq",
    );
}
#[test]
fn e8g_resume_line_with_wrong_prev_hash_rejected() {
    let fx = hand_built_batch();
    let wrong = resume_entry(
        fx.cp2.context.seq + 1,
        [0; 32],
        fx.cp2.context.seq,
        fx.cp2.hash(),
    );
    let both = format!("{}\n{}", fx.cp2_line, line_without_lf(&wrong));
    assert_invalid(
        verifier().end_before(&both, None),
        "resume line prev_hash does not equal cp.hash",
        "E8g wrong resume prev",
    );
}
#[test]
fn e8g2_resume_line_prev_hash_e1_rejected() {
    let fx = hand_built_batch();
    let wrong = resume_entry(
        fx.cp2.context.seq + 1,
        fx.e1.hash(),
        fx.cp2.context.seq,
        fx.cp2.hash(),
    );
    let both = format!("{}\n{}", fx.cp2_line, line_without_lf(&wrong));
    assert_invalid(
        verifier().end_before(&both, None),
        "resume line prev_hash does not equal cp.hash",
        "E8g2 prev as e1",
    );
}
#[test]
fn e8h_trailing_lf_accepted() {
    let fx = hand_built_batch();
    let with_lf = format!("{}\n", fx.cp2_line);
    assert!(
        verifier().end_before(&with_lf, None).is_ok(),
        "E8h trailing LF"
    );
}
#[test]
fn e8i_valid_resume_accepted() {
    let fx = hand_built_batch();
    let ok = resume_entry(
        fx.cp2.context.seq + 1,
        fx.cp2.hash(),
        fx.cp2.context.seq,
        fx.cp2.hash(),
    );
    let both = format!("{}\n{}", fx.cp2_line, line_without_lf(&ok));
    assert!(
        verifier().end_before(&both, None).is_ok(),
        "E8i valid resume"
    );
}

// =====================================================================
// E9 -- ACCEPTANCE. The conflict between `max_age` and
// `end_before` in both call orders (ruling 13-V6-d4 point 7): each
// is `InvalidConfig` from whichever call comes second. `end_before`
// called twice keeps the second call's record and anchor.
// =====================================================================
#[test]
fn e9a_max_age_then_end_before_errors() {
    let fx = hand_built_batch();
    let v = verifier().max_age(std::time::Duration::ZERO).unwrap();
    assert_invalid(
        v.end_before(&fx.cp2_line, None),
        "end_before conflicts with max_age",
        "E9a max_age then end_before",
    );
}
#[test]
fn e9b_end_before_then_max_age_errors() {
    let fx = hand_built_batch();
    let v = verifier().end_before(&fx.cp2_line, None).unwrap();
    match v.max_age(std::time::Duration::ZERO) {
        Ok(_) => panic!("E9b: expected InvalidConfig, got Ok"),
        Err(e) => {
            assert_eq!(e.kind(), AuditErrorKind::InvalidConfig);
            assert!(
                e.to_string().contains("max_age conflicts with end_before"),
                "E9b: {}",
                e,
            );
        }
    }
}
#[test]
fn e9b2_end_before_then_max_age_hour_errors() {
    // Pair for E9b with a non-zero `max_age`: the duration value
    // is not part of the conflict rule (ADR-0005 §19.2; ruling
    // 13-V6-d4 point 7), so a zero-duration row cannot be the only
    // one that proves the `max_age` side of the check.
    let fx = hand_built_batch();
    let v = verifier().end_before(&fx.cp2_line, None).unwrap();
    match v.max_age(std::time::Duration::from_secs(3600)) {
        Ok(_) => panic!("E9b2: expected InvalidConfig, got Ok"),
        Err(e) => {
            assert_eq!(e.kind(), AuditErrorKind::InvalidConfig);
            assert!(
                e.to_string().contains("max_age conflicts with end_before"),
                "E9b2: {}",
                e,
            );
        }
    }
}
#[test]
fn e9c_end_before_twice_keeps_second() {
    let fx = hand_built_batch();
    let anchor = checkpoint_of(&fx.cp2);
    let report = verifier()
        .end_before(&line_without_lf(&fx.cp0), None)
        .unwrap()
        .end_before(&fx.cp2_line, Some(anchor))
        .unwrap()
        .verify_files(vec![fx.archive_dir.clone()])
        .unwrap();
    let expected: Vec<Finding> = Vec::new();
    assert_findings(report.findings(), &expected, "E9c second wins");
}

fn digest_bytes_from_hex(h: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

// =====================================================================
// E10 -- ACCEPTANCE. Decision 2 l.956 "run digest equality":
// step 6 (archive + live) and step 7 (archive + `end_before`)
// each produce a `SegmentStructure` run finding whose digest is
// equal. The archive is a real resume opening produced by
// `AuditConfig::resume` with a pre-seeded `audit.trail` so the
// drawn hashes stay pinned.
// =====================================================================
#[test]
fn e10_step6_and_step7_report_the_same_findings() {
    let fx = writer_e10_scenario();
    let run_digest = digest_bytes_from_hex(RUN_DIGEST_E10_HEX);

    // Step 6: archive + live file containing the resume opening
    // plus the resume record.
    let d6 = Temp::new();
    put_segment(&d6.0, 0, &[], &[]);
    put_segment(&d6.0, 1, &[], &[]);
    let live6 = d6.0.join("audit.jsonl");
    let mut live6_bytes = fx.opening_line_bytes_with_lf.clone();
    live6_bytes.extend_from_slice(&fx.resume_line_bytes_with_lf);
    write_bytes(&live6, &live6_bytes);
    let report6 = Verifier::new(trust_writer_e10())
        .verify_files(vec![d6.0.clone()])
        .unwrap();

    // Step 7: same archive + `end_before(cp_opening + resume)`.
    let record = format!("{}\n{}", fx.cp_opening.line(), &fx.resume_line);
    let report7 = Verifier::new(trust_writer_e10())
        .end_before(&record, Some(fx.cp_opening.clone()))
        .unwrap()
        .verify_files(vec![fx.archive_dir.clone()])
        .unwrap();

    let resumed_detail = resumed_detail_e10(&fx);
    let s0_6 = segment_path(&d6.0, 0);
    let s1_6 = segment_path(&d6.0, 1);
    let expected6 = vec![
        located(K::SeqGap, live6.clone(), 1, 1, "missing seq 0..=0".into()),
        located(K::Resumed, live6, 2, 2, resumed_detail.clone()),
        unlocated(K::UncoveredTail, None, "records seq 2..=2".into()),
        Finding::new(
            K::SegmentStructure,
            Some(s0_6.clone()),
            None,
            None,
            "expected first complete record to be a checkpoint".into(),
        ),
        Finding::new(
            K::SegmentStructure,
            Some(s0_6),
            None,
            None,
            format!("digest blake3:{RUN_DIGEST_E10_HEX}"),
        )
        .with_run_digest(run_digest),
        Finding::new(
            K::SegmentStructure,
            Some(s1_6),
            None,
            None,
            "expected first complete record to be a checkpoint".into(),
        ),
    ];
    assert_findings(report6.findings(), &expected6, "E10 step 6");

    let s0_7 = segment_path(&fx.archive_dir, 0);
    let s1_7 = fx.s1_path.clone();
    // Ruling 13-V6-d6 point 3: with no file record below `e = 1`,
    // the end checkpoint is the lowest record and the chain rule
    // does not check it, so the end-specific `ChainBroken` fires.
    let expected7 = vec![
        unlocated(
            K::ChainBroken,
            Some(1),
            "end_before seq 1: no record precedes the end".into(),
        ),
        unlocated(K::SeqGap, Some(1), "missing seq 0..=0".into()),
        unlocated(K::Resumed, Some(2), resumed_detail),
        unlocated(K::UncoveredTail, None, "records seq 2..=2".into()),
        Finding::new(
            K::SegmentStructure,
            Some(s0_7.clone()),
            None,
            None,
            "expected first complete record to be a checkpoint".into(),
        ),
        Finding::new(
            K::SegmentStructure,
            Some(s0_7),
            None,
            None,
            format!("digest blake3:{RUN_DIGEST_E10_HEX}"),
        )
        .with_run_digest(run_digest),
        Finding::new(
            K::SegmentStructure,
            Some(s1_7),
            None,
            None,
            "expected first complete record to be a checkpoint".into(),
        ),
    ];
    assert_findings(report7.findings(), &expected7, "E10 step 7");

    let run6 = report6
        .findings()
        .iter()
        .find(|f| f.run_digest().is_some())
        .expect("E10 step 6 has a run finding");
    let run7 = report7
        .findings()
        .iter()
        .find(|f| f.run_digest().is_some())
        .expect("E10 step 7 has a run finding");
    assert_eq!(run6.run_digest(), run7.run_digest(), "E10 run digest");
    assert_eq!(run6.run_digest(), Some(run_digest), "E10 run digest pin");
}

// =====================================================================
// E10b -- ACCEPTANCE. A second step-7 row with the SAME archive
// layout as E10 but different operator and reason strings on the
// resume record. The loss layout is identical (opening at seq 1,
// `lost_through = 0`), so the run digest reuses `RUN_DIGEST_E10_HEX`
// (ruling 13-V4-d8 point 1: the digest covers only ranges and gap
// spans, not record contents). The `Resumed` detail and the resume
// line bytes differ from E10's, so if the end record is merged by
// `seq` only and never walked by the classifier the digest-bearing
// `SegmentStructure` finding disappears and this row fails
// independently of E10.
// =====================================================================
#[test]
fn e10b_second_step7_row_different_operator_reason() {
    let fx = writer_e10_scenario_with("admin", "dry-run");
    let run_digest = digest_bytes_from_hex(RUN_DIGEST_E10_HEX);
    let record = format!("{}\n{}", fx.cp_opening.line(), &fx.resume_line);
    let report = Verifier::new(trust_writer_e10())
        .end_before(&record, Some(fx.cp_opening.clone()))
        .unwrap()
        .verify_files(vec![fx.archive_dir.clone()])
        .unwrap();
    let s0 = segment_path(&fx.archive_dir, 0);
    let s1 = fx.s1_path.clone();
    let resumed = resumed_detail_e10_with("admin", "dry-run");
    // Ruling 13-V6-d6 point 3: no file record below `e = 1`.
    let expected = vec![
        unlocated(
            K::ChainBroken,
            Some(1),
            "end_before seq 1: no record precedes the end".into(),
        ),
        unlocated(K::SeqGap, Some(1), "missing seq 0..=0".into()),
        unlocated(K::Resumed, Some(2), resumed),
        unlocated(K::UncoveredTail, None, "records seq 2..=2".into()),
        Finding::new(
            K::SegmentStructure,
            Some(s0.clone()),
            None,
            None,
            "expected first complete record to be a checkpoint".into(),
        ),
        Finding::new(
            K::SegmentStructure,
            Some(s0),
            None,
            None,
            format!("digest blake3:{RUN_DIGEST_E10_HEX}"),
        )
        .with_run_digest(run_digest),
        Finding::new(
            K::SegmentStructure,
            Some(s1),
            None,
            None,
            "expected first complete record to be a checkpoint".into(),
        ),
    ];
    assert_findings(report.findings(), &expected, "E10b");
}

fn resumed_detail_e10(_fx: &WriterE10) -> String {
    resumed_detail_e10_with("operator", "incident")
}
fn resumed_detail_e10_with(operator: &str, reason: &str) -> String {
    // The resume opens from genesis (`AuditConfig::resume` with
    // head=(0, genesis(TRAIL))) and declares lost_through=0, so the
    // detail's head hash is the trail's genesis digest and the gap
    // takes the fixed genesis form `0..=L` (ADR l.407; ruling
    // 13-V3-d5 point 3).
    format!(
        "operator={operator} reason={reason} head=0:{} gap=0..=0 lost_records=0 structural=valid",
        digest_string(&Record::genesis(&TRAIL)),
    )
}

// =====================================================================
// E11 -- ACCEPTANCE. The end checkpoint is signed by an untrusted
// key: `UntrustedKey` fires on it, with no file and no line (ruling
// 13-V6-d4 point 6). Hand-built because the real writer cannot
// sign a checkpoint with a key the policy does not trust.
// =====================================================================
#[test]
fn e11_untrusted_end_checkpoint_has_untrusted_key_without_location() {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    put_segment(&d.0, 0, &[&cp0, &e1], &[]);
    let cp2 = signed_cp_other(2, e1.hash(), &mmr1);
    let cp2_line = line_without_lf(&cp2);
    let anchor = checkpoint_of(&cp2);
    let report = verifier()
        .end_before(&cp2_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let expected = vec![
        unlocated(
            K::UntrustedKey,
            Some(2),
            format!("key {UNTRUSTED_KEY_HEX} not listed for trail {TRAIL_HEX}"),
        ),
        unlocated(K::UncoveredTail, None, "records seq 1..=2".into()),
    ];
    assert_findings(report.findings(), &expected, "E11");
}

// =====================================================================
// REGRESSION. Fixture-hash pins: recompute the hashes the rows
// assert literally and compare with the layout builders by
// equality. A change in the fixture (seq, chain, key) fails here
// instead of drifting through many rows.
// =====================================================================
#[test]
fn fixture_hashes_match_literals() {
    let fx = hand_built_batch();
    assert_eq!(hex(&TRAIL), TRAIL_HEX);
    assert_eq!(hex(&fixture_pubkey()), FIXTURE_KEY_HEX);
    let untrusted = KeyFileSigner::from_hex(&"42".repeat(32)).unwrap();
    assert_eq!(hex(&untrusted.public_key()), UNTRUSTED_KEY_HEX);
    assert_eq!(digest_string(&fx.cp0.hash()), CP0_HONEST_DIGEST);
    assert_eq!(digest_string(&fx.e1.hash()), E1_HONEST_DIGEST);
    assert_eq!(digest_string(&fx.cp2.hash()), CP2_HONEST_DIGEST);
    let forged = entry_rec(2, fx.e1.hash());
    assert_eq!(digest_string(&forged.hash()), FORGED_E2_DIGEST);
    let alt_forged = {
        let ctx = context(2, fx.e1.hash());
        Record::new(ctx, Entry::new("actor", "change", "alt")).unwrap()
    };
    assert_eq!(digest_string(&alt_forged.hash()), FORGED_E2_ALT_DIGEST);
    let e3 = entry_rec(3, fx.cp2.hash());
    assert_eq!(digest_string(&e3.hash()), E3_HONEST_DIGEST);
    let alt = {
        let ctx = context(3, fx.cp2.hash());
        Record::new(ctx, Entry::new("actor", "change", "alt")).unwrap()
    };
    assert_eq!(digest_string(&alt.hash()), E3_ALT_DIGEST);
    // cp2's line parses back to the same checkpoint hash (so
    // `Checkpoint::parse` applied to the stored line of an honest
    // writer produces a checkpoint equal to the one the fixture
    // builder returned).
    let parsed = Checkpoint::parse(&fx.cp2_line).unwrap();
    assert_eq!(parsed.hash(), fx.cp2.hash());
    // Pin the E3 record hashes (P, E4, S) through a second,
    // independent build of the hand-built E3 chain. E2's hash is
    // the same byte sequence as E7's `FORGED_E2_DIGEST`
    // (`entry_rec(2, e1.hash())` under the fixture signer); pin
    // that equality explicitly through `E2_HONEST_DIGEST`.
    let e3_fx = hand_built_e3();
    let e2 = entry_rec(2, fx.e1.hash());
    assert_eq!(digest_string(&e2.hash()), E2_HONEST_DIGEST);
    assert_eq!(digest_string(&e3_fx.p.hash()), P_HONEST_DIGEST);
    let e4 = entry_rec(4, e3_fx.p.hash());
    assert_eq!(digest_string(&e4.hash()), E4_HONEST_DIGEST);
    assert_eq!(digest_string(&e3_fx.s.hash()), S_HONEST_DIGEST);
    // Pin the E10 run digest: build the A8-style resume archive and
    // walk it through the verifier; the SegmentStructure run
    // finding's digest must equal the literal constant.
    let fx10 = writer_e10_scenario();
    let record = format!("{}\n{}", fx10.cp_opening.line(), &fx10.resume_line);
    let report = Verifier::new(trust_writer_e10())
        .end_before(&record, Some(fx10.cp_opening.clone()))
        .unwrap()
        .verify_files(vec![fx10.archive_dir.clone()])
        .unwrap();
    let run = report
        .findings()
        .iter()
        .find(|f| f.run_digest().is_some())
        .expect("E10 pin: a run finding is present");
    assert_eq!(
        digest_string(&run.run_digest().unwrap()),
        format!("blake3:{RUN_DIGEST_E10_HEX}"),
        "E10 run digest literal pin",
    );
}
