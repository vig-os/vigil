//! Rows for the verifier's above-the-end set-aside under
//! `Verifier::end_before` (ADR-0005 decision 11 "It ends the range",
//! ~l.764, and "Inputs outside a batch", ~l.949; ruling 13-V6-d7).
//! Every row asserts the full sorted literal [`Finding`] list as
//! whole values through [`assert_findings`]; every digest and key in
//! an expected detail is a written-out hex constant pinned by
//! [`fixture_hashes_match_literals`]. Each row is labelled
//! ACCEPTANCE or REGRESSION in its doc comment.
//!
//! Fixture style: the writer stamps every record through a time hook
//! that is `pub(super)` inside `sink` and not reachable from this
//! module, so the writer's record hashes drift per run and these
//! rows are hand-built. They use the fixture `TRAIL` and
//! `signed_cp`/`entry_rec`, which construct a record through the
//! same `Record::checkpoint` / `CheckpointFields` call the writer's
//! `sink::signed` uses (`sink.rs` ~765..=781) at the fixture clock.

use crate::audit::{
    Checkpoint, Entry, FindingKind as K, KeyFileSigner, Mmr, Record, RecordContext, Signer,
    TrustPolicy, digest_string,
    format::CheckpointFields,
    hex,
    runs_v4a_fixtures::{
        TRAIL, Temp, context, entry_rec, fixture_pubkey, line_bytes, pushed, put_segment, seeded,
        segment_path, signed_cp,
    },
    verify::{Finding, Verifier},
};
use std::path::PathBuf;

// =====================================================================
// Shared literal hex constants pinned by `fixture_hashes_match_literals`.
// =====================================================================

const TRAIL_HEX: &str = "11111111111111111111111111111111";
const OTHER_TRAIL: [u8; 16] = [0x01; 16];
const OTHER_TRAIL_HEX: &str = "01010101010101010101010101010101";
const FIXTURE_KEY_HEX: &str = "ee45ecb9aca01a0abd83ef56dd985c8c874e6e7f4aebcedf20bd8d88c2a0add7";
const ALT_KEY_HEX: &str = "c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242";

/// `signed_cp(0, Record::genesis(&TRAIL), &Mmr::new())`.
const CP0_HONEST_DIGEST: &str =
    "blake3:fc26c6f2bb830592aaaca5413da1599489d86ac6e240a4a7a010681e0d4c8e77";
/// `signed_cp(2, e1.hash(), &fold([cp0, e1]))` on the honest chain.
const CP2_HONEST_DIGEST: &str =
    "blake3:4164966a12a675e55eb6e133b9e50313907f164fe142d941447defcdfdb25d06";
/// `signed_cp(3, cp2.hash(), &fold([cp0, e1, cp2]))` — the end
/// record `cp3` on the hand-built chain. Pinned by the self-test.
const CP3_HONEST_DIGEST: &str =
    "blake3:dfbf4e5a7173125e6d43847fa1c1b05420adc1c09022566ebbb292b72cf0203c";
/// `signed_cp(4, cp3.hash(), &fold([cp0, e1, cp2, cp3]))` — `cp4`
/// on the hand-built chain, used only as an anchor above the end.
const CP4_ABOVE_DIGEST: &str =
    "blake3:3fec32417882015ede12060ea10c7f50c6e74038cb2f706e5f9b69eb172c6520";
/// `signed_cp(5, cp4.hash(), &fold([cp0, e1, cp2, cp3, cp4]))` — `cp5`
/// above the end, used only as an anchor.
const CP5_ABOVE_DIGEST: &str =
    "blake3:9325fbabb9ce7a94cb7d90db41983d0626c7315cbcb5f56f38d23d8769948709";
/// `signed_cp_other(5, [0xaa; 32], &foreign_mmr_one())` on `OTHER_TRAIL`.
const CP5_OTHER_DIGEST: &str =
    "blake3:5642c84c7cb858d1acc2b0bb8ea45adda145d419d63ff35810b507212afcfbc0";
/// `signed_cp_other(4, [0xaa; 32], &foreign_mmr_one())` on `OTHER_TRAIL`.
const CP4_OTHER_DIGEST: &str =
    "blake3:fba7f2ac1edf3169f1573c4f2ff46d1615ec09f1b0ade17cdc2e1d97b7b98c0e";
/// `signed_cp(1, cp0.hash(), &seeded(&cp0))` — a checkpoint at `seq=1`
/// slot, used as an anchor below the start in X10.
const CP1_FROM_CP0_DIGEST: &str =
    "blake3:8a7785644d05dbdbcd8b128eb1f17aca5206eca1b9448483a49e5cdfb7ed4c42";
/// `sign_as(&alt_signer(), 3, cp2.hash(), &fold([cp0, e1, cp2]))` —
/// the alt-signed `cp3` used by X3 and X9 so the end record is
/// trusted by a key other than the bounded one.
const CP3_ALT_DIGEST: &str =
    "blake3:452daeab14e31d58bbde3cd306cc4ee0b3d1b3b54cd6c8df53838518a9944c04";

/// Fake hash used as the `through=5` bound target in X1/X2/X8.
const PIN_H5_HEX: &str = "blake3:5555555555555555555555555555555555555555555555555555555555555555";
/// Fake hash used as the trust-file `end=7`'s target in X1/X2/X8.
const END_H7_HEX: &str = "blake3:7777777777777777777777777777777777777777777777777777777777777777";

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

fn checkpoint_of(record: &Record) -> Checkpoint {
    let bytes = line_bytes(record);
    let text = std::str::from_utf8(&bytes).unwrap();
    Checkpoint::parse(text.strip_suffix('\n').unwrap()).unwrap()
}
fn line_without_lf(record: &Record) -> String {
    let bytes = line_bytes(record);
    std::str::from_utf8(&bytes)
        .unwrap()
        .strip_suffix('\n')
        .unwrap()
        .to_owned()
}

fn alt_signer() -> KeyFileSigner {
    KeyFileSigner::from_hex(&"55".repeat(32)).unwrap()
}

fn foreign_mmr_one() -> Mmr {
    let mut m = Mmr::new();
    m.push([0xaa; 32]).unwrap();
    m
}

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

fn sign_as(signer: &KeyFileSigner, seq: u64, previous: [u8; 32], mmr: &Mmr) -> Record {
    let ctx = RecordContext::new(TRAIL, seq, 100 + seq, "test", previous);
    let fields = |sig| {
        CheckpointFields::new(
            mmr.size(),
            mmr.root(),
            mmr.peaks().to_vec(),
            signer.public_key(),
            sig,
        )
        .unwrap()
    };
    let unsigned = Record::checkpoint(ctx.clone(), fields([0; 64])).unwrap();
    let signature = signer.sign(&unsigned.signing_message().unwrap()).unwrap();
    Record::checkpoint(ctx, fields(signature)).unwrap()
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

/// Honest hand-built chain `[cp0, e1, cp2, cp3]` at the fixture
/// `TRAIL` and fixture signer; `cp3` serves as the end record whose
/// checkpoint pins the batch (ruling 13-V6-d7 point 1).
struct Chain {
    cp0: Record,
    e1: Record,
    cp2: Record,
    cp3: Record,
    /// Running MMR fold through `[cp0, e1, cp2]`, the base for
    /// signing `cp3_alt` (X3, X9).
    mmr2: Mmr,
    /// Running MMR fold through `[cp0, e1, cp2, cp3]`, the base for
    /// building higher-seq anchors above the end.
    mmr3: Mmr,
}
fn build_chain() -> Chain {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    let cp3 = signed_cp(3, cp2.hash(), &mmr2);
    let mmr3 = pushed(&mmr2, &cp3);
    Chain {
        cp0,
        e1,
        cp2,
        cp3,
        mmr2,
        mmr3,
    }
}

struct Segment {
    _dir: Temp,
    dir_path: PathBuf,
    path: PathBuf,
}
fn seal(records: &[&Record]) -> Segment {
    let d = Temp::new();
    put_segment(&d.0, 0, records, &[]);
    let path = segment_path(&d.0, 0);
    let dir_path = d.0.clone();
    Segment {
        _dir: d,
        dir_path,
        path,
    }
}

fn trust_only_fixture() -> TrustPolicy {
    TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .build()
        .unwrap()
}

// Convenience builders for the above-end finding grammar.
fn out_of_range_anchor(seq: u64, hash_hex: &str, end_seq: u64) -> Finding {
    unlocated(
        K::OutOfRange,
        Some(seq),
        format!("anchor seq {seq} hash {hash_hex}: above end seq {end_seq}"),
    )
}
fn unanchored_end_anchor(seq: u64, hash_hex: &str, end_seq: u64) -> Finding {
    unlocated(
        K::UnanchoredEnd,
        Some(seq),
        format!("anchor seq {seq} hash {hash_hex}: above end seq {end_seq}"),
    )
}
fn out_of_range_pin(key_hex: &str, b: u64, end_seq: u64) -> Finding {
    unlocated(
        K::OutOfRange,
        Some(b),
        format!("key {key_hex} through={b}: above end seq {end_seq}"),
    )
}
fn unanchored_end_pin(key_hex: &str, b: u64, end_seq: u64) -> Finding {
    unlocated(
        K::UnanchoredEnd,
        Some(b),
        format!("key {key_hex} through={b}: above end seq {end_seq}"),
    )
}
fn out_of_range_end(s: u64, hash_hex: &str, end_seq: u64) -> Finding {
    unlocated(
        K::OutOfRange,
        Some(s),
        format!("end={s}:{hash_hex}: above end seq {end_seq}"),
    )
}
fn unanchored_end_end(s: u64, hash_hex: &str, end_seq: u64) -> Finding {
    unlocated(
        K::UnanchoredEnd,
        Some(s),
        format!("end={s}:{hash_hex}: above end seq {end_seq}"),
    )
}

// =====================================================================
// X1 -- ACCEPTANCE. "Inputs outside a batch" (ADR-0005 d11 l.949).
// Step 7 for batch 1 with the whole trust file (a `through=5` pin on
// the old fixture key, set by a key rotation that happens in batch 2,
// plus a trust-file `end=7` set after the batch), anchors above the
// end (`cp4`, `cp5`) and an anchored end at `cp3`. Every input above
// the end is `OutOfRange` (info), no `RevocationUnconfirmed` fires
// (the confirming checkpoint may lie above the end, ruling 13-V6-d7
// point 4), and `--strict` passes because `OutOfRange` is info.
// =====================================================================
#[test]
fn x1_inputs_outside_batch_anchored_end() {
    let c = build_chain();
    let seg = seal(&[&c.cp0, &c.e1, &c.cp2]);
    let cp3_line = line_without_lf(&c.cp3);
    let end_anchor = checkpoint_of(&c.cp3);
    let cp4 = signed_cp(4, c.cp3.hash(), &c.mmr3);
    let mmr4 = pushed(&c.mmr3, &cp4);
    let cp5 = signed_cp(5, cp4.hash(), &mmr4);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 5, [0x55; 32])
        .key(alt_signer().public_key())
        .end(7, [0x77; 32])
        .build()
        .unwrap();
    let report = Verifier::new(trust)
        .anchor(checkpoint_of(&cp4))
        .anchor(checkpoint_of(&cp5))
        .end_before(&cp3_line, Some(end_anchor))
        .unwrap()
        .verify_files(vec![seg.dir_path])
        .unwrap();
    let expected = vec![
        out_of_range_anchor(4, CP4_ABOVE_DIGEST, 3),
        out_of_range_pin(FIXTURE_KEY_HEX, 5, 3),
        out_of_range_anchor(5, CP5_ABOVE_DIGEST, 3),
        out_of_range_end(7, END_H7_HEX, 3),
    ];
    assert_findings(report.findings(), &expected, "X1");
    assert!(report.is_strict_valid(), "X1 report must pass --strict");
}

// =====================================================================
// X2 -- ACCEPTANCE. X1's layout with no end anchor: the end is
// unanchored, so every input above the end is `UnanchoredEnd`
// (error) instead of `OutOfRange`, plus one `UnanchoredEnd` at the
// end's own `seq` (ruling 13-V6-d4 point 5). `--strict` fails.
// =====================================================================
#[test]
fn x2_inputs_outside_batch_unanchored_end() {
    let c = build_chain();
    let seg = seal(&[&c.cp0, &c.e1, &c.cp2]);
    let cp3_line = line_without_lf(&c.cp3);
    let cp4 = signed_cp(4, c.cp3.hash(), &c.mmr3);
    let mmr4 = pushed(&c.mmr3, &cp4);
    let cp5 = signed_cp(5, cp4.hash(), &mmr4);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 5, [0x55; 32])
        .key(alt_signer().public_key())
        .end(7, [0x77; 32])
        .build()
        .unwrap();
    let report = Verifier::new(trust)
        .anchor(checkpoint_of(&cp4))
        .anchor(checkpoint_of(&cp5))
        .end_before(&cp3_line, None)
        .unwrap()
        .verify_files(vec![seg.dir_path])
        .unwrap();
    let expected = vec![
        unlocated(
            K::UnanchoredEnd,
            Some(3),
            "end_before seq 3: no end anchor".into(),
        ),
        unanchored_end_anchor(4, CP4_ABOVE_DIGEST, 3),
        unanchored_end_pin(FIXTURE_KEY_HEX, 5, 3),
        unanchored_end_anchor(5, CP5_ABOVE_DIGEST, 3),
        unanchored_end_end(7, END_H7_HEX, 3),
    ];
    assert_findings(report.findings(), &expected, "X2");
    assert!(!report.is_strict_valid(), "X2 report must fail --strict");
}

// =====================================================================
// X3 -- REGRESSION. The bounded check (ruling 13-V6-d7 point 4
// second sentence) still runs under `end_before`: an old-key
// checkpoint whose `seq` lies above its bound INSIDE the batch stays
// `UntrustedKey`. Here `cp2` at seq 2 is signed by the fixture key
// bounded `through=0`; the end record `cp3_alt` is signed by the alt
// key (also listed, trusted). `RevocationUnconfirmed` is not
// reported under `end_before`.
// =====================================================================
#[test]
fn x3_untrusted_key_above_bound_inside_batch_still_fires() {
    let c = build_chain();
    let cp3_alt = sign_as(&alt_signer(), 3, c.cp2.hash(), &c.mmr2);
    let seg = seal(&[&c.cp0, &c.e1, &c.cp2]);
    let cp3_line = line_without_lf(&cp3_alt);
    let end_anchor = checkpoint_of(&cp3_alt);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, c.cp0.hash())
        .key(alt_signer().public_key())
        .build()
        .unwrap();
    let report = Verifier::new(trust)
        .end_before(&cp3_line, Some(end_anchor))
        .unwrap()
        .verify_files(vec![seg.dir_path.clone()])
        .unwrap();
    let expected = vec![located(
        K::UntrustedKey,
        seg.path,
        3,
        2,
        format!("key {FIXTURE_KEY_HEX} bounded through seq 0"),
    )];
    assert_findings(report.findings(), &expected, "X3");
}

// =====================================================================
// X3b -- REGRESSION. Second UntrustedKey-inside-batch row pinning
// the bounded-check invariant (ruling 13-V6-d7 point 4 second
// sentence) on a second layout. The archive holds just `[cp0]`; the
// end record `cp1_fix` is a checkpoint at seq 1 signed by the
// fixture key bounded `through=0`, so `UntrustedKey` fires at seq 1
// (unlocated after the end-record strip, ruling 13-V6-d4 point 6).
// `UncoveredTail` names the uncovered record above the bound.
// =====================================================================
#[test]
fn x3b_untrusted_key_end_record_above_bound() {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let cp1_fix = signed_cp(1, cp0.hash(), &mmr0);
    let seg = seal(&[&cp0]);
    let cp1_line = line_without_lf(&cp1_fix);
    let end_anchor = checkpoint_of(&cp1_fix);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, cp0.hash())
        .build()
        .unwrap();
    let report = Verifier::new(trust)
        .end_before(&cp1_line, Some(end_anchor))
        .unwrap()
        .verify_files(vec![seg.dir_path.clone()])
        .unwrap();
    let expected = vec![
        unlocated(
            K::UntrustedKey,
            Some(1),
            format!("key {FIXTURE_KEY_HEX} bounded through seq 0"),
        ),
        unlocated(K::UncoveredTail, None, "records seq 1..=1".into()),
    ];
    assert_findings(report.findings(), &expected, "X3b");
}

// =====================================================================
// X4 -- ACCEPTANCE. A trust-file `end=<s>` with `s` strictly above
// `E` is set aside like the anchors and pins above the end (ruling
// 13-V6-d7 point 3): one `OutOfRange "end=<s>:<hash>: above end seq
// <E>"`, no `TrailEnded` from the `end=`, no grant (no tail
// exemption, no bound confirmation, no repair promotion). The pin
// at `b=0` is included so the "no grant" property is pinned on a
// bound the match would otherwise confirm; under `end_before` the
// confirmation is already skipped (ruling 13-V6-d7 point 4), so the
// grant is observationally identical to the set-aside case for the
// bound.
// =====================================================================
#[test]
fn x4_trust_file_end_above_e_is_set_aside() {
    let c = build_chain();
    let cp3_alt = sign_as(&alt_signer(), 3, c.cp2.hash(), &c.mmr2);
    let seg = seal(&[&c.cp0, &c.e1, &c.cp2]);
    let cp3_line = line_without_lf(&cp3_alt);
    let end_anchor = checkpoint_of(&cp3_alt);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 2, c.cp2.hash())
        .key(alt_signer().public_key())
        .end(7, [0x77; 32])
        .build()
        .unwrap();
    let report = Verifier::new(trust)
        .end_before(&cp3_line, Some(end_anchor))
        .unwrap()
        .verify_files(vec![seg.dir_path])
        .unwrap();
    let expected = vec![out_of_range_end(7, END_H7_HEX, 3)];
    assert_findings(report.findings(), &expected, "X4");
    assert!(report.is_strict_valid(), "X4 report must pass --strict");
}

// =====================================================================
// X5 -- REGRESSION. An anchor from another trail whose `seq` is
// above `E` is NOT set aside; it keeps its ordinary `AnchorMismatch
// … trail differs` (ruling 13-V6-d7 point 3 "An anchor from another
// trail is still `trail differs`"). "Trail differs" is checked
// before the position classifier and so takes precedence.
// =====================================================================
#[test]
fn x5_other_trail_anchor_above_end_keeps_trail_differs() {
    let c = build_chain();
    let seg = seal(&[&c.cp0, &c.e1, &c.cp2]);
    let cp3_line = line_without_lf(&c.cp3);
    let end_anchor = checkpoint_of(&c.cp3);
    // Foreign anchor at seq 5 on `OTHER_TRAIL`: above `E = 3` but on
    // a different trail, which wins.
    let foreign = signed_cp_other(5, [0xaa; 32], &foreign_mmr_one());
    let report = Verifier::new(trust_only_fixture())
        .anchor(checkpoint_of(&foreign))
        .end_before(&cp3_line, Some(end_anchor))
        .unwrap()
        .verify_files(vec![seg.dir_path])
        .unwrap();
    let expected = vec![unlocated(
        K::AnchorMismatch,
        Some(5),
        format!("anchor seq 5 hash {CP5_OTHER_DIGEST}: trail differs"),
    )];
    assert_findings(report.findings(), &expected, "X5");
    assert!(!report.is_valid(), "X5 report must carry the error");
}

// =====================================================================
// X5b -- REGRESSION. Second other-trail-anchor-above-end row: a
// foreign anchor at seq 4 (immediately above `E = 3`) also keeps
// its ordinary `AnchorMismatch … trail differs` (ruling 13-V6-d7
// point 3). Pairs with X5 to pin the "trail differs takes
// precedence over set-aside" invariant on two different seqs above
// the end.
// =====================================================================
#[test]
fn x5b_other_trail_anchor_just_above_end_keeps_trail_differs() {
    let c = build_chain();
    let seg = seal(&[&c.cp0, &c.e1, &c.cp2]);
    let cp3_line = line_without_lf(&c.cp3);
    let end_anchor = checkpoint_of(&c.cp3);
    let foreign = signed_cp_other(4, [0xaa; 32], &foreign_mmr_one());
    let report = Verifier::new(trust_only_fixture())
        .anchor(checkpoint_of(&foreign))
        .end_before(&cp3_line, Some(end_anchor))
        .unwrap()
        .verify_files(vec![seg.dir_path])
        .unwrap();
    let expected = vec![unlocated(
        K::AnchorMismatch,
        Some(4),
        format!("anchor seq 4 hash {CP4_OTHER_DIGEST}: trail differs"),
    )];
    assert_findings(report.findings(), &expected, "X5b");
    assert!(!report.is_valid(), "X5b report must carry the error");
}

// =====================================================================
// X6 -- REGRESSION. A `through=` pin at `b = E` and an anchor at
// `E` are both in range and are checked as usual (ruling 13-V6-d7
// point 2: "above the end" uses `<`, not `<=`). Here `E = 3` (no
// resume), the end record is `cp3`, the pin's bound is
// `through=3:cp3.hash` on the fixture key (passes: record at seq 3
// is `cp3`, hash matches, checkpoint, `key_id = fixture`), and the
// anchor at seq 3 is `cp3` itself (matches).
// `RevocationUnconfirmed` is skipped by ruling 13-V6-d7 point 4.
// =====================================================================
#[test]
fn x6_pin_and_anchor_at_b_equals_e_are_in_range() {
    let c = build_chain();
    let seg = seal(&[&c.cp0, &c.e1, &c.cp2]);
    let cp3_line = line_without_lf(&c.cp3);
    let end_anchor = checkpoint_of(&c.cp3);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 3, c.cp3.hash())
        .build()
        .unwrap();
    let report = Verifier::new(trust)
        .anchor(checkpoint_of(&c.cp3))
        .end_before(&cp3_line, Some(end_anchor))
        .unwrap()
        .verify_files(vec![seg.dir_path])
        .unwrap();
    let expected: Vec<Finding> = Vec::new();
    assert_findings(report.findings(), &expected, "X6");
    assert!(report.is_strict_valid(), "X6 report must pass --strict");
}

// =====================================================================
// X7 -- ACCEPTANCE. End record with a resume line: `E` is the
// resume line's `seq`, not the checkpoint's (ruling 13-V6-d7
// point 1). Here the end record is `cp2 + resume(seq=3, prev=
// cp2.hash, head=1:e1.hash)`, so `E = 3`. A pin at `b = 3 = E` is
// in range and runs the ordinary pin check: the record at seq 3 is
// the resume entry, not a checkpoint, so one `RevocationMismatch
// "record at seq 3 is not a checkpoint"` fires (unlocated after the
// end-record strip, ruling 13-V6-d4 point 6). An anchor at seq 4
// (> `E`) is above the end and anchored, so it is `OutOfRange`.
// =====================================================================
#[test]
fn x7_resume_line_sets_e_to_resume_seq() {
    let c = build_chain();
    let seg = seal(&[&c.cp0, &c.e1]);
    let resume = resume_entry(3, c.cp2.hash(), 1, c.e1.hash());
    let end_record = format!("{}\n{}", line_without_lf(&c.cp2), line_without_lf(&resume));
    let end_anchor = checkpoint_of(&c.cp2);
    let cp4 = signed_cp(4, c.cp3.hash(), &c.mmr3);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 3, resume.hash())
        .build()
        .unwrap();
    let report = Verifier::new(trust)
        .anchor(checkpoint_of(&cp4))
        .end_before(&end_record, Some(end_anchor))
        .unwrap()
        .verify_files(vec![seg.dir_path])
        .unwrap();
    let expected = vec![
        unlocated(
            K::Resumed,
            Some(3),
            format!(
                "operator=op reason=a head=1:{E1_HASH_FOR_X7} gap=none lost_records=0 structural=valid",
            ),
        ),
        unlocated(
            K::RevocationMismatch,
            Some(3),
            format!(
                "key {FIXTURE_KEY_HEX} through=3:{}: record at seq 3 is not a checkpoint",
                digest_string(&resume.hash()),
            ),
        ),
        out_of_range_anchor(4, CP4_ABOVE_DIGEST, 3),
        unlocated(K::UncoveredTail, None, "records seq 3..=3".into()),
    ];
    assert_findings(report.findings(), &expected, "X7");
    assert!(
        !report.is_strict_valid(),
        "X7 must fail --strict (Resumed warning)"
    );
}

/// `e1.hash()` as it appears in the X7 resume detail; pinned here
/// so the literal row is self-contained.
const E1_HASH_FOR_X7: &str =
    "blake3:c121282b5135adfe7a17142cae6bfc4c9040c4aed26d74bddc923b8dafcdb6e8";

// =====================================================================
// X8 -- REGRESSION. No `end_before`: the same trust file and
// anchors as X1 produce ordinary findings and
// `RevocationUnconfirmed` is reported where due (ruling 13-V6-d7
// point 5 "No `end_before`, nothing is above the end").
// =====================================================================
#[test]
fn x8_no_end_before_keeps_ordinary_findings() {
    let c = build_chain();
    let seg = seal(&[&c.cp0, &c.e1, &c.cp2]);
    let cp4 = signed_cp(4, c.cp3.hash(), &c.mmr3);
    let mmr4 = pushed(&c.mmr3, &cp4);
    let cp5 = signed_cp(5, cp4.hash(), &mmr4);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 5, [0x55; 32])
        .key(alt_signer().public_key())
        .end(7, [0x77; 32])
        .build()
        .unwrap();
    let report = Verifier::new(trust)
        .anchor(checkpoint_of(&cp4))
        .anchor(checkpoint_of(&cp5))
        .verify_files(vec![seg.dir_path.clone()])
        .unwrap();
    let expected = vec![
        unlocated(
            K::AnchorMismatch,
            Some(4),
            format!("anchor seq 4 hash {CP4_ABOVE_DIGEST}: no record"),
        ),
        unlocated(
            K::AnchorMismatch,
            Some(5),
            format!("anchor seq 5 hash {CP5_ABOVE_DIGEST}: no record"),
        ),
        unlocated(
            K::RevocationMismatch,
            Some(5),
            format!("key {FIXTURE_KEY_HEX} through=5:{PIN_H5_HEX}: no record at seq 5"),
        ),
        unlocated(
            K::RevocationUnconfirmed,
            Some(5),
            format!(
                "key {FIXTURE_KEY_HEX} through=5: no trusted checkpoint by another key above the bound"
            ),
        ),
        unlocated(
            K::TrailEnded,
            Some(7),
            format!("end=7:{END_H7_HEX}: no record at seq 7"),
        ),
    ];
    assert_findings(report.findings(), &expected, "X8");
}

// =====================================================================
// X8b -- REGRESSION. Second no-`end_before` row with a bound that
// is not confirmed, so `RevocationUnconfirmed` fires. The archive
// holds `[cp0, e1, cp2]` where the fixture key is bounded
// `through=0`; nothing above the bound is signed by another key, so
// the bound stays unconfirmed. Pairs with X8 to pin the
// `RevocationUnconfirmed`-reported-without-`end_before` invariant on
// two independent layouts.
// =====================================================================
#[test]
fn x8b_no_end_before_bound_unconfirmed() {
    let c = build_chain();
    let seg = seal(&[&c.cp0, &c.e1, &c.cp2]);
    let trust = TrustPolicy::builder()
        .trail(TRAIL)
        .key_through(fixture_pubkey(), 0, c.cp0.hash())
        .build()
        .unwrap();
    let report = Verifier::new(trust)
        .verify_files(vec![seg.dir_path.clone()])
        .unwrap();
    let expected = vec![
        located(
            K::RevocationUnconfirmed,
            seg.path.clone(),
            1,
            0,
            format!(
                "key {FIXTURE_KEY_HEX} through=0: no trusted checkpoint by another key above the bound"
            ),
        ),
        located(
            K::UntrustedKey,
            seg.path.clone(),
            3,
            2,
            format!("key {FIXTURE_KEY_HEX} bounded through seq 0"),
        ),
        unlocated(K::UncoveredTail, None, "records seq 1..=2".into()),
    ];
    assert_findings(report.findings(), &expected, "X8b");
}

// =====================================================================
// X9 -- ACCEPTANCE. An end anchor that differs from the record
// fires the ordinary `AnchorMismatch "end record differs from end
// anchor"` at `E`, and the end is NOT anchored for the above-end
// set-aside (ruling 13-V6-d4 point 5; ruling 13-V6-d7 point 2):
// inputs above `E` give `UnanchoredEnd`, not `OutOfRange`.
// =====================================================================
#[test]
fn x9_end_anchor_differs_from_record_inputs_above_are_unanchored() {
    let c = build_chain();
    let seg = seal(&[&c.cp0, &c.e1, &c.cp2]);
    let cp3_line = line_without_lf(&c.cp3);
    // The end anchor is a checkpoint at the same `seq` but signed
    // by the alt key, so its line byte-differs from `cp3`'s and
    // `end record differs from end anchor` fires. Also, `cp3_alt`
    // joins the anchors and is checked by the ordinary anchor rule
    // at seq 3 against the record there (the fixture-signed `cp3`),
    // emitting one more `AnchorMismatch "hash differs"`.
    let cp3_alt = sign_as(&alt_signer(), 3, c.cp2.hash(), &c.mmr2);
    let different_anchor = checkpoint_of(&cp3_alt);
    let cp4 = signed_cp(4, c.cp3.hash(), &c.mmr3);
    let report = Verifier::new(
        TrustPolicy::builder()
            .trail(TRAIL)
            .key(fixture_pubkey())
            .key(alt_signer().public_key())
            .build()
            .unwrap(),
    )
    .anchor(checkpoint_of(&cp4))
    .end_before(&cp3_line, Some(different_anchor))
    .unwrap()
    .verify_files(vec![seg.dir_path.clone()])
    .unwrap();
    let expected = vec![
        unlocated(
            K::AnchorMismatch,
            Some(3),
            format!(
                "anchor seq 3 hash {CP3_ALT_DIGEST}: hash differs (record {CP3_HONEST_DIGEST})"
            ),
        ),
        unlocated(
            K::AnchorMismatch,
            Some(3),
            "end record differs from end anchor".into(),
        ),
        unanchored_end_anchor(4, CP4_ABOVE_DIGEST, 3),
    ];
    assert_findings(report.findings(), &expected, "X9");
    assert!(!report.is_strict_valid(), "X9 report must fail --strict");
}

// =====================================================================
// X10 -- ACCEPTANCE. `Verifier::start_from` AND
// `Verifier::end_before` set in one call (batch 2 of the archiving
// schedule). Inputs below the start and inputs above the end are
// each classified correctly in one report (rulings 13-V6-d3 and
// 13-V6-d7). Here `start = cp2`, end record `cp3 + resume(seq=4)`
// so `E = 4`, archive holds `[cp2]` (batch 2 after prefix was
// archived in batch 1). An anchor at seq 1 (< start) is below the
// start and the start is anchored (`cp2` is also passed as an
// anchor), so it is `OutOfRange "below start seq 2"`. An anchor at
// seq 5 (> E = 4) is above the end and the end is anchored, so it
// is `OutOfRange "above end seq 4"`.
// =====================================================================
#[test]
fn x10_start_from_and_end_before_classify_both_sides() {
    let c = build_chain();
    let seg = seal(&[&c.cp2]);
    let resume = resume_entry(4, c.cp3.hash(), 2, c.cp2.hash());
    let end_record = format!("{}\n{}", line_without_lf(&c.cp3), line_without_lf(&resume));
    let end_anchor = checkpoint_of(&c.cp3);
    let mmr0 = seeded(&c.cp0);
    let cp1_from_cp0 = signed_cp(1, c.cp0.hash(), &mmr0);
    let cp4 = signed_cp(4, c.cp3.hash(), &c.mmr3);
    let mmr4 = pushed(&c.mmr3, &cp4);
    let cp5 = signed_cp(5, cp4.hash(), &mmr4);
    let report = Verifier::new(trust_only_fixture())
        .anchor(checkpoint_of(&cp1_from_cp0))
        .anchor(checkpoint_of(&c.cp2))
        .anchor(checkpoint_of(&cp5))
        .start_from(checkpoint_of(&c.cp2))
        .end_before(&end_record, Some(end_anchor))
        .unwrap()
        .verify_files(vec![seg.dir_path])
        .unwrap();
    let expected = vec![
        unlocated(
            K::OutOfRange,
            Some(1),
            format!("anchor seq 1 hash {CP1_FROM_CP0_DIGEST}: below start seq 2"),
        ),
        unlocated(
            K::Resumed,
            Some(4),
            format!(
                "operator=op reason=a head=2:{CP2_HONEST_DIGEST} gap=none lost_records=0 structural=valid"
            ),
        ),
        out_of_range_anchor(5, CP5_ABOVE_DIGEST, 4),
        unlocated(K::UncoveredTail, None, "records seq 4..=4".into()),
    ];
    assert_findings(report.findings(), &expected, "X10");
    assert!(
        !report.is_strict_valid(),
        "X10 must fail --strict (Resumed warning)"
    );
}

// =====================================================================
// Pins every literal hex constant in this module to the fixture it
// names so a hash change anywhere in `runs_v4a_fixtures` or in the
// code under test never slips through the literal-row assertions.
// =====================================================================
#[test]
fn fixture_hashes_match_literals() {
    let c = build_chain();
    assert_eq!(hex(&TRAIL), TRAIL_HEX);
    assert_eq!(hex(&OTHER_TRAIL), OTHER_TRAIL_HEX);
    assert_eq!(hex(&fixture_pubkey()), FIXTURE_KEY_HEX);
    assert_eq!(hex(&alt_signer().public_key()), ALT_KEY_HEX);
    assert_eq!(digest_string(&c.cp0.hash()), CP0_HONEST_DIGEST);
    assert_eq!(digest_string(&c.cp2.hash()), CP2_HONEST_DIGEST);
    assert_eq!(digest_string(&c.cp3.hash()), CP3_HONEST_DIGEST);
    let cp4 = signed_cp(4, c.cp3.hash(), &c.mmr3);
    assert_eq!(digest_string(&cp4.hash()), CP4_ABOVE_DIGEST);
    let mmr4 = pushed(&c.mmr3, &cp4);
    let cp5 = signed_cp(5, cp4.hash(), &mmr4);
    assert_eq!(digest_string(&cp5.hash()), CP5_ABOVE_DIGEST);
    let foreign = signed_cp_other(5, [0xaa; 32], &foreign_mmr_one());
    assert_eq!(digest_string(&foreign.hash()), CP5_OTHER_DIGEST);
    let foreign4 = signed_cp_other(4, [0xaa; 32], &foreign_mmr_one());
    assert_eq!(digest_string(&foreign4.hash()), CP4_OTHER_DIGEST);
    let mmr0 = seeded(&c.cp0);
    let cp1_from_cp0 = signed_cp(1, c.cp0.hash(), &mmr0);
    assert_eq!(digest_string(&cp1_from_cp0.hash()), CP1_FROM_CP0_DIGEST);
    let cp3_alt = sign_as(&alt_signer(), 3, c.cp2.hash(), &c.mmr2);
    assert_eq!(digest_string(&cp3_alt.hash()), CP3_ALT_DIGEST);
    assert_eq!(digest_string(&c.e1.hash()), E1_HASH_FOR_X7);
    assert_eq!(digest_string(&[0x55; 32]), PIN_H5_HEX);
    assert_eq!(digest_string(&[0x77; 32]), END_H7_HEX);
}
