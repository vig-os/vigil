//! Rows for the chain rule applied to `Verifier::end_before`
//! (ADR-0005 decision 2 step 6, decision 11 `accept-run` item 2,
//! the prefix-deletion and tail-cut bullets; ruling 13-V6-d6;
//! #13). Every row asserts the full sorted `Vec<Finding>` through
//! [`assert_findings`]; expected lists are written in the engine's
//! final sort order (`(seq.is_none(), seq, file, line, kind_debug)`),
//! so no per-row sort runs here. Hashes, roots and digests that
//! appear in a detail string are `const` hex literals pinned by
//! [`fixture_hashes_match_literals`] against the fixture builders.
//! Labels in each row's doc comment (ACCEPTANCE / REGRESSION)
//! follow the repo-wide row standard.
//!
//! Fixture style: the writer stamps every record with a wall-clock
//! time stamp through a time hook that is `pub(super)` inside
//! `sink` and is not reachable from this module, so the writer's
//! record hashes drift per run and these rows are hand-built. They
//! use the fixture `TRAIL` and `signed_cp` / `entry_rec`, which
//! construct a record through the same `Record::checkpoint` /
//! `CheckpointFields` call the writer's `sink::signed` uses
//! (`sink.rs` ~765..=781) and the same fixture signer, so the
//! resulting records are byte-for-byte what the writer would emit
//! at the fixture clock.

use crate::audit::{
    Checkpoint, Entry, FindingKind as K, Mmr, Record, TrustPolicy, digest_string, hex,
    runs_v4a_fixtures::{
        TRAIL, Temp, context, entry_rec, fixture_pubkey, line_bytes, pushed, put_segment, seeded,
        segment_path, signed_cp, write_bytes,
    },
    verify::{Finding, Verifier},
};
use std::path::PathBuf;

use super::end_before_tests::{
    CP0_HONEST_DIGEST, CP2_HONEST_DIGEST, E1_HONEST_DIGEST, E3_HONEST_DIGEST,
    FORGED_E2_ALT_DIGEST as E2_ALT_DIGEST, FORGED_E2_DIGEST as E2_HONEST_DIGEST,
};

// =====================================================================
// Shared literal hex constants. Verified by `fixture_hashes_match_literals`
// so a fixture-level drift surfaces here instead of across many rows.
// =====================================================================

/// Record hash of `signed_cp(4, e3.hash(), &fold([cp0, e1, cp2, e3]))`
/// on the hand-built L1/L10 chain (`build_chain`): the close
/// checkpoint reused as the end record for L1.
const CP4_L1_DIGEST: &str =
    "blake3:3800e98faa1a668c094936a2489dd8d0c1db9ed5dd3c337dd1de87e030b784cd";
/// Record hash of `signed_cp(3, e2.hash(), &fold([cp0, e1, e2]))` on
/// the hand-built L5/L3 chain (`build_chain_l5`): the end record for
/// L3, L3b, L5, L6, L7, L7b, L8, L12 and L13.
const CP3_L5_DIGEST: &str =
    "blake3:dda83f7bbaaf877076831dd97e6563148bf337d350bc58cf8bc6e8802eed2f66";
/// Record hash of `Record::new(context(2, e1.hash()),
/// Entry("actor","change","alt2"))`, the second alternate seq-2
/// payload used by L3b as an independent broken-link input from L3.
const E2_ALT2_DIGEST: &str =
    "blake3:2aea1ad4c7f8344b11b73eb08a0407139ac45fcd985f24d62628aa8dd01046d3";
/// Record hash of `Record::new(context(1, cp0.hash()),
/// Entry("actor","change","alt"))`, the shipped-only alternate
/// seq-1 payload used by L5b.
const E1_ALT_DIGEST: &str =
    "blake3:125619e12e657407511645cac8c311f0d32ac0f97377eb1e45f9ca0217516a1e";
/// Hex of `Record::genesis(&TRAIL)`, the digest the chain loop
/// seeds `expected` with at seq 0 (`signed_cp(0, …)`). Appears in
/// L11's `ChainBroken` detail.
const GENESIS_TRAIL_DIGEST: &str =
    "blake3:a03c7c40313d5ab5cf449ba187545083161360e5ed3e41e6f9254c3b4c5efaab";
/// Hex of the raw bytes `[1; 32]`: L11's forged `previous` for the
/// seq-0 end checkpoint, appearing in its `ChainBroken` detail.
const ONES_DIGEST: &str = "blake3:0101010101010101010101010101010101010101010101010101010101010101";
/// Hex of the raw bytes `[9; 32]`: L13's forged `previous` for the
/// seq-3 end checkpoint, appearing in its `ChainBroken` detail.
const NINES_DIGEST: &str =
    "blake3:0909090909090909090909090909090909090909090909090909090909090909";
/// MMR root `blake3:` of a size-1 fold over `[cp0]` on the hand-built
/// chain (`seeded(cp0)`). Appears in L7's and L12's `MmrMismatch`
/// details ("expected size 1 root ...").
const MMR_SIZE1_CP0_ROOT: &str =
    "blake3:e3a0ca91e171d05a5877b1352376e6e54fc54312c7d9295d4e7643bdba23f723";
/// MMR root of a size-2 fold over `[cp0, e1]` on the hand-built
/// chain (`seeded(cp0).push(e1)`). Appears in L7b's `MmrMismatch`.
const MMR_SIZE2_CP0_E1_ROOT: &str =
    "blake3:0233f700d6b926ff4f4b5acb5e25bae37975cd23a97ebe25d7c096fb281b12a2";
/// MMR root of a size-3 fold over `[cp0, e1, cp2]` on the hand-built
/// L1/L10 chain. Appears in L1's `MmrMismatch` ("expected size 3
/// root ..." for the archive side).
const MMR_SIZE3_CP0_E1_CP2_ROOT: &str =
    "blake3:3e3070dd2dba8c267662fb89cbeb5b88848d5146895bc4bb1258bf87aa510160";
/// MMR root of a size-4 fold over `[cp0, e1, cp2, e3]` on the
/// hand-built L1/L10 chain: the root `cp4` declares. Appears in
/// L1's `MmrMismatch` ("found size 4 root ...").
const MMR_SIZE4_CP4_DECL_ROOT: &str =
    "blake3:a0500d3db204068be41c921d0141b63695101542cd99195fd796cc63695c2c82";
/// MMR root of a size-3 fold over `[cp0, e1, e2_alt]` on the L3
/// scenario. Appears in L3's `MmrMismatch` ("expected size 3 root
/// ..." for the archive side with `e2_alt` at seq 2).
const MMR_SIZE3_L3_ARCHIVE_ROOT: &str =
    "blake3:cc00f3f08e70a468831321f04c3bed4ce6a133a19ecc1fce20d56725fd045285";
/// MMR root of a size-3 fold over `[cp0, e1, e2_alt2]` on the L3b
/// scenario (a second independent seq-2 payload).
const MMR_SIZE3_L3B_ARCHIVE_ROOT: &str =
    "blake3:9d2cc781b7cc611dc6bf301c634e0c96a55a1da29f9b68e47ea670f31918e6c6";
/// Record hash of `signed_cp(1, cp0.hash(), &seeded(&cp0))` on the
/// hand-built prefix-deletion chain (`build_prefix_deletion_chain`):
/// the opening of S1.
const CP1_PD_DIGEST: &str =
    "blake3:8a7785644d05dbdbcd8b128eb1f17aca5206eca1b9448483a49e5cdfb7ed4c42";
/// Record hash of `signed_cp(2, cp1.hash(), &pushed(&seeded(&cp0),
/// &cp1))` on the prefix-deletion chain: the opening of S2 and
/// the highest archive record for the step-7 chain compare.
const CP2_PD_DIGEST: &str =
    "blake3:5994ebc0656cdc5b1fbe0b37a163b3686b0e571d7b16c84737938149694f25b5";
/// Record hash of `signed_cp(3, cp2_pd.hash(), fold {cp0,cp1,cp2})`
/// on the prefix-deletion chain: the opening of the deleted S3.
const CP3_PD_DIGEST: &str =
    "blake3:76bcfbe5932c390604c73e365f19a517100860f01ccb38a9b46a16d9083d26d7";
/// Record hash of `signed_cp(4, cp3_pd.hash(), fold
/// {cp0,cp1,cp2,cp3})` on the prefix-deletion chain: the opening
/// of the deleted S4, named in cp5's `previous`.
const CP4_PD_DIGEST: &str =
    "blake3:83753b3c20f7280bf6b5c2025b5ec251b2bd1948f0b92ea216b69a041eff55c6";
/// Record hash of `signed_cp(5, cp4_pd.hash(), fold
/// {cp0,cp1,cp2,cp3,cp4})` on the prefix-deletion chain: the
/// opening of S5, the kept sealed segment in the live directory
/// and the end record for forms (a)/(b) plus the start anchor
/// for form (c).
const CP5_PD_DIGEST: &str =
    "blake3:ab2548e8b8def5ae2058e302b480792a212145b1e5ff5a5227ab88604638a2a1";
/// MMR root of the size-3 fold over `[cp0, cp1, cp2]` on the
/// prefix-deletion chain: the archive fold seen by step 7.
/// Appears in L4 step 7's `MmrMismatch` ("expected size 3
/// root ...").
const MMR_PD_SIZE3_ARCHIVE_ROOT: &str =
    "blake3:b4897d1be713bbb840c652cb7037e92604b8df6267467d8bf7a406c236c45a03";
/// MMR root of the size-5 fold over `[cp0, cp1, cp2, cp3, cp4]`
/// that cp5 declares. Appears in L4 step 7's `MmrMismatch`
/// ("found size 5 root ...").
const MMR_PD_SIZE5_CP5_DECL_ROOT: &str =
    "blake3:4d550db8f3135847465ce01f949ad2b7607d6cc4c08fe5207cd45043cc9efc60";
/// MMR root of the size-4 fold `{cp0, cp1, cp2, cp5}` that form
/// (b) sees after pushing `cp5` on top of the archive's fold.
/// Appears in L4 step 6's second `MmrMismatch` ("expected size
/// 4 root ...").
const MMR_PD_SIZE4_STEP6_AT_CP6_ROOT: &str =
    "blake3:8d59d646d628261a6ea589ec43436d67df9a31f5a31b1801227a4d8153d84fee";
/// MMR root of the size-6 fold `{cp0, cp1, cp2, cp3, cp4, cp5}`
/// that cp6 declares. Appears in L4 step 6's second
/// `MmrMismatch` ("found size 6 root ...").
const MMR_PD_SIZE6_CP6_DECL_ROOT: &str =
    "blake3:6d898b44f005a4db8cb0401f42afa3a40e74d281b476d1123290a125de458ffa";
/// MMR root of a size-3 fold over `[cp0, e1, e2]` on the hand-built
/// L5/L3 chain: the root `cp3` declares. Appears in L3's, L3b's,
/// L7's, L7b's and L12's `MmrMismatch` ("found size 3 root ..." for
/// the cp3 side).
const MMR_SIZE3_CP3_DECL_ROOT: &str =
    "blake3:5294780ba182581c89bbdbdd9d46f0094fde92d0532dbb1f281225ca1ba7345e";
/// Digest of the 4-byte `b"frag"` trailing fragment in L10's and
/// L10b's archive segment (pure `blake3` of the fragment bytes).
/// Deterministic from the literal bytes.
const FRAG_DIGEST: &str = "blake3:daa66297760aa0b9be67217331423472d1a024221fa3ca757297891a741866ff";
/// Hex-only form of [`FRAG_DIGEST`], used with `hex_to_bytes_32`
/// to build the trailing `TornWrite`'s internal `with_pin` input.
const FRAG_DIGEST_HEX: &str = "daa66297760aa0b9be67217331423472d1a024221fa3ca757297891a741866ff";
/// Hex of the run digest emitted on the L10b `SegmentStructure`
/// finding at the archive segment -- the classifier's accumulated
/// digest over the sealed archive plus the trailing fragment, with
/// the resume opening disabling the "no crash outcome" short-cut
/// (ruling 13-V6-d5 point 5). Deterministic from the fixture
/// records and the literal `b"frag"` suffix.
const L10B_SEG_STRUCT_RUN_HEX: &str =
    "eac147f5f101c01e66313a5f3350eefca8204361bd84ba373ebd3df464a64f68";

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

/// The hand-built L1/L10 chain: `cp0(0), e1(1), cp2(2), e3(3),
/// cp4(4)` at the fixture `TRAIL` and fixture signer. Each record
/// is produced through `signed_cp` (checkpoints) and `entry_rec`
/// (entries), which call `Record::checkpoint` /
/// `CheckpointFields::new` exactly as the writer's `sink::signed`
/// does (`sink.rs` ~765..=781) at the fixture clock, so each
/// record hash is a literal pinned in
/// [`fixture_hashes_match_literals`].
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

/// The hand-built L5/L3 chain: `cp0(0), e1(1), e2(2), cp3(3)` at the
/// fixture `TRAIL` and fixture signer. Reused by L3, L3b, L5, L6,
/// L7, L7b, L8, L12, L13 and L14 (`cp3` as the end record over
/// various archive shapes). Constructed through the same helpers as
/// [`build_chain`] so the writer's record construction is mirrored
/// exactly (`sink.rs` ~765..=781) at the fixture clock.
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

// =====================================================================
// L1 -- ACCEPTANCE. "Tail cut" bullet (ADR-0005 l.944): the
// archive's last segment is cut back to a periodic checkpoint, so
// its later records and its closing checkpoint are deleted. The
// archive is `[cp0, e1, cp2]`; the end record is `cp4`. The chain
// rule at `e = 4` compares with the record at the highest `seq`
// below (`cp2`), and `cp4.previous = e3.hash` mismatches, so one
// `ChainBroken` fires at `e`, one `MmrMismatch` at `e` (archive
// fold size 3 against `cp4`'s declared size 4), and one `SeqGap`
// for the cut range `3..=3`, each unlocated (ruling 13-V6-d4 point
// 6). Hand-built with the same `Record::checkpoint` /
// `CheckpointFields` construction as the writer (`sink.rs`
// ~765..=781) so the detail hashes stay literal.
// =====================================================================
#[test]
fn l1_tail_cut_has_chain_broken_and_seq_gap() {
    let c = build_chain();
    let d = Temp::new();
    put_segment(&d.0, 0, &[&c.cp0, &c.e1, &c.cp2], &[]);
    let cp4_line = line_without_lf(&c.cp4);
    let anchor = checkpoint_of(&c.cp4);
    let report = verifier()
        .end_before(&cp4_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let expected = vec![
        unlocated(
            K::ChainBroken,
            Some(4),
            format!("expected previous {CP2_HONEST_DIGEST}, found {E3_HONEST_DIGEST}"),
        ),
        unlocated(
            K::MmrMismatch,
            Some(4),
            format!(
                "expected size 3 root {MMR_SIZE3_CP0_E1_CP2_ROOT}, found size 4 root {MMR_SIZE4_CP4_DECL_ROOT}",
            ),
        ),
        unlocated(K::SeqGap, Some(4), "missing seq 3..=3".into()),
    ];
    assert_findings(report.findings(), &expected, "L1");
    assert!(!report.is_valid(), "L1 exit 1");
}

// =====================================================================
// L2 -- REGRESSION. The "Tail cut" bullet's "limit visible"
// assertion (ADR-0005 l.944): `verify <archive>` alone cannot see
// that the tail was cut back, so the archive's own finding list is
// empty. Pairs with L1 so a drift in the shared chain fixture
// fails both the limit-visible assertion and the end-link finding.
// =====================================================================
#[test]
fn l2_tail_cut_without_end_before_is_clean() {
    let c = build_chain();
    let d = Temp::new();
    put_segment(&d.0, 0, &[&c.cp0, &c.e1, &c.cp2], &[]);
    let report = verifier().verify_files(vec![d.0.clone()]).unwrap();
    let expected: Vec<Finding> = Vec::new();
    assert_findings(report.findings(), &expected, "L2");
    assert!(report.is_valid(), "L2 is valid");
}

// =====================================================================
// L3 -- REGRESSION. The last record is rewritten at the same `seq`
// without a jump (`e = p + 1`): a forged `e2_alt` sits in the
// archive at seq 2 while the end checkpoint `cp3` links to the
// honest `e2`. The chain rule at `e` compares with the record at
// the highest `seq` below (ruling 13-V6-d6 point 1), so exactly one
// `ChainBroken` fires at `e`, unlocated. `MmrMismatch` fires at
// `e` because the archive fold through `e2_alt` differs from
// `cp3`'s declared fold through the honest `e2`. Hand-built
// forged input.
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
                "expected size 3 root {MMR_SIZE3_L3_ARCHIVE_ROOT}, found size 3 root {MMR_SIZE3_CP3_DECL_ROOT}",
            ),
        ),
    ];
    assert_findings(report.findings(), &expected, "L3");
}

// =====================================================================
// L3b -- REGRESSION. Second rewritten-last-record row with a
// different alternate payload at the same `seq` (`e2_alt2` from
// `Entry("actor","change","alt2")`), so an independent broken-link
// input exercises the chain rule at `e` on a byte-different forgery
// from L3. Hand-built forged input.
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
            format!("expected previous {E2_ALT2_DIGEST}, found {E2_HONEST_DIGEST}"),
        ),
        unlocated(
            K::MmrMismatch,
            Some(3),
            format!(
                "expected size 3 root {MMR_SIZE3_L3B_ARCHIVE_ROOT}, found size 3 root {MMR_SIZE3_CP3_DECL_ROOT}",
            ),
        ),
    ];
    assert_findings(report.findings(), &expected, "L3b");
}

// =====================================================================
// L4 -- ACCEPTANCE. The prefix-deletion layout per ADR-0005
// l.942..=943: six sealed segments `S0..=S5`, each starting with
// its own opening checkpoint; `S0..=S4` were archived and `S5`
// kept, then `S3` and `S4` were deleted from the archive. `S5`
// lives in the live directory as a sealed segment with the live
// file `audit.jsonl` after it. The start, for form (c), is `S5`'s
// opening checkpoint. Three forms exercise the same layout from
// different verify-side angles. Hand-built because each form pins
// literal hashes of the records at the deletion boundary.
// =====================================================================

/// The hand-built prefix-deletion chain: six checkpoints
/// `cp0..=cp5`, each at the fixture `TRAIL` and fixture signer,
/// linked `cpN.previous = cp(N-1).hash` and declaring the running
/// MMR fold over the records at `seq < N`. Constructed through
/// the same `signed_cp` helper as the other chains in this module
/// so each record goes through the writer's `Record::checkpoint`
/// / `CheckpointFields` call (`sink.rs` ~765..=781) at the
/// fixture clock.
struct PrefixDelChain {
    cp0: Record,
    cp1: Record,
    cp2: Record,
    cp3: Record,
    cp4: Record,
    cp5: Record,
    /// MMR fold `{cp0, cp1, cp2}` -- the fold the archive produces
    /// after sealing `S0..=S2`, used for step 7's `MmrMismatch`.
    archive_mmr: Mmr,
    /// MMR fold `{cp0, cp1, cp2, cp3, cp4}` that `cp5` declares.
    cp5_declared_mmr: Mmr,
}
fn build_prefix_deletion_chain() -> PrefixDelChain {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr_after_cp0 = seeded(&cp0);
    let cp1 = signed_cp(1, cp0.hash(), &mmr_after_cp0);
    let mmr_after_cp1 = pushed(&mmr_after_cp0, &cp1);
    let cp2 = signed_cp(2, cp1.hash(), &mmr_after_cp1);
    let mmr_after_cp2 = pushed(&mmr_after_cp1, &cp2);
    let cp3 = signed_cp(3, cp2.hash(), &mmr_after_cp2);
    let mmr_after_cp3 = pushed(&mmr_after_cp2, &cp3);
    let cp4 = signed_cp(4, cp3.hash(), &mmr_after_cp3);
    let mmr_after_cp4 = pushed(&mmr_after_cp3, &cp4);
    let cp5 = signed_cp(5, cp4.hash(), &mmr_after_cp4);
    PrefixDelChain {
        cp0,
        cp1,
        cp2,
        cp3,
        cp4,
        cp5,
        archive_mmr: mmr_after_cp2,
        cp5_declared_mmr: mmr_after_cp4,
    }
}

/// Hand-built prefix-deletion scenario at the fixture `TRAIL`.
///
/// The archive holds three sealed segments after `S3` and `S4`
/// were deleted: `S0 = [cp0]`, `S1 = [cp1]`, `S2 = [cp2]`, at
/// writer-style segment ids 0, 1 and 2. The live directory holds
/// the kept sealed segment `S5 = [cp5]` at segment id 5 (its
/// writer-style name keeps `seq` and segment id aligned, so it
/// sorts after the archive's segments) and the writer's live file
/// `audit.jsonl` after it, which starts the next batch with a
/// fresh opening checkpoint `cp6 = signed_cp(6, cp5.hash(), fold
/// through cp5)` so the writer's directory shape is complete.
/// `cp5`'s opening checkpoint is the end record for forms (a)
/// and (b) and the start anchor for form (c).
struct PrefixDelScenario {
    _archive_tmp: Temp,
    _live_tmp: Temp,
    archive_dir: PathBuf,
    live_dir: PathBuf,
    /// The published path of the live directory's sealed segment
    /// `S5` -- the file verify_files locates `ChainBroken` /
    /// `SeqGap` at in form (b).
    s5_segment_path: PathBuf,
    /// The published path of the live file (`audit.jsonl`) that
    /// follows `S5`, where form (b) locates `MmrMismatch` at
    /// the next batch's opening `cp6`.
    live_file_path: PathBuf,
    /// The opening of `S5`, at seq 5: the end record for (a)/(b)
    /// and the start anchor for (c).
    s5_opening: Record,
}
fn build_prefix_deletion_scenario() -> PrefixDelScenario {
    let c = build_prefix_deletion_chain();
    let archive_tmp = Temp::new();
    put_segment(&archive_tmp.0, 0, &[&c.cp0], &[]);
    put_segment(&archive_tmp.0, 1, &[&c.cp1], &[]);
    put_segment(&archive_tmp.0, 2, &[&c.cp2], &[]);
    // S3 and S4 were deleted from the archive.
    let live_tmp = Temp::new();
    put_segment(&live_tmp.0, 5, &[&c.cp5], &[]);
    let s5_segment_path = segment_path(&live_tmp.0, 5);
    // The live file follows the kept sealed segment: the writer's
    // next batch opens with cp6, which chains from cp5 and
    // declares the running fold through cp5.
    let mmr_after_cp5 = pushed(&c.cp5_declared_mmr, &c.cp5);
    let cp6 = signed_cp(6, c.cp5.hash(), &mmr_after_cp5);
    let live_file_path = live_tmp.0.join("audit.jsonl");
    write_bytes(&live_file_path, &line_bytes(&cp6));
    PrefixDelScenario {
        archive_dir: archive_tmp.0.clone(),
        _archive_tmp: archive_tmp,
        live_dir: live_tmp.0.clone(),
        _live_tmp: live_tmp,
        s5_segment_path,
        live_file_path,
        s5_opening: c.cp5,
    }
}

/// Form (a): step 7 over the archive alone, with `end_before(S5
/// opening)` and the matching end anchor. The archive holds
/// `[cp0, cp1, cp2]`; the chain rule at `e = 5` compares with the
/// record at the highest `seq` below (`cp2`) and `cp5.previous =
/// cp4.hash` mismatches, so `ChainBroken` fires at `e`. The
/// archive fold through `S0..=S2` is size 3, while `cp5` declares
/// a size-5 fold through `[cp0..=cp4]`, so `MmrMismatch` fires at
/// `e`. `S3` and `S4`'s `seq`s are missing, so `SeqGap` covers
/// `3..=4` at `e`. Each finding is unlocated because it sits on
/// the end-record segment (ruling 13-V6-d4 point 6).
#[test]
fn l4_step7_archive_alone_literal() {
    let h = build_prefix_deletion_scenario();
    let cp5_line = line_without_lf(&h.s5_opening);
    let anchor = checkpoint_of(&h.s5_opening);
    let report = verifier()
        .end_before(&cp5_line, Some(anchor))
        .unwrap()
        .verify_files(vec![h.archive_dir.clone()])
        .unwrap();
    let expected = vec![
        unlocated(
            K::ChainBroken,
            Some(5),
            format!("expected previous {CP2_PD_DIGEST}, found {CP4_PD_DIGEST}"),
        ),
        unlocated(
            K::MmrMismatch,
            Some(5),
            format!(
                "expected size 3 root {MMR_PD_SIZE3_ARCHIVE_ROOT}, found size 5 root {MMR_PD_SIZE5_CP5_DECL_ROOT}",
            ),
        ),
        unlocated(K::SeqGap, Some(5), "missing seq 3..=4".into()),
    ];
    assert_findings(report.findings(), &expected, "L4 (a) step 7");
}

/// Form (b): step 6 over the archive directory plus the live
/// directory, with no start. The archive's `[cp0, cp1, cp2]` plus
/// `S5 = [cp5]` and the live file's `cp6` are the verified set.
/// The chain rule at seq 5 compares `cp5` with the record at the
/// highest `seq` below (`cp2`) and `cp5.previous = cp4.hash`
/// mismatches, so `ChainBroken` fires at `cp5`'s location in the
/// live sealed segment file. `SeqGap` covers the missing range
/// `3..=4`, located at `cp5`. `MmrMismatch` also fires at `cp5`
/// because the classifier's running fold after `[cp0, cp1, cp2]`
/// is size 3, while `cp5` declares the fold through the deleted
/// `cp3` and `cp4` (size 5) (ruling 13-V4-d10 points 2-3). A
/// second `MmrMismatch` fires at `cp6` in the live file because
/// the running fold there is `{cp0, cp1, cp2, cp5}` (size 4) and
/// `cp6` declares the fold through `cp5` with `cp3` and `cp4`
/// included (size 6).
#[test]
fn l4_step6_archive_plus_live_literal() {
    let h = build_prefix_deletion_scenario();
    let report = verifier()
        .verify_files(vec![h.archive_dir.clone(), h.live_dir.clone()])
        .unwrap();
    let expected = vec![
        located(
            K::ChainBroken,
            h.s5_segment_path.clone(),
            1,
            5,
            format!("expected previous {CP2_PD_DIGEST}, found {CP4_PD_DIGEST}"),
        ),
        located(
            K::MmrMismatch,
            h.s5_segment_path.clone(),
            1,
            5,
            format!(
                "expected size 3 root {MMR_PD_SIZE3_ARCHIVE_ROOT}, found size 5 root {MMR_PD_SIZE5_CP5_DECL_ROOT}",
            ),
        ),
        located(
            K::SeqGap,
            h.s5_segment_path.clone(),
            1,
            5,
            "missing seq 3..=4".into(),
        ),
        located(
            K::MmrMismatch,
            h.live_file_path.clone(),
            1,
            6,
            format!(
                "expected size 4 root {MMR_PD_SIZE4_STEP6_AT_CP6_ROOT}, found size 6 root {MMR_PD_SIZE6_CP6_DECL_ROOT}",
            ),
        ),
    ];
    assert_findings(report.findings(), &expected, "L4 (b) step 6");
}

/// Form (c): `start_from(S5 opening)` over the live directory
/// alone (which holds the sealed `S5`). The accepted start
/// anchors `cp5`, so the prefix `SeqGap` for `0..=4` is
/// suppressed and no other finding fires. The live directory
/// alone cannot see the archived part, which is the "limit
/// visible" assertion of ADR-0005 l.943.
#[test]
fn l4_start_from_live_only_literal() {
    let h = build_prefix_deletion_scenario();
    let start_anchor = checkpoint_of(&h.s5_opening);
    let report = verifier()
        .start_from(start_anchor)
        .verify_files(vec![h.live_dir.clone()])
        .unwrap();
    let expected: Vec<Finding> = Vec::new();
    assert_findings(report.findings(), &expected, "L4 (c) start_from");
    assert!(report.is_valid(), "L4 (c) is valid");
}

// =====================================================================
// L5 -- REGRESSION. The record at `p = e - 1` is forked: two
// distinct records sit at seq 2 (`e2` from the archive and
// `e2_alt` from a shipped copy). The chain rule's `expected` set
// covers both copies (ruling 13-V6-d6 point 1), so the end
// `cp3.previous = e2.hash` LINKS through the honest copy and no
// `ChainBroken` fires at `e`; the chain loop still reports
// `SeqConflict` at the archive's e2 copy. Hand-built because the
// fork is a forged input.
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
// L5b -- REGRESSION. Second forked-`p` row with the fork at seq 1
// (`e1` and an alternate seq-1 record). The expected set at seq 2
// covers both e1 copies, so `cp2.previous = e1.hash` LINKS and no
// `ChainBroken` fires at `e = 2`. One `SeqConflict` at seq 1 is
// the only finding. Hand-built forged input.
// =====================================================================
#[test]
fn l5b_fork_at_seq1_no_chain_broken_seq_conflict() {
    let c = build_chain_l5();
    let cp2 = signed_cp(2, c.e1.hash(), &pushed(&seeded(&c.cp0), &c.e1));
    let e1_alt = Record::new(
        context(1, c.cp0.hash()),
        Entry::new("actor", "change", "alt"),
    )
    .unwrap();
    let d = Temp::new();
    put_segment(&d.0, 0, &[&c.cp0, &c.e1], &[]);
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
    // `[u8; 32]`); `e1_alt`'s hash starts with `0x12` and `e1`'s
    // with `0xc1`, so `e1_alt` sorts first.
    let expected = vec![located(
        K::SeqConflict,
        archive,
        2,
        1,
        format!("conflicting hashes: {E1_ALT_DIGEST}, {E1_HONEST_DIGEST}"),
    )];
    assert_findings(report.findings(), &expected, "L5b");
}

// =====================================================================
// L6 -- ACCEPTANCE. The files hold nothing below `e`: an empty
// archive directory with the end record `cp3` at seq 3. The end
// checkpoint is the lowest record in the verified set, so the
// chain loop does not check it; the end-specific
// `ChainBroken end_before seq 3: no record precedes the end` fires
// (ruling 13-V6-d6 point 3). The chain loop still reports `SeqGap
// missing seq 0..=2` at the end record (unlocated by the strip
// pass).
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
// L6b -- REGRESSION. `e = 0` -- genesis as the end -- is a no-check
// case per ruling 13-V6-d6 point 3 ("At `e = 0` nothing is
// checked"). The chain loop at seq 0 (the lowest) seeds `expected =
// [genesis]`, the honest `cp0.previous = genesis(TRAIL)` LINKS, and
// nothing else fires.
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
// L6b2 -- REGRESSION. Second `e = 0` row: same no-check scenario
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
// does not link, so `ChainBroken` fires at `e` (unlocated),
// together with `SeqGap` for the missing range and `Resumed ...
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
        "operator=op reason=a head=2:{E2_HONEST_DIGEST} gap=none lost_records=0 structural=invalid(head-not-present)",
    );
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
                "expected size 1 root {MMR_SIZE1_CP0_ROOT}, found size 3 root {MMR_SIZE3_CP3_DECL_ROOT}",
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
        "operator=op reason=a head=2:{E2_HONEST_DIGEST} gap=none lost_records=0 structural=invalid(head-not-present)",
    );
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
                "expected size 2 root {MMR_SIZE2_CP0_E1_ROOT}, found size 3 root {MMR_SIZE3_CP3_DECL_ROOT}",
            ),
        ),
        unlocated(K::SeqGap, Some(3), "missing seq 2..=2".into()),
        unlocated(K::Resumed, Some(4), resumed_detail),
        unlocated(K::UncoveredTail, None, "records seq 4..=4".into()),
    ];
    assert_findings(report.findings(), &expected, "L7b");
}

// =====================================================================
// L8 -- REGRESSION. Resume line with an uncut tail: the archive
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
        "operator=op reason=a head=2:{E2_HONEST_DIGEST} gap=none lost_records=0 structural=valid",
    );
    let expected = vec![
        unlocated(K::Resumed, Some(4), resumed_detail),
        unlocated(K::UncoveredTail, None, "records seq 4..=4".into()),
    ];
    assert_findings(report.findings(), &expected, "L8");
}

// =====================================================================
// L9 -- REGRESSION. Honest `e = p + 1` layout where the hashes
// match: the archive is `[cp0, e1, cp2]` and the end record is
// `cp3_honest = signed_cp(3, cp2.hash, fold)`. `cp3.previous =
// cp2.hash` LINKS and the declared fold equals the archive fold,
// so no `ChainBroken` or `MmrMismatch` fires and the finding list
// is empty. Pairs with L1 to pin that the chain rule does not
// over-fire on an honest layout when its guards are engaged.
// =====================================================================
#[test]
fn l9_honest_batch_matching_hash_has_no_chain_broken() {
    let c = build_chain();
    let cp3_honest = signed_cp(
        3,
        c.cp2.hash(),
        &pushed(&pushed(&seeded(&c.cp0), &c.e1), &c.cp2),
    );
    let d = Temp::new();
    put_segment(&d.0, 0, &[&c.cp0, &c.e1, &c.cp2], &[]);
    let cp3_line = line_without_lf(&cp3_honest);
    let anchor = checkpoint_of(&cp3_honest);
    let report = verifier()
        .end_before(&cp3_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let expected: Vec<Finding> = Vec::new();
    assert_findings(report.findings(), &expected, "L9");
}

// =====================================================================
// L10 -- REGRESSION. The archive's last segment ends with a torn
// fragment after its closing checkpoint, and the end record opens
// cleanly without a resume line. `mark_no_crash` sees the end
// record as the successor native input and marks the trailing
// `TornWrite` "no crash outcome" (ruling 13-V6-d5 point 5; existing
// rule). Pairs with L10b to pin that a resume line disables the
// mark. The end record is an honest `cp3` so the chain rule at
// seq 3 LINKS and only the trailing `TornWrite` + `UncoveredTail`
// remain. Hand-built because the trailing fragment bytes do not
// match the real writer's clean output.
// =====================================================================
#[test]
fn l10_torn_write_before_end_opening_carries_no_crash_outcome() {
    let c = build_chain();
    let d = Temp::new();
    put_segment(&d.0, 0, &[&c.cp0, &c.e1, &c.cp2], b"frag");
    let cp3_honest = signed_cp(
        3,
        c.cp2.hash(),
        &pushed(&pushed(&seeded(&c.cp0), &c.e1), &c.cp2),
    );
    let cp3_line = line_without_lf(&cp3_honest);
    let anchor = checkpoint_of(&cp3_honest);
    let report = verifier()
        .end_before(&cp3_line, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let segment = segment_path(&d.0, 0);
    let expected = vec![
        Finding::new(
            K::TornWrite,
            Some(segment.clone()),
            Some(4),
            None,
            format!("trailing gap lines 4..=4 (4 bytes), digest {FRAG_DIGEST}; no crash outcome"),
        )
        .with_pin(Some(2), hex_to_bytes_32(FRAG_DIGEST_HEX)),
        Finding::new(
            K::Unparsable,
            Some(segment),
            Some(4),
            None,
            "CorruptTrail: Unparsable: invalid audit v1 OTLP line".into(),
        ),
    ];
    assert_findings(report.findings(), &expected, "L10");
}

// =====================================================================
// L10b -- REGRESSION. Same torn-write archive as L10 but the end
// record carries a resume line. `mark_no_crash` sees the resume
// entry as the successor's second record and returns `false`, so
// the trailing `TornWrite` does NOT carry the "no crash outcome"
// mark. The resume's head names `cp2` -- the archive's highest
// present record -- so the opening links and no chain-rule
// finding fires. Hand-built with a forged resume line.
// =====================================================================
#[test]
fn l10b_torn_write_before_end_with_resume_line_has_no_mark() {
    let c = build_chain();
    let d = Temp::new();
    put_segment(&d.0, 0, &[&c.cp0, &c.e1, &c.cp2], b"frag");
    let cp3_honest = signed_cp(
        3,
        c.cp2.hash(),
        &pushed(&pushed(&seeded(&c.cp0), &c.e1), &c.cp2),
    );
    let cp3_line = line_without_lf(&cp3_honest);
    let resume = resume_entry(4, cp3_honest.hash(), 2, c.cp2.hash());
    let anchor = checkpoint_of(&cp3_honest);
    let record = format!("{}\n{}", cp3_line, line_without_lf(&resume));
    let report = verifier()
        .end_before(&record, Some(anchor))
        .unwrap()
        .verify_files(vec![d.0.clone()])
        .unwrap();
    let segment = segment_path(&d.0, 0);
    let resumed_detail = format!(
        "operator=op reason=a head=2:{CP2_HONEST_DIGEST} gap=none lost_records=0 structural=valid",
    );
    let seg_run_digest = hex_to_bytes_32(L10B_SEG_STRUCT_RUN_HEX);
    let expected = vec![
        Finding::new(
            K::SegmentStructure,
            Some(segment.clone()),
            Some(1),
            Some(0),
            format!(
                "span seg 0 after 2 len 4 {FRAG_DIGEST}; digest blake3:{L10B_SEG_STRUCT_RUN_HEX}",
            ),
        )
        .with_run_digest(seg_run_digest),
        unlocated(K::Resumed, Some(4), resumed_detail),
        unlocated(K::UncoveredTail, None, "records seq 4..=4".into()),
        Finding::new(
            K::TornWrite,
            Some(segment.clone()),
            Some(4),
            None,
            format!("trailing gap lines 4..=4 (4 bytes), digest {FRAG_DIGEST}"),
        )
        .with_pin(Some(2), hex_to_bytes_32(FRAG_DIGEST_HEX)),
        Finding::new(
            K::Unparsable,
            Some(segment),
            Some(4),
            None,
            "CorruptTrail: Unparsable: invalid audit v1 OTLP line".into(),
        ),
    ];
    assert_findings(report.findings(), &expected, "L10b");
}

/// Decodes a 64-char hex string into its 32 raw bytes, for test-
/// time construction of `with_run_digest` arguments.
fn hex_to_bytes_32(h: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

// =====================================================================
// L11 -- REGRESSION. `e = 0` and the end checkpoint's `prev` is not
// the genesis value, over an empty archive. The chain loop's
// genesis seed fires `ChainBroken` at seq 0 (the existing genesis
// grammar), and `no_record_precedes` is skipped per the `e == 0`
// guard (ruling 13-V6-d6 point 3). Exactly one unlocated
// `ChainBroken` at seq 0 with the ordinary genesis grammar.
// Hand-built because the real writer always links its seq-0
// checkpoint to the genesis value.
// =====================================================================
#[test]
fn l11_end_at_seq_zero_with_wrong_prev_has_genesis_chain_broken() {
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
        format!("expected previous {GENESIS_TRAIL_DIGEST}, found {ONES_DIGEST}"),
    )];
    assert_findings(report.findings(), &expected, "L11");
}

// =====================================================================
// L12 -- ACCEPTANCE. The files hold a byte-identical shipped copy
// of the end line `cp3` and a different record below it (`cp0` at
// seq 0). The chain rule at seq 3 compares with the record at the
// highest `seq` below (`cp0`) and `cp3.previous = e2.hash`
// mismatches, so one `ChainBroken` fires, located at the shipped
// file copy of cp3 (the end record sorts after every file copy at
// the same `seq`, ruling 13-V6-d4 point 3). `DuplicateRecord` is
// suppressed at or above `e` (ruling 13-V6-d4 point 3), so no
// duplicate finding fires. `TrailEnded` names the end `seq`,
// `SeqGap` covers `1..=2`, and `MmrMismatch` contrasts the archive
// fold (size 1) with cp3's declared fold (size 3).
// =====================================================================
#[test]
fn l12_byte_identical_end_copy_in_files_has_one_chain_broken_at_e() {
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
                "expected size 1 root {MMR_SIZE1_CP0_ROOT}, found size 3 root {MMR_SIZE3_CP3_DECL_ROOT}",
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
// L13 -- REGRESSION. A resume line with a broken link and no jump
// (`e = p + 1`): files hold `[cp0, e1, e2]` and the end record is
// `cp3-forged + resume(head=(2, e2.hash))`. `cp3-forged.previous
// = [9; 32]`, not `e2.hash`, so the chain rule at seq 3 compares
// with `e2.hash` and the forged `previous` does not match: one
// `ChainBroken` fires at `e` -- the rule applies to resume
// openings exactly as elsewhere (ruling 13-V6-d6 point 2). The
// declared MMR matches the honest through-e2 fold so no
// `MmrMismatch` fires; only the chain rule does. Hand-built
// because the broken link is a forged record.
// =====================================================================
#[test]
fn l13_resume_broken_link_no_jump_has_chain_broken() {
    let c = build_chain_l5();
    let d = Temp::new();
    put_segment(&d.0, 0, &[&c.cp0, &c.e1, &c.e2], &[]);
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
            format!("expected previous {E2_HONEST_DIGEST}, found {NINES_DIGEST}"),
        ),
        unlocated(K::Resumed, Some(4), resumed_detail),
        unlocated(K::UncoveredTail, None, "records seq 4..=4".into()),
    ];
    assert_findings(report.findings(), &expected, "L13");
}

// =====================================================================
// L14 -- REGRESSION. An honest valid resume (head = last record,
// real gap): files hold `[cp0, e1, e2]` and the end record is
// `cp5-forged + resume(head=(2, e2.hash), lost_through=4)`. The
// opening at seq 5 links to `e2.hash` (the resume names seq 2 as
// the head and `cp5.previous = e2.hash`), so the chain rule at
// seq 5 LINKS and no `ChainBroken` fires. The jump `3..=4` is a
// resume gap (ADR-0005 decision 5, "Resume gaps"; ruling
// 13-V7-d1 point 7: a trusted-opening candidate's jump reports
// no `SeqGap`), so the row carries `Resumed ... structural=valid`
// and nothing else. Hand-built because the resume opening at
// seq 5 is a forged checkpoint (its `previous` must equal
// `e2.hash` to model an honest resume that lost seqs 3..=4).
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
        unlocated(K::Resumed, Some(6), resumed_detail),
        unlocated(K::UncoveredTail, None, "records seq 6..=6".into()),
    ];
    assert_findings(report.findings(), &expected, "L14");
}

// =====================================================================
// REGRESSION. Fixture-hash pins: recompute each literal in the
// shared constants from the fixture builders by equality, so a
// fixture-level drift surfaces here instead of across many rows.
// =====================================================================
#[test]
fn fixture_hashes_match_literals() {
    let c = build_chain();
    assert_eq!(digest_string(&c.cp0.hash()), CP0_HONEST_DIGEST);
    assert_eq!(digest_string(&c.e1.hash()), E1_HONEST_DIGEST);
    assert_eq!(digest_string(&c.cp2.hash()), CP2_HONEST_DIGEST);
    assert_eq!(digest_string(&c.e3.hash()), E3_HONEST_DIGEST);
    assert_eq!(digest_string(&c.cp4.hash()), CP4_L1_DIGEST);
    let cl5 = build_chain_l5();
    assert_eq!(digest_string(&cl5.cp0.hash()), CP0_HONEST_DIGEST);
    assert_eq!(digest_string(&cl5.e1.hash()), E1_HONEST_DIGEST);
    assert_eq!(digest_string(&cl5.e2.hash()), E2_HONEST_DIGEST);
    assert_eq!(digest_string(&cl5.cp3.hash()), CP3_L5_DIGEST);
    let e2_alt = Record::new(
        context(2, cl5.e1.hash()),
        Entry::new("actor", "change", "alt"),
    )
    .unwrap();
    assert_eq!(digest_string(&e2_alt.hash()), E2_ALT_DIGEST);
    let e2_alt2 = Record::new(
        context(2, cl5.e1.hash()),
        Entry::new("actor", "change", "alt2"),
    )
    .unwrap();
    assert_eq!(digest_string(&e2_alt2.hash()), E2_ALT2_DIGEST);
    let e1_alt = Record::new(
        context(1, cl5.cp0.hash()),
        Entry::new("actor", "change", "alt"),
    )
    .unwrap();
    assert_eq!(digest_string(&e1_alt.hash()), E1_ALT_DIGEST);
    assert_eq!(
        digest_string(&Record::genesis(&TRAIL)),
        GENESIS_TRAIL_DIGEST
    );
    assert_eq!(digest_string(&[1u8; 32]), ONES_DIGEST);
    assert_eq!(digest_string(&[9u8; 32]), NINES_DIGEST);
    let cp0_only = seeded(&c.cp0);
    assert_eq!(
        format!("blake3:{}", hex(&cp0_only.root())),
        MMR_SIZE1_CP0_ROOT,
    );
    let cp0_e1 = pushed(&seeded(&c.cp0), &c.e1);
    assert_eq!(
        format!("blake3:{}", hex(&cp0_e1.root())),
        MMR_SIZE2_CP0_E1_ROOT,
    );
    let cp0_e1_cp2 = pushed(&pushed(&seeded(&c.cp0), &c.e1), &c.cp2);
    assert_eq!(
        format!("blake3:{}", hex(&cp0_e1_cp2.root())),
        MMR_SIZE3_CP0_E1_CP2_ROOT,
    );
    let cp4_decl = pushed(&pushed(&pushed(&seeded(&c.cp0), &c.e1), &c.cp2), &c.e3);
    assert_eq!(
        format!("blake3:{}", hex(&cp4_decl.root())),
        MMR_SIZE4_CP4_DECL_ROOT,
    );
    let l3_archive = pushed(&pushed(&seeded(&cl5.cp0), &cl5.e1), &e2_alt);
    assert_eq!(
        format!("blake3:{}", hex(&l3_archive.root())),
        MMR_SIZE3_L3_ARCHIVE_ROOT,
    );
    let l3b_archive = pushed(&pushed(&seeded(&cl5.cp0), &cl5.e1), &e2_alt2);
    assert_eq!(
        format!("blake3:{}", hex(&l3b_archive.root())),
        MMR_SIZE3_L3B_ARCHIVE_ROOT,
    );
    let cp3_decl = pushed(&pushed(&seeded(&cl5.cp0), &cl5.e1), &cl5.e2);
    assert_eq!(
        format!("blake3:{}", hex(&cp3_decl.root())),
        MMR_SIZE3_CP3_DECL_ROOT,
    );
    let h = build_prefix_deletion_chain();
    assert_eq!(digest_string(&h.cp0.hash()), CP0_HONEST_DIGEST);
    assert_eq!(digest_string(&h.cp1.hash()), CP1_PD_DIGEST);
    assert_eq!(digest_string(&h.cp2.hash()), CP2_PD_DIGEST);
    assert_eq!(digest_string(&h.cp3.hash()), CP3_PD_DIGEST);
    assert_eq!(digest_string(&h.cp4.hash()), CP4_PD_DIGEST);
    assert_eq!(digest_string(&h.cp5.hash()), CP5_PD_DIGEST);
    assert_eq!(
        format!("blake3:{}", hex(&h.archive_mmr.root())),
        MMR_PD_SIZE3_ARCHIVE_ROOT,
    );
    assert_eq!(
        format!("blake3:{}", hex(&h.cp5_declared_mmr.root())),
        MMR_PD_SIZE5_CP5_DECL_ROOT,
    );
    // Step 6's running fold at cp6: {cp0, cp1, cp2, cp5} (size 4),
    // formed by pushing cp5 on top of the archive's size-3 fold.
    let step6_at_cp6 = pushed(&h.archive_mmr, &h.cp5);
    assert_eq!(
        format!("blake3:{}", hex(&step6_at_cp6.root())),
        MMR_PD_SIZE4_STEP6_AT_CP6_ROOT,
    );
    // cp6's declared size-6 fold: {cp0..cp4, cp5}.
    let cp6_decl = pushed(&h.cp5_declared_mmr, &h.cp5);
    assert_eq!(
        format!("blake3:{}", hex(&cp6_decl.root())),
        MMR_PD_SIZE6_CP6_DECL_ROOT,
    );
}
