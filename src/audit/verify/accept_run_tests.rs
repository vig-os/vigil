//! Rows for [`crate::audit::Verifier::accept_run`] and the three
//! outcomes `Accepted` / `AcceptMismatch` / `AcceptUnused`
//! (ADR-0005 decision 11 "Review file" `accept-run`; ruling
//! 13-V8-d1). Every row asserts the full sorted finding list
//! literally through `assert_findings`.

use super::tests_common::{assert_findings, parse_cp, report_of, trust_with_key, unlocated};
use super::{Finding, Verifier};
use crate::audit::{
    AuditErrorKind, FindingKind as K, Mmr, Record, digest_string,
    runs_v4a_fixtures::{
        A1_DIGEST, A3_DIGEST, A9_DIGEST, TRAIL, Temp, build_a1, build_a3, entry_rec,
        fixture_pubkey, headless, line_bytes, pushed, put_segment, resume_decl, seeded,
        segment_path, signed_cp, signed_cp_explicit, write_records,
    },
};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

// =====================================================================
// Pinned constants (consistency test pins the hex literals).
// =====================================================================

/// `run_digest(&[], &[])`: the "digest of nothing" used by the
/// `AcceptUnused` branch of ADR-0005 decision 11 `accept-run`.
/// Equal to the `A8_DIGEST` pin (an A8-layout run has empty ranges
/// and empty spans).
const EMPTY_RUN_DIGEST_HEX: &str =
    "blake3:1c02f080d9c70df74de0c13a4a30323f1b49ee624bab2c5d68fa5ee31c4400e4";
const WRONG_HASH: [u8; 32] = [0xC7; 32];
const WRONG_HASH_HEX: &str =
    "blake3:c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7";
const WRONG_DIGEST: [u8; 32] = [0x6B; 32];
const WRONG_DIGEST_HEX: &str =
    "blake3:6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b";

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("hex"),
    }
}
const fn hex_to_bytes(hex: &str) -> [u8; 32] {
    let s = hex.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(s[i * 2]) << 4) | nibble(s[i * 2 + 1]);
        i += 1;
    }
    out
}
const EMPTY_RUN_DIGEST: [u8; 32] =
    hex_to_bytes("1c02f080d9c70df74de0c13a4a30323f1b49ee624bab2c5d68fa5ee31c4400e4");
const A1_DIGEST_BYTES: [u8; 32] =
    hex_to_bytes("79d8cb1c4dfc89a80a4911120280e63ed383108f3199f05291bcb51f625f3931");
const A3_DIGEST_BYTES: [u8; 32] =
    hex_to_bytes("78d5088883d54faa6aefe350948c217bb5ef3c32a468f22184bc07e56d84c63d");
const A9_DIGEST_BYTES: [u8; 32] =
    hex_to_bytes("4905b9e63aa3fd9248f5c3605fe4beaf4af5a956f3f108b6dcecdbfbfda54026");

// `build_a1` / `build_a9` / `build_archive_start_fx` and
// `build_two_run_fx` share this honest cp0..e2 + r4 + cp5 prefix, so
// the chain-rule's "expected previous e2.hash, found r4.previous"
// detail and cp5's hash are the same pinned hex everywhere.
const E2_HASH_HEX: &str = "blake3:8a5ea9c989aad7e89033b58ad6f59a6384af43dfe6df5bada042420c0040c306";
const R4_PREV_HEX: &str = "blake3:b378374409602bc24aa87765b3cc3361e3b647368f57d9a06816f9b2bd0696c9";
/// Honest cp5 (`signed_cp` with the real fold root): A1, two-run,
/// archive-start and A8/A9 all stop here. `build_run_fx` and
/// `build_bad_cp6_fx` override cp5's declared root to 0x55 and so
/// produce `RUNFX_CP5_HASH_HEX` instead.
const HONEST_CP5_HASH_HEX: &str =
    "blake3:4181d394847e4274645a1b39a8366b0217c32abc5ab45e4dbee9f064c25361aa";
/// Honest fold at cp5 and honest resume7 (`resume_decl(&cp6, 5,
/// cp5.hash, 5)` with the honest cp5+cp6): same bytes across
/// `build_a1`, `build_archive_start_fx` and `build_two_run_fx`.
const HONEST_RESUME7_HASH_HEX: &str =
    "blake3:03363d305614474696044828fb575c52b1113510ef8bda859eec04bdac1ebd4e";
const HONEST_FOLD_ROOT_HEX: &str =
    "blake3:8c89e5675d09a83557775acf82c200357f94447d60bf5d4a455b525cf04ff242";

// `build_run_fx` and `build_bad_cp6_fx` override cp5's declared root
// to 0x55 via `signed_cp_explicit`, so cp5's hash and the dependent
// chain (cp6, resume7) differ from the honest prefix above.
const RUNFX_CP5_BAD_ROOT_HEX: &str =
    "blake3:5555555555555555555555555555555555555555555555555555555555555555";
const RUNFX_CP5_HASH_HEX: &str =
    "blake3:d41624c49a4d72567d21a937c5041984ae12a5b74e645430f2cee9ac1244f6eb";
const RUNFX_CP6_HASH_HEX: &str =
    "blake3:51ebc18bee718ec6b938c33aea145787fab90073c1e7563c6e111236c55874af";
const RUNFX_RESUME7_HASH_HEX: &str =
    "blake3:55e4befe78bd37a9b103ef382b8f4e521b73f8211340ea0df739a72a9b118238";
const RUNFX_CP5_BAD_ROOT: [u8; 32] = [0x55; 32];

// `build_bad_cp6_fx`: shared cp5 with `build_run_fx`, then cp6's
// declared root is also overridden -- to 0xAA -- producing a
// different cp6 hash and a different resume7 hash from `build_run_fx`.
const BAD_CP6_CP6_HASH_HEX: &str =
    "blake3:71017362c0c49ca521450fa7b53c4ea6a76b818ee622f3c306e14e798676aa20";
const BAD_CP6_BAD_ROOT_HEX: &str =
    "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BAD_CP6_FOLD6_ROOT_HEX: &str =
    "blake3:c5a3181cc4455bd7a1e22719189c9767e70c0cfd1a64d849dab5d7c46c693c21";
const BAD_CP6_RESUME_HASH_HEX: &str =
    "blake3:f3fc81a3657b3e3bc0c7cd5cb6e22d7661759fe4afb509d8eacd3f889e64bac7";

// `build_two_run_fx` extends the honest A1 prefix: S2 holds cp6,
// resume7 (honest), e8, and a `not json\n` trailing line (a 9-byte
// non-record span); S3 holds a headless r10 + cp11; live holds
// cp12 + resume13.
const TWO_RUN_E8_HASH_HEX: &str =
    "blake3:959f8e130b18bca13241caa616bea6b2dc47ef44442fd16497c0f6c0eb626437";
const TWO_RUN_R10_PREV_HEX: &str =
    "blake3:5072d3ddeeb4d9c56a4196b94482c69fcd4089d091a43d5db0083f9b37deb0f6";
const TWO_RUN_CP11_HASH_HEX: &str =
    "blake3:2094266b87ff559a57cf3db2f4a48066446ce244cbb0c3197b7a325161666093";
const TWO_RUN_RESUME13_HASH_HEX: &str =
    "blake3:1a01f602d7ba0c6f750f4019f86b6301d40b9a03aafafc6eedb673de5fb7bc3e";
/// Run 1's `run_digest` under `build_two_run_fx`: ranges =
/// `[(9, 1)]` (r10's loss), one span at `seg 0 after 8 len 9` with
/// the 9-byte `not json\n` gap digest.
const TWO_RUN_RUN1_DIGEST_HEX: &str =
    "blake3:4117087a671c5cb880a7099db775c60a3a818c901fdd23d9f3ac12d8ff1d771e";
/// Gap digest of the 9-byte `not json\n` tail on S2 under
/// `build_two_run_fx`. Reused as the trailing-gap digest in S2's
/// `TornWrite` finding.
const TWO_RUN_NOT_JSON_GAP_DIGEST_HEX: &str =
    "blake3:8b78e71ce40a5c8ed68f53d8601ac823e803eb9366d24f963163e8524438ce8a";
const TWO_RUN_RUN1_DIGEST: [u8; 32] =
    hex_to_bytes("4117087a671c5cb880a7099db775c60a3a818c901fdd23d9f3ac12d8ff1d771e");

// A3 record hashes (honest cp0..e1 + cp2 + r4 + cp5 + r7 + cp8 +
// cp10 + resume, all at `TRAIL`).
const A3_RESUME_HASH_HEX: &str =
    "blake3:4871666ace925019a742104d048684f3c0e0bd5dbd366b16fd440f976c3ba6d5";
const A3_CP2_HASH_HEX: &str =
    "blake3:4164966a12a675e55eb6e133b9e50313907f164fe142d941447defcdfdb25d06";
const A3_R4_PREV_HEX: &str =
    "blake3:6dd21c1a65b14cff0eecfb0679a9da4a45cc6d5007071d250295342d454fb9b5";
const A3_CP5_HASH_HEX: &str =
    "blake3:e06db9dc14e57aa46718ace1b95182f2e6515fa7f4ef49ba50fe30cdf57ea5b8";
const A3_R7_PREV_HEX: &str =
    "blake3:b4f78ec4465a0669bbe624bbc7c71327249263c0852fdd78c29cd567929bacab";
const A3_CP8_HASH_HEX: &str =
    "blake3:436c1a38d9dd40b9880233500e5c4c97783f180fcc0eb9c8376bee20e791d2ce";
const A3_RESUME_HASH: [u8; 32] =
    hex_to_bytes("4871666ace925019a742104d048684f3c0e0bd5dbd366b16fd440f976c3ba6d5");

// A8/A9 and `build_archive_start_cp1_fx` share this honest cp0 +
// cp_opening(seq=1) + resume(seq=2) layout.
const SHORT_RESUME_HASH_HEX: &str =
    "blake3:f41a21e13e87654f24b8fdb45a4901ef8fd0b8dbc43e861af279739e6bef9e13";
const CP0_HASH_HEX: &str =
    "blake3:fc26c6f2bb830592aaaca5413da1599489d86ac6e240a4a7a010681e0d4c8e77";

// `build_probe_fx`: `[cp0, e1, cp2]` with e1 at seq=1.
const PROBE_E1_HASH_HEX: &str =
    "blake3:c121282b5135adfe7a17142cae6bfc4c9040c4aed26d74bddc923b8dafcdb6e8";

// `forked_seq`: a mutated resume at seq 7 with lost_through=4
// (alongside the main resume's lost_through=5) -- distinct hashes
// at the same seq yield `conflicting_seqs ⊇ {7}` and `SeqConflict`.
const FORKED_ALT_RESUME_HEX: &str =
    "blake3:8ac9be84eb0b22a67ff83fdc68b76a1643c0e40f9bfffafc584f83e452ab003b";

// `write_shipped_trailing_r9(&fx.dir, &fx.resume)`: `headless(resume, 9)`
// produces an entry at seq=9 whose `previous` is the hash of the
// ghost `entry(8, resume.hash)`. For `RunFx`'s resume this gives:
const SHIPPED_R9_PREV_RUNFX_HEX: &str =
    "blake3:ca24dc0f3180b489931278efad427f40f1d7010835ddcebe213555cb5febb433";
// A3 shipped-trailing: `headless(A3's resume, 13)`.
const SHIPPED_R13_PREV_A3_HEX: &str =
    "blake3:c03fd329c45b0c67a008be082901eb8d3892f4eabe63bd0f9ced402c9b3c8b8f";
// `probe_lost_record_receipt`: `NoReceipt` for seq 4 on A3's S1
// (r4's hash) and seq 7 on A3's S2 (r7's hash).
const A3_R4_HASH_HEX: &str =
    "blake3:fb3b655a2ca6b530ea91af0e0669eb90bcfad2174ba55f54462370338393db5b";
const A3_R7_HASH_HEX: &str =
    "blake3:14ad68816a8cb2f17883ea576e74c099ac9a65d5f01153296423be2184c12dfb";
// A9's second span: the 14-byte `also not json\n` tail on S2.
const A9_SPAN1_DIGEST_HEX: &str =
    "blake3:4538bcdbaba974dc18a217221116cee0c884f72d52845285ab713a33c8d047da";

// Honest cp6 (`signed_cp(6, HONEST_CP5, honest fold6)`): shared
// between `build_archive_start_fx` and `build_hand_built_resume_fx`.
const HONEST_CP6_HASH_HEX: &str =
    "blake3:4501a0a713d1703db540fc8922a1d598ba8fea3cfd148c92f6e7bf33c5ebad1a";

// Hand-built resume layout: a resume at seq=7 built against
// `cp6_alt = signed_cp(6, cp0.hash(), &mmr0)` (a valid, signed
// checkpoint whose previous is cp0, not cp5). The writer never
// emits a resume whose opening is not the closing opening on the
// trail, so this record only exists in a hand-built file.
const HAND_BUILT_CP6_ALT_HASH_HEX: &str =
    "blake3:718997911d8bb05360f91ed31c96dbab4593f19414028bbe742ce741ce73b5c4";
const HAND_BUILT_RESUME_ALT_HASH_HEX: &str =
    "blake3:699cc110c028e776b688e1b3b55eb302e4f5859485d1e4fd0e19437c326b8077";

#[test]
fn pinned_literals_match() {
    let empty = super::lines::run_digest(&[], &[]);
    assert_eq!(digest_string(&empty), EMPTY_RUN_DIGEST_HEX, "empty digest");
    assert_eq!(EMPTY_RUN_DIGEST, empty, "empty digest bytes");
    assert_eq!(digest_string(&A1_DIGEST_BYTES), A1_DIGEST, "A1 bytes");
    assert_eq!(digest_string(&A3_DIGEST_BYTES), A3_DIGEST, "A3 bytes");
    assert_eq!(digest_string(&A9_DIGEST_BYTES), A9_DIGEST, "A9 bytes");
    assert_eq!(digest_string(&WRONG_HASH), WRONG_HASH_HEX, "wrong hash");
    assert_eq!(
        digest_string(&WRONG_DIGEST),
        WRONG_DIGEST_HEX,
        "wrong digest"
    );
    // Prefix hashes: the honest cp0..e2+r4+cp5 chain.
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    assert_eq!(digest_string(&cp0.hash()), CP0_HASH_HEX, "cp0");
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    assert_eq!(digest_string(&e1.hash()), PROBE_E1_HASH_HEX, "probe e1");
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    assert_eq!(digest_string(&e2.hash()), E2_HASH_HEX, "e2");
    let r4 = headless(&e2, 4);
    assert_eq!(digest_string(&r4.context.previous), R4_PREV_HEX, "r4 prev");
    let fold = pushed(&mmr2, &r4);
    assert_eq!(digest_string(&fold.root()), HONEST_FOLD_ROOT_HEX, "fold");
    assert_eq!(fold.size(), 4, "fold size");
    let cp5_honest = signed_cp(5, r4.hash(), &fold);
    assert_eq!(
        digest_string(&cp5_honest.hash()),
        HONEST_CP5_HASH_HEX,
        "honest cp5"
    );
    // `build_run_fx` / `build_bad_cp6_fx`: cp5 with bad root 0x55.
    let cp5_bad = signed_cp_explicit(5, r4.hash(), fold.size(), [0x55; 32], fold.peaks().to_vec());
    assert_eq!(
        digest_string(&cp5_bad.hash()),
        RUNFX_CP5_HASH_HEX,
        "cp5 bad"
    );
    assert_eq!(
        digest_string(&[0x55; 32]),
        RUNFX_CP5_BAD_ROOT_HEX,
        "bad root 0x55",
    );
    let fold6_bad = pushed(&fold, &cp5_bad);
    // `build_run_fx`: cp6 is `signed_cp` (honest declared root) on
    // top of the bad-rooted cp5 chain.
    let cp6_runfx = signed_cp(6, cp5_bad.hash(), &fold6_bad);
    assert_eq!(
        digest_string(&cp6_runfx.hash()),
        RUNFX_CP6_HASH_HEX,
        "runfx cp6"
    );
    let resume_runfx = resume_decl(&cp6_runfx, 5, cp5_bad.hash(), 5);
    assert_eq!(
        digest_string(&resume_runfx.hash()),
        RUNFX_RESUME7_HASH_HEX,
        "runfx resume7",
    );
    // `build_bad_cp6_fx`: cp6 also carries bad root 0xAA.
    let cp6_bbad = signed_cp_explicit(
        6,
        cp5_bad.hash(),
        fold6_bad.size(),
        [0xAA; 32],
        fold6_bad.peaks().to_vec(),
    );
    assert_eq!(
        digest_string(&cp6_bbad.hash()),
        BAD_CP6_CP6_HASH_HEX,
        "bad cp6 cp6",
    );
    assert_eq!(digest_string(&[0xAA; 32]), BAD_CP6_BAD_ROOT_HEX, "bad 0xAA");
    assert_eq!(
        digest_string(&fold6_bad.root()),
        BAD_CP6_FOLD6_ROOT_HEX,
        "bad fold6 root",
    );
    let resume_bad = resume_decl(&cp6_bbad, 5, cp5_bad.hash(), 5);
    assert_eq!(
        digest_string(&resume_bad.hash()),
        BAD_CP6_RESUME_HASH_HEX,
        "bad cp6 resume",
    );
    // Honest resume7 (cp5 + cp6 honest).
    let fold6_honest = pushed(&fold, &cp5_honest);
    let cp6_honest = signed_cp(6, cp5_honest.hash(), &fold6_honest);
    let resume_honest = resume_decl(&cp6_honest, 5, cp5_honest.hash(), 5);
    assert_eq!(
        digest_string(&resume_honest.hash()),
        HONEST_RESUME7_HASH_HEX,
        "honest resume7",
    );
    // Two-run extras: e8, r10, cp11, resume13.
    let mmr5 = pushed(&fold, &cp5_honest);
    let cp6 = signed_cp(6, cp5_honest.hash(), &mmr5);
    let resume7 = resume_decl(&cp6, 5, cp5_honest.hash(), 5);
    let e8 = entry_rec(8, resume7.hash());
    assert_eq!(digest_string(&e8.hash()), TWO_RUN_E8_HASH_HEX, "two-run e8");
    let mmr6 = pushed(&mmr5, &cp6);
    let mmr7 = pushed(&mmr6, &resume7);
    let mmr8 = pushed(&mmr7, &e8);
    let r10 = headless(&e8, 10);
    assert_eq!(
        digest_string(&r10.context.previous),
        TWO_RUN_R10_PREV_HEX,
        "two-run r10 prev",
    );
    let mmr_before_cp11 = pushed(&mmr8, &r10);
    let cp11 = signed_cp(11, r10.hash(), &mmr_before_cp11);
    assert_eq!(
        digest_string(&cp11.hash()),
        TWO_RUN_CP11_HASH_HEX,
        "two-run cp11",
    );
    let mmr11 = pushed(&mmr_before_cp11, &cp11);
    let cp12 = signed_cp(12, cp11.hash(), &mmr11);
    let resume13 = resume_decl(&cp12, 11, cp11.hash(), 11);
    assert_eq!(
        digest_string(&resume13.hash()),
        TWO_RUN_RESUME13_HASH_HEX,
        "two-run resume13",
    );
    // Run 1's digest: ranges=[(9,1)], one 9-byte span after seq 8.
    let gap_digest = hex_to_bytes(
        TWO_RUN_NOT_JSON_GAP_DIGEST_HEX
            .strip_prefix("blake3:")
            .unwrap(),
    );
    let span = super::lines::Span {
        seg: 0,
        after: 8,
        len: 9,
        digest: gap_digest,
    };
    let computed = super::lines::run_digest(&[(9, 1)], &[span]);
    assert_eq!(
        digest_string(&computed),
        TWO_RUN_RUN1_DIGEST_HEX,
        "two-run run 1 digest"
    );
    assert_eq!(TWO_RUN_RUN1_DIGEST, computed, "two-run run 1 bytes");
    assert_eq!(
        hex_to_bytes(A3_RESUME_HASH_HEX.strip_prefix("blake3:").unwrap()),
        A3_RESUME_HASH,
        "A3 resume bytes",
    );
}

fn verifier() -> Verifier {
    Verifier::new(trust_with_key(fixture_pubkey()))
}

trait WriteAllVec {
    fn write_all_vec(&mut self, bytes: &[u8]);
}
impl WriteAllVec for fs::File {
    fn write_all_vec(&mut self, bytes: &[u8]) {
        self.write_all(bytes).unwrap();
    }
}

// =====================================================================
// Two-run fixture (ruling 13-V4-d9 scoping security row). Two
// closed runs on one trail:
//   S0 = [cp0, e1, e2] (sealed)
//   S1 = [r4 headless, cp5] (run 0's segment, loss at seq=4)
//   S2 = [cp6, resume7, e8] + "not json\n" (run 0's closer AND
//        run 1's first segment; unparsable tail becomes a span
//        in run 1's digest)
//   S3 = [r10 headless, cp11] (run 1's segment, loss at seq=10)
//   live = [cp12, resume13] (run 1's closer)
// Under ruling 13-V4-d9 (the closer segment belongs to the next
// run), run 0's segment_paths are [S0, S1] (the range
// `first_segment..last_segment`, excluding S2), and run 1's are
// [S2, S3]. An `accept-run` line for run 0 therefore never
// promotes run 1's run-structure `SegmentStructure` at S2 line 1
// seq 6, and vice versa for run 1's line.
// =====================================================================
struct TwoRunFx {
    _dir: Temp,
    dir: PathBuf,
    s1: PathBuf,
    s2: PathBuf,
    s3: PathBuf,
    live: PathBuf,
    resume7: Record,
    resume13: Record,
}
fn build_two_run_fx() -> TwoRunFx {
    let d = Temp::new();
    // S0: sealed clean prefix.
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    put_segment(&d.0, 0, &[&cp0, &e1, &e2], &[]);
    // S1: run 0's own segment -- headless first record creates a
    // loss at seq=4 (ghost at seq=3). cp5 declares the honest fold
    // so no in-run `MmrMismatch` fires.
    let r4 = headless(&e2, 4);
    let mmr_before_cp5 = pushed(&mmr2, &r4);
    let cp5 = signed_cp(5, r4.hash(), &mmr_before_cp5);
    put_segment(&d.0, 1, &[&r4, &cp5], &[]);
    // S2: run 0's closer AND run 1's first segment. cp6 is the
    // closing opening of run 0; resume7 closes run 0. e8 is run 1's
    // first entry record on the trail; a trailing `not json\n` line
    // becomes a non-record gap -- a `Span(after=8, len=9)` on this
    // segment (seg 0 relative to run 1).
    let mmr5 = pushed(&mmr_before_cp5, &cp5);
    let cp6 = signed_cp(6, cp5.hash(), &mmr5);
    let resume7 = resume_decl(&cp6, 5, cp5.hash(), 5);
    let e8 = entry_rec(8, resume7.hash());
    let mut s2_bytes = line_bytes(&cp6);
    s2_bytes.extend(line_bytes(&resume7));
    s2_bytes.extend(line_bytes(&e8));
    s2_bytes.extend_from_slice(b"not json\n");
    fs::write(segment_path(&d.0, 2), &s2_bytes).unwrap();
    // S3: run 1's own segment -- headless first record creates a
    // loss at seq=10 (ghost at seq=9 between e8 and r10). cp11
    // declares the honest fold.
    //
    // The fold at cp11 pushes cp6, resume7, e8 above r4/cp5, then
    // r10 (headless), so seed a fresh MMR with cp5's state and
    // continue.
    let mmr6 = pushed(&mmr5, &cp6);
    let mmr7 = pushed(&mmr6, &resume7);
    let mmr8 = pushed(&mmr7, &e8);
    let r10 = headless(&e8, 10);
    let mmr_before_cp11 = pushed(&mmr8, &r10);
    let cp11 = signed_cp(11, r10.hash(), &mmr_before_cp11);
    put_segment(&d.0, 3, &[&r10, &cp11], &[]);
    // live: run 1's closer.
    let mmr11 = pushed(&mmr_before_cp11, &cp11);
    let cp12 = signed_cp(12, cp11.hash(), &mmr11);
    let resume13 = resume_decl(&cp12, 11, cp11.hash(), 11);
    write_records(&d.0, &[&cp12, &resume13]);
    // Pin the record hashes against the module-level consistency
    // test so the walker-produced chain here is the same one that
    // `pinned_literals_match` reconstructs.
    assert_eq!(digest_string(&e2.hash()), E2_HASH_HEX, "two-run e2");
    assert_eq!(
        digest_string(&r4.context.previous),
        R4_PREV_HEX,
        "two-run r4 prev"
    );
    assert_eq!(
        digest_string(&cp5.hash()),
        HONEST_CP5_HASH_HEX,
        "two-run cp5"
    );
    assert_eq!(digest_string(&e8.hash()), TWO_RUN_E8_HASH_HEX, "two-run e8");
    assert_eq!(
        digest_string(&r10.context.previous),
        TWO_RUN_R10_PREV_HEX,
        "two-run r10 prev",
    );
    assert_eq!(
        digest_string(&cp11.hash()),
        TWO_RUN_CP11_HASH_HEX,
        "two-run cp11"
    );
    let s1 = segment_path(&d.0, 1);
    let s2 = segment_path(&d.0, 2);
    let s3 = segment_path(&d.0, 3);
    let live = d.0.join("audit.jsonl");
    TwoRunFx {
        dir: d.0.clone(),
        _dir: d,
        s1,
        s2,
        s3,
        live,
        resume7,
        resume13,
    }
}

// Base finding list of the two-run fixture (used by the two scoping
// rows and by the mirror row). Pinned once here and reused so a
// drift shows up in one place. The findings are in the engine's
// sort order (`(seq.is_none, seq, file, line, kind-debug)`). Run 0's
// four items 1-3 findings sit at S1 line 1 seq 4; run 1's run
// finding sits at S2 line 1 seq 6; run 1's three S3 items 1-3
// findings sit at S3 line 1 seq 10; resumes, uncovered tail and the
// S2 unparsable tail (TornWrite + Unparsable at line 4) follow.
fn two_run_base_findings(fx: &TwoRunFx) -> [Finding; 13] {
    let chain_run0 = Finding::new(
        K::ChainBroken,
        Some(fx.s1.clone()),
        Some(1),
        Some(4),
        format!("expected previous {E2_HASH_HEX}, found {R4_PREV_HEX}"),
    );
    let per_seg_run0 = Finding::new(
        K::SegmentStructure,
        Some(fx.s1.clone()),
        Some(1),
        Some(4),
        "expected first complete record to be a checkpoint".into(),
    );
    let run_structure_run0 = Finding::new(
        K::SegmentStructure,
        Some(fx.s1.clone()),
        Some(1),
        Some(4),
        format!("loss seq 4 first 3 count 1; digest {A1_DIGEST}"),
    )
    .with_run_digest(A1_DIGEST_BYTES);
    let seq_gap_run0 = Finding::new(
        K::SeqGap,
        Some(fx.s1.clone()),
        Some(1),
        Some(4),
        "missing seq 3..=3".into(),
    );
    let run_structure_run1 = Finding::new(
        K::SegmentStructure,
        Some(fx.s2.clone()),
        Some(1),
        Some(6),
        format!(
            "loss seq 10 first 9 count 1; \
             span seg 0 after 8 len 9 {TWO_RUN_NOT_JSON_GAP_DIGEST_HEX}; \
             digest {TWO_RUN_RUN1_DIGEST_HEX}"
        ),
    )
    .with_run_digest(TWO_RUN_RUN1_DIGEST);
    let resume7 = Finding::new(
        K::Resumed,
        Some(fx.s2.clone()),
        Some(2),
        Some(7),
        format!(
            "operator=operator reason=incident head=5:{HONEST_CP5_HASH_HEX} \
             gap=none lost_records=0 structural=valid"
        ),
    );
    let chain_run1 = Finding::new(
        K::ChainBroken,
        Some(fx.s3.clone()),
        Some(1),
        Some(10),
        format!("expected previous {TWO_RUN_E8_HASH_HEX}, found {TWO_RUN_R10_PREV_HEX}"),
    );
    let per_seg_run1 = Finding::new(
        K::SegmentStructure,
        Some(fx.s3.clone()),
        Some(1),
        Some(10),
        "expected first complete record to be a checkpoint".into(),
    );
    let seq_gap_run1 = Finding::new(
        K::SeqGap,
        Some(fx.s3.clone()),
        Some(1),
        Some(10),
        "missing seq 9..=9".into(),
    );
    let resume13 = Finding::new(
        K::Resumed,
        Some(fx.live.clone()),
        Some(2),
        Some(13),
        format!(
            "operator=operator reason=incident head=11:{TWO_RUN_CP11_HASH_HEX} \
             gap=none lost_records=0 structural=valid"
        ),
    );
    let uncovered = unlocated(K::UncoveredTail, None, "records seq 13..=13".into());
    let torn_write = Finding::new(
        K::TornWrite,
        Some(fx.s2.clone()),
        Some(4),
        None,
        format!("trailing gap lines 4..=4 (9 bytes), digest {TWO_RUN_NOT_JSON_GAP_DIGEST_HEX}"),
    );
    let unparsable = Finding::new(
        K::Unparsable,
        Some(fx.s2.clone()),
        Some(4),
        None,
        "CorruptTrail: Unparsable: invalid audit v1 OTLP line".into(),
    );
    [
        chain_run0,
        per_seg_run0,
        run_structure_run0,
        seq_gap_run0,
        run_structure_run1,
        resume7,
        chain_run1,
        per_seg_run1,
        seq_gap_run1,
        resume13,
        uncovered,
        torn_write,
        unparsable,
    ]
}

// =====================================================================
// Ruling 13-V4-d9 scoping security (ADR-0005 decision 11 l.957
// "the list is exact"). Two closed runs on one trail (see
// `build_two_run_fx`). An `accept-run` line for run 0 pins run 0's
// closing resume record and the run digest; the list of items 1-3
// promoted to `Accepted` must stay inside run 0's own segments
// (`first_segment..last_segment`, excluding the closer segment S2
// per ruling 13-V4-d9). The mirror row for run 1 asserts the dual:
// run 1's line accepts only run 1's items 1-3 and run 0's four S1
// findings keep their severity.
// =====================================================================
#[test]
fn two_runs_accept_run_0_promotes_only_run_0() {
    let fx = build_two_run_fx();
    let base = two_run_base_findings(&fx);
    let v = verifier()
        .accept_run(7, fx.resume7.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let [
        chain_run0,
        per_seg_run0,
        run_structure_run0,
        seq_gap_run0,
        run_structure_run1,
        resume7,
        chain_run1,
        per_seg_run1,
        seq_gap_run1,
        resume13,
        uncovered,
        torn_write,
        unparsable,
    ] = base;
    // Run 0's four findings at S1 line 1 seq 4 flip to `Accepted`
    // (stable sort keeps the engine's insertion order: per-seg
    // first, then SeqGap and ChainBroken from the seq-loop, then
    // the run-finding appended last). Run 1's run-finding at S2
    // line 1 seq 6 and its S3 items 1-3 findings keep their
    // severity.
    let expected = vec![
        literal_accepted(per_seg_run0, "alice", "ok"),
        literal_accepted(seq_gap_run0, "alice", "ok"),
        literal_accepted(chain_run0, "alice", "ok"),
        literal_accepted(run_structure_run0, "alice", "ok"),
        run_structure_run1,
        resume7,
        chain_run1,
        per_seg_run1,
        seq_gap_run1,
        resume13,
        uncovered,
        torn_write,
        unparsable,
    ];
    assert_findings(report.findings(), &expected, "two_runs_accept_run_0");
}

#[test]
fn two_runs_accept_run_1_promotes_only_run_1() {
    let fx = build_two_run_fx();
    let base = two_run_base_findings(&fx);
    let v = verifier()
        .accept_run(13, fx.resume13.hash(), TWO_RUN_RUN1_DIGEST, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let [
        chain_run0,
        per_seg_run0,
        run_structure_run0,
        seq_gap_run0,
        run_structure_run1,
        resume7,
        chain_run1,
        per_seg_run1,
        seq_gap_run1,
        resume13,
        uncovered,
        torn_write,
        unparsable,
    ] = base;
    // Run 1's run-finding (at S2 line 1 seq 6) and its three
    // items 1-3 findings on S3 flip to `Accepted`. Run 0's S1
    // findings keep their severity.
    let expected = vec![
        chain_run0,
        per_seg_run0,
        run_structure_run0,
        seq_gap_run0,
        literal_accepted(run_structure_run1, "alice", "ok"),
        resume7,
        literal_accepted(per_seg_run1, "alice", "ok"),
        literal_accepted(seq_gap_run1, "alice", "ok"),
        literal_accepted(chain_run1, "alice", "ok"),
        resume13,
        uncovered,
        torn_write,
        unparsable,
    ];
    assert_findings(report.findings(), &expected, "two_runs_accept_run_1");
}

// =====================================================================
// A1-style run fixture with an in-run `MmrMismatch` at cp5. Mirrors
// `rule2_tests::build_a1_wrong_cp5_root` so items 1-3 of ADR-0005
// decision 11 are all exercisable:
//   S0 (sealed) = [cp0, e1, e2]
//   S1 (sealed, headless) = [r4, cp5_bad_root]  -- in-run `MmrMismatch`
//   live (closer) = [cp6, resume7]
// The run digest matches `A1_DIGEST`; cp6 is the closing opening
// (honest fold) and its own `MmrMismatch` is never emitted here.
// =====================================================================

struct RunFx {
    _dir: Temp,
    dir: PathBuf,
    s1: PathBuf,
    live: PathBuf,
    cp6: Record,
    resume: Record,
}

fn build_run_fx() -> RunFx {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    put_segment(&d.0, 0, &[&cp0, &e1, &e2], &[]);
    let r4 = headless(&e2, 4);
    let fold = pushed(&mmr2, &r4);
    let cp5 = signed_cp_explicit(
        5,
        r4.hash(),
        fold.size(),
        RUNFX_CP5_BAD_ROOT,
        fold.peaks().to_vec(),
    );
    put_segment(&d.0, 1, &[&r4, &cp5], &[]);
    let fold6 = pushed(&fold, &cp5);
    let cp6 = signed_cp(6, cp5.hash(), &fold6);
    let resume = resume_decl(&cp6, 5, cp5.hash(), 5);
    // Pin the records' hashes against `pinned_literals_match` so the
    // constants used by the helpers above match this fixture's
    // walker-produced chain.
    assert_eq!(digest_string(&cp5.hash()), RUNFX_CP5_HASH_HEX, "runfx cp5");
    assert_eq!(digest_string(&cp6.hash()), RUNFX_CP6_HASH_HEX, "runfx cp6");
    assert_eq!(
        digest_string(&resume.hash()),
        RUNFX_RESUME7_HASH_HEX,
        "runfx resume7",
    );
    write_records(&d.0, &[&cp6, &resume]);
    let s1 = segment_path(&d.0, 1);
    let live = d.0.join("audit.jsonl");
    RunFx {
        dir: d.0.clone(),
        _dir: d,
        s1,
        live,
        cp6,
        resume,
    }
}

fn chain_broken_at_4(fx: &RunFx) -> Finding {
    Finding::new(
        K::ChainBroken,
        Some(fx.s1.clone()),
        Some(1),
        Some(4),
        format!("expected previous {E2_HASH_HEX}, found {R4_PREV_HEX}"),
    )
}
fn per_seg_structure(fx: &RunFx) -> Finding {
    Finding::new(
        K::SegmentStructure,
        Some(fx.s1.clone()),
        Some(1),
        Some(4),
        "expected first complete record to be a checkpoint".into(),
    )
}
fn run_structure(fx: &RunFx) -> Finding {
    let detail = format!("loss seq 4 first 3 count 1; digest {A1_DIGEST}");
    Finding::new(
        K::SegmentStructure,
        Some(fx.s1.clone()),
        Some(1),
        Some(4),
        detail,
    )
    .with_run_digest(A1_DIGEST_BYTES)
}
fn seq_gap(fx: &RunFx) -> Finding {
    Finding::new(
        K::SeqGap,
        Some(fx.s1.clone()),
        Some(1),
        Some(4),
        "missing seq 3..=3".into(),
    )
}
fn mmr_mismatch(fx: &RunFx) -> Finding {
    Finding::new(
        K::MmrMismatch,
        Some(fx.s1.clone()),
        Some(2),
        Some(5),
        format!(
            "expected size 4 root {HONEST_FOLD_ROOT_HEX}, \
             found size 4 root {RUNFX_CP5_BAD_ROOT_HEX}"
        ),
    )
}
fn resumed(fx: &RunFx) -> Finding {
    Finding::new(
        K::Resumed,
        Some(fx.live.clone()),
        Some(2),
        Some(7),
        format!(
            "operator=operator reason=incident head=5:{RUNFX_CP5_HASH_HEX} \
             gap=none lost_records=0 structural=valid"
        ),
    )
}
fn uncovered_tail() -> Finding {
    unlocated(K::UncoveredTail, None, "records seq 7..=7".into())
}

fn literal_accepted(original: Finding, by: &str, reason: &str) -> Finding {
    let kind = original.kind();
    let file = original.file().map(Path::to_path_buf);
    let line = original.line();
    let seq = original.seq();
    let detail = format!("accepted by {by}: {reason}; was: {}", original.detail());
    Finding::new(K::Accepted, file, line, seq, detail).with_accepted_kind(kind)
}

// =====================================================================
// ADR-0005 decision 11 l.956: the right line. Every item 1-3 finding
// becomes `Accepted` through one `accept-run` line that pins the
// run's closing resume record and the run digest. `Resumed` stays a
// warning until its own `accept Resumed` line.
// =====================================================================
#[test]
fn match_promotes_items_1_through_3() {
    let fx = build_run_fx();
    let v = verifier()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    // All 4 findings at (seq=4, s1, line=1) become `Accepted`, so
    // their kind-debug ties and the stable sort preserves the
    // engine's insertion order: per-segment SegmentStructure (from
    // file_findings), then SeqGap and ChainBroken (from the
    // seq-loop), then the run SegmentStructure (from fold_findings
    // appended last).
    let expected = vec![
        literal_accepted(per_seg_structure(&fx), "alice", "ok"),
        literal_accepted(seq_gap(&fx), "alice", "ok"),
        literal_accepted(chain_broken_at_4(&fx), "alice", "ok"),
        literal_accepted(run_structure(&fx), "alice", "ok"),
        literal_accepted(mmr_mismatch(&fx), "alice", "ok"),
        resumed(&fx),
        uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "run_match");
    // An accepted run's `run_digest()` is `None` (ruling 13-V8-d1
    // point 4); the digest survives in the `was:` tail text. Keep
    // this invariant on the literal row (one whole-list assertion
    // above; this follow-on is on the same report).
    let accepted_run = &report.findings()[3];
    assert_eq!(
        accepted_run.accepted_kind(),
        Some(K::SegmentStructure),
        "run finding promoted"
    );
    assert_eq!(accepted_run.run_digest(), None, "run_digest cleared");
    assert!(
        accepted_run.detail().contains(A1_DIGEST),
        "was: carries the digest",
    );
}

// =====================================================================
// With both `accept-run` AND `accept Resumed` present, plain verify
// passes and `--strict` passes. Pinned as a tuple so a regression
// in either predicate flips the row.
// =====================================================================
struct CoveredRunFx {
    _dir: Temp,
    dir: PathBuf,
    resume: Record,
}
fn build_covered_run_fx() -> CoveredRunFx {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    put_segment(&d.0, 0, &[&cp0, &e1, &e2], &[]);
    let r4 = headless(&e2, 4);
    let fold = pushed(&mmr2, &r4);
    let bad_root = [0x55; 32];
    let cp5 = signed_cp_explicit(5, r4.hash(), fold.size(), bad_root, fold.peaks().to_vec());
    put_segment(&d.0, 1, &[&r4, &cp5], &[]);
    let fold6 = pushed(&fold, &cp5);
    let cp6 = signed_cp(6, cp5.hash(), &fold6);
    let resume = resume_decl(&cp6, 5, cp5.hash(), 5);
    let fold8 = pushed(&pushed(&fold6, &cp6), &resume);
    let cp8 = signed_cp(8, resume.hash(), &fold8);
    write_records(&d.0, &[&cp6, &resume, &cp8]);
    CoveredRunFx {
        dir: d.0.clone(),
        _dir: d,
        resume,
    }
}

#[test]
fn match_with_both_lines_strict_passes() {
    // Whole list: five items 1-3 findings accepted + the Resumed
    // warning accepted. With both lines present and strict on, the
    // run is clean. Pin strict/non-strict after the list.
    let fx = build_covered_run_fx();
    let dir = fx.dir.clone();
    let s0 = segment_path(&dir, 0);
    let s1 = segment_path(&dir, 1);
    let live = dir.join("audit.jsonl");
    let v = verifier()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap()
        .accept(K::Resumed, 7, fx.resume.hash(), "alice", "ok")
        .unwrap();
    let report = report_of(vec![dir], v);
    let per_seg = |seg: &PathBuf, line: u64, seq: u64| {
        Finding::new(
            K::SegmentStructure,
            Some(seg.clone()),
            Some(line),
            Some(seq),
            "expected first complete record to be a checkpoint".into(),
        )
    };
    let chain = |seg: &PathBuf, line: u64, seq: u64, exp: [u8; 32], got: [u8; 32]| {
        Finding::new(
            K::ChainBroken,
            Some(seg.clone()),
            Some(line),
            Some(seq),
            format!(
                "expected previous {}, found {}",
                digest_string(&exp),
                digest_string(&got),
            ),
        )
    };
    let seqgap_at = |seg: &PathBuf, line: u64, seq: u64, a: u64, b: u64| {
        Finding::new(
            K::SeqGap,
            Some(seg.clone()),
            Some(line),
            Some(seq),
            format!("missing seq {a}..={b}"),
        )
    };
    let mmr = Finding::new(
        K::MmrMismatch,
        Some(s1.clone()),
        Some(2),
        Some(5),
        format!(
            "expected size 4 root blake3:8c89e5675d09a83557775acf82c200357f94447d60bf5d4a455b525cf04ff242, \
             found size 4 root {}",
            digest_string(&[0x55; 32]),
        ),
    );
    // Reproduce the hashes we need for literal pins. The covered-
    // run fixture uses the SAME bad_root=0x55 as `build_run_fx`,
    // so cp5's hash matches `build_run_fx`'s cp5 hash.
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    let r4 = headless(&e2, 4);
    let fold = pushed(&mmr2, &r4);
    let cp5 = signed_cp_explicit(5, r4.hash(), fold.size(), [0x55; 32], fold.peaks().to_vec());
    let run_structure_fx = Finding::new(
        K::SegmentStructure,
        Some(s1.clone()),
        Some(1),
        Some(4),
        format!("loss seq 4 first 3 count 1; digest {A1_DIGEST}"),
    )
    .with_run_digest(A1_DIGEST_BYTES);
    let resumed = Finding::new(
        K::Resumed,
        Some(live.clone()),
        Some(2),
        Some(7),
        format!(
            "operator=operator reason=incident head=5:{} gap=none lost_records=0 structural=valid",
            digest_string(&cp5.hash()),
        ),
    );
    let _ = (s0,); // S0 is sealed but not independently asserted.
    let expected = vec![
        literal_accepted(per_seg(&s1, 1, 4), "alice", "ok"),
        literal_accepted(seqgap_at(&s1, 1, 4, 3, 3), "alice", "ok"),
        literal_accepted(
            chain(&s1, 1, 4, e2.hash(), r4.context.previous),
            "alice",
            "ok",
        ),
        literal_accepted(run_structure_fx, "alice", "ok"),
        literal_accepted(mmr, "alice", "ok"),
        literal_accepted(resumed, "alice", "ok"),
    ];
    assert_findings(report.findings(), &expected, "both_lines_literal");
    assert_eq!(
        (report.is_valid(), report.is_strict_valid()),
        (true, true),
        "verify and --strict both pass",
    );
}

// =====================================================================
// ADR-0005 decision 11 l.956: a wrong digest, a wrong resume hash, a
// `seq` with no record, and a `seq` whose record is not a resume
// record each give `AcceptMismatch` with none of the run's findings
// `Accepted`. Each row asserts the full literal list.
// =====================================================================
#[test]
fn wrong_run_digest_gives_accept_mismatch() {
    let fx = build_run_fx();
    let v = verifier()
        .accept_run(7, fx.resume.hash(), WRONG_DIGEST, "alice", "stale")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        chain_broken_at_4(&fx),
        per_seg_structure(&fx),
        run_structure(&fx),
        seq_gap(&fx),
        mmr_mismatch(&fx),
        unlocated(
            K::AcceptMismatch,
            Some(7),
            format!(
                "accept-run seq 7 hash {}: run digest differs (run {A1_DIGEST})",
                digest_string(&fx.resume.hash())
            ),
        ),
        resumed(&fx),
        uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "wrong_digest");
}

#[test]
fn wrong_resume_hash_gives_accept_mismatch() {
    let fx = build_run_fx();
    let v = verifier()
        .accept_run(7, WRONG_HASH, A1_DIGEST_BYTES, "alice", "stale")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let tail = format!(
        "accept-run seq 7 hash {WRONG_HASH_HEX}: hash differs (record {})",
        digest_string(&fx.resume.hash())
    );
    let expected = vec![
        chain_broken_at_4(&fx),
        per_seg_structure(&fx),
        run_structure(&fx),
        seq_gap(&fx),
        mmr_mismatch(&fx),
        unlocated(K::AcceptMismatch, Some(7), tail),
        resumed(&fx),
        uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "wrong_hash");
}

#[test]
fn seq_with_no_record_gives_accept_mismatch() {
    let fx = build_run_fx();
    let v = verifier()
        .accept_run(99, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "stale")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let tail = format!(
        "accept-run seq 99 hash {}: no record",
        digest_string(&fx.resume.hash())
    );
    let expected = vec![
        chain_broken_at_4(&fx),
        per_seg_structure(&fx),
        run_structure(&fx),
        seq_gap(&fx),
        mmr_mismatch(&fx),
        resumed(&fx),
        unlocated(K::AcceptMismatch, Some(99), tail),
        uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "no_record");
}

#[test]
fn seq_at_non_resume_record_gives_accept_mismatch() {
    let fx = build_run_fx();
    // seq 6 holds cp6 (a checkpoint), not a resume record.
    let v = verifier()
        .accept_run(6, fx.cp6.hash(), A1_DIGEST_BYTES, "alice", "stale")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let tail = format!(
        "accept-run seq 6 hash {}: not a resume record",
        digest_string(&fx.cp6.hash())
    );
    let expected = vec![
        chain_broken_at_4(&fx),
        per_seg_structure(&fx),
        run_structure(&fx),
        seq_gap(&fx),
        mmr_mismatch(&fx),
        unlocated(K::AcceptMismatch, Some(6), tail),
        resumed(&fx),
        uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "not_resume");
}

// =====================================================================
// ADR-0005 decision 11 l.957: the list is exact. A `SeqGap` or
// `ChainBroken` whose `(file, seq)` does not match a loss point of
// the matched run keeps its severity -- even inside the trail
// (ruling 13-V4-d9 scopes the run's span to its own segments).
//
// The A3 layout has TWO loss points in one run: at r4 (seq=4,
// first=3, count=1) and at r7 (seq=7, first=6, count=1). An
// `accept-run` line for A3's resume (seq=11, hash matches) is
// expected to accept both loss points' `ChainBroken` + `SeqGap`.
// This row asserts literally that the two named `SeqGap` /
// `ChainBroken` findings become `Accepted` and nothing else.
// =====================================================================
#[test]
fn two_named_ranges_both_accepted_nothing_else() {
    let a = build_a3();
    let dir = a.dir_path.clone();
    let s1 = segment_path(&dir, 1);
    let s2 = segment_path(&dir, 2);
    let live = dir.join("audit.jsonl");
    // Recompute the resume's hash locally (fixture does not expose
    // it): the fixture builds cp10 + resume(head=8,lt=9).
    let (resume_hash, _resume_seq) = resume_hash_of_a3(&a);
    let v = verifier()
        .accept_run(11, resume_hash, A3_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![dir], v);
    let cb_at = |seg: &PathBuf, line: u64, seq: u64, exp_prev: [u8; 32], found: [u8; 32]| {
        Finding::new(
            K::ChainBroken,
            Some(seg.clone()),
            Some(line),
            Some(seq),
            format!(
                "expected previous {}, found {}",
                digest_string(&exp_prev),
                digest_string(&found),
            ),
        )
    };
    let per_seg = |seg: &PathBuf, line: u64, seq: u64| {
        Finding::new(
            K::SegmentStructure,
            Some(seg.clone()),
            Some(line),
            Some(seq),
            "expected first complete record to be a checkpoint".into(),
        )
    };
    let seq_gap_for = |seg: &PathBuf, line: u64, seq: u64, first: u64, last: u64| {
        Finding::new(
            K::SeqGap,
            Some(seg.clone()),
            Some(line),
            Some(seq),
            format!("missing seq {first}..={last}"),
        )
    };
    let run = Finding::new(
        K::SegmentStructure,
        Some(s1.clone()),
        Some(1),
        Some(4),
        format!("loss seq 4 first 3 count 1; loss seq 7 first 6 count 1; digest {A3_DIGEST}"),
    )
    .with_run_digest(A3_DIGEST_BYTES);
    let expected = vec![
        literal_accepted(per_seg(&s1, 1, 4), "alice", "ok"),
        literal_accepted(seq_gap_for(&s1, 1, 4, 3, 3), "alice", "ok"),
        literal_accepted(cb_at(&s1, 1, 4, a.cp2_hash, a.r4_previous), "alice", "ok"),
        literal_accepted(run, "alice", "ok"),
        literal_accepted(per_seg(&s2, 1, 7), "alice", "ok"),
        literal_accepted(seq_gap_for(&s2, 1, 7, 6, 6), "alice", "ok"),
        literal_accepted(cb_at(&s2, 1, 7, a.cp5_hash, a.r7_previous), "alice", "ok"),
        Finding::new(
            K::Resumed,
            Some(live.clone()),
            Some(2),
            Some(11),
            format!(
                "operator=operator reason=incident head=8:{} gap=9..=9 lost_records=0 structural=valid",
                digest_string(&cp8_hash_of_a3(&a))
            ),
        ),
        unlocated(K::UncoveredTail, None, "records seq 11..=11".into()),
    ];
    assert_findings(report.findings(), &expected, "a3_two_losses_accepted");
}

/// Recompute A3's resume record hash (resume_decl(cp10, 8, cp8.hash, 9))
/// so the row can pin it literally without widening the fixture API.
fn resume_hash_of_a3(_a: &crate::audit::runs_v4a_fixtures::A3) -> ([u8; 32], u64) {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    let r4 = headless(&cp2, 4);
    let mmr4 = pushed(&mmr2, &r4);
    let cp5 = signed_cp(5, r4.hash(), &mmr4);
    let mmr5 = pushed(&mmr4, &cp5);
    let r7 = headless(&cp5, 7);
    let mmr7 = pushed(&mmr5, &r7);
    let cp8 = signed_cp(8, r7.hash(), &mmr7);
    let mmr8 = pushed(&mmr7, &cp8);
    let cp10 = signed_cp(10, cp8.hash(), &mmr8);
    let resume = resume_decl(&cp10, 8, cp8.hash(), 9);
    (resume.hash(), resume.context.seq)
}

fn cp8_hash_of_a3(_a: &crate::audit::runs_v4a_fixtures::A3) -> [u8; 32] {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    let r4 = headless(&cp2, 4);
    let mmr4 = pushed(&mmr2, &r4);
    let cp5 = signed_cp(5, r4.hash(), &mmr4);
    let mmr5 = pushed(&mmr4, &cp5);
    let r7 = headless(&cp5, 7);
    let mmr7 = pushed(&mmr5, &r7);
    let cp8 = signed_cp(8, r7.hash(), &mmr7);
    cp8.hash()
}

// =====================================================================
// ADR-0005 decision 11 l.957 "only items 1-3 are promoted", on a
// real closed run (no violation). `build_run_fx` is a closed A1
// run with 5 items 1-3 findings, one `Resumed` warning and one
// `UncoveredTail`. The accept-run line matches: items 1-3 become
// `Accepted`, every other finding keeps its severity. Fails on
// base because items 1-3 stay as errors without the match.
// Whole-list literal.
// =====================================================================
#[test]
fn only_items_1_through_3_are_accepted() {
    let fx = build_run_fx();
    let v = verifier()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        literal_accepted(per_seg_structure(&fx), "alice", "ok"),
        literal_accepted(seq_gap(&fx), "alice", "ok"),
        literal_accepted(chain_broken_at_4(&fx), "alice", "ok"),
        literal_accepted(run_structure(&fx), "alice", "ok"),
        literal_accepted(mmr_mismatch(&fx), "alice", "ok"),
        resumed(&fx),
        uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "only_items_1_3");
    // Resumed stays a warning (not accepted) and UncoveredTail
    // stays an info. The list is exact: only items 1-3 are
    // promoted.
    let accepted_count = report
        .findings()
        .iter()
        .filter(|f| f.kind() == K::Accepted)
        .count();
    let unresolved_warnings: Vec<K> = report
        .findings()
        .iter()
        .filter(|f| f.severity() == super::Severity::Warning)
        .map(super::Finding::kind)
        .collect();
    assert_eq!((accepted_count, unresolved_warnings), (5, vec![K::Resumed]));
}

// =====================================================================
// ADR-0005 decision 11 l.957: validation at the builder. Each
// `InvalidConfig` message is pinned. A mutation at the shared `by`
// / duplicate-`seq` validator flips every row below together (the
// two validators live in one place in `verify/mod.rs`).
// =====================================================================
#[test]
fn empty_reviewer_gives_invalid_config() {
    let err = verifier()
        .accept_run(7, WRONG_HASH, EMPTY_RUN_DIGEST, "", "r")
        .unwrap_err();
    assert_eq!(
        (err.kind(), err.to_string()),
        (
            AuditErrorKind::InvalidConfig,
            "InvalidConfig: accept-run reviewer must be a single token (no whitespace or control bytes)".to_owned(),
        ),
    );
}
#[test]
fn space_in_reviewer_gives_invalid_config() {
    let err = verifier()
        .accept_run(7, WRONG_HASH, EMPTY_RUN_DIGEST, "al ice", "r")
        .unwrap_err();
    assert_eq!(
        (err.kind(), err.to_string()),
        (
            AuditErrorKind::InvalidConfig,
            "InvalidConfig: accept-run reviewer must be a single token (no whitespace or control bytes)".to_owned(),
        ),
    );
}
#[test]
fn empty_reason_gives_invalid_config() {
    let err = verifier()
        .accept_run(7, WRONG_HASH, EMPTY_RUN_DIGEST, "alice", "")
        .unwrap_err();
    assert_eq!(
        (err.kind(), err.to_string()),
        (
            AuditErrorKind::InvalidConfig,
            "InvalidConfig: accept-run reason must be a non-empty single line (no LF or CR)"
                .to_owned(),
        ),
    );
}
#[test]
fn duplicate_seq_gives_invalid_config() {
    let v = verifier()
        .accept_run(7, WRONG_HASH, EMPTY_RUN_DIGEST, "alice", "r")
        .unwrap();
    let err = v
        .accept_run(7, WRONG_HASH, EMPTY_RUN_DIGEST, "bob", "r2")
        .unwrap_err();
    assert_eq!(
        (err.kind(), err.to_string()),
        (
            AuditErrorKind::InvalidConfig,
            "InvalidConfig: duplicate accept-run for seq 7".to_owned(),
        ),
    );
}

#[test]
fn duplicate_seq_different_values_still_invalid_config() {
    // Second layout for the "duplicate seq" validator: the hash,
    // digest, reviewer and reason all differ -- only the `seq`
    // collides. The validator must still reject on the `seq`
    // alone.
    let v = verifier()
        .accept_run(42, WRONG_HASH, EMPTY_RUN_DIGEST, "alice", "ok")
        .unwrap();
    let err = v
        .accept_run(42, [0xEE; 32], [0xDD; 32], "bob", "later")
        .unwrap_err();
    assert_eq!(
        (err.kind(), err.to_string()),
        (
            AuditErrorKind::InvalidConfig,
            "InvalidConfig: duplicate accept-run for seq 42".to_owned(),
        ),
    );
}

// =====================================================================
// Ruling 13-V8-d1 point 8, clarification 13-V8-d1a: an `accept-run`
// line is set aside under the start rule ONLY when an accepted
// start exists, the line's `seq` is start + 1, and the verified
// set holds at that `seq` one unforked `vigil.audit.resume`
// record whose hash equals the line's and whose opening is the
// start. Every other `start + 1` line (the record there is not a
// resume, has another hash, opens from somewhere else, or is
// absent) falls through to normal matching. A layout `[cp0, e1,
// cp2]` with `start_from(cp0)` and `accept_run(1, e1.hash, …)`
// correctly reports `AcceptMismatch "not a resume record"`
// because `e1` is an entry, not a resume.
// =====================================================================
struct ProbeFx {
    _dir: Temp,
    dir: PathBuf,
    cp0: Record,
    e1_hash: [u8; 32],
}
fn build_probe_fx() -> ProbeFx {
    let d = Temp::new();
    // A small trail grounded at the genesis (a non-zero-seq cp0 hits
    // the writer's "checkpoint count must be positive" guard).
    // `[cp0, e1, cp2]` with `start_from(cp0)` and
    // `accept_run(1, e1.hash, …)`: e1 is an entry, not a resume,
    // and no run closes at cp0, so the fixed override does not
    // fire and the line falls through to `AcceptMismatch "not a
    // resume record"`.
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    write_records(&d.0, &[&cp0, &e1, &cp2]);
    let e1_hash = e1.hash();
    ProbeFx {
        dir: d.0.clone(),
        _dir: d,
        cp0,
        e1_hash,
    }
}

#[test]
fn start_plus_one_non_resume_gives_accept_mismatch() {
    // The probe fixture has `[cp0, e1, cp2]` with `start_from(cp0)`
    // and `accept_run(1, e1.hash, …)`. `e1` at `start + 1` is an
    // entry, not a resume, and its hash differs trivially from
    // nothing -- the override must not fire. Normal matching sees
    // the record at seq=1 as "not a resume record" (ADR-0005
    // decision 11), so the line is `AcceptMismatch`. Whole list.
    let fx = build_probe_fx();
    let v = verifier()
        .start_from(parse_cp(&fx.cp0))
        .accept_run(1, fx.e1_hash, A1_DIGEST_BYTES, "alice", "stale")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![unlocated(
        K::AcceptMismatch,
        Some(1),
        format!(
            "accept-run seq 1 hash {}: not a resume record",
            digest_string(&fx.e1_hash),
        ),
    )];
    assert_findings(report.findings(), &expected, "start_plus_one_non_resume");
    assert!(!report.is_valid(), "AcceptMismatch is Error");
}

#[test]
fn start_plus_one_wrong_hash_gives_accept_mismatch() {
    // Second layout for the same rule: `[cp0, e1, cp2]`,
    // `start_from(cp0)`, `accept_run(1, WRONG_HASH, …)`. The record
    // at seq=1 has e1's hash, which differs from `WRONG_HASH`, so
    // the shared match rule emits `AcceptMismatch "hash differs
    // (record X)"`. The override must still not fire: the line's
    // hash is not a resume hash at start + 1.
    let fx = build_probe_fx();
    let v = verifier()
        .start_from(parse_cp(&fx.cp0))
        .accept_run(1, WRONG_HASH, A1_DIGEST_BYTES, "alice", "stale")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![unlocated(
        K::AcceptMismatch,
        Some(1),
        format!(
            "accept-run seq 1 hash {WRONG_HASH_HEX}: hash differs (record {})",
            digest_string(&fx.e1_hash)
        ),
    )];
    assert_findings(report.findings(), &expected, "start_plus_one_wrong_hash");
    assert!(!report.is_valid(), "AcceptMismatch is Error");
}

// =====================================================================
// Shared fixture for the ruling 13-V4-d8 "after a violation" row.
// The A1 layout with a torn tail appended runs the walker into a
// violation (ruling 13-V4-d8 point 3), which empties the run
// index. The resume at seq=7 is still a parseable resume in
// `groups`. Consumed by `after_violation_gives_accept_mismatch`.
// =====================================================================
fn build_no_run_fx() -> NoRunFx {
    let a = build_a1();
    fs::OpenOptions::new()
        .append(true)
        .open(a.dir_path.join("audit.jsonl"))
        .unwrap()
        .write_all_vec(b"not json\n");
    let (resume_hash, resume_seq) = resume_of_a1();
    NoRunFx {
        dir: a.dir_path.clone(),
        _a: a,
        resume_hash,
        resume_seq,
    }
}
fn resume_of_a1() -> ([u8; 32], u64) {
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    let r4 = headless(&e2, 4);
    let fold = pushed(&mmr2, &r4);
    let cp5 = signed_cp(5, r4.hash(), &fold);
    let fold6 = pushed(&fold, &cp5);
    let cp6 = signed_cp(6, cp5.hash(), &fold6);
    let resume = resume_decl(&cp6, 5, cp5.hash(), 5);
    (resume.hash(), resume.context.seq)
}
struct NoRunFx {
    _a: crate::audit::runs_v4a_fixtures::A1,
    dir: PathBuf,
    resume_hash: [u8; 32],
    resume_seq: u64,
}

// =====================================================================
// ADR-0005 decision 11 "Laundering": a deletion AFTER the review
// changes the run's ranges, so the same `accept-run` line flips to
// `AcceptMismatch` and the exit code becomes 1. Main assertion is
// the second-report `AcceptMismatch`; no `is_valid()` precondition.
// =====================================================================
#[test]
fn laundering_after_match_flips_to_accept_mismatch() {
    // ADR-0005 decision 11 "Laundering": a deletion AFTER the review
    // changes the run's ranges and digest, so the same `accept-run`
    // line that previously matched now flips to `AcceptMismatch`
    // (post-deletion run index is empty: the line sees "no matching
    // run" and reports the digest-of-nothing). The deletion also
    // removes the pre-S1 records so the walker has no `prev_complete`
    // before r4, and emits no `ChainBroken` and no run-structure
    // `SegmentStructure` -- the per-segment `SegmentStructure` and
    // `SeqGap` at S1 remain. Whole literal list.
    let fx = build_run_fx();
    let s0 = segment_path(&fx.dir, 0);
    fs::remove_file(s0).unwrap();
    let v = verifier()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        per_seg_structure(&fx),
        Finding::new(
            K::SeqGap,
            Some(fx.s1.clone()),
            Some(1),
            Some(4),
            "missing seq 0..=3".into(),
        ),
        unlocated(
            K::AcceptMismatch,
            Some(7),
            format!(
                "accept-run seq 7 hash {RUNFX_RESUME7_HASH_HEX}: \
                 run digest differs (run {EMPTY_RUN_DIGEST_HEX})"
            ),
        ),
        resumed(&fx),
        uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "laundering_literal");
    assert!(!report.is_valid(), "AcceptMismatch after deletion is Error");
}

// =====================================================================
// Ruling 13-V4-d8: after a violation there are no runs, so an
// `accept-run` line with any digest is `AcceptMismatch`. Pin one
// `AcceptMismatch` at the resume seq, zero `Accepted`, and that
// the report is not valid.
// =====================================================================
#[test]
fn after_violation_gives_accept_mismatch() {
    // Ruling 13-V4-d8: an unparsable line in the live file is a
    // violation that empties the run set, so no `accept-run` line
    // can match. The run finding is suppressed; the per-segment
    // `SegmentStructure`, `SeqGap` and `ChainBroken` at S1 remain,
    // and the `accept-run` line reports `AcceptMismatch "run digest
    // differs (run <digest of nothing>)"` -- the line's digest is
    // `A1_DIGEST`, the empty run's digest is `EMPTY_RUN_DIGEST`.
    // Whole literal list.
    let fx = build_no_run_fx();
    let live = fx.dir.join("audit.jsonl");
    let s1 = segment_path(&fx.dir, 1);
    let v = verifier()
        .accept_run(
            fx.resume_seq,
            fx.resume_hash,
            A1_DIGEST_BYTES,
            "alice",
            "ok",
        )
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        Finding::new(
            K::ChainBroken,
            Some(s1.clone()),
            Some(1),
            Some(4),
            format!("expected previous {E2_HASH_HEX}, found {R4_PREV_HEX}"),
        ),
        Finding::new(
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            "expected first complete record to be a checkpoint".into(),
        ),
        Finding::new(
            K::SeqGap,
            Some(s1),
            Some(1),
            Some(4),
            "missing seq 3..=3".into(),
        ),
        unlocated(
            K::AcceptMismatch,
            Some(7),
            format!(
                "accept-run seq 7 hash {HONEST_RESUME7_HASH_HEX}: \
                 run digest differs (run {EMPTY_RUN_DIGEST_HEX})"
            ),
        ),
        Finding::new(
            K::Resumed,
            Some(live.clone()),
            Some(2),
            Some(7),
            format!(
                "operator=operator reason=incident head=5:{HONEST_CP5_HASH_HEX} \
                 gap=none lost_records=0 structural=valid"
            ),
        ),
        uncovered_tail(),
        Finding::new(
            K::TornWrite,
            Some(live.clone()),
            Some(3),
            None,
            format!("trailing gap lines 3..=3 (9 bytes), digest {TWO_RUN_NOT_JSON_GAP_DIGEST_HEX}"),
        ),
        Finding::new(
            K::Unparsable,
            Some(live),
            Some(3),
            None,
            "CorruptTrail: Unparsable: invalid audit v1 OTLP line".into(),
        ),
    ];
    assert_findings(report.findings(), &expected, "after_violation_literal");
    assert!(!report.is_valid(), "post-violation AcceptMismatch is Error");
}

// =====================================================================
// ADR-0005 decision 11 l.958 archive criterion / step 7: with
// `end_before` whose record is the closing opening plus its resume
// line, the run verifies with an end anchor; without the end anchor,
// the result is `UnanchoredEnd`.
// =====================================================================
#[test]
fn end_before_anchored_closes_run_at_resume() {
    // The `end_before` archive is `[cp6, resume7]`; its anchor is
    // cp6. With `accept_run(7, resume.hash, A1_DIGEST)`, every item
    // 1-3 of the A1 run becomes `Accepted`; the end record emits no
    // `UnanchoredEnd` (end is anchored); the resume line is part of
    // the end record so its location is stripped. Whole list.
    let fx = build_run_fx();
    let mut archive_bytes = line_bytes(&fx.cp6);
    archive_bytes.extend(line_bytes(&fx.resume));
    let archive = std::str::from_utf8(&archive_bytes)
        .unwrap()
        .trim_end_matches('\n')
        .to_owned();
    let end_anchor = parse_cp(&fx.cp6);
    let s0 = segment_path(&fx.dir, 0);
    let v = verifier()
        .end_before(&archive, Some(end_anchor))
        .unwrap()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![s0, fx.s1.clone()], v);
    let expected = vec![
        literal_accepted(per_seg_structure(&fx), "alice", "ok"),
        literal_accepted(seq_gap(&fx), "alice", "ok"),
        literal_accepted(chain_broken_at_4(&fx), "alice", "ok"),
        literal_accepted(run_structure(&fx), "alice", "ok"),
        literal_accepted(mmr_mismatch(&fx), "alice", "ok"),
        unlocated(
            K::Resumed,
            Some(7),
            format!(
                "operator=operator reason=incident head=5:{RUNFX_CP5_HASH_HEX} \
                 gap=none lost_records=0 structural=valid"
            ),
        ),
        uncovered_tail(),
    ];
    assert_findings(
        report.findings(),
        &expected,
        "end_before_anchored_run_accepted",
    );
    assert!(
        report.is_valid(),
        "verify passes with every item 1-3 accepted"
    );
}

#[test]
fn end_before_unanchored_gives_unanchored_end() {
    // Without the end anchor, the end record is `UnanchoredEnd`.
    // Whole-list literal (ruling 13-V6-d7 points 2-3): the
    // unlocated `UnanchoredEnd` sits alongside every item 1-3
    // Accepted and nothing else fires.
    let fx = build_run_fx();
    let mut archive_bytes = line_bytes(&fx.cp6);
    archive_bytes.extend(line_bytes(&fx.resume));
    let archive = std::str::from_utf8(&archive_bytes)
        .unwrap()
        .trim_end_matches('\n')
        .to_owned();
    let s0 = segment_path(&fx.dir, 0);
    let v = verifier()
        .end_before(&archive, None)
        .unwrap()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![s0, fx.s1.clone()], v);
    let expected = vec![
        literal_accepted(per_seg_structure(&fx), "alice", "ok"),
        literal_accepted(seq_gap(&fx), "alice", "ok"),
        literal_accepted(chain_broken_at_4(&fx), "alice", "ok"),
        literal_accepted(run_structure(&fx), "alice", "ok"),
        literal_accepted(mmr_mismatch(&fx), "alice", "ok"),
        unlocated(
            K::UnanchoredEnd,
            Some(6),
            "end_before seq 6: no end anchor".into(),
        ),
        // The resume is part of the end record (ruling 13-V6-d4
        // point 6), so its location is stripped before sort.
        unlocated(
            K::Resumed,
            Some(7),
            format!(
                "operator=operator reason=incident head=5:{RUNFX_CP5_HASH_HEX} \
                 gap=none lost_records=0 structural=valid"
            ),
        ),
        uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "unanchored_end_run_accepted");
    assert!(!report.is_valid(), "UnanchoredEnd is Error, exit 1");
}

// =====================================================================
// Ruling 13-V8-d1 point 8, clarification 13-V8-d1a: an `accept-run`
// line whose `seq` is start + 1 is set aside under the start rule
// exactly when the verified set holds at that `seq` one unforked
// `vigil.audit.resume` record whose hash equals the line's and
// whose opening is the start. The run such a line closes lies
// wholly below the start and is never in the run index -- so the
// override consults the merged records at `start + 1` alone.
// =====================================================================

/// Live-only archive: the live file holds the closing opening +
/// its resume, every segment of the run that closed at the start
/// lies below the verified set. `cp6`'s declared `(size, root,
/// peaks)` are self-consistent (`CheckpointFields::new`), so the
/// fold classifier reads them as `Base` and emits no
/// `MmrMismatch`.
struct ArchiveStartFx {
    _dir: Temp,
    dir: PathBuf,
    live: PathBuf,
    cp6: Record,
    resume: Record,
    cp5_hash: [u8; 32],
}
fn build_archive_start_fx() -> ArchiveStartFx {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    let r4 = headless(&e2, 4);
    let fold = pushed(&mmr2, &r4);
    let cp5 = signed_cp(5, r4.hash(), &fold);
    let fold6 = pushed(&fold, &cp5);
    let cp6 = signed_cp(6, cp5.hash(), &fold6);
    let resume = resume_decl(&cp6, 5, cp5.hash(), 5);
    // The archive is just the live file: the closed run lies below
    // this set and only the closing opening + its resume are read.
    write_records(&d.0, &[&cp6, &resume]);
    let live = d.0.join("audit.jsonl");
    ArchiveStartFx {
        dir: d.0.clone(),
        _dir: d,
        live,
        cp5_hash: cp5.hash(),
        cp6,
        resume,
    }
}

fn archive_resumed_finding(fx: &ArchiveStartFx) -> Finding {
    // The archive sees the closing opening + its resume alone; the
    // run's head (cp5) sits below the verified set, so the Resumed
    // declaration is `structural=invalid(head-not-present)`.
    Finding::new(
        K::Resumed,
        Some(fx.live.clone()),
        Some(2),
        Some(7),
        format!(
            "operator=operator reason=incident head=5:{} gap=none lost_records=0 structural=invalid(head-not-present)",
            digest_string(&fx.cp5_hash)
        ),
    )
}
fn archive_uncovered_tail() -> Finding {
    unlocated(K::UncoveredTail, None, "records seq 7..=7".into())
}

#[test]
fn archive_start_anchored_sets_aside_as_out_of_range() {
    // The archive start, anchored: live `[cp6, resume7]`,
    // anchor(cp6), start_from(cp6), the correct line. Override at
    // start + 1 fires: resume at seq=7 has hash=resume.hash and
    // previous=cp6.hash, so the line is set aside under the start
    // rule as `OutOfRange`. The run digest on the line is never
    // consulted. Report is valid (OutOfRange is Info).
    let fx = build_archive_start_fx();
    let v = verifier()
        .anchor(parse_cp(&fx.cp6))
        .start_from(parse_cp(&fx.cp6))
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        unlocated(
            K::OutOfRange,
            Some(7),
            format!(
                "accept-run seq 7 hash {}: below start seq 6",
                digest_string(&fx.resume.hash())
            ),
        ),
        archive_resumed_finding(&fx),
        archive_uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "archive_start_anchored");
    assert!(report.is_valid(), "OutOfRange is Info, report stays valid");
}

#[test]
fn archive_start_unanchored_sets_aside_as_unanchored_start() {
    // The same, unanchored: no `anchor(cp6)`. The override still
    // fires but the start is not anchored, so the kind flips to
    // `UnanchoredStart` (Error). Report is not valid.
    let fx = build_archive_start_fx();
    let v = verifier()
        .start_from(parse_cp(&fx.cp6))
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        unlocated(
            K::UnanchoredStart,
            Some(7),
            format!(
                "accept-run seq 7 hash {}: below start seq 6",
                digest_string(&fx.resume.hash())
            ),
        ),
        archive_resumed_finding(&fx),
        archive_uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "archive_start_unanchored");
    assert!(!report.is_valid(), "UnanchoredStart is Error");
}

/// Second layout: the start sits at a different seq (`cp1`
/// instead of `cp6`), with only the live file `[cp1, resume2]` in
/// the verified set. The rule is seq-agnostic: the override still
/// fires through the record-at-start-plus-one check alone.
struct ArchiveStartCp1Fx {
    _dir: Temp,
    dir: PathBuf,
    live: PathBuf,
    cp1: Record,
    resume: Record,
    cp0_hash: [u8; 32],
}
fn build_archive_start_cp1_fx() -> ArchiveStartCp1Fx {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let cp1 = signed_cp(1, cp0.hash(), &mmr0);
    let resume = resume_decl(&cp1, 0, cp0.hash(), 0);
    // Live-only: the prior segment lies below the verified set; the
    // start rule still demands the start to be the first record
    // seen (start::check), so cp0 stays off-disk.
    write_records(&d.0, &[&cp1, &resume]);
    let live = d.0.join("audit.jsonl");
    ArchiveStartCp1Fx {
        dir: d.0.clone(),
        _dir: d,
        live,
        cp0_hash: cp0.hash(),
        cp1,
        resume,
    }
}

#[test]
fn archive_start_at_cp1_sets_aside_as_out_of_range() {
    // A second layout for the same rule. Start = cp1 (seq=1),
    // resume at seq=2, with cp0 sealed below the start. Override
    // fires regardless of which seq the start sits at.
    let fx = build_archive_start_cp1_fx();
    let v = verifier()
        .anchor(parse_cp(&fx.cp1))
        .start_from(parse_cp(&fx.cp1))
        .accept_run(2, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        unlocated(
            K::OutOfRange,
            Some(2),
            format!(
                "accept-run seq 2 hash {}: below start seq 1",
                digest_string(&fx.resume.hash())
            ),
        ),
        Finding::new(
            K::Resumed,
            Some(fx.live.clone()),
            Some(2),
            Some(2),
            format!(
                "operator=operator reason=incident head=0:{} gap=none lost_records=0 structural=invalid(head-not-present)",
                digest_string(&fx.cp0_hash)
            ),
        ),
        unlocated(K::UncoveredTail, None, "records seq 2..=2".into()),
    ];
    assert_findings(report.findings(), &expected, "archive_start_cp1");
    assert!(report.is_valid(), "OutOfRange is Info");
}

#[test]
fn wrong_hash_at_start_plus_one_gives_accept_mismatch() {
    // Wrong hash at start + 1: the record at `start + 1` is a real
    // resume, but the line's hash differs. The override reads the
    // line's hash and refuses to fire; the line falls through to
    // the shared receipt match rule which reports "hash differs
    // (record X)". A bogus line never clears an error.
    let fx = build_archive_start_fx();
    let v = verifier()
        .anchor(parse_cp(&fx.cp6))
        .start_from(parse_cp(&fx.cp6))
        .accept_run(7, WRONG_HASH, A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        unlocated(
            K::AcceptMismatch,
            Some(7),
            format!(
                "accept-run seq 7 hash {WRONG_HASH_HEX}: hash differs (record {HONEST_RESUME7_HASH_HEX})"
            ),
        ),
        archive_resumed_finding(&fx),
        archive_uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "wrong_hash_at_start_plus_one");
    assert!(!report.is_valid(), "AcceptMismatch is Error");
}

#[test]
fn wrong_hash_at_start_plus_one_cp1_gives_accept_mismatch() {
    // Second layout for the same rule (ruling 13-V8-d1a): start
    // = cp1 (seq=1), resume at seq=2, with cp0 off-disk. The
    // override reads the line's hash and refuses to fire when it
    // differs from the record's; the line falls through to the
    // shared receipt match rule's `hash differs` arm. Different
    // seq from the cp6 layout above so the row is seq-agnostic.
    let fx = build_archive_start_cp1_fx();
    let v = verifier()
        .anchor(parse_cp(&fx.cp1))
        .start_from(parse_cp(&fx.cp1))
        .accept_run(2, WRONG_HASH, A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        unlocated(
            K::AcceptMismatch,
            Some(2),
            format!(
                "accept-run seq 2 hash {WRONG_HASH_HEX}: hash differs (record {SHORT_RESUME_HASH_HEX})"
            ),
        ),
        Finding::new(
            K::Resumed,
            Some(fx.live.clone()),
            Some(2),
            Some(2),
            format!(
                "operator=operator reason=incident head=0:{CP0_HASH_HEX} \
                 gap=none lost_records=0 structural=invalid(head-not-present)"
            ),
        ),
        unlocated(K::UncoveredTail, None, "records seq 2..=2".into()),
    ];
    assert_findings(
        report.findings(),
        &expected,
        "wrong_hash_at_start_plus_one_cp1",
    );
    assert!(!report.is_valid(), "AcceptMismatch is Error");
}

// =====================================================================
// Ruling 13-V8-d1a: the override is gated on the record's opening
// matching the start (`record.previous == start.hash()`). A
// hand-built trail whose `start + 1` resume opens from a different
// checkpoint is used only because the writer cannot produce this
// layout (the writer always sets `resume.previous` to the closing
// opening). When the opening check is in place, the override does
// not fire and the `accept-run` line falls through to normal
// matching, which reports `AcceptMismatch`. Removing the opening
// check would flip this row's `AcceptMismatch` to `OutOfRange`.
// =====================================================================
struct HandBuiltResumeFx {
    _dir: Temp,
    dir: PathBuf,
    live: PathBuf,
    cp6_real: Record,
    resume_alt: Record,
}
fn build_hand_built_resume_fx() -> HandBuiltResumeFx {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    let r4 = headless(&e2, 4);
    let fold = pushed(&mmr2, &r4);
    let cp5 = signed_cp(5, r4.hash(), &fold);
    let fold6 = pushed(&fold, &cp5);
    let cp6_real = signed_cp(6, cp5.hash(), &fold6);
    // Hand-built cp6_alt at seq=6 whose previous is cp0.hash() (not
    // cp5.hash()), signed with the same key so parse succeeds. The
    // resume built against cp6_alt declares `previous = cp6_alt.hash()`
    // which differs from `cp6_real.hash()` -- this layout is not
    // producible by the writer, which always makes resume's previous
    // equal to the closing opening it follows on the trail.
    let cp6_alt = signed_cp(6, cp0.hash(), &mmr0);
    assert_ne!(cp6_alt.hash(), cp6_real.hash(), "cp6_alt differs from real");
    let resume_alt = resume_decl(&cp6_alt, 5, cp5.hash(), 5);
    assert_ne!(
        resume_alt.context.previous,
        cp6_real.hash(),
        "resume_alt.previous != cp6_real.hash",
    );
    // Live-only: cp6_real + resume_alt, start_from(cp6_real).
    write_records(&d.0, &[&cp6_real, &resume_alt]);
    let live = d.0.join("audit.jsonl");
    HandBuiltResumeFx {
        dir: d.0.clone(),
        _dir: d,
        live,
        cp6_real,
        resume_alt,
    }
}

#[test]
fn start_plus_one_resume_whose_opening_is_not_the_start_is_accept_mismatch() {
    // Hand-built fixture (ruling 13-V8-d1a; the writer cannot
    // produce this layout, so this fixture is the only parseable
    // trail that reaches the override's opening check): the
    // record at start + 1 is a resume, but its opening
    // (`previous`) is not the start. The override's opening
    // check refuses to fire, and the line goes through normal
    // matching. No run in the index names this resume, so the
    // match reports `AcceptMismatch "run digest differs (run
    // <digest of nothing>)"`.
    let fx = build_hand_built_resume_fx();
    let v = verifier()
        .start_from(parse_cp(&fx.cp6_real))
        .accept_run(7, fx.resume_alt.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    // Pin the hand-built hashes against the consistency test on
    // this fixture so a drift in `signed_cp` / `resume_decl`
    // flips the expected literals here first.
    assert_eq!(
        digest_string(&fx.cp6_real.hash()),
        HONEST_CP6_HASH_HEX,
        "hand-built cp6_real",
    );
    assert_eq!(
        digest_string(&fx.resume_alt.hash()),
        HAND_BUILT_RESUME_ALT_HASH_HEX,
        "hand-built resume_alt",
    );
    assert_eq!(
        digest_string(&fx.resume_alt.context.previous),
        HAND_BUILT_CP6_ALT_HASH_HEX,
        "hand-built cp6_alt (resume_alt.previous)",
    );
    let expected = vec![
        unlocated(
            K::AcceptMismatch,
            Some(7),
            format!(
                "accept-run seq 7 hash {HAND_BUILT_RESUME_ALT_HASH_HEX}: \
                 run digest differs (run {EMPTY_RUN_DIGEST_HEX})"
            ),
        ),
        Finding::new(
            K::ChainBroken,
            Some(fx.live.clone()),
            Some(2),
            Some(7),
            format!("expected previous {HONEST_CP6_HASH_HEX}, found {HAND_BUILT_CP6_ALT_HASH_HEX}"),
        ),
        Finding::new(
            K::Resumed,
            Some(fx.live),
            Some(2),
            Some(7),
            format!(
                "operator=operator reason=incident head=5:{HONEST_CP5_HASH_HEX} \
                 gap=none lost_records=0 structural=invalid(head-not-present)"
            ),
        ),
        unlocated(K::UncoveredTail, None, "records seq 7..=7".into()),
    ];
    assert_findings(
        report.findings(),
        &expected,
        "start_plus_one_mismatched_opening",
    );
    assert!(!report.is_valid(), "AcceptMismatch is Error");
}

// =====================================================================
// Ruling 13-V8-d1 FORK 4: a forked `seq` is `AcceptMismatch
// "... seq is forked"`. Also pins that `SeqConflict` is emitted at
// the forked seq.
// =====================================================================
#[test]
fn forked_seq_gives_accept_mismatch_and_seq_conflict() {
    // Two records at seq=7 with distinct hashes (the trail's own
    // resume `(head=5, lost_through=5)`, plus a sibling copy at
    // `(head=5, lost_through=4)`). The merge groups both hashes at
    // seq=7 so `conflicting_seqs ⊇ {7}` and the shared match rule
    // emits `AcceptMismatch "... seq is forked"`. No items 1-3 of
    // the A1 run are promoted. Whole literal list.
    let fx = build_run_fx();
    let sibling_path = fx.dir.join("audit-shipped-copy.jsonl");
    // The main resume `resume_decl(cp6, 5, cp5.hash, 5)` declares
    // `head=5:cp5.hash, lost_through=5`; the alternate differs
    // only in `lost_through=4`, so the two hashes form a fork at
    // seq=7.
    let cp5_bad_hash = hex_to_bytes(RUNFX_CP5_HASH_HEX.strip_prefix("blake3:").unwrap());
    let alt_resume = resume_decl(&fx.cp6, 5, cp5_bad_hash, 4);
    assert_eq!(
        digest_string(&alt_resume.hash()),
        FORKED_ALT_RESUME_HEX,
        "forked alt resume",
    );
    assert_ne!(alt_resume.hash(), fx.resume.hash(), "distinct hashes");
    fs::write(&sibling_path, line_bytes(&alt_resume)).unwrap();
    let v = verifier()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone(), sibling_path.clone()], v);
    let expected = vec![
        chain_broken_at_4(&fx),
        per_seg_structure(&fx),
        run_structure(&fx),
        seq_gap(&fx),
        mmr_mismatch(&fx),
        unlocated(
            K::AcceptMismatch,
            Some(7),
            format!("accept-run seq 7 hash {RUNFX_RESUME7_HASH_HEX}: seq is forked"),
        ),
        Finding::new(
            K::Resumed,
            Some(sibling_path.clone()),
            Some(1),
            Some(7),
            "malformed declaration".into(),
        ),
        Finding::new(
            K::SeqConflict,
            Some(sibling_path),
            Some(1),
            Some(7),
            format!("conflicting hashes: {RUNFX_RESUME7_HASH_HEX}, {FORKED_ALT_RESUME_HEX}"),
        ),
        resumed(&fx),
        uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "forked_seq_literal");
    assert!(!report.is_valid(), "AcceptMismatch is Error");
}

// =====================================================================
// ADR-0005 decision 11 "No run" honest row: a nothing-lost resume
// over an A8-style closed run, with the empty-run digest, is
// `AcceptUnused` (info). Any other digest is `AcceptMismatch`. The
// fixture is NOT a violation fixture -- the walker reaches the run
// honestly and `run_digest()` equals the digest of nothing because
// the run has no ranges and no spans.
// =====================================================================
/// Honest no-run layout: live = `[cp0, resume1]` where `resume1`
/// declares nothing lost (head=0, lost_through=0). `cp0` is the
/// genesis-adjacent first record and there is no closing opening
/// before it, so the classifier emits no closed run. The resume
/// still parses honestly (not a violation), and
/// `accept_run(1, resume1.hash, digest_of_nothing)` hits the "no
/// run" branch -> `AcceptUnused`.
struct HonestNoRunFx {
    _dir: Temp,
    dir: PathBuf,
    live: PathBuf,
    resume: Record,
    cp0_hash: [u8; 32],
}
fn build_honest_no_run_fx() -> HonestNoRunFx {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let resume = resume_decl(&cp0, 0, cp0.hash(), 0);
    write_records(&d.0, &[&cp0, &resume]);
    let dir = d.0.clone();
    let live = dir.join("audit.jsonl");
    HonestNoRunFx {
        dir,
        _dir: d,
        live,
        cp0_hash: cp0.hash(),
        resume,
    }
}

fn honest_no_run_resumed(fx: &HonestNoRunFx) -> Finding {
    // A resume that opens without a closing-opening checkpoint
    // before it is `structural=invalid(no-opening)`: the record
    // parses honestly, but the classifier does not recognise it as
    // closing any run.
    Finding::new(
        K::Resumed,
        Some(fx.live.clone()),
        Some(2),
        Some(1),
        format!(
            "operator=operator reason=incident head=0:{} gap=none lost_records=0 structural=invalid(no-opening)",
            digest_string(&fx.cp0_hash)
        ),
    )
}

#[test]
fn honest_no_run_with_empty_digest_gives_accept_unused() {
    let fx = build_honest_no_run_fx();
    let v = verifier()
        .accept_run(1, fx.resume.hash(), EMPTY_RUN_DIGEST, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        unlocated(
            K::AcceptUnused,
            Some(1),
            format!(
                "accept-run seq 1 hash {}: no matching run",
                digest_string(&fx.resume.hash())
            ),
        ),
        honest_no_run_resumed(&fx),
        unlocated(K::UncoveredTail, None, "records seq 1..=1".into()),
    ];
    assert_findings(report.findings(), &expected, "honest_no_run_empty");
    assert!(report.is_valid(), "AcceptUnused is Info");
}

#[test]
fn honest_no_run_with_other_digest_gives_accept_mismatch() {
    let fx = build_honest_no_run_fx();
    let v = verifier()
        .accept_run(1, fx.resume.hash(), WRONG_DIGEST, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        unlocated(
            K::AcceptMismatch,
            Some(1),
            format!(
                "accept-run seq 1 hash {}: run digest differs (run {EMPTY_RUN_DIGEST_HEX})",
                digest_string(&fx.resume.hash())
            ),
        ),
        honest_no_run_resumed(&fx),
        unlocated(K::UncoveredTail, None, "records seq 1..=1".into()),
    ];
    assert_findings(report.findings(), &expected, "honest_no_run_wrong");
    assert!(!report.is_valid(), "AcceptMismatch is Error");
}

// =====================================================================
// Ruling 13-V8-d1 FORK 5: an `accept-run` line inside a confirmed
// resume gap is `LostRecord` (receipt + accept-Resumed confirmation
// variants). The gap is confirmed, so the line is lost, not
// mismatched; the subject is still the full `accept-run` subject.
// =====================================================================
#[test]
fn accept_run_inside_gap_confirmed_by_receipt_is_lost_record() {
    // A3's resume at seq=11 declares a `9..=9` gap. A receipt at
    // `(11, A3_RESUME_HASH)` confirms the gap (ruling 13-V7-d1
    // point 8). An `accept-run` line at seq=9 (inside the gap) is
    // then demoted to `LostRecord` under the shared gap rule --
    // the gap is CONFIRMED (not merely declared), so the line is
    // "lost" rather than "mismatched". `NoReceipt` findings fire
    // for every seq without a receipt. Whole literal list.
    let a = build_a3();
    let dir = a.dir_path.clone();
    let s0 = segment_path(&dir, 0);
    let s1 = segment_path(&dir, 1);
    let s2 = segment_path(&dir, 2);
    let live = dir.join("audit.jsonl");
    let v = verifier()
        .receipts([(11, A3_RESUME_HASH)])
        .accept_run(9, WRONG_HASH, EMPTY_RUN_DIGEST, "alice", "ok")
        .unwrap();
    let report = report_of(vec![dir], v);
    let no_receipt = |file: PathBuf, line: u64, seq: u64, hash_hex: &str| {
        Finding::new(
            K::NoReceipt,
            Some(file),
            Some(line),
            Some(seq),
            format!("no receipt for seq {seq} hash {hash_hex}"),
        )
    };
    let expected = vec![
        no_receipt(s0.clone(), 2, 1, PROBE_E1_HASH_HEX),
        Finding::new(
            K::ChainBroken,
            Some(s1.clone()),
            Some(1),
            Some(4),
            format!("expected previous {A3_CP2_HASH_HEX}, found {A3_R4_PREV_HEX}"),
        ),
        no_receipt(s1.clone(), 1, 4, A3_R4_HASH_HEX),
        Finding::new(
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            "expected first complete record to be a checkpoint".into(),
        ),
        Finding::new(
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            format!("loss seq 4 first 3 count 1; loss seq 7 first 6 count 1; digest {A3_DIGEST}"),
        )
        .with_run_digest(A3_DIGEST_BYTES),
        Finding::new(
            K::SeqGap,
            Some(s1),
            Some(1),
            Some(4),
            "missing seq 3..=3".into(),
        ),
        Finding::new(
            K::ChainBroken,
            Some(s2.clone()),
            Some(1),
            Some(7),
            format!("expected previous {A3_CP5_HASH_HEX}, found {A3_R7_PREV_HEX}"),
        ),
        no_receipt(s2.clone(), 1, 7, A3_R7_HASH_HEX),
        Finding::new(
            K::SegmentStructure,
            Some(s2.clone()),
            Some(1),
            Some(7),
            "expected first complete record to be a checkpoint".into(),
        ),
        Finding::new(
            K::SeqGap,
            Some(s2),
            Some(1),
            Some(7),
            "missing seq 6..=6".into(),
        ),
        unlocated(
            K::LostRecord,
            Some(9),
            format!("accept-run seq 9 hash {WRONG_HASH_HEX}: lost in gap 9..=9"),
        ),
        Finding::new(
            K::Resumed,
            Some(live),
            Some(2),
            Some(11),
            format!(
                "operator=operator reason=incident head=8:{A3_CP8_HASH_HEX} \
                 gap=9..=9 lost_records=1 structural=valid"
            ),
        ),
        unlocated(K::UncoveredTail, None, "records seq 11..=11".into()),
    ];
    assert_findings(report.findings(), &expected, "lost_record_receipt_literal");
}

// =====================================================================
// ADR-0005 decision 11 `accept-run` l.957 "the list is exact":
// a `SeqGap` and a `ChainBroken` on a SEGMENT AFTER the run's
// closer (ruling 13-V4-d9: the closer segment belongs to the
// next run; anything beyond it is outside this run's scope) keep
// their severity even when the matching `accept-run` line
// accepts items 1-3. On A1, append an `entry_rec(9, GARBAGE)` to
// the live file so the walker reports SeqGap(8..=8) and
// ChainBroken at seq=9 on the closer segment, OUTSIDE the
// accepted run. Items 1-3 become `Accepted`; the extra findings
// stay as errors.
// =====================================================================
/// Variant of `build_run_fx` where `cp6`'s declared root is also
/// bad, so the fold classifier reports `MmrMismatch` at cp6 (the
/// closing opening). The run's `accept-run` line must NOT
/// promote this `MmrMismatch`: ruling 13-V8-d1 (`accept-run`) /
/// ADR-0005 decision 11 say the closing opening's `MmrMismatch`
/// is never accepted. The fixture witnesses the equivalence
/// argument: an honest trail cannot carry a matchable run
/// alongside a mismatched closing opening.
struct BadCp6Fx {
    _dir: Temp,
    dir: PathBuf,
    live: PathBuf,
    resume: Record,
}
fn build_bad_cp6_fx() -> BadCp6Fx {
    let d = Temp::new();
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let e2 = entry_rec(2, e1.hash());
    let mmr2 = pushed(&mmr1, &e2);
    put_segment(&d.0, 0, &[&cp0, &e1, &e2], &[]);
    let r4 = headless(&e2, 4);
    let fold = pushed(&mmr2, &r4);
    let bad5 = [0x55; 32];
    let cp5 = signed_cp_explicit(5, r4.hash(), fold.size(), bad5, fold.peaks().to_vec());
    put_segment(&d.0, 1, &[&r4, &cp5], &[]);
    let fold6 = pushed(&fold, &cp5);
    let bad6 = [0xAA; 32];
    let cp6 = signed_cp_explicit(6, cp5.hash(), fold6.size(), bad6, fold6.peaks().to_vec());
    let resume = resume_decl(&cp6, 5, cp5.hash(), 5);
    write_records(&d.0, &[&cp6, &resume]);
    let dir = d.0.clone();
    let live = dir.join("audit.jsonl");
    BadCp6Fx {
        dir,
        _dir: d,
        live,
        resume,
    }
}

#[test]
fn closing_opening_mmr_mismatch_fixture_closes_no_run() {
    // cp6 is the closing opening; its own declared root is also
    // bad (0xAA), so the fold classifier reports `Differs` at
    // cp6. Under the walker's violation rule (ruling 13-V4-d8
    // point 3 / ADR-0005 decision 5 amendment 6 (iii)), `Differs`
    // at a checkpoint empties the run set, so the `accept-run`
    // line cannot match -- it reports `AcceptMismatch "run digest
    // differs (run <digest of nothing>)"`. The cp6 `MmrMismatch`
    // and every per-walker finding keep their severity. This
    // writer-built fixture witnesses that no honest trail places
    // a cp6 `MmrMismatch` alongside a matchable run. Whole
    // literal list.
    let fx = build_bad_cp6_fx();
    let s0 = segment_path(&fx.dir, 0);
    let _ = s0;
    let s1 = segment_path(&fx.dir, 1);
    let v = verifier()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone()], v);
    let expected = vec![
        Finding::new(
            K::ChainBroken,
            Some(s1.clone()),
            Some(1),
            Some(4),
            format!("expected previous {E2_HASH_HEX}, found {R4_PREV_HEX}"),
        ),
        Finding::new(
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            "expected first complete record to be a checkpoint".into(),
        ),
        Finding::new(
            K::SeqGap,
            Some(s1.clone()),
            Some(1),
            Some(4),
            "missing seq 3..=3".into(),
        ),
        Finding::new(
            K::MmrMismatch,
            Some(s1),
            Some(2),
            Some(5),
            format!(
                "expected size 4 root {HONEST_FOLD_ROOT_HEX}, \
                 found size 4 root {RUNFX_CP5_BAD_ROOT_HEX}"
            ),
        ),
        Finding::new(
            K::MmrMismatch,
            Some(fx.live.clone()),
            Some(1),
            Some(6),
            format!(
                "expected size 5 root {BAD_CP6_FOLD6_ROOT_HEX}, \
                 found size 5 root {BAD_CP6_BAD_ROOT_HEX}"
            ),
        ),
        unlocated(
            K::AcceptMismatch,
            Some(7),
            format!(
                "accept-run seq 7 hash {BAD_CP6_RESUME_HASH_HEX}: \
                 run digest differs (run {EMPTY_RUN_DIGEST_HEX})"
            ),
        ),
        Finding::new(
            K::Resumed,
            Some(fx.live),
            Some(2),
            Some(7),
            format!(
                "operator=operator reason=incident head=5:{RUNFX_CP5_HASH_HEX} \
                 gap=none lost_records=0 structural=valid"
            ),
        ),
        uncovered_tail(),
    ];
    assert_findings(report.findings(), &expected, "closing_opening_mmr_literal");
}

/// Extend `build_run_fx` with a shipped copy that carries a
/// chain-breaking record at `seq = resume + 2`. Shipped records
/// live in `groups` (so the main seq-loop sees them) but are not
/// in the native segment set (so the run classifier ignores
/// them). `ChainBroken` and `SeqGap` at seq=9 are therefore
/// outside the run's loss-point ranges AND outside its segment
/// paths -- the test for the matching line pins that items 1-3
/// are accepted and these two findings keep severity.
fn write_shipped_trailing_r9(dir: &Path, after: &Record) -> PathBuf {
    let r9 = headless(after, 9);
    let path = dir.join("audit-shipped-trailing.jsonl");
    fs::write(&path, line_bytes(&r9)).unwrap();
    path
}

#[test]
fn list_is_exact_seq_gap_outside_run_stays_error() {
    // The `accept-run` line matches and promotes the A1 run's
    // five items 1-3 findings to `Accepted`; the shipped trailing
    // record at seq=9 creates `ChainBroken` and `SeqGap(8..=8)` on
    // the shipped file -- OUTSIDE the run's segment paths and
    // outside its loss points -- and these keep their severity.
    // Whole literal list.
    let fx = build_run_fx();
    let shipped = write_shipped_trailing_r9(&fx.dir, &fx.resume);
    let v = verifier()
        .accept_run(7, fx.resume.hash(), A1_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![fx.dir.clone(), shipped.clone()], v);
    let expected = vec![
        literal_accepted(per_seg_structure(&fx), "alice", "ok"),
        literal_accepted(seq_gap(&fx), "alice", "ok"),
        literal_accepted(chain_broken_at_4(&fx), "alice", "ok"),
        literal_accepted(run_structure(&fx), "alice", "ok"),
        literal_accepted(mmr_mismatch(&fx), "alice", "ok"),
        resumed(&fx),
        Finding::new(
            K::ChainBroken,
            Some(shipped.clone()),
            Some(1),
            Some(9),
            format!(
                "expected previous {RUNFX_RESUME7_HASH_HEX}, \
                 found {SHIPPED_R9_PREV_RUNFX_HEX}"
            ),
        ),
        Finding::new(
            K::SeqGap,
            Some(shipped),
            Some(1),
            Some(9),
            "missing seq 8..=8".into(),
        ),
        unlocated(K::UncoveredTail, None, "records seq 7..=9".into()),
    ];
    assert_findings(report.findings(), &expected, "list_is_exact_a1_literal");
    assert!(!report.is_valid(), "outside ChainBroken is Error");
}

#[test]
fn list_is_exact_second_layout_a3_shipped_trailing_seq_gap() {
    // A3 (two-range run) + a shipped trailing record at seq=13:
    // the `accept-run` line matches and promotes A3's seven items
    // 1-3 findings. The shipped `ChainBroken` and `SeqGap(12..=12)`
    // at seq=13 stay. Whole literal list.
    let a = build_a3();
    let dir = a.dir_path.clone();
    let s1 = segment_path(&dir, 1);
    let s2 = segment_path(&dir, 2);
    let live = dir.join("audit.jsonl");
    let cp0 = signed_cp(0, Record::genesis(&TRAIL), &Mmr::new());
    let mmr0 = seeded(&cp0);
    let e1 = entry_rec(1, cp0.hash());
    let mmr1 = pushed(&mmr0, &e1);
    let cp2 = signed_cp(2, e1.hash(), &mmr1);
    let mmr2 = pushed(&mmr1, &cp2);
    let r4 = headless(&cp2, 4);
    let mmr4 = pushed(&mmr2, &r4);
    let cp5 = signed_cp(5, r4.hash(), &mmr4);
    let mmr5 = pushed(&mmr4, &cp5);
    let r7 = headless(&cp5, 7);
    let mmr7 = pushed(&mmr5, &r7);
    let cp8 = signed_cp(8, r7.hash(), &mmr7);
    let mmr8 = pushed(&mmr7, &cp8);
    let cp10 = signed_cp(10, cp8.hash(), &mmr8);
    let resume = resume_decl(&cp10, 8, cp8.hash(), 9);
    let shipped_path = dir.join("audit-shipped-trailing.jsonl");
    let r13 = headless(&resume, 13);
    fs::write(&shipped_path, line_bytes(&r13)).unwrap();
    let v = verifier()
        .accept_run(11, A3_RESUME_HASH, A3_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![dir, shipped_path.clone()], v);
    let per_seg_s1 = Finding::new(
        K::SegmentStructure,
        Some(s1.clone()),
        Some(1),
        Some(4),
        "expected first complete record to be a checkpoint".into(),
    );
    let seqgap_s1 = Finding::new(
        K::SeqGap,
        Some(s1.clone()),
        Some(1),
        Some(4),
        "missing seq 3..=3".into(),
    );
    let chain_s1 = Finding::new(
        K::ChainBroken,
        Some(s1.clone()),
        Some(1),
        Some(4),
        format!("expected previous {A3_CP2_HASH_HEX}, found {A3_R4_PREV_HEX}"),
    );
    let run_struct = Finding::new(
        K::SegmentStructure,
        Some(s1),
        Some(1),
        Some(4),
        format!("loss seq 4 first 3 count 1; loss seq 7 first 6 count 1; digest {A3_DIGEST}"),
    )
    .with_run_digest(A3_DIGEST_BYTES);
    let per_seg_s2 = Finding::new(
        K::SegmentStructure,
        Some(s2.clone()),
        Some(1),
        Some(7),
        "expected first complete record to be a checkpoint".into(),
    );
    let seqgap_s2 = Finding::new(
        K::SeqGap,
        Some(s2.clone()),
        Some(1),
        Some(7),
        "missing seq 6..=6".into(),
    );
    let chain_s2 = Finding::new(
        K::ChainBroken,
        Some(s2),
        Some(1),
        Some(7),
        format!("expected previous {A3_CP5_HASH_HEX}, found {A3_R7_PREV_HEX}"),
    );
    let expected = vec![
        literal_accepted(per_seg_s1, "alice", "ok"),
        literal_accepted(seqgap_s1, "alice", "ok"),
        literal_accepted(chain_s1, "alice", "ok"),
        literal_accepted(run_struct, "alice", "ok"),
        literal_accepted(per_seg_s2, "alice", "ok"),
        literal_accepted(seqgap_s2, "alice", "ok"),
        literal_accepted(chain_s2, "alice", "ok"),
        Finding::new(
            K::Resumed,
            Some(live),
            Some(2),
            Some(11),
            format!(
                "operator=operator reason=incident head=8:{A3_CP8_HASH_HEX} \
                 gap=9..=9 lost_records=0 structural=valid"
            ),
        ),
        Finding::new(
            K::ChainBroken,
            Some(shipped_path.clone()),
            Some(1),
            Some(13),
            format!("expected previous {A3_RESUME_HASH_HEX}, found {SHIPPED_R13_PREV_A3_HEX}"),
        ),
        Finding::new(
            K::SeqGap,
            Some(shipped_path),
            Some(1),
            Some(13),
            "missing seq 12..=12".into(),
        ),
        unlocated(K::UncoveredTail, None, "records seq 11..=13".into()),
    ];
    assert_findings(report.findings(), &expected, "list_is_exact_a3_literal");
    assert!(!report.is_valid(), "outside ChainBroken is Error");
}

// =====================================================================
// ADR-0005 decision 11 `accept-run` l.957 "the list is exact", on
// a run with non-empty spans (A9). A9's digest covers both spans
// (`run_digest(&ranges, &spans)`), so `A9_DIGEST` differs from
// `EMPTY_RUN_DIGEST`: a match requires the spans to feed the
// digest. Each row names the full A9 digest; findings outside
// items 1-3 (TornWrite / Unparsable on S1 and S2; UncoveredTail)
// keep their severity.
// =====================================================================
#[test]
fn a9_run_with_spans_accepts_items_1_through_3() {
    // A9 (multi-segment record-free): S1 holds `not json\n`, S2
    // holds `also not json\n`. The run's digest is over both
    // spans (`run_digest(ranges=[], spans=[(seg 0, start, 9),
    // (seg 1, start, 14)])`), so a matching line needs the span
    // bytes to feed the digest. A match promotes the two
    // per-segment `SegmentStructure` findings (S1 and S2) and
    // the run's own `SegmentStructure` (at S1) to `Accepted`;
    // `Resumed`, `UncoveredTail`, and both segments' `TornWrite`
    // + `Unparsable` keep their severity. Whole literal list.
    let a = crate::audit::runs_v4a_fixtures::build_a9();
    let dir = a.dir_path.clone();
    let s1 = segment_path(&dir, 1);
    let s2 = segment_path(&dir, 2);
    let live = dir.join("audit.jsonl");
    let resume_hash = hex_to_bytes(SHORT_RESUME_HASH_HEX.strip_prefix("blake3:").unwrap());
    let v = verifier()
        .accept_run(2, resume_hash, A9_DIGEST_BYTES, "alice", "ok")
        .unwrap();
    let report = report_of(vec![dir], v);
    let per_seg_s1 = Finding::new(
        K::SegmentStructure,
        Some(s1.clone()),
        None,
        None,
        "expected first complete record to be a checkpoint".into(),
    );
    let run_detail = format!(
        "span seg 0 after start len 9 {TWO_RUN_NOT_JSON_GAP_DIGEST_HEX}; \
         span seg 1 after start len 14 {A9_SPAN1_DIGEST_HEX}; \
         digest {A9_DIGEST}"
    );
    let run_struct = Finding::new(
        K::SegmentStructure,
        Some(s1.clone()),
        None,
        None,
        run_detail,
    )
    .with_run_digest(A9_DIGEST_BYTES);
    let per_seg_s2 = Finding::new(
        K::SegmentStructure,
        Some(s2.clone()),
        None,
        None,
        "expected first complete record to be a checkpoint".into(),
    );
    let expected = vec![
        Finding::new(
            K::Resumed,
            Some(live),
            Some(2),
            Some(2),
            format!(
                "operator=operator reason=incident head=0:{CP0_HASH_HEX} \
                 gap=none lost_records=0 structural=valid"
            ),
        ),
        unlocated(K::UncoveredTail, None, "records seq 2..=2".into()),
        literal_accepted(per_seg_s1.clone(), "alice", "ok"),
        literal_accepted(run_struct, "alice", "ok"),
        Finding::new(
            K::TornWrite,
            Some(s1.clone()),
            Some(1),
            None,
            format!("trailing gap lines 1..=1 (9 bytes), digest {TWO_RUN_NOT_JSON_GAP_DIGEST_HEX}"),
        ),
        Finding::new(
            K::Unparsable,
            Some(s1),
            Some(1),
            None,
            "CorruptTrail: Unparsable: invalid audit v1 OTLP line".into(),
        ),
        literal_accepted(per_seg_s2, "alice", "ok"),
        Finding::new(
            K::TornWrite,
            Some(s2.clone()),
            Some(1),
            None,
            format!("trailing gap lines 1..=1 (14 bytes), digest {A9_SPAN1_DIGEST_HEX}"),
        ),
        Finding::new(
            K::Unparsable,
            Some(s2),
            Some(1),
            None,
            "CorruptTrail: Unparsable: invalid audit v1 OTLP line".into(),
        ),
    ];
    assert_findings(report.findings(), &expected, "a9_match_literal");
}

#[test]
fn a9_run_with_spans_wrong_digest_gives_accept_mismatch() {
    // Same A9 layout; the line names `EMPTY_RUN_DIGEST` (what a
    // digest-ranges-only implementation would compute). The run's
    // actual digest is over both spans (not ranges alone), so the
    // match reports `run digest differs (run A9_DIGEST)` and the
    // run's items 1-3 are NOT promoted. Whole literal list.
    let a = crate::audit::runs_v4a_fixtures::build_a9();
    let dir = a.dir_path.clone();
    let s1 = segment_path(&dir, 1);
    let s2 = segment_path(&dir, 2);
    let live = dir.join("audit.jsonl");
    let resume_hash = hex_to_bytes(SHORT_RESUME_HASH_HEX.strip_prefix("blake3:").unwrap());
    let v = verifier()
        .accept_run(2, resume_hash, EMPTY_RUN_DIGEST, "alice", "ok")
        .unwrap();
    let report = report_of(vec![dir], v);
    let expected = vec![
        unlocated(
            K::AcceptMismatch,
            Some(2),
            format!(
                "accept-run seq 2 hash {SHORT_RESUME_HASH_HEX}: \
                 run digest differs (run {A9_DIGEST})"
            ),
        ),
        Finding::new(
            K::Resumed,
            Some(live),
            Some(2),
            Some(2),
            format!(
                "operator=operator reason=incident head=0:{CP0_HASH_HEX} \
                 gap=none lost_records=0 structural=valid"
            ),
        ),
        unlocated(K::UncoveredTail, None, "records seq 2..=2".into()),
        Finding::new(
            K::SegmentStructure,
            Some(s1.clone()),
            None,
            None,
            "expected first complete record to be a checkpoint".into(),
        ),
        Finding::new(
            K::SegmentStructure,
            Some(s1.clone()),
            None,
            None,
            format!(
                "span seg 0 after start len 9 {TWO_RUN_NOT_JSON_GAP_DIGEST_HEX}; \
                 span seg 1 after start len 14 {A9_SPAN1_DIGEST_HEX}; \
                 digest {A9_DIGEST}"
            ),
        )
        .with_run_digest(A9_DIGEST_BYTES),
        Finding::new(
            K::TornWrite,
            Some(s1.clone()),
            Some(1),
            None,
            format!("trailing gap lines 1..=1 (9 bytes), digest {TWO_RUN_NOT_JSON_GAP_DIGEST_HEX}"),
        ),
        Finding::new(
            K::Unparsable,
            Some(s1),
            Some(1),
            None,
            "CorruptTrail: Unparsable: invalid audit v1 OTLP line".into(),
        ),
        Finding::new(
            K::SegmentStructure,
            Some(s2.clone()),
            None,
            None,
            "expected first complete record to be a checkpoint".into(),
        ),
        Finding::new(
            K::TornWrite,
            Some(s2.clone()),
            Some(1),
            None,
            format!("trailing gap lines 1..=1 (14 bytes), digest {A9_SPAN1_DIGEST_HEX}"),
        ),
        Finding::new(
            K::Unparsable,
            Some(s2),
            Some(1),
            None,
            "CorruptTrail: Unparsable: invalid audit v1 OTLP line".into(),
        ),
    ];
    assert_findings(report.findings(), &expected, "a9_wrong_digest_literal");
    assert!(!report.is_valid(), "A9 mismatch is Error");
}

#[test]
fn accept_run_inside_gap_confirmed_by_accept_resumed_is_lost_record() {
    // Same A3 gap, confirmed through `accept Resumed` on the
    // resume at seq=11 instead of a receipt (ADR-0005 decision 11
    // "accept Resumed confirms the gap"). The gap `9..=9` is
    // confirmed and the `accept-run` at seq=9 is `LostRecord`;
    // the Resumed warning becomes `Accepted` with `lost_records=1`
    // in the `was:` tail. Whole literal list.
    let a = build_a3();
    let dir = a.dir_path.clone();
    let s1 = segment_path(&dir, 1);
    let s2 = segment_path(&dir, 2);
    let live = dir.join("audit.jsonl");
    let v = verifier()
        .accept(K::Resumed, 11, A3_RESUME_HASH, "alice", "ok")
        .unwrap()
        .accept_run(9, WRONG_HASH, EMPTY_RUN_DIGEST, "bob", "lost")
        .unwrap();
    let report = report_of(vec![dir], v);
    let resumed_was = format!(
        "operator=operator reason=incident head=8:{A3_CP8_HASH_HEX} \
         gap=9..=9 lost_records=1 structural=valid"
    );
    let expected = vec![
        Finding::new(
            K::ChainBroken,
            Some(s1.clone()),
            Some(1),
            Some(4),
            format!("expected previous {A3_CP2_HASH_HEX}, found {A3_R4_PREV_HEX}"),
        ),
        Finding::new(
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            "expected first complete record to be a checkpoint".into(),
        ),
        Finding::new(
            K::SegmentStructure,
            Some(s1.clone()),
            Some(1),
            Some(4),
            format!("loss seq 4 first 3 count 1; loss seq 7 first 6 count 1; digest {A3_DIGEST}"),
        )
        .with_run_digest(A3_DIGEST_BYTES),
        Finding::new(
            K::SeqGap,
            Some(s1),
            Some(1),
            Some(4),
            "missing seq 3..=3".into(),
        ),
        Finding::new(
            K::ChainBroken,
            Some(s2.clone()),
            Some(1),
            Some(7),
            format!("expected previous {A3_CP5_HASH_HEX}, found {A3_R7_PREV_HEX}"),
        ),
        Finding::new(
            K::SegmentStructure,
            Some(s2.clone()),
            Some(1),
            Some(7),
            "expected first complete record to be a checkpoint".into(),
        ),
        Finding::new(
            K::SeqGap,
            Some(s2),
            Some(1),
            Some(7),
            "missing seq 6..=6".into(),
        ),
        unlocated(
            K::LostRecord,
            Some(9),
            format!("accept-run seq 9 hash {WRONG_HASH_HEX}: lost in gap 9..=9"),
        ),
        literal_accepted(
            Finding::new(K::Resumed, Some(live), Some(2), Some(11), resumed_was),
            "alice",
            "ok",
        ),
        unlocated(K::UncoveredTail, None, "records seq 11..=11".into()),
    ];
    assert_findings(
        report.findings(),
        &expected,
        "lost_record_accept_resumed_literal",
    );
}
