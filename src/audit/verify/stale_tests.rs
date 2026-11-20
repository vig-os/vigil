//! Rows for `Verifier::max_age` and `StaleHead` (ADR-0005 decision 5;
//! rulings 13-V5-d1 point 7 and 13-V5-d6).
//!
//! Row standard (repo-wide): every acceptance row asserts the FULL
//! sorted literal [`Finding`] list through [`assert_findings`] (a
//! thin wrapper around `assert_eq!` on `Vec<Finding>`), and also
//! [`Report::is_strict_valid`] and [`Report::covered_through`] where
//! the row's claim involves them. Regression rows are labelled in
//! their doc comments. Every digest and key in an expected detail is
//! a written-out hex constant pinned by [`fixture_hashes_match_literals`];
//! nanosecond integers appear as literal decimal integers and are
//! pinned by the same consistency test. Expected lists are written
//! in the engine's final sort order (`(seq.is_none(), seq, file,
//! line, kind_debug)`), so no per-row sort runs here.

#![allow(clippy::too_many_lines)]

use crate::audit::{
    CheckpointFields, Entry, FindingKind as K, KeyFileSigner, Mmr, Record, RecordContext, Signer,
    TrustPolicy, digest_string, hex,
    runs_v4a_fixtures::{
        TRAIL, Temp, fixture_pubkey, line_bytes, put_segment, segment_path, write_bytes,
    },
    verify::{Finding, Report, Verifier},
};
use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// =====================================================================
// Shared literals. `fixture_hashes_match_literals` pins every hex and
// nanosecond integer here against the fixtures the rows build.
// =====================================================================

const TRAIL_HEX: &str = "11111111111111111111111111111111";
const FIXTURE_KEY_HEX: &str = "ee45ecb9aca01a0abd83ef56dd985c8c874e6e7f4aebcedf20bd8d88c2a0add7";
const OTHER_KEY_HEX: &str = "248acbdbaf9e050196de704bea2d68770e519150d103b587dae2d9cad53dd930";

/// Max age used by every row that sets one. 1 second in nanoseconds.
const MAX_AGE_NS: u128 = 1_000_000_000;
const MAX_AGE: Duration = Duration::from_nanos(MAX_AGE_NS as u64);

/// Fixed "now" for every row, 3 seconds since the Unix epoch.
const NOW_NS: u128 = 3_000_000_000;
fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_nanos(NOW_NS as u64)
}

// Row-specific checkpoint times.
const T_S1: u64 = 1_000_000_000; // age 2s, stale.
const T_S2: u64 = 2_000_000_000; // age exactly 1s, not stale.
const T_S3: u64 = 1_999_999_999; // age 1s + 1ns, stale.
const T_FUTURE: u64 = 4_000_000_001; // > max_age in the future, not stale.
const T_FRESH_CP2: u64 = 2_500_000_000; // age 0.5s, not stale.
const T_OLD_CP0: u64 = 1_500_000_000; // age 1.5s, stale.
const T_S6_CP0: u64 = 2_800_000_000; // highest `time`, lower `seq`.
const T_S6_E1: u64 = 2_600_000_000;
const T_S6_CP2: u64 = 1_000_000_000; // lowest `time`, highest `seq`.
const T_S12_CP0: u64 = 2_999_999_999; // age 1ns, stale at Duration::ZERO.
// S13 — ADR-0005 decision 5 rollback: an old trusted cp0 at `T_OLD_CP0`
// and plain entries after it at strictly increasing times. Age is 1.5s
// against `NOW_NS` (stale), and no record carries a backwards `time`,
// so no `ClockWentBackwards` fires.
const T_S13_E1: u64 = T_OLD_CP0 + 1; // 1_500_000_001, > T_OLD_CP0.
const T_S13_E2: u64 = T_OLD_CP0 + 2; // 1_500_000_002, > T_S13_E1.
const T_S11_CP0: u64 = 1_800_000_000; // age 1.2s.

// Fork hashes for S9: two distinct `(size, root)` cp2s on seq=2.
const S9_CP2_A_HEX: &str =
    "blake3:033f9437ab0b83a04f4d5a1566ef4fb46277f482ab67d26dddcd01b7f1b5f433";
const S9_CP2_B_HEX: &str =
    "blake3:24a04e6415ac2c1f7ebd5ac7f6d07bfa09621190d2352aa97dde86e15256166f";
// Fork hashes for S9b: two cp0s at `T_S1` sharing the same `(seq,
// previous, time, key)` but differing in `(size, root, peaks)`, so
// `cp0_b`'s `verify_strict` rejects the record (`cp0_b` is forked but
// not trusted).
const S9B_CP0_A_HEX: &str =
    "blake3:d4665d39b8e3aea6c31eb536ea2007c683a692a3bfca62a26abcc34f5e9d4f83";
const S9B_CP0_B_HEX: &str =
    "blake3:b913e2bf34dea145d1d31a5c9b5b76b48f99ad21ff4a3a9537cfe0912b92edd6";
// Fork hashes for S9c: two cp2s at `T_S9C_CP2` sharing `(seq,
// previous, time, key)` but differing in `(size, root, peaks)`, so
// `cp2_b`'s `verify_strict` rejects the record (`cp2_b` is forked but
// not trusted).
const S9C_CP2_A_HEX: &str =
    "blake3:b8ae2cb2cfee3d50faffc6f13146e8a77fa0e2346a014fe5a3ec9edd702a5da4";
const S9C_CP2_B_HEX: &str =
    "blake3:3d7083eccf52466fe6954673ec41a241fadaeb3e88733589109a2f09f780e770";

// Times for S9c (fork fallback with a fresh trusted below the fork).
const T_S9C_CP0: u64 = T_FRESH_CP2; // 2_500_000_000, age 0.5s, fresh.
const T_S9C_E1: u64 = T_FRESH_CP2 + 1;
const T_S9C_CP2: u64 = T_FRESH_CP2 + 2;

// =====================================================================
// Helpers.
// =====================================================================

fn located(kind: K, file: PathBuf, line: u64, seq: u64, detail: String) -> Finding {
    Finding::new(kind, Some(file), Some(line), Some(seq), detail)
}
fn unlocated(kind: K, seq: Option<u64>, detail: String) -> Finding {
    Finding::new(kind, None, None, seq, detail)
}
fn uncovered(first: u64, last: u64) -> Finding {
    unlocated(
        K::UncoveredTail,
        None,
        format!("records seq {first}..={last}"),
    )
}
fn stale(file: PathBuf, line: u64, seq: u64, time: u64) -> Finding {
    located(
        K::StaleHead,
        file,
        line,
        seq,
        format!(
            "newest trusted checkpoint seq {seq} time {time} \
             is older than max_age {MAX_AGE_NS} at {NOW_NS}"
        ),
    )
}
fn stale_zero(file: PathBuf, line: u64, seq: u64, time: u64) -> Finding {
    located(
        K::StaleHead,
        file,
        line,
        seq,
        format!(
            "newest trusted checkpoint seq {seq} time {time} \
             is older than max_age 0 at {NOW_NS}"
        ),
    )
}
fn stale_untrusted(d: u128) -> Finding {
    unlocated(
        K::StaleHead,
        None,
        format!("no trusted checkpoint (max_age {d})"),
    )
}

#[track_caller]
fn assert_findings(actual: &[Finding], expected: &[Finding], label: &str) {
    assert_eq!(actual, expected, "{label} literal finding list");
}

fn report(
    files: Vec<PathBuf>,
    trust: TrustPolicy,
    max_age: Option<Duration>,
    at: SystemTime,
) -> Report {
    let mut v = Verifier::new(trust).with_now_for_test(at);
    if let Some(d) = max_age {
        v = v.max_age(d).unwrap();
    }
    v.verify_files(files).unwrap()
}

/// Entry record with explicit `time` (fixtures' `entry_rec` ties
/// `time` to `100 + seq`, which S6/S13 break on purpose).
fn entry_at(seq: u64, previous: [u8; 32], time: u64) -> Record {
    Record::new(
        RecordContext::new(TRAIL, seq, time, "test", previous),
        Entry::new("actor", "change", "object"),
    )
    .unwrap()
}

/// Checkpoint signed by the fixture key with explicit `time` and
/// taking an honest `Mmr` fold, mirroring `signed_cp` with a time
/// knob so the age arithmetic is a literal.
fn signed_cp_at(seq: u64, previous: [u8; 32], mmr: &Mmr, time: u64) -> Record {
    signed_cp_explicit_at(
        &"27".repeat(32),
        seq,
        previous,
        time,
        mmr.size(),
        mmr.root(),
        mmr.peaks().to_vec(),
    )
}

/// Same, but with an explicit key hex (for S4/S5 untrusted keys) and
/// explicit `(size, root, peaks)` (for S9 forks).
fn signed_cp_explicit_at(
    key_hex: &str,
    seq: u64,
    previous: [u8; 32],
    time: u64,
    size: u64,
    root: [u8; 32],
    peaks: Vec<[u8; 32]>,
) -> Record {
    let key = KeyFileSigner::from_hex(key_hex).unwrap();
    let ctx = || RecordContext::new(TRAIL, seq, time, "test", previous);
    let fields =
        |sig| CheckpointFields::new(size, root, peaks.clone(), key.public_key(), sig).unwrap();
    let unsigned = Record::checkpoint(ctx(), fields([0; 64])).unwrap();
    let signature = key.sign(&unsigned.signing_message().unwrap()).unwrap();
    Record::checkpoint(ctx(), fields(signature)).unwrap()
}

fn other_key_hex() -> String {
    "ab".repeat(32)
}
fn other_pubkey() -> [u8; 32] {
    KeyFileSigner::from_hex(&other_key_hex())
        .unwrap()
        .public_key()
}

// =====================================================================
// CONSISTENCY. Every hex and nanosecond integer used in the rows'
// expected details is pinned here, so a fixture change moves the
// literal the row fails.
// =====================================================================
#[test]
fn fixture_hashes_match_literals() {
    assert_eq!(hex(&TRAIL), TRAIL_HEX);
    assert_eq!(hex(&fixture_pubkey()), FIXTURE_KEY_HEX);
    assert_eq!(hex(&other_pubkey()), OTHER_KEY_HEX);
    // The S9 fork hashes are derived from two distinct `(size, root,
    // peaks)` cp2s on seq=2; both link to the same previous
    // (`e1.hash`) and are signed by the fixture key. The exact layout
    // the row builds is rebuilt here so a fixture change fails this
    // test, not S9's row.
    let cp0 = signed_cp_at(0, Record::genesis(&TRAIL), &Mmr::new(), T_OLD_CP0);
    let mut mmr0 = Mmr::new();
    mmr0.push(cp0.hash()).unwrap();
    let e1 = entry_at(1, cp0.hash(), T_OLD_CP0 + 1);
    let mut mmr1 = mmr0.clone();
    mmr1.push(e1.hash()).unwrap();
    let cp2_a = signed_cp_at(2, e1.hash(), &mmr1, T_FRESH_CP2);
    let cp2_b = signed_cp_explicit_at(
        &"27".repeat(32),
        2,
        e1.hash(),
        T_FRESH_CP2,
        2,
        [0xff; 32],
        vec![[0xff; 32]],
    );
    assert_eq!(digest_string(&cp2_a.hash()), S9_CP2_A_HEX);
    assert_eq!(digest_string(&cp2_b.hash()), S9_CP2_B_HEX);
    // The S9b fork hashes: two cp0s at `T_S1` with the same `(seq,
    // previous, time, key)` differing only by `(size, root, peaks)`.
    // Rebuilt here so a fixture change fails this consistency pin, not
    // S9b's row.
    let s9b_cp0_a = signed_cp_at(0, Record::genesis(&TRAIL), &Mmr::new(), T_S1);
    let s9b_cp0_b = signed_cp_explicit_at(
        &"27".repeat(32),
        0,
        Record::genesis(&TRAIL),
        T_S1,
        0,
        [0xff; 32],
        vec![],
    );
    assert_eq!(digest_string(&s9b_cp0_a.hash()), S9B_CP0_A_HEX);
    assert_eq!(digest_string(&s9b_cp0_b.hash()), S9B_CP0_B_HEX);
    // The S9c fork hashes: two cp2s at `T_S9C_CP2` above a fresh
    // trusted cp0, with the same `(seq, previous, time, key)`
    // differing only by `(size, root, peaks)`. Rebuilt here so a
    // fixture change fails this consistency pin, not S9c's row.
    let s9c_cp0 = signed_cp_at(0, Record::genesis(&TRAIL), &Mmr::new(), T_S9C_CP0);
    let mut s9c_mmr0 = Mmr::new();
    s9c_mmr0.push(s9c_cp0.hash()).unwrap();
    let s9c_e1 = entry_at(1, s9c_cp0.hash(), T_S9C_E1);
    let mut s9c_mmr1 = s9c_mmr0.clone();
    s9c_mmr1.push(s9c_e1.hash()).unwrap();
    let s9c_cp2_a = signed_cp_at(2, s9c_e1.hash(), &s9c_mmr1, T_S9C_CP2);
    let s9c_cp2_b = signed_cp_explicit_at(
        &"27".repeat(32),
        2,
        s9c_e1.hash(),
        T_S9C_CP2,
        2,
        [0xff; 32],
        vec![[0xff; 32]],
    );
    assert_eq!(digest_string(&s9c_cp2_a.hash()), S9C_CP2_A_HEX);
    assert_eq!(digest_string(&s9c_cp2_b.hash()), S9C_CP2_B_HEX);
    // Nanosecond integers: the row details reference them as literals;
    // re-stating them here anchors the row list against a typo.
    assert_eq!(MAX_AGE.as_nanos(), MAX_AGE_NS);
    assert_eq!(NOW_NS, 3_000_000_000);
}

/// Trust policy listing only the fixture key.
fn trusted_policy() -> TrustPolicy {
    TrustPolicy::builder()
        .trail(TRAIL)
        .key(fixture_pubkey())
        .build()
        .unwrap()
}

/// Trust policy listing only the OTHER key: cp signed by the fixture
/// key then yields `UntrustedKey`.
fn other_only_policy() -> TrustPolicy {
    TrustPolicy::builder()
        .trail(TRAIL)
        .key(other_pubkey())
        .build()
        .unwrap()
}

// =====================================================================
// S1 — ACCEPTANCE. Newest trusted checkpoint older than `max_age`
// (age 2s, max_age 1s): one `StaleHead` at that checkpoint.
// =====================================================================
#[test]
fn s1_newest_trusted_older_than_max_age_emits_stale_head() {
    let d = Temp::new();
    let cp0 = signed_cp_at(0, Record::genesis(&TRAIL), &Mmr::new(), T_S1);
    put_segment(&d.0, 0, &[&cp0], &[]);
    let path = segment_path(&d.0, 0);
    let r = report(vec![path.clone()], trusted_policy(), Some(MAX_AGE), now());
    let expected = vec![stale(path, 1, 0, T_S1)];
    assert_findings(r.findings(), &expected, "S1");
    assert!(!r.is_strict_valid(), "S1 strict fails on StaleHead");
    assert_eq!(r.covered_through(), Some(0));
}

// =====================================================================
// S2 — REGRESSION (no StaleHead when age exactly equals `max_age`):
// the boundary is "exceeds", not "equal or exceeds".
// =====================================================================
#[test]
fn s2_age_equal_to_max_age_is_not_stale() {
    let d = Temp::new();
    let cp0 = signed_cp_at(0, Record::genesis(&TRAIL), &Mmr::new(), T_S2);
    put_segment(&d.0, 0, &[&cp0], &[]);
    let path = segment_path(&d.0, 0);
    let r = report(vec![path], trusted_policy(), Some(MAX_AGE), now());
    assert_findings(r.findings(), &[], "S2");
    assert!(r.is_strict_valid(), "S2 strict passes: no finding");
    assert_eq!(r.covered_through(), Some(0));
}

// =====================================================================
// S3 — ACCEPTANCE. Age one nanosecond over `max_age` is stale.
// =====================================================================
#[test]
fn s3_age_one_ns_over_max_age_emits_stale_head() {
    let d = Temp::new();
    let cp0 = signed_cp_at(0, Record::genesis(&TRAIL), &Mmr::new(), T_S3);
    put_segment(&d.0, 0, &[&cp0], &[]);
    let path = segment_path(&d.0, 0);
    let r = report(vec![path.clone()], trusted_policy(), Some(MAX_AGE), now());
    let expected = vec![stale(path, 1, 0, T_S3)];
    assert_findings(r.findings(), &expected, "S3");
    assert!(!r.is_strict_valid());
    assert_eq!(r.covered_through(), Some(0));
}

// =====================================================================
// S4 — ACCEPTANCE. `max_age` set and no trusted checkpoint (cp0
// signed by a listed-but-not-this-key): `StaleHead "no trusted …"`
// plus the `UntrustedKey` finding.
// =====================================================================
#[test]
fn s4_no_trusted_checkpoint_emits_unlocated_stale_head() {
    let d = Temp::new();
    let cp0 = signed_cp_at(0, Record::genesis(&TRAIL), &Mmr::new(), T_S1);
    put_segment(&d.0, 0, &[&cp0], &[]);
    let path = segment_path(&d.0, 0);
    let r = report(
        vec![path.clone()],
        other_only_policy(),
        Some(MAX_AGE),
        now(),
    );
    let expected = vec![
        located(
            K::UntrustedKey,
            path,
            1,
            0,
            format!("key {FIXTURE_KEY_HEX} not listed for trail {TRAIL_HEX}"),
        ),
        stale_untrusted(MAX_AGE_NS),
        uncovered(0, 0),
    ];
    assert_findings(r.findings(), &expected, "S4");
    assert!(!r.is_strict_valid());
    assert_eq!(r.covered_through(), None);
}

// =====================================================================
// S5 — ACCEPTANCE. A newer checkpoint by an untrusted key and an
// older trusted one past `max_age`: the newer does not refresh
// freshness; `StaleHead` names the older trusted checkpoint.
// =====================================================================
#[test]
fn s5_untrusted_newer_does_not_refresh_freshness() {
    let d = Temp::new();
    let cp0 = signed_cp_at(0, Record::genesis(&TRAIL), &Mmr::new(), T_OLD_CP0);
    let mmr0 = {
        let mut m = Mmr::new();
        m.push(cp0.hash()).unwrap();
        m
    };
    let e1 = entry_at(1, cp0.hash(), T_OLD_CP0 + 1);
    let mmr1 = {
        let mut m = mmr0.clone();
        m.push(e1.hash()).unwrap();
        m
    };
    // cp2 signed by the OTHER key (not listed on this policy).
    let cp2 = signed_cp_explicit_at(
        &other_key_hex(),
        2,
        e1.hash(),
        T_FRESH_CP2,
        mmr1.size(),
        mmr1.root(),
        mmr1.peaks().to_vec(),
    );
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let path = segment_path(&d.0, 0);
    let r = report(vec![path.clone()], trusted_policy(), Some(MAX_AGE), now());
    let expected = vec![
        stale(path.clone(), 1, 0, T_OLD_CP0),
        located(
            K::UntrustedKey,
            path,
            3,
            2,
            format!("key {OTHER_KEY_HEX} not listed for trail {TRAIL_HEX}"),
        ),
        uncovered(1, 2),
    ];
    assert_findings(r.findings(), &expected, "S5");
    assert!(!r.is_strict_valid());
    assert_eq!(r.covered_through(), Some(0));
}

// =====================================================================
// S6 — ACCEPTANCE. "Highest seq" decides, whatever `time` says.
// cp0.time > cp2.time with cp2 at a higher seq → `StaleHead` names
// cp2 (not the latest-time cp0). The reversed times also fire
// `ClockWentBackwards` at e1 and cp2 (two warnings per ADR).
// =====================================================================
#[test]
fn s6_highest_seq_wins_over_latest_time() {
    let d = Temp::new();
    let cp0 = signed_cp_at(0, Record::genesis(&TRAIL), &Mmr::new(), T_S6_CP0);
    let mmr0 = {
        let mut m = Mmr::new();
        m.push(cp0.hash()).unwrap();
        m
    };
    let e1 = entry_at(1, cp0.hash(), T_S6_E1);
    let mmr1 = {
        let mut m = mmr0.clone();
        m.push(e1.hash()).unwrap();
        m
    };
    let cp2 = signed_cp_at(2, e1.hash(), &mmr1, T_S6_CP2);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let path = segment_path(&d.0, 0);
    let r = report(vec![path.clone()], trusted_policy(), Some(MAX_AGE), now());
    let expected = vec![
        located(
            K::ClockWentBackwards,
            path.clone(),
            2,
            1,
            format!("expected time >= {T_S6_CP0}, found {T_S6_E1}"),
        ),
        located(
            K::ClockWentBackwards,
            path.clone(),
            3,
            2,
            format!("expected time >= {T_S6_E1}, found {T_S6_CP2}"),
        ),
        stale(path, 3, 2, T_S6_CP2),
    ];
    assert_findings(r.findings(), &expected, "S6");
    assert!(!r.is_strict_valid());
    assert_eq!(r.covered_through(), Some(2));
}

// =====================================================================
// S7 — REGRESSION. A trusted checkpoint whose `time` is in the
// future relative to `now` saturates to age 0, so no `StaleHead`
// fires (clock problems are the business of `ClockWentBackwards`).
// =====================================================================
#[test]
fn s7_future_time_saturates_to_zero_age_not_stale() {
    let d = Temp::new();
    let cp0 = signed_cp_at(0, Record::genesis(&TRAIL), &Mmr::new(), T_FUTURE);
    put_segment(&d.0, 0, &[&cp0], &[]);
    let path = segment_path(&d.0, 0);
    let r = report(vec![path], trusted_policy(), Some(MAX_AGE), now());
    assert_findings(r.findings(), &[], "S7");
    assert!(r.is_strict_valid());
    assert_eq!(r.covered_through(), Some(0));
}

// =====================================================================
// S8 — REGRESSION. The highest-`seq` trusted checkpoint is in a
// shipped-only copy and is fresh: no `StaleHead`.
// =====================================================================
#[test]
fn s8_shipped_only_highest_seq_fresh_is_not_stale() {
    let d = Temp::new();
    let cp0 = signed_cp_at(0, Record::genesis(&TRAIL), &Mmr::new(), T_OLD_CP0);
    let mmr0 = {
        let mut m = Mmr::new();
        m.push(cp0.hash()).unwrap();
        m
    };
    let e1 = entry_at(1, cp0.hash(), T_OLD_CP0 + 1);
    let mmr1 = {
        let mut m = mmr0.clone();
        m.push(e1.hash()).unwrap();
        m
    };
    let cp2 = signed_cp_at(2, e1.hash(), &mmr1, T_FRESH_CP2);
    put_segment(&d.0, 0, &[&cp0, &e1], &[]);
    let native = segment_path(&d.0, 0);
    let shipped = d.0.join("shipped.jsonl");
    write_bytes(&shipped, &line_bytes(&cp2));
    let r = report(
        vec![native, shipped],
        trusted_policy(),
        Some(MAX_AGE),
        now(),
    );
    assert_findings(r.findings(), &[], "S8");
    assert!(r.is_strict_valid());
    assert_eq!(r.covered_through(), Some(2));
}

// =====================================================================
// S9 — ACCEPTANCE. The highest trusted `seq` is forked, so stale
// skips it. The highest unforked trusted `seq` below it is stale;
// `SeqConflict` fires at the forked seq.
// =====================================================================
#[test]
fn s9_forked_highest_skips_to_unforked_below() {
    let d = Temp::new();
    let cp0 = signed_cp_at(0, Record::genesis(&TRAIL), &Mmr::new(), T_OLD_CP0);
    let mmr0 = {
        let mut m = Mmr::new();
        m.push(cp0.hash()).unwrap();
        m
    };
    let e1 = entry_at(1, cp0.hash(), T_OLD_CP0 + 1);
    let mmr1 = {
        let mut m = mmr0.clone();
        m.push(e1.hash()).unwrap();
        m
    };
    let cp2_a = signed_cp_at(2, e1.hash(), &mmr1, T_FRESH_CP2);
    let cp2_b = signed_cp_explicit_at(
        &"27".repeat(32),
        2,
        e1.hash(),
        T_FRESH_CP2,
        2,
        [0xff; 32],
        vec![[0xff; 32]],
    );
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2_a], &[]);
    let native = segment_path(&d.0, 0);
    let shipped = d.0.join("twin.jsonl");
    write_bytes(&shipped, &line_bytes(&cp2_b));
    let r = report(
        vec![native.clone(), shipped],
        trusted_policy(),
        Some(MAX_AGE),
        now(),
    );
    let expected = vec![
        stale(native.clone(), 1, 0, T_OLD_CP0),
        located(
            K::SeqConflict,
            native,
            3,
            2,
            format!("conflicting hashes: {S9_CP2_A_HEX}, {S9_CP2_B_HEX}"),
        ),
    ];
    assert_findings(r.findings(), &expected, "S9");
    assert!(!r.is_strict_valid());
    assert_eq!(r.covered_through(), Some(2));
}

// =====================================================================
// S10 — REGRESSION (no StaleHead when `max_age` is unset): without
// `max_age` nothing is checked, even on a trail that would be stale
// if it were.
// =====================================================================
#[test]
fn s10_max_age_unset_never_emits_stale_head() {
    let d = Temp::new();
    let cp0 = signed_cp_at(0, Record::genesis(&TRAIL), &Mmr::new(), T_S1);
    put_segment(&d.0, 0, &[&cp0], &[]);
    let path = segment_path(&d.0, 0);
    let r = report(vec![path], trusted_policy(), None, now());
    assert_findings(r.findings(), &[], "S10");
    assert!(r.is_strict_valid());
    assert_eq!(r.covered_through(), Some(0));
}

// =====================================================================
// S11 — ACCEPTANCE. Calling `max_age` twice: the second value wins.
// First call sets a large `max_age` that would not catch cp0; second
// sets `MAX_AGE` which does.
// =====================================================================
#[test]
fn s11_second_max_age_call_wins() {
    let d = Temp::new();
    let cp0 = signed_cp_at(0, Record::genesis(&TRAIL), &Mmr::new(), T_S11_CP0);
    put_segment(&d.0, 0, &[&cp0], &[]);
    let path = segment_path(&d.0, 0);
    let v = Verifier::new(trusted_policy())
        .with_now_for_test(now())
        .max_age(Duration::from_secs(60))
        .unwrap()
        .max_age(MAX_AGE)
        .unwrap();
    let r = v.verify_files(vec![path.clone()]).unwrap();
    let expected = vec![stale(path, 1, 0, T_S11_CP0)];
    assert_findings(r.findings(), &expected, "S11");
    assert!(!r.is_strict_valid());
    assert_eq!(r.covered_through(), Some(0));
}

// =====================================================================
// S12 — ACCEPTANCE. `Duration::ZERO` with a checkpoint 1ns old is
// stale.
// =====================================================================
#[test]
fn s12_zero_max_age_with_one_ns_old_is_stale() {
    let d = Temp::new();
    let cp0 = signed_cp_at(0, Record::genesis(&TRAIL), &Mmr::new(), T_S12_CP0);
    put_segment(&d.0, 0, &[&cp0], &[]);
    let path = segment_path(&d.0, 0);
    let r = report(
        vec![path.clone()],
        trusted_policy(),
        Some(Duration::ZERO),
        now(),
    );
    let expected = vec![stale_zero(path, 1, 0, T_S12_CP0)];
    assert_findings(r.findings(), &expected, "S12");
    assert!(!r.is_strict_valid());
    assert_eq!(r.covered_through(), Some(0));
}

// =====================================================================
// S13 — ACCEPTANCE. ADR-0005 decision 5 rollback scenario: a trail
// rolled back to an old trusted checkpoint `cp0`, followed by plain
// entries at strictly increasing `time`s and no checkpoint signed
// again. `cp0` exceeds `max_age`, so `StaleHead` names it; the tail
// above `cp0` is `UncoveredTail`. No `ClockWentBackwards` fires
// (entries' `time`s increase from `cp0`'s), so the rollback isolates
// the staleness branch under decision 5.
// =====================================================================
#[test]
fn s13_rollback_old_trusted_with_no_checkpoint_signed_since_is_stale() {
    let d = Temp::new();
    let cp0 = signed_cp_at(0, Record::genesis(&TRAIL), &Mmr::new(), T_OLD_CP0);
    let e1 = entry_at(1, cp0.hash(), T_S13_E1);
    let e2 = entry_at(2, e1.hash(), T_S13_E2);
    put_segment(&d.0, 0, &[&cp0, &e1, &e2], &[]);
    let path = segment_path(&d.0, 0);
    let r = report(vec![path.clone()], trusted_policy(), Some(MAX_AGE), now());
    let expected = vec![stale(path, 1, 0, T_OLD_CP0), uncovered(1, 2)];
    assert_findings(r.findings(), &expected, "S13");
    assert!(!r.is_strict_valid());
    assert_eq!(r.covered_through(), Some(0));
}

// =====================================================================
// S9c — REGRESSION sibling of S9 (fork fallback with a fresh lower
// trusted): the highest trusted `seq` is forked AND the trusted
// checkpoint at the next unforked `seq` below is fresh. The fallback
// steps down from the forked `seq` to that fresh checkpoint, so only
// `SeqConflict` fires -- a `newest_trusted` that returned `None` at
// the forked `seq` (instead of stepping down) would spuriously emit
// the unlocated `no trusted checkpoint …` finding here. Pairs with S9
// so the "step down to the highest unforked trusted" rule is pinned
// on two layouts (stale below the fork; fresh below the fork).
// =====================================================================
#[test]
fn s9c_forked_highest_steps_down_to_fresh_trusted_below() {
    let d = Temp::new();
    let cp0 = signed_cp_at(0, Record::genesis(&TRAIL), &Mmr::new(), T_S9C_CP0);
    let mmr0 = {
        let mut m = Mmr::new();
        m.push(cp0.hash()).unwrap();
        m
    };
    let e1 = entry_at(1, cp0.hash(), T_S9C_E1);
    let mmr1 = {
        let mut m = mmr0.clone();
        m.push(e1.hash()).unwrap();
        m
    };
    let cp2_a = signed_cp_at(2, e1.hash(), &mmr1, T_S9C_CP2);
    let cp2_b = signed_cp_explicit_at(
        &"27".repeat(32),
        2,
        e1.hash(),
        T_S9C_CP2,
        2,
        [0xff; 32],
        vec![[0xff; 32]],
    );
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2_a], &[]);
    let native = segment_path(&d.0, 0);
    let shipped = d.0.join("twin.jsonl");
    write_bytes(&shipped, &line_bytes(&cp2_b));
    let r = report(
        vec![native.clone(), shipped],
        trusted_policy(),
        Some(MAX_AGE),
        now(),
    );
    // The engine sorts fork candidates by the hash bytes (`BTreeMap`
    // keyed by `record.hash`), so `conflicting hashes: …` prints the
    // two pinned literals in hash-byte order (`_B_HEX`, then `_A_HEX`).
    let expected = vec![located(
        K::SeqConflict,
        native,
        3,
        2,
        format!("conflicting hashes: {S9C_CP2_B_HEX}, {S9C_CP2_A_HEX}"),
    )];
    assert_findings(r.findings(), &expected, "S9c");
    assert!(!r.is_strict_valid());
    assert_eq!(r.covered_through(), Some(2));
}

// =====================================================================
// S2b — REGRESSION sibling of S2 (shipped-only equal-boundary): a
// trusted checkpoint in a shipped-only file at age exactly equal to
// `max_age` is not stale either, and pairs with S2 so the "exceeds"
// boundary is pinned on two independent layouts (native and shipped).
// =====================================================================
#[test]
fn s2b_shipped_only_equal_boundary_is_not_stale() {
    let d = Temp::new();
    let cp0 = signed_cp_at(0, Record::genesis(&TRAIL), &Mmr::new(), T_S2);
    let shipped = d.0.join("shipped.jsonl");
    write_bytes(&shipped, &line_bytes(&cp0));
    let r = report(vec![shipped], trusted_policy(), Some(MAX_AGE), now());
    assert_findings(r.findings(), &[], "S2b");
    assert!(r.is_strict_valid());
    assert_eq!(r.covered_through(), Some(0));
}

// =====================================================================
// S4b — ACCEPTANCE sibling of S4: two untrusted-key checkpoints on
// the verified trail. Still no trusted checkpoint, so `StaleHead "no
// trusted …"` fires once and is unlocated; paired with S4 so the
// "no trusted" branch is pinned on two independent layouts (one
// untrusted cp vs several).
// =====================================================================
#[test]
fn s4b_two_untrusted_checkpoints_still_emit_unlocated_stale_head() {
    let d = Temp::new();
    let cp0 = signed_cp_at(0, Record::genesis(&TRAIL), &Mmr::new(), T_S1);
    let mut mmr0 = Mmr::new();
    mmr0.push(cp0.hash()).unwrap();
    let e1 = entry_at(1, cp0.hash(), T_S1 + 1);
    let mut mmr1 = mmr0.clone();
    mmr1.push(e1.hash()).unwrap();
    let cp2 = signed_cp_at(2, e1.hash(), &mmr1, T_S1 + 2);
    put_segment(&d.0, 0, &[&cp0, &e1, &cp2], &[]);
    let path = segment_path(&d.0, 0);
    let r = report(
        vec![path.clone()],
        other_only_policy(),
        Some(MAX_AGE),
        now(),
    );
    let expected = vec![
        located(
            K::UntrustedKey,
            path.clone(),
            1,
            0,
            format!("key {FIXTURE_KEY_HEX} not listed for trail {TRAIL_HEX}"),
        ),
        located(
            K::UntrustedKey,
            path,
            3,
            2,
            format!("key {FIXTURE_KEY_HEX} not listed for trail {TRAIL_HEX}"),
        ),
        stale_untrusted(MAX_AGE_NS),
        uncovered(0, 2),
    ];
    assert_findings(r.findings(), &expected, "S4b");
    assert!(!r.is_strict_valid());
    assert_eq!(r.covered_through(), None);
}

// =====================================================================
// S7b — REGRESSION sibling of S7 (shipped-only future): a trusted
// checkpoint in a shipped-only file whose `time` is in the future
// relative to `now` is not stale, pinning "future `time` saturates
// to age zero" on a second, independent layout.
// =====================================================================
#[test]
fn s7b_shipped_only_future_time_is_not_stale() {
    let d = Temp::new();
    let cp0 = signed_cp_at(0, Record::genesis(&TRAIL), &Mmr::new(), T_FUTURE);
    let shipped = d.0.join("shipped.jsonl");
    write_bytes(&shipped, &line_bytes(&cp0));
    let r = report(vec![shipped], trusted_policy(), Some(MAX_AGE), now());
    assert_findings(r.findings(), &[], "S7b");
    assert!(r.is_strict_valid());
    assert_eq!(r.covered_through(), Some(0));
}

// =====================================================================
// S9b — ACCEPTANCE sibling of S9: fork at `seq 0` with no trusted
// checkpoint below means `newest_trusted` returns `None`, so the
// unlocated "no trusted" branch fires alongside `SeqConflict`. Pairs
// with S9 on the "skip forked `seq`s" rule for two layouts (fork at
// the highest with a lower unforked below, and fork with nothing
// below).
// =====================================================================
#[test]
fn s9b_forked_seq_zero_with_no_lower_trusted_emits_no_trusted() {
    let d = Temp::new();
    let cp0_a = signed_cp_at(0, Record::genesis(&TRAIL), &Mmr::new(), T_S1);
    let cp0_b = signed_cp_explicit_at(
        &"27".repeat(32),
        0,
        Record::genesis(&TRAIL),
        T_S1,
        0,
        [0xff; 32],
        vec![],
    );
    put_segment(&d.0, 0, &[&cp0_a], &[]);
    let native = segment_path(&d.0, 0);
    let shipped = d.0.join("twin.jsonl");
    write_bytes(&shipped, &line_bytes(&cp0_b));
    let r = report(
        vec![native.clone(), shipped],
        trusted_policy(),
        Some(MAX_AGE),
        now(),
    );
    // `S9B_CP0_A_HEX` and `S9B_CP0_B_HEX` are pinned. The engine
    // sorts fork candidates by the hash bytes (`BTreeMap` keyed by
    // `record.hash`), so `conflicting hashes: …` prints the two
    // literals in hash-byte order (`_B_HEX`, then `_A_HEX`); any
    // fixture drift fails `fixture_hashes_match_literals`, not this
    // row.
    let expected = vec![
        located(
            K::SeqConflict,
            native,
            1,
            0,
            format!("conflicting hashes: {S9B_CP0_B_HEX}, {S9B_CP0_A_HEX}"),
        ),
        stale_untrusted(MAX_AGE_NS),
    ];
    assert_findings(r.findings(), &expected, "S9b");
    assert!(!r.is_strict_valid());
    assert_eq!(r.covered_through(), Some(0));
}

// =====================================================================
// S10b — REGRESSION sibling of S10 (no trusted + `max_age` unset):
// `max_age` is unset on a trail with only an untrusted-key cp.
// Nothing stale-related runs: no `StaleHead "no trusted …"` either.
// Pairs with S10 so "`max_age` unset is checked nowhere" is pinned
// on two independent layouts (trusted present and absent).
// =====================================================================
#[test]
fn s10b_max_age_unset_with_no_trusted_emits_no_stale_head() {
    let d = Temp::new();
    let cp0 = signed_cp_at(0, Record::genesis(&TRAIL), &Mmr::new(), T_S1);
    put_segment(&d.0, 0, &[&cp0], &[]);
    let path = segment_path(&d.0, 0);
    let r = report(vec![path.clone()], other_only_policy(), None, now());
    let expected = vec![
        located(
            K::UntrustedKey,
            path,
            1,
            0,
            format!("key {FIXTURE_KEY_HEX} not listed for trail {TRAIL_HEX}"),
        ),
        uncovered(0, 0),
    ];
    assert_findings(r.findings(), &expected, "S10b");
    assert!(!r.is_strict_valid());
    assert_eq!(r.covered_through(), None);
}

// =====================================================================
// S11b — ACCEPTANCE sibling of S11: second call wins when it widens
// then tightens the tolerance. Pairs with S11 across two independent
// value pairs so "second `max_age` replaces first" is pinned on a
// second layout (tightening from `MAX_AGE` to `Duration::ZERO`).
// =====================================================================
#[test]
fn s11b_second_max_age_call_can_tighten_to_zero() {
    let d = Temp::new();
    let cp0 = signed_cp_at(0, Record::genesis(&TRAIL), &Mmr::new(), T_S12_CP0);
    put_segment(&d.0, 0, &[&cp0], &[]);
    let path = segment_path(&d.0, 0);
    let v = Verifier::new(trusted_policy())
        .with_now_for_test(now())
        .max_age(MAX_AGE)
        .unwrap()
        .max_age(Duration::ZERO)
        .unwrap();
    let r = v.verify_files(vec![path.clone()]).unwrap();
    let expected = vec![stale_zero(path, 1, 0, T_S12_CP0)];
    assert_findings(r.findings(), &expected, "S11b");
    assert!(!r.is_strict_valid());
    assert_eq!(r.covered_through(), Some(0));
}
