//! Operator resume API, durability and receipt handoff (B3d2b2).
use super::crash_fixtures::content;
use super::operators::SignOnly;
use super::tests::{Temp, bad, bytes, create, entry, records, signer, snapshot};
use super::*;
use std::fs;

fn config(t: &Temp) -> AuditConfig {
    AuditConfig::new("vigil").dir(&t.0)
}
fn head(r: &Record) -> (u64, [u8; 32]) {
    (r.context.seq, r.hash())
}
fn invoke(t: &Temp, h: (u64, [u8; 32]), lost: u64) -> (AuditTrail, Receipt, Checkpoint) {
    config(t)
        .resume(signer(), h, lost, "operator", "reviewed")
        .unwrap()
}
fn genesis_layout(t: &Temp, empty: bool) -> (u64, [u8; 32]) {
    let mut s = create(t);
    s.closed = true;
    let h = (0, Record::genesis(&s.trail));
    if empty {
        fs::write(t.0.join("audit.jsonl"), []).unwrap();
    } else {
        fs::remove_file(t.0.join("audit.jsonl")).unwrap();
    }
    h
}
#[test]
fn returned_opening_checkpoint_matches_disk_and_signature() {
    let t = Temp::new();
    let h = genesis_layout(&t, true);
    let key = signer();
    let (_trail, receipt, opening) = config(&t)
        .resume(key.clone(), h, 5, "operator", "reviewed")
        .unwrap();
    let rs = records(&t);
    let record = &rs[0];
    assert_eq!(opening.seq(), 6);
    assert_eq!(opening.seq(), record.context.seq);
    assert_eq!(opening.hash(), record.hash());
    assert_eq!(
        opening.line(),
        String::from_utf8(line(record).unwrap())
            .unwrap()
            .trim_end_matches('\n')
    );
    // Signature is the final field (tag 0x24) in the canonical record.
    let canonical = record.canonical();
    let signature: [u8; 64] = canonical[canonical.len() - 64..].try_into().unwrap();
    crate::audit::verify_signature(
        &key.public_key(),
        &record.signing_message().unwrap(),
        &signature,
    )
    .unwrap();
    assert_eq!(receipt.seq(), rs[1].context.seq);
}

#[test]
fn returned_resume_receipt_links_to_returned_opening_checkpoint() {
    let t = Temp::new();
    let h = genesis_layout(&t, true);
    let (_trail, receipt, opening) = config(&t)
        .resume(signer(), h, 5, "operator", "reviewed")
        .unwrap();
    let rs = records(&t);
    let record = rs.iter().find(|r| r.context.seq == receipt.seq()).unwrap();
    assert_eq!(record.hash(), receipt.hash());
    assert_eq!(record.context.previous, opening.hash());
}

#[test]
fn live_states_details_single_write_receipt_and_round_trip() {
    for state in 0..6 {
        let t = Temp::new();
        let mut setup = create(&t);
        setup.closed = true;
        setup.record(&entry()).unwrap();
        let original = records(&t);
        let mut h = head(original.last().unwrap());
        match state {
            0 => {
                // headless after a retained sealed base
                fs::write(
                    t.0.join("audit-20000101T000000.000000000Z.jsonl"),
                    line(&original[0]).unwrap(),
                )
                .unwrap();
                fs::write(t.0.join("audit.jsonl"), line(&original[1]).unwrap()).unwrap();
            }
            1 => {
                // creation-only rollback
                fs::write(t.0.join("audit.jsonl"), line(&original[0]).unwrap()).unwrap();
                h = head(&original[0]);
            }
            2 | 3 => {
                h = (0, Record::genesis(&setup.trail));
                if state == 2 {
                    fs::remove_file(t.0.join("audit.jsonl")).unwrap();
                } else {
                    fs::write(t.0.join("audit.jsonl"), []).unwrap();
                }
            }
            4 => {
                let mut b = bytes(&t);
                b.extend(b"{\"torn\":");
                fs::write(t.0.join("audit.jsonl"), b).unwrap();
            }
            _ => {} // well-formed at head, no gap
        }
        let before = t.0.join("audit.jsonl").exists().then(|| bytes(&t));
        let key = SignOnly::new("22", false);
        hooks::EVENTS.with(|e| e.borrow_mut().clear());
        let lost = if state == 5 { h.0 } else { 5 };
        let (trail, receipt, _) = config(&t)
            .resume(key.clone(), h, lost, "operator", "reviewed")
            .unwrap();
        let events = hooks::EVENTS.with(|e| e.borrow().clone());
        assert_eq!(events.iter().filter(|e| **e == "write").count(), 1);
        assert_eq!(events.iter().filter(|e| **e == "staging").count(), 1);
        assert_eq!(events.iter().filter(|e| **e == "staging-dir").count(), 1);
        assert_eq!(
            events
                .iter()
                .filter(|e| **e == "settle-promote-dir")
                .count(),
            1
        );
        assert_eq!(key.calls.load(Ordering::Relaxed), 1);
        assert!(!t.0.join(".audit-resume.jsonl").exists());
        let rs = records(&t);
        assert_eq!(rs.len(), 2);
        assert_eq!(receipt.seq(), lost + 2);
        assert_eq!(receipt.hash(), rs[1].hash());
        assert_eq!(rs[0].context.previous, h.1);
        assert_eq!(rs[1].context.previous, rs[0].hash());
        assert!(rs.iter().all(|r| r.context.repaired.is_none()));
        let Kind::Entry(e) = &rs[1].kind else {
            panic!()
        };
        assert_eq!(e.object, hex(&trail.trail()));
        let details = e.details.as_ref().unwrap();
        let file = details.split_once(" file=").unwrap().1;
        assert_eq!(
            details,
            &format!(
                "head={}:{} lost_through={lost} file={file}",
                h.0,
                digest_string(&h.1)
            )
        );
        if let Some(before) = before {
            assert_ne!(file, "-");
            assert_eq!(fs::read(t.0.join(file)).unwrap(), before);
        } else {
            assert_eq!(file, "-");
        }
        let reopened = config(&t)
            .expect_head(receipt.seq(), receipt.hash())
            .open(signer())
            .unwrap();
        assert_eq!(reopened.record(&entry()).unwrap().seq(), lost + 3);
        // The retained resume signer also signs subsequent checkpoints and Drop.
        trail.checkpoint().unwrap();
        assert_eq!(key.calls.load(Ordering::Relaxed), 2);
        drop(trail);
        assert_eq!(key.calls.load(Ordering::Relaxed), 3);
    }
}
#[test]
fn empty_sealed_then_lost_accepts_genesis_and_shared_leaf() {
    let t = Temp::new();
    let h = genesis_layout(&t, true);
    let (first, _, _) = invoke(&t, h, 5);
    fs::remove_file(t.0.join("audit.jsonl")).unwrap();
    let (_second, receipt, _) = invoke(&t, h, 8);
    let rs = records(&t);
    let Kind::Checkpoint(cp) = &rs[0].kind else {
        panic!()
    };
    let mut mmr = Mmr::new();
    mmr.push(h.1).unwrap();
    assert_eq!(cp.size, 1);
    assert_eq!(cp.peaks, mmr.peaks());
    assert_eq!(cp.root, mmr.root());
    assert_eq!(receipt.seq(), 10);
    // first has acknowledged 7, which the second resume's L=8 preserves.
    assert_eq!(first.record(&entry()).unwrap().seq(), 11);
}
#[test]
fn head_refusals_are_exact_in_every_live_branch() {
    for state in 0..7 {
        for mismatch in 0..4 {
            let t = Temp::new();
            let mut setup = create(&t);
            setup.closed = true;
            setup.record(&entry()).unwrap();
            let rs = records(&t);
            let mut h = head(&rs[1]);
            match state {
                0 => {}
                1 => {
                    fs::write(t.0.join("audit.jsonl"), line(&rs[0]).unwrap()).unwrap();
                    h = head(&rs[0]);
                }
                2 => {
                    fs::write(
                        t.0.join("audit-20000101T000000.000000000Z.jsonl"),
                        line(&rs[0]).unwrap(),
                    )
                    .unwrap();
                    fs::write(t.0.join("audit.jsonl"), line(&rs[1]).unwrap()).unwrap();
                }
                3 => {
                    fs::remove_file(t.0.join("audit.jsonl")).unwrap();
                    h = (0, Record::genesis(&setup.trail));
                }
                4 => {
                    fs::write(t.0.join("audit.jsonl"), []).unwrap();
                    h = (0, Record::genesis(&setup.trail));
                }
                _ => {
                    // Deleted and empty live files can still have a sealed predecessor.
                    fs::write(
                        t.0.join("audit-20000101T000000.000000000Z.jsonl"),
                        line(&rs[0]).unwrap(),
                    )
                    .unwrap();
                    if state == 5 {
                        fs::remove_file(t.0.join("audit.jsonl")).unwrap();
                    } else {
                        fs::write(t.0.join("audit.jsonl"), []).unwrap();
                    }
                    h = head(&rs[0]);
                }
            }
            h = match mismatch {
                0 => (h.0, [9; 32]),
                1 => (h.0.saturating_add(1), h.1),
                2 => (0, [8; 32]),
                _ if state <= 2 || state >= 5 => (0, Record::genesis(&setup.trail)),
                _ => continue,
            };
            let before = content(&t.0);
            let key = SignOnly::new("22", false);
            bad(
                config(&t).resume(key.clone(), h, 5, "a", "r"),
                AuditErrorKind::HeadMismatch,
            );
            assert_eq!(content(&t.0), before);
            assert_eq!(key.calls.load(Ordering::Relaxed), 0);
            assert_eq!(key.public.load(Ordering::Relaxed), 0);
        }
    }
}
#[test]
fn resume_loss_bound_precedes_head_and_poison_checks() {
    for poisoned in [false, true] {
        let t = Temp::new();
        let actual = genesis_layout(&t, false);
        let h = if poisoned {
            fs::write(t.0.join("audit.poison"), b"planted poison").unwrap();
            actual
        } else {
            (0, [7; 32])
        };
        let before = snapshot(&t);
        let key = SignOnly::new("22", false);
        bad(
            config(&t).resume(key.clone(), h, i64::MAX as u64 - 1, "a", "r"),
            AuditErrorKind::InvalidConfig,
        );
        assert_eq!(snapshot(&t), before);
        assert_eq!(key.calls.load(Ordering::Relaxed), 0);
    }
}
#[test]
fn validation_and_base_refusal_never_touch_signer() {
    let t = Temp::new();
    let key = SignOnly::new("22", false);
    bad(
        config(&t).resume(key.clone(), (2, [0; 32]), 1, "a", "r"),
        AuditErrorKind::InvalidConfig,
    );
    for (a, r) in [("", "r"), ("a", ""), ("a\0", "r"), ("a", "r\0")] {
        bad(
            config(&t).resume(key.clone(), (0, [0; 32]), 0, a, r),
            AuditErrorKind::InvalidEntry,
        );
    }
    bad(
        config(&t)
            .expect_head(0, [0; 32])
            .resume(key.clone(), (0, [0; 32]), 0, "a", "r"),
        AuditErrorKind::InvalidConfig,
    );
    assert!(content(&t.0).is_empty());
    let mut setup = create(&t);
    setup.closed = true;
    setup.record(&entry()).unwrap();
    let rs = records(&t);
    fs::write(t.0.join("audit.jsonl"), line(&rs[1]).unwrap()).unwrap();
    let before = content(&t.0);
    bad(
        config(&t).resume(key.clone(), head(&rs[1]), 5, "a", "r"),
        AuditErrorKind::CorruptTrail,
    );
    assert_eq!(content(&t.0), before);
    assert_eq!(key.calls.load(Ordering::Relaxed), 0);
    assert_eq!(key.public.load(Ordering::Relaxed), 0);
}
#[test]
fn returned_receipt_raises_acknowledgement_before_handoff() {
    let t = Temp::new();
    let mut setup = create(&t);
    setup.closed = true;
    let h = head(&records(&t)[0]);
    let (first, receipt, _) = invoke(&t, h, 5);
    assert_eq!(receipt.seq(), 7);
    fs::remove_file(t.0.join("audit.jsonl")).unwrap();
    let (_second, _, _) = invoke(&t, h, 6);
    let before = content(&t.0);
    bad(first.record(&entry()), AuditErrorKind::HeadMismatch);
    bad(first.checkpoint(), AuditErrorKind::HeadMismatch);
    bad(first.close(), AuditErrorKind::HeadMismatch);
    assert_eq!(content(&t.0), before);
}
#[test]
fn staging_failures_truncate_and_poison_only_when_required() {
    for site in ["write", "staging", "staging-dir"] {
        for truncate in [false, true] {
            let t = Temp::new();
            let h = genesis_layout(&t, false);
            hooks::FAIL.with(|v| {
                *v.borrow_mut() = if truncate {
                    vec![site, "truncate"]
                } else {
                    vec![site]
                }
            });
            bad(
                config(&t).resume(signer(), h, 5, "a", "r"),
                AuditErrorKind::Io,
            );
            assert_eq!(
                t.0.join("audit.poison").exists(),
                truncate && site != "write"
            );
            if !truncate {
                assert_eq!(
                    fs::metadata(t.0.join(".audit-resume.jsonl")).unwrap().len(),
                    0
                );
            }
            assert!(!t.0.join("audit.jsonl").exists());
        }
    }
}
#[test]
fn final_directory_fsync_poison_and_recovery() {
    let t = Temp::new();
    let h = genesis_layout(&t, true);
    hooks::FAIL.with(|v| *v.borrow_mut() = vec!["settle-promote-dir"]);
    bad(
        config(&t).resume(signer(), h, 5, "a", "r"),
        AuditErrorKind::Io,
    );
    assert!(t.0.join("audit.poison").exists());
    assert!(!t.0.join(".audit-resume.jsonl").exists());
    let rs = records(&t);
    assert_eq!(rs.len(), 2);
    // Model completed operator clearing procedure, not a library retry.
    fs::remove_file(t.0.join("audit.poison")).unwrap();
    let _reopened = config(&t)
        .expect_head(rs[1].context.seq, rs[1].hash())
        .open(signer())
        .unwrap();
}
#[test]
fn poison_precedes_settlement_even_when_planted_before_lock() {
    for seam in [false, true] {
        let t = Temp::new();
        let h = genesis_layout(&t, false);
        fs::write(t.0.join(".audit-next.jsonl"), b"pending evidence").unwrap();
        if seam {
            let path = t.0.clone();
            hooks::OBSERVE.with(|v| {
                *v.borrow_mut() = Some(Box::new(move |site| {
                    if site == "resume-before-lock" {
                        fs::write(path.join("audit.poison"), b"barrier").unwrap();
                    }
                }))
            });
        } else {
            fs::write(t.0.join("audit.poison"), b"barrier").unwrap();
        }
        let key = SignOnly::new("22", false);
        bad(
            config(&t).resume(key.clone(), h, 5, "a", "r"),
            AuditErrorKind::Poisoned,
        );
        hooks::OBSERVE.with(|v| *v.borrow_mut() = None);
        assert_eq!(
            fs::read(t.0.join(".audit-next.jsonl")).unwrap(),
            b"pending evidence"
        );
        assert!(!t.0.join("audit.jsonl").exists());
        assert_eq!(key.calls.load(Ordering::Relaxed), 0);
        assert_eq!(key.public.load(Ordering::Relaxed), 0);
    }
}
#[test]
fn pending_next_is_settled_before_head_check() {
    let t = Temp::new();
    let mut setup = create(&t);
    setup.closed = true;
    let prior = records(&t)[0].clone();
    let mut mmr = Mmr::new();
    mmr.push(prior.hash()).unwrap();
    let cp = Sink::signed(
        &*signer(),
        RecordContext::new(setup.trail, 1, 1_000_000_000, "vigil", prior.hash()),
        &mmr,
    )
    .unwrap();
    fs::write(t.0.join(".audit-next.jsonl"), line(&cp).unwrap()).unwrap();
    let (_trail, receipt, _) = invoke(&t, head(&cp), 5);
    assert_eq!(receipt.seq(), 7);
    assert!(!t.0.join(".audit-next.jsonl").exists());
}
#[test]
fn changed_directory_after_staging_discards_without_receipt() {
    let t = Temp::new();
    let h = genesis_layout(&t, true);
    let path = t.0.clone();
    hooks::OBSERVE.with(|v| {
        *v.borrow_mut() = Some(Box::new(move |site| {
            if site == "staging-dir" {
                fs::rename(
                    path.join("audit.jsonl"),
                    path.join("audit-20990101T000000.000000000Z.jsonl"),
                )
                .unwrap();
            }
        }))
    });
    bad(
        config(&t).resume(signer(), h, 5, "a", "r"),
        AuditErrorKind::Io,
    );
    hooks::OBSERVE.with(|v| *v.borrow_mut() = None);
    assert!(!t.0.join(".audit-resume.jsonl").exists());
}

#[test]
fn inline_every_short_write_prefix_rolls_back_pair() {
    let source = Temp::new();
    let h = genesis_layout(&source, true);
    let (_trail, _, _) = invoke(&source, h, 5);
    let length = bytes(&source).len();
    for prefix in 0..length {
        let t = Temp::new();
        let h = genesis_layout(&t, true);
        let before = bytes(&t);
        hooks::SHORT.with(|v| v.set(Some(prefix)));
        bad(
            config(&t).resume(signer(), h, 5, "operator", "reviewed"),
            AuditErrorKind::Io,
        );
        assert_eq!(bytes(&t), before, "prefix {prefix}");
        assert_eq!(
            fs::metadata(t.0.join(".audit-resume.jsonl")).unwrap().len(),
            0
        );
        assert!(!t.0.join("audit.poison").exists());
        let dir = File::open(&t.0).unwrap();
        assert!(rotate::rotated_names_at(&dir, "audit").unwrap().is_empty());
    }
}
#[test]
fn inline_crash_points_recover_matching_filename() {
    use super::crash_fixtures::Process;
    for empty in [false, true] {
        for site in [
            "resume-before-lock",
            "resume-poison-checked",
            "resume-marker-checked",
            "resume-settled",
            "resume-folded",
            "resume-name-picked",
            "create-staging",
            "after-write",
            "staging",
            "staging-dir",
            "resume-staging-read",
            "seal-rename",
            "promote",
            "settle-after-promote",
            "settle-promote-dir",
        ] {
            if !empty && site == "seal-rename" {
                continue;
            }
            let t = Temp::new();
            genesis_layout(&t, empty);
            let mut process = Process::spawn(&t.0, "resume", site);
            process.ready();
            process.kill();
            let dir = File::open(&t.0).unwrap();
            let id = marker(&dir).unwrap();
            settle(&dir, id, &AtomicBool::new(false)).unwrap();
            assert!(!t.0.join(".audit-resume.jsonl").exists());
            if let Ok(reader) = TrailReader::open(&t.0, id, None) {
                drop(reader);
                let rs = records(&t);
                assert_eq!(rs.len(), 2);
                let Kind::Entry(e) = &rs[1].kind else {
                    panic!()
                };
                let file = e.details.as_ref().unwrap().split_once(" file=").unwrap().1;
                if empty {
                    assert_ne!(file, "-");
                    assert!(t.0.join(file).exists());
                } else {
                    assert_eq!(file, "-");
                }
            } else {
                assert!(rotate::rotated_names_at(&dir, "audit").unwrap().is_empty());
            }
        }
    }
}

#[test]
fn two_process_resume_waits_for_rotate_checkpoint_and_resume() {
    use super::crash_fixtures::Process;
    for role in [
        "resume-race-rotate",
        "resume-race-checkpoint",
        "resume-race-resume",
    ] {
        let t = Temp::new();
        create(&t).close().unwrap();
        let mut first = Process::spawn(&t.0, role, "");
        first.ready();
        let mut second = Process::spawn(&t.0, "resume-race-contender", "");
        second.ready();
        first.close();
        second.finish();
        assert!(!t.0.join(".audit-resume.jsonl").exists());
        let _fresh = config(&t).open(signer()).unwrap();
    }
}

#[test]
fn checkpoint_conversion_failure_precedes_staging_and_promotion() {
    let t = Temp::new();
    let h = genesis_layout(&t, true);
    let before = content(&t.0);
    // Model a failure of the shared checkpoint constructor's validation.
    hooks::FAIL.with(|v| *v.borrow_mut() = vec!["checkpoint-convert"]);
    let error = config(&t).resume(signer(), h, 5, "a", "r").unwrap_err();
    assert_eq!(error.kind(), AuditErrorKind::CorruptTrail);
    assert_eq!(content(&t.0), before);
}

#[test]
fn failure_after_promotion_is_io_and_never_a_corruption_refusal() {
    let t = Temp::new();
    let h = genesis_layout(&t, true);
    let path = t.0.clone();
    hooks::OBSERVE.with(|v| {
        *v.borrow_mut() = Some(Box::new(move |site| {
            if site == "settle-after-promote" {
                fs::write(path.join("audit.jsonl"), b"invalid promoted data\n").unwrap();
            }
        }))
    });
    let error = config(&t).resume(signer(), h, 5, "a", "r").unwrap_err();
    hooks::OBSERVE.with(|v| *v.borrow_mut() = None);
    assert_eq!(error.kind(), AuditErrorKind::Io);
    assert!(error.to_string().contains("initial validation"));
}

#[test]
fn marker_errors_and_signer_failure_return_no_handle() {
    let t = Temp::new();
    let key = SignOnly::new("22", false);
    bad(
        config(&t)
            .dir(t.0.join("new"))
            .resume(key.clone(), (0, [0; 32]), 0, "a", "r"),
        AuditErrorKind::MissingTrail,
    );
    assert!(t.0.join("new").is_dir());
    bad(
        config(&t).resume(key.clone(), (0, [0; 32]), 0, "a", "r"),
        AuditErrorKind::MissingTrail,
    );
    fs::write(t.0.join("audit.trail"), b"NONCANONICAL\n").unwrap();
    bad(
        config(&t).resume(key.clone(), (0, [0; 32]), 0, "a", "r"),
        AuditErrorKind::CorruptTrail,
    );
    assert_eq!(key.public.load(Ordering::Relaxed), 0);
    let t = Temp::new();
    let h = genesis_layout(&t, true);
    let before = content(&t.0);
    let key = SignOnly::new("22", true);
    bad(
        config(&t).resume(key.clone(), h, 5, "a", "r"),
        AuditErrorKind::Signer,
    );
    assert_eq!(key.calls.load(Ordering::Relaxed), 1);
    assert_eq!(content(&t.0), before);
}

#[test]
fn restored_live_after_staging_discards_without_receipt() {
    let t = Temp::new();
    let mut setup = create(&t);
    setup.closed = true;
    setup.record(&entry()).unwrap();
    let original = bytes(&t);
    let h = (0, Record::genesis(&setup.trail));
    fs::remove_file(t.0.join("audit.jsonl")).unwrap();
    let path = t.0.clone();
    let restored = original.clone();
    hooks::OBSERVE.with(|v| {
        *v.borrow_mut() = Some(Box::new(move |site| {
            if site == "staging-dir" {
                fs::write(path.join("audit.jsonl"), &restored).unwrap();
            }
        }));
    });
    let result = config(&t).resume(signer(), h, 5, "a", "r");
    hooks::OBSERVE.with(|v| *v.borrow_mut() = None);
    bad(result, AuditErrorKind::Io);
    assert_eq!(bytes(&t), original);
    assert_eq!(
        records(&t)
            .iter()
            .map(|r| r.context.seq)
            .collect::<Vec<_>>(),
        [0, 1]
    );
    assert!(!t.0.join(".audit-resume.jsonl").exists());
}

#[test]
fn resume_int64_and_size_refusals_sign_nothing() {
    let t = Temp::new();
    let h = genesis_layout(&t, false);
    let key = SignOnly::new("22", false);
    let before = content(&t.0);
    for lost in [i64::MAX as u64 - 1, u64::MAX] {
        bad(
            config(&t).resume(key.clone(), h, lost, "a", "r"),
            AuditErrorKind::InvalidConfig,
        );
        assert_eq!(key.calls.load(Ordering::Relaxed), 0);
        assert_eq!(content(&t.0), before);
    }
    bad(
        config(&t).resume(key.clone(), h, 5, "a", "r".repeat(1_100_000)),
        AuditErrorKind::TooLarge,
    );
    assert_eq!(key.calls.load(Ordering::Relaxed), 0);
    assert_eq!(content(&t.0), before);
    bad(
        AuditConfig::new("s".repeat(1_100_000))
            .dir(&t.0)
            .resume(key.clone(), h, 5, "a", "r"),
        AuditErrorKind::InvalidConfig,
    );
    assert_eq!(key.calls.load(Ordering::Relaxed), 0);
    assert_eq!(content(&t.0), before);
    // Only action reserves the prefix; actor and reason may carry it as text.
    let (_trail, _, _) = config(&t)
        .resume(key.clone(), h, 5, "vigil.audit.actor", "vigil.audit.reason")
        .unwrap();
    assert_eq!(key.calls.load(Ordering::Relaxed), 1);
}

#[test]
fn resume_at_int64_top_refuses_next_record() {
    let t = Temp::new();
    let h = genesis_layout(&t, false);
    let (trail, receipt, _) = invoke(&t, h, i64::MAX as u64 - 2);
    assert_eq!(receipt.seq(), i64::MAX as u64);
    let before = content(&t.0);
    let error = trail.record(&entry()).unwrap_err();
    assert_eq!(error.kind(), AuditErrorKind::InvalidConfig);
    assert!(error.to_string().contains("sequence exceeds OTLP int64"));
    assert_eq!(content(&t.0), before);
}
