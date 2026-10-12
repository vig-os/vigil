//! Exact-head operator writes and their refusal/crash boundaries (B3c).
use super::crash_fixtures::content;
use super::tests::{Temp, bad, bytes, create, entry, records, signer};
use super::*;
use std::{fs, sync::atomic::AtomicUsize};

#[derive(Debug)]
pub(super) struct SignOnly {
    key: Arc<dyn Signer>,
    pub(super) calls: AtomicUsize,
    public: AtomicUsize,
    fail: bool,
}
impl SignOnly {
    pub(super) fn new(seed: &str, fail: bool) -> Arc<Self> {
        Arc::new(Self {
            key: Arc::new(KeyFileSigner::from_hex(&seed.repeat(32)).unwrap()),
            calls: AtomicUsize::new(0),
            public: AtomicUsize::new(0),
            fail,
        })
    }
}
impl Signer for SignOnly {
    fn public_key(&self) -> [u8; 32] {
        self.public.fetch_add(1, Ordering::Relaxed);
        self.key.public_key()
    }
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], SignerError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.fail {
            Err(SignerError::new("operator signer unavailable"))
        } else {
            self.key.sign(message)
        }
    }
}
fn head(r: &Record) -> Head {
    Head {
        seq: r.context.seq,
        hash: r.hash(),
    }
}
fn clean(t: &Temp) -> Head {
    head(&create(t).close().unwrap())
}
fn op(bound: Head) -> OperatorOp {
    OperatorOp::Rotate {
        bound,
        actor: "operator".into(),
        reason: "scheduled".into(),
    }
}
fn invoke(
    t: &Temp,
    key: Arc<dyn Signer>,
    expect: Head,
    op: OperatorOp,
) -> Result<OperatorWritten, AuditError> {
    Sink::open(&t.0, key, Config::default(), None)?.operator_write(expect, op)
}
fn append_raw(t: &Temp, bytes: &[u8]) {
    File::options()
        .append(true)
        .open(t.0.join("audit.jsonl"))
        .unwrap()
        .write_all(bytes)
        .unwrap();
}
fn chained(_t: &Temp, previous: &Record, e: Entry) -> Record {
    Record::new(
        RecordContext::new(
            previous.context.trail,
            previous.context.seq + 1,
            1_000_000_000,
            "vigil",
            previous.hash(),
        ),
        e,
    )
    .unwrap()
}
fn refused(t: &Temp, expected: Head, op: OperatorOp) {
    let before = content(&t.0);
    let key = SignOnly::new("22", false);
    bad(
        invoke(t, key.clone(), expected, op),
        AuditErrorKind::HeadMismatch,
    );
    assert_eq!(content(&t.0), before);
    assert_eq!(key.calls.load(Ordering::Relaxed), 0);
    assert_eq!(key.public.load(Ordering::Relaxed), 0);
}
#[test]
fn exact_sequence_and_hash_and_no_drop_signature() {
    for checkpoint in [false, true] {
        let t = Temp::new();
        let h = clean(&t);
        let operation = || {
            if checkpoint {
                OperatorOp::Checkpoint
            } else {
                op(h)
            }
        };
        refused(&t, Head { hash: [9; 32], ..h }, operation());
        refused(
            &t,
            Head {
                seq: h.seq - 1,
                ..h
            },
            if checkpoint {
                OperatorOp::Checkpoint
            } else {
                op(head(&records(&t)[0]))
            },
        );
        let key = SignOnly::new("22", true);
        let before = bytes(&t);
        bad(
            invoke(&t, key.clone(), h, operation()),
            AuditErrorKind::Signer,
        );
        assert_eq!(bytes(&t), before);
        assert_eq!(key.calls.load(Ordering::Relaxed), 1);
    }
}
#[test]
fn one_signature_one_write_no_sealing_or_cadence() {
    for checkpoint in [false, true] {
        let t = Temp::new();
        let h = clean(&t);
        let key = SignOnly::new("22", false);
        let sink = Sink::open(
            &t.0,
            key.clone(),
            Config {
                max_bytes: 1,
                checkpoint_every: 1,
                ..Config::default()
            },
            None,
        )
        .unwrap();
        hooks::EVENTS.with(|e| e.borrow_mut().clear());
        let result = sink
            .operator_write(
                h,
                if checkpoint {
                    OperatorOp::Checkpoint
                } else {
                    op(h)
                },
            )
            .unwrap();
        let events = hooks::EVENTS.with(|e| e.borrow().clone());
        assert_eq!(events.iter().filter(|e| **e == "write").count(), 1);
        assert_eq!(events.iter().filter(|e| **e == "operator-data").count(), 1);
        assert!(!events.contains(&"create-staging"));
        assert_eq!(key.calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            result.checkpoint.context.seq,
            h.seq + if checkpoint { 1 } else { 2 }
        );
        if let Some(record) = result.record {
            assert_eq!(result.checkpoint.context.previous, record.hash());
            let Kind::Entry(e) = record.kind else {
                panic!()
            };
            assert_eq!(e.action, "vigil.audit.key_rotated");
            assert_eq!(e.object, hex(&result.checkpoint.context.trail));
            assert_eq!(
                e.details.as_deref(),
                Some(
                    format!(
                        "old_key={} bound={}:{}",
                        hex(&signer().public_key()),
                        h.seq,
                        digest_string(&h.hash)
                    )
                    .as_str()
                )
            );
        }
        let all = records(&t);
        let mut covered = Mmr::new();
        for r in &all[..all.len() - 1] {
            covered.push(r.hash()).unwrap();
        }
        let Kind::Checkpoint(fields) = &result.checkpoint.kind else {
            panic!()
        };
        assert_eq!(fields.root, covered.root());
        assert_eq!(fields.size, covered.size());
        assert_eq!(fields.key, key.key.public_key());
        assert_eq!(fs::read_dir(&t.0).unwrap().count(), 2);
        let mut application = Sink::open(
            &t.0,
            key,
            Config {
                max_bytes: 1,
                ..Config::default()
            },
            None,
        )
        .unwrap();
        application.closed = true;
        application.record(&entry()).unwrap();
        assert!(fs::read_dir(&t.0).unwrap().count() > 2);
    }
}
#[test]
fn bound_lookup_uses_checkpoint_hash_and_its_key() {
    let t = Temp::new();
    let h = clean(&t);
    let later = invoke(&t, SignOnly::new("33", false), h, OperatorOp::Checkpoint)
        .unwrap()
        .checkpoint;
    let expected = head(&later);
    let r = invoke(&t, SignOnly::new("22", false), expected, op(h))
        .unwrap()
        .record
        .unwrap();
    let Kind::Entry(e) = r.kind else { panic!() };
    assert_eq!(
        e.details.unwrap(),
        format!(
            "old_key={} bound={}:{}",
            hex(&signer().public_key()),
            h.seq,
            digest_string(&h.hash)
        )
    );
    let current = head(records(&t).last().unwrap());
    refused(&t, current, op(Head { hash: [3; 32], ..h }));
    refused(&t, current, op(head(&records(&t)[3]))); // rotation entry, not checkpoint
    let before = bytes(&t);
    let same = SignOnly::new("11", false);
    bad(
        invoke(&t, same.clone(), current, op(h)),
        AuditErrorKind::InvalidConfig,
    );
    assert_eq!(same.calls.load(Ordering::Relaxed), 0);
    assert_eq!(bytes(&t), before);
}
#[test]
fn validation_happens_before_any_disk_access() {
    let t = Temp::new();
    let config = AuditConfig::new("svc").dir(t.0.join("missing"));
    let h = (1, [1; 32]);
    for (actor, reason) in [("", "r"), ("a", ""), ("a\0b", "r"), ("a", "r\0")] {
        bad(
            config.clone().rotate(signer(), h, h, actor, reason),
            AuditErrorKind::InvalidEntry,
        );
    }
    bad(
        config.clone().rotate(signer(), (2, [1; 32]), h, "a", "r"),
        AuditErrorKind::InvalidConfig,
    );
    for checkpoint in [false, true] {
        let config = config.clone().expect_head(1, [1; 32]);
        let error = if checkpoint {
            config.checkpoint(signer(), h).map(|_| ())
        } else {
            config.rotate(signer(), h, h, "a", "r").map(|_| ())
        }
        .unwrap_err();
        assert_eq!(error.kind(), AuditErrorKind::InvalidConfig);
        assert_eq!(
            error.to_string(),
            "InvalidConfig: rotate/checkpoint take an explicit expected head; builder expect_head is invalid"
        );
    }
    assert_eq!(fs::read_dir(&t.0).unwrap().count(), 0);
}
#[test]
fn between_open_and_lock_same_length_rewrite_is_seen() {
    for checkpoint in [false, true] {
        let t = Temp::new();
        let h = clean(&t);
        let path = t.0.join("audit.jsonl");
        let key = SignOnly::new("22", false);
        let sink = Sink::open(&t.0, key.clone(), Config::default(), None).unwrap();
        let mut rs = records(&t);
        let last = rs.last_mut().unwrap();
        last.context.time += 1;
        // Writers validate chain/hashes, not signatures. A changed final checkpoint
        // remains a structurally valid head of exactly the same encoded length.
        let replacement: Vec<u8> = rs.iter().flat_map(|r| line(r).unwrap()).collect();
        assert_eq!(replacement.len(), bytes(&t).len());
        let expected_bytes = replacement.clone();
        hooks::OBSERVE.with(|o| {
            *o.borrow_mut() = Some(Box::new(move |site| {
                if site == "operator-before-lock" {
                    fs::write(&path, &replacement).unwrap();
                }
            }))
        });
        bad(
            sink.operator_write(
                h,
                if checkpoint {
                    OperatorOp::Checkpoint
                } else {
                    op(h)
                },
            ),
            AuditErrorKind::HeadMismatch,
        );
        hooks::OBSERVE.with(|o| *o.borrow_mut() = None);
        assert_eq!(bytes(&t), expected_bytes);
        assert_eq!(key.calls.load(Ordering::Relaxed), 0);
        assert_eq!(key.public.load(Ordering::Relaxed), 0);
    }
}
#[test]
fn lock_honouring_writer_between_open_and_operator_section() {
    for checkpoint in [false, true] {
        let t = Temp::new();
        let h = clean(&t);
        let path = t.0.clone();
        let key = SignOnly::new("22", false);
        let sink = Sink::open(&t.0, key.clone(), Config::default(), None).unwrap();
        let changed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = changed.clone();
        hooks::OBSERVE.with(|o| {
            *o.borrow_mut() = Some(Box::new(move |site| {
                if site == "operator-before-lock" {
                    let mut writer = Sink::open(&path, signer(), Config::default(), None).unwrap();
                    writer.closed = true;
                    writer.record(&entry()).unwrap();
                    *captured.lock().unwrap() = fs::read(path.join("audit.jsonl")).unwrap();
                }
            }))
        });
        bad(
            sink.operator_write(
                h,
                if checkpoint {
                    OperatorOp::Checkpoint
                } else {
                    op(h)
                },
            ),
            AuditErrorKind::HeadMismatch,
        );
        hooks::OBSERVE.with(|o| *o.borrow_mut() = None);
        assert_eq!(bytes(&t), *changed.lock().unwrap());
        assert_eq!(key.calls.load(Ordering::Relaxed), 0);
    }
}
#[test]
fn poison_precedes_settlement_in_operator_section_cases_4_and_6() {
    for checkpoint in [false, true] {
        for staging in [false, true] {
            let t = Temp::new();
            let h = clean(&t);
            let path = t.0.clone();
            let key = SignOnly::new("22", false);
            let sink = Sink::open(&t.0, key.clone(), Config::default(), None).unwrap();
            let prior = records(&t).last().unwrap().clone();
            let mmr = {
                let mut m = Mmr::new();
                for r in records(&t) {
                    m.push(r.hash()).unwrap();
                }
                m
            };
            let cp = Sink::signed(
                &*signer(),
                RecordContext::new(
                    prior.context.trail,
                    h.seq + 1,
                    1_000_000_000,
                    "vigil",
                    h.hash,
                ),
                &mmr,
            )
            .unwrap();
            let snapshot = Arc::new(std::sync::Mutex::new(None));
            let captured = snapshot.clone();
            hooks::OBSERVE.with(|o| {
                *o.borrow_mut() = Some(Box::new(move |site| {
                    if site == "operator-before-lock" {
                        fs::write(path.join("audit.poison"), b"external failure").unwrap();
                        if staging {
                            fs::write(path.join(".audit-next.jsonl"), line(&cp).unwrap()).unwrap();
                        }
                        *captured.lock().unwrap() = Some(content(&path));
                    }
                }))
            });
            bad(
                sink.operator_write(
                    h,
                    if checkpoint {
                        OperatorOp::Checkpoint
                    } else {
                        op(h)
                    },
                ),
                AuditErrorKind::Poisoned,
            );
            hooks::OBSERVE.with(|o| *o.borrow_mut() = None);
            assert_eq!(content(&t.0), snapshot.lock().unwrap().clone().unwrap());
            assert_eq!(key.calls.load(Ordering::Relaxed), 0);
        }
    }
}
#[test]
fn failed_fsync_rollback_and_poison_barrier() {
    for checkpoint in [false, true] {
        for truncate_fails in [false, true] {
            let t = Temp::new();
            let h = clean(&t);
            let before = bytes(&t);
            let key = SignOnly::new("22", false);
            hooks::FAIL.with(|v| {
                *v.borrow_mut() = if truncate_fails {
                    vec!["operator-data", "truncate"]
                } else {
                    vec!["operator-data"]
                }
            });
            bad(
                invoke(
                    &t,
                    key.clone(),
                    h,
                    if checkpoint {
                        OperatorOp::Checkpoint
                    } else {
                        op(h)
                    },
                ),
                AuditErrorKind::Io,
            );
            assert_eq!(key.calls.load(Ordering::Relaxed), 1);
            if truncate_fails {
                assert!(t.0.join("audit.poison").exists());
            } else {
                assert_eq!(bytes(&t), before);
            }
        }
    }
}
fn repaired_tail_round_trip(checkpoint: bool) {
    let t = Temp::new();
    let h = clean(&t);
    let original = bytes(&t);
    let generated = invoke(&t, SignOnly::new("22", false), h, op(h)).unwrap();
    let r = generated.record.unwrap();
    let rb = line(&r).unwrap();
    let cb = line(&generated.checkpoint).unwrap();
    let mut expected = original;
    let (expect, operation, fragment) = if checkpoint {
        expected.extend(&rb);
        (head(&r), OperatorOp::Checkpoint, &cb[..cb.len() / 2])
    } else {
        (h, op(h), &rb[..rb.len() / 2])
    };
    expected.extend(fragment);
    fs::write(t.0.join("audit.jsonl"), &expected).unwrap();
    let key = SignOnly::new("22", false);
    let recovered = invoke(&t, key.clone(), expect, operation).unwrap();
    expected.push(b'\n');
    if let Some(record) = &recovered.record {
        assert!(record.context.repaired.is_some());
        expected.extend(line(record).unwrap());
    } else {
        assert!(recovered.checkpoint.context.repaired.is_some());
    }
    expected.extend(line(&recovered.checkpoint).unwrap());
    assert_eq!(bytes(&t), expected);
    assert_eq!(key.calls.load(Ordering::Relaxed), 1);
    let reopened = Sink::open(
        &t.0,
        key,
        Config::default(),
        Some(head(&recovered.checkpoint)),
    )
    .unwrap();
    assert_eq!(bytes(&t), expected);
    reopened.close().unwrap();
}
#[test]
fn rotate_repair_preserves_fragment_and_frames_records_on_disk() {
    repaired_tail_round_trip(false);
}
#[test]
fn checkpoint_repair_preserves_fragment_and_frames_records_on_disk() {
    repaired_tail_round_trip(true);
}
#[test]
fn crash_rotation_fragment_record_and_complete_checkpoint_states() {
    // Generate the exact R/C bytes once, then replay each documented crash prefix.
    let t = Temp::new();
    let h = clean(&t);
    let original = bytes(&t);
    let result = invoke(&t, SignOnly::new("22", false), h, op(h)).unwrap();
    let r = result.record.unwrap();
    let c = result.checkpoint;
    let rb = line(&r).unwrap();
    let cb = line(&c).unwrap();
    fs::write(t.0.join("audit.jsonl"), &original).unwrap();
    append_raw(&t, &rb[..rb.len() / 2]);
    let repaired = invoke(&t, SignOnly::new("22", false), h, op(h)).unwrap();
    assert!(repaired.record.unwrap().context.repaired.is_some());
    fs::write(t.0.join("audit.jsonl"), &original).unwrap();
    append_raw(&t, &rb);
    append_raw(&t, &cb[..cb.len() / 2]);
    let key = SignOnly::new("22", false);
    let recovered = invoke(&t, key.clone(), head(&r), OperatorOp::Checkpoint).unwrap();
    assert!(recovered.checkpoint.context.repaired.is_some());
    assert_eq!(key.calls.load(Ordering::Relaxed), 1);
    fs::write(t.0.join("audit.jsonl"), &original).unwrap();
    append_raw(&t, &rb);
    let attacker = chained(&t, &r, entry());
    append_raw(&t, &line(&attacker).unwrap());
    refused(&t, head(&r), OperatorOp::Checkpoint);
    fs::write(t.0.join("audit.jsonl"), &original).unwrap();
    append_raw(&t, &rb);
    append_raw(&t, &cb);
    refused(&t, h, op(h));
    refused(&t, head(&r), OperatorOp::Checkpoint);
}
pub(super) fn clean_stop_attacks(t: &Temp, h: Head) {
    let original = bytes(t);
    let rs = records(t);
    let earlier = rs
        .iter()
        .rev()
        .find(|r| r.context.seq < h.seq && matches!(r.kind, Kind::Checkpoint(_)))
        .unwrap()
        .context
        .seq;
    for attack in 0..3 {
        fs::write(t.0.join("audit.jsonl"), &original).unwrap();
        match attack {
            0 => append_raw(t, &line(&chained(t, rs.last().unwrap(), entry())).unwrap()),
            1 => fs::write(
                t.0.join("audit.jsonl"),
                rs.iter()
                    .take_while(|r| r.context.seq <= earlier)
                    .flat_map(|r| line(r).unwrap())
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
            _ => {
                let mut rewritten = rs.clone();
                let mut mmr = Mmr::new();
                for i in 0..rewritten.len() {
                    if i > 0 {
                        rewritten[i].context.previous = rewritten[i - 1].hash();
                    }
                    if let Kind::Entry(e) = &mut rewritten[i].kind {
                        e.details = Some("tampered".into());
                    } else {
                        rewritten[i] =
                            Sink::signed(&*signer(), rewritten[i].context.clone(), &mmr).unwrap();
                    }
                    mmr.push(rewritten[i].hash()).unwrap();
                }
                assert_eq!(rewritten.last().unwrap().context.seq, h.seq);
                fs::write(
                    t.0.join("audit.jsonl"),
                    rewritten
                        .iter()
                        .flat_map(|r| line(r).unwrap())
                        .collect::<Vec<_>>(),
                )
                .unwrap();
            }
        }
        refused(t, h, op(h));
    }
    fs::write(t.0.join("audit.jsonl"), original).unwrap();
}
#[test]
fn append_truncate_and_old_key_rewrite_after_clean_stop() {
    let t = Temp::new();
    let s = create(&t);
    s.record(&entry()).unwrap();
    let h = head(&s.close().unwrap());
    clean_stop_attacks(&t, h);
}
#[test]
fn append_between_closes_is_covered_by_newest_close() {
    let t = Temp::new();
    let a = create(&t).close().unwrap();
    append_raw(&t, &line(&chained(&t, &a, entry())).unwrap());
    let b = Sink::open(&t.0, signer(), Config::default(), None).unwrap();
    b.record(&entry()).unwrap();
    let h = head(&b.close().unwrap());
    invoke(&t, SignOnly::new("22", false), h, op(h)).unwrap();
    // The verify / NoReceipt half belongs to #13.
}
