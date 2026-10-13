//! Writer crash, SIGKILL, clean-stop and truncation evidence for ADR-0005.
use super::crash_fixtures::*;
use super::tests::{
    Failing, Temp, bad, bytes, counting, create, entry, open, records, scan_head, signer,
};
use super::*;
use std::{fs, path::PathBuf};

#[test]
fn child_role() {
    let Some(path) = std::env::var_os("VIGIL_CRASH_DIR") else {
        return;
    };
    hooks::TIME.with(|v| v.set(Some(1_000_000_000)));
    let path = PathBuf::from(path);
    let role = std::env::var("VIGIL_CRASH_ROLE").unwrap();
    if let Some(operation) = role.strip_prefix("resume-race-") {
        let dir = File::open(&path).unwrap();
        let trail = marker(&dir).unwrap();
        let h = predecessor_run(&dir, trail).unwrap().0.unwrap().head;
        let key = super::operators::SignOnly::new("22", false);
        let contender = operation == "contender";
        let once = std::cell::Cell::new(false);
        hooks::OBSERVE.with(|v| {
            *v.borrow_mut() = Some(Box::new(move |site| {
                if site
                    == if contender {
                        "resume-before-lock"
                    } else {
                        "clock"
                    }
                    && !once.replace(true)
                {
                    println!("READY");
                    std::io::stdout().flush().unwrap();
                    if !contender {
                        std::io::stdin().read_line(&mut String::new()).unwrap();
                    }
                }
            }))
        });
        if contender {
            bad(
                AuditConfig::new("vigil").dir(&path).resume(
                    key.clone(),
                    (h.seq, h.hash),
                    20,
                    "a",
                    "r",
                ),
                AuditErrorKind::HeadMismatch,
            );
            assert_eq!(key.calls.load(Ordering::Relaxed), 0);
            assert_eq!(key.public.load(Ordering::Relaxed), 0);
        } else if operation == "resume" {
            let (mut sink, _, _) = Sink::resume(
                &path,
                key.clone(),
                Config::default(),
                h,
                20,
                "a".into(),
                "r".into(),
            )
            .unwrap();
            sink.closed = true;
            assert_eq!(key.calls.load(Ordering::Relaxed), 1);
        } else {
            let op = if operation == "checkpoint" {
                OperatorOp::Checkpoint
            } else {
                OperatorOp::Rotate {
                    bound: h,
                    actor: "a".into(),
                    reason: "r".into(),
                }
            };
            Sink::open(&path, key.clone(), Config::default(), None)
                .unwrap()
                .operator_write(h, op)
                .unwrap();
            assert_eq!(key.calls.load(Ordering::Relaxed), 1);
        }
        hooks::OBSERVE.with(|v| *v.borrow_mut() = None);
        return;
    }
    if role == "resume" {
        let dir = File::open(&path).unwrap();
        let trail = marker(&dir).unwrap();
        let prior = predecessor_run(&dir, trail).unwrap().0;
        let head = prior.map_or((0, Record::genesis(&trail)), |s| (s.head.seq, s.head.hash));
        install_park(std::env::var("VIGIL_CRASH_SITE").unwrap());
        let _result = AuditConfig::new("vigil")
            .dir(&path)
            .resume(signer(), head, 20, "operator", "reviewed")
            .unwrap();
        panic!("resume did not crash");
    }
    if role == "stderr" {
        let key = Arc::new(Failing::new());
        let s = Sink::open(
            &path,
            key.clone(),
            Config {
                checkpoint_every: 1,
                ..Config::default()
            },
            None,
        )
        .unwrap();
        key.fail.store(true, Ordering::Relaxed);
        s.record(&entry()).unwrap();
        assert_eq!(hooks::STDERR.with(|v| v.borrow().len()), 1);
        return;
    }
    if role == "recover" {
        let expected: u64 = std::env::var("VIGIL_EXPECTED_SEQ")
            .unwrap()
            .parse()
            .unwrap();
        let before = content(&path);
        let key = counting();
        let mut sink = Sink::open(&path, key.clone(), Config::default(), None).unwrap();
        assert_eq!(scan_head(&sink).seq, expected);
        assert_eq!(key.calls.load(Ordering::Relaxed), 0);
        assert_recovery_bytes(&before, &content(&path));
        assert_eq!(sink.record(&entry()).unwrap().seq, expected + 1);
        sink.closed = true;
        return;
    }
    if role == "create" {
        let site = std::env::var("VIGIL_CRASH_SITE").unwrap();
        if site == "create-torn" {
            hooks::OBSERVE.with(|v| {
                *v.borrow_mut() = Some(Box::new(|event| {
                    if event == "create-staging" {
                        hooks::HALF.with(|v| v.set(true));
                    }
                    if event == "partial-write" {
                        println!("READY");
                        std::io::stdout().flush().unwrap();
                        loop {
                            std::thread::park();
                        }
                    }
                }))
            });
        } else {
            install_park(site);
        }
        let _sink = Sink::create(&path, signer(), Config::default()).unwrap();
        panic!("create did not crash");
    }
    let mut sink = Sink::open(&path, signer(), Config::default(), None).unwrap();
    if role == "seal" {
        sink.config.max_bytes = 1;
        install_park(std::env::var("VIGIL_CRASH_SITE").unwrap());
        sink.record(&entry()).unwrap();
        panic!("seal did not crash");
    }
    if role == "partial" || role == "orphan" {
        if role == "partial" {
            hooks::HALF.with(|v| v.set(true));
        }
        install_park(
            if role == "partial" {
                "partial-write"
            } else {
                "after-write"
            }
            .into(),
        );
        sink.record(&entry()).unwrap();
        panic!("write did not crash");
    }
    if role == "writer" || role == "writer-repair" {
        let count = knob("VIGIL_CRASH_RECORDS", 3);
        for _ in 0..count {
            let head = sink.record(&entry()).unwrap();
            println!("RECEIPT {} {}", head.seq, hex(&head.hash));
        }
        println!("READY");
        std::io::stdout().flush().unwrap();
        let mut instruction = String::new();
        std::io::stdin().read_line(&mut instruction).unwrap();
        if role == "writer-repair" {
            let head = sink.record(&entry()).unwrap();
            println!("RECEIPT {} {}", head.seq, hex(&head.hash));
        }
        let cp = sink.close().unwrap();
        println!("RECEIPT {} {}", cp.context.seq, hex(&cp.hash()));
        return;
    }
    panic!("unknown child role {role}");
}
#[test]
fn signer_failure_with_full_stderr_returns_normally() {
    let t = Temp::new();
    let mut s = create(&t);
    s.closed = true;
    #[cfg(target_os = "linux")]
    let stderr = File::options().write(true).open("/dev/full").unwrap();
    // macOS has no /dev/full: a read-only descriptor makes stderr fail EBADF.
    #[cfg(not(target_os = "linux"))]
    let stderr = File::open("/dev/null").unwrap();
    let output = command(&t.0, "stderr").stderr(stderr).output().unwrap();
    assert!(
        output.status.success(),
        "child exit {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn sealing_crash_matrix() {
    for step in 1..=6 {
        for fresh in [false, true] {
            let t = Temp::new();
            let mut initial = create(&t);
            initial.closed = true;
            initial.record(&entry()).unwrap();
            let key = counting();
            let mut b = Sink::open(&t.0, key.clone(), Config::default(), None).unwrap();
            b.closed = true;
            let mut a = Process::spawn(&t.0, "seal", &format!("seal-{step}"));
            a.ready();
            a.kill();
            let before = content(&t.0);
            let staged = before.get(Path::new(".audit-next.jsonl")).cloned();
            let old_live = before.get(Path::new("audit.jsonl")).cloned();
            if step == 1 {
                assert!(staged.is_none());
            }
            let expected = if step <= 2 { 1 } else { 3 };
            if fresh {
                let output = command(&t.0, "recover")
                    .env("VIGIL_EXPECTED_SEQ", expected.to_string())
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "step {step}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            } else {
                assert_eq!(scan_head(&b).seq, expected);
                assert_eq!(key.calls.load(Ordering::Relaxed), 0);
                let after = content(&t.0);
                assert_recovery_bytes(&before, &after);
                assert!(!after.contains_key(Path::new(".audit-next.jsonl")));
                if step <= 2 {
                    assert_eq!(after.get(Path::new("audit.jsonl")), old_live.as_ref());
                }
                if step == 3 || step == 4 {
                    assert_eq!(after.get(Path::new("audit.jsonl")), staged.as_ref());
                }
                assert_eq!(b.record(&entry()).unwrap().seq, expected + 1);
            }
            let all = chain(&t.0);
            assert_eq!(all.last().unwrap().context.seq, expected + 1);
        }
    }
}
#[test]
fn creation_crash_matrix() {
    for site in [
        "create-1",
        "create-2",
        "create-staging",
        "create-torn",
        "staging",
        "staging-dir",
        "promote",
        "promote-dir",
        "create-3",
        "create-4",
    ] {
        let t = Temp::new();
        let mut child = Process::spawn(&t.0, "create", site);
        child.ready();
        child.kill();
        let key = counting();
        let before = content(&t.0);
        let result = Sink::open(&t.0, key.clone(), Config::default(), None);
        assert_eq!(key.calls.load(Ordering::Relaxed), 0);
        if site == "create-1" {
            bad(result, AuditErrorKind::MissingTrail);
            let mut created = create(&t);
            created.closed = true;
        } else if ["create-2", "create-staging", "create-torn"].contains(&site) {
            bad(result, AuditErrorKind::CorruptTrail);
            bad(
                Sink::create(&t.0, signer(), Config::default()),
                AuditErrorKind::TrailExists,
            );
        } else {
            let mut recovered = result.unwrap();
            recovered.closed = true;
            assert_eq!(scan_head(&recovered).seq, 0);
            assert_recovery_bytes(&before, &content(&t.0));
            assert_eq!(records(&t).len(), 1);
        }
    }
}

#[test]
fn killed_mid_write_and_during_repair() {
    for fragments in 1..=2 {
        for fresh in [false, true] {
            let t = Temp::new();
            let mut initial = create(&t);
            initial.closed = true;
            initial.record(&entry()).unwrap();
            let key = counting();
            let mut b = Sink::open(&t.0, key.clone(), Config::default(), None).unwrap();
            b.closed = true;
            for _ in 0..fragments {
                let mut a = Process::spawn(&t.0, "partial", "");
                a.ready();
                a.kill();
            }
            let before = content(&t.0);
            if fresh {
                let output = command(&t.0, "recover")
                    .env("VIGIL_EXPECTED_SEQ", "1")
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            } else {
                assert_eq!(scan_head(&b).seq, 1);
                assert_eq!(key.calls.load(Ordering::Relaxed), 0);
                assert_eq!(content(&t.0), before);
                assert_eq!(b.record(&entry()).unwrap().seq, 2);
            }
            let all = chain(&t.0);
            assert_eq!(all.len(), 3);
            assert!(all.last().unwrap().context.repaired.is_some());
            let mut reopened = open(&t);
            reopened.closed = true;
            assert_eq!(scan_head(&reopened).hash, all.last().unwrap().hash());
        }
    }
}
#[test]
fn sigkill_concurrent_writers_twenty_runs() {
    let runs = knob("VIGIL_CRASH_RUNS", 20);
    let writers = knob("VIGIL_CRASH_WRITERS", 8).max(8);
    let killed = knob("VIGIL_CRASH_KILLED", 3).max(2);
    for _ in 0..runs {
        let t = Temp::new();
        let mut initial = create(&t);
        initial.closed = true;
        // Hold the lock in a torn write while all healthy writers start, then
        // release it by SIGKILL. Further killed writers contend with their calls.
        let mut first = Process::spawn(&t.0, "partial", "");
        first.ready();
        let mut survivors: Vec<_> = (0..writers)
            .map(|_| Process::spawn(&t.0, "writer-repair", ""))
            .collect();
        first.kill();
        for _ in 1..killed {
            let mut child = Process::spawn(&t.0, "partial", "");
            child.ready();
            child.kill();
        }
        for child in &mut survivors {
            child.ready();
        }
        for index in shuffled_indices(survivors.len()) {
            survivors[index].close();
        }
        let held: Vec<_> = survivors.iter().flat_map(|c| c.receipts.clone()).collect();
        let mut reopened = open(&t);
        reopened.closed = true;
        let all = chain(&t.0);
        assert_eq!(scan_head(&reopened).hash, all.last().unwrap().hash());
        assert_eq!(held.len(), writers * (knob("VIGIL_CRASH_RECORDS", 3) + 2));
        assert_receipts(&all, &held);
        let fragments = bytes(&t)
            .split(|b| *b == b'\n')
            .filter(|p| !p.is_empty() && Record::parse_line(p).is_err())
            .count();
        assert_eq!(fragments, killed);
        assert!(all.iter().any(|r| r.context.repaired.is_some()));
    }
}
#[test]
fn clean_stop_process_head_and_killed_orphan() {
    let t = Temp::new();
    let mut initial = create(&t);
    initial.closed = true;
    let count = knob("VIGIL_CLEAN_WRITERS", 8).max(8);
    let mut children: Vec<_> = (0..count)
        .map(|_| Process::spawn(&t.0, "writer", ""))
        .collect();
    for child in &mut children {
        child.ready();
    }
    for index in shuffled_indices(count) {
        children[index].close();
    }
    let held: Vec<_> = children.iter().flat_map(|c| c.receipts.clone()).collect();
    let all = chain(&t.0);
    let max = held.iter().max_by_key(|(seq, _)| seq).unwrap();
    assert_eq!(all.last().unwrap().context.seq, max.0);
    assert_eq!(hex(&all.last().unwrap().hash()), max.1);
    assert!(matches!(all.last().unwrap().kind, Kind::Checkpoint(_)));
    assert_eq!(held.len(), count * (knob("VIGIL_CRASH_RECORDS", 3) + 1));
    assert_receipts(&all, &held);
    let expected = Head {
        seq: max.0,
        hash: all.last().unwrap().hash(),
    };
    super::operators::clean_stop_attacks(&t, expected);
    let operation = || OperatorOp::Rotate {
        bound: expected,
        actor: "operator".into(),
        reason: "scheduled".into(),
    };
    let new_key = super::operators::SignOnly::new("22", false);
    bad(
        Sink::open(&t.0, new_key.clone(), Config::default(), None)
            .unwrap()
            .operator_write(
                Head {
                    seq: expected.seq - 1,
                    ..expected
                },
                OperatorOp::Rotate {
                    bound: Head {
                        seq: all[0].context.seq,
                        hash: all[0].hash(),
                    },
                    actor: "operator".into(),
                    reason: "scheduled".into(),
                },
            ),
        AuditErrorKind::HeadMismatch,
    );
    let rotated = Sink::open(&t.0, new_key.clone(), Config::default(), None)
        .unwrap()
        .operator_write(expected, operation())
        .unwrap();
    let rotated_head = Head {
        seq: rotated.checkpoint.context.seq,
        hash: rotated.checkpoint.hash(),
    };
    let mut orphan = Process::spawn(&t.0, "orphan", "");
    orphan.ready();
    orphan.kill();
    let before_refusal = bytes(&t);
    new_key.calls.store(0, Ordering::Relaxed);
    bad(
        Sink::open(&t.0, new_key.clone(), Config::default(), None)
            .unwrap()
            .operator_write(
                rotated_head,
                OperatorOp::Rotate {
                    bound: expected,
                    actor: "operator".into(),
                    reason: "scheduled".into(),
                },
            ),
        AuditErrorKind::HeadMismatch,
    );
    assert_eq!(bytes(&t), before_refusal);
    assert_eq!(new_key.calls.load(Ordering::Relaxed), 0);
    let restarted = open(&t);
    assert!(scan_head(&restarted).seq > max.0);
    let closed = restarted.close().unwrap();
    let disk = chain(&t.0);
    assert_eq!(closed.context.seq, disk.last().unwrap().context.seq);
    assert_eq!(closed.hash(), disk.last().unwrap().hash());
}

#[test]
fn truncation_properties() {
    use proptest::{
        prelude::*,
        test_runner::{Config as PropertyConfig, TestRunner},
    };
    let payload = super::super::format::roundtrip_tests::generated().prop_filter_map(
        "entry fitting the writer bound",
        |(r, _)| {
            match line(&r) {
                Err(e) if e.kind() == AuditErrorKind::TooLarge => return None,
                Err(e) => panic!("unexpected generator refusal {e}"),
                Ok(_) => {}
            }
            match r.kind {
                Kind::Entry(e) => Some(e),
                Kind::Checkpoint(_) => None,
            }
        },
    );
    let strategy = (
        proptest::collection::vec(payload, 1..=knob("VIGIL_TRUNCATION_RECORDS", 5)),
        any::<usize>(),
    );
    let mut runner = TestRunner::new(PropertyConfig {
        cases: knob("VIGIL_TRUNCATION_CASES", 64) as u32,
        source_file: Some(file!()),
        ..PropertyConfig::default()
    });
    runner
        .run(&strategy, |(entries, choice)| {
            let t = Temp::new();
            let mut s = create(&t);
            s.closed = true;
            let mut held = Vec::new();
            for e in entries {
                match s.record(&e) {
                    Ok(h) => held.push(h),
                    Err(e) => prop_assert_eq!(e.kind(), AuditErrorKind::TooLarge),
                }
            }
            let original = bytes(&t);
            let mut boundaries = vec![0];
            for (index, byte) in original.iter().enumerate() {
                if *byte == b'\n' {
                    boundaries.push(index + 1);
                }
            }
            // Each generated trail exercises every boundary, every missing-LF case,
            // the empty file and a random byte (including multibyte UTF-8 prefixes).
            let cuts: Vec<_> = boundaries
                .iter()
                .copied()
                .chain(boundaries.iter().skip(1).map(|n| n - 1))
                .chain([1, boundaries[1] / 2, choice % (original.len() + 1)])
                .collect();
            drop(s);
            for cut in cuts {
                fs::write(t.0.join("audit.jsonl"), &original[..cut]).unwrap();
                let complete: Vec<_> = original[..cut]
                    .split(|b| *b == b'\n')
                    .filter_map(|p| Record::parse_line(p).ok())
                    .flatten()
                    .collect();
                let result = Sink::open(&t.0, signer(), Config::default(), None);
                if complete.is_empty() {
                    prop_assert_eq!(result.err().unwrap().kind(), AuditErrorKind::CorruptTrail);
                    continue;
                }
                let mut recovered = result.unwrap();
                recovered.closed = true;
                let last = complete.last().unwrap();
                prop_assert_eq!(
                    scan_head(&recovered),
                    Head {
                        seq: last.context.seq,
                        hash: last.hash()
                    }
                );
                prop_assert_eq!(bytes(&t), &original[..cut]);
                let prefix = &original[..cut];
                let start = prefix
                    .iter()
                    .rposition(|b| *b == b'\n')
                    .map_or(0, |i| i + 1);
                let tail = &prefix[start..];
                let fragment = !tail.is_empty() && Record::parse_line(tail).is_err();
                let next = recovered.record(&entry()).unwrap();
                prop_assert_eq!(next.seq, last.context.seq + 1);
                let all = chain(&t.0);
                let written = all.last().unwrap();
                prop_assert_eq!(written.context.repaired.is_some(), fragment);
                for h in &held {
                    if h.seq <= last.context.seq {
                        prop_assert_eq!(
                            all.iter()
                                .filter(|r| r.context.seq == h.seq && r.hash() == h.hash)
                                .count(),
                            1
                        );
                    }
                }
                for (a, b) in complete.iter().zip(&all) {
                    prop_assert_eq!(a.hash(), b.hash());
                }
            }
            Ok(())
        })
        .unwrap();
}
