//! Segment order through the filesystem-facing public API.
use proptest::prelude::*;
use std::{
    collections::BTreeSet,
    fs,
    sync::atomic::{AtomicU64, Ordering},
};
use vigil::rotate::segments;
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn public_segment_order(items in prop::collection::vec((0u32..60, 0u64..10_000_000), 1..40)) {
        let dir = std::env::temp_dir().join(format!("vigil-prop-{}-{}", std::process::id(), SEQUENCE.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&dir).unwrap();
        let keys: BTreeSet<_> = items.into_iter().chain([(0, 999_999), (0, 1_000_000)]).collect();
        let expected: Vec<_> = keys.iter().map(|(second, counter)| dir.join(format!("logs-20261009T1200{second:02}.000000000Z_{counter:06}.jsonl"))).collect();
        for path in expected.iter().rev() { fs::write(path, b"{}\n").unwrap(); }
        fs::write(dir.join("logs.jsonl"), b"").unwrap();
        fs::write(dir.join("logs-invalid.jsonl"), b"").unwrap();
        fs::write(dir.join("other-20261009T120000.000000000Z.jsonl"), b"").unwrap();
        let actual = segments(&dir, "logs").unwrap();
        let mut expected = expected;
        expected.push(dir.join("logs.jsonl"));
        fs::remove_dir_all(&dir).unwrap();
        prop_assert_eq!(actual, expected);
    }
}
