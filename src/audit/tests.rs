use super::*;
fn vector(name: &str) -> Vec<u8> {
    let line = include_str!("../../tests/fixtures/audit/primitives.txt")
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{name} ")))
        .unwrap();
    (0..line.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap())
        .collect()
}
fn context() -> RecordContext {
    RecordContext::new([0x11; 16], 0, 123, "svc", Record::genesis(&[0x11; 16])).host("host")
}
fn entry() -> Entry {
    Entry::new("α", "sample.modify", "id:1")
        .reason("reason")
        .before(Value::Text("old".into()))
        .after(Value::digest_of(b"new"))
        .details("{}")
}
#[test]
fn canonical_hash_and_chain_golden() {
    let record = Record::new(context(), entry()).unwrap();
    assert_eq!(Record::genesis(&[0x11; 16]).as_slice(), vector("genesis"));
    assert_eq!(record.canonical(), vector("record_fields"));
    assert_eq!(record.hash().as_slice(), vector("record_hash"));
    assert_eq!(
        Value::digest_of(b"new"),
        Value::Digest(vector("value_digest").try_into().unwrap())
    );
    assert!(record.signing_message().is_none());
    // Chain link: the previous hash is the final canonical field, in raw bytes.
    let next = Record::new(
        RecordContext::new([0x11; 16], 1, 124, "svc", record.hash()),
        entry(),
    )
    .unwrap();
    assert_eq!(
        &next.canonical()[next.canonical().len() - 32..],
        record.hash()
    );
    assert_ne!(next.hash(), record.hash());
}
#[test]
fn checkpoint_domain_signature_and_golden() {
    let seed = KeySeed::parse(&"07".repeat(32)).unwrap();
    let cp = |signature| {
        CheckpointFields::new(0, Mmr::new().root(), vec![], seed.public_key(), signature).unwrap()
    };
    let unsigned = Record::checkpoint(context(), cp([0; 64])).unwrap();
    let message = unsigned.signing_message().unwrap();
    assert_eq!(message.len(), 58);
    assert_eq!(message, vector("message"));
    assert_eq!(checkpoint_message(&vector("checkpoint_unsigned")), message);
    let sig = seed.sign(&message).unwrap();
    assert_eq!(sig.as_slice(), vector("signature"));
    let signed = Record::checkpoint(context(), cp(sig)).unwrap();
    assert_eq!(signed.signing_message(), Some(message.clone()));
    assert_eq!(signed.canonical(), vector("checkpoint_fields"));
    assert_eq!(signed.hash().as_slice(), vector("checkpoint_hash"));
    verify_signature(&seed.public_key(), &message, &sig).unwrap();
    for i in 0..message.len() {
        let mut altered = message.clone();
        altered[i] ^= 1;
        assert!(verify_signature(&seed.public_key(), &altered, &sig).is_err());
    }
    for i in 0..64 {
        let mut altered = sig;
        altered[i] ^= 1;
        assert!(verify_signature(&seed.public_key(), &message, &altered).is_err());
    }
    assert!(verify_signature(&[0; 32], &message, &[0; 64]).is_err());
    let mut identity = [0; 32];
    identity[0] = 1;
    let mut weak_signature = [0; 64];
    weak_signature[0] = 1;
    assert!(verify_signature(&identity, b"", &weak_signature).is_err());
}
#[test]
fn mmr_tessera_vectors_and_resume() {
    let mut mmr = Mmr::new();
    let mut small = blake3::Hasher::new();
    let mut all = blake3::Hasher::new();
    for n in 0..=2048u64 {
        if n > 0 {
            mmr.push(*blake3::hash(&(n - 1).to_be_bytes()).as_bytes())
                .unwrap();
        }
        assert_eq!(mmr.size(), n);
        assert_eq!(mmr.peaks().len(), n.count_ones() as usize);
        if n <= 64 {
            small.update(&mmr.root());
        }
        all.update(&mmr.root());
        if [0, 1, 3, 7, 64, 2048].contains(&n) {
            assert_eq!(mmr.root().as_slice(), vector(&format!("mmr_{n}")));
        }
        mmr = Mmr::from_peaks(n, mmr.peaks().to_vec()).unwrap();
    }
    assert_eq!(small.finalize().as_bytes().as_slice(), vector("mmr_0_64"));
    assert_eq!(all.finalize().as_bytes().as_slice(), vector("mmr_0_2048"));
    assert_eq!(
        Mmr::from_peaks(2, vec![]).unwrap_err().kind(),
        AuditErrorKind::InvalidConfig
    );
    let mut full = Mmr::from_peaks(u64::MAX, vec![[0; 32]; 64]).unwrap();
    let root = full.root();
    assert_eq!(
        full.push([0; 32]).unwrap_err().kind(),
        AuditErrorKind::InvalidConfig
    );
    assert_eq!(full.root(), root);
}
#[test]
fn rfc8032_seed_and_strict_signature() {
    let seed =
        KeySeed::parse("  9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60\n")
            .unwrap();
    assert_eq!(
        hex(&seed.public_key()),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    let sig = seed.sign(b"").unwrap();
    assert_eq!(
        hex(&sig),
        concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f",
            "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
    );
    verify_signature(&seed.public_key(), b"", &sig).unwrap();
    assert_eq!(format!("{seed:?}"), "KeySeed([REDACTED])");
    assert_eq!(
        KeySeed::parse(&"AB".repeat(32)).unwrap().public_key(),
        KeySeed::parse(&"ab".repeat(32)).unwrap().public_key()
    );
    for bad in [
        "".into(),
        "00".repeat(31),
        "00".repeat(33),
        "gg".repeat(32),
        format!("{} 00", "00".repeat(31)),
        "é".repeat(32),
    ] {
        assert!(KeySeed::parse(&bad).is_err());
    }
}
#[test]
fn alternate_fields_and_nonempty_checkpoint() {
    let context = |seq| RecordContext::new([0; 16], seq, 0, "svc", [0; 32]);
    let record = Record::new(
        context(1),
        Entry::new("a", "b", "c")
            .before(Value::Digest([0x44; 32]))
            .after(Value::Text("new".into())),
    )
    .unwrap();
    assert_eq!(record.canonical(), vector("alternate_fields"));
    assert_eq!(record.hash().as_slice(), vector("alternate_hash"));
    let mut mmr = Mmr::new();
    for i in 0..3u64 {
        mmr.push(*blake3::hash(&i.to_be_bytes()).as_bytes())
            .unwrap();
    }
    let cp = Record::checkpoint(
        context(3),
        CheckpointFields::new(3, mmr.root(), mmr.peaks().to_vec(), [0; 32], [0x55; 64]).unwrap(),
    )
    .unwrap();
    assert_eq!(cp.canonical(), vector("peaks_fields"));
    assert_eq!(cp.hash().as_slice(), vector("peaks_hash"));
    assert_eq!(cp.signing_message().unwrap(), vector("peaks_message"));
}
#[test]
fn validation_optional_fields_and_limits() {
    for text in ["", "a\0b"] {
        for entry in [
            Entry::new(text, "a", "o"),
            Entry::new("a", text, "o"),
            Entry::new("a", "b", text),
            entry().reason(text),
            entry().details(text),
            entry().before(Value::Text(text.into())),
            entry().after(Value::Text(text.into())),
        ] {
            assert_eq!(
                Record::new(context(), entry).unwrap_err().kind(),
                AuditErrorKind::InvalidEntry
            );
        }
        assert_eq!(
            Record::new(RecordContext::new([0; 16], 0, 0, text, [0; 32]), entry())
                .unwrap_err()
                .kind(),
            AuditErrorKind::InvalidEntry
        );
        assert_eq!(
            Record::new(context().host(text), entry())
                .unwrap_err()
                .kind(),
            AuditErrorKind::InvalidEntry
        );
    }
    let minimal = Record::new(
        RecordContext::new([0; 16], 1, 0, "svc", [0; 32]),
        Entry::new("a", "b", "c"),
    )
    .unwrap();
    let bytes = minimal.canonical();
    assert!(!bytes.is_empty());
    assert_eq!(
        CheckpointFields::new(1, [0; 32], vec![], [0; 32], [0; 64])
            .unwrap_err()
            .kind(),
        AuditErrorKind::InvalidConfig
    );
    assert_eq!(
        Record::checkpoint(
            context(),
            CheckpointFields::new(1, [0; 32], vec![[0; 32]], [0; 32], [0; 64]).unwrap()
        )
        .unwrap_err()
        .kind(),
        AuditErrorKind::InvalidConfig
    );
    // Every encoded text byte is identity-bearing; no Unicode normalization.
    assert_ne!(
        Record::new(context(), entry().reason("é")).unwrap().hash(),
        Record::new(context(), entry().reason("e\u{301}"))
            .unwrap()
            .hash()
    );
    fn kind_bounds<T: Copy + Eq + std::fmt::Debug>() {}
    kind_bounds::<AuditErrorKind>();
    for kind in [
        AuditErrorKind::Io,
        AuditErrorKind::Poisoned,
        AuditErrorKind::TooLarge,
        AuditErrorKind::InvalidEntry,
        AuditErrorKind::CorruptTrail,
        AuditErrorKind::HeadMismatch,
        AuditErrorKind::MissingTrail,
        AuditErrorKind::TrailExists,
        AuditErrorKind::Signer,
        AuditErrorKind::InvalidConfig,
    ] {
        let error = AuditError::new(kind, "test");
        assert_eq!(error.kind(), kind);
        assert!(error.to_string().contains("test"));
    }
}
