use super::*;
use std::error::Error;

fn file(bytes: &[u8]) -> Result<TrustPolicy, AuditError> {
    let dir = std::env::temp_dir().join(format!(
        "vigil-trust-{}-{}",
        std::process::id(),
        super::super::hex(&getrandom_id())
    ));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("trust");
    std::fs::write(&path, bytes).unwrap();
    let result = TrustPolicy::from_file(&path);
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(dir).unwrap();
    result
}
fn getrandom_id() -> [u8; 16] {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).unwrap();
    bytes
}
fn input(text: &str) -> String {
    text.replace("ID", &"01".repeat(16))
        .replace("OTHER", &"02".repeat(16))
        .replace("KEY", &"03".repeat(32))
        .replace("HASH", &"ab".repeat(32))
}
fn rejects(text: &str, expected: &[&str]) {
    let error = file(input(text).as_bytes()).unwrap_err();
    assert_eq!(error.kind(), AuditErrorKind::InvalidConfig);
    for part in expected {
        assert!(error.to_string().contains(part), "{error}: missing {part}");
    }
}
#[test]
fn trust_line_syntax() {
    for (text, line) in [
        ("ed25519 KEY", 1),
        ("schema blake3:HASH", 1),
        ("trail ID\nschema blake3:HASH", 2),
        ("unknown ID", 1),
        ("trail ID\ned25519 KEY thru=1:blake3:HASH", 2),
        ("trail ID\ned25519 KEY end=1:blake3:HASH", 2),
        ("trail ID through=1:blake3:HASH", 1),
        ("trail ID end=1:blake3:HASH end=2:blake3:HASH", 1),
        (
            "trail ID\ned25519 KEY through=1:blake3:HASH through=2:blake3:HASH",
            2,
        ),
        ("trail", 1),
        ("trail ID\ned25519", 2),
    ] {
        rejects(text, &[&format!("line {line}")]);
    }
    rejects("schema blake3:HASH", &["#164 CP4"]);
}
#[test]
fn trust_spellings() {
    for value in [
        "1:HASH",
        "1HASH",
        ":blake3:HASH",
        "x:blake3:HASH",
        "+1:blake3:HASH",
        "١:blake3:HASH",
        "18446744073709551616:blake3:HASH",
        "1:blake3:aa",
        "1:blake3:AA",
        "1:blake3:UPPER",
    ] {
        let value = value.replace("UPPER", &"AB".repeat(32));
        rejects(&format!("trail ID end={value}"), &["line 1"]);
        rejects(
            &format!("trail ID\ned25519 KEY through={value}"),
            &["line 2"],
        );
    }
    for value in ["aa".to_owned(), "AB".repeat(16), "00".repeat(17)] {
        rejects(&format!("trail {value}"), &["line 1"]);
    }
    for value in ["aa".to_owned(), "AB".repeat(32), "00".repeat(33)] {
        rejects(&format!("trail ID\ned25519 {value}"), &["line 2"]);
    }
}
#[test]
fn trust_semantic_errors_and_builder_parity() {
    let cases = [
        (
            "trail ID\ntrail ID",
            TrustPolicy::builder().trail([1; 16]).trail([1; 16]).build(),
            vec!["line 1", "line 2"],
        ),
        (
            "trail ID\ned25519 KEY\ned25519 KEY",
            TrustPolicy::builder()
                .trail([1; 16])
                .key([3; 32])
                .key([3; 32])
                .build(),
            vec!["line 2", "line 3"],
        ),
        (
            "trail ID\ned25519 KEY\ned25519 KEY through=1:blake3:HASH",
            TrustPolicy::builder()
                .trail([1; 16])
                .key([3; 32])
                .key_through([3; 32], 1, [0xab; 32])
                .build(),
            vec!["line 2", "line 3"],
        ),
        (
            "trail ID\ned25519 KEY through=1:blake3:HASH\ntrail OTHER\ned25519 KEY",
            TrustPolicy::builder()
                .trail([1; 16])
                .key_through([3; 32], 1, [0xab; 32])
                .trail([2; 16])
                .key([3; 32])
                .build(),
            vec!["line 1", "line 2", "line 3", "line 4"],
        ),
    ];
    for (text, built, lines) in cases {
        assert_eq!(built.unwrap_err().kind(), AuditErrorKind::InvalidConfig);
        rejects(text, &lines);
    }
    let text = "trail ID\ned25519 KEY\ntrail OTHER\ned25519 KEY through=2:blake3:HASH";
    rejects(
        text,
        &[&"01".repeat(16), &"02".repeat(16), &"03".repeat(32)],
    );
    assert_eq!(
        TrustPolicy::builder()
            .trail([1; 16])
            .end(1, [0; 32])
            .end(2, [0; 32])
            .build()
            .unwrap_err()
            .kind(),
        AuditErrorKind::InvalidConfig
    );
}
#[test]
fn trust_whole_file_errors() {
    for bytes in [b"".as_slice(), b"# comment\n \r\n", b"\xff"] {
        let error = file(bytes).unwrap_err();
        assert_eq!(error.kind(), AuditErrorKind::InvalidConfig);
        assert!(!error.to_string().contains("line"));
    }
    assert_eq!(
        TrustPolicy::builder().build().unwrap_err().kind(),
        AuditErrorKind::InvalidConfig
    );
}
#[test]
fn trust_accepted_and_queries() {
    let parsed = file(input("# comment\r\n\r\ntrail ID end=9:blake3:HASH retired through=ignored\r\ned25519 KEY through=3:blake3:HASH comment x=y\r\ntrail OTHER\r\ned25519 KEY through=5:blake3:HASH\r\n").as_bytes()).unwrap();
    let built = TrustPolicy::builder()
        .trail([1; 16])
        .end(9, [0xab; 32])
        .key_through([3; 32], 3, [0xab; 32])
        .trail([2; 16])
        .key_through([3; 32], 5, [0xab; 32])
        .build()
        .unwrap();
    assert_eq!(
        parsed.trail_ids().copied().collect::<Vec<_>>(),
        vec![[1; 16], [2; 16]]
    );
    for id in [[1; 16], [2; 16], [4; 16]] {
        assert_eq!(parsed.pinned(&id), built.pinned(&id));
        assert_eq!(parsed.end(&id), built.end(&id));
        assert_eq!(parsed.bound(&id, &[3; 32]), built.bound(&id, &[3; 32]));
        for seq in [0, 3, 4, 5, 6, u64::MAX] {
            assert_eq!(
                parsed.trusted_at(&id, &[3; 32], seq),
                built.trusted_at(&id, &[3; 32], seq)
            );
        }
    }
    assert_eq!(parsed.end(&[1; 16]), Some((9, [0xab; 32])));
    assert_eq!(parsed.bound(&[2; 16], &[3; 32]), Some((5, [0xab; 32])));
    assert!(parsed.trusted_at(&[1; 16], &[3; 32], 3));
    assert!(!parsed.trusted_at(&[1; 16], &[3; 32], 4));
    assert!(!parsed.trusted_at(&[1; 16], &[4; 32], 0));
    let unbounded = file(input("trail ID\ned25519 KEY").as_bytes()).unwrap();
    assert!(unbounded.trusted_at(&[1; 16], &[3; 32], u64::MAX));
    assert_eq!(unbounded.bound(&[1; 16], &[3; 32]), None);
    assert!(!unbounded.pinned(&[2; 16]));
    assert_eq!(unbounded.end(&[1; 16]), None);
}
#[test]
fn trust_io_source_and_traits() {
    fn traits<T: std::fmt::Debug + Clone + Send + Sync>() {}
    fn send_sync<T: Send + Sync>() {}
    traits::<TrustPolicy>();
    send_sync::<AuditError>();
    let path = std::env::temp_dir()
        .join(format!("vigil-missing-{}", hex(&getrandom_id())))
        .join("trust");
    let error = TrustPolicy::from_file(path).unwrap_err();
    assert_eq!(error.kind(), AuditErrorKind::Io);
    assert_eq!(
        error
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .kind(),
        std::io::ErrorKind::NotFound
    );
}
