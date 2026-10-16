//! Assertions for exact-name child tests, including protection against zero tests.
use std::process::Output;

pub(crate) fn successful_test(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("1 passed;"), "{text}");
    text
}
