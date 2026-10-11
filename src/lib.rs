#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

#[cfg(feature = "audit")]
pub mod audit;

mod init;
mod lifecycle;
pub use init::{Config, Console, Guard, InitError, InitErrorKind, init};
pub use lifecycle::{FlushError, FlushErrorKind, Signal};

pub mod logs;
pub mod rotate;
pub mod sink;

/// The version of this crate. Producer versions must be supplied via `Config::version`.
///
/// ```
/// assert!(!vigil::VERSION.is_empty());
/// ```
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// Subscriber defaults permanently change tracing's process-wide installation
// state, even after a scoped default ends. Keep these tests in fresh children.
#[cfg(test)]
fn subscriber_test_child(name: &str) -> bool {
    const CHILD: &str = "VIGIL_SUBSCRIBER_TEST_CHILD";
    if std::env::var(CHILD).as_deref() == Ok(name) {
        return true;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env(CHILD, name)
        .output()
        .unwrap();
    assert!(
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed;"),
        "{name}: {}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    false
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_the_package_version() {
        assert_eq!(super::VERSION, env!("CARGO_PKG_VERSION"));
    }
}
