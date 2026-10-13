#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "audit")]
#[cfg_attr(docsrs, doc(cfg(feature = "audit")))]
pub mod audit;

#[cfg(feature = "audit")]
const _: () = {
    fn assert<T: Send + Sync>() {}
    let _ = assert::<audit::Receipt>;
    let _ = assert::<audit::AuditConfig>;
    let _ = assert::<audit::AuditTrail>;
};

mod init;
mod lifecycle;
#[cfg(feature = "metrics")]
#[cfg_attr(docsrs, doc(cfg(feature = "metrics")))]
pub mod metrics;
pub use init::{Config, Console, Guard, InitError, InitErrorKind, init};
pub use lifecycle::{FlushError, FlushErrorKind, Signal};

#[cfg(vigil_unstable)]
#[cfg_attr(docsrs, doc(cfg(vigil_unstable)))]
pub mod logs;
#[cfg(not(vigil_unstable))]
mod logs;
pub mod rotate;
#[cfg(vigil_unstable)]
#[cfg_attr(docsrs, doc(cfg(vigil_unstable)))]
pub mod sink;
#[cfg(not(vigil_unstable))]
mod sink;

/// Exact OpenTelemetry versions used by vigil; outside its semver promise.
///
/// Enable `--cfg vigil_unstable` in the application's build and pin `~1.N`.
/// Libraries using these paths require their applications to enable the cfg.
/// Global-provider installation is available (meter only; the tracer in #8).
/// The tracing integration re-export follows with traces in #8.
#[cfg(vigil_unstable)]
#[cfg_attr(docsrs, doc(cfg(vigil_unstable)))]
pub mod unstable {
    /// The OpenTelemetry API version linked by vigil.
    pub use opentelemetry;
    /// The OpenTelemetry SDK version linked by vigil.
    pub use opentelemetry_sdk;
}

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
    test_child(name, "VIGIL_SUBSCRIBER_TEST_CHILD").is_none()
}

// Share execution and verification so an incorrect --exact name cannot pass silently.
#[cfg(test)]
fn test_child(name: &str, child_env: &str) -> Option<std::process::Output> {
    test_child_with_env(name, child_env, &[])
}

#[cfg(test)]
fn test_child_with_env(
    name: &str,
    child_env: &str,
    env: &[(&str, &str)],
) -> Option<std::process::Output> {
    if std::env::var(child_env).as_deref() == Ok(name) {
        return None;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env(child_env, name)
        .envs(env.iter().copied())
        .output()
        .unwrap();
    assert!(
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed;"),
        "{name}: {}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    Some(output)
}

#[cfg(test)]
mod tests {
    #[test]
    fn child_runner_rejects_a_missing_test() {
        assert!(
            std::panic::catch_unwind(|| {
                super::test_child("tests::missing_test", "VIGIL_MISSING_TEST_CHILD");
            })
            .is_err()
        );
    }

    #[test]
    fn version_is_the_package_version() {
        assert_eq!(super::VERSION, env!("CARGO_PKG_VERSION"));
    }
}

mod ordered_json;

#[cfg(vigil_unstable)]
#[cfg_attr(docsrs, doc(cfg(vigil_unstable)))]
pub mod envelope;
#[cfg(not(vigil_unstable))]
mod envelope;
#[cfg(all(feature = "metrics", vigil_unstable))]
#[cfg_attr(docsrs, doc(cfg(vigil_unstable)))]
pub mod metric_export;
#[cfg(all(feature = "metrics", not(vigil_unstable)))]
mod metric_export;
#[cfg(feature = "metrics")]
mod metric_identity;

#[cfg(test)]
mod order_tests;

#[cfg(all(feature = "traces", vigil_unstable))]
#[cfg_attr(docsrs, doc(cfg(vigil_unstable)))]
pub mod span_export;
#[cfg(all(feature = "traces", not(vigil_unstable)))]
mod span_export;

#[cfg(feature = "traces")]
mod trace_pipeline;

#[cfg(all(test, feature = "traces"))]
#[path = "../tests/common/temp.rs"]
mod test_temp;
