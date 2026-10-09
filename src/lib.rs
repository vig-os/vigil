#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

pub mod rotate;

/// The version of this crate, stamped into every resource it describes.
///
/// ```
/// assert!(!vigil::VERSION.is_empty());
/// ```
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_the_package_version() {
        assert_eq!(super::VERSION, env!("CARGO_PKG_VERSION"));
    }
}
