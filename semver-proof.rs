#![doc = include_str!("README.md")]
#![forbid(unsafe_code)]

#[path = "src/init.rs"]
mod init;
pub use init::{Config, Console, Guard, InitError, InitErrorKind, init};

#[path = "src/logs.rs"]
pub mod logs;
#[path = "src/rotate.rs"]
pub mod rotate;
#[path = "src/sink.rs"]
pub mod sink;
