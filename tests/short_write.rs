//! A real file-size limit: a short write leaves a fragment, and a later writer
//! (here: this process without the limit) must not glue its line onto it.
//!
//! The parent test re-executes this test binary through `sh` with
//! `ulimit -f 2` (1024 bytes) and SIGXFSZ ignored, so the kernel returns a
//! short write instead of killing the child.
#![cfg(unix)]

use std::process::{Command, Stdio};

use vigil::sink::{AppendFile, LineSink};

const CHILD_ENV: &str = "VIGIL_SHORT_WRITE_FILE";

/// Runs only inside the limited child; a no-op when the test binary runs normally.
#[test]
fn child_phase() {
    let Some(path) = std::env::var_os(CHILD_ENV) else {
        return;
    };
    let sink = AppendFile::open(&path).unwrap();
    sink.write_line(&[b'a'; 700]).unwrap();
    let err = sink.write_line(&[b'b'; 700]).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::WriteZero);
    let message = err.to_string();
    assert!(message.contains("unterminated fragment"), "{message}");
    assert!(!message.contains("was terminated"), "{message}");
}

#[test]
fn a_fragment_from_a_real_short_write_does_not_swallow_the_next_line() {
    if std::env::var_os(CHILD_ENV).is_some() {
        return; // we are the child; `child_phase` does the work
    }
    let dir = std::env::temp_dir().join(format!("vigil-short-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("logs.jsonl");

    let exe = std::env::current_exe().unwrap();
    let status = Command::new("sh")
        .arg("-c")
        .arg(r#"ulimit -f 2 && trap '' XFSZ && exec "$0" --exact child_phase --test-threads=1"#)
        .arg(exe)
        .env(CHILD_ENV, &path)
        // File-size limits also apply to inherited regular stdout/stderr files.
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "limited child failed: {status}");

    // The kernel cut the second line off at the 1024-byte limit: no newline.
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(bytes.len(), 1024);
    assert_ne!(bytes.last(), Some(&b'\n'));

    // A later writer, without the limit, starts its line on a fresh line.
    AppendFile::open(&path)
        .unwrap()
        .write_line(b"next")
        .unwrap();
    let text = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 3, "{text:?}");
    assert_eq!(lines[0], "a".repeat(700));
    assert!(lines[1].bytes().all(|b| b == b'b') && lines[1].len() == 1024 - 701);
    assert_eq!(lines[2], "next");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn redirected_parent_output_does_not_hit_child_limit() {
    let path = std::env::temp_dir().join(format!("vigil-short-output-{}", std::process::id()));
    std::fs::write(&path, vec![b'x'; 4096]).unwrap();
    let output = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "a_fragment_from_a_real_short_write_does_not_swallow_the_next_line",
            "--nocapture",
        ])
        .stdout(output.try_clone().unwrap())
        .stderr(output)
        .status()
        .unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::remove_file(path).unwrap();
    assert!(status.success(), "redirected parent failed: {text}");
}
