//! Public API performance contracts. Child roles keep the one-shot pipeline isolated.
#![forbid(unsafe_code)]

use criterion::{Criterion, Throughput};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use vigil::rotate::{RotatingFile, RotationConfig};

const RECORDS: u64 = 4096;
const LINE: &[u8] = &[b'x'; 256];

struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::var_os("VIGIL_BENCH_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let path = root.join(format!("vigil-bench-{}-{id}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        // Cleanup must not panic during unwinding and turn an assertion into an abort.
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn writer(dir: &Path, max: u64) -> RotatingFile {
    RotatingFile::open(
        dir,
        "logs",
        RotationConfig::default().max_bytes(max).retention(None),
    )
    .unwrap()
}

fn child(role: &str, dir: &Path) -> Command {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--child", role])
        .arg(dir)
        .env_remove("VIGIL_CONSOLE")
        .env_remove("VIGIL_VCS_REVISION")
        .stdout(Stdio::piped());
    cmd
}

fn pipeline(role: &str, dir: &Path) {
    let cfg = vigil::Config::new("bench")
        .dir(dir)
        .max_bytes(u64::MAX)
        .retention(None)
        .queue_size(8192)
        .filter_env("VIGIL_BENCH_FILTER")
        .default_filter("info")
        .console(vigil::Console::Off);
    let start = Instant::now();
    let guard = cfg.init().unwrap();
    let init_time = start.elapsed();
    assert_eq!(guard.dir(), Some(dir));
    if role == "init" {
        guard.shutdown().unwrap();
        println!("{}", init_time.as_nanos());
        return;
    }
    // A 512-record SDK batch with 4096-byte bodies exceeds 1 MB, forcing
    // record-boundary splitting. 256-byte bodies measure ordinary throughput.
    let body = "x".repeat(if role == "split" { 4096 } else { 256 });
    let start = Instant::now();
    for _ in 0..RECORDS {
        tracing::info!(body = body.as_str(), "benchmark");
    }
    guard.flush().unwrap();
    let elapsed = start.elapsed();
    guard.shutdown().unwrap();
    // Verify actual persisted records, valid JSON, and the production cap.
    // Verification and shutdown are outside the measured interval.
    let bytes = fs::read(dir.join("logs.jsonl")).unwrap();
    let mut count = 0;
    let mut near_cap = false;
    for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
        assert!(line.len() <= 1_000_000);
        near_cap |= line.len() > 900_000;
        let json: serde_json::Value = serde_json::from_slice(line).unwrap();
        for resource in json["resourceLogs"].as_array().unwrap() {
            for scope in resource["scopeLogs"].as_array().unwrap() {
                count += scope["logRecords"].as_array().unwrap().len();
            }
        }
    }
    assert_eq!(count as u64, RECORDS);
    if role == "split" {
        assert!(near_cap, "splitting workload never approached the cap");
    }
    println!("{}", elapsed.as_nanos());
}

fn multiprocess(dir: &Path, processes: usize) -> Duration {
    let mut children: Vec<_> = (0..processes)
        .map(|_| {
            let mut command = child("append", dir);
            command.stdin(Stdio::piped()).spawn().unwrap()
        })
        .collect();
    // Each child opens its own directory descriptor before reporting ready.
    for child in &mut children {
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert_eq!(ready, "ready\n");
    }
    let start = Instant::now();
    for child in &mut children {
        child.stdin.take().unwrap().write_all(b"go\n").unwrap();
    }
    for child in &mut children {
        assert!(child.wait().unwrap().success());
    }
    let elapsed = start.elapsed();
    assert_eq!(
        fs::metadata(dir.join("logs.jsonl")).unwrap().len(),
        processes as u64 * RECORDS * (LINE.len() as u64 + 1)
    );
    elapsed
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--child") {
        let dir = Path::new(&args[3]);
        if args[2] == "append" {
            let log = writer(dir, u64::MAX);
            println!("ready");
            std::io::stdout().flush().unwrap();
            let mut go = String::new();
            std::io::stdin().read_line(&mut go).unwrap();
            assert_eq!(go, "go\n");
            for _ in 0..RECORDS {
                log.append(LINE).unwrap();
            }
        } else {
            pipeline(&args[2], dir);
        }
        return;
    }
    // Cargo test --all-targets passes test harness arguments to custom benches.
    // Run Criterion's single-iteration validation instead of timing in that case.
    if args.iter().any(|s| s.starts_with("--test-threads")) {
        assert!(
            Command::new(std::env::current_exe().unwrap())
                .arg("--test")
                .status()
                .unwrap()
                .success()
        );
        return;
    }
    if !args.iter().any(|arg| arg == "--bench") || args.iter().any(|arg| arg == "--test") {
        // Prove failed cleanup is harmless: Drop sees an already removed directory.
        let scratch = Scratch::new();
        fs::remove_dir(&scratch.0).unwrap();
        drop(scratch);
    }
    let mut c = Criterion::default().without_plots();
    if std::env::var_os("VIGIL_BENCH_QUICK").is_some() {
        c = c
            .sample_size(10)
            .warm_up_time(Duration::from_secs(1))
            .measurement_time(Duration::from_secs(1))
            .nresamples(1000);
    }
    c = c.configure_from_args();
    let mut append = c.benchmark_group("append");
    for processes in [1, 8] {
        append.throughput(Throughput::Elements(RECORDS * processes as u64));
        append.bench_function(format!("{processes}_processes"), |b| {
            b.iter_custom(|iters| {
                (0..iters)
                    .map(|_| {
                        let scratch = Scratch::new();
                        multiprocess(&scratch.0, processes)
                    })
                    .sum()
            })
        });
    }
    append.finish();
    for role in ["init", "export", "split"] {
        let mut group = c.benchmark_group(role);
        if role != "init" {
            group.throughput(Throughput::Elements(RECORDS));
        }
        group.bench_function("pipeline", |b| {
            b.iter_custom(|iters| {
                (0..iters)
                    .map(|_| {
                        let scratch = Scratch::new();
                        let output = child(role, &scratch.0)
                            .env_remove("VIGIL_BENCH_FILTER")
                            .output()
                            .unwrap();
                        assert!(
                            output.status.success(),
                            "child failed: {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                        Duration::from_nanos(
                            String::from_utf8(output.stdout)
                                .unwrap()
                                .trim()
                                .parse()
                                .unwrap(),
                        )
                    })
                    .sum()
            })
        });
        group.finish();
    }
    let mut rotation = c.benchmark_group("rotation");
    for count in [100, 1000, 10_000] {
        let scratch = Scratch::new();
        // Valid segment fixtures, retention off: avoid quadratic append setup.
        for index in 0..count {
            fs::write(
                scratch
                    .0
                    .join(format!("logs-20000101T000000.000000000Z_{index:06}.jsonl")),
                b"x\n",
            )
            .unwrap();
        }
        let log = writer(&scratch.0, 1);
        log.append(b"x").unwrap();
        rotation.bench_function(count.to_string(), |b| {
            b.iter_custom(|iters| {
                let mut elapsed = Duration::ZERO;
                for _ in 0..iters {
                    let start = Instant::now();
                    log.append(b"x").unwrap();
                    elapsed += start.elapsed();
                    // Restore exactly count rotated segments outside timing.
                    for entry in fs::read_dir(&scratch.0).unwrap() {
                        let entry = entry.unwrap();
                        let name = entry.file_name();
                        let name = name.to_str().unwrap();
                        if name.starts_with("logs-") && !name.starts_with("logs-20000101") {
                            fs::remove_file(entry.path()).unwrap();
                        }
                    }
                }
                elapsed
            })
        });
    }
    rotation.finish();
    c.final_summary();
    // Keep provenance with estimates: unsetting the environment later must not
    // make quick-mode measurements eligible for a reference update.
    if args.iter().any(|arg| arg == "--bench") && !args.iter().any(|arg| arg == "--test") {
        let root = std::env::var_os("CRITERION_HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::env::var_os("CARGO_TARGET_DIR")
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|| "target".into())
                    .join("criterion")
            });
        fs::write(
            root.join("performance-mode.json"),
            serde_json::to_vec(&serde_json::json!({
                "quick": std::env::var_os("VIGIL_BENCH_QUICK").is_some(),
            }))
            .unwrap(),
        )
        .unwrap();
    }
}
