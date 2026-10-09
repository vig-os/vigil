//! Guards the dependency footprint: vigil's default feature set must stay free
//! of the network stack. `opentelemetry-proto` is pulled in for its message
//! types and serde support only, so `tonic`, `tokio`, `hyper` and
//! `prost-build` must never appear in `Cargo.lock`.
//!
//! Reading `Cargo.lock` (rather than shelling out to `cargo tree`) keeps this
//! working inside the offline Nix sandbox. The equivalent manual check is
//! `cargo tree -i tonic` (and likewise for the others), which must fail with
//! "package ID specification ... did not match any packages".

const FORBIDDEN: [&str; 7] = [
    "tonic",
    "tokio",
    "hyper",
    "prost-build",
    "reqwest",
    "h2",
    "tower",
];

#[test]
fn no_network_stack_in_the_lockfile() {
    let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock"))
        .expect("Cargo.lock must be readable (and committed)");
    let packages: Vec<&str> = lock
        .lines()
        .filter_map(|l| l.strip_prefix("name = \""))
        .filter_map(|l| l.strip_suffix('"'))
        .collect();
    assert!(
        packages.contains(&"opentelemetry-proto"),
        "lockfile not parsed: {packages:?}"
    );
    let found: Vec<_> = FORBIDDEN.iter().filter(|f| packages.contains(f)).collect();
    assert!(
        found.is_empty(),
        "forbidden crates in Cargo.lock: {found:?}"
    );
}
