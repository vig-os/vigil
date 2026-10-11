//! Also run with `cargo test --test shared_pipeline` to share one process.
use std::sync::LazyLock;

static GUARD: LazyLock<vigil::Guard> = LazyLock::new(|| {
    vigil::Config::new("shared-tests")
        .dir(std::env::temp_dir().join(format!("vigil-shared-{}", std::process::id())))
        .filter_env("VIGIL_SHARED_TEST_LOG")
        .default_filter("info")
        .init()
        .unwrap()
});

fn record_and_read(test_case: &'static str) {
    let guard = &*GUARD;
    tracing::info!(test_case, "shared pipeline record");
    guard.flush().unwrap();
    let lines = vigil::rotate::read_since(guard.dir().unwrap(), "logs", None).unwrap();
    let mut own_records = 0;
    for line in lines {
        let data: serde_json::Value = serde_json::from_str(&line).unwrap();
        for scope in data["resourceLogs"][0]["scopeLogs"].as_array().unwrap() {
            own_records += scope["logRecords"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|record| {
                    record["attributes"].as_array().unwrap().iter().any(|attr| {
                        attr["key"] == "test_case" && attr["value"]["stringValue"] == test_case
                    })
                })
                .count();
        }
    }
    assert_eq!(own_records, 1);
}

#[test]
fn first_shared_consumer() {
    record_and_read("first_shared_consumer");
}
#[test]
fn second_shared_consumer() {
    record_and_read("second_shared_consumer");
}
