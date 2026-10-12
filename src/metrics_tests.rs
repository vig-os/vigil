use super::*;
use crate::{Config, FlushErrorKind, Signal};
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use std::{fs, panic::catch_unwind, process::Output, sync::Arc};
use tracing_subscriber::{Layer, layer::SubscriberExt};

fn panic_message(f: impl FnOnce() + std::panic::UnwindSafe) -> String {
    let error = catch_unwind(f).expect_err("validation must panic");
    error
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| error.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .unwrap()
}
#[test]
fn name_rule_panics_at_runtime() {
    for name in [
        "",
        "1bad",
        "bad!",
        "aé",
        ":",
        "a:",
        "_a",
        "a+b",
        "\x7f",
        "a\x7f",
        &"a".repeat(256),
    ] {
        let name = Box::leak(name.to_owned().into_boxed_str());
        assert!(
            panic_message(|| {
                let _ = Counter::new(crate::scope!(), name);
            })
            .starts_with("vigil::metrics: name")
        );
    }
}
#[test]
fn unit_rule_panics_at_runtime() {
    for unit in ["µs", &"a".repeat(64)] {
        let unit = Box::leak(unit.to_owned().into_boxed_str());
        assert!(
            panic_message(|| {
                let _ = Counter::new(crate::scope!(), "valid").with_unit(unit);
            })
            .starts_with("vigil::metrics: unit")
        );
    }
}
#[test]
fn boundaries_rule_panics_at_runtime() {
    for boundaries in [
        &[f64::NAN][..],
        &[f64::INFINITY],
        &[f64::NEG_INFINITY],
        &[2.0, 1.0],
        &[1.0, 1.0],
        &[-0.0, 0.0],
    ] {
        let boundaries = Box::leak(boundaries.to_vec().into_boxed_slice());
        assert!(
            panic_message(|| {
                let _ = Histogram::new(crate::scope!(), "valid").with_boundaries(boundaries);
            })
            .starts_with("vigil::metrics: boundaries")
        );
    }
}

struct Rejected(Arc<AtomicBool>);
impl<S: tracing::Subscriber> Layer<S> for Rejected {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if event.metadata().name() == "InstrumentCreationFailed" {
            self.0.store(true, Ordering::Relaxed);
        }
    }
}
#[test]
fn validation_matches_sdk() {
    if !crate::subscriber_test_child("metrics::tests::validation_matches_sdk") {
        return;
    }
    let rejected = Arc::new(AtomicBool::new(false));
    let subscriber = tracing_subscriber::registry().with(Rejected(rejected.clone()));
    let sink = crate::sink::MemorySink::new();
    let provider = SdkMeterProvider::builder()
        .with_reader(
            PeriodicReader::builder(crate::metric_export::OtlpJsonMetricExporter::new(sink))
                .build(),
        )
        .build();
    let meter = provider.meter("validation");
    tracing::subscriber::with_default(subscriber, || {
        for name in [
            "",
            "a",
            "A0_./-z",
            "1bad",
            "a b",
            ":",
            "a:",
            "_a",
            "a+b",
            "\x7f",
            "a\x7f",
            "aé",
            &"a".repeat(255),
            &"a".repeat(256),
        ] {
            rejected.store(false, Ordering::Relaxed);
            let name = Box::leak(name.to_owned().into_boxed_str());
            let ours = catch_unwind(|| {
                let _ = Counter::new(crate::scope!(), name);
            })
            .is_ok();
            let _ = meter.u64_counter(name as &'static str).build();
            assert_eq!(ours, !rejected.load(Ordering::Relaxed), "name {name:?}");
        }
        for unit in ["", "s", "µs", "\0", &"a".repeat(63), &"a".repeat(64)] {
            rejected.store(false, Ordering::Relaxed);
            let unit = Box::leak(unit.to_owned().into_boxed_str());
            let ours = catch_unwind(|| {
                let _ = Counter::new(crate::scope!(), "valid").with_unit(unit);
            })
            .is_ok();
            let _ = meter
                .u64_counter("valid")
                .with_unit(unit as &'static str)
                .build();
            assert_eq!(ours, !rejected.load(Ordering::Relaxed), "unit {unit:?}");
        }
        for boundaries in [
            &[][..],
            &[1.0],
            &[-1.0, 0.0, 1.0],
            &[f64::NAN],
            &[f64::INFINITY],
            &[f64::NEG_INFINITY],
            &[2.0, 1.0],
            &[1.0, 1.0],
            &[-0.0, 0.0],
        ] {
            rejected.store(false, Ordering::Relaxed);
            let boundaries = Box::leak(boundaries.to_vec().into_boxed_slice());
            let ours = catch_unwind(|| {
                let _ = Histogram::new(crate::scope!(), "valid").with_boundaries(boundaries);
            })
            .is_ok();
            let _ = meter
                .f64_histogram("hist")
                .with_boundaries(boundaries.to_vec())
                .build();
            assert_eq!(
                ours,
                !rejected.load(Ordering::Relaxed),
                "boundaries {boundaries:?}"
            );
        }
    });
    provider.shutdown().unwrap();
}
#[test]
fn attribute_conversions_and_scope() {
    assert_eq!(
        crate::scope!(),
        Scope::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
    );
    assert_ne!(Scope::new("crate", "1"), Scope::new("crate", "2"));
    assert_eq!(Value::from(true), Value::Bool(true));
    macro_rules! signed { ($($t:ty),+) => { $(assert_eq!(Value::from(-1 as $t), Value::I64(-1));)+ }; }
    signed!(i8, i16, i32, i64, isize);
    macro_rules! unsigned { ($($t:ty),+) => { $(assert_eq!(Value::from(1 as $t), Value::I64(1));)+ }; }
    unsigned!(u8, u16, u32, u64, usize);
    assert_eq!(Value::from(i64::MAX as u64), Value::I64(i64::MAX));
    assert_eq!(
        Value::from(i64::MAX as u64 + 1),
        Value::Str(Cow::Owned("9223372036854775808".into()))
    );
    assert_eq!(
        Value::from(u64::MAX),
        Value::Str(Cow::Owned("18446744073709551615".into()))
    );
    assert_eq!(Value::from(usize::MAX), Value::from(usize::MAX as u64));
    assert_eq!(Value::from(1.5_f32), Value::F64(1.5));
    assert_eq!(Value::from(1.5_f64), Value::F64(1.5));
    assert_eq!(Value::from("x"), Value::Str(Cow::Borrowed("x")));
    assert_eq!(
        Value::from(String::from("x")),
        Value::Str(Cow::Owned("x".into()))
    );
}
fn child(test: &str) -> Option<Output> {
    crate::test_child(&format!("metrics::tests::{test}"), "VIGIL_FACADE_CHILD")
}
fn dir(test: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("vigil-facade-{test}-{}", std::process::id()))
}
fn metrics(path: &std::path::Path) -> Vec<serde_json::Value> {
    fs::read_to_string(path.join("metrics.jsonl"))
        .unwrap()
        .lines()
        .flat_map(|line| {
            let json: serde_json::Value = serde_json::from_str(line).unwrap();
            json["resourceMetrics"][0]["scopeMetrics"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|s| s["metrics"].as_array().unwrap().clone())
                .collect::<Vec<_>>()
        })
        .collect()
}
#[test]
fn late_binding_losses_and_five_instruments() {
    if let Some(output) = child("late_binding_losses_and_five_instruments") {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            stderr
                .matches("vigil: 1 metric records before vigil::init were dropped")
                .count(),
            1
        );
        assert!(!stderr.contains("dropped measurements"));
        return;
    }
    static C: Counter = Counter::new(crate::scope!(), "requests")
        .with_unit("{request}")
        .with_description("Handled");
    static F: CounterF64 = CounterF64::new(crate::scope!(), "cpu").with_unit("s");
    static U: UpDownCounter = UpDownCounter::new(crate::scope!(), "inflight");
    static G: Gauge = Gauge::new(crate::scope!(), "memory").with_unit("By");
    static H: Histogram = Histogram::new(crate::scope!(), "latency").with_boundaries(&[1.0, 10.0]);
    C.add(99, &[]);
    assert!(C.0.handle.get().is_none());
    let path = dir("five");
    let (_, guard) = Config::new("facade")
        .dir(&path)
        .layer::<tracing_subscriber::Registry>()
        .unwrap();
    let attrs = [
        ("bool", true.into()),
        ("int", (-1).into()),
        ("double", 1.5.into()),
        ("str", "x".into()),
        ("large", u64::MAX.into()),
    ];
    C.add(3, &attrs);
    F.add(1.5, &[]);
    U.add(-2, &[]);
    G.record(42.0, &[]);
    H.record(4.0, &[]);
    let error = guard.flush().unwrap_err();
    assert_eq!(error.kind(), FlushErrorKind::DataLost);
    assert_eq!(error.lost(Signal::Metrics), 1);
    assert!(
        error
            .to_string()
            .contains("at least 1 metric measurements lost")
    );
    guard.flush().unwrap();
    drop(guard);
    let all = metrics(&path);
    let find = |name: &str| all.iter().find(|m| m["name"] == name).unwrap();
    let c = find("requests");
    assert_eq!(c["description"], "Handled");
    assert_eq!(c["unit"], "{request}");
    assert_eq!(c["sum"]["dataPoints"][0]["asInt"], 3);
    assert_eq!(
        c["sum"]["dataPoints"][0]["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["key"] == "large")
            .unwrap()["value"]["stringValue"],
        "18446744073709551615"
    );
    assert_eq!(find("cpu")["sum"]["dataPoints"][0]["asDouble"], 1.5);
    assert_eq!(find("inflight")["sum"]["dataPoints"][0]["asInt"], -2);
    assert_eq!(find("memory")["gauge"]["dataPoints"][0]["asDouble"], 42.0);
    assert_eq!(
        find("latency")["histogram"]["dataPoints"][0]["explicitBounds"],
        serde_json::json!([1.0, 10.0])
    );
    fs::remove_dir_all(path).unwrap();
}
#[test]
fn unset_empty_and_explicit_boundaries() {
    if child("unset_empty_and_explicit_boundaries").is_some() {
        return;
    }
    let path = dir("buckets");
    let (_, guard) = Config::new("buckets")
        .dir(&path)
        .layer::<tracing_subscriber::Registry>()
        .unwrap();
    Histogram::new(crate::scope!(), "defaults").record(2.0, &[]);
    Histogram::new(crate::scope!(), "empty")
        .with_boundaries(&[])
        .record(2.0, &[]);
    guard.shutdown().unwrap();
    let all = metrics(&path);
    let point =
        |name: &str| &all.iter().find(|m| m["name"] == name).unwrap()["histogram"]["dataPoints"][0];
    assert!(
        !point("defaults")["explicitBounds"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        point("empty")["explicitBounds"]
            .as_array()
            .is_none_or(Vec::is_empty)
    );
    assert_eq!(point("empty")["bucketCounts"], serde_json::json!([]));
    assert_eq!(point("empty")["explicitBounds"], serde_json::json!([]));
    assert_eq!(point("empty")["count"], "1");
    assert_eq!(point("empty")["sum"], 2.0);
    assert_eq!(point("empty")["min"], 2.0);
    assert_eq!(point("empty")["max"], 2.0);
    fs::remove_dir_all(path).unwrap();
}
#[test]
fn after_shutdown_never_counts_binds_or_calls_sdk() {
    if let Some(output) = child("after_shutdown_never_counts_binds_or_calls_sdk") {
        assert_eq!(
            String::from_utf8_lossy(&output.stderr)
                .matches("vigil: metric recorded after vigil shutdown; dropped")
                .count(),
            1
        );
        return;
    }
    struct Calls(AtomicU64);
    impl opentelemetry::metrics::SyncInstrument<u64> for Calls {
        fn measure(&self, _: u64, _: &[KeyValue]) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let path = dir("shutdown");
    let (_, guard) = Config::new("shutdown")
        .dir(&path)
        .layer::<tracing_subscriber::Registry>()
        .unwrap();
    let pipeline = crate::init::published_pipeline().unwrap();
    let calls = Arc::new(Calls(AtomicU64::new(0)));
    let counter = Counter::new(crate::scope!(), "bound");
    assert!(
        counter
            .0
            .handle
            .set(Some(Bound {
                handle: Some(opentelemetry::metrics::Counter::new(calls.clone())),
                poisoned: Arc::new(AtomicBool::new(false)),
                pipeline
            }))
            .is_ok()
    );
    counter.add(1, &[]);
    assert_eq!(calls.0.load(Ordering::Relaxed), 1);
    guard.shutdown().unwrap();
    counter.add(1, &[]);
    counter.add(1, &[]);
    let late = Counter::new(crate::scope!(), "late");
    late.add(1, &[]);
    assert!(late.0.handle.get().is_none());
    assert_eq!(calls.0.load(Ordering::Relaxed), 1);
    pipeline.losses.finish(Ok(())).unwrap();
    fs::remove_dir_all(path).unwrap();
}
#[test]
fn disabled_metrics_are_silent_even_after_shutdown() {
    if let Some(output) = child("disabled_metrics_are_silent_even_after_shutdown") {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("after vigil shutdown"));
        assert_eq!(
            stderr
                .matches("vigil: 1 metric records before vigil::init were dropped")
                .count(),
            1
        );
        assert!(!stderr.contains("dropped measurements"));
        return;
    }
    let path = dir("off");
    let counter = Counter::new(crate::scope!(), "off");
    counter.add(1, &[]);
    let (_, guard) = Config::new("off")
        .dir(&path)
        .metrics(false)
        .layer::<tracing_subscriber::Registry>()
        .unwrap();
    counter.add(1, &[]);
    assert!(matches!(counter.0.handle.get(), Some(None)));
    assert_eq!(guard.flush().unwrap_err().lost(Signal::Metrics), 1);
    guard.shutdown().unwrap();
    counter.add(1, &[]);
    assert!(!path.join("metrics.jsonl").exists());
    fs::remove_dir_all(path).unwrap();
}
#[test]
fn storage_failure_caches_no_handle() {
    if let Some(output) = child("storage_failure_caches_no_handle") {
        assert!(!String::from_utf8_lossy(&output.stderr).contains("after vigil shutdown"));
        return;
    }
    let path = dir("storage");
    fs::create_dir_all(path.join("metrics.jsonl")).unwrap();
    let counter = Counter::new(crate::scope!(), "failed");
    counter.add(1, &[]);
    let (_, guard) = Config::new("storage")
        .dir(&path)
        .layer::<tracing_subscriber::Registry>()
        .unwrap();
    counter.add(1, &[]);
    assert!(matches!(counter.0.handle.get(), Some(None)));
    assert_eq!(guard.flush().unwrap_err().lost(Signal::Metrics), 1);
    guard.shutdown().unwrap();
    counter.add(1, &[]);
    fs::remove_dir_all(path).unwrap();
}
#[test]
fn publication_race_drains_at_period_finish_and_drop() {
    if let Some(output) = child("publication_race_drains_at_period_finish_and_drop") {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("before vigil::init"));
        assert_eq!(stderr.matches("dropped measurements: 2").count(), 1);
        return;
    }
    let path = dir("race");
    let (_, guard) = Config::new("race")
        .dir(&path)
        .layer::<tracing_subscriber::Registry>()
        .unwrap();
    // A producer observed no publication before commit and increments after the startup drain.
    BEFORE_INIT.fetch_add(2, Ordering::Relaxed);
    assert_eq!(guard.flush().unwrap_err().lost(Signal::Metrics), 2);
    guard.flush().unwrap();
    drop(guard);
    fs::remove_dir_all(path).unwrap();
}
#[test]
fn explicit_shutdown_does_not_print_measurements() {
    if let Some(output) = child("explicit_shutdown_does_not_print_measurements") {
        assert!(!String::from_utf8_lossy(&output.stderr).contains("dropped measurements"));
        return;
    }
    let path = dir("explicit-shutdown");
    let (_, guard) = Config::new("explicit-shutdown")
        .dir(&path)
        .layer::<tracing_subscriber::Registry>()
        .unwrap();
    // Two producers observed no publication, then incremented after the startup drain.
    BEFORE_INIT.fetch_add(2, Ordering::Relaxed);
    assert_eq!(guard.shutdown().unwrap_err().lost(Signal::Metrics), 2);
    fs::remove_dir_all(path).unwrap();
}
#[test]
fn mixed_losses_display_in_signal_order() {
    let losses = Losses::default();
    losses.record(3, false);
    losses.measurements_dropped(2);
    losses.metric_data_points(false);
    let error = losses.finish(Ok(())).unwrap_err();
    assert_eq!(
        error.to_string(),
        "DataLost: at least 3 log records lost; at least 2 metric measurements lost; metric data points dropped"
    );
    assert_eq!(error.lost(Signal::Logs), 3);
    assert_eq!(error.lost(Signal::Metrics), 2);
}
#[test]
fn scope_versions_reach_disk_separately() {
    if child("scope_versions_reach_disk_separately").is_some() {
        return;
    }
    let path = dir("scopes");
    let (_, guard) = Config::new("scopes")
        .dir(&path)
        .layer::<tracing_subscriber::Registry>()
        .unwrap();
    Counter::new(Scope::new("declaring", "1"), "requests").add(1, &[]);
    Counter::new(Scope::new("declaring", "2"), "requests").add(2, &[]);
    guard.shutdown().unwrap();
    let json: serde_json::Value = serde_json::from_str(
        fs::read_to_string(path.join("metrics.jsonl"))
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    let scopes = json["resourceMetrics"][0]["scopeMetrics"]
        .as_array()
        .unwrap();
    assert_eq!(scopes.len(), 2);
    assert!(
        scopes
            .iter()
            .any(|s| s["scope"]["name"] == "declaring" && s["scope"]["version"] == "1")
    );
    assert!(
        scopes
            .iter()
            .any(|s| s["scope"]["name"] == "declaring" && s["scope"]["version"] == "2")
    );
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn drop_stops_bound_and_unbound_instruments() {
    if let Some(output) = child("drop_stops_bound_and_unbound_instruments") {
        assert_eq!(
            String::from_utf8_lossy(&output.stderr)
                .matches("vigil: metric recorded after vigil shutdown; dropped")
                .count(),
            1
        );
        return;
    }
    let path = dir("drop");
    let (_, guard) = Config::new("drop")
        .dir(&path)
        .layer::<tracing_subscriber::Registry>()
        .unwrap();
    let bound = Counter::new(crate::scope!(), "bound");
    bound.add(1, &[]);
    drop(guard);
    assert!(
        crate::init::published_pipeline()
            .unwrap()
            .stopped
            .load(Ordering::Acquire)
    );
    bound.add(99, &[]);
    let unbound = Counter::new(crate::scope!(), "unbound");
    unbound.add(99, &[]);
    assert!(unbound.0.handle.get().is_none());
    let all = metrics(&path);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0]["sum"]["dataPoints"][0]["asInt"], 1);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn staged_poisoning_filters_cumulative_streams_without_data_point_losses() {
    if let Some(output) =
        child("staged_poisoning_filters_cumulative_streams_without_data_point_losses")
    {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(stderr.matches("conflicting metric instruments:").count(), 1);
        assert!(!stderr.contains("dropped data points"));
        return;
    }
    static A: Counter = Counter::new(Scope::new("crate-a", "1"), "staged.x").with_unit("ms");
    static B: Counter = Counter::new(Scope::new("crate-b", "1"), "staged.x").with_unit("s");
    static OK: Counter = Counter::new(crate::scope!(), "staged.ok");
    let path = dir("staged-poison");
    let (_, guard) = Config::new("identity")
        .dir(&path)
        .metrics_interval(std::time::Duration::from_secs(3600))
        .layer::<tracing_subscriber::Registry>()
        .unwrap();
    A.add(1, &[]);
    OK.add(1, &[]);
    guard.flush().unwrap();
    assert!(metrics(&path).iter().any(|m| m["name"] == "staged.x"));
    let before = fs::read_to_string(path.join("metrics.jsonl"))
        .unwrap()
        .len();
    B.add(1, &[]);
    A.add(1, &[]);
    let error = guard.flush().unwrap_err();
    assert_eq!(error.lost(Signal::Metrics), 2);
    assert_eq!(error.kind(), FlushErrorKind::DataLost);
    assert!(
        error
            .to_string()
            .contains("metric names poisoned by conflicting declarations")
    );
    let text = fs::read_to_string(path.join("metrics.jsonl")).unwrap();
    assert!(!text[before..].contains("staged.x"));
    assert!(text[before..].contains("staged.ok"));
    guard.flush().unwrap();
    A.add(1, &[]);
    let error = guard.flush().unwrap_err();
    assert_eq!(error.lost(Signal::Metrics), 1);
    assert!(!error.to_string().contains("metric names poisoned"));
    guard.shutdown().unwrap();
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn poisoned_only_export_writes_no_line() {
    if child("poisoned_only_export_writes_no_line").is_some() {
        return;
    }
    static A: Counter = Counter::new(crate::scope!(), "empty.x").with_unit("ms");
    static B: Counter = Counter::new(crate::scope!(), "empty.x").with_unit("s");
    let path = dir("empty-poison");
    let (_, guard) = Config::new("identity")
        .dir(&path)
        .metrics_interval(std::time::Duration::from_secs(3600))
        .layer::<tracing_subscriber::Registry>()
        .unwrap();
    A.add(1, &[]);
    B.add(1, &[]);
    assert_eq!(guard.flush().unwrap_err().lost(Signal::Metrics), 1);
    assert!(
        fs::read_to_string(path.join("metrics.jsonl"))
            .unwrap()
            .is_empty()
    );
    guard.shutdown().unwrap();
    fs::remove_dir_all(path).unwrap();
}

/// Mask only timestamps, service.instance.id and process.pid for comparison.
/// ADR-0003 d7 keeps process identity in production output; ruling 7b2b-d2
/// excludes those process-specific fields from the determinism property.
fn normalize_identity_comparison(text: &str) -> String {
    // Retain object order and raw scalar spelling, so comparison still checks
    // bytes rather than silently sorting fields through serde_json::Map.
    struct Fields<'a>(Vec<(String, &'a serde_json::value::RawValue)>);
    impl<'de> serde::Deserialize<'de> for Fields<'de> {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Fields<'de>;
                fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    formatter.write_str("an OTLP object")
                }
                fn visit_map<M: serde::de::MapAccess<'de>>(
                    self,
                    mut map: M,
                ) -> Result<Self::Value, M::Error> {
                    let mut fields = Vec::new();
                    while let Some(entry) = map.next_entry()? {
                        fields.push(entry);
                    }
                    Ok(Fields(fields))
                }
            }
            deserializer.deserialize_map(Visitor)
        }
    }
    fn mask(raw: &serde_json::value::RawValue, resource: bool, attributes: bool) -> String {
        let text = raw.get();
        match text.as_bytes().first() {
            Some(b'{') => {
                let fields: Fields<'_> = serde_json::from_str(text).unwrap();
                let fields: Vec<_> = fields
                    .0
                    .into_iter()
                    .filter(|(key, _)| key != "timeUnixNano" && !key.ends_with("TimeUnixNano"))
                    .map(|(key, value)| {
                        let filtered =
                            mask(value, key == "resource", resource && key == "attributes");
                        format!("{}:{filtered}", serde_json::to_string(&key).unwrap())
                    })
                    .collect();
                format!("{{{}}}", fields.join(","))
            }
            Some(b'[') => {
                let values: Vec<&serde_json::value::RawValue> = serde_json::from_str(text).unwrap();
                let values: Vec<_> = values
                    .into_iter()
                    .filter(|value| {
                        if !attributes {
                            return true;
                        }
                        let value: serde_json::Value = serde_json::from_str(value.get()).unwrap();
                        !matches!(
                            value["key"].as_str(),
                            Some("service.instance.id" | "process.pid")
                        )
                    })
                    .map(|v| mask(v, false, false))
                    .collect();
                format!("[{}]", values.join(","))
            }
            _ => text.to_owned(),
        }
    }
    let mut normalized = text
        .lines()
        .map(|line| {
            let raw = serde_json::from_str(line).unwrap();
            mask(raw, false, false)
        })
        .collect::<Vec<_>>()
        .join("\n");
    if text.ends_with('\n') {
        normalized.push('\n');
    }
    normalized
}

fn determinism_run(reverse: bool) {
    let path = dir(if reverse {
        "determinism-reverse"
    } else {
        "determinism-forward"
    });
    static A: Counter = Counter::new(Scope::new("crate-a", "1"), "conflict.x").with_unit("ms");
    static B: Counter = Counter::new(Scope::new("crate-b", "1"), "conflict.x").with_unit("s");
    static OK: Counter = Counter::new(crate::scope!(), "identity.ok");
    let (_, guard) = Config::new("identity")
        .dir(&path)
        .metrics_interval(std::time::Duration::from_secs(3600))
        .layer::<tracing_subscriber::Registry>()
        .unwrap();
    if reverse {
        B.add(1, &[]);
        A.add(1, &[]);
    } else {
        A.add(1, &[]);
        B.add(1, &[]);
    }
    OK.add(7, &[]);
    assert_eq!(guard.flush().unwrap_err().kind(), FlushErrorKind::DataLost);
    let text = fs::read_to_string(path.join("metrics.jsonl")).unwrap();
    assert!(!text.is_empty());
    assert!(text.contains("identity.ok"));
    assert!(!text.contains("conflict.x"));
    println!(
        "DETERMINISTIC:{}",
        serde_json::to_string(&normalize_identity_comparison(&text)).unwrap()
    );
    guard.shutdown().unwrap();
    fs::remove_dir_all(path).unwrap();
}
#[test]
fn identity_determinism_forward() {
    if child("identity_determinism_forward").is_some() {
        return;
    }
    determinism_run(false);
}
#[test]
fn identity_determinism_reverse() {
    if child("identity_determinism_reverse").is_some() {
        return;
    }
    determinism_run(true);
}
#[test]
fn identity_determinism_compares_separate_processes() {
    let forward = child("identity_determinism_forward").unwrap();
    let reverse = child("identity_determinism_reverse").unwrap();
    let line = |out: &Output| {
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|l| l.strip_prefix("DETERMINISTIC:"))
            .unwrap()
            .to_owned()
    };
    assert_eq!(line(&forward), line(&reverse));
}

#[cfg(vigil_unstable)]
fn global_run(install: bool, poison: bool, init: bool) {
    let path = dir("global");
    let config = Config::new("global")
        .dir(&path)
        .metrics_interval(std::time::Duration::from_secs(3600));
    let config = if install {
        config.install_opentelemetry_globals()
    } else {
        config
    };
    let guard = if init {
        config.init().unwrap()
    } else {
        config.layer::<tracing_subscriber::Registry>().unwrap().1
    };
    let counter = opentelemetry::global::meter("global")
        .u64_counter("global.x")
        .build();
    counter.add(5, &[]);
    if poison {
        static A: Counter = Counter::new(crate::scope!(), "global.x").with_unit("ms");
        static B: Counter = Counter::new(crate::scope!(), "global.x").with_unit("s");
        A.add(1, &[]);
        B.add(1, &[]);
        assert_eq!(guard.flush().unwrap_err().kind(), FlushErrorKind::DataLost);
        guard.flush().unwrap();
    }
    guard.shutdown().unwrap();
    let text = fs::read_to_string(path.join("metrics.jsonl")).unwrap();
    assert_eq!(text.contains("global.x"), install && !poison);
    fs::remove_dir_all(path).unwrap();
}
#[cfg(vigil_unstable)]
macro_rules! globals {
    ($($name:ident: $install:literal,$poison:literal,$init:literal;)+) => {$(
        #[test] fn $name() { if child(stringify!($name)).is_none() { global_run($install,$poison,$init); } }
    )+};
}
#[cfg(vigil_unstable)]
globals! {
    global_installed_layer: true,false,false;
    global_installed_init: true,false,true;
    global_not_installed_layer: false,false,false;
    global_not_installed_init: false,false,true;
    global_poisoned: true,true,false;
}

#[test]
fn determinism_mask_preserves_metric_identity_and_measurements() {
    let input = serde_json::json!({
        "resource": {"attributes": [
            {"key":"service.instance.id", "value":{"stringValue":"id"}},
            {"key":"process.pid", "value":{"intValue":"123"}},
            {"key":"service.name", "value":{"stringValue":"service"}}
        ]},
        "name":"identity.ok", "description":"kept", "unit":"ms",
        "timeUnixNano":"1", "startTimeUnixNano":"2",
        "attributes":[{"key":"process.pid","value":{"intValue":"99"}}],
        "asInt":7
    });
    let normalized = normalize_identity_comparison(&input.to_string());
    let input: serde_json::Value = serde_json::from_str(&normalized).unwrap();
    assert!(input.get("timeUnixNano").is_none());
    assert!(input.get("startTimeUnixNano").is_none());
    assert_eq!(input["resource"]["attributes"].as_array().unwrap().len(), 1);
    assert_eq!(input["resource"]["attributes"][0]["key"], "service.name");
    assert_eq!(input["name"], "identity.ok");
    assert_eq!(input["asInt"], 7);
    assert_eq!(input["description"], "kept");
    assert_eq!(input["unit"], "ms");
    assert_eq!(input["attributes"][0]["value"]["intValue"], "99");
}

#[test]
fn determinism_mask_retains_field_order_and_scalar_spelling() {
    let text = "{\"name\":\"identity.ok\",\"timeUnixNano\":\"1\",\"asDouble\":1.0}\n";
    assert_eq!(
        normalize_identity_comparison(text),
        "{\"name\":\"identity.ok\",\"asDouble\":1.0}\n"
    );
    let reversed = "{\"asDouble\":1.0,\"name\":\"identity.ok\"}\n";
    assert_ne!(
        normalize_identity_comparison(text),
        normalize_identity_comparison(reversed)
    );
}

fn signed_zero_run(reverse: bool) {
    let path = dir("signed-zero");
    static NEGATIVE: Histogram =
        Histogram::new(Scope::new("crate-a", "1"), "zero.h").with_boundaries(&[-0.0, 1.0]);
    static POSITIVE: Histogram =
        Histogram::new(Scope::new("crate-a", "1"), "zero.h").with_boundaries(&[0.0, 1.0]);
    let (_, guard) = Config::new("signed-zero")
        .dir(&path)
        .metrics_interval(std::time::Duration::from_secs(3600))
        .layer::<tracing_subscriber::Registry>()
        .unwrap();
    if reverse {
        POSITIVE.record(0.5, &[]);
        NEGATIVE.record(0.5, &[]);
    } else {
        NEGATIVE.record(0.5, &[]);
        POSITIVE.record(0.5, &[]);
    }
    guard.flush().unwrap();
    let exported = metrics(&path);
    assert_eq!(exported.len(), 1);
    let point = &exported[0]["histogram"]["dataPoints"][0];
    assert_eq!(point["count"], "2");
    assert_eq!(
        point["explicitBounds"][0].as_f64().unwrap().to_bits(),
        0.0_f64.to_bits()
    );
    let text = fs::read_to_string(path.join("metrics.jsonl")).unwrap();
    println!(
        "SIGNED_ZERO:{}",
        serde_json::to_string(&normalize_identity_comparison(&text)).unwrap()
    );
    guard.shutdown().unwrap();
    fs::remove_dir_all(path).unwrap();
}
#[test]
fn identity_determinism_zero_forward() {
    if child("identity_determinism_zero_forward").is_none() {
        signed_zero_run(false);
    }
}
#[test]
fn identity_determinism_zero_reverse() {
    if child("identity_determinism_zero_reverse").is_none() {
        signed_zero_run(true);
    }
}
#[test]
fn identity_determinism_zero_compares_separate_processes() {
    let forward = child("identity_determinism_zero_forward").unwrap();
    let reverse = child("identity_determinism_zero_reverse").unwrap();
    let line = |out: &Output| {
        assert!(!String::from_utf8_lossy(&out.stderr).contains("conflicting metric instruments"));
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|line| line.strip_prefix("SIGNED_ZERO:"))
            .unwrap()
            .to_owned()
    };
    assert_eq!(line(&forward), line(&reverse));
}
