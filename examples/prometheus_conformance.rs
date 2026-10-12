//! Two explicit cumulative exports for the real Collector → Prometheus oracle.
#[cfg(feature = "metrics")]
mod enabled {
    use std::{
        error::Error,
        path::Path,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };
    use vigil::metrics::{Counter, CounterF64, Gauge, Histogram, Scope, UpDownCounter};

    // Oracle metadata is independent of the exported OTLP scope labels.
    fn package_scope() -> (&'static str, &'static str) {
        (env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
    }

    #[test]
    fn oracle_scope_matches_declaring_package() {
        assert_eq!(
            package_scope(),
            (env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
        );
    }

    enum Instrument {
        Counter(Counter),
        CounterF64(CounterF64),
        UpDownCounter(UpDownCounter),
        Gauge(Gauge),
        Histogram(Histogram),
    }
    impl Instrument {
        fn new(kind: &str, scope: Scope, name: &'static str, unit: &'static str) -> Self {
            match kind {
                "Counter" => Self::Counter(Counter::new(scope, name).with_unit(unit)),
                "CounterF64" => Self::CounterF64(CounterF64::new(scope, name).with_unit(unit)),
                "UpDownCounter" => {
                    Self::UpDownCounter(UpDownCounter::new(scope, name).with_unit(unit))
                }
                "Gauge" => Self::Gauge(Gauge::new(scope, name).with_unit(unit)),
                "Histogram" => Self::Histogram(Histogram::new(scope, name).with_unit(unit)),
                _ => panic!("unknown fixture kind {kind}"),
            }
        }
        fn record(&self, value: u64) {
            match self {
                Self::Counter(c) => c.add(value, &[]),
                Self::CounterF64(c) => c.add(value as f64, &[]),
                Self::UpDownCounter(c) => c.add(value as i64, &[]),
                Self::Gauge(c) => c.record(value as f64, &[]),
                Self::Histogram(c) => c.record(value as f64, &[]),
            }
        }
    }
    fn timestamp(path: &Path) -> Result<u128, Box<dyn Error>> {
        let text = std::fs::read_to_string(path)?;
        let line: serde_json::Value =
            serde_json::from_str(text.lines().last().ok_or("missing export")?)?;
        let mut latest = None;
        for resource in line["resourceMetrics"]
            .as_array()
            .ok_or("missing resources")?
        {
            for scope in resource["scopeMetrics"]
                .as_array()
                .ok_or("missing scopes")?
            {
                for metric in scope["metrics"].as_array().ok_or("missing metrics")? {
                    let data = ["sum", "gauge", "histogram"]
                        .into_iter()
                        .find_map(|kind| metric.get(kind))
                        .ok_or("missing metric data")?;
                    for point in data["dataPoints"].as_array().ok_or("missing points")? {
                        let stamp: u128 = point["timeUnixNano"]
                            .as_str()
                            .ok_or("missing timestamp")?
                            .parse()?;
                        latest = Some(latest.map_or(stamp, |old: u128| old.max(stamp)));
                    }
                }
            }
        }
        latest.ok_or_else(|| "export has no timestamp".into())
    }
    // Prometheus stores milliseconds and rejects a second sample at the same
    // timestamp as a duplicate, which would otherwise keep the round-1 value.
    // Anchor this correctness condition on the actual first export after flush.
    fn wait_after_export(first: u128) -> Result<(), Box<dyn Error>> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() <= first / 1_000_000 {
            if Instant::now() >= deadline {
                return Err(
                    "clock did not advance beyond first export's millisecond within 5s".into(),
                );
            }
            std::thread::sleep(Duration::from_micros(100));
        }
        Ok(())
    }
    pub(super) fn run() -> Result<(), Box<dyn Error>> {
        let args: Vec<_> = std::env::args().collect();
        let case = args
            .get(1)
            .ok_or("usage: prometheus_conformance <case> <state-dir>")?;
        let dir = Path::new(args.get(2).ok_or("missing state directory")?);
        let a = Scope::new("crate-a", "1");
        let b = Scope::new("crate-b", "1");
        let declarations = match case.as_str() {
            "S1" => vec![
                ("Counter", a.clone(), "app.x", ""),
                ("Counter", b.clone(), "app.x", ""),
            ],
            "S1b" => vec![
                ("Counter", a.clone(), "app.x", ""),
                ("Counter", b.clone(), "app_x", ""),
            ],
            "S2" => vec![
                ("Counter", a.clone(), "app.x", ""),
                ("Counter", a.clone(), "app_x", ""),
            ],
            "S3" => vec![
                ("Counter", a.clone(), "app.x", "ms"),
                ("Counter", a.clone(), "app.x.milliseconds", ""),
            ],
            "S4" => vec![
                ("Histogram", a.clone(), "app.y", ""),
                ("Gauge", a.clone(), "app.y.count", ""),
            ],
            "S4b" => vec![
                ("Histogram", a.clone(), "app.y", ""),
                ("Gauge", b.clone(), "app.y.count", ""),
            ],
            "S5" => vec![
                ("Counter", a.clone(), "app.total.x", ""),
                ("Counter", a.clone(), "app.x", ""),
            ],
            "clean" => vec![
                ("Counter", vigil::scope!(), "app.requests", "{request}"),
                ("Histogram", vigil::scope!(), "app.latency", "ms"),
                ("Gauge", vigil::scope!(), "app.memory", "By"),
            ],
            _ if case.starts_with("fixture-") => {
                let rows: serde_json::Value =
                    serde_json::from_str(include_str!("../tests/fixtures/prometheus_names.json"))?;
                let index: usize = case.trim_start_matches("fixture-").parse()?;
                let row = rows
                    .as_array()
                    .and_then(|rows| rows.get(index))
                    .ok_or("missing fixture row")?;
                if row.get("translation_only").is_some() {
                    return Err(
                        "translation-only row cannot run through facade (ADR-0003 d24)".into(),
                    );
                }
                let text = |key| -> Result<&'static str, Box<dyn Error>> {
                    Ok(Box::leak(
                        row[key]
                            .as_str()
                            .ok_or("invalid fixture string")?
                            .to_owned()
                            .into_boxed_str(),
                    ))
                };
                vec![(text("kind")?, vigil::scope!(), text("name")?, text("unit")?)]
            }
            _ => return Err(format!("unknown case {case}").into()),
        };
        let instruments: Vec<_> = declarations
            .into_iter()
            .map(|(kind, scope, name, unit)| Instrument::new(kind, scope, name, unit))
            .collect();
        let poisoned = matches!(case.as_str(), "S2" | "S3" | "S4" | "S4b" | "S5");
        let witness = Counter::new(a, "app.witness");
        let (_, guard) = vigil::Config::new("prometheus-conformance")
            .dir(dir)
            .metrics(true)
            .metrics_interval(Duration::from_secs(3600))
            .layer::<tracing_subscriber::Registry>()?;
        let record_round = |round: u64| {
            for (index, instrument) in instruments.iter().enumerate() {
                instrument.record(if case == "S1" {
                    if index == 0 { 5 } else { 7 }
                } else {
                    3 + round
                });
            }
            if poisoned {
                witness.add(1, &[]);
            }
        };
        let report = |operation, result: Result<(), vigil::FlushError>| {
            match &result {
                Ok(()) => eprintln!("vigil-conformance: {operation}: OK"),
                Err(error) => eprintln!("vigil-conformance: {operation}: {error}"),
            }
            result.is_err()
        };
        record_round(0);
        let flush_failed = report("flush", guard.flush());
        std::fs::write(
            dir.join("scope.json"),
            serde_json::to_vec(&package_scope())?,
        )?;
        let first = timestamp(&dir.join("metrics.jsonl"))?;
        eprintln!("vigil-conformance: flush timeUnixNano: {first}");
        wait_after_export(first)?;
        record_round(1);
        let shutdown_failed = report("shutdown", guard.shutdown());
        let second = timestamp(&dir.join("metrics.jsonl"))?;
        eprintln!("vigil-conformance: shutdown timeUnixNano: {second}");
        if flush_failed || shutdown_failed {
            std::process::exit(2);
        }
        Ok(())
    }
}
#[cfg(feature = "metrics")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    enabled::run()
}
#[cfg(not(feature = "metrics"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err("requires metrics feature".into())
}
