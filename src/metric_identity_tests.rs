use super::*;
use crate::{FlushErrorKind, Signal};

fn declaration(
    scope: &'static str,
    name: &'static str,
    kind: Kind,
    unit: &'static str,
    description: &'static str,
    boundaries: Option<&'static [f64]>,
) -> Declaration {
    Declaration {
        scope: (scope, "1"),
        name,
        kind,
        unit,
        description,
        boundaries,
    }
}
fn counter(scope: &'static str, name: &'static str, unit: &'static str) -> Declaration {
    declaration(scope, name, Kind::Counter, unit, "", None)
}
fn child(name: &str, poisoned: usize, informational: usize) -> bool {
    if let Some(out) = crate::test_child(
        &format!("metric_identity::tests::{name}"),
        "VIGIL_IDENTITY_CHILD",
    ) {
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            stderr
                .matches("vigil: conflicting metric instruments:")
                .count(),
            poisoned,
            "{stderr}"
        );
        assert_eq!(
            stderr
                .matches("Prometheus needs otlp.promote_scope_metadata: true")
                .count(),
            informational,
            "{stderr}"
        );
        if informational > 0 {
            assert!(stderr.contains("crate-a@1 and crate-b@1"), "{stderr}");
        }
        false
    } else {
        true
    }
}
fn pair(a: Declaration, b: Declaration, conflict: bool) {
    let registry = Registry::default();
    let losses = Losses::default();
    let (first, handle) = registry.bind(a.clone(), &losses, || ());
    assert!(handle.is_some());
    let (second, handle) = registry.bind(b.clone(), &losses, || ());
    assert_eq!(handle.is_none(), conflict);
    assert_eq!(first.load(Ordering::Acquire), conflict);
    assert_eq!(second.load(Ordering::Acquire), conflict);
    if conflict {
        // Two record calls, one on each already bound poison flag.
        for flag in [&first, &second] {
            if flag.load(Ordering::Acquire) {
                losses.measurements_dropped(1);
            }
        }
        let error = losses.finish(Ok(())).unwrap_err();
        assert_eq!(error.kind(), FlushErrorKind::DataLost);
        assert_eq!(error.lost(Signal::Metrics), 2);
        assert!(
            error
                .to_string()
                .contains("metric names poisoned by conflicting declarations")
        );
        assert!(!error.to_string().contains("data points"));
    } else {
        assert!(losses.finish(Ok(())).is_ok());
    }
    assert!(losses.finish(Ok(())).is_ok());
    // Empty scopes/resources are removed; other metrics retain their order.
    use opentelemetry_proto::tonic::metrics::v1::{Metric, ResourceMetrics, ScopeMetrics};
    let mut request = ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            scope_metrics: vec![ScopeMetrics {
                metrics: vec![
                    Metric {
                        name: a.name.into(),
                        ..Default::default()
                    },
                    Metric {
                        name: b.name.into(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    registry.filter(&mut request);
    assert_eq!(request.resource_metrics.is_empty(), conflict);
    assert!(losses.finish(Ok(())).is_ok());
}
macro_rules! cases {
    ($($forward:ident, $reverse:ident: $a:expr, $b:expr, $conflict:literal, $info:literal;)+) => {$(
        #[test] fn $forward() { if child(stringify!($forward), usize::from($conflict), $info) { pair($a, $b, $conflict); } }
        #[test] fn $reverse() { if child(stringify!($reverse), usize::from($conflict), $info) { pair($b, $a, $conflict); } }
    )+};
}
cases! {
    p15_boundaries, p15_boundaries_reverse: declaration("crate-a", "app.x", Kind::Histogram, "ms", "", Some(&[1.0,10.0])), declaration("crate-a", "app.x", Kind::Histogram, "ms", "", Some(&[5.0,50.0])), true, 0;
    p15_spelling, p15_spelling_reverse: counter("crate-a","app.x",""), counter("crate-a","App.X",""), true, 0;
    p15_description, p15_description_reverse: declaration("crate-a","app.x",Kind::Counter,"","d1",None), declaration("crate-a","app.x",Kind::Counter,"","d2",None), true, 0;
    p15_cross_boundaries, p15_cross_boundaries_reverse: declaration("crate-a", "app.x", Kind::Histogram, "ms", "", Some(&[1.0])), declaration("crate-b", "app.x", Kind::Histogram, "ms", "", Some(&[5.0])), true, 0;
    p15_cross_units, p15_cross_units_reverse: counter("crate-a","app.x","ms"), counter("crate-b","app.x","s"), true, 0;
    p15_kinds, p15_kinds_reverse: counter("crate-a","app.x",""), declaration("crate-a","app.x",Kind::Histogram,"","",None), true, 0;
    p15_cross_description, p15_cross_description_reverse: declaration("crate-a","app.x",Kind::Counter,"","d1",None), declaration("crate-b","app.x",Kind::Counter,"","d2",None), false, 1;
    p15_cross_spelling, p15_cross_spelling_reverse: counter("crate-a","app.x",""), counter("crate-b","App.X",""), false, 1;
    s1, s1_reverse: counter("crate-a","app.x",""), counter("crate-b","app.x",""), false, 1;
    s2, s2_reverse: counter("crate-a","app.x",""), counter("crate-a","app_x",""), true, 0;
    s3, s3_reverse: counter("crate-a","app.x","ms"), counter("crate-a","app.x.milliseconds",""), true, 0;
    s4, s4_reverse: declaration("crate-a","app.y",Kind::Histogram,"","",None), declaration("crate-a","app.y.count",Kind::Gauge,"","",None), true, 0;
    s5, s5_reverse: counter("crate-a","app.total.x",""), counter("crate-a","app.x",""), true, 0;
    s5_underscores, s5_underscores_reverse: counter("crate-a","app__y",""), counter("crate-a","app_y",""), true, 0;
    s5_ratio, s5_ratio_reverse: declaration("crate-a","app.r",Kind::Gauge,"1","",None), declaration("crate-a","app.r.ratio",Kind::Gauge,"","",None), true, 0;
    cross_compatible, cross_compatible_reverse: counter("crate-a","app.x",""), counter("crate-b","app_x",""), false, 0;
    cross_histogram_gauge, cross_histogram_gauge_reverse: declaration("crate-a","app.y",Kind::Histogram,"","",None), declaration("crate-b","app.y.count",Kind::Gauge,"","",None), true, 0;
    duplicate, duplicate_reverse: counter("crate-a","app.x",""), counter("crate-a","app.x",""), false, 0;
    value_type, value_type_reverse: counter("crate-a","app.x",""), declaration("crate-b","app.x",Kind::CounterF64,"","",None), true, 0;
}

#[test]
fn every_translation_row() {
    for (unit, suffix) in [
        ("d", "days"),
        ("h", "hours"),
        ("min", "minutes"),
        ("s", "seconds"),
        ("ms", "milliseconds"),
        ("us", "microseconds"),
        ("ns", "nanoseconds"),
        ("By", "bytes"),
        ("KiBy", "kibibytes"),
        ("MiBy", "mebibytes"),
        ("GiBy", "gibibytes"),
        ("TiBy", "tibibytes"),
        ("KBy", "kilobytes"),
        ("MBy", "megabytes"),
        ("GBy", "gigabytes"),
        ("TBy", "terabytes"),
        ("m", "meters"),
        ("V", "volts"),
        ("A", "amperes"),
        ("J", "joules"),
        ("W", "watts"),
        ("g", "grams"),
        ("Cel", "celsius"),
        ("Hz", "hertz"),
        ("%", "percent"),
    ] {
        assert_eq!(
            series_names("app.x", Kind::Counter, unit),
            [format!("app_x_{suffix}_total")]
        );
        assert_eq!(
            series_names(&format!("app.{suffix}.x"), Kind::Counter, unit),
            [format!("app_{suffix}_x_total")]
        );
    }
    for (unit, suffix) in [
        ("s", "second"),
        ("m", "minute"),
        ("h", "hour"),
        ("d", "day"),
        ("w", "week"),
        ("mo", "month"),
        ("y", "year"),
    ] {
        assert_eq!(
            series_names("app.x", Kind::Gauge, &format!("By/{unit}")),
            [format!("app_x_bytes_per_{suffix}")]
        );
    }
    for (name, kind, unit, expected) in [
        ("app.total.x", Kind::Counter, "", "app_x_total"),
        ("app__y", Kind::CounterF64, "", "app_y_total"),
        ("app.r", Kind::Gauge, "1", "app_r_ratio"),
        ("app.ratio.x", Kind::Gauge, "1", "app_x_ratio"),
        ("app.x", Kind::UpDownCounter, "1", "app_x"),
        ("app.x", Kind::Gauge, "{requests}/s", "app_x_per_second"),
        ("app.x", Kind::Gauge, "By/{requests}", "app_x_bytes"),
        ("app.x", Kind::Gauge, "custom-unit", "app_x_custom_unit"),
        ("1x", Kind::Gauge, "", "_1x"),
    ] {
        assert_eq!(series_names(name, kind, unit), [expected]);
    }
    assert_eq!(
        series_names("app.y", Kind::Histogram, "ms"),
        [
            "app_y_milliseconds_bucket",
            "app_y_milliseconds_sum",
            "app_y_milliseconds_count"
        ]
    );
}

#[test]
fn conflicting_and_already_poisoned_declarations_are_retained() {
    // Six permutations, including those that first poison app.x and later the alias.
    let ds = [
        counter("crate-a", "app.x", "ms"),
        counter("crate-a", "app.x", "s"),
        counter("crate-a", "app.x.seconds", ""),
    ];
    for order in [
        [0, 1, 2],
        [1, 0, 2],
        [0, 2, 1],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let registry = Registry::default();
        let losses = Losses::default();
        for i in order {
            registry.bind(ds[i].clone(), &losses, || ());
        }
        let state = registry.0.lock().unwrap();
        assert_eq!(
            state.names.keys().collect::<Vec<_>>(),
            [&"app.x", &"app.x.seconds"]
        );
        assert!(
            state
                .names
                .values()
                .all(|n| n.poisoned.load(Ordering::Acquire))
        );
        assert_eq!(state.names["app.x"].declarations.len(), 2);
    }
    let registry = Registry::default();
    let losses = Losses::default();
    for d in [
        counter("crate-a", "app.x", "By"),
        ds[0].clone(),
        ds[1].clone(),
        ds[2].clone(),
    ] {
        registry.bind(d, &losses, || ());
    }
    let state = registry.0.lock().unwrap();
    assert!(
        state
            .names
            .values()
            .all(|n| n.poisoned.load(Ordering::Acquire))
    );
    assert_eq!(state.names["app.x"].declarations.len(), 3);
}
#[test]
fn all_scope_declarations_are_compared() {
    let ds = [
        declaration("crate-a", "app.x", Kind::Counter, "", "d1", None),
        declaration("crate-b", "app.x", Kind::Counter, "", "d2", None),
        declaration("crate-b", "app.x", Kind::Counter, "", "d3", None),
    ];
    for order in [
        [0, 1, 2],
        [1, 0, 2],
        [0, 2, 1],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let registry = Registry::default();
        let losses = Losses::default();
        for i in order {
            registry.bind(ds[i].clone(), &losses, || ());
        }
        assert!(
            registry.0.lock().unwrap().names["app.x"]
                .poisoned
                .load(Ordering::Acquire)
        );
    }
}
#[test]
fn poisoning_without_records_is_reported_once() {
    let registry = Registry::default();
    let losses = Losses::default();
    registry.bind(counter("crate-a", "app.x", "ms"), &losses, || ());
    registry.bind(counter("crate-a", "app.x", "s"), &losses, || ());
    let error = losses.finish(Ok(())).unwrap_err();
    assert_eq!(error.kind(), FlushErrorKind::DataLost);
    assert_eq!(error.lost(Signal::Metrics), 0);
    assert_eq!(
        error.to_string(),
        "DataLost: metric names poisoned by conflicting declarations"
    );
    assert!(losses.finish(Ok(())).is_ok());
}
