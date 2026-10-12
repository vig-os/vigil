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
        boundaries: boundaries.map(canonical_boundaries),
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
    if a == b {
        assert_eq!(
            registry.0.lock().unwrap().names[&a.name.to_ascii_lowercase()]
                .declarations
                .len(),
            1
        );
    }
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
fn pair_test(name: &str, a: Declaration, b: Declaration, conflict: bool, info: usize) {
    if let Some(out) = crate::test_child(
        &format!("metric_identity::tests::{name}"),
        "VIGIL_IDENTITY_CHILD",
    ) {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let lines: Vec<_> = stderr
            .lines()
            .filter(|l| l.starts_with("vigil: conflicting metric instruments:"))
            .collect();
        assert_eq!(lines.len(), usize::from(conflict), "{stderr}");
        assert_eq!(
            stderr
                .matches("Prometheus needs otlp.promote_scope_metadata: true")
                .count(),
            info,
            "{stderr}"
        );
        if conflict {
            let mut declarations = vec![a, b];
            declarations.sort_by(Declaration::compare);
            assert_eq!(
                lines[0],
                format!(
                    "vigil: conflicting metric instruments: {declarations:?}; conflicting names dropped"
                )
            );
        }
        if info != 0 {
            assert!(stderr.contains("crate-a@1 and crate-b@1"), "{stderr}");
        }
        if !conflict && info == 0 {
            assert!(stderr.is_empty(), "{stderr}");
        }
    } else {
        pair(a, b, conflict);
    }
}
macro_rules! cases {
    ($($forward:ident, $reverse:ident: $a:expr, $b:expr, $conflict:literal, $info:literal;)+) => {$(
        #[test] fn $forward() { pair_test(stringify!($forward), $a, $b, $conflict, $info); }
        #[test] fn $reverse() { pair_test(stringify!($reverse), $b, $a, $conflict, $info); }
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
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("../tests/fixtures/prometheus_names.json")).unwrap();
    for row in rows.as_array().unwrap() {
        let kind = match row["kind"].as_str().unwrap() {
            "Counter" => Kind::Counter,
            "CounterF64" => Kind::CounterF64,
            "UpDownCounter" => Kind::UpDownCounter,
            "Gauge" => Kind::Gauge,
            "Histogram" => Kind::Histogram,
            kind => panic!("unknown fixture kind {kind}"),
        };
        let expected: Vec<_> = row["expected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| name.as_str().unwrap())
            .collect();
        assert_eq!(
            series_names(
                row["name"].as_str().unwrap(),
                kind,
                row["unit"].as_str().unwrap()
            ),
            expected,
            "{row}"
        );
    }
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

fn multi(name: &str, order: [usize; 3], abc: bool, diagnostics: usize, drops: u64) {
    let ds = if abc {
        [
            declaration("crate-a", "app.x", Kind::Counter, "", "d1", None),
            declaration("crate-b", "app.x", Kind::Counter, "", "d2", None),
            declaration("crate-b", "app.x", Kind::Counter, "", "d3", None),
        ]
    } else {
        [
            counter("crate-a", "app.x", "ms"),
            counter("crate-a", "app.x", "s"),
            counter("crate-a", "app.x.seconds", ""),
        ]
    };
    if let Some(out) = crate::test_child(
        &format!("metric_identity::tests::{name}"),
        "VIGIL_IDENTITY_CHILD",
    ) {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let lines: Vec<_> = stderr
            .lines()
            .filter(|l| l.starts_with("vigil: conflicting metric instruments:"))
            .collect();
        assert_eq!(lines.len(), diagnostics, "{stderr}");
        let groups = if abc {
            vec![vec![1, 2]]
        } else {
            match order {
                [0, 1, 2] | [1, 0, 2] => vec![vec![0, 1], vec![1, 2]],
                [0, 2, 1] | [2, 0, 1] => vec![vec![0, 1, 2]],
                _ => vec![vec![1, 2]],
            }
        };
        for (line, group) in lines.iter().zip(groups) {
            let mut expected: Vec<_> = group.into_iter().map(|i| ds[i].clone()).collect();
            expected.sort_by(Declaration::compare);
            assert_eq!(
                *line,
                format!(
                    "vigil: conflicting metric instruments: {expected:?}; conflicting names dropped"
                )
            );
        }
        return;
    }
    let registry = Registry::default();
    let losses = Losses::default();
    let mut flags = Vec::new();
    for i in order {
        let (flag, _) = registry.bind(ds[i].clone(), &losses, || ());
        if flag.load(Ordering::Acquire) {
            losses.measurements_dropped(1);
        }
        flags.push(flag);
    }
    for flag in flags {
        assert!(flag.load(Ordering::Acquire));
        losses.measurements_dropped(1);
    }
    let state = registry.0.lock().unwrap();
    assert!(
        state
            .names
            .values()
            .all(|n| n.poisoned.load(Ordering::Acquire))
    );
    assert_eq!(state.names.len(), if abc { 1 } else { 2 });
    drop(state);
    let error = losses.finish(Ok(())).unwrap_err();
    assert_eq!(error.kind(), FlushErrorKind::DataLost);
    assert_eq!(error.lost(Signal::Metrics), drops);
    assert!(
        error
            .to_string()
            .contains("metric names poisoned by conflicting declarations")
    );
    assert!(losses.finish(Ok(())).is_ok());
}
macro_rules! multi_cases {
    ($($name:ident: $order:expr,$abc:literal,$diag:literal,$drops:literal;)+) => {$(
        #[test] fn $name() { multi(stringify!($name),$order,$abc,$diag,$drops); }
    )+};
}
multi_cases! {
    d123: [0,1,2],false,2,5;
    d213: [1,0,2],false,2,5;
    d132: [0,2,1],false,1,4;
    d231: [1,2,0],false,1,5;
    d312: [2,0,1],false,1,4;
    d321: [2,1,0],false,1,5;
    abc: [0,1,2],true,1,4;
    bac: [1,0,2],true,1,4;
    acb: [0,2,1],true,1,4;
    bca: [1,2,0],true,1,5;
    cab: [2,0,1],true,1,4;
    cba: [2,1,0],true,1,5;
}
#[test]
fn d0123_already_poisoned_is_indexed() {
    if !child("d0123_already_poisoned_is_indexed", 2, 0) {
        return;
    }
    let registry = Registry::default();
    let losses = Losses::default();
    for d in [
        counter("crate-a", "app.x", "By"),
        counter("crate-a", "app.x", "ms"),
        counter("crate-a", "app.x", "s"),
        counter("crate-a", "app.x.seconds", ""),
    ] {
        let (flag, _) = registry.bind(d, &losses, || ());
        if flag.load(Ordering::Acquire) {
            losses.measurements_dropped(1);
        }
    }
    let state = registry.0.lock().unwrap();
    assert!(
        state.names["app.x.seconds"]
            .poisoned
            .load(Ordering::Acquire)
    );
    assert_eq!(state.names["app.x"].declarations.len(), 3);
    drop(state);
    let error = losses.finish(Ok(())).unwrap_err();
    assert_eq!(error.kind(), FlushErrorKind::DataLost);
    assert_eq!(error.lost(Signal::Metrics), 3);
    assert!(
        error
            .to_string()
            .contains("metric names poisoned by conflicting declarations")
    );
    assert!(losses.finish(Ok(())).is_ok());
}

#[test]
fn description_conflict_clause_is_redundant_for_every_kind() {
    for kind in [
        Kind::Counter,
        Kind::CounterF64,
        Kind::UpDownCounter,
        Kind::Gauge,
        Kind::Histogram,
    ] {
        for a_unit in ["ms", "s"] {
            for b_unit in ["ms", "s"] {
                for a_bounds in [
                    None,
                    Some(&[][..]),
                    Some(&[1.0, 2.0][..]),
                    Some(&[1.0, 3.0][..]),
                ] {
                    for b_bounds in [
                        None,
                        Some(&[][..]),
                        Some(&[1.0, 2.0][..]),
                        Some(&[1.0, 3.0][..]),
                    ] {
                        let a =
                            declaration("crate-a", "same.name", kind, a_unit, "first", a_bounds);
                        let b =
                            declaration("crate-a", "same.name", kind, b_unit, "second", b_bounds);
                        let a_series = series_names(a.name, a.kind, a.unit);
                        let b_series = series_names(b.name, b.kind, b.unit);
                        let overlap = a_series.iter().any(|name| b_series.contains(name));
                        assert!(a.conflicts(&b, overlap), "{a:?} {b:?}");
                        // Only compatible pairs can reach the description clause:
                        // equal name/kind/unit always translates to overlapping series.
                        assert!(overlap || !a.compatible(&b), "{a:?} {b:?}");
                        assert_eq!(a.conflicts(&b, overlap), overlap || !a.compatible(&b));
                        assert_eq!(b.conflicts(&a, overlap), overlap || !b.compatible(&a));
                    }
                }
            }
        }
    }
}

#[test]
fn canonical_boundary_equality_and_order_agree() {
    let a = declaration(
        "crate-a",
        "zero.h",
        Kind::Histogram,
        "",
        "",
        Some(&[-0.0, 1.0]),
    );
    let b = declaration(
        "crate-a",
        "zero.h",
        Kind::Histogram,
        "",
        "",
        Some(&[0.0, 1.0]),
    );
    assert_eq!(a, b);
    assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
    assert_eq!(a.partial_cmp(&b), Some(std::cmp::Ordering::Equal));
    assert_eq!(a.boundaries.unwrap()[0].to_bits(), 0.0_f64.to_bits());
}
