//! **Unstable:** OTLP/JSON metric data path. Enable `--cfg vigil_unstable`
//! and pin vigil with `~1.N`. Reader and file lifecycle wiring follows in #7.
use crate::{
    envelope::{self, BoundedLine, Envelope},
    lifecycle::Losses,
    sink::LineSink,
};
use opentelemetry_proto::tonic::{
    collector::metrics::v1::ExportMetricsServiceRequest,
    metrics::v1::{metric::Data, number_data_point},
};
use opentelemetry_sdk::{
    error::{OTelSdkError, OTelSdkResult},
    metrics::{Temporality, data::ResourceMetrics, exporter::PushMetricExporter},
};
use serde_json::Value as Json;
use std::{
    sync::{Arc, Mutex, atomic::Ordering},
    time::Duration,
};

/// **Unstable:** writes cumulative metrics as bounded OTLP/JSON lines.
/// Oversized data points are dropped; attributes are never shortened because
/// they identify series. Non-finite doubles retain their proto3 JSON spelling.
/// Use `--cfg vigil_unstable` and pin vigil with `~1.N`.
#[derive(Debug)]
#[cfg_attr(docsrs, doc(cfg(vigil_unstable)))]
pub struct OtlpJsonMetricExporter<S: LineSink> {
    sink: S,
    limit: usize,
    pub(crate) losses: Arc<Losses>,
    failures: Mutex<crate::init::Failures>,
}
impl<S: LineSink> OtlpJsonMetricExporter<S> {
    /// Write to `sink`, with a 1,000,000-byte payload limit.
    pub fn new(sink: S) -> Self {
        Self {
            sink,
            limit: 1_000_000,
            losses: Arc::new(Losses::default()),
            failures: Mutex::default(),
        }
    }
    pub(crate) fn with_losses(mut self, losses: Arc<Losses>) -> Self {
        self.losses = losses;
        self
    }
    /// Set the payload limit, clamped to 1..=1,048,575 bytes, excluding newline.
    #[cfg(any(test, vigil_unstable))]
    pub fn with_max_line_bytes(mut self, limit: usize) -> Self {
        self.limit = limit.clamp(1, 1_048_575);
        self
    }
    /// The sink receiving complete lines.
    pub fn sink(&self) -> &S {
        &self.sink
    }
    fn write(&self, metrics: &ResourceMetrics) -> (OTelSdkResult, usize) {
        let request = ExportMetricsServiceRequest::from(metrics);
        let mut lost = request
            .resource_metrics
            .iter()
            .flat_map(|r| &r.scope_metrics)
            .flat_map(|s| &s.metrics)
            .map(|m| match &m.data {
                Some(Data::Gauge(d)) => d.data_points.len(),
                Some(Data::Sum(d)) => d.data_points.len(),
                Some(Data::Histogram(d)) => d.data_points.len(),
                Some(Data::ExponentialHistogram(d)) => d.data_points.len(),
                Some(Data::Summary(d)) => d.data_points.len(),
                None => 0,
            })
            .sum::<usize>();
        let result = (|| {
            let json = project(request).map_err(OTelSdkError::InternalFailure)?;
            let lines = envelope::bounded_lines(&json, self.limit, Envelope::Metrics)
                .map_err(OTelSdkError::InternalFailure)?;
            for line in lines {
                self.sink.write_line(line.text().as_bytes()).map_err(|e| {
                    OTelSdkError::InternalFailure(format!("writing metric batch: {e}"))
                })?;
                lost -= line.records();
            }
            Ok(())
        })();
        (result, lost)
    }
}
impl<S: LineSink + 'static> PushMetricExporter for OtlpJsonMetricExporter<S> {
    async fn export(&self, metrics: &ResourceMetrics) -> OTelSdkResult {
        #[cfg(test)]
        if let Some(sender) = self
            .losses
            .metric_export_started
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            let _ = sender.send(());
        }
        let (result, lost) = self.write(metrics);
        if lost != 0 || result.is_err() {
            self.losses.metric_data_points(result.is_err());
        }
        let reported = self
            .failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record(
                "metric",
                "data points",
                lost,
                &result,
                self.losses.shutting_down.load(Ordering::Acquire),
            );
        self.losses.metric_pending(lost as u64, reported);
        result
    }
    fn force_flush(&self) -> OTelSdkResult {
        self.sink
            .flush()
            .map_err(|e| OTelSdkError::InternalFailure(format!("flushing metric sink: {e}")))
    }
    fn shutdown_with_timeout(&self, _: Duration) -> OTelSdkResult {
        self.force_flush()
    }
    fn temporality(&self) -> Temporality {
        Temporality::Cumulative
    }
}

const DATA: [&str; 5] = [
    "gauge",
    "sum",
    "histogram",
    "exponentialHistogram",
    "summary",
];
fn data(item: &Json) -> Option<&'static str> {
    DATA.into_iter().find(|field| item.get(*field).is_some())
}
pub(crate) fn point_count(item: &Json) -> usize {
    data(item)
        .and_then(|field| item[field]["dataPoints"].as_array())
        .map_or(0, Vec::len)
}
pub(crate) fn fit_metric(
    item: &Json,
    overhead: usize,
    limit: usize,
) -> Result<Vec<BoundedLine>, String> {
    let text = crate::ordered_json::encode(item, "metrics", crate::ordered_json::METRICS)?;
    let count = point_count(item);
    let line = |text, records| BoundedLine {
        text,
        records,
        stubs: 0,
    };
    if text.len() + overhead <= limit {
        return Ok(vec![line(text, count)]);
    }
    let Some(field) = data(item) else {
        return Ok(vec![]);
    };
    // Only metadata is cloned; no batch/metric data-point array is copied.
    let metadata = item
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(key, _)| key.as_str() != field)
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let metadata = crate::ordered_json::encode(
        &Json::Object(metadata),
        "metrics",
        crate::ordered_json::METRICS,
    )?;
    let (prefix, suffix) =
        envelope::array_frame(&item[field], "dataPoints", crate::ordered_json::METRICS)?;
    let prefix = format!("{{\"{field}\":{prefix}");
    let separator = if metadata == "{}" { "" } else { "," };
    let suffix = format!("{suffix}{separator}{}", &metadata[1..]);
    let mut text = prefix.clone();
    let mut count = 0;
    let mut lines = Vec::new();
    for point in item[field]["dataPoints"].as_array().into_iter().flatten() {
        let point = crate::ordered_json::encode(point, "dataPoints", crate::ordered_json::METRICS)?;
        if overhead + prefix.len() + point.len() + suffix.len() > limit {
            continue;
        }
        if count != 0 && overhead + text.len() + 1 + point.len() + suffix.len() > limit {
            text.push_str(&suffix);
            lines.push(line(text, count));
            text = prefix.clone();
            count = 0;
        }
        if count != 0 {
            text.push(',');
        }
        text.push_str(&point);
        count += 1;
    }
    if count != 0 {
        text.push_str(&suffix);
        lines.push(line(text, count));
    }
    Ok(lines)
}
fn patch_double(value: f64, json: &mut Json) {
    if !value.is_finite() {
        *json = Json::String(
            if value.is_nan() {
                "NaN"
            } else if value > 0.0 {
                "Infinity"
            } else {
                "-Infinity"
            }
            .into(),
        );
    }
}
fn project(mut request: ExportMetricsServiceRequest) -> Result<Json, String> {
    // Attribute ordering precedes patching so typed and JSON trees stay aligned.
    for resource in &mut request.resource_metrics {
        if let Some(r) = &mut resource.resource {
            envelope::sort_attributes(&mut r.attributes);
        }
        for scope in &mut resource.scope_metrics {
            if let Some(s) = &mut scope.scope {
                envelope::sort_attributes(&mut s.attributes);
            }
            for metric in &mut scope.metrics {
                macro_rules! sort {
                    ($d:expr) => {
                        for p in &mut $d.data_points {
                            envelope::sort_attributes(&mut p.attributes);
                        }
                    };
                }
                match &mut metric.data {
                    Some(Data::Gauge(d)) => sort!(d),
                    Some(Data::Sum(d)) => sort!(d),
                    Some(Data::Histogram(d)) => sort!(d),
                    Some(Data::ExponentialHistogram(d)) => sort!(d),
                    Some(Data::Summary(d)) => sort!(d),
                    None => {}
                }
            }
        }
    }
    let mut json = serde_json::to_value(&request).map_err(|e| e.to_string())?;
    for (resource, jr) in request
        .resource_metrics
        .iter()
        .zip(json["resourceMetrics"].as_array_mut().into_iter().flatten())
    {
        if let Some(r) = &resource.resource {
            envelope::patch_key_values(&r.attributes, &mut jr["resource"]["attributes"]);
        }
        for (scope, js) in resource
            .scope_metrics
            .iter()
            .zip(jr["scopeMetrics"].as_array_mut().into_iter().flatten())
        {
            if let Some(s) = &scope.scope {
                envelope::patch_key_values(&s.attributes, &mut js["scope"]["attributes"]);
            }
            for (metric, jm) in scope
                .metrics
                .iter()
                .zip(js["metrics"].as_array_mut().into_iter().flatten())
            {
                macro_rules! points {
                    ($d:expr, $field:literal, $patch:expr) => {
                        for (p, jp) in $d.data_points.iter().zip(
                            jm[$field]["dataPoints"]
                                .as_array_mut()
                                .into_iter()
                                .flatten(),
                        ) {
                            envelope::patch_key_values(&p.attributes, &mut jp["attributes"]);
                            ($patch)(p, jp);
                        }
                    };
                }
                macro_rules! numbers {
                    ($d:expr, $field:literal) => {
                        points!(
                            $d,
                            $field,
                            |p: &opentelemetry_proto::tonic::metrics::v1::NumberDataPoint,
                             jp: &mut Json| {
                                if let Some(number_data_point::Value::AsDouble(d)) = p.value {
                                    patch_double(d, &mut jp["asDouble"]);
                                }
                            }
                        )
                    };
                }
                macro_rules! histogram {
                    ($d:expr, $field:literal, $ty:ty) => {
                        points!($d, $field, |p: &$ty, jp: &mut Json| {
                            for (key, value) in [("sum", p.sum), ("min", p.min), ("max", p.max)] {
                                if let Some(d) = value {
                                    patch_double(d, &mut jp[key]);
                                }
                            }
                        })
                    };
                }
                match &metric.data {
                    Some(Data::Gauge(d)) => numbers!(d, "gauge"),
                    Some(Data::Sum(d)) => numbers!(d, "sum"),
                    Some(Data::Histogram(d)) => histogram!(
                        d,
                        "histogram",
                        opentelemetry_proto::tonic::metrics::v1::HistogramDataPoint
                    ),
                    Some(Data::ExponentialHistogram(d)) => histogram!(
                        d,
                        "exponentialHistogram",
                        opentelemetry_proto::tonic::metrics::v1::ExponentialHistogramDataPoint
                    ),
                    Some(Data::Summary(d)) => points!(
                        d,
                        "summary",
                        |p: &opentelemetry_proto::tonic::metrics::v1::SummaryDataPoint,
                         jp: &mut Json| {
                            patch_double(p.sum, &mut jp["sum"]);
                        }
                    ),
                    None => {}
                }
            }
        }
    }
    envelope::normalize(&mut json, "", crate::ordered_json::METRICS)?;
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FlushErrorKind, Signal, sink::MemorySink};
    use opentelemetry::{KeyValue, metrics::MeterProvider};
    use opentelemetry_sdk::{
        Resource,
        metrics::{PeriodicReader, SdkMeterProvider},
    };
    use std::task::{Context, Poll, Waker};

    #[test]
    fn metric_scope_permutations_have_identical_bytes() {
        use opentelemetry_proto::tonic::metrics::v1::{
            Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics, Sum,
        };
        for family in crate::order_tests::families() {
            let scopes: Vec<_> = family
                .into_iter()
                .enumerate()
                .map(|(i, scope)| ScopeMetrics {
                    scope: Some(scope),
                    metrics: vec![Metric {
                        name: format!("counter-{i}"),
                        data: Some(Data::Sum(Sum {
                            data_points: vec![NumberDataPoint {
                                time_unix_nano: 900 - i as u64 * 100,
                                start_time_unix_nano: 100,
                                value: Some(number_data_point::Value::AsInt(i as i64)),
                                ..Default::default()
                            }],
                            ..Default::default()
                        })),
                        ..Default::default()
                    }],
                    ..Default::default()
                })
                .collect();
            let mut expected = None;
            crate::order_tests::permutations(&scopes, |scope_metrics| {
                let request = ExportMetricsServiceRequest {
                    resource_metrics: vec![ResourceMetrics {
                        scope_metrics,
                        ..Default::default()
                    }],
                };
                let projected = project(request).unwrap();
                let nan: Vec<_> = projected["resourceMetrics"][0]["scopeMetrics"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|s| s["scope"]["attributes"][0]["value"]["doubleValue"] == "NaN")
                    .map(|s| s["metrics"][0]["name"].as_str().unwrap())
                    .collect();
                assert_eq!(nan, ["counter-0", "counter-1"]);
                let bytes =
                    crate::ordered_json::encode(&projected, "", crate::ordered_json::METRICS)
                        .unwrap();
                assert_eq!(*expected.get_or_insert_with(|| bytes.clone()), bytes);
            });
        }
    }

    #[test]
    fn sdk_nan_scope_order_is_independent_of_collection_timestamps() {
        let mut orders = std::collections::BTreeSet::new();
        // Fresh providers exercise independently seeded SDK HashMaps, while
        // repeated collections retain their real, per-scope SDK timestamps.
        for _ in 0..24 {
            let sink = MemorySink::new();
            let provider = SdkMeterProvider::builder()
                .with_reader(
                    PeriodicReader::builder(OtlpJsonMetricExporter::new(sink.clone()))
                        .with_interval(Duration::from_secs(3600))
                        .build(),
                )
                .build();
            let scope = opentelemetry::InstrumentationScope::builder("nan-scope")
                .with_attributes([KeyValue::new("nan", f64::NAN)])
                .build();
            let counters: Vec<_> = (0..4)
                .map(|i| {
                    provider
                        .meter_with_scope(scope.clone())
                        .u64_counter(format!("counter-{i}"))
                        .build()
                })
                .collect();
            for counter in &counters {
                counter.add(1, &[]);
            }
            for _ in 0..2 {
                provider.force_flush().unwrap();
                let lines = sink.lines();
                let json: Json = serde_json::from_str(lines.last().unwrap()).unwrap();
                let order: Vec<_> = json["resourceMetrics"][0]["scopeMetrics"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .flat_map(|scope| scope["metrics"].as_array().unwrap())
                    .map(|metric| metric["name"].as_str().unwrap().to_owned())
                    .collect();
                assert_eq!(order.len(), 4);
                orders.insert(order);
            }
            provider.shutdown().unwrap();
        }
        assert_eq!(
            orders.len(),
            1,
            "SDK collection timestamps leaked into scope order: {orders:?}"
        );
        assert_eq!(
            orders.first().unwrap(),
            &["counter-0", "counter-1", "counter-2", "counter-3"]
        );
    }

    fn ready<T>(future: impl std::future::Future<Output = T>) -> T {
        let mut future = std::pin::pin!(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("synchronous exporter"),
        }
    }
    #[derive(Debug)]
    struct Fixture(Arc<Mutex<Option<ExportMetricsServiceRequest>>>);
    impl PushMetricExporter for Fixture {
        async fn export(&self, rm: &ResourceMetrics) -> OTelSdkResult {
            *self.0.lock().unwrap() = Some(ExportMetricsServiceRequest::from(rm));
            Ok(())
        }
        fn temporality(&self) -> Temporality {
            Temporality::Cumulative
        }
        fn force_flush(&self) -> OTelSdkResult {
            Ok(())
        }
        fn shutdown_with_timeout(&self, _: Duration) -> OTelSdkResult {
            Ok(())
        }
    }
    fn fixture(reverse: bool) -> ExportMetricsServiceRequest {
        let captured = Arc::new(Mutex::new(None));
        let provider = SdkMeterProvider::builder()
            .with_resource(
                Resource::builder_empty()
                    .with_attribute(KeyValue::new("service.name", "fixture"))
                    .build(),
            )
            .with_reader(
                PeriodicReader::builder(Fixture(captured.clone()))
                    .with_interval(Duration::from_secs(3600))
                    .build(),
            )
            .build();
        let meter = provider.meter_with_scope(
            opentelemetry::InstrumentationScope::builder("fixture")
                .with_attributes([KeyValue::new("scope.nonfinite", f64::NEG_INFINITY)])
                .build(),
        );
        let gauge = meter.f64_gauge("gauge").build();
        let counter = meter.u64_counter("counter").build();
        let histogram = meter
            .f64_histogram("histogram")
            .with_description("d".repeat(700))
            .build();
        let mut indexes: Vec<_> = (0..10).collect();
        if reverse {
            indexes.reverse();
        }
        std::thread::scope(|scope| {
            for index in indexes {
                let (gauge, counter, histogram) = (&gauge, &counter, &histogram);
                scope.spawn(move || {
                    let attrs = [
                        KeyValue::new("series", index),
                        KeyValue::new("nonfinite", f64::NAN),
                    ];
                    gauge.record(f64::NAN, &attrs);
                    counter.add(1, &attrs);
                    histogram.record(f64::INFINITY, &attrs);
                });
            }
        });
        provider.force_flush().unwrap();
        provider.shutdown().unwrap();
        let mut request = captured.lock().unwrap().take().unwrap();
        // Two independent SDK collections necessarily have different clocks.
        // Fix only their timestamps, retaining SDK aggregation and attributes.
        for r in &mut request.resource_metrics {
            for s in &mut r.scope_metrics {
                for m in &mut s.metrics {
                    macro_rules! clock {
                        ($d:expr) => {
                            for p in &mut $d.data_points {
                                p.time_unix_nano = 1700000000000000001;
                                p.start_time_unix_nano = 1700000000000000000;
                            }
                        };
                    }
                    match &mut m.data {
                        Some(Data::Gauge(d)) => clock!(d),
                        Some(Data::Sum(d)) => clock!(d),
                        Some(Data::Histogram(d)) => clock!(d),
                        _ => {}
                    }
                }
            }
        }
        request
    }
    #[test]
    fn sdk_metrics_are_cumulative_sanitized_ordered_and_bounded() {
        let a = project(fixture(false)).unwrap();
        let b = project(fixture(true)).unwrap();
        let lines = envelope::bounded_lines(&a, 2400, Envelope::Metrics).unwrap();
        assert_eq!(
            lines.iter().map(|l| &l.text).collect::<Vec<_>>(),
            envelope::bounded_lines(&b, 2400, Envelope::Metrics)
                .unwrap()
                .iter()
                .map(|l| &l.text)
                .collect::<Vec<_>>()
        );
        assert_eq!(lines.iter().map(|l| l.records).sum::<usize>(), 30);
        assert!(lines.len() > 1);
        for line in &lines {
            assert!(line.text.len() <= 2400);
            let json: Json = serde_json::from_str(&line.text).unwrap();
            for r in json["resourceMetrics"].as_array().unwrap() {
                for s in r["scopeMetrics"].as_array().unwrap() {
                    for metric in s["metrics"].as_array().unwrap() {
                        let field = data(metric).unwrap();
                        if field != "gauge" {
                            assert_eq!(metric[field]["aggregationTemporality"], 2);
                        }
                        for p in metric[field]["dataPoints"].as_array().unwrap() {
                            assert!(p["attributes"].to_string().contains("NaN"));
                            if field == "gauge" {
                                assert_eq!(p["asDouble"], "NaN");
                            }
                            if field == "histogram" {
                                assert_eq!(p["sum"], "Infinity");
                            }
                        }
                    }
                }
            }
        }
        let first = &lines[0].text;
        assert!(first.starts_with("{\"resourceMetrics\":[{\"scopeMetrics\":[{\"metrics\":[{\"sum\":{\"dataPoints\":[{\"timeUnixNano\":"));
        let dropped = envelope::bounded_lines(&a, 1, Envelope::Metrics).unwrap();
        assert!(dropped.is_empty());
    }
    #[test]
    fn exporter_reports_drops_without_measurement_counts() {
        let exporter = OtlpJsonMetricExporter::new(MemorySink::new()).with_max_line_bytes(1);
        assert_eq!(exporter.temporality(), Temporality::Cumulative);
        let captured = Arc::new(Mutex::new(None));
        // Exercise ResourceMetrics through an actual SDK reader, not fixtures
        // assembled from private SDK fields or the testing feature.
        #[derive(Debug)]
        struct Check(
            OtlpJsonMetricExporter<MemorySink>,
            Arc<Mutex<Option<FlushErrorKind>>>,
        );
        impl PushMetricExporter for Check {
            async fn export(&self, rm: &ResourceMetrics) -> OTelSdkResult {
                ready(self.0.export(rm)).unwrap();
                let error = self.0.losses.finish(Ok(())).unwrap_err();
                assert_eq!(error.lost(Signal::Metrics), 0);
                *self.1.lock().unwrap() = Some(error.kind());
                Ok(())
            }
            fn temporality(&self) -> Temporality {
                self.0.temporality()
            }
            fn force_flush(&self) -> OTelSdkResult {
                Ok(())
            }
            fn shutdown_with_timeout(&self, _: Duration) -> OTelSdkResult {
                Ok(())
            }
        }
        let provider = SdkMeterProvider::builder()
            .with_reader(
                PeriodicReader::builder(Check(exporter, captured.clone()))
                    .with_interval(Duration::from_secs(3600))
                    .build(),
            )
            .build();
        provider
            .meter("loss")
            .u64_counter("count")
            .build()
            .add(1, &[]);
        provider.force_flush().unwrap();
        assert_eq!(*captured.lock().unwrap(), Some(FlushErrorKind::DataLost));
        provider.shutdown().unwrap();
    }
    #[test]
    fn canonical_ties_include_number_type_and_nonfinite_attributes() {
        let mut request = fixture(false);
        let scope = &mut request.resource_metrics[0].scope_metrics[0];
        let mut gauge = scope
            .metrics
            .iter()
            .find(|m| m.name == "gauge")
            .unwrap()
            .clone();
        gauge.name = "same".into();
        let Some(Data::Gauge(ref mut d)) = gauge.data else {
            panic!("gauge")
        };
        d.data_points.truncate(1);
        let mut signed = gauge.clone();
        if let Some(Data::Gauge(d)) = &mut signed.data {
            d.data_points[0].value = Some(number_data_point::Value::AsInt(-42));
        }
        let mut positive = gauge.clone();
        if let Some(Data::Gauge(d)) = &mut positive.data {
            d.data_points[0].value = Some(number_data_point::Value::AsInt(42));
        }
        scope.metrics = vec![signed, positive, gauge];
        let a = project(request.clone()).unwrap();
        request.resource_metrics[0].scope_metrics[0]
            .metrics
            .reverse();
        let b = project(request).unwrap();
        let encode = |j| {
            envelope::bounded_lines(&j, 1000, Envelope::Metrics)
                .unwrap()
                .into_iter()
                .map(|l| l.text)
                .collect::<Vec<_>>()
        };
        assert_eq!(encode(a), encode(b));
    }

    #[test]
    fn bounding_preserves_series_identity_and_all_metadata() {
        let mut json = project(fixture(false)).unwrap();
        let metric = &mut json["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0];
        let field = data(metric).unwrap();
        let mut oversized = metric[field]["dataPoints"][0].clone();
        oversized["attributes"][0]["value"] = serde_json::json!({"stringValue": "x".repeat(10000)});
        metric[field]["dataPoints"]
            .as_array_mut()
            .unwrap()
            .push(oversized);
        let lines = envelope::bounded_lines(&json, 1800, Envelope::Metrics).unwrap();
        assert_eq!(lines.iter().map(|l| l.records).sum::<usize>(), 30);
        let mut found_histograms = 0;
        for line in lines {
            assert!(line.text.len() <= 1800);
            assert!(!line.text.contains("vigil.truncated"));
            let j: Json = serde_json::from_str(&line.text).unwrap();
            for m in j["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
                .as_array()
                .unwrap()
            {
                if m["name"] == "histogram" {
                    found_histograms += 1;
                    assert_eq!(m["description"], "d".repeat(700));
                    assert_eq!(m["histogram"]["aggregationTemporality"], 2);
                }
                if m["name"] == "counter" {
                    assert_eq!(m["sum"]["isMonotonic"], true);
                }
            }
        }
        assert!(found_histograms > 1);
    }

    #[test]
    fn every_metric_row_has_time_first_fingerprint() {
        for field in DATA {
            let metric = serde_json::json!({
                "name": "n", "description": "d", "unit": "ms",
                field: {"aggregationTemporality": 2, "dataPoints": [{
                    "attributes": [], "startTimeUnixNano": "1", "timeUnixNano": "2"
                }]}
            });
            let json = serde_json::json!({"resourceMetrics": [{"resource": {}, "scopeMetrics": [{
                "scope": {"name": "s"}, "metrics": [metric]
            }]}]});
            let line = &envelope::bounded_lines(&json, 1000, Envelope::Metrics).unwrap()[0].text;
            assert!(line.starts_with(&format!(
                "{{\"resourceMetrics\":[{{\"scopeMetrics\":[{{\"metrics\":[{{\"{field}\":{{\"dataPoints\":[{{\"timeUnixNano\":\"2\""
            )));
        }
    }

    #[test]
    fn packing_points_and_metrics_includes_the_exact_limit() {
        let point = serde_json::json!({"timeUnixNano": "2", "asInt": "1"});
        let metric = |points| serde_json::json!({"name": "n", "gauge": {"dataPoints": points}});
        let one = metric(vec![point.clone()]);
        let two = metric(vec![point.clone(), point.clone()]);
        let three = metric(vec![point.clone(), point.clone(), point]);
        let wrap = |metrics| {
            serde_json::json!({"resourceMetrics": [{
                "scopeMetrics": [{"metrics": metrics}]
            }]})
        };
        let length = |json: &Json| {
            crate::ordered_json::encode(json, "", crate::ordered_json::METRICS)
                .unwrap()
                .len()
        };
        // Three points force the slow path; exactly two must share a fragment.
        let limit = length(&two);
        let packed = fit_metric(&three, 0, limit).unwrap();
        assert_eq!(
            packed.iter().map(BoundedLine::records).collect::<Vec<_>>(),
            [2, 1]
        );
        for line in &packed {
            serde_json::from_str::<Json>(line.text()).unwrap();
        }
        assert_eq!(packed[0].text().len(), limit);
        let smaller = fit_metric(&three, 0, limit - 1).unwrap();
        assert_eq!(
            smaller.iter().map(BoundedLine::records).collect::<Vec<_>>(),
            [1, 1, 1]
        );
        // Three metrics force envelope packing, independently of point splitting.
        let limit = length(&wrap(vec![one.clone(), one.clone()]));
        for (cap, expected) in [(limit, vec![2, 1]), (limit - 1, vec![1, 1, 1])] {
            let lines =
                envelope::bounded_lines(&wrap(vec![one.clone(); 3]), cap, Envelope::Metrics)
                    .unwrap();
            assert_eq!(
                lines.iter().map(BoundedLine::records).collect::<Vec<_>>(),
                expected
            );
            for line in &lines {
                serde_json::from_str::<Json>(line.text()).unwrap();
                assert!(line.text().len() <= cap);
            }
        }
    }

    #[test]
    fn split_without_metric_metadata_is_valid_at_exact_point_limit() {
        let point = serde_json::json!({"timeUnixNano": "2", "asInt": "1"});
        let single = serde_json::json!({"gauge": {"dataPoints": [point.clone()]}});
        let pair = serde_json::json!({"gauge": {"dataPoints": [point.clone(), point]}});
        let wrap = |metric| {
            serde_json::json!({"resourceMetrics": [{
                "scopeMetrics": [{"metrics": [metric]}]
            }]})
        };
        let single = wrap(single);
        let limit = envelope::bounded_lines(&single, 1000, Envelope::Metrics).unwrap()[0]
            .text
            .len();
        let lines = envelope::bounded_lines(&wrap(pair), limit, Envelope::Metrics).unwrap();
        assert_eq!(lines.len(), 2);
        for line in lines {
            let parsed: Json = serde_json::from_str(line.text()).unwrap();
            assert_eq!(line.text().len(), limit);
            assert_eq!(
                point_count(&parsed["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]),
                1
            );
        }
        assert!(
            envelope::bounded_lines(&single, limit - 1, Envelope::Metrics)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn empty_metric_and_envelope_fit_exactly_but_not_one_byte_less() {
        // Zero-point metrics still carry metadata; fitting must retain it.
        let metric = serde_json::json!({"name": "empty", "gauge": {"dataPoints": []}});
        let limit = crate::ordered_json::encode(&metric, "metrics", crate::ordered_json::METRICS)
            .unwrap()
            .len()
            + 17;
        let lines = fit_metric(&metric, 17, limit).unwrap();
        assert_eq!(lines.len(), 1);
        serde_json::from_str::<Json>(lines[0].text()).unwrap();
        assert!(fit_metric(&metric, 17, limit - 1).unwrap().is_empty());
        // An empty request remains an OTLP payload when it fits.
        let request = serde_json::json!({"resourceMetrics": []});
        let limit = crate::ordered_json::encode(&request, "", crate::ordered_json::METRICS)
            .unwrap()
            .len();
        let lines = envelope::bounded_lines(&request, limit, Envelope::Metrics).unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(
            serde_json::from_str::<Json>(lines[0].text()).unwrap(),
            request
        );
        assert!(
            envelope::bounded_lines(&request, limit - 1, Envelope::Metrics)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn sdk_scope_attributes_are_sanitized() {
        let json = project(fixture(false)).unwrap();
        assert_eq!(
            json["resourceMetrics"][0]["scopeMetrics"][0]["scope"]["attributes"][0]["value"]["doubleValue"],
            "-Infinity"
        );
        for line in envelope::bounded_lines(&json, 2400, Envelope::Metrics).unwrap() {
            let parsed: Json = serde_json::from_str(line.text()).unwrap();
            assert_eq!(
                parsed["resourceMetrics"][0]["scopeMetrics"][0]["scope"]["attributes"][0]["value"]
                    ["doubleValue"],
                "-Infinity"
            );
        }
    }

    #[test]
    fn failed_line_marks_failed_without_counting_written_points() {
        #[derive(Debug)]
        struct FailSecond(Mutex<Vec<String>>);
        impl LineSink for FailSecond {
            fn write_line(&self, bytes: &[u8]) -> std::io::Result<()> {
                let mut lines = self.0.lock().unwrap();
                if lines.len() == 1 {
                    return Err(std::io::Error::other("deliberate failure"));
                }
                lines.push(String::from_utf8(bytes.to_vec()).unwrap());
                Ok(())
            }
        }
        #[derive(Debug)]
        struct Check(Arc<OtlpJsonMetricExporter<FailSecond>>);
        impl PushMetricExporter for Check {
            async fn export(&self, rm: &ResourceMetrics) -> OTelSdkResult {
                let total = ExportMetricsServiceRequest::from(rm)
                    .resource_metrics
                    .iter()
                    .flat_map(|r| &r.scope_metrics)
                    .flat_map(|s| &s.metrics)
                    .map(|m| {
                        if let Some(Data::Sum(d)) = &m.data {
                            d.data_points.len()
                        } else {
                            0
                        }
                    })
                    .sum::<usize>();
                let (result, lost) = self.0.write(rm);
                assert!(result.is_err());
                let line = self.0.sink.0.lock().unwrap()[0].clone();
                let written: Json = serde_json::from_str(&line).unwrap();
                let written = written["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(point_count)
                    .sum::<usize>();
                assert_eq!(lost, total - written);
                assert!(ready(self.0.export(rm)).is_err());
                let error = self.0.losses.finish(Ok(())).unwrap_err();
                assert_eq!(error.kind(), FlushErrorKind::Failed);
                assert_eq!(error.lost(Signal::Metrics), 0);
                Ok(())
            }
            fn temporality(&self) -> Temporality {
                Temporality::Cumulative
            }
            fn force_flush(&self) -> OTelSdkResult {
                Ok(())
            }
            fn shutdown_with_timeout(&self, _: Duration) -> OTelSdkResult {
                Ok(())
            }
        }
        let exporter = Arc::new(
            OtlpJsonMetricExporter::new(FailSecond(Mutex::default())).with_max_line_bytes(900),
        );
        let provider = SdkMeterProvider::builder()
            .with_reader(
                PeriodicReader::builder(Check(exporter))
                    .with_interval(Duration::from_secs(3600))
                    .build(),
            )
            .build();
        let counter = provider.meter("failure").u64_counter("counter").build();
        for i in 0..20 {
            counter.add(1, &[KeyValue::new("series", i)]);
        }
        provider.shutdown().unwrap();
    }
}
