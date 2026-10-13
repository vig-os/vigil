//! Trace provider construction, layer configuration and export loss reporting.
use crate::{
    init::Failures,
    lifecycle::{Losses, QueueSignal},
    sink::LineSink,
    span_export::OtlpJsonSpanExporter,
};
use opentelemetry_sdk::{
    Resource,
    error::OTelSdkResult,
    trace::{SpanData, SpanExporter},
};
use std::{
    sync::{Arc, Mutex, atomic::Ordering},
    time::Duration,
};

/// Explicit synchronous batch settings; timeout and concurrency are ignored by the SDK.
fn span_batch_config(queue: usize) -> opentelemetry_sdk::trace::BatchConfig {
    opentelemetry_sdk::trace::BatchConfigBuilder::default()
        .with_max_queue_size(queue)
        .with_max_export_batch_size(512)
        .with_scheduled_delay(Duration::from_secs(1))
        .build()
}

/// Set every limit without consulting the environment.
fn span_limits() -> opentelemetry_sdk::trace::SpanLimits {
    opentelemetry_sdk::trace::SpanLimits {
        max_events_per_span: 0,
        max_attributes_per_span: 128,
        max_links_per_span: 128,
        max_attributes_per_event: 128,
        max_attributes_per_link: 128,
    }
}

/// Resolved before provider construction; shutdown closes the slot.
#[derive(Debug)]
pub(crate) struct TraceStorage(pub(crate) Mutex<TraceStorageState>);

#[cfg_attr(not(test), expect(dead_code, reason = "wired into init in #8 8c-2"))]
#[derive(Debug)]
pub(crate) enum TraceStorageState {
    Ready(Arc<crate::rotate::RotatingFile>),
    Disabled,
    Closed,
}
impl LineSink for TraceStorage {
    fn write_line(&self, line: &[u8]) -> std::io::Result<()> {
        match &*self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            TraceStorageState::Ready(file) => file.write_line(line),
            TraceStorageState::Disabled => Ok(()),
            TraceStorageState::Closed => Err(std::io::ErrorKind::BrokenPipe.into()),
        }
    }
    fn flush(&self) -> std::io::Result<()> {
        match &*self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            TraceStorageState::Ready(file) => file.flush(),
            TraceStorageState::Disabled => Ok(()),
            TraceStorageState::Closed => Err(std::io::ErrorKind::BrokenPipe.into()),
        }
    }
}
impl TraceStorage {
    #[cfg_attr(not(test), expect(dead_code, reason = "wired into init in #8 8c-2"))]
    pub(crate) fn close(&self) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = TraceStorageState::Closed;
    }
}

/// Build a provider only after storage has resolved to ready or disabled.
#[cfg_attr(not(test), expect(dead_code, reason = "wired into init in #8 8c-2"))]
pub(crate) fn build_tracer(
    storage: Arc<TraceStorage>,
    resource: Resource,
    queue: usize,
    losses: Arc<Losses>,
) -> opentelemetry_sdk::trace::SdkTracerProvider {
    use opentelemetry_sdk::trace::{BatchSpanProcessor, Sampler, SdkTracerProvider};
    SdkTracerProvider::builder()
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::AlwaysOn)))
        .with_span_limits(span_limits())
        .with_resource(resource)
        .with_span_processor(crate::lifecycle::ReportingSpanProcessor {
            inner: BatchSpanProcessor::builder(ReportingSpanExporter {
                inner: OtlpJsonSpanExporter::new(storage),
                failures: Mutex::new(Failures::default()),
                losses: losses.clone(),
            })
            .with_batch_config(span_batch_config(queue))
            .build(),
            losses,
        })
        .build()
}

/// Configure the layer for its concrete subscriber position.
#[cfg_attr(not(test), expect(dead_code, reason = "wired into init in #8 8c-2"))]
pub(crate) fn otel_layer<S>(
    provider: &opentelemetry_sdk::trace::SdkTracerProvider,
) -> tracing_opentelemetry::OpenTelemetryLayer<S, opentelemetry_sdk::trace::SdkTracer>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    use opentelemetry::trace::TracerProvider as _;
    tracing_opentelemetry::layer()
        .with_tracer(provider.tracer("vigil"))
        .with_location(true)
        .with_threads(true)
        .with_target(true)
        .with_tracked_inactivity(false)
        .with_context_activation(true)
        .with_level(false)
}

/// Preserve error status while the zero-event limit removes duplicate events.
#[cfg_attr(not(test), expect(dead_code, reason = "wired into init in #8 8c-2"))]
pub(crate) fn spans_or_error(metadata: &tracing::Metadata<'_>) -> bool {
    metadata.is_span() || *metadata.level() == tracing::Level::ERROR
}

/// Records spans reaching export, failed lines and diagnostic stubs.
#[derive(Debug)]
pub(crate) struct ReportingSpanExporter<S: LineSink> {
    pub(crate) inner: OtlpJsonSpanExporter<S>,
    pub(crate) failures: Mutex<Failures>,
    pub(crate) losses: Arc<Losses>,
}
impl<S: LineSink + 'static> SpanExporter for ReportingSpanExporter<S> {
    async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        self.losses.reached(QueueSignal::Traces, batch.len() as u64);
        let result = self.inner.export(batch).await;
        let lost = self.inner.take_dropped_spans();
        self.losses
            .record(QueueSignal::Traces, lost as u64, result.is_err());
        let reported = self
            .failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record(
                "span",
                "spans",
                lost,
                &result,
                self.losses.shutting_down.load(Ordering::Acquire),
            );
        self.losses.reported(QueueSignal::Traces, reported);
        Ok(())
    }
    fn set_resource(&mut self, resource: &Resource) {
        self.inner.set_resource(resource);
    }
    fn force_flush(&self) -> OTelSdkResult {
        self.inner.force_flush()
    }
    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Signal;
    use crate::span_export::fixtures;
    use crate::{lifecycle::FlushErrorKind, sink::MemorySink};

    use tracing_subscriber::{Layer as _, layer::SubscriberExt as _};

    fn capture(emit: impl FnOnce(), filter: bool) -> Vec<serde_json::Value> {
        let dir = crate::test_temp::TempDir::new();
        let storage = Arc::new(TraceStorage(Mutex::new(TraceStorageState::Ready(
            Arc::new(
                crate::rotate::RotatingFile::open(&dir.0, "traces", Default::default()).unwrap(),
            ),
        ))));
        let losses = Arc::new(Losses::default());
        let provider = build_tracer(
            storage,
            Resource::builder_empty().build(),
            65536,
            losses.clone(),
        );
        let subscriber = tracing_subscriber::registry().with(
            otel_layer(&provider)
                .with_filter(tracing_subscriber::filter::filter_fn(spans_or_error))
                .with_filter(if filter {
                    tracing_subscriber::filter::LevelFilter::INFO
                } else {
                    tracing_subscriber::filter::LevelFilter::TRACE
                }),
        );
        tracing::subscriber::with_default(subscriber, emit);
        losses
            .finish_signals(Ok(()), Ok(()), provider.force_flush())
            .unwrap();
        provider.shutdown().unwrap();
        std::fs::read_to_string(dir.0.join("traces.jsonl"))
            .unwrap()
            .lines()
            .flat_map(|line| {
                let value: serde_json::Value = serde_json::from_str(line).unwrap();
                value["resourceSpans"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .flat_map(|r| {
                        r["scopeSpans"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .flat_map(|scope| {
                                assert_eq!(scope["scope"]["name"], "vigil");
                                assert_eq!(scope["scope"]["version"].as_str().unwrap_or(""), "");
                                scope["spans"].as_array().unwrap().clone()
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    fn attrs(span: &serde_json::Value) -> std::collections::BTreeMap<String, serde_json::Value> {
        span["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| (a["key"].as_str().unwrap().to_owned(), a["value"].clone()))
            .collect()
    }

    #[test]
    fn batch_config_debug_pin() {
        for (queue, batch) in [(65536, 512), (16, 16)] {
            let debug = format!("{:?}", span_batch_config(queue));
            // The synchronous processor ignores timeout and concurrency. Normalize
            // precisely those fields, leaving every effective setting pinned.
            let fields = debug
                .trim_start_matches("BatchConfig { ")
                .trim_end_matches(" }")
                .split(", ")
                .map(|field| {
                    if field.starts_with("max_export_timeout:") {
                        "max_export_timeout: ignored"
                    } else if field.starts_with("max_concurrent_exports:") {
                        "max_concurrent_exports: ignored"
                    } else {
                        field
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            assert_eq!(
                fields,
                format!(
                    "max_queue_size: {queue}, scheduled_delay: 1s, max_export_batch_size: {batch}, max_export_timeout: ignored, max_concurrent_exports: ignored"
                )
            );
        }
    }

    #[test]
    fn layer_attributes_and_level_pin() {
        let spans = capture(
            || {
                let span = tracing::info_span!("attributes");
                span.in_scope(|| {});
            },
            false,
        );
        let a = attrs(&spans[0]);
        for key in [
            "code.file.path",
            "code.module.name",
            "code.line.number",
            "thread.id",
            "thread.name",
            "target",
        ] {
            assert!(a.contains_key(key), "{key}");
        }
        for key in ["busy_ns", "idle_ns", "level"] {
            assert!(!a.contains_key(key), "{key}");
        }
    }

    #[test]
    fn errors_set_status_without_events_and_info_filter_excludes_debug() {
        let spans = capture(
            || {
                tracing::debug_span!("excluded").in_scope(|| {});
                tracing::info_span!("included").in_scope(|| {
                    tracing::info!("ordinary");
                    tracing::error!("first");
                    tracing::error!("second");
                });
            },
            true,
        );
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0]["name"], "included");
        assert_eq!(spans[0]["status"]["code"], 2);
        assert_eq!(spans[0]["droppedEventsCount"], 2);
        assert!(spans[0]["events"].as_array().unwrap().is_empty());
    }

    #[test]
    fn special_fields_are_honoured() {
        let spans = capture(
            || {
                drop(tracing::info_span!(
                    "original",
                    otel.name = "renamed",
                    otel.kind = "server",
                    otel.status_code = "ERROR",
                    otel.status_description = "explicit"
                ));
            },
            false,
        );
        assert_eq!(spans[0]["name"], "renamed");
        assert_eq!(spans[0]["kind"], 2);
        assert_eq!(spans[0]["status"]["code"], 2);
        assert_eq!(spans[0]["status"]["message"], "explicit");
    }

    #[tracing::instrument(err)]
    fn instrumented_error() -> Result<(), std::io::Error> {
        Err(std::io::Error::other("instrumented"))
    }

    #[test]
    fn error_mapping_pin() {
        let spans = capture(
            || {
                let _ = instrumented_error();
                let e = std::io::Error::other("failure");
                tracing::info_span!("message_less").in_scope(|| tracing::error!(error = %e));
                tracing::info_span!("with_message").in_scope(|| tracing::error!(error = %e, "msg"));
                let error: &dyn std::error::Error = &e;
                drop(tracing::info_span!("typed", error));
            },
            false,
        );
        for name in ["instrumented_error", "message_less", "with_message"] {
            let span = spans.iter().find(|s| s["name"] == name).unwrap();
            assert_eq!(span["status"]["code"], 2);
            if name == "with_message" {
                assert!(span["status"]["message"].as_str().unwrap_or("").is_empty());
            } else {
                assert!(!span["status"]["message"].as_str().unwrap().is_empty());
            }
        }
        let typed = spans.iter().find(|s| s["name"] == "typed").unwrap();
        assert_eq!(attrs(typed)["exception.message"]["stringValue"], "failure");
    }

    #[test]
    fn all_local_spans_export_without_loss() {
        let spans = capture(
            || {
                for i in 0..2000 {
                    drop(tracing::info_span!("volume", index = i));
                }
            },
            false,
        );
        assert_eq!(spans.len(), 2000);
    }

    #[test]
    fn environment_cannot_override_pipeline() {
        const NAME: &str = "trace_pipeline::tests::environment_cannot_override_pipeline";
        const CHILD: &str = "VIGIL_TRACE_ENV_CHILD";
        if crate::test_child_with_env(
            NAME,
            CHILD,
            &[
                ("OTEL_TRACES_SAMPLER", "always_off"),
                ("OTEL_SPAN_EVENT_COUNT_LIMIT", "5"),
                ("OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT", "1"),
                ("OTEL_SPAN_LINK_COUNT_LIMIT", "0"),
                ("OTEL_BSP_MAX_QUEUE_SIZE", "1"),
            ],
        )
        .is_some()
        {
            return;
        }
        let spans = capture(
            || {
                for i in 0..2000 {
                    tracing::info_span!("environment", index = i, extra = "kept")
                        .in_scope(|| tracing::error!("failure"));
                }
            },
            false,
        );
        assert_eq!(spans.len(), 2000);
        for span in spans {
            assert!(attrs(&span).contains_key("index"));
            assert!(attrs(&span).contains_key("extra"));
            assert!(span["events"].as_array().unwrap().is_empty());
            assert_eq!(span["droppedEventsCount"], 1);
        }
    }

    #[test]
    fn storage_ready_writes_and_closes() {
        let dir = crate::test_temp::TempDir::new();
        let storage = TraceStorage(Mutex::new(TraceStorageState::Ready(Arc::new(
            crate::rotate::RotatingFile::open(&dir.0, "traces", Default::default()).unwrap(),
        ))));
        storage.write_line(b"{}").unwrap();
        storage.flush().unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.0.join("traces.jsonl")).unwrap(),
            "{}\n"
        );
        storage.close();
        assert_eq!(
            storage.write_line(b"{}").unwrap_err().kind(),
            std::io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn storage_disabled_discards_without_loss() {
        let storage = Arc::new(TraceStorage(Mutex::new(TraceStorageState::Disabled)));
        storage.write_line(b"{}").unwrap();
        storage.flush().unwrap();
        let exporter = exporter(storage.clone(), 10000);
        fixtures::ready(exporter.export(fixtures::batch())).unwrap();
        exporter.losses.finish(Ok(())).unwrap();
        storage.close();
        assert!(storage.flush().is_err());
    }

    #[test]
    fn storage_closed_counts_lost_spans() {
        let storage = TraceStorage(Mutex::new(TraceStorageState::Closed));
        assert_eq!(
            storage.write_line(b"{}").unwrap_err().kind(),
            std::io::ErrorKind::BrokenPipe
        );
        let exporter = exporter(storage, 10000);
        fixtures::ready(exporter.export(fixtures::batch())).unwrap();
        assert_eq!(
            exporter
                .losses
                .finish(Ok(()))
                .unwrap_err()
                .lost(Signal::Traces),
            4
        );
    }

    fn exporter<S: LineSink>(sink: S, limit: usize) -> ReportingSpanExporter<S> {
        ReportingSpanExporter {
            inner: OtlpJsonSpanExporter::new(sink).with_max_line_bytes(limit),
            failures: Mutex::new(Failures::default()),
            losses: Arc::new(Losses::default()),
        }
    }

    #[test]
    fn real_trace_stack_flushes_without_losses() {
        use crate::{lifecycle::ReportingSpanProcessor, sink::AppendFile};
        use opentelemetry::trace::{Tracer as _, TracerProvider as _};
        use opentelemetry_sdk::trace::{BatchSpanProcessor, SdkTracerProvider};
        let dir = crate::test_temp::TempDir::new();
        let path = dir.0.join("traces.jsonl");
        let exporter = exporter(AppendFile::open(&path).unwrap(), 10000);
        let losses = exporter.losses.clone();
        let provider = SdkTracerProvider::builder()
            .with_span_processor(ReportingSpanProcessor {
                inner: BatchSpanProcessor::builder(exporter).build(),
                losses: losses.clone(),
            })
            .build();
        let tracer = provider.tracer("real-stack");
        for name in ["first", "second", "third"] {
            drop(tracer.start(name));
        }
        let result = crate::lifecycle::flush(|| provider.force_flush());
        result.as_ref().unwrap();
        let outcome = losses.finish_signals(Ok(()), Ok(()), result);
        let lost = outcome
            .as_ref()
            .err()
            .map_or(0, |error| error.lost(Signal::Traces));
        assert_eq!(lost, 0);
        outcome.unwrap();
        let lines = std::fs::read_to_string(&path).unwrap();
        let names: Vec<_> = lines
            .lines()
            .flat_map(|line| {
                let json: serde_json::Value = serde_json::from_str(line).unwrap();
                json["resourceSpans"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .flat_map(|resource| {
                        resource["scopeSpans"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .flat_map(|scope| {
                                scope["spans"]
                                    .as_array()
                                    .unwrap()
                                    .iter()
                                    .map(|span| span["name"].as_str().unwrap().to_owned())
                            })
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        assert_eq!(names, ["first", "second", "third"]);
        losses
            .finish_signals(Ok(()), Ok(()), provider.shutdown())
            .unwrap();
    }

    #[test]
    fn failed_line_counts_spans_and_stub_counts_one() {
        #[derive(Debug)]
        struct Broken;
        impl LineSink for Broken {
            fn write_line(&self, _: &[u8]) -> std::io::Result<()> {
                Err(std::io::Error::other("broken"))
            }
            fn flush(&self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let exporter = exporter(Broken, 10000);
        fixtures::ready(exporter.export(fixtures::batch())).unwrap();
        let error = exporter.losses.finish(Ok(())).unwrap_err();
        assert_eq!(error.lost(Signal::Traces), 4);
        assert_eq!(error.lost(Signal::Logs), 0);
        assert_eq!(error.kind(), FlushErrorKind::Failed);
        let exporter = self::exporter(MemorySink::new(), 800);
        let mut batch = fixtures::batch();
        batch[1].attributes.extend(
            (0..100).map(|i| opentelemetry::KeyValue::new(format!("key-{i}"), i64::from(i))),
        );
        fixtures::ready(exporter.export(batch)).unwrap();
        let error = exporter.losses.finish(Ok(())).unwrap_err();
        assert_eq!(error.lost(Signal::Traces), 1);
        assert_eq!(error.kind(), FlushErrorKind::DataLost);
    }

    #[test]
    fn reported_span_losses_leave_pending_logs_unchanged() {
        let exporter = exporter(MemorySink::new(), 800);
        exporter.losses.record(QueueSignal::Logs, 2, true);
        let mut span = fixtures::span("stub", 1);
        span.attributes.extend(
            (0..100).map(|i| opentelemetry::KeyValue::new(format!("key-{i}"), i64::from(i))),
        );
        fixtures::ready(exporter.export(vec![span])).unwrap();
        assert_eq!(
            exporter.losses.pending_stderr(QueueSignal::Traces),
            (0, false)
        );
        assert_eq!(exporter.losses.pending_stderr(QueueSignal::Logs), (2, true));
        let error = exporter.losses.finish(Ok(())).unwrap_err();
        assert_eq!(error.lost(Signal::Traces), 1);
        assert_eq!(error.lost(Signal::Logs), 2);
    }

    #[test]
    fn runtime_span_loss_summary() {
        if let Some(output) = crate::test_child(
            "trace_pipeline::tests::runtime_span_loss_summary",
            "VIGIL_TRACE_STDERR_CHILD",
        ) {
            assert_eq!(
                String::from_utf8(output.stderr).unwrap(),
                "vigil: runtime span export losses; dropped spans: 1\n"
            );
            return;
        }
        let exporter = exporter(MemorySink::new(), 800);
        let mut span = fixtures::span("stub", 1);
        span.attributes.extend(
            (0..100).map(|i| opentelemetry::KeyValue::new(format!("key-{i}"), i64::from(i))),
        );
        fixtures::ready(exporter.export(vec![span])).unwrap();
    }
}
