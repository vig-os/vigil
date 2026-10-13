//! Trace export loss reporting; provider construction follows in 8c (#8).
use crate::{
    Signal, init::Failures, lifecycle::Losses, sink::LineSink, span_export::OtlpJsonSpanExporter,
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

/// Records spans reaching export, failed lines and diagnostic stubs.
#[cfg_attr(not(test), expect(dead_code, reason = "wired into init by 8c (#8)"))]
#[derive(Debug)]
pub(crate) struct ReportingSpanExporter<S: LineSink> {
    pub(crate) inner: OtlpJsonSpanExporter<S>,
    pub(crate) failures: Mutex<Failures>,
    pub(crate) losses: Arc<Losses>,
}
impl<S: LineSink + 'static> SpanExporter for ReportingSpanExporter<S> {
    async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        self.losses.reached(Signal::Traces, batch.len() as u64);
        let result = self.inner.export(batch).await;
        let lost = self.inner.take_dropped_spans();
        self.losses
            .record(Signal::Traces, lost as u64, result.is_err());
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
        self.losses.reported(Signal::Traces, reported);
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
    use crate::span_export::fixtures;
    use crate::{lifecycle::FlushErrorKind, sink::MemorySink};

    fn exporter<S: LineSink>(sink: S, limit: usize) -> ReportingSpanExporter<S> {
        ReportingSpanExporter {
            inner: OtlpJsonSpanExporter::new(sink).with_max_line_bytes(limit),
            failures: Mutex::new(Failures::default()),
            losses: Arc::new(Losses::default()),
        }
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
