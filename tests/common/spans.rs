//! Fixed SDK span fixtures shared by golden and Collector tests.
use opentelemetry::{
    InstrumentationScope, KeyValue,
    trace::{SpanContext, SpanId, SpanKind, Status, TraceFlags, TraceId, TraceState},
};
use opentelemetry_sdk::trace::{SpanData, SpanEvents, SpanLinks};
use std::time::{Duration, UNIX_EPOCH};

pub fn span(scope: &'static str, id: u64) -> SpanData {
    SpanData {
        span_context: SpanContext::new(
            TraceId::from(0xabcdef_u128),
            SpanId::from(id),
            TraceFlags::SAMPLED,
            false,
            TraceState::from_key_value([("vendor", "state")]).unwrap(),
        ),
        parent_span_id: SpanId::from(1),
        parent_span_is_remote: false,
        span_kind: SpanKind::Server,
        name: format!("span-{id}").into(),
        start_time: UNIX_EPOCH + Duration::from_secs(1),
        end_time: UNIX_EPOCH + Duration::from_secs(2),
        attributes: vec![KeyValue::new("z", f64::NAN), KeyValue::new("a", "value")],
        dropped_attributes_count: 0,
        events: SpanEvents::default(),
        links: SpanLinks::default(),
        status: Status::error("failure"),
        instrumentation_scope: InstrumentationScope::builder(scope).build(),
    }
}
pub fn batch() -> Vec<SpanData> {
    vec![span("b", 4), span("a", 3), span("b", 2), span("a", 1)]
}

/// Poll the synchronous exporter once and propagate its result.
pub fn ready(
    future: impl std::future::Future<Output = opentelemetry_sdk::error::OTelSdkResult>,
) -> opentelemetry_sdk::error::OTelSdkResult {
    use std::task::{Context, Poll, Waker};
    match std::pin::pin!(future)
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("span export must be ready immediately"),
    }
}
