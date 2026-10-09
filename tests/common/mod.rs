//! Shared helpers: build fixed SDK log records and push them through the
//! exporter as one batch.
#![allow(dead_code)]

use std::future::Future;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use opentelemetry::logs::{AnyValue, LogRecord as _, Logger as _, LoggerProvider as _, Severity};
use opentelemetry::trace::{SpanId, TraceFlags, TraceId};
use opentelemetry::{InstrumentationScope, KeyValue};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::{LogBatch, LogExporter, SdkLogRecord, SdkLoggerProvider};

use vigil::logs::OtlpJsonLogExporter;
use vigil::sink::LineSink;

/// A fixed point in time, `secs` + `nanos` after the epoch.
pub fn at(secs: u64, nanos: u32) -> SystemTime {
    UNIX_EPOCH + Duration::new(secs, nanos)
}

/// A bare record with a fixed observed time, plus the scope it belongs to.
pub struct Rec {
    pub record: SdkLogRecord,
    pub scope: InstrumentationScope,
}

pub fn rec(scope: &InstrumentationScope, build: impl FnOnce(&mut SdkLogRecord)) -> Rec {
    let provider = SdkLoggerProvider::builder().build();
    let logger = provider.logger_with_scope(scope.clone());
    let mut record = logger.create_log_record();
    record.set_observed_timestamp(at(1_700_000_000, 123_456_789));
    build(&mut record);
    Rec {
        record,
        scope: scope.clone(),
    }
}

pub fn scope(name: &'static str, version: &'static str) -> InstrumentationScope {
    InstrumentationScope::builder(name)
        .with_version(version)
        .build()
}

pub fn scope_with(
    name: &'static str,
    version: &'static str,
    attributes: Vec<KeyValue>,
) -> InstrumentationScope {
    InstrumentationScope::builder(name)
        .with_version(version)
        .with_attributes(attributes)
        .build()
}

pub fn resource(attributes: Vec<KeyValue>) -> Resource {
    Resource::builder_empty()
        .with_attributes(attributes)
        .build()
}

/// Export `records` as one batch through a fresh exporter on `sink`.
pub fn export<S: LineSink + 'static>(sink: S, resource: &Resource, records: &[Rec]) {
    let mut exporter = OtlpJsonLogExporter::new(sink);
    exporter.set_resource(resource);
    let pairs: Vec<_> = records.iter().map(|r| (&r.record, &r.scope)).collect();
    let mut future = std::pin::pin!(exporter.export(LogBatch::new(&pairs)));
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result.expect("export failed"),
        Poll::Pending => panic!("the exporter future must be ready immediately"),
    }
}

pub fn ids() -> (TraceId, SpanId, TraceFlags) {
    (
        TraceId::from_bytes([
            0x5b, 0x8e, 0xfd, 0xe7, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xaa, 0xbb,
        ]),
        SpanId::from_bytes([0xee, 0xe1, 0x9b, 0x7e, 0xc3, 0xc1, 0xb1, 0x74]),
        TraceFlags::SAMPLED,
    )
}

pub fn any_map(entries: Vec<(&'static str, AnyValue)>) -> AnyValue {
    AnyValue::Map(Box::new(
        entries.into_iter().map(|(k, v)| (k.into(), v)).collect(),
    ))
}

/// The fixed record set the golden test pins: every `AnyValue` kind, empty
/// body, ids, several scopes.
pub fn golden_records() -> (Resource, Vec<Rec>) {
    let (trace_id, span_id, flags) = ids();
    let alpha = scope("alpha", "1.0.0");
    let beta = scope("beta", "2.1.0");
    let alpha_new = scope("alpha", "1.1.0");

    let resource = resource(vec![
        KeyValue::new("service.name", "vigil-golden"),
        KeyValue::new("host.name", "test-host"),
        KeyValue::new("deployment.environment", "ci"),
        KeyValue::new("res_inf", f64::INFINITY),
        KeyValue::new("res_nan", f64::NAN),
    ]);
    // A NaN scope attribute: NaN != NaN, so the SDK puts every record of this
    // scope into its own group.
    let nan_scope = scope_with(
        "gamma",
        "3.0.0",
        vec![
            KeyValue::new("scope_nan", f64::NAN),
            KeyValue::new("scope_neg_inf", f64::NEG_INFINITY),
        ],
    );

    let records = vec![
        // beta first on purpose: output must be sorted by scope.
        rec(&beta, |r| {
            r.set_timestamp(at(1_700_000_000, 5));
            r.set_severity_number(Severity::Error);
            r.set_severity_text("ERROR");
            r.set_body("kinds".into());
            r.add_attribute("string", "text");
            r.add_attribute("bool", true);
            r.add_attribute("int", 9_007_199_254_740_993_i64);
            r.add_attribute("double", 1.5_f64);
            r.add_attribute("nan", f64::NAN);
            r.add_attribute("inf", f64::INFINITY);
            r.add_attribute("neg_inf", f64::NEG_INFINITY);
            r.add_attribute(
                "bytes",
                AnyValue::Bytes(Box::new(vec![0, 1, 2, 0xfe, 0xff])),
            );
            r.add_attribute(
                "array",
                AnyValue::ListAny(Box::new(vec![
                    1_i64.into(),
                    f64::NAN.into(),
                    "two".into(),
                    AnyValue::ListAny(Box::new(vec![false.into(), f64::NEG_INFINITY.into()])),
                ])),
            );
            r.add_attribute(
                "kvlist",
                any_map(vec![
                    ("zeta", 1_i64.into()),
                    ("alpha", f64::INFINITY.into()),
                    ("mid", any_map(vec![("b", true.into()), ("a", "x".into())])),
                ]),
            );
        }),
        rec(&alpha, |r| {
            r.set_timestamp(at(1_700_000_001, 0));
            r.set_severity_number(Severity::Info);
            r.set_severity_text("INFO");
            r.set_body("traced".into());
            r.set_trace_context(trace_id, span_id, Some(flags));
            r.add_attribute("code.lineno", 42_i64);
            r.add_attribute("code.filepath", "src/main.rs");
        }),
        // Not set: timestamp (copied from observed), severity, body.
        rec(&alpha, |_| {}),
        // Empty-string body and a body that is itself a map with a NaN.
        rec(&alpha, |r| {
            r.set_severity_number(Severity::Warn);
            r.set_body("".into());
        }),
        rec(&alpha_new, |r| {
            r.set_severity_number(Severity::Debug);
            r.set_body(any_map(vec![
                ("v", f64::NAN.into()),
                ("a", AnyValue::Int(-1)),
            ]));
        }),
    ];
    let mut records = records;
    for i in 0..4_i64 {
        records.push(rec(&nan_scope, |r| {
            r.set_timestamp(at(1_700_000_010 + i as u64, 0));
            r.set_body(format!("nan scope {i}").into());
        }));
    }
    (resource, records)
}
