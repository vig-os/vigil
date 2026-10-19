//! Metrics declared once in statics and bound lazily to the process pipeline.
//! Use [`crate::scope!`] for the declaring crate's instrumentation scope.
//! Records before initialization are counted silently and reported at startup.
//! The startup report still prints when metrics are off. Records after shutdown
//! warn once and are not counted.

use crate::{
    init::PublishedPipeline,
    lifecycle::Losses,
    metric_identity::{Declaration as Identity, Kind},
};
use opentelemetry::{InstrumentationScope, KeyValue, metrics::MeterProvider as _};
use std::{
    borrow::Cow,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

/// Instrumentation library identity, including its version.
/// Use [`crate::scope!`] in application code; `new` supports generated code.
#[derive(Debug, Clone, PartialEq)]
pub struct Scope {
    name: &'static str,
    version: &'static str,
}
impl Scope {
    /// Construct a scope for generated code. Prefer [`crate::scope!`].
    #[must_use]
    pub const fn new(name: &'static str, version: &'static str) -> Self {
        Self { name, version }
    }
}

/// The documented way to identify the crate declaring an instrument.
/// [`Scope::new`] is available for generated code.
#[cfg(feature = "metrics")]
#[cfg_attr(docsrs, doc(cfg(feature = "metrics")))]
#[macro_export]
macro_rules! scope {
    () => {
        $crate::metrics::Scope::new(
            ::core::env!("CARGO_PKG_NAME"),
            ::core::env!("CARGO_PKG_VERSION"),
        )
    };
}

/// A metric attribute value.
///
/// `u64` and `usize` become `I64` when representable, otherwise an exact decimal
/// `Str`: OTLP has no unsigned 64-bit attribute. Above `i64::MAX` the attribute
/// changes type, which splits its series.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Boolean attribute.
    Bool(bool),
    /// Signed integer attribute.
    I64(i64),
    /// Floating-point attribute.
    F64(f64),
    /// Borrowed static or owned string attribute.
    Str(Cow<'static, str>),
}
macro_rules! value_from {
    ($variant:ident, $target:ty; $($source:ty),+ $(,)?) => {$(
        impl From<$source> for Value {
            fn from(value: $source) -> Self { Self::$variant(value as $target) }
        }
    )+};
}
value_from!(Bool, bool; bool);
value_from!(I64, i64; i8, i16, i32, i64, u8, u16, u32, isize);
value_from!(F64, f64; f32, f64);
impl From<u64> for Value {
    fn from(value: u64) -> Self {
        match i64::try_from(value) {
            Ok(value) => Self::I64(value),
            Err(_) => Self::Str(Cow::Owned(value.to_string())),
        }
    }
}
impl From<usize> for Value {
    fn from(value: usize) -> Self {
        Self::from(value as u64)
    }
}
impl From<&'static str> for Value {
    fn from(value: &'static str) -> Self {
        Self::Str(Cow::Borrowed(value))
    }
}
impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::Str(Cow::Owned(value))
    }
}

static BEFORE_INIT: AtomicU64 = AtomicU64::new(0);
static WARNED_AFTER_SHUTDOWN: AtomicBool = AtomicBool::new(false);

pub(crate) fn drain_before_init(losses: &Losses, starting: bool) {
    if !starting
        && !crate::init::published_pipeline()
            .is_some_and(|pipeline| std::ptr::eq(losses, &*pipeline.losses))
    {
        return;
    }
    let count = BEFORE_INIT.swap(0, Ordering::AcqRel);
    if starting {
        losses.measurements_reported_at_start(count);
        if count != 0 {
            use std::io::Write;
            let _ = writeln!(
                std::io::stderr(),
                "vigil: {count} metric records before vigil::init were dropped"
            );
        }
    } else {
        losses.measurements_dropped(count);
    }
}

struct Bound<T> {
    handle: Option<T>,
    poisoned: Arc<AtomicBool>,
    pipeline: &'static PublishedPipeline,
}
struct Declaration<T> {
    scope: Scope,
    name: &'static str,
    unit: &'static str,
    description: &'static str,
    boundaries: Option<&'static [f64]>,
    handle: OnceLock<Option<Bound<T>>>,
}
impl<T> Declaration<T> {
    const fn new(scope: Scope, name: &'static str) -> Self {
        validate_name(name);
        Self {
            scope,
            name,
            unit: "",
            description: "",
            boundaries: None,
            handle: OnceLock::new(),
        }
    }
    fn handle(
        &self,
        kind: Kind,
        build: impl FnOnce(opentelemetry::metrics::Meter) -> T,
    ) -> Option<&T> {
        let bound = if let Some(bound) = self.handle.get() {
            bound.as_ref()?
        } else {
            let Some(pipeline) = crate::init::published_pipeline() else {
                BEFORE_INIT.fetch_add(1, Ordering::Relaxed);
                return None;
            };
            let Some(provider) = &pipeline.metrics else {
                self.handle.get_or_init(|| None);
                return None;
            };
            if stopped(pipeline) {
                return None;
            }
            self.handle
                .get_or_init(|| {
                    let identity = Identity {
                        scope: (self.scope.name, self.scope.version),
                        name: self.name,
                        kind,
                        unit: self.unit,
                        description: self.description,
                        boundaries: self
                            .boundaries
                            .map(crate::metric_identity::canonical_boundaries),
                    };
                    let scope = InstrumentationScope::builder(self.scope.name)
                        .with_version(self.scope.version)
                        .build();
                    let (poisoned, handle) =
                        pipeline.registry.bind(identity, &pipeline.losses, || {
                            build(provider.meter_with_scope(scope))
                        });
                    Some(Bound {
                        handle,
                        poisoned,
                        pipeline,
                    })
                })
                .as_ref()?
        };
        if stopped(bound.pipeline) {
            None
        } else if bound.poisoned.load(Ordering::Acquire) {
            bound.pipeline.losses.measurements_dropped(1);
            None
        } else {
            bound.handle.as_ref()
        }
    }
}
fn stopped(pipeline: &PublishedPipeline) -> bool {
    if !pipeline.stopped.load(Ordering::Acquire) {
        return false;
    }
    if !WARNED_AFTER_SHUTDOWN.swap(true, Ordering::Relaxed) {
        use std::io::Write;
        let _ = writeln!(
            std::io::stderr(),
            "vigil: metric recorded after vigil shutdown; dropped"
        );
    }
    true
}
fn attributes(values: &[(&'static str, Value)]) -> Vec<KeyValue> {
    values
        .iter()
        .map(|(key, value)| {
            KeyValue::new(
                *key,
                match value {
                    Value::Bool(v) => opentelemetry::Value::Bool(*v),
                    Value::I64(v) => opentelemetry::Value::I64(*v),
                    Value::F64(v) => opentelemetry::Value::F64(*v),
                    Value::Str(v) => opentelemetry::Value::String(v.clone().into()),
                },
            )
        })
        .collect()
}
const fn validate_name(name: &str) {
    let bytes = name.as_bytes();
    assert!(
        !bytes.is_empty() && bytes.len() <= 255 && bytes[0].is_ascii_alphabetic(),
        "vigil::metrics: name must start with an ASCII letter and contain at most 255 bytes"
    );
    let mut i = 1;
    while i < bytes.len() {
        assert!(
            bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b'.' | b'-' | b'/'),
            "vigil::metrics: name contains an invalid character"
        );
        i += 1;
    }
}
const fn validate_unit(unit: &str) {
    assert!(
        unit.len() <= 63 && unit.is_ascii(),
        "vigil::metrics: unit must be ASCII and contain at most 63 bytes"
    );
}
const fn validate_boundaries(boundaries: &[f64]) {
    let mut i = 0;
    while i < boundaries.len() {
        assert!(
            boundaries[i].is_finite() && (i == 0 || boundaries[i - 1] < boundaries[i]),
            "vigil::metrics: boundaries must be finite and strictly increasing"
        );
        i += 1;
    }
}

macro_rules! instrument {
    ($name:ident, $sdk:ident, $value:ty, $builder:ident, $record:ident, $doc:literal) => {
        #[doc = $doc]
        pub struct $name(Declaration<opentelemetry::metrics::$sdk<$value>>);
        impl $name {
            /// Declare an instrument in its instrumentation scope.
            ///
            /// # Panics
            /// Panics if the name does not start with an ASCII letter, exceeds
            /// 255 bytes, or contains anything except ASCII letters, digits,
            /// `_`, `.`, `-` and `/`. In a static this is a compile error.
            #[must_use]
            pub const fn new(scope: Scope, name: &'static str) -> Self {
                Self(Declaration::new(scope, name))
            }
            /// Set the instrument's unit.
            ///
            /// # Panics
            /// Panics if the unit is not ASCII or exceeds 63 bytes.
            /// In a static this is a compile error.
            #[must_use]
            pub const fn with_unit(mut self, unit: &'static str) -> Self {
                validate_unit(unit);
                self.0.unit = unit;
                self
            }
            /// Describe what the instrument measures.
            #[must_use]
            pub const fn with_description(mut self, description: &'static str) -> Self {
                self.0.description = description;
                self
            }
            /// Record one measurement with its attributes.
            pub fn $record(&self, value: $value, attrs: &[(&'static str, Value)]) {
                if let Some(handle) = self.0.handle(Kind::$name, |meter| {
                    meter
                        .$builder(self.0.name)
                        .with_unit(self.0.unit)
                        .with_description(self.0.description)
                        .build()
                }) {
                    handle.$record(value, &attributes(attrs));
                }
            }
        }
    };
}
instrument!(
    Counter,
    Counter,
    u64,
    u64_counter,
    add,
    "A monotonic unsigned integer counter."
);
instrument!(
    CounterF64,
    Counter,
    f64,
    f64_counter,
    add,
    "A monotonic floating-point counter."
);
instrument!(
    UpDownCounter,
    UpDownCounter,
    i64,
    i64_up_down_counter,
    add,
    "A signed counter that can increase or decrease."
);
instrument!(
    Gauge,
    Gauge,
    f64,
    f64_gauge,
    record,
    "The last recorded floating-point value."
);

/// A floating-point histogram with explicit bucket boundaries.
///
/// Invalid names fail in statics; the sibling uses a valid name:
/// ```compile_fail
/// use vigil::metrics::Histogram;
/// static H: Histogram = Histogram::new(vigil::scope!(), "1bad");
/// ```
/// ```
/// use vigil::metrics::Histogram;
/// static H: Histogram = Histogram::new(vigil::scope!(), "valid");
/// ```
/// Invalid units fail in statics:
/// ```compile_fail
/// use vigil::metrics::Histogram;
/// static H: Histogram = Histogram::new(vigil::scope!(), "valid").with_unit("µs");
/// ```
/// ```
/// use vigil::metrics::Histogram;
/// static H: Histogram = Histogram::new(vigil::scope!(), "valid").with_unit("us");
/// ```
/// Boundaries must be finite and strictly increasing:
/// ```compile_fail
/// use vigil::metrics::Histogram;
/// static H: Histogram = Histogram::new(vigil::scope!(), "valid").with_boundaries(&[2.0, 1.0]);
/// ```
/// ```
/// use vigil::metrics::Histogram;
/// static H: Histogram = Histogram::new(vigil::scope!(), "valid").with_boundaries(&[1.0, 2.0]);
/// ```
pub struct Histogram(Declaration<opentelemetry::metrics::Histogram<f64>>);
impl Histogram {
    /// Declare a histogram in its instrumentation scope.
    ///
    /// # Panics
    /// Panics if the name does not start with an ASCII letter, exceeds 255
    /// bytes, or contains anything except ASCII letters, digits, `_`, `.`, `-`
    /// and `/`. In a static this is a compile error.
    #[must_use]
    pub const fn new(scope: Scope, name: &'static str) -> Self {
        Self(Declaration::new(scope, name))
    }
    /// Set the histogram's unit.
    ///
    /// # Panics
    /// Panics if the unit is not ASCII or exceeds 63 bytes.
    /// In a static this is a compile error.
    #[must_use]
    pub const fn with_unit(mut self, unit: &'static str) -> Self {
        validate_unit(unit);
        self.0.unit = unit;
        self
    }
    /// Describe what the histogram measures.
    #[must_use]
    pub const fn with_description(mut self, description: &'static str) -> Self {
        self.0.description = description;
        self
    }
    /// An empty slice exports count, sum, min and max with no buckets; not
    /// calling this builder (`None`) keeps the SDK default boundaries.
    /// -0.0 is exported as 0.0.
    ///
    /// # Panics
    /// Panics if boundaries are non-finite or not strictly increasing.
    /// In a static this is a compile error.
    #[must_use]
    pub const fn with_boundaries(mut self, boundaries: &'static [f64]) -> Self {
        validate_boundaries(boundaries);
        self.0.boundaries = Some(boundaries);
        self
    }
    /// Record one observation with its attributes.
    pub fn record(&self, value: f64, attrs: &[(&'static str, Value)]) {
        if let Some(handle) = self.0.handle(Kind::Histogram, |meter| {
            let mut builder = meter
                .f64_histogram(self.0.name)
                .with_unit(self.0.unit)
                .with_description(self.0.description);
            if let Some(boundaries) = self.0.boundaries {
                builder = builder
                    .with_boundaries(crate::metric_identity::canonical_boundaries(boundaries));
            }
            builder.build()
        }) {
            handle.record(value, &attributes(attrs));
        }
    }
}
const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    let _ = assert_send_sync::<Counter>;
    let _ = assert_send_sync::<CounterF64>;
    let _ = assert_send_sync::<UpDownCounter>;
    let _ = assert_send_sync::<Histogram>;
    let _ = assert_send_sync::<Gauge>;
};

#[cfg(test)]
#[path = "metrics_tests.rs"]
mod tests;
