//! ADR-0003 d21: retain every declaration and poison conflicts under one lock.
use crate::lifecycle::Losses;
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Kind {
    Counter,
    CounterF64,
    UpDownCounter,
    Gauge,
    Histogram,
}
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Declaration {
    pub(crate) scope: (&'static str, &'static str),
    pub(crate) name: &'static str,
    pub(crate) kind: Kind,
    pub(crate) unit: &'static str,
    pub(crate) description: &'static str,
    pub(crate) boundaries: Option<&'static [f64]>,
}
impl Declaration {
    fn compatible(&self, other: &Self) -> bool {
        self.kind == other.kind && self.unit == other.unit && self.boundaries == other.boundaries
    }
    fn conflicts(&self, other: &Self, overlap: bool) -> bool {
        if self == other {
            return false;
        }
        let same_name = self.name.eq_ignore_ascii_case(other.name);
        if self.scope == other.scope {
            overlap
                || (same_name
                    && (!self.compatible(other)
                        || self.name != other.name
                        || self.description != other.description))
        } else {
            (same_name && !self.compatible(other))
                || (overlap && (self.kind != other.kind || self.unit != other.unit))
        }
    }
    fn compare(&self, other: &Self) -> std::cmp::Ordering {
        (
            self.scope,
            self.name,
            self.kind,
            self.unit,
            self.description,
        )
            .cmp(&(
                other.scope,
                other.name,
                other.kind,
                other.unit,
                other.description,
            ))
            .then_with(|| match (self.boundaries, other.boundaries) {
                (None, None) => std::cmp::Ordering::Equal,
                (None, Some(_)) => std::cmp::Ordering::Less,
                (Some(_), None) => std::cmp::Ordering::Greater,
                (Some(a), Some(b)) => a
                    .iter()
                    .zip(b)
                    .map(|(a, b)| a.total_cmp(b))
                    .find(|o| !o.is_eq())
                    .unwrap_or_else(|| a.len().cmp(&b.len())),
            })
    }
}
#[derive(Debug, Default)]
struct Name {
    declarations: Vec<Declaration>,
    poisoned: Arc<AtomicBool>,
    informed: bool,
}
#[derive(Debug, Default)]
struct State {
    names: BTreeMap<String, Name>,
    series: BTreeMap<String, Vec<Declaration>>,
}
#[derive(Debug, Default)]
pub(crate) struct Registry(Mutex<State>);
impl Registry {
    // SDK creation stays inside this lock, so no poisoned name creates a handle.
    pub(crate) fn bind<T>(
        &self,
        declaration: Declaration,
        losses: &Losses,
        build: impl FnOnce() -> T,
    ) -> (Arc<AtomicBool>, Option<T>) {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let name = declaration.name.to_ascii_lowercase();
        let series = series_names(declaration.name, declaration.kind, declaration.unit);
        let mut candidates = state
            .names
            .get(&name)
            .map_or_else(Vec::new, |n| n.declarations.clone());
        for s in &series {
            candidates.extend(state.series.get(s).into_iter().flatten().cloned());
        }
        candidates.sort_by(Declaration::compare);
        candidates.dedup();
        let conflicts: Vec<_> = candidates
            .into_iter()
            .filter(|other| {
                let other_series = series_names(other.name, other.kind, other.unit);
                declaration.conflicts(other, series.iter().any(|s| other_series.contains(s)))
            })
            .collect();
        let flag = state
            .names
            .entry(name.clone())
            .or_default()
            .poisoned
            .clone();
        let mut newly_poisoned = false;
        if !conflicts.is_empty() {
            let names: BTreeSet<_> = conflicts
                .iter()
                .map(|d| d.name.to_ascii_lowercase())
                .chain(std::iter::once(name.clone()))
                .collect();
            for name in names {
                newly_poisoned |= !state
                    .names
                    .entry(name)
                    .or_default()
                    .poisoned
                    .swap(true, Ordering::AcqRel);
            }
        }
        if newly_poisoned {
            losses.metric_name_poisoned();
            let mut involved = conflicts;
            involved.push(declaration.clone());
            involved.sort_by(Declaration::compare);
            let _ = writeln!(
                std::io::stderr(),
                "vigil: conflicting metric instruments: {involved:?}; conflicting names dropped"
            );
        }
        let entry = state.names.entry(name.clone()).or_default();
        if !entry.declarations.contains(&declaration) {
            entry.declarations.push(declaration.clone());
            for s in series {
                state.series.entry(s).or_default().push(declaration.clone());
            }
        }
        let entry = state.names.entry(name.clone()).or_default();
        let scopes: BTreeSet<_> = entry.declarations.iter().map(|d| d.scope).collect();
        if scopes.len() > 1 && !entry.informed && !flag.load(Ordering::Acquire) {
            entry.informed = true;
            let scopes = scopes
                .into_iter()
                .map(|(n, v)| format!("{n}@{v}"))
                .collect::<Vec<_>>()
                .join(" and ");
            let _ = writeln!(
                std::io::stderr(),
                "vigil: metric {name:?} is recorded by {scopes}; Prometheus needs otlp.promote_scope_metadata: true to keep them apart"
            );
        }
        let handle = (!flag.load(Ordering::Acquire)).then(build);
        (flag, handle)
    }
    pub(crate) fn filter(&self, request: &mut ExportMetricsServiceRequest) {
        let state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for resource in &mut request.resource_metrics {
            for scope in &mut resource.scope_metrics {
                scope.metrics.retain(|m| {
                    !state
                        .names
                        .get(&m.name.to_ascii_lowercase())
                        .is_some_and(|n| n.poisoned.load(Ordering::Acquire))
                });
            }
            resource.scope_metrics.retain(|s| !s.metrics.is_empty());
        }
        request
            .resource_metrics
            .retain(|r| !r.scope_metrics.is_empty());
    }
}

// Port of prometheus/otlptranslator v1.0.0, pinned by Prometheus 3.12.0.
// https://github.com/prometheus/otlptranslator/blob/v1.0.0/metric_namer.go
// https://github.com/prometheus/otlptranslator/blob/v1.0.0/unit_namer.go
// Copyright 2025 The Prometheus Authors; Apache-2.0.
pub(crate) fn series_names(name: &str, kind: Kind, unit: &str) -> Vec<String> {
    let mut tokens: Vec<String> = name
        .split(|c: char| !c.is_ascii_alphanumeric() && c != ':')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    let (main, per) = unit.split_once('/').map_or((unit, ""), |pair| pair);
    let clean = |s: &str| {
        let mut out = String::new();
        for c in s.chars() {
            let c = if c.is_ascii_alphanumeric() || c == ':' {
                c
            } else {
                '_'
            };
            if c != '_' || !out.ends_with('_') {
                out.push(c);
            }
        }
        out.strip_prefix('_').unwrap_or(&out).to_owned()
    };
    let suffix = |s: &str, per: bool| {
        let s = s.trim();
        if s.contains(['{', '}']) || s.is_empty() {
            return String::new();
        }
        let mapped = if per {
            match s {
                "s" => "second",
                "m" => "minute",
                "h" => "hour",
                "d" => "day",
                "w" => "week",
                "mo" => "month",
                "y" => "year",
                _ => s,
            }
        } else {
            match s {
                "d" => "days",
                "h" => "hours",
                "min" => "minutes",
                "s" => "seconds",
                "ms" => "milliseconds",
                "us" => "microseconds",
                "ns" => "nanoseconds",
                "By" => "bytes",
                "KiBy" => "kibibytes",
                "MiBy" => "mebibytes",
                "GiBy" => "gibibytes",
                "TiBy" => "tibibytes",
                "KBy" => "kilobytes",
                "MBy" => "megabytes",
                "GBy" => "gigabytes",
                "TBy" => "terabytes",
                "m" => "meters",
                "V" => "volts",
                "A" => "amperes",
                "J" => "joules",
                "W" => "watts",
                "g" => "grams",
                "Cel" => "celsius",
                "Hz" => "hertz",
                "1" => "",
                "%" => "percent",
                _ => s,
            }
        };
        clean(&if per {
            format!("per_{mapped}")
        } else {
            mapped.to_owned()
        })
    };
    let mut main = suffix(main, false);
    let mut per = suffix(per, true);
    if tokens.contains(&main) {
        main.clear();
    }
    if per == "per_" {
        per.clear();
    } else {
        if per.ends_with('_') {
            per.pop();
        }
        if tokens.contains(&per) {
            per.clear();
        }
    }
    if !per.is_empty() && main.ends_with('_') {
        main.pop();
    }
    for s in [main, per] {
        if !s.is_empty() {
            tokens.push(s);
        }
    }
    if matches!(kind, Kind::Counter | Kind::CounterF64) {
        tokens.retain(|s| s != "total");
        tokens.push("total".into());
    }
    if kind == Kind::Gauge && unit == "1" {
        tokens.retain(|s| s != "ratio");
        tokens.push("ratio".into());
    }
    let mut base = tokens.join("_");
    if base.starts_with(|c: char| c.is_ascii_digit()) {
        base.insert(0, '_');
    }
    if kind == Kind::Histogram {
        ["bucket", "sum", "count"]
            .into_iter()
            .map(|s| format!("{base}_{s}"))
            .collect()
    } else {
        vec![base]
    }
}

#[cfg(test)]
#[path = "metric_identity_tests.rs"]
mod tests;
