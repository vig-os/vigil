//! Validated verifier trust input (ADR-0005 decision 9).
use super::{AuditError, AuditErrorKind, hex, parse_hex};
use std::{collections::BTreeMap, path::Path};

type Bound = (u64, [u8; 32]);
#[derive(Clone, Debug)]
struct Key {
    bytes: [u8; 32],
    bound: Option<Bound>,
    line: Option<usize>,
}
#[derive(Clone, Debug)]
struct Section {
    id: [u8; 16],
    keys: Vec<Key>,
    ends: Vec<Bound>,
    line: Option<usize>,
}
impl Section {
    fn new(id: [u8; 16], line: Option<usize>) -> Self {
        Self {
            id,
            keys: Vec::new(),
            ends: Vec::new(),
            line,
        }
    }
}

/// Validated, pinned trust input for the verifier, which follows in #13.
///
/// Trust files contain UTF-8 lines split on ASCII whitespace:
/// ```text
/// # Pinned trail and its trusted signing key
/// trail 00000000000000000000000000000001 end=9:blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
/// ed25519 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb through=9:blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa retired key
/// ```
/// Blank and `#` lines are ignored. Ids and keys are exactly 32 and 64 lowercase
/// hex characters. Bounds use a decimal u64 and `blake3:` plus 64 lowercase hex
/// characters. Only `end=` on a trail and `through=` on a key are options;
/// unknown or repeated options fail. The first non-option starts a free comment.
/// Unknown line kinds fail; schema pins arrive with #164 CP4.
///
/// A key bounded on one trail must be bounded on every trail listing it, though
/// each trail has its own bound. This check covers one trust file: every trail a
/// key signs for must belong in that file. Independently revocable keys must be
/// different keys. Keep the file outside the writable trail directory.
/// An `end=` comes from the application's close checkpoint, a receipt or an
/// anchor, never from a read of the trail directory.
///
/// ```
/// use vigil::audit::TrustPolicy;
/// let policy = TrustPolicy::builder().trail([1; 16]).key([2; 32]).build()?;
/// # Ok::<(), vigil::audit::AuditError>(())
/// ```
#[derive(Clone, Debug)]
pub struct TrustPolicy {
    sections: BTreeMap<[u8; 16], Section>,
}

/// Collects trail sections; only `build` creates a validated policy.
#[derive(Debug)]
pub struct TrustPolicyBuilder {
    sections: Vec<Section>,
}
/// Collects keys and an optional retirement head for the current trail section.
#[derive(Debug)]
pub struct TrailTrust {
    builder: TrustPolicyBuilder,
    current: Section,
}
impl TrustPolicy {
    /// Starts a policy builder. At least one trail section is required.
    pub fn builder() -> TrustPolicyBuilder {
        TrustPolicyBuilder {
            sections: Vec::new(),
        }
    }
    /// Reads and validates a trust file using the grammar above.
    ///
    /// # Errors
    /// Returns `Io` with its underlying source if reading fails, or
    /// `InvalidConfig` for invalid UTF-8, syntax or trust semantics.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let bytes = std::fs::read(path).map_err(AuditError::from_io)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| invalid("trust file is not UTF-8"))?;
        validate(parse(text)?)
    }
    /// Whether the policy pins this trail id.
    pub(crate) fn pinned(&self, id: &[u8; 16]) -> bool {
        self.sections.contains_key(id)
    }
    /// Iterates pinned ids in byte order.
    pub(crate) fn trail_ids(&self) -> impl Iterator<Item = &[u8; 16]> {
        self.sections.keys()
    }
    /// Whether the listed key is trusted at this sequence, inclusively.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "consumed by the verifier, #13 V3/V5")
    )]
    pub(crate) fn trusted_at(&self, id: &[u8; 16], key: &[u8; 32], seq: u64) -> bool {
        self.sections
            .get(id)
            .and_then(|s| s.keys.iter().find(|k| &k.bytes == key))
            .is_some_and(|k| k.bound.is_none_or(|(through, _)| seq <= through))
    }
    /// Returns the key's trail-local revocation bound, if present.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "consumed by the verifier, #13 V3/V5")
    )]
    pub(crate) fn bound(&self, id: &[u8; 16], key: &[u8; 32]) -> Option<Bound> {
        self.sections
            .get(id)?
            .keys
            .iter()
            .find(|k| &k.bytes == key)?
            .bound
    }
    /// Returns the trail's pinned retirement head, if present.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "consumed by the verifier, #13 V3/V5")
    )]
    pub(crate) fn end(&self, id: &[u8; 16]) -> Option<Bound> {
        self.sections.get(id)?.ends.first().copied()
    }
}
impl TrustPolicyBuilder {
    /// Starts the first pinned trail section.
    pub fn trail(self, id: [u8; 16]) -> TrailTrust {
        TrailTrust {
            builder: self,
            current: Section::new(id, None),
        }
    }
    /// Validates all collected sections.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if no section exists or trust semantics fail.
    pub fn build(self) -> Result<TrustPolicy, AuditError> {
        validate(self.sections)
    }
}
impl TrailTrust {
    /// Lists an unbounded signing key for this trail.
    pub fn key(mut self, public_key: [u8; 32]) -> Self {
        self.current.keys.push(Key {
            bytes: public_key,
            bound: None,
            line: None,
        });
        self
    }
    /// Lists a signing key with an inclusive trail-local checkpoint bound.
    pub fn key_through(mut self, public_key: [u8; 32], seq: u64, hash: [u8; 32]) -> Self {
        self.current.keys.push(Key {
            bytes: public_key,
            bound: Some((seq, hash)),
            line: None,
        });
        self
    }
    /// Pins the retirement head from an external checkpoint, receipt or anchor.
    /// Calling this twice is rejected by `build`.
    pub fn end(mut self, seq: u64, hash: [u8; 32]) -> Self {
        self.current.ends.push((seq, hash));
        self
    }
    /// Finishes this section and starts the next pinned trail section.
    pub fn trail(mut self, id: [u8; 16]) -> TrailTrust {
        self.builder.sections.push(self.current);
        self.builder.trail(id)
    }
    /// Validates all sections and returns the policy.
    ///
    /// # Errors
    /// Returns `InvalidConfig` for duplicate trails, keys or retirement heads,
    /// or a key bounded in one section and unbounded in another.
    pub fn build(mut self) -> Result<TrustPolicy, AuditError> {
        self.builder.sections.push(self.current);
        self.builder.build()
    }
}
fn invalid(detail: impl Into<String>) -> AuditError {
    AuditError::new(AuditErrorKind::InvalidConfig, detail)
}
fn location(line: Option<usize>) -> String {
    line.map_or_else(String::new, |n| format!(" at line {n}"))
}
fn validate(sections: Vec<Section>) -> Result<TrustPolicy, AuditError> {
    if sections.is_empty() {
        return Err(invalid("trust policy requires a trail section"));
    }
    let mut trails = BTreeMap::new();
    let mut shared = BTreeMap::new();
    for section in sections {
        let trail = format!("trail {}{}", hex(&section.id), location(section.line));
        if let Some(previous) = trails.get(&section.id) {
            let previous: &Section = previous;
            return Err(invalid(format!(
                "duplicate {trail}; first section{}",
                location(previous.line)
            )));
        }
        if section.ends.len() > 1 {
            return Err(invalid(format!("repeated end for {trail}")));
        }
        let mut keys = BTreeMap::new();
        for key in &section.keys {
            let context = format!("key {}{} in {trail}", hex(&key.bytes), location(key.line));
            if let Some(previous) = keys.insert(key.bytes, key.line) {
                return Err(invalid(format!(
                    "duplicate {context}; first key{}",
                    location(previous)
                )));
            }
            if let Some((bounded, previous)) = shared.get(&key.bytes) {
                if *bounded != key.bound.is_some() {
                    return Err(invalid(format!(
                        "inconsistent through for {context}; also {previous}"
                    )));
                }
            } else {
                shared.insert(key.bytes, (key.bound.is_some(), context));
            }
        }
        trails.insert(section.id, section);
    }
    Ok(TrustPolicy { sections: trails })
}
fn parse(text: &str) -> Result<Vec<Section>, AuditError> {
    let mut sections: Vec<Section> = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        let bad = |rule: &str| invalid(format!("line {number}: {rule}"));
        let mut fields = line.split_ascii_whitespace();
        let Some(kind) = fields.next() else {
            continue;
        };
        if kind.starts_with('#') {
            continue;
        }
        if kind == "schema" {
            return Err(bad("schema pins arrive with #164 CP4"));
        }
        if kind != "trail" && kind != "ed25519" {
            return Err(bad("unknown line kind"));
        }
        let value = fields.next().ok_or_else(|| bad("missing id or key"))?;
        let mut bound = None;
        for field in fields {
            let Some((name, value)) = field.split_once('=') else {
                break;
            };
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
                break;
            }
            let expected = if kind == "trail" { "end" } else { "through" };
            if name != expected {
                return Err(bad("unknown option or option on wrong line kind"));
            }
            if bound.is_some() {
                return Err(bad("repeated option"));
            }
            bound = Some(
                parse_bound(value)
                    .ok_or_else(|| bad("bound requires decimal u64:blake3:<64 lowercase hex>"))?,
            );
        }
        if kind == "trail" {
            let id = parse_hex(value)
                .map_err(|_| bad("trail id requires 32 lowercase hex characters"))?;
            let mut section = Section::new(id, Some(number));
            section.ends.extend(bound);
            sections.push(section);
        } else {
            let key =
                parse_hex(value).map_err(|_| bad("key requires 64 lowercase hex characters"))?;
            let section = sections
                .last_mut()
                .ok_or_else(|| bad("key before first trail"))?;
            section.keys.push(Key {
                bytes: key,
                bound,
                line: Some(number),
            });
        }
    }
    Ok(sections)
}
fn parse_bound(value: &str) -> Option<Bound> {
    let (seq, hash) = value.split_once(":blake3:")?;
    if seq.is_empty() || !seq.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((seq.parse().ok()?, parse_hex(hash).ok()?))
}
#[cfg(test)]
#[path = "trust_tests.rs"]
mod tests;
