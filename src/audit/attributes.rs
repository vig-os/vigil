//! Typed attribute shapes and the canonical details block (ADR-0005 §20.3).
use super::{AuditError, AuditErrorKind, hex, parse_hex};
use std::collections::BTreeMap;

/// The kind of one typed attribute. Arguments are validated when a schema is built.
///
/// ```
/// use vigil::audit::FieldKind;
/// let verdict = FieldKind::one_of(["approved", "denied"]);
/// let commitment = FieldKind::digest("sha256");
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldKind(Kind);

#[derive(Clone, Debug, PartialEq, Eq)]
enum Kind {
    Id,
    Token,
    Enum(Vec<String>),
    Int(i64, i64),
    Digest(String),
}

impl FieldKind {
    /// An opaque identifier: 1–128 bytes of `[A-Za-z0-9._:-]`.
    pub fn id() -> Self {
        Self(Kind::Id)
    }
    /// A token: 1–64 bytes of `[a-z0-9._-]`.
    pub fn token() -> Self {
        Self(Kind::Token)
    }
    /// A closed set of 1–64 distinct tokens, sorted into canonical byte order.
    pub fn one_of<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut values: Vec<String> = values.into_iter().map(Into::into).collect();
        values.sort();
        Self(Kind::Enum(values))
    }
    /// An inclusive signed integer range. Schema construction checks `min <= max`.
    pub fn int(min: i64, max: i64) -> Self {
        Self(Kind::Int(min, max))
    }
    /// A 32-byte digest with a schema-supplied algorithm label.
    /// Labels contain 1–16 bytes of `[a-z0-9-]`, beginning with a letter.
    pub fn digest(algorithm: impl Into<String>) -> Self {
        Self(Kind::Digest(algorithm.into()))
    }

    pub(super) fn validate(&self) -> Result<(), AuditError> {
        let valid = match &self.0 {
            Kind::Id | Kind::Token => true,
            Kind::Enum(values) => {
                (1..=64).contains(&values.len())
                    && values.iter().all(|v| token(v))
                    && values.windows(2).all(|v| v[0] < v[1])
            }
            Kind::Int(min, max) => min <= max,
            Kind::Digest(alg) => {
                (1..=16).contains(&alg.len())
                    && alg.as_bytes()[0].is_ascii_lowercase()
                    && alg
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            }
        };
        if valid {
            Ok(())
        } else {
            Err(invalid(AuditErrorKind::InvalidConfig))
        }
    }

    pub(super) fn schema_text(&self) -> String {
        match &self.0 {
            Kind::Id => "id".into(),
            Kind::Token => "token".into(),
            Kind::Enum(values) => format!("enum:{}", values.join(",")),
            Kind::Int(min, max) => format!("int:{min}:{max}"),
            Kind::Digest(alg) => format!("digest:{alg}"),
        }
    }

    pub(super) fn parse_schema(text: &str) -> Result<Self, AuditError> {
        let bad = || invalid(AuditErrorKind::InvalidConfig);
        let kind = if text == "id" {
            Self::id()
        } else if text == "token" {
            Self::token()
        } else if let Some(values) = text.strip_prefix("enum:") {
            Self::one_of(values.split(','))
        } else if let Some(range) = text.strip_prefix("int:") {
            let (min, max) = range.split_once(':').ok_or_else(bad)?;
            Self::int(
                min.parse().map_err(|_| bad())?,
                max.parse().map_err(|_| bad())?,
            )
        } else if let Some(alg) = text.strip_prefix("digest:") {
            Self::digest(alg)
        } else {
            return Err(bad());
        };
        kind.validate()?;
        Ok(kind)
    }

    fn render(&self, value: &AttrValue) -> Result<String, AuditError> {
        self.validate()?;
        let text = match (&self.0, value) {
            (Kind::Id, AttrValue::Id(v))
                if (1..=128).contains(&v.len())
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b)) =>
            {
                v.clone()
            }
            (Kind::Token, AttrValue::Token(v)) if token(v) => v.clone(),
            (Kind::Enum(values), AttrValue::Token(v)) if values.contains(v) => v.clone(),
            (Kind::Int(min, max), AttrValue::Int(v)) if (min..=max).contains(&v) => v.to_string(),
            (Kind::Digest(alg), AttrValue::Digest(v)) => format!("{alg}:{}", hex(v)),
            _ => return Err(invalid(AuditErrorKind::InvalidEntry)),
        };
        Ok(text)
    }

    pub(super) fn parse(&self, text: &str) -> Result<AttrValue, AuditError> {
        let value = match &self.0 {
            Kind::Id => AttrValue::Id(text.into()),
            Kind::Token | Kind::Enum(_) => AttrValue::Token(text.into()),
            Kind::Int(_, _) => AttrValue::Int(
                text.parse()
                    .map_err(|_| invalid(AuditErrorKind::InvalidEntry))?,
            ),
            Kind::Digest(alg) => AttrValue::Digest(parse_hex(
                text.strip_prefix(&format!("{alg}:"))
                    .ok_or_else(|| invalid(AuditErrorKind::InvalidEntry))?,
            )?),
        };
        if self.render(&value)? != text {
            return Err(invalid(AuditErrorKind::InvalidEntry));
        }
        Ok(value)
    }
}

/// One typed attribute value; a closed enum value uses [`AttrValue::Token`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttrValue {
    /// An opaque identifier, checked against the declared kind.
    Id(String),
    /// A token or a member of a declared closed enum.
    Token(String),
    /// A signed integer, checked against the declared inclusive range.
    Int(i64),
    /// Exactly 32 digest bytes. The algorithm label comes from the schema.
    Digest([u8; 32]),
}

fn invalid(kind: AuditErrorKind) -> AuditError {
    AuditError::new(kind, "invalid typed attribute kind, key, value or block")
}
pub(super) fn token(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

/// Shared P2 validator; schema construction maps failures to InvalidConfig.
pub(super) fn validate_key(key: &str) -> Result<(), AuditError> {
    if !(1..=64).contains(&key.len())
        || !key.as_bytes()[0].is_ascii_lowercase()
        || !key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.".contains(&b))
        || key.starts_with("vigil.")
    {
        return Err(invalid(AuditErrorKind::InvalidConfig));
    }
    Ok(())
}

/// Renders independently of insertion order; duplicate keys are always refused.
pub(super) fn render_block<'a>(
    digest: &[u8; 32],
    kinds: &BTreeMap<String, FieldKind>,
    values: impl IntoIterator<Item = (&'a str, &'a AttrValue)>,
) -> Result<String, AuditError> {
    let mut lines = BTreeMap::new();
    for (key, value) in values {
        validate_key(key)?;
        let kind = kinds
            .get(key)
            .ok_or_else(|| invalid(AuditErrorKind::InvalidEntry))?;
        if lines.insert(key, kind.render(value)?).is_some() {
            return Err(invalid(AuditErrorKind::InvalidEntry));
        }
    }
    let mut text = format!("vigil.attrs.v1 blake3:{}", hex(digest));
    for (key, value) in lines {
        text.push_str(&format!("\n{key}={value}"));
    }
    Ok(text)
}

/// Parses only canonical blocks, using declared kinds for every value.
pub(super) fn parse_block(
    text: &str,
    kinds: &BTreeMap<String, FieldKind>,
) -> Result<([u8; 32], BTreeMap<String, AttrValue>), AuditError> {
    let mut lines = text.split('\n');
    let header = lines
        .next()
        .and_then(|s| s.strip_prefix("vigil.attrs.v1 blake3:"))
        .ok_or_else(|| invalid(AuditErrorKind::InvalidEntry))?;
    let digest = parse_hex(header)?;
    let mut values = BTreeMap::new();
    for line in lines {
        let (key, text) = line
            .split_once('=')
            .ok_or_else(|| invalid(AuditErrorKind::InvalidEntry))?;
        validate_key(key)?;
        let kind = kinds
            .get(key)
            .ok_or_else(|| invalid(AuditErrorKind::InvalidEntry))?;
        if values.insert(key.to_owned(), kind.parse(text)?).is_some() {
            return Err(invalid(AuditErrorKind::InvalidEntry));
        }
    }
    if render_block(&digest, kinds, values.iter().map(|(k, v)| (k.as_str(), v)))? != text {
        return Err(invalid(AuditErrorKind::InvalidEntry));
    }
    Ok((digest, values))
}

#[cfg(test)]
#[path = "attribute_tests.rs"]
mod tests;
