//! Validated schemas and their canonical, domain-separated identities.
use super::attributes::{token, validate_key};
use super::{AuditError, AuditErrorKind, FieldKind};

/// A validated per-trail record schema (ADR-0005 §20.4).
///
/// ```
/// use vigil::audit::{RecordSchema, FieldKind};
/// let schema = RecordSchema::builder("decisions")
///     .action("approve").required("tenant", FieldKind::id()).build()?;
/// assert_eq!(RecordSchema::parse(schema.text())?, schema);
/// # Ok::<(), vigil::audit::AuditError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordSchema {
    name: String,
    text: String,
}

#[derive(Clone, Debug)]
struct Action {
    name: String,
    object: FieldKind,
    fields: Vec<(String, bool, FieldKind)>,
}

/// Collects action declarations; validation happens at `build()`.
#[derive(Clone, Debug)]
#[must_use]
pub struct RecordSchemaBuilder {
    name: String,
    actions: Vec<Action>,
}

/// Declares the object kind and required or optional keys of the current action.
#[derive(Clone, Debug)]
#[must_use]
pub struct ActionFields {
    builder: RecordSchemaBuilder,
    current: Action,
}

fn invalid() -> AuditError {
    AuditError::new(AuditErrorKind::InvalidConfig, "invalid record schema")
}

impl RecordSchema {
    /// Starts a schema with a token name, checked at `build()`.
    pub fn builder(name: impl Into<String>) -> RecordSchemaBuilder {
        RecordSchemaBuilder {
            name: name.into(),
            actions: Vec::new(),
        }
    }

    /// Accepts only canonical schema text.
    ///
    /// # Errors
    /// Returns `InvalidConfig` for invalid declarations or non-canonical text.
    pub fn parse(text: &str) -> Result<Self, AuditError> {
        let mut lines = text.split('\n');
        let name = lines
            .next()
            .and_then(|l| l.strip_prefix("vigil.schema.v1 "))
            .ok_or_else(invalid)?;
        let mut builder = Self::builder(name);
        for line in lines {
            let parts: Vec<_> = line.split(' ').collect();
            match parts.as_slice() {
                ["action", name, object] => {
                    let kind = object.strip_prefix("object=").ok_or_else(invalid)?;
                    builder.actions.push(Action {
                        name: (*name).into(),
                        object: FieldKind::parse_schema(kind)?,
                        fields: Vec::new(),
                    });
                }
                ["field", key, presence, kind] if matches!(*presence, "required" | "optional") => {
                    builder
                        .actions
                        .last_mut()
                        .ok_or_else(invalid)?
                        .fields
                        .push((
                            (*key).into(),
                            *presence == "required",
                            FieldKind::parse_schema(kind)?,
                        ));
                }
                _ => return Err(invalid()),
            }
        }
        let schema = builder.build()?;
        if schema.text() != text {
            return Err(invalid());
        }
        Ok(schema)
    }

    /// The schema's token name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// The canonical UTF-8 text, with LF separators and no trailing LF.
    pub fn text(&self) -> &str {
        &self.text
    }
    /// BLAKE3 over `b"vigil.audit.v1.schema\0"` followed by the canonical text.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"vigil.audit.v1.schema\0");
        hasher.update(self.text.as_bytes());
        *hasher.finalize().as_bytes()
    }
    /// The digest spelled `blake3:<64 lowercase hex>`.
    pub fn digest_string(&self) -> String {
        super::digest_string(&self.digest())
    }
}

impl RecordSchemaBuilder {
    /// Declares an action and starts its field builder.
    pub fn action(self, action: impl Into<String>) -> ActionFields {
        ActionFields {
            builder: self,
            current: Action {
                name: action.into(),
                object: FieldKind::id(),
                fields: Vec::new(),
            },
        }
    }
    /// Validates all declarations.
    ///
    /// # Errors
    /// Returns `InvalidConfig` for an invalid name, no actions, duplicate actions
    /// or keys, reserved actions or keys, or an invalid object or field kind.
    pub fn build(mut self) -> Result<RecordSchema, AuditError> {
        if !token(&self.name) || self.actions.is_empty() {
            return Err(invalid());
        }
        self.actions.sort_by(|a, b| a.name.cmp(&b.name));
        if self.actions.windows(2).any(|a| a[0].name == a[1].name) {
            return Err(invalid());
        }
        let mut text = format!("vigil.schema.v1 {}", self.name);
        for action in &mut self.actions {
            if !(1..=128).contains(&action.name.len())
                || !action
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
                || action.name.starts_with("vigil.audit.")
            {
                return Err(invalid());
            }
            action.object.validate()?;
            text.push_str(&format!(
                "\naction {} object={}",
                action.name,
                action.object.schema_text()
            ));
            action.fields.sort_by(|a, b| a.0.cmp(&b.0));
            if action.fields.windows(2).any(|f| f[0].0 == f[1].0) {
                return Err(invalid());
            }
            for (key, required, kind) in &action.fields {
                validate_key(key)?;
                kind.validate()?;
                text.push_str(&format!(
                    "\nfield {key} {} {}",
                    if *required { "required" } else { "optional" },
                    kind.schema_text()
                ));
            }
        }
        Ok(RecordSchema {
            name: self.name,
            text,
        })
    }
}

impl ActionFields {
    /// Sets the kind of `audit.object` (default: `FieldKind::id()`).
    pub fn object(mut self, kind: FieldKind) -> Self {
        self.current.object = kind;
        self
    }
    /// Declares a required key and its kind.
    pub fn required(mut self, key: impl Into<String>, kind: FieldKind) -> Self {
        self.current.fields.push((key.into(), true, kind));
        self
    }
    /// Declares an optional key and its kind.
    pub fn optional(mut self, key: impl Into<String>, kind: FieldKind) -> Self {
        self.current.fields.push((key.into(), false, kind));
        self
    }
    fn finish(mut self) -> RecordSchemaBuilder {
        self.builder.actions.push(self.current);
        self.builder
    }
    /// Declares the next action.
    pub fn action(self, action: impl Into<String>) -> ActionFields {
        self.finish().action(action)
    }
    /// Validates all actions and builds the schema.
    ///
    /// # Errors
    /// Returns `InvalidConfig` for any invalid declaration; see
    /// [`RecordSchemaBuilder::build`].
    pub fn build(self) -> Result<RecordSchema, AuditError> {
        self.finish().build()
    }
}

#[cfg(test)]
#[path = "schema_tests.rs"]
mod tests;
