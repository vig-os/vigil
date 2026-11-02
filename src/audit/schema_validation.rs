//! Shared writer/verifier shape checks for ADR-0005 P5–P8.
use super::{
    AuditError, AuditErrorKind, Entry, FieldKind, RecordSchema, Value,
    attributes::{parse_block, render_block},
};
use std::collections::BTreeMap;

/// A shape failure never discloses the rejected content.
fn invalid() -> AuditError {
    AuditError::new(AuditErrorKind::InvalidEntry, "entry violates record schema")
}

/// Checks opaque operator references before any sink is opened.
pub(super) fn operator(
    schema: Option<&RecordSchema>,
    actor: &str,
    reason: &str,
) -> Result<(), AuditError> {
    if schema.is_some() {
        FieldKind::id().parse(actor)?;
        FieldKind::id().parse(reason)?;
    }
    Ok(())
}

/// Finds the closed action declaration and its attribute kinds.
fn declaration<'a>(
    schema: &'a RecordSchema,
    entry: &Entry,
) -> Result<(&'a super::schema::Action, BTreeMap<String, FieldKind>), AuditError> {
    let action = schema
        .actions
        .iter()
        .find(|a| a.name == entry.action)
        .ok_or_else(invalid)?;
    let kinds = action
        .fields
        .iter()
        .map(|(k, _, v)| (k.clone(), v.clone()))
        .collect();
    Ok((action, kinds))
}

/// Validates an ordinary decoded record's entry, including its canonical block.
/// CP4 can call this same path after resolving the block's pinned schema.
pub(super) fn validate(schema: &RecordSchema, entry: &Entry) -> Result<(), AuditError> {
    FieldKind::id().parse(&entry.actor)?;
    let (action, kinds) = declaration(schema, entry)?;
    action.object.parse(&entry.object)?;
    if entry.reason.is_some()
        || [&entry.before, &entry.after]
            .into_iter()
            .flatten()
            .any(|v| matches!(v, Value::Text(_)))
    {
        return Err(invalid());
    }
    let (digest, values) = parse_block(entry.details.as_deref().ok_or_else(invalid)?, &kinds)
        .map_err(|_| invalid())?;
    if digest != schema.digest()
        || action
            .fields
            .iter()
            .any(|(key, required, _)| *required && !values.contains_key(key))
    {
        return Err(invalid());
    }
    Ok(())
}

/// Refuses caller details and renders a checked block before directory locking.
pub(super) fn prepare(entry: &Entry, schema: Option<&RecordSchema>) -> Result<Entry, AuditError> {
    let Some(schema) = schema else {
        if !entry.attrs.is_empty() {
            return Err(invalid());
        }
        return Ok(entry.clone());
    };
    if entry.details.is_some() {
        return Err(invalid());
    }
    let (_, kinds) = declaration(schema, entry)?;
    let mut prepared = entry.clone();
    prepared.details = Some(
        render_block(
            &schema.digest(),
            &kinds,
            entry.attrs.iter().map(|(k, v)| (k.as_str(), v)),
        )
        .map_err(|_| invalid())?,
    );
    validate(schema, &prepared)?;
    prepared.attrs.clear();
    Ok(prepared)
}
