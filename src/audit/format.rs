use super::{AuditError, AuditErrorKind};
use validation::valid_text;

#[path = "validation.rs"]
pub(super) mod validation;
#[cfg_attr(not(test), allow(dead_code))] // B2/B3 consume this production boundary.
#[path = "writer.rs"]
mod writer;
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use writer::request;

/// A before/after value. Use digests for personal or large values; retain the
/// referenced data separately in the application's own store.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Value {
    /// UTF-8 text, without normalization.
    Text(String),
    /// The raw BLAKE3 digest of a value.
    Digest([u8; 32]),
}
impl Value {
    /// Hashes arbitrary bytes, without the record domain prefix.
    pub fn digest_of(bytes: &[u8]) -> Self {
        Self::Digest(*blake3::hash(bytes).as_bytes())
    }
}

/// One action, attributed by the application to an authenticated actor.
/// Validation occurs when constructing a record, before any bytes are emitted.
#[derive(Clone, Debug)]
pub struct Entry {
    actor: String,
    pub(super) action: String,
    pub(super) object: String,
    reason: Option<String>,
    before: Option<Value>,
    after: Option<Value>,
    pub(super) details: Option<String>,
}
impl Entry {
    /// Creates an action with its actor and regulated object identifier.
    pub fn new(
        actor: impl Into<String>,
        action: impl Into<String>,
        object: impl Into<String>,
    ) -> Self {
        Self {
            actor: actor.into(),
            action: action.into(),
            object: object.into(),
            reason: None,
            before: None,
            after: None,
            details: None,
        }
    }
    /// Sets the reason for the change.
    pub fn reason(mut self, value: impl Into<String>) -> Self {
        self.reason = Some(value.into());
        self
    }
    /// Sets the prior value (replaces any previous value or digest).
    pub fn before(mut self, value: Value) -> Self {
        self.before = Some(value);
        self
    }
    /// Sets the new value (replaces any previous value or digest).
    pub fn after(mut self, value: Value) -> Self {
        self.after = Some(value);
        self
    }
    /// Sets additional authenticated text, such as application JSON.
    pub fn details(mut self, value: impl Into<String>) -> Self {
        self.details = Some(value.into());
        self
    }
    fn validate(&self) -> Result<(), AuditError> {
        for text in [
            Some(&self.actor),
            Some(&self.action),
            Some(&self.object),
            self.reason.as_ref(),
            self.details.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            valid_text(text)?;
        }
        for value in [&self.before, &self.after].into_iter().flatten() {
            if let Value::Text(text) = value {
                valid_text(text)?;
            }
        }
        Ok(())
    }
    fn fields(&self) -> Vec<(u8, Vec<u8>)> {
        let mut fields = Vec::new();
        for (tag, text) in [
            (0x10, Some(&self.actor)),
            (0x11, Some(&self.action)),
            (0x12, Some(&self.object)),
            (0x13, self.reason.as_ref()),
            (0x18, self.details.as_ref()),
        ] {
            if let Some(text) = text {
                fields.push((tag, text.as_bytes().to_vec()));
            }
        }
        for (tag, value) in [(0x14, &self.before), (0x16, &self.after)] {
            match value {
                Some(Value::Text(text)) => {
                    fields.push((tag, text.as_bytes().to_vec()));
                }
                Some(Value::Digest(hash)) => fields.push((tag + 1, hash.to_vec())),
                None => {}
            }
        }
        fields.sort_by_key(|(tag, _)| *tag);
        fields
    }
}
/// **Unstable:** enable `--cfg vigil_unstable` and pin vigil with `~1.N`.
/// Applications only: library pins constrain every dependent to that minor.
///
/// Checkpoint commitment to all leaves preceding its own sequence number.
#[derive(Clone, Debug)]
pub struct CheckpointFields {
    pub(super) size: u64,
    pub(super) root: [u8; 32],
    pub(super) peaks: Vec<[u8; 32]>,
    pub(super) key: [u8; 32],
    signature: [u8; 64],
}
impl CheckpointFields {
    /// **Unstable:** enable `--cfg vigil_unstable` and pin vigil with `~1.N`.
    /// Applications only: library pins constrain every dependent to that minor.
    ///
    /// Creates fields; peak count must equal the population count of `size`.
    /// The caller supplies the MMR root and left-to-right peaks. Signature
    /// verification and consistency with trail history belong to #13.
    ///
    /// # Errors
    ///
    /// Returns [`AuditErrorKind::InvalidConfig`] if the number of peaks differs
    /// from the population count of `size`.
    pub fn new(
        size: u64,
        root: [u8; 32],
        peaks: Vec<[u8; 32]>,
        key: [u8; 32],
        signature: [u8; 64],
    ) -> Result<Self, AuditError> {
        if peaks.len() != size.count_ones() as usize {
            return Err(AuditError::new(
                AuditErrorKind::InvalidConfig,
                "MMR peak count differs from popcount(size)",
            ));
        }
        Ok(Self {
            size,
            root,
            peaks,
            key,
            signature,
        })
    }
    fn fields(&self) -> Vec<(u8, Vec<u8>)> {
        let mut fields = vec![
            (0x20, self.size.to_be_bytes().to_vec()),
            (0x21, self.root.to_vec()),
        ];
        if self.size != 0 {
            fields.push((0x22, self.peaks.concat()));
        }
        fields.extend([(0x23, self.key.to_vec()), (0x24, self.signature.to_vec())]);
        fields
    }
}

#[derive(Clone, Debug)]
pub(super) enum Kind {
    Entry(Entry),
    Checkpoint(CheckpointFields),
}

/// **Unstable:** enable `--cfg vigil_unstable` and pin vigil with `~1.N`.
/// Applications only: library pins constrain every dependent to that minor.
///
/// Context supplied by a writer under its lock; times are nanoseconds since epoch.
#[derive(Clone, Debug)]
pub struct RecordContext {
    pub(super) trail: [u8; 16],
    pub(super) seq: u64,
    pub(super) time: u64,
    service: String,
    host: Option<String>,
    pub(super) repaired: Option<[u8; 32]>,
    pub(super) previous: [u8; 32],
}
impl RecordContext {
    /// **Unstable:** enable `--cfg vigil_unstable` and pin vigil with `~1.N`.
    /// Applications only: library pins constrain every dependent to that minor.
    ///
    /// Sets trail identity, order, timestamp, service and previous chain hash.
    pub fn new(
        trail: [u8; 16],
        seq: u64,
        time: u64,
        service: impl Into<String>,
        previous: [u8; 32],
    ) -> Self {
        Self {
            trail,
            seq,
            time,
            service: service.into(),
            host: None,
            repaired: None,
            previous,
        }
    }
    /// **Unstable:** enable `--cfg vigil_unstable` and pin vigil with `~1.N`.
    /// Applications only: library pins constrain every dependent to that minor.
    ///
    /// Attests a torn-tail gap repaired by the writer, including repair newlines.
    /// Supply BLAKE3 of `b"vigil.audit.v1.repaired\0"` followed by the gap bytes.
    /// Only the first record or checkpoint after a repair carries this digest;
    /// applications must not derive it from an entry. Recovery checks belong to #11.
    pub fn repaired(mut self, digest: [u8; 32]) -> Self {
        self.repaired = Some(digest);
        self
    }
    /// **Unstable:** enable `--cfg vigil_unstable` and pin vigil with `~1.N`.
    /// Applications only: library pins constrain every dependent to that minor.
    ///
    /// Adds the authenticated host name when present in the writer's resource.
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }
}

/// **Unstable:** enable `--cfg vigil_unstable` and pin vigil with `~1.N`.
/// Applications only: library pins constrain every dependent to that minor.
///
/// A validated v1 record with explicit format context. This is an I/O-free
/// building block: the future trail writer supplies time inside its lock.
#[derive(Clone, Debug)]
pub struct Record {
    pub(super) context: RecordContext,
    pub(super) kind: Kind,
}
impl Record {
    /// **Unstable:** enable `--cfg vigil_unstable` and pin vigil with `~1.N`.
    /// Applications only: library pins constrain every dependent to that minor.
    ///
    /// Builds a record. `previous` must be the genesis hash at sequence zero,
    /// or the preceding record hash; the writer is responsible for that link.
    ///
    /// # Errors
    ///
    /// Returns [`AuditErrorKind::InvalidConfig`] if the sequence exceeds
    /// `i64::MAX` (the OTLP int64 bound), or [`AuditErrorKind::InvalidEntry`]
    /// if any supplied text (including
    /// service, host, or before/after text) is empty or contains NUL, or the
    /// action starts with the reserved `vigil.audit.` prefix, or
    /// [`AuditErrorKind::TooLarge`] if a canonical field exceeds `u32::MAX` bytes.
    pub fn new(context: RecordContext, entry: Entry) -> Result<Self, AuditError> {
        if entry.action.starts_with("vigil.audit.") {
            return Err(AuditError::new(
                AuditErrorKind::InvalidEntry,
                "reserved action prefix",
            ));
        }
        Self::new_internal(context, entry)
    }
    /// Shared internal construction path for reserved actions and decoding.
    pub(crate) fn new_internal(context: RecordContext, entry: Entry) -> Result<Self, AuditError> {
        entry.validate()?;
        Self::build(context, Kind::Entry(entry))
    }
    /// **Unstable:** enable `--cfg vigil_unstable` and pin vigil with `~1.N`.
    /// Applications only: library pins constrain every dependent to that minor.
    ///
    /// Builds a checkpoint. MMR size counts records preceding this checkpoint,
    /// while sequence numbers can skip lost records at a declared resume gap.
    /// Size must not exceed sequence; equality holds before any resume gap.
    /// Zero size is allowed only at seq 0: every later checkpoint includes
    /// the creation checkpoint as a leaf (ADR-0005 decisions 7 and 8).
    /// Checking the exact count and the gap declaration requires trail history (#13).
    ///
    /// # Errors
    ///
    /// Returns [`AuditErrorKind::InvalidConfig`] if MMR size exceeds the
    /// sequence number, is zero at a nonzero sequence, or either exceeds `i64::MAX`,
    /// [`AuditErrorKind::InvalidEntry`] if service or host is
    /// empty or contains NUL, or [`AuditErrorKind::TooLarge`] if a canonical
    /// field exceeds `u32::MAX` bytes.
    pub fn checkpoint(
        context: RecordContext,
        fields: CheckpointFields,
    ) -> Result<Self, AuditError> {
        validation::checkpoint_count(context.seq, fields.size)?;
        Self::build(context, Kind::Checkpoint(fields))
    }
    fn build(context: RecordContext, kind: Kind) -> Result<Self, AuditError> {
        if context.seq > i64::MAX as u64 {
            return Err(AuditError::new(
                AuditErrorKind::InvalidConfig,
                "sequence exceeds OTLP int64",
            ));
        }
        valid_text(&context.service)?;
        if let Some(host) = &context.host {
            valid_text(host)?;
        }
        let result = Self { context, kind };
        // Every tag length is u32. The sink checks the smaller OTLP line
        // limit (#11) after serialization with the shared OTLP encoder.
        for (_, bytes) in result.fields() {
            if u32::try_from(bytes.len()).is_err() {
                return Err(AuditError::new(
                    AuditErrorKind::TooLarge,
                    "canonical field exceeds u32 length",
                ));
            }
        }
        Ok(result)
    }
    fn fields(&self) -> Vec<(u8, Vec<u8>)> {
        let mut fields = vec![
            (1, self.context.trail.to_vec()),
            (2, self.context.seq.to_be_bytes().to_vec()),
            (3, self.context.time.to_be_bytes().to_vec()),
            (
                4,
                vec![match self.kind {
                    Kind::Entry(_) => 1,
                    Kind::Checkpoint(_) => 2,
                }],
            ),
            (5, self.context.service.as_bytes().to_vec()),
        ];
        if let Some(host) = &self.context.host {
            fields.push((6, host.as_bytes().to_vec()));
        }
        if let Some(repaired) = self.context.repaired {
            fields.push((7, repaired.to_vec()));
        }
        match &self.kind {
            // Entry validation is completed by new; fields cannot change.
            Kind::Entry(entry) => fields.extend(entry.fields()),
            Kind::Checkpoint(cp) => fields.extend(cp.fields()),
        }
        fields.push((0x7f, self.context.previous.to_vec()));
        fields
    }
    /// **Unstable:** enable `--cfg vigil_unstable` and pin vigil with `~1.N`.
    /// Applications only: library pins constrain every dependent to that minor.
    ///
    /// Returns canonical tag + u32 big-endian length + value bytes.
    /// Optional fields are omitted and tags always ascend.
    pub fn canonical(&self) -> Vec<u8> {
        encode(self.fields(), false)
    }
    /// **Unstable:** enable `--cfg vigil_unstable` and pin vigil with `~1.N`.
    /// Applications only: library pins constrain every dependent to that minor.
    ///
    /// Returns the domain-separated BLAKE3 record hash, including a
    /// checkpoint's signature when present.
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"vigil.audit.v1.record\0");
        hasher.update(&self.canonical());
        *hasher.finalize().as_bytes()
    }
    /// **Unstable:** enable `--cfg vigil_unstable` and pin vigil with `~1.N`.
    /// Applications only: library pins constrain every dependent to that minor.
    ///
    /// Returns the signing message for a checkpoint, omitting only tag 0x24.
    /// An ordinary action has no checkpoint signing message.
    pub fn signing_message(&self) -> Option<Vec<u8>> {
        match self.kind {
            Kind::Entry(_) => None,
            Kind::Checkpoint(_) => Some(super::checkpoint_message(&encode(self.fields(), true))),
        }
    }
    /// **Unstable:** enable `--cfg vigil_unstable` and pin vigil with `~1.N`.
    /// Applications only: library pins constrain every dependent to that minor.
    ///
    /// Computes the sequence-zero previous hash for a trail id.
    pub fn genesis(trail: &[u8; 16]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"vigil.audit.v1.genesis\0");
        h.update(trail);
        *h.finalize().as_bytes()
    }
}
fn encode(fields: Vec<(u8, Vec<u8>)>, omit_signature: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (tag, value) in fields {
        if omit_signature && tag == 0x24 {
            continue;
        }
        bytes.push(tag);
        bytes.extend((value.len() as u32).to_be_bytes());
        bytes.extend(value);
    }
    bytes
}

#[path = "codec.rs"]
mod codec;
pub use codec::Checkpoint;

#[cfg(test)]
#[path = "roundtrip_tests.rs"]
pub(super) mod roundtrip_tests;
