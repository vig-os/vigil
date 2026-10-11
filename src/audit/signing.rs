use std::fmt;

/// A key-custody failure, containing no secret material.
#[derive(Debug)]
pub struct SignerError(String);
impl SignerError {
    /// Creates an error for an application-provided signer.
    pub fn new(detail: impl Into<String>) -> Self {
        Self(detail.into())
    }
}
impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for SignerError {}

/// Pure Ed25519 signing, implemented by software or external key custody.
/// The durable writer calls this inside its directory lock. A slow signer
/// therefore blocks all writers. New required methods cannot be added in 1.x.
pub trait Signer: Send + Sync + fmt::Debug {
    /// Returns the raw 32-byte Ed25519 public key.
    fn public_key(&self) -> [u8; 32];
    /// Signs the exact message using pure Ed25519 (not prehashed Ed25519ph).
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], SignerError>;
}

/// A parsed 32-byte seed, zeroized on drop by ed25519-dalek.
/// No file is opened: ownership and permission checks belong to #11's
/// KeyFileSigner. Use separate keys for audit trails and tessera products.
pub struct KeySeed(ed25519_dalek::SigningKey);
impl fmt::Debug for KeySeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeySeed([REDACTED])")
    }
}
impl KeySeed {
    /// Parses 64 hex characters with surrounding whitespace allowed, matching
    /// tessera's key files. Uppercase hex is accepted for seeds only; wire
    /// hashes and public keys are always written in lowercase.
    ///
    /// **Supply the secret seed, never the public key or `.pub` file.** Both
    /// are 32 bytes written as 64 hex characters, so this parser cannot tell
    /// them apart. A public key is accepted as a seed and silently derives a
    /// different signing key. Check the derived public key against the trusted
    /// key id before use. The v1 key-file format allows no header or prefix.
    pub fn parse(text: &str) -> Result<Self, SignerError> {
        let text = text.trim().as_bytes();
        if text.len() != 64 {
            return Err(SignerError::new(
                "seed must contain exactly 64 hex characters",
            ));
        }
        let mut seed = zeroize::Zeroizing::new([0; 32]);
        for (byte, pair) in seed.iter_mut().zip(text.chunks_exact(2)) {
            let digit = |b: u8| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            };
            let (Some(high), Some(low)) = (digit(pair[0]), digit(pair[1])) else {
                return Err(SignerError::new("seed contains non-hex characters"));
            };
            *byte = (high << 4) | low;
        }
        let key = Self(ed25519_dalek::SigningKey::from_bytes(&seed));
        Ok(key)
    }
}
impl Signer for KeySeed {
    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], SignerError> {
        use ed25519_dalek::Signer as _;
        Ok(self.0.sign(message).to_bytes())
    }
}

/// Builds `vigil.audit.v1.checkpoint\0 || blake3(fields without tag 0x24)`.
/// The result is exactly 58 bytes; supply canonical fields, not JSON bytes.
pub fn checkpoint_message(unsigned_fields: &[u8]) -> Vec<u8> {
    let mut message = b"vigil.audit.v1.checkpoint\0".to_vec();
    message.extend(blake3::hash(unsigned_fields).as_bytes());
    message
}

/// Checks a pure Ed25519 signature with strict canonical/small-order checks.
/// This validates a message signature only, not trust policy or trail history.
pub fn verify_signature(
    key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), SignerError> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(key)
        .map_err(|_| SignerError::new("invalid Ed25519 public key"))?;
    key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature))
        .map_err(|_| SignerError::new("invalid Ed25519 signature"))
}
