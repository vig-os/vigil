use std::{
    fmt,
    fs::File,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

/// A key-custody failure, containing no secret material.
/// The `Display` text is for people; it is not part of the stability promise. Do not parse it.
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
    ///
    /// # Errors
    ///
    /// Returns [`SignerError`] when the implementation cannot access its key
    /// or complete signing, for example if external key custody is unavailable.
    /// The [`KeyFileSigner`] implementation always succeeds.
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], SignerError>;
}

/// A verified file-backed Ed25519 seed (ADR-0005 decision 9).
/// The held signing key zeroizes on drop; Debug redacts secret material.
pub struct KeyFileSigner(ed25519_dalek::SigningKey);
impl fmt::Debug for KeyFileSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyFileSigner([REDACTED])")
    }
}
impl KeyFileSigner {
    /// Loads a regular seed file owned by the effective user with no group or
    /// other permission bits (ADR-0005 decision 9, amendment 7).
    /// Symlinks are followed; metadata checks use the opened descriptor.
    /// Surrounding ASCII whitespace is allowed. Non-regular files are refused
    /// either at open with an I/O error or after open as "not a regular file".
    ///
    /// **Use the secret seed file, never a public key or `.pub` file.** A public
    /// key silently derives a different signing key: compare [`Signer::public_key`]
    /// against the trusted `key_id`. Use separate keys for vigil and tessera.
    ///
    /// # Errors
    /// Returns [`SignerError`] on I/O, metadata policy violations, files larger
    /// than 1024 bytes, or invalid UTF-8/hex. No error includes secret bytes.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, SignerError> {
        let path = path.as_ref();
        let fd = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|e| file_error(path, e))?;
        let stat = rustix::fs::fstat(&fd).map_err(|e| file_error(path, e))?;
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile {
            return Err(SignerError::new(format!(
                "key file is not a regular file: {}",
                path.display()
            )));
        }
        #[allow(
            clippy::useless_conversion,
            reason = "mode_t is u16 on macOS and u32 on Linux"
        )]
        let mode = u32::from(stat.st_mode);
        check_key_metadata(path, mode, stat.st_uid, rustix::process::geteuid().as_raw())?;
        let mut file = File::from(fd);
        let mut bytes = zeroize::Zeroizing::new([0u8; 1025]);
        let mut length = 0;
        while length < bytes.len() {
            let read = match file.read(&mut bytes[length..]) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                result => result.map_err(|e| file_error(path, e))?,
            };
            if read == 0 {
                break;
            }
            length += read;
        }
        if length > 1024 {
            return Err(SignerError::new(format!(
                "key file too large: {}",
                path.display()
            )));
        }
        let text = std::str::from_utf8(&bytes[..length])
            .map_err(|_| SignerError::new("key file is not UTF-8"))?;
        parse_hex_seed(text).map(Self)
    }

    #[cfg(test)]
    pub(crate) fn from_hex(text: &str) -> Result<Self, SignerError> {
        parse_hex_seed(text).map(Self)
    }
}

pub(crate) fn check_key_metadata(
    path: &Path,
    mode: u32,
    uid: u32,
    euid: u32,
) -> Result<(), SignerError> {
    if mode & 0o077 != 0 {
        return Err(SignerError::new(format!(
            "key file has group or other permission bits: {} ({:o})",
            path.display(),
            mode & 0o7777
        )));
    }
    if uid != euid {
        return Err(SignerError::new(format!(
            "key file owned by uid {uid}, not the current user {euid}: {}",
            path.display()
        )));
    }
    Ok(())
}

pub(crate) fn parse_hex_seed(text: &str) -> Result<ed25519_dalek::SigningKey, SignerError> {
    let text = text.trim_ascii().as_bytes();
    if !text.is_ascii() {
        return Err(SignerError::new("seed contains non-hex characters"));
    }
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
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}
impl Signer for KeyFileSigner {
    /// Returns the raw public key for the held seed (ADR-0005 decision 9).
    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    /// Signs with pure Ed25519 (ADR-0005 decision 9); this implementation succeeds.
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], SignerError> {
        use ed25519_dalek::Signer as _;
        Ok(self.0.sign(message).to_bytes())
    }
}

fn file_error(path: &Path, error: impl fmt::Display) -> SignerError {
    SignerError::new(format!("key file I/O error: {}: {error}", path.display()))
}
fn create_key_file(path: &Path, mode: u32) -> Result<File, SignerError> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                SignerError::new(format!("key file exists: {}", path.display()))
            } else {
                file_error(path, e)
            }
        })
}
fn hex_line(bytes: &[u8; 32], output: &mut [u8; 65]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, byte) in bytes.iter().enumerate() {
        output[2 * i] = HEX[(byte >> 4) as usize];
        output[2 * i + 1] = HEX[(byte & 15) as usize];
    }
    output[64] = b'\n';
}

/// Generates a seed and returns its raw public key (ADR-0005 decision 9,
/// amendment 7). Both files are exclusively created before entropy or writes:
/// `path` with mode 0600 and the appended suffix `.pub` with mode 0644.
/// The process umask may narrow these modes. Files and their parent directory
/// are fsynced before success (decision 6).
///
/// On failure, only files created by this call are unlinked. Cleanup uses paths;
/// an attacker who can write the directory can race those unlinks. SIGKILL may
/// leave a short seed; incomplete seed hex is rejected by [`KeyFileSigner::load`].
/// Use separate keys for vigil and tessera (decision 9).
///
/// # Errors
/// Returns [`SignerError`] if either file exists, entropy fails, or any creation,
/// write or fsync fails. Cleanup is best effort if unlink itself fails.
pub fn keygen(path: impl AsRef<Path>) -> Result<[u8; 32], SignerError> {
    let path = path.as_ref();
    let mut pub_name = path.as_os_str().to_os_string();
    pub_name.push(".pub");
    let pub_path = Path::new(&pub_name);
    let mut seed_file = create_key_file(path, 0o600)?;
    let mut pub_file = match create_key_file(pub_path, 0o644) {
        Ok(file) => file,
        Err(error) => {
            let _ = std::fs::remove_file(path);
            return Err(error);
        }
    };
    let result = (|| {
        let mut seed = zeroize::Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *seed)
            .map_err(|e| SignerError::new(format!("key entropy failed: {e}")))?;
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public_key = key.verifying_key().to_bytes();
        let mut encoded = zeroize::Zeroizing::new([0u8; 65]);
        hex_line(&seed, &mut encoded);
        seed_file
            .write_all(&*encoded)
            .map_err(|e| file_error(path, e))?;
        hex_line(&public_key, &mut encoded);
        pub_file
            .write_all(&*encoded)
            .map_err(|e| file_error(pub_path, e))?;
        super::sink::sync_io(&seed_file, "keygen-seed").map_err(|e| file_error(path, e))?;
        super::sink::sync_io(&pub_file, "keygen-pub").map_err(|e| file_error(pub_path, e))?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let directory = File::open(parent).map_err(|e| file_error(parent, e))?;
        super::sink::sync_io(&directory, "keygen-dir").map_err(|e| file_error(parent, e))?;
        Ok(public_key)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(pub_path);
    }
    result
}

/// **Unstable:** enable `--cfg vigil_unstable` and pin `=0.N.M` before 1.0; pin `~1.N` from 1.0.
/// Applications only: library pins constrain every dependent to that minor.
///
/// Builds `vigil.audit.v1.checkpoint\0 || blake3(fields without tag 0x24)`.
/// The result is exactly 58 bytes; supply canonical fields, not JSON bytes.
pub fn checkpoint_message(unsigned_fields: &[u8]) -> Vec<u8> {
    let mut message = b"vigil.audit.v1.checkpoint\0".to_vec();
    message.extend(blake3::hash(unsigned_fields).as_bytes());
    message
}

/// **Unstable:** enable `--cfg vigil_unstable` and pin `=0.N.M` before 1.0; pin `~1.N` from 1.0.
/// Applications only: library pins constrain every dependent to that minor.
///
/// Checks a pure Ed25519 signature with strict canonical/small-order checks.
/// This validates a message signature only, not trust policy or trail history.
///
/// # Errors
///
/// Returns [`SignerError`] if the public key cannot be decoded or strict
/// Ed25519 verification rejects the signature for the supplied key and message,
/// including noncanonical signatures and small-order keys or signature points.
#[cfg_attr(
    not(any(test, vigil_unstable)),
    expect(dead_code, reason = "verification follows in #13")
)]
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
