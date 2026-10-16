use std::io::{self, Write};
use vigil::audit::{AuditError, AuditErrorKind, Checkpoint, Receipt, SignerError};

pub(super) struct Failure(pub u8, pub String);
impl From<AuditError> for Failure {
    fn from(error: AuditError) -> Self {
        let code = match error.kind() {
            AuditErrorKind::Io | AuditErrorKind::InvalidConfig => 2,
            _ => 1,
        };
        Self(code, error.to_string())
    }
}
impl From<SignerError> for Failure {
    fn from(error: SignerError) -> Self {
        Self(1, format!("Signer: {error}"))
    }
}
impl From<io::Error> for Failure {
    fn from(error: io::Error) -> Self {
        Self(2, format!("Io: {error}"))
    }
}

#[derive(Default)]
pub(super) struct Output {
    lines: Vec<String>,
}
impl Output {
    pub(super) fn line(&mut self, line: impl Into<String>) {
        self.lines.push(line.into());
    }
    pub(super) fn receipt(&mut self, receipt: &Receipt) {
        self.line(format!("{} {}", receipt.seq(), receipt.hash_string()));
    }
    pub(super) fn checkpoint(&mut self, checkpoint: &Checkpoint) {
        self.line(checkpoint.line());
    }
    pub(super) fn checkpoint_receipt(&mut self, checkpoint: &Checkpoint) {
        self.line(format!(
            "{} blake3:{}",
            checkpoint.seq(),
            hex(&checkpoint.hash())
        ));
    }
    pub(super) fn flush(&self) -> Result<(), Failure> {
        let text = self
            .lines
            .iter()
            .map(|s| format!("{s}\n"))
            .collect::<String>();
        let mut stdout = io::stdout().lock();
        if let Err(error) = stdout
            .write_all(text.as_bytes())
            .and_then(|()| stdout.flush())
        {
            let _ = io::stderr().lock().write_all(text.as_bytes());
            return Err(error.into());
        }
        Ok(())
    }
}
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
