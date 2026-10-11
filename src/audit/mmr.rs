use super::{AuditError, AuditErrorKind, digest_string};

/// Trail-wide Merkle mountain range, compatible with tessera's construction.
/// Peaks are ordered left to right; no tessera dependency is used.
#[derive(Clone, Debug, Default)]
pub struct Mmr {
    size: u64,
    peaks: Vec<[u8; 32]>,
}
impl Mmr {
    /// Starts an empty MMR whose root is BLAKE3 of empty input.
    pub fn new() -> Self {
        Self::default()
    }
    /// Restores peaks; their heights are the set bits of size, high to low.
    /// This checks shape only: callers must authenticate the checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`AuditErrorKind::InvalidConfig`] if peak count differs from
    /// the population count of `size`.
    pub fn from_peaks(size: u64, peaks: Vec<[u8; 32]>) -> Result<Self, AuditError> {
        if peaks.len() != size.count_ones() as usize {
            return Err(AuditError::new(
                AuditErrorKind::InvalidConfig,
                "MMR peak count differs from popcount(size)",
            ));
        }
        Ok(Self { size, peaks })
    }
    /// Appends a record hash (checkpoints are leaves too). At u64::MAX leaves,
    /// returns InvalidConfig without changing state.
    ///
    /// # Errors
    ///
    /// Returns [`AuditErrorKind::InvalidConfig`] if the leaf count would
    /// overflow `u64`, or a peak needed for merging is missing. The latter
    /// cannot occur for state constructed through this type's public API.
    pub fn push(&mut self, hash: [u8; 32]) -> Result<(), AuditError> {
        let next = self
            .size
            .checked_add(1)
            .ok_or_else(|| AuditError::new(AuditErrorKind::InvalidConfig, "MMR size overflow"))?;
        let mut h = blake3::Hasher::new();
        h.update(&[0]);
        h.update(digest_string(&hash).as_bytes());
        let mut leaf = *h.finalize().as_bytes();
        for _ in 0..self.size.trailing_ones() {
            let left = self.peaks.pop().ok_or_else(|| {
                AuditError::new(AuditErrorKind::InvalidConfig, "missing MMR peak")
            })?;
            leaf = node(&left, &leaf);
        }
        self.peaks.push(leaf);
        self.size = next;
        Ok(())
    }
    /// Returns the number of leaves.
    pub fn size(&self) -> u64 {
        self.size
    }
    /// Returns left-to-right peaks for a checkpoint.
    pub fn peaks(&self) -> &[[u8; 32]] {
        &self.peaks
    }
    /// Bags peaks right to left, using the same node domain as tree nodes.
    pub fn root(&self) -> [u8; 32] {
        let mut peaks = self.peaks.iter().rev();
        let Some(&last) = peaks.next() else {
            return *blake3::hash(b"").as_bytes();
        };
        peaks.fold(last, |right, left| node(left, &right))
    }
}
fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[1]);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}
