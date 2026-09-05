//! SHA-256 hashing.

use sha2::{Digest, Sha256};

/// Computes a SHA-256 digest of the input.
///
/// Returns the 32-byte hash.
///
/// # Example
///
/// ```rust
/// use cryptkit::hash::sha256;
///
/// let hash = sha256(b"hello world");
/// assert_eq!(hash.len(), 32);
/// ```
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// Tests exercise failure paths and invariants directly; unwrap/expect,
// slicing, and panicking asserts are acceptable here — violations
// surface as test failures, not production panics.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = sha256(b"");
        let hex = hex::encode(hash);
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn deterministic() {
        let h1 = sha256(b"test");
        let h2 = sha256(b"test");
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_inputs_differ() {
        let h1 = sha256(b"abc");
        let h2 = sha256(b"abd");
        assert_ne!(h1, h2);
    }
}
