//! Secure random byte generation.

use rand::RngCore;

/// Fills the provided buffer with cryptographically secure random bytes.
///
/// Uses the OS entropy source via `rand::thread_rng()`.
///
/// # Requirements
/// REQ-CK-004, REQ-CK-105
///
/// # Example
///
/// ```rust
/// use cryptkit::random::secure_random_bytes;
///
/// let mut buf = [0u8; 32];
/// secure_random_bytes(&mut buf);
/// // buf is now filled with random bytes
/// ```
pub fn secure_random_bytes(buf: &mut [u8]) {
    rand::thread_rng().fill_bytes(buf);
}

/// Generates a random byte vector of the specified length.
///
/// # Example
///
/// ```rust
/// use cryptkit::random::random_bytes;
///
/// let bytes = random_bytes(16);
/// assert_eq!(bytes.len(), 16);
/// ```
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    secure_random_bytes(&mut buf);
    buf
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
    fn fills_buffer() {
        let mut buf = [0u8; 64];
        secure_random_bytes(&mut buf);
        // Statistically, not all bytes will be zero
        assert_ne!(buf, [0u8; 64]);
    }

    #[test]
    fn random_bytes_length() {
        let bytes = random_bytes(42);
        assert_eq!(bytes.len(), 42);
    }

    #[test]
    fn two_calls_differ() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        secure_random_bytes(&mut a);
        secure_random_bytes(&mut b);
        assert_ne!(a, b);
    }
}
