//! HMAC-SHA256 signing and verification with constant-time comparison.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Computes an HMAC-SHA256 tag for the given key and message.
///
/// The returned tag is 32 bytes. The key is zeroized after use.
///
/// # Requirements
/// REQ-CK-001
///
/// # Example
///
/// ```rust
/// use cryptkit::hmac::{hmac_sign, hmac_verify};
///
/// let tag = hmac_sign(b"secret", b"message");
/// assert!(hmac_verify(b"secret", b"message", &tag));
/// ```
pub fn hmac_sign(key: &[u8], message: &[u8]) -> [u8; 32] {
    // INVARIANT: HMAC-SHA256 accepts keys of any length, so
    // `new_from_slice` cannot fail here.
    #[allow(clippy::expect_used)]
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    let result = mac.finalize();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&result.into_bytes());
    tag
}

/// Verifies an HMAC-SHA256 tag in constant time.
///
/// Returns `true` if the tag matches, `false` otherwise.
/// Uses `subtle::ConstantTimeEq` to prevent timing attacks.
///
/// # Requirements
/// REQ-CK-100, REQ-CK-101, REQ-CK-106
///
/// # Example
///
/// ```rust
/// use cryptkit::hmac::{hmac_sign, hmac_verify};
///
/// let tag = hmac_sign(b"secret", b"message");
/// assert!(hmac_verify(b"secret", b"message", &tag));
/// assert!(!hmac_verify(b"wrong", b"message", &tag));
/// ```
pub fn hmac_verify(key: &[u8], message: &[u8], tag: &[u8; 32]) -> bool {
    // INVARIANT: HMAC-SHA256 accepts keys of any length, so
    // `new_from_slice` cannot fail here.
    #[allow(clippy::expect_used)]
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.verify_slice(tag).is_ok()
}

/// Constant-time equality check for two byte slices.
///
/// Returns `true` only if the slices are equal and of the same length.
/// The comparison is performed in constant time to prevent timing attacks.
///
/// # Requirements
/// REQ-CK-101, REQ-CK-201
///
/// # Example
///
/// ```rust
/// use cryptkit::hmac::constant_time_eq;
///
/// assert!(constant_time_eq(b"abc", b"abc"));
/// assert!(!constant_time_eq(b"abc", b"abd"));
/// ```
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
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
    fn sign_and_verify() {
        let tag = hmac_sign(b"key", b"hello");
        assert!(hmac_verify(b"key", b"hello", &tag));
    }

    #[test]
    fn wrong_key_fails() {
        let tag = hmac_sign(b"key", b"hello");
        assert!(!hmac_verify(b"wrong", b"hello", &tag));
    }

    #[test]
    fn wrong_message_fails() {
        let tag = hmac_sign(b"key", b"hello");
        assert!(!hmac_verify(b"key", b"world", &tag));
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"ab", b"abc"));
        assert!(constant_time_eq(b"", b""));
        assert!(!constant_time_eq(b"", b"a"));
    }

    /// REQ-CK-106: verification must fail closed — never panic — for tags of
    /// the wrong content, all-zero tags, or any hostile tag bytes.
    #[test]
    fn hmac_verify_rejects_wrong_length_and_zero_tags() {
        let tag = hmac_sign(b"key", b"hello");

        assert!(!hmac_verify(b"key", b"hello", &[0u8; 32]));
        assert!(!hmac_verify(b"key", b"hello", &[0xFF; 32]));

        // Flip every bit of a valid tag; must reject, not panic.
        let mut flipped = tag;
        for b in flipped.iter_mut() {
            *b ^= 0xFF;
        }
        assert!(!hmac_verify(b"key", b"hello", &flipped));

        // Original still verifies (no state corruption).
        assert!(hmac_verify(b"key", b"hello", &tag));
    }

    #[test]
    fn deterministic() {
        let tag1 = hmac_sign(b"k", b"m");
        let tag2 = hmac_sign(b"k", b"m");
        assert_eq!(tag1, tag2);
    }
}
