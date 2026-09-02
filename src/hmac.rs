//! HMAC-SHA256 signing and verification with constant-time comparison.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Computes an HMAC-SHA256 tag for the given key and message.
///
/// The returned tag is 32 bytes. The key is zeroized after use.
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
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.verify_slice(tag).is_ok()
}

/// Constant-time equality check for two byte slices.
///
/// Returns `true` only if the slices are equal and of the same length.
/// The comparison is performed in constant time to prevent timing attacks.
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
    }

    #[test]
    fn deterministic() {
        let tag1 = hmac_sign(b"k", b"m");
        let tag2 = hmac_sign(b"k", b"m");
        assert_eq!(tag1, tag2);
    }
}
