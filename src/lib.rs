#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Cryptographic primitives for Rust.
//!
//! Provides HMAC-SHA256, AES-GCM, constant-time comparison,
//! SHA-256 hashing, and secure random byte generation — all
//! with zeroize-on-drop for secrets.
//!
//! # Quick Start
//!
//! ```rust
//! use cryptkit::hmac::{hmac_sign, hmac_verify};
//!
//! let key = b"super-secret-key";
//! let message = b"hello world";
//!
//! let tag = hmac_sign(key, message);
//! assert!(hmac_verify(key, message, &tag));
//! ```

#[cfg(feature = "hmac_sha256")]
pub mod hmac;

#[cfg(feature = "aes-gcm")]
pub mod aes;

pub mod hash;
pub mod random;

/// Re-export of constant-time comparison.
pub use subtle::ConstantTimeEq;

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
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn hmac_sign_verify_roundtrip(key in "\\PC{1,256}", message in "\\PC{1,256}") {
            let key = key.as_bytes();
            let message = message.as_bytes();
            let tag = hmac::hmac_sign(key, message);
            prop_assert!(hmac::hmac_verify(key, message, &tag));
        }

        #[test]
        fn hmac_wrong_key_fails(key1 in "\\PC{1,256}", key2 in "\\PC{1,256}", message in "\\PC{1,256}") {
            let key1 = key1.as_bytes();
            let key2 = key2.as_bytes();
            let message = message.as_bytes();
            prop_assume!(key1 != key2);
            let tag = hmac::hmac_sign(key1, message);
            prop_assert!(!hmac::hmac_verify(key2, message, &tag));
        }

        #[test]
        fn aes_gcm_roundtrip(plaintext in "\\PC{0,1024}") {
            let plaintext = plaintext.as_bytes();
            let enc = aes::AesGcmEncryptor::generate().unwrap();
            let ciphertext = enc.encrypt(plaintext).unwrap();
            let decrypted = enc.decrypt(&ciphertext).unwrap();
            prop_assert_eq!(decrypted, plaintext);
        }

        #[test]
        fn aes_gcm_wrong_key_fails(plaintext in "\\PC{1,256}") {
            let plaintext = plaintext.as_bytes();
            let enc1 = aes::AesGcmEncryptor::generate().unwrap();
            let enc2 = aes::AesGcmEncryptor::generate().unwrap();
            let ciphertext = enc1.encrypt(plaintext).unwrap();
            prop_assert!(enc2.decrypt(&ciphertext).is_err());
        }

        #[test]
        fn sha256_deterministic(data in "\\PC{0,1024}") {
            let data = data.as_bytes();
            let h1 = hash::sha256(data);
            let h2 = hash::sha256(data);
            prop_assert_eq!(h1, h2);
        }

        #[test]
        fn sha256_different_inputs(a in "\\PC{1,256}", b in "\\PC{1,256}") {
            prop_assume!(a != b);
            let h1 = hash::sha256(a.as_bytes());
            let h2 = hash::sha256(b.as_bytes());
            prop_assert_ne!(h1, h2);
        }
    }
}
