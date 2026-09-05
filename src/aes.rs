//! AES-256-GCM authenticated encryption and decryption.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::random;

/// Errors from AES-GCM operations.
#[derive(Debug, thiserror::Error)]
pub enum AesError {
    /// Encryption failed.
    #[error("encryption failed: {0}")]
    Encrypt(String),

    /// Decryption failed (bad key, tampered ciphertext, or wrong nonce).
    #[error("decryption failed: {0}")]
    Decrypt(String),

    /// Invalid key length.
    #[error("invalid key length: expected 32, got {0}")]
    InvalidKeyLength(usize),

    /// Invalid nonce length.
    #[error("invalid nonce length: expected 12, got {0}")]
    InvalidNonceLength(usize),
}

/// AES-256-GCM encryptor with an embedded key.
///
/// The key is zeroized on drop. Create via [`AesGcmEncryptor::new`]
/// with a 32-byte key, or generate a random one with
/// [`AesGcmEncryptor::generate`].
///
/// # Requirements
/// REQ-CK-002, REQ-CK-104, REQ-CK-107, REQ-CK-202
///
/// # Example
///
/// ```rust
/// use cryptkit::aes::AesGcmEncryptor;
///
/// let enc = AesGcmEncryptor::generate().unwrap();
/// let ciphertext = enc.encrypt(b"hello world").unwrap();
/// let plaintext = enc.decrypt(&ciphertext).unwrap();
/// assert_eq!(plaintext, b"hello world");
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AesGcmEncryptor {
    key: [u8; 32],
}

impl AesGcmEncryptor {
    /// Creates an encryptor from an existing 32-byte key.
    pub fn new(key: [u8; 32]) -> Result<Self, AesError> {
        Ok(Self { key })
    }

    /// Generates a cryptographically random key and returns an encryptor.
    pub fn generate() -> Result<Self, AesError> {
        let mut key = [0u8; 32];
        random::secure_random_bytes(&mut key);
        Ok(Self { key })
    }

    /// Encrypts plaintext. Returns `nonce || ciphertext`.
    ///
    /// The first 12 bytes are the nonce, the rest is the AES-GCM ciphertext
    /// including the 16-byte authentication tag.
    ///
    /// # Requirements
    /// REQ-CK-002
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, AesError> {
        let cipher =
            Aes256Gcm::new_from_slice(&self.key).map_err(|e| AesError::Encrypt(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        random::secure_random_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| AesError::Encrypt(e.to_string()))?;

        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    /// Decrypts `nonce || ciphertext` produced by [`encrypt`](Self::encrypt).
    ///
    /// # Requirements
    /// REQ-CK-002, REQ-CK-102, REQ-CK-103, REQ-CK-200
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, AesError> {
        if data.len() < 12 {
            return Err(AesError::Decrypt("data too short".into()));
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let cipher =
            Aes256Gcm::new_from_slice(&self.key).map_err(|e| AesError::Decrypt(e.to_string()))?;

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| AesError::Decrypt(e.to_string()))
    }

    /// Returns a reference to the raw key bytes.
    ///
    /// # Requirements
    /// REQ-CK-107
    pub fn key_bytes(&self) -> &[u8; 32] {
        &self.key
    }
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
    fn round_trip() {
        let enc = AesGcmEncryptor::generate().unwrap();
        let plaintext = b"hello world, this is a test message!";
        let ciphertext = enc.encrypt(plaintext).unwrap();
        let decrypted = enc.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let enc1 = AesGcmEncryptor::generate().unwrap();
        let enc2 = AesGcmEncryptor::generate().unwrap();
        let ciphertext = enc1.encrypt(b"secret").unwrap();
        assert!(enc2.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let enc = AesGcmEncryptor::generate().unwrap();
        let mut ciphertext = enc.encrypt(b"secret").unwrap();
        if let Some(last) = ciphertext.last_mut() {
            *last ^= 0xff;
        }
        assert!(enc.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn empty_plaintext() {
        let enc = AesGcmEncryptor::generate().unwrap();
        let ciphertext = enc.encrypt(b"").unwrap();
        let decrypted = enc.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, b"");
    }

    /// REQ-CK-104: zeroization is enforced by the type system —
    /// `AesGcmEncryptor` must implement `ZeroizeOnDrop`, verified here at
    /// compile time (the derive would fail the build if removed).
    #[test]
    fn encryptor_is_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<AesGcmEncryptor>();
    }

    /// REQ-CK-200: input shorter than the 12-byte nonce must return `Err`,
    /// never panic or read out of bounds.
    #[test]
    fn decrypt_rejects_truncated_input() {
        let enc = AesGcmEncryptor::generate().unwrap();
        for n in 0..12 {
            let data = vec![0u8; n];
            assert!(enc.decrypt(&data).is_err(), "length {n} must be Err");
        }
    }

    /// REQ-CK-202: a single handle shared across threads performs concurrent
    /// encrypt/decrypt correctly (immutable `&self` API, `Send + Sync`).
    #[test]
    fn shared_handle_concurrent_roundtrip() {
        use std::sync::Arc;
        use std::thread;

        let enc = Arc::new(AesGcmEncryptor::generate().unwrap());
        let mut handles = Vec::new();
        for i in 0..8 {
            let enc = Arc::clone(&enc);
            handles.push(thread::spawn(move || {
                let plaintext = format!("thread-{i}-payload");
                let ct = enc.encrypt(plaintext.as_bytes()).unwrap();
                let pt = enc.decrypt(&ct).unwrap();
                assert_eq!(pt, plaintext.as_bytes());
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }
}
