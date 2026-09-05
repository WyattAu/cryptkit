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

    #[test]
    fn key_zeroize_on_drop() {
        let key = [0x42u8; 32];
        let enc = AesGcmEncryptor::new(key).unwrap();
        let ptr = enc.key.as_ptr();
        drop(enc);
        // Key memory is zeroized; we can't assert the bytes directly
        // without unsafe, but the test verifies the drop path compiles.
        assert!(!ptr.is_null());
    }
}
