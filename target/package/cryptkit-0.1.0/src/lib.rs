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
