# cryptkit

[![docs.rs](https://docs.rs/cryptkit/badge.svg)](https://docs.rs/cryptkit)
[![crates.io](https://img.shields.io/crates/v/cryptkit.svg)](https://crates.io/crates/cryptkit)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

Cryptographic primitives for Rust — HMAC-SHA256, AES-GCM, constant-time comparison, and secure random with zeroize.

## Purpose

`cryptkit` provides a curated set of cryptographic building blocks designed for application-level use:

- **HMAC-SHA256** — keyed hashing for message authentication
- **AES-256-GCM** — authenticated encryption with associated data
- **Constant-time comparison** — prevents timing side-channel attacks
- **SHA-256** — fast cryptographic hashing
- **Secure random** — OS-backed random byte generation with `zeroize` support

All secret material is zeroized on drop via the `zeroize` crate.

## Quick Start

### HMAC-SHA256

```rust
use cryptkit::hmac::{hmac_sign, hmac_verify};

let key = b"my-secret-key";
let message = b"important data";

let tag = hmac_sign(key, message);
assert!(hmac_verify(key, message, &tag));
```

### AES-256-GCM Encryption

```rust
use cryptkit::aes::AesGcmEncryptor;

let enc = AesGcmEncryptor::generate().unwrap();
let ciphertext = enc.encrypt(b"classified info").unwrap();
let plaintext = enc.decrypt(&ciphertext).unwrap();
assert_eq!(plaintext, b"classified info");
```

### SHA-256 Hashing

```rust
use cryptkit::hash::sha256;

let hash = sha256(b"input");
assert_eq!(hash.len(), 32);
```

### Constant-Time Comparison

```rust
use cryptkit::hmac::constant_time_eq;

assert!(constant_time_eq(b"abc", b"abc"));
assert!(!constant_time_eq(b"abc", b"abd"));
```

## Security Properties

- **`#![forbid(unsafe_code)]`** — no unsafe in the entire crate
- **Zeroize on drop** — all secret keys are cleared from memory when dropped
- **Constant-time operations** — HMAC verification and equality checks use `subtle` crate
- **OS entropy** — random generation uses the platform CSPRNG
- **No hard-coded keys or IVs** — all nonces are randomly generated per encryption

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `hmac_sha256` | yes | HMAC-SHA256 signing and verification |
| `aes-gcm` | yes | AES-256-GCM authenticated encryption |
| `ed25519` | no | Ed25519 signatures via `ed25519-dalek` |
| `fips` | no | FIPS-approved primitives via `ring` |

## Comparison with other crates

### vs `hmac` + `sha2` directly

`cryptkit` wraps `hmac` and `sha2` with a simpler API and adds constant-time verification. If you need fine-grained HMAC control, use the underlying crates directly.

### vs `ring`

`ring` provides FIPS-grade primitives but has a complex build process and unsafe internals. `cryptkit` uses pure-Rust crates with `#![forbid(unsafe_code)]` for simplicity. Enable the `fips` feature to pull in `ring` when you need it.

### vs `aes-gcm` directly

`cryptkit` wraps `aes-gcm` with automatic nonce generation and key management. The `AesGcmEncryptor` struct handles nonce storage in the ciphertext, so you don't need to manage nonces yourself.

### vs `rust-crypto`

`rust-crypto` is unmaintained. `cryptkit` uses actively maintained, audited crates from the RustCrypto project.

## MSRV

Rust **1.85** (edition 2024).

## Mutation testing

`cargo mutants` (config in [`.cargo/mutants.toml`](.cargo/mutants.toml), not run in CI):

- **2026-09-16 baseline: 25 mutants, 25 caught, 0 missed, 0 unviable = 100% kill score.**
- Scope: all `src/` modules (`aes.rs`, `hash.rs`, `hmac.rs`, `lib.rs`, `random.rs`); `tests/` and `benches/` excluded from mutation.
- Reproduce: `CARGO_TARGET_DIR=/var/tmp/target-mutants-cryptkit cargo mutants --no-shuffle -j 4` (~20 s).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.

## Security

Threat model: [THREAT-MODEL.md](THREAT-MODEL.md).
