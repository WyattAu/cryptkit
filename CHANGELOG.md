# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/) — versions follow [semver](https://semver.org).

## [Unreleased]

## [0.1.0] - 2026-08-31

### Added

- HMAC-SHA256 keyed hashing for message authentication.
- AES-256-GCM authenticated encryption with associated data; nonces are
  randomly generated per encryption from the OS CSPRNG.
- SHA-256 fast cryptographic hashing.
- Constant-time comparison backed by `subtle` (timing side-channel safe).
- Secure random byte generation with `zeroize` support; all secret keys
  are zeroized on drop.
- `#![forbid(unsafe_code)]`; criterion benches.
