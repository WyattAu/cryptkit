# Threat Model — cryptkit

Status: **v1.0** · Method: STRIDE over the public API surface
(`hmac_sign`/`hmac_verify`/`constant_time_eq`, `AesGcmEncryptor`,
`secure_random_bytes`, `sha256`).

Trust boundaries: (1) ciphertext/tags and messages supplied by callers
(potentially attacker-influenced), (2) key material held in process memory,
(3) the `hmac`/`aes-gcm`/`subtle`/`rand` dependency tree.

## Assets

| ID | Asset | Example |
|----|-------|---------|
| A1 | MAC verification decisions | Forged HMAC tag accepted |
| A2 | AES-GCM plaintext confidentiality + integrity | Ciphertext tampered or decrypted under wrong key |
| A3 | Key material | Key bytes leaked via logs/Debug/memory |
| A4 | Randomness | Predictable nonces/keys |

## STRIDE Analysis

| # | Threat | Category | Surface | Mitigation | Verifying test |
|---|--------|----------|---------|------------|----------------|
| T1 | Timing side channel on MAC comparison | Spoofing | `hmac_verify`, `constant_time_eq` | `Mac::verify_slice` and `subtle::ConstantTimeEq`; length mismatch returns early (length is public) | `src/hmac.rs::constant_time_eq_works`, `wrong_key_fails`; `src/lib.rs` proptests `hmac_sign_verify_roundtrip`, `hmac_wrong_key_fails` |
| T2 | Ciphertext bit-flipping / truncation | Tampering | `AesGcmEncryptor::decrypt` | AES-256-GCM auth tag; input shorter than the 12-byte nonce rejected with `Decrypt("data too short")` | `src/aes.rs::tampered_ciphertext_fails`; `fuzz/fuzz_targets/fuzz_decrypt_aes_gcm.rs` |
| T3 | Wrong-key decryption | Spoofing | `decrypt` | GCM tag fails under a different key | `src/aes.rs::wrong_key_fails`; proptest `aes_gcm_wrong_key_fails` |
| T4 | Key disclosure via logs / `Debug` | Info disclosure | `AesGcmEncryptor` | `#[derive(Zeroize, ZeroizeOnDrop)]` on the key holder; the type deliberately has no `Debug` impl that prints the key | `src/aes.rs::key_zeroize_on_drop` (drop path compiles; byte-level assertion impossible without `unsafe`) |
| T5 | Weak randomness for keys and nonces | Spoofing | `random::secure_random_bytes` | OS entropy via `rand` thread RNG (ChaCha-based CSPRNG) | `src/random.rs::two_calls_differ`, `fills_buffer` (statistical smoke only) |
| T6 | Crash/panic on hostile input | DoS | all functions | `#![forbid(unsafe_code)]`; HMAC accepts any key length; `decrypt` bounds-checks input | `fuzz/fuzz_targets/fuzz_hmac_verify.rs`, `fuzz_decrypt_aes_gcm.rs`; proptest `aes_gcm_roundtrip` with empty plaintext |

## OPEN RISKS (missing mitigations — not fabricated)

- **OPEN-1 — random 96-bit nonces with no usage accounting.** `encrypt`
  generates a fresh random nonce per message; there is no counter, no
  collision monitor, and no documented message-volume bound. NIST's 2³²
  per-key bound for random nonces is unenforced and untested.
- **OPEN-2 — `AesGcmEncryptor::key_bytes()` deliberately exposes the raw
  key.** Any caller (or `Debug` of a returned reference) can leak A3; the
  accessor is a documented API choice, not an accident.
- **OPEN-3 — no AEAD associated-data support.** `encrypt` never binds
  context (AAD is always empty); ciphertexts are freely interchangeable
  between messages/records under the same key.
- **OPEN-4 — `rand::thread_rng()` instead of `OsRng`/`getrandom` directly.**
  Fork- and reseed-behavior caveats of a process-global RNG apply; the doc
  comment says "OS entropy source", which is indirect. No test distinguishes.
- **OPEN-5 — HMAC doc overstates zeroization.** `hmac_sign`'s doc says "the
  key is zeroized after use"; no zeroization happens on the borrowed
  `&[u8]` key (only `AesGcmEncryptor` is `ZeroizeOnDrop`). Doc drift.

## Out of Scope

- Caller-side nonce/key reuse across processes (crate never persists keys).
- Side channels beyond tag comparison (e.g., cache timing inside
  `aes-gcm`/`sha2` crates).

## Residual Risks

- `constant_time_eq` leaks *length* inequality (required for the API,
  standard practice).
- Keys passed as `&[u8]` may be cloned by the HMAC crate internals;
  process-memory hygiene beyond `AesGcmEncryptor` is not guaranteed.
