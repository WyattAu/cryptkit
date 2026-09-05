# Requirements — cryptkit

Numbered, testable requirements. Every requirement maps to at least one named
test; every security-relevant test cites at least one requirement. Doc
comments on the implementing public item carry `REQ-CK-NNN` tags.

## Functional

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-CK-001 | `hmac_sign` returns a deterministic 32-byte HMAC-SHA256 tag; `hmac_verify` accepts it for the same key/message | MUST |
| REQ-CK-002 | `AesGcmEncryptor::encrypt` produces `nonce(12) ‖ ciphertext+tag(16)` and `decrypt` inverts it exactly, including empty plaintext | MUST |
| REQ-CK-003 | `hash::sha256` returns the 32-byte FIPS 180-4 digest (known-vector checked), deterministic for identical input | MUST |
| REQ-CK-004 | `secure_random_bytes` fills a buffer of any length with CSPRNG bytes; `random_bytes(len)` returns exactly `len` bytes | MUST |

## Security

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-CK-100 | `hmac_verify` rejects a tag produced under a different key or over a different message | MUST |
| REQ-CK-101 | All secret-dependent comparisons are constant-time: HMAC via `hmac::Mac::verify_slice` (subtle-backed), equality via `subtle::ConstantTimeEq`; no `==`/`eq_ignore_ascii_case` on secrets | MUST |
| REQ-CK-102 | AES-GCM decryption of a tampered ciphertext or tag fails closed with `Err` (forgery rejected) | MUST |
| REQ-CK-103 | AES-GCM decryption under a different key fails closed with `Err` | MUST |
| REQ-CK-104 | `AesGcmEncryptor` key material is zeroized on drop, enforced by the type system (`ZeroizeOnDrop`), not by convention | MUST |
| REQ-CK-105 | Random generation is CSPRNG-backed (OS entropy via `rand::thread_rng`); successive draws differ and a 32-byte draw is never all-zero | MUST |
| REQ-CK-106 | `hmac_verify` never panics for any tag content or length (wrong-length and all-zero tags return `false`) | MUST |
| REQ-CK-107 | `AesGcmEncryptor` deliberately exposes `key_bytes()` for key management; it implements neither `Debug` nor `Display`, so the key cannot leak through formatting | SHOULD |

## Robustness

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-CK-200 | `decrypt` on input shorter than the 12-byte nonce returns `Err`, never panics | MUST |
| REQ-CK-201 | `constant_time_eq` returns `false` for unequal lengths, `true` for two empty slices, without panicking | MUST |
| REQ-CK-202 | `AesGcmEncryptor` is `Send + Sync`; one handle shared across threads performs concurrent encrypt/decrypt with correct results | MUST |

## Constant-Time Audit

- AUDIT: MAC comparison via `hmac::Mac::verify_slice` (`src/hmac.rs`) —
  constant-time (subtle-backed). ✓
- AUDIT: `constant_time_eq` via `subtle::ConstantTimeEq` (`src/hmac.rs`). ✓
  Length mismatch short-circuits before the CT compare — leaks only the
  (public) length, standard practice.
- AUDIT: AES-GCM tag verification is internal to the `aes-gcm` crate
  (RustCrypto, constant-time bitsliced implementation). ✓
- AUDIT: `sha256` hashes public input only; no secret-dependent branch.
- Grep result: no `==` on secret byte slices outside test code; no
  `eq_ignore_ascii_case` on secrets anywhere.

## Traceability Matrix

| Requirement | Test (fn, file) | Property class |
|-------------|-----------------|----------------|
| REQ-CK-001 | `sign_and_verify`, `deterministic` (`src/hmac.rs`); `hmac_sign_verify_roundtrip` (`src/lib.rs`) | unit/property |
| REQ-CK-002 | `round_trip`, `empty_plaintext` (`src/aes.rs`); `aes_gcm_roundtrip` (`src/lib.rs`) | unit/property |
| REQ-CK-003 | `known_vector` (`src/hash.rs`); `sha256_deterministic`, `sha256_different_inputs` (`src/lib.rs`) | unit/property |
| REQ-CK-004 | `fills_buffer`, `random_bytes_length` (`src/random.rs`) | unit |
| REQ-CK-100 | `wrong_key_fails`, `wrong_message_fails` (`src/hmac.rs`); `hmac_wrong_key_fails` (`src/lib.rs`) | unit/property |
| REQ-CK-101 | `constant_time_eq_works` (`src/hmac.rs`); AUDIT above | unit/audit |
| REQ-CK-102 | `tampered_ciphertext_fails` (`src/aes.rs`) | unit |
| REQ-CK-103 | `wrong_key_fails` (`src/aes.rs`); `aes_gcm_wrong_key_fails` (`src/lib.rs`) | unit/property |
| REQ-CK-104 | `encryptor_is_zeroize_on_drop` (`src/aes.rs`) — **gap test added** (compile-time trait proof; replaces placeholder `key_zeroize_on_drop`) | unit/design |
| REQ-CK-105 | `two_calls_differ` (`src/random.rs`) | unit |
| REQ-CK-106 | `hmac_verify_rejects_wrong_length_and_zero_tags` (`src/hmac.rs`) — **gap test added** | unit |
| REQ-CK-107 | AUDIT + API review (`src/aes.rs`: no `Debug`/`Display` derive on `AesGcmEncryptor`) | design |
| REQ-CK-200 | `decrypt_rejects_truncated_input` (`src/aes.rs`) — **gap test added** | unit |
| REQ-CK-201 | `constant_time_eq_works` (`src/hmac.rs`) | unit |
| REQ-CK-202 | `shared_handle_concurrent_roundtrip` (`src/aes.rs`) — **gap test added** | unit/concurrency |

## Test Count Delta

- Before: 22 tests (16 unit + 6 proptests).
- Added: 4 (`encryptor_is_zeroize_on_drop`, `hmac_verify_rejects_wrong_length_and_zero_tags`, `decrypt_rejects_truncated_input`, `shared_handle_concurrent_roundtrip`); removed placeholder `key_zeroize_on_drop`.
- After: 25.
