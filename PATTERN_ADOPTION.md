# Pattern adoption: cryptkit

Relationship to the WyattAu pattern canon
(`pattern-standards/references/catalog.md`). Validated by
`pattern-standards/scripts/adoption-check.py`.

| Pattern | Status | Evidence |
|---|---|---|
| P4 | partial | src/aes.rs:50 (key zeroized on drop via `ZeroizeOnDrop` derive, enforced by compile-time test at src/aes.rs:174; no `Debug`/`Display` per REQ-CK-107 in REQUIREMENTS.md; no `Sensitive<T>` wrapper type) |
| P43 | refused | R6 (primitive library: caller-held keys only, no per-entity data store or DEK hierarchy to shred) |
| P46 | partial | supply-chain/audits.toml (cargo-vet audits, wired in .github/workflows/vet.yml) |
| P64 | adopted | src/lib.rs:51 (proptest suite: HMAC sign/verify roundtrip, AES-GCM roundtrip and wrong-key rejection, SHA-256 determinism) |
| P66 | adopted | .github/workflows/mutation.yml (cargo-mutants gate in CI) |
| P67 | partial | fuzz/fuzz_targets/fuzz_decrypt_aes_gcm.rs (libfuzzer feeds arbitrary bytes to `decrypt`; second target fuzz/fuzz_targets/fuzz_hmac_verify.rs; no structured generators) |
| P115 | partial | Cargo.toml:32 (feature-gated `fips` (ring) and `ed25519` backends; core APIs hardcode HMAC-SHA256 tag shape at src/hmac.rs:23 and AES-256-GCM key size at src/aes.rs:52) |

Reviewed: 2026-11-19
