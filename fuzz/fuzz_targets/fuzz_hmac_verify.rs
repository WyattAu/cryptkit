#![no_main]

use libfuzzer_sys::fuzz_target;
use cryptkit::hmac::{hmac_sign, hmac_verify};

fuzz_target!(|data: &[u8]| {
    // Fuzz HMAC verify with a known key, using arbitrary bytes as the signature
    let key = b"fuzz-test-key";
    let message = b"fuzz-test-message";
    let tag_bytes: [u8; 32] = if data.len() >= 32 {
        data[..32].try_into().unwrap()
    } else {
        // Pad with zeros if less than 32 bytes
        let mut buf = [0u8; 32];
        let len = data.len().min(32);
        buf[..len].copy_from_slice(&data[..len]);
        buf
    };
    // Must not panic on arbitrary tag bytes
    let _ = hmac_verify(key, message, &tag_bytes);
});
