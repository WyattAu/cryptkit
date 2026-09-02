#![no_main]

use libfuzzer_sys::fuzz_target;
use cryptkit::aes::AesGcmEncryptor;

fuzz_target!(|data: &[u8]| {
    // Create an encryptor with a known key and fuzz decrypt with arbitrary bytes
    let enc = AesGcmEncryptor::new([0x42u8; 32]).unwrap();
    // Must not panic on arbitrary input
    let _ = enc.decrypt(data);
});
