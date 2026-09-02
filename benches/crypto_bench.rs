use criterion::{Criterion, criterion_group, criterion_main};

fn bench_hmac_sign(c: &mut Criterion) {
    let key = b"super-secret-key-for-benchmarking";
    let mut group = c.benchmark_group("hmac_sign");
    for size in [64, 1024, 64 * 1024] {
        let msg = vec![0xABu8; size];
        group.bench_with_input(format!("{size}B"), &msg, |b, msg| {
            b.iter(|| cryptkit::hmac::hmac_sign(key, msg));
        });
    }
    group.finish();
}

fn bench_hmac_verify(c: &mut Criterion) {
    let key = b"super-secret-key-for-benchmarking";
    let mut group = c.benchmark_group("hmac_verify");
    for size in [64, 1024, 64 * 1024] {
        let msg = vec![0xABu8; size];
        let tag = cryptkit::hmac::hmac_sign(key, &msg);
        group.bench_with_input(format!("{size}B"), &msg, |b, msg| {
            b.iter(|| cryptkit::hmac::hmac_verify(key, msg, &tag));
        });
    }
    group.finish();
}

fn bench_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");
    for size in [64, 1024, 64 * 1024] {
        let msg = vec![0xABu8; size];
        group.bench_with_input(format!("{size}B"), &msg, |b, msg| {
            b.iter(|| cryptkit::hash::sha256(msg));
        });
    }
    group.finish();
}

fn bench_aes_encrypt(c: &mut Criterion) {
    let enc = cryptkit::aes::AesGcmEncryptor::generate().unwrap();
    let mut group = c.benchmark_group("aes_gcm_encrypt");
    for size in [64, 1024, 64 * 1024] {
        let plaintext = vec![0xABu8; size];
        group.bench_with_input(format!("{size}B"), &plaintext, |b, pt| {
            b.iter(|| enc.encrypt(pt).unwrap());
        });
    }
    group.finish();
}

fn bench_aes_decrypt(c: &mut Criterion) {
    let enc = cryptkit::aes::AesGcmEncryptor::generate().unwrap();
    let mut group = c.benchmark_group("aes_gcm_decrypt");
    for size in [64, 1024, 64 * 1024] {
        let plaintext = vec![0xABu8; size];
        let ciphertext = enc.encrypt(&plaintext).unwrap();
        group.bench_with_input(format!("{size}B"), &ciphertext, |b, ct| {
            b.iter(|| enc.decrypt(ct).unwrap());
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_hmac_sign,
    bench_hmac_verify,
    bench_sha256,
    bench_aes_encrypt,
    bench_aes_decrypt,
);
criterion_main!(benches);
