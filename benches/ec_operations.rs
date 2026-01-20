// EC Operations Benchmarks
//
// Measures performance of elliptic curve operations to validate gas optimizations:
// - scalar_mul vs scalar_mul_g (precomputed tables)
// - multi_scalar_mul_2 (Shamir's trick)
// - Ring signature creation/verification
// - Schnorr proof creation/verification
// - Encryption operations

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use bitsage_node::obelysk::elgamal::{
    Felt252, ECPoint,
    scalar_mul_g, scalar_mul_h, multi_scalar_mul_2, multi_scalar_mul_g,
    encrypt, encrypt_secure, create_schnorr_proof, verify_schnorr_proof,
    create_ring_signature, verify_ring_signature, generate_randomness,
    generate_keypair, KeyPair,
};

/// Generate a random scalar for benchmarking
fn random_scalar() -> Felt252 {
    generate_randomness().expect("RNG should work")
}

/// Generate a random key pair for benchmarking
fn random_keypair() -> KeyPair {
    generate_keypair().expect("keypair generation should work")
}

/// Benchmark: scalar_mul_g vs generator().scalar_mul()
///
/// Expected: scalar_mul_g should be ~4x faster due to precomputed tables
fn bench_scalar_mul_precomputed(c: &mut Criterion) {
    let mut group = c.benchmark_group("scalar_mul_comparison");

    let k = random_scalar();
    let g = ECPoint::generator();

    group.bench_function("generator().scalar_mul() [naive]", |b| {
        b.iter(|| g.scalar_mul(&k))
    });

    group.bench_function("scalar_mul_g() [precomputed]", |b| {
        b.iter(|| scalar_mul_g(&k))
    });

    group.bench_function("scalar_mul_h() [precomputed]", |b| {
        b.iter(|| scalar_mul_h(&k))
    });

    group.finish();
}

/// Benchmark: multi_scalar_mul_2 (Shamir's trick) vs separate scalar_muls
///
/// Expected: Shamir's trick should be ~2x faster for k1*P1 + k2*P2
fn bench_multi_scalar_mul(c: &mut Criterion) {
    let mut group = c.benchmark_group("multi_scalar_mul");

    let k1 = random_scalar();
    let k2 = random_scalar();
    let keypair = random_keypair();
    let p1 = ECPoint::generator();
    let p2 = keypair.public_key;

    group.bench_function("separate scalar_muls + add", |b| {
        b.iter(|| {
            let r1 = p1.scalar_mul(&k1);
            let r2 = p2.scalar_mul(&k2);
            r1.add(&r2)
        })
    });

    group.bench_function("multi_scalar_mul_2 [Shamir]", |b| {
        b.iter(|| multi_scalar_mul_2(&p1, &k1, &p2, &k2))
    });

    group.bench_function("multi_scalar_mul_g [precomputed + Shamir]", |b| {
        b.iter(|| multi_scalar_mul_g(&k1, &p2, &k2))
    });

    group.finish();
}

/// Benchmark: Schnorr proof creation and verification
fn bench_schnorr_proofs(c: &mut Criterion) {
    let mut group = c.benchmark_group("schnorr_proofs");

    let keypair = random_keypair();
    let nonce = random_scalar();
    let context: Vec<Felt252> = vec![Felt252::from_u64(0x1234567890abcdef)];

    // Create a proof for verification benchmarking
    let proof = create_schnorr_proof(
        &keypair.secret_key,
        &keypair.public_key,
        &nonce,
        &context,
    );

    group.bench_function("create_schnorr_proof", |b| {
        b.iter(|| {
            create_schnorr_proof(
                &keypair.secret_key,
                &keypair.public_key,
                &nonce,
                &context,
            )
        })
    });

    group.bench_function("verify_schnorr_proof", |b| {
        b.iter(|| {
            verify_schnorr_proof(
                &keypair.public_key,
                &proof,
                &context,
            )
        })
    });

    group.finish();
}

/// Benchmark: Ring signature creation and verification for various ring sizes
fn bench_ring_signatures(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_signatures");
    group.sample_size(20); // Ring sigs are slow, reduce sample size

    // Test various ring sizes
    for ring_size in [4, 8, 16].iter() {
        // Generate ring members
        let keypairs: Vec<KeyPair> = (0..*ring_size)
            .map(|_| random_keypair())
            .collect();

        let ring: Vec<ECPoint> = keypairs.iter()
            .map(|kp| kp.public_key)
            .collect();

        // Signer is the first member
        let signer_idx = 0usize;
        let signer_secret = keypairs[signer_idx].secret_key;
        let message = Felt252::from_u64(0xdeadbeef);

        // Create signature for verification benchmarking
        let signature = create_ring_signature(
            &message,
            &ring,
            &signer_secret,
            signer_idx,
        ).expect("ring sig creation should work");

        group.bench_with_input(
            BenchmarkId::new("create", ring_size),
            ring_size,
            |b, _| {
                b.iter(|| {
                    create_ring_signature(
                        &message,
                        &ring,
                        &signer_secret,
                        signer_idx,
                    )
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("verify", ring_size),
            ring_size,
            |b, _| {
                b.iter(|| {
                    verify_ring_signature(
                        &message,
                        &ring,
                        &signature,
                    )
                })
            },
        );
    }

    group.finish();
}

/// Benchmark: Encryption operations
fn bench_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("encryption");

    let keypair = random_keypair();
    let amount = 1000u64;
    let randomness = random_scalar();

    group.bench_function("encrypt (deterministic)", |b| {
        b.iter(|| {
            encrypt(
                black_box(amount),
                &keypair.public_key,
                &randomness,
            )
        })
    });

    group.bench_function("encrypt_secure (with RNG)", |b| {
        b.iter(|| {
            encrypt_secure(
                black_box(amount),
                &keypair.public_key,
            )
        })
    });

    group.finish();
}

/// Benchmark: Point operations (add, double)
fn bench_point_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("point_operations");

    let k1 = random_scalar();
    let k2 = random_scalar();
    let p1 = scalar_mul_g(&k1);
    let p2 = scalar_mul_g(&k2);

    group.bench_function("point_add", |b| {
        b.iter(|| p1.add(&p2))
    });

    group.bench_function("point_double", |b| {
        b.iter(|| p1.double())
    });

    group.bench_function("point_neg", |b| {
        b.iter(|| p1.neg())
    });

    group.finish();
}

/// Benchmark: Keypair generation
fn bench_keypair_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("keypair_generation");

    group.bench_function("generate_keypair", |b| {
        b.iter(|| generate_keypair())
    });

    group.bench_function("generate_randomness", |b| {
        b.iter(|| generate_randomness())
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_scalar_mul_precomputed,
    bench_multi_scalar_mul,
    bench_schnorr_proofs,
    bench_ring_signatures,
    bench_encryption,
    bench_point_operations,
    bench_keypair_generation,
);
criterion_main!(benches);
