//! Benchmark for Montgomery arithmetic optimizations
//!
//! Compares performance of BigUint-based vs optimized modular arithmetic

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use bitsage_node::obelysk::elgamal::{Felt252, mul_mod_n, add_mod_n, sub_mod_n};
use bitsage_node::obelysk::montgomery::{mul_mod_n_fast, add_mod_n_fast, sub_mod_n_fast};

fn bench_mul_mod_n(c: &mut Criterion) {
    let a = Felt252::from_u64(12345678);
    let b = Felt252::from_u64(87654321);

    let mut group = c.benchmark_group("mul_mod_n");

    group.bench_function("BigUint (slow)", |bencher| {
        bencher.iter(|| {
            black_box(mul_mod_n(black_box(&a), black_box(&b)))
        });
    });

    group.bench_function("Optimized (fast)", |bencher| {
        bencher.iter(|| {
            black_box(mul_mod_n_fast(black_box(&a), black_box(&b)))
        });
    });

    group.finish();
}

fn bench_add_mod_n(c: &mut Criterion) {
    let a = Felt252::from_u64(u64::MAX);
    let b = Felt252::from_u64(u64::MAX);

    let mut group = c.benchmark_group("add_mod_n");

    group.bench_function("BigUint (slow)", |bencher| {
        bencher.iter(|| {
            black_box(add_mod_n(black_box(&a), black_box(&b)))
        });
    });

    group.bench_function("Optimized (fast)", |bencher| {
        bencher.iter(|| {
            black_box(add_mod_n_fast(black_box(&a), black_box(&b)))
        });
    });

    group.finish();
}

fn bench_sub_mod_n(c: &mut Criterion) {
    let a = Felt252::from_u64(100);
    let b = Felt252::from_u64(200);

    let mut group = c.benchmark_group("sub_mod_n");

    group.bench_function("BigUint (slow)", |bencher| {
        bencher.iter(|| {
            black_box(sub_mod_n(black_box(&a), black_box(&b)))
        });
    });

    group.bench_function("Optimized (fast)", |bencher| {
        bencher.iter(|| {
            black_box(sub_mod_n_fast(black_box(&a), black_box(&b)))
        });
    });

    group.finish();
}

criterion_group!(benches, bench_mul_mod_n, bench_add_mod_n, bench_sub_mod_n);
criterion_main!(benches);
