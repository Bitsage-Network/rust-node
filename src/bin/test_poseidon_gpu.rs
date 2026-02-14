// Quick test: verify GPU Poseidon252 Merkle kernel compiles PTX and runs
// Run: cargo run --release --features cuda --bin test_poseidon_gpu

fn main() {
    #[cfg(feature = "cuda")]
    cuda_test();

    #[cfg(not(feature = "cuda"))]
    println!("This binary requires --features cuda");
}

#[cfg(feature = "cuda")]
fn cuda_test() {
    use std::time::Instant;
    use stwo_prover::prover::backend::gpu::cuda_executor::{
        get_cuda_executor, upload_poseidon252_round_constants, compute_poseidon252_round_constants,
    };

    println!("=== GPU Poseidon252 Merkle Kernel Test ===\n");

    println!("1. Computing round constants...");
    let rc = compute_poseidon252_round_constants();
    println!("   {} u64 limbs (expected 428)", rc.len());
    assert_eq!(rc.len(), 428);

    println!("2. Getting CUDA executor (compiles PTX if needed)...");
    let start = Instant::now();
    let executor = get_cuda_executor().expect("CUDA executor");
    println!("   Executor ready in {:?}", start.elapsed());

    println!("3. Uploading round constants to GPU...");
    let d_rc = upload_poseidon252_round_constants(&executor.device).expect("RC upload");
    println!("   Uploaded {} bytes", 428 * 8);

    // Test with a simple leaf layer: 4 columns, 1024 hashes
    let n_hashes = 1024;
    let n_columns = 4;
    let columns: Vec<Vec<u32>> = (0..n_columns)
        .map(|c| (0..n_hashes).map(|i| ((i + c * 1000) as u32) % (1u32 << 31)).collect())
        .collect();

    println!(
        "4. Running GPU Poseidon252 Merkle (leaf layer, {} cols, {} hashes)...",
        n_columns, n_hashes
    );
    let start = Instant::now();
    let result = executor
        .execute_poseidon252_merkle(&columns, None, n_hashes, &d_rc)
        .expect("GPU Poseidon252 kernel");
    let elapsed = start.elapsed();
    println!("   {} output u64s ({} hashes x 4 limbs)", result.len(), n_hashes);
    println!("   Time: {:?}", elapsed);
    println!(
        "   First hash limbs: [{:#x}, {:#x}, {:#x}, {:#x}]",
        result[0], result[1], result[2], result[3]
    );

    // Verify non-zero output
    let non_zero = result.iter().filter(|&&v| v != 0).count();
    println!("   Non-zero limbs: {}/{}", non_zero, result.len());
    assert!(non_zero > 0, "All-zero output indicates kernel failure");

    // Test internal layer: hash pairs of previous results
    let n_internal = n_hashes / 2;
    println!(
        "\n5. Running GPU Poseidon252 Merkle (internal, {} hashes from {} prev)...",
        n_internal, n_hashes
    );
    let start = Instant::now();
    let empty_cols: Vec<Vec<u32>> = vec![];
    let result2 = executor
        .execute_poseidon252_merkle(&empty_cols, Some(&result), n_internal, &d_rc)
        .expect("GPU internal layer");
    let elapsed = start.elapsed();
    println!("   {} output u64s ({} hashes x 4 limbs)", result2.len(), n_internal);
    println!("   Time: {:?}", elapsed);

    // Benchmark at larger scale
    println!("\n6. Benchmarks (leaf layer, 4 columns):");
    println!("{:<12} {:>10} {:>12} {:>14}", "LogSize", "Hashes", "Time(ms)", "Khash/s");
    println!("{}", "-".repeat(52));

    for log_size in [14u32, 16, 18, 20] {
        let n = 1usize << log_size;
        let cols: Vec<Vec<u32>> = (0..4)
            .map(|c| (0..n).map(|i| ((i + c * 1000) as u32) % (1u32 << 31)).collect())
            .collect();

        let start = Instant::now();
        let _r = executor
            .execute_poseidon252_merkle(&cols, None, n, &d_rc)
            .expect("benchmark");
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        println!(
            "{:<12} {:>10} {:>11.1} {:>13.0}",
            format!("2^{}", log_size),
            n,
            ms,
            (n as f64) / ms
        );
    }

    println!("\n=== DONE: GPU Poseidon252 kernel works! ===");
}
