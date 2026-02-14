// Benchmark: Poseidon252 vs Blake2s Merkle Hashing + CPU STARK Proof
//
// Measures Merkle tree commit performance for both hash functions across
// multiple tree sizes, plus end-to-end STARK proof generation.
//
// Run: cargo run --bin bench_poseidon_vs_blake --release

use std::time::Instant;

use bitsage_node::obelysk::field::M31;
use bitsage_node::obelysk::vm::{ObelyskVM, OpCode, Instruction};
use bitsage_node::obelysk::stwo_adapter::{prove_with_stwo, prove_with_stwo_gpu};

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║   Poseidon252 vs Blake2s — Merkle + STARK Proof Benchmark      ║");
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║  CPU: Apple M4 Max (arm64, SIMD backend)                       ║");
    println!("║  Hash: Poseidon252 (algebraic) vs Blake2s (symmetric)          ║");
    println!("║  Note: GPU (CUDA) not available — CPU/SIMD only                ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    // ---- Part 1: Merkle tree hashing benchmark ----
    println!("━━━ Part 1: Merkle Tree Hashing (SimdBackend) ━━━\n");

    merkle_benchmark();

    // ---- Part 2: End-to-end STARK proof ----
    println!("\n━━━ Part 2: End-to-End STARK Proof (CPU SIMD) ━━━\n");

    let trace_sizes: Vec<usize> = vec![64, 256, 1024, 4096];

    println!("{:<12} {:>10} {:>10} {:>10} {:>8}",
        "Trace", "Steps", "Prove(ms)", "FRI Lyrs", "Opens");
    println!("{}", "─".repeat(60));

    for &target in &trace_sizes {
        let program = generate_program(target);
        let mut vm = ObelyskVM::new();
        vm.load_program(program);
        let trace = match vm.execute() {
            Ok(t) => t,
            Err(e) => {
                println!("{:<12} FAILED: {:?}", format!("{}steps", target), e);
                continue;
            }
        };

        let steps = trace.steps.len();
        let start = Instant::now();
        // prove_with_stwo_gpu falls back to SIMD on non-GPU machines
        let proof = prove_with_stwo_gpu(&trace, 80);
        let prove_ms = start.elapsed().as_millis();

        match proof {
            Ok(p) => {
                println!("{:<12} {:>10} {:>10} {:>10} {:>8}",
                    format!("{}steps", target),
                    steps,
                    prove_ms,
                    p.fri_layers.len(),
                    p.openings.len(),
                );
            }
            Err(e) => {
                println!("{:<12} {:>10} {:>10} {:?}",
                    format!("{}steps", target), steps, prove_ms, e);
            }
        }
    }

    println!("\nDone.");
}

fn merkle_benchmark() {
    use stwo_prover::prover::backend::simd::SimdBackend;
    use stwo_prover::prover::backend::simd::column::BaseColumn;
    use stwo_prover::prover::backend::{Column, Col};
    use stwo_prover::prover::vcs::ops::MerkleOps;
    use stwo_prover::core::vcs::blake2_merkle::Blake2sMerkleHasher;
    use stwo_prover::core::vcs::poseidon252_merkle::Poseidon252MerkleHasher;
    use stwo_prover::core::fields::m31::BaseField;

    let log_sizes: Vec<u32> = vec![10, 14, 16, 18, 20];
    let n_columns = 4;

    println!("{:<10} {:>8} {:>14} {:>14} {:>10}",
        "LogSize", "Leaves", "Blake2s(ms)", "Poseidon(ms)", "Ratio");
    println!("{}", "─".repeat(62));

    for &log_size in &log_sizes {
        let n = 1usize << log_size;

        // Create test columns
        let columns: Vec<BaseColumn> = (0..n_columns)
            .map(|c| {
                let mut col = BaseColumn::zeros(n);
                for i in 0..n {
                    col.set(i, BaseField::from((i + c * 1000) as u32));
                }
                col
            })
            .collect();
        let col_refs: Vec<&Col<SimdBackend, BaseField>> = columns.iter().collect();

        // Blake2s Merkle
        let start = Instant::now();
        let mut blake_layer = <SimdBackend as MerkleOps<Blake2sMerkleHasher>>::commit_on_layer(
            log_size, None, &col_refs,
        );
        // Build full tree
        for l in (0..log_size).rev() {
            blake_layer = <SimdBackend as MerkleOps<Blake2sMerkleHasher>>::commit_on_layer(
                l, Some(&blake_layer), &[],
            );
        }
        let blake_ms = start.elapsed().as_secs_f64() * 1000.0;

        // Poseidon252 Merkle
        let start = Instant::now();
        let mut poseidon_layer = <SimdBackend as MerkleOps<Poseidon252MerkleHasher>>::commit_on_layer(
            log_size, None, &col_refs,
        );
        for l in (0..log_size).rev() {
            poseidon_layer = <SimdBackend as MerkleOps<Poseidon252MerkleHasher>>::commit_on_layer(
                l, Some(&poseidon_layer), &[],
            );
        }
        let poseidon_ms = start.elapsed().as_secs_f64() * 1000.0;

        let ratio = if poseidon_ms > 0.0 { blake_ms / poseidon_ms } else { 0.0 };
        println!("{:<10} {:>8} {:>13.1} {:>13.1} {:>9.2}x",
            log_size, n, blake_ms, poseidon_ms, ratio);
    }
}

fn generate_program(target_steps: usize) -> Vec<Instruction> {
    let mut program = Vec::with_capacity(target_steps + 16);

    for i in 0..16usize.min(target_steps) {
        program.push(Instruction {
            opcode: OpCode::LoadImm,
            dst: (i % 16) as u8,
            src1: 0, src2: 0,
            immediate: Some(M31::new((i as u32 + 1) * 7)),
            address: None,
        });
    }

    let remaining = target_steps.saturating_sub(16);
    for i in 0..remaining {
        let opcode = if i % 2 == 0 { OpCode::Mul } else { OpCode::Add };
        program.push(Instruction {
            opcode,
            dst: (i % 16) as u8,
            src1: ((i + 1) % 16) as u8,
            src2: ((i + 3) % 16) as u8,
            immediate: None,
            address: None,
        });
    }

    program
}
