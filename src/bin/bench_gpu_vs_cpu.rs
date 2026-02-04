// GPU vs CPU STARK Proof Benchmark with Real On-Chain Proofs
//
// Generates realistic OVM execution traces exercising all constrained opcodes
// (Add, Sub, Mul, LoadImm, Load, Store, Xor, And, Lt) then proves them with
// both GPU and CPU backends. Outputs a performance + cost comparison table.
//
// Run on GPU server:
//   cargo run --release --features cuda --bin bench_gpu_vs_cpu

use bitsage_node::obelysk::field::M31;
use bitsage_node::obelysk::vm::{ObelyskVM, Instruction, OpCode, ExecutionTrace};
use bitsage_node::obelysk::stwo_adapter::{prove_with_stwo, prove_with_stwo_gpu, prewarm_gpu};

use std::time::Instant;

/// Build a sequential OVM program (no branches) that exercises all
/// constraint-verified opcodes. Each "block" is ~10 trace steps.
/// The program computes iterative Fibonacci with arithmetic, memory, and bitwise ops.
fn build_sequential_program(n_blocks: usize) -> (Vec<Instruction>, Vec<M31>) {
    let mut program = Vec::new();

    // Setup: r0 = 1, r1 = 1 (Fibonacci seeds)
    program.push(Instruction {
        opcode: OpCode::LoadImm, dst: 0, src1: 0, src2: 0,
        immediate: Some(M31::from_u32(1)), address: None,
    });
    program.push(Instruction {
        opcode: OpCode::LoadImm, dst: 1, src1: 0, src2: 0,
        immediate: Some(M31::from_u32(1)), address: None,
    });
    // r2 = 100 (base memory address)
    program.push(Instruction {
        opcode: OpCode::LoadImm, dst: 2, src1: 0, src2: 0,
        immediate: Some(M31::from_u32(100)), address: None,
    });

    let inputs = vec![M31::from_u32(1), M31::from_u32(1)];

    for i in 0..n_blocks {
        let mem_addr = 100 + i;

        // 1. Add: r3 = r0 + r1
        program.push(Instruction {
            opcode: OpCode::Add, dst: 3, src1: 0, src2: 1,
            immediate: None, address: None,
        });
        // 2. Sub: r4 = r3 - r1
        program.push(Instruction {
            opcode: OpCode::Sub, dst: 4, src1: 3, src2: 1,
            immediate: None, address: None,
        });
        // 3. Mul: r5 = r0 * r1
        program.push(Instruction {
            opcode: OpCode::Mul, dst: 5, src1: 0, src2: 1,
            immediate: None, address: None,
        });
        // 4. Store: mem[mem_addr] = r3
        program.push(Instruction {
            opcode: OpCode::Store, dst: 0, src1: 3, src2: 0,
            immediate: None, address: Some(mem_addr),
        });
        // 5. Load: r6 = mem[mem_addr]
        program.push(Instruction {
            opcode: OpCode::Load, dst: 6, src1: 0, src2: 0,
            immediate: None, address: Some(mem_addr),
        });
        // 6. LoadImm: r7 = i+1
        program.push(Instruction {
            opcode: OpCode::LoadImm, dst: 7, src1: 0, src2: 0,
            immediate: Some(M31::from_u32((i + 1) as u32)), address: None,
        });
        // 7. Xor: r8 = r0 ^ r1 (no selector constraint, just fills columns)
        program.push(Instruction {
            opcode: OpCode::Xor, dst: 8, src1: 0, src2: 1,
            immediate: None, address: None,
        });
        // 8. And: r9 = r0 & r1
        program.push(Instruction {
            opcode: OpCode::And, dst: 9, src1: 0, src2: 1,
            immediate: None, address: None,
        });
        // 9. Lt: r10 = (r0 < r1)
        program.push(Instruction {
            opcode: OpCode::Lt, dst: 10, src1: 0, src2: 1,
            immediate: None, address: None,
        });
        // 10. Advance Fibonacci: r0 = r1, r1 = r3
        program.push(Instruction {
            opcode: OpCode::Add, dst: 0, src1: 1, src2: 31, // r0 = r1 + 0
            immediate: None, address: None,
        });
        program.push(Instruction {
            opcode: OpCode::Add, dst: 1, src1: 3, src2: 31, // r1 = r3 + 0
            immediate: None, address: None,
        });
    }

    // Halt
    program.push(Instruction {
        opcode: OpCode::Halt, dst: 0, src1: 0, src2: 0,
        immediate: None, address: None,
    });

    (program, inputs)
}

/// Generate an execution trace with approximately `target_steps` steps.
fn generate_trace(target_steps: usize) -> ExecutionTrace {
    let steps_per_block = 11; // 11 non-branching instructions per block
    let setup_steps = 3;
    let n_blocks = ((target_steps.saturating_sub(setup_steps)) / steps_per_block).max(1);

    let (program, inputs) = build_sequential_program(n_blocks);
    let mut vm = ObelyskVM::new();
    vm.set_public_inputs(inputs);
    vm.load_program(program);

    vm.execute().expect("VM execution should succeed")
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".into())
        )
        .init();

    println!("=================================================================");
    println!("  BitSage GPU vs CPU STARK Proof Benchmark");
    println!("  Real On-Chain Proofs (Add/Sub/Mul/Load/Store/Xor/And/Lt)");
    println!("=================================================================\n");

    // Pre-warm GPU
    println!("Pre-warming GPU...");
    let gpu_available = prewarm_gpu();
    if gpu_available {
        println!("  GPU ready (CUDA kernels compiled)\n");
    } else {
        println!("  No GPU available — will benchmark CPU only\n");
    }

    // Pricing constants (USD/hr)
    let h100_pcie_rate: f64 = 1.70;
    let cpu_rate: f64 = 0.25; // EPYC vCPU estimate

    let trace_targets: Vec<(u32, usize)> = vec![
        (8,      256),
        (10,    1_024),
        (12,    4_096),
        (14,   16_384),
        (16,   65_536),
        (18,  262_144),
        (20, 1_048_576),
    ];

    struct Result {
        log_size: u32,
        actual_steps: usize,
        cpu_ms: f64,
        gpu_ms: f64,
        cpu_ok: bool,
        gpu_ok: bool,
        proof_size_cpu: usize,
        proof_size_gpu: usize,
        fri_layers_cpu: usize,
        fri_layers_gpu: usize,
    }

    let mut results: Vec<Result> = Vec::new();

    for &(log_size, target_steps) in &trace_targets {
        println!("--- 2^{} ({} target steps) ---", log_size, target_steps);

        let trace = generate_trace(target_steps);
        let actual = trace.steps.len();

        // Count opcode diversity
        let mut opcodes = std::collections::HashMap::new();
        for s in &trace.steps {
            *opcodes.entry(format!("{:?}", s.instruction.opcode)).or_insert(0u32) += 1;
        }
        let mem_ops = opcodes.get("Store").copied().unwrap_or(0)
            + opcodes.get("Load").copied().unwrap_or(0);
        println!("  {} steps, {} opcodes, {} mem ops, io_commit={}",
            actual, opcodes.len(), mem_ops,
            trace.io_commitment.is_some());

        // CPU proof
        print!("  CPU: ");
        let t0 = Instant::now();
        let cpu_result = prove_with_stwo(&trace, 128);
        let cpu_ms = t0.elapsed().as_secs_f64() * 1000.0;
        let (cpu_ok, psz_cpu, fri_cpu) = match &cpu_result {
            Ok(p) => {
                println!("{:.1}ms, {}B, {} FRI layers", cpu_ms, p.metadata.proof_size_bytes, p.fri_layers.len());
                (true, p.metadata.proof_size_bytes, p.fri_layers.len())
            }
            Err(e) => {
                println!("FAIL: {:?}", e);
                (false, 0, 0)
            }
        };

        // GPU proof
        let (gpu_ok, gpu_ms, psz_gpu, fri_gpu) = if gpu_available {
            print!("  GPU: ");
            let t0 = Instant::now();
            let gpu_result = prove_with_stwo_gpu(&trace, 128);
            let ms = t0.elapsed().as_secs_f64() * 1000.0;
            match &gpu_result {
                Ok(p) => {
                    println!("{:.1}ms, {}B, {} FRI layers", ms, p.metadata.proof_size_bytes, p.fri_layers.len());
                    (true, ms, p.metadata.proof_size_bytes, p.fri_layers.len())
                }
                Err(e) => {
                    println!("FAIL: {:?}", e);
                    (false, ms, 0, 0)
                }
            }
        } else {
            (false, 0.0, 0, 0)
        };

        results.push(Result {
            log_size, actual_steps: actual,
            cpu_ms, gpu_ms, cpu_ok, gpu_ok,
            proof_size_cpu: psz_cpu, proof_size_gpu: psz_gpu,
            fri_layers_cpu: fri_cpu, fri_layers_gpu: fri_gpu,
        });
        println!();
    }

    // === Summary Tables ===
    println!("=================================================================");
    println!("  PERFORMANCE COMPARISON");
    println!("=================================================================\n");
    println!("{:<7} {:>7} {:>10} {:>10} {:>8}  {:>9} {:>9}",
        "Size", "Steps", "CPU(ms)", "GPU(ms)", "Speedup", "CPU Sz", "GPU Sz");
    println!("{}", "-".repeat(66));
    for r in &results {
        let speedup = if r.gpu_ms > 0.0 && r.gpu_ok { r.cpu_ms / r.gpu_ms } else { 0.0 };
        println!("{:<7} {:>7} {:>10.1} {:>10.1} {:>7.1}x  {:>8}B {:>8}B",
            format!("2^{}", r.log_size), r.actual_steps,
            r.cpu_ms, r.gpu_ms, speedup,
            r.proof_size_cpu, r.proof_size_gpu);
    }

    println!("\n=================================================================");
    println!("  COST COMPARISON (USD per proof)");
    println!("  CPU: ${:.2}/hr (EPYC)  |  GPU: ${:.2}/hr (H100 PCIe @ BitSage rate)",
        cpu_rate, h100_pcie_rate);
    println!("=================================================================\n");
    println!("{:<7} {:>14} {:>14} {:>9}",
        "Size", "CPU Cost($)", "GPU Cost($)", "Savings");
    println!("{}", "-".repeat(48));
    for r in &results {
        let cpu_cost = (r.cpu_ms / 1000.0 / 3600.0) * cpu_rate;
        let gpu_cost = if r.gpu_ok { (r.gpu_ms / 1000.0 / 3600.0) * h100_pcie_rate } else { 0.0 };
        let savings = if cpu_cost > 0.0 && r.gpu_ok {
            (1.0 - gpu_cost / cpu_cost) * 100.0
        } else { 0.0 };
        println!("{:<7} {:>14.8} {:>14.8} {:>8.1}%",
            format!("2^{}", r.log_size), cpu_cost, gpu_cost, savings);
    }

    println!("\n=================================================================");
    println!("  ON-CHAIN GAS ESTIMATION (Starknet L2)");
    println!("  ~500 gas/felt252 + 100K base verification");
    println!("=================================================================\n");
    println!("{:<7} {:>10} {:>10} {:>12}",
        "Size", "ProofSize", "Felts", "Est Gas");
    println!("{}", "-".repeat(42));
    for r in &results {
        let sz = if r.proof_size_gpu > 0 { r.proof_size_gpu } else { r.proof_size_cpu };
        let felts = (sz + 31) / 32;
        let gas = felts as u64 * 500 + 100_000;
        println!("{:<7} {:>9}B {:>10} {:>12}",
            format!("2^{}", r.log_size), sz, felts, gas);
    }

    println!("\n=== Benchmark complete ===");
}
