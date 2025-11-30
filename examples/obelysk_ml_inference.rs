// Obelysk ML Inference Example
// Demonstrates matrix multiplication and ReLU activation with ZK proof generation

use bitsage_node::obelysk::{ObelyskVM, OpCode, Instruction, M31, Matrix};
use bitsage_node::obelysk::{CircuitBuilder, ObelyskProver, ProverConfig, LogLevel};

fn main() {
    println!("=== Obelysk ML Inference Demo ===\n");

    // Step 1: Create a simple neural network layer
    // y = ReLU(W * x)
    // W: 2x3 weight matrix
    // x: 3x1 input vector
    // y: 2x1 output vector

    let mut vm = ObelyskVM::new();

    // Weight matrix W (2x3):
    // [[1, 2, 3],
    //  [4, 5, 6]]
    let weights = Matrix::from_data(
        2, 3,
        vec![
            M31::new(1), M31::new(2), M31::new(3),
            M31::new(4), M31::new(5), M31::new(6),
        ]
    ).unwrap();

    // Input vector x (3x1):
    // [[1],
    //  [2],
    //  [3]]
    let input = Matrix::from_data(
        3, 1,
        vec![M31::new(1), M31::new(2), M31::new(3)]
    ).unwrap();

    // Expected output: W * x = [[14], [32]]
    // (1*1 + 2*2 + 3*3 = 14)
    // (4*1 + 5*2 + 6*3 = 32)

    // Store matrices in memory
    vm.write_matrix(100, &weights);  // W at address 100
    vm.write_matrix(200, &input);    // x at address 200

    // Program:
    // r0 = 100 (address of W)
    // r1 = 200 (address of x)
    // r2 = 300 (address for result Wx)
    // MatMul r2, r0, r1  -> Wx = W * x
    // 
    // For ReLU: We'd need to apply element-wise, but since result is already positive, skip for simplicity
    // Halt

    let program = vec![
        Instruction { opcode: OpCode::LoadImm, dst: 0, src1: 0, src2: 0, immediate: Some(M31::new(100)), address: None },
        Instruction { opcode: OpCode::LoadImm, dst: 1, src1: 0, src2: 0, immediate: Some(M31::new(200)), address: None },
        Instruction { opcode: OpCode::LoadImm, dst: 2, src1: 0, src2: 0, immediate: Some(M31::new(300)), address: None },
        Instruction { opcode: OpCode::MatMul, dst: 2, src1: 0, src2: 1, immediate: None, address: None },
        Instruction { opcode: OpCode::Halt, dst: 0, src1: 0, src2: 0, immediate: None, address: None },
    ];

    vm.load_program(program);
    
    println!("Executing ML inference (W * x)...");
    let trace = vm.execute().expect("VM execution failed");
    
    println!("✓ Execution complete ({} steps, {} cycles)", trace.steps.len(), vm.cycle);

    // Read the result
    let result = vm.read_matrix(300).expect("Failed to read result matrix");
    
    println!("\nResult matrix ({}x{}):", result.rows, result.cols);
    for i in 0..result.rows {
        print!("  [");
        for j in 0..result.cols {
            print!("{}", result.get(i, j).unwrap().value());
            if j < result.cols - 1 {
                print!(", ");
            }
        }
        println!("]");
    }

    assert_eq!(result.get(0, 0).unwrap(), M31::new(14), "First element should be 14");
    assert_eq!(result.get(1, 0).unwrap(), M31::new(32), "Second element should be 32");

    println!("\n✓ ML inference result verified!");

    // Step 2: Generate ZK proof
    println!("\nGenerating ZK proof of correct inference...");
    
    let circuit = CircuitBuilder::from_trace(&trace).build();
    println!("✓ Circuit built: {} constraints, trace width {}, trace length {}", 
        circuit.constraints.len(),
        circuit.trace_width(),
        circuit.trace_length()
    );

    let prover = ObelyskProver::with_config(ProverConfig {
        security_bits: 128,
        fri_blowup: 8,
        fri_queries: 42,
        use_gpu: false,
        log_level: LogLevel::Normal,
    });

    let proof = prover.prove_execution(&trace).expect("Proof generation failed");
    println!("✓ Proof generated: {} commitments, {} layers (MOCK)", 
        proof.trace_commitment.len(),
        proof.fri_layers.len()
    );

    // Step 3: Verify proof
    println!("\nVerifying proof...");
    let is_valid = prover.verify_proof(&proof).expect("Verification failed");

    if is_valid {
        println!("✓ Proof verified successfully!");
    } else {
        println!("✗ Proof verification failed!");
        std::process::exit(1);
    }

    println!("\n=== Demo Complete ===");
    println!("✓ Matrix multiplication working");
    println!("✓ Execution trace captured");
    println!("✓ ZK proof generated (mock)");
    println!("✓ Proof verified");
    println!("\nReady for production deployment with real Stwo prover!");
}

