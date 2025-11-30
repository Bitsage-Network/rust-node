//! Integration tests for GPU backend with Stwo prover.
//!
//! These tests verify that the GPU backend correctly integrates with
//! Stwo's proving pipeline and produces valid proofs.

use bitsage_node::obelysk::{
    ObelyskVM, OpCode, Instruction, M31,
    stwo_adapter::{prove_with_stwo, prove_with_stwo_gpu, is_gpu_available},
};

/// Create a simple test trace for proving
fn create_test_trace(size: usize) -> bitsage_node::obelysk::ExecutionTrace {
    let mut vm = ObelyskVM::new();
    
    // Execute some simple operations to generate a trace
    let program = vec![
        Instruction { opcode: OpCode::LoadImm, operands: [0, 42, 0] },
        Instruction { opcode: OpCode::LoadImm, operands: [1, 100, 0] },
        Instruction { opcode: OpCode::Add, operands: [2, 0, 1] },
        Instruction { opcode: OpCode::Mul, operands: [3, 2, 0] },
    ];
    
    // Execute enough times to get desired trace size
    for _ in 0..(size / program.len()).max(1) {
        for instruction in &program {
            let _ = vm.execute_instruction(instruction);
        }
    }
    
    vm.get_execution_trace()
}

#[test]
fn test_gpu_availability_check() {
    // This should not panic regardless of GPU availability
    let available = is_gpu_available();
    println!("GPU available: {}", available);
}

#[test]
fn test_prove_with_simd_backend() {
    // Create a small trace
    let trace = create_test_trace(64);
    
    // Generate proof using SIMD backend (should always work)
    let result = prove_with_stwo(&trace, 128);
    
    assert!(result.is_ok(), "SIMD backend proof generation failed: {:?}", result.err());
    
    let proof = result.unwrap();
    assert!(!proof.trace_commitment.is_empty(), "Trace commitment should not be empty");
    assert!(!proof.fri_layers.is_empty(), "FRI layers should not be empty");
    println!("SIMD proof generated successfully with {} FRI layers", proof.fri_layers.len());
}

#[test]
fn test_prove_with_gpu_backend() {
    // Create a small trace
    let trace = create_test_trace(64);
    
    // Generate proof using GPU backend (falls back to SIMD if no GPU)
    let result = prove_with_stwo_gpu(&trace, 128);
    
    assert!(result.is_ok(), "GPU backend proof generation failed: {:?}", result.err());
    
    let proof = result.unwrap();
    assert!(!proof.trace_commitment.is_empty(), "Trace commitment should not be empty");
    assert!(!proof.fri_layers.is_empty(), "FRI layers should not be empty");
    
    if is_gpu_available() {
        println!("GPU proof generated successfully with {} FRI layers", proof.fri_layers.len());
    } else {
        println!("GPU not available, SIMD fallback proof generated with {} FRI layers", proof.fri_layers.len());
    }
}

#[test]
fn test_gpu_and_simd_produce_equivalent_proofs() {
    // Create identical traces
    let trace = create_test_trace(64);
    
    // Generate proofs with both backends
    let simd_proof = prove_with_stwo(&trace, 128).expect("SIMD proof failed");
    let gpu_proof = prove_with_stwo_gpu(&trace, 128).expect("GPU proof failed");
    
    // Proofs should have the same structure
    assert_eq!(
        simd_proof.fri_layers.len(),
        gpu_proof.fri_layers.len(),
        "FRI layer count should match"
    );
    
    assert_eq!(
        simd_proof.openings.len(),
        gpu_proof.openings.len(),
        "Opening count should match"
    );
    
    // Note: Exact proof bytes may differ due to randomness in the protocol,
    // but the structure should be equivalent
    println!("Both backends produced structurally equivalent proofs");
}

#[test]
#[ignore] // Run with --ignored for performance testing
fn test_large_trace_gpu_performance() {
    use std::time::Instant;
    
    // Create a large trace to see GPU speedup
    let trace = create_test_trace(1 << 14); // 16K elements
    
    // Measure SIMD time
    let simd_start = Instant::now();
    let _simd_proof = prove_with_stwo(&trace, 128).expect("SIMD proof failed");
    let simd_time = simd_start.elapsed();
    
    // Measure GPU time
    let gpu_start = Instant::now();
    let _gpu_proof = prove_with_stwo_gpu(&trace, 128).expect("GPU proof failed");
    let gpu_time = gpu_start.elapsed();
    
    println!("SIMD time: {:?}", simd_time);
    println!("GPU time: {:?}", gpu_time);
    
    if is_gpu_available() {
        let speedup = simd_time.as_secs_f64() / gpu_time.as_secs_f64();
        println!("GPU speedup: {:.2}x", speedup);
    } else {
        println!("GPU not available, times should be similar");
    }
}

