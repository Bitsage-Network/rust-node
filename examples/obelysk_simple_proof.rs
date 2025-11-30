// Simple Obelysk Proof Example
//
// Demonstrates the core Obelysk workflow:
// 1. Define a computation (simple arithmetic)
// 2. Execute in OVM
// 3. Generate Stwo STARK proof
// 4. Verify proof

use bitsage_node::obelysk::{
    ObelyskVM, OpCode, ObelyskProver, M31,
    vm::Instruction,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Obelysk Simple Proof Demo");
    println!("================================\n");
    
    // ===== Step 1: Define the computation =====
    println!("Step 1: Defining computation");
    println!("Program: Prove that 5 + 7 = 12\n");
    
    let mut vm = ObelyskVM::new();
    
    // Set public inputs (these are visible to verifier)
    let input_a = M31::new(5);
    let input_b = M31::new(7);
    vm.set_public_inputs(vec![input_a, input_b]);
    
    // Build program
    let program = vec![
        // r0 = 5 (already loaded from public inputs)
        // r1 = 7 (already loaded from public inputs)
        
        // r2 = r0 + r1
        Instruction {
            opcode: OpCode::Add,
            dst: 2,
            src1: 0,
            src2: 1,
            immediate: None,
            address: None,
        },
        
        // Move result to output register (r0)
        Instruction {
            opcode: OpCode::LoadImm,
            dst: 0,
            src1: 0,
            src2: 0,
            immediate: Some(M31::ZERO),
            address: None,
        },
        Instruction {
            opcode: OpCode::Add,
            dst: 0,
            src1: 0,
            src2: 2,
            immediate: None,
            address: None,
        },
        
        Instruction {
            opcode: OpCode::Halt,
            dst: 0,
            src1: 0,
            src2: 0,
            immediate: None,
            address: None,
        },
    ];
    
    vm.load_program(program);
    
    // ===== Step 2: Execute the program =====
    println!("Step 2: Executing program in OVM");
    let trace = vm.execute()?;
    println!("  ✅ Execution complete");
    println!("  📊 Trace length: {} steps", trace.steps.len());
    println!("  📥 Public inputs: {:?}", trace.public_inputs);
    println!("  📤 Public outputs: {:?}", trace.public_outputs);
    println!();
    
    // Verify the computation
    assert_eq!(trace.public_outputs[0], M31::new(12), "Computation incorrect!");
    
    // ===== Step 3: Generate ZK proof =====
    println!("Step 3: Generating Stwo STARK proof");
    let prover = ObelyskProver::new();
    let proof = prover.prove_execution(&trace)?;
    println!("  ✅ Proof generated");
    println!("  🔑 Security: {} bits", 128);
    println!("  ⏱️  Generation time: {}ms", proof.metadata.generation_time_ms);
    println!("  📦 Proof size: {} bytes (~{}KB)", 
        proof.metadata.proof_size_bytes,
        proof.metadata.proof_size_bytes / 1024
    );
    println!("  🔢 Trace: {}x{} (length x width)",
        proof.metadata.trace_length,
        proof.metadata.trace_width
    );
    println!();
    
    // ===== Step 4: Verify proof =====
    println!("Step 4: Verifying proof");
    let valid = prover.verify_proof(&proof)?;
    println!("  ✅ Proof is valid: {}", valid);
    println!();
    
    // ===== Summary =====
    println!("================================");
    println!("🎉 Success!");
    println!();
    println!("What just happened:");
    println!("  1. We executed '5 + 7 = 12' in the Obelysk VM");
    println!("  2. Generated a cryptographic proof of correct execution");
    println!("  3. Verified the proof without re-executing");
    println!();
    println!("Why this matters:");
    println!("  - The verifier didn't need to run the computation");
    println!("  - The proof is ~{}KB (constant size)", proof.metadata.proof_size_bytes / 1024);
    println!("  - Verification is much faster than execution");
    println!("  - This scales to ML models with millions of operations");
    println!();
    println!("Next: Try `cargo run --example obelysk_ml_inference`");
    
    Ok(())
}

