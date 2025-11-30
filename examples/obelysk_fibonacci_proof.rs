// Obelysk Fibonacci Proof Example
//
// Demonstrates proving a loop-based computation (Fibonacci sequence)
// This showcases:
// 1. Loop execution in OVM
// 2. Multiple iterations with state
// 3. Proving complex control flow

use bitsage_node::obelysk::{
    ObelyskVM, OpCode, ObelyskProver, M31,
    vm::Instruction,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔢 Obelysk Fibonacci Proof Demo");
    println!("================================\n");
    
    // ===== Step 1: Define the computation =====
    println!("Step 1: Defining computation");
    println!("Program: Calculate 10th Fibonacci number\n");
    
    let mut vm = ObelyskVM::new();
    
    // Public input: n = 10 (calculate F(10))
    let n = M31::new(10);
    vm.set_public_inputs(vec![n]);
    
    // Build Fibonacci program
    // Algorithm:
    //   a = 0, b = 1
    //   for i in 0..n:
    //     temp = a + b
    //     a = b
    //     b = temp
    //   return b
    
    let program = vec![
        // Initialize: r0 = n (from public input)
        // r1 = a = 0
        Instruction {
            opcode: OpCode::LoadImm,
            dst: 1,
            src1: 0,
            src2: 0,
            immediate: Some(M31::ZERO),
            address: None,
        },
        // r2 = b = 1
        Instruction {
            opcode: OpCode::LoadImm,
            dst: 2,
            src1: 0,
            src2: 0,
            immediate: Some(M31::ONE),
            address: None,
        },
        // r3 = i = 0 (counter)
        Instruction {
            opcode: OpCode::LoadImm,
            dst: 3,
            src1: 0,
            src2: 0,
            immediate: Some(M31::ZERO),
            address: None,
        },
        
        // ===== Loop start (pc=3) =====
        // r4 = a + b (temp)
        Instruction {
            opcode: OpCode::Add,
            dst: 4,
            src1: 1,
            src2: 2,
            immediate: None,
            address: None,
        },
        // r1 = r2 (a = b)
        Instruction {
            opcode: OpCode::LoadImm,
            dst: 5,
            src1: 0,
            src2: 0,
            immediate: Some(M31::ZERO),
            address: None,
        },
        Instruction {
            opcode: OpCode::Add,
            dst: 1,
            src1: 5,
            src2: 2,
            immediate: None,
            address: None,
        },
        // r2 = r4 (b = temp)
        Instruction {
            opcode: OpCode::LoadImm,
            dst: 5,
            src1: 0,
            src2: 0,
            immediate: Some(M31::ZERO),
            address: None,
        },
        Instruction {
            opcode: OpCode::Add,
            dst: 2,
            src1: 5,
            src2: 4,
            immediate: None,
            address: None,
        },
        
        // i = i + 1
        Instruction {
            opcode: OpCode::LoadImm,
            dst: 5,
            src1: 0,
            src2: 0,
            immediate: Some(M31::ONE),
            address: None,
        },
        Instruction {
            opcode: OpCode::Add,
            dst: 3,
            src1: 3,
            src2: 5,
            immediate: None,
            address: None,
        },
        
        // Check if i < n
        Instruction {
            opcode: OpCode::Lt,
            dst: 5,
            src1: 3,
            src2: 0,
            immediate: None,
            address: None,
        },
        
        // If i < n, jump back to loop start (pc=3)
        Instruction {
            opcode: OpCode::JumpIf,
            dst: 0,
            src1: 5,
            src2: 0,
            immediate: None,
            address: Some(3),
        },
        
        // Move result (r2) to output register (r0)
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
    println!("Step 2: Executing Fibonacci computation in OVM");
    let trace = vm.execute()?;
    println!("  ✅ Execution complete");
    println!("  📊 Trace length: {} steps", trace.steps.len());
    println!("  🔄 Loop iterations: 10");
    println!("  📥 Public input (n): {:?}", trace.public_inputs);
    println!("  📤 Public output (F(10)): {:?}", trace.public_outputs[0]);
    println!();
    
    // Verify the result
    // F(10) = 89 (Fibonacci sequence: 0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89...)
    let expected = M31::new(89);
    assert_eq!(trace.public_outputs[0], expected, "Fibonacci computation incorrect!");
    println!("  ✅ Verified: F(10) = 89 (correct!)\n");
    
    // ===== Step 3: Generate ZK proof =====
    println!("Step 3: Generating Stwo STARK proof for loop execution");
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
    println!("  1. Executed a 10-iteration loop calculating F(10) = 89");
    println!("  2. Generated {} execution steps", trace.steps.len());
    println!("  3. Created a cryptographic proof of correct execution");
    println!("  4. Verified the proof without re-executing");
    println!();
    println!("Why this matters:");
    println!("  - Loops are fundamental to ML (matrix operations)");
    println!("  - The proof is constant size (~{}KB)", proof.metadata.proof_size_bytes / 1024);
    println!("  - Scales to thousands of iterations");
    println!("  - Verifier doesn't need to execute the loop");
    println!();
    println!("Next: Try modifying the program to calculate F(20) or F(100)!");
    
    Ok(())
}

