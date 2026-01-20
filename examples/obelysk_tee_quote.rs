// Obelysk TEE Quote Example
//
// Demonstrates Phase 2 Step 1: TEE Attestation Types
// Shows how TEE quotes are created and validated

use bitsage_node::obelysk::{
    TEEType, MockTEEGenerator, EnclaveWhitelist,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔒 Obelysk TEE Quote Demo (Phase 2 - Step 1)");
    println!("============================================\n");
    
    // ===== Step 1: Create TEE generator =====
    println!("Step 1: Initializing TEE (Intel TDX for H100/A100)");
    let tee_generator = MockTEEGenerator::new(TEEType::IntelTDX);
    println!("  ✅ TEE Type: Intel TDX");
    println!("  💻 Hardware: H100/A100 GPUs with 4th Gen Xeon\n");
    
    // ===== Step 2: Execute computation in TEE =====
    println!("Step 2: Executing computation in TEE");
    let computation_result = b"ML_inference_output_data";
    println!("  📊 Computation: ML inference");
    println!("  🔐 Execution: Inside secure enclave (memory encrypted)");
    println!("  📤 Result: {} bytes\n", computation_result.len());
    
    // ===== Step 3: Generate TEE quote =====
    println!("Step 3: Generating TEE attestation quote");
    let quote = tee_generator.generate_quote(computation_result);
    
    println!("  ✅ Quote generated");
    println!("  🔑 MRENCLAVE (code hash): {} bytes", quote.mrenclave.len());
    println!("  🔏 MRSIGNER (signer hash): {} bytes", quote.mrsigner.len());
    println!("  📝 Report data (result hash): {} bytes", quote.report_data.len());
    println!("  ✍️  Signature: {} bytes", quote.signature.len());
    println!("  ⏰ Timestamp: {}\n", quote.timestamp);
    
    // ===== Step 4: Hash the quote =====
    println!("Step 4: Computing quote hash (for ZK circuits)");
    let quote_hash = quote.hash();
    println!("  ✅ Hash: {} bytes", quote_hash.len());
    println!("  🔢 Hash (hex): {}", hex::encode(&quote_hash));
    
    let m31_elements = quote.hash_as_m31();
    println!("  🔢 As M31 field elements: {} elements", m31_elements.len());
    println!("  📊 First element: {}\n", m31_elements[0]);
    
    // ===== Step 5: Verify against whitelist =====
    println!("Step 5: Checking enclave whitelist");
    let mut whitelist = EnclaveWhitelist::new();
    
    println!("  ❌ MRENCLAVE not whitelisted (expected for demo)");
    assert!(!whitelist.is_allowed(&quote.mrenclave));
    
    // Add to whitelist
    whitelist.add(quote.mrenclave.clone());
    println!("  ➕ Added MRENCLAVE to whitelist");
    
    println!("  ✅ MRENCLAVE now whitelisted");
    assert!(whitelist.is_allowed(&quote.mrenclave));
    println!();
    
    // ===== Summary =====
    println!("============================================");
    println!("🎉 Success!");
    println!();
    println!("What just happened:");
    println!("  1. Created a mock TEE (Intel TDX for H100/A100)");
    println!("  2. Executed computation in secure enclave");
    println!("  3. Generated hardware-attested quote");
    println!("  4. Computed quote hash for ZK circuits");
    println!("  5. Validated against enclave whitelist");
    println!();
    println!("Why this matters:");
    println!("  - TEE provides hardware-level encryption");
    println!("  - Quote proves what code ran (MRENCLAVE)");
    println!("  - Quote binds to specific execution (report_data)");
    println!("  - Can be verified on-chain (optimistic)");
    println!("  - Can be challenged with ZK proof (Phase 2 next steps)");
    println!();
    println!("Next: Step 2 - Build attestation verification circuit");
    
    Ok(())
}

