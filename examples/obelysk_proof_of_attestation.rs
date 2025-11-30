// Obelysk Proof of Attestation (PoA) Example
//
// Demonstrates Phase 2 Step 2: TEE Attestation Verification
// Shows the complete PoA workflow:
// 1. Generate TEE quote
// 2. Verify locally (optimistic)
// 3. Generate ZK proof (if challenged)
// 4. Verify proof

use bitsage_node::obelysk::{
    TEEType, TEEQuote, MockTEEGenerator, EnclaveWhitelist,
    ProofOfAttestation,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Obelysk Proof of Attestation Demo (Phase 2 - Step 2)");
    println!("========================================================\n");
    
    // ===== Setup =====
    println!("Setup: Creating TEE environment");
    let tee_generator = MockTEEGenerator::new(TEEType::IntelTDX);
    println!("  ✅ TEE Type: Intel TDX (for H100/A100)");
    
    // Create whitelist and add our enclave
    let mut whitelist = EnclaveWhitelist::new();
    println!("  ✅ Enclave whitelist initialized\n");
    
    // ===== Scenario 1: Happy Path (Optimistic) =====
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Scenario 1: Happy Path (No Challenge)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    // Step 1: Execute computation in TEE
    println!("Step 1: Worker executes ML inference in TEE");
    let computation_result = b"ml_inference_output_vector_data";
    let quote = tee_generator.generate_quote(computation_result);
    println!("  💻 Execution: In secure enclave");
    println!("  📤 Result: {} bytes", computation_result.len());
    println!("  🔑 TEE Quote: Generated\n");
    
    // Add enclave to whitelist (in production, done via governance)
    whitelist.add(quote.mrenclave.clone());
    println!("Step 2: Enclave added to whitelist (via governance)");
    println!("  ✅ MRENCLAVE whitelisted\n");
    
    // Step 2: Submit result with quote (optimistic)
    println!("Step 3: Worker submits result + quote to blockchain");
    let poa = ProofOfAttestation::with_whitelist(whitelist.clone());
    let is_valid = poa.verify_quote_locally(&quote)?;
    println!("  🚀 Submitted optimistically");
    println!("  ⏱️  No ZK proof generated (fast!)");
    println!("  ⏰ 24-hour challenge period starts");
    println!("  ✅ Quote verified locally: {}\n", is_valid);
    
    println!("Step 4: Wait for challenge period (24 hours)");
    println!("  ⏳ No challenges received");
    println!("  ✅ Result accepted after challenge period");
    println!("  💰 Worker paid\n");
    
    println!("═══════════════════════════════════════════════");
    println!("✅ Happy Path Complete: TEE-only verification");
    println!("⚡ Speed: Native execution (~10ms)");
    println!("💵 Cost: Minimal (no proof generation)");
    println!("═══════════════════════════════════════════════\n");
    
    // ===== Scenario 2: Challenge Path (ZK Proof) =====
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Scenario 2: Challenge Path (ZK Verification)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    // Step 1: New job execution
    println!("Step 1: Worker executes another job in TEE");
    let computation_result_2 = b"another_ml_inference_result";
    let quote_2 = tee_generator.generate_quote(computation_result_2);
    whitelist.add(quote_2.mrenclave.clone());
    println!("  💻 Execution: In secure enclave");
    println!("  📤 Result: {} bytes\n", computation_result_2.len());
    
    // Step 2: Submit optimistically
    println!("Step 2: Worker submits result + quote");
    println!("  🚀 Submitted optimistically\n");
    
    // Step 3: Someone challenges!
    println!("Step 3: ⚠️  Challenge received!");
    println!("  🚨 Challenger suspects invalid result");
    println!("  ⏱️  Worker must provide ZK proof within 1 hour\n");
    
    // Step 4: Generate ZK proof
    println!("Step 4: Worker generates Proof of Attestation (PoA)");
    let poa = ProofOfAttestation::with_whitelist(whitelist.clone());
    let attestation_proof = poa.generate_proof(quote_2)?;
    println!("  ⚙️  Generating Stwo STARK proof...");
    println!("  ✅ Proof generated");
    println!("  📦 Proof size: {} bytes", attestation_proof.proof_data.len());
    println!("  🔑 Proves: TEE quote signature is valid");
    println!("  🔍 Verifies: MRENCLAVE, certificate chain, signature\n");
    
    // Step 5: Submit proof to resolve challenge
    println!("Step 5: Submit proof to smart contract");
    let proof_valid = poa.verify_proof(&attestation_proof)?;
    println!("  📤 Proof submitted on-chain");
    println!("  ✅ Proof verified: {}", proof_valid);
    println!("  🎯 Challenge resolved");
    println!("  💰 Worker vindicated, challenger slashed\n");
    
    println!("═══════════════════════════════════════════════");
    println!("✅ Challenge Path Complete: Hybrid TEE+ZK");
    println!("⚡ Speed: ~1-10 seconds (proof generation)");
    println!("🔒 Trust: Zero-knowledge verified");
    println!("═══════════════════════════════════════════════\n");
    
    // ===== Summary =====
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Summary: Hybrid TEE+ZK Architecture");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    println!("Default Path (99% of jobs):");
    println!("  • Execute in TEE (native speed)");
    println!("  • Submit quote optimistically");
    println!("  • Accept after 24h if no challenge");
    println!("  • ⚡ Ultra-fast: ~10ms execution\n");
    
    println!("Challenge Path (1% of jobs):");
    println!("  • Challenger disputes result");
    println!("  • Worker generates PoA (Stwo proof)");
    println!("  • Proof verified on-chain");
    println!("  • 🔒 Trustless: Zero-knowledge guaranteed\n");
    
    println!("Why This Is Revolutionary:");
    println!("  ✅ Speed: TEE gives native execution (no ZK overhead)");
    println!("  ✅ Privacy: TEE encrypts memory (model weights stay secret)");
    println!("  ✅ Trust: ZK fallback provides ultimate security");
    println!("  ✅ Economics: Only generate proofs when challenged");
    println!("  ✅ Hardware: Works on H100/A100 with Intel TDX\n");
    
    println!("vs Pure ZK (Giza's approach):");
    println!("  ❌ Slow: Every job requires proof generation");
    println!("  ❌ Expensive: Constant proving costs");
    println!("  ❌ No privacy: Model weights visible to prover\n");
    
    println!("vs Pure TEE (no verification):");
    println!("  ❌ Trust: Must trust hardware manufacturer");
    println!("  ❌ Exploits: Vulnerable to zero-days");
    println!("  ❌ No recourse: Can't challenge bad results\n");
    
    println!("Obelysk = Best of Both Worlds! 🚀");
    println!("\nNext: Step 3 - Optimistic TEE smart contract");
    
    Ok(())
}

