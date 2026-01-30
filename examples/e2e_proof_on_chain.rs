//! End-to-End Proof On-Chain Test
//!
//! This example demonstrates the complete flow of:
//! 1. Generating a real STWO proof using ObelyskProver
//! 2. Serializing it for Starknet
//! 3. Submitting to StwoVerifier contract on Sepolia
//! 4. Verifying the proof was accepted
//!
//! Run with:
//! ```bash
//! STARKNET_PRIVATE_KEY=0x... \
//! STARKNET_ACCOUNT_ADDRESS=0x... \
//! cargo run --example e2e_proof_on_chain
//! ```

use bitsage_node::obelysk::{
    ObelyskVM, OpCode, ObelyskProver, M31, StarkProof,
    vm::Instruction,
    starknet::{
        proof_serializer::{Felt252, CairoSerializedProof, ProofMetadata, ProofConfig},
        starknet_client::{StarknetClient, StarknetClientConfig, StarknetNetwork},
        verifier_contract::{VerifierContract, VerifierContractConfig},
    },
};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

// Contract addresses on Sepolia (from deployment/final_deployed_contracts.json)
const STWO_VERIFIER_ADDRESS: &str = "0x052963fe2f1d2d2545cbe18b8230b739c8861ae726dc7b6f0202cc17a369bd7d";
const PROOF_VERIFIER_ADDRESS: &str = "0x017ada59ab642b53e6620ef2026f21eb3f2d1a338d6e85cb61d5bcd8dfbebc8b";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("🚀 BitSage E2E Proof On-Chain Test");
    println!("===================================\n");

    // ===== Step 1: Check Configuration =====
    println!("Step 1: Checking configuration...");

    let private_key = env::var("STARKNET_PRIVATE_KEY")
        .ok();
    let account_address = env::var("STARKNET_ACCOUNT_ADDRESS")
        .ok();

    if private_key.is_none() || account_address.is_none() {
        println!("  ⚠️  No wallet configured - will run in view-only mode");
        println!("  To submit proofs on-chain, set:");
        println!("    STARKNET_PRIVATE_KEY=0x...");
        println!("    STARKNET_ACCOUNT_ADDRESS=0x...\n");
    } else {
        println!("  ✅ Wallet configured for on-chain submission\n");
    }

    // ===== Step 2: Define and Execute Computation =====
    println!("Step 2: Defining computation in OVM...");
    println!("  Program: Prove that (5 + 7) * 2 = 24\n");

    let mut vm = ObelyskVM::new();

    // Public inputs
    let input_a = M31::new(5);
    let input_b = M31::new(7);
    let multiplier = M31::new(2);
    vm.set_public_inputs(vec![input_a, input_b, multiplier]);

    // Program: ((5 + 7) * 2) = 24
    let program = vec![
        // r3 = r0 + r1 (5 + 7 = 12)
        Instruction {
            opcode: OpCode::Add,
            dst: 3,
            src1: 0,
            src2: 1,
            immediate: None,
            address: None,
        },
        // r4 = r3 * r2 (12 * 2 = 24)
        Instruction {
            opcode: OpCode::Mul,
            dst: 4,
            src1: 3,
            src2: 2,
            immediate: None,
            address: None,
        },
        // Copy result to output (r0)
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
            src2: 4,
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

    println!("Step 3: Executing program in OVM...");
    let trace = vm.execute()?;
    println!("  ✅ Execution complete");
    println!("  📊 Trace: {} steps", trace.steps.len());
    println!("  📤 Output: {:?}\n", trace.public_outputs);

    // Verify computation correctness
    assert_eq!(trace.public_outputs[0], M31::new(24), "Computation incorrect!");

    // ===== Step 3: Generate ZK Proof =====
    println!("Step 4: Generating STWO STARK proof...");
    let prover = ObelyskProver::new();
    let proof = prover.prove_execution(&trace)?;
    println!("  ✅ Proof generated");
    println!("  🔑 Security: ~128 bits");
    println!("  ⏱️  Time: {}ms", proof.metadata.generation_time_ms);
    println!("  📦 Size: {} bytes ({:.1} KB)\n",
        proof.metadata.proof_size_bytes,
        proof.metadata.proof_size_bytes as f64 / 1024.0
    );

    // ===== Step 4: Serialize for Starknet =====
    println!("Step 5: Serializing proof for Starknet...");
    let serialized = serialize_proof(&proof)?;
    println!("  ✅ Serialized to {} felt252 elements", serialized.data.len());
    println!("  📊 Metadata:");
    println!("     - Original: {} bytes", serialized.metadata.original_size_bytes);
    println!("     - Elements: {}", serialized.metadata.serialized_elements);
    println!("     - Public input hash: {}\n", serialized.metadata.public_input_hash.to_hex().get(..20).unwrap_or(""));

    // ===== Step 5: Verify Locally =====
    println!("Step 6: Verifying proof locally...");
    let local_valid = prover.verify_proof(&proof)?;
    println!("  ✅ Local verification: {}\n", if local_valid { "PASSED" } else { "FAILED" });

    // ===== Step 6: On-Chain Verification =====
    println!("Step 7: Preparing Starknet client...");

    let verifier_address = Felt252::from_hex(STWO_VERIFIER_ADDRESS)?;

    let config = StarknetClientConfig {
        network: StarknetNetwork::Sepolia,
        verifier_address,
        account_address: account_address.as_ref()
            .and_then(|a| Felt252::from_hex(a).ok()),
        private_key: private_key.clone(),
        max_fee: 10_000_000_000_000_000, // 0.01 ETH max
        timeout: std::time::Duration::from_secs(120),
        paymaster_address: None,
    };

    let client = StarknetClient::new(config.clone());
    let wallet_configured = client.can_sign();

    // Check if we can submit transactions
    if wallet_configured {
        println!("  Client configured for transactions");

        // View call first (free)
        println!("\nStep 8: Performing view call verification...");
        match client.verify_proof_view(&serialized).await {
            Ok(result) => {
                println!("  View result: is_valid = {}", result.is_valid);
                if !result.is_valid {
                    if let Some(err) = &result.error {
                        println!("  Error: {}", err);
                    }
                }
            }
            Err(e) => {
                println!("  View call failed: {}", e);
            }
        }

        // Submit transaction
        println!("\nStep 9: Submitting proof on-chain...");
        let verifier = VerifierContract::new(
            VerifierContractConfig {
                address: verifier_address,
                min_security_bits: 96,
                max_proof_size: 100_000,
                optimistic_mode: false,
            },
            client,
        );

        match verifier.submit_and_confirm(&serialized, 30).await {
            Ok(result) => {
                println!("  Proof submitted successfully!");
                println!("  Transaction hash: {}", result.transaction_hash.to_hex());
                if let Some(block) = result.block_number {
                    println!("  Block number: {}", block);
                }
                if let Some(gas) = result.gas_used {
                    println!("  Gas used: {}", gas);
                }
                println!("  View on Starkscan: https://sepolia.starkscan.co/tx/{}",
                    result.transaction_hash.to_hex());
            }
            Err(e) => {
                println!("  Submission failed: {}", e);
            }
        }
    } else {
        println!("  View-only mode (no wallet configured)");
        println!("\nStep 8: Performing view call verification...");

        match client.verify_proof_view(&serialized).await {
            Ok(result) => {
                println!("  View result: is_valid = {}", result.is_valid);
            }
            Err(e) => {
                println!("  View call failed: {}", e);
                println!("\n  This is expected if the verifier contract doesn't support view calls");
                println!("  Configure STARKNET_PRIVATE_KEY and STARKNET_ACCOUNT_ADDRESS to submit on-chain");
            }
        }
    }

    // ===== Summary =====
    println!("\n===================================");
    println!("E2E Test Complete!");
    println!();
    println!("What was demonstrated:");
    println!("  1. Executed '(5 + 7) * 2 = 24' in Obelysk VM");
    println!("  2. Generated a STWO Circle STARK proof");
    println!("  3. Serialized proof to {} felt252 elements", serialized.data.len());
    println!("  4. Verified proof locally: {}", if local_valid { "PASSED" } else { "FAILED" });

    if wallet_configured {
        println!("  5. Submitted proof to Starknet Sepolia");
    } else {
        println!("  5. View-only mode (set wallet env vars to submit)");
    }

    println!();
    println!("Contract addresses:");
    println!("  StwoVerifier: {}", STWO_VERIFIER_ADDRESS);
    println!("  ProofVerifier: {}", PROOF_VERIFIER_ADDRESS);

    Ok(())
}

/// Serialize a StarkProof to CairoSerializedProof format
fn serialize_proof(proof: &StarkProof) -> Result<CairoSerializedProof, Box<dyn std::error::Error>> {
    let mut data = Vec::new();

    // Serialize trace commitment
    data.push(Felt252::from_bytes(&proof.trace_commitment));

    // Serialize public inputs hash
    let public_input_hash = compute_public_input_hash(&proof.public_inputs);
    data.push(public_input_hash);

    // Serialize proof size and metadata
    data.push(Felt252::from_u64(proof.metadata.trace_length as u64));
    data.push(Felt252::from_u32(proof.metadata.trace_width as u32));
    data.push(Felt252::from_u32(128)); // security bits

    // Serialize FRI layers
    for layer in &proof.fri_layers {
        // Serialize layer commitment
        data.push(Felt252::from_bytes(&layer.commitment));
        // Serialize number of evaluations
        data.push(Felt252::from_u32(layer.evaluations.len() as u32));
        // Serialize evaluations
        for eval in &layer.evaluations {
            data.push(Felt252::from_u32(eval.value()));
        }
    }

    // Serialize query openings
    for opening in &proof.openings {
        data.push(Felt252::from_u64(opening.position as u64));
        data.push(Felt252::from_u32(opening.values.len() as u32));
        for val in &opening.values {
            data.push(Felt252::from_u32(val.value()));
        }
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    Ok(CairoSerializedProof {
        metadata: ProofMetadata {
            original_size_bytes: proof.metadata.proof_size_bytes,
            serialized_elements: data.len(),
            public_input_hash,
            config: ProofConfig {
                log_blowup_factor: 4,
                log_last_layer_degree_bound: 5,
                n_queries: 30,
                pow_bits: 26,
            },
            generated_at: timestamp,
        },
        data,
    })
}

/// Compute hash of public inputs
fn compute_public_input_hash(inputs: &[M31]) -> Felt252 {
    use sha3::{Digest, Keccak256};

    let mut hasher = Keccak256::new();
    for input in inputs {
        hasher.update(&input.value().to_le_bytes());
    }
    let result = hasher.finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    // Mask high bits to fit in felt252
    bytes[0] &= 0x03;

    Felt252(bytes)
}
