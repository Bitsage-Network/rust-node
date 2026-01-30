//! Submit ML Inference Proof to Starknet
//!
//! This example loads the saved ML proof and submits it to the
//! StwoVerifier contract on Starknet Sepolia.
//!
//! Run with:
//! ```bash
//! STARKNET_PRIVATE_KEY=0x... \
//! STARKNET_ACCOUNT_ADDRESS=0x... \
//! cargo run --example submit_ml_proof_to_starknet --release
//! ```

use bitsage_node::obelysk::{
    StarkProof, M31,
    starknet::{
        proof_serializer::{Felt252, CairoSerializedProof, ProofMetadata, ProofConfig},
        starknet_client::{StarknetClient, StarknetClientConfig, StarknetNetwork},
    },
};
use std::env;
use std::fs;
use sha3::{Digest, Keccak256};

// Contract addresses on Sepolia (from deployment/final_deployed_contracts.json)
const STWO_VERIFIER_ADDRESS: &str = "0x52963fe2f1d2d2545cbe18b8230b739c8861ae726dc7b6f0202cc17a369bd7d";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== BitSage ML Proof Submission to Starknet ===\n");

    // Load the saved proof
    println!("Step 1: Loading saved ML inference proof...");
    let proof_json = fs::read_to_string("/tmp/ml_inference_proof.json")?;
    let proof: StarkProof = serde_json::from_str(&proof_json)?;

    println!("  Proof loaded successfully");
    println!("  - Trace: {}x{}", proof.metadata.trace_length, proof.metadata.trace_width);
    println!("  - Size: {} bytes", proof.metadata.proof_size_bytes);
    println!("  - FRI layers: {}", proof.fri_layers.len());

    // Serialize for Starknet
    println!("\nStep 2: Serializing proof for Starknet...");
    let serialized = serialize_proof_for_starknet(&proof)?;
    println!("  Serialized to {} felt252 elements", serialized.data.len());
    println!("  Public input hash: {}", serialized.metadata.public_input_hash.to_hex());

    // Print the serialized proof for manual submission if needed
    println!("\n=== Serialized Proof Data (for manual submission) ===");
    println!("\nproof_data: [");
    for (i, felt) in serialized.data.iter().enumerate() {
        if i < 10 || i >= serialized.data.len() - 3 {
            println!("  {},  // element {}", felt.to_hex(), i);
        } else if i == 10 {
            println!("  ... ({} more elements) ...", serialized.data.len() - 13);
        }
    }
    println!("]");
    println!("\npublic_input_hash: {}", serialized.metadata.public_input_hash.to_hex());

    // Check for wallet configuration
    let private_key = env::var("STARKNET_PRIVATE_KEY").ok();
    let account_address = env::var("STARKNET_ACCOUNT_ADDRESS").ok();

    if private_key.is_none() || account_address.is_none() {
        println!("\n=== Wallet Not Configured ===");
        println!("To submit this proof on-chain, set:");
        println!("  export STARKNET_PRIVATE_KEY=0x...");
        println!("  export STARKNET_ACCOUNT_ADDRESS=0x...");
        println!("\nAlternatively, use the above proof_data with Voyager or Starkscan:");
        println!("  Contract: {}", STWO_VERIFIER_ADDRESS);
        println!("  Function: submit_proof(proof_data, public_input_hash)");
        return Ok(());
    }

    println!("\nStep 3: Submitting proof to Starknet Sepolia...");

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

    let client = StarknetClient::new(config);

    if !client.can_sign() {
        println!("  Error: Wallet not properly configured");
        return Err("Wallet configuration error".into());
    }

    println!("  Wallet configured, submitting transaction...");

    match client.submit_proof(&serialized).await {
        Ok(result) => {
            println!("\n=== Proof Submitted Successfully! ===");
            println!("  Transaction hash: {}", result.transaction_hash.to_hex());
            if let Some(block) = result.block_number {
                println!("  Block number: {}", block);
            }
            println!("\n  View on Starkscan:");
            println!("  https://sepolia.starkscan.co/tx/{}", result.transaction_hash.to_hex());
        }
        Err(e) => {
            println!("\n  Submission failed: {}", e);
            println!("\n  You can still submit manually using the proof data above.");
        }
    }

    Ok(())
}

/// Serialize a StarkProof to CairoSerializedProof format
fn serialize_proof_for_starknet(proof: &StarkProof) -> Result<CairoSerializedProof, Box<dyn std::error::Error>> {
    let mut data = Vec::new();

    // Element 0: Trace commitment
    data.push(Felt252::from_bytes(&proof.trace_commitment));

    // Element 1: Security bits + trace dimensions (packed)
    let packed_config = (128u64 << 32) | (proof.metadata.trace_length as u64);
    data.push(Felt252::from_u64(packed_config));

    // Element 2: Trace width
    data.push(Felt252::from_u32(proof.metadata.trace_width as u32));

    // Element 3: Number of FRI layers
    data.push(Felt252::from_u32(proof.fri_layers.len() as u32));

    // Serialize FRI layers
    for layer in &proof.fri_layers {
        // Layer commitment
        data.push(Felt252::from_bytes(&layer.commitment));
        // Number of evaluations
        data.push(Felt252::from_u32(layer.evaluations.len() as u32));
        // Evaluations (M31 values fit in felt252)
        for eval in &layer.evaluations {
            data.push(Felt252::from_u32(eval.value()));
        }
    }

    // Number of query openings
    data.push(Felt252::from_u32(proof.openings.len() as u32));

    // Serialize query openings
    for opening in &proof.openings {
        data.push(Felt252::from_u64(opening.position as u64));
        data.push(Felt252::from_u32(opening.values.len() as u32));
        for val in &opening.values {
            data.push(Felt252::from_u32(val.value()));
        }
        // Merkle path length
        data.push(Felt252::from_u32(opening.merkle_path.len() as u32));
        for node in &opening.merkle_path {
            data.push(Felt252::from_bytes(node));
        }
    }

    // Public inputs
    data.push(Felt252::from_u32(proof.public_inputs.len() as u32));
    for input in &proof.public_inputs {
        data.push(Felt252::from_u32(input.value()));
    }

    // Public outputs
    data.push(Felt252::from_u32(proof.public_outputs.len() as u32));
    for output in &proof.public_outputs {
        data.push(Felt252::from_u32(output.value()));
    }

    // Compute public input hash
    let public_input_hash = compute_public_input_hash(&proof.public_inputs);

    Ok(CairoSerializedProof {
        metadata: ProofMetadata {
            original_size_bytes: proof.metadata.proof_size_bytes,
            serialized_elements: data.len(),
            public_input_hash,
            config: ProofConfig {
                log_blowup_factor: 4,
                log_last_layer_degree_bound: 5,
                n_queries: proof.openings.len(),
                pow_bits: 26,
            },
            generated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        },
        data,
    })
}

/// Compute hash of public inputs
fn compute_public_input_hash(inputs: &[M31]) -> Felt252 {
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
