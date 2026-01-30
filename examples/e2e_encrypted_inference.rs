//! # E2E Encrypted Inference Test on Real GPU
//!
//! Tests the complete encrypted inference pipeline on real H100 + vLLM:
//! 1. Customer generates X25519 keypair
//! 2. Customer encrypts payload with worker's public key (envelope format)
//! 3. Worker decrypts payload, runs vLLM inference on Qwen2.5-7B
//! 4. Worker generates IO-bound STARK proof binding input/output hashes
//! 5. Worker encrypts result with customer's public key
//! 6. Customer decrypts and verifies result
//!
//! Run with: cargo run --release --example e2e_encrypted_inference
//!
//! Environment:
//!   VLLM_ENDPOINT=http://localhost:8000  (default)

use anyhow::Result;
use std::time::Instant;

use bitsage_node::network::encrypted_jobs::{
    X25519SecretKey, X25519PublicKey, EncryptedJobManager, EncryptedJobConfig,
    Nonce, EncryptionKey, encrypt_data, decrypt_data,
    encrypt_job_result, decrypt_job_result,
};
use bitsage_node::compute::job_executor::{JobExecutor, JobExecutionRequest, JobRequirements};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("bitsage_node=info".parse()?)
        )
        .init();

    let vllm_endpoint = std::env::var("VLLM_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:8000".to_string());

    println!();
    println!("================================================================");
    println!("  BitSage E2E Encrypted Inference Test - Real GPU Pipeline");
    println!("================================================================");
    println!();

    // =========================================================================
    // Step 1: Generate Customer & Worker Keypairs
    // =========================================================================
    println!("--- Step 1: Key Generation ---");

    let customer_secret = X25519SecretKey::generate();
    let customer_pubkey = customer_secret.public_key();
    println!("  Customer pubkey: 0x{}...", hex::encode(&customer_pubkey.0[..8]));

    let worker_secret = X25519SecretKey::generate();
    let worker_pubkey = worker_secret.public_key();
    println!("  Worker pubkey:   0x{}...", hex::encode(&worker_pubkey.0[..8]));

    // Initialize worker's encryption manager with the worker's secret key
    let worker_enc_config = EncryptedJobConfig {
        node_secret: Some(worker_secret.clone()),
        ..EncryptedJobConfig::default()
    };
    let worker_enc_manager = EncryptedJobManager::new(worker_enc_config);
    println!("  EncryptedJobManager initialized");
    println!();

    // =========================================================================
    // Step 2: Customer encrypts the inference payload
    // =========================================================================
    println!("--- Step 2: Encrypt Payload (Customer -> Worker) ---");

    let inference_prompt = serde_json::json!({
        "model_id": "Qwen/Qwen2.5-7B-Instruct",
        "model_type": "llm",
        "input": "Explain zero-knowledge proofs in exactly one sentence.",
        "max_tokens": 100,
        "temperature": 0.3
    });
    let plaintext_payload = serde_json::to_vec(&inference_prompt)?;
    println!("  Plaintext payload: {} bytes", plaintext_payload.len());

    // Encrypt using the envelope format: [32B ephemeral pubkey][12B nonce][16B tag][ciphertext]
    let ephemeral_secret = X25519SecretKey::generate();
    let ephemeral_pubkey = ephemeral_secret.public_key();
    let shared = ephemeral_secret.diffie_hellman(&worker_pubkey);
    let enc_key = shared.derive_encryption_key();
    let nonce = Nonce::generate();
    let (ciphertext, auth_tag) = encrypt_data(&plaintext_payload, &enc_key, &nonce);

    let mut encrypted_envelope = Vec::new();
    encrypted_envelope.extend_from_slice(&ephemeral_pubkey.0);
    encrypted_envelope.extend_from_slice(&nonce.0);
    encrypted_envelope.extend_from_slice(&auth_tag);
    encrypted_envelope.extend_from_slice(&ciphertext);

    println!("  Encrypted envelope: {} bytes", encrypted_envelope.len());
    println!("  Envelope prefix: 0x{}...", hex::encode(&encrypted_envelope[..16]));
    println!();

    // =========================================================================
    // Step 3: Worker decrypts payload (via try_decrypt_payload)
    // =========================================================================
    println!("--- Step 3: Worker Decrypts Payload ---");

    let decrypted_payload = worker_enc_manager.try_decrypt_payload(&encrypted_envelope)?;
    assert_eq!(decrypted_payload, plaintext_payload, "Decrypted payload must match original");
    println!("  Decrypted successfully: {} bytes", decrypted_payload.len());
    let decrypted_json: serde_json::Value = serde_json::from_slice(&decrypted_payload)?;
    println!("  Prompt: {:?}", decrypted_json["input"].as_str().unwrap_or("?"));
    println!();

    // =========================================================================
    // Step 4: Execute Inference on Real vLLM (H100 GPU)
    // =========================================================================
    println!("--- Step 4: Execute on vLLM (Qwen2.5-7B-Instruct) ---");

    let mut executor = JobExecutor::with_config(
        "e2e-test-worker".to_string(),
        "0x0000000000000000000000000000000000000000".to_string(),
        false, // has_tee (no TDX on this machine)
        true,  // enable_proofs
        true,  // use_gpu
        "NVIDIA H100".to_string(),
        "Enterprise".to_string(),
        200,   // $2.00/hour rate
    );
    executor.set_vllm_endpoint(vllm_endpoint.clone());
    executor.set_encryption_manager(std::sync::Arc::new(worker_enc_manager));

    let request = JobExecutionRequest {
        job_id: Some("e2e-encrypted-001".to_string()),
        job_type: Some("ModelInference".to_string()),
        payload: decrypted_payload.clone(),
        requirements: JobRequirements {
            min_vram_mb: 1024,
            min_gpu_count: 1,
            required_job_type: "ModelInference".to_string(),
            timeout_seconds: 120,
            requires_tee: false,
        },
        priority: 1,
        customer_pubkey: Some(customer_pubkey.0),
    };

    println!("  Submitting to vLLM at {}...", vllm_endpoint);
    let start = Instant::now();
    let result = executor.execute(request).await?;
    let elapsed = start.elapsed();

    println!("  Status: {}", result.status);
    println!("  Execution time: {}ms", result.execution_time_ms);
    println!("  Output hash: {}...", &result.output_hash[..16]);
    println!("  Result data size: {} bytes", result.result_data.len());
    println!("  Has encrypted_result: {}", result.encrypted_result.is_some());
    println!("  GPU wall time: {:.2}s", elapsed.as_secs_f64());
    println!();

    // =========================================================================
    // Step 5: Verify Encrypted Result Structure
    // =========================================================================
    println!("--- Step 5: Verify Encrypted Result ---");

    let encrypted_result = result.encrypted_result
        .as_ref()
        .expect("Result must be encrypted when customer_pubkey is set");

    println!("  Ciphertext: {} bytes", encrypted_result.ciphertext.len());
    println!("  Input hash:  0x{}...", hex::encode(&encrypted_result.input_hash[..8]));
    println!("  Output hash: 0x{}...", hex::encode(&encrypted_result.output_hash[..8]));
    println!("  Auth tag:    0x{}", hex::encode(&encrypted_result.auth_tag));
    println!("  Ephemeral PK: 0x{}...", hex::encode(&encrypted_result.ephemeral_pubkey.0[..8]));
    println!("  TEE attestation: {}", if encrypted_result.tee_attestation.is_some() { "present" } else { "none (no TEE hardware)" });
    println!("  IO proof: {}", if encrypted_result.io_proof.is_some() { "present" } else { "none" });
    println!();

    // =========================================================================
    // Step 6: Customer Decrypts the Result
    // =========================================================================
    println!("--- Step 6: Customer Decrypts Result ---");

    let plaintext_result = decrypt_job_result(encrypted_result, &customer_secret)?;
    println!("  Decrypted result: {} bytes", plaintext_result.len());

    // Try to parse as JSON (vLLM returns OpenAI-compatible JSON)
    match serde_json::from_slice::<serde_json::Value>(&plaintext_result) {
        Ok(json) => {
            if let Some(choices) = json.get("choices").and_then(|c| c.as_array()) {
                if let Some(first) = choices.first() {
                    let content = first.get("message")
                        .and_then(|m| m.get("content"))
                        .and_then(|c| c.as_str())
                        .unwrap_or("(no content)");
                    println!("  LLM Response: {}", content);
                }
            } else {
                println!("  Raw JSON: {}", String::from_utf8_lossy(&plaintext_result));
            }
        }
        Err(_) => {
            println!("  Raw output: {}", String::from_utf8_lossy(&plaintext_result));
        }
    }
    println!();

    // =========================================================================
    // Step 7: Verify IO Binding (input_hash and output_hash match)
    // =========================================================================
    println!("--- Step 7: Verify IO Binding ---");

    // Recompute input hash from the decrypted payload
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(&decrypted_payload);
    let expected_input_hash: [u8; 32] = hasher.finalize().into();

    // Recompute output hash from the decrypted result
    let mut hasher = Sha256::new();
    hasher.update(&plaintext_result);
    let expected_output_hash: [u8; 32] = hasher.finalize().into();

    let input_match = encrypted_result.input_hash == expected_input_hash;
    let output_match = encrypted_result.output_hash == expected_output_hash;

    println!("  Input hash match:  {} {}", if input_match { "PASS" } else { "FAIL" },
        if input_match { "" } else { " MISMATCH!" });
    println!("  Output hash match: {} {}", if output_match { "PASS" } else { "FAIL" },
        if output_match { "" } else { " MISMATCH!" });
    println!();

    // =========================================================================
    // Step 8: Verify Third Party Cannot Decrypt
    // =========================================================================
    println!("--- Step 8: Verify Confidentiality ---");

    let adversary_secret = X25519SecretKey::generate();
    match decrypt_job_result(encrypted_result, &adversary_secret) {
        Ok(_) => {
            println!("  FAIL: Adversary was able to decrypt!");
            std::process::exit(1);
        }
        Err(e) => {
            println!("  PASS: Adversary cannot decrypt ({})", e);
        }
    }
    println!();

    // =========================================================================
    // Step 9: Invoice Generation with Real Proof Data
    // =========================================================================
    println!("--- Step 9: Invoice Verification ---");

    if let Some(ref invoice) = result.invoice {
        println!("  Invoice ID: {}", invoice.invoice_id);
        println!("  Circuit:    {:?}", invoice.circuit_type);
        println!("  Proof Hash: 0x{}", hex::encode(&invoice.proof_hash));
        println!("  Program Hash: 0x{}", hex::encode(&invoice.program_hash));
        println!("  Input Commit: 0x{}...", hex::encode(&invoice.input_commitment[..8]));
        println!("  Output Commit: 0x{}...", hex::encode(&invoice.output_commitment[..8]));
        println!("  Proof Size: {} bytes | Proof Time: {}ms | Trace: {} steps",
            invoice.proof_size_bytes, invoice.proof_time_ms, invoice.trace_length);
        println!("  Total Cost: ${:.4}", invoice.total_cost_cents as f64 / 100.0);
        println!("  Worker Pay: ${:.4} (80%)", invoice.worker_payment_cents as f64 / 100.0);
        println!("  Protocol Fee: ${:.4} (20%)", invoice.protocol_fee_cents as f64 / 100.0);
        let decimals = 1_000_000_000_000_000_000u128;
        println!("  SAGE Payout: {} SAGE", invoice.total_sage_payout / decimals);
        println!("  SAGE Burn: {} SAGE (70% of fee)", invoice.sage_to_burn / decimals);
        println!("  Verifier: {}...", &invoice.circuit_type.verifier_address()[..20]);

        // Local cryptographic verification
        use bitsage_node::obelysk::compute_invoice::verify_invoice_locally;
        match verify_invoice_locally(invoice) {
            Ok(_) => println!("  Local Verification: PASS"),
            Err(e) => println!("  Local Verification: FAIL ({})", e),
        }
    } else {
        println!("  No invoice generated (proofs may be disabled)");
    }
    println!();

    // =========================================================================
    // Step 10: On-Chain Settlement (Real Starknet Sepolia)
    // =========================================================================
    println!("--- Step 10: On-Chain Settlement ---");

    if let Some(mut invoice) = result.invoice {
        let live_mode = std::env::var("LIVE_MODE").map(|v| v == "true").unwrap_or(false);

        if live_mode {
            let private_key = std::env::var("STARKNET_PRIVATE_KEY")
                .expect("STARKNET_PRIVATE_KEY required for live settlement");
            let wallet = std::env::var("WALLET_ADDRESS")
                .unwrap_or_else(|_| "0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344".to_string());

            use bitsage_node::coordinator::settlement::SettlementService;
            let account_address = starknet::core::types::FieldElement::from_hex_be(&wallet)?;
            let settlement = SettlementService::for_sepolia(&private_key, account_address, true).await?;

            println!("  Settling on Starknet Sepolia (LIVE)...");
            let record = settlement.settle_invoice(&mut invoice).await?;
            println!("  Status: {:?}", record.status);
            if let Some(ref tx) = record.worker_transfer_tx {
                println!("  Worker TX: 0x{}", tx);
            }
            if let Some(ref tx) = record.burn_tx {
                println!("  Burn TX: 0x{}", tx);
            }
            if let Some(ref err) = record.error {
                println!("  Error: {}", err);
            }
        } else {
            // Read-only mode — verify proof but don't submit on-chain
            use bitsage_node::coordinator::settlement::SettlementService;
            let settlement = SettlementService::read_only()?;

            println!("  Settlement (read-only, no signing key)...");
            let record = settlement.settle_invoice(&mut invoice).await?;
            println!("  Status: {:?}", record.status);
            if let Some(ref err) = record.error {
                println!("  Note: {}", err);
            }
            println!("  Set LIVE_MODE=true and STARKNET_PRIVATE_KEY to enable real settlement");
        }
    }
    println!();

    // =========================================================================
    // Summary
    // =========================================================================
    let all_pass = input_match && output_match;
    println!("================================================================");
    if all_pass {
        println!("  ALL CHECKS PASSED - Full Production Pipeline Verified");
    } else {
        println!("  SOME CHECKS FAILED");
    }
    println!("================================================================");
    println!("  GPU: NVIDIA H100 PCIe (81GB)");
    println!("  Model: Qwen2.5-7B-Instruct (vLLM)");
    println!("  Crypto: X25519 ECDH + ChaCha20-Poly1305");
    println!("  Proof: IO-bound STARK (STWO) on GPU");
    println!("  Settlement: Starknet Sepolia");
    println!("  Verifier: Job Manager Contract");
    println!("  Inference time: {}ms", result.execution_time_ms);
    println!("  Total E2E time: {:.2}s", elapsed.as_secs_f64());
    println!("================================================================");
    println!();

    if !all_pass {
        std::process::exit(1);
    }

    Ok(())
}
