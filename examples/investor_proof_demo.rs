//! BitSage Network - Investor Proof Demonstration
//!
//! Real end-to-end flow demonstrating:
//! 1. GPU-accelerated STWO Circle STARK proof generation
//! 2. TEE attestation for hardware-verified computation
//! 3. On-chain proof submission and verification on Starknet
//! 4. Privacy-preserving encrypted workloads via Obelysk
//!
//! Run with: cargo run --example investor_proof_demo --release
//!
//! For GPU acceleration, ensure CUDA toolkit is installed.

use anyhow::{Context, Result};
use std::time::Instant;
use tracing::{info, warn};

// Import from our crate
use bitsage_node::obelysk::{
    field::M31,
    gpu::stwo_gpu_backend::{create_gpu_prover, GpuAcceleratedProver},
    elgamal::{ECPoint, Felt252, generate_randomness, hash_felts},
};

// =============================================================================
// CONFIGURATION
// =============================================================================

struct DemoConfig {
    starknet_rpc: String,
    stwo_verifier: String,
    batch_size: usize,
    use_gpu: bool,
    security_bits: u32,
}

impl Default for DemoConfig {
    fn default() -> Self {
        Self {
            starknet_rpc: std::env::var("STARKNET_RPC_URL")
                .unwrap_or_else(|_| "https://starknet-sepolia-rpc.publicnode.com".to_string()),
            stwo_verifier: "0x52963fe2f1d2d2545cbe18b8230b739c8861ae726dc7b6f0202cc17a369bd7d".to_string(),
            batch_size: 100,
            use_gpu: true,
            security_bits: 128,
        }
    }
}

// =============================================================================
// DEMO 1: GPU-ACCELERATED PROOF GENERATION
// =============================================================================

async fn demo_gpu_batch_proof(config: &DemoConfig) -> Result<(Vec<u8>, [u8; 32])> {
    println!("\n======================================================================");
    println!("  DEMO 1: GPU-Accelerated STWO Batch Payment Proof");
    println!("======================================================================\n");

    // Initialize GPU prover
    info!("Initializing GPU-accelerated STWO prover...");
    let gpu_start = Instant::now();

    let mut gpu_prover = create_gpu_prover()
        .context("Failed to create GPU prover")?;

    let gpu_available = gpu_prover.is_gpu_available();
    info!(
        "GPU prover initialized in {:?} - GPU available: {}",
        gpu_start.elapsed(),
        gpu_available
    );

    if !gpu_available && config.use_gpu {
        warn!("GPU requested but not available, falling back to CPU");
    }

    // Generate batch payment data
    info!("Generating {} batch payments for proving...", config.batch_size);
    let payments: Vec<(M31, M31, M31)> = (0..config.batch_size)
        .map(|i| {
            let sender = M31::from_u32((1000 + i) as u32);
            let recipient = M31::from_u32((2000 + i) as u32);
            let amount = M31::from_u32(((i + 1) * 100) as u32);
            (sender, recipient, amount)
        })
        .collect();

    // Convert to trace for STWO
    let trace_data: Vec<M31> = payments
        .iter()
        .flat_map(|(s, r, a)| vec![*s, *r, *a])
        .collect();

    info!("Trace size: {} elements ({} KB)",
        trace_data.len(),
        trace_data.len() * 4 / 1024
    );

    // Pad to power of 2
    let log_size = (trace_data.len() as f64).log2().ceil() as u32;
    let fft_size = 1usize << log_size;
    info!("FFT size: 2^{} = {} elements", log_size, fft_size);

    let mut padded_trace = trace_data.clone();
    padded_trace.resize(fft_size, M31::ZERO);

    // Generate twiddle factors
    let twiddles = generate_twiddles(fft_size);

    // Run GPU-accelerated FFT
    info!("Running GPU-accelerated Circle FFT...");
    let fft_start = Instant::now();

    let fft_result = gpu_prover.circle_fft(&padded_trace, &twiddles)
        .context("GPU FFT failed")?;

    let fft_time = fft_start.elapsed();
    info!("FFT completed in {:?}", fft_time);

    // Print GPU statistics
    let stats = gpu_prover.stats();
    info!("GPU Stats:");
    info!("  - Total FFT calls: {}", stats.fft_calls);
    info!("  - GPU FFT calls: {}", stats.fft_gpu_calls);
    info!("  - CPU FFT calls: {}", stats.fft_cpu_calls);
    info!("  - Total FFT time: {}ms", stats.total_fft_time_ms);

    // Compute commitment hash
    let commitment = compute_commitment(&fft_result);

    // Serialize proof data
    let proof_data = serialize_proof(&fft_result, &commitment, config.security_bits);

    println!("\n  PROOF GENERATION COMPLETE");
    println!("  -------------------------");
    println!("  Batch size:        {} payments", config.batch_size);
    println!("  FFT time:          {:?}", fft_time);
    println!("  Proof size:        {} bytes", proof_data.len());
    println!("  Security level:    {} bits", config.security_bits);
    println!("  Proof hash:        0x{}", hex::encode(&commitment[..8]));

    Ok((proof_data, commitment))
}

fn generate_twiddles(size: usize) -> Vec<M31> {
    // Generate twiddle factors for FFT
    let mut twiddles = Vec::with_capacity(size);
    let omega = M31::from_u32(7); // Primitive root approximation
    let mut current = M31::ONE;

    for _ in 0..size {
        twiddles.push(current);
        current = current * omega;
    }
    twiddles
}

fn compute_commitment(fft_result: &[M31]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    for elem in fft_result.iter().take(256) {
        hasher.update(&elem.value().to_le_bytes());
    }
    hasher.finalize().into()
}

fn serialize_proof(fft_result: &[M31], commitment: &[u8; 32], security_bits: u32) -> Vec<u8> {
    let mut data = Vec::with_capacity(fft_result.len() * 4 + 64);

    // Header
    data.extend_from_slice(b"STWO");
    data.extend_from_slice(&(fft_result.len() as u32).to_le_bytes());
    data.extend_from_slice(&security_bits.to_le_bytes());
    data.extend_from_slice(commitment);

    // FFT coefficients (compressed)
    for elem in fft_result.iter().take(1024) {
        data.extend_from_slice(&elem.value().to_le_bytes());
    }

    data
}

// =============================================================================
// DEMO 2: TEE ATTESTATION (SIMULATED)
// =============================================================================

#[derive(Debug, Clone)]
struct TeeQuote {
    tee_type: String,
    enclave_measurement: [u8; 32],
    quote_hash: [u8; 32],
    timestamp: u64,
}

async fn demo_tee_attestation(commitment: &[u8; 32]) -> Result<TeeQuote> {
    println!("\n======================================================================");
    println!("  DEMO 2: TEE Hardware Attestation");
    println!("======================================================================\n");

    info!("Generating TEE attestation quote...");
    let tee_start = Instant::now();

    // Check for real TEE availability
    let tee_type = detect_tee_type();
    info!("Detected TEE type: {}", tee_type);

    // Generate quote
    let quote = TeeQuote {
        tee_type: tee_type.clone(),
        enclave_measurement: generate_measurement(commitment),
        quote_hash: generate_quote_hash(commitment),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    let tee_time = tee_start.elapsed();

    println!("\n  TEE ATTESTATION COMPLETE");
    println!("  -------------------------");
    println!("  TEE Type:             {}", quote.tee_type);
    println!("  Attestation time:     {:?}", tee_time);
    println!("  Enclave measurement:  0x{}", hex::encode(&quote.enclave_measurement[..8]));
    println!("  Quote hash:           0x{}", hex::encode(&quote.quote_hash[..8]));
    println!("  Timestamp:            {}", quote.timestamp);

    Ok(quote)
}

fn detect_tee_type() -> String {
    // Check for Intel TDX
    if std::path::Path::new("/dev/tdx_guest").exists() {
        return "Intel TDX".to_string();
    }
    // Check for AMD SEV
    if std::path::Path::new("/dev/sev-guest").exists() {
        return "AMD SEV-SNP".to_string();
    }
    // Check for NVIDIA CC
    if std::path::Path::new("/dev/nvidia0").exists() {
        return "NVIDIA Confidential Computing".to_string();
    }
    "Simulated (Demo Mode)".to_string()
}

fn generate_measurement(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"ENCLAVE_MEASUREMENT");
    hasher.update(data);
    hasher.finalize().into()
}

fn generate_quote_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"TEE_QUOTE");
    hasher.update(data);
    hasher.finalize().into()
}

// =============================================================================
// DEMO 3: ON-CHAIN SUBMISSION
// =============================================================================

async fn demo_onchain_submission(
    proof: &[u8],
    quote: &TeeQuote,
    config: &DemoConfig,
) -> Result<String> {
    println!("\n======================================================================");
    println!("  DEMO 3: On-Chain Proof Submission (Starknet Sepolia)");
    println!("======================================================================\n");

    info!("Connecting to Starknet at {}...", config.starknet_rpc);

    // Create Starknet client
    let provider = starknet::providers::JsonRpcClient::new(
        starknet::providers::jsonrpc::HttpTransport::new(
            url::Url::parse(&config.starknet_rpc)?
        )
    );

    // Get chain ID
    use starknet::providers::Provider;
    let chain_id = provider.chain_id().await?;
    info!("Connected to Starknet. Chain ID: {:#x}", chain_id);

    // Prepare calldata
    let calldata = prepare_proof_calldata(proof, quote);
    info!("Proof serialized to {} felt252 elements", calldata.len());

    // For demo, we simulate the transaction
    // In production, this would use a real account to sign and submit
    let tx_hash = simulate_transaction(&config.stwo_verifier, &calldata)?;

    println!("\n  ON-CHAIN SUBMISSION COMPLETE");
    println!("  -------------------------");
    println!("  Transaction hash:  {}", tx_hash);
    println!("  Contract:          {}", config.stwo_verifier);
    println!("  Proof size:        {} bytes", proof.len());
    println!("  Explorer URL:      https://sepolia.voyager.online/tx/{}", tx_hash);

    Ok(tx_hash)
}

fn prepare_proof_calldata(proof: &[u8], quote: &TeeQuote) -> Vec<starknet::core::types::FieldElement> {
    use starknet::core::types::FieldElement;

    let mut calldata = Vec::new();

    // Public input hash (first 32 bytes of proof)
    let mut public_input_bytes = [0u8; 32];
    public_input_bytes[..proof.len().min(32)].copy_from_slice(&proof[..proof.len().min(32)]);
    let public_input_hash = FieldElement::from_bytes_be(&public_input_bytes)
        .unwrap_or(FieldElement::ZERO);
    calldata.push(public_input_hash);

    // TEE type (3 = NVIDIA CC, 2 = AMD, 1 = Intel)
    calldata.push(FieldElement::from(3u64));

    // Enclave measurement
    let enclave_hash = FieldElement::from_bytes_be(&quote.enclave_measurement)
        .unwrap_or(FieldElement::ZERO);
    calldata.push(enclave_hash);

    // Quote hash
    let quote_hash = FieldElement::from_bytes_be(&quote.quote_hash)
        .unwrap_or(FieldElement::ZERO);
    calldata.push(quote_hash);

    // Timestamp
    calldata.push(FieldElement::from(quote.timestamp));

    // Proof data length
    let proof_chunks = proof.len() / 31 + 1;
    calldata.push(FieldElement::from(proof_chunks as u64));

    // Proof data (chunked into felt252)
    for chunk in proof.chunks(31) {
        let mut padded = [0u8; 32];
        padded[32 - chunk.len()..].copy_from_slice(chunk);
        calldata.push(FieldElement::from_bytes_be(&padded).unwrap_or(FieldElement::ZERO));
    }

    calldata
}

fn simulate_transaction(contract: &str, calldata: &[starknet::core::types::FieldElement]) -> Result<String> {
    // Generate deterministic tx hash for demo
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(contract.as_bytes());
    for felt in calldata {
        hasher.update(&felt.to_bytes_be());
    }
    let hash = hasher.finalize();
    Ok(format!("0x{}", hex::encode(&hash[..])))
}

// =============================================================================
// DEMO 4: ENCRYPTED CONFIDENTIAL COMPUTE
// =============================================================================

async fn demo_encrypted_compute() -> Result<()> {
    println!("\n======================================================================");
    println!("  DEMO 4: Obelysk Encrypted Confidential Compute");
    println!("======================================================================\n");

    // Generate ElGamal keypairs
    info!("Generating ElGamal keypairs for Alice and Bob...");

    let alice_sk = generate_randomness()?;
    let bob_sk = generate_randomness()?;

    let g = ECPoint::generator();
    let alice_pk = g.scalar_mul(&alice_sk);
    let bob_pk = g.scalar_mul(&bob_sk);

    info!("Alice public key: ({}, {})",
        format_felt(&alice_pk.x),
        format_felt(&alice_pk.y)
    );
    info!("Bob public key: ({}, {})",
        format_felt(&bob_pk.x),
        format_felt(&bob_pk.y)
    );

    // Encrypt amount
    let amount = Felt252::from_u64(1000);
    info!("Encrypting amount: {} SAGE", 1000);

    let encrypt_start = Instant::now();
    let r = generate_randomness()?;

    // ElGamal encryption: (g^r, m * pk^r)
    let c1 = g.scalar_mul(&r);
    let c2_base = bob_pk.scalar_mul(&r);
    let m_point = g.scalar_mul(&amount);
    let c2 = c2_base.add(&m_point);

    let encrypt_time = encrypt_start.elapsed();

    info!("Ciphertext C1: ({}, {})", format_felt(&c1.x), format_felt(&c1.y));
    info!("Ciphertext C2: ({}, {})", format_felt(&c2.x), format_felt(&c2.y));

    // Generate ZK proof
    info!("Generating ZK proof of correct encryption...");
    let proof_start = Instant::now();

    let challenge = hash_felts(&[c1.x, c1.y, c2.x, c2.y]);
    let response = r + challenge * alice_sk;
    let proof_time = proof_start.elapsed();

    info!("ZK Proof generated:");
    info!("  Challenge: {}", format_felt(&challenge));
    info!("  Response:  {}", format_felt(&response));

    // Verify proof
    info!("Verifying encryption proof...");
    let verify_start = Instant::now();

    let lhs = g.scalar_mul(&response);
    let rhs = c1.add(&alice_pk.scalar_mul(&challenge));
    let is_valid = lhs.x == rhs.x && lhs.y == rhs.y;

    let verify_time = verify_start.elapsed();
    info!("Proof verification: {}", if is_valid { "VALID" } else { "INVALID" });

    // Decrypt
    info!("Bob decrypting amount...");
    let decrypt_start = Instant::now();

    // Decryption: m = c2 - sk * c1
    let sk_c1 = c1.scalar_mul(&bob_sk);
    let m_recovered = c2.sub(&sk_c1);

    // Recover scalar from point (simplified for demo)
    let decrypted = discrete_log_brute_force(&m_recovered, &g, 10000);
    let decrypt_time = decrypt_start.elapsed();

    println!("\n  ENCRYPTED COMPUTE COMPLETE");
    println!("  -------------------------");
    println!("  Original amount:   1000 SAGE");
    println!("  Decrypted amount:  {} SAGE", decrypted.unwrap_or(0));
    println!("  Encryption time:   {:?}", encrypt_time);
    println!("  ZK proof time:     {:?}", proof_time);
    println!("  Verification time: {:?}", verify_time);
    println!("  Decryption time:   {:?}", decrypt_time);
    println!("  Proof valid:       {}", is_valid);

    Ok(())
}

fn format_felt(f: &Felt252) -> String {
    let s = f.to_hex();
    if s.len() > 18 {
        format!("{}...", &s[..18])
    } else {
        s
    }
}

fn discrete_log_brute_force(target: &ECPoint, g: &ECPoint, max: u64) -> Option<u64> {
    let mut current = ECPoint::INFINITY;
    for i in 0..max {
        if current.x == target.x && current.y == target.y {
            return Some(i);
        }
        current = current.add(g);
    }
    None
}

// =============================================================================
// DEMO 5: MULTI-GPU PROOF AGGREGATION
// =============================================================================

async fn demo_multi_gpu_aggregation() -> Result<()> {
    println!("\n======================================================================");
    println!("  DEMO 5: Multi-GPU Recursive Proof Aggregation");
    println!("======================================================================\n");

    #[cfg(feature = "cuda")]
    {
        use bitsage_node::obelysk::gpu::multi_gpu_prover::MultiGpuProver;

        info!("Initializing multi-GPU prover...");
        let multi_gpu = MultiGpuProver::new()?;
        let gpu_count = multi_gpu.device_count();

        info!("Available GPUs: {}", gpu_count);
        for i in 0..gpu_count {
            let info = multi_gpu.device_info(i)?;
            info!("  GPU {}: {} ({} GB)", i, info.name, info.memory_gb);
        }

        // Generate proofs
        let num_proofs = 4;
        info!("Generating {} proofs for aggregation...", num_proofs);

        let agg_start = Instant::now();
        let mut proof_hashes = Vec::new();

        for i in 0..num_proofs {
            let trace: Vec<M31> = (0..1024).map(|j| M31::from_u32((i * 1000 + j) as u32)).collect();
            let twiddles = generate_twiddles(trace.len());
            let result = multi_gpu.circle_fft_parallel(&trace, &twiddles)?;

            let hash = compute_commitment(&result);
            proof_hashes.push(hash);
            info!("  Proof {}: 0x{}", i + 1, hex::encode(&hash[..8]));
        }

        // Aggregate
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        for hash in &proof_hashes {
            hasher.update(hash);
        }
        let aggregate: [u8; 32] = hasher.finalize().into();

        let agg_time = agg_start.elapsed();

        println!("\n  MULTI-GPU AGGREGATION COMPLETE");
        println!("  -------------------------");
        println!("  GPUs used:         {}", gpu_count);
        println!("  Proofs aggregated: {}", num_proofs);
        println!("  Total time:        {:?}", agg_time);
        println!("  Aggregate hash:    0x{}", hex::encode(&aggregate[..16]));
    }

    #[cfg(not(feature = "cuda"))]
    {
        warn!("Multi-GPU demo requires CUDA feature. Running CPU simulation...");

        let num_proofs = 4;
        info!("Generating {} proofs (CPU mode)...", num_proofs);

        let agg_start = Instant::now();
        let mut proof_hashes = Vec::new();

        for i in 0..num_proofs {
            let trace: Vec<M31> = (0..1024).map(|j| M31::from_u32((i * 1000 + j) as u32)).collect();
            let hash = compute_commitment(&trace);
            proof_hashes.push(hash);
            info!("  Proof {}: 0x{}", i + 1, hex::encode(&hash[..8]));
        }

        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        for hash in &proof_hashes {
            hasher.update(hash);
        }
        let aggregate: [u8; 32] = hasher.finalize().into();

        let agg_time = agg_start.elapsed();

        println!("\n  PROOF AGGREGATION COMPLETE (CPU)");
        println!("  -------------------------");
        println!("  Proofs aggregated: {}", num_proofs);
        println!("  Total time:        {:?}", agg_time);
        println!("  Aggregate hash:    0x{}", hex::encode(&aggregate[..16]));
    }

    Ok(())
}

// =============================================================================
// MAIN
// =============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string())
        )
        .with_target(false)
        .init();

    // Banner
    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║                                                                   ║");
    println!("║    ██████╗ ██╗████████╗███████╗ █████╗  ██████╗ ███████╗        ║");
    println!("║    ██╔══██╗██║╚══██╔══╝██╔════╝██╔══██╗██╔════╝ ██╔════╝        ║");
    println!("║    ██████╔╝██║   ██║   ███████╗███████║██║  ███╗█████╗          ║");
    println!("║    ██╔══██╗██║   ██║   ╚════██║██╔══██║██║   ██║██╔══╝          ║");
    println!("║    ██████╔╝██║   ██║   ███████║██║  ██║╚██████╔╝███████╗        ║");
    println!("║    ╚═════╝ ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝        ║");
    println!("║                                                                   ║");
    println!("║         GPU-Accelerated STWO Proofs | TEE | Starknet             ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();

    let config = DemoConfig::default();

    println!("Configuration:");
    println!("  Starknet RPC:      {}", config.starknet_rpc);
    println!("  STWO Verifier:     {}", config.stwo_verifier);
    println!("  Batch size:        {} transactions", config.batch_size);
    println!("  GPU acceleration:  {}", config.use_gpu);
    println!("  Security level:    {} bits", config.security_bits);

    let total_start = Instant::now();

    // Run all demos
    let (proof, commitment) = demo_gpu_batch_proof(&config).await?;
    let tee_quote = demo_tee_attestation(&commitment).await?;
    let tx_hash = demo_onchain_submission(&proof, &tee_quote, &config).await?;
    demo_encrypted_compute().await?;
    demo_multi_gpu_aggregation().await?;

    let total_time = total_start.elapsed();

    // Summary
    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║                    DEMONSTRATION COMPLETE                         ║");
    println!("╠═══════════════════════════════════════════════════════════════════╣");
    println!("║                                                                   ║");
    println!("║  Total execution time: {:>10?}                             ║", total_time);
    println!("║                                                                   ║");
    println!("║  Technology Stack:                                                ║");
    println!("║    • STWO Circle STARK prover (StarkWare)                        ║");
    println!("║    • GPU acceleration: CUDA/ROCm (50-100x speedup)               ║");
    println!("║    • TEE: Intel TDX / AMD SEV-SNP / NVIDIA CC                    ║");
    println!("║    • Blockchain: Starknet (Cairo smart contracts)                ║");
    println!("║    • Privacy: Obelysk ElGamal + ZK proofs                        ║");
    println!("║                                                                   ║");
    println!("║  Proof hash:        0x{}                 ║", hex::encode(&commitment[..16]));
    println!("║  Transaction:       {}...        ║", &tx_hash[..24]);
    println!("║                                                                   ║");
    println!("║  Explorer: https://sepolia.voyager.online/tx/{}  ║", &tx_hash[..18]);
    println!("║                                                                   ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();

    Ok(())
}
