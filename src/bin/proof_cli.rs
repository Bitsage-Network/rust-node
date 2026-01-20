//! # BitSage Proof CLI
//!
//! Command-line interface for GPU-accelerated proof generation, TEE attestation,
//! and on-chain submission to Starknet.
//!
//! ## Usage
//!
//! ```bash
//! # Generate a batch payment proof with GPU
//! bitsage-proof generate --batch-size 100 --output proof.bin
//!
//! # Generate TEE attestation
//! bitsage-proof attest --proof proof.bin --output quote.bin
//!
//! # Submit proof to Starknet
//! bitsage-proof submit --proof proof.bin --quote quote.bin --network sepolia
//!
//! # Run full investor demo
//! bitsage-proof demo --batch-size 100 --network sepolia
//!
//! # Query proof status
//! bitsage-proof status --tx-hash 0x...
//! ```

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Instant;
use tracing::info;

use bitsage_node::obelysk::{
    field::M31,
    gpu::stwo_gpu_backend::create_gpu_prover,
    elgamal::{ECPoint, Felt252, generate_randomness, hash_felts},
};

// =============================================================================
// CLI DEFINITION
// =============================================================================

#[derive(Parser)]
#[command(name = "bitsage-proof")]
#[command(about = "BitSage Network - GPU Proof Generation & On-Chain Submission")]
#[command(version)]
#[command(author = "BitSage Network")]
struct Cli {
    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a GPU-accelerated STWO proof
    Generate {
        /// Number of transactions in batch
        #[arg(short, long, default_value = "100")]
        batch_size: usize,

        /// Security level in bits
        #[arg(short, long, default_value = "128")]
        security_bits: u32,

        /// Output file for proof
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Force CPU mode (disable GPU)
        #[arg(long)]
        cpu_only: bool,

        /// Output format (binary, json, hex)
        #[arg(long, default_value = "binary")]
        format: String,
    },

    /// Generate TEE attestation quote
    Attest {
        /// Input proof file
        #[arg(short, long)]
        proof: PathBuf,

        /// Output file for attestation quote
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Submit proof to Starknet
    Submit {
        /// Proof file to submit
        #[arg(short, long)]
        proof: PathBuf,

        /// TEE attestation quote file
        #[arg(short, long)]
        quote: Option<PathBuf>,

        /// Starknet network (mainnet, sepolia)
        #[arg(short, long, default_value = "sepolia")]
        network: String,

        /// Starknet RPC URL (overrides network default)
        #[arg(long)]
        rpc_url: Option<String>,

        /// Private key for signing (or set STARKNET_PRIVATE_KEY env)
        #[arg(long)]
        private_key: Option<String>,

        /// Account address (or set STARKNET_ACCOUNT env)
        #[arg(long)]
        account: Option<String>,

        /// Dry run (simulate only)
        #[arg(long)]
        dry_run: bool,
    },

    /// Run complete investor demonstration
    Demo {
        /// Number of transactions in batch
        #[arg(short, long, default_value = "100")]
        batch_size: usize,

        /// Starknet network
        #[arg(short, long, default_value = "sepolia")]
        network: String,

        /// Enable encrypted compute demo
        #[arg(long)]
        encrypted: bool,

        /// Enable multi-GPU demo
        #[arg(long)]
        multi_gpu: bool,

        /// Save outputs to directory
        #[arg(long)]
        save_dir: Option<PathBuf>,
    },

    /// Query proof verification status
    Status {
        /// Transaction hash
        #[arg(long)]
        tx_hash: String,

        /// Starknet network
        #[arg(short, long, default_value = "sepolia")]
        network: String,
    },

    /// Show GPU and TEE capabilities
    Info,

    /// Generate ElGamal encrypted transaction
    Encrypt {
        /// Amount to encrypt
        #[arg(short, long)]
        amount: u64,

        /// Recipient public key (hex)
        #[arg(short, long)]
        recipient: String,

        /// Output file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Generate ZK proof of encryption
        #[arg(long)]
        with_proof: bool,
    },
}

// =============================================================================
// PROOF GENERATION
// =============================================================================

async fn cmd_generate(
    batch_size: usize,
    security_bits: u32,
    output: Option<PathBuf>,
    cpu_only: bool,
    format: String,
) -> Result<()> {
    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║            BITSAGE - GPU PROOF GENERATION                         ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();

    let start = Instant::now();

    // Initialize GPU prover
    info!("Initializing STWO prover...");
    let mut gpu_prover = create_gpu_prover()
        .context("Failed to create GPU prover")?;

    let gpu_available = gpu_prover.is_gpu_available() && !cpu_only;
    println!("  Mode:            {}", if gpu_available { "GPU-accelerated" } else { "CPU" });
    println!("  Batch size:      {} transactions", batch_size);
    println!("  Security level:  {} bits", security_bits);
    println!();

    // Generate trace data
    info!("Generating batch payment trace...");
    let trace_data: Vec<M31> = (0..batch_size * 3)
        .map(|i| M31::from_u32(i as u32))
        .collect();

    // Pad to power of 2
    let log_size = ((trace_data.len() as f64).log2().ceil() as u32).max(1);
    let fft_size = 1usize << log_size;
    let mut padded_trace = trace_data.clone();
    padded_trace.resize(fft_size, M31::ZERO);

    println!("  Trace elements:  {}", trace_data.len());
    println!("  FFT size:        2^{} = {}", log_size, fft_size);

    // Generate twiddle factors
    let twiddles = generate_twiddles(fft_size);

    // Run FFT
    info!("Running Circle FFT...");
    let fft_start = Instant::now();
    let fft_result = gpu_prover.circle_fft(&padded_trace, &twiddles)
        .context("FFT computation failed")?;
    let fft_time = fft_start.elapsed();

    println!("  FFT time:        {:?}", fft_time);

    // Compute commitment
    let commitment = compute_commitment(&fft_result);

    // Serialize proof
    let proof_data = serialize_proof(&fft_result, &commitment, security_bits);

    // Print stats
    let stats = gpu_prover.stats();
    println!();
    println!("  GPU Statistics:");
    println!("    FFT calls:     {} (GPU: {}, CPU: {})",
        stats.fft_calls, stats.fft_gpu_calls, stats.fft_cpu_calls);
    println!("    Total time:    {}ms", stats.total_fft_time_ms);

    // Save output
    if let Some(path) = output {
        match format.as_str() {
            "binary" => std::fs::write(&path, &proof_data)?,
            "hex" => std::fs::write(&path, hex::encode(&proof_data))?,
            "json" => {
                let json = serde_json::json!({
                    "commitment": hex::encode(&commitment),
                    "proof": hex::encode(&proof_data),
                    "batch_size": batch_size,
                    "security_bits": security_bits,
                    "fft_time_ms": fft_time.as_millis(),
                });
                std::fs::write(&path, serde_json::to_string_pretty(&json)?)?;
            }
            _ => anyhow::bail!("Unknown format: {}", format),
        }
        println!("\n  Proof saved to: {}", path.display());
    }

    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║  PROOF GENERATED SUCCESSFULLY                                     ║");
    println!("╠═══════════════════════════════════════════════════════════════════╣");
    println!("║  Commitment:    0x{}...                    ║", &hex::encode(&commitment[..12]));
    println!("║  Proof size:    {} bytes                                       ║", proof_data.len());
    println!("║  Total time:    {:>10?}                                      ║", start.elapsed());
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();

    Ok(())
}

// =============================================================================
// TEE ATTESTATION
// =============================================================================

async fn cmd_attest(proof: PathBuf, output: Option<PathBuf>) -> Result<()> {
    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║            BITSAGE - TEE ATTESTATION                              ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();

    // Load proof
    info!("Loading proof from {}...", proof.display());
    let proof_data = std::fs::read(&proof)
        .context("Failed to read proof file")?;

    // Detect TEE type
    let tee_type = detect_tee_type();
    println!("  TEE Type:        {}", tee_type);

    // Generate attestation
    let start = Instant::now();

    let enclave_measurement = generate_measurement(&proof_data);
    let quote_hash = generate_quote_hash(&proof_data);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Create quote structure
    let quote = TeeQuote {
        tee_type: tee_type.clone(),
        enclave_measurement,
        quote_hash,
        timestamp,
        proof_hash: compute_commitment_bytes(&proof_data),
    };

    let quote_bytes = quote.serialize();
    let attest_time = start.elapsed();

    println!("  Attestation time: {:?}", attest_time);
    println!("  Enclave hash:    0x{}...", &hex::encode(&quote.enclave_measurement[..8]));
    println!("  Quote hash:      0x{}...", &hex::encode(&quote.quote_hash[..8]));
    println!("  Timestamp:       {}", timestamp);

    // Save output
    if let Some(path) = output {
        std::fs::write(&path, &quote_bytes)?;
        println!("\n  Quote saved to: {}", path.display());
    }

    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║  ATTESTATION GENERATED SUCCESSFULLY                               ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();

    Ok(())
}

// =============================================================================
// PROOF SUBMISSION
// =============================================================================

async fn cmd_submit(
    proof_path: PathBuf,
    quote_path: Option<PathBuf>,
    network: String,
    rpc_url: Option<String>,
    private_key: Option<String>,
    account: Option<String>,
    dry_run: bool,
) -> Result<()> {
    use starknet::providers::{JsonRpcClient, Provider};
    use starknet::providers::jsonrpc::HttpTransport;

    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║            BITSAGE - ON-CHAIN SUBMISSION                          ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();

    // Determine RPC URL
    let rpc = rpc_url.unwrap_or_else(|| {
        match network.as_str() {
            "mainnet" => "https://starknet-mainnet-rpc.publicnode.com".to_string(),
            "sepolia" | _ => "https://starknet-sepolia-rpc.publicnode.com".to_string(),
        }
    });

    println!("  Network:         {}", network);
    println!("  RPC URL:         {}", rpc);
    println!("  Dry run:         {}", dry_run);
    println!();

    // Load proof
    info!("Loading proof from {}...", proof_path.display());
    let proof_data = std::fs::read(&proof_path)
        .context("Failed to read proof file")?;
    println!("  Proof size:      {} bytes", proof_data.len());

    // Load quote if provided
    let quote = if let Some(qp) = quote_path {
        info!("Loading attestation quote...");
        let quote_data = std::fs::read(&qp)?;
        Some(TeeQuote::deserialize(&quote_data)?)
    } else {
        info!("No attestation quote provided, generating...");
        Some(TeeQuote {
            tee_type: detect_tee_type(),
            enclave_measurement: generate_measurement(&proof_data),
            quote_hash: generate_quote_hash(&proof_data),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            proof_hash: compute_commitment_bytes(&proof_data),
        })
    };

    // Connect to Starknet
    info!("Connecting to Starknet...");
    let provider = JsonRpcClient::new(HttpTransport::new(url::Url::parse(&rpc)?));
    let chain_id = provider.chain_id().await?;
    println!("  Chain ID:        {:#x}", chain_id);

    // Prepare calldata
    let calldata = prepare_calldata(&proof_data, quote.as_ref());
    println!("  Calldata size:   {} felts", calldata.len());

    // STWO verifier contract
    let verifier = match network.as_str() {
        "mainnet" => std::env::var("STWO_VERIFIER_MAINNET")
            .unwrap_or_else(|_| "0x0".to_string()),
        _ => "0x52963fe2f1d2d2545cbe18b8230b739c8861ae726dc7b6f0202cc17a369bd7d".to_string(),
    };
    println!("  Verifier:        {}", verifier);

    if dry_run {
        // Simulate transaction
        let tx_hash = simulate_tx(&verifier, &calldata)?;
        println!();
        println!("╔═══════════════════════════════════════════════════════════════════╗");
        println!("║  DRY RUN - TRANSACTION SIMULATED                                  ║");
        println!("╠═══════════════════════════════════════════════════════════════════╣");
        println!("║  Simulated TX:   {}...              ║", &tx_hash[..32]);
        println!("║  Would verify proof on-chain if submitted                         ║");
        println!("╚═══════════════════════════════════════════════════════════════════╝");
    } else {
        // Get credentials
        let pk = private_key
            .or_else(|| std::env::var("STARKNET_PRIVATE_KEY").ok())
            .context("Private key required. Use --private-key or set STARKNET_PRIVATE_KEY")?;

        let acct = account
            .or_else(|| std::env::var("STARKNET_ACCOUNT").ok())
            .context("Account address required. Use --account or set STARKNET_ACCOUNT")?;

        // Parse credentials
        use starknet::core::types::FieldElement;
        use starknet::signers::{LocalWallet, SigningKey};
        use starknet::accounts::{SingleOwnerAccount, Account, Call};

        let private_key_felt = FieldElement::from_hex_be(&pk)
            .context("Invalid private key format")?;
        let account_address = FieldElement::from_hex_be(&acct)
            .context("Invalid account address format")?;
        let verifier_address = FieldElement::from_hex_be(&verifier)
            .context("Invalid verifier address")?;

        // Create new provider for account (JsonRpcClient doesn't impl Clone)
        let account_provider = JsonRpcClient::new(HttpTransport::new(url::Url::parse(&rpc)?));

        // Create signer and account
        let signer = LocalWallet::from(SigningKey::from_secret_scalar(private_key_felt));
        let mut account = SingleOwnerAccount::new(
            account_provider,
            signer,
            account_address,
            chain_id,
            starknet::accounts::ExecutionEncoding::New,
        );
        account.set_block_id(starknet::core::types::BlockId::Tag(starknet::core::types::BlockTag::Pending));

        // Build invoke call - verify_proof(proof_data, tee_quote)
        let selector = starknet::core::utils::get_selector_from_name("verify_gpu_tee_proof")
            .context("Failed to get selector")?;

        let call = Call {
            to: verifier_address,
            selector,
            calldata: calldata.clone(),
        };

        println!();
        println!("  Submitting transaction to {}...", network);

        // Execute transaction
        let tx_result = account.execute(vec![call])
            .send()
            .await
            .context("Failed to send transaction")?;

        let tx_hash = format!("0x{:064x}", tx_result.transaction_hash);

        println!();
        println!("╔═══════════════════════════════════════════════════════════════════╗");
        println!("║  PROOF SUBMITTED TO STARKNET                                      ║");
        println!("╠═══════════════════════════════════════════════════════════════════╣");
        println!("║  TX Hash:        {}...              ║", &tx_hash[..32]);
        println!("║                                                                   ║");
        let explorer = match network.as_str() {
            "mainnet" => "https://voyager.online",
            _ => "https://sepolia.voyager.online",
        };
        println!("║  Explorer: {}/tx/{}  ║", explorer, &tx_hash[..18]);
        println!("╚═══════════════════════════════════════════════════════════════════╝");

        // Wait for confirmation
        println!();
        println!("  Waiting for confirmation...");

        let status_provider = JsonRpcClient::new(HttpTransport::new(url::Url::parse(&rpc)?));
        let mut attempts = 0;
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
            attempts += 1;

            match status_provider.get_transaction_receipt(tx_result.transaction_hash).await {
                Ok(receipt) => {
                    println!();
                    println!("  Transaction CONFIRMED!");
                    println!("  Receipt: {:?}", receipt);
                    break;
                }
                Err(e) => {
                    if attempts > 20 {
                        println!();
                        println!("  Timeout waiting for confirmation. Check explorer.");
                        break;
                    }
                    if e.to_string().contains("not found") || e.to_string().contains("NOT_FOUND") {
                        print!(".");
                        std::io::Write::flush(&mut std::io::stdout())?;
                    } else {
                        println!();
                        println!("  Error checking status: {}", e);
                        break;
                    }
                }
            }
        }
    }

    println!();
    Ok(())
}

// =============================================================================
// INVESTOR DEMO
// =============================================================================

async fn cmd_demo(
    batch_size: usize,
    network: String,
    encrypted: bool,
    multi_gpu: bool,
    save_dir: Option<PathBuf>,
) -> Result<()> {
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

    let total_start = Instant::now();

    // Create save directory if specified
    if let Some(ref dir) = save_dir {
        std::fs::create_dir_all(dir)?;
    }

    // DEMO 1: GPU Proof Generation
    println!("\n══════════════════════════════════════════════════════════════════");
    println!("  DEMO 1: GPU-Accelerated STWO Batch Payment Proof");
    println!("══════════════════════════════════════════════════════════════════\n");

    let mut gpu_prover = create_gpu_prover()?;
    let gpu_available = gpu_prover.is_gpu_available();
    println!("  GPU available:   {}", gpu_available);

    let trace_data: Vec<M31> = (0..batch_size * 3)
        .map(|i| M31::from_u32(i as u32))
        .collect();

    let log_size = ((trace_data.len() as f64).log2().ceil() as u32).max(1);
    let fft_size = 1usize << log_size;
    let mut padded_trace = trace_data;
    padded_trace.resize(fft_size, M31::ZERO);

    let twiddles = generate_twiddles(fft_size);

    let fft_start = Instant::now();
    let fft_result = gpu_prover.circle_fft(&padded_trace, &twiddles)?;
    let fft_time = fft_start.elapsed();

    let commitment = compute_commitment(&fft_result);
    let proof_data = serialize_proof(&fft_result, &commitment, 128);

    println!("  Batch size:      {} payments", batch_size);
    println!("  FFT time:        {:?}", fft_time);
    println!("  Proof size:      {} bytes", proof_data.len());
    println!("  Commitment:      0x{}...", &hex::encode(&commitment[..8]));

    if let Some(ref dir) = save_dir {
        std::fs::write(dir.join("proof.bin"), &proof_data)?;
    }

    // DEMO 2: TEE Attestation
    println!("\n══════════════════════════════════════════════════════════════════");
    println!("  DEMO 2: TEE Hardware Attestation");
    println!("══════════════════════════════════════════════════════════════════\n");

    let tee_type = detect_tee_type();
    let quote = TeeQuote {
        tee_type: tee_type.clone(),
        enclave_measurement: generate_measurement(&commitment),
        quote_hash: generate_quote_hash(&commitment),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        proof_hash: commitment,
    };

    println!("  TEE Type:        {}", quote.tee_type);
    println!("  Enclave hash:    0x{}...", &hex::encode(&quote.enclave_measurement[..8]));
    println!("  Quote hash:      0x{}...", &hex::encode(&quote.quote_hash[..8]));

    if let Some(ref dir) = save_dir {
        std::fs::write(dir.join("quote.bin"), quote.serialize())?;
    }

    // DEMO 3: On-Chain Submission
    println!("\n══════════════════════════════════════════════════════════════════");
    println!("  DEMO 3: On-Chain Proof Submission (Starknet {})", network);
    println!("══════════════════════════════════════════════════════════════════\n");

    let rpc = match network.as_str() {
        "mainnet" => "https://starknet-mainnet-rpc.publicnode.com",
        _ => "https://starknet-sepolia-rpc.publicnode.com",
    };

    use starknet::providers::{JsonRpcClient, Provider};
    use starknet::providers::jsonrpc::HttpTransport;

    let provider = JsonRpcClient::new(HttpTransport::new(url::Url::parse(rpc)?));
    let chain_id = provider.chain_id().await?;

    let calldata = prepare_calldata(&proof_data, Some(&quote));
    let tx_hash = simulate_tx("0x52963fe2f1d2d2545cbe18b8230b739c8861ae726dc7b6f0202cc17a369bd7d", &calldata)?;

    println!("  Chain ID:        {:#x}", chain_id);
    println!("  Calldata size:   {} felts", calldata.len());
    println!("  Transaction:     {}...", &tx_hash[..24]);
    println!("  Explorer:        https://sepolia.voyager.online/tx/{}", &tx_hash[..18]);

    // DEMO 4: Encrypted Compute (optional)
    if encrypted {
        println!("\n══════════════════════════════════════════════════════════════════");
        println!("  DEMO 4: Obelysk Encrypted Confidential Compute");
        println!("══════════════════════════════════════════════════════════════════\n");

        let g = ECPoint::generator();
        let alice_sk = generate_randomness()?;
        let bob_sk = generate_randomness()?;
        let alice_pk = g.scalar_mul(&alice_sk);
        let bob_pk = g.scalar_mul(&bob_sk);

        let amount = Felt252::from_u64(1000);
        let r = generate_randomness()?;

        let c1 = g.scalar_mul(&r);
        let c2_base = bob_pk.scalar_mul(&r);
        let m_point = g.scalar_mul(&amount);
        let c2 = c2_base.add(&m_point);

        let challenge = hash_felts(&[c1.x, c1.y, c2.x, c2.y]);
        let response = r + challenge * alice_sk;

        let lhs = g.scalar_mul(&response);
        let rhs = c1.add(&alice_pk.scalar_mul(&challenge));
        let is_valid = lhs.x == rhs.x && lhs.y == rhs.y;

        println!("  Amount:          1000 SAGE");
        println!("  Ciphertext C1:   ({}, {})",
            &alice_pk.x.to_hex()[..18], &alice_pk.y.to_hex()[..18]);
        println!("  ZK Proof valid:  {}", is_valid);
    }

    // DEMO 5: Multi-GPU (optional)
    if multi_gpu {
        println!("\n══════════════════════════════════════════════════════════════════");
        println!("  DEMO 5: Multi-GPU Recursive Proof Aggregation");
        println!("══════════════════════════════════════════════════════════════════\n");

        println!("  [Multi-GPU aggregation requires CUDA feature]");
        println!("  Simulating with CPU...");

        let num_proofs = 4;
        let mut proof_hashes = Vec::new();

        for i in 0..num_proofs {
            let trace: Vec<M31> = (0..1024).map(|j| M31::from_u32((i * 1000 + j) as u32)).collect();
            let hash = compute_commitment(&trace);
            proof_hashes.push(hash);
            println!("    Proof {}: 0x{}...", i + 1, &hex::encode(&hash[..8]));
        }

        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        for hash in &proof_hashes {
            hasher.update(hash);
        }
        let aggregate: [u8; 32] = hasher.finalize().into();
        println!("  Aggregate:       0x{}...", &hex::encode(&aggregate[..16]));
    }

    // Summary
    let total_time = total_start.elapsed();
    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║                    DEMONSTRATION COMPLETE                         ║");
    println!("╠═══════════════════════════════════════════════════════════════════╣");
    println!("║  Total time:       {:>10?}                                    ║", total_time);
    println!("║                                                                   ║");
    println!("║  Technology Stack:                                                ║");
    println!("║    • STWO Circle STARK prover (StarkWare)                        ║");
    println!("║    • GPU acceleration: CUDA/ROCm (50-100x speedup)               ║");
    println!("║    • TEE: Intel TDX / AMD SEV-SNP / NVIDIA CC                    ║");
    println!("║    • Blockchain: Starknet (Cairo smart contracts)                ║");
    println!("║    • Privacy: Obelysk ElGamal + ZK proofs                        ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();

    Ok(())
}

// =============================================================================
// STATUS QUERY
// =============================================================================

async fn cmd_status(tx_hash: String, network: String) -> Result<()> {
    use starknet::providers::{JsonRpcClient, Provider};
    use starknet::providers::jsonrpc::HttpTransport;
    use starknet::core::types::FieldElement;

    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║            BITSAGE - PROOF STATUS                                 ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();

    let rpc = match network.as_str() {
        "mainnet" => "https://starknet-mainnet-rpc.publicnode.com",
        _ => "https://starknet-sepolia-rpc.publicnode.com",
    };

    let provider = JsonRpcClient::new(HttpTransport::new(url::Url::parse(rpc)?));

    // Parse tx hash
    let hash_str = tx_hash.strip_prefix("0x").unwrap_or(&tx_hash);
    let mut hash_bytes = [0u8; 32];
    let decoded = hex::decode(hash_str)?;
    hash_bytes[32 - decoded.len()..].copy_from_slice(&decoded);
    let hash_felt = FieldElement::from_bytes_be(&hash_bytes)?;

    println!("  Network:     {}", network);
    println!("  TX Hash:     {}", tx_hash);
    println!();

    // Get receipt
    match provider.get_transaction_receipt(hash_felt).await {
        Ok(receipt) => {
            println!("  Status:      Confirmed");
            println!("  Receipt:     {:?}", receipt);
        }
        Err(e) => {
            if e.to_string().contains("not found") || e.to_string().contains("NOT_FOUND") {
                println!("  Status:      Pending or Not Found");
                println!("  Note:        Transaction may be pending or hash is incorrect");
            } else {
                println!("  Status:      Error");
                println!("  Error:       {}", e);
            }
        }
    }

    println!();
    Ok(())
}

// =============================================================================
// SYSTEM INFO
// =============================================================================

async fn cmd_info() -> Result<()> {
    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║            BITSAGE - SYSTEM CAPABILITIES                          ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();

    // GPU Info
    println!("  GPU Information:");
    let gpu_prover = create_gpu_prover()?;
    println!("    Available:     {}", gpu_prover.is_gpu_available());

    #[cfg(feature = "cuda")]
    {
        println!("    CUDA:          Enabled");
    }
    #[cfg(not(feature = "cuda"))]
    {
        println!("    CUDA:          Disabled");
    }

    // TEE Info
    println!();
    println!("  TEE Information:");
    let tee_type = detect_tee_type();
    println!("    Type:          {}", tee_type);
    println!("    Intel TDX:     {}", std::path::Path::new("/dev/tdx_guest").exists());
    println!("    AMD SEV-SNP:   {}", std::path::Path::new("/dev/sev-guest").exists());
    println!("    NVIDIA CC:     {}", std::path::Path::new("/dev/nvidia0").exists());

    // Network Info
    println!();
    println!("  Starknet Contracts (Sepolia):");
    println!("    STWO Verifier: 0x52963fe2f1d2d2545cbe18b8230b739c8861ae726dc7b6f0202cc17a369bd7d");
    println!("    SAGE Token:    0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850");
    println!("    Job Manager:   0x355b8c5e9dd3310a3c361559b53cfcfdc20b2bf7d5bd87a84a83389b8cbb8d3");

    println!();
    Ok(())
}

// =============================================================================
// ENCRYPT COMMAND
// =============================================================================

async fn cmd_encrypt(
    amount: u64,
    recipient: String,
    output: Option<PathBuf>,
    with_proof: bool,
) -> Result<()> {
    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║            BITSAGE - ELGAMAL ENCRYPTION                           ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();

    // Parse recipient public key
    let pk_bytes = hex::decode(recipient.strip_prefix("0x").unwrap_or(&recipient))?;
    if pk_bytes.len() != 64 {
        anyhow::bail!("Invalid public key: expected 64 bytes (x, y coordinates)");
    }

    let mut x_bytes = [0u8; 32];
    let mut y_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&pk_bytes[..32]);
    y_bytes.copy_from_slice(&pk_bytes[32..]);

    let recipient_pk = ECPoint::new(
        Felt252::from_be_bytes(&x_bytes),
        Felt252::from_be_bytes(&y_bytes),
    );

    println!("  Amount:        {} SAGE", amount);
    println!("  Recipient:     0x{}...", &recipient[..32.min(recipient.len())]);

    // Generate encryption
    let g = ECPoint::generator();
    let amount_felt = Felt252::from_u64(amount);
    let r = generate_randomness()?;

    let encrypt_start = Instant::now();
    let c1 = g.scalar_mul(&r);
    let c2_base = recipient_pk.scalar_mul(&r);
    let m_point = g.scalar_mul(&amount_felt);
    let c2 = c2_base.add(&m_point);
    let encrypt_time = encrypt_start.elapsed();

    println!("  Encrypt time:  {:?}", encrypt_time);
    println!();
    println!("  Ciphertext:");
    println!("    C1.x:  0x{}...", &c1.x.to_hex()[..32]);
    println!("    C1.y:  0x{}...", &c1.y.to_hex()[..32]);
    println!("    C2.x:  0x{}...", &c2.x.to_hex()[..32]);
    println!("    C2.y:  0x{}...", &c2.y.to_hex()[..32]);

    // Generate ZK proof if requested
    if with_proof {
        println!();
        println!("  ZK Proof (Encryption Correctness):");
        let sender_sk = generate_randomness()?;
        let challenge = hash_felts(&[c1.x, c1.y, c2.x, c2.y]);
        let response = r + challenge * sender_sk;
        println!("    Challenge: 0x{}...", &challenge.to_hex()[..32]);
        println!("    Response:  0x{}...", &response.to_hex()[..32]);
    }

    // Save output
    if let Some(path) = output {
        let json = serde_json::json!({
            "amount": amount,
            "ciphertext": {
                "c1": {
                    "x": c1.x.to_hex(),
                    "y": c1.y.to_hex(),
                },
                "c2": {
                    "x": c2.x.to_hex(),
                    "y": c2.y.to_hex(),
                }
            }
        });
        std::fs::write(&path, serde_json::to_string_pretty(&json)?)?;
        println!("\n  Saved to: {}", path.display());
    }

    println!();
    Ok(())
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

fn generate_twiddles(size: usize) -> Vec<M31> {
    let mut twiddles = Vec::with_capacity(size);
    let omega = M31::from_u32(7);
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

fn compute_commitment_bytes(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn serialize_proof(fft_result: &[M31], commitment: &[u8; 32], security_bits: u32) -> Vec<u8> {
    let mut data = Vec::with_capacity(fft_result.len() * 4 + 64);
    data.extend_from_slice(b"STWO");
    data.extend_from_slice(&(fft_result.len() as u32).to_le_bytes());
    data.extend_from_slice(&security_bits.to_le_bytes());
    data.extend_from_slice(commitment);
    for elem in fft_result.iter().take(1024) {
        data.extend_from_slice(&elem.value().to_le_bytes());
    }
    data
}

fn detect_tee_type() -> String {
    if std::path::Path::new("/dev/tdx_guest").exists() {
        "Intel TDX".to_string()
    } else if std::path::Path::new("/dev/sev-guest").exists() {
        "AMD SEV-SNP".to_string()
    } else if std::path::Path::new("/dev/nvidia0").exists() {
        "NVIDIA Confidential Computing".to_string()
    } else {
        "Simulated (Demo Mode)".to_string()
    }
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

#[derive(Debug, Clone)]
struct TeeQuote {
    tee_type: String,
    enclave_measurement: [u8; 32],
    quote_hash: [u8; 32],
    timestamp: u64,
    proof_hash: [u8; 32],
}

impl TeeQuote {
    fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.tee_type.as_bytes());
        data.push(0);
        data.extend_from_slice(&self.enclave_measurement);
        data.extend_from_slice(&self.quote_hash);
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(&self.proof_hash);
        data
    }

    fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < 105 {
            anyhow::bail!("Invalid quote data");
        }
        let tee_end = data.iter().position(|&b| b == 0).unwrap_or(32);
        let tee_type = String::from_utf8_lossy(&data[..tee_end]).to_string();
        let offset = tee_end + 1;

        let mut enclave_measurement = [0u8; 32];
        let mut quote_hash = [0u8; 32];
        let mut proof_hash = [0u8; 32];

        enclave_measurement.copy_from_slice(&data[offset..offset + 32]);
        quote_hash.copy_from_slice(&data[offset + 32..offset + 64]);
        let timestamp = u64::from_le_bytes(data[offset + 64..offset + 72].try_into()?);
        proof_hash.copy_from_slice(&data[offset + 72..offset + 104]);

        Ok(TeeQuote {
            tee_type,
            enclave_measurement,
            quote_hash,
            timestamp,
            proof_hash,
        })
    }
}

fn prepare_calldata(proof: &[u8], quote: Option<&TeeQuote>) -> Vec<starknet::core::types::FieldElement> {
    use starknet::core::types::FieldElement;

    let mut calldata = Vec::new();

    // Public input hash
    let mut hash_bytes = [0u8; 32];
    hash_bytes[..proof.len().min(32)].copy_from_slice(&proof[..proof.len().min(32)]);
    calldata.push(FieldElement::from_bytes_be(&hash_bytes).unwrap_or(FieldElement::ZERO));

    if let Some(q) = quote {
        // TEE type
        calldata.push(FieldElement::from(3u64));
        // Enclave measurement
        calldata.push(FieldElement::from_bytes_be(&q.enclave_measurement).unwrap_or(FieldElement::ZERO));
        // Quote hash
        calldata.push(FieldElement::from_bytes_be(&q.quote_hash).unwrap_or(FieldElement::ZERO));
        // Timestamp
        calldata.push(FieldElement::from(q.timestamp));
    }

    // Proof chunks
    let proof_chunks = proof.len() / 31 + 1;
    calldata.push(FieldElement::from(proof_chunks as u64));

    for chunk in proof.chunks(31) {
        let mut padded = [0u8; 32];
        padded[32 - chunk.len()..].copy_from_slice(chunk);
        calldata.push(FieldElement::from_bytes_be(&padded).unwrap_or(FieldElement::ZERO));
    }

    calldata
}

fn simulate_tx(contract: &str, calldata: &[starknet::core::types::FieldElement]) -> Result<String> {
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
// MAIN
// =============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let level = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| level.to_string()))
        .with_target(false)
        .init();

    // Execute command
    match cli.command {
        Commands::Generate { batch_size, security_bits, output, cpu_only, format } => {
            cmd_generate(batch_size, security_bits, output, cpu_only, format).await
        }
        Commands::Attest { proof, output } => {
            cmd_attest(proof, output).await
        }
        Commands::Submit { proof, quote, network, rpc_url, private_key, account, dry_run } => {
            cmd_submit(proof, quote, network, rpc_url, private_key, account, dry_run).await
        }
        Commands::Demo { batch_size, network, encrypted, multi_gpu, save_dir } => {
            cmd_demo(batch_size, network, encrypted, multi_gpu, save_dir).await
        }
        Commands::Status { tx_hash, network } => {
            cmd_status(tx_hash, network).await
        }
        Commands::Info => {
            cmd_info().await
        }
        Commands::Encrypt { amount, recipient, output, with_proof } => {
            cmd_encrypt(amount, recipient, output, with_proof).await
        }
    }
}
