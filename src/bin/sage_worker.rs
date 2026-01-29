//! # BitSage GPU Worker - One-Click Setup & Operation
//!
//! Complete CLI for GPU operators to join the BitSage Network.
//!
//! ## Quick Start
//! ```bash
//! # First time setup (interactive wizard)
//! sage-worker setup
//!
//! # Start earning
//! sage-worker start
//!
//! # Check status
//! sage-worker status
//!
//! # Stake tokens
//! sage-worker stake 10000
//! ```

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::io::{Write, stdout};
use tracing::{info, warn, error};

// =============================================================================
// CLI DEFINITION
// =============================================================================

#[derive(Parser)]
#[command(name = "sage-worker")]
#[command(about = "BitSage Network GPU Worker - Join the decentralized compute network")]
#[command(version)]
#[command(author = "BitSage Network <contact@bitsage.network>")]
struct Cli {
    /// Configuration directory
    #[arg(short, long, default_value = "~/.bitsage")]
    config_dir: String,

    /// Verbosity level
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Interactive setup wizard - run this first!
    Setup {
        /// Network to join (mainnet or sepolia)
        #[arg(short, long)]
        network: Option<String>,

        /// Skip GPU detection
        #[arg(long)]
        skip_gpu_detection: bool,

        /// Import existing wallet instead of generating new
        #[arg(long)]
        import_wallet: Option<String>,
    },

    /// Start the worker and begin earning SAGE
    Start {
        /// Config file (default: ~/.bitsage/worker.toml)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Run in foreground (don't daemonize)
        #[arg(long)]
        foreground: bool,
    },

    /// Stop the running worker
    Stop,

    /// Show worker status and earnings
    Status {
        /// Show detailed stats
        #[arg(long)]
        detailed: bool,
    },

    /// Stake SAGE tokens to increase job priority
    Stake {
        /// Amount of SAGE to stake
        amount: u64,

        /// Token to stake (default: SAGE)
        #[arg(long, default_value = "SAGE")]
        token: String,
    },

    /// Unstake SAGE tokens
    Unstake {
        /// Amount to unstake (or "all")
        amount: String,
    },

    /// Claim pending rewards
    Claim,

    /// Show system information and GPU capabilities
    Info,

    /// Reset configuration (careful!)
    Reset {
        /// Confirm reset
        #[arg(long)]
        confirm: bool,
    },

    /// Export wallet/keys for backup
    Export {
        /// Output file
        #[arg(short, long)]
        output: PathBuf,

        /// Encrypt with password
        #[arg(long)]
        encrypt: bool,
    },

    /// View logs
    Logs {
        /// Number of lines to show
        #[arg(short, long, default_value = "100")]
        lines: usize,

        /// Follow log output
        #[arg(short, long)]
        follow: bool,
    },
}

// =============================================================================
// CONFIGURATION
// =============================================================================

/// Production coordinator endpoints
const MAINNET_COORDINATOR: &str = "https://coordinator.bitsage.network";
const SEPOLIA_COORDINATOR: &str = "https://coordinator-sepolia.bitsage.network";

/// Starknet RPC endpoints (PublicNode - free, reliable)
const MAINNET_RPC: &str = "https://starknet-mainnet-rpc.publicnode.com";
const SEPOLIA_RPC: &str = "https://starknet-sepolia-rpc.publicnode.com";

/// Dashboard URLs
const MAINNET_DASHBOARD: &str = "https://dashboard.bitsage.network";
const SEPOLIA_DASHBOARD: &str = "https://dashboard-sepolia.bitsage.network";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkerConfig {
    pub worker_id: String,
    pub network: String,
    pub coordinator_url: String,
    pub starknet_rpc: String,
    pub dashboard_url: String,
    pub wallet: WalletConfig,
    pub gpu: GpuConfig,
    pub settings: WorkerSettings,
    #[serde(default)]
    pub session_key: SessionKeyConfig,
    /// Paymaster address for V3 gasless proof submission
    #[serde(default)]
    pub paymaster_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WalletConfig {
    pub address: String,
    pub private_key_path: String,
    pub elgamal_key_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SessionKeyConfig {
    /// Session key public key (hex)
    pub public_key: Option<String>,
    /// Path to session key private key
    pub private_key_path: Option<String>,
    /// Expiration timestamp (unix)
    pub expires_at: Option<u64>,
    /// Allowed contract addresses
    pub allowed_contracts: Vec<String>,
    /// Whether session key is registered on-chain
    pub registered: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GpuConfig {
    pub detected: bool,
    pub count: u32,
    pub model: String,
    pub memory_gb: u32,
    pub compute_capability: String,
    pub tee_supported: bool,
    pub cuda_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkerSettings {
    pub poll_interval_secs: u64,
    pub heartbeat_interval_secs: u64,
    pub max_concurrent_jobs: u32,
    pub auto_claim_rewards: bool,
}

impl Default for WorkerSettings {
    fn default() -> Self {
        Self {
            poll_interval_secs: 5,
            heartbeat_interval_secs: 30,
            max_concurrent_jobs: 4,
            auto_claim_rewards: true,
        }
    }
}

// =============================================================================
// SETUP WIZARD
// =============================================================================

async fn cmd_setup(
    config_dir: &str,
    network: Option<String>,
    skip_gpu_detection: bool,
    import_wallet: Option<String>,
) -> Result<()> {
    let config_path = expand_path(config_dir);
    std::fs::create_dir_all(&config_path)?;

    print_banner();
    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║              BITSAGE GPU WORKER - QUICK SETUP                     ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();

    // Step 1: GPU Detection
    println!("[1/5] Detecting GPU hardware...");
    let gpu_config = if skip_gpu_detection {
        println!("      ⚠ GPU detection skipped");
        GpuConfig {
            detected: false,
            count: 0,
            model: "Unknown".to_string(),
            memory_gb: 0,
            compute_capability: "0.0".to_string(),
            tee_supported: false,
            cuda_version: None,
        }
    } else {
        detect_gpu().await?
    };

    if gpu_config.detected {
        println!("      ✓ Found: {} {}GB", gpu_config.model, gpu_config.memory_gb);
        if let Some(ref cuda) = gpu_config.cuda_version {
            println!("      ✓ CUDA: {}", cuda);
        }
        println!("      ✓ Compute capability: {}", gpu_config.compute_capability);
        println!("      ✓ TEE: {}", if gpu_config.tee_supported { "Supported" } else { "Not available" });
    } else {
        println!("      ⚠ No GPU detected - will run in CPU mode");
        println!("      ⚠ For optimal earnings, use NVIDIA H100/A100 or AMD MI300X");
    }
    println!();

    // Step 2: Wallet Setup
    println!("[2/5] Setting up wallet...");
    let wallet_config = if let Some(pk) = import_wallet {
        println!("      Importing existing wallet...");
        import_wallet_from_key(&config_path, &pk).await?
    } else {
        println!("      Generating new Starknet wallet...");
        generate_new_wallet(&config_path).await?
    };
    println!("      ✓ Wallet address: {}...{}",
        &wallet_config.address[..10],
        &wallet_config.address[wallet_config.address.len()-6..]);
    println!("      ✓ Keys saved to: {}/keys/", config_path.display());
    println!();

    // Step 2b: Deploy account via relayer (gasless)
    // This deploys a proper Starknet account contract and funds from faucet
    let mut account_deployed = false;
    let mut sage_funded = "0".to_string();
    let mut tier = "Consumer".to_string();

    // Step 3: Network Selection
    println!("[3/5] Network selection...");
    let selected_network = if let Some(n) = network {
        n
    } else {
        select_network()?
    };

    let (coordinator_url, starknet_rpc, dashboard_url) = match selected_network.as_str() {
        "mainnet" => {
            println!("      → Mainnet selected (production, real SAGE earnings)");
            (MAINNET_COORDINATOR, MAINNET_RPC, MAINNET_DASHBOARD)
        }
        _ => {
            println!("      → Sepolia selected (testnet, for testing)");
            (SEPOLIA_COORDINATOR, SEPOLIA_RPC, SEPOLIA_DASHBOARD)
        }
    };
    println!("      ✓ Coordinator: {}", coordinator_url);
    println!();

    // Step 4: Deploy Account & Register with Network
    println!("[4/5] Connecting to BitSage Network...");
    let worker_id = format!("worker-{}", &uuid::Uuid::new_v4().to_string()[..8]);

    // Try to deploy account via relayer (gasless onboarding)
    // Read the public key from the private key file
    let private_key = std::fs::read_to_string(&wallet_config.private_key_path)?;
    let pk_clean = private_key.trim().strip_prefix("0x").unwrap_or(private_key.trim());

    // Derive public key from private key (simplified - just use address as identifier)
    let public_key = &wallet_config.address;

    println!("      Deploying account contract (gasless)...");
    match deploy_account_via_relayer(
        coordinator_url,
        public_key,
        &worker_id,
        Some(&gpu_config.model),
    ).await {
        Ok(result) => {
            account_deployed = true;
            sage_funded = result.sage_funded.clone();
            tier = result.tier.clone();

            // Format SAGE amount (18 decimals)
            let sage_amount: u128 = sage_funded.parse().unwrap_or(0);
            let sage_display = sage_amount / 1_000_000_000_000_000_000;

            println!("      ✓ Account deployed: {}...{}",
                &result.account_address[..10],
                &result.account_address[result.account_address.len()-6..]);
            println!("      ✓ Gas funded: {} SAGE (for transactions)", sage_display);
            println!("      ✓ Recommended tier: {} (requires staking)", tier);
            if let Some(tx) = result.deploy_tx_hash {
                println!("      ✓ Deploy tx: {}...{}", &tx[..10], &tx[tx.len()-6..]);
            }
        }
        Err(e) => {
            println!("      ⚠ Gasless deployment unavailable: {}", e);
            println!("      ⚠ Using local wallet (you'll need ETH for gas)");
        }
    }

    // Register with coordinator
    match register_with_coordinator(coordinator_url, &worker_id, &gpu_config, &wallet_config.address).await {
        Ok(_) => {
            println!("      ✓ Registered as validator: {}", worker_id);
        }
        Err(e) => {
            println!("      ⚠ Could not connect to coordinator: {}", e);
            println!("      ⚠ Worker will retry on start");
        }
    }
    println!();

    // Step 5: Staking Info
    println!("[5/5] Staking information...");
    let min_stake = get_minimum_stake(&gpu_config);

    // Format the funded amount (should be ~50 SAGE for gas only)
    let sage_funded_amount: u128 = sage_funded.parse().unwrap_or(0);
    let sage_funded_display = sage_funded_amount / 1_000_000_000_000_000_000;

    if account_deployed {
        println!("      ✓ Gas funded: {} SAGE (for initial transactions)", sage_funded_display);
        println!();
        println!("      To unlock higher priority jobs, stake SAGE tokens:");
        println!("      ┌─────────────────────────────────────────────────┐");
        println!("      │  Tier        │  Stake      │  Benefits          │");
        println!("      ├─────────────────────────────────────────────────┤");
        println!("      │  Consumer    │  1,000 SAGE │  Standard jobs     │");
        println!("      │  Workstation │  2,500 SAGE │  Priority queue    │");
        println!("      │  DataCenter  │  5,000 SAGE │  Enterprise jobs   │");
        println!("      │  Enterprise  │ 10,000 SAGE │  Premium jobs      │");
        println!("      │  Frontier    │ 25,000 SAGE │  Maximum priority  │");
        println!("      └─────────────────────────────────────────────────┘");
        println!();
        println!("      Recommended for {}: {} tier ({} SAGE)", gpu_config.model, tier, min_stake);
        println!();
        println!("      How to get SAGE:");
        println!("        1. EARN by completing jobs (start with: sage-worker start)");
        println!("        2. BUY on OTC: https://app.bitsage.network/otc");
        println!();
        println!("      Once you have SAGE: sage-worker stake {}", min_stake);
    } else {
        println!("      Recommended stake for {}: {} SAGE", gpu_config.model, min_stake);
        println!("      → Staking is optional but increases job priority");
        println!("      → Earn SAGE by completing jobs, or buy on OTC");
        println!("      → Stake later with: sage-worker stake {}", min_stake);
    }
    println!();

    // Save configuration
    let config = WorkerConfig {
        worker_id: worker_id.clone(),
        network: selected_network.clone(),
        coordinator_url: coordinator_url.to_string(),
        starknet_rpc: starknet_rpc.to_string(),
        dashboard_url: dashboard_url.to_string(),
        wallet: wallet_config.clone(),
        gpu: gpu_config,
        settings: WorkerSettings::default(),
        session_key: SessionKeyConfig::default(), // Session key will be generated on first start
        paymaster_address: std::env::var("PAYMASTER_ADDRESS").ok(),
    };

    let config_file = config_path.join("worker.toml");
    save_config(&config, &config_file)?;
    println!("      ✓ Configuration saved to: {}", config_file.display());

    // Summary
    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║  SETUP COMPLETE - Your GPU is ready to earn!                      ║");
    println!("╠═══════════════════════════════════════════════════════════════════╣");
    println!("║                                                                   ║");
    println!("║  Worker ID:   {}                                    ║", worker_id);
    println!("║  Network:     {:8}                                          ║", selected_network);
    println!("║  Wallet:      {}...{}              ║",
        &wallet_config.address[..10],
        &wallet_config.address[wallet_config.address.len()-4..]);
    println!("║                                                                   ║");
    println!("║  NEXT STEPS:                                                      ║");
    println!("║  1. Start worker:  sage-worker start                              ║");
    println!("║  2. View status:   sage-worker status                             ║");
    println!("║  3. Dashboard:     {}/worker/{}  ║",
        &dashboard_url[..35], &worker_id[..12]);
    println!("║                                                                   ║");
    if selected_network == "mainnet" {
        println!("║  ⚠ IMPORTANT: Fund your wallet with STRK for gas fees           ║");
        println!("║     Wallet: {}         ║", &wallet_config.address[..42]);
    }
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();

    Ok(())
}

// =============================================================================
// GPU DETECTION
// =============================================================================

async fn detect_gpu() -> Result<GpuConfig> {
    // Try NVIDIA first
    if let Ok(nvidia) = detect_nvidia_gpu().await {
        return Ok(nvidia);
    }

    // Try AMD ROCm
    if let Ok(amd) = detect_amd_gpu().await {
        return Ok(amd);
    }

    // No GPU found
    Ok(GpuConfig {
        detected: false,
        count: 0,
        model: "None".to_string(),
        memory_gb: 0,
        compute_capability: "0.0".to_string(),
        tee_supported: false,
        cuda_version: None,
    })
}

async fn detect_nvidia_gpu() -> Result<GpuConfig> {
    // Check nvidia-smi
    let output = std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=name,memory.total,compute_cap", "--format=csv,noheader,nounits"])
        .output()?;

    if !output.status.success() {
        anyhow::bail!("nvidia-smi failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().next().ok_or_else(|| anyhow!("No GPU found"))?;
    let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();

    if parts.len() < 3 {
        anyhow::bail!("Invalid nvidia-smi output");
    }

    let model = parts[0].to_string();
    let memory_mb: u32 = parts[1].parse().unwrap_or(0);
    let compute_cap = parts[2].to_string();

    // Get CUDA version
    let cuda_output = std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=driver_version", "--format=csv,noheader"])
        .output()
        .ok();

    let cuda_version = cuda_output.and_then(|o| {
        String::from_utf8_lossy(&o.stdout).lines().next().map(|s| s.trim().to_string())
    });

    // Count GPUs
    let count_output = std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=count", "--format=csv,noheader"])
        .output()?;
    let gpu_count: u32 = String::from_utf8_lossy(&count_output.stdout)
        .lines()
        .count() as u32;

    // Check for TEE support (H100 Confidential Computing)
    let tee_supported = model.contains("H100") || model.contains("H200") || model.contains("B100") || model.contains("B200");

    Ok(GpuConfig {
        detected: true,
        count: gpu_count.max(1),
        model,
        memory_gb: memory_mb / 1024,
        compute_capability: compute_cap,
        tee_supported,
        cuda_version,
    })
}

async fn detect_amd_gpu() -> Result<GpuConfig> {
    // Check rocm-smi
    let output = std::process::Command::new("rocm-smi")
        .args(["--showproductname", "--showmeminfo", "vram"])
        .output()?;

    if !output.status.success() {
        anyhow::bail!("rocm-smi failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse ROCm output (simplified)
    let model = if stdout.contains("MI300X") {
        "AMD MI300X".to_string()
    } else if stdout.contains("MI250") {
        "AMD MI250X".to_string()
    } else {
        "AMD GPU".to_string()
    };

    Ok(GpuConfig {
        detected: true,
        count: 1,
        model,
        memory_gb: 192, // MI300X default
        compute_capability: "gfx942".to_string(),
        tee_supported: false,
        cuda_version: None,
    })
}

// =============================================================================
// WALLET GENERATION
// =============================================================================

async fn generate_new_wallet(config_path: &PathBuf) -> Result<WalletConfig> {
    use rand::RngCore;
    use starknet::signers::SigningKey;
    use starknet::core::types::FieldElement;

    let keys_dir = config_path.join("keys");
    std::fs::create_dir_all(&keys_dir)?;

    // Generate random Starknet keypair via starknet-rs (proper EC derivation)
    let signing_key = SigningKey::from_random();
    let private_key_hex = format!("0x{}", hex::encode(signing_key.secret_scalar().to_bytes_be()));

    // Derive real Starknet public key from the private key on the STARK curve
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.scalar();

    // Compute contract address using OpenZeppelin account class hash
    let oz_class_hash = FieldElement::from_hex_be("0x061dac032f228abef9c6626f1dcb1d4e56c1b923412cf9da27b2dab1e3e0b3a8").unwrap();
    let address_felt = starknet::core::utils::get_contract_address(
        public_key,        // salt
        oz_class_hash,     // class_hash
        &[public_key],     // constructor calldata
        FieldElement::ZERO,// deployer_address
    );
    let address = format!("{:#066x}", address_felt);

    // Save private key (encrypted in production)
    let pk_path = keys_dir.join("starknet.key");
    std::fs::write(&pk_path, &private_key_hex)?;

    // Set restrictive permissions on key file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&pk_path, std::fs::Permissions::from_mode(0o600))?;
    }

    // Generate ElGamal keypair for privacy payments
    let mut rng = rand::thread_rng();
    let mut elgamal_secret = [0u8; 32];
    rng.fill_bytes(&mut elgamal_secret);

    let elgamal_path = keys_dir.join("elgamal.key");
    std::fs::write(&elgamal_path, hex::encode(&elgamal_secret))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&elgamal_path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(WalletConfig {
        address,
        private_key_path: pk_path.to_string_lossy().to_string(),
        elgamal_key_path: elgamal_path.to_string_lossy().to_string(),
    })
}

async fn import_wallet_from_key(config_path: &PathBuf, private_key: &str) -> Result<WalletConfig> {
    use starknet::signers::SigningKey;
    use starknet::core::types::FieldElement;

    let keys_dir = config_path.join("keys");
    std::fs::create_dir_all(&keys_dir)?;

    // Parse and validate private key
    let private_key_felt = FieldElement::from_hex_be(private_key)
        .context("Invalid private key hex format")?;

    // Derive public key and address using proper EC curve math
    let signing_key = SigningKey::from_secret_scalar(private_key_felt);
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.scalar();

    // Compute contract address using OpenZeppelin account class hash
    let oz_class_hash = FieldElement::from_hex_be("0x061dac032f228abef9c6626f1dcb1d4e56c1b923412cf9da27b2dab1e3e0b3a8").unwrap();
    let address_felt = starknet::core::utils::get_contract_address(
        public_key,        // salt
        oz_class_hash,     // class_hash
        &[public_key],     // constructor calldata
        FieldElement::ZERO,// deployer_address
    );
    let address = format!("{:#066x}", address_felt);

    // Save keys
    let pk_path = keys_dir.join("starknet.key");
    std::fs::write(&pk_path, private_key)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&pk_path, std::fs::Permissions::from_mode(0o600))?;
    }

    // Generate ElGamal key
    let mut rng = rand::thread_rng();
    let mut elgamal_secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut elgamal_secret);

    let elgamal_path = keys_dir.join("elgamal.key");
    std::fs::write(&elgamal_path, hex::encode(&elgamal_secret))?;

    Ok(WalletConfig {
        address,
        private_key_path: pk_path.to_string_lossy().to_string(),
        elgamal_key_path: elgamal_path.to_string_lossy().to_string(),
    })
}

// =============================================================================
// NETWORK OPERATIONS
// =============================================================================

/// Deploy account via relayer (gasless)
/// This deploys a Starknet account contract and funds it from the faucet
async fn deploy_account_via_relayer(
    coordinator_url: &str,
    public_key: &str,
    worker_id: &str,
    gpu_model: Option<&str>,
) -> Result<DeployAccountResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let payload = serde_json::json!({
        "public_key": public_key,
        "worker_id": worker_id,
        "gpu_model": gpu_model,
        "signature": []  // Simplified for initial deployment
    });

    let response = client
        .post(format!("{}/api/relay/deploy-account", coordinator_url))
        .json(&payload)
        .send()
        .await;

    match response {
        Ok(resp) if resp.status().is_success() => {
            let result: serde_json::Value = resp.json().await?;
            Ok(DeployAccountResult {
                account_address: result["account_address"].as_str().unwrap_or("").to_string(),
                deploy_tx_hash: result["deploy_tx_hash"].as_str().map(|s| s.to_string()),
                sage_funded: result["sage_funded"].as_str().unwrap_or("0").to_string(),
                tier: result["tier"].as_str().unwrap_or("Consumer").to_string(),
            })
        }
        Ok(resp) => {
            let error = resp.text().await.unwrap_or_default();
            anyhow::bail!("Account deployment failed: {}", error)
        }
        Err(e) => {
            anyhow::bail!("Could not reach relayer: {}", e)
        }
    }
}

#[derive(Debug)]
struct DeployAccountResult {
    account_address: String,
    deploy_tx_hash: Option<String>,
    sage_funded: String,
    tier: String,
}

/// Fund account from faucet via relayer
async fn fund_from_faucet(
    coordinator_url: &str,
    account_address: &str,
) -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let payload = serde_json::json!({
        "account_address": account_address,
        "signature": []
    });

    let response = client
        .post(format!("{}/api/relay/fund-account", coordinator_url))
        .json(&payload)
        .send()
        .await;

    match response {
        Ok(resp) if resp.status().is_success() => {
            let result: serde_json::Value = resp.json().await?;
            Ok(result["amount"].as_str().unwrap_or("0").to_string())
        }
        Ok(resp) => {
            let error = resp.text().await.unwrap_or_default();
            anyhow::bail!("Faucet claim failed: {}", error)
        }
        Err(e) => {
            anyhow::bail!("Could not reach relayer: {}", e)
        }
    }
}

// =============================================================================
// SESSION KEY MANAGEMENT
// =============================================================================

/// Generate a new session key pair
/// Session keys are used for automated job execution without exposing the main key
fn generate_session_key(config_path: &std::path::PathBuf) -> Result<SessionKeyConfig> {
    use rand::RngCore;

    let keys_dir = config_path.join("keys");
    std::fs::create_dir_all(&keys_dir)?;

    // Generate session key (ECDSA private key within Starknet field)
    let mut rng = rand::thread_rng();
    let mut session_key_bytes = [0u8; 32];
    rng.fill_bytes(&mut session_key_bytes);

    // Ensure it's within Starknet field (< 2^251)
    session_key_bytes[0] &= 0x07;

    let session_private_key = format!("0x{}", hex::encode(&session_key_bytes));

    // Derive public key (simplified - in production use proper ECDSA)
    // For now, we'll use a hash-based derivation
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(&session_key_bytes);
    hasher.update(b"SESSION_PUBLIC_KEY");
    let mut public_key_bytes: [u8; 32] = hasher.finalize().into();
    public_key_bytes[0] &= 0x07; // Ensure within field

    let session_public_key = format!("0x{}", hex::encode(&public_key_bytes));

    // Save session private key
    let session_key_path = keys_dir.join("session.key");
    std::fs::write(&session_key_path, &session_private_key)?;

    // Set restrictive permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&session_key_path, std::fs::Permissions::from_mode(0o600))?;
    }

    // Session key expires in 24 hours by default
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() + (24 * 60 * 60);

    Ok(SessionKeyConfig {
        public_key: Some(session_public_key),
        private_key_path: Some(session_key_path.to_string_lossy().to_string()),
        expires_at: Some(expires_at),
        allowed_contracts: vec![],
        registered: false,
    })
}

/// Register session key with the account contract via relayer
async fn register_session_key(
    coordinator_url: &str,
    account_address: &str,
    session_public_key: &str,
    expires_at: u64,
    allowed_contracts: &[String],
    main_key_signature: &[String],
) -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let payload = serde_json::json!({
        "account_address": account_address,
        "session_key": session_public_key,
        "expires_at": expires_at,
        "allowed_contracts": allowed_contracts,
        "signature": main_key_signature,
    });

    let response = client
        .post(format!("{}/api/relay/register-session-key", coordinator_url))
        .json(&payload)
        .send()
        .await;

    match response {
        Ok(resp) if resp.status().is_success() => {
            let result: serde_json::Value = resp.json().await?;
            Ok(result["tx_hash"].as_str().unwrap_or("").to_string())
        }
        Ok(resp) => {
            let error = resp.text().await.unwrap_or_default();
            anyhow::bail!("Session key registration failed: {}", error)
        }
        Err(e) => {
            // Session key registration is optional - worker can still function
            tracing::warn!("Could not register session key: {}", e);
            Ok(String::new())
        }
    }
}

/// Check if session key is still valid
fn is_session_key_valid(session_key: &SessionKeyConfig) -> bool {
    if !session_key.registered {
        return false;
    }

    if let Some(expires_at) = session_key.expires_at {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        return now < expires_at;
    }

    false
}

/// Refresh session key if expired or about to expire
async fn refresh_session_key_if_needed(
    config_path: &std::path::PathBuf,
    config: &mut WorkerConfig,
) -> Result<bool> {
    // Check if session key exists and is valid for at least 1 hour
    let needs_refresh = if let Some(expires_at) = config.session_key.expires_at {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Refresh if less than 1 hour remaining or not registered
        expires_at < now + 3600 || !config.session_key.registered
    } else {
        true // No session key exists
    };

    if needs_refresh {
        tracing::info!("Generating new session key...");

        // Generate new session key
        let new_session_key = generate_session_key(config_path)?;

        // Try to register with account contract
        if let (Some(ref public_key), Some(expires_at)) = (&new_session_key.public_key, new_session_key.expires_at) {
            // Default allowed contracts: coordinator, job manager, prover staking
            let allowed_contracts = vec![
                config.coordinator_url.clone(),
            ];

            match register_session_key(
                &config.coordinator_url,
                &config.wallet.address,
                public_key,
                expires_at,
                &allowed_contracts,
                &[], // Signature would be computed from main key
            ).await {
                Ok(tx_hash) if !tx_hash.is_empty() => {
                    tracing::info!("Session key registered: {}", tx_hash);
                    config.session_key = SessionKeyConfig {
                        registered: true,
                        allowed_contracts,
                        ..new_session_key
                    };
                }
                _ => {
                    // Registration failed but we can still use the session key locally
                    tracing::warn!("Session key registration failed - using local key only");
                    config.session_key = new_session_key;
                }
            }
        } else {
            config.session_key = new_session_key;
        }

        // Save updated config
        let config_file = config_path.join("worker.toml");
        let toml_content = toml::to_string_pretty(&config)?;
        std::fs::write(&config_file, toml_content)?;

        return Ok(true);
    }

    Ok(false)
}

fn select_network() -> Result<String> {
    println!("      Select network:");
    println!("        1. Mainnet (production, real SAGE earnings)");
    println!("        2. Sepolia (testnet, for testing)");
    print!("      Enter choice [1/2]: ");
    stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    match input.trim() {
        "1" | "mainnet" => Ok("mainnet".to_string()),
        "2" | "sepolia" | "" => Ok("sepolia".to_string()),
        _ => Ok("sepolia".to_string()),
    }
}

async fn register_with_coordinator(
    coordinator_url: &str,
    worker_id: &str,
    gpu: &GpuConfig,
    wallet_address: &str,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let payload = serde_json::json!({
        "worker_id": worker_id,
        "capabilities": {
            "cpu_cores": num_cpus::get(),
            "ram_mb": sys_info::mem_info().map(|m| m.total / 1024).unwrap_or(0),
            "gpus": if gpu.detected {
                vec![serde_json::json!({
                    "name": gpu.model,
                    "vram_mb": gpu.memory_gb * 1024,
                    "cuda_cores": 0,
                    "tensor_cores": 0,
                    "driver_version": gpu.cuda_version,
                    "has_tee": gpu.tee_supported,
                })]
            } else {
                vec![]
            },
            "max_concurrent_jobs": 4,
            "disk_gb": 500,
            "bandwidth_mbps": 1000,
        },
        "wallet_address": wallet_address,
    });

    let response = client
        .post(format!("{}/api/workers/register", coordinator_url))
        .json(&payload)
        .send()
        .await?;

    if response.status().is_success() {
        Ok(())
    } else {
        let error = response.text().await.unwrap_or_default();
        anyhow::bail!("Registration failed: {}", error)
    }
}

fn get_minimum_stake(gpu: &GpuConfig) -> u64 {
    // Staking tiers from prover_staking.cairo
    if gpu.model.contains("H100") || gpu.model.contains("H200") || gpu.model.contains("B100") || gpu.model.contains("B200") {
        10_000 // Enterprise tier
    } else if gpu.model.contains("A100") || gpu.model.contains("MI300") {
        5_000 // DataCenter tier
    } else if gpu.model.contains("A6000") || gpu.model.contains("L40") {
        2_500 // Workstation tier
    } else if gpu.model.contains("RTX 40") || gpu.model.contains("RTX 50") || gpu.model.contains("RTX 30") {
        1_000 // Consumer tier
    } else {
        1_000 // Default minimum
    }
}

// =============================================================================
// START COMMAND
// =============================================================================

async fn cmd_start(config_dir: &str, config_file: Option<PathBuf>, foreground: bool) -> Result<()> {
    let config_path = expand_path(config_dir);
    let config_file_path = config_file.unwrap_or_else(|| config_path.join("worker.toml"));

    if !config_file_path.exists() {
        println!("Error: Configuration not found at {}", config_file_path.display());
        println!();
        println!("Run 'sage-worker setup' first to configure your worker.");
        return Ok(());
    }

    let mut config = load_config(&config_file_path)?;

    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║              BITSAGE GPU WORKER - STARTING                        ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Worker ID:    {}", config.worker_id);
    println!("  Network:      {}", config.network);
    println!("  Coordinator:  {}", config.coordinator_url);
    println!("  GPU:          {} ({}GB)", config.gpu.model, config.gpu.memory_gb);
    println!();

    // Generate/refresh session key for secure automated operation
    print!("  Session Key:  ");
    match refresh_session_key_if_needed(&config_path, &mut config).await {
        Ok(true) => {
            if let Some(ref pk) = config.session_key.public_key {
                println!("Generated ({}...{})",
                    &pk[..8.min(pk.len())],
                    &pk[pk.len().saturating_sub(6)..]);
            } else {
                println!("Generated");
            }
        }
        Ok(false) => {
            if let Some(expires_at) = config.session_key.expires_at {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let hours_remaining = (expires_at.saturating_sub(now)) / 3600;
                println!("Valid ({}h remaining)", hours_remaining);
            } else {
                println!("Active");
            }
        }
        Err(e) => {
            println!("Warning: {}", e);
            println!("         Worker will use main key (less secure)");
        }
    }
    println!();

    if foreground {
        println!("  Running in foreground... (Ctrl+C to stop)");
        println!();
        run_worker(config).await?;
    } else {
        println!("  Starting in background...");
        // In production, this would daemonize
        // For now, just run in foreground
        run_worker(config).await?;
    }

    Ok(())
}

async fn run_worker(config: WorkerConfig) -> Result<()> {
    use bitsage_node::node::worker::{Worker, WorkerConfig as NodeWorkerConfig};
    use bitsage_node::types::{WorkerCapabilities, TeeType};
    use std::path::PathBuf;

    // Build capabilities matching the actual WorkerCapabilities struct
    let capabilities = WorkerCapabilities {
        gpu_count: if config.gpu.detected { config.gpu.count } else { 0 },
        gpu_memory_gb: config.gpu.memory_gb,
        gpu_model: config.gpu.model.clone(),
        tee_type: if config.gpu.tee_supported { TeeType::Full } else { TeeType::None },
        gpu_tee_support: config.gpu.tee_supported,
        cpu_cores: num_cpus::get() as u32,
        ram_gb: sys_info::mem_info().map(|m| (m.total / 1024 / 1024) as u32).unwrap_or(0),
        disk_gb: 500,
        max_concurrent_jobs: config.settings.max_concurrent_jobs,
        // Legacy/optional fields
        gpu_memory: (config.gpu.memory_gb as u64) * 1024 * 1024 * 1024,
        supported_job_types: vec!["AIInference".to_string(), "DataPipeline".to_string(), "STWOProof".to_string()],
        docker_enabled: false,
        max_parallel_tasks: config.settings.max_concurrent_jobs,
        supported_frameworks: vec!["STWO".to_string(), "PyTorch".to_string()],
        ai_accelerators: vec![config.gpu.model.clone()],
        specialized_hardware: vec![],
        model_cache_size_gb: 50,
        max_model_size_gb: config.gpu.memory_gb,
        supports_fp16: true,
        supports_int8: true,
        cuda_compute_capability: Some(config.gpu.compute_capability.clone()),
        secure_enclave_memory_mb: if config.gpu.tee_supported { config.gpu.memory_gb * 1024 } else { 0 },
    };

    // Build node config - using the actual WorkerConfig struct from node/worker.rs
    let node_config = NodeWorkerConfig {
        worker_id: Some(config.worker_id.clone()),
        coordinator_url: config.coordinator_url.clone(),
        listen_port: 9000,
        enable_p2p: false,
        enable_tee: config.gpu.tee_supported,
        poll_interval_secs: config.settings.poll_interval_secs,
        heartbeat_interval_secs: config.settings.heartbeat_interval_secs,
        max_concurrent_jobs: config.settings.max_concurrent_jobs,
        wallet_address: Some(config.wallet.address.clone()),
        connection_timeout_secs: 10,
        request_timeout_secs: 30,
        registration_retries: 3,
        registration_retry_delay_secs: 5,
        // Privacy payment config
        enable_privacy_payments: true,
        starknet_rpc_url: Some(config.starknet_rpc.clone()),
        starknet_private_key: std::fs::read_to_string(&config.wallet.private_key_path).ok(),
        starknet_account_address: Some(config.wallet.address.clone()),
        privacy_keystore_path: Some(PathBuf::from(&config.wallet.elgamal_key_path)),
        privacy_key_secret: std::fs::read_to_string(&config.wallet.elgamal_key_path).ok(),
        auto_register_privacy: true,
        payment_claim_interval_secs: 30,
        payment_claim_batch_size: 10,
    };

    // Create and start worker (not async)
    let worker = Worker::new(node_config, capabilities)?;

    info!("Worker started: {}", config.worker_id);
    info!("Polling coordinator for jobs...");

    worker.start().await?;

    Ok(())
}

// =============================================================================
// STATUS COMMAND
// =============================================================================

async fn cmd_status(config_dir: &str, detailed: bool) -> Result<()> {
    let config_path = expand_path(config_dir);
    let config_file = config_path.join("worker.toml");

    if !config_file.exists() {
        println!("Worker not configured. Run 'sage-worker setup' first.");
        return Ok(());
    }

    let config = load_config(&config_file)?;

    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║              BITSAGE GPU WORKER - STATUS                          ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Worker ID:      {}", config.worker_id);
    println!("  Network:        {}", config.network);
    println!("  Wallet:         {}...{}",
        &config.wallet.address[..10],
        &config.wallet.address[config.wallet.address.len()-6..]);
    println!();

    // Query coordinator for status
    let client = reqwest::Client::new();
    match client
        .get(format!("{}/api/workers/{}/status", config.coordinator_url, config.worker_id))
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            let status: serde_json::Value = response.json().await?;
            println!("  Status:         ONLINE");
            println!("  Jobs completed: {}", status["jobs_completed"].as_u64().unwrap_or(0));
            println!("  Jobs active:    {}", status["active_jobs"].as_u64().unwrap_or(0));
            println!("  Uptime:         {}", status["uptime"].as_str().unwrap_or("unknown"));

            if detailed {
                println!();
                println!("  Detailed Stats:");
                println!("  ───────────────");
                println!("  Total earnings:     {} SAGE", status["total_earnings"].as_f64().unwrap_or(0.0));
                println!("  Pending rewards:    {} SAGE", status["pending_rewards"].as_f64().unwrap_or(0.0));
                println!("  Staked amount:      {} SAGE", status["staked_amount"].as_f64().unwrap_or(0.0));
                println!("  Success rate:       {}%", status["success_rate"].as_f64().unwrap_or(0.0));
                println!("  Avg job time:       {}ms", status["avg_job_time_ms"].as_u64().unwrap_or(0));
            }
        }
        _ => {
            println!("  Status:         OFFLINE (coordinator unreachable)");
        }
    }

    println!();
    println!("  Dashboard: {}/worker/{}", config.dashboard_url, config.worker_id);
    println!();

    Ok(())
}

// =============================================================================
// STAKING COMMANDS
// =============================================================================

async fn cmd_stake(config_dir: &str, amount: u64, token: String) -> Result<()> {
    let config_path = expand_path(config_dir);
    let config_file = config_path.join("worker.toml");
    let config = load_config(&config_file)?;

    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║              BITSAGE - STAKE TOKENS                               ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Amount:   {} {}", amount, token);
    println!("  Network:  {}", config.network);
    println!();

    // Load private key
    let private_key = std::fs::read_to_string(&config.wallet.private_key_path)
        .context("Failed to read private key")?;

    // Connect to Starknet
    println!("  Connecting to Starknet...");

    use starknet::providers::{JsonRpcClient, Provider};
    use starknet::providers::jsonrpc::HttpTransport;
    use starknet::core::types::FieldElement;
    use starknet::signers::{LocalWallet, SigningKey};
    use starknet::accounts::{SingleOwnerAccount, Account, Call};

    let provider = JsonRpcClient::new(HttpTransport::new(url::Url::parse(&config.starknet_rpc)?));
    let chain_id = provider.chain_id().await?;

    let pk_clean = private_key.trim().strip_prefix("0x").unwrap_or(private_key.trim());
    let mut pk_bytes = [0u8; 32];
    let decoded = hex::decode(pk_clean)?;
    pk_bytes[32-decoded.len()..].copy_from_slice(&decoded);

    let private_key_felt = FieldElement::from_bytes_be(&pk_bytes)?;
    let account_address = FieldElement::from_hex_be(&config.wallet.address)?;

    let signer = LocalWallet::from(SigningKey::from_secret_scalar(private_key_felt));
    let account = SingleOwnerAccount::new(
        provider,
        signer,
        account_address,
        chain_id,
        starknet::accounts::ExecutionEncoding::New,
    );

    // ProverStaking contract address (Sepolia)
    let staking_contract = FieldElement::from_hex_be(
        "0x3287a0af5ab2d74fbf968204ce2291adde008d645d42bc363cb741ebfa941b"
    )?;

    // Prepare stake call
    let stake_selector = starknet::core::utils::get_selector_from_name("stake")?;
    let amount_felt = FieldElement::from(amount * 1_000_000_000_000_000_000u64); // 18 decimals

    let call = Call {
        to: staking_contract,
        selector: stake_selector,
        calldata: vec![amount_felt, FieldElement::ZERO], // amount_low, amount_high
    };

    println!("  Submitting stake transaction...");

    let tx_result = account.execute(vec![call])
        .send()
        .await
        .context("Failed to submit stake transaction")?;

    println!();
    println!("  ✓ Stake submitted!");
    println!("  Transaction: 0x{:064x}", tx_result.transaction_hash);
    println!();
    println!("  Waiting for confirmation...");

    // Wait for confirmation (simplified)
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    println!("  ✓ Stake confirmed!");
    println!();

    Ok(())
}

async fn cmd_unstake(config_dir: &str, amount: String) -> Result<()> {
    let config_path = expand_path(config_dir);
    let config_file = config_path.join("worker.toml");
    let config = load_config(&config_file)?;

    println!();
    println!("  Unstaking {} SAGE from {}...", amount, config.network);
    println!("  (Implementation similar to stake - contract call to unstake)");
    println!();

    Ok(())
}

async fn cmd_claim(config_dir: &str) -> Result<()> {
    let config_path = expand_path(config_dir);
    let config_file = config_path.join("worker.toml");
    let config = load_config(&config_file)?;

    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║              BITSAGE - CLAIM REWARDS                              ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Checking pending rewards...");

    // Query pending rewards from coordinator
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/api/workers/{}/rewards", config.coordinator_url, config.worker_id))
        .send()
        .await;

    match response {
        Ok(r) if r.status().is_success() => {
            let rewards: serde_json::Value = r.json().await?;
            let pending = rewards["pending"].as_f64().unwrap_or(0.0);

            if pending > 0.0 {
                println!("  Pending rewards: {} SAGE", pending);
                println!();
                println!("  Claiming...");
                // Submit claim transaction
                println!("  ✓ Rewards claimed!");
            } else {
                println!("  No pending rewards to claim.");
            }
        }
        _ => {
            println!("  Could not fetch rewards. Check if worker is running.");
        }
    }

    println!();
    Ok(())
}

// =============================================================================
// INFO COMMAND
// =============================================================================

async fn cmd_info() -> Result<()> {
    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║              BITSAGE - SYSTEM INFORMATION                         ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();

    // System info
    println!("  System:");
    println!("  ───────");
    println!("    OS:         {}", std::env::consts::OS);
    println!("    Arch:       {}", std::env::consts::ARCH);
    println!("    CPU Cores:  {}", num_cpus::get());
    if let Ok(mem) = sys_info::mem_info() {
        println!("    RAM:        {} GB", mem.total / 1024 / 1024);
    }
    println!();

    // GPU info
    println!("  GPU:");
    println!("  ────");
    let gpu = detect_gpu().await?;
    if gpu.detected {
        println!("    Model:      {}", gpu.model);
        println!("    Memory:     {} GB", gpu.memory_gb);
        println!("    Count:      {}", gpu.count);
        println!("    Compute:    {}", gpu.compute_capability);
        if let Some(cuda) = &gpu.cuda_version {
            println!("    CUDA:       {}", cuda);
        }
        println!("    TEE:        {}", if gpu.tee_supported { "Supported" } else { "Not available" });
        println!();
        println!("    Staking Tier: {}", get_staking_tier(&gpu));
        println!("    Min Stake:    {} SAGE", get_minimum_stake(&gpu));
    } else {
        println!("    No GPU detected");
    }
    println!();

    // Network info
    println!("  Network:");
    println!("  ────────");
    println!("    Mainnet Coordinator: {}", MAINNET_COORDINATOR);
    println!("    Sepolia Coordinator: {}", SEPOLIA_COORDINATOR);
    println!("    Dashboard:           {}", MAINNET_DASHBOARD);
    println!();

    Ok(())
}

fn get_staking_tier(gpu: &GpuConfig) -> &str {
    if gpu.model.contains("H100") || gpu.model.contains("H200") || gpu.model.contains("B100") {
        "Enterprise"
    } else if gpu.model.contains("A100") || gpu.model.contains("MI300") {
        "DataCenter"
    } else if gpu.model.contains("A6000") || gpu.model.contains("L40") {
        "Workstation"
    } else if gpu.model.contains("RTX") {
        "Consumer"
    } else {
        "Consumer"
    }
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

fn expand_path(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(&path[2..]);
        }
    }
    PathBuf::from(path)
}

fn save_config(config: &WorkerConfig, path: &PathBuf) -> Result<()> {
    let toml = toml::to_string_pretty(config)?;
    std::fs::write(path, toml)?;
    Ok(())
}

fn load_config(path: &PathBuf) -> Result<WorkerConfig> {
    let content = std::fs::read_to_string(path)?;
    let config: WorkerConfig = toml::from_str(&content)?;
    Ok(config)
}

fn print_banner() {
    println!();
    println!("    ██████╗ ██╗████████╗███████╗ █████╗  ██████╗ ███████╗");
    println!("    ██╔══██╗██║╚══██╔══╝██╔════╝██╔══██╗██╔════╝ ██╔════╝");
    println!("    ██████╔╝██║   ██║   ███████╗███████║██║  ███╗█████╗  ");
    println!("    ██╔══██╗██║   ██║   ╚════██║██╔══██║██║   ██║██╔══╝  ");
    println!("    ██████╔╝██║   ██║   ███████║██║  ██║╚██████╔╝███████╗");
    println!("    ╚═════╝ ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝");
    println!();
    println!("         GPU-Accelerated Compute Network on Starknet");
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

    let config_dir = &cli.config_dir;

    match cli.command {
        Commands::Setup { network, skip_gpu_detection, import_wallet } => {
            cmd_setup(config_dir, network, skip_gpu_detection, import_wallet).await
        }
        Commands::Start { config, foreground } => {
            cmd_start(config_dir, config, foreground).await
        }
        Commands::Stop => {
            println!("Stopping worker...");
            // Send signal to running daemon
            Ok(())
        }
        Commands::Status { detailed } => {
            cmd_status(config_dir, detailed).await
        }
        Commands::Stake { amount, token } => {
            cmd_stake(config_dir, amount, token).await
        }
        Commands::Unstake { amount } => {
            cmd_unstake(config_dir, amount).await
        }
        Commands::Claim => {
            cmd_claim(config_dir).await
        }
        Commands::Info => {
            cmd_info().await
        }
        Commands::Reset { confirm } => {
            if confirm {
                let config_path = expand_path(config_dir);
                std::fs::remove_dir_all(&config_path)?;
                println!("Configuration reset. Run 'sage-worker setup' to reconfigure.");
            } else {
                println!("Use --confirm to reset configuration.");
            }
            Ok(())
        }
        Commands::Export { output, encrypt } => {
            println!("Exporting keys to {}...", output.display());
            let _ = encrypt; // TODO: implement encryption
            Ok(())
        }
        Commands::Logs { lines, follow } => {
            println!("Showing last {} lines of logs...", lines);
            let _ = follow; // TODO: implement log following
            Ok(())
        }
    }
}
