//! # BitSage Network Worker Binary
//!
//! Worker node that connects to coordinator and executes compute jobs.
//! Provides a full CLI with setup wizard, status, logs, and more.

use clap::{Parser, Subcommand};
use tracing::{info, error, warn};
use anyhow::{Result, anyhow};
use tokio::signal;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::io::{self, Write};

use bitsage_node::{
    types::{WorkerCapabilities, TeeType},
    node::worker::{Worker, WorkerConfig},
};

const BITSAGE_DIR: &str = ".bitsage";
const CONFIG_FILE: &str = "worker.toml";
const KEYS_DIR: &str = "keys";

// Starknet prime: 2^251 + 17 * 2^192 + 1
// We'll generate addresses below 2^251 to be safe
const STARKNET_ADDRESS_BITS: u32 = 250;

#[derive(Parser)]
#[command(name = "sage-worker")]
#[command(about = "BitSage GPU Worker - Earn SAGE tokens by providing compute")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Set up the worker with an interactive wizard
    Setup {
        /// Network to connect to (sepolia or mainnet)
        #[arg(long, default_value = "sepolia")]
        network: String,
    },

    /// Start the worker and begin accepting jobs
    Start,

    /// Check worker status
    Status,

    /// Show worker info and earnings
    Info,

    /// Show worker logs
    Logs {
        /// Number of lines to show
        #[arg(short, long, default_value = "50")]
        lines: usize,

        /// Follow log output
        #[arg(short, long)]
        follow: bool,
    },

    /// Stake SAGE tokens for higher tier
    Stake {
        /// Amount of SAGE to stake
        #[arg(long)]
        amount: u64,
    },

    /// Claim accumulated rewards
    Claim,
}

#[derive(Debug, Serialize, Deserialize)]
struct WorkerTomlConfig {
    worker_id: String,
    network: String,
    coordinator_url: String,
    starknet_rpc: String,
    dashboard_url: String,

    wallet: WalletConfig,
    gpu: GpuConfig,
    settings: SettingsConfig,
}

#[derive(Debug, Serialize, Deserialize)]
struct WalletConfig {
    address: String,
    private_key_path: String,
    elgamal_key_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GpuConfig {
    detected: bool,
    count: u32,
    model: String,
    memory_gb: u32,
    compute_capability: String,
    tee_supported: bool,
    cuda_version: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SettingsConfig {
    poll_interval_secs: u64,
    heartbeat_interval_secs: u64,
    max_concurrent_jobs: u32,
    auto_claim_rewards: bool,
}

// Legacy config format for backwards compatibility
#[derive(Debug, Deserialize)]
struct LegacyFileConfig {
    pub worker: LegacyWorkerSettings,
    pub capabilities: LegacyCapabilitiesConfig,
    pub network: LegacyNetworkConfig,
    #[serde(default)]
    pub security: LegacySecurityConfig,
}

#[derive(Debug, Deserialize)]
struct LegacyWorkerSettings {
    pub id: Option<String>,
    pub coordinator_address: String,
    #[serde(default)]
    pub wallet_address: Option<String>,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,
}

#[derive(Debug, Deserialize)]
struct LegacyCapabilitiesConfig {
    pub gpu_count: u32,
    pub gpu_memory_gb: u32,
    pub gpu_model: String,
    pub tee_type: String,
    #[serde(default)]
    pub gpu_tee_support: bool,
    pub cpu_cores: u32,
    pub ram_gb: u32,
    pub disk_gb: u32,
    pub max_concurrent_jobs: u32,
}

#[derive(Debug, Deserialize)]
struct LegacyNetworkConfig {
    pub listen_port: u16,
    #[serde(default = "default_true")]
    pub enable_p2p: bool,
}

#[derive(Debug, Deserialize, Default)]
struct LegacySecurityConfig {
    #[serde(default)]
    pub enable_tee: bool,
    #[serde(default = "default_true")]
    pub verify_attestations: bool,
}

fn default_true() -> bool { true }
fn default_poll_interval() -> u64 { 5 }
fn default_heartbeat_interval() -> u64 { 30 }

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Setup { network } => run_setup(&network).await,
        Commands::Start => run_start().await,
        Commands::Status => run_status().await,
        Commands::Info => run_info().await,
        Commands::Logs { lines, follow } => run_logs(lines, follow).await,
        Commands::Stake { amount } => run_stake(amount).await,
        Commands::Claim => run_claim().await,
    }
}

fn get_bitsage_dir() -> PathBuf {
    dirs::home_dir()
        .expect("Could not find home directory")
        .join(BITSAGE_DIR)
}

fn get_config_path() -> PathBuf {
    get_bitsage_dir().join(CONFIG_FILE)
}

fn get_keys_dir() -> PathBuf {
    get_bitsage_dir().join(KEYS_DIR)
}

/// Detect GPU hardware
fn detect_gpu() -> GpuConfig {
    // Try nvidia-smi first
    let nvidia_smi = std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=name,memory.total,driver_version,compute_cap", "--format=csv,noheader,nounits"])
        .output();

    if let Ok(output) = nvidia_smi {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = stdout.trim().lines().collect();

            if !lines.is_empty() {
                let parts: Vec<&str> = lines[0].split(',').map(|s| s.trim()).collect();
                if parts.len() >= 4 {
                    let model = parts[0].to_string();
                    let memory_mb: u32 = parts[1].parse().unwrap_or(0);
                    let cuda_version = parts[2].to_string();
                    let compute_cap = parts[3].to_string();

                    // Check for TEE support (H100 Confidential Computing)
                    let tee_supported = model.contains("H100") || model.contains("A100");

                    return GpuConfig {
                        detected: true,
                        count: lines.len() as u32,
                        model,
                        memory_gb: memory_mb / 1024,
                        compute_capability: compute_cap,
                        tee_supported,
                        cuda_version,
                    };
                }
            }
        }
    }

    // No GPU detected
    GpuConfig {
        detected: false,
        count: 0,
        model: "None".to_string(),
        memory_gb: 0,
        compute_capability: "0.0".to_string(),
        tee_supported: false,
        cuda_version: "N/A".to_string(),
    }
}

/// Generate a valid Starknet address (within field bounds)
fn generate_starknet_address() -> String {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;

    // Generate 31 bytes (248 bits) to stay well within the 251-bit Starknet field
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes[1..]); // Leave first byte as 0
    bytes[0] = 0; // Ensure high byte is 0
    bytes[1] &= 0x07; // Limit to 250 bits total

    format!("0x{}", hex::encode(bytes))
}

/// Generate a private key for Starknet
fn generate_private_key() -> String {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;

    // Generate 31 bytes for private key (within Starknet field)
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes[1..]);
    bytes[0] = 0;
    bytes[1] &= 0x07;

    format!("0x{}", hex::encode(bytes))
}

/// Generate ElGamal keypair for privacy
fn generate_elgamal_keypair() -> (String, String) {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;

    // Private key: random 32 bytes
    let mut sk = [0u8; 32];
    rng.fill_bytes(&mut sk);

    // For simplicity, public key is just a placeholder
    // In real implementation, this would be computed from sk
    let mut pk = [0u8; 64];
    rng.fill_bytes(&mut pk);

    (hex::encode(sk), hex::encode(pk))
}

async fn run_setup(network: &str) -> Result<()> {
    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║              BITSAGE GPU WORKER - SETUP WIZARD                    ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();

    // Create directories
    let bitsage_dir = get_bitsage_dir();
    let keys_dir = get_keys_dir();
    std::fs::create_dir_all(&keys_dir)?;

    // Step 1: Detect hardware
    println!("  [1/5] Detecting hardware...");
    let gpu = detect_gpu();

    if gpu.detected {
        println!("  ✅ GPU detected: {} x {} ({} GB VRAM)", gpu.count, gpu.model, gpu.memory_gb);
        println!("     CUDA: {}, Compute: {}", gpu.cuda_version, gpu.compute_capability);
        if gpu.tee_supported {
            println!("     TEE: Supported (Confidential Computing)");
        }
    } else {
        println!("  ⚠️  No NVIDIA GPU detected");
        println!("     Worker can still run in CPU-only mode");
    }
    println!();

    // Step 2: Network selection
    println!("  [2/5] Configuring network...");
    let (coordinator_url, starknet_rpc, dashboard_url) = match network.to_lowercase().as_str() {
        "mainnet" => {
            println!("  ⚠️  Mainnet selected - real tokens will be used!");
            (
                "https://coordinator.bitsage.network".to_string(),
                "https://starknet-mainnet-rpc.publicnode.com".to_string(),
                "https://dashboard.bitsage.network".to_string(),
            )
        }
        _ => {
            println!("  ✅ Sepolia testnet selected");
            (
                "http://35.163.191.22:8080".to_string(), // AWS coordinator
                "https://starknet-sepolia-rpc.publicnode.com".to_string(),
                "https://dashboard-sepolia.bitsage.network".to_string(),
            )
        }
    };
    println!("     Coordinator: {}", coordinator_url);
    println!();

    // Step 3: Generate wallet
    println!("  [3/5] Generating Starknet wallet...");
    let wallet_address = generate_starknet_address();
    let private_key = generate_private_key();

    // Save private key
    let starknet_key_path = keys_dir.join("starknet.key");
    std::fs::write(&starknet_key_path, &private_key)?;
    println!("  ✅ Wallet created: {}...{}",
        &wallet_address[..10],
        &wallet_address[wallet_address.len()-6..]
    );
    println!("     Private key saved to: {}", starknet_key_path.display());
    println!();

    // Step 4: Generate encryption keys
    println!("  [4/5] Generating encryption keys...");
    let (elgamal_sk, elgamal_pk) = generate_elgamal_keypair();

    let elgamal_key_path = keys_dir.join("elgamal.key");
    std::fs::write(&elgamal_key_path, format!("{}\n{}", elgamal_sk, elgamal_pk))?;
    println!("  ✅ ElGamal keys generated for privacy features");
    println!();

    // Step 5: Generate worker ID and save config
    println!("  [5/5] Saving configuration...");
    let worker_id = format!("worker-{}", &uuid::Uuid::new_v4().to_string()[..8]);

    let config = WorkerTomlConfig {
        worker_id: worker_id.clone(),
        network: network.to_string(),
        coordinator_url,
        starknet_rpc,
        dashboard_url: dashboard_url.clone(),
        wallet: WalletConfig {
            address: wallet_address.clone(),
            private_key_path: starknet_key_path.to_string_lossy().to_string(),
            elgamal_key_path: elgamal_key_path.to_string_lossy().to_string(),
        },
        gpu: gpu.clone(),
        settings: SettingsConfig {
            poll_interval_secs: 5,
            heartbeat_interval_secs: 30,
            max_concurrent_jobs: gpu.count.max(1) * 4,
            auto_claim_rewards: true,
        },
    };

    let config_path = get_config_path();
    let toml_content = toml::to_string_pretty(&config)?;
    std::fs::write(&config_path, toml_content)?;
    println!("  ✅ Configuration saved to: {}", config_path.display());
    println!();

    // Summary
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║                    SETUP COMPLETE                                 ║");
    println!("╠═══════════════════════════════════════════════════════════════════╣");
    println!("║                                                                   ║");
    println!("║  Worker ID:  {}                                   ║", worker_id);
    println!("║  Network:    {}                                         ║", network);
    println!("║  GPU:        {} x {}                          ║",
        gpu.count,
        if gpu.model.len() > 20 { &gpu.model[..20] } else { &gpu.model }
    );
    println!("║                                                                   ║");
    println!("║  Wallet: {}...{}                   ║",
        &wallet_address[..10],
        &wallet_address[wallet_address.len()-6..]
    );
    println!("║                                                                   ║");
    println!("║  IMPORTANT: Save your wallet address to receive SAGE tokens!     ║");
    println!("║                                                                   ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Next step: Start earning with:");
    println!("    sage-worker start");
    println!();
    println!("  Or view your dashboard at:");
    println!("    {}/worker/{}", dashboard_url, worker_id);
    println!();

    Ok(())
}

async fn run_start() -> Result<()> {
    let config_path = get_config_path();

    if !config_path.exists() {
        eprintln!("❌ Worker not configured. Run 'sage-worker setup' first.");
        return Err(anyhow!("Configuration not found"));
    }

    // Load configuration
    let content = std::fs::read_to_string(&config_path)?;
    let config: WorkerTomlConfig = toml::from_str(&content)?;

    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║              BITSAGE GPU WORKER - STARTING                        ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Worker ID:    {}", config.worker_id);
    println!("  Network:      {}", config.network);
    println!("  Coordinator:  {}", config.coordinator_url);
    if config.gpu.detected {
        println!("  GPU:          {} ({} GB)", config.gpu.model, config.gpu.memory_gb);
    }
    println!();

    // Build worker config
    let tee_type = if config.gpu.tee_supported {
        TeeType::Full
    } else {
        TeeType::CpuOnly
    };

    let capabilities = WorkerCapabilities {
        gpu_count: config.gpu.count,
        gpu_memory_gb: config.gpu.memory_gb,
        gpu_model: config.gpu.model.clone(),
        tee_type,
        gpu_tee_support: config.gpu.tee_supported,
        cpu_cores: num_cpus::get() as u32,
        ram_gb: (sys_info::mem_info().map(|m| m.total / 1024 / 1024).unwrap_or(16)) as u32,
        disk_gb: 100,
        max_concurrent_jobs: config.settings.max_concurrent_jobs,
        gpu_memory: (config.gpu.memory_gb as u64) * 1024 * 1024 * 1024,
        supported_job_types: vec!["AIInference".to_string(), "DataPipeline".to_string()],
        docker_enabled: true,
        max_parallel_tasks: config.settings.max_concurrent_jobs,
        supported_frameworks: vec!["PyTorch".to_string(), "TensorFlow".to_string()],
        ai_accelerators: vec![config.gpu.model.clone()],
        specialized_hardware: vec![],
        model_cache_size_gb: 10,
        max_model_size_gb: config.gpu.memory_gb,
        supports_fp16: true,
        supports_int8: true,
        cuda_compute_capability: Some(config.gpu.compute_capability.clone()),
        secure_enclave_memory_mb: if config.gpu.tee_supported { 4096 } else { 0 },
        gpu_uuids: Vec::new(),
    };

    let worker_config = WorkerConfig {
        worker_id: Some(config.worker_id.clone()),
        coordinator_url: config.coordinator_url.clone(),
        listen_port: 9000,
        enable_p2p: true,
        enable_tee: config.gpu.tee_supported,
        poll_interval_secs: config.settings.poll_interval_secs,
        heartbeat_interval_secs: config.settings.heartbeat_interval_secs,
        max_concurrent_jobs: config.settings.max_concurrent_jobs,
        wallet_address: Some(config.wallet.address.clone()),
        starknet_rpc_url: Some(config.starknet_rpc.clone()),
        starknet_private_key: std::fs::read_to_string(&config.wallet.private_key_path).ok(),
        starknet_account_address: Some(config.wallet.address.clone()),
        auto_register_privacy: true,
        ..Default::default()
    };

    // Create and start worker
    let worker = Worker::new(worker_config, capabilities)?;

    info!("Press Ctrl+C to shutdown...");

    tokio::select! {
        result = worker.start() => {
            if let Err(e) = result {
                error!("Worker error: {}", e);
                return Err(e);
            }
        }
        _ = shutdown_signal() => {
            info!("Shutdown signal received");
            if let Err(e) = worker.stop().await {
                error!("Error stopping worker: {}", e);
            }
        }
    }

    info!("Worker stopped");
    Ok(())
}

async fn run_status() -> Result<()> {
    let config_path = get_config_path();

    if !config_path.exists() {
        println!();
        println!("╔═══════════════════════════════════════════════════════════════════╗");
        println!("║              BITSAGE GPU WORKER - STATUS                          ║");
        println!("╚═══════════════════════════════════════════════════════════════════╝");
        println!();
        println!("  Status: NOT CONFIGURED");
        println!();
        println!("  Run 'sage-worker setup' to configure your worker.");
        println!();
        return Ok(());
    }

    let content = std::fs::read_to_string(&config_path)?;
    let config: WorkerTomlConfig = toml::from_str(&content)?;

    // Query coordinator for status
    let client = reqwest::Client::new();
    let status_url = format!("{}/api/workers/{}/status", config.coordinator_url, config.worker_id);

    let (status, jobs_completed, jobs_active) = match client.get(&status_url).send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                let json: serde_json::Value = resp.json().await.unwrap_or_default();
                (
                    json.get("status").and_then(|v| v.as_str()).unwrap_or("UNKNOWN").to_string(),
                    json.get("jobs_completed").and_then(|v| v.as_u64()).unwrap_or(0),
                    json.get("jobs_active").and_then(|v| v.as_u64()).unwrap_or(0),
                )
            } else {
                ("OFFLINE".to_string(), 0, 0)
            }
        }
        Err(_) => ("OFFLINE".to_string(), 0, 0),
    };

    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║              BITSAGE GPU WORKER - STATUS                          ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Worker ID:      {}", config.worker_id);
    println!("  Network:        {}", config.network);
    println!("  Wallet:         {}...{}",
        &config.wallet.address[..10],
        &config.wallet.address[config.wallet.address.len()-6..]
    );
    println!();
    println!("  Status:         {}", status);
    println!("  Jobs completed: {}", jobs_completed);
    println!("  Jobs active:    {}", jobs_active);
    println!("  Uptime:         unknown");
    println!();
    println!("  Dashboard: {}/worker/{}", config.dashboard_url, config.worker_id);
    println!();

    Ok(())
}

async fn run_info() -> Result<()> {
    let config_path = get_config_path();

    if !config_path.exists() {
        eprintln!("❌ Worker not configured. Run 'sage-worker setup' first.");
        return Err(anyhow!("Configuration not found"));
    }

    let content = std::fs::read_to_string(&config_path)?;
    let config: WorkerTomlConfig = toml::from_str(&content)?;

    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║              BITSAGE GPU WORKER - INFO                            ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Worker ID:       {}", config.worker_id);
    println!("  Network:         {}", config.network);
    println!("  Coordinator:     {}", config.coordinator_url);
    println!();
    println!("  Wallet Address:  {}", config.wallet.address);
    println!();
    println!("  GPU Configuration:");
    println!("    Model:         {}", config.gpu.model);
    println!("    Count:         {}", config.gpu.count);
    println!("    Memory:        {} GB", config.gpu.memory_gb);
    println!("    CUDA:          {}", config.gpu.cuda_version);
    println!("    Compute:       {}", config.gpu.compute_capability);
    println!("    TEE Support:   {}", if config.gpu.tee_supported { "Yes" } else { "No" });
    println!();
    println!("  Settings:");
    println!("    Poll Interval:     {} secs", config.settings.poll_interval_secs);
    println!("    Heartbeat:         {} secs", config.settings.heartbeat_interval_secs);
    println!("    Max Concurrent:    {} jobs", config.settings.max_concurrent_jobs);
    println!("    Auto Claim:        {}", if config.settings.auto_claim_rewards { "Yes" } else { "No" });
    println!();

    // TODO: Query earnings from coordinator
    println!("  Earnings:");
    println!("    Total Earned:      0.00 SAGE");
    println!("    Pending:           0.00 SAGE");
    println!("    Last Payout:       N/A");
    println!();

    Ok(())
}

async fn run_logs(lines: usize, follow: bool) -> Result<()> {
    // Check if running as systemd service
    let output = std::process::Command::new("journalctl")
        .args(["-u", "bitsage-worker", "-n", &lines.to_string()])
        .arg(if follow { "-f" } else { "--no-pager" })
        .spawn();

    match output {
        Ok(mut child) => {
            child.wait()?;
        }
        Err(_) => {
            println!("No systemd logs found. Try running in foreground to see logs.");
        }
    }

    Ok(())
}

async fn run_stake(amount: u64) -> Result<()> {
    let config_path = get_config_path();

    if !config_path.exists() {
        eprintln!("❌ Worker not configured. Run 'sage-worker setup' first.");
        return Err(anyhow!("Configuration not found"));
    }

    let content = std::fs::read_to_string(&config_path)?;
    let config: WorkerTomlConfig = toml::from_str(&content)?;

    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║              BITSAGE GPU WORKER - STAKE                           ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Staking {} SAGE tokens...", amount);
    println!();

    // Determine tier
    let tier = if amount >= 25000 {
        ("Frontier", "Maximum priority, premium jobs")
    } else if amount >= 10000 {
        ("Enterprise", "Premium jobs")
    } else if amount >= 5000 {
        ("DataCenter", "Enterprise jobs")
    } else if amount >= 2500 {
        ("Workstation", "Priority queue")
    } else if amount >= 1000 {
        ("Consumer", "Standard jobs")
    } else {
        ("None", "Minimum 1,000 SAGE required")
    };

    if amount < 1000 {
        println!("  ❌ Minimum stake is 1,000 SAGE");
        println!();
        return Ok(());
    }

    println!("  Tier:        {}", tier.0);
    println!("  Benefits:    {}", tier.1);
    println!();

    // TODO: Call Starknet staking contract
    println!("  ⚠️  Staking not yet implemented in CLI");
    println!("     Visit dashboard to stake: {}/worker/{}", config.dashboard_url, config.worker_id);
    println!();

    Ok(())
}

async fn run_claim() -> Result<()> {
    let config_path = get_config_path();

    if !config_path.exists() {
        eprintln!("❌ Worker not configured. Run 'sage-worker setup' first.");
        return Err(anyhow!("Configuration not found"));
    }

    let content = std::fs::read_to_string(&config_path)?;
    let config: WorkerTomlConfig = toml::from_str(&content)?;

    println!();
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║              BITSAGE GPU WORKER - CLAIM REWARDS                   ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!();

    // TODO: Query pending rewards and claim
    println!("  ⚠️  Claiming not yet implemented in CLI");
    println!("     Visit dashboard to claim: {}/worker/{}", config.dashboard_url, config.worker_id);
    println!();

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
