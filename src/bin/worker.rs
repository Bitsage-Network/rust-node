//! # BitSage Network Worker Binary
//!
//! Worker node that connects to coordinator and executes compute jobs.
//! This binary uses the Worker struct from `bitsage_node::node::worker`.

use clap::Parser;
use tracing::{info, error};
use anyhow::Result;
use tokio::signal;
use serde::Deserialize;

use bitsage_node::{
    types::{WorkerCapabilities, TeeType},
    node::worker::{Worker, WorkerConfig},
};

#[derive(Parser)]
#[command(name = "bitsage-worker")]
#[command(about = "BitSage Network Worker - Executes compute jobs")]
#[command(version)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "config/worker.toml")]
    config: String,

    /// Worker ID (auto-generated if not specified)
    #[arg(short, long)]
    id: Option<String>,

    /// Coordinator URL
    #[arg(long)]
    coordinator: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FileConfig {
    pub worker: WorkerSettings,
    pub capabilities: CapabilitiesConfig,
    pub network: NetworkConfig,
    #[serde(default)]
    pub security: SecurityConfig,
}

#[derive(Debug, Deserialize)]
struct WorkerSettings {
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
struct CapabilitiesConfig {
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
struct NetworkConfig {
    pub listen_port: u16,
    #[serde(default = "default_true")]
    pub enable_p2p: bool,
}

#[derive(Debug, Deserialize, Default)]
struct SecurityConfig {
    #[serde(default)]
    pub enable_tee: bool,
    #[serde(default = "default_true")]
    pub verify_attestations: bool,
}

fn default_true() -> bool {
    true
}

fn default_poll_interval() -> u64 {
    5
}

fn default_heartbeat_interval() -> u64 {
    30
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .init();

    // Parse CLI args
    let cli = Cli::parse();

    info!("🚀 Starting BitSage Worker...");
    info!("📋 Config file: {}", cli.config);

    // Load configuration
    let file_config = load_config(&cli.config)?;
    info!("✅ Configuration loaded");

    // Determine worker ID
    let worker_id = cli.id
        .or(file_config.worker.id.clone())
        .unwrap_or_else(|| format!("worker-{}", uuid::Uuid::new_v4()));
    info!("🆔 Worker ID: {}", worker_id);

    // Determine coordinator address
    let coordinator_url = cli.coordinator
        .unwrap_or(file_config.worker.coordinator_address.clone());
    info!("🎯 Coordinator: {}", coordinator_url);

    // Build capabilities
    let capabilities = build_capabilities(&file_config.capabilities)?;
    info!("💻 Capabilities detected:");
    info!("   GPU: {} x {} ({} GB each)",
        capabilities.gpu_count,
        capabilities.gpu_model,
        capabilities.gpu_memory_gb
    );
    info!("   TEE: {:?}", capabilities.tee_type);
    info!("   CPU: {} cores, {} GB RAM",
        capabilities.cpu_cores,
        capabilities.ram_gb
    );

    // Build worker configuration
    let config = WorkerConfig {
        worker_id: Some(worker_id.clone()),
        coordinator_url: coordinator_url.clone(),
        listen_port: file_config.network.listen_port,
        enable_p2p: file_config.network.enable_p2p,
        enable_tee: file_config.security.enable_tee,
        poll_interval_secs: file_config.worker.poll_interval_secs,
        heartbeat_interval_secs: file_config.worker.heartbeat_interval_secs,
        max_concurrent_jobs: file_config.capabilities.max_concurrent_jobs,
        wallet_address: file_config.worker.wallet_address.clone(),
        ..Default::default()
    };

    // Create worker
    let worker = Worker::new(config, capabilities)?;
    info!("✅ Worker initialized");

    info!("📡 Listening on port: {}", file_config.network.listen_port);
    info!("");
    info!("Press Ctrl+C to shutdown...");

    // Run worker with graceful shutdown
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

    info!("✅ Worker stopped cleanly");
    Ok(())
}

/// Load worker configuration from TOML file
fn load_config(path: &str) -> Result<FileConfig> {
    let content = std::fs::read_to_string(path)?;
    let config: FileConfig = toml::from_str(&content)?;
    Ok(config)
}

/// Build WorkerCapabilities from config
fn build_capabilities(config: &CapabilitiesConfig) -> Result<WorkerCapabilities> {
    let tee_type = match config.tee_type.to_lowercase().as_str() {
        "none" => TeeType::None,
        "cpuonly" | "cpu_only" => TeeType::CpuOnly,
        "full" => TeeType::Full,
        _ => {
            tracing::warn!(tee_type = %config.tee_type, "Unknown TEE type, defaulting to None");
            TeeType::None
        }
    };

    let has_tee = tee_type != TeeType::None;

    Ok(WorkerCapabilities {
        gpu_count: config.gpu_count,
        gpu_memory_gb: config.gpu_memory_gb,
        gpu_model: config.gpu_model.clone(),
        tee_type,
        gpu_tee_support: config.gpu_tee_support,
        cpu_cores: config.cpu_cores,
        ram_gb: config.ram_gb,
        disk_gb: config.disk_gb,
        max_concurrent_jobs: config.max_concurrent_jobs,
        // Legacy fields with defaults
        gpu_memory: (config.gpu_memory_gb as u64) * 1024 * 1024 * 1024,
        supported_job_types: vec!["AIInference".to_string(), "DataPipeline".to_string()],
        docker_enabled: true,
        max_parallel_tasks: config.max_concurrent_jobs,
        supported_frameworks: vec!["PyTorch".to_string(), "TensorFlow".to_string()],
        ai_accelerators: vec![config.gpu_model.clone()],
        specialized_hardware: vec![],
        model_cache_size_gb: 10,
        max_model_size_gb: config.gpu_memory_gb,
        supports_fp16: true,
        supports_int8: true,
        cuda_compute_capability: Some("8.0".to_string()),
        secure_enclave_memory_mb: if has_tee { 4096 } else { 0 },
    })
}

/// Graceful shutdown signal handler
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
