//! # BitSage Network Worker Binary
//!
//! Worker node that connects to coordinator and executes compute jobs

use std::sync::Arc;
use clap::Parser;
use tracing::{info, error};
use anyhow::Result;
use tokio::signal;
use serde::Deserialize;

use bitsage_node::{
    types::WorkerCapabilities,
    compute::executor::ComputeExecutor,
    compute::job_executor::{JobExecutor, JobExecutionRequest},
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
struct WorkerConfig {
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
    let config = load_config(&cli.config)?;
    info!("✅ Configuration loaded");
    
    // Determine worker ID
    let worker_id = cli.id
        .or(config.worker.id.clone())
        .unwrap_or_else(|| format!("worker-{}", uuid::Uuid::new_v4()));
    info!("🆔 Worker ID: {}", worker_id);
    
    // Determine coordinator address
    let coordinator_address = cli.coordinator
        .unwrap_or(config.worker.coordinator_address.clone());
    info!("🎯 Coordinator: {}", coordinator_address);
    
    // Detect GPU capabilities
    let capabilities = detect_capabilities(&config.capabilities).await?;
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
    
    // Initialize compute executor
    let executor = Arc::new(ComputeExecutor::new());
    info!("✅ Compute executor initialized");
    
    // Register with coordinator
    info!("📡 Registering with coordinator...");
    match register_with_coordinator(&coordinator_address, &worker_id, &capabilities).await {
        Ok(_) => info!("✅ Successfully registered with coordinator"),
        Err(e) => {
            error!("❌ Failed to register with coordinator: {}", e);
            error!("   Continuing anyway (will retry periodically)...");
        }
    }
    
    // Start worker loop
    info!("✅ BitSage Worker is running!");
    info!("📡 Listening on port: {}", config.network.listen_port);
    info!("🔄 Polling coordinator for jobs...");
    info!("");
    info!("Press Ctrl+C to shutdown...");
    
    // Run worker with graceful shutdown
    tokio::select! {
        result = worker_loop(&coordinator_address, &worker_id, executor) => {
            if let Err(e) = result {
                error!("Worker loop error: {}", e);
            }
        }
        _ = shutdown_signal() => {
            info!("Shutdown signal received");
        }
    }
    
    // Cleanup
    info!("🛑 Shutting down worker...");
    unregister_from_coordinator(&coordinator_address, &worker_id).await?;
    info!("✅ Worker stopped cleanly");
    
    Ok(())
}

/// Load worker configuration from TOML file
fn load_config(path: &str) -> Result<WorkerConfig> {
    let content = std::fs::read_to_string(path)?;
    let config: WorkerConfig = toml::from_str(&content)?;
    Ok(config)
}

/// Detect hardware capabilities
async fn detect_capabilities(config: &CapabilitiesConfig) -> Result<WorkerCapabilities> {
    use bitsage_node::types::TeeType;
    
    let tee_type = match config.tee_type.to_lowercase().as_str() {
        "none" => TeeType::None,
        "cpuonly" | "cpu_only" => TeeType::CpuOnly,
        "full" => TeeType::Full,
        _ => {
            eprintln!("⚠️  Unknown TEE type '{}', defaulting to None", config.tee_type);
            TeeType::None
        }
    };
    
    let has_tee = tee_type != bitsage_node::types::TeeType::None;
    
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

/// Register worker with coordinator
async fn register_with_coordinator(
    coordinator_url: &str,
    worker_id: &str,
    capabilities: &WorkerCapabilities,
) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{}/api/workers/register", coordinator_url);
    
    // Convert to production coordinator format
    let prod_capabilities = serde_json::json!({
        "cpu_cores": capabilities.cpu_cores,
        "ram_mb": capabilities.ram_gb * 1024,
        "gpus": if capabilities.gpu_count > 0 {
            vec![serde_json::json!({
                "name": capabilities.gpu_model,
                "vram_mb": capabilities.gpu_memory_gb * 1024,
                "cuda_cores": 10000, // Mock value
                "tensor_cores": 300, // Mock value
                "driver_version": "535.129.03",
                "has_tee": capabilities.gpu_tee_support,
            })]
        } else {
            vec![]
        },
        "bandwidth_mbps": 1000,
        "supported_job_types": capabilities.supported_job_types.clone(),
        "tee_cpu": matches!(capabilities.tee_type, bitsage_node::types::TeeType::CpuOnly | bitsage_node::types::TeeType::Full),
    });
    
    let response = client
        .post(&url)
        .json(&serde_json::json!({
            "worker_id": worker_id,
            "capabilities": prod_capabilities,
        }))
        .send()
        .await?;
    
    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
        anyhow::bail!("Registration failed: {}", error_text);
    }
    
    Ok(())
}

/// Unregister worker from coordinator
async fn unregister_from_coordinator(
    coordinator_url: &str,
    worker_id: &str,
) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{}/api/workers/{}/unregister", coordinator_url, worker_id);
    
    let _ = client.post(&url).send().await; // Best effort
    Ok(())
}

/// Main worker loop - polls coordinator for jobs
async fn worker_loop(
    coordinator_url: &str,
    worker_id: &str,
    executor: Arc<ComputeExecutor>,
) -> Result<()> {
    let client = reqwest::Client::new();
    let poll_url = format!("{}/api/workers/{}/poll", coordinator_url, worker_id);
    
    loop {
        // Poll for new jobs
        match client.get(&poll_url).send().await {
            Ok(response) if response.status().is_success() => {
                if let Ok(job) = response.json::<serde_json::Value>().await {
                    if !job.is_null() {
                        info!("📥 Received job: {}", job);
                        
                        // Extract job ID first
                        let job_id = job.get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                            .to_string();
                        
                        // Execute job
                        tokio::spawn({
                            let executor = executor.clone();
                            let coordinator_url = coordinator_url.to_string();
                            let worker_id = worker_id.to_string();
                            async move {
                                match execute_job(job, executor).await {
                                    Ok(result) => {
                                        info!("✅ Job {} completed successfully", job_id);
                                        let _ = report_result(&coordinator_url, &job_id, &result).await;
                                    }
                                    Err(e) => {
                                        error!("❌ Job {} execution failed: {}", job_id, e);
                                        let _ = report_error(&coordinator_url, &job_id, &e.to_string()).await;
                                    }
                                }
                            }
                        });
                    }
                }
            }
            Err(e) => {
                error!("❌ Failed to poll coordinator: {}", e);
            }
            _ => {}
        }
        
        // Sleep between polls
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }
}

/// Execute a job using the real JobExecutor
async fn execute_job(
    job: serde_json::Value,
    executor: Arc<ComputeExecutor>,
) -> Result<serde_json::Value> {
    // Manually construct JobExecutionRequest from the coordinator's format
    let job_req = JobExecutionRequest {
        job_id: job.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()),
        job_type: job.get("requirements")
            .and_then(|r| r.get("required_job_type"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        payload: job.get("payload")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect())
            .unwrap_or_default(),
        requirements: serde_json::from_value(job.get("requirements").cloned().unwrap_or_default())?,
        priority: job.get("priority").and_then(|v| v.as_u64()).unwrap_or(0) as u8,
    };
    
    // Create job executor (TODO: pass actual worker_id and TEE status)
    let job_executor = JobExecutor::new("worker".to_string(), false);
    
    // Execute job
    let result = job_executor.execute(job_req).await?;
    
    // Convert result to JSON
    Ok(serde_json::to_value(result)?)
}

/// Report job result to coordinator
async fn report_result(
    coordinator_url: &str,
    job_id: &str,
    result: &serde_json::Value,
) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{}/api/jobs/{}/complete", coordinator_url, job_id);
    
    // Extract result_data from JobExecutionResult
    let result_data = result.get("result_data")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect::<Vec<u8>>())
        .unwrap_or_default();
    
    let response = client.post(&url)
        .json(&serde_json::json!({
            "result": result_data
        }))
        .send()
        .await?;
    
    if !response.status().is_success() {
        anyhow::bail!("Failed to report result: {}", response.status());
    }
    
    Ok(())
}

/// Report job error to coordinator
async fn report_error(
    coordinator_url: &str,
    job_id: &str,
    error: &str,
) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{}/api/jobs/{}/fail", coordinator_url, job_id);
    
    let response = client.post(&url)
        .json(&serde_json::json!({
            "error": error
        }))
        .send()
        .await?;
    
    if !response.status().is_success() {
        anyhow::bail!("Failed to report error: {}", response.status());
    }
    
    Ok(())
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

