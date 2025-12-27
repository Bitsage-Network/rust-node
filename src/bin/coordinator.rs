//! # BitSage Network Coordinator Binary
//!
//! Comprehensive coordinator service with job processing, monitoring, and blockchain integration

use std::sync::Arc;
use std::net::SocketAddr;
use clap::Parser;
use tracing::{info, error};
use anyhow::Result;
use axum::{Router, routing::get};
use tower_http::cors::CorsLayer;
use tokio::signal;

use bitsage_node::{
    coordinator::{
        job_processor::JobProcessor,
        config::{CoordinatorConfig, JobProcessorConfig, load_config},
    },
    api::{
        create_monitoring_router, MonitoringApiState,
        create_submission_router, SubmissionApiState,
    },
    storage::Database,
    blockchain::{client::StarknetClient, contracts::JobManagerContract},
};

#[derive(Parser)]
#[command(name = "bitsage-coordinator")]
#[command(about = "BitSage Network Coordinator - Job orchestration and monitoring")]
#[command(version)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "config/coordinator.toml")]
    config: String,
    
    /// HTTP API port
    #[arg(short, long, default_value = "8080")]
    port: u16,
    
    /// Bind address
    #[arg(short, long, default_value = "0.0.0.0")]
    bind: String,
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
    
    info!("🚀 Starting BitSage Coordinator...");
    info!("📋 Config file: {}", cli.config);

    // Load configuration
    let config = load_config(&cli.config)?;
    info!("✅ Configuration loaded");

    // Initialize database
    let database = Arc::new(Database::new(&config.database_url).await?);
    info!("✅ Database connected: {}", config.database_url);

    // Initialize blockchain client
    let starknet_client = Arc::new(StarknetClient::new(config.blockchain.rpc_url.clone())?);
    starknet_client.connect().await?;

    // Initialize job manager contract
    let job_manager = Arc::new(
        JobManagerContract::new_from_address(
            starknet_client.clone(),
            &config.blockchain.job_manager_address,
        )?
    );
    info!("✅ Connected to JobManager contract: {}", config.blockchain.job_manager_address);

    // Use the job processor config from the loaded config
    let job_processor = Arc::new(
        JobProcessor::new(
            config.job_processor.clone(),
            database.clone(),
            job_manager.clone(),
        )
    );
    info!("✅ Job processor initialized");
    
    // Start job processor
    job_processor.start().await?;
    info!("✅ Job processor started");
    
    // Create API routers
    let monitoring_state = MonitoringApiState {
        job_processor: job_processor.clone(),
    };
    
    let submission_state = SubmissionApiState {
        job_processor: job_processor.clone(),
    };
    
    let monitoring_router = create_monitoring_router(monitoring_state);
    let submission_router = create_submission_router(submission_state);
    
    // Combine routers
    let app = Router::new()
        .nest("/", monitoring_router)
        .nest("/", submission_router)
        .route("/", get(root_handler))
        .layer(CorsLayer::permissive());
    
    // Start HTTP server
    let addr: SocketAddr = format!("{}:{}", cli.bind, cli.port).parse()?;
    info!("🌐 Starting HTTP API server on http://{}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    
    info!("✅ BitSage Coordinator is running!");
    info!("📡 API: http://{}", addr);
    info!("📊 Health: http://{}/api/health", addr);
    info!("📈 Stats: http://{}/api/stats", addr);
    info!("📝 Submit job: POST http://{}/api/submit", addr);
    info!("");
    info!("Press Ctrl+C to shutdown...");
    
    // Run server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    
    // Cleanup
    info!("🛑 Shutting down...");
    job_processor.stop().await?;
    info!("✅ Coordinator stopped cleanly");
    
    Ok(())
}

/// Root handler
async fn root_handler() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "service": "BitSage Network Coordinator",
        "version": env!("CARGO_PKG_VERSION"),
        "status": "running",
        "endpoints": {
            "health": "/api/health",
            "stats": "/api/stats",
            "submit_job": "POST /api/submit",
            "list_jobs": "/api/jobs",
            "job_status": "/api/jobs/{job_id}",
            "job_result": "/api/jobs/{job_id}/result",
            "job_stream": "/api/jobs/{job_id}/stream",
            "cancel_job": "POST /api/jobs/{job_id}/cancel"
        }
    }))
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

    info!("Shutdown signal received");
}

