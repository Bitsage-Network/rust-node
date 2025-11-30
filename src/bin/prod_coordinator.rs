//! # Production Coordinator Binary
//!
//! Enterprise-grade coordinator with full API

use std::sync::Arc;
use std::net::SocketAddr;
use axum::{
    Router,
    routing::{get, post},
    extract::{State, Path},
    Json,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use tracing::{info, error};
use clap::Parser;

use bitsage_node::coordinator::production_coordinator::{
    ProductionCoordinator,
    WorkerCapabilities,
    WorkerHeartbeat,
    JobRequest,
    JobRequirements,
    GpuSpecification,
};

#[derive(Parser)]
#[command(name = "prod-coordinator")]
#[command(about = "Production BitSage Coordinator")]
#[command(version)]
struct Cli {
    #[arg(short, long, default_value = "8080")]
    port: u16,
    
    #[arg(short, long, default_value = "0.0.0.0")]
    bind: String,
}

#[derive(Clone)]
struct AppState {
    coordinator: Arc<ProductionCoordinator>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .init();

    let cli = Cli::parse();
    let coordinator = Arc::new(ProductionCoordinator::new());
    
    info!("🚀 Starting Production BitSage Coordinator");
    info!("   Port: {}", cli.port);
    
    let state = AppState { coordinator };
    
    let app = Router::new()
        // Root & Health
        .route("/", get(root_handler))
        .route("/api/health", get(health_handler))
        .route("/api/stats", get(stats_handler))
        
        // Worker Management
        .route("/api/workers/register", post(register_worker))
        .route("/api/workers/heartbeat", post(worker_heartbeat))
        .route("/api/workers/:id/status", get(worker_status))
        .route("/api/workers/:id/poll", get(poll_for_work))
        .route("/api/workers/list", get(list_workers))
        
        // Job Management
        .route("/api/jobs/submit", post(submit_job))
        .route("/api/jobs/:id/complete", post(complete_job))
        .route("/api/jobs/:id/fail", post(fail_job))
        .route("/api/jobs/:id/status", get(job_status))
        
        .layer(CorsLayer::permissive())
        .with_state(state);
    
    let addr: SocketAddr = format!("{}:{}", cli.bind, cli.port).parse()?;
    info!("✅ Production Coordinator running on http://{}", addr);
    info!("📡 API endpoints:");
    info!("   POST /api/workers/register");
    info!("   POST /api/workers/heartbeat");
    info!("   GET  /api/workers/:id/poll");
    info!("   POST /api/jobs/submit");
    info!("   POST /api/jobs/:id/complete");
    info!("");
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .await?;
    
    Ok(())
}

// ==========================================
// API Handlers
// ==========================================

async fn root_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "service": "BitSage Production Coordinator",
        "version": env!("CARGO_PKG_VERSION"),
        "status": "online",
        "capabilities": [
            "multi-gpu-scheduling",
            "tee-awareness",
            "fault-tolerance",
            "priority-queuing"
        ]
    }))
}

async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().timestamp()
    }))
}

async fn stats_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    let stats = state.coordinator.get_stats().await;
    Json(serde_json::to_value(stats).unwrap())
}

// Worker Endpoints

#[derive(Debug, Deserialize)]
struct RegisterWorkerRequest {
    worker_id: String,
    capabilities: WorkerCapabilities,
}

async fn register_worker(
    State(state): State<AppState>,
    Json(req): Json<RegisterWorkerRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    state.coordinator
        .register_worker(req.worker_id.clone(), req.capabilities)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    Ok(Json(serde_json::json!({
        "status": "registered",
        "worker_id": req.worker_id
    })))
}

async fn worker_heartbeat(
    State(state): State<AppState>,
    Json(heartbeat): Json<WorkerHeartbeat>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    state.coordinator
        .update_worker_heartbeat(heartbeat)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    
    Ok(Json(serde_json::json!({"status": "ok"})))
}

async fn worker_status(
    State(state): State<AppState>,
    Path(worker_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.coordinator.get_worker_status(&worker_id).await {
        Some(status) => Ok(Json(serde_json::json!({
            "worker_id": worker_id,
            "status": format!("{:?}", status)
        }))),
        None => Err((StatusCode::NOT_FOUND, "Worker not found".to_string()))
    }
}

async fn poll_for_work(
    State(state): State<AppState>,
    Path(worker_id): Path<String>,
) -> Json<serde_json::Value> {
    match state.coordinator.poll_for_work(worker_id).await {
        Some(job) => Json(serde_json::to_value(job).unwrap()),
        None => Json(serde_json::json!(null))
    }
}

async fn list_workers(
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let workers = state.coordinator.list_workers().await;
    Json(serde_json::json!({
        "workers": workers.iter().map(|(id, status, load)| {
            serde_json::json!({
                "id": id,
                "status": format!("{:?}", status),
                "load": load
            })
        }).collect::<Vec<_>>()
    }))
}

// Job Endpoints

async fn submit_job(
    State(state): State<AppState>,
    Json(req): Json<JobRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let job_id = state.coordinator
        .submit_job(req)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    Ok(Json(serde_json::json!({
        "status": "submitted",
        "job_id": job_id
    })))
}

#[derive(Debug, Deserialize)]
struct CompleteJobRequest {
    result: Vec<u8>,
}

async fn complete_job(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
    Json(req): Json<CompleteJobRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    state.coordinator
        .complete_job(job_id, req.result)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    Ok(Json(serde_json::json!({"status": "completed"})))
}

#[derive(Debug, Deserialize)]
struct FailJobRequest {
    error: String,
}

async fn fail_job(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
    Json(req): Json<FailJobRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    state.coordinator
        .fail_job(job_id, req.error)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    Ok(Json(serde_json::json!({"status": "failed"})))
}

async fn job_status(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.coordinator.get_job_status(&job_id).await {
        Some(status) => Ok(Json(serde_json::json!({
            "job_id": job_id,
            "status": format!("{:?}", status)
        }))),
        None => Err((StatusCode::NOT_FOUND, "Job not found".to_string()))
    }
}

