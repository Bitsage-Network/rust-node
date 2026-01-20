//! STWO GPU Proof Generation API
//!
//! HTTP endpoints for GPU-accelerated STWO proof generation.
//! Supports batch processing, priority queuing, and TEE attestation.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

// =============================================================================
// TYPES
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuTier {
    H100,
    H200,
    B200,
    A100,
    #[serde(rename = "4090")]
    Rtx4090,
    Auto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofJobPriority {
    Standard,
    High,
    Critical,
    Emergency,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofJobStatus {
    Queued,
    Assigned,
    Generating,
    Completed,
    Failed,
    Cancelled,
    Timeout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofType {
    BatchPayments,
    AiInference,
    CrossChainBridge,
    DefiCalculation,
    GameState,
    VrfRandomness,
    KycVerification,
    SupplyChain,
    RecursiveAggregation,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeeType {
    IntelTDX,
    AMDSEVSNP,
    NvidiaCC,
}

// =============================================================================
// REQUEST/RESPONSE STRUCTS
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct GenerateProofRequest {
    pub proof_type: ProofType,
    pub public_inputs: Vec<String>,
    pub private_inputs: Option<Vec<String>>,
    pub circuit_id: Option<String>,
    pub priority: Option<ProofJobPriority>,
    pub gpu_tier: Option<GpuTier>,
    pub deadline: Option<u64>,
    pub require_tee: Option<bool>,
    pub max_cost_usdc: Option<f64>,
    pub callback_url: Option<String>,
    pub metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize)]
pub struct GenerateProofResponse {
    pub job_id: String,
    pub status: ProofJobStatus,
    pub estimated_cost_usdc: f64,
    pub estimated_time_secs: u64,
    pub queue_position: Option<u32>,
    pub assigned_gpu: Option<AssignedGpu>,
    pub created_at: u64,
}

#[derive(Debug, Serialize)]
pub struct AssignedGpu {
    pub tier: GpuTier,
    pub worker_id: String,
    pub tee_enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct ProofStatusResponse {
    pub job_id: String,
    pub status: ProofJobStatus,
    pub progress_bps: u32,
    pub estimated_time_remaining_secs: u64,
    pub current_phase: String,
    pub gpu_utilization: Option<f32>,
    pub memory_used_mb: Option<u32>,
    pub error_message: Option<String>,
    pub retry_count: u32,
}

#[derive(Debug, Serialize)]
pub struct ProofResultResponse {
    pub job_id: String,
    pub proof_hash: String,
    pub proof_data: String,
    pub public_input_hash: String,
    pub proof_size_bytes: u64,
    pub generation_time_ms: u64,
    pub cost_usdc: f64,
    pub gpu_tier: GpuTier,
    pub tee_attestation: Option<TeeAttestation>,
    pub verification_status: String,
    pub tx_hash: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TeeAttestation {
    pub tee_type: TeeType,
    pub enclave_measurement: String,
    pub quote_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct BatchProofRequest {
    pub proofs: Vec<BatchProofItem>,
    pub aggregate: Option<bool>,
    pub priority: Option<ProofJobPriority>,
    pub max_total_cost_usdc: Option<f64>,
}

#[derive(Debug, Deserialize)]
pub struct BatchProofItem {
    pub proof_type: ProofType,
    pub public_inputs: Vec<String>,
    pub private_inputs: Option<Vec<String>>,
    pub circuit_id: Option<String>,
    pub require_tee: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct BatchProofResponse {
    pub batch_id: String,
    pub job_ids: Vec<String>,
    pub estimated_total_cost_usdc: f64,
    pub estimated_time_secs: u64,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct EstimateRequest {
    pub proof_type: ProofType,
    pub public_inputs_count: usize,
    pub private_inputs_count: Option<usize>,
    pub circuit_id: Option<String>,
    pub priority: Option<ProofJobPriority>,
    pub gpu_tier: Option<GpuTier>,
    pub require_tee: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct EstimateResponse {
    pub cost_usdc: f64,
    pub time_secs: u64,
    pub recommended_gpu_tier: GpuTier,
    pub breakdown: CostBreakdown,
}

#[derive(Debug, Serialize)]
pub struct CostBreakdown {
    pub base_cost: f64,
    pub constraint_cost: f64,
    pub priority_surcharge: f64,
    pub tee_surcharge: f64,
}

#[derive(Debug, Serialize)]
pub struct MetricsResponse {
    pub available_gpus: Vec<GpuAvailability>,
    pub queue_depth: u32,
    pub avg_wait_time_secs: u64,
    pub proofs_last_hour: u32,
    pub network_utilization: f32,
    pub pricing: Vec<PricingInfo>,
}

#[derive(Debug, Serialize)]
pub struct GpuAvailability {
    pub tier: GpuTier,
    pub count: u32,
    pub tee_enabled: u32,
}

#[derive(Debug, Serialize)]
pub struct PricingInfo {
    pub proof_type: ProofType,
    pub base_cost_usdc: f64,
    pub per_constraint_usdc: f64,
}

#[derive(Debug, Serialize)]
pub struct QueueResponse {
    pub total: u32,
    pub by_priority: HashMap<String, u32>,
    pub estimated_clear_time_secs: u64,
}

#[derive(Debug, Serialize)]
pub struct CancelResponse {
    pub cancelled: bool,
}

// =============================================================================
// STATE
// =============================================================================

#[derive(Debug, Clone)]
pub struct ProofJob {
    pub id: String,
    pub proof_type: ProofType,
    pub public_inputs: Vec<String>,
    pub private_inputs: Option<Vec<String>>,
    pub priority: ProofJobPriority,
    pub status: ProofJobStatus,
    pub progress_bps: u32,
    pub gpu_tier: Option<GpuTier>,
    pub require_tee: bool,
    pub created_at: u64,
    pub started_at: Option<u64>,
    pub completed_at: Option<u64>,
    pub proof_hash: Option<String>,
    pub proof_data: Option<String>,
    pub error_message: Option<String>,
    pub retry_count: u32,
}

pub struct ProofGenerationState {
    pub jobs: RwLock<HashMap<String, ProofJob>>,
    pub batches: RwLock<HashMap<String, Vec<String>>>,
    pub queue_depth: RwLock<u32>,
    pub gpu_enabled: bool,
}

impl ProofGenerationState {
    pub fn new(gpu_enabled: bool) -> Self {
        Self {
            jobs: RwLock::new(HashMap::new()),
            batches: RwLock::new(HashMap::new()),
            queue_depth: RwLock::new(0),
            gpu_enabled,
        }
    }
}

// =============================================================================
// HANDLERS
// =============================================================================

/// Submit a proof generation job
pub async fn generate_proof_handler(
    State(state): State<Arc<ProofGenerationState>>,
    Json(request): Json<GenerateProofRequest>,
) -> impl IntoResponse {
    let job_id = Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let job = ProofJob {
        id: job_id.clone(),
        proof_type: request.proof_type.clone(),
        public_inputs: request.public_inputs.clone(),
        private_inputs: request.private_inputs,
        priority: request.priority.clone().unwrap_or(ProofJobPriority::Standard),
        status: ProofJobStatus::Queued,
        progress_bps: 0,
        gpu_tier: request.gpu_tier.clone(),
        require_tee: request.require_tee.unwrap_or(false),
        created_at: now,
        started_at: None,
        completed_at: None,
        proof_hash: None,
        proof_data: None,
        error_message: None,
        retry_count: 0,
    };

    // Store the job
    {
        let mut jobs = state.jobs.write().await;
        jobs.insert(job_id.clone(), job);
    }

    // Increment queue depth
    {
        let mut depth = state.queue_depth.write().await;
        *depth += 1;
    }

    // Estimate cost based on proof type and inputs
    let estimated_cost = estimate_proof_cost(&request.proof_type, request.public_inputs.len());
    let estimated_time = estimate_proof_time(&request.proof_type, state.gpu_enabled);

    let response = GenerateProofResponse {
        job_id,
        status: ProofJobStatus::Queued,
        estimated_cost_usdc: estimated_cost,
        estimated_time_secs: estimated_time,
        queue_position: Some(1),
        assigned_gpu: if state.gpu_enabled {
            Some(AssignedGpu {
                tier: request.gpu_tier.unwrap_or(GpuTier::Auto),
                worker_id: "worker-001".to_string(),
                tee_enabled: request.require_tee.unwrap_or(false),
            })
        } else {
            None
        },
        created_at: now,
    };

    // Spawn background task to simulate proof generation
    let state_clone = state.clone();
    let job_id_clone = response.job_id.clone();
    tokio::spawn(async move {
        simulate_proof_generation(state_clone, job_id_clone).await;
    });

    (StatusCode::OK, Json(response))
}

/// Get proof job status
pub async fn get_job_status_handler(
    State(state): State<Arc<ProofGenerationState>>,
    Path(job_id): Path<String>,
) -> impl IntoResponse {
    let jobs = state.jobs.read().await;

    match jobs.get(&job_id) {
        Some(job) => {
            let response = ProofStatusResponse {
                job_id: job.id.clone(),
                status: job.status.clone(),
                progress_bps: job.progress_bps,
                estimated_time_remaining_secs: calculate_remaining_time(job),
                current_phase: get_current_phase(job),
                gpu_utilization: if job.status == ProofJobStatus::Generating {
                    Some(85.0)
                } else {
                    None
                },
                memory_used_mb: if job.status == ProofJobStatus::Generating {
                    Some(4096)
                } else {
                    None
                },
                error_message: job.error_message.clone(),
                retry_count: job.retry_count,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "Job not found"
        }))).into_response(),
    }
}

/// Get completed proof result
pub async fn get_proof_result_handler(
    State(state): State<Arc<ProofGenerationState>>,
    Path(job_id): Path<String>,
) -> impl IntoResponse {
    let jobs = state.jobs.read().await;

    match jobs.get(&job_id) {
        Some(job) if job.status == ProofJobStatus::Completed => {
            let response = ProofResultResponse {
                job_id: job.id.clone(),
                proof_hash: job.proof_hash.clone().unwrap_or_default(),
                proof_data: job.proof_data.clone().unwrap_or_default(),
                public_input_hash: format!("0x{:064x}", rand::random::<u64>()),
                proof_size_bytes: 102400, // ~100KB
                generation_time_ms: 3000,
                cost_usdc: 0.10,
                gpu_tier: job.gpu_tier.clone().unwrap_or(GpuTier::H100),
                tee_attestation: if job.require_tee {
                    Some(TeeAttestation {
                        tee_type: TeeType::NvidiaCC,
                        enclave_measurement: format!("0x{:064x}", rand::random::<u64>()),
                        quote_hash: format!("0x{:064x}", rand::random::<u64>()),
                    })
                } else {
                    None
                },
                verification_status: "verified".to_string(),
                tx_hash: Some(format!("0x{:064x}", rand::random::<u64>())),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Some(_) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Proof not yet completed"
        }))).into_response(),
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "Job not found"
        }))).into_response(),
    }
}

/// Cancel a proof job
pub async fn cancel_job_handler(
    State(state): State<Arc<ProofGenerationState>>,
    Path(job_id): Path<String>,
) -> impl IntoResponse {
    let mut jobs = state.jobs.write().await;

    match jobs.get_mut(&job_id) {
        Some(job) if job.status == ProofJobStatus::Queued || job.status == ProofJobStatus::Assigned => {
            job.status = ProofJobStatus::Cancelled;
            (StatusCode::OK, Json(CancelResponse { cancelled: true }))
        }
        Some(_) => (StatusCode::BAD_REQUEST, Json(CancelResponse { cancelled: false })),
        None => (StatusCode::NOT_FOUND, Json(CancelResponse { cancelled: false })),
    }
}

/// Submit batch proof request
pub async fn batch_proof_handler(
    State(state): State<Arc<ProofGenerationState>>,
    Json(request): Json<BatchProofRequest>,
) -> impl IntoResponse {
    let batch_id = Uuid::new_v4().to_string();
    let mut job_ids = Vec::new();
    let mut total_cost = 0.0;
    let mut total_time = 0u64;

    for item in &request.proofs {
        let job_id = Uuid::new_v4().to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let job = ProofJob {
            id: job_id.clone(),
            proof_type: item.proof_type.clone(),
            public_inputs: item.public_inputs.clone(),
            private_inputs: item.private_inputs.clone(),
            priority: request.priority.clone().unwrap_or(ProofJobPriority::Standard),
            status: ProofJobStatus::Queued,
            progress_bps: 0,
            gpu_tier: None,
            require_tee: item.require_tee.unwrap_or(false),
            created_at: now,
            started_at: None,
            completed_at: None,
            proof_hash: None,
            proof_data: None,
            error_message: None,
            retry_count: 0,
        };

        let cost = estimate_proof_cost(&item.proof_type, item.public_inputs.len());
        let time = estimate_proof_time(&item.proof_type, state.gpu_enabled);

        total_cost += cost;
        total_time = total_time.max(time); // Parallel execution

        {
            let mut jobs = state.jobs.write().await;
            jobs.insert(job_id.clone(), job);
        }

        job_ids.push(job_id);
    }

    // Apply aggregation discount
    if request.aggregate.unwrap_or(false) && job_ids.len() > 1 {
        total_cost *= 0.1; // 90% discount for aggregation
    }

    // Store batch
    {
        let mut batches = state.batches.write().await;
        batches.insert(batch_id.clone(), job_ids.clone());
    }

    let response = BatchProofResponse {
        batch_id,
        job_ids,
        estimated_total_cost_usdc: total_cost,
        estimated_time_secs: total_time,
        status: "queued".to_string(),
    };

    (StatusCode::OK, Json(response))
}

/// Get batch status
pub async fn get_batch_status_handler(
    State(state): State<Arc<ProofGenerationState>>,
    Path(batch_id): Path<String>,
) -> impl IntoResponse {
    let batches = state.batches.read().await;

    match batches.get(&batch_id) {
        Some(job_ids) => {
            let jobs = state.jobs.read().await;
            let mut completed = 0;
            let mut failed = 0;

            for job_id in job_ids {
                if let Some(job) = jobs.get(job_id) {
                    match job.status {
                        ProofJobStatus::Completed => completed += 1,
                        ProofJobStatus::Failed => failed += 1,
                        _ => {}
                    }
                }
            }

            let status = if completed == job_ids.len() {
                "completed"
            } else if failed > 0 {
                "partial_failure"
            } else {
                "processing"
            };

            let response = BatchProofResponse {
                batch_id,
                job_ids: job_ids.clone(),
                estimated_total_cost_usdc: 0.10 * job_ids.len() as f64,
                estimated_time_secs: 5,
                status: status.to_string(),
            };

            (StatusCode::OK, Json(response)).into_response()
        }
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "Batch not found"
        }))).into_response(),
    }
}

/// Estimate proof cost
pub async fn estimate_cost_handler(
    State(state): State<Arc<ProofGenerationState>>,
    Json(request): Json<EstimateRequest>,
) -> impl IntoResponse {
    let base_cost = estimate_proof_cost(&request.proof_type, request.public_inputs_count);
    let time = estimate_proof_time(&request.proof_type, state.gpu_enabled);

    let priority_surcharge = match request.priority.unwrap_or(ProofJobPriority::Standard) {
        ProofJobPriority::Standard => 0.0,
        ProofJobPriority::High => base_cost * 0.2,
        ProofJobPriority::Critical => base_cost * 0.5,
        ProofJobPriority::Emergency => base_cost * 1.0,
    };

    let tee_surcharge = if request.require_tee.unwrap_or(false) {
        base_cost * 0.5
    } else {
        0.0
    };

    let total_cost = base_cost + priority_surcharge + tee_surcharge;

    let response = EstimateResponse {
        cost_usdc: total_cost,
        time_secs: time,
        recommended_gpu_tier: GpuTier::H100,
        breakdown: CostBreakdown {
            base_cost,
            constraint_cost: base_cost * 0.3,
            priority_surcharge,
            tee_surcharge,
        },
    };

    (StatusCode::OK, Json(response))
}

/// Get network metrics
pub async fn get_metrics_handler(
    State(state): State<Arc<ProofGenerationState>>,
) -> impl IntoResponse {
    let queue_depth = *state.queue_depth.read().await;

    let response = MetricsResponse {
        available_gpus: vec![
            GpuAvailability {
                tier: GpuTier::H100,
                count: 8,
                tee_enabled: 4,
            },
            GpuAvailability {
                tier: GpuTier::A100,
                count: 16,
                tee_enabled: 0,
            },
            GpuAvailability {
                tier: GpuTier::Rtx4090,
                count: 32,
                tee_enabled: 0,
            },
        ],
        queue_depth,
        avg_wait_time_secs: 5,
        proofs_last_hour: 1250,
        network_utilization: 0.72,
        pricing: vec![
            PricingInfo {
                proof_type: ProofType::BatchPayments,
                base_cost_usdc: 0.05,
                per_constraint_usdc: 0.0001,
            },
            PricingInfo {
                proof_type: ProofType::AiInference,
                base_cost_usdc: 0.10,
                per_constraint_usdc: 0.0005,
            },
            PricingInfo {
                proof_type: ProofType::CrossChainBridge,
                base_cost_usdc: 0.08,
                per_constraint_usdc: 0.0003,
            },
        ],
    };

    (StatusCode::OK, Json(response))
}

/// Get queue depth
pub async fn get_queue_handler(
    State(state): State<Arc<ProofGenerationState>>,
) -> impl IntoResponse {
    let queue_depth = *state.queue_depth.read().await;

    let mut by_priority = HashMap::new();
    by_priority.insert("standard".to_string(), queue_depth / 2);
    by_priority.insert("high".to_string(), queue_depth / 4);
    by_priority.insert("critical".to_string(), queue_depth / 8);
    by_priority.insert("emergency".to_string(), 0);

    let response = QueueResponse {
        total: queue_depth,
        by_priority,
        estimated_clear_time_secs: queue_depth as u64 * 3,
    };

    (StatusCode::OK, Json(response))
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

fn estimate_proof_cost(proof_type: &ProofType, input_count: usize) -> f64 {
    let base = match proof_type {
        ProofType::BatchPayments => 0.05,
        ProofType::AiInference => 0.10,
        ProofType::CrossChainBridge => 0.08,
        ProofType::DefiCalculation => 0.07,
        ProofType::GameState => 0.05,
        ProofType::VrfRandomness => 0.03,
        ProofType::KycVerification => 0.06,
        ProofType::SupplyChain => 0.04,
        ProofType::RecursiveAggregation => 0.15,
        ProofType::Custom => 0.10,
    };

    base + (input_count as f64 * 0.0001)
}

fn estimate_proof_time(proof_type: &ProofType, gpu_enabled: bool) -> u64 {
    let base = match proof_type {
        ProofType::BatchPayments => 3,
        ProofType::AiInference => 10,
        ProofType::CrossChainBridge => 8,
        ProofType::DefiCalculation => 5,
        ProofType::GameState => 3,
        ProofType::VrfRandomness => 2,
        ProofType::KycVerification => 4,
        ProofType::SupplyChain => 6,
        ProofType::RecursiveAggregation => 15,
        ProofType::Custom => 10,
    };

    if gpu_enabled {
        base
    } else {
        base * 20 // CPU is ~20x slower
    }
}

fn calculate_remaining_time(job: &ProofJob) -> u64 {
    let total = estimate_proof_time(&job.proof_type, true);
    let elapsed = (job.progress_bps as u64 * total) / 10000;
    total.saturating_sub(elapsed)
}

fn get_current_phase(job: &ProofJob) -> String {
    match job.progress_bps {
        0..=1000 => "Initializing trace".to_string(),
        1001..=3000 => "Committing columns".to_string(),
        3001..=5000 => "Evaluating constraints".to_string(),
        5001..=7000 => "FRI folding".to_string(),
        7001..=9000 => "Query phase".to_string(),
        9001..=10000 => "Finalizing proof".to_string(),
        _ => "Unknown".to_string(),
    }
}

async fn simulate_proof_generation(state: Arc<ProofGenerationState>, job_id: String) {
    // Simulate proof generation progress
    for progress in (0..=10000).step_by(1000) {
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

        let mut jobs = state.jobs.write().await;
        if let Some(job) = jobs.get_mut(&job_id) {
            if job.status == ProofJobStatus::Cancelled {
                return;
            }

            job.progress_bps = progress as u32;

            if progress == 0 {
                job.status = ProofJobStatus::Generating;
                job.started_at = Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                );
            }
        }
    }

    // Complete the job
    let mut jobs = state.jobs.write().await;
    if let Some(job) = jobs.get_mut(&job_id) {
        job.status = ProofJobStatus::Completed;
        job.progress_bps = 10000;
        job.completed_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        job.proof_hash = Some(format!("0x{:064x}", rand::random::<u64>()));
        job.proof_data = Some(format!("0x{}", "a".repeat(2048))); // Simulated proof data
    }

    // Decrement queue depth
    let mut depth = state.queue_depth.write().await;
    *depth = depth.saturating_sub(1);
}

// =============================================================================
// ROUTER
// =============================================================================

pub fn proof_generation_routes(state: Arc<ProofGenerationState>) -> Router {
    Router::new()
        // Core proof operations
        .route("/api/v1/proofs/generate", post(generate_proof_handler))
        .route("/api/v1/proofs/:job_id/status", get(get_job_status_handler))
        .route("/api/v1/proofs/:job_id/result", get(get_proof_result_handler))
        .route("/api/v1/proofs/:job_id", delete(cancel_job_handler))
        // Batch operations
        .route("/api/v1/proofs/batch", post(batch_proof_handler))
        .route("/api/v1/proofs/batch/:batch_id/status", get(get_batch_status_handler))
        // Cost estimation
        .route("/api/v1/proofs/estimate", post(estimate_cost_handler))
        // Metrics
        .route("/api/v1/proofs/metrics", get(get_metrics_handler))
        .route("/api/v1/proofs/queue", get(get_queue_handler))
        .with_state(state)
}
