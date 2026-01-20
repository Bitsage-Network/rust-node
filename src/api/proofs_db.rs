//! # Proofs Database API
//!
//! Database-backed REST API endpoints for proof management.
//! Provides proof history, verification stats, and STWO metadata.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    Router, routing::get,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;

/// API State with database pool
#[derive(Clone)]
pub struct ProofsDbState {
    pub pool: Arc<PgPool>,
}

impl ProofsDbState {
    /// Create a new ProofsDbState with the given database pool
    pub fn new(pool: PgPool) -> Self {
        Self { pool: Arc::new(pool) }
    }
}

/// Query parameters for listing proofs
#[derive(Debug, Deserialize)]
pub struct ListProofsQuery {
    pub worker: Option<String>,
    pub job_id: Option<String>,
    pub is_valid: Option<bool>,
    pub proof_type: Option<String>,
    pub page: Option<i64>,
    pub limit: Option<i64>,
}

/// Proof response from database
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ProofResponse {
    pub id: String,
    pub job_id: String,
    pub worker_id: String,
    pub proof_hash: String,
    pub proof_type: Option<String>,
    pub circuit_type: Option<String>,
    pub proof_size_bytes: Option<i32>,
    pub generation_time_ms: Option<i32>,
    pub security_bits: Option<i32>,
    pub is_valid: Option<bool>,
    pub verification_time_ms: Option<i32>,
    pub verified_at: Option<chrono::DateTime<chrono::Utc>>,
    pub verifier_address: Option<String>,
    pub tx_hash: Option<String>,
    pub block_number: Option<i64>,
}

/// Paginated proofs response
#[derive(Debug, Serialize)]
pub struct ProofsListResponse {
    pub proofs: Vec<ProofResponse>,
    pub total: i64,
    pub page: i64,
    pub limit: i64,
    pub total_pages: i64,
}

/// Proof detail with job info
#[derive(Debug, Serialize)]
pub struct ProofDetailResponse {
    pub proof: ProofResponse,
    pub job: Option<JobSummary>,
    pub worker: Option<WorkerSummary>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct JobSummary {
    pub job_id: String,
    pub job_type: String,
    pub status: String,
    pub client_address: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct WorkerSummary {
    pub worker_id: String,
    pub address: String,
    pub reputation_score: i32,
    pub jobs_completed: i64,
}

/// Proof statistics response
#[derive(Debug, Serialize)]
pub struct ProofStatsResponse {
    pub total_proofs: i64,
    // Field aliases for frontend compatibility
    #[serde(alias = "valid_proofs")]
    pub verified_proofs: i64,
    #[serde(alias = "invalid_proofs")]
    pub failed_proofs: i64,
    #[serde(alias = "pending_verification")]
    pub pending_proofs: i64,
    pub verification_rate: f64,
    pub avg_verification_time_ms: Option<f64>,
    pub avg_proof_size_bytes: Option<f64>,
    pub avg_generation_time_ms: Option<f64>,
    pub proofs_last_24h: i64,
    pub proofs_last_7d: i64,
    pub by_type: Vec<ProofTypeStats>,
    pub by_circuit: Vec<CircuitStats>,
    pub verification_trend: Vec<DailyVerification>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ProofTypeStats {
    pub proof_type: Option<String>,
    pub count: i64,
    pub avg_verification_time_ms: Option<f64>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct CircuitStats {
    pub circuit_type: Option<String>,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct DailyVerification {
    pub date: chrono::NaiveDate,
    pub total: i64,
    pub valid: i64,
    pub invalid: i64,
}

/// Worker proof history
#[derive(Debug, Serialize)]
pub struct WorkerProofHistory {
    pub worker_id: String,
    pub total_proofs: i64,
    pub valid_proofs: i64,
    pub success_rate: f64,
    pub avg_generation_time_ms: Option<f64>,
    pub proofs: Vec<ProofResponse>,
}

/// Create proofs database router
pub fn proofs_db_routes(state: ProofsDbState) -> Router {
    Router::new()
        .route("/api/proofs", get(list_proofs))
        .route("/api/proofs/:id", get(get_proof_detail))
        .route("/api/proofs/stats", get(get_proof_stats))
        .route("/api/proofs/by-job/:job_id", get(get_proofs_by_job))
        .route("/api/proofs/by-worker/:worker_id", get(get_worker_proof_history))
        .route("/api/proofs/recent", get(get_recent_proofs))
        .route("/api/proofs/pending", get(get_pending_proofs))
        .with_state(state)
}

/// List proofs from database
async fn list_proofs(
    State(state): State<ProofsDbState>,
    Query(params): Query<ListProofsQuery>,
) -> Result<Json<ProofsListResponse>, (StatusCode, String)> {
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(20).min(100);
    let offset = (page - 1) * limit;
    
    // Build conditions
    let mut conditions = vec!["1=1".to_string()];
    
    if let Some(ref worker) = params.worker {
        conditions.push(format!("worker_id = '{}'", worker));
    }
    if let Some(ref job_id) = params.job_id {
        conditions.push(format!("job_id = '{}'", job_id));
    }
    if let Some(is_valid) = params.is_valid {
        conditions.push(format!("is_valid = {}", is_valid));
    }
    if let Some(ref proof_type) = params.proof_type {
        conditions.push(format!("proof_type = '{}'", proof_type));
    }
    
    let where_clause = conditions.join(" AND ");
    
    // Get total
    let count_query = format!(
        "SELECT COUNT(*) FROM proofs WHERE {}",
        where_clause
    );
    
    let total: i64 = sqlx::query_scalar(&count_query)
        .fetch_one(state.pool.as_ref())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Get proofs
    let proofs_query = format!(
        r#"
        SELECT 
            id::text, job_id, worker_id, proof_hash, proof_type, circuit_type,
            proof_size_bytes, generation_time_ms, security_bits, is_valid,
            verification_time_ms, verified_at, verifier_address, tx_hash, block_number
        FROM proofs 
        WHERE {}
        ORDER BY verified_at DESC NULLS LAST
        LIMIT {} OFFSET {}
        "#,
        where_clause, limit, offset
    );
    
    let proofs: Vec<ProofResponse> = sqlx::query_as(&proofs_query)
        .fetch_all(state.pool.as_ref())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let total_pages = (total + limit - 1) / limit;
    
    Ok(Json(ProofsListResponse {
        proofs,
        total,
        page,
        limit,
        total_pages,
    }))
}

/// Get proof detail with related info
async fn get_proof_detail(
    State(state): State<ProofsDbState>,
    Path(id): Path<String>,
) -> Result<Json<ProofDetailResponse>, (StatusCode, String)> {
    // Get proof
    let proof: ProofResponse = sqlx::query_as(
        r#"
        SELECT 
            id::text, job_id, worker_id, proof_hash, proof_type, circuit_type,
            proof_size_bytes, generation_time_ms, security_bits, is_valid,
            verification_time_ms, verified_at, verifier_address, tx_hash, block_number
        FROM proofs 
        WHERE id::text = $1 OR proof_hash = $1
        "#
    )
    .bind(&id)
    .fetch_optional(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::NOT_FOUND, "Proof not found".to_string()))?;
    
    // Get job summary
    let job: Option<JobSummary> = sqlx::query_as(
        "SELECT job_id, job_type, status, client_address FROM jobs WHERE job_id = $1"
    )
    .bind(&proof.job_id)
    .fetch_optional(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Get worker summary
    let worker: Option<WorkerSummary> = sqlx::query_as(
        "SELECT worker_id, address, reputation_score, jobs_completed FROM workers WHERE worker_id = $1 OR address = $1"
    )
    .bind(&proof.worker_id)
    .fetch_optional(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    Ok(Json(ProofDetailResponse {
        proof,
        job,
        worker,
    }))
}

/// Get proof statistics
async fn get_proof_stats(
    State(state): State<ProofsDbState>,
) -> Result<Json<ProofStatsResponse>, (StatusCode, String)> {
    // Counts
    let total_proofs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM proofs")
        .fetch_one(state.pool.as_ref())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let valid_proofs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM proofs WHERE is_valid = true")
        .fetch_one(state.pool.as_ref())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let invalid_proofs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM proofs WHERE is_valid = false")
        .fetch_one(state.pool.as_ref())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let pending_verification: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM proofs WHERE is_valid IS NULL")
        .fetch_one(state.pool.as_ref())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Averages
    let avg_verification_time_ms: Option<f64> = sqlx::query_scalar(
        "SELECT AVG(verification_time_ms) FROM proofs WHERE verification_time_ms IS NOT NULL"
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let avg_proof_size_bytes: Option<f64> = sqlx::query_scalar(
        "SELECT AVG(proof_size_bytes) FROM proofs WHERE proof_size_bytes IS NOT NULL"
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let avg_generation_time_ms: Option<f64> = sqlx::query_scalar(
        "SELECT AVG(generation_time_ms) FROM proofs WHERE generation_time_ms IS NOT NULL"
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Recent counts
    let proofs_last_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM proofs WHERE verified_at > NOW() - INTERVAL '24 hours'"
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let proofs_last_7d: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM proofs WHERE verified_at > NOW() - INTERVAL '7 days'"
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // By type
    let by_type: Vec<ProofTypeStats> = sqlx::query_as(
        r#"
        SELECT proof_type, COUNT(*) as count, AVG(verification_time_ms) as avg_verification_time_ms
        FROM proofs
        GROUP BY proof_type
        ORDER BY count DESC
        "#
    )
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // By circuit
    let by_circuit: Vec<CircuitStats> = sqlx::query_as(
        "SELECT circuit_type, COUNT(*) as count FROM proofs GROUP BY circuit_type ORDER BY count DESC"
    )
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Verification trend (last 7 days)
    let trend_rows: Vec<(chrono::NaiveDate, i64, i64, i64)> = sqlx::query_as(
        r#"
        SELECT 
            DATE(verified_at) as date,
            COUNT(*) as total,
            COUNT(*) FILTER (WHERE is_valid = true) as valid,
            COUNT(*) FILTER (WHERE is_valid = false) as invalid
        FROM proofs
        WHERE verified_at > NOW() - INTERVAL '7 days'
        GROUP BY DATE(verified_at)
        ORDER BY date
        "#
    )
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let verification_trend: Vec<DailyVerification> = trend_rows
        .into_iter()
        .map(|(date, total, valid, invalid)| DailyVerification { date, total, valid, invalid })
        .collect();
    
    let verification_rate = if total_proofs > 0 {
        valid_proofs as f64 / total_proofs as f64 * 100.0
    } else {
        0.0
    };

    Ok(Json(ProofStatsResponse {
        total_proofs,
        verified_proofs: valid_proofs,
        failed_proofs: invalid_proofs,
        pending_proofs: pending_verification,
        verification_rate,
        avg_verification_time_ms,
        avg_proof_size_bytes,
        avg_generation_time_ms,
        proofs_last_24h,
        proofs_last_7d,
        by_type,
        by_circuit,
        verification_trend,
    }))
}

/// Get proofs for a specific job
async fn get_proofs_by_job(
    State(state): State<ProofsDbState>,
    Path(job_id): Path<String>,
) -> Result<Json<Vec<ProofResponse>>, (StatusCode, String)> {
    let proofs: Vec<ProofResponse> = sqlx::query_as(
        r#"
        SELECT 
            id::text, job_id, worker_id, proof_hash, proof_type, circuit_type,
            proof_size_bytes, generation_time_ms, security_bits, is_valid,
            verification_time_ms, verified_at, verifier_address, tx_hash, block_number
        FROM proofs 
        WHERE job_id = $1
        ORDER BY verified_at DESC NULLS LAST
        "#
    )
    .bind(&job_id)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    Ok(Json(proofs))
}

/// Get worker proof history
async fn get_worker_proof_history(
    State(state): State<ProofsDbState>,
    Path(worker_id): Path<String>,
    Query(params): Query<ListProofsQuery>,
) -> Result<Json<WorkerProofHistory>, (StatusCode, String)> {
    let limit = params.limit.unwrap_or(20).min(100);
    
    // Get counts
    let total_proofs: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM proofs WHERE worker_id = $1"
    )
    .bind(&worker_id)
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let valid_proofs: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM proofs WHERE worker_id = $1 AND is_valid = true"
    )
    .bind(&worker_id)
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let avg_generation_time_ms: Option<f64> = sqlx::query_scalar(
        "SELECT AVG(generation_time_ms) FROM proofs WHERE worker_id = $1"
    )
    .bind(&worker_id)
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Get recent proofs
    let proofs: Vec<ProofResponse> = sqlx::query_as(
        r#"
        SELECT 
            id::text, job_id, worker_id, proof_hash, proof_type, circuit_type,
            proof_size_bytes, generation_time_ms, security_bits, is_valid,
            verification_time_ms, verified_at, verifier_address, tx_hash, block_number
        FROM proofs 
        WHERE worker_id = $1
        ORDER BY verified_at DESC NULLS LAST
        LIMIT $2
        "#
    )
    .bind(&worker_id)
    .bind(limit)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let success_rate = if total_proofs > 0 {
        valid_proofs as f64 / total_proofs as f64 * 100.0
    } else {
        0.0
    };
    
    Ok(Json(WorkerProofHistory {
        worker_id,
        total_proofs,
        valid_proofs,
        success_rate,
        avg_generation_time_ms,
        proofs,
    }))
}

/// Get recent proofs
async fn get_recent_proofs(
    State(state): State<ProofsDbState>,
    Query(params): Query<ListProofsQuery>,
) -> Result<Json<Vec<ProofResponse>>, (StatusCode, String)> {
    let limit = params.limit.unwrap_or(10).min(50);
    
    let proofs: Vec<ProofResponse> = sqlx::query_as(
        r#"
        SELECT 
            id::text, job_id, worker_id, proof_hash, proof_type, circuit_type,
            proof_size_bytes, generation_time_ms, security_bits, is_valid,
            verification_time_ms, verified_at, verifier_address, tx_hash, block_number
        FROM proofs 
        ORDER BY verified_at DESC NULLS LAST
        LIMIT $1
        "#
    )
    .bind(limit)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    Ok(Json(proofs))
}

/// Get pending proofs awaiting verification
async fn get_pending_proofs(
    State(state): State<ProofsDbState>,
    Query(params): Query<ListProofsQuery>,
) -> Result<Json<Vec<ProofResponse>>, (StatusCode, String)> {
    let limit = params.limit.unwrap_or(20).min(100);
    
    let proofs: Vec<ProofResponse> = sqlx::query_as(
        r#"
        SELECT 
            id::text, job_id, worker_id, proof_hash, proof_type, circuit_type,
            proof_size_bytes, generation_time_ms, security_bits, is_valid,
            verification_time_ms, verified_at, verifier_address, tx_hash, block_number
        FROM proofs 
        WHERE is_valid IS NULL
        ORDER BY block_number ASC
        LIMIT $1
        "#
    )
    .bind(limit)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    Ok(Json(proofs))
}
