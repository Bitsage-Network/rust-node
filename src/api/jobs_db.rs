//! # Jobs Database API
//!
//! Database-backed REST API endpoints for job management.
//! Provides historical data, analytics, and timeline queries from PostgreSQL.

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
pub struct JobsDbState {
    pub pool: Arc<PgPool>,
}

impl JobsDbState {
    /// Create a new JobsDbState with the given database pool
    pub fn new(pool: PgPool) -> Self {
        Self { pool: Arc::new(pool) }
    }
}

/// Query parameters for listing jobs
#[derive(Debug, Deserialize)]
pub struct ListJobsQuery {
    pub status: Option<String>,
    pub client: Option<String>,
    pub worker: Option<String>,
    pub job_type: Option<String>,
    pub page: Option<i64>,
    pub limit: Option<i64>,
    pub sort_by: Option<String>,  // created_at, completed_at, execution_time_ms
    pub sort_order: Option<String>,  // asc, desc
}

/// Job response from database
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct JobResponse {
    pub id: String,
    pub job_id: String,
    pub client_address: String,
    pub worker_address: Option<String>,
    pub job_type: String,
    pub status: String,
    pub priority: i32,
    pub payment_amount: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub assigned_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub execution_time_ms: Option<i64>,
    pub result_hash: Option<String>,
    pub error_message: Option<String>,
}

/// Paginated jobs response
#[derive(Debug, Serialize)]
pub struct JobsListResponse {
    pub jobs: Vec<JobResponse>,
    pub total: i64,
    pub page: i64,
    pub limit: i64,
    pub total_pages: i64,
}

/// Job detail response with timeline
#[derive(Debug, Serialize)]
pub struct JobDetailResponse {
    pub job: JobResponse,
    pub timeline: Vec<JobTimelineEvent>,
    pub proof: Option<ProofInfo>,
}

/// Timeline event
#[derive(Debug, Serialize)]
pub struct JobTimelineEvent {
    pub event_type: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub details: serde_json::Value,
    pub tx_hash: Option<String>,
}

/// Proof info for a job
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ProofInfo {
    pub proof_hash: String,
    pub proof_type: Option<String>,
    pub is_valid: Option<bool>,
    pub verification_time_ms: Option<i32>,
    pub verified_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Job analytics response
#[derive(Debug, Serialize)]
pub struct JobAnalyticsResponse {
    pub total_jobs: i64,
    pub completed_jobs: i64,
    pub failed_jobs: i64,
    pub pending_jobs: i64,
    pub avg_execution_time_ms: Option<f64>,
    pub total_payment_amount: String,
    pub jobs_last_24h: i64,
    pub jobs_last_7d: i64,
    pub completion_rate: f64,
    pub by_status: Vec<StatusCount>,
    pub by_type: Vec<TypeCount>,
    pub hourly_distribution: Vec<HourlyCount>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct StatusCount {
    pub status: String,
    pub count: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct TypeCount {
    pub job_type: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct HourlyCount {
    pub hour: i32,
    pub count: i64,
}

/// Recent jobs response
#[derive(Debug, Serialize)]
pub struct RecentJobsResponse {
    pub jobs: Vec<JobResponse>,
}

/// Create jobs database router
pub fn jobs_db_routes(state: JobsDbState) -> Router {
    Router::new()
        .route("/api/jobs/db", get(list_jobs_db))
        .route("/api/jobs/db/:job_id", get(get_job_detail))
        .route("/api/jobs/db/:job_id/timeline", get(get_job_timeline))
        .route("/api/jobs/db/analytics", get(get_job_analytics))
        .route("/api/jobs/db/recent", get(get_recent_jobs))
        .route("/api/jobs/db/by-client/:address", get(get_jobs_by_client))
        .route("/api/jobs/db/by-worker/:address", get(get_jobs_by_worker))
        .with_state(state)
}

/// List jobs from database with filtering and pagination
async fn list_jobs_db(
    State(state): State<JobsDbState>,
    Query(params): Query<ListJobsQuery>,
) -> Result<Json<JobsListResponse>, (StatusCode, String)> {
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(20).min(100);
    let offset = (page - 1) * limit;
    
    // Whitelist sort_by to prevent SQL injection via ORDER BY
    let sort_by = match params.sort_by.as_deref() {
        Some("created_at") => "created_at",
        Some("completed_at") => "completed_at",
        Some("priority") => "priority",
        Some("status") => "status",
        _ => "created_at",
    };
    let sort_order = match params.sort_order.as_deref() {
        Some("asc") | Some("ASC") => "ASC",
        _ => "DESC",
    };

    // Get total count (parameterized)
    let total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM jobs
        WHERE ($1::text IS NULL OR status = $1)
          AND ($2::text IS NULL OR client_address = $2)
          AND ($3::text IS NULL OR worker_address = $3)
          AND ($4::text IS NULL OR job_type = $4)
        "#
    )
    .bind(&params.status)
    .bind(&params.client)
    .bind(&params.worker)
    .bind(&params.job_type)
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database query failed: {}", e)))?;

    // Get jobs (sort_by and sort_order are whitelisted, safe to interpolate)
    let jobs_query = format!(
        r#"
        SELECT
            id::text, job_id, client_address, worker_address, job_type, status,
            priority, payment_amount::text as payment_amount, created_at,
            assigned_at, completed_at, execution_time_ms, result_hash, error_message
        FROM jobs
        WHERE ($1::text IS NULL OR status = $1)
          AND ($2::text IS NULL OR client_address = $2)
          AND ($3::text IS NULL OR worker_address = $3)
          AND ($4::text IS NULL OR job_type = $4)
        ORDER BY {} {}
        LIMIT $5 OFFSET $6
        "#,
        sort_by, sort_order
    );

    let jobs: Vec<JobResponse> = sqlx::query_as(&jobs_query)
        .bind(&params.status)
        .bind(&params.client)
        .bind(&params.worker)
        .bind(&params.job_type)
        .bind(limit)
        .bind(offset)
        .fetch_all(state.pool.as_ref())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database query failed: {}", e)))?;
    
    let total_pages = (total + limit - 1) / limit;
    
    Ok(Json(JobsListResponse {
        jobs,
        total,
        page,
        limit,
        total_pages,
    }))
}

/// Get job detail with timeline and proof
async fn get_job_detail(
    State(state): State<JobsDbState>,
    Path(job_id): Path<String>,
) -> Result<Json<JobDetailResponse>, (StatusCode, String)> {
    // Get job
    let job: JobResponse = sqlx::query_as(
        r#"
        SELECT 
            id::text, job_id, client_address, worker_address, job_type, status,
            priority, payment_amount::text as payment_amount, created_at, 
            assigned_at, completed_at, execution_time_ms, result_hash, error_message
        FROM jobs 
        WHERE job_id = $1
        "#
    )
    .bind(&job_id)
    .fetch_optional(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::NOT_FOUND, "Job not found".to_string()))?;
    
    // Get timeline from blockchain_events
    let timeline = get_timeline_for_job(state.pool.as_ref(), &job_id).await?;
    
    // Get proof if exists
    let proof: Option<ProofInfo> = sqlx::query_as(
        r#"
        SELECT proof_hash, proof_type, is_valid, verification_time_ms, verified_at
        FROM proofs
        WHERE job_id = $1
        ORDER BY verified_at DESC
        LIMIT 1
        "#
    )
    .bind(&job_id)
    .fetch_optional(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    Ok(Json(JobDetailResponse {
        job,
        timeline,
        proof,
    }))
}

/// Get job timeline
async fn get_job_timeline(
    State(state): State<JobsDbState>,
    Path(job_id): Path<String>,
) -> Result<Json<Vec<JobTimelineEvent>>, (StatusCode, String)> {
    let timeline = get_timeline_for_job(state.pool.as_ref(), &job_id).await?;
    Ok(Json(timeline))
}

/// Helper to get timeline events for a job
async fn get_timeline_for_job(
    pool: &PgPool,
    job_id: &str,
) -> Result<Vec<JobTimelineEvent>, (StatusCode, String)> {
    let events: Vec<(String, chrono::DateTime<chrono::Utc>, serde_json::Value, Option<String>)> = sqlx::query_as(
        r#"
        SELECT event_name, created_at, event_data, tx_hash
        FROM blockchain_events
        WHERE event_data->>'job_id' = $1
        ORDER BY block_number ASC, created_at ASC
        "#
    )
    .bind(job_id)
    .fetch_all(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let timeline: Vec<JobTimelineEvent> = events
        .into_iter()
        .map(|(event_type, timestamp, details, tx_hash)| {
            JobTimelineEvent {
                event_type,
                timestamp,
                details,
                tx_hash,
            }
        })
        .collect();
    
    Ok(timeline)
}

/// Get job analytics
async fn get_job_analytics(
    State(state): State<JobsDbState>,
) -> Result<Json<JobAnalyticsResponse>, (StatusCode, String)> {
    // Total counts
    let total_jobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs")
        .fetch_one(state.pool.as_ref())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let completed_jobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE status = 'completed'")
        .fetch_one(state.pool.as_ref())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let failed_jobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE status = 'failed'")
        .fetch_one(state.pool.as_ref())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let pending_jobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE status = 'pending'")
        .fetch_one(state.pool.as_ref())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Average execution time
    let avg_execution_time_ms: Option<f64> = sqlx::query_scalar(
        "SELECT AVG(execution_time_ms) FROM jobs WHERE status = 'completed'"
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Total payment
    let total_payment: Option<String> = sqlx::query_scalar(
        "SELECT COALESCE(SUM(payment_amount), 0)::text FROM jobs WHERE status = 'completed'"
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Jobs in last 24h and 7d
    let jobs_last_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM jobs WHERE created_at > NOW() - INTERVAL '24 hours'"
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let jobs_last_7d: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM jobs WHERE created_at > NOW() - INTERVAL '7 days'"
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // By status
    let by_status: Vec<StatusCount> = sqlx::query_as(
        "SELECT status, COUNT(*) as count FROM jobs GROUP BY status ORDER BY count DESC"
    )
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // By type
    let by_type: Vec<TypeCount> = sqlx::query_as(
        "SELECT job_type, COUNT(*) as count FROM jobs GROUP BY job_type ORDER BY count DESC"
    )
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Hourly distribution (last 24h)
    let hourly_rows: Vec<(i32, i64)> = sqlx::query_as(
        r#"
        SELECT EXTRACT(HOUR FROM created_at)::int as hour, COUNT(*) as count
        FROM jobs
        WHERE created_at > NOW() - INTERVAL '24 hours'
        GROUP BY hour
        ORDER BY hour
        "#
    )
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let hourly_distribution: Vec<HourlyCount> = hourly_rows
        .into_iter()
        .map(|(hour, count)| HourlyCount { hour, count })
        .collect();
    
    let completion_rate = if total_jobs > 0 {
        completed_jobs as f64 / total_jobs as f64 * 100.0
    } else {
        0.0
    };
    
    Ok(Json(JobAnalyticsResponse {
        total_jobs,
        completed_jobs,
        failed_jobs,
        pending_jobs,
        avg_execution_time_ms,
        total_payment_amount: total_payment.unwrap_or_else(|| "0".to_string()),
        jobs_last_24h,
        jobs_last_7d,
        completion_rate,
        by_status,
        by_type,
        hourly_distribution,
    }))
}

/// Get recent jobs
async fn get_recent_jobs(
    State(state): State<JobsDbState>,
    Query(params): Query<ListJobsQuery>,
) -> Result<Json<RecentJobsResponse>, (StatusCode, String)> {
    let limit = params.limit.unwrap_or(5).min(20);
    
    let jobs: Vec<JobResponse> = sqlx::query_as(
        r#"
        SELECT 
            id::text, job_id, client_address, worker_address, job_type, status,
            priority, payment_amount::text as payment_amount, created_at, 
            assigned_at, completed_at, execution_time_ms, result_hash, error_message
        FROM jobs 
        ORDER BY created_at DESC
        LIMIT $1
        "#
    )
    .bind(limit)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    Ok(Json(RecentJobsResponse { jobs }))
}

/// Get jobs by client address
async fn get_jobs_by_client(
    State(state): State<JobsDbState>,
    Path(address): Path<String>,
    Query(params): Query<ListJobsQuery>,
) -> Result<Json<JobsListResponse>, (StatusCode, String)> {
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(20).min(100);
    let offset = (page - 1) * limit;
    
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM jobs WHERE client_address = $1"
    )
    .bind(&address)
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let jobs: Vec<JobResponse> = sqlx::query_as(
        r#"
        SELECT 
            id::text, job_id, client_address, worker_address, job_type, status,
            priority, payment_amount::text as payment_amount, created_at, 
            assigned_at, completed_at, execution_time_ms, result_hash, error_message
        FROM jobs 
        WHERE client_address = $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
        "#
    )
    .bind(&address)
    .bind(limit)
    .bind(offset)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let total_pages = (total + limit - 1) / limit;
    
    Ok(Json(JobsListResponse {
        jobs,
        total,
        page,
        limit,
        total_pages,
    }))
}

/// Get jobs by worker address
async fn get_jobs_by_worker(
    State(state): State<JobsDbState>,
    Path(address): Path<String>,
    Query(params): Query<ListJobsQuery>,
) -> Result<Json<JobsListResponse>, (StatusCode, String)> {
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(20).min(100);
    let offset = (page - 1) * limit;
    
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM jobs WHERE worker_address = $1"
    )
    .bind(&address)
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let jobs: Vec<JobResponse> = sqlx::query_as(
        r#"
        SELECT 
            id::text, job_id, client_address, worker_address, job_type, status,
            priority, payment_amount::text as payment_amount, created_at, 
            assigned_at, completed_at, execution_time_ms, result_hash, error_message
        FROM jobs 
        WHERE worker_address = $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
        "#
    )
    .bind(&address)
    .bind(limit)
    .bind(offset)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let total_pages = (total + limit - 1) / limit;
    
    Ok(Json(JobsListResponse {
        jobs,
        total,
        page,
        limit,
        total_pages,
    }))
}
