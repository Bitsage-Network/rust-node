//! # Dashboard Database API
//!
//! Database-backed REST API endpoints for dashboard statistics.
//! Aggregates data from jobs, workers, and payments tables.

use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    Router, routing::get,
};
use serde::Serialize;
use sqlx::{PgPool, Row};
use std::sync::Arc;
use tracing::{info, error};

/// API State with database pool
#[derive(Clone)]
pub struct DashboardDbState {
    pub pool: Arc<PgPool>,
}

impl DashboardDbState {
    /// Create a new DashboardDbState with the given database pool
    pub fn new(pool: PgPool) -> Self {
        Self { pool: Arc::new(pool) }
    }
}

/// Dashboard stats response
#[derive(Debug, Serialize)]
pub struct DashboardStats {
    pub total_jobs: i64,
    pub completed_jobs: i64,
    pub active_jobs: i64,
    pub failed_jobs: i64,
    pub total_workers: i64,
    pub active_workers: i64,
    pub total_earnings: String,
    pub earnings_24h: String,
    pub avg_job_time_ms: i64,
    pub success_rate: f64,
    pub jobs_24h: i64,
    pub total_staked: String,
}

/// Recent activity item
#[derive(Debug, Serialize)]
pub struct RecentActivityItem {
    pub activity_type: String,
    pub description: String,
    pub amount: Option<String>,
    pub timestamp: i64,
    pub tx_hash: Option<String>,
}

/// Create dashboard database routes
pub fn dashboard_db_routes(state: DashboardDbState) -> Router {
    Router::new()
        .route("/api/dashboard/stats", get(get_dashboard_stats))
        .route("/api/dashboard/activity", get(get_recent_activity))
        .with_state(state)
}

/// Get aggregated dashboard statistics
async fn get_dashboard_stats(
    State(state): State<DashboardDbState>,
) -> Result<Json<DashboardStats>, (StatusCode, String)> {
    info!("Fetching dashboard stats from database");

    // Query job counts
    let job_counts = sqlx::query(
        r#"
        SELECT
            COUNT(*) as total_jobs,
            COUNT(*) FILTER (WHERE status = 'completed') as completed_jobs,
            COUNT(*) FILTER (WHERE status IN ('pending', 'assigned', 'running')) as active_jobs,
            COUNT(*) FILTER (WHERE status = 'failed') as failed_jobs,
            COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') as jobs_24h,
            COALESCE(AVG(execution_time_ms) FILTER (WHERE execution_time_ms IS NOT NULL), 0)::bigint as avg_job_time_ms
        FROM jobs
        "#
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| {
        error!("Failed to query job counts: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
    })?;

    // Query worker counts
    let worker_counts = sqlx::query(
        r#"
        SELECT
            COUNT(*) as total_workers,
            COUNT(*) FILTER (WHERE status = 'active') as active_workers,
            COALESCE(SUM(staked_amount::numeric), 0)::text as total_staked
        FROM workers
        "#
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| {
        error!("Failed to query worker counts: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
    })?;

    // Query earnings
    let earnings = sqlx::query(
        r#"
        SELECT
            COALESCE(SUM(amount::numeric), 0)::text as total_earnings,
            COALESCE(SUM(amount::numeric) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours'), 0)::text as earnings_24h
        FROM payments
        "#
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| {
        error!("Failed to query earnings: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
    })?;

    let total_jobs: i64 = job_counts.try_get("total_jobs").unwrap_or(0);
    let completed_jobs: i64 = job_counts.try_get("completed_jobs").unwrap_or(0);
    let success_rate = if total_jobs > 0 {
        (completed_jobs as f64 / total_jobs as f64) * 100.0
    } else {
        0.0
    };

    Ok(Json(DashboardStats {
        total_jobs,
        completed_jobs,
        active_jobs: job_counts.try_get("active_jobs").unwrap_or(0),
        failed_jobs: job_counts.try_get("failed_jobs").unwrap_or(0),
        total_workers: worker_counts.try_get("total_workers").unwrap_or(0),
        active_workers: worker_counts.try_get("active_workers").unwrap_or(0),
        total_earnings: earnings.try_get("total_earnings").unwrap_or_else(|_| "0".to_string()),
        earnings_24h: earnings.try_get("earnings_24h").unwrap_or_else(|_| "0".to_string()),
        avg_job_time_ms: job_counts.try_get("avg_job_time_ms").unwrap_or(0),
        success_rate,
        jobs_24h: job_counts.try_get("jobs_24h").unwrap_or(0),
        total_staked: worker_counts.try_get("total_staked").unwrap_or_else(|_| "0".to_string()),
    }))
}

/// Get recent activity across all tables
async fn get_recent_activity(
    State(state): State<DashboardDbState>,
) -> Result<Json<Vec<RecentActivityItem>>, (StatusCode, String)> {
    info!("Fetching recent activity from database");

    let activities = sqlx::query(
        r#"
        (
            SELECT
                'job' as activity_type,
                CASE
                    WHEN status = 'completed' THEN 'Job completed: ' || job_type
                    WHEN status = 'failed' THEN 'Job failed: ' || job_type
                    ELSE 'Job ' || status || ': ' || job_type
                END as description,
                payment_amount as amount,
                EXTRACT(EPOCH FROM created_at)::bigint as timestamp,
                tx_hash
            FROM jobs
            ORDER BY created_at DESC
            LIMIT 5
        )
        UNION ALL
        (
            SELECT
                'payment' as activity_type,
                'Payment received: ' || payment_type as description,
                amount::text as amount,
                EXTRACT(EPOCH FROM created_at)::bigint as timestamp,
                tx_hash
            FROM payments
            ORDER BY created_at DESC
            LIMIT 5
        )
        UNION ALL
        (
            SELECT
                'staking' as activity_type,
                event_type || ' event' as description,
                amount::text as amount,
                EXTRACT(EPOCH FROM created_at)::bigint as timestamp,
                tx_hash
            FROM staking_events
            ORDER BY created_at DESC
            LIMIT 5
        )
        ORDER BY timestamp DESC
        LIMIT 10
        "#
    )
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| {
        error!("Failed to query recent activity: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
    })?;

    let items: Vec<RecentActivityItem> = activities
        .into_iter()
        .map(|row| RecentActivityItem {
            activity_type: row.try_get("activity_type").unwrap_or_else(|_| "unknown".to_string()),
            description: row.try_get("description").unwrap_or_else(|_| "Activity".to_string()),
            amount: row.try_get("amount").ok(),
            timestamp: row.try_get("timestamp").unwrap_or(0),
            tx_hash: row.try_get("tx_hash").ok(),
        })
        .collect();

    Ok(Json(items))
}
