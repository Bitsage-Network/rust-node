//! # Staking Database API
//!
//! Database-backed REST API endpoints for staking management.
//! Provides staking history, worker info, and leaderboard.

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
pub struct StakingDbState {
    pub pool: Arc<PgPool>,
}

impl StakingDbState {
    /// Create a new StakingDbState with the given database pool
    pub fn new(pool: PgPool) -> Self {
        Self { pool: Arc::new(pool) }
    }
}

/// Query parameters
#[derive(Debug, Deserialize)]
pub struct StakingQuery {
    pub page: Option<i64>,
    pub limit: Option<i64>,
    pub event_type: Option<String>,
}

/// Worker staking info
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct WorkerStakingInfo {
    pub worker_id: String,
    pub address: String,
    pub status: String,
    pub staked_amount: String,
    pub gpu_tier: Option<String>,
    pub has_tee: bool,
    pub reputation_score: i32,
    pub jobs_completed: i64,
    pub jobs_failed: i64,
    pub total_earnings: String,
    pub registered_at: chrono::DateTime<chrono::Utc>,
    pub last_heartbeat: Option<chrono::DateTime<chrono::Utc>>,
}

/// Staking event from history
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct StakingEventResponse {
    pub id: String,
    pub worker_id: String,
    pub worker_address: String,
    pub event_type: String,
    pub amount: String,
    pub gpu_tier: Option<String>,
    pub has_tee: Option<bool>,
    pub reason: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub tx_hash: String,
    pub block_number: i64,
}

/// Staking history response
#[derive(Debug, Serialize)]
pub struct StakingHistoryResponse {
    pub events: Vec<StakingEventResponse>,
    pub total: i64,
    pub page: i64,
    pub limit: i64,
}

/// Leaderboard entry
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct LeaderboardEntry {
    pub rank: i64,
    pub address: String,
    pub worker_id: String,
    pub staked_amount: String,
    pub reputation_score: i32,
    pub jobs_completed: i64,
    pub total_earnings: String,
    pub success_rate: f64,
}

/// Leaderboard response
#[derive(Debug, Serialize)]
pub struct LeaderboardResponse {
    pub leaderboard: Vec<LeaderboardEntry>,
    pub total_stakers: i64,
    pub total_staked: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Staking statistics
#[derive(Debug, Serialize)]
pub struct StakingStatsResponse {
    pub total_stakers: i64,
    pub active_stakers: i64,
    pub total_staked: String,
    pub avg_stake: Option<f64>,
    pub total_slashed: String,
    pub staking_events_24h: i64,
    pub by_tier: Vec<TierStats>,
    pub by_event_type: Vec<EventTypeStats>,
    pub daily_trend: Vec<DailyStakingStats>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct TierStats {
    pub gpu_tier: Option<String>,
    pub count: i64,
    pub total_staked: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct EventTypeStats {
    pub event_type: String,
    pub count: i64,
    pub total_amount: String,
}

#[derive(Debug, Serialize)]
pub struct DailyStakingStats {
    pub date: chrono::NaiveDate,
    pub staked: String,
    pub unstaked: String,
    pub net: String,
}

/// Create staking database router
pub fn staking_db_routes(state: StakingDbState) -> Router {
    Router::new()
        .route("/api/staking/db/info/:address", get(get_worker_staking_info))
        .route("/api/staking/db/history/:address", get(get_staking_history))
        .route("/api/staking/db/leaderboard", get(get_leaderboard))
        .route("/api/staking/db/stats", get(get_staking_stats))
        .route("/api/staking/db/workers", get(list_stakers))
        .route("/api/staking/db/events", get(get_all_staking_events))
        .with_state(state)
}

/// Get worker staking info
async fn get_worker_staking_info(
    State(state): State<StakingDbState>,
    Path(address): Path<String>,
) -> Result<Json<WorkerStakingInfo>, (StatusCode, String)> {
    let info: WorkerStakingInfo = sqlx::query_as(
        r#"
        SELECT 
            worker_id, address, status, staked_amount::text as staked_amount,
            gpu_tier, COALESCE(has_tee, false) as has_tee, 
            COALESCE(reputation_score, 100) as reputation_score,
            COALESCE(jobs_completed, 0) as jobs_completed,
            COALESCE(jobs_failed, 0) as jobs_failed,
            COALESCE(total_earnings, 0)::text as total_earnings,
            registered_at, last_heartbeat
        FROM workers
        WHERE address = $1 OR worker_id = $1
        "#
    )
    .bind(&address)
    .fetch_optional(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::NOT_FOUND, "Worker not found".to_string()))?;
    
    Ok(Json(info))
}

/// Get staking history for an address
async fn get_staking_history(
    State(state): State<StakingDbState>,
    Path(address): Path<String>,
    Query(params): Query<StakingQuery>,
) -> Result<Json<StakingHistoryResponse>, (StatusCode, String)> {
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(50).min(100);
    let offset = (page - 1) * limit;
    
    // Get total (parameterized query)
    let total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM staking_events
        WHERE (worker_address = $1 OR worker_id = $1)
          AND ($2::text IS NULL OR event_type = $2)
        "#
    )
    .bind(&address)
    .bind(&params.event_type)
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database query failed: {}", e)))?;

    // Get events (parameterized query)
    let events: Vec<StakingEventResponse> = sqlx::query_as(
        r#"
        SELECT
            id::text, worker_id, worker_address, event_type,
            amount::text as amount, gpu_tier, has_tee, reason,
            created_at, tx_hash, block_number
        FROM staking_events
        WHERE (worker_address = $1 OR worker_id = $1)
          AND ($2::text IS NULL OR event_type = $2)
        ORDER BY created_at DESC
        LIMIT $3 OFFSET $4
        "#
    )
    .bind(&address)
    .bind(&params.event_type)
    .bind(limit)
    .bind(offset)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database query failed: {}", e)))?;
    
    Ok(Json(StakingHistoryResponse {
        events,
        total,
        page,
        limit,
    }))
}

/// Get staking leaderboard
async fn get_leaderboard(
    State(state): State<StakingDbState>,
    Query(params): Query<StakingQuery>,
) -> Result<Json<LeaderboardResponse>, (StatusCode, String)> {
    let limit = params.limit.unwrap_or(20).min(100);
    
    // Get leaderboard
    let leaderboard: Vec<LeaderboardEntry> = sqlx::query_as(
        r#"
        SELECT 
            ROW_NUMBER() OVER (ORDER BY staked_amount DESC) as rank,
            address, worker_id, staked_amount::text as staked_amount,
            COALESCE(reputation_score, 100) as reputation_score,
            COALESCE(jobs_completed, 0) as jobs_completed,
            COALESCE(total_earnings, 0)::text as total_earnings,
            CASE 
                WHEN jobs_completed + jobs_failed > 0 
                THEN ROUND(jobs_completed::numeric / (jobs_completed + jobs_failed) * 100, 2)
                ELSE 100
            END as success_rate
        FROM workers
        WHERE status = 'active' AND staked_amount > 0
        ORDER BY staked_amount DESC
        LIMIT $1
        "#
    )
    .bind(limit)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Get totals
    let total_stakers: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM workers WHERE staked_amount > 0"
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let total_staked: String = sqlx::query_scalar(
        "SELECT COALESCE(SUM(staked_amount), 0)::text FROM workers"
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    Ok(Json(LeaderboardResponse {
        leaderboard,
        total_stakers,
        total_staked,
        updated_at: chrono::Utc::now(),
    }))
}

/// Get staking statistics
async fn get_staking_stats(
    State(state): State<StakingDbState>,
) -> Result<Json<StakingStatsResponse>, (StatusCode, String)> {
    // Counts
    let total_stakers: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM workers WHERE staked_amount > 0"
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let active_stakers: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM workers WHERE status = 'active' AND staked_amount > 0"
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let total_staked: String = sqlx::query_scalar(
        "SELECT COALESCE(SUM(staked_amount), 0)::text FROM workers"
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let avg_stake: Option<f64> = sqlx::query_scalar(
        "SELECT AVG(staked_amount::float8) FROM workers WHERE staked_amount > 0"
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let total_slashed: String = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount), 0)::text FROM staking_events WHERE event_type = 'slashed'"
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let staking_events_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM staking_events WHERE created_at > NOW() - INTERVAL '24 hours'"
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // By tier
    let by_tier: Vec<TierStats> = sqlx::query_as(
        r#"
        SELECT gpu_tier, COUNT(*) as count, SUM(staked_amount)::text as total_staked
        FROM workers
        WHERE staked_amount > 0
        GROUP BY gpu_tier
        ORDER BY count DESC
        "#
    )
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // By event type
    let by_event_type: Vec<EventTypeStats> = sqlx::query_as(
        r#"
        SELECT event_type, COUNT(*) as count, SUM(amount)::text as total_amount
        FROM staking_events
        GROUP BY event_type
        ORDER BY count DESC
        "#
    )
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Daily trend (last 7 days)
    let trend_rows: Vec<(chrono::NaiveDate, String, String)> = sqlx::query_as(
        r#"
        SELECT 
            DATE(created_at) as date,
            COALESCE(SUM(CASE WHEN event_type = 'stake' THEN amount ELSE 0 END), 0)::text as staked,
            COALESCE(SUM(CASE WHEN event_type IN ('unstake', 'unstake_initiated', 'slashed') THEN amount ELSE 0 END), 0)::text as unstaked
        FROM staking_events
        WHERE created_at > NOW() - INTERVAL '7 days'
        GROUP BY DATE(created_at)
        ORDER BY date
        "#
    )
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let daily_trend: Vec<DailyStakingStats> = trend_rows
        .into_iter()
        .map(|(date, staked, unstaked)| {
            let staked_val: i128 = staked.parse().unwrap_or(0);
            let unstaked_val: i128 = unstaked.parse().unwrap_or(0);
            let net = staked_val - unstaked_val;
            DailyStakingStats {
                date,
                staked,
                unstaked,
                net: net.to_string(),
            }
        })
        .collect();
    
    Ok(Json(StakingStatsResponse {
        total_stakers,
        active_stakers,
        total_staked,
        avg_stake,
        total_slashed,
        staking_events_24h,
        by_tier,
        by_event_type,
        daily_trend,
    }))
}

/// List all stakers
async fn list_stakers(
    State(state): State<StakingDbState>,
    Query(params): Query<StakingQuery>,
) -> Result<Json<Vec<WorkerStakingInfo>>, (StatusCode, String)> {
    let limit = params.limit.unwrap_or(50).min(100);
    
    let stakers: Vec<WorkerStakingInfo> = sqlx::query_as(
        r#"
        SELECT 
            worker_id, address, status, staked_amount::text as staked_amount,
            gpu_tier, COALESCE(has_tee, false) as has_tee, 
            COALESCE(reputation_score, 100) as reputation_score,
            COALESCE(jobs_completed, 0) as jobs_completed,
            COALESCE(jobs_failed, 0) as jobs_failed,
            COALESCE(total_earnings, 0)::text as total_earnings,
            registered_at, last_heartbeat
        FROM workers
        WHERE staked_amount > 0
        ORDER BY staked_amount DESC
        LIMIT $1
        "#
    )
    .bind(limit)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    Ok(Json(stakers))
}

/// Get all staking events
async fn get_all_staking_events(
    State(state): State<StakingDbState>,
    Query(params): Query<StakingQuery>,
) -> Result<Json<StakingHistoryResponse>, (StatusCode, String)> {
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(50).min(100);
    let offset = (page - 1) * limit;
    
    let mut conditions = vec!["1=1".to_string()];
    
    if let Some(ref event_type) = params.event_type {
        conditions.push(format!("event_type = '{}'", event_type));
    }
    
    let where_clause = conditions.join(" AND ");
    
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM staking_events WHERE {}",
        where_clause
    ))
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let events: Vec<StakingEventResponse> = sqlx::query_as(&format!(
        r#"
        SELECT 
            id::text, worker_id, worker_address, event_type, 
            amount::text as amount, gpu_tier, has_tee, reason,
            created_at, tx_hash, block_number
        FROM staking_events 
        WHERE {}
        ORDER BY created_at DESC
        LIMIT {} OFFSET {}
        "#,
        where_clause, limit, offset
    ))
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    Ok(Json(StakingHistoryResponse {
        events,
        total,
        page,
        limit,
    }))
}
