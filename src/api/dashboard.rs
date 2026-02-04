//! # Dashboard API Endpoints
//!
//! REST API endpoints for the BitSage Validator Dashboard.
//! Provides validator status, GPU metrics, rewards, job analytics, and network stats.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use tracing::{debug, warn, error};

use super::metrics_aggregator::MetricsAggregator;
use super::cache::{DashboardCache, CacheKeys, CacheTTL};

/// Dashboard API state
pub struct DashboardApiState {
    /// Network configuration
    pub network: String,
    /// Contract addresses
    pub contracts: DashboardContracts,
    /// Metrics aggregator (optional - None for simple coordinator mode)
    pub metrics_aggregator: Option<Arc<MetricsAggregator>>,
    /// Database pool for direct queries
    pub db: Option<PgPool>,
    /// Dashboard cache for reducing load
    pub cache: Option<Arc<DashboardCache>>,
}

/// Contract addresses for dashboard
#[derive(Clone, Debug)]
pub struct DashboardContracts {
    pub sage_token: String,
    pub prover_staking: String,
    pub reputation_manager: String,
    pub job_manager: String,
    pub faucet: Option<String>,
}

/// Create dashboard routes
pub fn dashboard_routes(state: Arc<DashboardApiState>) -> Router {
    Router::new()
        .route("/api/validator/status", get(get_validator_status))
        .route("/api/validator/gpus", get(get_gpu_metrics))
        .route("/api/validator/rewards", get(get_rewards_info))
        .route("/api/validator/history", get(get_reward_history))
        .route("/api/jobs/analytics", get(get_job_analytics))
        .route("/api/jobs/recent", get(get_recent_jobs))
        .route("/api/network/stats", get(get_network_stats))
        .route("/api/network/workers", get(get_network_workers))
        .route("/api/contracts", get(get_contract_addresses))
        .with_state(state)
}

// ============================================================================
// Response Types
// ============================================================================

/// Validator status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorStatusResponse {
    pub is_active: bool,
    pub is_registered: bool,
    pub staked_amount: String,
    pub staked_amount_formatted: String,
    pub stake_tier: String,
    pub reputation_score: u32,
    pub total_earnings: String,
    pub total_earnings_formatted: String,
    pub pending_rewards: String,
    pub pending_rewards_formatted: String,
    pub jobs_completed: u64,
    pub jobs_in_progress: u32,
    pub jobs_failed: u64,
    pub uptime_percent: f32,
    pub last_heartbeat: Option<u64>,
}

/// GPU metrics response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuMetricsResponse {
    pub gpus: Vec<GpuInfo>,
    pub total_vram_mb: u64,
    pub used_vram_mb: u64,
    pub avg_utilization: f32,
    pub avg_temperature: f32,
}

/// Individual GPU info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuInfo {
    pub index: u32,
    pub model: String,
    pub name: String,
    pub tier: String,
    pub vram_total_gb: f32,
    pub vram_used_gb: f32,
    pub compute_utilization: f32,
    pub temperature_celsius: f32,
    pub power_watts: f32,
    pub status: String,
    pub has_tee: bool,
    pub tee_type: Option<String>,
    pub current_job_id: Option<String>,
}

/// Rewards info response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardsInfoResponse {
    pub total_earned: String,
    pub total_earned_formatted: String,
    pub pending_rewards: String,
    pub pending_rewards_formatted: String,
    pub claimable_rewards: String,
    pub claimable_rewards_formatted: String,
    pub last_claim_timestamp: Option<u64>,
    pub next_reward_estimate: String,
    pub apy_estimate: f32,
}

/// Reward history query params
#[derive(Debug, Deserialize)]
pub struct RewardHistoryParams {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub period: Option<String>, // "day", "week", "month", "all"
}

/// Reward history response
#[derive(Debug, Serialize)]
pub struct RewardHistoryResponse {
    pub rewards: Vec<RewardEntry>,
    pub total_count: u64,
    pub period_summary: PeriodSummary,
}

/// Individual reward entry
#[derive(Debug, Serialize)]
pub struct RewardEntry {
    pub timestamp: u64,
    pub amount: String,
    pub amount_formatted: String,
    pub job_id: Option<String>,
    pub reward_type: String, // "job_completion", "stake_reward", "bonus"
    pub tx_hash: Option<String>,
}

/// Period summary
#[derive(Debug, Serialize)]
pub struct PeriodSummary {
    pub period: String,
    pub total_rewards: String,
    pub total_rewards_formatted: String,
    pub job_count: u64,
    pub avg_reward_per_job: String,
}

/// Job analytics response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobAnalyticsResponse {
    pub total_jobs: u64,
    pub jobs_completed: u64,
    pub jobs_failed: u64,
    pub jobs_in_progress: u32,
    pub avg_completion_time_secs: f32,
    pub success_rate: f32,
    pub jobs_by_type: Vec<JobTypeCount>,
    pub jobs_last_24h: u64,
    pub jobs_last_7d: u64,
}

/// Job count by type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobTypeCount {
    pub job_type: String,
    pub count: u64,
    pub percentage: f32,
}

/// Recent jobs query params
#[derive(Debug, Deserialize)]
pub struct RecentJobsParams {
    pub limit: Option<u32>,
    pub status: Option<String>,
}

/// Recent jobs response
#[derive(Debug, Serialize)]
pub struct RecentJobsResponse {
    pub jobs: Vec<RecentJob>,
    pub total_count: u64,
}

/// Recent job entry
#[derive(Debug, Serialize)]
pub struct RecentJob {
    pub job_id: String,
    pub job_type: String,
    pub status: String,
    pub submitted_at: u64,
    pub completed_at: Option<u64>,
    pub duration_secs: Option<u32>,
    pub reward: Option<String>,
    pub client_address: String,
}

/// Network stats response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatsResponse {
    pub network: String,
    pub total_workers: u32,
    pub active_workers: u32,
    pub total_jobs_processed: u64,
    pub jobs_last_24h: u64,
    pub avg_job_completion_time_secs: f32,
    pub total_compute_hours: f64,
    pub network_utilization: f32,
    pub total_staked: String,
    pub total_staked_formatted: String,
    pub current_block: u64,
}

/// Network workers response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkWorkersResponse {
    pub workers: Vec<WorkerSummary>,
    pub total_count: u32,
}

/// Worker summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerSummary {
    pub worker_id: String,
    pub address: String,
    pub status: String,
    pub gpu_count: u32,
    pub gpu_type: String,
    pub reputation: u32,
    pub jobs_completed: u64,
    pub stake_tier: String,
}

/// Contract addresses response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractsResponse {
    pub network: String,
    pub sage_token: String,
    pub prover_staking: String,
    pub reputation_manager: String,
    pub job_manager: String,
    pub faucet: Option<String>,
    pub explorer_base_url: String,
}

// ============================================================================
// Handlers
// ============================================================================

/// Get validator status
async fn get_validator_status(
    State(state): State<Arc<DashboardApiState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<ValidatorStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Getting validator status for network: {}", state.network);

    // Extract wallet address from headers
    let address = headers
        .get("X-Wallet-Address")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("0x0");

    // Get aggregated metrics from all sources (or defaults if no aggregator)
    let Some(ref aggregator) = state.metrics_aggregator else {
        // Return defaults when no metrics aggregator available
        return Ok(Json(ValidatorStatusResponse {
            is_active: false,
            is_registered: false,
            staked_amount: "0".to_string(),
            staked_amount_formatted: "0 SAGE".to_string(),
            stake_tier: "None".to_string(),
            reputation_score: 0,
            total_earnings: "0".to_string(),
            total_earnings_formatted: "0 SAGE".to_string(),
            pending_rewards: "0".to_string(),
            pending_rewards_formatted: "0 SAGE".to_string(),
            jobs_completed: 0,
            jobs_in_progress: 0,
            jobs_failed: 0,
            uptime_percent: 0.0,
            last_heartbeat: None,
        }));
    };

    let metrics = match aggregator.get_validator_metrics(address).await {
        Ok(m) => m,
        Err(e) => {
            warn!("Failed to get validator metrics: {}, using defaults", e);
            // Return defaults on error
            return Ok(Json(ValidatorStatusResponse {
                is_active: false,
                is_registered: false,
                staked_amount: "0".to_string(),
                staked_amount_formatted: "0 SAGE".to_string(),
                stake_tier: "None".to_string(),
                reputation_score: 0,
                total_earnings: "0".to_string(),
                total_earnings_formatted: "0 SAGE".to_string(),
                pending_rewards: "0".to_string(),
                pending_rewards_formatted: "0 SAGE".to_string(),
                jobs_completed: 0,
                jobs_in_progress: 0,
                jobs_failed: 0,
                uptime_percent: 0.0,
                last_heartbeat: None,
            }));
        }
    };

    // Get rewards for display
    let rewards = aggregator.get_rewards(address).await
        .unwrap_or_else(|_| super::metrics_aggregator::AggregatedRewards {
            claimable_rewards: "0".to_string(),
            pending_rewards: "0".to_string(),
            total_earned: "0".to_string(),
            total_claimed: "0".to_string(),
            estimated_apy_bps: 0,
            last_claim_at: None,
            mining_rewards: "0".to_string(),
            staking_rewards: "0".to_string(),
        });

    Ok(Json(ValidatorStatusResponse {
        is_active: metrics.is_active,
        is_registered: metrics.is_registered,
        staked_amount: metrics.staked_amount.clone(),
        staked_amount_formatted: format_sage_amount(&metrics.staked_amount),
        stake_tier: metrics.stake_tier,
        reputation_score: metrics.reputation_score,
        total_earnings: rewards.total_earned.clone(),
        total_earnings_formatted: format_sage_amount(&rewards.total_earned),
        pending_rewards: rewards.claimable_rewards.clone(),
        pending_rewards_formatted: format_sage_amount(&rewards.claimable_rewards),
        jobs_completed: metrics.jobs_completed,
        jobs_in_progress: metrics.jobs_in_progress,
        jobs_failed: metrics.jobs_failed,
        uptime_percent: metrics.uptime_percent,
        last_heartbeat: metrics.last_heartbeat,
    }))
}

/// Get GPU metrics
async fn get_gpu_metrics(
    State(state): State<Arc<DashboardApiState>>,
) -> Result<Json<GpuMetricsResponse>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Getting GPU metrics from NVML");

    // Return empty response if no metrics aggregator
    let Some(ref aggregator) = state.metrics_aggregator else {
        return Ok(Json(GpuMetricsResponse {
            gpus: vec![],
            total_vram_mb: 0,
            used_vram_mb: 0,
            avg_utilization: 0.0,
            avg_temperature: 0.0,
        }));
    };

    // Get aggregated GPU metrics
    let gpu_metrics = match aggregator.get_gpu_metrics().await {
        Ok(m) => m,
        Err(e) => {
            warn!("Failed to get GPU metrics: {}, returning empty", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to get GPU metrics: {}", e),
                }),
            ));
        }
    };

    // Convert to API response format
    let gpus: Vec<GpuInfo> = gpu_metrics.gpus.iter().map(|g| {
        GpuInfo {
            index: g.index,
            model: g.model.clone(),
            name: format!("GPU {}", g.index),
            tier: g.tier.clone(),
            vram_total_gb: g.vram_total_gb,
            vram_used_gb: g.vram_used_gb,
            compute_utilization: g.compute_utilization,
            temperature_celsius: g.temperature_celsius,
            power_watts: g.power_watts,
            status: if g.compute_utilization > 5.0 { "active" } else { "idle" }.to_string(),
            has_tee: g.has_tee,
            tee_type: g.tee_type.clone(),
            current_job_id: g.current_job_id.clone(),
        }
    }).collect();

    let total_vram_mb = (gpu_metrics.gpus.iter().map(|g| g.vram_total_gb).sum::<f32>() * 1024.0) as u64;
    let used_vram_mb = (gpu_metrics.gpus.iter().map(|g| g.vram_used_gb).sum::<f32>() * 1024.0) as u64;
    let avg_temperature = if !gpu_metrics.gpus.is_empty() {
        gpu_metrics.gpus.iter().map(|g| g.temperature_celsius).sum::<f32>() / gpu_metrics.gpus.len() as f32
    } else {
        0.0
    };

    Ok(Json(GpuMetricsResponse {
        gpus,
        total_vram_mb,
        used_vram_mb,
        avg_utilization: gpu_metrics.avg_utilization,
        avg_temperature,
    }))
}

/// Get rewards info
async fn get_rewards_info(
    State(state): State<Arc<DashboardApiState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<RewardsInfoResponse>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Getting rewards info");

    // Extract wallet address from headers
    let address = headers
        .get("X-Wallet-Address")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("0x0");

    // Return defaults if no metrics aggregator
    let Some(ref aggregator) = state.metrics_aggregator else {
        return Ok(Json(RewardsInfoResponse {
            total_earned: "0".to_string(),
            total_earned_formatted: "0 SAGE".to_string(),
            pending_rewards: "0".to_string(),
            pending_rewards_formatted: "0 SAGE".to_string(),
            claimable_rewards: "0".to_string(),
            claimable_rewards_formatted: "0 SAGE".to_string(),
            last_claim_timestamp: None,
            next_reward_estimate: "0 SAGE".to_string(),
            apy_estimate: 0.0,
        }));
    };

    // Get aggregated rewards
    let rewards = match aggregator.get_rewards(address).await {
        Ok(r) => r,
        Err(e) => {
            warn!("Failed to get rewards: {}, using defaults", e);
            return Ok(Json(RewardsInfoResponse {
                total_earned: "0".to_string(),
                total_earned_formatted: "0 SAGE".to_string(),
                pending_rewards: "0".to_string(),
                pending_rewards_formatted: "0 SAGE".to_string(),
                claimable_rewards: "0".to_string(),
                claimable_rewards_formatted: "0 SAGE".to_string(),
                last_claim_timestamp: None,
                next_reward_estimate: "0 SAGE".to_string(),
                apy_estimate: 0.0,
            }));
        }
    };

    // Calculate APY as percentage from basis points
    let apy_estimate = rewards.estimated_apy_bps as f32 / 100.0;

    // Estimate next reward (rough calculation)
    let next_estimate = if let Ok(claimable) = rewards.claimable_rewards.parse::<u128>() {
        if claimable > 0 {
            format!("~{}", format_sage_amount(&rewards.claimable_rewards))
        } else {
            "Pending".to_string()
        }
    } else {
        "Pending".to_string()
    };

    Ok(Json(RewardsInfoResponse {
        total_earned: rewards.total_earned.clone(),
        total_earned_formatted: format_sage_amount(&rewards.total_earned),
        pending_rewards: rewards.pending_rewards.clone(),
        pending_rewards_formatted: format_sage_amount(&rewards.pending_rewards),
        claimable_rewards: rewards.claimable_rewards.clone(),
        claimable_rewards_formatted: format_sage_amount(&rewards.claimable_rewards),
        last_claim_timestamp: rewards.last_claim_at,
        next_reward_estimate: next_estimate,
        apy_estimate,
    }))
}

/// Get reward history
async fn get_reward_history(
    State(state): State<Arc<DashboardApiState>>,
    headers: axum::http::HeaderMap,
    Query(params): Query<RewardHistoryParams>,
) -> Json<RewardHistoryResponse> {
    let limit = params.limit.unwrap_or(20) as i64;
    let offset = params.offset.unwrap_or(0) as i64;
    let period = params.period.unwrap_or_else(|| "week".to_string());

    debug!("Getting reward history: limit={}, period={}", limit, period);

    // Extract wallet address from headers
    let address = headers
        .get("X-Wallet-Address")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("0x0");

    // Return empty if no database
    let Some(ref db) = state.db else {
        return Json(RewardHistoryResponse {
            rewards: vec![],
            total_count: 0,
            period_summary: PeriodSummary {
                period,
                total_rewards: "0".to_string(),
                total_rewards_formatted: "0 SAGE".to_string(),
                job_count: 0,
                avg_reward_per_job: "0 SAGE".to_string(),
            },
        });
    };

    // Determine interval based on period
    let interval = match period.as_str() {
        "day" => "1 day",
        "week" => "7 days",
        "month" => "30 days",
        "all" => "100 years",
        _ => "7 days",
    };

    // Query completed jobs as rewards
    let rewards_query = format!(
        r#"
        SELECT
            EXTRACT(EPOCH FROM completed_at)::bigint as timestamp,
            payment_amount::text as amount,
            job_id,
            'job_completion' as reward_type,
            result_hash as tx_hash
        FROM jobs
        WHERE worker_address = $1
          AND status = 'completed'
          AND completed_at > NOW() - INTERVAL '{}'
        ORDER BY completed_at DESC
        LIMIT $2 OFFSET $3
        "#,
        interval
    );

    let rewards = match sqlx::query(&rewards_query)
        .bind(address)
        .bind(limit)
        .bind(offset)
        .fetch_all(db)
        .await
    {
        Ok(rows) => rows.iter().map(|row| {
            let amount: String = row.try_get("amount").unwrap_or_else(|_| "0".to_string());
            RewardEntry {
                timestamp: row.try_get::<i64, _>("timestamp").unwrap_or(0) as u64,
                amount: amount.clone(),
                amount_formatted: format_sage_amount(&amount),
                job_id: row.try_get("job_id").ok(),
                reward_type: row.try_get("reward_type").unwrap_or_else(|_| "job_completion".to_string()),
                tx_hash: row.try_get("tx_hash").ok(),
            }
        }).collect(),
        Err(e) => {
            error!("Failed to query reward history: {}", e);
            vec![]
        }
    };

    // Query summary
    let summary_query = format!(
        r#"
        SELECT
            COUNT(*) as job_count,
            COALESCE(SUM(payment_amount), 0)::text as total_rewards
        FROM jobs
        WHERE worker_address = $1
          AND status = 'completed'
          AND completed_at > NOW() - INTERVAL '{}'
        "#,
        interval
    );

    let (total_rewards, job_count) = match sqlx::query(&summary_query)
        .bind(address)
        .fetch_one(db)
        .await
    {
        Ok(row) => (
            row.try_get::<String, _>("total_rewards").unwrap_or_else(|_| "0".to_string()),
            row.try_get::<i64, _>("job_count").unwrap_or(0) as u64,
        ),
        Err(_) => ("0".to_string(), 0),
    };

    let avg_per_job = if job_count > 0 {
        if let Ok(total) = total_rewards.parse::<u128>() {
            format_sage_amount(&(total / job_count as u128).to_string())
        } else {
            "0 SAGE".to_string()
        }
    } else {
        "0 SAGE".to_string()
    };

    Json(RewardHistoryResponse {
        rewards,
        total_count: job_count,
        period_summary: PeriodSummary {
            period,
            total_rewards: total_rewards.clone(),
            total_rewards_formatted: format_sage_amount(&total_rewards),
            job_count,
            avg_reward_per_job: avg_per_job,
        },
    })
}

/// Get job analytics
async fn get_job_analytics(
    State(state): State<Arc<DashboardApiState>>,
) -> Json<JobAnalyticsResponse> {
    // Check cache first
    if let Some(ref cache) = state.cache {
        if let Some(cached) = cache.get::<JobAnalyticsResponse>(&CacheKeys::job_analytics()).await {
            debug!("Returning cached job analytics");
            return Json(cached);
        }
    }

    // Return defaults if no database
    let Some(ref db) = state.db else {
        return Json(JobAnalyticsResponse {
            total_jobs: 0,
            jobs_completed: 0,
            jobs_failed: 0,
            jobs_in_progress: 0,
            avg_completion_time_secs: 0.0,
            success_rate: 0.0,
            jobs_by_type: vec![],
            jobs_last_24h: 0,
            jobs_last_7d: 0,
        });
    };

    // Query job counts by status
    let counts = sqlx::query(
        r#"
        SELECT
            COUNT(*) as total,
            COUNT(*) FILTER (WHERE status = 'completed') as completed,
            COUNT(*) FILTER (WHERE status = 'failed') as failed,
            COUNT(*) FILTER (WHERE status IN ('pending', 'running', 'assigned')) as in_progress,
            AVG(execution_time_ms) FILTER (WHERE status = 'completed') as avg_time_ms,
            COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') as last_24h,
            COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '7 days') as last_7d
        FROM jobs
        "#
    )
    .fetch_one(db)
    .await;

    let (total, completed, failed, in_progress, avg_time_ms, last_24h, last_7d) = match counts {
        Ok(row) => (
            row.try_get::<i64, _>("total").unwrap_or(0) as u64,
            row.try_get::<i64, _>("completed").unwrap_or(0) as u64,
            row.try_get::<i64, _>("failed").unwrap_or(0) as u64,
            row.try_get::<i64, _>("in_progress").unwrap_or(0) as u32,
            row.try_get::<Option<f64>, _>("avg_time_ms").unwrap_or(None),
            row.try_get::<i64, _>("last_24h").unwrap_or(0) as u64,
            row.try_get::<i64, _>("last_7d").unwrap_or(0) as u64,
        ),
        Err(e) => {
            error!("Failed to query job analytics: {}", e);
            (0, 0, 0, 0, None, 0, 0)
        }
    };

    // Query jobs by type
    let by_type = sqlx::query(
        r#"
        SELECT job_type, COUNT(*) as count
        FROM jobs
        GROUP BY job_type
        ORDER BY count DESC
        LIMIT 10
        "#
    )
    .fetch_all(db)
    .await;

    let jobs_by_type: Vec<JobTypeCount> = match by_type {
        Ok(rows) => {
            let total_f = total.max(1) as f32;
            rows.iter().map(|row| {
                let count = row.try_get::<i64, _>("count").unwrap_or(0) as u64;
                JobTypeCount {
                    job_type: row.try_get("job_type").unwrap_or_else(|_| "Unknown".to_string()),
                    count,
                    percentage: (count as f32 / total_f) * 100.0,
                }
            }).collect()
        },
        Err(_) => vec![],
    };

    let success_rate = if total > 0 {
        (completed as f32 / total as f32) * 100.0
    } else {
        0.0
    };

    let avg_completion_time_secs = avg_time_ms.map(|ms| ms / 1000.0).unwrap_or(0.0) as f32;

    let response = JobAnalyticsResponse {
        total_jobs: total,
        jobs_completed: completed,
        jobs_failed: failed,
        jobs_in_progress: in_progress,
        avg_completion_time_secs,
        success_rate,
        jobs_by_type,
        jobs_last_24h: last_24h,
        jobs_last_7d: last_7d,
    };

    // Cache the response
    if let Some(ref cache) = state.cache {
        cache.set(&CacheKeys::job_analytics(), &response, CacheTTL::JOB_ANALYTICS).await;
    }

    Json(response)
}

/// Get recent jobs
async fn get_recent_jobs(
    State(state): State<Arc<DashboardApiState>>,
    Query(params): Query<RecentJobsParams>,
) -> Json<RecentJobsResponse> {
    let limit = params.limit.unwrap_or(10) as i64;
    let status_filter = params.status.clone();
    debug!("Getting recent jobs: limit={}", limit);

    // Return empty if no database
    let Some(ref db) = state.db else {
        return Json(RecentJobsResponse {
            jobs: vec![],
            total_count: 0,
        });
    };

    // Parameterized query for status filter
    let jobs_query = r#"
        SELECT
            job_id,
            job_type,
            status,
            EXTRACT(EPOCH FROM created_at)::bigint as submitted_at,
            EXTRACT(EPOCH FROM completed_at)::bigint as completed_at,
            execution_time_ms / 1000 as duration_secs,
            payment_amount::text as reward,
            client_address
        FROM jobs
        WHERE ($1::text IS NULL OR status = $1)
        ORDER BY created_at DESC
        LIMIT $2
    "#;

    let count_query = "SELECT COUNT(*) FROM jobs WHERE ($1::text IS NULL OR status = $1)";

    // Get total count
    let total_count: u64 = sqlx::query_scalar(count_query)
        .bind(&status_filter)
        .fetch_one(db)
        .await
        .map(|c: i64| c as u64)
        .unwrap_or(0);

    // Get recent jobs
    let jobs = match sqlx::query(jobs_query)
        .bind(&status_filter)
        .bind(limit)
        .fetch_all(db)
        .await
    {
        Ok(rows) => rows.iter().map(|row| {
            let reward_wei: Option<String> = row.try_get("reward").ok();
            let reward = reward_wei.as_ref().map(|r| format_sage_amount(r));

            RecentJob {
                job_id: row.try_get("job_id").unwrap_or_else(|_| "unknown".to_string()),
                job_type: row.try_get("job_type").unwrap_or_else(|_| "Unknown".to_string()),
                status: row.try_get("status").unwrap_or_else(|_| "unknown".to_string()),
                submitted_at: row.try_get::<Option<i64>, _>("submitted_at").unwrap_or(None).unwrap_or(0) as u64,
                completed_at: row.try_get::<Option<i64>, _>("completed_at").unwrap_or(None).map(|t| t as u64),
                duration_secs: row.try_get::<Option<i64>, _>("duration_secs").unwrap_or(None).map(|d| d as u32),
                reward,
                client_address: row.try_get("client_address").unwrap_or_else(|_| "0x0".to_string()),
            }
        }).collect(),
        Err(e) => {
            error!("Failed to query recent jobs: {}", e);
            vec![]
        }
    };

    Json(RecentJobsResponse {
        jobs,
        total_count,
    })
}

/// Get network stats
async fn get_network_stats(
    State(state): State<Arc<DashboardApiState>>,
) -> Json<NetworkStatsResponse> {
    // Check cache first
    if let Some(ref cache) = state.cache {
        if let Some(cached) = cache.get::<NetworkStatsResponse>(&CacheKeys::network_stats()).await {
            debug!("Returning cached network stats");
            return Json(cached);
        }
    }

    // Return defaults if no database
    let Some(ref db) = state.db else {
        return Json(NetworkStatsResponse {
            network: state.network.clone(),
            total_workers: 0,
            active_workers: 0,
            total_jobs_processed: 0,
            jobs_last_24h: 0,
            avg_job_completion_time_secs: 0.0,
            total_compute_hours: 0.0,
            network_utilization: 0.0,
            total_staked: "0".to_string(),
            total_staked_formatted: "0 SAGE".to_string(),
            current_block: 0,
        });
    };

    // Query worker counts
    let worker_counts = sqlx::query(
        r#"
        SELECT
            COUNT(DISTINCT worker_address) as total_workers,
            COUNT(DISTINCT worker_address) FILTER (
                WHERE status IN ('running', 'assigned', 'pending')
                  AND created_at > NOW() - INTERVAL '5 minutes'
            ) as active_workers
        FROM jobs
        WHERE worker_address IS NOT NULL
        "#
    )
    .fetch_one(db)
    .await;

    let (total_workers, active_workers) = match worker_counts {
        Ok(row) => (
            row.try_get::<i64, _>("total_workers").unwrap_or(0) as u32,
            row.try_get::<i64, _>("active_workers").unwrap_or(0) as u32,
        ),
        Err(_) => (0, 0),
    };

    // Query job stats
    let job_stats = sqlx::query(
        r#"
        SELECT
            COUNT(*) as total_jobs,
            COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') as jobs_24h,
            AVG(execution_time_ms) FILTER (WHERE status = 'completed') as avg_time_ms,
            SUM(execution_time_ms) FILTER (WHERE status = 'completed') as total_time_ms
        FROM jobs
        "#
    )
    .fetch_one(db)
    .await;

    let (total_jobs, jobs_24h, avg_time_ms, total_time_ms) = match job_stats {
        Ok(row) => (
            row.try_get::<i64, _>("total_jobs").unwrap_or(0) as u64,
            row.try_get::<i64, _>("jobs_24h").unwrap_or(0) as u64,
            row.try_get::<Option<f64>, _>("avg_time_ms").unwrap_or(None),
            row.try_get::<Option<i64>, _>("total_time_ms").unwrap_or(None),
        ),
        Err(_) => (0, 0, None, None),
    };

    // Calculate compute hours (total execution time in hours)
    let total_compute_hours = total_time_ms
        .map(|ms| ms as f64 / (1000.0 * 60.0 * 60.0))
        .unwrap_or(0.0);

    // Get total staked from staking contract via metrics aggregator
    let total_staked = if let Some(ref _aggregator) = state.metrics_aggregator {
        // Query total staked from staking events
        let staked_result = sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(SUM(amount), 0)::bigint FROM staking_events WHERE event_type = 'stake'"
        )
        .fetch_one(db)
        .await
        .unwrap_or(0);

        let unstaked_result = sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(SUM(amount), 0)::bigint FROM staking_events WHERE event_type = 'unstake'"
        )
        .fetch_one(db)
        .await
        .unwrap_or(0);

        (staked_result - unstaked_result).max(0).to_string()
    } else {
        "0".to_string()
    };

    // Get current block from latest indexed event
    let current_block: u64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(block_number), 0)::bigint FROM blockchain_events"
    )
    .fetch_one(db)
    .await
    .map(|b: i64| b as u64)
    .unwrap_or(0);

    // Calculate network utilization (active workers / total workers * 100)
    let network_utilization = if total_workers > 0 {
        (active_workers as f32 / total_workers as f32) * 100.0
    } else {
        0.0
    };

    let response = NetworkStatsResponse {
        network: state.network.clone(),
        total_workers,
        active_workers,
        total_jobs_processed: total_jobs,
        jobs_last_24h: jobs_24h,
        avg_job_completion_time_secs: avg_time_ms.map(|ms| ms / 1000.0).unwrap_or(0.0) as f32,
        total_compute_hours,
        network_utilization,
        total_staked: total_staked.clone(),
        total_staked_formatted: format_sage_amount(&total_staked),
        current_block,
    };

    // Cache the response
    if let Some(ref cache) = state.cache {
        cache.set(&CacheKeys::network_stats(), &response, CacheTTL::NETWORK_STATS).await;
    }

    Json(response)
}

/// Get network workers
async fn get_network_workers(
    State(state): State<Arc<DashboardApiState>>,
) -> Json<NetworkWorkersResponse> {
    // Check cache first
    if let Some(ref cache) = state.cache {
        if let Some(cached) = cache.get::<NetworkWorkersResponse>(&CacheKeys::network_workers()).await {
            debug!("Returning cached network workers");
            return Json(cached);
        }
    }

    // Return empty if no database
    let Some(ref db) = state.db else {
        return Json(NetworkWorkersResponse {
            workers: vec![],
            total_count: 0,
        });
    };

    // Query workers from jobs table (aggregated by worker_address)
    let workers_result = sqlx::query(
        r#"
        SELECT
            worker_address,
            COUNT(*) FILTER (WHERE status = 'completed') as jobs_completed,
            MAX(created_at) as last_active
        FROM jobs
        WHERE worker_address IS NOT NULL
        GROUP BY worker_address
        ORDER BY jobs_completed DESC
        LIMIT 100
        "#
    )
    .fetch_all(db)
    .await;

    let workers: Vec<WorkerSummary> = match workers_result {
        Ok(rows) => {
            let mut workers = Vec::with_capacity(rows.len());
            for row in rows.iter() {
                let address: String = row.try_get("worker_address").unwrap_or_else(|_| "0x0".to_string());
                let jobs_completed = row.try_get::<i64, _>("jobs_completed").unwrap_or(0) as u64;
                let last_active: Option<chrono::DateTime<chrono::Utc>> = row.try_get("last_active").ok();

                // Determine status based on recent activity
                let status = if let Some(ts) = last_active {
                    let age = chrono::Utc::now() - ts;
                    if age.num_minutes() < 5 {
                        "online"
                    } else if age.num_hours() < 1 {
                        "idle"
                    } else {
                        "offline"
                    }
                } else {
                    "unknown"
                };

                // Try to get worker details from workers table
                let worker_details = sqlx::query(
                    r#"
                    SELECT
                        worker_id,
                        COALESCE(gpu_count, 1) as gpu_count,
                        COALESCE(gpu_type, gpu_tier, 'Unknown') as gpu_type,
                        COALESCE(reputation_score, 500) as reputation_score
                    FROM workers
                    WHERE address = $1
                    LIMIT 1
                    "#
                )
                .bind(&address)
                .fetch_optional(db)
                .await;

                let (worker_id, gpu_count, gpu_type, reputation) = match worker_details {
                    Ok(Some(detail)) => (
                        detail.try_get::<String, _>("worker_id").unwrap_or_else(|_| {
                            if address.len() > 12 {
                                format!("{}...{}", &address[..6], &address[address.len()-4..])
                            } else {
                                address.clone()
                            }
                        }),
                        detail.try_get::<i32, _>("gpu_count").unwrap_or(1) as u32,
                        detail.try_get::<String, _>("gpu_type").unwrap_or_else(|_| "Unknown".to_string()),
                        detail.try_get::<i32, _>("reputation_score").unwrap_or(500) as u32,
                    ),
                    _ => (
                        if address.len() > 12 { format!("{}...{}", &address[..6], &address[address.len()-4..]) } else { address.clone() },
                        1,
                        "Unknown".to_string(),
                        500,
                    ),
                };

                // Determine stake tier based on jobs completed
                let stake_tier = if jobs_completed > 10000 {
                    "Enterprise"
                } else if jobs_completed > 1000 {
                    "Professional"
                } else if jobs_completed > 100 {
                    "Standard"
                } else {
                    "Basic"
                };

                workers.push(WorkerSummary {
                    worker_id,
                    address: if address.len() > 12 {
                        format!("{}...{}", &address[..6], &address[address.len()-4..])
                    } else {
                        address
                    },
                    status: status.to_string(),
                    gpu_count,
                    gpu_type,
                    reputation,
                    jobs_completed,
                    stake_tier: stake_tier.to_string(),
                });
            }
            workers
        },
        Err(e) => {
            error!("Failed to query network workers: {}", e);
            vec![]
        }
    };

    let total_count = workers.len() as u32;

    let response = NetworkWorkersResponse {
        workers,
        total_count,
    };

    // Cache the response
    if let Some(ref cache) = state.cache {
        cache.set(&CacheKeys::network_workers(), &response, CacheTTL::WORKERS).await;
    }

    Json(response)
}

/// Get contract addresses
async fn get_contract_addresses(
    State(state): State<Arc<DashboardApiState>>,
) -> Json<ContractsResponse> {
    // Check cache first (contracts rarely change)
    if let Some(ref cache) = state.cache {
        if let Some(cached) = cache.get::<ContractsResponse>(&CacheKeys::contracts()).await {
            return Json(cached);
        }
    }

    let explorer_base_url = match state.network.as_str() {
        "mainnet" => "https://starkscan.co",
        "sepolia" => "https://sepolia.starkscan.co",
        _ => "https://sepolia.starkscan.co",
    };

    let response = ContractsResponse {
        network: state.network.clone(),
        sage_token: state.contracts.sage_token.clone(),
        prover_staking: state.contracts.prover_staking.clone(),
        reputation_manager: state.contracts.reputation_manager.clone(),
        job_manager: state.contracts.job_manager.clone(),
        faucet: state.contracts.faucet.clone(),
        explorer_base_url: explorer_base_url.to_string(),
    };

    // Cache for a long time (contracts rarely change)
    if let Some(ref cache) = state.cache {
        cache.set(&CacheKeys::contracts(), &response, CacheTTL::CONTRACTS).await;
    }

    Json(response)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Format SAGE amount from wei string to human-readable format
/// Converts wei (10^18) to SAGE with comma separators
fn format_sage_amount(wei_str: &str) -> String {
    // Parse wei string to u128
    let wei = match wei_str.parse::<u128>() {
        Ok(w) => w,
        Err(_) => return "0 SAGE".to_string(),
    };

    // Convert wei to SAGE (divide by 10^18)
    let sage = wei / 1_000_000_000_000_000_000;
    let remainder = wei % 1_000_000_000_000_000_000;
    
    // Format with comma separators
    let sage_str = format_with_commas(sage);
    
    // If there's a significant remainder, show decimal
    if remainder > 100_000_000_000_000_000 { // > 0.1 SAGE
        let decimal = remainder / 100_000_000_000_000_000;
        format!("{}.{} SAGE", sage_str, decimal)
    } else {
        format!("{} SAGE", sage_str)
    }
}

/// Add comma separators to number
fn format_with_commas(n: u128) -> String {
    let s = n.to_string();
    let bytes: Vec<u8> = s.bytes().rev().collect();
    let chunks: Vec<Vec<u8>> = bytes
        .chunks(3)
        .map(|chunk| chunk.iter().rev().copied().collect())
        .collect();

    chunks
        .iter()
        .rev()
        .filter_map(|chunk| String::from_utf8(chunk.clone()).ok())
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_serialization() {
        let status = ValidatorStatusResponse {
            is_active: true,
            is_registered: true,
            staked_amount: "5000".to_string(),
            staked_amount_formatted: "5,000 SAGE".to_string(),
            stake_tier: "Enterprise".to_string(),
            reputation_score: 850,
            total_earnings: "1000".to_string(),
            total_earnings_formatted: "1,000 SAGE".to_string(),
            pending_rewards: "100".to_string(),
            pending_rewards_formatted: "100 SAGE".to_string(),
            jobs_completed: 100,
            jobs_in_progress: 2,
            jobs_failed: 1,
            uptime_percent: 99.5,
            last_heartbeat: Some(1234567890),
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("is_active"));
        assert!(json.contains("Enterprise"));
    }
}
