//! # Worker Heartbeat API
//!
//! Endpoints for worker heartbeat tracking to enable uptime monitoring
//! and real-time worker status updates for the validator dashboard.
//!
//! Workers should send heartbeats every 30-60 seconds to maintain "active" status.

use axum::{
    extract::{State, Query},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{debug, error, info};

use crate::api::websocket::WebSocketState;

/// Worker heartbeat API state
pub struct WorkerHeartbeatState {
    /// Database pool for storing heartbeats
    pub db: PgPool,
    /// WebSocket state for broadcasting worker updates
    pub ws_state: Option<Arc<WebSocketState>>,
}

/// Heartbeat request from a worker
#[derive(Debug, Deserialize)]
pub struct HeartbeatRequest {
    /// Worker's wallet address
    pub worker_address: String,
    /// Optional worker ID (derived if not provided)
    pub worker_id: Option<String>,
    /// Number of GPUs available
    pub gpu_count: Option<u32>,
    /// Average GPU utilization across all GPUs (0-100)
    pub gpu_utilization: Option<f32>,
    /// Average memory utilization (0-100)
    pub memory_utilization: Option<f32>,
    /// Current jobs being processed
    pub jobs_in_progress: Option<u32>,
    /// Network latency to coordinator in ms
    pub latency_ms: Option<u32>,
    /// Worker software version
    pub version: Option<String>,
}

/// Heartbeat response
#[derive(Debug, Serialize)]
pub struct HeartbeatResponse {
    pub success: bool,
    pub message: String,
    /// Current worker status
    pub status: String,
    /// Uptime percentage (last 24h)
    pub uptime_percent: f32,
    /// Recommended heartbeat interval in seconds
    pub heartbeat_interval_secs: u32,
}

/// Worker uptime query params
#[derive(Debug, Deserialize)]
pub struct UptimeParams {
    /// Worker address to query
    pub address: String,
    /// Period in hours (default 24)
    pub period_hours: Option<u32>,
}

/// Worker uptime response
#[derive(Debug, Serialize)]
pub struct UptimeResponse {
    pub worker_address: String,
    pub period_hours: u32,
    pub uptime_percent: f32,
    pub total_heartbeats: u64,
    pub expected_heartbeats: u64,
    pub last_heartbeat: Option<u64>,
    pub status: String,
}

/// GPU metrics recording request (periodic, e.g., every 5 minutes)
#[derive(Debug, Deserialize)]
pub struct GpuMetricsRequest {
    /// Worker's wallet address
    pub worker_address: String,
    /// Array of GPU metrics
    pub gpus: Vec<GpuMetricEntry>,
}

/// Individual GPU metric entry
#[derive(Debug, Deserialize)]
pub struct GpuMetricEntry {
    pub gpu_index: u32,
    pub gpu_model: Option<String>,
    pub gpu_tier: Option<String>,
    pub vram_total_gb: Option<f32>,
    pub vram_used_gb: Option<f32>,
    pub compute_utilization: Option<f32>,
    pub temperature_celsius: Option<f32>,
    pub power_watts: Option<f32>,
    pub has_tee: Option<bool>,
    pub current_job_id: Option<String>,
}

/// GPU metrics response
#[derive(Debug, Serialize)]
pub struct GpuMetricsResponse {
    pub success: bool,
    pub recorded_count: usize,
}

/// Reward claim recording request
#[derive(Debug, Deserialize)]
pub struct RewardClaimRequest {
    /// Worker's wallet address
    pub address: String,
    /// Amount claimed in wei
    pub amount: String,
    /// Type of claim: "staking", "mining", "referral", "bonus"
    pub claim_type: String,
    /// Transaction hash on-chain
    pub tx_hash: Option<String>,
    /// Block number
    pub block_number: Option<u64>,
    /// Epoch number if applicable
    pub epoch_number: Option<u32>,
}

/// Reward claim response
#[derive(Debug, Serialize)]
pub struct RewardClaimResponse {
    pub success: bool,
    pub claim_id: String,
    pub total_claimed: String,
}

/// Create worker heartbeat routes
pub fn worker_heartbeat_routes(state: Arc<WorkerHeartbeatState>) -> Router {
    Router::new()
        .route("/api/worker/heartbeat", post(record_heartbeat))
        .route("/api/worker/uptime", get(get_worker_uptime))
        .route("/api/worker/gpu-metrics", post(record_gpu_metrics))
        .route("/api/worker/claim-reward", post(record_reward_claim))
        .route("/api/worker/status", get(get_worker_status))
        .with_state(state)
}

/// Record a worker heartbeat
async fn record_heartbeat(
    State(state): State<Arc<WorkerHeartbeatState>>,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Recording heartbeat for worker: {}", req.worker_address);

    // Validate address format
    if !req.worker_address.starts_with("0x") || req.worker_address.len() < 10 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid worker address format".to_string(),
            }),
        ));
    }

    // Hash IP for privacy (not storing actual IP)
    let ip_hash: Option<String> = None;

    // Insert heartbeat record
    let result = sqlx::query(
        r#"
        INSERT INTO heartbeats (
            worker_address, worker_id, heartbeat_time, gpu_count,
            gpu_utilization_avg, memory_utilization_avg, jobs_in_progress,
            latency_ms, version, ip_hash
        )
        VALUES ($1, $2, NOW(), $3, $4, $5, $6, $7, $8, $9)
        RETURNING id
        "#
    )
    .bind(&req.worker_address)
    .bind(req.worker_id.as_ref().unwrap_or(&req.worker_address))
    .bind(req.gpu_count.map(|c| c as i32))
    .bind(req.gpu_utilization.map(|u| u as f64))
    .bind(req.memory_utilization.map(|u| u as f64))
    .bind(req.jobs_in_progress.map(|j| j as i32))
    .bind(req.latency_ms.map(|l| l as i32))
    .bind(&req.version)
    .bind(&ip_hash)
    .fetch_one(&state.db)
    .await;

    if let Err(e) = result {
        error!("Failed to record heartbeat: {}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to record heartbeat: {}", e),
            }),
        ));
    }

    // Calculate uptime for the last 24 hours
    let uptime = calculate_uptime(&state.db, &req.worker_address, 24).await
        .unwrap_or(100.0);

    // Determine worker status based on jobs
    let status = if req.jobs_in_progress.unwrap_or(0) > 0 {
        "active"
    } else {
        "idle"
    };

    // Broadcast worker update via WebSocket
    if let Some(ref ws) = state.ws_state {
        ws.broadcast_worker_update(
            req.worker_address.clone(),
            status.to_string(),
            req.gpu_count,
            req.gpu_utilization,
        );
    }

    info!(
        "Recorded heartbeat for {} - Status: {}, Uptime: {:.1}%",
        req.worker_address, status, uptime
    );

    Ok(Json(HeartbeatResponse {
        success: true,
        message: "Heartbeat recorded".to_string(),
        status: status.to_string(),
        uptime_percent: uptime,
        heartbeat_interval_secs: 60, // Recommend 60-second intervals
    }))
}

/// Get worker uptime statistics
async fn get_worker_uptime(
    State(state): State<Arc<WorkerHeartbeatState>>,
    Query(params): Query<UptimeParams>,
) -> Result<Json<UptimeResponse>, (StatusCode, Json<ErrorResponse>)> {
    let period_hours = params.period_hours.unwrap_or(24);

    // Query heartbeat statistics
    let stats = sqlx::query(
        r#"
        SELECT
            COUNT(*) as total_heartbeats,
            MAX(heartbeat_time) as last_heartbeat
        FROM heartbeats
        WHERE worker_address = $1
          AND heartbeat_time > NOW() - INTERVAL '1 hour' * $2
        "#
    )
    .bind(&params.address)
    .bind(period_hours as i32)
    .fetch_optional(&state.db)
    .await;

    match stats {
        Ok(Some(row)) => {
            use sqlx::Row;
            let total_heartbeats: i64 = row.try_get("total_heartbeats").unwrap_or(0);
            let last_heartbeat: Option<chrono::DateTime<chrono::Utc>> = row.try_get("last_heartbeat").ok();

            // Expected heartbeats: 1 per minute * 60 minutes * hours
            let expected_heartbeats = (period_hours as u64) * 60;
            let uptime_percent = if expected_heartbeats > 0 {
                ((total_heartbeats as f32) / (expected_heartbeats as f32) * 100.0).min(100.0)
            } else {
                0.0
            };

            // Determine status based on last heartbeat
            let status = if let Some(ts) = last_heartbeat {
                let age = chrono::Utc::now() - ts;
                if age.num_minutes() < 2 {
                    "online"
                } else if age.num_minutes() < 10 {
                    "idle"
                } else {
                    "offline"
                }
            } else {
                "unknown"
            };

            Ok(Json(UptimeResponse {
                worker_address: params.address,
                period_hours,
                uptime_percent,
                total_heartbeats: total_heartbeats as u64,
                expected_heartbeats,
                last_heartbeat: last_heartbeat.map(|ts| ts.timestamp() as u64),
                status: status.to_string(),
            }))
        }
        Ok(None) => {
            Ok(Json(UptimeResponse {
                worker_address: params.address,
                period_hours,
                uptime_percent: 0.0,
                total_heartbeats: 0,
                expected_heartbeats: (period_hours as u64) * 60,
                last_heartbeat: None,
                status: "unknown".to_string(),
            }))
        }
        Err(e) => {
            error!("Failed to query uptime: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to query uptime: {}", e),
                }),
            ))
        }
    }
}

/// Record GPU metrics snapshot
async fn record_gpu_metrics(
    State(state): State<Arc<WorkerHeartbeatState>>,
    Json(req): Json<GpuMetricsRequest>,
) -> Result<Json<GpuMetricsResponse>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Recording GPU metrics for worker: {}", req.worker_address);

    let mut recorded_count = 0;

    for gpu in &req.gpus {
        let result = sqlx::query(
            r#"
            INSERT INTO gpu_metrics_history (
                worker_address, gpu_index, gpu_model, gpu_tier,
                vram_total_gb, vram_used_gb, compute_utilization,
                temperature_celsius, power_watts, has_tee, current_job_id,
                recorded_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
            "#
        )
        .bind(&req.worker_address)
        .bind(gpu.gpu_index as i32)
        .bind(&gpu.gpu_model)
        .bind(&gpu.gpu_tier)
        .bind(gpu.vram_total_gb.map(|v| v as f64))
        .bind(gpu.vram_used_gb.map(|v| v as f64))
        .bind(gpu.compute_utilization.map(|v| v as f64))
        .bind(gpu.temperature_celsius.map(|v| v as f64))
        .bind(gpu.power_watts.map(|v| v as f64))
        .bind(gpu.has_tee.unwrap_or(false))
        .bind(&gpu.current_job_id)
        .execute(&state.db)
        .await;

        if result.is_ok() {
            recorded_count += 1;
        }
    }

    Ok(Json(GpuMetricsResponse {
        success: true,
        recorded_count,
    }))
}

/// Record a reward claim (called after on-chain claim succeeds)
async fn record_reward_claim(
    State(state): State<Arc<WorkerHeartbeatState>>,
    Json(req): Json<RewardClaimRequest>,
) -> Result<Json<RewardClaimResponse>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Recording reward claim for: {}", req.address);

    // Insert claim record
    let result = sqlx::query(
        r#"
        INSERT INTO reward_claims (
            address, amount, claim_type, claim_time,
            epoch_number, tx_hash, block_number, status
        )
        VALUES ($1, $2::numeric, $3, NOW(), $4, $5, $6, 'completed')
        RETURNING id
        "#
    )
    .bind(&req.address)
    .bind(&req.amount)
    .bind(&req.claim_type)
    .bind(req.epoch_number.map(|e| e as i32))
    .bind(&req.tx_hash)
    .bind(req.block_number.map(|b| b as i64))
    .fetch_one(&state.db)
    .await;

    match result {
        Ok(row) => {
            use sqlx::Row;
            let id: uuid::Uuid = match row.try_get("id") {
                Ok(id) => id,
                Err(e) => {
                    tracing::error!("Failed to read reward claim id: {}", e);
                    return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                        error: "Failed to read claim record".to_string(),
                    })));
                }
            };

            // Get total claimed
            let total_result = sqlx::query(
                "SELECT COALESCE(SUM(amount), 0)::text as total FROM reward_claims WHERE address = $1"
            )
            .bind(&req.address)
            .fetch_one(&state.db)
            .await;

            let total_claimed = total_result
                .map(|r| {
                    use sqlx::Row;
                    r.try_get::<String, _>("total").unwrap_or_else(|_| "0".to_string())
                })
                .unwrap_or_else(|_| "0".to_string());

            info!(
                "Recorded reward claim: {} {} for {}",
                req.amount, req.claim_type, req.address
            );

            Ok(Json(RewardClaimResponse {
                success: true,
                claim_id: id.to_string(),
                total_claimed,
            }))
        }
        Err(e) => {
            error!("Failed to record reward claim: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to record claim: {}", e),
                }),
            ))
        }
    }
}

/// Get worker status summary
async fn get_worker_status(
    State(state): State<Arc<WorkerHeartbeatState>>,
    Query(params): Query<UptimeParams>,
) -> Result<Json<WorkerStatusSummary>, (StatusCode, Json<ErrorResponse>)> {
    // Get latest heartbeat
    let heartbeat = sqlx::query(
        r#"
        SELECT
            heartbeat_time,
            gpu_count,
            gpu_utilization_avg,
            jobs_in_progress,
            version
        FROM heartbeats
        WHERE worker_address = $1
        ORDER BY heartbeat_time DESC
        LIMIT 1
        "#
    )
    .bind(&params.address)
    .fetch_optional(&state.db)
    .await;

    // Get uptime
    let uptime = calculate_uptime(&state.db, &params.address, 24).await.unwrap_or(0.0);

    // Get total claims
    let claims_result = sqlx::query(
        r#"
        SELECT
            COUNT(*) as claim_count,
            COALESCE(SUM(amount), 0)::text as total_claimed
        FROM reward_claims
        WHERE address = $1 AND status = 'completed'
        "#
    )
    .bind(&params.address)
    .fetch_optional(&state.db)
    .await;

    match (heartbeat, claims_result) {
        (Ok(hb), Ok(claims)) => {
            use sqlx::Row;

            let (last_seen, gpu_count, gpu_util, jobs, version) = if let Some(ref h) = hb {
                let ts: chrono::DateTime<chrono::Utc> = h.try_get("heartbeat_time").unwrap_or_default();
                (
                    Some(ts.timestamp() as u64),
                    h.try_get::<i32, _>("gpu_count").ok().map(|c| c as u32),
                    h.try_get::<f64, _>("gpu_utilization_avg").ok().map(|u| u as f32),
                    h.try_get::<i32, _>("jobs_in_progress").ok().map(|j| j as u32),
                    h.try_get::<String, _>("version").ok(),
                )
            } else {
                (None, None, None, None, None)
            };

            let (claim_count, total_claimed) = if let Some(ref c) = claims {
                (
                    c.try_get::<i64, _>("claim_count").unwrap_or(0) as u64,
                    c.try_get::<String, _>("total_claimed").unwrap_or_else(|_| "0".to_string()),
                )
            } else {
                (0, "0".to_string())
            };

            // Determine status
            let status = if let Some(ts) = last_seen {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let age = now - ts;
                if age < 120 {
                    "online"
                } else if age < 600 {
                    "idle"
                } else {
                    "offline"
                }
            } else {
                "unknown"
            };

            Ok(Json(WorkerStatusSummary {
                worker_address: params.address,
                status: status.to_string(),
                uptime_percent_24h: uptime,
                last_seen,
                gpu_count,
                gpu_utilization: gpu_util,
                jobs_in_progress: jobs.unwrap_or(0),
                version,
                total_claims: claim_count,
                total_claimed,
            }))
        }
        _ => {
            Ok(Json(WorkerStatusSummary {
                worker_address: params.address,
                status: "unknown".to_string(),
                uptime_percent_24h: 0.0,
                last_seen: None,
                gpu_count: None,
                gpu_utilization: None,
                jobs_in_progress: 0,
                version: None,
                total_claims: 0,
                total_claimed: "0".to_string(),
            }))
        }
    }
}

/// Worker status summary
#[derive(Debug, Serialize)]
pub struct WorkerStatusSummary {
    pub worker_address: String,
    pub status: String,
    pub uptime_percent_24h: f32,
    pub last_seen: Option<u64>,
    pub gpu_count: Option<u32>,
    pub gpu_utilization: Option<f32>,
    pub jobs_in_progress: u32,
    pub version: Option<String>,
    pub total_claims: u64,
    pub total_claimed: String,
}

/// Error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Calculate uptime percentage for a worker
async fn calculate_uptime(db: &PgPool, address: &str, hours: u32) -> Result<f32, sqlx::Error> {
    use sqlx::Row;

    let result = sqlx::query(
        r#"
        SELECT COUNT(*) as total
        FROM heartbeats
        WHERE worker_address = $1
          AND heartbeat_time > NOW() - INTERVAL '1 hour' * $2
        "#
    )
    .bind(address)
    .bind(hours as i32)
    .fetch_one(db)
    .await?;

    let total: i64 = result.try_get("total").unwrap_or(0);
    let expected = (hours as i64) * 60; // 1 heartbeat per minute expected

    if expected > 0 {
        Ok(((total as f32) / (expected as f32) * 100.0).min(100.0))
    } else {
        Ok(0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heartbeat_request_deserialization() {
        let json = r#"{
            "worker_address": "0x123abc",
            "gpu_count": 2,
            "gpu_utilization": 75.5,
            "jobs_in_progress": 1
        }"#;

        let req: HeartbeatRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.worker_address, "0x123abc");
        assert_eq!(req.gpu_count, Some(2));
        assert_eq!(req.gpu_utilization, Some(75.5));
    }
}
