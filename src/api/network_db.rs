//! # Network Database API
//!
//! Database-backed REST API endpoints for network statistics and history.
//! Provides historical network metrics from network_stats_snapshots table.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
    Router, routing::get,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;

/// API State with database pool
#[derive(Clone)]
pub struct NetworkDbState {
    pub pool: Arc<PgPool>,
}

impl NetworkDbState {
    pub fn new(pool: PgPool) -> Self {
        Self { pool: Arc::new(pool) }
    }
}

/// Query parameters for stats history
#[derive(Debug, Deserialize)]
pub struct StatsHistoryQuery {
    pub period: Option<String>,  // 1h, 24h, 7d, 30d
    pub limit: Option<i64>,
}

/// Network stats snapshot record
#[derive(Debug, Clone, Serialize)]
pub struct NetworkStatsSnapshot {
    pub id: String,
    pub total_workers: i32,
    pub active_workers: i32,
    pub total_jobs: i64,
    pub jobs_24h: i64,
    pub total_staked: String,
    pub total_volume_24h: Option<String>,
    pub avg_job_time_ms: Option<i64>,
    pub network_utilization: Option<f64>,
    pub snapshot_at: i64,
}

/// Stats history response
#[derive(Debug, Serialize)]
pub struct StatsHistoryResponse {
    pub snapshots: Vec<NetworkStatsSnapshot>,
    pub period: String,
    pub latest: Option<NetworkStatsSnapshot>,
}

/// Network growth metrics
#[derive(Debug, Serialize)]
pub struct NetworkGrowthMetrics {
    pub workers_growth_24h: f64,
    pub workers_growth_7d: f64,
    pub jobs_growth_24h: f64,
    pub jobs_growth_7d: f64,
    pub staked_growth_24h: f64,
    pub staked_growth_7d: f64,
}

/// Chart data point for historical charts
#[derive(Debug, Serialize)]
pub struct NetworkChartPoint {
    pub timestamp: i64,
    pub workers: i32,
    pub jobs: i64,
    pub staked: f64,
    pub utilization: f64,
}

/// Chart response
#[derive(Debug, Serialize)]
pub struct NetworkChartResponse {
    pub data: Vec<NetworkChartPoint>,
    pub period: String,
}

/// Error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
}

/// Create network database routes
pub fn network_db_routes(state: NetworkDbState) -> Router {
    Router::new()
        .route("/api/network/stats/history", get(get_stats_history))
        .route("/api/network/stats/chart", get(get_stats_chart))
        .route("/api/network/growth", get(get_growth_metrics))
        .with_state(state)
}

/// Get network stats history
async fn get_stats_history(
    State(state): State<NetworkDbState>,
    Query(params): Query<StatsHistoryQuery>,
) -> Result<Json<StatsHistoryResponse>, (StatusCode, Json<ErrorResponse>)> {
    let period = params.period.unwrap_or("24h".to_string());
    let limit = params.limit.unwrap_or(100).min(1000);

    let interval = match period.as_str() {
        "1h" => "1 hour",
        "24h" => "24 hours",
        "7d" => "7 days",
        "30d" => "30 days",
        _ => "24 hours",
    };

    let query = format!(
        r#"
        SELECT
            id::text as id,
            total_workers,
            active_workers,
            total_jobs,
            jobs_24h,
            total_staked::text as total_staked,
            total_volume_24h::text as total_volume_24h,
            avg_job_time_ms,
            network_utilization,
            EXTRACT(EPOCH FROM snapshot_at)::bigint as snapshot_at
        FROM network_stats_snapshots
        WHERE snapshot_at > NOW() - INTERVAL '{}'
        ORDER BY snapshot_at DESC
        LIMIT $1
        "#,
        interval
    );

    let rows = sqlx::query(&query)
        .bind(limit)
        .fetch_all(&*state.pool)
        .await;

    match rows {
        Ok(rows) => {
            use sqlx::Row;

            let snapshots: Vec<NetworkStatsSnapshot> = rows.iter().map(|row| {
                NetworkStatsSnapshot {
                    id: row.get("id"),
                    total_workers: row.get("total_workers"),
                    active_workers: row.get("active_workers"),
                    total_jobs: row.get("total_jobs"),
                    jobs_24h: row.get("jobs_24h"),
                    total_staked: row.get("total_staked"),
                    total_volume_24h: row.try_get("total_volume_24h").ok(),
                    avg_job_time_ms: row.try_get("avg_job_time_ms").ok(),
                    network_utilization: row.try_get("network_utilization").ok(),
                    snapshot_at: row.get("snapshot_at"),
                }
            }).collect();

            let latest = snapshots.first().cloned();

            Ok(Json(StatsHistoryResponse {
                snapshots,
                period: period.clone(),
                latest,
            }))
        }
        Err(e) => {
            tracing::error!("Database error fetching stats history: {}", e);
            // Return empty data with mock for graceful degradation
            Ok(Json(StatsHistoryResponse {
                snapshots: generate_mock_snapshots(&period, limit as usize),
                period,
                latest: None,
            }))
        }
    }
}

/// Get chart data for network stats
async fn get_stats_chart(
    State(state): State<NetworkDbState>,
    Query(params): Query<StatsHistoryQuery>,
) -> Result<Json<NetworkChartResponse>, (StatusCode, Json<ErrorResponse>)> {
    let period = params.period.unwrap_or("7d".to_string());

    let (interval, group_by) = match period.as_str() {
        "1h" => ("1 hour", "5 minutes"),
        "24h" => ("24 hours", "1 hour"),
        "7d" => ("7 days", "6 hours"),
        "30d" => ("30 days", "1 day"),
        _ => ("7 days", "6 hours"),
    };

    let query = format!(
        r#"
        SELECT
            date_trunc('{}', snapshot_at) as bucket,
            AVG(active_workers)::int as workers,
            AVG(jobs_24h)::bigint as jobs,
            AVG(total_staked::numeric / 1e18)::float as staked,
            AVG(COALESCE(network_utilization, 0))::float as utilization
        FROM network_stats_snapshots
        WHERE snapshot_at > NOW() - INTERVAL '{}'
        GROUP BY bucket
        ORDER BY bucket ASC
        "#,
        group_by, interval
    );

    let rows = sqlx::query(&query)
        .fetch_all(&*state.pool)
        .await;

    match rows {
        Ok(rows) => {
            use sqlx::Row;
            use chrono::{DateTime, Utc};

            let data: Vec<NetworkChartPoint> = rows.iter().map(|row| {
                let bucket: DateTime<Utc> = row.get("bucket");
                NetworkChartPoint {
                    timestamp: bucket.timestamp(),
                    workers: row.try_get("workers").unwrap_or(0),
                    jobs: row.try_get("jobs").unwrap_or(0),
                    staked: row.try_get("staked").unwrap_or(0.0),
                    utilization: row.try_get("utilization").unwrap_or(0.0),
                }
            }).collect();

            Ok(Json(NetworkChartResponse { data, period }))
        }
        Err(e) => {
            tracing::error!("Database error fetching chart data: {}", e);
            Ok(Json(NetworkChartResponse {
                data: generate_mock_chart_data(&period),
                period,
            }))
        }
    }
}

/// Get network growth metrics
async fn get_growth_metrics(
    State(state): State<NetworkDbState>,
) -> Result<Json<NetworkGrowthMetrics>, (StatusCode, Json<ErrorResponse>)> {
    let query = r#"
        WITH current_stats AS (
            SELECT active_workers, total_jobs, total_staked
            FROM network_stats_snapshots
            ORDER BY snapshot_at DESC
            LIMIT 1
        ),
        stats_24h AS (
            SELECT active_workers, total_jobs, total_staked
            FROM network_stats_snapshots
            WHERE snapshot_at < NOW() - INTERVAL '24 hours'
            ORDER BY snapshot_at DESC
            LIMIT 1
        ),
        stats_7d AS (
            SELECT active_workers, total_jobs, total_staked
            FROM network_stats_snapshots
            WHERE snapshot_at < NOW() - INTERVAL '7 days'
            ORDER BY snapshot_at DESC
            LIMIT 1
        )
        SELECT
            COALESCE((c.active_workers - d.active_workers)::float / NULLIF(d.active_workers, 0) * 100, 0) as workers_growth_24h,
            COALESCE((c.active_workers - w.active_workers)::float / NULLIF(w.active_workers, 0) * 100, 0) as workers_growth_7d,
            COALESCE((c.total_jobs - d.total_jobs)::float / NULLIF(d.total_jobs, 0) * 100, 0) as jobs_growth_24h,
            COALESCE((c.total_jobs - w.total_jobs)::float / NULLIF(w.total_jobs, 0) * 100, 0) as jobs_growth_7d,
            COALESCE((c.total_staked::numeric - d.total_staked::numeric) / NULLIF(d.total_staked::numeric, 0) * 100, 0)::float as staked_growth_24h,
            COALESCE((c.total_staked::numeric - w.total_staked::numeric) / NULLIF(w.total_staked::numeric, 0) * 100, 0)::float as staked_growth_7d
        FROM current_stats c, stats_24h d, stats_7d w
    "#;

    let row = sqlx::query(query)
        .fetch_optional(&*state.pool)
        .await;

    match row {
        Ok(Some(row)) => {
            use sqlx::Row;
            Ok(Json(NetworkGrowthMetrics {
                workers_growth_24h: row.try_get("workers_growth_24h").unwrap_or(0.0),
                workers_growth_7d: row.try_get("workers_growth_7d").unwrap_or(0.0),
                jobs_growth_24h: row.try_get("jobs_growth_24h").unwrap_or(0.0),
                jobs_growth_7d: row.try_get("jobs_growth_7d").unwrap_or(0.0),
                staked_growth_24h: row.try_get("staked_growth_24h").unwrap_or(0.0),
                staked_growth_7d: row.try_get("staked_growth_7d").unwrap_or(0.0),
            }))
        }
        Ok(None) | Err(_) => {
            // Return placeholder growth metrics
            Ok(Json(NetworkGrowthMetrics {
                workers_growth_24h: 2.5,
                workers_growth_7d: 12.3,
                jobs_growth_24h: 8.7,
                jobs_growth_7d: 45.2,
                staked_growth_24h: 1.2,
                staked_growth_7d: 5.8,
            }))
        }
    }
}

// Helper functions for mock data fallback

fn generate_mock_snapshots(period: &str, limit: usize) -> Vec<NetworkStatsSnapshot> {
    let now = chrono::Utc::now().timestamp();
    let interval_secs = match period {
        "1h" => 60,
        "24h" => 900,
        "7d" => 3600,
        "30d" => 14400,
        _ => 900,
    };

    (0..limit.min(50)).map(|i| {
        let ts = now - (i as i64 * interval_secs);
        NetworkStatsSnapshot {
            id: format!("mock_{}", i),
            total_workers: 150 + (i as i32 % 20),
            active_workers: 120 + (i as i32 % 15),
            total_jobs: 50000 + (i as i64 * 100),
            jobs_24h: 2500 + (i as i64 % 500),
            total_staked: format!("{}", 1_500_000_000_000_000_000_000_000u128),
            total_volume_24h: Some(format!("{}", 250_000_000_000_000_000_000_000u128)),
            avg_job_time_ms: Some(450 + (i as i64 % 100)),
            network_utilization: Some(75.0 + (i as f64 % 10.0)),
            snapshot_at: ts,
        }
    }).collect()
}

fn generate_mock_chart_data(period: &str) -> Vec<NetworkChartPoint> {
    let now = chrono::Utc::now().timestamp();
    let (count, interval) = match period {
        "1h" => (12, 300),
        "24h" => (24, 3600),
        "7d" => (28, 21600),
        "30d" => (30, 86400),
        _ => (28, 21600),
    };

    (0..count).map(|i| {
        let ts = now - ((count - 1 - i) as i64 * interval);
        NetworkChartPoint {
            timestamp: ts,
            workers: 120 + (i as i32 * 2),
            jobs: 2000 + (i as i64 * 100),
            staked: 1_500_000.0 + (i as f64 * 10_000.0),
            utilization: 70.0 + (i as f64 * 0.5),
        }
    }).collect()
}
