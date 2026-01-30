//! # Earnings Database API
//!
//! Database-backed REST API endpoints for earnings and payments.
//! Provides earnings history, summaries, and charts.

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
pub struct EarningsDbState {
    pub pool: Arc<PgPool>,
}

impl EarningsDbState {
    /// Create a new EarningsDbState with the given database pool
    pub fn new(pool: PgPool) -> Self {
        Self { pool: Arc::new(pool) }
    }
}

/// Query parameters
#[derive(Debug, Deserialize)]
pub struct EarningsQuery {
    pub payment_type: Option<String>,
    pub token: Option<String>,
    pub period: Option<String>,  // 7d, 30d, 90d, all
    pub page: Option<i64>,
    pub limit: Option<i64>,
}

/// Payment/earning record
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct PaymentResponse {
    pub id: String,
    pub job_id: Option<String>,
    pub worker_address: String,
    pub amount: String,
    pub payment_type: String,
    pub token: String,
    pub privacy_enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub tx_hash: Option<String>,
    pub block_number: Option<i64>,
}

/// Earnings history response
#[derive(Debug, Serialize)]
pub struct EarningsHistoryResponse {
    pub payments: Vec<PaymentResponse>,
    pub total: i64,
    pub page: i64,
    pub limit: i64,
}

/// Earnings summary
#[derive(Debug, Serialize)]
pub struct EarningsSummaryResponse {
    pub total_earnings: String,
    pub pending_earnings: String,
    pub claimed_earnings: String,
    pub earnings_24h: String,
    pub earnings_7d: String,
    pub earnings_30d: String,
    pub by_type: Vec<EarningsByType>,
    pub by_token: Vec<EarningsByToken>,
    pub rank: Option<i64>,
    pub percentile: Option<f64>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct EarningsByType {
    pub payment_type: String,
    pub total: String,
    pub count: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct EarningsByToken {
    pub token: String,
    pub total: String,
    pub count: i64,
}

/// Earnings chart data point
#[derive(Debug, Serialize)]
pub struct EarningsChartPoint {
    pub date: chrono::NaiveDate,
    pub amount: String,
    pub count: i64,
}

/// Earnings chart response
#[derive(Debug, Serialize)]
pub struct EarningsChartResponse {
    pub data: Vec<EarningsChartPoint>,
    pub period: String,
    pub total: String,
}

/// Network earnings stats
#[derive(Debug, Serialize)]
pub struct NetworkEarningsStats {
    pub total_paid: String,
    pub total_payments: i64,
    pub avg_payment: Option<f64>,
    pub payments_24h: i64,
    pub amount_24h: String,
    pub top_earners: Vec<TopEarner>,
    pub by_type_distribution: Vec<TypeDistribution>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct TopEarner {
    pub address: String,
    pub total_earnings: String,
    pub payment_count: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct TypeDistribution {
    pub payment_type: String,
    pub total: String,
    pub percentage: f64,
}

/// Create earnings database router
pub fn earnings_db_routes(state: EarningsDbState) -> Router {
    Router::new()
        .route("/api/earnings/:address/summary", get(get_earnings_summary))
        .route("/api/earnings/:address/history", get(get_earnings_history))
        .route("/api/earnings/:address/chart", get(get_earnings_chart))
        .route("/api/earnings/:address/breakdown", get(get_earnings_breakdown))
        .route("/api/earnings/network/stats", get(get_network_earnings_stats))
        .route("/api/earnings/recent", get(get_recent_payments))
        .with_state(state)
}

/// Get earnings summary for an address
async fn get_earnings_summary(
    State(state): State<EarningsDbState>,
    Path(address): Path<String>,
) -> Result<Json<EarningsSummaryResponse>, (StatusCode, String)> {
    // Total earnings
    let total_earnings: String = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount), 0)::text FROM payments WHERE worker_address = $1"
    )
    .bind(&address)
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Get pending from worker table (rewards not yet claimed)
    let pending_earnings: String = sqlx::query_scalar(
        "SELECT COALESCE(total_earnings - (SELECT COALESCE(SUM(amount), 0) FROM payments WHERE worker_address = $1), 0)::text FROM workers WHERE address = $1"
    )
    .bind(&address)
    .fetch_optional(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .unwrap_or_else(|| "0".to_string());
    
    // Earnings by time period
    let earnings_24h: String = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount), 0)::text FROM payments WHERE worker_address = $1 AND created_at > NOW() - INTERVAL '24 hours'"
    )
    .bind(&address)
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let earnings_7d: String = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount), 0)::text FROM payments WHERE worker_address = $1 AND created_at > NOW() - INTERVAL '7 days'"
    )
    .bind(&address)
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let earnings_30d: String = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount), 0)::text FROM payments WHERE worker_address = $1 AND created_at > NOW() - INTERVAL '30 days'"
    )
    .bind(&address)
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // By type
    let by_type: Vec<EarningsByType> = sqlx::query_as(
        r#"
        SELECT payment_type, SUM(amount)::text as total, COUNT(*) as count
        FROM payments
        WHERE worker_address = $1
        GROUP BY payment_type
        ORDER BY total DESC
        "#
    )
    .bind(&address)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // By token
    let by_token: Vec<EarningsByToken> = sqlx::query_as(
        r#"
        SELECT token, SUM(amount)::text as total, COUNT(*) as count
        FROM payments
        WHERE worker_address = $1
        GROUP BY token
        ORDER BY total DESC
        "#
    )
    .bind(&address)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Rank among all earners
    let rank: Option<i64> = sqlx::query_scalar(
        r#"
        SELECT rank FROM (
            SELECT worker_address, RANK() OVER (ORDER BY SUM(amount) DESC) as rank
            FROM payments
            GROUP BY worker_address
        ) ranked
        WHERE worker_address = $1
        "#
    )
    .bind(&address)
    .fetch_optional(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Calculate percentile
    let total_workers: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT worker_address) FROM payments"
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let percentile = rank.map(|r| {
        if total_workers > 0 {
            ((total_workers - r + 1) as f64 / total_workers as f64) * 100.0
        } else {
            0.0
        }
    });
    
    Ok(Json(EarningsSummaryResponse {
        total_earnings: total_earnings.clone(),
        pending_earnings,
        claimed_earnings: total_earnings,
        earnings_24h,
        earnings_7d,
        earnings_30d,
        by_type,
        by_token,
        rank,
        percentile,
    }))
}

/// Get earnings history
async fn get_earnings_history(
    State(state): State<EarningsDbState>,
    Path(address): Path<String>,
    Query(params): Query<EarningsQuery>,
) -> Result<Json<EarningsHistoryResponse>, (StatusCode, String)> {
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(20).min(100);
    let offset = (page - 1) * limit;
    
    // Whitelist period to safe interval string
    let interval = match params.period.as_deref() {
        Some("7d") => "7 days",
        Some("30d") => "30 days",
        Some("90d") => "90 days",
        _ => "1000 years", // 'all'
    };

    // Build query with parameterized inputs (interval is whitelisted, safe to interpolate)
    let count_sql = format!(
        r#"
        SELECT COUNT(*) FROM payments
        WHERE worker_address = $1
          AND ($2::text IS NULL OR payment_type = $2)
          AND ($3::text IS NULL OR token = $3)
          AND created_at > NOW() - INTERVAL '{}'
        "#,
        interval
    );

    let total: i64 = sqlx::query_scalar(&count_sql)
    .bind(&address)
    .bind(&params.payment_type)
    .bind(&params.token)
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database query failed: {}", e)))?;

    let list_sql = format!(
        r#"
        SELECT
            id::text, job_id, worker_address, amount::text as amount,
            payment_type, token, COALESCE(privacy_enabled, false) as privacy_enabled,
            created_at, tx_hash, block_number
        FROM payments
        WHERE worker_address = $1
          AND ($2::text IS NULL OR payment_type = $2)
          AND ($3::text IS NULL OR token = $3)
          AND created_at > NOW() - INTERVAL '{}'
        ORDER BY created_at DESC
        LIMIT $4 OFFSET $5
        "#,
        interval
    );

    let payments: Vec<PaymentResponse> = sqlx::query_as(&list_sql)
    .bind(&address)
    .bind(&params.payment_type)
    .bind(&params.token)
    .bind(limit)
    .bind(offset)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database query failed: {}", e)))?;
    
    Ok(Json(EarningsHistoryResponse {
        payments,
        total,
        page,
        limit,
    }))
}

/// Get earnings chart data
async fn get_earnings_chart(
    State(state): State<EarningsDbState>,
    Path(address): Path<String>,
    Query(params): Query<EarningsQuery>,
) -> Result<Json<EarningsChartResponse>, (StatusCode, String)> {
    let period = params.period.as_deref().unwrap_or("30d");
    
    let interval = match period {
        "7d" => "7 days",
        "30d" => "30 days",
        "90d" => "90 days",
        _ => "30 days",
    };
    
    let data_rows: Vec<(chrono::NaiveDate, String, i64)> = sqlx::query_as(&format!(
        r#"
        SELECT 
            DATE(created_at) as date,
            COALESCE(SUM(amount), 0)::text as amount,
            COUNT(*) as count
        FROM payments
        WHERE worker_address = $1 AND created_at > NOW() - INTERVAL '{}'
        GROUP BY DATE(created_at)
        ORDER BY date
        "#,
        interval
    ))
    .bind(&address)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let data: Vec<EarningsChartPoint> = data_rows
        .into_iter()
        .map(|(date, amount, count)| EarningsChartPoint { date, amount, count })
        .collect();
    
    // Total for period
    let total: String = sqlx::query_scalar(&format!(
        "SELECT COALESCE(SUM(amount), 0)::text FROM payments WHERE worker_address = $1 AND created_at > NOW() - INTERVAL '{}'",
        interval
    ))
    .bind(&address)
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    Ok(Json(EarningsChartResponse {
        data,
        period: period.to_string(),
        total,
    }))
}

/// Get earnings breakdown by type
async fn get_earnings_breakdown(
    State(state): State<EarningsDbState>,
    Path(address): Path<String>,
) -> Result<Json<Vec<EarningsByType>>, (StatusCode, String)> {
    let breakdown: Vec<EarningsByType> = sqlx::query_as(
        r#"
        SELECT payment_type, SUM(amount)::text as total, COUNT(*) as count
        FROM payments
        WHERE worker_address = $1
        GROUP BY payment_type
        ORDER BY total DESC
        "#
    )
    .bind(&address)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    Ok(Json(breakdown))
}

/// Get network earnings statistics
async fn get_network_earnings_stats(
    State(state): State<EarningsDbState>,
) -> Result<Json<NetworkEarningsStats>, (StatusCode, String)> {
    // Total paid
    let total_paid: String = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount), 0)::text FROM payments"
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let total_payments: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM payments"
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let avg_payment: Option<f64> = sqlx::query_scalar(
        "SELECT AVG(amount::float8) FROM payments"
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let payments_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM payments WHERE created_at > NOW() - INTERVAL '24 hours'"
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let amount_24h: String = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount), 0)::text FROM payments WHERE created_at > NOW() - INTERVAL '24 hours'"
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Top earners
    let top_earners: Vec<TopEarner> = sqlx::query_as(
        r#"
        SELECT 
            worker_address as address, 
            SUM(amount)::text as total_earnings,
            COUNT(*) as payment_count
        FROM payments
        GROUP BY worker_address
        ORDER BY SUM(amount) DESC
        LIMIT 10
        "#
    )
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Type distribution
    let total_amount: f64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount::float8), 1) FROM payments"
    )
    .fetch_one(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let type_rows: Vec<(String, String)> = sqlx::query_as(
        r#"
        SELECT payment_type, SUM(amount)::text as total
        FROM payments
        GROUP BY payment_type
        ORDER BY SUM(amount) DESC
        "#
    )
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let by_type_distribution: Vec<TypeDistribution> = type_rows
        .into_iter()
        .map(|(payment_type, total)| {
            let amount: f64 = total.parse().unwrap_or(0.0);
            let percentage = if total_amount > 0.0 {
                (amount / total_amount) * 100.0
            } else {
                0.0
            };
            TypeDistribution {
                payment_type,
                total,
                percentage,
            }
        })
        .collect();
    
    Ok(Json(NetworkEarningsStats {
        total_paid,
        total_payments,
        avg_payment,
        payments_24h,
        amount_24h,
        top_earners,
        by_type_distribution,
    }))
}

/// Get recent payments network-wide
async fn get_recent_payments(
    State(state): State<EarningsDbState>,
    Query(params): Query<EarningsQuery>,
) -> Result<Json<Vec<PaymentResponse>>, (StatusCode, String)> {
    let limit = params.limit.unwrap_or(20).min(100);
    
    let payments: Vec<PaymentResponse> = sqlx::query_as(
        r#"
        SELECT 
            id::text, job_id, worker_address, amount::text as amount,
            payment_type, token, COALESCE(privacy_enabled, false) as privacy_enabled,
            created_at, tx_hash, block_number
        FROM payments 
        ORDER BY created_at DESC
        LIMIT $1
        "#
    )
    .bind(limit)
    .fetch_all(state.pool.as_ref())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    Ok(Json(payments))
}
