//! # Trading API Endpoints
//!
//! REST API endpoints for OTC orderbook trading operations.
//! Provides orderbook data, order management, trade history, and market stats.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info};

/// Trading API state
pub struct TradingApiState {
    pub network: String,
    pub otc_orderbook_address: String,
    pub db_pool: Option<sqlx::PgPool>,
}

impl TradingApiState {
    pub fn new(network: &str, otc_orderbook_address: &str) -> Self {
        Self {
            network: network.to_string(),
            otc_orderbook_address: otc_orderbook_address.to_string(),
            db_pool: None,
        }
    }

    pub fn with_db(network: &str, otc_orderbook_address: &str, db_pool: sqlx::PgPool) -> Self {
        Self {
            network: network.to_string(),
            otc_orderbook_address: otc_orderbook_address.to_string(),
            db_pool: Some(db_pool),
        }
    }

    pub fn disabled(network: &str) -> Self {
        Self {
            network: network.to_string(),
            otc_orderbook_address: String::new(),
            db_pool: None,
        }
    }
}

/// Create trading routes
pub fn trading_routes(state: Arc<TradingApiState>) -> Router {
    Router::new()
        // Trading Pairs
        .route("/api/trading/pairs", get(get_trading_pairs))
        .route("/api/trading/pairs/:pair_id", get(get_pair_info))
        // Orderbook
        .route("/api/trading/orderbook/:pair_id", get(get_orderbook))
        .route("/api/trading/orderbook/:pair_id/depth", get(get_orderbook_depth))
        // Orders
        .route("/api/trading/orders", get(get_user_orders))
        .route("/api/trading/orders/:order_id", get(get_order))
        .route("/api/trading/orders/place", post(place_order))
        .route("/api/trading/orders/:order_id/cancel", post(cancel_order))
        // Trades
        .route("/api/trading/trades/:pair_id", get(get_trade_history))
        .route("/api/trading/trades/:pair_id/recent", get(get_recent_trades))
        // Market Stats
        .route("/api/trading/stats/:pair_id", get(get_market_stats))
        .route("/api/trading/stats/:pair_id/24h", get(get_24h_stats))
        .route("/api/trading/stats/:pair_id/twap", get(get_twap))
        .route("/api/trading/stats/:pair_id/price-history", get(get_price_history))
        // Global Stats
        .route("/api/trading/stats", get(get_global_trading_stats))
        .with_state(state)
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Trading pair info
#[derive(Debug, Serialize, Clone)]
pub struct TradingPairInfo {
    pub pair_id: u8,
    pub base_token: String,
    pub base_symbol: String,
    pub quote_token: String,
    pub quote_symbol: String,
    pub min_order_size: String,
    pub tick_size: String,
    pub is_active: bool,
    pub last_price: String,
    pub price_change_24h: f64,
    pub volume_24h: String,
}

/// Orderbook entry (aggregated by price level)
#[derive(Debug, Serialize, Clone)]
pub struct OrderbookLevel {
    pub price: String,
    pub amount: String,
    pub total: String,
    pub order_count: u32,
}

/// Full orderbook response
#[derive(Debug, Serialize)]
pub struct OrderbookResponse {
    pub pair_id: u8,
    pub bids: Vec<OrderbookLevel>,
    pub asks: Vec<OrderbookLevel>,
    pub best_bid: String,
    pub best_ask: String,
    pub spread: String,
    pub spread_percentage: f64,
    pub last_updated: u64,
}

/// Order info
#[derive(Debug, Serialize, Clone)]
pub struct OrderInfo {
    pub order_id: String,
    pub maker: String,
    pub pair_id: u8,
    pub side: String,
    pub order_type: String,
    pub price: String,
    pub amount: String,
    pub remaining: String,
    pub filled_percentage: f64,
    pub status: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub tx_hash: Option<String>,
}

/// Place order request
#[derive(Debug, Deserialize)]
pub struct PlaceOrderRequest {
    pub pair_id: u8,
    pub side: String,      // "buy" or "sell"
    pub order_type: String, // "limit" or "market"
    pub price: Option<String>,
    pub amount: String,
    pub expires_in_secs: Option<u64>,
}

/// Place order response
#[derive(Debug, Serialize)]
pub struct PlaceOrderResponse {
    pub success: bool,
    pub order_id: Option<String>,
    pub message: String,
    pub estimated_cost: Option<String>,
    pub transaction_data: Option<TransactionData>,
}

/// Transaction data for wallet signing
#[derive(Debug, Serialize)]
pub struct TransactionData {
    pub contract_address: String,
    pub function_name: String,
    pub calldata: Vec<String>,
}

/// Trade record
#[derive(Debug, Serialize, Clone)]
pub struct TradeInfo {
    pub trade_id: String,
    pub pair_id: u8,
    pub maker_order_id: String,
    pub taker_order_id: String,
    pub maker: String,
    pub taker: String,
    pub side: String,
    pub price: String,
    pub amount: String,
    pub quote_amount: String,
    pub maker_fee: String,
    pub taker_fee: String,
    pub executed_at: u64,
    pub tx_hash: Option<String>,
}

/// 24h market stats
#[derive(Debug, Serialize)]
pub struct MarketStats24h {
    pub pair_id: u8,
    pub volume_24h: String,
    pub volume_24h_usd: String,
    pub high_24h: String,
    pub low_24h: String,
    pub last_price: String,
    pub price_change_24h: String,
    pub price_change_percentage: f64,
    pub trade_count_24h: u64,
    pub avg_trade_size: String,
}

/// TWAP response
#[derive(Debug, Serialize)]
pub struct TwapResponse {
    pub pair_id: u8,
    pub twap: String,
    pub period_hours: u32,
    pub samples: u32,
    pub calculated_at: u64,
}

/// Price history entry
#[derive(Debug, Serialize, Clone)]
pub struct PriceSnapshot {
    pub price: String,
    pub timestamp: u64,
}

/// Global trading stats
#[derive(Debug, Serialize)]
pub struct GlobalTradingStats {
    pub total_orders: u64,
    pub total_trades: u64,
    pub total_volume_sage: String,
    pub total_volume_usd: String,
    pub active_pairs: u32,
    pub total_users: u64,
}

/// Query parameters for pagination
#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

/// Query parameters for user orders
#[derive(Debug, Deserialize)]
pub struct UserOrdersQuery {
    pub address: String,
    pub pair_id: Option<u8>,
    pub status: Option<String>,
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

/// Error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
}

// ============================================================================
// Handlers
// ============================================================================

/// Get all trading pairs
async fn get_trading_pairs(
    State(state): State<Arc<TradingApiState>>,
) -> Json<Vec<TradingPairInfo>> {
    debug!("Getting trading pairs");

    // Try to query from database if available
    if let Some(ref pool) = state.db_pool {
        let pairs_result = sqlx::query(
            r#"
            SELECT tp.pair_id, tp.base_token, tp.quote_token,
                   tp.min_order_size::text, tp.tick_size::text, tp.is_active,
                   COALESCE(stats.last_price, '100000000000000000')::text as last_price,
                   COALESCE(stats.price_change_pct, 0.0) as price_change_24h,
                   COALESCE(stats.volume_24h, '0')::text as volume_24h
            FROM trading_pairs tp
            LEFT JOIN LATERAL (
                SELECT
                    (SELECT price::text FROM trades WHERE pair_id = tp.pair_id ORDER BY executed_at DESC LIMIT 1) as last_price,
                    COALESCE(SUM(amount), 0)::text as volume_24h,
                    CASE
                        WHEN (SELECT price FROM trades WHERE pair_id = tp.pair_id
                              AND executed_at > NOW() - INTERVAL '24 hours'
                              ORDER BY executed_at ASC LIMIT 1) > 0
                        THEN ((SELECT price FROM trades WHERE pair_id = tp.pair_id ORDER BY executed_at DESC LIMIT 1)::float -
                              (SELECT price FROM trades WHERE pair_id = tp.pair_id
                               AND executed_at > NOW() - INTERVAL '24 hours'
                               ORDER BY executed_at ASC LIMIT 1)::float) /
                              (SELECT price FROM trades WHERE pair_id = tp.pair_id
                               AND executed_at > NOW() - INTERVAL '24 hours'
                               ORDER BY executed_at ASC LIMIT 1)::float * 100
                        ELSE 0.0
                    END as price_change_pct
                FROM trades
                WHERE pair_id = tp.pair_id AND executed_at > NOW() - INTERVAL '24 hours'
            ) stats ON true
            WHERE tp.is_active = true
            ORDER BY tp.pair_id
            "#
        )
        .fetch_all(pool)
        .await;

        if let Ok(rows) = pairs_result {
            use sqlx::Row;

            let pairs: Vec<TradingPairInfo> = rows.iter().map(|row| {
                let pair_id: i32 = row.get("pair_id");
                let base_token: String = row.get("base_token");
                let quote_token: String = row.get("quote_token");

                // Derive symbols from token addresses using proper mapping
                let base_symbol = derive_symbol(&base_token);
                let quote_symbol = derive_symbol(&quote_token);

                TradingPairInfo {
                    pair_id: pair_id as u8,
                    base_token,
                    base_symbol: base_symbol.to_string(),
                    quote_token,
                    quote_symbol: quote_symbol.to_string(),
                    min_order_size: row.get("min_order_size"),
                    tick_size: row.get("tick_size"),
                    is_active: row.get("is_active"),
                    last_price: row.get("last_price"),
                    price_change_24h: row.get("price_change_24h"),
                    volume_24h: row.get("volume_24h"),
                }
            }).collect();

            if !pairs.is_empty() {
                return Json(pairs);
            }
        }
    }

    // Fallback: return configured trading pairs with correct Sepolia addresses
    // No fake volume/price data - only the pair configuration
    let pairs = vec![
        TradingPairInfo {
            pair_id: 0,
            // SAGE token on Sepolia
            base_token: "0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850".to_string(),
            base_symbol: "SAGE".to_string(),
            // USDC on Sepolia
            quote_token: "0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8".to_string(),
            quote_symbol: "USDC".to_string(),
            min_order_size: "1000000000000000000".to_string(), // 1 SAGE min
            tick_size: "100000000000000".to_string(), // 0.0001 tick
            is_active: true,
            last_price: "0".to_string(), // No fake price
            price_change_24h: 0.0,
            volume_24h: "0".to_string(), // No fake volume
        },
        TradingPairInfo {
            pair_id: 1,
            // SAGE token on Sepolia
            base_token: "0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850".to_string(),
            base_symbol: "SAGE".to_string(),
            // STRK on Starknet
            quote_token: "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d".to_string(),
            quote_symbol: "STRK".to_string(),
            min_order_size: "1000000000000000000".to_string(), // 1 SAGE min
            tick_size: "100000000000000".to_string(), // 0.0001 tick
            is_active: true,
            last_price: "0".to_string(), // No fake price
            price_change_24h: 0.0,
            volume_24h: "0".to_string(), // No fake volume
        },
    ];

    Json(pairs)
}

/// Get specific pair info
async fn get_pair_info(
    State(state): State<Arc<TradingApiState>>,
    Path(pair_id): Path<u8>,
) -> Result<Json<TradingPairInfo>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Getting pair info for pair_id: {}", pair_id);

    // Query from database if available
    if let Some(ref pool) = state.db_pool {
        let pair_result = sqlx::query(
            r#"
            SELECT tp.pair_id, tp.base_token, tp.quote_token, tp.base_symbol, tp.quote_symbol,
                   tp.min_order_size::text, tp.tick_size::text, tp.is_active
            FROM trading_pairs tp
            WHERE tp.pair_id = $1
            "#
        )
        .bind(pair_id as i32)
        .fetch_optional(pool)
        .await;

        // Get 24h stats for this pair
        let stats_result = sqlx::query(
            r#"
            SELECT
                (SELECT price::text FROM trades WHERE pair_id = $1 ORDER BY executed_at DESC LIMIT 1) as last_price,
                COALESCE(SUM(amount), 0)::text as volume_24h,
                (SELECT price::float FROM trades WHERE pair_id = $1 ORDER BY executed_at DESC LIMIT 1) as last_price_f,
                (SELECT price::float FROM trades WHERE pair_id = $1
                 AND executed_at > NOW() - INTERVAL '24 hours'
                 ORDER BY executed_at ASC LIMIT 1) as first_price_f
            FROM trades
            WHERE pair_id = $1 AND executed_at > NOW() - INTERVAL '24 hours'
            "#
        )
        .bind(pair_id as i32)
        .fetch_optional(pool)
        .await;

        if let Ok(Some(row)) = pair_result {
            use sqlx::Row;

            let base_token: String = row.get("base_token");
            let quote_token: String = row.get("quote_token");

            // Try to get symbols from DB, or derive from token address
            let base_symbol: String = row.try_get("base_symbol")
                .unwrap_or_else(|_| derive_symbol(&base_token));
            let quote_symbol: String = row.try_get("quote_symbol")
                .unwrap_or_else(|_| derive_symbol(&quote_token));

            let (last_price, volume_24h, price_change_24h) = if let Ok(Some(stats)) = stats_result {
                let last_price: String = stats.try_get("last_price")
                    .unwrap_or_else(|_| "100000000000000000".to_string());
                let volume_24h: String = stats.get("volume_24h");
                let last_price_f: f64 = stats.try_get("last_price_f").unwrap_or(0.1);
                let first_price_f: f64 = stats.try_get("first_price_f").unwrap_or(last_price_f);
                let price_change = if first_price_f > 0.0 {
                    ((last_price_f - first_price_f) / first_price_f) * 100.0
                } else {
                    0.0
                };
                (last_price, volume_24h, price_change)
            } else {
                ("100000000000000000".to_string(), "0".to_string(), 0.0)
            };

            return Ok(Json(TradingPairInfo {
                pair_id: row.get::<i32, _>("pair_id") as u8,
                base_token,
                base_symbol,
                quote_token,
                quote_symbol,
                min_order_size: row.get("min_order_size"),
                tick_size: row.get("tick_size"),
                is_active: row.get("is_active"),
                last_price,
                price_change_24h,
                volume_24h,
            }));
        }
    }

    // Fallback for known pairs with correct Sepolia addresses
    let pair = match pair_id {
        0 => TradingPairInfo {
            pair_id: 0,
            // SAGE token on Sepolia
            base_token: "0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850".to_string(),
            base_symbol: "SAGE".to_string(),
            // USDC on Sepolia
            quote_token: "0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8".to_string(),
            quote_symbol: "USDC".to_string(),
            min_order_size: "1000000000000000000".to_string(), // 1 SAGE min
            tick_size: "100000000000000".to_string(), // 0.0001 tick
            is_active: true,
            last_price: "0".to_string(), // No fake price
            price_change_24h: 0.0,
            volume_24h: "0".to_string(),
        },
        1 => TradingPairInfo {
            pair_id: 1,
            // SAGE token on Sepolia
            base_token: "0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850".to_string(),
            base_symbol: "SAGE".to_string(),
            // STRK on Starknet
            quote_token: "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d".to_string(),
            quote_symbol: "STRK".to_string(),
            min_order_size: "1000000000000000000".to_string(), // 1 SAGE min
            tick_size: "100000000000000".to_string(), // 0.0001 tick
            is_active: true,
            last_price: "0".to_string(), // No fake price
            price_change_24h: 0.0,
            volume_24h: "0".to_string(),
        },
        _ => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Trading pair not found".to_string(),
                    code: "PAIR_NOT_FOUND".to_string(),
                }),
            ));
        }
    };

    Ok(Json(pair))
}

/// Get orderbook for a pair
async fn get_orderbook(
    State(state): State<Arc<TradingApiState>>,
    Path(pair_id): Path<u8>,
    Query(params): Query<PaginationQuery>,
) -> Result<Json<OrderbookResponse>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Getting orderbook for pair_id: {}", pair_id);

    let depth = params.limit.unwrap_or(20).min(50) as i64;

    // Try to query from database if available
    if let Some(ref pool) = state.db_pool {
        // Query bids aggregated by price
        let bid_rows = sqlx::query(
            r#"
            SELECT price::text, SUM(remaining_amount)::text as amount, COUNT(*)::integer as order_count
            FROM orders
            WHERE pair_id = $1 AND side = 'buy' AND status = 'open'
            GROUP BY price
            ORDER BY price DESC
            LIMIT $2
            "#
        )
        .bind(pair_id as i32)
        .bind(depth)
        .fetch_all(pool)
        .await;

        // Query asks aggregated by price
        let ask_rows = sqlx::query(
            r#"
            SELECT price::text, SUM(remaining_amount)::text as amount, COUNT(*)::integer as order_count
            FROM orders
            WHERE pair_id = $1 AND side = 'sell' AND status = 'open'
            GROUP BY price
            ORDER BY price ASC
            LIMIT $2
            "#
        )
        .bind(pair_id as i32)
        .bind(depth)
        .fetch_all(pool)
        .await;

        // If database queries succeed, use real data
        if let (Ok(bids_data), Ok(asks_data)) = (bid_rows, ask_rows) {
            use sqlx::Row;

            let bids: Vec<OrderbookLevel> = bids_data.iter().map(|row| {
                let price: String = row.get("price");
                let amount: String = row.get("amount");
                let order_count: i32 = row.get("order_count");
                let price_f: f64 = price.parse().unwrap_or(0.0);
                let amount_f: f64 = amount.parse().unwrap_or(0.0);
                OrderbookLevel {
                    price: price.clone(),
                    amount: amount.clone(),
                    total: format!("{:.0}", price_f * amount_f / 1e18),
                    order_count: order_count as u32,
                }
            }).collect();

            let asks: Vec<OrderbookLevel> = asks_data.iter().map(|row| {
                let price: String = row.get("price");
                let amount: String = row.get("amount");
                let order_count: i32 = row.get("order_count");
                let price_f: f64 = price.parse().unwrap_or(0.0);
                let amount_f: f64 = amount.parse().unwrap_or(0.0);
                OrderbookLevel {
                    price: price.clone(),
                    amount: amount.clone(),
                    total: format!("{:.0}", price_f * amount_f / 1e18),
                    order_count: order_count as u32,
                }
            }).collect();

            let best_bid = bids.first().map(|b| b.price.clone()).unwrap_or_default();
            let best_ask = asks.first().map(|a| a.price.clone()).unwrap_or_default();

            let best_bid_f64: f64 = best_bid.parse().unwrap_or(0.0) / 1e18;
            let best_ask_f64: f64 = best_ask.parse().unwrap_or(0.0) / 1e18;
            let spread = best_ask_f64 - best_bid_f64;
            let spread_pct = if best_bid_f64 > 0.0 { (spread / best_bid_f64) * 100.0 } else { 0.0 };

            return Ok(Json(OrderbookResponse {
                pair_id,
                bids,
                asks,
                best_bid,
                best_ask,
                spread: format!("{:.18}", spread * 1e18),
                spread_percentage: spread_pct,
                last_updated: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            }));
        }
    }

    // Return empty orderbook when no data available (no mock data)
    Ok(Json(OrderbookResponse {
        pair_id,
        bids: Vec::new(),
        asks: Vec::new(),
        best_bid: "0".to_string(),
        best_ask: "0".to_string(),
        spread: "0".to_string(),
        spread_percentage: 0.0,
        last_updated: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    }))
}

/// Get orderbook depth (simplified)
async fn get_orderbook_depth(
    State(state): State<Arc<TradingApiState>>,
    Path(pair_id): Path<u8>,
) -> Result<Json<OrderbookResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Same as orderbook but with limited depth
    let query = PaginationQuery { page: None, limit: Some(10) };
    get_orderbook(State(state), Path(pair_id), Query(query)).await
}

/// Get user orders
async fn get_user_orders(
    State(state): State<Arc<TradingApiState>>,
    Query(params): Query<UserOrdersQuery>,
) -> Result<Json<Vec<OrderInfo>>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Getting orders for user: {}", params.address);

    if !is_valid_starknet_address(&params.address) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid Starknet address".to_string(),
                code: "INVALID_ADDRESS".to_string(),
            }),
        ));
    }

    let limit = params.limit.unwrap_or(50).min(100) as i64;
    let offset = ((params.page.unwrap_or(1) - 1) * params.limit.unwrap_or(50)) as i64;

    // Try to query from database if available
    if let Some(ref pool) = state.db_pool {
        let order_rows = sqlx::query(
            r#"
            SELECT order_id, maker_address, pair_id, side, order_type,
                   price::text, original_amount::text, remaining_amount::text,
                   filled_amount::text, status,
                   EXTRACT(EPOCH FROM created_at)::bigint as created_at,
                   EXTRACT(EPOCH FROM expires_at)::bigint as expires_at,
                   tx_hash
            FROM orders
            WHERE maker_address = $1
              AND ($2::integer IS NULL OR pair_id = $2)
              AND ($3::text IS NULL OR status = $3)
            ORDER BY created_at DESC
            LIMIT $4 OFFSET $5
            "#
        )
        .bind(&params.address)
        .bind(params.pair_id.map(|p| p as i32))
        .bind(&params.status)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await;

        if let Ok(rows) = order_rows {
            use sqlx::Row;

            let orders: Vec<OrderInfo> = rows.iter().map(|row| {
                let original_amount: String = row.get("original_amount");
                let filled_amount: String = row.get("filled_amount");
                let original_f: f64 = original_amount.parse().unwrap_or(1.0);
                let filled_f: f64 = filled_amount.parse().unwrap_or(0.0);
                let filled_pct = if original_f > 0.0 { (filled_f / original_f) * 100.0 } else { 0.0 };

                OrderInfo {
                    order_id: row.get::<String, _>("order_id"),
                    maker: row.get::<String, _>("maker_address"),
                    pair_id: row.get::<i32, _>("pair_id") as u8,
                    side: row.get::<String, _>("side"),
                    order_type: row.get::<String, _>("order_type"),
                    price: row.get::<String, _>("price"),
                    amount: original_amount,
                    remaining: row.get::<String, _>("remaining_amount"),
                    filled_percentage: filled_pct,
                    status: row.get::<String, _>("status"),
                    created_at: row.get::<i64, _>("created_at") as u64,
                    expires_at: row.try_get::<i64, _>("expires_at").unwrap_or(0) as u64,
                    tx_hash: row.try_get::<String, _>("tx_hash").ok(),
                }
            }).collect();

            return Ok(Json(orders));
        }
    }

    // Return empty list when no database available
    // This avoids showing misleading mock orders
    Ok(Json(Vec::new()))
}

/// Get specific order
async fn get_order(
    State(state): State<Arc<TradingApiState>>,
    Path(order_id): Path<String>,
) -> Result<Json<OrderInfo>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Getting order: {}", order_id);

    // Try to query from database if available
    if let Some(ref pool) = state.db_pool {
        let order_row = sqlx::query(
            r#"
            SELECT order_id, maker_address, pair_id, side, order_type,
                   price::text, original_amount::text, remaining_amount::text,
                   filled_amount::text, status,
                   EXTRACT(EPOCH FROM created_at)::bigint as created_at,
                   EXTRACT(EPOCH FROM expires_at)::bigint as expires_at,
                   tx_hash
            FROM orders
            WHERE order_id = $1
            "#
        )
        .bind(&order_id)
        .fetch_optional(pool)
        .await;

        if let Ok(Some(row)) = order_row {
            use sqlx::Row;

            let original_amount: String = row.get("original_amount");
            let filled_amount: String = row.get("filled_amount");
            let original_f: f64 = original_amount.parse().unwrap_or(1.0);
            let filled_f: f64 = filled_amount.parse().unwrap_or(0.0);
            let filled_pct = if original_f > 0.0 { (filled_f / original_f) * 100.0 } else { 0.0 };

            return Ok(Json(OrderInfo {
                order_id: row.get::<String, _>("order_id"),
                maker: row.get::<String, _>("maker_address"),
                pair_id: row.get::<i32, _>("pair_id") as u8,
                side: row.get::<String, _>("side"),
                order_type: row.get::<String, _>("order_type"),
                price: row.get::<String, _>("price"),
                amount: original_amount,
                remaining: row.get::<String, _>("remaining_amount"),
                filled_percentage: filled_pct,
                status: row.get::<String, _>("status"),
                created_at: row.get::<i64, _>("created_at") as u64,
                expires_at: row.try_get::<i64, _>("expires_at").unwrap_or(0) as u64,
                tx_hash: row.try_get::<String, _>("tx_hash").ok(),
            }));
        }
    }

    // Order not found
    Err((
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "Order not found".to_string(),
            code: "ORDER_NOT_FOUND".to_string(),
        }),
    ))
}

/// Place order (returns transaction data for wallet signing)
async fn place_order(
    State(state): State<Arc<TradingApiState>>,
    Json(request): Json<PlaceOrderRequest>,
) -> Result<Json<PlaceOrderResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!(
        "Place order request: pair={}, side={}, type={}, amount={}",
        request.pair_id, request.side, request.order_type, request.amount
    );

    // Validate side
    if request.side != "buy" && request.side != "sell" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid order side. Must be 'buy' or 'sell'".to_string(),
                code: "INVALID_SIDE".to_string(),
            }),
        ));
    }

    // Validate order type
    if request.order_type != "limit" && request.order_type != "market" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid order type. Must be 'limit' or 'market'".to_string(),
                code: "INVALID_ORDER_TYPE".to_string(),
            }),
        ));
    }

    // For limit orders, price is required
    if request.order_type == "limit" && request.price.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Price is required for limit orders".to_string(),
                code: "PRICE_REQUIRED".to_string(),
            }),
        ));
    }

    // Build transaction data for wallet signing
    let function_name = if request.order_type == "limit" {
        "place_limit_order"
    } else {
        "place_market_order"
    };

    let side_felt = if request.side == "buy" { "0x0" } else { "0x1" };
    let expires_in = request.expires_in_secs.unwrap_or(604800).to_string(); // Default 7 days

    let calldata = if request.order_type == "limit" {
        vec![
            request.pair_id.to_string(),
            side_felt.to_string(),
            request.price.clone().unwrap_or_default(),
            "0".to_string(), // price high (u256)
            request.amount.clone(),
            "0".to_string(), // amount high (u256)
            expires_in,
        ]
    } else {
        vec![
            request.pair_id.to_string(),
            side_felt.to_string(),
            request.amount.clone(),
            "0".to_string(), // amount high (u256)
        ]
    };

    Ok(Json(PlaceOrderResponse {
        success: true,
        order_id: None, // Order ID assigned after on-chain execution
        message: "Transaction data ready for wallet signing".to_string(),
        estimated_cost: Some("~0.001 ETH".to_string()),
        transaction_data: Some(TransactionData {
            contract_address: state.otc_orderbook_address.clone(),
            function_name: function_name.to_string(),
            calldata,
        }),
    }))
}

/// Cancel order (returns transaction data for wallet signing)
async fn cancel_order(
    State(state): State<Arc<TradingApiState>>,
    Path(order_id): Path<String>,
) -> Result<Json<PlaceOrderResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Cancel order request: order_id={}", order_id);

    Ok(Json(PlaceOrderResponse {
        success: true,
        order_id: Some(order_id.clone()),
        message: "Transaction data ready for wallet signing".to_string(),
        estimated_cost: Some("~0.0005 ETH".to_string()),
        transaction_data: Some(TransactionData {
            contract_address: state.otc_orderbook_address.clone(),
            function_name: "cancel_order".to_string(),
            calldata: vec![order_id, "0".to_string()], // order_id as u256 (low, high)
        }),
    }))
}

/// Get trade history for a pair
async fn get_trade_history(
    State(state): State<Arc<TradingApiState>>,
    Path(pair_id): Path<u8>,
    Query(params): Query<PaginationQuery>,
) -> Result<Json<Vec<TradeInfo>>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Getting trade history for pair: {}", pair_id);

    let limit = params.limit.unwrap_or(50).min(100) as i64;

    // Try to query from database if available
    if let Some(ref pool) = state.db_pool {
        let trade_rows = sqlx::query(
            r#"
            SELECT trade_id, pair_id, maker_order_id, taker_order_id,
                   maker_address, taker_address, side,
                   price::text, amount::text, quote_amount::text,
                   maker_fee::text, taker_fee::text,
                   EXTRACT(EPOCH FROM executed_at)::bigint as executed_at,
                   tx_hash
            FROM trades
            WHERE pair_id = $1
            ORDER BY executed_at DESC
            LIMIT $2
            "#
        )
        .bind(pair_id as i32)
        .bind(limit)
        .fetch_all(pool)
        .await;

        if let Ok(rows) = trade_rows {
            use sqlx::Row;

            let trades: Vec<TradeInfo> = rows.iter().map(|row| {
                TradeInfo {
                    trade_id: row.get::<String, _>("trade_id"),
                    pair_id: row.get::<i32, _>("pair_id") as u8,
                    maker_order_id: row.get::<String, _>("maker_order_id"),
                    taker_order_id: row.try_get::<String, _>("taker_order_id").unwrap_or_default(),
                    maker: row.get::<String, _>("maker_address"),
                    taker: row.get::<String, _>("taker_address"),
                    side: row.get::<String, _>("side"),
                    price: row.get::<String, _>("price"),
                    amount: row.get::<String, _>("amount"),
                    quote_amount: row.get::<String, _>("quote_amount"),
                    maker_fee: row.try_get::<String, _>("maker_fee").unwrap_or_default(),
                    taker_fee: row.try_get::<String, _>("taker_fee").unwrap_or_default(),
                    executed_at: row.get::<i64, _>("executed_at") as u64,
                    tx_hash: row.try_get::<String, _>("tx_hash").ok(),
                }
            }).collect();

            return Ok(Json(trades));
        }
    }

    // Return empty list when no database or no trades available
    // This avoids showing misleading mock data
    Ok(Json(Vec::new()))
}

/// Get recent trades (last 20)
async fn get_recent_trades(
    State(state): State<Arc<TradingApiState>>,
    Path(pair_id): Path<u8>,
) -> Result<Json<Vec<TradeInfo>>, (StatusCode, Json<ErrorResponse>)> {
    let query = PaginationQuery { page: None, limit: Some(20) };
    get_trade_history(State(state), Path(pair_id), Query(query)).await
}

/// Get 24h market stats
async fn get_24h_stats(
    State(state): State<Arc<TradingApiState>>,
    Path(pair_id): Path<u8>,
) -> Result<Json<MarketStats24h>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Getting 24h stats for pair: {}", pair_id);

    // Try to query from database if available
    if let Some(ref pool) = state.db_pool {
        let stats_row = sqlx::query(
            r#"
            SELECT
                COALESCE(MAX(price), 0)::text as high_24h,
                COALESCE(MIN(price), 0)::text as low_24h,
                COALESCE(SUM(amount), 0)::text as volume_24h,
                COUNT(*)::bigint as trade_count_24h
            FROM trades
            WHERE pair_id = $1
              AND executed_at > NOW() - INTERVAL '24 hours'
            "#
        )
        .bind(pair_id as i32)
        .fetch_one(pool)
        .await;

        let last_trade = sqlx::query(
            r#"
            SELECT price::text as last_price
            FROM trades
            WHERE pair_id = $1
            ORDER BY executed_at DESC
            LIMIT 1
            "#
        )
        .bind(pair_id as i32)
        .fetch_optional(pool)
        .await;

        let first_trade = sqlx::query(
            r#"
            SELECT price::text as first_price
            FROM trades
            WHERE pair_id = $1
              AND executed_at > NOW() - INTERVAL '24 hours'
            ORDER BY executed_at ASC
            LIMIT 1
            "#
        )
        .bind(pair_id as i32)
        .fetch_optional(pool)
        .await;

        if let Ok(row) = stats_row {
            use sqlx::Row;

            let high_24h: String = row.get("high_24h");
            let low_24h: String = row.get("low_24h");
            let volume_24h: String = row.get("volume_24h");
            let trade_count_24h: i64 = row.get("trade_count_24h");

            let last_price = last_trade
                .ok()
                .flatten()
                .map(|r| r.get::<String, _>("last_price"))
                .unwrap_or_else(|| "100000000000000000".to_string());

            let first_price = first_trade
                .ok()
                .flatten()
                .map(|r| r.get::<String, _>("first_price"))
                .unwrap_or_else(|| last_price.clone());

            let last_price_f: f64 = last_price.parse().unwrap_or(0.0);
            let first_price_f: f64 = first_price.parse().unwrap_or(0.0);
            let price_change = last_price_f - first_price_f;
            let price_change_pct = if first_price_f > 0.0 {
                (price_change / first_price_f) * 100.0
            } else {
                0.0
            };

            let volume_f: f64 = volume_24h.parse().unwrap_or(0.0);
            let avg_trade = if trade_count_24h > 0 {
                volume_f / trade_count_24h as f64
            } else {
                0.0
            };

            return Ok(Json(MarketStats24h {
                pair_id,
                volume_24h: volume_24h.clone(),
                volume_24h_usd: format!("{:.0}", volume_f * 0.10), // Assume $0.10/SAGE for USD
                high_24h,
                low_24h,
                last_price,
                price_change_24h: format!("{:.0}", price_change),
                price_change_percentage: price_change_pct,
                trade_count_24h: trade_count_24h as u64,
                avg_trade_size: format!("{:.0}", avg_trade),
            }));
        }
    }

    // Return empty/zero data when no database or no trades available
    // This avoids showing misleading mock data
    Ok(Json(MarketStats24h {
        pair_id,
        volume_24h: "0".to_string(),
        volume_24h_usd: "0".to_string(),
        high_24h: "0".to_string(),
        low_24h: "0".to_string(),
        last_price: "0".to_string(),
        price_change_24h: "0".to_string(),
        price_change_percentage: 0.0,
        trade_count_24h: 0,
        avg_trade_size: "0".to_string(),
    }))
}

/// Get market stats (alias for 24h stats)
async fn get_market_stats(
    state: State<Arc<TradingApiState>>,
    path: Path<u8>,
) -> Result<Json<MarketStats24h>, (StatusCode, Json<ErrorResponse>)> {
    get_24h_stats(state, path).await
}

/// Get TWAP (Time-Weighted Average Price)
///
/// Calculates TWAP from indexed trade data using time-weighted averaging.
async fn get_twap(
    State(state): State<Arc<TradingApiState>>,
    Path(pair_id): Path<u8>,
) -> Result<Json<TwapResponse>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Getting TWAP for pair: {}", pair_id);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Calculate TWAP from indexed trade data
    if let Some(ref pool) = state.db_pool {
        // Get trades from last 24 hours grouped into time buckets (5-minute intervals)
        let twap_result = sqlx::query(
            r#"
            WITH time_buckets AS (
                SELECT
                    date_trunc('hour', executed_at) +
                    (EXTRACT(minute FROM executed_at)::integer / 5 * interval '5 minutes') as bucket_time,
                    price::numeric as price,
                    amount::numeric as amount,
                    LEAD(executed_at) OVER (ORDER BY executed_at) as next_trade_time,
                    executed_at
                FROM trades
                WHERE pair_id = $1
                  AND executed_at > NOW() - INTERVAL '24 hours'
            ),
            weighted_prices AS (
                SELECT
                    bucket_time,
                    AVG(price) as avg_price,
                    SUM(amount) as volume,
                    -- Time weight: duration this price was effective
                    EXTRACT(EPOCH FROM
                        COALESCE(next_trade_time, NOW()) - executed_at
                    ) as time_weight
                FROM time_buckets
                GROUP BY bucket_time, next_trade_time, executed_at
            )
            SELECT
                COALESCE(
                    SUM(avg_price * time_weight) / NULLIF(SUM(time_weight), 0),
                    0
                )::text as twap,
                COUNT(DISTINCT bucket_time)::integer as samples
            FROM weighted_prices
            "#
        )
        .bind(pair_id as i32)
        .fetch_optional(pool)
        .await;

        if let Ok(Some(row)) = twap_result {
            use sqlx::Row;

            let twap: String = row.get("twap");
            let samples: i32 = row.get("samples");

            // If we have valid TWAP data, return it
            if samples > 0 {
                return Ok(Json(TwapResponse {
                    pair_id,
                    twap,
                    period_hours: 24,
                    samples: samples as u32,
                    calculated_at: now,
                }));
            }
        }

        // Fallback: use simple average of recent prices if no time-weighted data
        let simple_avg = sqlx::query(
            r#"
            SELECT
                COALESCE(AVG(price), 100000000000000000)::text as avg_price,
                COUNT(*)::integer as trade_count
            FROM trades
            WHERE pair_id = $1
              AND executed_at > NOW() - INTERVAL '24 hours'
            "#
        )
        .bind(pair_id as i32)
        .fetch_optional(pool)
        .await;

        if let Ok(Some(row)) = simple_avg {
            use sqlx::Row;

            let avg_price: String = row.get("avg_price");
            let trade_count: i32 = row.get("trade_count");

            if trade_count > 0 {
                return Ok(Json(TwapResponse {
                    pair_id,
                    twap: avg_price,
                    period_hours: 24,
                    samples: trade_count as u32,
                    calculated_at: now,
                }));
            }
        }
    }

    // No database or no trades - return zero (no mock data)
    Ok(Json(TwapResponse {
        pair_id,
        twap: "0".to_string(),
        period_hours: 24,
        samples: 0,
        calculated_at: now,
    }))
}

/// Get price history (hourly snapshots)
///
/// Returns historical price data aggregated by hour from trade data.
async fn get_price_history(
    State(state): State<Arc<TradingApiState>>,
    Path(pair_id): Path<u8>,
    Query(params): Query<PaginationQuery>,
) -> Result<Json<Vec<PriceSnapshot>>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Getting price history for pair: {}", pair_id);

    let limit = params.limit.unwrap_or(24).min(168) as i64; // Max 7 days

    // Query hourly price snapshots from trade data
    if let Some(ref pool) = state.db_pool {
        let history_result = sqlx::query(
            r#"
            WITH hourly_prices AS (
                SELECT
                    date_trunc('hour', executed_at) as hour,
                    -- Use closing price (last trade in the hour)
                    (ARRAY_AGG(price::text ORDER BY executed_at DESC))[1] as close_price,
                    EXTRACT(EPOCH FROM date_trunc('hour', executed_at))::bigint as timestamp
                FROM trades
                WHERE pair_id = $1
                  AND executed_at > NOW() - INTERVAL '7 days'
                GROUP BY date_trunc('hour', executed_at)
                ORDER BY hour DESC
                LIMIT $2
            )
            SELECT close_price as price, timestamp
            FROM hourly_prices
            ORDER BY timestamp ASC
            "#
        )
        .bind(pair_id as i32)
        .bind(limit)
        .fetch_all(pool)
        .await;

        if let Ok(rows) = history_result {
            if !rows.is_empty() {
                use sqlx::Row;

                let snapshots: Vec<PriceSnapshot> = rows.iter().map(|row| {
                    PriceSnapshot {
                        price: row.get::<String, _>("price"),
                        timestamp: row.get::<i64, _>("timestamp") as u64,
                    }
                }).collect();

                return Ok(Json(snapshots));
            }
        }

        // If no trade-based history, try to get from blockchain events
        let events_result = sqlx::query(
            r#"
            SELECT
                event_data->>'price' as price,
                EXTRACT(EPOCH FROM block_timestamp)::bigint as timestamp
            FROM blockchain_events
            WHERE contract_name = 'OTCOrderbook'
              AND event_name = 'TradeExecuted'
              AND (event_data->>'pair_id')::int = $1
              AND block_timestamp > NOW() - INTERVAL '7 days'
            ORDER BY block_timestamp DESC
            LIMIT $2
            "#
        )
        .bind(pair_id as i32)
        .bind(limit)
        .fetch_all(pool)
        .await;

        if let Ok(rows) = events_result {
            if !rows.is_empty() {
                use sqlx::Row;

                let snapshots: Vec<PriceSnapshot> = rows.iter().filter_map(|row| {
                    let price: Option<String> = row.try_get("price").ok();
                    let timestamp: i64 = row.get("timestamp");
                    price.map(|p| PriceSnapshot {
                        price: p,
                        timestamp: timestamp as u64,
                    })
                }).collect();

                if !snapshots.is_empty() {
                    return Ok(Json(snapshots));
                }
            }
        }
    }

    // No price history available - return empty array (no mock data)
    Ok(Json(Vec::new()))
}

/// Get global trading stats
async fn get_global_trading_stats(
    State(state): State<Arc<TradingApiState>>,
) -> Json<GlobalTradingStats> {
    debug!("Getting global trading stats");

    // Try to query from database if available
    if let Some(ref pool) = state.db_pool {
        // Query aggregate stats from orders and trades tables
        let orders_stats = sqlx::query(
            r#"
            SELECT COUNT(*)::bigint as total_orders,
                   COUNT(DISTINCT maker_address)::bigint as unique_makers
            FROM orders
            "#
        )
        .fetch_one(pool)
        .await;

        let trades_stats = sqlx::query(
            r#"
            SELECT COUNT(*)::bigint as total_trades,
                   COALESCE(SUM(amount), 0)::text as total_volume,
                   COUNT(DISTINCT maker_address) + COUNT(DISTINCT taker_address) as unique_traders
            FROM trades
            "#
        )
        .fetch_one(pool)
        .await;

        let pairs_count = sqlx::query(
            r#"
            SELECT COUNT(*)::integer as active_pairs
            FROM trading_pairs
            WHERE is_active = true
            "#
        )
        .fetch_one(pool)
        .await;

        if let (Ok(orders), Ok(trades), Ok(pairs)) = (orders_stats, trades_stats, pairs_count) {
            use sqlx::Row;

            let total_orders: i64 = orders.get("total_orders");
            let total_trades: i64 = trades.get("total_trades");
            let total_volume: String = trades.get("total_volume");
            let unique_makers: i64 = orders.get("unique_makers");
            let unique_traders: i64 = trades.try_get("unique_traders").unwrap_or(0);
            let active_pairs: i32 = pairs.get("active_pairs");

            // Calculate USD value (assume $0.10/SAGE)
            let volume_f: f64 = total_volume.parse().unwrap_or(0.0);
            let volume_usd = volume_f * 0.10;

            return Json(GlobalTradingStats {
                total_orders: total_orders as u64,
                total_trades: total_trades as u64,
                total_volume_sage: total_volume,
                total_volume_usd: format!("{:.0}", volume_usd),
                active_pairs: active_pairs as u32,
                total_users: (unique_makers + unique_traders) as u64,
            });
        }
    }

    // Return zeros when no database available
    // This avoids showing misleading mock data
    Json(GlobalTradingStats {
        total_orders: 0,
        total_trades: 0,
        total_volume_sage: "0".to_string(),
        total_volume_usd: "0".to_string(),
        active_pairs: 2,
        total_users: 0,
    })
}

// ============================================================================
// Helpers
// ============================================================================

fn is_valid_starknet_address(address: &str) -> bool {
    if !address.starts_with("0x") {
        return false;
    }

    let hex_part = &address[2..];

    if hex_part.is_empty() || hex_part.len() > 64 {
        return false;
    }

    hex_part.chars().all(|c| c.is_ascii_hexdigit())
}

/// Derive token symbol from Starknet token address
fn derive_symbol(token_address: &str) -> String {
    // Known token address mappings (partial matching on address fragments)
    let address_lower = token_address.to_lowercase();

    // SAGE token (Sepolia: 0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850)
    if address_lower.contains("72349097") || address_lower.contains("293a99850") {
        "SAGE".to_string()
    // SAGE token (alternate/devnet)
    } else if address_lower.contains("02de76e624") || address_lower.contains("1306bce") {
        "SAGE".to_string()
    // ETH (0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7)
    } else if address_lower.contains("049d36570") || address_lower.contains("004dc7") {
        "ETH".to_string()
    // STRK (0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d)
    } else if address_lower.contains("04718f5a0") || address_lower.contains("87c938d") {
        "STRK".to_string()
    // USDC (Sepolia: 0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8)
    } else if address_lower.contains("053c91253") || address_lower.contains("cf368a8") {
        "USDC".to_string()
    } else if address_lower.contains("00be521d24") {
        "USDC".to_string()
    // USDT
    } else if address_lower.contains("068f5c6a6") {
        "USDT".to_string()
    // BTC (via StarkGate bridge)
    } else if address_lower.contains("03fe2b97c") {
        "BTC".to_string()
    // DAI
    } else if address_lower.contains("da114221") {
        "DAI".to_string()
    } else {
        // Unknown token - show abbreviated address for debugging
        if token_address.len() > 16 {
            format!("{}...", &token_address[..10])
        } else {
            token_address.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_starknet_address() {
        assert!(is_valid_starknet_address("0x1234abcd"));
        assert!(is_valid_starknet_address(
            "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"
        ));
        assert!(!is_valid_starknet_address("1234abcd")); // Missing 0x
        assert!(!is_valid_starknet_address("0x")); // Empty hex
        assert!(!is_valid_starknet_address("0xGHIJ")); // Invalid hex
    }
}
