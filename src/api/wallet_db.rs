//! # Wallet Database API
//!
//! Database-backed REST API endpoints for wallet transactions.
//! Provides transaction history combining public and private transfers,
//! recent transfers, contacts, and token balances.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    Router, routing::get,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use std::collections::HashMap;

/// API State with database pool
#[derive(Clone)]
pub struct WalletDbState {
    pub pool: Arc<PgPool>,
}

impl WalletDbState {
    pub fn new(pool: PgPool) -> Self {
        Self { pool: Arc::new(pool) }
    }
}

/// Query parameters
#[derive(Debug, Deserialize)]
pub struct TransactionsQuery {
    pub tx_type: Option<String>,  // all, transfer, private_transfer, deposit, withdrawal, payment
    pub period: Option<String>,   // 7d, 30d, 90d, all
    pub page: Option<i64>,
    pub limit: Option<i64>,
}

/// Transaction record
#[derive(Debug, Serialize)]
pub struct WalletTransaction {
    pub id: String,
    pub tx_type: String,
    pub direction: String,  // in, out
    pub amount: String,
    pub amount_formatted: String,
    pub token: String,
    pub token_symbol: String,
    pub counterparty: Option<String>,
    pub status: String,
    pub is_private: bool,
    pub timestamp: i64,
    pub tx_hash: Option<String>,
    pub block_number: Option<i64>,
}

/// Transactions list response
#[derive(Debug, Serialize)]
pub struct TransactionsResponse {
    pub transactions: Vec<WalletTransaction>,
    pub total: i64,
    pub page: i64,
    pub limit: i64,
}

/// Wallet summary
#[derive(Debug, Serialize)]
pub struct WalletSummary {
    pub address: String,
    pub total_transactions: i64,
    pub total_sent: String,
    pub total_received: String,
    pub transactions_24h: i64,
    pub transactions_7d: i64,
}

/// Error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
}

/// Query for recent transfers
#[derive(Debug, Deserialize)]
pub struct RecentTransfersQuery {
    pub limit: Option<i64>,
}

/// Recent transfer record (simplified)
#[derive(Debug, Serialize)]
pub struct RecentTransfer {
    pub id: String,
    pub tx_type: String,
    pub direction: String,
    pub amount: String,
    pub amount_formatted: String,
    pub token_symbol: String,
    pub counterparty: Option<String>,
    pub is_private: bool,
    pub timestamp: i64,
    pub tx_hash: Option<String>,
}

/// Recent transfers response
#[derive(Debug, Serialize)]
pub struct RecentTransfersResponse {
    pub transfers: Vec<RecentTransfer>,
    pub count: i64,
}

/// Contact record (derived from transaction counterparties)
#[derive(Debug, Serialize)]
pub struct Contact {
    pub address: String,
    pub address_short: String,
    pub label: Option<String>,
    pub transaction_count: i64,
    pub last_interaction: i64,
}

/// Contacts response
#[derive(Debug, Serialize)]
pub struct ContactsResponse {
    pub contacts: Vec<Contact>,
    pub total: i64,
}

/// Token balance record
#[derive(Debug, Serialize)]
pub struct TokenBalance {
    pub token_address: String,
    pub token_symbol: String,
    pub token_name: String,
    pub balance: String,
    pub balance_formatted: String,
    pub decimals: u8,
    pub usd_value: Option<String>,
}

/// Balances response
#[derive(Debug, Serialize)]
pub struct BalancesResponse {
    pub address: String,
    pub balances: Vec<TokenBalance>,
    pub total_usd_value: Option<String>,
}

/// Create wallet database routes
pub fn wallet_db_routes(state: WalletDbState) -> Router {
    Router::new()
        .route("/api/wallet/:address/transactions", get(get_transactions))
        .route("/api/wallet/:address/summary", get(get_wallet_summary))
        .route("/api/wallet/:address/transfers/recent", get(get_recent_transfers))
        .route("/api/wallet/:address/contacts", get(get_contacts))
        .route("/api/wallet/:address/balances", get(get_balances))
        .with_state(state)
}

/// Get all transactions for an address
async fn get_transactions(
    State(state): State<WalletDbState>,
    Path(address): Path<String>,
    Query(params): Query<TransactionsQuery>,
) -> Result<Json<TransactionsResponse>, (StatusCode, Json<ErrorResponse>)> {
    if !is_valid_address(&address) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid address".to_string(),
                code: "INVALID_ADDRESS".to_string(),
            }),
        ));
    }

    let limit = params.limit.unwrap_or(50).min(100);
    let page = params.page.unwrap_or(1).max(1);
    let offset = (page - 1) * limit;

    let period_filter = match params.period.as_deref() {
        Some("7d") => "AND created_at > NOW() - INTERVAL '7 days'",
        Some("30d") => "AND created_at > NOW() - INTERVAL '30 days'",
        Some("90d") => "AND created_at > NOW() - INTERVAL '90 days'",
        _ => "",
    };

    // Query payments (earnings)
    let payments_query = format!(
        r#"
        SELECT
            id::text as id,
            'payment' as tx_type,
            'in' as direction,
            amount::text as amount,
            token,
            worker_address as counterparty,
            'completed' as status,
            privacy_enabled as is_private,
            EXTRACT(EPOCH FROM created_at)::bigint as timestamp,
            tx_hash,
            block_number
        FROM payments
        WHERE worker_address = $1
        {}
        "#,
        period_filter
    );

    // Query private transfers (both sent and received)
    let private_transfers_query = format!(
        r#"
        SELECT
            id::text as id,
            CASE
                WHEN sender_address = $1 THEN 'private_transfer_out'
                ELSE 'private_transfer_in'
            END as tx_type,
            CASE
                WHEN sender_address = $1 THEN 'out'
                ELSE 'in'
            END as direction,
            '' as amount,
            'SAGE' as token,
            CASE
                WHEN sender_address = $1 THEN receiver_address
                ELSE sender_address
            END as counterparty,
            status,
            true as is_private,
            EXTRACT(EPOCH FROM initiated_at)::bigint as timestamp,
            tx_hash,
            block_number
        FROM private_transfers
        WHERE sender_address = $1 OR receiver_address = $1
        {}
        "#,
        period_filter.replace("created_at", "initiated_at")
    );

    // Combined query with UNION ALL
    let combined_query = format!(
        r#"
        WITH all_transactions AS (
            {}
            UNION ALL
            {}
        )
        SELECT * FROM all_transactions
        ORDER BY timestamp DESC
        LIMIT $2 OFFSET $3
        "#,
        payments_query, private_transfers_query
    );

    let count_query = format!(
        r#"
        SELECT COUNT(*) as total FROM (
            SELECT 1 FROM payments WHERE worker_address = $1 {}
            UNION ALL
            SELECT 1 FROM private_transfers WHERE sender_address = $1 OR receiver_address = $1 {}
        ) combined
        "#,
        period_filter,
        period_filter.replace("created_at", "initiated_at")
    );

    // Execute count query
    let total: i64 = sqlx::query_scalar(&count_query)
        .bind(&address)
        .fetch_one(&*state.pool)
        .await
        .unwrap_or(0);

    // Execute main query
    let rows = sqlx::query(&combined_query)
        .bind(&address)
        .bind(limit)
        .bind(offset)
        .fetch_all(&*state.pool)
        .await;

    match rows {
        Ok(rows) => {
            use sqlx::Row;

            let transactions: Vec<WalletTransaction> = rows.iter().map(|row| {
                let amount: String = row.try_get("amount").unwrap_or_default();
                let token: String = row.try_get("token").unwrap_or_else(|_| "SAGE".to_string());
                let is_private: bool = row.try_get("is_private").unwrap_or(false);

                // Format amount (or show encrypted for private)
                let amount_formatted = if is_private && amount.is_empty() {
                    "••••••".to_string()
                } else {
                    format_amount(&amount, &token)
                };

                let counterparty: Option<String> = row.try_get("counterparty").ok();
                let formatted_counterparty = counterparty.map(|cp| {
                    if cp.len() > 12 {
                        format!("0x{}...{}", &cp[2..6], &cp[cp.len()-4..])
                    } else {
                        cp
                    }
                });

                WalletTransaction {
                    id: row.get("id"),
                    tx_type: row.get("tx_type"),
                    direction: row.get("direction"),
                    amount,
                    amount_formatted,
                    token: token.clone(),
                    token_symbol: get_token_symbol(&token),
                    counterparty: formatted_counterparty,
                    status: row.get("status"),
                    is_private,
                    timestamp: row.get("timestamp"),
                    tx_hash: row.try_get("tx_hash").ok(),
                    block_number: row.try_get("block_number").ok(),
                }
            }).collect();

            Ok(Json(TransactionsResponse {
                transactions,
                total,
                page,
                limit,
            }))
        }
        Err(e) => {
            tracing::error!("Database error fetching transactions: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to fetch transactions".to_string(),
                    code: "DATABASE_ERROR".to_string(),
                }),
            ))
        }
    }
}

/// Get wallet summary
async fn get_wallet_summary(
    State(state): State<WalletDbState>,
    Path(address): Path<String>,
) -> Result<Json<WalletSummary>, (StatusCode, Json<ErrorResponse>)> {
    if !is_valid_address(&address) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid address".to_string(),
                code: "INVALID_ADDRESS".to_string(),
            }),
        ));
    }

    let summary = sqlx::query(
        r#"
        WITH stats AS (
            SELECT
                COUNT(*) as total_tx,
                COALESCE(SUM(CASE WHEN direction = 'in' THEN amount ELSE 0 END), 0)::text as total_received,
                COALESCE(SUM(CASE WHEN direction = 'out' THEN amount ELSE 0 END), 0)::text as total_sent,
                COUNT(*) FILTER (WHERE timestamp > EXTRACT(EPOCH FROM NOW() - INTERVAL '24 hours')) as tx_24h,
                COUNT(*) FILTER (WHERE timestamp > EXTRACT(EPOCH FROM NOW() - INTERVAL '7 days')) as tx_7d
            FROM (
                SELECT amount::numeric as amount, 'in' as direction, EXTRACT(EPOCH FROM created_at) as timestamp
                FROM payments WHERE worker_address = $1
                UNION ALL
                SELECT 0 as amount,
                    CASE WHEN sender_address = $1 THEN 'out' ELSE 'in' END as direction,
                    EXTRACT(EPOCH FROM initiated_at) as timestamp
                FROM private_transfers
                WHERE sender_address = $1 OR receiver_address = $1
            ) combined
        )
        SELECT * FROM stats
        "#
    )
    .bind(&address)
    .fetch_one(&*state.pool)
    .await;

    match summary {
        Ok(row) => {
            use sqlx::Row;
            Ok(Json(WalletSummary {
                address: address.clone(),
                total_transactions: row.try_get("total_tx").unwrap_or(0),
                total_sent: row.try_get("total_sent").unwrap_or_else(|_| "0".to_string()),
                total_received: row.try_get("total_received").unwrap_or_else(|_| "0".to_string()),
                transactions_24h: row.try_get("tx_24h").unwrap_or(0),
                transactions_7d: row.try_get("tx_7d").unwrap_or(0),
            }))
        }
        Err(e) => {
            tracing::error!("Database error fetching wallet summary: {}", e);
            // Return empty summary on error
            Ok(Json(WalletSummary {
                address,
                total_transactions: 0,
                total_sent: "0".to_string(),
                total_received: "0".to_string(),
                transactions_24h: 0,
                transactions_7d: 0,
            }))
        }
    }
}

/// Get recent transfers for an address (simplified endpoint)
async fn get_recent_transfers(
    State(state): State<WalletDbState>,
    Path(address): Path<String>,
    Query(params): Query<RecentTransfersQuery>,
) -> Result<Json<RecentTransfersResponse>, (StatusCode, Json<ErrorResponse>)> {
    if !is_valid_address(&address) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid address".to_string(),
                code: "INVALID_ADDRESS".to_string(),
            }),
        ));
    }

    let limit = params.limit.unwrap_or(10).min(50);

    // Query combining payments and private transfers
    let query = r#"
        WITH all_transfers AS (
            SELECT
                id::text as id,
                'payment' as tx_type,
                'in' as direction,
                amount::text as amount,
                token,
                worker_address as counterparty,
                privacy_enabled as is_private,
                EXTRACT(EPOCH FROM created_at)::bigint as timestamp,
                tx_hash
            FROM payments
            WHERE worker_address = $1

            UNION ALL

            SELECT
                id::text as id,
                CASE
                    WHEN sender_address = $1 THEN 'transfer_out'
                    ELSE 'transfer_in'
                END as tx_type,
                CASE
                    WHEN sender_address = $1 THEN 'out'
                    ELSE 'in'
                END as direction,
                '' as amount,
                'SAGE' as token,
                CASE
                    WHEN sender_address = $1 THEN receiver_address
                    ELSE sender_address
                END as counterparty,
                true as is_private,
                EXTRACT(EPOCH FROM initiated_at)::bigint as timestamp,
                tx_hash
            FROM private_transfers
            WHERE sender_address = $1 OR receiver_address = $1
        )
        SELECT * FROM all_transfers
        ORDER BY timestamp DESC
        LIMIT $2
    "#;

    let rows = sqlx::query(query)
        .bind(&address)
        .bind(limit)
        .fetch_all(&*state.pool)
        .await;

    match rows {
        Ok(rows) => {
            use sqlx::Row;

            let transfers: Vec<RecentTransfer> = rows.iter().map(|row| {
                let amount: String = row.try_get("amount").unwrap_or_default();
                let token: String = row.try_get("token").unwrap_or_else(|_| "SAGE".to_string());
                let is_private: bool = row.try_get("is_private").unwrap_or(false);

                let amount_formatted = if is_private && amount.is_empty() {
                    "••••••".to_string()
                } else {
                    format_amount(&amount, &token)
                };

                let counterparty: Option<String> = row.try_get("counterparty").ok();
                let formatted_counterparty = counterparty.map(|cp| {
                    if cp.len() > 12 {
                        format!("0x{}...{}", &cp[2..6], &cp[cp.len()-4..])
                    } else {
                        cp
                    }
                });

                RecentTransfer {
                    id: row.get("id"),
                    tx_type: row.get("tx_type"),
                    direction: row.get("direction"),
                    amount,
                    amount_formatted,
                    token_symbol: get_token_symbol(&token),
                    counterparty: formatted_counterparty,
                    is_private,
                    timestamp: row.get("timestamp"),
                    tx_hash: row.try_get("tx_hash").ok(),
                }
            }).collect();

            let count = transfers.len() as i64;
            Ok(Json(RecentTransfersResponse { transfers, count }))
        }
        Err(e) => {
            tracing::error!("Database error fetching recent transfers: {}", e);
            // Return empty list on error
            Ok(Json(RecentTransfersResponse {
                transfers: vec![],
                count: 0,
            }))
        }
    }
}

/// Get contacts (unique counterparties) for an address
async fn get_contacts(
    State(state): State<WalletDbState>,
    Path(address): Path<String>,
) -> Result<Json<ContactsResponse>, (StatusCode, Json<ErrorResponse>)> {
    if !is_valid_address(&address) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid address".to_string(),
                code: "INVALID_ADDRESS".to_string(),
            }),
        ));
    }

    // Derive contacts from transaction counterparties
    let query = r#"
        WITH all_counterparties AS (
            -- From payments (counterparty is client who paid)
            SELECT
                worker_address as counterparty,
                created_at as interaction_time
            FROM payments
            WHERE worker_address = $1 AND worker_address IS NOT NULL

            UNION ALL

            -- From private transfers (sender or receiver)
            SELECT
                CASE
                    WHEN sender_address = $1 THEN receiver_address
                    ELSE sender_address
                END as counterparty,
                initiated_at as interaction_time
            FROM private_transfers
            WHERE (sender_address = $1 OR receiver_address = $1)
              AND sender_address IS NOT NULL
              AND receiver_address IS NOT NULL

            UNION ALL

            -- From trades (as maker or taker)
            SELECT
                CASE
                    WHEN maker_address = $1 THEN taker_address
                    ELSE maker_address
                END as counterparty,
                executed_at as interaction_time
            FROM trades
            WHERE maker_address = $1 OR taker_address = $1
        )
        SELECT
            counterparty as address,
            COUNT(*) as transaction_count,
            EXTRACT(EPOCH FROM MAX(interaction_time))::bigint as last_interaction
        FROM all_counterparties
        WHERE counterparty IS NOT NULL AND counterparty != $1
        GROUP BY counterparty
        ORDER BY last_interaction DESC
        LIMIT 100
    "#;

    let rows = sqlx::query(query)
        .bind(&address)
        .fetch_all(&*state.pool)
        .await;

    match rows {
        Ok(rows) => {
            use sqlx::Row;

            let contacts: Vec<Contact> = rows.iter().map(|row| {
                let addr: String = row.get("address");
                let address_short = if addr.len() > 12 {
                    format!("0x{}...{}", &addr[2..6], &addr[addr.len()-4..])
                } else {
                    addr.clone()
                };

                Contact {
                    address: addr,
                    address_short,
                    label: None, // Labels can be added via user settings later
                    transaction_count: row.get("transaction_count"),
                    last_interaction: row.get("last_interaction"),
                }
            }).collect();

            let total = contacts.len() as i64;
            Ok(Json(ContactsResponse { contacts, total }))
        }
        Err(e) => {
            tracing::error!("Database error fetching contacts: {}", e);
            Ok(Json(ContactsResponse {
                contacts: vec![],
                total: 0,
            }))
        }
    }
}

/// Get token balances for an address
/// Note: This aggregates from on-chain indexed data. For real-time balances,
/// the frontend should also query Starknet RPC directly.
async fn get_balances(
    State(state): State<WalletDbState>,
    Path(address): Path<String>,
) -> Result<Json<BalancesResponse>, (StatusCode, Json<ErrorResponse>)> {
    if !is_valid_address(&address) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid address".to_string(),
                code: "INVALID_ADDRESS".to_string(),
            }),
        ));
    }

    // Aggregate balances from indexed payments and known tokens
    // This provides an approximation based on indexed on-chain activity
    let query = r#"
        WITH payment_totals AS (
            SELECT
                token,
                SUM(amount) as total_received
            FROM payments
            WHERE worker_address = $1
            GROUP BY token
        ),
        staking_info AS (
            SELECT
                SUM(CASE WHEN event_type = 'stake' THEN amount ELSE 0 END) -
                SUM(CASE WHEN event_type IN ('unstake_completed', 'slashed') THEN amount ELSE 0 END) as staked_amount
            FROM staking_events
            WHERE worker_address = $1
        )
        SELECT
            COALESCE(pt.token, 'SAGE') as token,
            COALESCE(pt.total_received, 0)::text as received,
            COALESCE(si.staked_amount, 0)::text as staked
        FROM payment_totals pt
        FULL OUTER JOIN staking_info si ON true
    "#;

    let rows = sqlx::query(query)
        .bind(&address)
        .fetch_all(&*state.pool)
        .await;

    // Build balances map
    let mut token_balances: HashMap<String, (i128, i128)> = HashMap::new();

    if let Ok(rows) = rows {
        use sqlx::Row;
        for row in rows {
            let token: String = row.try_get("token").unwrap_or_else(|_| "SAGE".to_string());
            let received: String = row.try_get("received").unwrap_or_else(|_| "0".to_string());
            let staked: String = row.try_get("staked").unwrap_or_else(|_| "0".to_string());

            let received_val: i128 = received.parse().unwrap_or(0);
            let staked_val: i128 = staked.parse().unwrap_or(0);

            token_balances.insert(token, (received_val, staked_val));
        }
    }

    // Build response with known token metadata
    let known_tokens = vec![
        ("0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850", "SAGE", "Sage Token", 18u8),
        ("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d", "STRK", "Starknet Token", 18u8),
        ("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7", "ETH", "Ethereum", 18u8),
    ];

    let mut balances: Vec<TokenBalance> = known_tokens.iter().map(|(addr, symbol, name, decimals)| {
        let (received, _staked) = token_balances.get(&symbol.to_string())
            .or_else(|| token_balances.get(&addr.to_string()))
            .copied()
            .unwrap_or((0, 0));

        let balance = received; // Net received as balance approximation
        let balance_str = balance.to_string();

        TokenBalance {
            token_address: addr.to_string(),
            token_symbol: symbol.to_string(),
            token_name: name.to_string(),
            balance: balance_str.clone(),
            balance_formatted: format_amount(&balance_str, symbol),
            decimals: *decimals,
            usd_value: None, // USD value requires price oracle integration
        }
    }).collect();

    // Filter out zero balances for cleaner response (keep SAGE always)
    balances.retain(|b| b.token_symbol == "SAGE" || b.balance != "0");

    // Ensure SAGE is always present
    if !balances.iter().any(|b| b.token_symbol == "SAGE") {
        balances.insert(0, TokenBalance {
            token_address: "0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850".to_string(),
            token_symbol: "SAGE".to_string(),
            token_name: "Sage Token".to_string(),
            balance: "0".to_string(),
            balance_formatted: "0".to_string(),
            decimals: 18,
            usd_value: None,
        });
    }

    Ok(Json(BalancesResponse {
        address,
        balances,
        total_usd_value: None,
    }))
}

// Helper functions

fn is_valid_address(address: &str) -> bool {
    address.starts_with("0x") && address.len() >= 10 && address.len() <= 66
}

fn format_amount(amount: &str, token: &str) -> String {
    let decimals = match token {
        t if t.contains("USDC") => 6,
        t if t.contains("wBTC") => 8,
        _ => 18,
    };

    if let Ok(val) = amount.parse::<f64>() {
        let formatted = val / (10_f64.powi(decimals));
        if formatted >= 1_000_000.0 {
            format!("{:.2}M", formatted / 1_000_000.0)
        } else if formatted >= 1_000.0 {
            format!("{:.2}K", formatted / 1_000.0)
        } else {
            format!("{:.4}", formatted)
        }
    } else {
        amount.to_string()
    }
}

fn get_token_symbol(token_address: &str) -> String {
    match token_address {
        t if t.contains("02de76e624") => "SAGE".to_string(),
        t if t.contains("00be521d24") => "USDC".to_string(),
        t if t.contains("03273352d5") => "STRK".to_string(),
        t if t.contains("049d36570") => "ETH".to_string(),
        _ => "TOKEN".to_string(),
    }
}
