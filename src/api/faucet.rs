//! # Faucet API Endpoints
//!
//! REST API endpoints for the BitSage testnet faucet.
//! Allows users to claim SAGE tokens for testing.

use axum::{
    extract::{Path, Query, State, ConnectInfo},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn, error};

use crate::obelysk::starknet::{FaucetClient, FaucetStatus};
use super::captcha::{CaptchaVerifier, CaptchaConfig};

/// Faucet API state
pub struct FaucetApiState {
    pub faucet_client: Arc<FaucetClient>,
    pub captcha_verifier: Arc<CaptchaVerifier>,
    pub db_pool: Option<Arc<PgPool>>,
    pub network: String,
}

impl FaucetApiState {
    /// Create a new faucet API state with default (disabled) CAPTCHA
    pub fn new(faucet_client: Arc<FaucetClient>, network: &str) -> Self {
        Self {
            faucet_client,
            captcha_verifier: Arc::new(CaptchaVerifier::new(CaptchaConfig::default())),
            db_pool: None,
            network: network.to_string(),
        }
    }

    /// Create a new faucet API state with custom CAPTCHA config
    pub fn with_captcha(faucet_client: Arc<FaucetClient>, captcha_config: CaptchaConfig, network: &str) -> Self {
        Self {
            faucet_client,
            captcha_verifier: Arc::new(CaptchaVerifier::new(captcha_config)),
            db_pool: None,
            network: network.to_string(),
        }
    }

    /// Create a new faucet API state with database pool
    pub fn with_db(faucet_client: Arc<FaucetClient>, db_pool: PgPool, network: &str) -> Self {
        Self {
            faucet_client,
            captcha_verifier: Arc::new(CaptchaVerifier::new(CaptchaConfig::default())),
            db_pool: Some(Arc::new(db_pool)),
            network: network.to_string(),
        }
    }
}

/// Create faucet routes
pub fn faucet_routes(state: Arc<FaucetApiState>) -> Router {
    Router::new()
        .route("/api/faucet/status/:address", get(get_faucet_status))
        .route("/api/faucet/claim", post(claim_tokens))
        .route("/api/faucet/config", get(get_faucet_config))
        .route("/api/faucet/history/:address", get(get_claim_history))
        .with_state(state)
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Faucet status response
#[derive(Debug, Serialize)]
pub struct FaucetStatusResponse {
    pub can_claim: bool,
    pub time_until_next_claim_secs: u64,
    pub claim_amount: String,
    pub claim_amount_formatted: String,
    pub total_claimed: String,
    pub total_claimed_formatted: String,
}

impl From<FaucetStatus> for FaucetStatusResponse {
    fn from(status: FaucetStatus) -> Self {
        Self {
            can_claim: status.can_claim,
            time_until_next_claim_secs: status.time_until_next_claim_secs,
            claim_amount: status.claim_amount.to_string(),
            claim_amount_formatted: format_sage_amount(status.claim_amount),
            total_claimed: status.total_claimed.to_string(),
            total_claimed_formatted: format_sage_amount(status.total_claimed),
        }
    }
}

/// Claim request
#[derive(Debug, Deserialize)]
pub struct ClaimRequest {
    /// Starknet address to receive tokens
    pub address: String,
    /// Optional captcha token for anti-bot protection
    pub captcha_token: Option<String>,
}

/// Claim response
#[derive(Debug, Serialize)]
pub struct ClaimResponse {
    pub success: bool,
    pub amount: String,
    pub amount_formatted: String,
    pub transaction_hash: String,
    pub message: String,
}

/// Faucet config response
#[derive(Debug, Serialize)]
pub struct FaucetConfigResponse {
    pub enabled: bool,
    pub claim_amount: String,
    pub claim_amount_formatted: String,
    pub cooldown_secs: u64,
    pub cooldown_formatted: String,
    pub network: String,
}

/// Error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
}

/// Claim history item
#[derive(Debug, Serialize)]
pub struct ClaimHistoryItem {
    pub id: String,
    pub amount: String,
    pub amount_formatted: String,
    pub claim_type: String,
    pub claimed_at: i64,
    pub tx_hash: String,
}

/// Claim history response
#[derive(Debug, Serialize)]
pub struct ClaimHistoryResponse {
    pub claims: Vec<ClaimHistoryItem>,
    pub total_claims: i64,
    pub total_claimed: String,
    pub total_claimed_formatted: String,
}

/// Query params for history
#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// ============================================================================
// Handlers
// ============================================================================

/// Get faucet status for an address
async fn get_faucet_status(
    State(state): State<Arc<FaucetApiState>>,
    Path(address): Path<String>,
) -> Result<Json<FaucetStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Validate address format
    if !is_valid_starknet_address(&address) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid Starknet address format".to_string(),
                code: "INVALID_ADDRESS".to_string(),
            }),
        ));
    }

    match state.faucet_client.get_status(&address).await {
        Ok(status) => Ok(Json(FaucetStatusResponse::from(status))),
        Err(e) => {
            error!("Failed to get faucet status for {}: {}", address, e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to get faucet status".to_string(),
                    code: "INTERNAL_ERROR".to_string(),
                }),
            ))
        }
    }
}

/// Claim tokens from faucet
async fn claim_tokens(
    State(state): State<Arc<FaucetApiState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<ClaimRequest>,
) -> Result<Json<ClaimResponse>, (StatusCode, Json<ErrorResponse>)> {
    let ip = addr.ip().to_string();

    // Validate address format
    if !is_valid_starknet_address(&request.address) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid Starknet address format".to_string(),
                code: "INVALID_ADDRESS".to_string(),
            }),
        ));
    }

    // Check if faucet is enabled
    if !state.faucet_client.is_enabled() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Faucet is currently disabled".to_string(),
                code: "FAUCET_DISABLED".to_string(),
            }),
        ));
    }

    // Verify CAPTCHA if required
    if state.captcha_verifier.is_required() {
        match &request.captcha_token {
            Some(token) => {
                match state.captcha_verifier.verify(token, Some(&ip)).await {
                    Ok(true) => {
                        // CAPTCHA valid, continue
                    }
                    Ok(false) => {
                        warn!("CAPTCHA verification failed for {} from IP {}", request.address, ip);
                        return Err((
                            StatusCode::BAD_REQUEST,
                            Json(ErrorResponse {
                                error: "CAPTCHA verification failed".to_string(),
                                code: "INVALID_CAPTCHA".to_string(),
                            }),
                        ));
                    }
                    Err(e) => {
                        error!("CAPTCHA verification error: {}", e);
                        return Err((
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(ErrorResponse {
                                error: "CAPTCHA service unavailable".to_string(),
                                code: "CAPTCHA_ERROR".to_string(),
                            }),
                        ));
                    }
                }
            }
            None => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "CAPTCHA token is required".to_string(),
                        code: "CAPTCHA_REQUIRED".to_string(),
                    }),
                ));
            }
        }
    }

    info!("Processing faucet claim for {} from IP {}", request.address, ip);

    // Attempt claim
    match state.faucet_client.claim(&request.address, Some(&ip)).await {
        Ok(result) => {
            let tx_hash_str = format!("{:#x}", result.transaction_hash);
            info!(
                "Faucet claim successful: {} SAGE to {}",
                format_sage_amount(result.amount),
                request.address
            );

            // Save claim to database if available
            if let Some(ref pool) = state.db_pool {
                let save_result = sqlx::query(
                    r#"
                    INSERT INTO faucet_claims (claimer_address, amount, claim_type, tx_hash)
                    VALUES ($1, $2, 'standard', $3)
                    "#
                )
                .bind(&request.address)
                .bind(result.amount.to_string())
                .bind(&tx_hash_str)
                .execute(pool.as_ref())
                .await;

                if let Err(e) = save_result {
                    warn!("Failed to save claim to database: {}", e);
                }
            }

            Ok(Json(ClaimResponse {
                success: true,
                amount: result.amount.to_string(),
                amount_formatted: format_sage_amount(result.amount),
                transaction_hash: tx_hash_str,
                message: format!(
                    "Successfully claimed {} SAGE tokens",
                    format_sage_amount(result.amount)
                ),
            }))
        }
        Err(e) => {
            let error_msg = e.to_string();
            warn!("Faucet claim failed for {}: {}", request.address, error_msg);

            // Determine appropriate error code
            let (status_code, code) = if error_msg.contains("Cannot claim yet") {
                (StatusCode::TOO_MANY_REQUESTS, "COOLDOWN_ACTIVE")
            } else if error_msg.contains("Rate limit") {
                (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED")
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, "CLAIM_FAILED")
            };

            Err((
                status_code,
                Json(ErrorResponse {
                    error: error_msg,
                    code: code.to_string(),
                }),
            ))
        }
    }
}

/// Get faucet configuration
async fn get_faucet_config(
    State(state): State<Arc<FaucetApiState>>,
) -> Json<FaucetConfigResponse> {
    let config = state.faucet_client.get_config();

    Json(FaucetConfigResponse {
        enabled: config.enabled,
        claim_amount: config.claim_amount.to_string(),
        claim_amount_formatted: format_sage_amount(config.claim_amount),
        cooldown_secs: config.cooldown_secs,
        cooldown_formatted: format_duration(config.cooldown_secs),
        network: state.network.clone(),
    })
}

/// Get claim history for an address
async fn get_claim_history(
    State(state): State<Arc<FaucetApiState>>,
    Path(address): Path<String>,
    Query(params): Query<HistoryQuery>,
) -> Result<Json<ClaimHistoryResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Validate address format
    if !is_valid_starknet_address(&address) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid Starknet address format".to_string(),
                code: "INVALID_ADDRESS".to_string(),
            }),
        ));
    }

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);

    // Try to get from database if available
    if let Some(ref pool) = state.db_pool {
        let claims_result = sqlx::query(
            r#"
            SELECT
                id::text as id,
                amount::text as amount,
                claim_type,
                EXTRACT(EPOCH FROM claimed_at)::bigint as claimed_at,
                tx_hash
            FROM faucet_claims
            WHERE claimer_address = $1
            ORDER BY claimed_at DESC
            LIMIT $2 OFFSET $3
            "#
        )
        .bind(&address)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool.as_ref())
        .await;

        let totals_result = sqlx::query(
            r#"
            SELECT
                COUNT(*) as total_claims,
                COALESCE(SUM(amount), 0)::text as total_claimed
            FROM faucet_claims
            WHERE claimer_address = $1
            "#
        )
        .bind(&address)
        .fetch_one(pool.as_ref())
        .await;

        if let (Ok(claims_rows), Ok(totals_row)) = (claims_result, totals_result) {
            use sqlx::Row;

            let claims: Vec<ClaimHistoryItem> = claims_rows.iter().map(|row| {
                let amount_str: String = row.get("amount");
                let amount_u64: u64 = amount_str.parse().unwrap_or(0);
                ClaimHistoryItem {
                    id: row.get("id"),
                    amount: amount_str,
                    amount_formatted: format_sage_amount(amount_u64),
                    claim_type: row.get("claim_type"),
                    claimed_at: row.get("claimed_at"),
                    tx_hash: row.get("tx_hash"),
                }
            }).collect();

            let total_claims: i64 = totals_row.get("total_claims");
            let total_claimed: String = totals_row.get("total_claimed");
            let total_claimed_u64: u64 = total_claimed.parse().unwrap_or(0);

            return Ok(Json(ClaimHistoryResponse {
                claims,
                total_claims,
                total_claimed,
                total_claimed_formatted: format_sage_amount(total_claimed_u64),
            }));
        }
    }

    // Fallback: empty history
    Ok(Json(ClaimHistoryResponse {
        claims: vec![],
        total_claims: 0,
        total_claimed: "0".to_string(),
        total_claimed_formatted: "0 SAGE".to_string(),
    }))
}

// ============================================================================
// Helpers
// ============================================================================

/// Validate Starknet address format
fn is_valid_starknet_address(address: &str) -> bool {
    // Must start with 0x and be a valid hex string
    if !address.starts_with("0x") {
        return false;
    }

    let hex_part = &address[2..];

    // Must be 1-64 hex characters
    if hex_part.is_empty() || hex_part.len() > 64 {
        return false;
    }

    // Must be valid hex
    hex_part.chars().all(|c| c.is_ascii_hexdigit())
}

/// Format SAGE amount (18 decimals) to human-readable string
fn format_sage_amount(wei: u64) -> String {
    let sage = wei as f64 / 1e18;
    if sage >= 1.0 {
        format!("{:.2} SAGE", sage)
    } else if sage >= 0.001 {
        format!("{:.4} SAGE", sage)
    } else {
        format!("{} wei", wei)
    }
}

/// Format duration in seconds to human-readable string
fn format_duration(secs: u64) -> String {
    if secs >= 86400 {
        let days = secs / 86400;
        format!("{} day{}", days, if days == 1 { "" } else { "s" })
    } else if secs >= 3600 {
        let hours = secs / 3600;
        format!("{} hour{}", hours, if hours == 1 { "" } else { "s" })
    } else if secs >= 60 {
        let mins = secs / 60;
        format!("{} minute{}", mins, if mins == 1 { "" } else { "s" })
    } else {
        format!("{} second{}", secs, if secs == 1 { "" } else { "s" })
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_starknet_address() {
        assert!(is_valid_starknet_address("0x1234abcd"));
        assert!(is_valid_starknet_address("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"));
        assert!(!is_valid_starknet_address("1234abcd")); // Missing 0x
        assert!(!is_valid_starknet_address("0x")); // Empty hex
        assert!(!is_valid_starknet_address("0xGHIJ")); // Invalid hex
    }

    #[test]
    fn test_format_sage_amount() {
        // Note: 18 * 10^18 is close to u64::MAX (~18.4 * 10^18)
        assert_eq!(format_sage_amount(18_000_000_000_000_000_000), "18.00 SAGE");
        assert_eq!(format_sage_amount(1_500_000_000_000_000_000), "1.50 SAGE");
        assert_eq!(format_sage_amount(1_000_000_000_000_000), "0.0010 SAGE");
        assert_eq!(format_sage_amount(1000), "1000 wei");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(86400), "1 day");
        assert_eq!(format_duration(172800), "2 days");
        assert_eq!(format_duration(3600), "1 hour");
        assert_eq!(format_duration(7200), "2 hours");
        assert_eq!(format_duration(60), "1 minute");
        assert_eq!(format_duration(120), "2 minutes");
        assert_eq!(format_duration(30), "30 seconds");
    }
}
