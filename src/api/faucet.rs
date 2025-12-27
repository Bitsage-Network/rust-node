//! # Faucet API Endpoints
//!
//! REST API endpoints for the BitSage testnet faucet.
//! Allows users to claim SAGE tokens for testing.

use axum::{
    extract::{Path, State, ConnectInfo},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn, error};

use crate::obelysk::starknet::{FaucetClient, FaucetStatus, FaucetConfig};

/// Faucet API state
pub struct FaucetApiState {
    pub faucet_client: Arc<FaucetClient>,
}

/// Create faucet routes
pub fn faucet_routes(state: Arc<FaucetApiState>) -> Router {
    Router::new()
        .route("/api/faucet/status/:address", get(get_faucet_status))
        .route("/api/faucet/claim", post(claim_tokens))
        .route("/api/faucet/config", get(get_faucet_config))
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

    // Optional: Verify captcha if provided
    if let Some(token) = &request.captcha_token {
        if !verify_captcha(token).await {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid captcha".to_string(),
                    code: "INVALID_CAPTCHA".to_string(),
                }),
            ));
        }
    }

    info!("Processing faucet claim for {} from IP {}", request.address, ip);

    // Attempt claim
    match state.faucet_client.claim(&request.address, Some(&ip)).await {
        Ok(result) => {
            info!(
                "Faucet claim successful: {} SAGE to {}",
                format_sage_amount(result.amount),
                request.address
            );

            Ok(Json(ClaimResponse {
                success: true,
                amount: result.amount.to_string(),
                amount_formatted: format_sage_amount(result.amount),
                transaction_hash: format!("{:#x}", result.transaction_hash),
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
        network: "sepolia".to_string(), // TODO: Get from config
    })
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

/// Verify captcha token (placeholder - integrate with actual service)
async fn verify_captcha(_token: &str) -> bool {
    // TODO: Integrate with hCaptcha or Turnstile
    // For now, accept all tokens
    true
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
        assert_eq!(format_sage_amount(20_000_000_000_000_000_000), "20.00 SAGE");
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
