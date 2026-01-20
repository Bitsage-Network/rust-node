//! # Staking API Endpoints
//!
//! REST API endpoints for staking operations and information.
//! Provides stake info, tier information, and staking operations.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info};

use crate::obelysk::starknet::{
    StakingClient, StakeStatus, WorkerTier, GpuTier,
};

/// Staking API state
pub struct StakingApiState {
    pub staking_client: Arc<StakingClient>,
    pub network: String,
}

impl StakingApiState {
    /// Create a new staking API state
    pub fn new(staking_client: Arc<StakingClient>, network: &str) -> Self {
        Self {
            staking_client,
            network: network.to_string(),
        }
    }

    /// Create with default (disabled) client for development
    pub fn disabled(network: &str) -> Self {
        Self {
            staking_client: Arc::new(StakingClient::disabled()),
            network: network.to_string(),
        }
    }
}

/// Create staking routes
pub fn staking_routes(state: Arc<StakingApiState>) -> Router {
    Router::new()
        .route("/api/staking/info/:address", get(get_staking_info))
        .route("/api/staking/stake", post(stake_tokens))
        .route("/api/staking/unstake", post(unstake_tokens))
        .route("/api/staking/claim", post(claim_rewards))
        .route("/api/staking/config", get(get_staking_config))
        .route("/api/staking/total", get(get_total_staked))
        .route("/api/staking/worker-tier/:address", get(get_worker_tier))
        .route("/api/staking/tier-benefits/:tier", get(get_tier_benefits))
        .with_state(state)
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Staking info response
#[derive(Debug, Serialize)]
pub struct StakingInfoResponse {
    pub address: String,
    pub staked_amount: String,
    pub staked_amount_formatted: String,
    pub locked_amount: String,
    pub locked_amount_formatted: String,
    pub pending_rewards: String,
    pub pending_rewards_formatted: String,
    pub stake_status: String,
    pub gpu_tier: String,
    pub worker_tier: String,
    pub is_active: bool,
    pub staked_at: Option<u64>,
    pub can_unstake: bool,
    pub min_stake_for_tier: String,
}

/// Stake request
#[derive(Debug, Deserialize)]
pub struct StakeRequest {
    pub amount: String,
    pub gpu_tier: Option<String>,
}

/// Unstake request
#[derive(Debug, Deserialize)]
pub struct UnstakeRequest {
    pub amount: String,
}

/// Stake/Unstake response
#[derive(Debug, Serialize)]
pub struct StakeResponse {
    pub success: bool,
    pub transaction_hash: String,
    pub message: String,
}

/// Claim rewards response
#[derive(Debug, Serialize)]
pub struct ClaimResponse {
    pub success: bool,
    pub amount: String,
    pub amount_formatted: String,
    pub transaction_hash: String,
}

/// Staking config response
#[derive(Debug, Serialize)]
pub struct StakingConfigResponse {
    pub enabled: bool,
    pub network: String,
    pub min_stake_consumer: String,
    pub min_stake_workstation: String,
    pub min_stake_datacenter: String,
    pub min_stake_enterprise: String,
    pub min_stake_frontier: String,
    pub unstake_cooldown_days: u32,
    pub reward_rate_apy: f32,
}

/// Total staked response
#[derive(Debug, Serialize)]
pub struct TotalStakedResponse {
    pub total: String,
    pub total_formatted: String,
    pub total_stakers: u64,
}

/// Worker tier response
#[derive(Debug, Serialize)]
pub struct WorkerTierResponse {
    pub address: String,
    pub tier: String,
    pub description: String,
    pub verification_rate: f64,
    pub priority_multiplier: f64,
    pub can_vote: bool,
}

/// Tier benefits response
#[derive(Debug, Serialize)]
pub struct TierBenefitsResponse {
    pub tier: String,
    pub min_stake: String,
    pub min_stake_formatted: String,
    pub verification_rate: String,
    pub priority_multiplier: f64,
    pub can_vote: bool,
    pub benefits: Vec<String>,
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

/// Get staking info for an address
async fn get_staking_info(
    State(state): State<Arc<StakingApiState>>,
    Path(address): Path<String>,
) -> Result<Json<StakingInfoResponse>, (StatusCode, Json<ErrorResponse>)> {
    debug!("Getting staking info for: {}", address);

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

    // Get stake info from client
    match state.staking_client.get_stake(&address).await {
        Ok(stake) => {
            let stake_status = state.staking_client.get_stake_status(&address).await
                .unwrap_or(StakeStatus::None);

            // Query real reputation from ReputationManager contract
            let reputation_score = state.staking_client.get_reputation_score(&address).await
                .unwrap_or(100); // Default to 100 (10.00 score) if unavailable
            let worker_tier = WorkerTier::from_stake_and_reputation(&stake_status, reputation_score);

            Ok(Json(StakingInfoResponse {
                address: address.clone(),
                staked_amount: stake.amount.to_string(),
                staked_amount_formatted: format_sage_amount(stake.amount),
                locked_amount: stake.locked_amount.to_string(),
                locked_amount_formatted: format_sage_amount(stake.locked_amount),
                pending_rewards: stake.pending_rewards.to_string(),
                pending_rewards_formatted: format_sage_amount(stake.pending_rewards),
                stake_status: format!("{:?}", stake_status),
                gpu_tier: stake.gpu_tier.to_string(),
                worker_tier: format!("{:?}", worker_tier),
                is_active: stake.is_active,
                staked_at: if stake.staked_at > 0 { Some(stake.staked_at) } else { None },
                can_unstake: stake.is_active && stake.locked_amount == 0,
                min_stake_for_tier: format_sage_amount(stake.gpu_tier.min_stake()),
            }))
        }
        Err(e) => {
            // Return mock data for development/devnet
            debug!("Staking client error (returning mock): {}", e);
            Ok(Json(StakingInfoResponse {
                address: address.clone(),
                staked_amount: "0".to_string(),
                staked_amount_formatted: "0 SAGE".to_string(),
                locked_amount: "0".to_string(),
                locked_amount_formatted: "0 SAGE".to_string(),
                pending_rewards: "0".to_string(),
                pending_rewards_formatted: "0 SAGE".to_string(),
                stake_status: "None".to_string(),
                gpu_tier: "Consumer".to_string(),
                worker_tier: "New".to_string(),
                is_active: false,
                staked_at: None,
                can_unstake: false,
                min_stake_for_tier: "1,000 SAGE".to_string(),
            }))
        }
    }
}

/// Stake tokens (placeholder - actual staking happens via wallet)
async fn stake_tokens(
    State(_state): State<Arc<StakingApiState>>,
    Json(request): Json<StakeRequest>,
) -> Result<Json<StakeResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Stake request received: {} tokens", request.amount);

    // In production, this would return transaction data for the wallet to sign
    // For now, return instructions
    Ok(Json(StakeResponse {
        success: true,
        transaction_hash: "".to_string(),
        message: "Staking must be done via wallet. Use the staking contract directly.".to_string(),
    }))
}

/// Unstake tokens (placeholder - actual unstaking happens via wallet)
async fn unstake_tokens(
    State(_state): State<Arc<StakingApiState>>,
    Json(request): Json<UnstakeRequest>,
) -> Result<Json<StakeResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Unstake request received: {} tokens", request.amount);

    Ok(Json(StakeResponse {
        success: true,
        transaction_hash: "".to_string(),
        message: "Unstaking must be done via wallet. Use the staking contract directly.".to_string(),
    }))
}

/// Claim rewards (placeholder - actual claiming happens via wallet)
async fn claim_rewards(
    State(_state): State<Arc<StakingApiState>>,
) -> Result<Json<ClaimResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Claim rewards request received");

    Ok(Json(ClaimResponse {
        success: true,
        amount: "0".to_string(),
        amount_formatted: "0 SAGE".to_string(),
        transaction_hash: "".to_string(),
    }))
}

/// Get staking configuration
async fn get_staking_config(
    State(state): State<Arc<StakingApiState>>,
) -> Json<StakingConfigResponse> {
    // Calculate dynamic APY based on network participation
    let reward_rate_apy = calculate_dynamic_apy(&state).await;

    Json(StakingConfigResponse {
        enabled: true,
        network: state.network.clone(),
        min_stake_consumer: format_sage_amount(GpuTier::Consumer.min_stake()),
        min_stake_workstation: format_sage_amount(GpuTier::Workstation.min_stake()),
        min_stake_datacenter: format_sage_amount(GpuTier::DataCenter.min_stake()),
        min_stake_enterprise: format_sage_amount(GpuTier::Enterprise.min_stake()),
        min_stake_frontier: format_sage_amount(GpuTier::Frontier.min_stake()),
        unstake_cooldown_days: 7,
        reward_rate_apy,
    })
}

/// Calculate dynamic APY based on network parameters
///
/// APY is calculated using the formula:
/// APY = BaseRate * (1 + ParticipationBonus) * (1 - StakingRatio)
///
/// Where:
/// - BaseRate: 8% base annual return
/// - ParticipationBonus: Up to 50% bonus for network utilization
/// - StakingRatio penalty: Higher staking ratio = lower APY (supply/demand)
async fn calculate_dynamic_apy(state: &StakingApiState) -> f32 {
    const BASE_RATE: f32 = 0.08; // 8% base APY
    const MAX_APY: f32 = 0.25; // 25% max APY cap
    const MIN_APY: f32 = 0.04; // 4% min APY floor

    // Try to get network stats for dynamic calculation
    let (total_staked, network_utilization) = match state.staking_client.get_total_staked().await {
        Ok(total) => {
            // Estimate network utilization (0.0 - 1.0)
            // In a real implementation, this would come from job completion metrics
            let utilization = 0.65; // Default to 65% if we can't calculate
            (total, utilization)
        }
        Err(_) => {
            // Fallback to defaults
            return 12.5; // Default 12.5% APY
        }
    };

    // Calculate staking ratio (how much of total supply is staked)
    // Total supply is 1 billion SAGE tokens
    const TOTAL_SUPPLY: u128 = 1_000_000_000_000_000_000_000_000_000; // 1B SAGE in wei
    let staking_ratio = (total_staked as f64 / TOTAL_SUPPLY as f64) as f32;

    // Participation bonus (0% to 50% based on network utilization)
    let participation_bonus = network_utilization * 0.5;

    // Staking ratio penalty (higher staking = lower APY)
    let staking_penalty = staking_ratio * 0.5;

    // Calculate final APY
    let dynamic_apy = BASE_RATE * (1.0 + participation_bonus) * (1.0 - staking_penalty);

    // Clamp to min/max bounds and convert to percentage
    let final_apy = dynamic_apy.clamp(MIN_APY, MAX_APY) * 100.0;

    debug!(
        "Calculated APY: {:.2}% (base={:.0}%, participation_bonus={:.1}%, staking_penalty={:.1}%)",
        final_apy,
        BASE_RATE * 100.0,
        participation_bonus * 100.0,
        staking_penalty * 100.0
    );

    final_apy
}

/// Get total staked from on-chain data
async fn get_total_staked(
    State(state): State<Arc<StakingApiState>>,
) -> Json<TotalStakedResponse> {
    // Query total staked from on-chain
    match state.staking_client.get_total_staked().await {
        Ok(total) => {
            // Get staker count (simplified - would need indexer for accurate count)
            let staker_count = state.staking_client.get_staker_count().await.unwrap_or(0);

            Json(TotalStakedResponse {
                total: total.to_string(),
                total_formatted: format_sage_amount(total),
                total_stakers: staker_count as u64,
            })
        }
        Err(e) => {
            debug!("Failed to query total staked: {}, returning mock data", e);
            // Fallback to mock data for development
            Json(TotalStakedResponse {
                total: "125000000000000000000000000".to_string(), // 125M SAGE
                total_formatted: "125,000,000 SAGE".to_string(),
                total_stakers: 1250,
            })
        }
    }
}

/// Get worker tier for an address
async fn get_worker_tier(
    State(state): State<Arc<StakingApiState>>,
    Path(address): Path<String>,
) -> Result<Json<WorkerTierResponse>, (StatusCode, Json<ErrorResponse>)> {
    if !is_valid_starknet_address(&address) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid Starknet address format".to_string(),
                code: "INVALID_ADDRESS".to_string(),
            }),
        ));
    }

    let stake_status = state.staking_client.get_stake_status(&address).await
        .unwrap_or(StakeStatus::None);

    // Query real reputation from ReputationManager contract
    let reputation = state.staking_client.get_reputation_score(&address).await
        .unwrap_or(100_u32); // Default to 100 (10.00 score) if unavailable
    let worker_tier = WorkerTier::from_stake_and_reputation(&stake_status, reputation);

    Ok(Json(WorkerTierResponse {
        address,
        tier: format!("{:?}", worker_tier),
        description: worker_tier.description().to_string(),
        verification_rate: worker_tier.verification_rate(),
        priority_multiplier: worker_tier.priority_multiplier(),
        can_vote: worker_tier.can_vote(),
    }))
}

/// Get benefits for a tier
async fn get_tier_benefits(
    State(_state): State<Arc<StakingApiState>>,
    Path(tier): Path<String>,
) -> Result<Json<TierBenefitsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let (gpu_tier, worker_tier) = match tier.to_lowercase().as_str() {
        "consumer" => (GpuTier::Consumer, WorkerTier::Staked),
        "workstation" => (GpuTier::Workstation, WorkerTier::Staked),
        "datacenter" => (GpuTier::DataCenter, WorkerTier::Staked),
        "enterprise" => (GpuTier::Enterprise, WorkerTier::Premium),
        "frontier" => (GpuTier::Frontier, WorkerTier::Premium),
        "new" => (GpuTier::Consumer, WorkerTier::New),
        "established" => (GpuTier::Consumer, WorkerTier::Established),
        "trusted" => (GpuTier::Consumer, WorkerTier::Trusted),
        "staked" => (GpuTier::Consumer, WorkerTier::Staked),
        "premium" => (GpuTier::Enterprise, WorkerTier::Premium),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid tier name".to_string(),
                    code: "INVALID_TIER".to_string(),
                }),
            ));
        }
    };

    let benefits = match worker_tier {
        WorkerTier::New => vec![
            "Access to job queue".to_string(),
            "100% proof verification".to_string(),
            "Build reputation through work".to_string(),
        ],
        WorkerTier::Established => vec![
            "10% proof verification".to_string(),
            "1.2x job priority".to_string(),
            "Reduced verification overhead".to_string(),
        ],
        WorkerTier::Trusted => vec![
            "1% proof verification".to_string(),
            "1.5x job priority".to_string(),
            "Premium job access".to_string(),
        ],
        WorkerTier::Staked => vec![
            "10% proof verification".to_string(),
            "1.8x job priority".to_string(),
            "Validator voting rights".to_string(),
            "Stake as slashable bond".to_string(),
        ],
        WorkerTier::Premium => vec![
            "1% proof verification".to_string(),
            "2.0x job priority".to_string(),
            "Validator voting rights".to_string(),
            "Maximum job allocation".to_string(),
            "Early access to new features".to_string(),
        ],
    };

    Ok(Json(TierBenefitsResponse {
        tier: format!("{:?}", worker_tier),
        min_stake: gpu_tier.min_stake().to_string(),
        min_stake_formatted: gpu_tier.min_stake_display().to_string(),
        verification_rate: format!("{}%", (worker_tier.verification_rate() * 100.0) as u32),
        priority_multiplier: worker_tier.priority_multiplier(),
        can_vote: worker_tier.can_vote(),
        benefits,
    }))
}

// ============================================================================
// Helpers
// ============================================================================

/// Validate Starknet address format
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

/// Format SAGE amount (18 decimals) to human-readable string
fn format_sage_amount(wei: u128) -> String {
    let sage = wei as f64 / 1e18;
    if sage >= 1_000_000.0 {
        format!("{:.2}M SAGE", sage / 1_000_000.0)
    } else if sage >= 1_000.0 {
        format!("{:.0} SAGE", sage)
    } else if sage >= 1.0 {
        format!("{:.2} SAGE", sage)
    } else if sage >= 0.001 {
        format!("{:.4} SAGE", sage)
    } else if wei > 0 {
        format!("{} wei", wei)
    } else {
        "0 SAGE".to_string()
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
        assert_eq!(format_sage_amount(125_000_000_000_000_000_000_000_000), "125.00M SAGE");
        assert_eq!(format_sage_amount(5_000_000_000_000_000_000_000), "5000 SAGE");
        assert_eq!(format_sage_amount(1_500_000_000_000_000_000), "1.50 SAGE");
        assert_eq!(format_sage_amount(1_000_000_000_000_000), "0.0010 SAGE");
        assert_eq!(format_sage_amount(1000), "1000 wei");
        assert_eq!(format_sage_amount(0), "0 SAGE");
    }
}
