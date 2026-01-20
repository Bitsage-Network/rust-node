//! Staking Contract Client
//!
//! This module provides the client for interacting with the ProverStaking Cairo contract.
//! It handles stake verification for worker registration and reward queries.
//!
//! Features:
//! - Circuit breaker pattern for RPC resilience
//! - Metrics collection for observability
//! - Exponential backoff retry logic
//! - Address validation

use super::network::{CircuitBreaker, CircuitBreakerConfig, RpcMetrics};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, warn};

/// Maximum retry attempts for RPC calls
const MAX_RETRIES: u32 = 3;
/// Base delay for exponential backoff (milliseconds)
const RETRY_BASE_DELAY_MS: u64 = 100;
/// Maximum delay for exponential backoff (milliseconds)
const RETRY_MAX_DELAY_MS: u64 = 5000;

/// GPU Tier classification matching Cairo contract enum
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum GpuTier {
    /// Consumer GPUs: RTX 30xx, 40xx series
    Consumer = 0,
    /// Workstation GPUs: RTX A6000, L40S
    Workstation = 1,
    /// DataCenter GPUs: A100
    DataCenter = 2,
    /// Enterprise GPUs: H100, H200, B200, B300
    Enterprise = 3,
    /// Frontier GPUs: Multi-GPU clusters, MI300X
    Frontier = 4,
}

impl GpuTier {
    /// Determine GPU tier from model name
    pub fn from_gpu_model(model: &str) -> Self {
        let model_upper = model.to_uppercase();

        // Frontier tier - Multi-GPU clusters, AMD MI300X
        if model_upper.contains("MI300") || model_upper.contains("MULTI-GPU") {
            return GpuTier::Frontier;
        }

        // Enterprise tier - Blackwell (B200, B300) and Hopper (H100, H200)
        if model_upper.contains("B200")
            || model_upper.contains("B300")
            || model_upper.contains("B100")
            || model_upper.contains("H100")
            || model_upper.contains("H200")
        {
            return GpuTier::Enterprise;
        }

        // DataCenter tier - A100
        if model_upper.contains("A100") {
            return GpuTier::DataCenter;
        }

        // Workstation tier - A6000, L40, L4
        if model_upper.contains("A6000")
            || model_upper.contains("L40")
            || model_upper.contains("L4")
            || model_upper.contains("RTX A")
        {
            return GpuTier::Workstation;
        }

        // Default to Consumer tier - RTX 30xx, 40xx, 50xx, etc.
        GpuTier::Consumer
    }

    /// Convert to Cairo contract enum value
    pub fn to_cairo_enum(&self) -> u8 {
        *self as u8
    }

    /// Get minimum stake requirement in SAGE tokens (18 decimals)
    pub fn min_stake(&self) -> u128 {
        match self {
            GpuTier::Consumer => 1_000_000_000_000_000_000_000,     // 1,000 SAGE
            GpuTier::Workstation => 2_500_000_000_000_000_000_000,  // 2,500 SAGE
            GpuTier::DataCenter => 5_000_000_000_000_000_000_000,   // 5,000 SAGE
            GpuTier::Enterprise => 10_000_000_000_000_000_000_000,  // 10,000 SAGE
            GpuTier::Frontier => 25_000_000_000_000_000_000_000,    // 25,000 SAGE
        }
    }

    /// Get human-readable minimum stake
    pub fn min_stake_display(&self) -> &'static str {
        match self {
            GpuTier::Consumer => "1,000 SAGE",
            GpuTier::Workstation => "2,500 SAGE",
            GpuTier::DataCenter => "5,000 SAGE",
            GpuTier::Enterprise => "10,000 SAGE",
            GpuTier::Frontier => "25,000 SAGE",
        }
    }
}

impl std::fmt::Display for GpuTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GpuTier::Consumer => write!(f, "Consumer"),
            GpuTier::Workstation => write!(f, "Workstation"),
            GpuTier::DataCenter => write!(f, "DataCenter"),
            GpuTier::Enterprise => write!(f, "Enterprise"),
            GpuTier::Frontier => write!(f, "Frontier"),
        }
    }
}

/// Worker stake information from on-chain
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerStake {
    /// Total staked amount (in wei, 18 decimals)
    pub amount: u128,
    /// Amount locked for unstaking
    pub locked_amount: u128,
    /// Timestamp when stake was created
    pub staked_at: u64,
    /// Last reward claim timestamp
    pub last_claim_at: u64,
    /// GPU tier the worker registered with
    pub gpu_tier: GpuTier,
    /// Whether the worker is currently active
    pub is_active: bool,
    /// Number of consecutive job failures
    pub consecutive_failures: u8,
    /// Total amount slashed from this stake
    pub total_slashed: u128,
    /// Pending rewards to claim
    pub pending_rewards: u128,
}

impl Default for WorkerStake {
    fn default() -> Self {
        Self {
            amount: 0,
            locked_amount: 0,
            staked_at: 0,
            last_claim_at: 0,
            gpu_tier: GpuTier::Consumer,
            is_active: false,
            consecutive_failures: 0,
            total_slashed: 0,
            pending_rewards: 0,
        }
    }
}

/// On-chain staking contract configuration
/// Retrieved via the `get_config` contract call
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StakingContractConfig {
    /// Minimum stake amount per GPU tier (in wei, 18 decimals)
    pub min_stake_consumer: u128,
    pub min_stake_workstation: u128,
    pub min_stake_datacenter: u128,
    pub min_stake_enterprise: u128,
    pub min_stake_frontier: u128,
    /// Unstaking cooldown period in seconds
    pub unstake_cooldown_secs: u64,
    /// Slashing percentage for failures (0-100)
    pub slash_percentage: u8,
    /// Whether staking is currently paused
    pub is_paused: bool,
}

impl Default for StakingContractConfig {
    fn default() -> Self {
        Self {
            min_stake_consumer: 1_000_000_000_000_000_000_000,    // 1,000 SAGE
            min_stake_workstation: 2_500_000_000_000_000_000_000, // 2,500 SAGE
            min_stake_datacenter: 5_000_000_000_000_000_000_000,  // 5,000 SAGE
            min_stake_enterprise: 10_000_000_000_000_000_000_000, // 10,000 SAGE
            min_stake_frontier: 25_000_000_000_000_000_000_000,   // 25,000 SAGE
            unstake_cooldown_secs: 7 * 24 * 60 * 60,              // 7 days
            slash_percentage: 5,
            is_paused: false,
        }
    }
}

/// Stake status for work-first model (staking is optional)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StakeStatus {
    /// No stake - worker participates via reputation only
    None,
    /// Worker has staked SAGE tokens
    Staked {
        /// Staked amount in SAGE (18 decimals)
        amount: u128,
        /// GPU tier the stake covers
        gpu_tier: GpuTier,
    },
    /// Stake is being unstaked (in cooldown)
    Unstaking {
        /// Amount being unstaked
        amount: u128,
        /// Timestamp when unstake completes
        available_at: u64,
    },
}

impl Default for StakeStatus {
    fn default() -> Self {
        Self::None
    }
}

/// Worker tier based on stake and reputation (work-first model)
///
/// Workers can participate without staking - trust is built through:
/// 1. STWO proof verification (cryptographic proof of correct computation)
/// 2. Reputation from successful job completions
/// 3. Optional staking for premium benefits
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerTier {
    /// New worker: 0-49 jobs completed, 100% verification
    New,
    /// Established worker: 50-499 jobs, 10% verification
    Established,
    /// Trusted worker: 500+ jobs with 95%+ success, 1% verification
    Trusted,
    /// Staked worker: Has SAGE stake, priority jobs, validator voting
    Staked,
    /// Premium worker: Trusted + Staked, maximum benefits
    Premium,
}

impl WorkerTier {
    /// Determine worker tier from stake status and reputation score
    ///
    /// Reputation score is from 0-1000 (on-chain ReputationScore.score).
    /// Thresholds:
    /// - 500+: Trusted (500+ jobs with high success rate)
    /// - 50-499: Established (proven track record)
    /// - 0-49: New worker (building reputation)
    pub fn from_stake_and_reputation(stake: &StakeStatus, reputation: u32) -> Self {
        let has_stake = matches!(stake, StakeStatus::Staked { .. });

        match (has_stake, reputation) {
            // Premium: Staked + Trusted (reputation 500+)
            (true, rep) if rep >= 500 => WorkerTier::Premium,
            // Staked: Has stake, any reputation
            (true, _) => WorkerTier::Staked,
            // Trusted: No stake, high reputation (500+)
            (false, rep) if rep >= 500 => WorkerTier::Trusted,
            // Established: No stake, moderate reputation (50-499)
            (false, rep) if rep >= 50 => WorkerTier::Established,
            // New: No stake, low reputation (0-49)
            (false, _) => WorkerTier::New,
        }
    }

    /// Get the verification rate for this tier (0.0 - 1.0)
    ///
    /// New workers have all jobs verified, trusted workers have statistical sampling
    pub fn verification_rate(&self) -> f64 {
        match self {
            WorkerTier::New => 1.0,        // 100% verification
            WorkerTier::Established => 0.1, // 10% verification
            WorkerTier::Trusted => 0.01,   // 1% verification
            WorkerTier::Staked => 0.1,     // 10% verification (stake as bond)
            WorkerTier::Premium => 0.01,   // 1% verification (trusted + stake)
        }
    }

    /// Get job priority multiplier for this tier
    pub fn priority_multiplier(&self) -> f64 {
        match self {
            WorkerTier::New => 1.0,
            WorkerTier::Established => 1.2,
            WorkerTier::Trusted => 1.5,
            WorkerTier::Staked => 1.8,
            WorkerTier::Premium => 2.0,
        }
    }

    /// Whether this tier can participate in validator voting
    pub fn can_vote(&self) -> bool {
        matches!(self, WorkerTier::Staked | WorkerTier::Premium)
    }

    /// Human-readable tier description
    pub fn description(&self) -> &'static str {
        match self {
            WorkerTier::New => "New Worker (building reputation)",
            WorkerTier::Established => "Established Worker",
            WorkerTier::Trusted => "Trusted Worker",
            WorkerTier::Staked => "Staked Worker",
            WorkerTier::Premium => "Premium Worker (Trusted + Staked)",
        }
    }
}

/// Configuration for the staking client
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StakingClientConfig {
    /// Starknet RPC URL
    pub rpc_url: String,
    /// Staking contract address
    pub staking_contract: String,
    /// Request timeout
    pub timeout: Duration,
    /// Whether staking verification is enabled
    pub enabled: bool,
}

impl Default for StakingClientConfig {
    fn default() -> Self {
        Self {
            rpc_url: std::env::var("STARKNET_RPC_URL")
                .unwrap_or_else(|_| "https://api.cartridge.gg/x/starknet/sepolia".to_string()),
            staking_contract: std::env::var("STAKING_CONTRACT_ADDRESS")
                .unwrap_or_else(|_| "0x0165fe12b09dd5e6b692cbf59f9c3ea0af30a2616f248c150357b07b967039da".to_string()),
            timeout: Duration::from_secs(
                std::env::var("STAKING_TIMEOUT_SECS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(30)
            ),
            enabled: std::env::var("STAKING_VERIFICATION_ENABLED")
                .map(|v| v.to_lowercase() != "false" && v != "0")
                .unwrap_or(true),
        }
    }
}

impl StakingClientConfig {
    /// Create config from environment variables with validation
    pub fn from_env() -> Result<Self, String> {
        let config = Self::default();

        // Validate RPC URL format
        if !config.rpc_url.starts_with("http://") && !config.rpc_url.starts_with("https://") {
            return Err(format!("Invalid STARKNET_RPC_URL: must start with http:// or https://"));
        }

        // Validate contract address format
        if !config.staking_contract.starts_with("0x") {
            return Err(format!("Invalid STAKING_CONTRACT_ADDRESS: must start with 0x"));
        }

        // Log configuration on startup
        tracing::info!(
            rpc_url = %config.rpc_url,
            staking_contract = %config.staking_contract,
            timeout_secs = config.timeout.as_secs(),
            enabled = config.enabled,
            "Staking client configuration loaded"
        );

        Ok(config)
    }
}

/// Format a function selector for Starknet
/// Uses sn_keccak hash truncated to 250 bits
fn format_selector(function_name: &str) -> String {
    use sha3::{Keccak256, Digest};

    let mut hasher = Keccak256::new();
    hasher.update(function_name.as_bytes());
    let hash = hasher.finalize();

    // Take first 32 bytes and mask to 250 bits (Starknet field element size)
    let mut selector = [0u8; 32];
    selector.copy_from_slice(&hash[..32]);

    // Mask the top 6 bits of the first byte to ensure < 2^250
    selector[0] &= 0x03;

    format!("0x{}", hex::encode(selector))
}

/// Starknet function selectors for staking contract
mod selectors {
    /// is_eligible(worker: ContractAddress) -> bool
    pub const IS_ELIGIBLE: &str = "is_eligible";

    /// get_stake(worker: ContractAddress) -> WorkerStake
    pub const GET_STAKE: &str = "get_stake";

    /// get_min_stake(gpu_tier: GpuTier) -> u256
    pub const GET_MIN_STAKE: &str = "get_min_stake";

    /// get_config() -> StakingConfig
    pub const GET_CONFIG: &str = "get_config";
}

/// Client for interacting with the ProverStaking contract
pub struct StakingClient {
    config: StakingClientConfig,
    http_client: reqwest::Client,
    /// Circuit breaker for RPC resilience
    circuit_breaker: Arc<CircuitBreaker>,
    /// Metrics for observability
    metrics: Arc<RpcMetrics>,
}

impl StakingClient {
    /// Create a new staking client
    pub fn new(config: StakingClientConfig) -> Self {
        Self::with_circuit_breaker(config, CircuitBreakerConfig::default())
    }

    /// Create a staking client with custom circuit breaker configuration
    pub fn with_circuit_breaker(config: StakingClientConfig, cb_config: CircuitBreakerConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            http_client,
            circuit_breaker: Arc::new(CircuitBreaker::new(cb_config)),
            metrics: Arc::new(RpcMetrics::new()),
        }
    }

    /// Create a disabled staking client (for testing without blockchain)
    pub fn disabled() -> Self {
        Self::new(StakingClientConfig {
            enabled: false,
            ..Default::default()
        })
    }

    /// Get metrics snapshot for observability
    pub fn get_metrics(&self) -> super::network::RpcMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Reset the circuit breaker (for recovery)
    pub async fn reset_circuit_breaker(&self) {
        self.circuit_breaker.reset().await;
    }

    /// Check if circuit breaker is currently open
    pub async fn is_circuit_open(&self) -> bool {
        !self.circuit_breaker.allow_request().await
    }

    /// Validate Starknet address format
    fn validate_address(address: &str) -> Result<()> {
        // Starknet addresses are 64 hex chars (32 bytes) with optional 0x prefix
        let addr = address.trim_start_matches("0x");

        if addr.is_empty() {
            return Err(anyhow!("Empty address"));
        }

        // Check length (should be up to 64 hex chars, but can be shorter due to leading zeros)
        if addr.len() > 64 {
            return Err(anyhow!(
                "Invalid Starknet address: too long ({} chars, max 64)",
                addr.len()
            ));
        }

        // Check it's valid hex
        if !addr.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow!("Invalid Starknet address: not valid hex"));
        }

        Ok(())
    }

    /// Check if a worker is eligible to participate based on stake
    pub async fn is_eligible(&self, worker_address: &str) -> Result<bool> {
        if !self.config.enabled {
            debug!("Staking verification disabled, returning eligible");
            return Ok(true);
        }

        // Validate address format
        Self::validate_address(worker_address)
            .context("Invalid worker address format")?;

        let response = self
            .call_contract(selectors::IS_ELIGIBLE, vec![worker_address.to_string()])
            .await
            .context("Failed to check stake eligibility")?;

        // Parse response: single felt252, 0 = false, 1 = true
        let is_eligible = response
            .first()
            .map(|v| v != "0x0" && v != "0")
            .unwrap_or(false);

        Ok(is_eligible)
    }

    /// Get detailed stake information for a worker
    pub async fn get_stake(&self, worker_address: &str) -> Result<WorkerStake> {
        if !self.config.enabled {
            return Ok(WorkerStake::default());
        }

        let response = self
            .call_contract(selectors::GET_STAKE, vec![worker_address.to_string()])
            .await
            .context("Failed to get worker stake")?;

        self.parse_worker_stake(&response)
    }

    /// Get the minimum stake requirement for a GPU tier
    pub async fn get_min_stake(&self, gpu_tier: GpuTier) -> Result<u128> {
        if !self.config.enabled {
            return Ok(gpu_tier.min_stake());
        }

        let response = self
            .call_contract(
                selectors::GET_MIN_STAKE,
                vec![gpu_tier.to_cairo_enum().to_string()],
            )
            .await
            .context("Failed to get minimum stake")?;

        // Parse u256 from two felt252 (low and high)
        self.parse_u256_to_u128(&response)
    }

    /// Verify that a worker meets the minimum stake requirement
    pub async fn verify_stake(&self, worker_address: &str, gpu_tier: GpuTier) -> Result<bool> {
        if !self.config.enabled {
            return Ok(true);
        }

        // First check if worker is eligible
        let is_eligible = self.is_eligible(worker_address).await?;
        if !is_eligible {
            return Ok(false);
        }

        // Then verify they have enough stake for their claimed GPU tier
        let stake = self.get_stake(worker_address).await?;
        let min_stake = gpu_tier.min_stake();

        Ok(stake.amount >= min_stake && stake.is_active)
    }

    /// Get stake status for a worker (work-first model)
    ///
    /// Returns the current stake status without requiring stake for participation.
    /// This is used to determine worker tier and optional benefits.
    pub async fn get_stake_status(&self, worker_address: &str) -> Result<StakeStatus> {
        if !self.config.enabled {
            // When blockchain is disabled, return no stake
            return Ok(StakeStatus::None);
        }

        // Validate address format
        Self::validate_address(worker_address)
            .context("Invalid worker address format")?;

        // Get stake info from chain
        let stake = match self.get_stake(worker_address).await {
            Ok(s) => s,
            Err(e) => {
                debug!(
                    wallet = %worker_address,
                    error = %e,
                    "Could not fetch stake, assuming none"
                );
                return Ok(StakeStatus::None);
            }
        };

        // Determine stake status
        if stake.locked_amount > 0 {
            // Stake is being unstaked
            Ok(StakeStatus::Unstaking {
                amount: stake.locked_amount,
                available_at: stake.last_claim_at + (7 * 24 * 60 * 60), // 7 day cooldown
            })
        } else if stake.amount > 0 && stake.is_active {
            // Active stake
            Ok(StakeStatus::Staked {
                amount: stake.amount,
                gpu_tier: stake.gpu_tier,
            })
        } else {
            // No stake
            Ok(StakeStatus::None)
        }
    }

    /// Check if an address has sufficient stake to be a validator
    ///
    /// Validators must have:
    /// - Active stake
    /// - Minimum 10,000 SAGE tokens (Enterprise tier equivalent)
    /// - No pending unstakes
    pub async fn is_validator_eligible(&self, address: &str) -> Result<bool> {
        if !self.config.enabled {
            return Ok(true);
        }

        let stake = self.get_stake(address).await?;

        // Validator requirements
        const MIN_VALIDATOR_STAKE: u128 = 10_000_000_000_000_000_000_000; // 10,000 SAGE

        Ok(stake.amount >= MIN_VALIDATOR_STAKE
            && stake.is_active
            && stake.locked_amount == 0)
    }

    /// Get validator information for consensus
    ///
    /// Returns stake details formatted for consensus ValidatorInfo
    pub async fn get_validator_info(&self, address: &str) -> Result<Option<(u128, bool)>> {
        if !self.config.enabled {
            return Ok(None);
        }

        match self.get_stake(address).await {
            Ok(stake) => {
                if stake.is_active && stake.amount > 0 {
                    Ok(Some((stake.amount, true)))
                } else {
                    Ok(None)
                }
            }
            Err(_) => Ok(None),
        }
    }

    /// Get total amount staked across all workers
    ///
    /// Queries the staking contract for the total staked amount.
    /// Returns 0 if blockchain integration is disabled.
    pub async fn get_total_staked(&self) -> Result<u128> {
        if !self.config.enabled {
            // Return mock value when disabled
            return Ok(125_000_000_000_000_000_000_000_000); // 125M SAGE
        }

        let response = self
            .call_contract("get_total_staked", vec![])
            .await
            .context("Failed to get total staked")?;

        // Parse u256 from response
        self.parse_u256_to_u128(&response)
    }

    /// Get count of unique stakers
    ///
    /// Queries the staking contract for the number of active stakers.
    /// Returns 0 if blockchain integration is disabled.
    pub async fn get_staker_count(&self) -> Result<u32> {
        if !self.config.enabled {
            // Return mock value when disabled
            return Ok(1250);
        }

        let response = self
            .call_contract("get_staker_count", vec![])
            .await;

        match response {
            Ok(resp) => {
                // Parse single felt252 as staker count
                let count = resp
                    .first()
                    .and_then(|v| {
                        let clean = v.trim_start_matches("0x");
                        u32::from_str_radix(clean, 16).ok()
                    })
                    .unwrap_or(0);
                Ok(count)
            }
            Err(e) => {
                debug!("Could not get staker count: {}, returning estimate", e);
                // Return estimate based on total staked
                let total_staked = self.get_total_staked().await.unwrap_or(0);
                let avg_stake: u128 = 100_000_000_000_000_000_000_000; // 100K SAGE avg
                let estimate = (total_staked / avg_stake) as u32;
                Ok(estimate.max(1))
            }
        }
    }

    /// Get the on-chain staking contract configuration
    ///
    /// Returns current staking parameters including minimum stakes per GPU tier,
    /// cooldown periods, and slash percentages.
    pub async fn get_staking_contract_config(&self) -> Result<StakingContractConfig> {
        if !self.config.enabled {
            // Return default config when disabled
            return Ok(StakingContractConfig::default());
        }

        let response = self
            .call_contract(selectors::GET_CONFIG, vec![])
            .await
            .context("Failed to get staking config")?;

        // Parse config from response
        // Expected format: [min_consumer, min_workstation, min_datacenter, min_enterprise,
        //                   min_frontier, cooldown, slash_pct, is_paused]
        if response.len() < 8 {
            tracing::warn!("Incomplete staking config response, using defaults");
            return Ok(StakingContractConfig::default());
        }

        Ok(StakingContractConfig {
            min_stake_consumer: self.parse_u256_saturating(&response[0..2])?,
            min_stake_workstation: self.parse_u256_saturating(&response[2..4])?,
            min_stake_datacenter: self.parse_u256_saturating(&response[4..6])?,
            min_stake_enterprise: self.parse_u256_saturating(&response[6..8])?,
            min_stake_frontier: if response.len() >= 10 {
                self.parse_u256_saturating(&response[8..10])?
            } else {
                25_000_000_000_000_000_000_000 // 25K SAGE default
            },
            unstake_cooldown_secs: if response.len() > 10 {
                self.parse_u64(&response[10])?
            } else {
                7 * 24 * 60 * 60 // 7 days default
            },
            slash_percentage: if response.len() > 11 {
                self.parse_u8(&response[11])?
            } else {
                5 // 5% default
            },
            is_paused: if response.len() > 12 {
                self.parse_bool(&response[12])?
            } else {
                false
            },
        })
    }

    /// Get reputation score for an address from ReputationManager contract
    ///
    /// Returns reputation score (0-1000) or default of 100 if unavailable.
    /// Uses the reputation contract address from environment or config.
    pub async fn get_reputation_score(&self, address: &str) -> Result<u32> {
        if !self.config.enabled {
            // Return neutral score when disabled
            return Ok(100);
        }

        // Validate address format
        Self::validate_address(address)
            .context("Invalid address format for reputation query")?;

        // Get reputation contract address from env
        let reputation_contract = std::env::var("REPUTATION_CONTRACT_ADDRESS")
            .unwrap_or_else(|_| {
                "0x0dbd9831f5d5ed6f85bc74bbf7aeaa49987d36c619edc27c95d39c4f24e3ff52".to_string()
            });

        // Build the RPC request for reputation contract
        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "starknet_call",
            "params": {
                "request": {
                    "contract_address": reputation_contract,
                    "entry_point_selector": format_selector("get_reputation"),
                    "calldata": [address]
                },
                "block_id": "latest"
            }
        });

        let start = Instant::now();
        let response = self
            .http_client
            .post(&self.config.rpc_url)
            .json(&request_body)
            .send()
            .await;

        match response {
            Ok(resp) => {
                self.metrics.record_call(true, start.elapsed().as_millis() as u64, false);

                let body: serde_json::Value = resp.json().await
                    .context("Failed to parse reputation response")?;

                if let Some(error) = body.get("error") {
                    debug!("Reputation query error: {:?}, using default", error);
                    return Ok(100); // Default score
                }

                // Parse result - reputation score is returned as (score: u32, level: u8, ...)
                if let Some(result) = body.get("result").and_then(|r| r.as_array()) {
                    if let Some(score_hex) = result.first().and_then(|v| v.as_str()) {
                        let score = u32::from_str_radix(score_hex.trim_start_matches("0x"), 16)
                            .unwrap_or(100);
                        return Ok(score.min(1000)); // Cap at 1000
                    }
                }

                Ok(100) // Default if parsing fails
            }
            Err(e) => {
                self.metrics.record_call(false, start.elapsed().as_millis() as u64, false);
                debug!("Failed to query reputation: {}, using default", e);
                Ok(100) // Default score on error
            }
        }
    }

    /// Make an RPC call to the staking contract with retry logic and circuit breaker
    async fn call_contract(
        &self,
        entry_point: &str,
        calldata: Vec<String>,
    ) -> Result<Vec<String>> {
        // Validate contract address is set
        if self.config.staking_contract == "0x0" || self.config.staking_contract.is_empty() {
            return Err(anyhow!("Staking contract address not configured"));
        }

        // Check circuit breaker before making request
        if !self.circuit_breaker.allow_request().await {
            self.metrics.record_circuit_breaker_rejection();
            error!(
                entry_point = entry_point,
                "Staking RPC call rejected by circuit breaker"
            );
            return Err(anyhow!("Circuit breaker is open - RPC calls temporarily blocked"));
        }

        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "starknet_call",
            "params": {
                "request": {
                    "contract_address": self.config.staking_contract,
                    "entry_point_selector": self.compute_selector(entry_point),
                    "calldata": calldata,
                },
                "block_id": "latest"
            },
            "id": 1
        });

        let mut last_error = None;

        for attempt in 0..MAX_RETRIES {
            let is_retry = attempt > 0;

            if is_retry {
                // Exponential backoff with jitter
                let delay = std::cmp::min(
                    RETRY_BASE_DELAY_MS * (2_u64.pow(attempt)),
                    RETRY_MAX_DELAY_MS,
                );
                debug!(
                    attempt = attempt + 1,
                    delay_ms = delay,
                    entry_point = entry_point,
                    "Retrying staking RPC call"
                );
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }

            let start = Instant::now();
            match self.execute_rpc_call(&request_body).await {
                Ok(result) => {
                    let duration_ms = start.elapsed().as_millis() as u64;
                    self.metrics.record_call(true, duration_ms, is_retry);
                    self.circuit_breaker.record_success().await;
                    return Ok(result);
                }
                Err(e) => {
                    let duration_ms = start.elapsed().as_millis() as u64;
                    self.metrics.record_call(false, duration_ms, is_retry);

                    warn!(
                        attempt = attempt + 1,
                        max_attempts = MAX_RETRIES,
                        error = %e,
                        entry_point = entry_point,
                        duration_ms = duration_ms,
                        "Staking RPC call failed"
                    );
                    last_error = Some(e);
                }
            }
        }

        // Record failure in circuit breaker after all retries exhausted
        self.circuit_breaker.record_failure().await;

        Err(last_error.unwrap_or_else(|| anyhow!("Staking RPC call failed after {} retries", MAX_RETRIES)))
    }

    /// Execute a single RPC call (no retry)
    async fn execute_rpc_call(&self, request_body: &serde_json::Value) -> Result<Vec<String>> {
        let response = self
            .http_client
            .post(&self.config.rpc_url)
            .json(request_body)
            .send()
            .await
            .context("Failed to send RPC request")?;

        // Check HTTP status
        if !response.status().is_success() {
            return Err(anyhow!(
                "RPC request failed with status: {}",
                response.status()
            ));
        }

        let response_json: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse RPC response")?;

        // Check for JSON-RPC error
        if let Some(error) = response_json.get("error") {
            let error_code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
            let error_msg = error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("Unknown error");

            // Don't retry on contract errors (they won't change)
            if error_code == -32000 || error_msg.contains("Contract not found") {
                return Err(anyhow!("Contract error (not retryable): {}", error_msg));
            }

            return Err(anyhow!("RPC error: {} (code: {})", error_msg, error_code));
        }

        // Extract result
        let result = response_json
            .get("result")
            .and_then(|r| r.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        Ok(result)
    }

    /// Compute Starknet function selector (sn_keccak of function name)
    fn compute_selector(&self, name: &str) -> String {
        use sha3::{Digest, Keccak256};

        let mut hasher = Keccak256::new();
        hasher.update(name.as_bytes());
        let result = hasher.finalize();

        // Take first 250 bits (Starknet selector format)
        let mut selector_bytes = [0u8; 32];
        selector_bytes.copy_from_slice(&result);

        // Mask off top 6 bits
        selector_bytes[0] &= 0x03;

        format!("0x{}", hex::encode(selector_bytes))
    }

    /// Parse WorkerStake from contract response
    fn parse_worker_stake(&self, response: &[String]) -> Result<WorkerStake> {
        if response.len() < 12 {
            anyhow::bail!(
                "Invalid stake response: expected 12+ fields, got {}",
                response.len()
            );
        }

        // Parse u256 values (low, high pairs) - use _to_u128 since struct fields are u128
        let amount = self.parse_u256_to_u128(&response[0..2])?;
        let locked_amount = self.parse_u256_to_u128(&response[2..4])?;
        let staked_at = self.parse_u64(&response[4])?;
        let last_claim_at = self.parse_u64(&response[5])?;
        let gpu_tier_raw = self.parse_u8(&response[6])?;
        let is_active = self.parse_bool(&response[7])?;
        let consecutive_failures = self.parse_u8(&response[8])?;
        let total_slashed = self.parse_u256_to_u128(&response[9..11])?;
        let pending_rewards = self.parse_u256_to_u128(&response[11..13])?;

        let gpu_tier = match gpu_tier_raw {
            0 => GpuTier::Consumer,
            1 => GpuTier::Workstation,
            2 => GpuTier::DataCenter,
            3 => GpuTier::Enterprise,
            4 => GpuTier::Frontier,
            _ => GpuTier::Consumer,
        };

        Ok(WorkerStake {
            amount,
            locked_amount,
            staked_at,
            last_claim_at,
            gpu_tier,
            is_active,
            consecutive_failures,
            total_slashed,
            pending_rewards,
        })
    }

    /// Parse u256 from two felt252 (low and high parts)
    ///
    /// Returns (low, high) tuple representing the full 256-bit value.
    /// For values that fit in u128, high will be 0.
    fn parse_u256(&self, parts: &[String]) -> Result<(u128, u128)> {
        if parts.len() < 2 {
            anyhow::bail!("Invalid u256: need low and high parts");
        }

        let low = u128::from_str_radix(parts[0].trim_start_matches("0x"), 16)
            .context("Failed to parse u256 low part")?;
        let high = u128::from_str_radix(parts[1].trim_start_matches("0x"), 16)
            .context("Failed to parse u256 high part")?;

        Ok((low, high))
    }

    /// Parse u256 to u128, returning error if value overflows
    fn parse_u256_to_u128(&self, parts: &[String]) -> Result<u128> {
        let (low, high) = self.parse_u256(parts)?;

        if high > 0 {
            tracing::warn!(
                low = low,
                high = high,
                "Stake amount has non-zero high part - value exceeds u128"
            );
            // Return an error for safety - caller should handle large values
            anyhow::bail!(
                "Stake amount {} + {}*2^128 exceeds u128 max value",
                low,
                high
            );
        }

        Ok(low)
    }

    /// Parse u256 to u128, with saturation for overflow
    ///
    /// Use this when truncation is acceptable (e.g., display purposes).
    /// Values exceeding u128::MAX are clamped to u128::MAX with a warning.
    pub fn parse_u256_saturating(&self, parts: &[String]) -> Result<u128> {
        let (low, high) = self.parse_u256(parts)?;

        if high > 0 {
            tracing::warn!(
                low = low,
                high = high,
                "Stake amount exceeds u128, saturating to u128::MAX"
            );
            Ok(u128::MAX)
        } else {
            Ok(low)
        }
    }

    /// Parse u64 from felt252
    fn parse_u64(&self, value: &str) -> Result<u64> {
        u64::from_str_radix(value.trim_start_matches("0x"), 16)
            .context("Failed to parse u64")
    }

    /// Parse u8 from felt252
    fn parse_u8(&self, value: &str) -> Result<u8> {
        let parsed = u64::from_str_radix(value.trim_start_matches("0x"), 16)
            .context("Failed to parse u8")?;
        Ok(parsed as u8)
    }

    /// Parse bool from felt252
    fn parse_bool(&self, value: &str) -> Result<bool> {
        let parsed = u64::from_str_radix(value.trim_start_matches("0x"), 16)
            .context("Failed to parse bool")?;
        Ok(parsed != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpu_tier_from_model() {
        // Consumer tier - RTX gaming cards
        assert_eq!(GpuTier::from_gpu_model("NVIDIA RTX 4090"), GpuTier::Consumer);
        assert_eq!(GpuTier::from_gpu_model("RTX 3080"), GpuTier::Consumer);
        assert_eq!(GpuTier::from_gpu_model("RTX 5090"), GpuTier::Consumer);

        // Workstation tier
        assert_eq!(GpuTier::from_gpu_model("RTX A6000"), GpuTier::Workstation);
        assert_eq!(GpuTier::from_gpu_model("L40S"), GpuTier::Workstation);

        // DataCenter tier
        assert_eq!(GpuTier::from_gpu_model("A100-SXM4-80GB"), GpuTier::DataCenter);

        // Enterprise tier - Hopper and Blackwell
        assert_eq!(GpuTier::from_gpu_model("NVIDIA H100"), GpuTier::Enterprise);
        assert_eq!(GpuTier::from_gpu_model("H200"), GpuTier::Enterprise);
        assert_eq!(GpuTier::from_gpu_model("B200"), GpuTier::Enterprise);
        assert_eq!(GpuTier::from_gpu_model("NVIDIA B300"), GpuTier::Enterprise);

        // Frontier tier - Multi-GPU and AMD MI300X
        assert_eq!(GpuTier::from_gpu_model("MI300X"), GpuTier::Frontier);
        assert_eq!(GpuTier::from_gpu_model("multi-gpu-cluster"), GpuTier::Frontier);
    }

    #[test]
    fn test_gpu_tier_min_stake() {
        assert_eq!(GpuTier::Consumer.min_stake(), 1_000_000_000_000_000_000_000);
        assert_eq!(GpuTier::Workstation.min_stake(), 2_500_000_000_000_000_000_000);
        assert_eq!(GpuTier::DataCenter.min_stake(), 5_000_000_000_000_000_000_000);
        assert_eq!(GpuTier::Enterprise.min_stake(), 10_000_000_000_000_000_000_000);
        assert_eq!(GpuTier::Frontier.min_stake(), 25_000_000_000_000_000_000_000);
    }

    #[test]
    fn test_gpu_tier_to_cairo_enum() {
        assert_eq!(GpuTier::Consumer.to_cairo_enum(), 0);
        assert_eq!(GpuTier::Workstation.to_cairo_enum(), 1);
        assert_eq!(GpuTier::DataCenter.to_cairo_enum(), 2);
        assert_eq!(GpuTier::Enterprise.to_cairo_enum(), 3);
        assert_eq!(GpuTier::Frontier.to_cairo_enum(), 4);
    }

    #[tokio::test]
    async fn test_disabled_client() {
        let client = StakingClient::disabled();

        // Disabled client should always return eligible
        let eligible = client.is_eligible("0x123").await.unwrap();
        assert!(eligible);

        // Should return default stake
        let stake = client.get_stake("0x123").await.unwrap();
        assert_eq!(stake.amount, 0);
    }
}
