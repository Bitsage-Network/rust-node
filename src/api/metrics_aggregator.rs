//! Metrics Aggregator
//!
//! Aggregates metrics from multiple sources:
//! - Blockchain (stake, reputation, rewards)
//! - Database (job counts, earnings)
//! - System (GPU metrics via NVML)

use anyhow::{Result, anyhow};
use serde::Serialize;
use std::sync::Arc;
use tracing::{debug, warn, error};
use sqlx::{PgPool, Row};

use crate::gpu::{GpuMonitor, GpuMetrics};
use crate::obelysk::starknet::{
    StarknetClient, StakingClient, ReputationClient,
};

/// Aggregated validator metrics
#[derive(Debug, Clone, Serialize)]
pub struct ValidatorMetrics {
    /// Wallet address
    pub address: String,

    /// Is validator active
    pub is_active: bool,

    /// Is registered on-chain
    pub is_registered: bool,

    /// Staked amount (wei)
    pub staked_amount: String,

    /// Stake tier
    pub stake_tier: String,

    /// Reputation score (0-1000)
    pub reputation_score: u32,

    /// Total jobs completed
    pub jobs_completed: u64,

    /// Jobs currently in progress
    pub jobs_in_progress: u32,

    /// Failed jobs
    pub jobs_failed: u64,

    /// Uptime percentage
    pub uptime_percent: f32,

    /// Last heartbeat timestamp
    pub last_heartbeat: Option<u64>,
}

/// Aggregated GPU metrics
#[derive(Debug, Clone, Serialize)]
pub struct AggregatedGpuMetrics {
    /// Individual GPU metrics
    pub gpus: Vec<GpuMetrics>,

    /// Total GPUs
    pub total_gpus: u32,

    /// Active GPUs (running jobs)
    pub active_gpus: u32,

    /// Average utilization across all GPUs
    pub avg_utilization: f32,

    /// Total compute power (estimated TFLOPs)
    pub total_tflops: f32,
}

/// Aggregated rewards information
#[derive(Debug, Clone, Serialize)]
pub struct AggregatedRewards {
    /// Claimable rewards (wei)
    pub claimable_rewards: String,

    /// Pending rewards not yet claimable (wei)
    pub pending_rewards: String,

    /// Total earned lifetime (wei)
    pub total_earned: String,

    /// Total claimed lifetime (wei)
    pub total_claimed: String,

    /// Estimated APY (basis points)
    pub estimated_apy_bps: u32,

    /// Last claim timestamp
    pub last_claim_at: Option<u64>,

    /// Mining rewards from jobs
    pub mining_rewards: String,

    /// Staking rewards
    pub staking_rewards: String,
}

/// Metrics Aggregator
pub struct MetricsAggregator {
    /// PostgreSQL connection pool
    db: PgPool,

    /// Starknet client for on-chain queries
    starknet: Arc<StarknetClient>,

    /// Staking contract client
    staking_client: Arc<StakingClient>,

    /// Reputation contract client
    reputation_client: Arc<ReputationClient>,

    /// GPU monitor (optional - None if no GPUs)
    gpu_monitor: Option<GpuMonitor>,

    /// Contract addresses
    contracts: ContractAddresses,
}

#[derive(Clone)]
pub struct ContractAddresses {
    pub prover_staking: String,
    pub reputation_manager: String,
    pub mining_rewards: Option<String>,
}

impl MetricsAggregator {
    /// Create a new metrics aggregator
    pub async fn new(
        db: PgPool,
        starknet: Arc<StarknetClient>,
        staking_client: Arc<StakingClient>,
        reputation_client: Arc<ReputationClient>,
        contracts: ContractAddresses,
    ) -> Result<Self> {
        // Initialize GPU monitor (may return None if no GPUs)
        let gpu_monitor = match crate::gpu::initialize_gpu_monitor() {
            Ok(monitor) => monitor,
            Err(e) => {
                warn!("Failed to initialize GPU monitor: {}", e);
                None
            }
        };

        Ok(Self {
            db,
            starknet,
            staking_client,
            reputation_client,
            gpu_monitor,
            contracts,
        })
    }

    /// Get aggregated validator metrics
    pub async fn get_validator_metrics(&self, address: &str) -> Result<ValidatorMetrics> {
        debug!("Aggregating validator metrics for {}", address);

        // Query stake info from blockchain
        let (staked_amount, stake_tier) = self.query_stake_info(address).await
            .unwrap_or_else(|e| {
                warn!("Failed to query stake info from blockchain: {}", e);
                ("0".to_string(), "None".to_string())
            });

        // Query reputation from blockchain
        let reputation_score = self.query_reputation(address).await
            .unwrap_or_else(|e| {
                warn!("Failed to query reputation from blockchain: {}", e);
                0
            });

        // Query job counts from database
        let (jobs_completed, jobs_in_progress, jobs_failed) = self.query_job_counts(address).await
            .unwrap_or_else(|e| {
                warn!("Failed to query job counts from database: {}", e);
                (0, 0, 0)
            });

        // Calculate uptime (simplified - based on heartbeats)
        let uptime_percent = self.calculate_uptime(address).await
            .unwrap_or(0.0);

        // Get last heartbeat
        let last_heartbeat = self.get_last_heartbeat(address).await.ok();

        // Determine if active (has stake and recent heartbeat)
        let is_active = staked_amount != "0" &&
                       matches!(last_heartbeat, Some(ts) if ts > (chrono::Utc::now().timestamp() as u64 - 300));

        let is_registered = staked_amount != "0";

        Ok(ValidatorMetrics {
            address: address.to_string(),
            is_active,
            is_registered,
            staked_amount,
            stake_tier,
            reputation_score,
            jobs_completed,
            jobs_in_progress,
            jobs_failed,
            uptime_percent,
            last_heartbeat,
        })
    }

    /// Get aggregated GPU metrics
    pub async fn get_gpu_metrics(&self) -> Result<AggregatedGpuMetrics> {
        let gpus = if let Some(ref monitor) = self.gpu_monitor {
            match monitor.get_all_gpus() {
                Ok(gpus) => gpus,
                Err(e) => {
                    error!("Failed to get GPU metrics from NVML: {}", e);
                    crate::gpu::nvml_monitor::create_mock_gpu_metrics()
                }
            }
        } else {
            // No GPU monitor - return mock data
            crate::gpu::nvml_monitor::create_mock_gpu_metrics()
        };

        let total_gpus = gpus.len() as u32;
        let active_gpus = gpus.iter()
            .filter(|g| g.current_job_id.is_some() || g.compute_utilization > 5.0)
            .count() as u32;

        let avg_utilization = if !gpus.is_empty() {
            gpus.iter().map(|g| g.compute_utilization).sum::<f32>() / gpus.len() as f32
        } else {
            0.0
        };

        // Estimate TFLOPs (very rough - based on GPU tier and count)
        let total_tflops = gpus.iter().map(|g| Self::estimate_tflops(&g.tier)).sum();

        Ok(AggregatedGpuMetrics {
            gpus,
            total_gpus,
            active_gpus,
            avg_utilization,
            total_tflops,
        })
    }

    /// Get aggregated rewards information
    pub async fn get_rewards(&self, address: &str) -> Result<AggregatedRewards> {
        debug!("Aggregating rewards for {}", address);

        // Query on-chain rewards
        let (claimable, pending, staking_rewards) = self.query_onchain_rewards(address).await
            .unwrap_or_else(|e| {
                warn!("Failed to query on-chain rewards: {}", e);
                ("0".to_string(), "0".to_string(), "0".to_string())
            });

        // Query historical earnings from database
        let (total_earned, total_claimed, mining_rewards) = self.query_historical_earnings(address).await
            .unwrap_or_else(|e| {
                warn!("Failed to query historical earnings: {}", e);
                ("0".to_string(), "0".to_string(), "0".to_string())
            });

        // Calculate estimated APY
        let estimated_apy_bps = self.calculate_apy(address).await
            .unwrap_or(0);

        // Get last claim timestamp
        let last_claim_at = self.get_last_claim_timestamp(address).await.ok();

        Ok(AggregatedRewards {
            claimable_rewards: claimable,
            pending_rewards: pending,
            total_earned,
            total_claimed,
            estimated_apy_bps,
            last_claim_at,
            mining_rewards,
            staking_rewards,
        })
    }

    // ========================================================================
    // Blockchain Queries
    // ========================================================================

    /// Query stake info from ProverStaking contract
    async fn query_stake_info(&self, address: &str) -> Result<(String, String)> {
        debug!("Querying stake info for {} from ProverStaking contract", address);

        // Call the staking client to get stake information
        match self.staking_client.get_stake(address).await {
            Ok(stake) => {
                let amount = stake.amount.to_string();
                let tier = format!("{}", stake.gpu_tier);
                debug!("✅ Retrieved stake: {} wei, tier: {}", amount, tier);
                Ok((amount, tier))
            }
            Err(e) => {
                warn!("Failed to query stake info from blockchain: {}", e);
                // Return zero stake as fallback
                Ok(("0".to_string(), "None".to_string()))
            }
        }
    }

    /// Query reputation from ReputationManager contract
    async fn query_reputation(&self, address: &str) -> Result<u32> {
        debug!("Querying reputation for {} from ReputationManager contract", address);

        // Call the reputation client to get reputation score
        match self.reputation_client.get_reputation(address).await {
            Ok(reputation) => {
                debug!("✅ Retrieved reputation score: {} (level: {})", reputation.score, reputation.level);
                Ok(reputation.score)
            }
            Err(e) => {
                warn!("Failed to query reputation from blockchain: {}", e);
                // Return neutral reputation score as fallback
                Ok(500) // Default neutral score (50.00 out of 100.00)
            }
        }
    }

    /// Query on-chain rewards
    async fn query_onchain_rewards(&self, address: &str) -> Result<(String, String, String)> {
        debug!("Querying on-chain rewards for {}", address);

        // Query staking rewards from ProverStaking contract
        let staking_rewards = match self.staking_client.get_stake(address).await {
            Ok(stake) => {
                debug!("✅ Retrieved pending staking rewards: {} wei", stake.pending_rewards);
                stake.pending_rewards.to_string()
            }
            Err(e) => {
                warn!("Failed to query staking rewards: {}", e);
                "0".to_string()
            }
        };

        // For now, mining rewards would come from a separate contract if deployed
        // Since we don't have that integrated yet, we'll use "0"
        let mining_rewards = "0".to_string();

        // Claimable = pending staking rewards for now
        let claimable = staking_rewards.clone();

        debug!("Rewards - Claimable: {}, Pending: {}, Staking: {}",
               claimable, mining_rewards, staking_rewards);

        Ok((claimable, mining_rewards, staking_rewards))
    }

    // ========================================================================
    // Database Queries
    // ========================================================================

    /// Query job counts from database
    async fn query_job_counts(&self, address: &str) -> Result<(u64, u32, u64)> {
        let result = sqlx::query(
            r#"
            SELECT
                COUNT(*) FILTER (WHERE status = 'completed') as completed,
                COUNT(*) FILTER (WHERE status IN ('pending', 'running')) as in_progress,
                COUNT(*) FILTER (WHERE status = 'failed') as failed
            FROM jobs
            WHERE worker_address = $1
            "#
        )
        .bind(address)
        .fetch_one(&self.db)
        .await?;

        Ok((
            result.try_get::<i64, _>("completed").unwrap_or(0) as u64,
            result.try_get::<i64, _>("in_progress").unwrap_or(0) as u32,
            result.try_get::<i64, _>("failed").unwrap_or(0) as u64,
        ))
    }

    /// Query historical earnings from database
    async fn query_historical_earnings(&self, address: &str) -> Result<(String, String, String)> {
        let result = sqlx::query(
            r#"
            SELECT
                COALESCE(SUM(payment_amount), 0) as total_earned
            FROM jobs
            WHERE worker_address = $1 AND status = 'completed'
            "#
        )
        .bind(address)
        .fetch_one(&self.db)
        .await?;

        let total_earned: i64 = result.try_get("total_earned").unwrap_or(0);
        let total_earned_str = total_earned.to_string();

        // Claimed amount would come from blockchain events
        // For now, we'll query from a claims table if it exists
        let claimed = sqlx::query(
            r#"
            SELECT COALESCE(SUM(amount), 0) as total_claimed
            FROM reward_claims
            WHERE address = $1
            "#
        )
        .bind(address)
        .fetch_optional(&self.db)
        .await?
        .map(|r| r.try_get::<i64, _>("total_claimed").unwrap_or(0).to_string())
        .unwrap_or_else(|| "0".to_string());

        Ok((total_earned_str.clone(), claimed, total_earned_str))
    }

    /// Calculate uptime based on heartbeats
    async fn calculate_uptime(&self, address: &str) -> Result<f32> {
        // Query heartbeat history from database
        let result = sqlx::query(
            r#"
            SELECT
                COUNT(*) as total_expected,
                COUNT(*) FILTER (WHERE heartbeat_time > NOW() - INTERVAL '1 hour') as recent_heartbeats
            FROM heartbeats
            WHERE worker_address = $1 AND heartbeat_time > NOW() - INTERVAL '24 hours'
            "#
        )
        .bind(address)
        .fetch_optional(&self.db)
        .await?;

        if let Some(r) = result {
            let total: i64 = r.try_get("total_expected").unwrap_or(0);
            let recent: i64 = r.try_get("recent_heartbeats").unwrap_or(0);

            if total > 0 {
                Ok((recent as f32 / total as f32) * 100.0)
            } else {
                Ok(0.0)
            }
        } else {
            Ok(0.0)
        }
    }

    /// Get last heartbeat timestamp
    async fn get_last_heartbeat(&self, address: &str) -> Result<u64> {
        let result = sqlx::query(
            r#"
            SELECT heartbeat_time
            FROM heartbeats
            WHERE worker_address = $1
            ORDER BY heartbeat_time DESC
            LIMIT 1
            "#
        )
        .bind(address)
        .fetch_optional(&self.db)
        .await?;

        result
            .map(|r| {
                let ts: chrono::NaiveDateTime = r.try_get("heartbeat_time").unwrap_or_default();
                ts.and_utc().timestamp() as u64
            })
            .ok_or_else(|| anyhow!("No heartbeat found"))
    }

    /// Get last claim timestamp
    async fn get_last_claim_timestamp(&self, address: &str) -> Result<u64> {
        let result = sqlx::query(
            r#"
            SELECT claim_time
            FROM reward_claims
            WHERE address = $1
            ORDER BY claim_time DESC
            LIMIT 1
            "#
        )
        .bind(address)
        .fetch_optional(&self.db)
        .await?;

        result
            .map(|r| {
                let ts: chrono::NaiveDateTime = r.try_get("claim_time").unwrap_or_default();
                ts.and_utc().timestamp() as u64
            })
            .ok_or_else(|| anyhow!("No claims found"))
    }

    /// Calculate APY based on historical data
    ///
    /// APY is calculated using the formula:
    /// APY = (Total Earnings / Staked Amount) * (365 / Days Active) * 10000
    ///
    /// Returns APY in basis points (1250 = 12.50%)
    async fn calculate_apy(&self, address: &str) -> Result<u32> {
        // Query historical earnings and staked amount
        let (total_earned, days_active) = self.query_earnings_history(address).await?;

        // Query current staked amount
        let staked_amount = match self.staking_client.get_stake(address).await {
            Ok(stake) => stake.amount,
            Err(_) => return Ok(1250), // Default 12.5% if stake unavailable
        };

        if staked_amount == 0 {
            return Ok(0); // No APY if no stake
        }

        if days_active == 0 {
            return Ok(1250); // Default 12.5% for new stakers
        }

        // Calculate APY: (earnings / stake) * (365 / days) * 10000 basis points
        let earnings_f = total_earned as f64 / 1e18; // Convert from wei
        let stake_f = staked_amount as f64 / 1e18;

        if stake_f == 0.0 {
            return Ok(0);
        }

        let return_rate = earnings_f / stake_f;
        let annualized = return_rate * (365.0 / days_active as f64);
        let apy_bps = (annualized * 10000.0) as u32;

        // Clamp to reasonable bounds (0% - 100%)
        let clamped_apy = apy_bps.clamp(0, 10000);

        debug!(
            "Calculated APY for {}: {:.2}% (earned={:.4} SAGE over {} days on {:.4} SAGE stake)",
            address,
            clamped_apy as f64 / 100.0,
            earnings_f,
            days_active,
            stake_f
        );

        Ok(clamped_apy)
    }

    /// Query earnings history for APY calculation
    async fn query_earnings_history(&self, address: &str) -> Result<(u128, u64)> {
        let result = sqlx::query(
            r#"
            SELECT
                COALESCE(SUM(payment_amount), 0)::bigint as total_earned,
                EXTRACT(DAY FROM (NOW() - MIN(completed_at)))::bigint as days_active
            FROM jobs
            WHERE worker_address = $1 AND status = 'completed'
            "#
        )
        .bind(address)
        .fetch_one(&self.db)
        .await?;

        let total_earned: i64 = result.try_get("total_earned").unwrap_or(0);
        let days_active: i64 = result.try_get("days_active").unwrap_or(0);

        Ok((total_earned as u128, days_active.max(1) as u64))
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    /// Estimate TFLOPs based on GPU tier
    fn estimate_tflops(tier: &str) -> f32 {
        match tier {
            "DataCenter" => 60.0,   // H100: ~60 TFLOPs FP32
            "Enterprise" => 40.0,   // A6000: ~40 TFLOPs FP32
            "Professional" => 80.0, // RTX 4090: ~82 TFLOPs FP32
            "Consumer" => 30.0,     // RTX 3080: ~30 TFLOPs FP32
            _ => 20.0,
        }
    }

    /// Get the Starknet client reference
    pub fn starknet(&self) -> &Arc<StarknetClient> {
        &self.starknet
    }

    /// Get the contract addresses
    pub fn contracts(&self) -> &ContractAddresses {
        &self.contracts
    }
}
