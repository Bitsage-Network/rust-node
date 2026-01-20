//! # Mining Rewards Module
//!
//! Implements per-job mining rewards with daily caps to prevent early validator capture.
//!
//! Key features:
//! - Per-job reward: Fixed SAGE per valid proof (not pool-based)
//! - Daily caps: Prevents any single validator from capturing too much
//! - Staking tier bonuses: Higher caps for staked validators
//! - GPU tier multipliers: Harder work = higher rewards
//! - Halvening schedule: Rewards decrease over time

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use chrono::{DateTime, Utc, Datelike};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::obelysk::starknet::{GpuTier, StakeStatus};

// =============================================================================
// Constants
// =============================================================================

/// Base mining reward per valid proof (in SAGE wei, 18 decimals)
/// 2 SAGE = 2_000_000_000_000_000_000 wei
pub const BASE_REWARD_WEI: u128 = 2_000_000_000_000_000_000;

/// Base mining reward in human-readable SAGE
pub const BASE_REWARD_SAGE: f64 = 2.0;

/// Mining pool total allocation (300M SAGE)
pub const MINING_POOL_TOTAL: u128 = 300_000_000_000_000_000_000_000_000;

// =============================================================================
// Daily Caps by Staking Tier (in SAGE, not wei)
// =============================================================================

/// Daily mining cap for validators with no stake
pub const CAP_NO_STAKE: u64 = 100;

/// Daily mining cap for Bronze tier (1,000 SAGE staked)
pub const CAP_BRONZE: u64 = 150;

/// Daily mining cap for Silver tier (10,000 SAGE staked)
pub const CAP_SILVER: u64 = 200;

/// Daily mining cap for Gold tier (50,000 SAGE staked)
pub const CAP_GOLD: u64 = 300;

/// Daily mining cap for Platinum tier (200,000 SAGE staked)
pub const CAP_PLATINUM: u64 = 500;

// =============================================================================
// Types
// =============================================================================

/// Staking tier for mining cap calculation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StakingTier {
    /// No stake - base participation
    None,
    /// Bronze: 1,000+ SAGE staked
    Bronze,
    /// Silver: 10,000+ SAGE staked
    Silver,
    /// Gold: 50,000+ SAGE staked
    Gold,
    /// Platinum: 200,000+ SAGE staked
    Platinum,
}

impl StakingTier {
    /// Determine staking tier from stake amount (in wei, 18 decimals)
    pub fn from_stake_amount(stake_wei: u128) -> Self {
        // Convert thresholds to wei (18 decimals)
        const SAGE_DECIMALS: u128 = 1_000_000_000_000_000_000;

        let platinum_threshold = 200_000 * SAGE_DECIMALS;
        let gold_threshold = 50_000 * SAGE_DECIMALS;
        let silver_threshold = 10_000 * SAGE_DECIMALS;
        let bronze_threshold = 1_000 * SAGE_DECIMALS;

        if stake_wei >= platinum_threshold {
            StakingTier::Platinum
        } else if stake_wei >= gold_threshold {
            StakingTier::Gold
        } else if stake_wei >= silver_threshold {
            StakingTier::Silver
        } else if stake_wei >= bronze_threshold {
            StakingTier::Bronze
        } else {
            StakingTier::None
        }
    }

    /// Get daily mining cap for this tier (in SAGE)
    pub fn daily_cap(&self) -> u64 {
        match self {
            StakingTier::None => CAP_NO_STAKE,
            StakingTier::Bronze => CAP_BRONZE,
            StakingTier::Silver => CAP_SILVER,
            StakingTier::Gold => CAP_GOLD,
            StakingTier::Platinum => CAP_PLATINUM,
        }
    }

    /// Get daily mining cap in wei
    pub fn daily_cap_wei(&self) -> u128 {
        (self.daily_cap() as u128) * 1_000_000_000_000_000_000
    }

    /// Human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            StakingTier::None => "No Stake (100 SAGE/day cap)",
            StakingTier::Bronze => "Bronze (150 SAGE/day cap)",
            StakingTier::Silver => "Silver (200 SAGE/day cap)",
            StakingTier::Gold => "Gold (300 SAGE/day cap)",
            StakingTier::Platinum => "Platinum (500 SAGE/day cap)",
        }
    }
}

/// GPU tier multiplier for mining rewards
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GpuMultiplier {
    pub gpu_tier: GpuTier,
    pub multiplier: f64,
}

impl GpuMultiplier {
    /// Get mining reward multiplier for GPU tier
    /// Higher-tier GPUs doing harder work get higher rewards
    pub fn for_gpu(gpu_tier: GpuTier) -> Self {
        let multiplier = match gpu_tier {
            GpuTier::Consumer => 1.0,      // RTX 3090/4090/5090
            GpuTier::Workstation => 1.25,  // A6000, L40S
            GpuTier::DataCenter => 1.5,    // A100
            GpuTier::Enterprise => 2.0,    // H100, H200, B200, B300
            GpuTier::Frontier => 2.5,      // MI300X, Multi-GPU clusters
        };
        Self { gpu_tier, multiplier }
    }
}

/// Halvening schedule for mining rewards
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct HalveningSchedule {
    /// Year since network launch (1-based)
    pub year: u32,
    /// Reward multiplier (1.0 = base, 0.5 = halved, etc.)
    pub multiplier: f64,
}

impl HalveningSchedule {
    /// Get reward multiplier based on years since launch
    pub fn for_year(year: u32) -> Self {
        let multiplier = match year {
            1 => 1.0,       // Year 1: Full rewards (2 SAGE/job)
            2 => 0.75,      // Year 2: 1.5 SAGE/job
            3 => 0.5,       // Year 3: 1.0 SAGE/job
            4 => 0.375,     // Year 4: 0.75 SAGE/job
            _ => 0.25,      // Year 5+: 0.5 SAGE/job (floor)
        };
        Self { year, multiplier }
    }

    /// Get base reward for this halvening period (in SAGE)
    pub fn base_reward_sage(&self) -> f64 {
        BASE_REWARD_SAGE * self.multiplier
    }

    /// Get base reward in wei
    pub fn base_reward_wei(&self) -> u128 {
        ((BASE_REWARD_WEI as f64) * self.multiplier) as u128
    }
}

/// Daily mining stats for a validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorDailyStats {
    /// Validator wallet address
    pub wallet_address: String,
    /// Date (YYYY-MM-DD format)
    pub date: String,
    /// Jobs completed today
    pub jobs_completed: u64,
    /// Mining rewards earned today (in wei)
    pub rewards_earned_wei: u128,
    /// Daily cap for this validator (in wei)
    pub daily_cap_wei: u128,
    /// Whether cap has been reached
    pub cap_reached: bool,
    /// Staking tier
    pub staking_tier: StakingTier,
    /// Last update timestamp
    pub last_updated: DateTime<Utc>,
}

impl ValidatorDailyStats {
    /// Create new daily stats for a validator
    pub fn new(wallet_address: String, staking_tier: StakingTier) -> Self {
        let today = Utc::now().format("%Y-%m-%d").to_string();
        Self {
            wallet_address,
            date: today,
            jobs_completed: 0,
            rewards_earned_wei: 0,
            daily_cap_wei: staking_tier.daily_cap_wei(),
            cap_reached: false,
            staking_tier,
            last_updated: Utc::now(),
        }
    }

    /// Check if validator can earn more rewards today
    pub fn can_earn_more(&self) -> bool {
        !self.cap_reached && self.rewards_earned_wei < self.daily_cap_wei
    }

    /// Get remaining rewards available today (in wei)
    pub fn remaining_wei(&self) -> u128 {
        if self.rewards_earned_wei >= self.daily_cap_wei {
            0
        } else {
            self.daily_cap_wei - self.rewards_earned_wei
        }
    }

    /// Get remaining rewards in SAGE
    pub fn remaining_sage(&self) -> f64 {
        (self.remaining_wei() as f64) / 1e18
    }

    /// Get earned rewards in SAGE
    pub fn earned_sage(&self) -> f64 {
        (self.rewards_earned_wei as f64) / 1e18
    }
}

/// Mining reward calculation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningRewardResult {
    /// Base reward before multipliers
    pub base_reward_wei: u128,
    /// GPU tier multiplier applied
    pub gpu_multiplier: f64,
    /// Halvening multiplier applied
    pub halvening_multiplier: f64,
    /// Final reward after all multipliers
    pub final_reward_wei: u128,
    /// Amount actually awarded (may be less if cap reached)
    pub awarded_wei: u128,
    /// Whether reward was capped
    pub was_capped: bool,
    /// Remaining daily allowance after this reward
    pub remaining_daily_wei: u128,
    /// Human-readable reward in SAGE
    pub awarded_sage: f64,
    /// Stake tier used for cap calculation
    pub stake_tier: StakingTier,
}

// =============================================================================
// Configuration
// =============================================================================

/// Mining rewards configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningRewardsConfig {
    /// Whether mining rewards are enabled
    pub enabled: bool,
    /// Network launch date (for halvening calculation)
    pub launch_date: DateTime<Utc>,
    /// Override base reward (for testing)
    pub base_reward_override: Option<u128>,
    /// Override daily caps (for testing)
    pub cap_override: Option<u64>,
    /// Enable GPU multipliers
    pub enable_gpu_multipliers: bool,
    /// Enable halvening schedule
    pub enable_halvening: bool,
}

impl Default for MiningRewardsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            launch_date: Utc::now(), // Will be set to actual launch date
            base_reward_override: None,
            cap_override: None,
            enable_gpu_multipliers: true,
            enable_halvening: true,
        }
    }
}

// =============================================================================
// Mining Rewards Manager
// =============================================================================

/// Manages mining reward calculations and daily cap tracking
pub struct MiningRewardsManager {
    config: MiningRewardsConfig,
    /// Daily stats per validator, keyed by wallet address
    daily_stats: Arc<RwLock<HashMap<String, ValidatorDailyStats>>>,
    /// Total rewards distributed (for pool tracking)
    total_distributed: Arc<RwLock<u128>>,
}

impl MiningRewardsManager {
    /// Create a new mining rewards manager
    pub fn new(config: MiningRewardsConfig) -> Self {
        Self {
            config,
            daily_stats: Arc::new(RwLock::new(HashMap::new())),
            total_distributed: Arc::new(RwLock::new(0)),
        }
    }

    /// Create with default configuration
    pub fn default_config() -> Self {
        Self::new(MiningRewardsConfig::default())
    }

    /// Calculate mining reward for a completed job
    ///
    /// # Arguments
    /// * `wallet_address` - Validator's Starknet wallet address
    /// * `gpu_tier` - GPU tier used for the job
    /// * `stake_status` - Validator's current stake status
    ///
    /// # Returns
    /// Mining reward calculation result
    pub async fn calculate_reward(
        &self,
        wallet_address: &str,
        gpu_tier: GpuTier,
        stake_status: &StakeStatus,
    ) -> Result<MiningRewardResult> {
        if !self.config.enabled {
            return Ok(MiningRewardResult {
                base_reward_wei: 0,
                gpu_multiplier: 1.0,
                halvening_multiplier: 1.0,
                final_reward_wei: 0,
                awarded_wei: 0,
                was_capped: false,
                remaining_daily_wei: 0,
                awarded_sage: 0.0,
                stake_tier: StakingTier::None,
            });
        }

        // Get staking tier from stake status
        let staking_tier = match stake_status {
            StakeStatus::Staked { amount, .. } => StakingTier::from_stake_amount(*amount),
            _ => StakingTier::None,
        };

        // Get or create daily stats for this validator
        let mut stats = self.daily_stats.write().await;
        let today = Utc::now().format("%Y-%m-%d").to_string();

        let validator_stats = stats
            .entry(wallet_address.to_string())
            .or_insert_with(|| ValidatorDailyStats::new(wallet_address.to_string(), staking_tier));

        // Reset if it's a new day
        if validator_stats.date != today {
            *validator_stats = ValidatorDailyStats::new(wallet_address.to_string(), staking_tier);
        }

        // Update staking tier (might have changed)
        validator_stats.staking_tier = staking_tier;
        validator_stats.daily_cap_wei = self.config.cap_override
            .map(|c| (c as u128) * 1_000_000_000_000_000_000)
            .unwrap_or_else(|| staking_tier.daily_cap_wei());

        // Check if already at cap
        if !validator_stats.can_earn_more() {
            return Ok(MiningRewardResult {
                base_reward_wei: 0,
                gpu_multiplier: 1.0,
                halvening_multiplier: 1.0,
                final_reward_wei: 0,
                awarded_wei: 0,
                was_capped: true,
                remaining_daily_wei: 0,
                awarded_sage: 0.0,
                stake_tier: staking_tier.clone(),
            });
        }

        // Calculate base reward
        let base_reward_wei = self.config.base_reward_override.unwrap_or(BASE_REWARD_WEI);

        // Apply GPU multiplier
        let gpu_mult = if self.config.enable_gpu_multipliers {
            GpuMultiplier::for_gpu(gpu_tier).multiplier
        } else {
            1.0
        };

        // Apply halvening
        let years_since_launch = self.years_since_launch();
        let halvening_mult = if self.config.enable_halvening {
            HalveningSchedule::for_year(years_since_launch).multiplier
        } else {
            1.0
        };

        // Calculate final reward
        let final_reward_wei = ((base_reward_wei as f64) * gpu_mult * halvening_mult) as u128;

        // Apply daily cap
        let remaining = validator_stats.remaining_wei();
        let (awarded_wei, was_capped) = if final_reward_wei > remaining {
            (remaining, true)
        } else {
            (final_reward_wei, false)
        };

        // Update stats
        validator_stats.rewards_earned_wei += awarded_wei;
        validator_stats.jobs_completed += 1;
        validator_stats.cap_reached = validator_stats.rewards_earned_wei >= validator_stats.daily_cap_wei;
        validator_stats.last_updated = Utc::now();

        // Update total distributed
        {
            let mut total = self.total_distributed.write().await;
            *total += awarded_wei;
        }

        let remaining_daily_wei = validator_stats.remaining_wei();
        let awarded_sage = (awarded_wei as f64) / 1e18;

        debug!(
            wallet = %wallet_address,
            gpu_tier = ?gpu_tier,
            staking_tier = ?staking_tier,
            awarded_sage = awarded_sage,
            was_capped = was_capped,
            remaining_sage = (remaining_daily_wei as f64) / 1e18,
            "Mining reward calculated"
        );

        Ok(MiningRewardResult {
            base_reward_wei,
            gpu_multiplier: gpu_mult,
            halvening_multiplier: halvening_mult,
            final_reward_wei,
            awarded_wei,
            was_capped,
            remaining_daily_wei,
            awarded_sage,
            stake_tier: staking_tier,
        })
    }

    /// Get daily stats for a validator
    pub async fn get_validator_stats(&self, wallet_address: &str) -> Option<ValidatorDailyStats> {
        let stats = self.daily_stats.read().await;
        stats.get(wallet_address).cloned()
    }

    /// Get all validators' daily stats
    pub async fn get_all_stats(&self) -> HashMap<String, ValidatorDailyStats> {
        self.daily_stats.read().await.clone()
    }

    /// Get total rewards distributed
    pub async fn get_total_distributed(&self) -> u128 {
        *self.total_distributed.read().await
    }

    /// Get total distributed in SAGE
    pub async fn get_total_distributed_sage(&self) -> f64 {
        (self.get_total_distributed().await as f64) / 1e18
    }

    /// Get remaining pool allocation
    pub async fn get_remaining_pool(&self) -> u128 {
        let distributed = self.get_total_distributed().await;
        if distributed >= MINING_POOL_TOTAL {
            0
        } else {
            MINING_POOL_TOTAL - distributed
        }
    }

    /// Check if mining pool is exhausted
    pub async fn is_pool_exhausted(&self) -> bool {
        self.get_total_distributed().await >= MINING_POOL_TOTAL
    }

    /// Get years since network launch
    fn years_since_launch(&self) -> u32 {
        let now = Utc::now();
        let launch = self.config.launch_date;

        let years = now.year() - launch.year();
        if years < 1 {
            1
        } else {
            years as u32
        }
    }

    /// Reset daily stats (for testing or manual reset)
    pub async fn reset_daily_stats(&self) {
        let mut stats = self.daily_stats.write().await;
        stats.clear();
        info!("Daily mining stats reset");
    }

    /// Get current halvening info
    pub fn get_halvening_info(&self) -> HalveningSchedule {
        let year = self.years_since_launch();
        HalveningSchedule::for_year(year)
    }

    /// Get mining reward summary for display
    pub async fn get_reward_summary(&self) -> MiningRewardSummary {
        let halvening = self.get_halvening_info();
        let total_distributed = self.get_total_distributed().await;
        let remaining_pool = self.get_remaining_pool().await;
        let stats = self.daily_stats.read().await;

        MiningRewardSummary {
            enabled: self.config.enabled,
            current_base_reward_sage: halvening.base_reward_sage(),
            halvening_year: halvening.year,
            halvening_multiplier: halvening.multiplier,
            total_distributed_sage: (total_distributed as f64) / 1e18,
            remaining_pool_sage: (remaining_pool as f64) / 1e18,
            pool_percentage_used: (total_distributed as f64) / (MINING_POOL_TOTAL as f64) * 100.0,
            active_validators_today: stats.len(),
            total_jobs_today: stats.values().map(|s| s.jobs_completed).sum(),
        }
    }
}

/// Summary of mining reward status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningRewardSummary {
    pub enabled: bool,
    pub current_base_reward_sage: f64,
    pub halvening_year: u32,
    pub halvening_multiplier: f64,
    pub total_distributed_sage: f64,
    pub remaining_pool_sage: f64,
    pub pool_percentage_used: f64,
    pub active_validators_today: usize,
    pub total_jobs_today: u64,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_staking_tier_from_amount() {
        const SAGE: u128 = 1_000_000_000_000_000_000;

        assert_eq!(StakingTier::from_stake_amount(0), StakingTier::None);
        assert_eq!(StakingTier::from_stake_amount(500 * SAGE), StakingTier::None);
        assert_eq!(StakingTier::from_stake_amount(1_000 * SAGE), StakingTier::Bronze);
        assert_eq!(StakingTier::from_stake_amount(5_000 * SAGE), StakingTier::Bronze);
        assert_eq!(StakingTier::from_stake_amount(10_000 * SAGE), StakingTier::Silver);
        assert_eq!(StakingTier::from_stake_amount(50_000 * SAGE), StakingTier::Gold);
        assert_eq!(StakingTier::from_stake_amount(200_000 * SAGE), StakingTier::Platinum);
        assert_eq!(StakingTier::from_stake_amount(1_000_000 * SAGE), StakingTier::Platinum);
    }

    #[test]
    fn test_daily_caps() {
        assert_eq!(StakingTier::None.daily_cap(), 100);
        assert_eq!(StakingTier::Bronze.daily_cap(), 150);
        assert_eq!(StakingTier::Silver.daily_cap(), 200);
        assert_eq!(StakingTier::Gold.daily_cap(), 300);
        assert_eq!(StakingTier::Platinum.daily_cap(), 500);
    }

    #[test]
    fn test_gpu_multipliers() {
        assert_eq!(GpuMultiplier::for_gpu(GpuTier::Consumer).multiplier, 1.0);
        assert_eq!(GpuMultiplier::for_gpu(GpuTier::Workstation).multiplier, 1.25);
        assert_eq!(GpuMultiplier::for_gpu(GpuTier::DataCenter).multiplier, 1.5);
        assert_eq!(GpuMultiplier::for_gpu(GpuTier::Enterprise).multiplier, 2.0);
        assert_eq!(GpuMultiplier::for_gpu(GpuTier::Frontier).multiplier, 2.5);
    }

    #[test]
    fn test_halvening_schedule() {
        assert_eq!(HalveningSchedule::for_year(1).multiplier, 1.0);
        assert_eq!(HalveningSchedule::for_year(2).multiplier, 0.75);
        assert_eq!(HalveningSchedule::for_year(3).multiplier, 0.5);
        assert_eq!(HalveningSchedule::for_year(4).multiplier, 0.375);
        assert_eq!(HalveningSchedule::for_year(5).multiplier, 0.25);
        assert_eq!(HalveningSchedule::for_year(10).multiplier, 0.25); // Floor
    }

    #[test]
    fn test_halvening_rewards() {
        assert_eq!(HalveningSchedule::for_year(1).base_reward_sage(), 2.0);
        assert_eq!(HalveningSchedule::for_year(2).base_reward_sage(), 1.5);
        assert_eq!(HalveningSchedule::for_year(3).base_reward_sage(), 1.0);
        assert_eq!(HalveningSchedule::for_year(5).base_reward_sage(), 0.5);
    }

    #[tokio::test]
    async fn test_mining_reward_calculation() {
        let manager = MiningRewardsManager::default_config();

        let result = manager.calculate_reward(
            "0x1234567890abcdef",
            GpuTier::Consumer,
            &StakeStatus::None,
        ).await.unwrap();

        // Base reward: 2 SAGE, no multipliers
        assert_eq!(result.awarded_sage, 2.0);
        assert!(!result.was_capped);
    }

    #[tokio::test]
    async fn test_daily_cap_enforcement() {
        let mut config = MiningRewardsConfig::default();
        config.cap_override = Some(5); // 5 SAGE daily cap for testing

        let manager = MiningRewardsManager::new(config);
        let wallet = "0xtest";

        // First job: 2 SAGE
        let result1 = manager.calculate_reward(wallet, GpuTier::Consumer, &StakeStatus::None).await.unwrap();
        assert_eq!(result1.awarded_sage, 2.0);
        assert!(!result1.was_capped);

        // Second job: 2 SAGE
        let result2 = manager.calculate_reward(wallet, GpuTier::Consumer, &StakeStatus::None).await.unwrap();
        assert_eq!(result2.awarded_sage, 2.0);
        assert!(!result2.was_capped);

        // Third job: Should be capped at 1 SAGE (5 - 4 = 1 remaining)
        let result3 = manager.calculate_reward(wallet, GpuTier::Consumer, &StakeStatus::None).await.unwrap();
        assert_eq!(result3.awarded_sage, 1.0);
        assert!(result3.was_capped);

        // Fourth job: Should get 0 (cap reached)
        let result4 = manager.calculate_reward(wallet, GpuTier::Consumer, &StakeStatus::None).await.unwrap();
        assert_eq!(result4.awarded_wei, 0);
        assert!(result4.was_capped);
    }

    #[tokio::test]
    async fn test_gpu_multiplier_applied() {
        let manager = MiningRewardsManager::default_config();

        // Consumer GPU: 2 SAGE
        let consumer = manager.calculate_reward("0xa", GpuTier::Consumer, &StakeStatus::None).await.unwrap();
        assert_eq!(consumer.awarded_sage, 2.0);

        // Enterprise GPU (H100): 2 * 2.0 = 4 SAGE
        let enterprise = manager.calculate_reward("0xb", GpuTier::Enterprise, &StakeStatus::None).await.unwrap();
        assert_eq!(enterprise.awarded_sage, 4.0);

        // Frontier GPU (B200): 2 * 2.5 = 5 SAGE
        let frontier = manager.calculate_reward("0xc", GpuTier::Frontier, &StakeStatus::None).await.unwrap();
        assert_eq!(frontier.awarded_sage, 5.0);
    }
}
