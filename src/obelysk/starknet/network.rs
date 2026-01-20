//! Starknet Network Configuration
//!
//! Production-ready network configuration for mainnet, testnet, and devnet deployments.
//! Includes circuit breaker pattern and metrics collection.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Starknet network identifiers
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum StarknetNetwork {
    /// Mainnet - production network
    Mainnet,
    /// Sepolia testnet - primary testnet
    #[default]
    Sepolia,
    /// Goerli testnet (deprecated, but still used)
    Goerli,
    /// Local devnet for development
    Devnet,
    /// Custom network (user-specified RPC)
    Custom,
}

impl StarknetNetwork {
    /// Get the default RPC URL for this network
    pub fn default_rpc_url(&self) -> &'static str {
        match self {
            StarknetNetwork::Mainnet => "https://starknet-mainnet-rpc.publicnode.com",
            StarknetNetwork::Sepolia => "https://api.cartridge.gg/x/starknet/sepolia",
            StarknetNetwork::Goerli => "https://api.cartridge.gg/x/starknet/sepolia", // Goerli deprecated, use Sepolia
            StarknetNetwork::Devnet => "http://localhost:5050",
            StarknetNetwork::Custom => "",
        }
    }

    /// Get chain ID for this network
    pub fn chain_id(&self) -> &'static str {
        match self {
            StarknetNetwork::Mainnet => "SN_MAIN",
            StarknetNetwork::Sepolia => "SN_SEPOLIA",
            StarknetNetwork::Goerli => "SN_GOERLI",
            StarknetNetwork::Devnet => "SN_DEVNET",
            StarknetNetwork::Custom => "SN_CUSTOM",
        }
    }

    /// Check if this is a production network
    pub fn is_production(&self) -> bool {
        matches!(self, StarknetNetwork::Mainnet)
    }

    /// Get recommended confirmation blocks
    pub fn confirmation_blocks(&self) -> u64 {
        match self {
            StarknetNetwork::Mainnet => 10,
            StarknetNetwork::Sepolia | StarknetNetwork::Goerli => 2,
            StarknetNetwork::Devnet | StarknetNetwork::Custom => 0,
        }
    }
}

impl std::fmt::Display for StarknetNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StarknetNetwork::Mainnet => write!(f, "mainnet"),
            StarknetNetwork::Sepolia => write!(f, "sepolia"),
            StarknetNetwork::Goerli => write!(f, "goerli"),
            StarknetNetwork::Devnet => write!(f, "devnet"),
            StarknetNetwork::Custom => write!(f, "custom"),
        }
    }
}

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation - requests allowed
    Closed,
    /// Too many failures - requests blocked
    Open,
    /// Testing if service recovered
    HalfOpen,
}

/// Circuit breaker configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening circuit
    pub failure_threshold: u32,
    /// Duration to keep circuit open before testing
    pub open_duration_secs: u64,
    /// Number of successful requests in half-open to close circuit
    pub half_open_success_threshold: u32,
    /// Time window for counting failures (seconds)
    pub failure_window_secs: u64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            open_duration_secs: 30,
            half_open_success_threshold: 2,
            failure_window_secs: 60,
        }
    }
}

/// Circuit breaker for RPC resilience
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: RwLock<CircuitState>,
    failure_count: AtomicU32,
    success_count: AtomicU32,
    last_failure_time: RwLock<Option<Instant>>,
    opened_at: RwLock<Option<Instant>>,
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: RwLock::new(CircuitState::Closed),
            failure_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            last_failure_time: RwLock::new(None),
            opened_at: RwLock::new(None),
        }
    }

    /// Check if request should be allowed
    pub async fn allow_request(&self) -> bool {
        let state = *self.state.read().await;

        match state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if enough time has passed to try half-open
                if let Some(opened_at) = *self.opened_at.read().await {
                    if opened_at.elapsed() >= Duration::from_secs(self.config.open_duration_secs) {
                        // Transition to half-open
                        *self.state.write().await = CircuitState::HalfOpen;
                        self.success_count.store(0, Ordering::SeqCst);
                        debug!("Circuit breaker transitioning to half-open");
                        return true;
                    }
                }
                false
            }
            CircuitState::HalfOpen => true, // Allow limited requests for testing
        }
    }

    /// Record a successful request
    pub async fn record_success(&self) {
        let state = *self.state.read().await;

        match state {
            CircuitState::HalfOpen => {
                let count = self.success_count.fetch_add(1, Ordering::SeqCst) + 1;
                if count >= self.config.half_open_success_threshold {
                    // Close the circuit
                    *self.state.write().await = CircuitState::Closed;
                    self.failure_count.store(0, Ordering::SeqCst);
                    info!("Circuit breaker closed after successful recovery");
                }
            }
            CircuitState::Closed => {
                // Reset failure count on success (sliding window)
                let last = self.last_failure_time.read().await;
                if let Some(t) = *last {
                    if t.elapsed() >= Duration::from_secs(self.config.failure_window_secs) {
                        self.failure_count.store(0, Ordering::SeqCst);
                    }
                }
            }
            CircuitState::Open => {}
        }
    }

    /// Record a failed request
    pub async fn record_failure(&self) {
        let state = *self.state.read().await;

        match state {
            CircuitState::HalfOpen => {
                // Any failure in half-open returns to open
                *self.state.write().await = CircuitState::Open;
                *self.opened_at.write().await = Some(Instant::now());
                warn!("Circuit breaker re-opened after failure in half-open state");
            }
            CircuitState::Closed => {
                let count = self.failure_count.fetch_add(1, Ordering::SeqCst) + 1;
                *self.last_failure_time.write().await = Some(Instant::now());

                if count >= self.config.failure_threshold {
                    *self.state.write().await = CircuitState::Open;
                    *self.opened_at.write().await = Some(Instant::now());
                    error!(
                        failures = count,
                        threshold = self.config.failure_threshold,
                        "Circuit breaker opened due to failures"
                    );
                }
            }
            CircuitState::Open => {}
        }
    }

    /// Get current circuit state
    pub async fn state(&self) -> CircuitState {
        *self.state.read().await
    }

    /// Force reset the circuit breaker
    pub async fn reset(&self) {
        *self.state.write().await = CircuitState::Closed;
        self.failure_count.store(0, Ordering::SeqCst);
        self.success_count.store(0, Ordering::SeqCst);
        *self.opened_at.write().await = None;
        info!("Circuit breaker manually reset");
    }
}

/// RPC client metrics for observability
#[derive(Debug, Default)]
pub struct RpcMetrics {
    /// Total RPC calls made
    pub total_calls: AtomicU64,
    /// Successful RPC calls
    pub successful_calls: AtomicU64,
    /// Failed RPC calls
    pub failed_calls: AtomicU64,
    /// Retried RPC calls
    pub retried_calls: AtomicU64,
    /// Circuit breaker rejections
    pub circuit_breaker_rejections: AtomicU64,
    /// Total response time in milliseconds
    pub total_response_time_ms: AtomicU64,
    /// Cache hits (for reputation client)
    pub cache_hits: AtomicU64,
    /// Cache misses
    pub cache_misses: AtomicU64,
}

impl RpcMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_call(&self, success: bool, duration_ms: u64, was_retry: bool) {
        self.total_calls.fetch_add(1, Ordering::Relaxed);
        self.total_response_time_ms.fetch_add(duration_ms, Ordering::Relaxed);

        if success {
            self.successful_calls.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed_calls.fetch_add(1, Ordering::Relaxed);
        }

        if was_retry {
            self.retried_calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_circuit_breaker_rejection(&self) {
        self.circuit_breaker_rejections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_access(&self, hit: bool) {
        if hit {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.cache_misses.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get success rate (0.0 - 1.0)
    pub fn success_rate(&self) -> f64 {
        let total = self.total_calls.load(Ordering::Relaxed);
        if total == 0 {
            return 1.0;
        }
        let successful = self.successful_calls.load(Ordering::Relaxed);
        successful as f64 / total as f64
    }

    /// Get average response time in milliseconds
    pub fn avg_response_time_ms(&self) -> f64 {
        let total = self.total_calls.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        let total_time = self.total_response_time_ms.load(Ordering::Relaxed);
        total_time as f64 / total as f64
    }

    /// Get cache hit rate (0.0 - 1.0)
    pub fn cache_hit_rate(&self) -> f64 {
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let misses = self.cache_misses.load(Ordering::Relaxed);
        let total = hits + misses;
        if total == 0 {
            return 0.0;
        }
        hits as f64 / total as f64
    }

    /// Get metrics snapshot for reporting
    pub fn snapshot(&self) -> RpcMetricsSnapshot {
        RpcMetricsSnapshot {
            total_calls: self.total_calls.load(Ordering::Relaxed),
            successful_calls: self.successful_calls.load(Ordering::Relaxed),
            failed_calls: self.failed_calls.load(Ordering::Relaxed),
            retried_calls: self.retried_calls.load(Ordering::Relaxed),
            circuit_breaker_rejections: self.circuit_breaker_rejections.load(Ordering::Relaxed),
            avg_response_time_ms: self.avg_response_time_ms(),
            success_rate: self.success_rate(),
            cache_hit_rate: self.cache_hit_rate(),
        }
    }
}

/// Serializable metrics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcMetricsSnapshot {
    pub total_calls: u64,
    pub successful_calls: u64,
    pub failed_calls: u64,
    pub retried_calls: u64,
    pub circuit_breaker_rejections: u64,
    pub avg_response_time_ms: f64,
    pub success_rate: f64,
    pub cache_hit_rate: f64,
}

/// Known contract addresses for different networks
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkContracts {
    /// SAGE token contract address
    pub sage_token: String,
    /// Prover staking contract address
    pub prover_staking: String,
    /// Reputation manager contract address
    pub reputation_manager: String,
    /// Job manager contract address
    pub job_manager: String,
    /// CDC pool contract address
    pub cdc_pool: String,
    /// Payment router contract address
    pub payment_router: String,
    /// Faucet contract address (testnet only)
    pub faucet: Option<String>,
    /// OptimisticTEE contract address
    pub optimistic_tee: String,
    /// ProofVerifier contract address
    pub proof_verifier: String,
    /// ValidatorRegistry contract address
    pub validator_registry: String,
    /// Collateral contract address
    pub collateral: String,
    /// Escrow contract address
    pub escrow: String,
    /// FeeManager contract address
    pub fee_manager: String,
    /// FraudProof contract address
    pub fraud_proof: String,
    /// Gamification contract address
    pub gamification: String,
    /// PrivacyRouter contract address
    pub privacy_router: String,
    /// StwoVerifier contract address
    pub stwo_verifier: String,
    /// MeteredBilling contract address
    pub metered_billing: String,
    /// ProofGatedPayment contract address
    pub proof_gated_payment: String,
    /// ObelyskProverRegistry contract address
    pub prover_registry: String,
    /// WorkerStaking contract address
    pub worker_staking: String,
    /// WorkerPrivacyHelper contract address
    pub worker_privacy_helper: String,
    /// OracleWrapper contract address
    pub oracle_wrapper: String,
    /// RewardVesting contract address
    pub reward_vesting: String,
    /// BurnManager contract address
    pub burn_manager: String,
    /// LinearVestingWithCliff contract address
    pub linear_vesting: String,
    /// MilestoneVesting contract address
    pub milestone_vesting: String,
    /// TreasuryTimelock contract address
    pub treasury_timelock: String,
    /// GovernanceTreasury contract address
    pub governance_treasury: String,
}

impl NetworkContracts {
    /// Get contracts for a specific network
    pub fn for_network(network: StarknetNetwork) -> Self {
        match network {
            StarknetNetwork::Mainnet => {
                let contracts = Self::mainnet();
                // Validate mainnet contracts are properly configured
                if let Err(e) = contracts.validate_for_production() {
                    panic!("CRITICAL: Mainnet contract addresses not configured: {}", e);
                }
                contracts
            },
            StarknetNetwork::Sepolia => Self::sepolia(),
            _ => Self::default(),
        }
    }

    /// Validate that contract addresses are properly configured for production
    pub fn validate_for_production(&self) -> Result<(), String> {
        let mut uninitialized = Vec::new();

        // Check critical contracts
        if self.sage_token == "0x0" || self.sage_token.is_empty() {
            uninitialized.push("sage_token");
        }
        if self.prover_staking == "0x0" || self.prover_staking.is_empty() {
            uninitialized.push("prover_staking");
        }
        if self.reputation_manager == "0x0" || self.reputation_manager.is_empty() {
            uninitialized.push("reputation_manager");
        }
        if self.job_manager == "0x0" || self.job_manager.is_empty() {
            uninitialized.push("job_manager");
        }
        if self.payment_router == "0x0" || self.payment_router.is_empty() {
            uninitialized.push("payment_router");
        }
        if self.fraud_proof == "0x0" || self.fraud_proof.is_empty() {
            uninitialized.push("fraud_proof");
        }

        if !uninitialized.is_empty() {
            return Err(format!(
                "The following critical contracts have uninitialized addresses (0x0): {}. \
                Deploy contracts to mainnet and update addresses before launching.",
                uninitialized.join(", ")
            ));
        }

        Ok(())
    }

    /// Mainnet contract addresses
    ///
    /// Note: These are placeholder addresses. Replace with actual deployed
    /// contract addresses after mainnet deployment. Attempting to use these
    /// zero addresses will result in transaction failures.
    pub fn mainnet() -> Self {
        Self {
            // MAINNET: Update these addresses after contract deployment
            sage_token: "0x0".to_string(),
            prover_staking: "0x0".to_string(),
            reputation_manager: "0x0".to_string(),
            job_manager: "0x0".to_string(),
            cdc_pool: "0x0".to_string(),
            payment_router: "0x0".to_string(),
            faucet: None,
            optimistic_tee: "0x0".to_string(),
            proof_verifier: "0x0".to_string(),
            validator_registry: "0x0".to_string(),
            collateral: "0x0".to_string(),
            escrow: "0x0".to_string(),
            fee_manager: "0x0".to_string(),
            fraud_proof: "0x0".to_string(),
            gamification: "0x0".to_string(),
            privacy_router: "0x0".to_string(),
            stwo_verifier: "0x0".to_string(),
            metered_billing: "0x0".to_string(),
            proof_gated_payment: "0x0".to_string(),
            prover_registry: "0x0".to_string(),
            worker_staking: "0x0".to_string(),
            worker_privacy_helper: "0x0".to_string(),
            oracle_wrapper: "0x0".to_string(),
            reward_vesting: "0x0".to_string(),
            burn_manager: "0x0".to_string(),
            linear_vesting: "0x0".to_string(),
            milestone_vesting: "0x0".to_string(),
            treasury_timelock: "0x0".to_string(),
            governance_treasury: "0x0".to_string(),
        }
    }

    /// Sepolia testnet contract addresses (deployed 2025-12-27)
    /// All 27 contracts deployed via sncast with Cartridge RPC
    pub fn sepolia() -> Self {
        Self {
            // Core contracts
            sage_token: "0x04321b7282ae6aa354988eed57f2ff851314af8524de8b1f681a128003cc4ea5".to_string(),
            prover_staking: "0x0165fe12b09dd5e6b692cbf59f9c3ea0af30a2616f248c150357b07b967039da".to_string(),
            reputation_manager: "0x019c05a8f648c835e66e98c700b628d14ed4249e5e60e32c7f779d38da90e9d9".to_string(),
            job_manager: "0x0534a8f5cc1399b368b5be211df25e370f4a74d3d5b2d040f9d5b69981b069ed".to_string(),
            cdc_pool: "0x012c8ab3fad97954eafbf99ab9d76a9c8e85dd0f6b38139d12d3c5e3f14f950b".to_string(),
            payment_router: "0x006bfcc028c9976c18f8e22c2472df36d8d7848e7b55b814a5f15d339b97e1fe".to_string(),
            faucet: Some("0x07943ad334da99ab3dd138ff14d2045a7d962f1a426a4dd909fda026f37acf9f".to_string()),

            // Obelysk privacy/TEE contracts
            optimistic_tee: "0x04ea542ccad82e75681f438e1667baaeaca5285791dc2449e0f9f3df3e998b49".to_string(),
            proof_verifier: "0x06c27c897108f20afbd045e561e465e0843d85e84fe7dfd55f910ee75df6385a".to_string(),
            validator_registry: "0x0252d13615dd74b70c9d653250fe8baa66130f683783c542c582dbc9709ee2cd".to_string(),
            privacy_router: "0x0051e114ec3d524f203900c78e5217f23de51e29d6a6ecabb6dc92fb8ccca6e0".to_string(),
            stwo_verifier: "0x00555555e154e28a596a59f98f857ec85f6dc7038f8d18dd1a08364d8e76dd47".to_string(),
            prover_registry: "0x005d46ac3e32242c2681a5171551abb773464812b77eec7e52d60ec612e9bf3a".to_string(),
            worker_staking: "0x064df40ab00145394de98676d0934e49c0f436c4589d4d35ffa720e45c3de7e7".to_string(),
            worker_privacy_helper: "0x06219e1e40b7a07c0a07fa38e4c19b661943d2f410839ddfe5e3bf7376206e47".to_string(),

            // Economics contracts
            collateral: "0x01384e775b5b19bd8756d5a77c7d9e99a739b35523915a1ad0b4c3c4d0b00f7c".to_string(),
            escrow: "0x045aa77cfaf3a902d879f3a26165922a423f5902c9d1647dbfe0274328930d4f".to_string(),
            fee_manager: "0x0762a276d38f66b6fe8cf3eb140247624f02bb87e32917dffbad197c73f3fb56".to_string(),
            reward_vesting: "0x07bb26a7d6d97e8292af9bb14244afbaaf2d722140111b8cced185bbde1a026d".to_string(),

            // Game mechanics contracts
            fraud_proof: "0x0249179135c4d35f6a199de0fb91a1fbe29d5798e862bc14a108f1da8ec42acf".to_string(),
            gamification: "0x047402be0797cda868f2601f6234f56fa814e51957fa1981989ffcbf471e81e4".to_string(),

            // Payment contracts
            metered_billing: "0x058b10cf0a1369fca1a90192d5b58a757a30a93af2ce5c3af0c16001fb57bb4b".to_string(),
            proof_gated_payment: "0x06f153aff8835202fb3183ddf2edde40b1ca0360cdf20611649f05a16ca04cc7".to_string(),

            // Oracle integration
            oracle_wrapper: "0x0020ba92a5df4c7719decbc8e43d5475059311b0b8bb2cdd623f5f29d61f0f2d".to_string(),

            // Vesting & governance contracts
            burn_manager: "0x04d11f83401087bc1813ae4f69ecb4e7c2477829b740d6a5ae900e9e81df1933".to_string(),
            linear_vesting: "0x06df34218f99b8bd19b0cdec2fcef7ca7bc07218799aed0d72f2078b9a68e6ba".to_string(),
            milestone_vesting: "0x04ae08af901c3952bf97252ad888b9138c930da780a66ec3a87b192413e95dd5".to_string(),
            treasury_timelock: "0x03246a3d6f51c08033a7030f795088f84c67c5ed8f7790405a4e192f0c59ff79".to_string(),
            governance_treasury: "0x00f8718089716c532f084326a707678ae1b159386613e86ced48c53fa24c8a3b".to_string(),
        }
    }

    /// Check if all required contracts are configured
    pub fn is_configured(&self) -> bool {
        self.sage_token != "0x0"
            && self.prover_staking != "0x0"
            && self.reputation_manager != "0x0"
            && self.job_manager != "0x0"
    }
}

impl Default for NetworkContracts {
    fn default() -> Self {
        Self {
            sage_token: "0x0".to_string(),
            prover_staking: "0x0".to_string(),
            reputation_manager: "0x0".to_string(),
            job_manager: "0x0".to_string(),
            cdc_pool: "0x0".to_string(),
            payment_router: "0x0".to_string(),
            faucet: None,
            optimistic_tee: "0x0".to_string(),
            proof_verifier: "0x0".to_string(),
            validator_registry: "0x0".to_string(),
            collateral: "0x0".to_string(),
            escrow: "0x0".to_string(),
            fee_manager: "0x0".to_string(),
            fraud_proof: "0x0".to_string(),
            gamification: "0x0".to_string(),
            privacy_router: "0x0".to_string(),
            stwo_verifier: "0x0".to_string(),
            metered_billing: "0x0".to_string(),
            proof_gated_payment: "0x0".to_string(),
            prover_registry: "0x0".to_string(),
            worker_staking: "0x0".to_string(),
            worker_privacy_helper: "0x0".to_string(),
            oracle_wrapper: "0x0".to_string(),
            reward_vesting: "0x0".to_string(),
            burn_manager: "0x0".to_string(),
            linear_vesting: "0x0".to_string(),
            milestone_vesting: "0x0".to_string(),
            treasury_timelock: "0x0".to_string(),
            governance_treasury: "0x0".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_defaults() {
        assert_eq!(StarknetNetwork::default(), StarknetNetwork::Sepolia);
        assert!(!StarknetNetwork::Sepolia.is_production());
        assert!(StarknetNetwork::Mainnet.is_production());
    }

    #[test]
    fn test_network_rpc_urls() {
        // Mainnet uses Lava: rpc.starknet.lava.build
        assert!(StarknetNetwork::Mainnet.default_rpc_url().contains("starknet.lava"));
        // Sepolia uses Cartridge: api.cartridge.gg/x/starknet/sepolia
        assert!(StarknetNetwork::Sepolia.default_rpc_url().contains("sepolia"));
        assert!(StarknetNetwork::Sepolia.default_rpc_url().contains("cartridge"));
    }

    #[tokio::test]
    async fn test_circuit_breaker_closed() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig::default());
        assert!(cb.allow_request().await);
        assert_eq!(cb.state().await, CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_circuit_breaker_opens_after_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let cb = CircuitBreaker::new(config);

        // Record failures
        for _ in 0..3 {
            cb.record_failure().await;
        }

        assert_eq!(cb.state().await, CircuitState::Open);
        assert!(!cb.allow_request().await);
    }

    #[test]
    fn test_metrics_success_rate() {
        let metrics = RpcMetrics::new();

        metrics.record_call(true, 100, false);
        metrics.record_call(true, 100, false);
        metrics.record_call(false, 100, false);

        let rate = metrics.success_rate();
        assert!((rate - 0.666).abs() < 0.01);
    }
}
