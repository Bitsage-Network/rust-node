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
            StarknetNetwork::Mainnet => "https://starknet-mainnet.public.blastapi.io",
            StarknetNetwork::Sepolia => "https://starknet-sepolia.public.blastapi.io",
            StarknetNetwork::Goerli => "https://starknet-goerli.public.blastapi.io",
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
    /// Faucet contract address (testnet only)
    pub faucet: Option<String>,
}

impl NetworkContracts {
    /// Get contracts for a specific network
    pub fn for_network(network: StarknetNetwork) -> Self {
        match network {
            StarknetNetwork::Mainnet => Self::mainnet(),
            StarknetNetwork::Sepolia => Self::sepolia(),
            _ => Self::default(),
        }
    }

    /// Mainnet contract addresses
    pub fn mainnet() -> Self {
        Self {
            // TODO: Replace with actual mainnet addresses after deployment
            sage_token: "0x0".to_string(),
            prover_staking: "0x0".to_string(),
            reputation_manager: "0x0".to_string(),
            job_manager: "0x0".to_string(),
            cdc_pool: "0x0".to_string(),
            faucet: None,
        }
    }

    /// Sepolia testnet contract addresses
    pub fn sepolia() -> Self {
        Self {
            // TODO: Replace with actual Sepolia addresses after deployment
            sage_token: "0x0".to_string(),
            prover_staking: "0x0".to_string(),
            reputation_manager: "0x0".to_string(),
            job_manager: "0x00bf025663b8a7c7e43393f082b10afe66bd9ddb06fb5e521e3adbcf693094bd".to_string(),
            cdc_pool: "0x0".to_string(),
            faucet: Some("0x0".to_string()),
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
            faucet: None,
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
        assert!(StarknetNetwork::Mainnet.default_rpc_url().contains("mainnet"));
        assert!(StarknetNetwork::Sepolia.default_rpc_url().contains("sepolia"));
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
