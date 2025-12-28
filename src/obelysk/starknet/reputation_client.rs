//! Reputation Contract Client
//!
//! This module provides the client for querying on-chain reputation scores
//! from the ReputationManager Cairo contract for worker selection and ranking.
//!
//! Features:
//! - Circuit breaker pattern for RPC resilience
//! - In-memory caching with configurable TTL
//! - Metrics collection for observability
//! - Exponential backoff retry logic

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

/// Reputation score from on-chain (matches Cairo ReputationScore struct)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReputationScore {
    /// Current reputation score (0-1000)
    pub score: u32,
    /// Reputation level (1-5)
    pub level: u8,
    /// Timestamp of last update
    pub last_updated: u64,
    /// Total jobs completed by this worker
    pub total_jobs_completed: u32,
    /// Successful jobs (proofs accepted)
    pub successful_jobs: u32,
    /// Failed jobs (proofs rejected or timeouts)
    pub failed_jobs: u32,
    /// Number of disputes
    pub dispute_count: u32,
    /// Number of times slashed
    pub slash_count: u32,
    /// Computed success rate (0.0 - 1.0) - derived field
    pub success_rate: f64,
}

impl Default for ReputationScore {
    fn default() -> Self {
        Self {
            score: 500, // Default neutral score (50.00)
            level: 3,   // Default to mid-level
            last_updated: 0,
            total_jobs_completed: 0,
            successful_jobs: 0,
            failed_jobs: 0,
            dispute_count: 0,
            slash_count: 0,
            success_rate: 0.5,
        }
    }
}

impl ReputationScore {
    /// Get reputation as a float (0.0 - 10.0)
    pub fn as_float(&self) -> f64 {
        self.score as f64 / 100.0
    }

    /// Check if reputation is above minimum threshold for work
    pub fn is_eligible(&self) -> bool {
        // Workers with score < 200 (2.00) are not eligible
        self.score >= 200
    }

    /// Check if this is a high-reputation worker (score >= 700)
    pub fn is_high_reputation(&self) -> bool {
        self.score >= 700
    }
}

/// Configuration for the reputation client
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReputationClientConfig {
    /// Starknet RPC URL
    pub rpc_url: String,
    /// Reputation manager contract address
    pub reputation_contract: String,
    /// Request timeout
    pub timeout: Duration,
    /// Whether reputation queries are enabled
    pub enabled: bool,
    /// Cache TTL for reputation scores (seconds)
    pub cache_ttl_secs: u64,
}

impl Default for ReputationClientConfig {
    fn default() -> Self {
        Self {
            rpc_url: "https://rpc.starknet-testnet.lava.build".to_string(),
            reputation_contract: "0x0".to_string(),
            timeout: Duration::from_secs(15),
            enabled: true,
            cache_ttl_secs: 60, // Cache for 1 minute
        }
    }
}

/// Starknet function selectors for reputation contract
mod selectors {
    /// get_reputation(worker: ContractAddress) -> ReputationInfo
    pub const GET_REPUTATION: &str = "get_reputation";

    /// get_total_jobs(worker: ContractAddress) -> u64
    pub const GET_TOTAL_JOBS: &str = "get_total_jobs";

    /// is_eligible(worker: ContractAddress) -> bool
    pub const IS_ELIGIBLE: &str = "is_eligible";
}

/// Reputation client with caching, circuit breaker, and metrics
pub struct ReputationClient {
    config: ReputationClientConfig,
    http_client: reqwest::Client,
    /// Simple in-memory cache for reputation scores
    cache: dashmap::DashMap<String, (ReputationScore, Instant)>,
    /// Circuit breaker for RPC resilience
    circuit_breaker: Arc<CircuitBreaker>,
    /// Metrics for observability
    metrics: Arc<RpcMetrics>,
}

impl ReputationClient {
    /// Create a new reputation client
    pub fn new(config: ReputationClientConfig) -> Self {
        Self::with_circuit_breaker(config, CircuitBreakerConfig::default())
    }

    /// Create a reputation client with custom circuit breaker configuration
    pub fn with_circuit_breaker(config: ReputationClientConfig, cb_config: CircuitBreakerConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            http_client,
            cache: dashmap::DashMap::new(),
            circuit_breaker: Arc::new(CircuitBreaker::new(cb_config)),
            metrics: Arc::new(RpcMetrics::new()),
        }
    }

    /// Create a disabled reputation client (for testing)
    pub fn disabled() -> Self {
        Self::new(ReputationClientConfig {
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

    /// Get reputation score for a worker, using cache if available
    pub async fn get_reputation(&self, worker_address: &str) -> Result<ReputationScore> {
        if !self.config.enabled {
            return Ok(ReputationScore::default());
        }

        // Check cache first
        if let Some(cached) = self.cache.get(worker_address) {
            let (score, cached_at) = cached.value();
            if cached_at.elapsed() < Duration::from_secs(self.config.cache_ttl_secs) {
                self.metrics.record_cache_access(true);
                return Ok(score.clone());
            }
        }

        // Cache miss
        self.metrics.record_cache_access(false);

        // Query on-chain
        let score = self.query_reputation(worker_address).await?;

        // Update cache
        self.cache.insert(
            worker_address.to_string(),
            (score.clone(), Instant::now()),
        );

        Ok(score)
    }

    /// Query reputation from on-chain (bypasses cache)
    async fn query_reputation(&self, worker_address: &str) -> Result<ReputationScore> {
        let response = self
            .call_contract(selectors::GET_REPUTATION, vec![worker_address.to_string()])
            .await
            .context("Failed to query reputation")?;

        self.parse_reputation_score(&response)
    }

    /// Check if a worker is eligible based on on-chain reputation
    pub async fn is_eligible(&self, worker_address: &str) -> Result<bool> {
        if !self.config.enabled {
            return Ok(true);
        }

        let response = self
            .call_contract(selectors::IS_ELIGIBLE, vec![worker_address.to_string()])
            .await
            .context("Failed to check eligibility")?;

        // Parse response: single felt252, 0 = false, 1 = true
        let is_eligible = response
            .first()
            .map(|v| v != "0x0" && v != "0")
            .unwrap_or(true); // Default to eligible if query fails

        Ok(is_eligible)
    }

    /// Get multiple worker reputations efficiently (for batch selection)
    pub async fn get_reputations(&self, worker_addresses: &[String]) -> Vec<(String, ReputationScore)> {
        let mut results = Vec::with_capacity(worker_addresses.len());

        for address in worker_addresses {
            let score = self.get_reputation(address).await.unwrap_or_default();
            results.push((address.clone(), score));
        }

        results
    }

    /// Invalidate cache for a specific worker (after job completion)
    pub fn invalidate_cache(&self, worker_address: &str) {
        self.cache.remove(worker_address);
    }

    /// Clear entire cache
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Make an RPC call to the reputation contract with retry logic and circuit breaker
    async fn call_contract(
        &self,
        entry_point: &str,
        calldata: Vec<String>,
    ) -> Result<Vec<String>> {
        // Validate contract address is set
        if self.config.reputation_contract == "0x0" || self.config.reputation_contract.is_empty() {
            return Err(anyhow!("Reputation contract address not configured"));
        }

        // Check circuit breaker before making request
        if !self.circuit_breaker.allow_request().await {
            self.metrics.record_circuit_breaker_rejection();
            error!(
                entry_point = entry_point,
                "Reputation RPC call rejected by circuit breaker"
            );
            return Err(anyhow!("Circuit breaker is open - RPC calls temporarily blocked"));
        }

        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "starknet_call",
            "params": {
                "request": {
                    "contract_address": self.config.reputation_contract,
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
                // Exponential backoff
                let delay = std::cmp::min(
                    RETRY_BASE_DELAY_MS * (2_u64.pow(attempt)),
                    RETRY_MAX_DELAY_MS,
                );
                debug!(
                    attempt = attempt + 1,
                    delay_ms = delay,
                    entry_point = entry_point,
                    "Retrying reputation RPC call"
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
                        "Reputation RPC call failed"
                    );
                    last_error = Some(e);
                }
            }
        }

        // Record failure in circuit breaker after all retries exhausted
        self.circuit_breaker.record_failure().await;

        Err(last_error.unwrap_or_else(|| anyhow!("Reputation RPC call failed after {} retries", MAX_RETRIES)))
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

    /// Parse ReputationScore from contract response
    ///
    /// Cairo struct layout (all felt252 serialized):
    /// [0]: score (u32)
    /// [1]: level (u8)
    /// [2]: last_updated (u64)
    /// [3]: total_jobs_completed (u32)
    /// [4]: successful_jobs (u32)
    /// [5]: failed_jobs (u32)
    /// [6]: dispute_count (u32)
    /// [7]: slash_count (u32)
    fn parse_reputation_score(&self, response: &[String]) -> Result<ReputationScore> {
        if response.len() < 8 {
            // Return default for workers not yet registered
            tracing::debug!(
                response_len = response.len(),
                "Reputation response too short, returning default"
            );
            return Ok(ReputationScore::default());
        }

        let score = self.parse_u32(&response[0])?;
        let level = self.parse_u8(&response[1])?;
        let last_updated = self.parse_u64(&response[2])?;
        let total_jobs_completed = self.parse_u32(&response[3])?;
        let successful_jobs = self.parse_u32(&response[4])?;
        let failed_jobs = self.parse_u32(&response[5])?;
        let dispute_count = self.parse_u32(&response[6])?;
        let slash_count = self.parse_u32(&response[7])?;

        let success_rate = if total_jobs_completed > 0 {
            successful_jobs as f64 / total_jobs_completed as f64
        } else {
            0.5 // Default 50% for new workers
        };

        Ok(ReputationScore {
            score,
            level,
            last_updated,
            total_jobs_completed,
            successful_jobs,
            failed_jobs,
            dispute_count,
            slash_count,
            success_rate,
        })
    }

    fn parse_u32(&self, value: &str) -> Result<u32> {
        u32::from_str_radix(value.trim_start_matches("0x"), 16)
            .context("Failed to parse u32")
    }

    fn parse_u8(&self, value: &str) -> Result<u8> {
        let parsed = u32::from_str_radix(value.trim_start_matches("0x"), 16)
            .context("Failed to parse u8")?;
        Ok(parsed as u8)
    }

    fn parse_u64(&self, value: &str) -> Result<u64> {
        u64::from_str_radix(value.trim_start_matches("0x"), 16)
            .context("Failed to parse u64")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reputation_score_as_float() {
        let score = ReputationScore {
            score: 750,
            ..Default::default()
        };
        assert!((score.as_float() - 7.5).abs() < 0.001);
    }

    #[test]
    fn test_reputation_eligibility() {
        let mut score = ReputationScore::default();

        // Default (500) should be eligible
        score.score = 500;
        assert!(score.is_eligible());

        // Low score (199) should not be eligible
        score.score = 199;
        assert!(!score.is_eligible());

        // At threshold (200) should be eligible
        score.score = 200;
        assert!(score.is_eligible());
    }

    #[test]
    fn test_high_reputation_detection() {
        let mut score = ReputationScore::default();

        score.score = 699;
        assert!(!score.is_high_reputation());

        score.score = 700;
        assert!(score.is_high_reputation());

        score.score = 1000;
        assert!(score.is_high_reputation());
    }

    #[test]
    fn test_level_based_eligibility() {
        let score = ReputationScore {
            score: 800,
            level: 4,
            total_jobs_completed: 100,
            successful_jobs: 95,
            failed_jobs: 5,
            ..Default::default()
        };

        assert!(score.is_eligible());
        assert!(score.is_high_reputation());
        assert!((score.success_rate - 0.5).abs() < 0.01); // default success_rate
    }

    #[tokio::test]
    async fn test_disabled_client() {
        let client = ReputationClient::disabled();

        let score = client.get_reputation("0x123").await.unwrap();
        assert_eq!(score.score, 500); // Default score
        assert_eq!(score.level, 3); // Default level

        let eligible = client.is_eligible("0x123").await.unwrap();
        assert!(eligible);
    }
}
