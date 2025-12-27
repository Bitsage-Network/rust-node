//! # Rate Limiter
//!
//! Token bucket rate limiting for job and proof submissions to prevent abuse
//! and ensure fair resource distribution across the BitSage network.

use anyhow::{anyhow, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Rate limiter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimiterConfig {
    /// Enable rate limiting
    pub enabled: bool,

    /// Job submission limits per client
    pub job_limits: RateLimitConfig,

    /// Proof submission limits per worker
    pub proof_limits: RateLimitConfig,

    /// Faucet claim limits per address
    pub faucet_limits: RateLimitConfig,

    /// General API limits per IP
    pub api_limits: RateLimitConfig,

    /// Cleanup interval for expired buckets (seconds)
    pub cleanup_interval_secs: u64,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            job_limits: RateLimitConfig {
                requests_per_minute: 10,
                requests_per_hour: 100,
                burst_size: 5,
            },
            proof_limits: RateLimitConfig {
                requests_per_minute: 50,
                requests_per_hour: 500,
                burst_size: 10,
            },
            faucet_limits: RateLimitConfig {
                requests_per_minute: 1,
                requests_per_hour: 1,
                burst_size: 1,
            },
            api_limits: RateLimitConfig {
                requests_per_minute: 120,
                requests_per_hour: 3600,
                burst_size: 20,
            },
            cleanup_interval_secs: 300, // 5 minutes
        }
    }
}

/// Rate limit configuration for a specific resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum requests per minute
    pub requests_per_minute: u32,

    /// Maximum requests per hour
    pub requests_per_hour: u32,

    /// Burst size (max tokens in bucket)
    pub burst_size: u32,
}

/// Token bucket state for rate limiting
#[derive(Debug, Clone)]
struct TokenBucket {
    /// Available tokens
    tokens: f64,

    /// Maximum tokens (burst capacity)
    max_tokens: f64,

    /// Tokens added per second
    refill_rate: f64,

    /// Last refill timestamp
    last_refill: Instant,

    /// Hourly request counter
    hourly_count: u32,

    /// Hour start timestamp
    hour_start: Instant,
}

impl TokenBucket {
    fn new(config: &RateLimitConfig) -> Self {
        // Calculate refill rate: tokens per second
        let refill_rate = config.requests_per_minute as f64 / 60.0;

        Self {
            tokens: config.burst_size as f64,
            max_tokens: config.burst_size as f64,
            refill_rate,
            last_refill: Instant::now(),
            hourly_count: 0,
            hour_start: Instant::now(),
        }
    }

    /// Try to consume a token, returns true if successful
    fn try_consume(&mut self, hourly_limit: u32) -> bool {
        let now = Instant::now();

        // Reset hourly counter if hour has passed
        if now.duration_since(self.hour_start) >= Duration::from_secs(3600) {
            self.hourly_count = 0;
            self.hour_start = now;
        }

        // Check hourly limit
        if self.hourly_count >= hourly_limit {
            return false;
        }

        // Refill tokens based on elapsed time
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;

        // Try to consume a token
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            self.hourly_count += 1;
            true
        } else {
            false
        }
    }

    /// Get time until next token is available
    fn time_until_available(&self) -> Duration {
        if self.tokens >= 1.0 {
            Duration::ZERO
        } else {
            let tokens_needed = 1.0 - self.tokens;
            Duration::from_secs_f64(tokens_needed / self.refill_rate)
        }
    }

    /// Check if bucket is stale (no activity for extended period)
    fn is_stale(&self, max_age: Duration) -> bool {
        Instant::now().duration_since(self.last_refill) > max_age
    }
}

/// Rate limit error with details for client feedback
#[derive(Debug, Clone)]
pub struct RateLimitError {
    pub resource_type: String,
    pub identifier: String,
    pub retry_after_secs: u64,
    pub hourly_remaining: u32,
    pub minute_remaining: u32,
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Rate limit exceeded for {} '{}'. Retry after {} seconds.",
            self.resource_type, self.identifier, self.retry_after_secs
        )
    }
}

impl std::error::Error for RateLimitError {}

/// Main rate limiter service
pub struct RateLimiter {
    config: RateLimiterConfig,

    /// Job submission buckets by client wallet address
    job_buckets: DashMap<String, TokenBucket>,

    /// Proof submission buckets by worker ID
    proof_buckets: DashMap<String, TokenBucket>,

    /// Faucet claim buckets by address
    faucet_buckets: DashMap<String, TokenBucket>,

    /// API request buckets by IP address
    api_buckets: DashMap<String, TokenBucket>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: RateLimiterConfig) -> Self {
        Self {
            config,
            job_buckets: DashMap::new(),
            proof_buckets: DashMap::new(),
            faucet_buckets: DashMap::new(),
            api_buckets: DashMap::new(),
        }
    }

    /// Create a disabled rate limiter (for testing)
    pub fn disabled() -> Self {
        Self::new(RateLimiterConfig {
            enabled: false,
            ..Default::default()
        })
    }

    /// Check if rate limiting is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Check job submission rate limit for a client
    pub fn check_job_submission(&self, client_address: &str) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let mut bucket = self
            .job_buckets
            .entry(client_address.to_string())
            .or_insert_with(|| TokenBucket::new(&self.config.job_limits));

        if bucket.try_consume(self.config.job_limits.requests_per_hour) {
            debug!(
                client = %client_address,
                "Job submission rate check passed"
            );
            Ok(())
        } else {
            let retry_after = bucket.time_until_available();
            warn!(
                client = %client_address,
                retry_after_secs = retry_after.as_secs(),
                "Job submission rate limit exceeded"
            );
            Err(anyhow!(RateLimitError {
                resource_type: "job_submission".to_string(),
                identifier: client_address.to_string(),
                retry_after_secs: retry_after.as_secs(),
                hourly_remaining: self.config.job_limits.requests_per_hour.saturating_sub(bucket.hourly_count),
                minute_remaining: 0,
            }))
        }
    }

    /// Check proof submission rate limit for a worker
    pub fn check_proof_submission(&self, worker_id: &str) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let mut bucket = self
            .proof_buckets
            .entry(worker_id.to_string())
            .or_insert_with(|| TokenBucket::new(&self.config.proof_limits));

        if bucket.try_consume(self.config.proof_limits.requests_per_hour) {
            debug!(
                worker = %worker_id,
                "Proof submission rate check passed"
            );
            Ok(())
        } else {
            let retry_after = bucket.time_until_available();
            warn!(
                worker = %worker_id,
                retry_after_secs = retry_after.as_secs(),
                "Proof submission rate limit exceeded"
            );
            Err(anyhow!(RateLimitError {
                resource_type: "proof_submission".to_string(),
                identifier: worker_id.to_string(),
                retry_after_secs: retry_after.as_secs(),
                hourly_remaining: self.config.proof_limits.requests_per_hour.saturating_sub(bucket.hourly_count),
                minute_remaining: 0,
            }))
        }
    }

    /// Check faucet claim rate limit for an address
    pub fn check_faucet_claim(&self, address: &str) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let mut bucket = self
            .faucet_buckets
            .entry(address.to_string())
            .or_insert_with(|| TokenBucket::new(&self.config.faucet_limits));

        if bucket.try_consume(self.config.faucet_limits.requests_per_hour) {
            debug!(
                address = %address,
                "Faucet claim rate check passed"
            );
            Ok(())
        } else {
            let retry_after = bucket.time_until_available();
            warn!(
                address = %address,
                retry_after_secs = retry_after.as_secs(),
                "Faucet claim rate limit exceeded"
            );
            Err(anyhow!(RateLimitError {
                resource_type: "faucet_claim".to_string(),
                identifier: address.to_string(),
                retry_after_secs: retry_after.as_secs(),
                hourly_remaining: self.config.faucet_limits.requests_per_hour.saturating_sub(bucket.hourly_count),
                minute_remaining: 0,
            }))
        }
    }

    /// Check general API rate limit for an IP address
    pub fn check_api_request(&self, ip_address: &str) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let mut bucket = self
            .api_buckets
            .entry(ip_address.to_string())
            .or_insert_with(|| TokenBucket::new(&self.config.api_limits));

        if bucket.try_consume(self.config.api_limits.requests_per_hour) {
            Ok(())
        } else {
            let retry_after = bucket.time_until_available();
            Err(anyhow!(RateLimitError {
                resource_type: "api_request".to_string(),
                identifier: ip_address.to_string(),
                retry_after_secs: retry_after.as_secs(),
                hourly_remaining: self.config.api_limits.requests_per_hour.saturating_sub(bucket.hourly_count),
                minute_remaining: 0,
            }))
        }
    }

    /// Get remaining requests for job submissions
    pub fn get_job_remaining(&self, client_address: &str) -> (u32, u32) {
        if let Some(bucket) = self.job_buckets.get(client_address) {
            let hourly = self.config.job_limits.requests_per_hour.saturating_sub(bucket.hourly_count);
            let minute = bucket.tokens as u32;
            (minute, hourly)
        } else {
            (
                self.config.job_limits.requests_per_minute,
                self.config.job_limits.requests_per_hour,
            )
        }
    }

    /// Get remaining requests for proof submissions
    pub fn get_proof_remaining(&self, worker_id: &str) -> (u32, u32) {
        if let Some(bucket) = self.proof_buckets.get(worker_id) {
            let hourly = self.config.proof_limits.requests_per_hour.saturating_sub(bucket.hourly_count);
            let minute = bucket.tokens as u32;
            (minute, hourly)
        } else {
            (
                self.config.proof_limits.requests_per_minute,
                self.config.proof_limits.requests_per_hour,
            )
        }
    }

    /// Cleanup stale buckets to prevent memory bloat
    pub fn cleanup_stale_buckets(&self) {
        let max_age = Duration::from_secs(self.config.cleanup_interval_secs * 2);

        let mut removed = 0;

        self.job_buckets.retain(|_, bucket| {
            let keep = !bucket.is_stale(max_age);
            if !keep {
                removed += 1;
            }
            keep
        });

        self.proof_buckets.retain(|_, bucket| {
            let keep = !bucket.is_stale(max_age);
            if !keep {
                removed += 1;
            }
            keep
        });

        self.faucet_buckets.retain(|_, bucket| {
            let keep = !bucket.is_stale(max_age);
            if !keep {
                removed += 1;
            }
            keep
        });

        self.api_buckets.retain(|_, bucket| {
            let keep = !bucket.is_stale(max_age);
            if !keep {
                removed += 1;
            }
            keep
        });

        if removed > 0 {
            debug!(removed, "Cleaned up stale rate limit buckets");
        }
    }

    /// Get statistics about rate limiting
    pub fn get_stats(&self) -> RateLimiterStats {
        RateLimiterStats {
            enabled: self.config.enabled,
            active_job_buckets: self.job_buckets.len(),
            active_proof_buckets: self.proof_buckets.len(),
            active_faucet_buckets: self.faucet_buckets.len(),
            active_api_buckets: self.api_buckets.len(),
        }
    }
}

/// Rate limiter statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimiterStats {
    pub enabled: bool,
    pub active_job_buckets: usize,
    pub active_proof_buckets: usize,
    pub active_faucet_buckets: usize,
    pub active_api_buckets: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let config = RateLimiterConfig {
            enabled: true,
            job_limits: RateLimitConfig {
                requests_per_minute: 5,
                requests_per_hour: 100,
                burst_size: 5,
            },
            ..Default::default()
        };

        let limiter = RateLimiter::new(config);

        // Should allow 5 requests (burst size)
        for i in 0..5 {
            assert!(
                limiter.check_job_submission("client1").is_ok(),
                "Request {} should be allowed",
                i + 1
            );
        }
    }

    #[test]
    fn test_rate_limiter_blocks_excess() {
        let config = RateLimiterConfig {
            enabled: true,
            job_limits: RateLimitConfig {
                requests_per_minute: 2,
                requests_per_hour: 100,
                burst_size: 2,
            },
            ..Default::default()
        };

        let limiter = RateLimiter::new(config);

        // Use up burst
        assert!(limiter.check_job_submission("client1").is_ok());
        assert!(limiter.check_job_submission("client1").is_ok());

        // Third request should be blocked
        let result = limiter.check_job_submission("client1");
        assert!(result.is_err());
    }

    #[test]
    fn test_disabled_limiter_allows_all() {
        let limiter = RateLimiter::disabled();

        // Should allow unlimited requests when disabled
        for _ in 0..100 {
            assert!(limiter.check_job_submission("client1").is_ok());
        }
    }

    #[test]
    fn test_different_clients_have_separate_limits() {
        let config = RateLimiterConfig {
            enabled: true,
            job_limits: RateLimitConfig {
                requests_per_minute: 2,
                requests_per_hour: 100,
                burst_size: 2,
            },
            ..Default::default()
        };

        let limiter = RateLimiter::new(config);

        // Exhaust client1 limit
        assert!(limiter.check_job_submission("client1").is_ok());
        assert!(limiter.check_job_submission("client1").is_ok());
        assert!(limiter.check_job_submission("client1").is_err());

        // client2 should still have quota
        assert!(limiter.check_job_submission("client2").is_ok());
        assert!(limiter.check_job_submission("client2").is_ok());
    }
}
