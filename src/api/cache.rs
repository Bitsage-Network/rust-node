//! # Dashboard Cache Layer
//!
//! Provides caching for dashboard metrics to reduce database and blockchain load.
//! Supports Redis when available (with `redis-cache` feature) or falls back to in-memory.
//!
//! ## Usage
//!
//! ```rust,ignore
//! let cache = DashboardCache::new_memory(CacheConfig::default());
//! cache.set("validator:status:0x123", json!({"active": true}), 60).await;
//! let value = cache.get::<serde_json::Value>("validator:status:0x123").await;
//! ```

use dashmap::DashMap;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Default TTL for cached items (seconds)
    pub default_ttl_secs: u64,
    /// Maximum items in memory cache
    pub max_memory_items: usize,
    /// Redis URL (if using Redis)
    pub redis_url: Option<String>,
    /// Enable cache
    pub enabled: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            default_ttl_secs: 30,
            max_memory_items: 10000,
            redis_url: None,
            enabled: true,
        }
    }
}

/// Cache entry with expiration
#[derive(Debug, Clone)]
struct CacheEntry {
    value: String,
    expires_at: Instant,
}

impl CacheEntry {
    fn new(value: String, ttl_secs: u64) -> Self {
        Self {
            value,
            expires_at: Instant::now() + Duration::from_secs(ttl_secs),
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

/// Dashboard cache supporting multiple backends
pub struct DashboardCache {
    config: CacheConfig,
    /// In-memory cache (always available)
    memory: DashMap<String, CacheEntry>,
    /// Redis connection (optional, requires feature)
    #[cfg(feature = "redis-cache")]
    redis: Option<redis::aio::ConnectionManager>,
}

impl DashboardCache {
    /// Create a new memory-only cache
    pub fn new_memory(config: CacheConfig) -> Self {
        Self {
            config,
            memory: DashMap::new(),
            #[cfg(feature = "redis-cache")]
            redis: None,
        }
    }

    /// Create a cache with Redis backend
    #[cfg(feature = "redis-cache")]
    pub async fn new_with_redis(config: CacheConfig) -> Result<Self, CacheError> {
        let redis = if let Some(ref url) = config.redis_url {
            let client = redis::Client::open(url.as_str())
                .map_err(|e| CacheError::ConnectionError(e.to_string()))?;

            let manager = redis::aio::ConnectionManager::new(client)
                .await
                .map_err(|e| CacheError::ConnectionError(e.to_string()))?;

            debug!("Connected to Redis at {}", url);
            Some(manager)
        } else {
            None
        };

        Ok(Self {
            config,
            memory: DashMap::new(),
            redis,
        })
    }

    /// Check if cache is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get a value from cache
    pub async fn get<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        if !self.config.enabled {
            return None;
        }

        // Try Redis first if available
        #[cfg(feature = "redis-cache")]
        if let Some(ref redis) = self.redis {
            match self.get_from_redis(redis, key).await {
                Ok(Some(value)) => {
                    debug!("Cache hit (Redis): {}", key);
                    return Some(value);
                }
                Ok(None) => {}
                Err(e) => {
                    warn!("Redis get error: {}", e);
                    // Fall through to memory cache
                }
            }
        }

        // Try memory cache
        if let Some(entry) = self.memory.get(key) {
            if !entry.is_expired() {
                if let Ok(value) = serde_json::from_str(&entry.value) {
                    debug!("Cache hit (memory): {}", key);
                    return Some(value);
                }
            } else {
                // Remove expired entry
                drop(entry);
                self.memory.remove(key);
            }
        }

        debug!("Cache miss: {}", key);
        None
    }

    /// Set a value in cache with TTL
    pub async fn set<T: Serialize>(&self, key: &str, value: &T, ttl_secs: u64) {
        if !self.config.enabled {
            return;
        }

        let serialized = match serde_json::to_string(value) {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to serialize cache value: {}", e);
                return;
            }
        };

        // Set in Redis if available
        #[cfg(feature = "redis-cache")]
        if let Some(ref redis) = self.redis {
            if let Err(e) = self.set_in_redis(redis, key, &serialized, ttl_secs).await {
                warn!("Redis set error: {}", e);
            }
        }

        // Always set in memory as backup
        if self.memory.len() < self.config.max_memory_items {
            self.memory.insert(
                key.to_string(),
                CacheEntry::new(serialized, ttl_secs),
            );
        }

        debug!("Cache set: {} (TTL: {}s)", key, ttl_secs);
    }

    /// Set with default TTL
    pub async fn set_default<T: Serialize>(&self, key: &str, value: &T) {
        self.set(key, value, self.config.default_ttl_secs).await;
    }

    /// Delete a key from cache
    pub async fn delete(&self, key: &str) {
        // Delete from Redis
        #[cfg(feature = "redis-cache")]
        if let Some(ref redis) = self.redis {
            let _ = self.delete_from_redis(redis, key).await;
        }

        // Delete from memory
        self.memory.remove(key);
        debug!("Cache delete: {}", key);
    }

    /// Delete all keys matching a pattern
    pub async fn delete_pattern(&self, pattern: &str) {
        // For memory cache, iterate and remove matching keys
        let keys_to_remove: Vec<String> = self
            .memory
            .iter()
            .filter(|entry| entry.key().starts_with(pattern.trim_end_matches('*')))
            .map(|entry| entry.key().clone())
            .collect();

        for key in keys_to_remove {
            self.memory.remove(&key);
        }

        debug!("Cache delete pattern: {} (memory)", pattern);

        // For Redis, use SCAN + DEL
        #[cfg(feature = "redis-cache")]
        if let Some(ref _redis) = self.redis {
            // Redis pattern delete would go here
            // Using SCAN to avoid blocking
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            memory_items: self.memory.len(),
            max_memory_items: self.config.max_memory_items,
            enabled: self.config.enabled,
            #[cfg(feature = "redis-cache")]
            redis_connected: self.redis.is_some(),
            #[cfg(not(feature = "redis-cache"))]
            redis_connected: false,
        }
    }

    /// Cleanup expired entries from memory cache
    pub fn cleanup_expired(&self) {
        let before = self.memory.len();
        self.memory.retain(|_, entry| !entry.is_expired());
        let removed = before - self.memory.len();
        if removed > 0 {
            debug!("Cache cleanup: removed {} expired entries", removed);
        }
    }

    // Redis helper methods
    #[cfg(feature = "redis-cache")]
    async fn get_from_redis<T: DeserializeOwned>(
        &self,
        redis: &redis::aio::ConnectionManager,
        key: &str,
    ) -> Result<Option<T>, CacheError> {
        use redis::AsyncCommands;

        let mut conn = redis.clone();
        let value: Option<String> = conn
            .get(key)
            .await
            .map_err(|e| CacheError::OperationError(e.to_string()))?;

        match value {
            Some(s) => {
                let parsed = serde_json::from_str(&s)
                    .map_err(|e| CacheError::SerializationError(e.to_string()))?;
                Ok(Some(parsed))
            }
            None => Ok(None),
        }
    }

    #[cfg(feature = "redis-cache")]
    async fn set_in_redis(
        &self,
        redis: &redis::aio::ConnectionManager,
        key: &str,
        value: &str,
        ttl_secs: u64,
    ) -> Result<(), CacheError> {
        use redis::AsyncCommands;

        let mut conn = redis.clone();
        conn.set_ex(key, value, ttl_secs)
            .await
            .map_err(|e| CacheError::OperationError(e.to_string()))?;
        Ok(())
    }

    #[cfg(feature = "redis-cache")]
    async fn delete_from_redis(
        &self,
        redis: &redis::aio::ConnectionManager,
        key: &str,
    ) -> Result<(), CacheError> {
        use redis::AsyncCommands;

        let mut conn = redis.clone();
        conn.del(key)
            .await
            .map_err(|e| CacheError::OperationError(e.to_string()))?;
        Ok(())
    }
}

/// Cache statistics
#[derive(Debug, Clone, serde::Serialize)]
pub struct CacheStats {
    pub memory_items: usize,
    pub max_memory_items: usize,
    pub enabled: bool,
    pub redis_connected: bool,
}

/// Cache error types
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("Connection error: {0}")]
    ConnectionError(String),
    #[error("Operation error: {0}")]
    OperationError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

// ============================================================================
// Dashboard-Specific Cache Keys
// ============================================================================

/// Generate cache keys for dashboard data
pub struct CacheKeys;

impl CacheKeys {
    /// Validator status cache key
    pub fn validator_status(address: &str) -> String {
        format!("validator:status:{}", address)
    }

    /// Validator rewards cache key
    pub fn validator_rewards(address: &str) -> String {
        format!("validator:rewards:{}", address)
    }

    /// Network stats cache key
    pub fn network_stats() -> String {
        "network:stats".to_string()
    }

    /// Network workers list cache key
    pub fn network_workers() -> String {
        "network:workers".to_string()
    }

    /// Job analytics cache key
    pub fn job_analytics() -> String {
        "jobs:analytics".to_string()
    }

    /// Worker uptime cache key
    pub fn worker_uptime(address: &str) -> String {
        format!("worker:uptime:{}", address)
    }

    /// Stake info cache key
    pub fn stake_info(address: &str) -> String {
        format!("stake:{}", address)
    }

    /// Reputation cache key
    pub fn reputation(address: &str) -> String {
        format!("reputation:{}", address)
    }

    /// Contract addresses cache key
    pub fn contracts() -> String {
        "contracts".to_string()
    }
}

/// Cache TTL constants (in seconds)
pub struct CacheTTL;

impl CacheTTL {
    /// Short TTL for frequently changing data (10 seconds)
    pub const SHORT: u64 = 10;
    /// Medium TTL for moderately changing data (30 seconds)
    pub const MEDIUM: u64 = 30;
    /// Long TTL for slowly changing data (5 minutes)
    pub const LONG: u64 = 300;
    /// Very long TTL for rarely changing data (1 hour)
    pub const VERY_LONG: u64 = 3600;

    /// Validator status (changes with jobs/heartbeats)
    pub const VALIDATOR_STATUS: u64 = 15;
    /// Rewards (changes on claim)
    pub const REWARDS: u64 = 60;
    /// Network stats (aggregate, changes slowly)
    pub const NETWORK_STATS: u64 = 30;
    /// Worker list (changes with registration)
    pub const WORKERS: u64 = 60;
    /// Job analytics (computed, expensive)
    pub const JOB_ANALYTICS: u64 = 120;
    /// Stake info (on-chain, expensive to query)
    pub const STAKE_INFO: u64 = 60;
    /// Reputation (on-chain, expensive to query)
    pub const REPUTATION: u64 = 60;
    /// Contract addresses (static)
    pub const CONTRACTS: u64 = 3600;
}

/// Background task to cleanup expired cache entries
pub async fn cache_cleanup_task(cache: Arc<DashboardCache>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;
        cache.cleanup_expired();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_cache_basic() {
        let cache = DashboardCache::new_memory(CacheConfig::default());

        // Set a value
        cache.set("test:key", &"hello", 60).await;

        // Get it back
        let value: Option<String> = cache.get("test:key").await;
        assert_eq!(value, Some("hello".to_string()));
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let config = CacheConfig {
            default_ttl_secs: 1,
            ..Default::default()
        };
        let cache = DashboardCache::new_memory(config);

        // Set with 1 second TTL
        cache.set("test:expire", &"value", 1).await;

        // Should exist immediately
        let value: Option<String> = cache.get("test:expire").await;
        assert_eq!(value, Some("value".to_string()));

        // Wait for expiration
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Should be gone
        let value: Option<String> = cache.get("test:expire").await;
        assert!(value.is_none());
    }

    #[tokio::test]
    async fn test_cache_delete() {
        let cache = DashboardCache::new_memory(CacheConfig::default());

        cache.set("test:delete", &"value", 60).await;
        assert!(cache.get::<String>("test:delete").await.is_some());

        cache.delete("test:delete").await;
        assert!(cache.get::<String>("test:delete").await.is_none());
    }

    #[tokio::test]
    async fn test_cache_disabled() {
        let config = CacheConfig {
            enabled: false,
            ..Default::default()
        };
        let cache = DashboardCache::new_memory(config);

        cache.set("test:disabled", &"value", 60).await;
        let value: Option<String> = cache.get("test:disabled").await;
        assert!(value.is_none());
    }

    #[test]
    fn test_cache_keys() {
        assert_eq!(
            CacheKeys::validator_status("0x123"),
            "validator:status:0x123"
        );
        assert_eq!(CacheKeys::network_stats(), "network:stats");
    }
}
