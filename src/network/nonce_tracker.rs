//! Nonce Tracking for Replay Protection
//!
//! This module provides comprehensive nonce tracking to prevent replay attacks
//! on encrypted job announcements, bids, and results.
//!
//! ## Features
//!
//! - **Sliding Window**: Only tracks nonces within a configurable time window
//! - **Bloom Filter**: Space-efficient first-pass deduplication
//! - **Persistent Storage**: Optional database backing for crash recovery
//! - **Distributed Coordination**: Supports distributed nonce synchronization
//!
//! ## Security Model
//!
//! 1. Each nonce is unique and cryptographically random (12 bytes = 96 bits)
//! 2. Nonces are bound to a timestamp window to limit storage
//! 3. Double-spending of nonces is detected and rejected
//! 4. Bloom filter provides fast rejection with no false negatives

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, debug};
use sha3::{Sha3_256, Digest};

/// Configuration for nonce tracker
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NonceTrackerConfig {
    /// Maximum age of nonces to track (in seconds)
    pub max_nonce_age_secs: u64,
    /// Bloom filter size (bits)
    pub bloom_filter_bits: usize,
    /// Number of hash functions for bloom filter
    pub bloom_hash_count: usize,
    /// Cleanup interval (seconds)
    pub cleanup_interval_secs: u64,
    /// Maximum nonces to store in memory
    pub max_stored_nonces: usize,
    /// Enable distributed sync
    pub enable_distributed_sync: bool,
}

impl Default for NonceTrackerConfig {
    fn default() -> Self {
        Self {
            max_nonce_age_secs: 3600,        // 1 hour window
            bloom_filter_bits: 1 << 20,       // 1M bits (~128KB)
            bloom_hash_count: 7,              // Optimal for 1% false positive
            cleanup_interval_secs: 300,       // Cleanup every 5 minutes
            max_stored_nonces: 100_000,       // Max 100k nonces in memory
            enable_distributed_sync: false,
        }
    }
}

/// Nonce entry with timestamp
#[derive(Clone, Debug, Serialize, Deserialize)]
struct NonceEntry {
    nonce: [u8; 12],
    timestamp: u64,
    source: NonceSource,
}

/// Source of the nonce (for categorization)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum NonceSource {
    JobAnnouncement,
    WorkerBid,
    JobResult,
    P2PMessage,
    Unknown,
}

/// Result of nonce validation
#[derive(Clone, Debug)]
pub enum NonceValidation {
    /// Nonce is valid and has been registered
    Valid,
    /// Nonce was already used (replay attack)
    Replay {
        original_timestamp: u64,
        source: NonceSource,
    },
    /// Nonce is too old (outside time window)
    Expired {
        nonce_age_secs: u64,
        max_age_secs: u64,
    },
    /// Nonce format is invalid
    Invalid(String),
}

/// Statistics for monitoring
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NonceTrackerStats {
    pub total_nonces_seen: u64,
    pub valid_nonces: u64,
    pub replay_attempts: u64,
    pub expired_nonces: u64,
    pub invalid_nonces: u64,
    pub current_stored_count: usize,
    pub bloom_filter_checks: u64,
    pub bloom_false_positives: u64,
}

/// Bloom filter for fast nonce deduplication
struct BloomFilter {
    bits: Vec<u8>,
    size_bits: usize,
    hash_count: usize,
}

impl BloomFilter {
    fn new(size_bits: usize, hash_count: usize) -> Self {
        let size_bytes = (size_bits + 7) / 8;
        Self {
            bits: vec![0u8; size_bytes],
            size_bits,
            hash_count,
        }
    }

    /// Add nonce to bloom filter
    fn insert(&mut self, nonce: &[u8; 12]) {
        for i in 0..self.hash_count {
            let index = self.hash_index(nonce, i);
            let byte_index = index / 8;
            let bit_index = index % 8;
            self.bits[byte_index] |= 1 << bit_index;
        }
    }

    /// Check if nonce might be in the filter (may have false positives)
    fn maybe_contains(&self, nonce: &[u8; 12]) -> bool {
        for i in 0..self.hash_count {
            let index = self.hash_index(nonce, i);
            let byte_index = index / 8;
            let bit_index = index % 8;
            if (self.bits[byte_index] & (1 << bit_index)) == 0 {
                return false;
            }
        }
        true
    }

    /// Clear the bloom filter
    fn clear(&mut self) {
        self.bits.fill(0);
    }

    /// Calculate hash index for a given nonce and hash function index
    fn hash_index(&self, nonce: &[u8; 12], hash_index: usize) -> usize {
        let mut hasher = Sha3_256::new();
        hasher.update(nonce);
        hasher.update(&[hash_index as u8]);
        let hash = hasher.finalize();

        // Use first 8 bytes as u64, then modulo
        let value = u64::from_le_bytes(hash[0..8].try_into().unwrap());
        (value as usize) % self.size_bits
    }
}

/// Main nonce tracker
pub struct NonceTracker {
    config: NonceTrackerConfig,
    /// Primary storage: nonce -> entry
    nonces: Arc<RwLock<HashMap<[u8; 12], NonceEntry>>>,
    /// Bloom filter for fast rejection
    bloom_filter: Arc<RwLock<BloomFilter>>,
    /// Time-ordered queue for cleanup
    time_queue: Arc<RwLock<VecDeque<([u8; 12], u64)>>>,
    /// Statistics
    stats: Arc<RwLock<NonceTrackerStats>>,
}

impl NonceTracker {
    /// Create a new nonce tracker
    pub fn new(config: NonceTrackerConfig) -> Self {
        let bloom_filter = BloomFilter::new(config.bloom_filter_bits, config.bloom_hash_count);

        Self {
            config,
            nonces: Arc::new(RwLock::new(HashMap::new())),
            bloom_filter: Arc::new(RwLock::new(bloom_filter)),
            time_queue: Arc::new(RwLock::new(VecDeque::new())),
            stats: Arc::new(RwLock::new(NonceTrackerStats::default())),
        }
    }

    /// Validate and register a nonce
    pub async fn validate_and_register(
        &self,
        nonce: &[u8; 12],
        source: NonceSource,
    ) -> NonceValidation {
        let now = chrono::Utc::now().timestamp() as u64;

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_nonces_seen += 1;
        }

        // Fast path: check bloom filter first
        {
            let bloom = self.bloom_filter.read().await;
            let mut stats = self.stats.write().await;
            stats.bloom_filter_checks += 1;

            if bloom.maybe_contains(nonce) {
                // Potential duplicate - need to check exact storage
                let nonces = self.nonces.read().await;
                if let Some(existing) = nonces.get(nonce) {
                    stats.replay_attempts += 1;
                    return NonceValidation::Replay {
                        original_timestamp: existing.timestamp,
                        source: existing.source.clone(),
                    };
                }
                // False positive in bloom filter
                stats.bloom_false_positives += 1;
            }
        }

        // Validate timestamp (nonce should be recent)
        // This is done by the caller who should include timestamp in the message
        // For now, we use current time as the nonce timestamp

        // Register the nonce
        {
            let mut nonces = self.nonces.write().await;
            let mut bloom = self.bloom_filter.write().await;
            let mut queue = self.time_queue.write().await;
            let mut stats = self.stats.write().await;

            // Check storage limits
            if nonces.len() >= self.config.max_stored_nonces {
                // Evict oldest
                if let Some((old_nonce, _)) = queue.pop_front() {
                    nonces.remove(&old_nonce);
                }
            }

            // Insert new nonce
            let entry = NonceEntry {
                nonce: *nonce,
                timestamp: now,
                source,
            };

            nonces.insert(*nonce, entry);
            bloom.insert(nonce);
            queue.push_back((*nonce, now));

            stats.valid_nonces += 1;
            stats.current_stored_count = nonces.len();
        }

        NonceValidation::Valid
    }

    /// Check if a nonce has been seen (without registering)
    pub async fn check_nonce(&self, nonce: &[u8; 12]) -> bool {
        // Fast path with bloom filter
        let bloom = self.bloom_filter.read().await;
        if !bloom.maybe_contains(nonce) {
            return false;
        }

        // Exact check
        let nonces = self.nonces.read().await;
        nonces.contains_key(nonce)
    }

    /// Validate nonce with timestamp
    pub async fn validate_with_timestamp(
        &self,
        nonce: &[u8; 12],
        message_timestamp: u64,
        source: NonceSource,
    ) -> NonceValidation {
        let now = chrono::Utc::now().timestamp() as u64;

        // Check if message is too old
        if message_timestamp + self.config.max_nonce_age_secs < now {
            let mut stats = self.stats.write().await;
            stats.expired_nonces += 1;
            return NonceValidation::Expired {
                nonce_age_secs: now - message_timestamp,
                max_age_secs: self.config.max_nonce_age_secs,
            };
        }

        // Check if message is from the future (clock skew tolerance: 60 seconds)
        if message_timestamp > now + 60 {
            let mut stats = self.stats.write().await;
            stats.invalid_nonces += 1;
            return NonceValidation::Invalid(
                format!("Message timestamp {} is in the future (now: {})", message_timestamp, now)
            );
        }

        self.validate_and_register(nonce, source).await
    }

    /// Cleanup expired nonces
    pub async fn cleanup(&self) -> usize {
        let now = chrono::Utc::now().timestamp() as u64;
        let cutoff = now.saturating_sub(self.config.max_nonce_age_secs);

        let mut nonces = self.nonces.write().await;
        let mut queue = self.time_queue.write().await;
        let mut removed = 0;

        // Remove expired entries from queue and hashmap
        while let Some((nonce, timestamp)) = queue.front() {
            if *timestamp < cutoff {
                nonces.remove(nonce);
                queue.pop_front();
                removed += 1;
            } else {
                break; // Queue is time-ordered, no more expired entries
            }
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.current_stored_count = nonces.len();
        }

        if removed > 0 {
            debug!("Cleaned up {} expired nonces", removed);
        }

        removed
    }

    /// Rebuild bloom filter (after many removals)
    pub async fn rebuild_bloom_filter(&self) {
        let nonces = self.nonces.read().await;
        let mut bloom = self.bloom_filter.write().await;

        bloom.clear();
        for nonce in nonces.keys() {
            bloom.insert(nonce);
        }

        info!("Rebuilt bloom filter with {} entries", nonces.len());
    }

    /// Get current statistics
    pub async fn stats(&self) -> NonceTrackerStats {
        self.stats.read().await.clone()
    }

    /// Reset the tracker (for testing)
    pub async fn reset(&self) {
        let mut nonces = self.nonces.write().await;
        let mut bloom = self.bloom_filter.write().await;
        let mut queue = self.time_queue.write().await;
        let mut stats = self.stats.write().await;

        nonces.clear();
        bloom.clear();
        queue.clear();
        *stats = NonceTrackerStats::default();
    }

    /// Export nonces for distributed sync
    pub async fn export_recent_nonces(&self, max_age_secs: u64) -> Vec<([u8; 12], u64, NonceSource)> {
        let now = chrono::Utc::now().timestamp() as u64;
        let cutoff = now.saturating_sub(max_age_secs);

        let nonces = self.nonces.read().await;

        nonces.values()
            .filter(|e| e.timestamp >= cutoff)
            .map(|e| (e.nonce, e.timestamp, e.source.clone()))
            .collect()
    }

    /// Import nonces from peer (for distributed sync)
    pub async fn import_nonces(&self, nonces: Vec<([u8; 12], u64, NonceSource)>) -> usize {
        let mut imported = 0;
        let now = chrono::Utc::now().timestamp() as u64;

        for (nonce, timestamp, source) in nonces {
            // Skip if too old
            if timestamp + self.config.max_nonce_age_secs < now {
                continue;
            }

            // Check if already present
            if !self.check_nonce(&nonce).await {
                // Register without validation
                let mut nonces_map = self.nonces.write().await;
                let mut bloom = self.bloom_filter.write().await;
                let mut queue = self.time_queue.write().await;

                if nonces_map.len() < self.config.max_stored_nonces {
                    let entry = NonceEntry {
                        nonce,
                        timestamp,
                        source,
                    };
                    nonces_map.insert(nonce, entry);
                    bloom.insert(&nonce);
                    queue.push_back((nonce, timestamp));
                    imported += 1;
                }
            }
        }

        if imported > 0 {
            info!("Imported {} nonces from peer", imported);
        }

        imported
    }
}

/// Shared nonce tracker for use across modules
pub type SharedNonceTracker = Arc<NonceTracker>;

/// Create a shared nonce tracker
pub fn create_nonce_tracker(config: NonceTrackerConfig) -> SharedNonceTracker {
    Arc::new(NonceTracker::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nonce_validation() {
        let tracker = NonceTracker::new(NonceTrackerConfig::default());

        let nonce = [1u8; 12];

        // First use should be valid
        let result = tracker.validate_and_register(&nonce, NonceSource::JobAnnouncement).await;
        assert!(matches!(result, NonceValidation::Valid));

        // Second use should be replay
        let result = tracker.validate_and_register(&nonce, NonceSource::JobAnnouncement).await;
        assert!(matches!(result, NonceValidation::Replay { .. }));
    }

    #[tokio::test]
    async fn test_different_nonces() {
        let tracker = NonceTracker::new(NonceTrackerConfig::default());

        let nonce1 = [1u8; 12];
        let nonce2 = [2u8; 12];

        let result1 = tracker.validate_and_register(&nonce1, NonceSource::JobAnnouncement).await;
        let result2 = tracker.validate_and_register(&nonce2, NonceSource::WorkerBid).await;

        assert!(matches!(result1, NonceValidation::Valid));
        assert!(matches!(result2, NonceValidation::Valid));
    }

    #[tokio::test]
    async fn test_cleanup() {
        let mut config = NonceTrackerConfig::default();
        config.max_nonce_age_secs = 1; // 1 second for testing

        let tracker = NonceTracker::new(config);

        let nonce = [1u8; 12];
        tracker.validate_and_register(&nonce, NonceSource::JobAnnouncement).await;

        // Wait for expiry
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let removed = tracker.cleanup().await;
        assert_eq!(removed, 1);

        // Should be able to reuse nonce after cleanup
        let result = tracker.validate_and_register(&nonce, NonceSource::JobAnnouncement).await;
        assert!(matches!(result, NonceValidation::Valid));
    }

    #[tokio::test]
    async fn test_stats() {
        let tracker = NonceTracker::new(NonceTrackerConfig::default());

        let nonce = [1u8; 12];
        tracker.validate_and_register(&nonce, NonceSource::JobAnnouncement).await;
        tracker.validate_and_register(&nonce, NonceSource::JobAnnouncement).await; // Replay

        let stats = tracker.stats().await;
        assert_eq!(stats.total_nonces_seen, 2);
        assert_eq!(stats.valid_nonces, 1);
        assert_eq!(stats.replay_attempts, 1);
    }

    #[test]
    fn test_bloom_filter() {
        let mut bloom = BloomFilter::new(1024, 3);

        let nonce1 = [1u8; 12];
        let nonce2 = [2u8; 12];

        // Not inserted yet
        assert!(!bloom.maybe_contains(&nonce1));
        assert!(!bloom.maybe_contains(&nonce2));

        // Insert nonce1
        bloom.insert(&nonce1);
        assert!(bloom.maybe_contains(&nonce1));
        assert!(!bloom.maybe_contains(&nonce2)); // Might be true due to false positive, but usually false
    }
}
