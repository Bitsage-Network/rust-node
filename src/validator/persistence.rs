//! Consensus Persistence Layer
//!
//! Provides RocksDB-backed persistence for SageGuard consensus state:
//! - Consensus results history
//! - Validator information and metrics
//! - Vote records
//! - View change history
//!
//! This enables validators to:
//! - Recover from crashes without losing consensus state
//! - Query historical consensus decisions
//! - Track validator performance over time
//! - Audit vote history for fraud detection

use anyhow::{Context, Result};
use rocksdb::{Options, DB};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info};

use super::consensus::{ConsensusResult, ValidatorInfo, Vote, View};

/// Column families for different data types
const CF_CONSENSUS_RESULTS: &str = "consensus_results";
const CF_VALIDATORS: &str = "validators";
const CF_VOTES: &str = "votes";
const CF_VIEWS: &str = "views";
const CF_METRICS: &str = "metrics";

/// Consensus persistence configuration
#[derive(Debug, Clone)]
pub struct PersistenceConfig {
    /// Path to RocksDB database directory
    pub db_path: String,

    /// Enable compression (saves disk space)
    pub enable_compression: bool,

    /// Maximum number of results to keep in history (0 = unlimited)
    pub max_results_history: u64,

    /// Whether to enable write-ahead logging
    pub enable_wal: bool,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            db_path: "./data/consensus".to_string(),
            enable_compression: true,
            max_results_history: 10000,
            enable_wal: true,
        }
    }
}

/// Consensus persistence layer using RocksDB
pub struct ConsensusPersistence {
    db: Arc<DB>,
    config: PersistenceConfig,
}

impl ConsensusPersistence {
    /// Open or create a new persistence layer
    pub fn new(config: PersistenceConfig) -> Result<Self> {
        let path = Path::new(&config.db_path);

        // Create parent directories if they don't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create database directory")?;
        }

        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);

        if config.enable_compression {
            db_opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        }

        // Define column families
        let cfs = vec![
            CF_CONSENSUS_RESULTS,
            CF_VALIDATORS,
            CF_VOTES,
            CF_VIEWS,
            CF_METRICS,
        ];

        let db = DB::open_cf(&db_opts, path, cfs)
            .context("Failed to open RocksDB")?;

        info!("Opened consensus persistence at {}", config.db_path);

        Ok(Self {
            db: Arc::new(db),
            config,
        })
    }

    /// Save a consensus result for a job
    pub fn save_consensus_result(&self, job_id: u128, result: &ConsensusResult) -> Result<()> {
        let cf = self.db.cf_handle(CF_CONSENSUS_RESULTS)
            .context("Consensus results CF not found")?;

        let key = job_id.to_be_bytes();
        let value = bincode::serialize(result)
            .context("Failed to serialize consensus result")?;

        self.db.put_cf(cf, key, value)
            .context("Failed to save consensus result")?;

        debug!("Saved consensus result for job {}", job_id);
        Ok(())
    }

    /// Load a consensus result for a job
    pub fn load_consensus_result(&self, job_id: u128) -> Result<Option<ConsensusResult>> {
        let cf = self.db.cf_handle(CF_CONSENSUS_RESULTS)
            .context("Consensus results CF not found")?;

        let key = job_id.to_be_bytes();
        let value = self.db.get_cf(cf, key)
            .context("Failed to load consensus result")?;

        match value {
            Some(bytes) => {
                let result = bincode::deserialize(&bytes)
                    .context("Failed to deserialize consensus result")?;
                Ok(Some(result))
            }
            None => Ok(None),
        }
    }

    /// Save validator information
    pub fn save_validator(&self, validator: &ValidatorInfo) -> Result<()> {
        let cf = self.db.cf_handle(CF_VALIDATORS)
            .context("Validators CF not found")?;

        let key = validator.address.as_bytes();
        let value = bincode::serialize(validator)
            .context("Failed to serialize validator")?;

        self.db.put_cf(cf, key, value)
            .context("Failed to save validator")?;

        debug!("Saved validator {}", validator.address);
        Ok(())
    }

    /// Load validator information
    pub fn load_validator(&self, address: &str) -> Result<Option<ValidatorInfo>> {
        let cf = self.db.cf_handle(CF_VALIDATORS)
            .context("Validators CF not found")?;

        let key = address.as_bytes();
        let value = self.db.get_cf(cf, key)
            .context("Failed to load validator")?;

        match value {
            Some(bytes) => {
                let validator = bincode::deserialize(&bytes)
                    .context("Failed to deserialize validator")?;
                Ok(Some(validator))
            }
            None => Ok(None),
        }
    }

    /// Load all validators
    pub fn load_all_validators(&self) -> Result<Vec<ValidatorInfo>> {
        let cf = self.db.cf_handle(CF_VALIDATORS)
            .context("Validators CF not found")?;

        let mut validators = Vec::new();
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);

        for item in iter {
            let (_key, value) = item?;
            let validator: ValidatorInfo = bincode::deserialize(&value)
                .context("Failed to deserialize validator")?;
            validators.push(validator);
        }

        Ok(validators)
    }

    /// Save a vote
    pub fn save_vote(&self, vote: &Vote) -> Result<()> {
        let cf = self.db.cf_handle(CF_VOTES)
            .context("Votes CF not found")?;

        // Key: job_id + validator_address
        let key = format!("{}:{}", vote.job_id, vote.validator_address);
        let value = bincode::serialize(vote)
            .context("Failed to serialize vote")?;

        self.db.put_cf(cf, key.as_bytes(), value)
            .context("Failed to save vote")?;

        debug!("Saved vote for job {} from {}", vote.job_id, vote.validator_address);
        Ok(())
    }

    /// Load all votes for a job
    pub fn load_votes_for_job(&self, job_id: u128) -> Result<Vec<Vote>> {
        let cf = self.db.cf_handle(CF_VOTES)
            .context("Votes CF not found")?;

        let prefix = format!("{}:", job_id);
        let mut votes = Vec::new();

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, value) = item?;
            let key_str = String::from_utf8_lossy(&key);

            if key_str.starts_with(&prefix) {
                let vote: Vote = bincode::deserialize(&value)
                    .context("Failed to deserialize vote")?;
                votes.push(vote);
            }
        }

        Ok(votes)
    }

    /// Save current view
    pub fn save_view(&self, view: &View) -> Result<()> {
        let cf = self.db.cf_handle(CF_VIEWS)
            .context("Views CF not found")?;

        let key = b"current_view";
        let value = bincode::serialize(view)
            .context("Failed to serialize view")?;

        self.db.put_cf(cf, key, value)
            .context("Failed to save view")?;

        debug!("Saved view {}", view.view_number);
        Ok(())
    }

    /// Load current view
    pub fn load_current_view(&self) -> Result<Option<View>> {
        let cf = self.db.cf_handle(CF_VIEWS)
            .context("Views CF not found")?;

        let key = b"current_view";
        let value = self.db.get_cf(cf, key)
            .context("Failed to load view")?;

        match value {
            Some(bytes) => {
                let view = bincode::deserialize(&bytes)
                    .context("Failed to deserialize view")?;
                Ok(Some(view))
            }
            None => Ok(None),
        }
    }

    /// Get total number of consensus results
    pub fn get_consensus_count(&self) -> Result<u64> {
        let cf = self.db.cf_handle(CF_CONSENSUS_RESULTS)
            .context("Consensus results CF not found")?;

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        Ok(iter.count() as u64)
    }

    /// Delete old consensus results beyond max_results_history
    pub fn cleanup_old_results(&self) -> Result<u64> {
        if self.config.max_results_history == 0 {
            return Ok(0); // No cleanup needed
        }

        let cf = self.db.cf_handle(CF_CONSENSUS_RESULTS)
            .context("Consensus results CF not found")?;

        let count = self.get_consensus_count()?;
        if count <= self.config.max_results_history {
            return Ok(0);
        }

        let to_delete = count - self.config.max_results_history;
        let mut deleted = 0;

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        for item in iter.take(to_delete as usize) {
            let (key, _) = item?;
            self.db.delete_cf(cf, key)
                .context("Failed to delete old result")?;
            deleted += 1;
        }

        if deleted > 0 {
            info!("Cleaned up {} old consensus results", deleted);
        }

        Ok(deleted)
    }

    /// Flush all pending writes to disk
    pub fn flush(&self) -> Result<()> {
        self.db.flush()
            .context("Failed to flush database")?;
        Ok(())
    }

    /// Compact the database to reclaim space
    pub fn compact(&self) -> Result<()> {
        info!("Compacting consensus database...");
        self.db.compact_range::<&[u8], &[u8]>(None, None);
        info!("Database compaction complete");
        Ok(())
    }

    /// Get database statistics
    pub fn get_stats(&self) -> Result<PersistenceStats> {
        let consensus_count = self.get_consensus_count()?;
        let validators = self.load_all_validators()?;

        Ok(PersistenceStats {
            consensus_results: consensus_count,
            validators: validators.len() as u64,
            database_path: self.config.db_path.clone(),
        })
    }
}

/// Persistence statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceStats {
    pub consensus_results: u64,
    pub validators: u64,
    pub database_path: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::consensus::{ProofOfComputeMetrics, Vote};
    use tempfile::TempDir;

    fn create_test_persistence() -> (ConsensusPersistence, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let config = PersistenceConfig {
            db_path: temp_dir.path().join("test_db").to_string_lossy().to_string(),
            enable_compression: true,
            max_results_history: 100,
            enable_wal: true,
        };

        let persistence = ConsensusPersistence::new(config).unwrap();
        (persistence, temp_dir)
    }

    #[test]
    fn test_save_and_load_consensus_result() {
        let (persistence, _temp) = create_test_persistence();

        let result = ConsensusResult::Approved {
            votes_for: vec![],
            votes_against: vec![],
            stake_for: 1000,
        };

        // Save result
        persistence.save_consensus_result(100, &result).unwrap();

        // Load result
        let loaded = persistence.load_consensus_result(100).unwrap();
        assert!(loaded.is_some());
        assert!(matches!(loaded.unwrap(), ConsensusResult::Approved { .. }));

        // Non-existent result
        let missing = persistence.load_consensus_result(999).unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn test_save_and_load_validator() {
        let (persistence, _temp) = create_test_persistence();

        let validator = ValidatorInfo {
            address: "validator1".to_string(),
            public_key: vec![1, 2, 3],
            stake_amount: 1000_000_000_000_000_000,
            is_active: true,
            last_seen: 12345,
            poc_metrics: ProofOfComputeMetrics::default(),
        };

        // Save validator
        persistence.save_validator(&validator).unwrap();

        // Load validator
        let loaded = persistence.load_validator("validator1").unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().address, "validator1");

        // Load all validators
        let all_validators = persistence.load_all_validators().unwrap();
        assert_eq!(all_validators.len(), 1);
    }

    #[test]
    fn test_save_and_load_votes() {
        let (persistence, _temp) = create_test_persistence();

        let vote1 = Vote::new(
            "validator1".to_string(),
            100,
            [1u8; 32],
            true,
            &[0u8; 64],
        );

        let vote2 = Vote::new(
            "validator2".to_string(),
            100,
            [1u8; 32],
            false,
            &[0u8; 64],
        );

        // Save votes
        persistence.save_vote(&vote1).unwrap();
        persistence.save_vote(&vote2).unwrap();

        // Load votes for job
        let votes = persistence.load_votes_for_job(100).unwrap();
        assert_eq!(votes.len(), 2);

        // Votes for non-existent job
        let no_votes = persistence.load_votes_for_job(999).unwrap();
        assert_eq!(no_votes.len(), 0);
    }

    #[test]
    fn test_save_and_load_view() {
        let (persistence, _temp) = create_test_persistence();

        let view = View {
            view_number: 5,
            leader_address: "validator1".to_string(),
            started_at: 12345,
            timeout_at: 12445,
        };

        // Save view
        persistence.save_view(&view).unwrap();

        // Load view
        let loaded = persistence.load_current_view().unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().view_number, 5);
    }

    #[test]
    fn test_get_stats() {
        let (persistence, _temp) = create_test_persistence();

        let validator = ValidatorInfo {
            address: "validator1".to_string(),
            public_key: vec![1, 2, 3],
            stake_amount: 1000_000_000_000_000_000,
            is_active: true,
            last_seen: 12345,
            poc_metrics: ProofOfComputeMetrics::default(),
        };

        persistence.save_validator(&validator).unwrap();

        let result = ConsensusResult::Approved {
            votes_for: vec![],
            votes_against: vec![],
            stake_for: 1000,
        };
        persistence.save_consensus_result(100, &result).unwrap();

        let stats = persistence.get_stats().unwrap();
        assert_eq!(stats.validators, 1);
        assert_eq!(stats.consensus_results, 1);
    }

    #[test]
    fn test_cleanup_old_results() {
        let temp_dir = TempDir::new().unwrap();
        let config = PersistenceConfig {
            db_path: temp_dir.path().join("test_db").to_string_lossy().to_string(),
            enable_compression: true,
            max_results_history: 5, // Keep only 5 results
            enable_wal: true,
        };

        let persistence = ConsensusPersistence::new(config).unwrap();

        // Add 10 results
        let result = ConsensusResult::Approved {
            votes_for: vec![],
            votes_against: vec![],
            stake_for: 1000,
        };

        for i in 1..=10 {
            persistence.save_consensus_result(i, &result).unwrap();
        }

        assert_eq!(persistence.get_consensus_count().unwrap(), 10);

        // Cleanup should delete 5 oldest
        let deleted = persistence.cleanup_old_results().unwrap();
        assert_eq!(deleted, 5);
        assert_eq!(persistence.get_consensus_count().unwrap(), 5);
    }
}
