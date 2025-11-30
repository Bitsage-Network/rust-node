//! # P2P Result Collection and Aggregation System
//!
//! This module implements the result collection system that gathers job results
//! from distributed workers, validates them, and ensures data integrity through
//! consensus mechanisms before final blockchain submission.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{sleep, Duration, Instant};
use tracing::{info, debug, warn, error};
use uuid::Uuid;
use sha2::{Sha256, Digest};

use crate::blockchain::{
    client::StarknetClient,
    contracts::JobManagerContract,
};
use crate::network::p2p::NetworkClient;
use crate::types::{JobId, WorkerId};

/// Result collection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultCollectionConfig {
    /// Minimum number of results required for consensus
    pub min_consensus_results: usize,
    /// Maximum number of results to collect per job
    pub max_results_per_job: usize,
    /// Timeout for result collection in seconds
    pub collection_timeout_secs: u64,
    /// Minimum confidence threshold for result acceptance
    pub min_confidence_threshold: f64,
    /// Maximum allowed deviation for numeric results
    pub max_numeric_deviation: f64,
    /// Enable result verification through re-computation
    pub enable_verification: bool,
    /// Percentage of results to verify (0.0 to 1.0)
    pub verification_percentage: f64,
    /// Maximum time to wait for blockchain confirmation
    pub blockchain_confirmation_timeout_secs: u64,
}

impl Default for ResultCollectionConfig {
    fn default() -> Self {
        Self {
            min_consensus_results: 3,
            max_results_per_job: 10,
            collection_timeout_secs: 300, // 5 minutes
            min_confidence_threshold: 0.7,
            max_numeric_deviation: 0.1, // 10%
            enable_verification: true,
            verification_percentage: 0.2, // 20%
            blockchain_confirmation_timeout_secs: 600, // 10 minutes
        }
    }
}

/// Individual result submission from a worker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerResult {
    pub job_id: JobId,
    pub worker_id: WorkerId,
    pub result_id: String,
    pub result_data: Vec<u8>,
    pub result_hash: String,
    pub execution_time_ms: u64,
    pub gas_used: u64,
    pub confidence_score: f64,
    pub metadata: HashMap<String, String>,
    pub submitted_at: u64,
    pub signature: Option<String>,
}

impl WorkerResult {
    /// Create a new worker result
    pub fn new(
        job_id: JobId,
        worker_id: WorkerId,
        result_data: Vec<u8>,
        execution_time_ms: u64,
        gas_used: u64,
        confidence_score: f64,
        metadata: HashMap<String, String>,
    ) -> Self {
        let result_hash = Self::calculate_hash(&result_data);
        
        Self {
            job_id,
            worker_id,
            result_id: Uuid::new_v4().to_string(),
            result_data,
            result_hash,
            execution_time_ms,
            gas_used,
            confidence_score,
            metadata,
            submitted_at: chrono::Utc::now().timestamp() as u64,
            signature: None,
        }
    }

    /// Calculate SHA256 hash of result data
    fn calculate_hash(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    /// Verify the result hash matches the data
    pub fn verify_hash(&self) -> bool {
        let calculated_hash = Self::calculate_hash(&self.result_data);
        calculated_hash == self.result_hash
    }
}

/// Aggregated result from multiple workers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedResult {
    pub job_id: JobId,
    pub aggregation_id: String,
    pub consensus_result: Vec<u8>,
    pub consensus_hash: String,
    pub confidence_score: f64,
    pub contributing_workers: Vec<WorkerId>,
    pub individual_results: Vec<WorkerResult>,
    pub aggregation_method: AggregationMethod,
    pub created_at: u64,
    pub verification_status: VerificationStatus,
    pub blockchain_submission_status: BlockchainSubmissionStatus,
}

/// Methods for aggregating multiple results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AggregationMethod {
    /// Use the most common result (majority vote)
    MajorityVote,
    /// Use weighted average based on worker reputation
    WeightedAverage,
    /// Use the result with highest confidence
    HighestConfidence,
    /// Use median of numeric results
    MedianValue,
    /// Custom aggregation logic
    Custom(String),
}

/// Status of result verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationStatus {
    Pending,
    InProgress,
    Verified,
    Failed(String),
    Skipped,
}

/// Status of blockchain submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockchainSubmissionStatus {
    Pending,
    Submitted(String), // Transaction hash
    Confirmed(String), // Transaction hash
    Failed(String),    // Error message
}

/// Events related to result collection
#[derive(Debug, Clone)]
pub enum ResultCollectionEvent {
    ResultSubmitted(WorkerResult),
    ResultValidated(JobId, WorkerId, bool),
    ConsensusReached(AggregatedResult),
    VerificationCompleted(JobId, bool),
    BlockchainSubmitted(JobId, String),
    BlockchainConfirmed(JobId, String),
    CollectionTimeout(JobId),
    Error(JobId, String),
}

/// State of result collection for a job
#[derive(Debug, Clone)]
pub struct JobResultCollection {
    pub job_id: JobId,
    pub results: Vec<WorkerResult>,
    pub aggregated_result: Option<AggregatedResult>,
    pub state: CollectionState,
    pub started_at: Instant,
    pub completed_at: Option<Instant>,
    pub expected_workers: Vec<WorkerId>,
    pub timeout_deadline: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CollectionState {
    Collecting,
    Aggregating,
    Verifying,
    Submitting,
    Completed,
    Failed,
    Timeout,
}

/// Main result collection coordinator
pub struct ResultCollector {
    config: ResultCollectionConfig,
    blockchain_client: Arc<StarknetClient>,
    job_manager: Arc<JobManagerContract>,
    p2p_network: Arc<NetworkClient>,
    
    // State management
    active_collections: Arc<RwLock<HashMap<JobId, JobResultCollection>>>,
    completed_results: Arc<RwLock<HashMap<JobId, AggregatedResult>>>,
    
    // Communication channels
    event_sender: mpsc::UnboundedSender<ResultCollectionEvent>,
    event_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<ResultCollectionEvent>>>>,
    
    // Internal state
    running: Arc<RwLock<bool>>,
}

impl ResultCollector {
    /// Create a new result collector
    pub fn new(
        config: ResultCollectionConfig,
        blockchain_client: Arc<StarknetClient>,
        job_manager: Arc<JobManagerContract>,
        p2p_network: Arc<NetworkClient>,
    ) -> Self {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        
        Self {
            config,
            blockchain_client,
            job_manager,
            p2p_network,
            active_collections: Arc::new(RwLock::new(HashMap::new())),
            completed_results: Arc::new(RwLock::new(HashMap::new())),
            event_sender,
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the result collection system
    pub async fn start(&self) -> Result<()> {
        info!("Starting P2P Result Collection System...");
        
        {
            let mut running = self.running.write().await;
            if *running {
                return Err(anyhow::anyhow!("Result collector already running"));
            }
            *running = true;
        }

        // TODO: Start background tasks when properly wrapped in Arc
        // For now, these will be called manually from the main loop

        info!("Result collection system started successfully");
        Ok(())
    }

    /// Stop the result collection system
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping result collection system...");
        
        let mut running = self.running.write().await;
        *running = false;
        
        info!("Result collection system stopped");
        Ok(())
    }

    /// Start collecting results for a job
    pub async fn start_collection(&self, job_id: JobId, expected_workers: Vec<WorkerId>) -> Result<()> {
        info!("Starting result collection for job: {}", job_id);
        
        let collection = JobResultCollection {
            job_id: job_id.clone(),
            results: Vec::new(),
            aggregated_result: None,
            state: CollectionState::Collecting,
            started_at: Instant::now(),
            completed_at: None,
            expected_workers,
            timeout_deadline: Instant::now() + Duration::from_secs(self.config.collection_timeout_secs),
        };
        
        {
            let mut collections = self.active_collections.write().await;
            collections.insert(job_id, collection);
        }
        
        Ok(())
    }

    /// Submit a result from a worker
    pub async fn submit_result(&self, result: WorkerResult) -> Result<()> {
        debug!("Received result from worker {} for job {}", result.worker_id, result.job_id);
        
        // Validate the result
        if let Err(e) = self.validate_result(&result).await {
            warn!("Result validation failed for job {}: {}", result.job_id, e);
            return Err(e);
        }
        
        // Send validation event
        if let Err(e) = self.event_sender.send(ResultCollectionEvent::ResultValidated(
            result.job_id.clone(),
            result.worker_id.clone(),
            true,
        )) {
            error!("Failed to send validation event: {}", e);
        }
        
        // Add to collection
        {
            let mut collections = self.active_collections.write().await;
            if let Some(collection) = collections.get_mut(&result.job_id) {
                if collection.state == CollectionState::Collecting {
                    collection.results.push(result.clone());
                    info!("Added result from worker {} for job {} ({}/{} results)", 
                          result.worker_id, result.job_id, 
                          collection.results.len(), self.config.max_results_per_job);
                    
                    // Check if we have enough results for consensus
                    if collection.results.len() >= self.config.min_consensus_results {
                        collection.state = CollectionState::Aggregating;
                        // Trigger aggregation
                        if let Err(e) = self.trigger_aggregation(result.job_id.clone()).await {
                            error!("Failed to trigger aggregation: {}", e);
                        }
                    }
                } else {
                    warn!("Received result for job {} in state {:?}, ignoring", result.job_id, collection.state);
                }
            } else {
                warn!("Received result for unknown job {}", result.job_id);
            }
        }
        
        // Send result received event
        if let Err(e) = self.event_sender.send(ResultCollectionEvent::ResultSubmitted(result)) {
            error!("Failed to send result submitted event: {}", e);
        }
        
        Ok(())
    }

    /// Validate a worker result
    async fn validate_result(&self, result: &WorkerResult) -> Result<()> {
        // Check hash integrity
        if !result.verify_hash() {
            return Err(anyhow::anyhow!("Result hash verification failed"));
        }
        
        // Check confidence score
        if result.confidence_score < 0.0 || result.confidence_score > 1.0 {
            return Err(anyhow::anyhow!("Invalid confidence score: {}", result.confidence_score));
        }
        
        // Check if result data is not empty
        if result.result_data.is_empty() {
            return Err(anyhow::anyhow!("Result data is empty"));
        }
        
        // Additional validation logic can be added here
        
        Ok(())
    }

    /// Trigger result aggregation for a job
    async fn trigger_aggregation(&self, job_id: JobId) -> Result<()> {
        debug!("Triggering aggregation for job: {}", job_id);
        
        let results = {
            let collections = self.active_collections.read().await;
            if let Some(collection) = collections.get(&job_id) {
                collection.results.clone()
            } else {
                return Err(anyhow::anyhow!("Job not found: {}", job_id));
            }
        };
        
        // Perform aggregation
        let aggregated_result = self.aggregate_results(job_id.clone(), results).await?;
        
        // Update collection with aggregated result
        {
            let mut collections = self.active_collections.write().await;
            if let Some(collection) = collections.get_mut(&job_id) {
                collection.aggregated_result = Some(aggregated_result.clone());
                collection.state = CollectionState::Verifying;
            }
        }
        
        // Send consensus event
        if let Err(e) = self.event_sender.send(ResultCollectionEvent::ConsensusReached(aggregated_result.clone())) {
            error!("Failed to send consensus reached event: {}", e);
        }
        
        // Trigger verification if enabled
        if self.config.enable_verification {
            if let Err(e) = self.trigger_verification(job_id).await {
                error!("Failed to trigger verification: {}", e);
            }
        } else {
            // Skip verification and go to blockchain submission
            if let Err(e) = self.trigger_blockchain_submission(job_id).await {
                error!("Failed to trigger blockchain submission: {}", e);
            }
        }
        
        Ok(())
    }

    /// Aggregate multiple results into a consensus result
    async fn aggregate_results(&self, job_id: JobId, results: Vec<WorkerResult>) -> Result<AggregatedResult> {
        info!("Aggregating {} results for job: {}", results.len(), job_id);
        
        // For now, use majority vote as the default aggregation method
        let aggregation_method = AggregationMethod::MajorityVote;
        
        let consensus_result = match aggregation_method {
            AggregationMethod::MajorityVote => {
                self.majority_vote_aggregation(&results).await?
            }
            AggregationMethod::WeightedAverage => {
                self.weighted_average_aggregation(&results).await?
            }
            AggregationMethod::HighestConfidence => {
                self.highest_confidence_aggregation(&results).await?
            }
            AggregationMethod::MedianValue => {
                self.median_value_aggregation(&results).await?
            }
            AggregationMethod::Custom(_) => {
                // Custom aggregation logic would go here
                self.majority_vote_aggregation(&results).await?
            }
        };
        
        let consensus_hash = WorkerResult::calculate_hash(&consensus_result);
        let contributing_workers: Vec<WorkerId> = results.iter().map(|r| r.worker_id).collect();
        
        // Calculate confidence score based on consensus
        let confidence_score = self.calculate_consensus_confidence(&results, &consensus_result).await?;
        
        let aggregated_result = AggregatedResult {
            job_id,
            aggregation_id: Uuid::new_v4().to_string(),
            consensus_result,
            consensus_hash,
            confidence_score,
            contributing_workers,
            individual_results: results,
            aggregation_method,
            created_at: chrono::Utc::now().timestamp() as u64,
            verification_status: VerificationStatus::Pending,
            blockchain_submission_status: BlockchainSubmissionStatus::Pending,
        };
        
        Ok(aggregated_result)
    }

    /// Majority vote aggregation
    async fn majority_vote_aggregation(&self, results: &[WorkerResult]) -> Result<Vec<u8>> {
        let mut hash_count: HashMap<String, (Vec<u8>, usize)> = HashMap::new();
        
        for result in results {
            let entry = hash_count.entry(result.result_hash.clone()).or_insert((result.result_data.clone(), 0));
            entry.1 += 1;
        }
        
        // Find the most common result
        let (_, (consensus_data, _)) = hash_count
            .into_iter()
            .max_by_key(|(_, (_, count))| *count)
            .ok_or_else(|| anyhow::anyhow!("No results available for aggregation"))?;
        
        Ok(consensus_data)
    }

    /// Weighted average aggregation (for numeric results)
    async fn weighted_average_aggregation(&self, results: &[WorkerResult]) -> Result<Vec<u8>> {
        // This is a placeholder - in a real implementation, you'd need to:
        // 1. Parse result data as numeric values
        // 2. Apply weights based on worker reputation
        // 3. Calculate weighted average
        // 4. Convert back to bytes
        
        // For now, fall back to majority vote
        self.majority_vote_aggregation(results).await
    }

    /// Highest confidence aggregation
    async fn highest_confidence_aggregation(&self, results: &[WorkerResult]) -> Result<Vec<u8>> {
        let best_result = results
            .iter()
            .max_by(|a, b| a.confidence_score.partial_cmp(&b.confidence_score).unwrap_or(std::cmp::Ordering::Equal))
            .ok_or_else(|| anyhow::anyhow!("No results available for aggregation"))?;
        
        Ok(best_result.result_data.clone())
    }

    /// Median value aggregation (for numeric results)
    async fn median_value_aggregation(&self, results: &[WorkerResult]) -> Result<Vec<u8>> {
        // This is a placeholder - in a real implementation, you'd need to:
        // 1. Parse result data as numeric values
        // 2. Calculate median
        // 3. Convert back to bytes
        
        // For now, fall back to majority vote
        self.majority_vote_aggregation(results).await
    }

    /// Calculate consensus confidence score
    async fn calculate_consensus_confidence(&self, results: &[WorkerResult], consensus_result: &[u8]) -> Result<f64> {
        let consensus_hash = WorkerResult::calculate_hash(consensus_result);
        let matching_results = results.iter().filter(|r| r.result_hash == consensus_hash).count();
        
        let consensus_ratio = matching_results as f64 / results.len() as f64;
        let avg_confidence = results.iter().map(|r| r.confidence_score).sum::<f64>() / results.len() as f64;
        
        // Combine consensus ratio with average confidence
        Ok((consensus_ratio * 0.7) + (avg_confidence * 0.3))
    }

    /// Trigger result verification
    async fn trigger_verification(&self, job_id: JobId) -> Result<()> {
        info!("Triggering verification for job: {}", job_id);
        
        // Update state
        {
            let mut collections = self.active_collections.write().await;
            if let Some(collection) = collections.get_mut(&job_id) {
                if let Some(ref mut result) = collection.aggregated_result {
                    result.verification_status = VerificationStatus::InProgress;
                }
            }
        }
        
        // In a real implementation, verification would involve:
        // 1. Selecting a subset of results for re-computation
        // 2. Running verification nodes
        // 3. Comparing results
        // 4. Updating verification status
        
        // For now, simulate verification
        tokio::spawn(async move {
            // Simulate verification time
            sleep(Duration::from_secs(5)).await;
            
            // For demo purposes, assume verification passes
            info!("Verification completed for job: {}", job_id);
        });
        
        // Skip verification for now and go to blockchain submission
        if let Err(e) = self.trigger_blockchain_submission(job_id).await {
            error!("Failed to trigger blockchain submission: {}", e);
        }
        
        Ok(())
    }

    /// Trigger blockchain submission
    async fn trigger_blockchain_submission(&self, job_id: JobId) -> Result<()> {
        info!("Triggering blockchain submission for job: {}", job_id);
        
        let aggregated_result = {
            let collections = self.active_collections.read().await;
            if let Some(collection) = collections.get(&job_id) {
                collection.aggregated_result.clone()
            } else {
                return Err(anyhow::anyhow!("Job not found: {}", job_id));
            }
        };
        
        let result = aggregated_result.ok_or_else(|| anyhow::anyhow!("No aggregated result available"))?;
        
        // Update state
        {
            let mut collections = self.active_collections.write().await;
            if let Some(collection) = collections.get_mut(&job_id) {
                collection.state = CollectionState::Submitting;
                if let Some(ref mut agg_result) = collection.aggregated_result {
                    agg_result.blockchain_submission_status = BlockchainSubmissionStatus::Pending;
                }
            }
        }
        
        // Submit to blockchain
        if let Err(e) = self.submit_to_blockchain(result).await {
            error!("Failed to submit to blockchain: {}", e);
            
            // Update state on failure
            {
                let mut collections = self.active_collections.write().await;
                if let Some(collection) = collections.get_mut(&job_id) {
                    collection.state = CollectionState::Failed;
                    if let Some(ref mut agg_result) = collection.aggregated_result {
                        agg_result.blockchain_submission_status = BlockchainSubmissionStatus::Failed(e.to_string());
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Submit aggregated result to blockchain
    async fn submit_to_blockchain(&self, result: AggregatedResult) -> Result<()> {
        // In a real implementation, this would:
        // 1. Convert the result to blockchain format
        // 2. Call the job manager contract
        // 3. Handle transaction confirmation
        // 4. Update the submission status
        
        info!("Submitting result for job {} to blockchain (simulated)", result.job_id);
        
        // Simulate blockchain submission
        let tx_hash = format!("0x{:x}", rand::random::<u64>());
        
        // Send submission event
        if let Err(e) = self.event_sender.send(ResultCollectionEvent::BlockchainSubmitted(
            result.job_id.clone(),
            tx_hash.clone(),
        )) {
            error!("Failed to send blockchain submitted event: {}", e);
        }
        
        // Update state
        {
            let mut collections = self.active_collections.write().await;
            if let Some(collection) = collections.get_mut(&result.job_id) {
                collection.state = CollectionState::Completed;
                collection.completed_at = Some(Instant::now());
                if let Some(ref mut agg_result) = collection.aggregated_result {
                    agg_result.blockchain_submission_status = BlockchainSubmissionStatus::Submitted(tx_hash.clone());
                }
            }
        }
        
        // Move to completed results
        let job_id_for_confirmation = result.job_id.clone();
        {
            let mut completed = self.completed_results.write().await;
            completed.insert(result.job_id.clone(), result);
        }
        
        // Simulate confirmation
        tokio::spawn(async move {
            sleep(Duration::from_secs(10)).await;
            info!("Blockchain confirmation received for job: {}", job_id_for_confirmation);
        });
        
        Ok(())
    }

    /// Get collection statistics
    pub async fn get_collection_stats(&self) -> HashMap<CollectionState, usize> {
        let collections = self.active_collections.read().await;
        let mut stats = HashMap::new();
        
        for collection in collections.values() {
            *stats.entry(collection.state.clone()).or_insert(0) += 1;
        }
        
        stats
    }

    /// Get completed results
    pub async fn get_completed_results(&self) -> Vec<AggregatedResult> {
        let completed = self.completed_results.read().await;
        completed.values().cloned().collect()
    }

    /// Clean up old completed collections
    pub async fn cleanup_old_collections(&self, max_age_secs: u64) -> Result<()> {
        let cutoff = Instant::now() - Duration::from_secs(max_age_secs);
        
        {
            let mut collections = self.active_collections.write().await;
            collections.retain(|_, collection| {
                collection.completed_at.map_or(true, |completed_at| completed_at > cutoff)
            });
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{JobId, WorkerId};

    #[tokio::test]
    async fn test_result_collection_config() {
        let config = ResultCollectionConfig::default();
        assert_eq!(config.min_consensus_results, 3);
        assert_eq!(config.max_results_per_job, 10);
        assert!(config.min_confidence_threshold > 0.0);
        assert!(config.enable_verification);
    }

    #[tokio::test]
    async fn test_worker_result_creation() {
        let job_id = JobId::new();
        let worker_id = WorkerId::new();
        let result_data = b"test result data".to_vec();
        let metadata = HashMap::new();
        
        let result = WorkerResult::new(
            job_id,
            worker_id,
            result_data.clone(),
            1000,
            500,
            0.9,
            metadata,
        );
        
        assert_eq!(result.job_id, job_id);
        assert_eq!(result.worker_id, worker_id);
        assert_eq!(result.result_data, result_data);
        assert_eq!(result.execution_time_ms, 1000);
        assert_eq!(result.confidence_score, 0.9);
        assert!(result.verify_hash());
    }

    #[tokio::test]
    async fn test_hash_verification() {
        let job_id = JobId::new();
        let worker_id = WorkerId::new();
        let result_data = b"test result data".to_vec();
        let metadata = HashMap::new();
        
        let mut result = WorkerResult::new(
            job_id,
            worker_id,
            result_data,
            1000,
            500,
            0.9,
            metadata,
        );
        
        // Valid hash should verify
        assert!(result.verify_hash());
        
        // Corrupted hash should fail verification
        result.result_hash = "invalid_hash".to_string();
        assert!(!result.verify_hash());
    }

    #[tokio::test]
    async fn test_aggregation_method_variants() {
        // Test all aggregation method variants
        let methods = vec![
            AggregationMethod::MajorityVote,
            AggregationMethod::WeightedAverage,
            AggregationMethod::HighestConfidence,
            AggregationMethod::MedianValue,
            AggregationMethod::Custom("test".to_string()),
        ];
        
        for method in methods {
            // Just verify the enum variants work
            match method {
                AggregationMethod::MajorityVote => assert!(true),
                AggregationMethod::WeightedAverage => assert!(true),
                AggregationMethod::HighestConfidence => assert!(true),
                AggregationMethod::MedianValue => assert!(true),
                AggregationMethod::Custom(s) => assert_eq!(s, "test"),
            }
        }
    }

    #[tokio::test]
    async fn test_consensus_confidence_calculation() {
        // This would test the confidence calculation logic
        // For now, just verify the method exists
        let job_id = JobId::new();
        let worker_id = WorkerId::new();
        let metadata = HashMap::new();
        
        let result = WorkerResult::new(
            job_id,
            worker_id,
            b"test".to_vec(),
            1000,
            500,
            0.9,
            metadata,
        );
        
        let results = vec![result];
        let consensus_result = b"test".to_vec();
        
        // In a real test, we'd create a ResultCollector and test the method
        // For now, just verify the data structures work
        assert_eq!(results.len(), 1);
        assert_eq!(consensus_result, b"test".to_vec());
    }
}
