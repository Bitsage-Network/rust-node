//! # P2P Job Distribution System
//!
//! This module implements the core job distribution system that bridges
//! the blockchain contract with the P2P network for decentralized job processing.

use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{sleep, Duration};
use tracing::{info, debug, warn, error};
use uuid::Uuid;

use crate::blockchain::{
    client::StarknetClient,
    contracts::JobManagerContract,
    types::{JobSpec, WorkerCapabilities},
};
use crate::network::p2p::{NetworkClient, P2PMessage};
use crate::network::health_reputation::{
    HealthReputationSystem, HealthReputationConfig, HealthMetrics, PenaltyType
};
use crate::types::{JobId, WorkerId};

/// Job distribution configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobDistributionConfig {
    /// Maximum number of workers to consider for a job
    pub max_workers_per_job: usize,
    /// Timeout for worker bids in seconds
    pub bid_timeout_secs: u64,
    /// Minimum reputation score for workers
    pub min_worker_reputation: f64,
    /// Job announcement retry attempts
    pub announcement_retries: u32,
    /// Blockchain polling interval in seconds
    pub blockchain_poll_interval_secs: u64,
    /// Health reputation system configuration
    pub health_reputation_config: HealthReputationConfig,
}

impl Default for JobDistributionConfig {
    fn default() -> Self {
        Self {
            max_workers_per_job: 10,
            bid_timeout_secs: 30,
            min_worker_reputation: 0.7,
            announcement_retries: 3,
            blockchain_poll_interval_secs: 10,
            health_reputation_config: HealthReputationConfig::default(),
        }
    }
}

/// Job announcement message broadcasted via P2P
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobAnnouncement {
    pub job_id: JobId,
    pub job_spec: JobSpec,
    pub max_reward: u128,
    pub deadline: u64,
    pub required_capabilities: WorkerCapabilities,
    pub announcement_id: String,
    pub announced_at: u64,
}

/// Worker bid for a job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerBid {
    pub job_id: JobId,
    pub worker_id: WorkerId,
    pub bid_amount: u128,
    pub estimated_completion_time: u64,
    pub worker_capabilities: WorkerCapabilities,
    pub reputation_score: f64,
    pub health_score: f64,
    pub bid_id: String,
    pub submitted_at: u64,
}

/// Job assignment to a selected worker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobAssignment {
    pub job_id: JobId,
    pub worker_id: WorkerId,
    pub assignment_id: String,
    pub assigned_at: u64,
    pub deadline: u64,
    pub reward_amount: u128,
}

/// Job execution result from worker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResult {
    pub job_id: JobId,
    pub worker_id: WorkerId,
    pub assignment_id: String,
    pub success: bool,
    pub result_data: Vec<u8>,
    pub execution_time_ms: u64,
    pub completed_at: u64,
    pub error_message: Option<String>,
    pub result_quality: Option<f64>,
    pub confidence_score: Option<f64>,
}

/// Job distribution events
#[derive(Debug, Clone)]
pub enum JobDistributionEvent {
    JobAnnounced(JobAnnouncement),
    BidReceived(WorkerBid),
    JobAssigned(JobAssignment),
    ResultSubmitted(JobResult),
    JobCompleted(JobId),
    JobFailed(JobId, String),
    WorkerTimeout(WorkerId, JobId),
    WorkerHealthUpdated(WorkerId, HealthMetrics),
    MaliciousBehaviorDetected(WorkerId, String),
}

/// Job state tracking
#[derive(Debug, Clone)]
pub struct DistributedJob {
    pub job_id: JobId,
    pub announcement: JobAnnouncement,
    pub bids: Vec<WorkerBid>,
    pub assignment: Option<JobAssignment>,
    pub result: Option<JobResult>,
    pub state: JobDistributionState,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum JobDistributionState {
    Announced,
    CollectingBids,
    Assigned,
    InProgress,
    Completed,
    Failed,
    Timeout,
}

/// Main job distribution coordinator
pub struct JobDistributor {
    config: JobDistributionConfig,
    blockchain_client: Arc<StarknetClient>,
    job_manager: Arc<JobManagerContract>,
    p2p_network: Arc<NetworkClient>,
    health_reputation_system: Arc<HealthReputationSystem>,
    
    // State management
    jobs: Arc<RwLock<HashMap<JobId, DistributedJob>>>,
    
    // Communication channels
    event_sender: mpsc::UnboundedSender<JobDistributionEvent>,
    event_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<JobDistributionEvent>>>>,
    
    // Internal state
    running: Arc<RwLock<bool>>,
    last_blockchain_poll: Arc<RwLock<u64>>,
}

impl JobDistributor {
    /// Create a new job distributor
    pub fn new(
        config: JobDistributionConfig,
        blockchain_client: Arc<StarknetClient>,
        job_manager: Arc<JobManagerContract>,
        p2p_network: Arc<NetworkClient>,
    ) -> Self {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        
        // Create health reputation system
        let health_reputation_system = Arc::new(HealthReputationSystem::new(config.health_reputation_config.clone()));
        
        Self {
            config,
            blockchain_client,
            job_manager,
            p2p_network,
            health_reputation_system,
            jobs: Arc::new(RwLock::new(HashMap::new())),
            event_sender,
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
            running: Arc::new(RwLock::new(false)),
            last_blockchain_poll: Arc::new(RwLock::new(0)),
        }
    }

    /// Start the job distribution system
    pub async fn start(&self) -> Result<()> {
        info!("Starting P2P Job Distribution System...");
        
        {
            let mut running = self.running.write().await;
            if *running {
                return Err(anyhow::anyhow!("Job distributor already running"));
            }
            *running = true;
        }

        // Start health reputation system
        self.health_reputation_system.start().await?;

        // Spawn event loop
        let event_loop_self = self.clone_for_task();
        tokio::spawn(async move {
            if let Err(e) = event_loop_self.run_event_loop().await {
                error!("Job distributor event loop failed: {}", e);
            }
        });

        // Spawn blockchain monitor
        let monitor_self = self.clone_for_task();
        tokio::spawn(async move {
            if let Err(e) = monitor_self.monitor_blockchain().await {
                error!("Job distributor blockchain monitor failed: {}", e);
            }
        });

        info!("Job distribution system started successfully");
        Ok(())
    }

    /// Helper to clone self for background tasks
    fn clone_for_task(&self) -> Self {
        Self {
            config: self.config.clone(),
            blockchain_client: self.blockchain_client.clone(),
            job_manager: self.job_manager.clone(),
            p2p_network: self.p2p_network.clone(),
            health_reputation_system: self.health_reputation_system.clone(),
            jobs: self.jobs.clone(),
            event_sender: self.event_sender.clone(),
            event_receiver: self.event_receiver.clone(),
            running: self.running.clone(),
            last_blockchain_poll: self.last_blockchain_poll.clone(),
        }
    }

    /// Stop the job distribution system
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping job distribution system...");
        
        let mut running = self.running.write().await;
        *running = false;
        
        // Stop health reputation system
        self.health_reputation_system.stop().await?;
        
        info!("Job distribution system stopped");
        Ok(())
    }

    /// Main event processing loop
    async fn run_event_loop(&self) -> Result<()> {
        let mut receiver = {
            let mut guard = self.event_receiver.write().await;
            guard.take().context("Event receiver already taken")?
        };

        while *self.running.read().await {
            tokio::select! {
                Some(event) = receiver.recv() => {
                    if let Err(e) = self.handle_event(event).await {
                        error!("Failed to handle event: {}", e);
                    }
                }
                _ = sleep(Duration::from_millis(100)) => {
                    // Periodic maintenance
                    if let Err(e) = self.periodic_maintenance().await {
                        warn!("Periodic maintenance failed: {}", e);
                    }
                    
                    // Health reputation maintenance
                    if let Err(e) = self.health_reputation_system.periodic_maintenance().await {
                        warn!("Health reputation maintenance failed: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Monitor blockchain for new jobs
    async fn monitor_blockchain(&self) -> Result<()> {
        while *self.running.read().await {
            let current_time = chrono::Utc::now().timestamp() as u64;
            let last_poll = *self.last_blockchain_poll.read().await;
            
            if current_time - last_poll >= self.config.blockchain_poll_interval_secs {
                if let Err(e) = self.poll_blockchain_jobs().await {
                    warn!("Failed to poll blockchain jobs: {}", e);
                }
                
                let mut last_poll_guard = self.last_blockchain_poll.write().await;
                *last_poll_guard = current_time;
            }
            
            sleep(Duration::from_secs(1)).await;
        }
        
        Ok(())
    }

    /// Poll blockchain for new jobs
    async fn poll_blockchain_jobs(&self) -> Result<()> {
        // TODO: Implement actual blockchain polling
        // For now, this is a placeholder
        debug!("Polling blockchain for new jobs");
        Ok(())
    }

    /// Handle job distribution events
    async fn handle_event(&self, event: JobDistributionEvent) -> Result<()> {
        match event {
            JobDistributionEvent::JobAnnounced(announcement) => {
                self.handle_job_announced(announcement).await?;
            }
            JobDistributionEvent::BidReceived(bid) => {
                self.handle_bid_received(bid).await?;
            }
            JobDistributionEvent::JobAssigned(assignment) => {
                self.handle_job_assigned(assignment).await?;
            }
            JobDistributionEvent::ResultSubmitted(result) => {
                self.handle_result_submitted(result).await?;
            }
            JobDistributionEvent::JobCompleted(job_id) => {
                self.handle_job_completed(job_id).await?;
            }
            JobDistributionEvent::JobFailed(job_id, error) => {
                self.handle_job_failed(job_id, error).await?;
            }
            JobDistributionEvent::WorkerTimeout(worker_id, job_id) => {
                self.handle_worker_timeout(worker_id, job_id).await?;
            }
            JobDistributionEvent::WorkerHealthUpdated(worker_id, metrics) => {
                self.handle_worker_health_update(worker_id, metrics).await?;
            }
            JobDistributionEvent::MaliciousBehaviorDetected(worker_id, behavior) => {
                self.handle_malicious_behavior(worker_id, behavior).await?;
            }
        }
        
        Ok(())
    }

    /// Handle job announcement
    async fn handle_job_announced(&self, announcement: JobAnnouncement) -> Result<()> {
        info!("Job announced: {}", announcement.job_id);
        
        let job = DistributedJob {
            job_id: announcement.job_id.clone(),
            announcement: announcement.clone(),
            bids: Vec::new(),
            assignment: None,
            result: None,
            state: JobDistributionState::Announced,
            created_at: chrono::Utc::now().timestamp() as u64,
            updated_at: chrono::Utc::now().timestamp() as u64,
        };
        
        {
            let mut jobs = self.jobs.write().await;
            jobs.insert(announcement.job_id.clone(), job);
        }
        
        // Start bid collection timer
        self.start_bid_collection_timer(announcement.job_id).await?;
        
        Ok(())
    }

    /// Handle bid received
    async fn handle_bid_received(&self, bid: WorkerBid) -> Result<()> {
        debug!("Received bid from worker {} for job {}", bid.worker_id, bid.job_id);
        
        // Check if worker is eligible
        if !self.health_reputation_system.is_worker_eligible(&bid.worker_id).await {
            warn!("Worker {} not eligible for job {}", bid.worker_id, bid.job_id);
            return Ok(());
        }
        
        // Update job with new bid
        {
            let mut jobs = self.jobs.write().await;
            if let Some(job) = jobs.get_mut(&bid.job_id) {
                if job.state == JobDistributionState::CollectingBids {
                    job.bids.push(bid.clone());
                    job.updated_at = chrono::Utc::now().timestamp() as u64;
                    info!("Added bid from worker {} for job {}", bid.worker_id, bid.job_id);
                } else {
                    warn!("Received bid for job {} in state {:?}, ignoring", bid.job_id, job.state);
                }
            } else {
                warn!("Received bid for unknown job {}", bid.job_id);
            }
        }
        
        Ok(())
    }

    /// Handle job assignment
    async fn handle_job_assigned(&self, assignment: JobAssignment) -> Result<()> {
        info!("Job assigned: {} to worker {}", assignment.job_id, assignment.worker_id);
        
        {
            let mut jobs = self.jobs.write().await;
            if let Some(job) = jobs.get_mut(&assignment.job_id) {
                job.assignment = Some(assignment.clone());
                job.state = JobDistributionState::Assigned;
                job.updated_at = chrono::Utc::now().timestamp() as u64;
            }
        }
        
        Ok(())
    }

    /// Handle result submitted
    async fn handle_result_submitted(&self, result: JobResult) -> Result<()> {
        info!("Result submitted for job {} by worker {}", result.job_id, result.worker_id);
        
        // Update job with result
        {
            let mut jobs = self.jobs.write().await;
            if let Some(job) = jobs.get_mut(&result.job_id) {
                job.result = Some(result.clone());
                job.state = if result.success {
                    JobDistributionState::Completed
                } else {
                    JobDistributionState::Failed
                };
                job.updated_at = chrono::Utc::now().timestamp() as u64;
            }
        }
        
        // Submit result to blockchain
        if let Err(e) = self.submit_result_to_blockchain(&result).await {
            error!("Failed to submit result to blockchain: {}", e);
        }
        
        // Update worker reputation in health reputation system
        self.health_reputation_system.update_worker_reputation(
            result.worker_id.clone(),
            result.success,
            result.execution_time_ms,
            result.assignment_id.parse().unwrap_or(0), // Use assignment ID as earnings for now
            result.result_quality,
        ).await?;
        
        // Apply penalties for failures
        if !result.success {
            self.health_reputation_system.apply_penalty(
                result.worker_id.clone(),
                PenaltyType::JobFailure,
                0.3,
                result.error_message.unwrap_or_else(|| "Job failed".to_string()),
                Some(result.job_id.clone()),
            ).await?;
        }
        
        Ok(())
    }

    /// Handle job completion
    async fn handle_job_completed(&self, job_id: JobId) -> Result<()> {
        info!("Job {} completed successfully", job_id);
        
        // Clean up job state
        {
            let mut jobs = self.jobs.write().await;
            if let Some(job) = jobs.get_mut(&job_id) {
                job.state = JobDistributionState::Completed;
                job.updated_at = chrono::Utc::now().timestamp() as u64;
            }
        }
        
        Ok(())
    }

    /// Handle job failure
    async fn handle_job_failed(&self, job_id: JobId, error: String) -> Result<()> {
        warn!("Job {} failed: {}", job_id, error);
        
        // Update job state
        {
            let mut jobs = self.jobs.write().await;
            if let Some(job) = jobs.get_mut(&job_id) {
                job.state = JobDistributionState::Failed;
                job.updated_at = chrono::Utc::now().timestamp() as u64;
            }
        }
        
        // Consider reassignment or termination
        self.handle_job_reassignment(job_id).await?;
        
        Ok(())
    }

    /// Handle worker timeout
    async fn handle_worker_timeout(&self, worker_id: WorkerId, job_id: JobId) -> Result<()> {
        warn!("Worker {} timed out for job {}", worker_id, job_id);
        
        // Apply timeout penalty
        self.health_reputation_system.apply_penalty(
            worker_id.clone(),
            PenaltyType::JobTimeout,
            0.5,
            "Job timeout".to_string(),
            Some(job_id.clone()),
        ).await?;
        
        // Reassign job
        self.handle_job_reassignment(job_id).await?;
        
        Ok(())
    }

    /// Handle worker health update
    async fn handle_worker_health_update(&self, worker_id: WorkerId, metrics: HealthMetrics) -> Result<()> {
        debug!("Worker health update: {}", worker_id);
        
        self.health_reputation_system.update_worker_health(worker_id, metrics).await?;
        
        Ok(())
    }

    /// Handle malicious behavior detection
    async fn handle_malicious_behavior(&self, worker_id: WorkerId, behavior: String) -> Result<()> {
        warn!("Malicious behavior detected from worker {}: {}", worker_id, behavior);
        
        self.health_reputation_system.detect_malicious_behavior(worker_id, behavior).await?;
        
        Ok(())
    }

    /// Start bid collection timer
    async fn start_bid_collection_timer(&self, job_id: JobId) -> Result<()> {
        // TODO: Implement timer when JobDistributor supports proper async spawning
        // For now, this is a placeholder that would be handled by the main event loop
        info!("Bid collection timer started for job {} ({}s timeout)", job_id, self.config.bid_timeout_secs);
        Ok(())
    }

    /// Process collected bids and assign job
    async fn process_bids_and_assign(&self, job_id: JobId) -> Result<()> {
        let bids = {
            let jobs = self.jobs.read().await;
            if let Some(job) = jobs.get(&job_id) {
                job.bids.clone()
            } else {
                return Err(anyhow::anyhow!("Job not found"));
            }
        };
        
        if bids.is_empty() {
            warn!("No bids received for job {}", job_id);
            return Ok(());
        }
        
        // Select best worker
        let best_bid = self.select_best_worker(&bids).await?;
        
        // Create assignment
        let assignment = JobAssignment {
            job_id: job_id.clone(),
            worker_id: best_bid.worker_id.clone(),
            assignment_id: Uuid::new_v4().to_string(),
            assigned_at: chrono::Utc::now().timestamp() as u64,
            deadline: chrono::Utc::now().timestamp() as u64 + best_bid.estimated_completion_time,
            reward_amount: best_bid.bid_amount,
        };
        
        // Update job state
        {
            let mut jobs = self.jobs.write().await;
            if let Some(job) = jobs.get_mut(&job_id) {
                job.assignment = Some(assignment.clone());
                job.state = JobDistributionState::Assigned;
                job.updated_at = chrono::Utc::now().timestamp() as u64;
            }
        }
        
        info!("Job {} assigned to worker {}", job_id, best_bid.worker_id);
        
        Ok(())
    }

    /// Select best worker from bids
    async fn select_best_worker(&self, bids: &[WorkerBid]) -> Result<WorkerBid> {
        // Filter bids by minimum reputation and health
        let mut qualified_bids: Vec<_> = bids.iter()
            .filter(|bid| {
                bid.reputation_score >= self.config.min_worker_reputation &&
                bid.health_score >= 0.7 // Minimum health score
            })
            .collect();
        
        if qualified_bids.is_empty() {
            return Err(anyhow::anyhow!("No qualified workers found"));
        }
        
        // Sort by composite score (reputation + health + bid competitiveness)
        qualified_bids.sort_by(|a, b| {
            let score_a = self.calculate_worker_score(a);
            let score_b = self.calculate_worker_score(b);
            score_b.partial_cmp(&score_a).unwrap_or(std::cmp::Ordering::Equal)
        });
        
        Ok(qualified_bids[0].clone())
    }

    /// Calculate worker selection score
    fn calculate_worker_score(&self, bid: &WorkerBid) -> f64 {
        // Composite score based on:
        // - Reputation (35%)
        // - Health score (25%)
        // - Bid competitiveness (25%) 
        // - Estimated completion time (15%)
        
        let reputation_score = bid.reputation_score * 0.35;
        let health_score = bid.health_score * 0.25;
        let bid_score = (1.0 / (bid.bid_amount as f64 + 1.0)) * 0.25;
        let time_score = (1.0 / (bid.estimated_completion_time as f64 + 1.0)) * 0.15;
        
        reputation_score + health_score + bid_score + time_score
    }

    /// Handle job reassignment after failure
    async fn handle_job_reassignment(&self, job_id: JobId) -> Result<()> {
        // In real implementation, this would:
        // 1. Check if job can be reassigned
        // 2. Select next best worker from previous bids
        // 3. Or re-announce the job if needed
        
        info!("Job {} marked for reassignment (implementation pending)", job_id);
        Ok(())
    }

    /// Submit result to blockchain
    async fn submit_result_to_blockchain(&self, result: &JobResult) -> Result<()> {
        // In real implementation, this would:
        // 1. Format result for blockchain submission
        // 2. Call job manager contract
        // 3. Handle transaction confirmation
        
        info!("Submitting result for job {} to blockchain (simulated)", result.job_id);
        Ok(())
    }

    /// Periodic maintenance tasks
    async fn periodic_maintenance(&self) -> Result<()> {
        // Clean up old completed jobs
        let current_time = chrono::Utc::now().timestamp() as u64;
        let cleanup_threshold = current_time - 3600; // 1 hour
        
        {
            let mut jobs = self.jobs.write().await;
            jobs.retain(|_, job| {
                job.updated_at > cleanup_threshold || 
                (job.state != JobDistributionState::Completed && job.state != JobDistributionState::Failed)
            });
        }
        
        Ok(())
    }

    /// Get current job statistics
    pub async fn get_job_stats(&self) -> HashMap<JobDistributionState, usize> {
        let jobs = self.jobs.read().await;
        let mut stats = HashMap::new();
        
        for job in jobs.values() {
            *stats.entry(job.state.clone()).or_insert(0) += 1;
        }
        
        stats
    }

    /// Get worker reputation stats
    pub async fn get_worker_stats(&self) -> Vec<crate::network::health_reputation::WorkerReputation> {
        self.health_reputation_system.get_all_reputations().await
    }

    /// Get network health
    pub async fn get_network_health(&self) -> crate::network::health_reputation::NetworkHealth {
        self.health_reputation_system.get_network_health().await
    }

    /// Get health reputation system reference
    pub fn health_reputation_system(&self) -> Arc<HealthReputationSystem> {
        self.health_reputation_system.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::types::{JobType, ModelId, VerificationMethod};
    use starknet::core::types::FieldElement;
    use crate::network::p2p::NetworkActor;

    #[tokio::test]
    async fn test_job_distribution_config() {
        let config = JobDistributionConfig::default();
        assert_eq!(config.max_workers_per_job, 10);
        assert_eq!(config.bid_timeout_secs, 30);
        assert!(config.min_worker_reputation > 0.0);
    }

    #[tokio::test]
    async fn test_job_announcement_creation() {
        let job_spec = JobSpec {
            job_type: JobType::AIInference,
            model_id: ModelId::new(FieldElement::from(1u32)),
            input_data_hash: FieldElement::from_hex_be("0x123").unwrap(),
            expected_output_format: FieldElement::from_hex_be("0x456").unwrap(),
            verification_method: VerificationMethod::StatisticalSampling,
            max_reward: 1000,
            sla_deadline: 3600,
            compute_requirements: vec![],
            metadata: vec![],
        };

        let job_id = JobId::new();
        let announcement = JobAnnouncement {
            job_id: job_id.clone(),
            job_spec,
            max_reward: 1000,
            deadline: 3600,
            required_capabilities: WorkerCapabilities {
                gpu_memory: 8192,
                cpu_cores: 8,
                ram: 16384,
                storage: 1000,
                bandwidth: 1000,
                capability_flags: 0xFF,
                gpu_model: FieldElement::from(0x4090u32),
                cpu_model: FieldElement::from(0x7950u32),
            },
            announcement_id: Uuid::new_v4().to_string(),
            announced_at: chrono::Utc::now().timestamp() as u64,
        };

        assert_eq!(announcement.job_id, job_id);
        assert_eq!(announcement.max_reward, 1000);
    }

    #[tokio::test]
    async fn test_worker_bid_creation() {
        let job_id = JobId::new();
        let worker_id = WorkerId::new();
        let bid = WorkerBid {
            job_id: job_id.clone(),
            worker_id: worker_id.clone(),
            bid_amount: 800,
            estimated_completion_time: 1800,
            worker_capabilities: WorkerCapabilities {
                gpu_memory: 8192,
                cpu_cores: 8,
                ram: 16384,
                storage: 1000,
                bandwidth: 1000,
                capability_flags: 0xFF,
                gpu_model: FieldElement::from(0x4090u32),
                cpu_model: FieldElement::from(0x7950u32),
            },
            reputation_score: 0.85,
            health_score: 0.9,
            bid_id: Uuid::new_v4().to_string(),
            submitted_at: chrono::Utc::now().timestamp() as u64,
        };

        assert_eq!(bid.job_id, job_id);
        assert_eq!(bid.worker_id, worker_id);
        assert_eq!(bid.bid_amount, 800);
        assert!(bid.reputation_score > 0.0);
        assert!(bid.health_score > 0.0);
    }

    #[tokio::test]
    async fn test_worker_score_calculation() {
        let bid = WorkerBid {
            job_id: JobId::new(),
            worker_id: WorkerId::new(),
            bid_amount: 800,
            estimated_completion_time: 1800,
            worker_capabilities: crate::types::WorkerCapabilities {
                cpu_cores: 8,
                memory_gb: 32,
                gpu_count: 1,
                gpu_model: Some("RTX3090".to_string()),
                gpu_memory_gb: Some(24),
                disk_gb: 1000,
                max_concurrent_jobs: 4,
                tee_type: crate::types::TeeType::None,
                secure_enclave_memory_mb: None,
                attestation_mechanism: None,
                trusted_boot_enabled: false,
                secure_storage_enabled: false,
                network_isolation_enabled: false,
                supported_os: vec!["linux".to_string()],
            },
            reputation_score: 0.85,
            health_score: 0.9,
            bid_id: Uuid::new_v4().to_string(),
            submitted_at: chrono::Utc::now().timestamp() as u64,
        };

        // Create a dummy distributor to test the calculation method
        let config = JobDistributionConfig::default();
        let blockchain_client = Arc::new(StarknetClient::new("http://localhost:5050".to_string()).expect("Failed to create client"));
        let job_manager = Arc::new(JobManagerContract::new(
            blockchain_client.clone(),
            FieldElement::from_hex_be("0x123").unwrap(),
        ));
        let (p2p_client, _event_receiver) = NetworkActor::new(crate::network::p2p::P2PConfig::default()).unwrap();
        let p2p_network = Arc::new(p2p_client);
        
        let distributor = JobDistributor::new(
            config,
            blockchain_client,
            job_manager,
            p2p_network,
        );

        let score = distributor.calculate_worker_score(&bid);
        assert!(score > 0.0);
        assert!(score <= 1.0);
    }
}
