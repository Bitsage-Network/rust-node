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
use crate::network::encrypted_jobs::{
    EncryptedJobManager, EncryptedJobConfig, EncryptedJobAnnouncement,
    EncryptedWorkerBid, EncryptedJobResult,
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

/// Status of bid collection for a job
#[derive(Debug, Clone)]
pub struct BidCollectionStatus {
    pub job_id: JobId,
    pub state: JobDistributionState,
    pub bid_count: usize,
    pub created_at: u64,
    pub has_active_timer: bool,
}

/// Calculate a composite score for a worker bid.
/// Higher scores are better.
fn calculate_bid_score(bid: &WorkerBid) -> f64 {
    // Composite score based on:
    // - Reputation (35%)
    // - Health score (25%)
    // - Bid competitiveness (25%) - lower bids are better
    // - Estimated completion time (15%) - faster is better
    let reputation_score = bid.reputation_score * 0.35;
    let health_score = bid.health_score * 0.25;
    // Use log scale for bid amount to avoid extreme values
    let bid_score = (1.0 / (bid.bid_amount as f64 + 1.0).ln().max(0.1)) * 0.25;
    // Use log scale for completion time as well
    let time_score = (1.0 / (bid.estimated_completion_time as f64 + 1.0).ln().max(0.1)) * 0.15;

    reputation_score + health_score + bid_score + time_score
}

/// Blockchain polling statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainPollStats {
    pub last_processed_block: u64,
    pub jobs_discovered_from_blockchain: usize,
    pub last_poll_timestamp: u64,
    pub poll_interval_secs: u64,
}

/// Main job distribution coordinator
pub struct JobDistributor {
    config: JobDistributionConfig,
    blockchain_client: Arc<StarknetClient>,
    job_manager: Arc<JobManagerContract>,
    p2p_network: Arc<NetworkClient>,
    health_reputation_system: Arc<HealthReputationSystem>,

    // Privacy-preserving job distribution
    encrypted_job_manager: Arc<RwLock<EncryptedJobManager>>,

    // State management
    jobs: Arc<RwLock<HashMap<JobId, DistributedJob>>>,

    // Communication channels
    event_sender: mpsc::UnboundedSender<JobDistributionEvent>,
    event_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<JobDistributionEvent>>>>,

    // Internal state
    running: Arc<RwLock<bool>>,
    last_blockchain_poll: Arc<RwLock<u64>>,
    /// Last processed blockchain block number for event polling
    last_processed_block: Arc<RwLock<u64>>,
    /// Jobs discovered from blockchain (by event data to avoid duplicates)
    known_blockchain_jobs: Arc<RwLock<std::collections::HashSet<String>>>,
    /// Active bid collection timers (job_id -> cancel_token)
    bid_timers: Arc<RwLock<HashMap<JobId, tokio::sync::watch::Sender<bool>>>>,
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

        // Create encrypted job manager for privacy-preserving distribution
        let encrypted_job_config = EncryptedJobConfig::default();
        let encrypted_job_manager = Arc::new(RwLock::new(EncryptedJobManager::new(encrypted_job_config)));

        Self {
            config,
            blockchain_client,
            job_manager,
            p2p_network,
            health_reputation_system,
            encrypted_job_manager,
            jobs: Arc::new(RwLock::new(HashMap::new())),
            event_sender,
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
            running: Arc::new(RwLock::new(false)),
            last_blockchain_poll: Arc::new(RwLock::new(0)),
            last_processed_block: Arc::new(RwLock::new(0)),
            known_blockchain_jobs: Arc::new(RwLock::new(std::collections::HashSet::new())),
            bid_timers: Arc::new(RwLock::new(HashMap::new())),
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
            encrypted_job_manager: self.encrypted_job_manager.clone(),
            jobs: self.jobs.clone(),
            event_sender: self.event_sender.clone(),
            event_receiver: self.event_receiver.clone(),
            running: self.running.clone(),
            last_blockchain_poll: self.last_blockchain_poll.clone(),
            last_processed_block: self.last_processed_block.clone(),
            known_blockchain_jobs: self.known_blockchain_jobs.clone(),
            bid_timers: self.bid_timers.clone(),
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
    ///
    /// This method queries the blockchain for JobSubmitted events since the last
    /// processed block. For each new job found, it creates a job announcement
    /// and broadcasts it to the P2P network for bidding.
    async fn poll_blockchain_jobs(&self) -> Result<()> {
        use crate::blockchain::types::selectors;

        // Get current block number
        let current_block = self.blockchain_client.get_block_number().await
            .context("Failed to get current block number")?;

        // Get last processed block (start from current - 100 blocks on first run)
        let last_block = {
            let last = *self.last_processed_block.read().await;
            if last == 0 {
                // First run - look back 100 blocks for any pending jobs
                current_block.saturating_sub(100)
            } else {
                last
            }
        };

        // Don't process if no new blocks
        if current_block <= last_block {
            debug!("No new blocks to process (current: {}, last: {})", current_block, last_block);
            return Ok(());
        }

        debug!(
            "Polling blockchain for jobs from block {} to {}",
            last_block + 1,
            current_block
        );

        // Get JobSubmitted events from the contract
        let contract_address = self.job_manager.contract_address();
        let events = self.blockchain_client
            .get_events_by_key(
                contract_address,
                *selectors::EVENT_JOB_SUBMITTED,
                last_block + 1,
                Some(current_block),
            )
            .await
            .context("Failed to get JobSubmitted events")?;

        let new_jobs_count = events.len();
        if new_jobs_count > 0 {
            info!("Found {} new job submissions on blockchain", new_jobs_count);
        }

        // Process each job submission event
        for event in events {
            if let Err(e) = self.process_job_submitted_event(event).await {
                warn!("Failed to process job submission event: {}", e);
                // Continue processing other events
            }
        }

        // Update last processed block
        *self.last_processed_block.write().await = current_block;

        Ok(())
    }

    /// Process a JobSubmitted event from the blockchain
    async fn process_job_submitted_event(
        &self,
        event: starknet::core::types::EmittedEvent,
    ) -> Result<()> {
        // Generate a unique key for this event to avoid duplicates
        let event_key = format!(
            "{}:{}:{}",
            event.block_number,
            event.transaction_hash,
            event.data.len()
        );

        // Check if we've already processed this event
        {
            let known_jobs = self.known_blockchain_jobs.read().await;
            if known_jobs.contains(&event_key) {
                debug!("Skipping already processed job event: {}", event_key);
                return Ok(());
            }
        }

        // Parse event data
        // Event format: JobSubmitted(job_id, client, job_type, max_reward, deadline)
        if event.data.len() < 5 {
            warn!("Invalid JobSubmitted event: expected at least 5 data elements, got {}", event.data.len());
            return Err(anyhow::anyhow!("Invalid event data length"));
        }

        // Extract job ID from event data (first field)
        let job_id_field = event.data[0];
        let job_id_bytes = job_id_field.to_bytes_be();
        // Use the last 16 bytes as the UUID
        let mut uuid_bytes = [0u8; 16];
        uuid_bytes.copy_from_slice(&job_id_bytes[16..32]);
        let job_id = JobId::from(uuid::Uuid::from_bytes(uuid_bytes));

        // Check if we already have this job
        {
            let jobs = self.jobs.read().await;
            if jobs.contains_key(&job_id) {
                debug!("Job {} already exists, skipping", job_id);
                return Ok(());
            }
        }

        info!("Discovered new job from blockchain: {}", job_id);

        // Get full job details from the contract
        let job_details = self.job_manager.get_job(job_id)
            .await
            .context("Failed to get job details from contract")?;

        let details = match job_details {
            Some(d) => d,
            None => {
                warn!("Job {} not found in contract storage", job_id);
                return Err(anyhow::anyhow!("Job not found"));
            }
        };

        // Construct JobSpec from JobDetails
        // Note: Some fields are not available in JobDetails and use defaults
        let job_spec = crate::blockchain::types::JobSpec {
            job_type: details.job_type,
            model_id: crate::blockchain::types::ModelId::new(starknet::core::types::FieldElement::ZERO),
            input_data_hash: starknet::core::types::FieldElement::ZERO,
            expected_output_format: starknet::core::types::FieldElement::ZERO,
            verification_method: crate::blockchain::types::VerificationMethod::None,
            max_reward: details.payment_amount,
            sla_deadline: details.created_at + 3600, // Default 1 hour deadline
            compute_requirements: Vec::new(),
            metadata: Vec::new(),
        };

        // Create job announcement
        let announcement = JobAnnouncement {
            job_id,
            job_spec: job_spec.clone(),
            max_reward: job_spec.max_reward,
            deadline: job_spec.sla_deadline,
            required_capabilities: WorkerCapabilities {
                gpu_memory: 0,
                cpu_cores: 0,
                ram: 0,
                storage: 0,
                bandwidth: 0,
                capability_flags: 0,
                gpu_model: starknet::core::types::FieldElement::ZERO,
                cpu_model: starknet::core::types::FieldElement::ZERO,
            },
            announcement_id: uuid::Uuid::new_v4().to_string(),
            announced_at: chrono::Utc::now().timestamp() as u64,
        };

        // Mark as known
        self.known_blockchain_jobs.write().await.insert(event_key);

        // Broadcast the job announcement via P2P
        let p2p_message = P2PMessage::JobAnnouncement {
            job_id,
            spec: job_spec,
            max_reward: announcement.max_reward,
            deadline: announcement.deadline,
        };

        if let Err(e) = self.p2p_network.broadcast_message(p2p_message, "bitsage-jobs").await {
            warn!("Failed to broadcast job announcement for {}: {}", job_id, e);
        }

        // Send internal event
        self.event_sender.send(JobDistributionEvent::JobAnnounced(announcement))
            .context("Failed to send job announced event")?;

        info!("Job {} announced from blockchain", job_id);
        Ok(())
    }

    /// Get blockchain polling statistics
    pub async fn get_blockchain_poll_stats(&self) -> BlockchainPollStats {
        let last_block = *self.last_processed_block.read().await;
        let known_jobs = self.known_blockchain_jobs.read().await.len();
        let last_poll = *self.last_blockchain_poll.read().await;

        BlockchainPollStats {
            last_processed_block: last_block,
            jobs_discovered_from_blockchain: known_jobs,
            last_poll_timestamp: last_poll,
            poll_interval_secs: self.config.blockchain_poll_interval_secs,
        }
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
    ///
    /// Spawns a background task that waits for the bid timeout period,
    /// then processes collected bids and assigns the job to the best worker.
    /// The timer can be cancelled early via `cancel_bid_timer`.
    async fn start_bid_collection_timer(&self, job_id: JobId) -> Result<()> {
        let timeout_secs = self.config.bid_timeout_secs;
        info!("Bid collection timer started for job {} ({}s timeout)", job_id, timeout_secs);

        // Create a cancellation channel for this timer
        let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);

        // Store the cancel sender so it can be used to cancel early if needed
        {
            let mut timers = self.bid_timers.write().await;
            timers.insert(job_id.clone(), cancel_tx);
        }

        // Clone what we need for the spawned task
        let jobs = self.jobs.clone();
        let bid_timers = self.bid_timers.clone();
        let p2p_network = self.p2p_network.clone();
        let event_sender = self.event_sender.clone();
        let min_reputation = self.config.min_worker_reputation;
        let job_id_clone = job_id.clone();

        tokio::spawn(async move {
            let job_id = job_id_clone;

            // Wait for timeout or cancellation
            let timed_out = tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(timeout_secs)) => {
                    true
                }
                _ = cancel_rx.changed() => {
                    // Timer was cancelled early
                    info!("Bid collection timer cancelled for job {}", job_id);
                    false
                }
            };

            // Remove from active timers
            {
                let mut timers = bid_timers.write().await;
                timers.remove(&job_id);
            }

            if !timed_out {
                // Was cancelled, don't process
                return;
            }

            info!("Bid collection timeout reached for job {}, processing bids", job_id);

            // Get bids for this job
            let (bids, current_state) = {
                let jobs_guard = jobs.read().await;
                match jobs_guard.get(&job_id) {
                    Some(job) => (job.bids.clone(), job.state.clone()),
                    None => {
                        warn!("Job {} not found when processing bids", job_id);
                        return;
                    }
                }
            };

            // Only process if still in CollectingBids state
            if current_state != JobDistributionState::CollectingBids {
                warn!("Job {} no longer collecting bids (state: {:?}), skipping assignment",
                    job_id, current_state);
                return;
            }

            if bids.is_empty() {
                warn!("No bids received for job {}", job_id);
                // Update state to timeout
                {
                    let mut jobs_guard = jobs.write().await;
                    if let Some(job) = jobs_guard.get_mut(&job_id) {
                        job.state = JobDistributionState::Timeout;
                        job.updated_at = chrono::Utc::now().timestamp() as u64;
                    }
                }
                return;
            }

            // Filter and sort bids
            let mut qualified_bids: Vec<_> = bids.iter()
                .filter(|bid| {
                    bid.reputation_score >= min_reputation && bid.health_score >= 0.7
                })
                .cloned()
                .collect();

            if qualified_bids.is_empty() {
                warn!("No qualified bids for job {} (min reputation: {})", job_id, min_reputation);
                {
                    let mut jobs_guard = jobs.write().await;
                    if let Some(job) = jobs_guard.get_mut(&job_id) {
                        job.state = JobDistributionState::Failed;
                        job.updated_at = chrono::Utc::now().timestamp() as u64;
                    }
                }
                return;
            }

            // Sort by score (highest first)
            qualified_bids.sort_by(|a, b| {
                let score_a = calculate_bid_score(a);
                let score_b = calculate_bid_score(b);
                score_b.partial_cmp(&score_a).unwrap_or(std::cmp::Ordering::Equal)
            });

            let best_bid = qualified_bids[0].clone();
            info!("Selected worker {} for job {} (bid: {}, score: {:.3})",
                best_bid.worker_id, job_id, best_bid.bid_amount, calculate_bid_score(&best_bid));

            // Create assignment
            let assignment = JobAssignment {
                job_id: job_id.clone(),
                worker_id: best_bid.worker_id.clone(),
                assignment_id: Uuid::new_v4().to_string(),
                assigned_at: chrono::Utc::now().timestamp() as u64,
                deadline: chrono::Utc::now().timestamp() as u64 + best_bid.estimated_completion_time,
                reward_amount: best_bid.bid_amount,
            };

            // Update job with assignment
            {
                let mut jobs_guard = jobs.write().await;
                if let Some(job) = jobs_guard.get_mut(&job_id) {
                    job.assignment = Some(assignment.clone());
                    job.state = JobDistributionState::InProgress;
                    job.updated_at = chrono::Utc::now().timestamp() as u64;
                }
            }

            // Broadcast assignment via P2P
            let p2p_message = crate::network::p2p::P2PMessage::JobAssignment {
                job_id: job_id.clone(),
                worker_id: best_bid.worker_id.clone(),
                assignment_id: assignment.assignment_id.clone(),
                reward_amount: assignment.reward_amount,
            };

            if let Err(e) = p2p_network.broadcast_message(p2p_message, "bitsage-jobs").await {
                error!("Failed to broadcast job assignment: {}", e);
            }

            // Send assignment event
            if let Err(e) = event_sender.send(JobDistributionEvent::JobAssigned(assignment)) {
                error!("Failed to send job assigned event: {}", e);
            }

            info!("Job {} successfully assigned to worker {}", job_id, best_bid.worker_id);
        });

        Ok(())
    }

    /// Cancel the bid collection timer for a job
    ///
    /// This is useful when a job needs to be cancelled or when enough
    /// high-quality bids have been received to make an early decision.
    pub async fn cancel_bid_timer(&self, job_id: &JobId) -> bool {
        let mut timers = self.bid_timers.write().await;
        if let Some(cancel_tx) = timers.remove(job_id) {
            if cancel_tx.send(true).is_ok() {
                info!("Bid collection timer cancelled for job {}", job_id);
                return true;
            }
        }
        false
    }

    /// Get the number of active bid timers
    pub async fn get_active_bid_timers_count(&self) -> usize {
        self.bid_timers.read().await.len()
    }

    /// Get bid collection status for a job
    pub async fn get_bid_collection_status(&self, job_id: &JobId) -> Option<BidCollectionStatus> {
        let jobs = self.jobs.read().await;
        let job = jobs.get(job_id)?;

        let has_active_timer = self.bid_timers.read().await.contains_key(job_id);

        Some(BidCollectionStatus {
            job_id: job_id.clone(),
            state: job.state.clone(),
            bid_count: job.bids.len(),
            created_at: job.created_at,
            has_active_timer,
        })
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

    // =========================================================================
    // ENCRYPTED JOB DISTRIBUTION (Privacy-Preserving)
    // =========================================================================

    /// Announce a job with encryption (privacy-preserving mode)
    /// Only workers with matching capabilities can decrypt and bid
    pub async fn announce_encrypted_job(
        &self,
        job_spec: JobSpec,
        max_reward: u128,
        deadline_secs: u64,
        target_worker_pubkeys: Vec<crate::network::encrypted_jobs::X25519PublicKey>,
        required_capabilities: WorkerCapabilities,
    ) -> Result<Vec<String>> {
        info!("Creating encrypted job announcement");

        // Convert job spec to DecryptedJobSpec
        let decrypted_spec = crate::network::encrypted_jobs::DecryptedJobSpec {
            job_id: JobId::new(),
            job_type: format!("{:?}", job_spec.job_type),
            computation_id: format!("{:#x}", job_spec.model_id.0),
            input_data: crate::network::encrypted_jobs::JobInputData::Reference {
                uri: format!("hash://{:#x}", job_spec.input_data_hash),
                decryption_key: Vec::new(),
                size_bytes: 0,
            },
            max_reward,
            deadline_secs,
            require_tee: false,
            metadata: HashMap::new(),
        };

        // Generate capability filter hash
        let capability_filter = self.hash_capabilities(&required_capabilities);
        let expiry_block = chrono::Utc::now().timestamp() as u64 + deadline_secs;

        // Create encrypted announcements for each target worker
        let encrypted_announcements = {
            let manager = self.encrypted_job_manager.read().await;
            manager.create_encrypted_announcement(
                &decrypted_spec,
                &target_worker_pubkeys,
                capability_filter,
                expiry_block,
            )?
        };

        let mut announcement_ids = Vec::new();

        // Broadcast each announcement via P2P network
        for announcement in encrypted_announcements {
            announcement_ids.push(announcement.announcement_id.clone());
            let message = P2PMessage::EncryptedAnnouncement(announcement);
            self.p2p_network.broadcast_message(message, "encrypted_jobs").await?;
        }

        info!("Encrypted job announced to {} workers", announcement_ids.len());
        Ok(announcement_ids)
    }

    /// Process received encrypted job announcement
    /// Attempts decryption - if successful, the job is for us
    pub async fn process_encrypted_announcement(
        &self,
        announcement: EncryptedJobAnnouncement,
    ) -> Result<Option<crate::network::encrypted_jobs::DecryptedJobSpec>> {
        let manager = self.encrypted_job_manager.read().await;

        // Try to decrypt - returns None if not for us
        match manager.try_decrypt_announcement(&announcement) {
            Ok(spec) => {
                info!("Successfully decrypted job: {}", spec.job_id);
                Ok(Some(spec))
            }
            Err(_) => {
                // Not for us - this is normal, not an error
                debug!("Announcement {} not for us", announcement.announcement_id);
                Ok(None)
            }
        }
    }

    /// Submit encrypted bid for a job
    pub async fn submit_encrypted_bid(
        &self,
        announcement: &EncryptedJobAnnouncement,
        bid_amount: u128,
        estimated_time_secs: u64,
        _worker_id: WorkerId,
    ) -> Result<()> {
        info!("Submitting encrypted bid for job {}", announcement.announcement_id);

        // Create bid details
        let manager = self.encrypted_job_manager.read().await;
        let bid_details = crate::network::encrypted_jobs::DecryptedBidDetails {
            worker_pubkey: manager.public_key().clone(),
            bid_amount,
            estimated_time_secs,
            tee_attestation: None,
        };

        let encrypted_bid = manager.create_encrypted_bid(
            announcement,
            &bid_details,
            Vec::new(), // capability_proof
        )?;

        // Broadcast encrypted bid
        let message = P2PMessage::EncryptedBid(encrypted_bid);
        self.p2p_network.broadcast_message(message, "encrypted_jobs").await?;

        info!("Encrypted bid submitted for {}", announcement.announcement_id);
        Ok(())
    }

    /// Submit encrypted job result
    pub async fn submit_encrypted_result(
        &self,
        job_id: JobId,
        result_data: Vec<u8>,
        success: bool,
        execution_time_ms: u64,
        client_pubkey: &crate::network::encrypted_jobs::X25519PublicKey,
    ) -> Result<()> {
        info!("Submitting encrypted result for job {}", job_id);

        let result = crate::network::encrypted_jobs::DecryptedJobResult {
            success,
            result_data,
            execution_time_ms,
            tee_attestation: None,
            stwo_proof: None,
        };

        let encrypted_result = {
            let manager = self.encrypted_job_manager.read().await;
            manager.create_encrypted_result(job_id.clone(), &result, client_pubkey)?
        };

        // Broadcast encrypted result
        let message = P2PMessage::EncryptedResult(encrypted_result);
        self.p2p_network.broadcast_message(message, "encrypted_jobs").await?;

        info!("Encrypted result submitted for job {}", job_id);
        Ok(())
    }

    /// Decrypt a received job result (as the client who created the job)
    pub async fn decrypt_job_result(
        &self,
        encrypted_result: &EncryptedJobResult,
    ) -> Result<crate::network::encrypted_jobs::DecryptedJobResult> {
        let manager = self.encrypted_job_manager.read().await;
        manager.decrypt_result(encrypted_result)
    }

    /// Register worker's public key for encrypted communications
    pub async fn register_encryption_key(
        &self,
        worker_id: WorkerId,
        public_key: crate::network::encrypted_jobs::X25519PublicKey,
    ) -> Result<()> {
        let manager = self.encrypted_job_manager.read().await;
        manager.register_worker_key(worker_id.clone(), public_key).await;
        info!("Registered encryption key for worker {}", worker_id);
        Ok(())
    }

    /// Get the encrypted job manager (for advanced operations)
    pub fn encrypted_job_manager(&self) -> Arc<RwLock<EncryptedJobManager>> {
        self.encrypted_job_manager.clone()
    }

    /// Hash worker capabilities for capability filtering
    fn hash_capabilities(&self, capabilities: &WorkerCapabilities) -> [u8; 32] {
        use sha3::{Sha3_256, Digest};
        let mut hasher = Sha3_256::new();
        hasher.update(&capabilities.gpu_memory.to_le_bytes());
        hasher.update(&capabilities.cpu_cores.to_le_bytes());
        hasher.update(&capabilities.ram.to_le_bytes());
        hasher.update(&capabilities.capability_flags.to_le_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
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
            worker_capabilities: WorkerCapabilities {
                gpu_memory: 24 * 1024 * 1024 * 1024, // 24 GB
                cpu_cores: 8,
                ram: 32 * 1024 * 1024 * 1024, // 32 GB
                storage: 1000 * 1024 * 1024 * 1024, // 1 TB
                bandwidth: 1000, // Mbps
                capability_flags: 0,
                gpu_model: FieldElement::ZERO,
                cpu_model: FieldElement::ZERO,
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
