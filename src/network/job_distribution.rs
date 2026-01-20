//! # P2P Job Distribution System
//!
//! This module implements the GPU marketplace allocation system that connects
//! users to available validator GPUs. Unlike auction-based systems, this uses
//! direct allocation - users select a GPU type and are instantly connected to
//! an available worker with that GPU.
//!
//! ## Architecture
//!
//! 1. Validators register their GPUs (H100, A100, RTX 4090, etc.)
//! 2. GPUs are added to a pool organized by type
//! 3. Users browse available GPU types in the marketplace
//! 4. User selects GPU type → instant allocation to available worker
//! 5. Direct connection established for compute tasks

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
    EncryptedJobResult,
};
use crate::types::{JobId, WorkerId};

/// GPU types available in the marketplace
///
/// Organized by NVIDIA architecture generations:
/// - Blackwell (B-series): B200, B100 - Latest generation, 192GB HBM3e
/// - Hopper (H-series): H200, H100 - High-performance LLM training/inference
/// - Lovelace (L-series): L40S, L40, L4 - Energy-efficient inference
/// - Ampere (A-series): A100, A40, A10 - Established data center workhorses
/// - Turing (T-series): T4 - Entry-level inference
/// - Consumer GPUs: RTX 4090/4080/3090 - Sometimes used for smaller workloads
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GpuType {
    // === Blackwell Architecture (2024+) ===
    /// NVIDIA B200 - 192GB HBM3e, Frontier-scale AI, multi-trillion parameter models
    B200,
    /// NVIDIA B100 - 192GB HBM3e, Next-gen AI training, inference, HPC
    B100,

    // === Hopper Architecture (2022-2024) ===
    /// NVIDIA H200 - 141GB HBM3e, Ultra-large models, long-context inference
    H200,
    /// NVIDIA H100 - 80GB HBM3, Advanced LLM training & inference, FP8
    H100,

    // === Lovelace Architecture (2022-2023) ===
    /// NVIDIA L40S - 48GB GDDR6, Improved L40 for inference
    L40S,
    /// NVIDIA L40 - 48GB GDDR6, Mid-range data center inference
    L40,
    /// NVIDIA L4 - 24GB GDDR6, Energy-efficient inference
    L4,

    // === Ampere Architecture (2020-2022) ===
    /// NVIDIA A100 - 40GB/80GB HBM2e, High-performance LLM training & inference
    A100,
    /// NVIDIA A40 - 48GB GDDR6, Data center visualization and inference
    A40,
    /// NVIDIA A10 - 24GB GDDR6, Mid-range inference, AI training
    A10,

    // === Turing Architecture (2018-2020) ===
    /// NVIDIA T4 - 16GB GDDR6, Entry-level inference
    T4,

    // === Consumer GPUs (not recommended for production) ===
    /// NVIDIA RTX 4090 - 24GB GDDR6X (Consumer/Gaming)
    Rtx4090,
    /// NVIDIA RTX 4080 - 16GB GDDR6X (Consumer/Gaming)
    Rtx4080,
    /// NVIDIA RTX 3090 - 24GB GDDR6X (Consumer/Gaming)
    Rtx3090,

    /// Other/Unknown GPU with custom identifier
    Other(u32),
}

impl GpuType {
    /// Get the typical VRAM in GB for this GPU type
    pub fn vram_gb(&self) -> u32 {
        match self {
            // Blackwell
            GpuType::B200 => 192,
            GpuType::B100 => 192,
            // Hopper
            GpuType::H200 => 141,
            GpuType::H100 => 80,
            // Lovelace
            GpuType::L40S => 48,
            GpuType::L40 => 48,
            GpuType::L4 => 24,
            // Ampere
            GpuType::A100 => 80, // Can be 40GB or 80GB, assume 80GB
            GpuType::A40 => 48,
            GpuType::A10 => 24,
            // Turing
            GpuType::T4 => 16,
            // Consumer
            GpuType::Rtx4090 => 24,
            GpuType::Rtx4080 => 16,
            GpuType::Rtx3090 => 24,
            GpuType::Other(_) => 0,
        }
    }

    /// Get display name for the GPU
    pub fn display_name(&self) -> &str {
        match self {
            // Blackwell
            GpuType::B200 => "NVIDIA B200",
            GpuType::B100 => "NVIDIA B100",
            // Hopper
            GpuType::H200 => "NVIDIA H200",
            GpuType::H100 => "NVIDIA H100",
            // Lovelace
            GpuType::L40S => "NVIDIA L40S",
            GpuType::L40 => "NVIDIA L40",
            GpuType::L4 => "NVIDIA L4",
            // Ampere
            GpuType::A100 => "NVIDIA A100",
            GpuType::A40 => "NVIDIA A40",
            GpuType::A10 => "NVIDIA A10",
            // Turing
            GpuType::T4 => "NVIDIA T4",
            // Consumer
            GpuType::Rtx4090 => "NVIDIA RTX 4090",
            GpuType::Rtx4080 => "NVIDIA RTX 4080",
            GpuType::Rtx3090 => "NVIDIA RTX 3090",
            GpuType::Other(_) => "Other GPU",
        }
    }

    /// Get the GPU architecture generation
    pub fn architecture(&self) -> &str {
        match self {
            GpuType::B200 | GpuType::B100 => "Blackwell",
            GpuType::H200 | GpuType::H100 => "Hopper",
            GpuType::L40S | GpuType::L40 | GpuType::L4 => "Lovelace",
            GpuType::A100 | GpuType::A40 | GpuType::A10 => "Ampere",
            GpuType::T4 => "Turing",
            GpuType::Rtx4090 | GpuType::Rtx4080 => "Ada Lovelace",
            GpuType::Rtx3090 => "Ampere",
            GpuType::Other(_) => "Unknown",
        }
    }

    /// Check if this is a data center GPU (recommended for production)
    pub fn is_datacenter(&self) -> bool {
        !matches!(self, GpuType::Rtx4090 | GpuType::Rtx4080 | GpuType::Rtx3090 | GpuType::Other(_))
    }
}

/// Registered GPU in the pool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredGpu {
    pub gpu_id: String,
    pub worker_id: WorkerId,
    pub gpu_type: GpuType,
    pub gpu_count: u32,
    pub vram_gb: u32,
    pub status: GpuStatus,
    pub hourly_rate: u128,
    pub reputation_score: f64,
    pub health_score: f64,
    pub registered_at: u64,
    pub last_heartbeat: u64,
}

/// GPU availability status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GpuStatus {
    /// GPU is available for allocation
    Available,
    /// GPU is currently in use
    InUse,
    /// GPU is idle but reserved
    Reserved,
    /// GPU is offline or unreachable
    Offline,
    /// GPU is undergoing maintenance
    Maintenance,
}

/// Job distribution configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobDistributionConfig {
    /// Minimum reputation score for workers to be eligible
    pub min_worker_reputation: f64,
    /// Minimum health score for workers to be eligible
    pub min_worker_health: f64,
    /// Blockchain polling interval in seconds
    pub blockchain_poll_interval_secs: u64,
    /// Worker heartbeat timeout in seconds
    pub worker_heartbeat_timeout_secs: u64,
    /// Maximum jobs per worker concurrently
    pub max_jobs_per_worker: u32,
    /// Health reputation system configuration
    pub health_reputation_config: HealthReputationConfig,
}

impl Default for JobDistributionConfig {
    fn default() -> Self {
        Self {
            min_worker_reputation: 0.5,
            min_worker_health: 0.7,
            blockchain_poll_interval_secs: 10,
            worker_heartbeat_timeout_secs: 60,
            max_jobs_per_worker: 4,
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
    /// Worker registered their GPU in the pool
    GpuRegistered(RegisteredGpu),
    /// GPU status changed (available, in use, offline)
    GpuStatusChanged(String, GpuStatus),
    /// Job was announced to the network
    JobAnnounced(JobAnnouncement),
    /// GPU was allocated to a job (instant, no bidding)
    GpuAllocated { gpu_id: String, job_id: JobId },
    /// Job was assigned to a worker
    JobAssigned(JobAssignment),
    /// Result was submitted by worker
    ResultSubmitted(JobResult),
    /// Job completed successfully
    JobCompleted(JobId),
    /// Job failed with error
    JobFailed(JobId, String),
    /// Worker timed out on a job
    WorkerTimeout(WorkerId, JobId),
    /// Worker health metrics updated
    WorkerHealthUpdated(WorkerId, HealthMetrics),
    /// Malicious behavior detected
    MaliciousBehaviorDetected(WorkerId, String),
    /// Worker went offline
    WorkerOffline(WorkerId),
}

/// Job state tracking
#[derive(Debug, Clone)]
pub struct DistributedJob {
    pub job_id: JobId,
    pub announcement: JobAnnouncement,
    pub allocated_gpu: Option<String>,
    pub assignment: Option<JobAssignment>,
    pub result: Option<JobResult>,
    pub state: JobDistributionState,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum JobDistributionState {
    /// Job announced, waiting for GPU allocation
    Pending,
    /// GPU allocated, assignment in progress
    Allocated,
    /// Job assigned to worker
    Assigned,
    /// Worker is executing the job
    InProgress,
    /// Job completed successfully
    Completed,
    /// Job failed
    Failed,
    /// Job timed out
    Timeout,
    /// Job cancelled
    Cancelled,
}

/// GPU pool statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuPoolStats {
    pub total_gpus: usize,
    pub available_gpus: usize,
    pub in_use_gpus: usize,
    pub offline_gpus: usize,
    pub gpus_by_type: HashMap<String, usize>,
    pub available_by_type: HashMap<String, usize>,
}

/// GPU allocation request - direct selection, what you pay is what you get
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuAllocationRequest {
    /// Job ID this allocation is for
    pub job_id: JobId,
    /// Exact GPU type requested (required)
    pub gpu_type: GpuType,
    /// Specific worker ID if user wants a particular provider
    pub worker_id: Option<WorkerId>,
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
///
/// Manages the GPU marketplace pool and handles direct allocation
/// of GPUs to users without bidding or auctions.
pub struct JobDistributor {
    config: JobDistributionConfig,
    blockchain_client: Arc<StarknetClient>,
    job_manager: Arc<JobManagerContract>,
    p2p_network: Arc<NetworkClient>,
    health_reputation_system: Arc<HealthReputationSystem>,

    // Privacy-preserving job distribution
    encrypted_job_manager: Arc<RwLock<EncryptedJobManager>>,

    // GPU Pool - the core marketplace data structure
    gpu_pool: Arc<RwLock<HashMap<String, RegisteredGpu>>>,

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
            gpu_pool: Arc::new(RwLock::new(HashMap::new())),
            jobs: Arc::new(RwLock::new(HashMap::new())),
            event_sender,
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
            running: Arc::new(RwLock::new(false)),
            last_blockchain_poll: Arc::new(RwLock::new(0)),
            last_processed_block: Arc::new(RwLock::new(0)),
            known_blockchain_jobs: Arc::new(RwLock::new(std::collections::HashSet::new())),
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
            gpu_pool: self.gpu_pool.clone(),
            jobs: self.jobs.clone(),
            event_sender: self.event_sender.clone(),
            event_receiver: self.event_receiver.clone(),
            running: self.running.clone(),
            last_blockchain_poll: self.last_blockchain_poll.clone(),
            last_processed_block: self.last_processed_block.clone(),
            known_blockchain_jobs: self.known_blockchain_jobs.clone(),
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
            JobDistributionEvent::GpuRegistered(gpu) => {
                self.handle_gpu_registered(gpu).await?;
            }
            JobDistributionEvent::GpuStatusChanged(gpu_id, status) => {
                self.handle_gpu_status_changed(gpu_id, status).await?;
            }
            JobDistributionEvent::JobAnnounced(announcement) => {
                self.handle_job_announced(announcement).await?;
            }
            JobDistributionEvent::GpuAllocated { gpu_id, job_id } => {
                info!("GPU {} allocated to job {}", gpu_id, job_id);
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
            JobDistributionEvent::WorkerOffline(worker_id) => {
                self.handle_worker_offline(worker_id).await?;
            }
        }

        Ok(())
    }

    /// Handle GPU registration from a worker
    async fn handle_gpu_registered(&self, gpu: RegisteredGpu) -> Result<()> {
        info!("GPU registered: {} ({}) from worker {}",
            gpu.gpu_id, gpu.gpu_type.display_name(), gpu.worker_id);

        let mut pool = self.gpu_pool.write().await;
        pool.insert(gpu.gpu_id.clone(), gpu);

        Ok(())
    }

    /// Handle GPU status change
    async fn handle_gpu_status_changed(&self, gpu_id: String, status: GpuStatus) -> Result<()> {
        let mut pool = self.gpu_pool.write().await;
        if let Some(gpu) = pool.get_mut(&gpu_id) {
            gpu.status = status;
            info!("GPU {} status changed to {:?}", gpu_id, status);
        }
        Ok(())
    }

    /// Handle worker going offline
    async fn handle_worker_offline(&self, worker_id: WorkerId) -> Result<()> {
        warn!("Worker {} went offline, marking GPUs as offline", worker_id);

        let mut pool = self.gpu_pool.write().await;
        for gpu in pool.values_mut() {
            if gpu.worker_id == worker_id {
                gpu.status = GpuStatus::Offline;
            }
        }

        Ok(())
    }

    /// Handle job announcement - immediately allocate an available GPU
    ///
    /// Unlike bidding systems, this uses direct allocation:
    /// 1. Find an available GPU matching job requirements
    /// 2. Allocate it immediately
    /// 3. Create assignment and notify via P2P
    async fn handle_job_announced(&self, announcement: JobAnnouncement) -> Result<()> {
        info!("Job announced: {}, attempting direct GPU allocation", announcement.job_id);

        // Create the job record
        let job = DistributedJob {
            job_id: announcement.job_id.clone(),
            announcement: announcement.clone(),
            allocated_gpu: None,
            assignment: None,
            result: None,
            state: JobDistributionState::Pending,
            created_at: chrono::Utc::now().timestamp() as u64,
            updated_at: chrono::Utc::now().timestamp() as u64,
        };

        {
            let mut jobs = self.jobs.write().await;
            jobs.insert(announcement.job_id.clone(), job);
        }

        // Extract GPU type from job requirements - direct selection required
        // GPU model encodings organized by architecture:
        // Blackwell: 1-2, Hopper: 3-4, Lovelace: 5-7, Ampere: 8-10, Turing: 11, Consumer: 12-14
        let gpu_type = if announcement.required_capabilities.gpu_model != starknet::core::types::FieldElement::ZERO {
            let model_val: u64 = announcement.required_capabilities.gpu_model.try_into().unwrap_or(0);
            match model_val {
                // Blackwell (newest, highest performance)
                1 => Some(GpuType::B200),
                2 => Some(GpuType::B100),
                // Hopper
                3 => Some(GpuType::H200),
                4 => Some(GpuType::H100),
                // Lovelace
                5 => Some(GpuType::L40S),
                6 => Some(GpuType::L40),
                7 => Some(GpuType::L4),
                // Ampere
                8 => Some(GpuType::A100),
                9 => Some(GpuType::A40),
                10 => Some(GpuType::A10),
                // Turing
                11 => Some(GpuType::T4),
                // Consumer (not recommended for production)
                12 => Some(GpuType::Rtx4090),
                13 => Some(GpuType::Rtx4080),
                14 => Some(GpuType::Rtx3090),
                // Unknown model
                other => Some(GpuType::Other(other as u32)),
            }
        } else {
            // No GPU type specified - cannot allocate
            warn!("Job {} has no GPU type specified, cannot allocate", announcement.job_id);
            return Ok(());
        };

        let gpu_type = gpu_type.unwrap();

        // Try to allocate a GPU - direct selection, what you pay is what you get
        let allocation_request = GpuAllocationRequest {
            job_id: announcement.job_id.clone(),
            gpu_type,
            worker_id: None, // No specific worker preference from blockchain announcement
        };

        match self.allocate_gpu(allocation_request).await {
            Ok(Some((gpu_id, worker_id))) => {
                info!("GPU {} allocated to job {} (worker: {})",
                    gpu_id, announcement.job_id, worker_id);

                // Create assignment
                let assignment = JobAssignment {
                    job_id: announcement.job_id.clone(),
                    worker_id: worker_id.clone(),
                    assignment_id: Uuid::new_v4().to_string(),
                    assigned_at: chrono::Utc::now().timestamp() as u64,
                    deadline: announcement.deadline,
                    reward_amount: announcement.max_reward,
                };

                // Update job state
                {
                    let mut jobs = self.jobs.write().await;
                    if let Some(job) = jobs.get_mut(&announcement.job_id) {
                        job.allocated_gpu = Some(gpu_id.clone());
                        job.assignment = Some(assignment.clone());
                        job.state = JobDistributionState::Assigned;
                        job.updated_at = chrono::Utc::now().timestamp() as u64;
                    }
                }

                // Broadcast assignment via P2P
                let p2p_message = P2PMessage::JobAssignment {
                    job_id: announcement.job_id.clone(),
                    worker_id: worker_id.clone(),
                    assignment_id: assignment.assignment_id.clone(),
                    reward_amount: assignment.reward_amount,
                };

                if let Err(e) = self.p2p_network.broadcast_message(p2p_message, "bitsage-jobs").await {
                    error!("Failed to broadcast job assignment: {}", e);
                }

                // Emit event
                let _ = self.event_sender.send(JobDistributionEvent::JobAssigned(assignment));
            }
            Ok(None) => {
                warn!("No available GPU for job {}, job remains pending", announcement.job_id);
                // Job stays in Pending state, will be picked up when a GPU becomes available
            }
            Err(e) => {
                error!("Failed to allocate GPU for job {}: {}", announcement.job_id, e);
            }
        }

        Ok(())
    }

    /// Allocate an available GPU for a job - direct selection only
    ///
    /// User selects exact GPU type, optionally a specific worker.
    /// No routing, no scoring - what you pay is what you get.
    ///
    /// Returns (gpu_id, worker_id) if allocation successful, None if no GPU available
    pub async fn allocate_gpu(&self, request: GpuAllocationRequest) -> Result<Option<(String, WorkerId)>> {
        let mut pool = self.gpu_pool.write().await;

        // Find matching GPU - exact type match required
        let matching_gpu = pool.values()
            .find(|gpu| {
                // Must be available
                if gpu.status != GpuStatus::Available {
                    return false;
                }

                // Must match exact GPU type
                if gpu.gpu_type != request.gpu_type {
                    return false;
                }

                // If specific worker requested, must match
                if let Some(ref worker_id) = request.worker_id {
                    if &gpu.worker_id != worker_id {
                        return false;
                    }
                }

                true
            });

        let Some(gpu) = matching_gpu else {
            return Ok(None);
        };

        let gpu_id = gpu.gpu_id.clone();
        let worker_id = gpu.worker_id.clone();

        // Mark as in use
        if let Some(gpu) = pool.get_mut(&gpu_id) {
            gpu.status = GpuStatus::InUse;
        }

        info!("GPU {} ({}) allocated to job {} via worker {}",
            gpu_id, request.gpu_type.display_name(), request.job_id, worker_id);

        // Emit allocation event
        let _ = self.event_sender.send(JobDistributionEvent::GpuAllocated {
            gpu_id: gpu_id.clone(),
            job_id: request.job_id,
        });

        Ok(Some((gpu_id, worker_id)))
    }

    /// Release a GPU back to the available pool
    pub async fn release_gpu(&self, gpu_id: &str) -> Result<()> {
        let mut pool = self.gpu_pool.write().await;
        if let Some(gpu) = pool.get_mut(gpu_id) {
            gpu.status = GpuStatus::Available;
            info!("GPU {} released back to pool", gpu_id);

            // Emit status change event
            let _ = self.event_sender.send(JobDistributionEvent::GpuStatusChanged(
                gpu_id.to_string(),
                GpuStatus::Available,
            ));
        }
        Ok(())
    }

    /// Get GPU pool statistics
    pub async fn get_gpu_pool_stats(&self) -> GpuPoolStats {
        let pool = self.gpu_pool.read().await;

        let mut gpus_by_type: HashMap<String, usize> = HashMap::new();
        let mut available_by_type: HashMap<String, usize> = HashMap::new();
        let mut available_count = 0;
        let mut in_use_count = 0;
        let mut offline_count = 0;

        for gpu in pool.values() {
            let type_name = gpu.gpu_type.display_name().to_string();
            *gpus_by_type.entry(type_name.clone()).or_insert(0) += 1;

            match gpu.status {
                GpuStatus::Available => {
                    available_count += 1;
                    *available_by_type.entry(type_name).or_insert(0) += 1;
                }
                GpuStatus::InUse | GpuStatus::Reserved => {
                    in_use_count += 1;
                }
                GpuStatus::Offline | GpuStatus::Maintenance => {
                    offline_count += 1;
                }
            }
        }

        GpuPoolStats {
            total_gpus: pool.len(),
            available_gpus: available_count,
            in_use_gpus: in_use_count,
            offline_gpus: offline_count,
            gpus_by_type,
            available_by_type,
        }
    }

    /// Get available GPUs by type
    pub async fn get_available_gpus_by_type(&self, gpu_type: GpuType) -> Vec<RegisteredGpu> {
        let pool = self.gpu_pool.read().await;
        pool.values()
            .filter(|gpu| {
                gpu.gpu_type == gpu_type
                    && gpu.status == GpuStatus::Available
                    && gpu.reputation_score >= self.config.min_worker_reputation
                    && gpu.health_score >= self.config.min_worker_health
            })
            .cloned()
            .collect()
    }

    /// Register a new GPU in the pool
    pub async fn register_gpu(&self, gpu: RegisteredGpu) -> Result<()> {
        info!("Registering GPU {} ({}) from worker {}",
            gpu.gpu_id, gpu.gpu_type.display_name(), gpu.worker_id);

        let mut pool = self.gpu_pool.write().await;
        pool.insert(gpu.gpu_id.clone(), gpu.clone());

        // Emit registration event
        let _ = self.event_sender.send(JobDistributionEvent::GpuRegistered(gpu));

        Ok(())
    }

    /// Unregister a GPU from the pool
    pub async fn unregister_gpu(&self, gpu_id: &str) -> Result<Option<RegisteredGpu>> {
        let mut pool = self.gpu_pool.write().await;
        let removed = pool.remove(gpu_id);

        if let Some(ref gpu) = removed {
            info!("Unregistered GPU {} from worker {}", gpu_id, gpu.worker_id);
        }

        Ok(removed)
    }

    /// Update worker heartbeat timestamp
    pub async fn update_worker_heartbeat(&self, worker_id: &WorkerId) {
        let mut pool = self.gpu_pool.write().await;
        let now = chrono::Utc::now().timestamp() as u64;

        for gpu in pool.values_mut() {
            if &gpu.worker_id == worker_id {
                gpu.last_heartbeat = now;
                // If GPU was offline due to timeout, bring it back
                if gpu.status == GpuStatus::Offline {
                    gpu.status = GpuStatus::Available;
                }
            }
        }
    }

    // =========================================================================
    // LEGACY METHODS (kept for compatibility, may be removed later)
    // =========================================================================

    /// Handle bid received - DEPRECATED, kept for P2P message compatibility
    /// Bids are now ignored as we use direct GPU allocation
    #[allow(dead_code)]
    async fn handle_bid_received_legacy(&self, bid: &WorkerBid) -> Result<()> {
        debug!("Received legacy bid from worker {} for job {} (ignored - using direct allocation)",
            bid.worker_id, bid.job_id);
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
        assert!(config.min_worker_reputation > 0.0);
        assert!(config.min_worker_health > 0.0);
        assert!(config.blockchain_poll_interval_secs > 0);
        assert!(config.worker_heartbeat_timeout_secs > 0);
        assert!(config.max_jobs_per_worker > 0);
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
    async fn test_gpu_pool_stats() {
        // Create a distributor
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

        // Register a GPU
        let gpu = RegisteredGpu {
            gpu_id: "gpu_001".to_string(),
            worker_id: WorkerId::new(),
            gpu_type: GpuType::Rtx4090,
            gpu_count: 1,
            vram_gb: 24,
            status: GpuStatus::Available,
            hourly_rate: 100,
            reputation_score: 0.9,
            health_score: 0.95,
            registered_at: chrono::Utc::now().timestamp() as u64,
            last_heartbeat: chrono::Utc::now().timestamp() as u64,
        };

        distributor.register_gpu(gpu).await.unwrap();

        // Check stats
        let stats = distributor.get_gpu_pool_stats().await;
        assert_eq!(stats.total_gpus, 1);
        assert_eq!(stats.available_gpus, 1);
        assert_eq!(stats.in_use_gpus, 0);
    }

    #[tokio::test]
    async fn test_gpu_type_info() {
        assert_eq!(GpuType::H100.vram_gb(), 80);
        assert_eq!(GpuType::A100.vram_gb(), 80);
        assert_eq!(GpuType::Rtx4090.vram_gb(), 24);
        assert_eq!(GpuType::Rtx4090.display_name(), "NVIDIA RTX 4090");
    }
}
