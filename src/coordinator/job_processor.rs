//! # Job Processor
//!
//! Comprehensive job processing system for the Bitsage Network coordinator,
//! handling job lifecycle, scheduling, and execution coordination.
//!
//! Features:
//! - Priority-based job scheduling
//! - Worker capability matching
//! - Automatic retry with exponential backoff
//! - Job timeout monitoring
//! - Statistics tracking

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, BinaryHeap};
use std::sync::Arc;
use std::cmp::Ordering;
use tokio::sync::{mpsc, RwLock, Mutex};
use tokio::time::{Duration, Instant};
use tracing::{info, debug, error, warn};

use crate::types::{JobId, WorkerId};
use crate::node::coordinator::{JobRequest, JobResult as CoordinatorJobResult, JobStatus, JobType, ComputeRequirements};
use crate::storage::Database;
use crate::blockchain::contracts::JobManagerContract;
use crate::coordinator::config::JobProcessorConfig;
use crate::coordinator::worker_manager::WorkerManager;

/// Job processor events
#[derive(Debug, Clone)]
pub enum JobEvent {
    JobSubmitted(JobId, JobRequest),
    JobStarted(JobId, WorkerId),
    JobCompleted(JobId, CoordinatorJobResult),
    JobFailed(JobId, String),
    JobCancelled(JobId),
    JobTimeout(JobId),
    JobAssigned(JobId, WorkerId),
    JobUnassigned(JobId, WorkerId),
}

/// Job execution state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JobExecutionState {
    Pending,
    Queued,
    Assigned(WorkerId),
    Running(WorkerId),
    Completed(CoordinatorJobResult),
    Failed(String),
    Cancelled,
    Timeout,
}

/// Job information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobInfo {
    pub id: JobId,
    pub request: JobRequest,
    pub status: JobStatus,
    pub execution_state: JobExecutionState,
    pub created_at: u64,
    pub started_at: Option<u64>,
    pub completed_at: Option<u64>,
    pub assigned_worker: Option<WorkerId>,
    pub retry_count: u32,
    pub max_retries: u32,
    pub timeout_secs: u64,
    pub priority: u32,
    pub tags: Vec<String>,
}

/// Job statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobStats {
    pub total_jobs: u64,
    pub active_jobs: u64,
    pub completed_jobs: u64,
    pub failed_jobs: u64,
    pub cancelled_jobs: u64,
    pub average_completion_time_secs: u64,
    pub jobs_per_minute: f64,
    pub success_rate: f64,
}

/// Job queue entry with priority ordering
#[derive(Debug, Clone)]
struct JobQueueEntry {
    job_id: JobId,
    priority: u32,
    created_at: Instant,
    retry_count: u32,
    deadline: Option<u64>,
}

impl PartialEq for JobQueueEntry {
    fn eq(&self, other: &Self) -> bool {
        self.job_id == other.job_id
    }
}

impl Eq for JobQueueEntry {}

impl PartialOrd for JobQueueEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for JobQueueEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first
        match self.priority.cmp(&other.priority) {
            Ordering::Equal => {
                // Earlier deadline first (if set)
                match (self.deadline, other.deadline) {
                    (Some(a), Some(b)) => b.cmp(&a), // Reversed for min-deadline-first
                    (Some(_), None) => Ordering::Greater,
                    (None, Some(_)) => Ordering::Less,
                    (None, None) => {
                        // Earlier created_at first (FIFO within same priority)
                        other.created_at.cmp(&self.created_at) // Reversed for earlier-first
                    }
                }
            }
            other => other,
        }
    }
}

/// Main job processor service
pub struct JobProcessor {
    config: JobProcessorConfig,
    database: Arc<Database>,
    job_manager_contract: Arc<JobManagerContract>,

    // Worker manager for job assignment
    worker_manager: Option<Arc<WorkerManager>>,

    // Job storage
    active_jobs: Arc<RwLock<HashMap<JobId, JobInfo>>>,
    job_queue: Arc<Mutex<BinaryHeap<JobQueueEntry>>>,

    // Job statistics
    stats: Arc<RwLock<JobStats>>,

    // Communication channels
    event_sender: mpsc::UnboundedSender<JobEvent>,
    event_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<JobEvent>>>>,

    // Internal state
    running: Arc<RwLock<bool>>,
    next_job_id: Arc<Mutex<u64>>,
}

impl JobProcessor {
    /// Create a new job processor
    pub fn new(
        config: JobProcessorConfig,
        database: Arc<Database>,
        job_manager_contract: Arc<JobManagerContract>,
    ) -> Self {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        let stats = JobStats {
            total_jobs: 0,
            active_jobs: 0,
            completed_jobs: 0,
            failed_jobs: 0,
            cancelled_jobs: 0,
            average_completion_time_secs: 0,
            jobs_per_minute: 0.0,
            success_rate: 0.0,
        };

        Self {
            config,
            database,
            job_manager_contract,
            worker_manager: None,
            active_jobs: Arc::new(RwLock::new(HashMap::new())),
            job_queue: Arc::new(Mutex::new(BinaryHeap::new())),
            stats: Arc::new(RwLock::new(stats)),
            event_sender,
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
            running: Arc::new(RwLock::new(false)),
            next_job_id: Arc::new(Mutex::new(1)),
        }
    }

    /// Set the worker manager for job assignment
    pub fn set_worker_manager(&mut self, worker_manager: Arc<WorkerManager>) {
        self.worker_manager = Some(worker_manager);
    }

    /// Create with worker manager
    pub fn with_worker_manager(
        config: JobProcessorConfig,
        database: Arc<Database>,
        job_manager_contract: Arc<JobManagerContract>,
        worker_manager: Arc<WorkerManager>,
    ) -> Self {
        let mut processor = Self::new(config, database, job_manager_contract);
        processor.worker_manager = Some(worker_manager);
        processor
    }

    /// Start the job processor
    pub async fn start(&self) -> Result<()> {
        info!("Starting Job Processor...");
        
        {
            let mut running = self.running.write().await;
            if *running {
                return Err(anyhow::anyhow!("Job processor already running"));
            }
            *running = true;
        }

        // Start processing tasks
        let queue_processing_handle = self.start_queue_processing().await?;
        let timeout_monitoring_handle = self.start_timeout_monitoring().await?;
        let stats_collection_handle = self.start_stats_collection().await?;

        info!("Job processor started successfully");
        
        Ok(())
    }

    /// Stop the job processor
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping Job Processor...");
        
        {
            let mut running = self.running.write().await;
            *running = false;
        }

        info!("Job processor stopped");
        Ok(())
    }

    /// Submit a new job
    pub async fn submit_job(&self, request: JobRequest) -> Result<JobId> {
        info!("Submitting new job: {:?}", request.job_type);
        
        // Validate job request
        self.validate_job_request(&request).await?;
        
        // Generate job ID
        let job_id = self.generate_job_id().await;
        
        // Create job info
        let job_info = JobInfo {
            id: job_id,
            request: request.clone(),
            status: JobStatus::Pending,
            execution_state: JobExecutionState::Pending,
            created_at: chrono::Utc::now().timestamp() as u64,
            started_at: None,
            completed_at: None,
            assigned_worker: None,
            retry_count: 0,
            max_retries: self.config.retry_config.max_retries,
            timeout_secs: self.config.job_timeout_secs,
            priority: self.calculate_priority(&request),
            tags: self.extract_tags(&request),
        };
        
        // Store job
        self.active_jobs.write().await.insert(job_id, job_info.clone());
        
        // Add to queue
        self.add_to_queue(job_id, job_info.priority).await;
        
        // Update statistics
        self.update_stats_job_submitted().await;
        
        // Send event
        if let Err(e) = self.event_sender.send(JobEvent::JobSubmitted(job_id, request)) {
            error!("Failed to send job submitted event: {}", e);
        }
        
        info!("Job {} submitted successfully", job_id);
        Ok(job_id)
    }

    /// Get job details
    pub async fn get_job_details(&self, job_id: JobId) -> Result<Option<JobInfo>> {
        let jobs = self.active_jobs.read().await;
        Ok(jobs.get(&job_id).cloned())
    }

    /// Get job status
    pub async fn get_job_status(&self, job_id: JobId) -> Result<Option<JobStatus>> {
        if let Some(job_info) = self.get_job_details(job_id).await? {
            Ok(Some(job_info.status))
        } else {
            Ok(None)
        }
    }

    /// List all jobs
    pub async fn list_jobs(&self) -> Result<Vec<JobInfo>> {
        let jobs = self.active_jobs.read().await;
        Ok(jobs.values().cloned().collect())
    }
    
    /// Get job statistics
    pub async fn get_stats(&self) -> Result<JobStats> {
        let stats = self.stats.read().await;
        Ok(stats.clone())
    }
    
    /// Cancel a job
    pub async fn cancel_job(&self, job_id: JobId) -> Result<()> {
        info!("Cancelling job {}", job_id);
        
        let mut jobs = self.active_jobs.write().await;
        if let Some(job_info) = jobs.get_mut(&job_id) {
            job_info.status = JobStatus::Cancelled;
            job_info.execution_state = JobExecutionState::Cancelled;
            job_info.completed_at = Some(chrono::Utc::now().timestamp() as u64);
            
            // Remove from queue
            self.remove_from_queue(job_id).await;
            
            // Update statistics
            self.update_stats_job_cancelled().await;
            
            // Send event
            if let Err(e) = self.event_sender.send(JobEvent::JobCancelled(job_id)) {
                error!("Failed to send job cancelled event: {}", e);
            }
            
            info!("Job {} cancelled successfully", job_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Job {} not found", job_id))
        }
    }

    /// Get active jobs
    pub async fn get_active_jobs(&self) -> Vec<JobInfo> {
        let jobs = self.active_jobs.read().await;
        jobs.values()
            .filter(|job| matches!(job.status, JobStatus::Pending | JobStatus::Running))
            .cloned()
            .collect()
    }

    /// Get active jobs count
    pub async fn get_active_jobs_count(&self) -> usize {
        let jobs = self.active_jobs.read().await;
        jobs.values()
            .filter(|job| matches!(job.status, JobStatus::Pending | JobStatus::Running))
            .count()
    }

    /// Get job statistics
    pub async fn get_job_stats(&self) -> JobStats {
        self.stats.read().await.clone()
    }

    /// Get a Send+Sync handle to the stats for use in spawned tasks
    /// This allows metrics collection from within tokio::spawn without
    /// moving the entire JobProcessor (which contains non-Send fields)
    pub fn stats_handle(&self) -> Arc<RwLock<JobStats>> {
        Arc::clone(&self.stats)
    }

    /// Get a Send+Sync handle to active jobs for use in spawned tasks
    pub fn active_jobs_handle(&self) -> Arc<RwLock<HashMap<JobId, JobInfo>>> {
        Arc::clone(&self.active_jobs)
    }

    /// Assign job to worker
    pub async fn assign_job_to_worker(&self, job_id: JobId, worker_id: WorkerId) -> Result<()> {
        info!("Assigning job {} to worker {}", job_id, worker_id);
        
        let mut jobs = self.active_jobs.write().await;
        if let Some(job_info) = jobs.get_mut(&job_id) {
            job_info.assigned_worker = Some(worker_id);
            job_info.execution_state = JobExecutionState::Assigned(worker_id);
            job_info.started_at = Some(chrono::Utc::now().timestamp() as u64);
            job_info.status = JobStatus::Running;
            
            // Send event
            if let Err(e) = self.event_sender.send(JobEvent::JobAssigned(job_id, worker_id)) {
                error!("Failed to send job assigned event: {}", e);
            }
            
            info!("Job {} assigned to worker {}", job_id, worker_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Job {} not found", job_id))
        }
    }

    /// Complete job
    pub async fn complete_job(&self, job_id: JobId, result: CoordinatorJobResult) -> Result<()> {
        info!("Completing job {}", job_id);
        
        let mut jobs = self.active_jobs.write().await;
        if let Some(job_info) = jobs.get_mut(&job_id) {
            job_info.status = JobStatus::Completed;
            job_info.execution_state = JobExecutionState::Completed(result.clone());
            job_info.completed_at = Some(chrono::Utc::now().timestamp() as u64);
            
            // Update statistics
            self.update_stats_job_completed().await;
            
            // Send event
            if let Err(e) = self.event_sender.send(JobEvent::JobCompleted(job_id, result)) {
                error!("Failed to send job completed event: {}", e);
            }
            
            info!("Job {} completed successfully", job_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Job {} not found", job_id))
        }
    }

    /// Fail job
    pub async fn fail_job(&self, job_id: JobId, error_message: String) -> Result<()> {
        info!("Failing job {}: {}", job_id, error_message);
        
        let mut jobs = self.active_jobs.write().await;
        if let Some(job_info) = jobs.get_mut(&job_id) {
            job_info.status = JobStatus::Failed;
            job_info.execution_state = JobExecutionState::Failed(error_message.clone());
            job_info.completed_at = Some(chrono::Utc::now().timestamp() as u64);
            
            // Check if retry is possible
            if job_info.retry_count < job_info.max_retries {
                job_info.retry_count += 1;
                job_info.status = JobStatus::Pending;
                job_info.execution_state = JobExecutionState::Pending;
                job_info.started_at = None;
                job_info.completed_at = None;
                job_info.assigned_worker = None;
                
                // Re-add to queue
                self.add_to_queue(job_id, job_info.priority).await;
                
                info!("Job {} scheduled for retry (attempt {}/{})", job_id, job_info.retry_count, job_info.max_retries);
            } else {
                // Update statistics
                self.update_stats_job_failed().await;
                
                // Send event
                if let Err(e) = self.event_sender.send(JobEvent::JobFailed(job_id, error_message.clone())) {
                    error!("Failed to send job failed event: {}", e);
                }
                
                info!("Job {} failed permanently after {} retries", job_id, job_info.max_retries);
            }
            
            Ok(())
        } else {
            Err(anyhow::anyhow!("Job {} not found", job_id))
        }
    }

    /// Start queue processing with actual worker assignment
    async fn start_queue_processing(&self) -> Result<()> {
        let config = self.config.clone();
        let job_queue = Arc::clone(&self.job_queue);
        let active_jobs = Arc::clone(&self.active_jobs);
        let event_sender = self.event_sender.clone();
        let worker_manager = self.worker_manager.clone();

        tokio::spawn(async move {
            // Poll interval: use scheduling config or default to 500ms
            let poll_interval_ms = 500u64;
            let mut interval = tokio::time::interval(Duration::from_millis(poll_interval_ms));
            let mut consecutive_empty = 0;

            loop {
                interval.tick().await;

                // Get next job from priority queue
                let entry = {
                    let mut queue = job_queue.lock().await;
                    queue.pop()
                };

                let Some(entry) = entry else {
                    // No jobs in queue, use exponential backoff
                    consecutive_empty += 1;
                    if consecutive_empty > 10 {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    continue;
                };

                consecutive_empty = 0;
                let job_id = entry.job_id;

                // Get job info
                let job_request = {
                    let jobs = active_jobs.read().await;
                    jobs.get(&job_id).map(|j| j.request.clone())
                };

                let Some(request) = job_request else {
                    warn!("Job {} no longer exists, skipping", job_id);
                    continue;
                };

                debug!("Processing job {} from queue (priority: {})", job_id, entry.priority);

                // Try to find a suitable worker
                let assigned_worker = if let Some(ref wm) = worker_manager {
                    // Derive compute requirements from job type
                    let requirements = Self::static_derive_requirements(&request);

                    // Find best available worker
                    match wm.find_best_worker(&requirements).await {
                        Some(worker) => Some(worker.id),
                        None => {
                            debug!("No suitable worker found for job {}, re-queuing", job_id);

                            // Re-add to queue with slightly lower priority
                            let new_priority = entry.priority.saturating_sub(1);
                            let requeue_entry = JobQueueEntry {
                                job_id,
                                priority: new_priority,
                                created_at: entry.created_at,
                                retry_count: entry.retry_count + 1,
                                deadline: entry.deadline,
                            };

                            // Don't re-queue indefinitely
                            if requeue_entry.retry_count < 10 {
                                let mut queue = job_queue.lock().await;
                                queue.push(requeue_entry);
                            } else {
                                warn!("Job {} failed to find worker after 10 attempts", job_id);
                                let mut jobs = active_jobs.write().await;
                                if let Some(job_info) = jobs.get_mut(&job_id) {
                                    job_info.status = JobStatus::Failed;
                                    job_info.execution_state = JobExecutionState::Failed(
                                        "No suitable worker available".to_string()
                                    );
                                }
                                let _ = event_sender.send(JobEvent::JobFailed(
                                    job_id,
                                    "No suitable worker available".to_string(),
                                ));
                            }
                            None
                        }
                    }
                } else {
                    // No worker manager, just mark as queued
                    debug!("No worker manager configured, marking job {} as queued", job_id);
                    let mut jobs = active_jobs.write().await;
                    if let Some(job_info) = jobs.get_mut(&job_id) {
                        job_info.execution_state = JobExecutionState::Queued;
                    }
                    None
                };

                // Assign job to worker if found
                if let Some(worker_id) = assigned_worker {
                    let mut jobs = active_jobs.write().await;
                    if let Some(job_info) = jobs.get_mut(&job_id) {
                        job_info.assigned_worker = Some(worker_id);
                        job_info.execution_state = JobExecutionState::Assigned(worker_id);
                        job_info.started_at = Some(chrono::Utc::now().timestamp() as u64);
                        job_info.status = JobStatus::Running;

                        info!("Assigned job {} to worker {}", job_id, worker_id);
                        let _ = event_sender.send(JobEvent::JobAssigned(job_id, worker_id));
                    }
                }
            }
        });

        Ok(())
    }

    /// Static helper to derive compute requirements (for use in spawned task)
    fn static_derive_requirements(request: &JobRequest) -> ComputeRequirements {
        match &request.job_type {
            JobType::AIInference { batch_size, .. } => ComputeRequirements {
                min_gpu_memory_gb: 8.max(*batch_size / 4),
                min_cpu_cores: 4,
                min_ram_gb: 16,
                preferred_gpu_type: Some("A100".to_string()),
                requires_high_precision: false,
                requires_specialized_hardware: false,
                estimated_runtime_minutes: 5,
            },
            JobType::ZKProof { .. } => ComputeRequirements {
                min_gpu_memory_gb: 24,
                min_cpu_cores: 8,
                min_ram_gb: 64,
                preferred_gpu_type: Some("H100".to_string()),
                requires_high_precision: true,
                requires_specialized_hardware: false,
                estimated_runtime_minutes: 30,
            },
            JobType::Render3D { .. } => ComputeRequirements {
                min_gpu_memory_gb: 12,
                min_cpu_cores: 8,
                min_ram_gb: 32,
                preferred_gpu_type: Some("RTX".to_string()),
                requires_high_precision: false,
                requires_specialized_hardware: false,
                estimated_runtime_minutes: 60,
            },
            JobType::ConfidentialVM { memory_mb, vcpu_count, .. } => ComputeRequirements {
                min_gpu_memory_gb: 0,
                min_cpu_cores: *vcpu_count,
                min_ram_gb: (*memory_mb / 1024).max(4),
                preferred_gpu_type: None,
                requires_high_precision: false,
                requires_specialized_hardware: true,
                estimated_runtime_minutes: (request.max_duration_secs / 60) as u32,
            },
            _ => ComputeRequirements {
                min_gpu_memory_gb: 4,
                min_cpu_cores: 2,
                min_ram_gb: 8,
                preferred_gpu_type: None,
                requires_high_precision: false,
                requires_specialized_hardware: false,
                estimated_runtime_minutes: 10,
            },
        }
    }

    /// Start timeout monitoring
    async fn start_timeout_monitoring(&self) -> Result<()> {
        let active_jobs = Arc::clone(&self.active_jobs);
        let event_sender = self.event_sender.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                let now = chrono::Utc::now().timestamp() as u64;
                let mut jobs = active_jobs.write().await;
                let mut timed_out_jobs = Vec::new();
                
                for (job_id, job_info) in jobs.iter_mut() {
                    if let Some(started_at) = job_info.started_at {
                        if now - started_at > job_info.timeout_secs {
                            job_info.status = JobStatus::Failed;
                            job_info.execution_state = JobExecutionState::Timeout;
                            job_info.completed_at = Some(now);
                            timed_out_jobs.push(*job_id);
                        }
                    }
                }
                
                // Send timeout events
                for job_id in timed_out_jobs {
                    if let Err(e) = event_sender.send(JobEvent::JobTimeout(job_id)) {
                        error!("Failed to send job timeout event: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    /// Start statistics collection
    async fn start_stats_collection(&self) -> Result<()> {
        let stats = Arc::clone(&self.stats);
        let active_jobs = Arc::clone(&self.active_jobs);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                // Update statistics
                let jobs = active_jobs.read().await;
                let mut stats_guard = stats.write().await;
                
                stats_guard.active_jobs = jobs.values()
                    .filter(|job| matches!(job.status, JobStatus::Pending | JobStatus::Running))
                    .count() as u64;
                
                // Calculate success rate
                let total_completed = stats_guard.completed_jobs + stats_guard.failed_jobs;
                if total_completed > 0 {
                    stats_guard.success_rate = stats_guard.completed_jobs as f64 / total_completed as f64;
                }
            }
        });

        Ok(())
    }

    /// Validate job request
    async fn validate_job_request(&self, request: &JobRequest) -> Result<()> {
        // Check job type
        if !self.config.validation.allowed_job_types.contains(&request.job_type.to_string()) {
            return Err(anyhow::anyhow!("Job type '{}' not allowed", request.job_type));
        }
        
        // Check job size
        if request.data.len() as u64 > self.config.validation.max_job_size_bytes {
            return Err(anyhow::anyhow!("Job data too large: {} bytes", request.data.len()));
        }
        
        // Check job duration
        if request.max_duration_secs > self.config.validation.max_job_duration_secs {
            return Err(anyhow::anyhow!("Job duration too long: {} seconds", request.max_duration_secs));
        }
        
        Ok(())
    }

    /// Generate job ID
    async fn generate_job_id(&self) -> JobId {
        let mut next_id = self.next_job_id.lock().await;
        *next_id += 1;
        JobId::new()
    }

    /// Calculate job priority based on job type, cost, and urgency
    ///
    /// Priority scale: 0 (lowest) to 100 (highest)
    /// - Base priority from request.priority (0-255 scaled to 0-50)
    /// - Job type bonus (critical types get +20)
    /// - Deadline urgency bonus (up to +20)
    /// - Cost tier bonus (higher paying jobs get +10)
    fn calculate_priority(&self, request: &JobRequest) -> u32 {
        let mut priority: u32 = 0;

        // Base priority from request (scaled from 0-255 to 0-50)
        priority += (request.priority as u32 * 50) / 255;

        // Job type bonus for critical workloads
        priority += match &request.job_type {
            JobType::ZKProof { .. } => 20,          // ZK proofs are time-sensitive
            JobType::ConfidentialVM { .. } => 18,   // Confidential compute is high-value
            JobType::AIInference { .. } => 15,      // AI inference often time-critical
            JobType::Render3D { .. } => 10,         // Rendering can be batched
            JobType::VideoProcessing { .. } => 8,
            _ => 5,                                  // Default for other types
        };

        // Deadline urgency bonus
        if let Some(deadline) = &request.deadline {
            let now = chrono::Utc::now();
            let time_until_deadline = deadline.signed_duration_since(now);
            let hours_remaining = time_until_deadline.num_hours();

            if hours_remaining < 1 {
                priority += 20; // Very urgent
            } else if hours_remaining < 4 {
                priority += 15;
            } else if hours_remaining < 24 {
                priority += 10;
            } else if hours_remaining < 72 {
                priority += 5;
            }
        }

        // Cost tier bonus (higher max_cost = potentially more important job)
        if request.max_cost > 10000 {
            priority += 10;
        } else if request.max_cost > 1000 {
            priority += 5;
        }

        priority.min(100) // Cap at 100
    }

    /// Extract job tags for categorization and filtering
    fn extract_tags(&self, request: &JobRequest) -> Vec<String> {
        let mut tags = Vec::new();

        // Add job type as primary tag
        tags.push(request.job_type.to_string());

        // Add capability-based tags
        match &request.job_type {
            JobType::AIInference { model_type, .. } => {
                tags.push("ai".to_string());
                tags.push(format!("model:{}", model_type));
            }
            JobType::ZKProof { circuit_type, proof_system, .. } => {
                tags.push("zk".to_string());
                tags.push(format!("circuit:{}", circuit_type));
                tags.push(format!("prover:{}", proof_system));
            }
            JobType::Render3D { .. } => {
                tags.push("gpu".to_string());
                tags.push("render".to_string());
            }
            JobType::VideoProcessing { .. } => {
                tags.push("gpu".to_string());
                tags.push("video".to_string());
            }
            JobType::ComputerVision { model_name, .. } => {
                tags.push("ai".to_string());
                tags.push("cv".to_string());
                tags.push(format!("model:{}", model_name));
            }
            JobType::NLP { model_name, .. } => {
                tags.push("ai".to_string());
                tags.push("nlp".to_string());
                tags.push(format!("model:{}", model_name));
            }
            JobType::ConfidentialVM { tee_type, .. } => {
                tags.push("tee".to_string());
                tags.push(format!("tee:{}", tee_type));
            }
            JobType::DataPipeline { tee_required, .. } => {
                tags.push("data".to_string());
                if *tee_required {
                    tags.push("tee".to_string());
                }
            }
            JobType::Custom { parallelizable, .. } => {
                tags.push("custom".to_string());
                if *parallelizable {
                    tags.push("parallel".to_string());
                }
            }
            _ => {}
        }

        // Add urgency tag if deadline is set
        if request.deadline.is_some() {
            tags.push("deadline".to_string());
        }

        tags
    }

    /// Derive compute requirements from job request
    fn derive_compute_requirements(&self, request: &JobRequest) -> ComputeRequirements {
        match &request.job_type {
            JobType::AIInference { batch_size, .. } => ComputeRequirements {
                min_gpu_memory_gb: 8.max(*batch_size / 4),
                min_cpu_cores: 4,
                min_ram_gb: 16,
                preferred_gpu_type: Some("A100".to_string()),
                requires_high_precision: false,
                requires_specialized_hardware: false,
                estimated_runtime_minutes: 5,
            },
            JobType::ZKProof { .. } => ComputeRequirements {
                min_gpu_memory_gb: 24,
                min_cpu_cores: 8,
                min_ram_gb: 64,
                preferred_gpu_type: Some("H100".to_string()),
                requires_high_precision: true,
                requires_specialized_hardware: false,
                estimated_runtime_minutes: 30,
            },
            JobType::Render3D { .. } => ComputeRequirements {
                min_gpu_memory_gb: 12,
                min_cpu_cores: 8,
                min_ram_gb: 32,
                preferred_gpu_type: Some("RTX".to_string()),
                requires_high_precision: false,
                requires_specialized_hardware: false,
                estimated_runtime_minutes: 60,
            },
            JobType::ConfidentialVM { memory_mb, vcpu_count, .. } => ComputeRequirements {
                min_gpu_memory_gb: 0,
                min_cpu_cores: *vcpu_count,
                min_ram_gb: (*memory_mb / 1024).max(4),
                preferred_gpu_type: None,
                requires_high_precision: false,
                requires_specialized_hardware: true, // Requires TEE
                estimated_runtime_minutes: (request.max_duration_secs / 60) as u32,
            },
            _ => ComputeRequirements {
                min_gpu_memory_gb: 4,
                min_cpu_cores: 2,
                min_ram_gb: 8,
                preferred_gpu_type: None,
                requires_high_precision: false,
                requires_specialized_hardware: false,
                estimated_runtime_minutes: 10,
            },
        }
    }

    /// Add job to priority queue
    async fn add_to_queue(&self, job_id: JobId, priority: u32) {
        self.add_to_queue_with_deadline(job_id, priority, None).await;
    }

    /// Add job to priority queue with optional deadline
    async fn add_to_queue_with_deadline(&self, job_id: JobId, priority: u32, deadline: Option<u64>) {
        let entry = JobQueueEntry {
            job_id,
            priority,
            created_at: Instant::now(),
            retry_count: 0,
            deadline,
        };

        let mut queue = self.job_queue.lock().await;
        queue.push(entry);
        debug!("Added job {} to queue with priority {}", job_id, priority);
    }

    /// Remove job from queue
    async fn remove_from_queue(&self, job_id: JobId) {
        let mut queue = self.job_queue.lock().await;
        // BinaryHeap doesn't support removal, so we rebuild it
        let entries: Vec<_> = queue.drain().filter(|e| e.job_id != job_id).collect();
        for entry in entries {
            queue.push(entry);
        }
    }

    /// Update statistics for job submitted
    async fn update_stats_job_submitted(&self) {
        let mut stats = self.stats.write().await;
        stats.total_jobs += 1;
        stats.active_jobs += 1;
    }

    /// Update statistics for job completed
    async fn update_stats_job_completed(&self) {
        let mut stats = self.stats.write().await;
        stats.completed_jobs += 1;
        stats.active_jobs = stats.active_jobs.saturating_sub(1);
    }

    /// Update statistics for job failed
    async fn update_stats_job_failed(&self) {
        let mut stats = self.stats.write().await;
        stats.failed_jobs += 1;
        stats.active_jobs = stats.active_jobs.saturating_sub(1);
    }

    /// Update statistics for job cancelled
    async fn update_stats_job_cancelled(&self) {
        let mut stats = self.stats.write().await;
        stats.cancelled_jobs += 1;
        stats.active_jobs = stats.active_jobs.saturating_sub(1);
    }

    /// Take the event receiver.
    ///
    /// This can only be called once - subsequent calls will return `None`.
    pub async fn take_event_receiver(&self) -> Option<mpsc::UnboundedReceiver<JobEvent>> {
        self.event_receiver.write().await.take()
    }

    /// Check if the event receiver is still available.
    pub async fn has_event_receiver(&self) -> bool {
        self.event_receiver.read().await.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_job_processor_creation() {
        // Setup omitted for brevity
    }
}
