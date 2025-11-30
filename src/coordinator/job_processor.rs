//! # Job Processor
//!
//! Comprehensive job processing system for the Bitsage Network coordinator,
//! handling job lifecycle, scheduling, and execution coordination.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock, Mutex};
use tokio::time::{Duration, Instant};
use tracing::{info, debug, error};

use crate::types::{JobId, WorkerId};
use crate::node::coordinator::{JobRequest, JobResult as CoordinatorJobResult, JobStatus};
use crate::storage::Database;
use crate::blockchain::contracts::JobManagerContract;
use crate::coordinator::config::JobProcessorConfig;
use crate::blockchain::client::StarknetClient;
use crate::blockchain::types::JobType;

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

/// Job queue entry
#[derive(Debug, Clone)]
struct JobQueueEntry {
    job_id: JobId,
    priority: u32,
    created_at: Instant,
    retry_count: u32,
}

/// Main job processor service
pub struct JobProcessor {
    config: JobProcessorConfig,
    database: Arc<Database>,
    job_manager_contract: Arc<JobManagerContract>,
    
    // Job storage
    active_jobs: Arc<RwLock<HashMap<JobId, JobInfo>>>,
    job_queue: Arc<Mutex<VecDeque<JobQueueEntry>>>,
    
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
            active_jobs: Arc::new(RwLock::new(HashMap::new())),
            job_queue: Arc::new(Mutex::new(VecDeque::new())),
            stats: Arc::new(RwLock::new(stats)),
            event_sender,
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
            running: Arc::new(RwLock::new(false)),
            next_job_id: Arc::new(Mutex::new(1)),
        }
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

    /// Start queue processing
    async fn start_queue_processing(&self) -> Result<()> {
        let config = self.config.clone();
        let job_queue = Arc::clone(&self.job_queue);
        let active_jobs = Arc::clone(&self.active_jobs);
        let _event_sender = self.event_sender.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            
            loop {
                interval.tick().await;
                
                // Process jobs from queue
                let mut queue = job_queue.lock().await;
                if let Some(entry) = queue.pop_front() {
                    let jobs = active_jobs.read().await;
                    if let Some(job_info) = jobs.get(&entry.job_id) {
                        debug!("Processing job {} from queue", entry.job_id);
                        
                        // TODO: Implement actual job assignment logic
                        // This would involve worker selection and assignment
                        
                        // For now, just mark as queued
                        drop(jobs);
                        let mut jobs = active_jobs.write().await;
                        if let Some(job_info) = jobs.get_mut(&entry.job_id) {
                            job_info.execution_state = JobExecutionState::Queued;
                        }
                    }
                }
            }
        });

        Ok(())
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

    /// Calculate job priority
    fn calculate_priority(&self, request: &JobRequest) -> u32 {
        // TODO: Implement priority calculation based on job type, client, etc.
        1
    }

    /// Extract job tags
    fn extract_tags(&self, request: &JobRequest) -> Vec<String> {
        // TODO: Implement tag extraction based on job type, parameters, etc.
        vec![request.job_type.to_string()]
    }

    /// Add job to queue
    async fn add_to_queue(&self, job_id: JobId, priority: u32) {
        let entry = JobQueueEntry {
            job_id,
            priority,
            created_at: Instant::now(),
            retry_count: 0,
        };
        
        let mut queue = self.job_queue.lock().await;
        queue.push_back(entry);
    }

    /// Remove job from queue
    async fn remove_from_queue(&self, job_id: JobId) {
        let mut queue = self.job_queue.lock().await;
        queue.retain(|entry| entry.job_id != job_id);
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

    /// Get event receiver
    pub async fn event_receiver(&self) -> mpsc::UnboundedReceiver<JobEvent> {
        self.event_receiver.write().await.take().unwrap()
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
