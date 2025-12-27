//! # Worker Node
//!
//! Worker nodes execute compute tasks assigned by coordinators.
//! This module provides a complete worker implementation with:
//! - Coordinator registration and communication
//! - Job polling and execution
//! - Health monitoring and heartbeat
//! - Graceful shutdown handling

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, Context, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn, error, debug, instrument};

use crate::types::{WorkerId, JobId, WorkerCapabilities, TeeType};
use crate::compute::job_executor::{JobExecutor, JobExecutionRequest, JobExecutionResult, JobRequirements};

// ============================================================================
// Configuration Types
// ============================================================================

/// Worker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerConfig {
    /// Worker identifier (auto-generated if not specified)
    pub worker_id: Option<String>,
    /// Coordinator URL for registration and job polling
    pub coordinator_url: String,
    /// Port for P2P communication (if enabled)
    pub listen_port: u16,
    /// Enable P2P networking
    pub enable_p2p: bool,
    /// Enable TEE attestations
    pub enable_tee: bool,
    /// Interval between job polls (seconds)
    pub poll_interval_secs: u64,
    /// Interval between heartbeats (seconds)
    pub heartbeat_interval_secs: u64,
    /// Maximum concurrent jobs
    pub max_concurrent_jobs: u32,
    /// Worker wallet address for payments
    pub wallet_address: Option<String>,
    /// Connection timeout for HTTP requests (seconds)
    pub connection_timeout_secs: u64,
    /// Request timeout for HTTP requests (seconds)
    pub request_timeout_secs: u64,
    /// Number of registration retries
    pub registration_retries: u32,
    /// Delay between registration retries (seconds)
    pub registration_retry_delay_secs: u64,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            worker_id: None,
            coordinator_url: "http://localhost:8080".to_string(),
            listen_port: 9000,
            enable_p2p: false,
            enable_tee: false,
            poll_interval_secs: 5,
            heartbeat_interval_secs: 30,
            max_concurrent_jobs: 4,
            wallet_address: None,
            connection_timeout_secs: 10,
            request_timeout_secs: 30,
            registration_retries: 3,
            registration_retry_delay_secs: 5,
        }
    }
}

// ============================================================================
// Worker Statistics
// ============================================================================

/// Worker statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkerStats {
    /// Total jobs executed
    pub total_jobs_executed: u64,
    /// Successful jobs
    pub successful_jobs: u64,
    /// Failed jobs
    pub failed_jobs: u64,
    /// Total execution time (milliseconds)
    pub total_execution_time_ms: u64,
    /// Average execution time (milliseconds)
    pub avg_execution_time_ms: u64,
    /// Jobs currently running
    pub current_jobs: u32,
    /// Last job completed timestamp
    pub last_job_completed: Option<DateTime<Utc>>,
    /// Worker uptime (seconds)
    pub uptime_secs: u64,
    /// Time worker started
    pub started_at: Option<DateTime<Utc>>,
    /// Total bytes processed
    pub bytes_processed: u64,
}

impl WorkerStats {
    /// Record a successful job completion
    pub fn record_success(&mut self, execution_time_ms: u64, bytes: u64) {
        self.total_jobs_executed += 1;
        self.successful_jobs += 1;
        self.total_execution_time_ms += execution_time_ms;
        self.bytes_processed += bytes;
        self.last_job_completed = Some(Utc::now());
        self.update_average();
    }

    /// Record a job failure
    pub fn record_failure(&mut self) {
        self.total_jobs_executed += 1;
        self.failed_jobs += 1;
    }

    /// Update average execution time
    fn update_average(&mut self) {
        if self.successful_jobs > 0 {
            self.avg_execution_time_ms = self.total_execution_time_ms / self.successful_jobs;
        }
    }

    /// Calculate success rate
    pub fn success_rate(&self) -> f64 {
        if self.total_jobs_executed == 0 {
            1.0
        } else {
            self.successful_jobs as f64 / self.total_jobs_executed as f64
        }
    }
}

// ============================================================================
// Worker Events
// ============================================================================

/// Events emitted by the worker
#[derive(Debug, Clone)]
pub enum WorkerEvent {
    /// Worker has started
    Started,
    /// Worker has stopped
    Stopped,
    /// Worker registered with coordinator
    Registered,
    /// Worker unregistered from coordinator
    Unregistered,
    /// Registration failed
    RegistrationFailed(String),
    /// Job received from coordinator
    JobReceived(JobId),
    /// Job execution started
    JobStarted(JobId),
    /// Job completed successfully
    JobCompleted(JobId, u64), // job_id, execution_time_ms
    /// Job failed
    JobFailed(JobId, String), // job_id, error
    /// Heartbeat sent
    HeartbeatSent,
    /// Heartbeat failed
    HeartbeatFailed(String),
    /// Health status updated
    HealthUpdated(f32), // current_load
    /// Error occurred
    Error(String),
}

// ============================================================================
// Health Status
// ============================================================================

/// Worker health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Current CPU load (0.0 - 1.0)
    pub cpu_load: f32,
    /// Current memory usage (0.0 - 1.0)
    pub memory_usage: f32,
    /// Current GPU load (0.0 - 1.0)
    pub gpu_load: f32,
    /// Current GPU memory usage (0.0 - 1.0)
    pub gpu_memory_usage: f32,
    /// Overall health score (0.0 - 1.0)
    pub overall_score: f32,
    /// Is worker healthy
    pub is_healthy: bool,
    /// Last health check timestamp
    pub last_check: DateTime<Utc>,
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self {
            cpu_load: 0.0,
            memory_usage: 0.0,
            gpu_load: 0.0,
            gpu_memory_usage: 0.0,
            overall_score: 1.0,
            is_healthy: true,
            last_check: Utc::now(),
        }
    }
}

// ============================================================================
// Job State Tracking
// ============================================================================

/// Internal job state for tracking active jobs
#[derive(Debug, Clone)]
struct ActiveJob {
    job_id: JobId,
    started_at: Instant,
    job_type: String,
}

// ============================================================================
// Worker Implementation
// ============================================================================

/// Worker node implementation
pub struct Worker {
    // Identity
    id: WorkerId,
    id_string: String,

    // Configuration
    config: WorkerConfig,
    capabilities: WorkerCapabilities,

    // HTTP client for coordinator communication
    http_client: reqwest::Client,

    // Job execution
    job_executor: Arc<JobExecutor>,

    // State tracking
    running: Arc<RwLock<bool>>,
    active_jobs: Arc<RwLock<HashMap<JobId, ActiveJob>>>,
    health_status: Arc<RwLock<HealthStatus>>,
    stats: Arc<RwLock<WorkerStats>>,
    started_at: Arc<RwLock<Option<Instant>>>,
    last_heartbeat: Arc<RwLock<Option<Instant>>>,

    // Event channel
    event_sender: mpsc::UnboundedSender<WorkerEvent>,
    event_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<WorkerEvent>>>>,
}

impl Worker {
    /// Create a new worker with the given configuration and capabilities
    pub fn new(config: WorkerConfig, capabilities: WorkerCapabilities) -> Result<Self> {
        // Generate or use provided worker ID
        let id_string = config.worker_id.clone()
            .unwrap_or_else(|| format!("worker-{}", uuid::Uuid::new_v4()));
        let id = WorkerId::new();

        // Create HTTP client with timeouts
        let http_client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(config.connection_timeout_secs))
            .timeout(Duration::from_secs(config.request_timeout_secs))
            .build()
            .context("Failed to create HTTP client")?;

        // Create job executor
        let has_tee = capabilities.tee_type != TeeType::None;
        let job_executor = Arc::new(JobExecutor::new(id_string.clone(), has_tee));

        // Create event channel
        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        Ok(Self {
            id,
            id_string,
            config,
            capabilities,
            http_client,
            job_executor,
            running: Arc::new(RwLock::new(false)),
            active_jobs: Arc::new(RwLock::new(HashMap::new())),
            health_status: Arc::new(RwLock::new(HealthStatus::default())),
            stats: Arc::new(RwLock::new(WorkerStats::default())),
            started_at: Arc::new(RwLock::new(None)),
            last_heartbeat: Arc::new(RwLock::new(None)),
            event_sender,
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
        })
    }

    /// Create a worker with default configuration
    pub fn with_defaults(capabilities: WorkerCapabilities) -> Result<Self> {
        Self::new(WorkerConfig::default(), capabilities)
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    /// Get the worker ID
    pub fn id(&self) -> WorkerId {
        self.id
    }

    /// Get the worker ID as string
    pub fn id_string(&self) -> &str {
        &self.id_string
    }

    /// Get worker capabilities
    pub fn capabilities(&self) -> &WorkerCapabilities {
        &self.capabilities
    }

    /// Get worker configuration
    pub fn config(&self) -> &WorkerConfig {
        &self.config
    }

    /// Check if worker is running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Get current job count
    pub async fn current_job_count(&self) -> usize {
        self.active_jobs.read().await.len()
    }

    /// Get worker statistics
    pub async fn get_stats(&self) -> WorkerStats {
        let mut stats = self.stats.read().await.clone();

        // Update uptime if running
        if let Some(started) = *self.started_at.read().await {
            stats.uptime_secs = started.elapsed().as_secs();
        }
        stats.current_jobs = self.active_jobs.read().await.len() as u32;

        stats
    }

    /// Get health status
    pub async fn get_health_status(&self) -> HealthStatus {
        self.health_status.read().await.clone()
    }

    /// Take the event receiver (can only be called once)
    pub async fn take_event_receiver(&self) -> Option<mpsc::UnboundedReceiver<WorkerEvent>> {
        self.event_receiver.write().await.take()
    }

    // ========================================================================
    // Lifecycle Methods
    // ========================================================================

    /// Start the worker
    ///
    /// This method:
    /// 1. Registers with the coordinator
    /// 2. Spawns background tasks for heartbeat and health monitoring
    /// 3. Enters the main job polling loop
    #[instrument(skip(self), fields(worker_id = %self.id_string))]
    pub async fn start(&self) -> Result<()> {
        // Check if already running
        if *self.running.read().await {
            bail!("Worker is already running");
        }

        info!("🚀 Starting worker {}...", self.id_string);

        // Mark as running
        {
            *self.running.write().await = true;
            *self.started_at.write().await = Some(Instant::now());
            self.stats.write().await.started_at = Some(Utc::now());
        }

        // Register with coordinator
        self.register_with_retries().await?;

        // Send started event
        self.send_event(WorkerEvent::Started);

        // Spawn heartbeat task
        let heartbeat_handle = self.spawn_heartbeat_task();

        // Spawn health monitoring task
        let health_handle = self.spawn_health_monitoring_task();

        info!("✅ Worker {} is running", self.id_string);
        info!("🔄 Polling coordinator for jobs...");

        // Main job polling loop
        let poll_result = self.run_polling_loop().await;

        // Cancel background tasks
        heartbeat_handle.abort();
        health_handle.abort();

        // Unregister from coordinator
        if let Err(e) = self.unregister_from_coordinator().await {
            warn!("Failed to unregister from coordinator: {}", e);
        }

        // Mark as stopped
        *self.running.write().await = false;
        self.send_event(WorkerEvent::Stopped);

        info!("🛑 Worker {} stopped", self.id_string);

        poll_result
    }

    /// Stop the worker gracefully
    #[instrument(skip(self), fields(worker_id = %self.id_string))]
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping worker {}...", self.id_string);
        *self.running.write().await = false;
        Ok(())
    }

    /// Run the main job polling loop
    async fn run_polling_loop(&self) -> Result<()> {
        let poll_interval = Duration::from_secs(self.config.poll_interval_secs);

        while *self.running.read().await {
            // Check if we can accept more jobs
            if self.can_accept_job().await {
                match self.poll_for_jobs().await {
                    Ok(Some(job)) => {
                        // Spawn job execution task
                        self.spawn_job_execution(job);
                    }
                    Ok(None) => {
                        // No jobs available, continue polling
                        debug!("No jobs available");
                    }
                    Err(e) => {
                        warn!("Failed to poll for jobs: {}", e);
                        self.send_event(WorkerEvent::Error(format!("Poll failed: {}", e)));
                    }
                }
            } else {
                debug!("At max capacity ({} jobs), skipping poll",
                    self.active_jobs.read().await.len());
            }

            tokio::time::sleep(poll_interval).await;
        }

        Ok(())
    }

    // ========================================================================
    // Coordinator Communication
    // ========================================================================

    /// Register with coordinator, with retries
    async fn register_with_retries(&self) -> Result<()> {
        let mut attempts = 0;
        let max_attempts = self.config.registration_retries;
        let retry_delay = Duration::from_secs(self.config.registration_retry_delay_secs);

        loop {
            attempts += 1;
            info!("📡 Registering with coordinator (attempt {}/{})", attempts, max_attempts);

            match self.register_with_coordinator().await {
                Ok(()) => {
                    info!("✅ Successfully registered with coordinator");
                    self.send_event(WorkerEvent::Registered);
                    return Ok(());
                }
                Err(e) => {
                    if attempts >= max_attempts {
                        error!("❌ Failed to register after {} attempts: {}", max_attempts, e);
                        self.send_event(WorkerEvent::RegistrationFailed(e.to_string()));
                        return Err(e);
                    }
                    warn!("Registration attempt {} failed: {}, retrying in {}s",
                        attempts, e, retry_delay.as_secs());
                    tokio::time::sleep(retry_delay).await;
                }
            }
        }
    }

    /// Register with coordinator
    #[instrument(skip(self), fields(worker_id = %self.id_string))]
    pub async fn register_with_coordinator(&self) -> Result<()> {
        let url = format!("{}/api/workers/register", self.config.coordinator_url);

        // Build capabilities payload in coordinator format
        let capabilities_payload = self.build_capabilities_payload();

        let payload = serde_json::json!({
            "worker_id": self.id_string,
            "capabilities": capabilities_payload,
            "wallet_address": self.config.wallet_address,
        });

        debug!("Sending registration request to {}", url);

        let response = self.http_client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .context("Failed to send registration request")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await
                .unwrap_or_else(|_| "Unknown error".to_string());
            bail!("Registration failed with status {}: {}", status, error_text);
        }

        Ok(())
    }

    /// Unregister from coordinator
    #[instrument(skip(self), fields(worker_id = %self.id_string))]
    pub async fn unregister_from_coordinator(&self) -> Result<()> {
        let url = format!("{}/api/workers/{}/unregister",
            self.config.coordinator_url, self.id_string);

        debug!("Sending unregister request to {}", url);

        // Best effort - don't fail if coordinator is unreachable
        match self.http_client.post(&url).send().await {
            Ok(response) if response.status().is_success() => {
                info!("Unregistered from coordinator");
                self.send_event(WorkerEvent::Unregistered);
            }
            Ok(response) => {
                warn!("Unregister returned status: {}", response.status());
            }
            Err(e) => {
                warn!("Failed to unregister: {}", e);
            }
        }

        Ok(())
    }

    /// Poll coordinator for new jobs
    #[instrument(skip(self), fields(worker_id = %self.id_string))]
    pub async fn poll_for_jobs(&self) -> Result<Option<serde_json::Value>> {
        let url = format!("{}/api/workers/{}/poll",
            self.config.coordinator_url, self.id_string);

        let response = self.http_client
            .get(&url)
            .send()
            .await
            .context("Failed to poll for jobs")?;

        if !response.status().is_success() {
            let status = response.status();
            if status.as_u16() == 404 || status.as_u16() == 204 {
                // No jobs available
                return Ok(None);
            }
            let error_text = response.text().await
                .unwrap_or_else(|_| "Unknown error".to_string());
            bail!("Poll failed with status {}: {}", status, error_text);
        }

        let job: serde_json::Value = response.json().await
            .context("Failed to parse job response")?;

        if job.is_null() || job.as_object().map(|o| o.is_empty()).unwrap_or(true) {
            return Ok(None);
        }

        Ok(Some(job))
    }

    /// Report job completion to coordinator
    #[instrument(skip(self, result), fields(worker_id = %self.id_string, job_id = %job_id))]
    pub async fn report_job_completion(&self, job_id: &str, result: &JobExecutionResult) -> Result<()> {
        let url = format!("{}/api/jobs/{}/complete",
            self.config.coordinator_url, job_id);

        let payload = serde_json::json!({
            "worker_id": self.id_string,
            "result": result.result_data,
            "output_hash": result.output_hash,
            "execution_time_ms": result.execution_time_ms,
            "tee_attestation": result.tee_attestation,
        });

        let response = self.http_client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .context("Failed to report job completion")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await
                .unwrap_or_else(|_| "Unknown error".to_string());
            bail!("Failed to report completion with status {}: {}", status, error_text);
        }

        info!("✅ Reported job {} completion", job_id);
        Ok(())
    }

    /// Report job failure to coordinator
    #[instrument(skip(self), fields(worker_id = %self.id_string, job_id = %job_id))]
    pub async fn report_job_failure(&self, job_id: &str, error: &str) -> Result<()> {
        let url = format!("{}/api/jobs/{}/fail",
            self.config.coordinator_url, job_id);

        let payload = serde_json::json!({
            "worker_id": self.id_string,
            "error": error,
        });

        let response = self.http_client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .context("Failed to report job failure")?;

        if !response.status().is_success() {
            warn!("Failed to report job failure: {}", response.status());
        }

        Ok(())
    }

    /// Send heartbeat to coordinator
    #[instrument(skip(self), fields(worker_id = %self.id_string))]
    pub async fn send_heartbeat(&self) -> Result<()> {
        let url = format!("{}/api/workers/{}/heartbeat",
            self.config.coordinator_url, self.id_string);

        let current_load = self.calculate_current_load().await;
        let active_job_ids: Vec<String> = self.active_jobs.read().await
            .keys()
            .map(|id| id.to_string())
            .collect();

        let payload = serde_json::json!({
            "worker_id": self.id_string,
            "current_load": current_load,
            "active_jobs": active_job_ids.len(),
            "active_job_ids": active_job_ids,
            "timestamp": Utc::now().to_rfc3339(),
            "health": self.health_status.read().await.clone(),
        });

        let response = self.http_client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .context("Failed to send heartbeat")?;

        if !response.status().is_success() {
            bail!("Heartbeat failed with status: {}", response.status());
        }

        *self.last_heartbeat.write().await = Some(Instant::now());
        self.send_event(WorkerEvent::HeartbeatSent);

        debug!("💓 Heartbeat sent (load: {:.2})", current_load);
        Ok(())
    }

    // ========================================================================
    // Job Execution
    // ========================================================================

    /// Check if worker can accept more jobs
    pub async fn can_accept_job(&self) -> bool {
        let current = self.active_jobs.read().await.len() as u32;
        current < self.config.max_concurrent_jobs
    }

    /// Check if worker can handle a specific job's requirements
    pub fn can_handle_job(&self, requirements: &JobRequirements) -> bool {
        // Check GPU requirements
        if requirements.min_gpu_count > 0 {
            if self.capabilities.gpu_count < requirements.min_gpu_count as u32 {
                return false;
            }
            let vram_mb = self.capabilities.gpu_memory_gb * 1024;
            if vram_mb < requirements.min_vram_mb as u32 {
                return false;
            }
        }

        // Check TEE requirements
        if requirements.requires_tee && self.capabilities.tee_type == TeeType::None {
            return false;
        }

        true
    }

    /// Spawn a job execution task
    fn spawn_job_execution(&self, job: serde_json::Value) {
        let job_id_str = job.get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let job_id = job_id_str.parse::<uuid::Uuid>()
            .map(JobId::from)
            .unwrap_or_else(|_| JobId::new());

        let job_type = job.get("requirements")
            .and_then(|r| r.get("required_job_type"))
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown")
            .to_string();

        info!("📥 Received job: {} (type: {})", job_id_str, job_type);
        self.send_event(WorkerEvent::JobReceived(job_id));

        // Clone necessary state for the spawned task
        let executor = self.job_executor.clone();
        let active_jobs = self.active_jobs.clone();
        let stats = self.stats.clone();
        let event_sender = self.event_sender.clone();
        let coordinator_url = self.config.coordinator_url.clone();
        let http_client = self.http_client.clone();
        let worker_id = self.id_string.clone();

        // Track active job
        {
            let mut jobs = futures::executor::block_on(active_jobs.write());
            jobs.insert(job_id, ActiveJob {
                job_id,
                started_at: Instant::now(),
                job_type: job_type.clone(),
            });
        }

        tokio::spawn(async move {
            let _ = event_sender.send(WorkerEvent::JobStarted(job_id));

            // Build execution request
            let exec_request = match Self::build_execution_request(&job) {
                Ok(req) => req,
                Err(e) => {
                    error!("Failed to build execution request: {}", e);
                    active_jobs.write().await.remove(&job_id);
                    let _ = event_sender.send(WorkerEvent::JobFailed(job_id, e.to_string()));
                    return;
                }
            };

            // Execute job
            let start_time = Instant::now();
            match executor.execute(exec_request).await {
                Ok(result) => {
                    let execution_time_ms = start_time.elapsed().as_millis() as u64;
                    info!("✅ Job {} completed in {}ms", job_id_str, execution_time_ms);

                    // Update stats
                    {
                        let mut stats = stats.write().await;
                        stats.record_success(execution_time_ms, result.result_data.len() as u64);
                    }

                    // Report completion
                    if let Err(e) = Self::report_completion_static(
                        &http_client, &coordinator_url, &job_id_str, &worker_id, &result
                    ).await {
                        error!("Failed to report completion: {}", e);
                    }

                    let _ = event_sender.send(WorkerEvent::JobCompleted(job_id, execution_time_ms));
                }
                Err(e) => {
                    error!("❌ Job {} failed: {}", job_id_str, e);

                    // Update stats
                    {
                        let mut stats = stats.write().await;
                        stats.record_failure();
                    }

                    // Report failure
                    if let Err(report_err) = Self::report_failure_static(
                        &http_client, &coordinator_url, &job_id_str, &worker_id, &e.to_string()
                    ).await {
                        error!("Failed to report failure: {}", report_err);
                    }

                    let _ = event_sender.send(WorkerEvent::JobFailed(job_id, e.to_string()));
                }
            }

            // Remove from active jobs
            active_jobs.write().await.remove(&job_id);
        });
    }

    /// Build job execution request from JSON
    fn build_execution_request(job: &serde_json::Value) -> Result<JobExecutionRequest> {
        let job_id = job.get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let job_type = job.get("requirements")
            .and_then(|r| r.get("required_job_type"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let payload = job.get("payload")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter()
                .filter_map(|v| v.as_u64().map(|n| n as u8))
                .collect())
            .unwrap_or_default();

        let requirements: JobRequirements = job.get("requirements")
            .cloned()
            .map(|r| serde_json::from_value(r).unwrap_or_default())
            .unwrap_or_default();

        let priority = job.get("priority")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u8;

        Ok(JobExecutionRequest {
            job_id,
            job_type,
            payload,
            requirements,
            priority,
        })
    }

    /// Static version of report_completion for use in spawned tasks
    async fn report_completion_static(
        client: &reqwest::Client,
        coordinator_url: &str,
        job_id: &str,
        worker_id: &str,
        result: &JobExecutionResult,
    ) -> Result<()> {
        let url = format!("{}/api/jobs/{}/complete", coordinator_url, job_id);

        let payload = serde_json::json!({
            "worker_id": worker_id,
            "result": result.result_data,
            "output_hash": result.output_hash,
            "execution_time_ms": result.execution_time_ms,
            "tee_attestation": result.tee_attestation,
        });

        let response = client.post(&url).json(&payload).send().await?;

        if !response.status().is_success() {
            bail!("Failed to report completion: {}", response.status());
        }

        Ok(())
    }

    /// Static version of report_failure for use in spawned tasks
    async fn report_failure_static(
        client: &reqwest::Client,
        coordinator_url: &str,
        job_id: &str,
        worker_id: &str,
        error: &str,
    ) -> Result<()> {
        let url = format!("{}/api/jobs/{}/fail", coordinator_url, job_id);

        let payload = serde_json::json!({
            "worker_id": worker_id,
            "error": error,
        });

        let _ = client.post(&url).json(&payload).send().await;
        Ok(())
    }

    // ========================================================================
    // Background Tasks
    // ========================================================================

    /// Spawn heartbeat background task
    fn spawn_heartbeat_task(&self) -> tokio::task::JoinHandle<()> {
        let running = self.running.clone();
        let interval = Duration::from_secs(self.config.heartbeat_interval_secs);
        let coordinator_url = self.config.coordinator_url.clone();
        let worker_id = self.id_string.clone();
        let http_client = self.http_client.clone();
        let active_jobs = self.active_jobs.clone();
        let health_status = self.health_status.clone();
        let event_sender = self.event_sender.clone();
        let max_concurrent = self.config.max_concurrent_jobs;

        tokio::spawn(async move {
            while *running.read().await {
                tokio::time::sleep(interval).await;

                if !*running.read().await {
                    break;
                }

                // Calculate current load
                let current_jobs = active_jobs.read().await.len() as f32;
                let current_load = current_jobs / max_concurrent as f32;

                let active_job_ids: Vec<String> = active_jobs.read().await
                    .keys()
                    .map(|id| id.to_string())
                    .collect();

                let url = format!("{}/api/workers/{}/heartbeat", coordinator_url, worker_id);

                let payload = serde_json::json!({
                    "worker_id": worker_id,
                    "current_load": current_load,
                    "active_jobs": active_job_ids.len(),
                    "active_job_ids": active_job_ids,
                    "timestamp": Utc::now().to_rfc3339(),
                    "health": health_status.read().await.clone(),
                });

                match http_client.post(&url).json(&payload).send().await {
                    Ok(response) if response.status().is_success() => {
                        debug!("💓 Heartbeat sent");
                        let _ = event_sender.send(WorkerEvent::HeartbeatSent);
                    }
                    Ok(response) => {
                        warn!("Heartbeat returned status: {}", response.status());
                        let _ = event_sender.send(WorkerEvent::HeartbeatFailed(
                            format!("Status: {}", response.status())
                        ));
                    }
                    Err(e) => {
                        warn!("Heartbeat failed: {}", e);
                        let _ = event_sender.send(WorkerEvent::HeartbeatFailed(e.to_string()));
                    }
                }
            }
        })
    }

    /// Spawn health monitoring background task
    fn spawn_health_monitoring_task(&self) -> tokio::task::JoinHandle<()> {
        let running = self.running.clone();
        let health_status = self.health_status.clone();
        let active_jobs = self.active_jobs.clone();
        let event_sender = self.event_sender.clone();
        let max_concurrent = self.config.max_concurrent_jobs;

        tokio::spawn(async move {
            let interval = Duration::from_secs(10);

            while *running.read().await {
                tokio::time::sleep(interval).await;

                if !*running.read().await {
                    break;
                }

                // Update health status
                let current_jobs = active_jobs.read().await.len() as f32;
                let load = current_jobs / max_concurrent as f32;

                let mut status = health_status.write().await;
                status.cpu_load = load; // Simplified - use actual system metrics in production
                status.gpu_load = load;
                status.overall_score = 1.0 - (load * 0.5);
                status.is_healthy = status.overall_score > 0.3;
                status.last_check = Utc::now();

                let _ = event_sender.send(WorkerEvent::HealthUpdated(load));
            }
        })
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// Calculate current load (0.0 - 1.0)
    pub async fn calculate_current_load(&self) -> f32 {
        let current_jobs = self.active_jobs.read().await.len() as f32;
        (current_jobs / self.config.max_concurrent_jobs as f32).min(1.0)
    }

    /// Build capabilities payload for coordinator
    fn build_capabilities_payload(&self) -> serde_json::Value {
        let caps = &self.capabilities;

        serde_json::json!({
            "cpu_cores": caps.cpu_cores,
            "ram_mb": caps.ram_gb * 1024,
            "gpus": if caps.gpu_count > 0 {
                vec![serde_json::json!({
                    "name": caps.gpu_model,
                    "vram_mb": caps.gpu_memory_gb * 1024,
                    "cuda_cores": 10000,
                    "tensor_cores": 300,
                    "driver_version": "535.129.03",
                    "has_tee": caps.gpu_tee_support,
                })]
            } else {
                vec![]
            },
            "bandwidth_mbps": 1000,
            "supported_job_types": caps.supported_job_types.clone(),
            "tee_cpu": matches!(caps.tee_type, TeeType::CpuOnly | TeeType::Full),
            "max_concurrent_jobs": caps.max_concurrent_jobs,
            "disk_gb": caps.disk_gb,
        })
    }

    /// Send an event (non-blocking)
    fn send_event(&self, event: WorkerEvent) {
        if let Err(e) = self.event_sender.send(event) {
            debug!("Failed to send event: {}", e);
        }
    }
}

// ============================================================================
// Default JobRequirements
// ============================================================================

impl Default for JobRequirements {
    fn default() -> Self {
        Self {
            min_vram_mb: 0,
            min_gpu_count: 0,
            required_job_type: "Generic".to_string(),
            timeout_seconds: 3600,
            requires_tee: false,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_capabilities() -> WorkerCapabilities {
        WorkerCapabilities {
            gpu_count: 1,
            gpu_memory_gb: 8,
            gpu_model: "Test GPU".to_string(),
            tee_type: TeeType::None,
            gpu_tee_support: false,
            cpu_cores: 8,
            ram_gb: 16,
            disk_gb: 100,
            max_concurrent_jobs: 4,
            ..Default::default()
        }
    }

    #[test]
    fn test_worker_config_default() {
        let config = WorkerConfig::default();
        assert_eq!(config.poll_interval_secs, 5);
        assert_eq!(config.heartbeat_interval_secs, 30);
        assert_eq!(config.max_concurrent_jobs, 4);
    }

    #[test]
    fn test_worker_stats_recording() {
        let mut stats = WorkerStats::default();

        stats.record_success(1000, 1024);
        assert_eq!(stats.total_jobs_executed, 1);
        assert_eq!(stats.successful_jobs, 1);
        assert_eq!(stats.avg_execution_time_ms, 1000);

        stats.record_success(2000, 2048);
        assert_eq!(stats.total_jobs_executed, 2);
        assert_eq!(stats.avg_execution_time_ms, 1500);

        stats.record_failure();
        assert_eq!(stats.total_jobs_executed, 3);
        assert_eq!(stats.failed_jobs, 1);
        assert!((stats.success_rate() - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_worker_creation() {
        let config = WorkerConfig::default();
        let capabilities = create_test_capabilities();

        let worker = Worker::new(config, capabilities);
        assert!(worker.is_ok());

        let worker = worker.unwrap();
        assert_eq!(worker.capabilities().gpu_count, 1);
    }

    #[test]
    fn test_can_handle_job_gpu_requirements() {
        let config = WorkerConfig::default();
        let capabilities = create_test_capabilities();
        let worker = Worker::new(config, capabilities).unwrap();

        // Can handle job with lower requirements
        let requirements = JobRequirements {
            min_gpu_count: 1,
            min_vram_mb: 4096,
            ..Default::default()
        };
        assert!(worker.can_handle_job(&requirements));

        // Cannot handle job with higher GPU requirements
        let requirements = JobRequirements {
            min_gpu_count: 2,
            min_vram_mb: 4096,
            ..Default::default()
        };
        assert!(!worker.can_handle_job(&requirements));
    }

    #[test]
    fn test_can_handle_job_tee_requirements() {
        let config = WorkerConfig::default();
        let mut capabilities = create_test_capabilities();
        capabilities.tee_type = TeeType::None;
        let worker = Worker::new(config, capabilities).unwrap();

        // Cannot handle TEE-required job without TEE
        let requirements = JobRequirements {
            requires_tee: true,
            ..Default::default()
        };
        assert!(!worker.can_handle_job(&requirements));
    }

    #[tokio::test]
    async fn test_worker_stats_async() {
        let config = WorkerConfig::default();
        let capabilities = create_test_capabilities();
        let worker = Worker::new(config, capabilities).unwrap();

        let stats = worker.get_stats().await;
        assert_eq!(stats.total_jobs_executed, 0);
        assert_eq!(stats.current_jobs, 0);
    }
}
