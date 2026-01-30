//! # Worker Node
//!
//! Worker nodes execute compute tasks assigned by coordinators.
//! This module provides a complete worker implementation with:
//! - Coordinator registration and communication
//! - Job polling and execution
//! - Health monitoring and heartbeat
//! - Graceful shutdown handling

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, Context, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock, watch};
use tracing::{info, warn, error, debug, instrument};

use crate::types::{WorkerId, JobId, WorkerCapabilities, TeeType};
use crate::compute::job_executor::{JobExecutor, JobExecutionRequest, JobExecutionResult, JobRequirements};
use crate::obelysk::worker_keys::WorkerKeyManager;
use crate::obelysk::privacy_client::WorkerPrivacyManager;
use crate::obelysk::privacy_swap::AssetId;
use crate::obelysk::proof_compression::CompressedProof;
use crate::obelysk::compute_invoice::ComputeInvoice;

// ============================================================================
// Payment Claim Types
// ============================================================================

/// Pending payment claim with proof data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingPaymentClaim {
    /// Job ID
    pub job_id: u128,
    /// Payment asset type (SAGE, USDC, etc.)
    pub asset_id: AssetId,
    /// Payment amount in base units
    pub amount: u128,
    /// Compressed proof for payment verification
    pub compressed_proof: Option<CompressedProof>,
    /// Proof hash (Blake3)
    pub proof_hash: Option<[u8; 32]>,
    /// Proof attestation
    pub proof_attestation: Option<[u8; 32]>,
    /// Proof commitment
    pub proof_commitment: Option<[u8; 32]>,
    /// Timestamp when claim was queued
    pub queued_at: u64,
    /// Number of times this claim has been retried
    #[serde(default)]
    pub retry_count: u32,
}

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

    // ========== Privacy Payment Configuration ==========

    /// Enable privacy payments (requires Starknet RPC)
    pub enable_privacy_payments: bool,
    /// Starknet RPC URL for privacy operations
    pub starknet_rpc_url: Option<String>,
    /// Private key for Starknet account (hex without 0x prefix)
    pub starknet_private_key: Option<String>,
    /// Starknet account address
    pub starknet_account_address: Option<String>,
    /// Path to privacy keystore file
    pub privacy_keystore_path: Option<PathBuf>,
    /// Secret for key derivation (should be securely stored)
    pub privacy_key_secret: Option<String>,
    /// Auto-register privacy account on startup
    pub auto_register_privacy: bool,
    /// Payment claim interval in seconds
    pub payment_claim_interval_secs: u64,
    /// Max batch size for payment claims
    pub payment_claim_batch_size: usize,

    /// vLLM endpoint URL (e.g. "http://localhost:8000") for real inference
    pub vllm_endpoint: Option<String>,

    /// X25519 encryption public key for E2E encrypted job communication
    #[serde(default)]
    pub encryption_pubkey: Option<[u8; 32]>,

    /// X25519 encryption secret key (raw bytes, for EncryptedJobManager initialization)
    /// Must correspond to encryption_pubkey. If None but encryption_pubkey is Some,
    /// a new ephemeral secret is generated (not recommended for production).
    #[serde(skip)]
    pub encryption_secret: Option<[u8; 32]>,

    /// Automatically claim SAGE from the faucet on startup and periodically
    pub auto_claim_rewards: bool,
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
            // Privacy payment defaults
            enable_privacy_payments: false,
            starknet_rpc_url: None,
            starknet_private_key: None,
            starknet_account_address: None,
            privacy_keystore_path: None,
            privacy_key_secret: None,
            auto_register_privacy: true,
            payment_claim_interval_secs: 30,
            payment_claim_batch_size: 10,
            vllm_endpoint: None,
            encryption_pubkey: None,
            encryption_secret: None,
            auto_claim_rewards: false,
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

    // Privacy payment management
    /// Privacy key manager for ElGamal operations
    key_manager: Option<Arc<WorkerKeyManager>>,
    /// Privacy manager for claiming encrypted payments (initialized async in start())
    privacy_manager: Arc<RwLock<Option<Arc<WorkerPrivacyManager>>>>,
    /// Queue of (job_id, asset_id) pairs pending payment claim
    pending_payment_claims: Arc<RwLock<VecDeque<PendingPaymentClaim>>>,
    /// Track claimed payments per asset to avoid duplicates: job_id -> set of claimed assets
    claimed_payments: Arc<RwLock<HashMap<u128, HashSet<AssetId>>>>,
    /// Shutdown signal sender for payment claim loop
    shutdown_tx: Arc<RwLock<Option<watch::Sender<bool>>>>,
    /// Optional database pool for invoice persistence
    db: Option<sqlx::PgPool>,
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
        let mut executor = JobExecutor::new(id_string.clone(), has_tee);
        if let Some(ref endpoint) = config.vllm_endpoint {
            executor.set_vllm_endpoint(endpoint.clone());
        }

        // Wire wallet address from config
        if let Some(ref wallet) = config.wallet_address {
            executor.set_wallet(wallet.clone());
        }

        // Wire GPU model, tier, and hourly rate from detected capabilities
        if capabilities.gpu_count > 0 && !capabilities.gpu_model.is_empty() {
            executor.set_gpu_model(capabilities.gpu_model.clone());
            executor.set_gpu_tier(gpu_tier_from_model(&capabilities.gpu_model));
            executor.set_hourly_rate(hourly_rate_for_tier(&capabilities.gpu_model));
        }

        // Wire E2E encryption if encryption pubkey is configured
        if config.encryption_pubkey.is_some() {
            use crate::network::encrypted_jobs::{EncryptedJobConfig, EncryptedJobManager, X25519SecretKey};

            // Use the persistent secret key if provided, otherwise EncryptedJobManager
            // will generate an ephemeral one (which won't match the published pubkey)
            let node_secret = config.encryption_secret
                .map(X25519SecretKey::from_bytes);

            let enc_config = EncryptedJobConfig {
                node_secret,
                ..EncryptedJobConfig::default()
            };
            let enc_manager = EncryptedJobManager::new(enc_config);
            executor.set_encryption_manager(std::sync::Arc::new(enc_manager));
            executor.set_tee_enforced(has_tee);
            info!("🔐 E2E encryption wired to job executor (persistent key: {}, TEE enforced: {})",
                config.encryption_secret.is_some(), has_tee);
        }

        let job_executor = Arc::new(executor);

        // Create event channel
        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        // Initialize privacy key manager if enabled
        let key_manager = if config.enable_privacy_payments {
            let keystore_path = config.privacy_keystore_path.clone()
                .unwrap_or_else(|| PathBuf::from(format!(".privacy_keys/{}.key", id_string)));

            let secret = config.privacy_key_secret.as_ref()
                .map(|s| s.as_bytes().to_vec())
                .unwrap_or_else(|| id_string.as_bytes().to_vec());

            match WorkerKeyManager::load_or_generate(&id_string, &secret, &keystore_path) {
                Ok(manager) => {
                    info!("🔐 Privacy key manager initialized for worker {}", id_string);
                    Some(Arc::new(manager))
                }
                Err(e) => {
                    warn!("Failed to initialize privacy key manager: {}", e);
                    None
                }
            }
        } else {
            None
        };

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
            // Privacy fields
            key_manager,
            privacy_manager: Arc::new(RwLock::new(None)), // Initialized async in start()
            pending_payment_claims: Arc::new(RwLock::new(VecDeque::new())),
            claimed_payments: Arc::new(RwLock::new(HashMap::new())),
            shutdown_tx: Arc::new(RwLock::new(None)),
            db: None,
        })
    }

    /// Set a database pool for invoice persistence
    pub fn set_db(&mut self, pool: sqlx::PgPool) {
        self.db = Some(pool);
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
    /// 1. Initializes privacy payment system if enabled
    /// 2. Registers with the coordinator
    /// 3. Spawns background tasks for heartbeat, health monitoring, and payment claims
    /// 4. Enters the main job polling loop
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

        // Initialize privacy payment system if enabled
        let payment_claim_handle = if self.config.enable_privacy_payments {
            self.initialize_privacy_payments().await
        } else {
            None
        };

        // Attempt initial faucet claim if enabled
        if self.config.auto_claim_rewards && self.config.wallet_address.is_some() {
            self.claim_faucet_sage().await;
        }

        // Register with coordinator
        self.register_with_retries().await?;

        // Send started event
        self.send_event(WorkerEvent::Started);

        // Spawn heartbeat task
        let heartbeat_handle = self.spawn_heartbeat_task();

        // Spawn health monitoring task
        let health_handle = self.spawn_health_monitoring_task();

        // Spawn periodic faucet claim task if enabled
        let faucet_handle = if self.config.auto_claim_rewards && self.config.wallet_address.is_some() {
            Some(self.spawn_faucet_claim_task())
        } else {
            None
        };

        info!("✅ Worker {} is running", self.id_string);
        info!("🔄 Polling coordinator for jobs...");

        // Main job polling loop
        let poll_result = self.run_polling_loop().await;

        // Signal shutdown for payment claim loop
        if let Some(tx) = self.shutdown_tx.write().await.take() {
            let _ = tx.send(true);
        }

        // Cancel background tasks
        heartbeat_handle.abort();
        health_handle.abort();
        if let Some(handle) = payment_claim_handle {
            handle.abort();
        }
        if let Some(handle) = faucet_handle {
            handle.abort();
        }

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

    /// Initialize privacy payment system
    ///
    /// Creates the PrivacyRouterClient and WorkerPrivacyManager,
    /// registers the privacy account, and spawns the payment claim loop.
    async fn initialize_privacy_payments(&self) -> Option<tokio::task::JoinHandle<()>> {
        let key_manager = match &self.key_manager {
            Some(km) => km.clone(),
            None => {
                warn!("Privacy payments enabled but no key manager available");
                return None;
            }
        };

        // Check required config (rpc_url reserved for future multi-network support)
        let (_rpc_url, private_key, account_address) = match (
            &self.config.starknet_rpc_url,
            &self.config.starknet_private_key,
            &self.config.starknet_account_address,
        ) {
            (Some(rpc), Some(pk), Some(addr)) => (rpc.clone(), pk.clone(), addr.clone()),
            _ => {
                warn!("Privacy payments enabled but Starknet config incomplete");
                info!("Required: starknet_rpc_url, starknet_private_key, starknet_account_address");
                return None;
            }
        };

        // Parse account address
        let account_fe = match starknet::core::types::FieldElement::from_hex_be(&account_address) {
            Ok(fe) => fe,
            Err(e) => {
                error!("Invalid Starknet account address: {}", e);
                return None;
            }
        };

        // Create privacy router client
        info!("🔐 Initializing privacy payment system...");
        let privacy_client = match crate::obelysk::privacy_client::PrivacyRouterClient::for_sepolia(
            &private_key,
            account_fe,
        ).await {
            Ok(client) => client,
            Err(e) => {
                error!("Failed to create privacy client: {}", e);
                return None;
            }
        };

        // Create privacy manager
        let privacy_manager = Arc::new(WorkerPrivacyManager::new(
            privacy_client,
            key_manager.keypair().secret_key,
        ));

        // Store privacy manager
        *self.privacy_manager.write().await = Some(privacy_manager.clone());

        // Auto-register privacy account if configured
        if self.config.auto_register_privacy {
            match privacy_manager.register().await {
                Ok(tx) => info!("✅ Registered privacy account: {:?}", tx),
                Err(e) => {
                    let error_msg = e.to_string();
                    if error_msg.contains("already registered") {
                        debug!("Privacy account already registered");
                    } else if error_msg.contains("ContractNotFound") || error_msg.contains("contract not found") {
                        warn!("Privacy router contract not deployed — skipping privacy registration");
                    } else {
                        warn!("Failed to register privacy account: {}", e);
                    }
                }
            }
        }

        // Create shutdown channel and spawn payment claim loop
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        *self.shutdown_tx.write().await = Some(shutdown_tx);

        let pending_claims = self.pending_payment_claims.clone();
        let claimed = self.claimed_payments.clone();
        let claim_interval = self.config.payment_claim_interval_secs;
        let batch_size = self.config.payment_claim_batch_size;

        let handle = tokio::spawn(async move {
            Self::run_payment_claim_loop(
                privacy_manager,
                pending_claims,
                claimed,
                shutdown_rx,
                claim_interval,
                batch_size,
            ).await;
        });

        info!("💰 Payment claim loop started (interval: {}s, batch: {})",
              claim_interval, batch_size);

        Some(handle)
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

        // Build base payload
        let mut payload = serde_json::json!({
            "worker_id": self.id_string,
            "capabilities": capabilities_payload,
            "wallet_address": self.config.wallet_address,
        });

        // Include privacy public key and signature if key manager is available
        if let Some(ref key_manager) = self.key_manager {
            let timestamp = chrono::Utc::now().timestamp() as u64;
            let signature = key_manager.sign_registration(timestamp);
            let public_key = key_manager.public_key();

            // Add privacy fields to payload
            if let Some(obj) = payload.as_object_mut() {
                obj.insert("privacy_public_key".to_string(), serde_json::to_value(&public_key)?);
                obj.insert("privacy_key_signature".to_string(), serde_json::to_value(&signature)?);
            }

            debug!("Including privacy public key in registration");
        }

        // Include X25519 encryption public key if configured
        if let Some(ref enc_pubkey) = self.config.encryption_pubkey {
            if let Some(obj) = payload.as_object_mut() {
                obj.insert("encryption_pubkey".to_string(), serde_json::to_value(enc_pubkey)?);
            }
            debug!("Including X25519 encryption pubkey in registration");
        }

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

        // Log whether privacy was enabled
        let response_json: serde_json::Value = response.json().await
            .unwrap_or_else(|_| serde_json::json!({}));
        if response_json.get("privacy_enabled").and_then(|v| v.as_bool()).unwrap_or(false) {
            info!("Registered with coordinator (privacy payments enabled)");
        } else {
            info!("Registered with coordinator");
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
        let url = format!("{}/api/workers/heartbeat",
            self.config.coordinator_url);

        let current_load = self.calculate_current_load().await;
        let active_jobs_info: Vec<serde_json::Value> = self.active_jobs.read().await
            .iter()
            .map(|(id, job)| {
                serde_json::json!({
                    "job_id": id.to_string(),
                    "job_type": job.job_type,
                    "running_secs": job.started_at.elapsed().as_secs(),
                })
            })
            .collect();

        let payload = serde_json::json!({
            "worker_id": self.id_string,
            "current_load": current_load,
            "active_jobs": active_jobs_info.len(),
            "active_job_details": active_jobs_info,
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
        let pending_payment_claims = self.pending_payment_claims.clone();
        let enable_privacy_payments = self.config.enable_privacy_payments;
        let db_pool = self.db.clone();

        // Track active job
        {
            let mut jobs = futures::executor::block_on(active_jobs.write());
            jobs.insert(job_id, ActiveJob {
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

                    // Persist invoice to database if available
                    if let (Some(ref invoice), Some(ref db)) = (&result.invoice, &db_pool) {
                        Self::persist_invoice(db, invoice).await;
                    }

                    // Queue job for payment claim if privacy payments enabled
                    if enable_privacy_payments {
                        if let Some(job_id_u128) = Self::parse_job_id_to_u128(&job_id_str) {
                            // Extract payment asset from job metadata, default to SAGE
                            let asset_id = job.get("payment_token")
                                .and_then(|v| v.as_str())
                                .map(|s| Self::parse_asset_id_from_string(s))
                                .unwrap_or(AssetId::SAGE);

                            // Extract payment amount from job metadata (default to 100 SAGE if not specified)
                            let amount = job.get("payment_amount")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(100_000_000_000_000_000) as u128; // 0.1 SAGE default

                            // Create payment claim with proof data
                            let claim = PendingPaymentClaim {
                                job_id: job_id_u128,
                                asset_id,
                                amount,
                                compressed_proof: result.compressed_proof.clone(),
                                proof_hash: result.proof_hash,
                                proof_attestation: result.proof_attestation,
                                proof_commitment: result.proof_commitment,
                                queued_at: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                                retry_count: 0,
                            };

                            pending_payment_claims.write().await.push_back(claim);
                            info!("💰 Queued job {} for payment claim (asset: {}, with_proof: {})",
                                  job_id_u128,
                                  asset_id.name(),
                                  result.proof_hash.is_some());
                        }
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

        let payload: Vec<u8> = job.get("payload")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter()
                .filter_map(|v| v.as_u64().map(|n| n as u8))
                .collect::<Vec<u8>>())
            .unwrap_or_default();

        let requirements: JobRequirements = job.get("requirements")
            .cloned()
            .map(|r| serde_json::from_value(r).unwrap_or_default())
            .unwrap_or_default();

        let priority = job.get("priority")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u8;

        // Extract customer_pubkey for E2E encrypted inference
        // It can be either a top-level field on the job or embedded in the payload JSON
        let customer_pubkey = job.get("customer_pubkey")
            .and_then(|v| {
                // Try as array of bytes
                if let Some(arr) = v.as_array() {
                    let bytes: Vec<u8> = arr.iter()
                        .filter_map(|b| b.as_u64().map(|n| n as u8))
                        .collect();
                    if bytes.len() == 32 {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&bytes);
                        return Some(key);
                    }
                }
                None
            })
            .or_else(|| {
                // Also check inside payload JSON (model_inference embeds it there)
                let payload_json: serde_json::Value = serde_json::from_slice(&payload).ok()?;
                payload_json.get("customer_pubkey")
                    .and_then(|v| v.as_array())
                    .and_then(|arr| {
                        let bytes: Vec<u8> = arr.iter()
                            .filter_map(|b| b.as_u64().map(|n| n as u8))
                            .collect();
                        if bytes.len() == 32 {
                            let mut key = [0u8; 32];
                            key.copy_from_slice(&bytes);
                            Some(key)
                        } else {
                            None
                        }
                    })
            });

        Ok(JobExecutionRequest {
            job_id,
            job_type,
            payload,
            requirements,
            priority,
            customer_pubkey,
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
            // Proof data for on-chain verification
            "proof_hash": result.proof_hash.map(hex::encode),
            "proof_commitment": result.proof_commitment.map(hex::encode),
            "proof_size_bytes": result.compressed_proof.as_ref().map(|p| p.compressed_size()),
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

                // Calculate current load and gather job details
                let jobs_guard = active_jobs.read().await;
                let current_jobs = jobs_guard.len() as f32;
                let current_load = current_jobs / max_concurrent as f32;

                let active_jobs_info: Vec<serde_json::Value> = jobs_guard
                    .iter()
                    .map(|(id, job)| {
                        serde_json::json!({
                            "job_id": id.to_string(),
                            "job_type": job.job_type,
                            "running_secs": job.started_at.elapsed().as_secs(),
                        })
                    })
                    .collect();
                drop(jobs_guard);

                let url = format!("{}/api/workers/heartbeat", coordinator_url);

                let payload = serde_json::json!({
                    "worker_id": worker_id,
                    "current_load": current_load,
                    "active_jobs": active_jobs_info.len(),
                    "active_job_details": active_jobs_info,
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
            "gpu_uuids": caps.gpu_uuids,
        })
    }

    /// Send an event (non-blocking)
    fn send_event(&self, event: WorkerEvent) {
        if let Err(e) = self.event_sender.send(event) {
            debug!("Failed to send event: {}", e);
        }
    }

    // ========================================================================
    // Faucet Claim Methods
    // ========================================================================

    /// Claim SAGE from the coordinator's faucet endpoint.
    /// Non-fatal: logs result but never blocks startup.
    async fn claim_faucet_sage(&self) {
        let wallet = match &self.config.wallet_address {
            Some(w) => w.clone(),
            None => return,
        };

        let url = format!("{}/api/faucet/claim", self.config.coordinator_url);

        let payload = serde_json::json!({
            "address": wallet,
        });

        match self.http_client.post(&url).json(&payload).send().await {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<serde_json::Value>().await {
                    Ok(body) => {
                        let amount = body.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
                        let tx_hash = body.get("transaction_hash").and_then(|v| v.as_str()).unwrap_or("unknown");
                        info!("Claimed {} SAGE from faucet (tx: {})", amount, tx_hash);
                    }
                    Err(e) => {
                        info!("Faucet claim response parse error: {}", e);
                    }
                }
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                if body.contains("cooldown") || body.contains("wait") {
                    debug!("Faucet cooldown active: {}", body);
                } else {
                    warn!("Faucet claim failed ({}): {}", status, body);
                }
            }
            Err(e) => {
                warn!("Faucet claim request failed: {}", e);
            }
        }
    }

    /// Spawn a background task that re-claims from the faucet every 24 hours.
    fn spawn_faucet_claim_task(&self) -> tokio::task::JoinHandle<()> {
        let running = self.running.clone();
        let http_client = self.http_client.clone();
        let coordinator_url = self.config.coordinator_url.clone();
        let wallet_address = self.config.wallet_address.clone().unwrap_or_default();

        tokio::spawn(async move {
            let interval = Duration::from_secs(24 * 60 * 60);

            loop {
                tokio::time::sleep(interval).await;

                if !*running.read().await {
                    break;
                }

                let url = format!("{}/api/faucet/claim", coordinator_url);
                let payload = serde_json::json!({ "address": wallet_address });

                match http_client.post(&url).json(&payload).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(body) = resp.json::<serde_json::Value>().await {
                            let amount = body.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
                            let tx_hash = body.get("transaction_hash").and_then(|v| v.as_str()).unwrap_or("unknown");
                            info!("Periodic faucet claim: {} SAGE (tx: {})", amount, tx_hash);
                        }
                    }
                    Ok(resp) => {
                        debug!("Periodic faucet claim not available: {}", resp.status());
                    }
                    Err(e) => {
                        warn!("Periodic faucet claim failed: {}", e);
                    }
                }
            }
        })
    }

    // ========================================================================
    // Privacy Payment Methods
    // ========================================================================

    /// Parse job ID string to u128 for payment system
    ///
    /// Attempts to parse as UUID and convert to u128, or as direct u128.
    fn parse_job_id_to_u128(job_id_str: &str) -> Option<u128> {
        // Try parsing as UUID first
        if let Ok(uuid) = job_id_str.parse::<uuid::Uuid>() {
            return Some(uuid.as_u128());
        }

        // Try parsing as hex
        if job_id_str.starts_with("0x") {
            if let Ok(val) = u128::from_str_radix(&job_id_str[2..], 16) {
                return Some(val);
            }
        }

        // Try parsing as decimal
        job_id_str.parse::<u128>().ok()
    }

    /// Parse asset ID from string (from job metadata)
    ///
    /// Accepts various formats:
    /// - Token names: "SAGE", "sage", "USDC", "STRK", "BTC"
    /// - Numeric IDs: "0", "1", "2", "3"
    fn parse_asset_id_from_string(s: &str) -> AssetId {
        match s.to_uppercase().as_str() {
            "SAGE" | "0" => AssetId::SAGE,
            "USDC" | "1" => AssetId::USDC,
            "STRK" | "2" => AssetId::STRK,
            "BTC" | "WBTC" | "3" => AssetId::BTC,
            "ETH" | "4" => AssetId::ETH,
            _ => {
                warn!("Unknown payment token '{}', defaulting to SAGE", s);
                AssetId::SAGE
            }
        }
    }

    /// Run the payment claim loop in the background
    ///
    /// This loop periodically checks for pending payments and claims them.
    /// Supports multi-asset payments where each payment is identified by (job_id, asset_id).
    async fn run_payment_claim_loop(
        privacy_manager: Arc<WorkerPrivacyManager>,
        pending_claims: Arc<RwLock<VecDeque<PendingPaymentClaim>>>,
        claimed: Arc<RwLock<HashMap<u128, HashSet<AssetId>>>>,
        mut shutdown_rx: watch::Receiver<bool>,
        claim_interval_secs: u64,
        batch_size: usize,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(claim_interval_secs));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    Self::process_pending_claims(
                        &privacy_manager,
                        &pending_claims,
                        &claimed,
                        batch_size,
                    ).await;
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("💰 Payment claim loop shutting down");
                        break;
                    }
                }
            }
        }
    }

    /// Process pending payment claims with proof verification
    ///
    /// Claims payments using proof-gated submission. Each claim includes
    /// the compressed proof which is verified on-chain before payment release.
    /// Falls back to non-proof claims if proof data is missing (for backwards compatibility).
    async fn process_pending_claims(
        manager: &WorkerPrivacyManager,
        pending: &RwLock<VecDeque<PendingPaymentClaim>>,
        claimed: &RwLock<HashMap<u128, HashSet<AssetId>>>,
        batch_size: usize,
    ) {
        // Collect batch of pending claims
        let batch: Vec<PendingPaymentClaim> = {
            let mut pending_guard = pending.write().await;
            let mut batch = Vec::with_capacity(batch_size);

            while batch.len() < batch_size {
                if let Some(claim) = pending_guard.pop_front() {
                    // Skip if already claimed for this asset
                    let already_claimed = claimed.read().await
                        .get(&claim.job_id)
                        .map(|assets| assets.contains(&claim.asset_id))
                        .unwrap_or(false);

                    if !already_claimed {
                        batch.push(claim);
                    }
                } else {
                    break;
                }
            }
            batch
        };

        if batch.is_empty() {
            return;
        }

        info!("💰 Processing {} pending payment claims (with proofs)", batch.len());

        // Process claims individually with proof verification
        // Note: Batch claiming with proofs requires aggregated proof, not yet implemented
        for claim in batch {
            // Try proof-gated claim if proof data is available
            let result = if let Some(ref compressed_proof) = claim.compressed_proof {
                info!("🔐 Claiming payment for job {} with proof verification", claim.job_id);
                manager.claim_payment_with_proof(
                    claim.job_id,
                    claim.asset_id,
                    claim.amount,
                    compressed_proof
                ).await
            } else {
                // Fall back to regular claim if no proof (backwards compatibility)
                warn!("⚠️ No proof data for job {}, using legacy claim", claim.job_id);
                manager.claim_payment_for_asset(claim.job_id, claim.asset_id).await
            };

            match result {
                Ok(tx_hash) => {
                    info!("✅ Claimed {} payment for job {}: tx={:?} (proof_verified: {})",
                          claim.asset_id.name(),
                          claim.job_id,
                          tx_hash,
                          claim.compressed_proof.is_some());
                    claimed.write().await
                        .entry(claim.job_id)
                        .or_insert_with(HashSet::new)
                        .insert(claim.asset_id);
                }
                Err(e) => {
                    let error_msg = e.to_string();
                    if error_msg.contains("already claimed") || error_msg.contains("Payment already claimed") {
                        debug!("Payment for job {} ({}) already claimed", claim.job_id, claim.asset_id.name());
                        claimed.write().await
                            .entry(claim.job_id)
                            .or_insert_with(HashSet::new)
                            .insert(claim.asset_id);
                    } else if error_msg.contains("not found") || error_msg.contains("no payment") {
                        if claim.retry_count == 0 {
                            warn!("No {} payment found for job {} (may not be ready yet)",
                                  claim.asset_id.name(), claim.job_id);
                        } else {
                            debug!("No {} payment found for job {} (retry {})",
                                   claim.asset_id.name(), claim.job_id, claim.retry_count);
                        }
                        Self::requeue_with_limits(pending, claim).await;
                    } else if error_msg.contains("Proof verification failed") || error_msg.contains("Invalid proof") {
                        warn!("❌ Proof verification failed for job {}: {}",
                              claim.job_id, e);
                        // Do not re-queue - proof is invalid
                    } else {
                        warn!("Failed to claim {} payment for job {}: {}",
                              claim.asset_id.name(), claim.job_id, e);
                        Self::requeue_with_limits(pending, claim).await;
                    }
                }
            }
        }
    }

    /// Persist a compute invoice to the database
    async fn persist_invoice(db: &sqlx::PgPool, invoice: &ComputeInvoice) {
        let result = sqlx::query(
            "INSERT INTO invoices (id, job_id, worker_id, worker_wallet, job_type, circuit_type, \
             total_cost_cents, worker_payment_cents, protocol_fee_cents, sage_to_worker, \
             gpu_seconds, gpu_model, proof_hash, proof_size_bytes, proof_time_ms, status) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) \
             ON CONFLICT (job_id, worker_id) DO NOTHING"
        )
        .bind(&invoice.invoice_id)
        .bind(&invoice.job_id)
        .bind(&invoice.worker_id)
        .bind(&invoice.worker_wallet)
        .bind(&invoice.job_type)
        .bind(invoice.circuit_type.name())
        .bind(invoice.total_cost_cents as i64)
        .bind(invoice.worker_payment_cents as i64)
        .bind(invoice.protocol_fee_cents as i64)
        .bind(invoice.sage_to_worker as i64)
        .bind(invoice.gpu_seconds)
        .bind(&invoice.gpu_model)
        .bind(hex::encode(invoice.proof_hash))
        .bind(invoice.proof_size_bytes as i64)
        .bind(invoice.proof_time_ms as i64)
        .bind(format!("{:?}", invoice.status))
        .execute(db)
        .await;

        match result {
            Ok(_) => info!("📜 Invoice {} persisted to database", invoice.invoice_id),
            Err(e) => warn!("Failed to persist invoice {}: {}", invoice.invoice_id, e),
        }
    }

    /// Re-queue a payment claim with retry and TTL limits
    async fn requeue_with_limits(
        pending: &RwLock<VecDeque<PendingPaymentClaim>>,
        claim: PendingPaymentClaim,
    ) {
        const MAX_CLAIM_RETRIES: u32 = 3;
        const CLAIM_TTL_SECS: u64 = 3600;

        let mut claim = claim;
        claim.retry_count += 1;

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let age = now_secs.saturating_sub(claim.queued_at);

        if claim.retry_count > MAX_CLAIM_RETRIES || age > CLAIM_TTL_SECS {
            info!("Abandoning payment claim for job {} after {} retries ({}s old)",
                  claim.job_id, claim.retry_count, age);
        } else {
            pending.write().await.push_back(claim);
        }
    }

    /// Get count of pending payment claims
    pub async fn pending_payment_count(&self) -> usize {
        self.pending_payment_claims.read().await.len()
    }

    /// Get count of claimed payments (total across all jobs and assets)
    pub async fn claimed_payment_count(&self) -> usize {
        self.claimed_payments.read().await
            .values()
            .map(|assets| assets.len())
            .sum()
    }

    /// Check if privacy payments are enabled
    pub fn is_privacy_payments_enabled(&self) -> bool {
        self.config.enable_privacy_payments && self.key_manager.is_some()
    }

    /// Get worker's privacy public key (if enabled)
    pub fn privacy_public_key(&self) -> Option<crate::obelysk::elgamal::ECPoint> {
        self.key_manager.as_ref().map(|km| km.public_key())
    }
}

// ============================================================================
// GPU Tier and Pricing Helpers
// ============================================================================

/// Map GPU model name to a tier classification
fn gpu_tier_from_model(model: &str) -> String {
    let model_upper = model.to_uppercase();
    if model_upper.contains("H100") || model_upper.contains("H200") || model_upper.contains("B200") {
        "Enterprise".to_string()
    } else if model_upper.contains("A100") || model_upper.contains("A800") {
        "Professional".to_string()
    } else if model_upper.contains("L40") || model_upper.contains("A6000") {
        "Workstation".to_string()
    } else if model_upper.contains("4090") || model_upper.contains("3090") || model_upper.contains("4080") {
        "Consumer-High".to_string()
    } else {
        "Standard".to_string()
    }
}

/// Map GPU model name to an hourly rate in cents
fn hourly_rate_for_tier(model: &str) -> u64 {
    let model_upper = model.to_uppercase();
    if model_upper.contains("H100") || model_upper.contains("H200") || model_upper.contains("B200") {
        300 // $3.00/hr
    } else if model_upper.contains("A100") || model_upper.contains("A800") {
        200 // $2.00/hr
    } else if model_upper.contains("L40") || model_upper.contains("A6000") {
        100 // $1.00/hr
    } else if model_upper.contains("4090") || model_upper.contains("3090") || model_upper.contains("4080") {
        50 // $0.50/hr
    } else {
        50 // $0.50/hr default
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
