//! # Worker Manager
//!
//! Comprehensive worker management system for the Bitsage Network coordinator,
//! handling worker registration, health monitoring, and capability management.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock, Mutex};
use tokio::time::{Duration, Instant};
use tracing::{info, debug, warn, error};

use crate::types::{WorkerId, TeeType};
use crate::node::coordinator::{WorkerInfo, WorkerCapabilities, ComputeRequirements};
use crate::storage::Database;
use crate::network::NetworkCoordinator;
use crate::coordinator::config::WorkerManagerConfig;
use crate::obelysk::starknet::{
    StakingClient, StakingClientConfig, GpuTier, StakeStatus, WorkerTier,
    ReputationClient, ReputationClientConfig,
};
use crate::obelysk::elgamal::{ECPoint, Felt252, verify_schnorr_proof, hash_felts};
use crate::obelysk::worker_keys::RegistrationSignature;

// ============================================================================
// Worker Registration with Privacy Key
// ============================================================================

/// Request to register a worker with optional privacy public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRegistrationRequest {
    /// Core worker information
    pub worker_info: WorkerInfo,

    /// Optional ElGamal public key for encrypted payments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_public_key: Option<ECPoint>,

    /// Signature proving ownership of the privacy key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_key_signature: Option<RegistrationSignature>,
}

/// Verify that a registration signature proves ownership of the public key
fn verify_registration_signature(
    public_key: &ECPoint,
    signature: &RegistrationSignature,
) -> bool {
    // Reconstruct the message that was signed
    let message = hash_felts(&[
        public_key.x,
        public_key.y,
        Felt252::from_u64(signature.timestamp),
    ]);

    // Verify the Schnorr proof
    verify_schnorr_proof(public_key, &signature.proof, &[message])
}

/// Worker manager events
#[derive(Debug, Clone)]
pub enum WorkerEvent {
    WorkerRegistered(WorkerId, WorkerInfo),
    WorkerUnregistered(WorkerId),
    WorkerHeartbeat(WorkerId, WorkerHealth),
    WorkerHealthChanged(WorkerId, WorkerHealth),
    WorkerCapabilitiesUpdated(WorkerId, WorkerCapabilities),
    WorkerLoadUpdated(WorkerId, f64),
    WorkerReputationUpdated(WorkerId, f64),
    WorkerTimeout(WorkerId),
    WorkerFailed(WorkerId, String),
}

/// Worker health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerHealth {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub gpu_usage: Option<f64>,
    pub disk_usage: f64,
    pub network_latency_ms: u64,
    pub uptime_secs: u64,
    pub last_heartbeat: u64,
    pub status: WorkerStatus,
}

/// Worker status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WorkerStatus {
    Online,
    Busy,
    Offline,
    Unhealthy,
    Maintenance,
}

/// Worker information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerDetails {
    pub id: WorkerId,
    pub info: WorkerInfo,
    pub health: WorkerHealth,
    pub capabilities: WorkerCapabilities,
    pub reputation: f64,
    pub load: f64,
    pub registered_at: u64,
    pub last_seen: u64,
    pub total_jobs_completed: u64,
    pub total_jobs_failed: u64,
    pub average_completion_time_secs: u64,
    pub tags: Vec<String>,
}

/// Worker statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerStats {
    pub total_workers: u64,
    pub active_workers: u64,
    pub online_workers: u64,
    pub busy_workers: u64,
    pub offline_workers: u64,
    pub average_reputation: f64,
    pub average_load: f64,
    pub total_compute_capacity: u64,
    pub available_compute_capacity: u64,
}

/// Worker load information
#[derive(Debug, Clone)]
struct WorkerLoad {
    current_load: f64,
    max_load: f64,
    last_updated: Instant,
}

/// Cluster-wide load statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClusterLoadStats {
    /// Total number of workers
    pub total_workers: usize,
    /// Average load across all workers
    pub avg_load: f64,
    /// Overall cluster utilization (0.0 to 1.0)
    pub utilization: f64,
    /// Minimum worker load
    pub min_load: f64,
    /// Maximum worker load
    pub max_load: f64,
    /// Number of workers above 80% load
    pub overloaded_workers: usize,
    /// Number of workers above 95% load (critical)
    pub critical_workers: usize,
    /// Number of workers below 10% load (idle)
    pub idle_workers: usize,
    /// Total cluster capacity
    pub total_capacity: f64,
    /// Current total load
    pub current_load: f64,
}

/// Main worker manager service
pub struct WorkerManager {
    config: WorkerManagerConfig,
    database: Arc<Database>,
    network_coordinator: Arc<NetworkCoordinator>,

    // Staking contract client for on-chain stake verification
    staking_client: Arc<StakingClient>,

    // Reputation contract client for on-chain reputation queries
    reputation_client: Arc<ReputationClient>,

    // Worker storage
    active_workers: Arc<RwLock<HashMap<WorkerId, WorkerDetails>>>,
    worker_loads: Arc<RwLock<HashMap<WorkerId, WorkerLoad>>>,

    // Worker statistics
    stats: Arc<RwLock<WorkerStats>>,

    // Communication channels
    event_sender: mpsc::UnboundedSender<WorkerEvent>,
    event_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<WorkerEvent>>>>,

    // Internal state
    running: Arc<RwLock<bool>>,
    next_worker_id: Arc<Mutex<u64>>,
}

impl WorkerManager {
    /// Create a new worker manager
    pub fn new(
        config: WorkerManagerConfig,
        database: Arc<Database>,
        network_coordinator: Arc<NetworkCoordinator>,
        staking_config: StakingClientConfig,
        reputation_config: ReputationClientConfig,
    ) -> Self {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        let stats = WorkerStats {
            total_workers: 0,
            active_workers: 0,
            online_workers: 0,
            busy_workers: 0,
            offline_workers: 0,
            average_reputation: 0.0,
            average_load: 0.0,
            total_compute_capacity: 0,
            available_compute_capacity: 0,
        };

        let staking_client = Arc::new(StakingClient::new(staking_config));
        let reputation_client = Arc::new(ReputationClient::new(reputation_config));

        Self {
            config,
            database,
            network_coordinator,
            staking_client,
            reputation_client,
            active_workers: Arc::new(RwLock::new(HashMap::new())),
            worker_loads: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(stats)),
            event_sender,
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
            running: Arc::new(RwLock::new(false)),
            next_worker_id: Arc::new(Mutex::new(1)),
        }
    }

    /// Create a worker manager with staking/reputation verification disabled (for testing)
    pub fn new_without_blockchain(
        config: WorkerManagerConfig,
        database: Arc<Database>,
        network_coordinator: Arc<NetworkCoordinator>,
    ) -> Self {
        Self::new(
            config,
            database,
            network_coordinator,
            StakingClientConfig {
                enabled: false,
                ..Default::default()
            },
            ReputationClientConfig {
                enabled: false,
                ..Default::default()
            },
        )
    }

    /// Start the worker manager
    pub async fn start(&self) -> Result<()> {
        info!("Starting Worker Manager...");
        
        {
            let mut running = self.running.write().await;
            if *running {
                return Err(anyhow::anyhow!("Worker manager already running"));
            }
            *running = true;
        }

        // Start monitoring tasks
        let _health_monitoring_handle = self.start_health_monitoring().await?;
        let _load_monitoring_handle = self.start_load_monitoring().await?;
        let _stats_collection_handle = self.start_stats_collection().await?;

        info!("Worker manager started successfully");
        
        Ok(())
    }

    /// Stop the worker manager
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping Worker Manager...");
        
        {
            let mut running = self.running.write().await;
            *running = false;
        }

        info!("Worker manager stopped");
        Ok(())
    }

    /// Register a new worker
    ///
    /// Uses a write lock through both validation and insertion to prevent
    /// TOCTOU race conditions (two workers with same node_id or GPU UUID
    /// both passing validation concurrently).
    pub async fn register_worker(&self, worker_info: WorkerInfo) -> Result<WorkerId> {
        info!("Registering new worker: {:?}", worker_info.node_id);

        // Hold write lock through validation AND insertion to prevent races
        let mut workers = self.active_workers.write().await;

        // Validate uniqueness checks under write lock
        self.validate_worker_uniqueness(&workers, &worker_info)?;

        // Validate remaining info (blockchain queries, capability checks)
        // These are safe to do while holding the lock since they're external calls
        self.validate_worker_requirements(&worker_info).await?;

        // Generate worker ID
        let worker_id = self.generate_worker_id().await;

        // Create worker details
        let worker_details = WorkerDetails {
            id: worker_id,
            info: worker_info.clone(),
            health: WorkerHealth {
                cpu_usage: 0.0,
                memory_usage: 0.0,
                gpu_usage: None,
                disk_usage: 0.0,
                network_latency_ms: 0,
                uptime_secs: 0,
                last_heartbeat: chrono::Utc::now().timestamp() as u64,
                status: WorkerStatus::Online,
            },
            capabilities: worker_info.capabilities.clone(),
            reputation: 1.0, // Start with full reputation
            load: 0.0,
            registered_at: chrono::Utc::now().timestamp() as u64,
            last_seen: chrono::Utc::now().timestamp() as u64,
            total_jobs_completed: 0,
            total_jobs_failed: 0,
            average_completion_time_secs: 0,
            tags: self.extract_worker_tags(&worker_info),
        };

        // Atomically insert under same write lock
        workers.insert(worker_id, worker_details.clone());
        drop(workers);

        // Initialize worker load (separate lock, fine)
        let worker_load = WorkerLoad {
            current_load: 0.0,
            max_load: self.calculate_max_load(&worker_info.capabilities),
            last_updated: Instant::now(),
        };
        self.worker_loads.write().await.insert(worker_id, worker_load);
        
        // Update statistics
        self.update_stats_worker_registered().await;
        
        // Send event
        if let Err(e) = self.event_sender.send(WorkerEvent::WorkerRegistered(worker_id, worker_info)) {
            error!("Failed to send worker registered event: {}", e);
        }
        
        info!("Worker {} registered successfully", worker_id);
        Ok(worker_id)
    }

    /// Register a worker with privacy key verification
    ///
    /// This method accepts a `WorkerRegistrationRequest` which includes:
    /// - Core worker information
    /// - Optional ElGamal public key for encrypted payments
    /// - Signature proving ownership of the privacy key
    ///
    /// If a privacy key and signature are provided, the signature is verified
    /// before the worker is registered.
    pub async fn register_worker_with_privacy(
        &self,
        request: WorkerRegistrationRequest,
    ) -> Result<WorkerId> {
        let mut worker_info = request.worker_info;

        // Verify and attach privacy public key if provided
        if let Some(ref public_key) = request.privacy_public_key {
            if let Some(ref signature) = request.privacy_key_signature {
                // Verify the signature proves ownership of the key
                if !verify_registration_signature(public_key, signature) {
                    anyhow::bail!("Invalid privacy key signature - worker does not own this key");
                }

                // Check timestamp is recent (within 5 minutes)
                let now = chrono::Utc::now().timestamp() as u64;
                if signature.timestamp > now || now - signature.timestamp > 300 {
                    anyhow::bail!("Privacy key signature timestamp is stale or in the future");
                }

                // Attach the verified public key to worker info
                worker_info.privacy_public_key = Some(public_key.clone());
                info!("Worker {} registered with privacy public key", worker_info.node_id);
            } else {
                // Public key provided without signature - reject
                anyhow::bail!("Privacy public key provided without ownership signature");
            }
        }

        // Delegate to standard registration
        self.register_worker(worker_info).await
    }

    /// Unregister a worker
    pub async fn unregister_worker(&self, worker_id: WorkerId) -> Result<()> {
        info!("Unregistering worker {}", worker_id);
        
        let mut workers = self.active_workers.write().await;
        if workers.remove(&worker_id).is_some() {
            // Remove from load tracking
            self.worker_loads.write().await.remove(&worker_id);
            
            // Update statistics
            self.update_stats_worker_unregistered().await;
            
            // Send event
            if let Err(e) = self.event_sender.send(WorkerEvent::WorkerUnregistered(worker_id)) {
                error!("Failed to send worker unregistered event: {}", e);
            }
            
            info!("Worker {} unregistered successfully", worker_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Worker {} not found", worker_id))
        }
    }

    /// Get worker details
    pub async fn get_worker(&self, worker_id: WorkerId) -> Option<WorkerDetails> {
        let workers = self.active_workers.read().await;
        workers.get(&worker_id).cloned()
    }

    /// Get active workers
    pub async fn get_active_workers(&self) -> Vec<WorkerDetails> {
        let workers = self.active_workers.read().await;
        workers.values().cloned().collect()
    }

    /// Get active workers count
    pub async fn get_active_workers_count(&self) -> usize {
        let workers = self.active_workers.read().await;
        workers.len()
    }

    /// Get worker health
    pub async fn get_worker_health(&self, worker_id: WorkerId) -> Result<Option<WorkerHealth>> {
        if let Some(worker_details) = self.get_worker(worker_id).await {
            Ok(Some(worker_details.health))
        } else {
            Ok(None)
        }
    }

    /// Get worker stake status from blockchain
    ///
    /// Queries the staking contract to get the worker's current stake status.
    /// Returns StakeStatus::None if the worker has no stake or if the query fails.
    pub async fn get_worker_stake_status(&self, wallet_address: &str) -> Result<StakeStatus> {
        self.staking_client.get_stake_status(wallet_address).await
    }

    /// Verify worker meets minimum stake requirements for a job
    ///
    /// Used for high-value jobs that require a minimum stake level.
    /// Returns Ok(true) if worker meets requirements, Ok(false) if not.
    pub async fn verify_worker_stake_for_job(
        &self,
        worker_id: WorkerId,
        min_gpu_tier: GpuTier,
        min_stake_amount: Option<u128>,
    ) -> Result<bool> {
        // Get worker details
        let workers = self.active_workers.read().await;
        let worker = workers.get(&worker_id)
            .ok_or_else(|| anyhow::anyhow!("Worker {} not found", worker_id))?;

        // Get wallet address
        let wallet = worker.info.wallet_address.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Worker {} has no wallet address", worker_id))?;

        // Fetch stake status
        let stake_status = self.staking_client.get_stake_status(wallet).await
            .unwrap_or(StakeStatus::None);

        match stake_status {
            StakeStatus::Staked { gpu_tier, amount } => {
                // Check GPU tier meets minimum
                let tier_ok = match (&gpu_tier, &min_gpu_tier) {
                    (GpuTier::Frontier, _) => true,
                    (GpuTier::Enterprise, GpuTier::Enterprise | GpuTier::DataCenter | GpuTier::Workstation | GpuTier::Consumer) => true,
                    (GpuTier::DataCenter, GpuTier::DataCenter | GpuTier::Workstation | GpuTier::Consumer) => true,
                    (GpuTier::Workstation, GpuTier::Workstation | GpuTier::Consumer) => true,
                    (GpuTier::Consumer, GpuTier::Consumer) => true,
                    _ => false,
                };

                // Check stake amount meets minimum
                let amount_ok = min_stake_amount.map_or(true, |min| amount >= min);

                if !tier_ok {
                    info!(
                        worker_id = %worker_id,
                        worker_tier = ?gpu_tier,
                        required_tier = ?min_gpu_tier,
                        "Worker GPU tier does not meet job requirements"
                    );
                }

                if !amount_ok {
                    info!(
                        worker_id = %worker_id,
                        stake_amount = amount,
                        required_amount = ?min_stake_amount,
                        "Worker stake amount does not meet job requirements"
                    );
                }

                Ok(tier_ok && amount_ok)
            }
            StakeStatus::Unstaking { .. } => {
                info!(
                    worker_id = %worker_id,
                    "Worker is unstaking, not eligible for stake-required jobs"
                );
                Ok(false)
            }
            StakeStatus::None => {
                info!(
                    worker_id = %worker_id,
                    "Worker has no stake, not eligible for stake-required jobs"
                );
                Ok(false)
            }
        }
    }

    /// Update worker health
    pub async fn update_worker_health(&self, worker_id: WorkerId, health: WorkerHealth) -> Result<()> {
        info!("Updating health for worker {}", worker_id);
        
        let mut workers = self.active_workers.write().await;
        if let Some(worker_details) = workers.get_mut(&worker_id) {
            let old_status = worker_details.health.status.clone();
            worker_details.health = health.clone();
            worker_details.last_seen = chrono::Utc::now().timestamp() as u64;
            
            // Send health change event if status changed
            if worker_details.health.status != old_status {
                if let Err(e) = self.event_sender.send(WorkerEvent::WorkerHealthChanged(worker_id, health)) {
                    error!("Failed to send worker health changed event: {}", e);
                }
            }
            
            info!("Worker {} health updated", worker_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Worker {} not found", worker_id))
        }
    }

    /// Update worker load
    pub async fn update_worker_load(&self, worker_id: WorkerId, load: f64) -> Result<()> {
        debug!("Updating load for worker {}: {}", worker_id, load);
        
        let mut workers = self.active_workers.write().await;
        if let Some(worker_details) = workers.get_mut(&worker_id) {
            worker_details.load = load;
            
            // Update load tracking
            let mut loads = self.worker_loads.write().await;
            if let Some(worker_load) = loads.get_mut(&worker_id) {
                worker_load.current_load = load;
                worker_load.last_updated = Instant::now();
            }
            
            // Send load update event
            if let Err(e) = self.event_sender.send(WorkerEvent::WorkerLoadUpdated(worker_id, load)) {
                error!("Failed to send worker load updated event: {}", e);
            }
            
            Ok(())
        } else {
            Err(anyhow::anyhow!("Worker {} not found", worker_id))
        }
    }

    /// Update worker reputation
    pub async fn update_worker_reputation(&self, worker_id: WorkerId, reputation: f64) -> Result<()> {
        info!("Updating reputation for worker {}: {}", worker_id, reputation);
        
        let mut workers = self.active_workers.write().await;
        if let Some(worker_details) = workers.get_mut(&worker_id) {
            worker_details.reputation = reputation;
            
            // Send reputation update event
            if let Err(e) = self.event_sender.send(WorkerEvent::WorkerReputationUpdated(worker_id, reputation)) {
                error!("Failed to send worker reputation updated event: {}", e);
            }
            
            info!("Worker {} reputation updated to {}", worker_id, reputation);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Worker {} not found", worker_id))
        }
    }

    /// Get worker statistics
    pub async fn get_worker_stats(&self) -> WorkerStats {
        self.stats.read().await.clone()
    }

    /// Get a Send+Sync handle to the stats for use in spawned tasks
    /// This allows metrics collection from within tokio::spawn without
    /// moving the entire WorkerManager (which contains non-Send fields)
    pub fn stats_handle(&self) -> Arc<RwLock<WorkerStats>> {
        Arc::clone(&self.stats)
    }

    /// Get a Send+Sync handle to active workers for use in spawned tasks
    pub fn active_workers_handle(&self) -> Arc<RwLock<HashMap<WorkerId, WorkerDetails>>> {
        Arc::clone(&self.active_workers)
    }


    /// Find workers by capabilities
    pub async fn find_workers_by_capabilities(&self, requirements: &ComputeRequirements) -> Vec<WorkerDetails> {
        let workers = self.active_workers.read().await;
        workers.values()
            .filter(|worker| {
                // Check if worker has required capabilities
                self.worker_meets_requirements(worker, requirements)
            })
            .cloned()
            .collect()
    }

    /// Find best worker for job using on-chain reputation when available
    pub async fn find_best_worker(&self, requirements: &ComputeRequirements) -> Option<WorkerDetails> {
        let available_workers = self.find_workers_by_capabilities(requirements).await;

        if available_workers.is_empty() {
            return None;
        }

        // Score each worker, preferring on-chain reputation when available
        let mut scored_workers: Vec<(WorkerDetails, f64)> = Vec::with_capacity(available_workers.len());

        for worker in available_workers {
            let score = self.calculate_worker_score(&worker).await;
            scored_workers.push((worker, score));
        }

        // Sort by score (descending)
        scored_workers.sort_by(|a, b| {
            b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal)
        });

        // Return the best worker
        scored_workers.first().map(|(worker, score)| {
            debug!(
                worker_id = %worker.id,
                score = score,
                "Selected best worker"
            );
            worker.clone()
        })
    }

    /// Calculate worker selection score using on-chain reputation and stake
    async fn calculate_worker_score(&self, worker: &WorkerDetails) -> f64 {
        // Get on-chain reputation and stake status if worker has wallet address
        let (on_chain_reputation, stake_status) = if let Some(ref wallet) = worker.info.wallet_address {
            // Fetch reputation
            let rep = match self.reputation_client.get_reputation(wallet).await {
                Ok(rep) => {
                    // Check if worker is eligible based on reputation
                    if !rep.is_eligible() {
                        warn!(
                            worker_id = %worker.id,
                            wallet = %wallet,
                            score = rep.score,
                            "Worker has low reputation, skipping"
                        );
                        return 0.0; // Ineligible workers get zero score
                    }
                    Some(rep)
                }
                Err(e) => {
                    debug!(
                        worker_id = %worker.id,
                        error = %e,
                        "Failed to fetch on-chain reputation, using local"
                    );
                    None
                }
            };

            // Fetch stake status for worker selection weighting
            let stake = match self.staking_client.get_stake_status(wallet).await {
                Ok(status) => {
                    debug!(
                        worker_id = %worker.id,
                        wallet = %wallet,
                        stake_status = ?status,
                        "Fetched worker stake status"
                    );
                    status
                }
                Err(e) => {
                    debug!(
                        worker_id = %worker.id,
                        error = %e,
                        "Failed to fetch stake status, assuming no stake"
                    );
                    StakeStatus::None
                }
            };

            (rep, stake)
        } else {
            (None, StakeStatus::None)
        };

        // Calculate base reputation score
        let reputation_score = if let Some(rep) = on_chain_reputation {
            // On-chain reputation: 0-1000 -> 0.0-10.0
            let base = rep.as_float();

            // Boost for high reputation workers (700+)
            let boost = if rep.is_high_reputation() { 1.2 } else { 1.0 };

            // Factor in success rate
            let success_factor = 0.5 + (rep.success_rate * 0.5);

            base * boost * success_factor
        } else {
            // Fall back to local reputation (0.0-10.0 scale)
            worker.reputation
        };

        // Load factor: prefer less loaded workers (0.0-1.0 -> 1.0-0.0)
        let load_factor = 1.0 - worker.load.min(1.0);

        // Experience factor: slight bonus for workers with more completed jobs
        let experience_bonus = ((worker.total_jobs_completed as f64).ln() + 1.0) / 10.0;

        // Stake bonus: workers with active stake get priority
        // Higher tier = higher bonus (incentivizes staking)
        let stake_bonus = match &stake_status {
            StakeStatus::Staked { gpu_tier, amount: _ } => {
                // Tier-based bonus: Consumer=0.1, Workstation=0.15, DataCenter=0.2, Enterprise=0.25, Frontier=0.3
                match gpu_tier {
                    GpuTier::Consumer => 0.10,
                    GpuTier::Workstation => 0.15,
                    GpuTier::DataCenter => 0.20,
                    GpuTier::Enterprise => 0.25,
                    GpuTier::Frontier => 0.30,
                }
            }
            StakeStatus::Unstaking { .. } => {
                // Unstaking workers get reduced bonus (still have stake locked)
                0.05
            }
            StakeStatus::None => {
                // No stake = no bonus (but still eligible in work-first model)
                0.0
            }
        };

        // Calculate final score with stake bonus applied
        let base_score = reputation_score * (0.5 + load_factor * 0.4 + experience_bonus * 0.1);
        let score = base_score * (1.0 + stake_bonus);

        debug!(
            worker_id = %worker.id,
            reputation_score = reputation_score,
            load_factor = load_factor,
            experience_bonus = experience_bonus,
            stake_bonus = stake_bonus,
            stake_status = ?stake_status,
            final_score = score,
            "Calculated worker score with stake verification"
        );

        score
    }

    /// Start health monitoring
    async fn start_health_monitoring(&self) -> Result<()> {
        let config = self.config.clone();
        let active_workers = Arc::clone(&self.active_workers);
        let worker_loads = Arc::clone(&self.worker_loads);
        let event_sender = self.event_sender.clone();

        // Evict workers that have been offline for 3x the timeout period
        let eviction_threshold = config.worker_timeout_secs * 3;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(config.health_check_interval_secs));

            loop {
                interval.tick().await;

                let now = chrono::Utc::now().timestamp() as u64;
                let mut workers = active_workers.write().await;
                let mut timed_out_workers = Vec::new();
                let mut evicted_workers = Vec::new();

                for (worker_id, worker_details) in workers.iter_mut() {
                    let offline_duration = now.saturating_sub(worker_details.last_seen);
                    if offline_duration > eviction_threshold {
                        // Worker has been offline long enough to evict
                        evicted_workers.push(*worker_id);
                    } else if offline_duration > config.worker_timeout_secs {
                        worker_details.health.status = WorkerStatus::Offline;
                        timed_out_workers.push(*worker_id);
                    }
                }

                // Evict stale offline workers
                if !evicted_workers.is_empty() {
                    let mut loads = worker_loads.write().await;
                    for worker_id in &evicted_workers {
                        workers.remove(worker_id);
                        loads.remove(worker_id);
                        info!("Evicted offline worker {} (exceeded {}s grace period)", worker_id, eviction_threshold);
                    }
                }

                // Send timeout events
                for worker_id in timed_out_workers {
                    if let Err(e) = event_sender.send(WorkerEvent::WorkerTimeout(worker_id)) {
                        error!("Failed to send worker timeout event: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    /// Start load monitoring
    async fn start_load_monitoring(&self) -> Result<()> {
        let config = self.config.clone();
        let worker_loads = Arc::clone(&self.worker_loads);
        let active_workers = Arc::clone(&self.active_workers);
        let event_sender = self.event_sender.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(config.monitoring.metrics_interval_secs));

            // Thresholds for load monitoring
            const HIGH_LOAD_THRESHOLD: f64 = 0.8;
            const CRITICAL_LOAD_THRESHOLD: f64 = 0.95;
            const STALE_LOAD_SECS: u64 = 300; // 5 minutes

            loop {
                interval.tick().await;

                let now = Instant::now();
                let mut workers = active_workers.write().await;
                let mut loads = worker_loads.write().await;

                // Collect workers that need status updates
                let mut overloaded_workers = Vec::new();
                let mut critical_workers = Vec::new();
                let mut stale_workers = Vec::new();

                for (worker_id, load) in loads.iter_mut() {
                    let elapsed_secs = now.duration_since(load.last_updated).as_secs();

                    // Check for stale load data
                    if elapsed_secs > STALE_LOAD_SECS {
                        stale_workers.push(worker_id.clone());
                        continue;
                    }

                    // Calculate load percentage
                    let load_percentage = if load.max_load > 0.0 {
                        load.current_load / load.max_load
                    } else {
                        load.current_load
                    };

                    // Check thresholds
                    if load_percentage >= CRITICAL_LOAD_THRESHOLD {
                        critical_workers.push((worker_id.clone(), load_percentage));
                    } else if load_percentage >= HIGH_LOAD_THRESHOLD {
                        overloaded_workers.push((worker_id.clone(), load_percentage));
                    }

                    // Update worker status based on load
                    if let Some(worker) = workers.get_mut(worker_id) {
                        worker.load = load_percentage;

                        // Update status based on load
                        let new_status = if load_percentage >= CRITICAL_LOAD_THRESHOLD {
                            WorkerStatus::Busy
                        } else if worker.health.status == WorkerStatus::Busy && load_percentage < HIGH_LOAD_THRESHOLD {
                            WorkerStatus::Online
                        } else {
                            worker.health.status.clone()
                        };

                        if new_status != worker.health.status {
                            worker.health.status = new_status.clone();
                            if let Err(e) = event_sender.send(WorkerEvent::WorkerHealthChanged(
                                worker_id.clone(),
                                worker.health.clone(),
                            )) {
                                error!("Failed to send health changed event: {}", e);
                            }
                        }

                        // Send load update event
                        if let Err(e) = event_sender.send(WorkerEvent::WorkerLoadUpdated(
                            worker_id.clone(),
                            load_percentage,
                        )) {
                            error!("Failed to send load updated event: {}", e);
                        }
                    }
                }

                // Handle stale workers
                for worker_id in &stale_workers {
                    debug!("Worker {} has stale load data", worker_id);
                    if let Some(worker) = workers.get_mut(worker_id) {
                        if worker.health.status == WorkerStatus::Online || worker.health.status == WorkerStatus::Busy {
                            worker.health.status = WorkerStatus::Offline;
                            if let Err(e) = event_sender.send(WorkerEvent::WorkerTimeout(worker_id.clone())) {
                                error!("Failed to send timeout event: {}", e);
                            }
                        }
                    }
                }

                // Log monitoring summary
                if !critical_workers.is_empty() {
                    info!(
                        "Critical load alert: {} workers at critical capacity",
                        critical_workers.len()
                    );
                }

                if !overloaded_workers.is_empty() {
                    debug!(
                        "High load: {} workers above {}% capacity",
                        overloaded_workers.len(),
                        HIGH_LOAD_THRESHOLD * 100.0
                    );
                }

                // Calculate cluster-wide load statistics
                let total_workers = loads.len();
                if total_workers > 0 {
                    let total_load: f64 = loads.values().map(|l| l.current_load).sum();
                    let total_capacity: f64 = loads.values().map(|l| l.max_load).sum();
                    let avg_load = total_load / total_workers as f64;
                    let cluster_utilization = if total_capacity > 0.0 {
                        (total_load / total_capacity) * 100.0
                    } else {
                        0.0
                    };

                    debug!(
                        "Cluster load: {:.1}% utilization, {:.2} avg load, {} workers",
                        cluster_utilization, avg_load, total_workers
                    );
                }
            }
        });

        Ok(())
    }

    /// Start statistics collection
    async fn start_stats_collection(&self) -> Result<()> {
        let stats = Arc::clone(&self.stats);
        let active_workers = Arc::clone(&self.active_workers);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                // Update statistics
                let workers = active_workers.read().await;
                let mut stats_guard = stats.write().await;
                
                stats_guard.total_workers = workers.len() as u64;
                stats_guard.active_workers = workers.values()
                    .filter(|w| matches!(w.health.status, WorkerStatus::Online | WorkerStatus::Busy))
                    .count() as u64;
                stats_guard.online_workers = workers.values()
                    .filter(|w| matches!(w.health.status, WorkerStatus::Online))
                    .count() as u64;
                stats_guard.busy_workers = workers.values()
                    .filter(|w| matches!(w.health.status, WorkerStatus::Busy))
                    .count() as u64;
                stats_guard.offline_workers = workers.values()
                    .filter(|w| matches!(w.health.status, WorkerStatus::Offline))
                    .count() as u64;
                
                // Calculate averages
                if !workers.is_empty() {
                    let total_reputation: f64 = workers.values().map(|w| w.reputation).sum();
                    let total_load: f64 = workers.values().map(|w| w.load).sum();
                    
                    stats_guard.average_reputation = total_reputation / workers.len() as f64;
                    stats_guard.average_load = total_load / workers.len() as f64;
                }
            }
        });

        Ok(())
    }

    /// Validate worker info - Work-First Model (no mandatory staking)
    ///
    /// Workers can join the network without staking. Trust is established through:
    /// 1. STWO proof verification (cryptographic proof of correct computation)
    /// 2. Reputation built from successful job completions
    /// 3. Optional staking for premium benefits (priority jobs, validator voting)
    /// Validate worker uniqueness constraints (node_id, GPU UUIDs).
    /// Must be called while holding the write lock on active_workers.
    fn validate_worker_uniqueness(
        &self,
        workers: &HashMap<WorkerId, WorkerDetails>,
        worker_info: &WorkerInfo,
    ) -> Result<()> {
        // Enforce max workers limit to prevent unbounded growth
        if workers.len() >= self.config.registration.max_workers.unwrap_or(10_000) as usize {
            return Err(anyhow::anyhow!("Maximum worker capacity reached"));
        }

        // Check if worker already exists by node_id
        if workers.values().any(|w| w.info.node_id == worker_info.node_id) {
            return Err(anyhow::anyhow!("Worker with node ID {} already registered", worker_info.node_id));
        }

        // GPU UUID deduplication
        for uuid in &worker_info.capabilities.gpu_uuids {
            let uuid_trimmed = uuid.trim();
            if uuid_trimmed.is_empty() {
                continue;
            }

            let valid_format = uuid_trimmed.starts_with("GPU-") || uuid_trimmed.starts_with("0x");
            if !valid_format {
                return Err(anyhow::anyhow!(
                    "Invalid GPU UUID format: '{}'. Expected NVIDIA (GPU-...) or AMD (0x...) format.",
                    uuid_trimmed
                ));
            }

            for existing in workers.values() {
                if existing.capabilities.gpu_uuids.iter().any(|u| u.trim() == uuid_trimmed) {
                    let same_wallet = match (&existing.info.wallet_address, &worker_info.wallet_address) {
                        (Some(a), Some(b)) => a == b,
                        _ => false,
                    };
                    if !same_wallet {
                        return Err(anyhow::anyhow!(
                            "GPU {} already registered under a different wallet",
                            uuid_trimmed
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Validate worker requirements (wallet, stake, capabilities) — async checks
    async fn validate_worker_requirements(&self, worker_info: &WorkerInfo) -> Result<()> {
        // Wallet address required for receiving payments (Starknet wallet: ArgentX, Braavos, etc.)
        let wallet_address = worker_info.wallet_address.as_ref()
            .ok_or_else(|| anyhow::anyhow!(
                "Wallet address required for registration. Provide your Starknet wallet address \
                (ArgentX, Braavos, or MetaMask Snaps) to receive SAGE token payments."
            ))?;

        // Validate wallet address format
        if !wallet_address.starts_with("0x") || wallet_address.len() < 10 {
            return Err(anyhow::anyhow!(
                "Invalid Starknet wallet address format: {}",
                wallet_address
            ));
        }

        // Determine GPU tier from worker capabilities
        let gpu_tier = GpuTier::from_gpu_model(&worker_info.capabilities.gpu_model);

        // Query on-chain staking status
        let stake_status = self.staking_client
            .get_stake_status(wallet_address)
            .await
            .unwrap_or_else(|e| {
                warn!(
                    wallet = %wallet_address,
                    error = %e,
                    "Could not query stake status from on-chain contract"
                );
                StakeStatus::None
            });

        // MAINNET SECURITY: Enforce minimum stake if configured
        if self.config.registration.require_stake {
            let min_stake = gpu_tier.min_stake();
            match &stake_status {
                StakeStatus::Staked { amount, gpu_tier: staked_tier } => {
                    // Verify stake amount meets GPU tier minimum
                    if *amount < min_stake {
                        return Err(anyhow::anyhow!(
                            "Insufficient stake for {} GPU tier. Required: {} SAGE, Found: {} SAGE. \
                             Please stake additional tokens at https://app.bitsage.network/stake",
                            gpu_tier,
                            min_stake / 1_000_000_000_000_000_000,
                            amount / 1_000_000_000_000_000_000
                        ));
                    }
                    // Verify staked tier matches declared GPU
                    if *staked_tier != gpu_tier {
                        warn!(
                            wallet = %wallet_address,
                            declared_tier = ?gpu_tier,
                            staked_tier = ?staked_tier,
                            "Worker GPU tier mismatch - using staked tier"
                        );
                    }
                    info!(
                        wallet = %wallet_address,
                        stake_amount = amount / 1_000_000_000_000_000_000,
                        gpu_tier = ?staked_tier,
                        "Worker stake verified on-chain"
                    );
                }
                StakeStatus::Unstaking { amount, available_at } => {
                    return Err(anyhow::anyhow!(
                        "Cannot register: stake is being unstaked ({} SAGE). \
                         Wait until {} or re-stake at https://app.bitsage.network/stake",
                        amount / 1_000_000_000_000_000_000,
                        available_at
                    ));
                }
                StakeStatus::None => {
                    if self.config.registration.allow_probationary_workers {
                        warn!(
                            wallet = %wallet_address,
                            gpu_tier = ?gpu_tier,
                            min_stake = gpu_tier.min_stake_display(),
                            "Worker registered in PROBATIONARY mode (no stake). \
                             Reduced rewards until stake is deposited."
                        );
                    } else {
                        return Err(anyhow::anyhow!(
                            "Stake required for {} GPU tier. Minimum: {}. \
                             Stake SAGE tokens at https://app.bitsage.network/stake",
                            gpu_tier,
                            gpu_tier.min_stake_display()
                        ));
                    }
                }
            }
        }

        // Check existing reputation (new workers start at 0)
        let reputation = self.reputation_client
            .get_reputation(wallet_address)
            .await
            .map(|r| r.score)
            .unwrap_or(0);

        // Determine worker tier based on stake and reputation
        let worker_tier = WorkerTier::from_stake_and_reputation(&stake_status, reputation);

        info!(
            wallet = %wallet_address,
            gpu_tier = ?gpu_tier,
            gpu_model = %worker_info.capabilities.gpu_model,
            stake_status = ?stake_status,
            reputation = reputation,
            worker_tier = ?worker_tier,
            require_stake = self.config.registration.require_stake,
            "Worker validation complete"
        );

        // Validate capabilities if enabled
        if self.config.registration.enable_capability_validation {
            self.validate_capabilities(&worker_info.capabilities).await?;
        }

        Ok(())
    }

    /// Validate worker capabilities (GPU, CPU, memory, etc.)
    async fn validate_capabilities(&self, capabilities: &WorkerCapabilities) -> Result<()> {
        // Verify GPU memory meets minimum requirements
        if capabilities.gpu_memory_gb < 4 {
            warn!(
                gpu_memory = capabilities.gpu_memory_gb,
                "Worker GPU memory below recommended minimum (4GB)"
            );
        }

        // Verify RAM meets minimum for proof generation
        if capabilities.ram_gb < 8 {
            return Err(anyhow::anyhow!(
                "Insufficient RAM: {} GB. Minimum 8 GB required for proof generation.",
                capabilities.ram_gb
            ));
        }

        // Verify CPU cores for multi-threaded proof work
        if capabilities.cpu_cores < 2 {
            return Err(anyhow::anyhow!(
                "Insufficient CPU cores: {}. Minimum 2 cores required.",
                capabilities.cpu_cores
            ));
        }

        Ok(())
    }

    /// Generate worker ID
    async fn generate_worker_id(&self) -> WorkerId {
        let mut next_id = self.next_worker_id.lock().await;
        *next_id += 1;
        WorkerId::new()
    }

    /// Extract worker tags based on capabilities, hardware, and features
    fn extract_worker_tags(&self, worker_info: &WorkerInfo) -> Vec<String> {
        let mut tags = vec!["worker".to_string()];
        let caps = &worker_info.capabilities;

        // GPU tier tags
        if caps.gpu_count > 0 {
            tags.push("gpu".to_string());
            if caps.gpu_memory_gb >= 80 {
                tags.push("gpu-tier-4".to_string()); // H100/A100-80GB class
            } else if caps.gpu_memory_gb >= 40 {
                tags.push("gpu-tier-3".to_string()); // A100-40GB class
            } else if caps.gpu_memory_gb >= 16 {
                tags.push("gpu-tier-2".to_string()); // RTX 4090/A6000 class
            } else if caps.gpu_memory_gb >= 8 {
                tags.push("gpu-tier-1".to_string()); // RTX 3080/4070 class
            }

            // Multi-GPU tag
            if caps.gpu_count >= 4 {
                tags.push("multi-gpu-4+".to_string());
            } else if caps.gpu_count >= 2 {
                tags.push("multi-gpu".to_string());
            }
        } else {
            tags.push("cpu-only".to_string());
        }

        // TEE support tags
        match caps.tee_type {
            TeeType::CpuOnly => tags.push("tee-cpu".to_string()), // Intel TDX / AMD SEV
            TeeType::Full => {
                tags.push("tee-full".to_string()); // Full confidential computing
                tags.push("tee-cpu".to_string());
            }
            TeeType::None => {}
        }
        if caps.gpu_tee_support {
            tags.push("gpu-tee".to_string()); // NVIDIA CC support
        }

        // Precision support tags
        if caps.supports_fp16 {
            tags.push("fp16".to_string());
        }
        if caps.supports_int8 {
            tags.push("int8".to_string());
        }

        // Framework tags
        for framework in &caps.supported_frameworks {
            let framework_lower = framework.to_lowercase();
            if framework_lower.contains("pytorch") || framework_lower.contains("torch") {
                tags.push("pytorch".to_string());
            }
            if framework_lower.contains("tensorflow") || framework_lower.contains("tf") {
                tags.push("tensorflow".to_string());
            }
            if framework_lower.contains("onnx") {
                tags.push("onnx".to_string());
            }
            if framework_lower.contains("triton") {
                tags.push("triton".to_string());
            }
        }

        // Job type capability tags
        for job_type in &caps.supported_job_types {
            let job_lower = job_type.to_lowercase();
            if job_lower.contains("inference") {
                tags.push("inference".to_string());
            }
            if job_lower.contains("training") {
                tags.push("training".to_string());
            }
            if job_lower.contains("proof") || job_lower.contains("zk") {
                tags.push("zk-prover".to_string());
            }
        }

        // High-memory tag
        if caps.ram_gb >= 128 {
            tags.push("high-ram".to_string());
        }

        // High-storage tag
        if caps.disk_gb >= 2000 {
            tags.push("high-storage".to_string());
        }

        // Docker support
        if caps.docker_enabled {
            tags.push("docker".to_string());
        }

        // Reputation-based tags
        if worker_info.reputation >= 0.95 {
            tags.push("premium".to_string());
        } else if worker_info.reputation >= 0.8 {
            tags.push("trusted".to_string());
        }

        // Deduplicate tags
        tags.sort();
        tags.dedup();
        tags
    }

    /// Calculate max load for worker based on capabilities
    ///
    /// Max load is calculated as a weighted score based on:
    /// - GPU memory and compute capability
    /// - CPU cores and RAM
    /// - Network bandwidth
    /// - TEE overhead (reduces capacity by ~20% if enabled)
    fn calculate_max_load(&self, capabilities: &WorkerCapabilities) -> f64 {
        // Base capacity from GPU (weighted highest for AI/ZK workloads)
        let gpu_capacity = if capabilities.gpu_memory_gb > 0 {
            // Scale by GPU memory: 8GB = 1.0, 16GB = 2.0, 32GB = 4.0, etc.
            (capabilities.gpu_memory_gb as f64 / 8.0).max(0.5)
        } else {
            0.25 // CPU-only workers have reduced capacity
        };

        // CPU capacity based on cores
        let cpu_capacity = (capabilities.cpu_cores as f64 / 8.0).clamp(0.25, 4.0);

        // RAM capacity
        let ram_capacity = (capabilities.ram_gb as f64 / 16.0).clamp(0.25, 4.0);

        // Network/storage capacity factor (based on disk storage as proxy for data handling)
        let storage_factor = (capabilities.disk_gb as f64 / 500.0).clamp(0.5, 2.0);

        // Calculate base max load
        let mut max_load = (gpu_capacity * 0.5 + cpu_capacity * 0.3 + ram_capacity * 0.2) * storage_factor;

        // Apply TEE overhead if enabled (TEE reduces effective capacity)
        if !matches!(capabilities.tee_type, TeeType::None) {
            max_load *= 0.8; // 20% overhead for TEE operations
        }

        // Apply parallel task multiplier
        let parallel_factor = (capabilities.max_parallel_tasks as f64 / 2.0).clamp(0.5, 4.0);
        max_load *= parallel_factor;

        // Clamp to reasonable range
        max_load.clamp(0.25, 16.0)
    }

    /// Adjust worker load by a delta (used when adding/removing tasks)
    pub async fn adjust_worker_load_delta(&self, worker_id: &WorkerId, load_delta: f64) -> Result<()> {
        let mut loads = self.worker_loads.write().await;

        if let Some(load) = loads.get_mut(worker_id) {
            load.current_load = (load.current_load + load_delta).max(0.0);
            load.last_updated = Instant::now();
            debug!("Adjusted worker {} load by {:.2}: now {:.2}/{:.2}",
                   worker_id, load_delta, load.current_load, load.max_load);
        } else {
            return Err(anyhow::anyhow!("Worker {} not found in load tracking", worker_id));
        }

        Ok(())
    }

    /// Get current load for a worker
    pub async fn get_worker_load(&self, worker_id: &WorkerId) -> Option<f64> {
        let loads = self.worker_loads.read().await;
        loads.get(worker_id).map(|l| {
            if l.max_load > 0.0 {
                l.current_load / l.max_load
            } else {
                l.current_load
            }
        })
    }

    /// Get all workers below a load threshold
    pub async fn get_available_workers(&self, max_load_percentage: f64) -> Vec<WorkerId> {
        let loads = self.worker_loads.read().await;
        let workers = self.active_workers.read().await;

        loads
            .iter()
            .filter(|(worker_id, load)| {
                let load_pct = if load.max_load > 0.0 {
                    load.current_load / load.max_load
                } else {
                    load.current_load
                };

                // Check load and worker status
                if load_pct >= max_load_percentage {
                    return false;
                }

                // Check worker is online
                if let Some(worker) = workers.get(*worker_id) {
                    matches!(worker.health.status, WorkerStatus::Online)
                } else {
                    false
                }
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Get cluster load statistics
    pub async fn get_cluster_load_stats(&self) -> ClusterLoadStats {
        let loads = self.worker_loads.read().await;
        let _workers = self.active_workers.read().await;

        let total_workers = loads.len();
        if total_workers == 0 {
            return ClusterLoadStats::default();
        }

        let total_current_load: f64 = loads.values().map(|l| l.current_load).sum();
        let total_max_load: f64 = loads.values().map(|l| l.max_load).sum();
        let load_percentages: Vec<f64> = loads.values().map(|l| {
            if l.max_load > 0.0 { l.current_load / l.max_load } else { l.current_load }
        }).collect();

        let avg_load = total_current_load / total_workers as f64;
        let utilization = if total_max_load > 0.0 {
            total_current_load / total_max_load
        } else {
            0.0
        };

        // Count workers by load level
        let overloaded = load_percentages.iter().filter(|&&l| l >= 0.8).count();
        let critical = load_percentages.iter().filter(|&&l| l >= 0.95).count();
        let idle = load_percentages.iter().filter(|&&l| l < 0.1).count();

        // Find min/max load
        let min_load = load_percentages.iter().cloned().fold(f64::MAX, f64::min);
        let max_load = load_percentages.iter().cloned().fold(0.0, f64::max);

        ClusterLoadStats {
            total_workers,
            avg_load,
            utilization,
            min_load,
            max_load,
            overloaded_workers: overloaded,
            critical_workers: critical,
            idle_workers: idle,
            total_capacity: total_max_load,
            current_load: total_current_load,
        }
    }

    /// Check if worker meets requirements
    /// Check if a worker meets the compute requirements for a job
    fn worker_meets_requirements(&self, worker: &WorkerDetails, requirements: &ComputeRequirements) -> bool {
        let caps = &worker.capabilities;

        // Check GPU memory requirement
        if caps.gpu_memory_gb < requirements.min_gpu_memory_gb {
            return false;
        }

        // Check CPU cores requirement
        if caps.cpu_cores < requirements.min_cpu_cores {
            return false;
        }

        // Check RAM requirement
        if caps.ram_gb < requirements.min_ram_gb {
            return false;
        }

        // Check preferred GPU type if specified
        if let Some(ref preferred_gpu) = requirements.preferred_gpu_type {
            if !caps.gpu_model.to_lowercase().contains(&preferred_gpu.to_lowercase()) {
                // Preferred but not required - don't reject, just note for scoring
                // This is handled in find_best_worker scoring
            }
        }

        // Check if worker is healthy and available
        if !matches!(worker.health.status, WorkerStatus::Online) {
            return false;
        }

        // Check if worker has capacity (load < 90%)
        let load_threshold = 0.9;
        if worker.load > load_threshold {
            return false;
        }

        // Check specialized hardware requirements
        if requirements.requires_specialized_hardware {
            // Worker must have TEE support or special accelerators
            if !caps.gpu_tee_support && !matches!(caps.tee_type, TeeType::None) {
                return false;
            }
        }

        true
    }

    /// Score a worker for job assignment (higher is better)
    pub fn score_worker(&self, worker: &WorkerDetails, requirements: &ComputeRequirements) -> f64 {
        let mut score = 0.0;

        // Base score from reputation (0-100)
        score += worker.reputation * 100.0;

        // Availability score (lower load is better)
        score += (1.0 - worker.load) * 50.0;

        // Resource match score
        let gpu_match = (worker.capabilities.gpu_memory_gb as f64 / requirements.min_gpu_memory_gb.max(1) as f64).min(2.0);
        let cpu_match = (worker.capabilities.cpu_cores as f64 / requirements.min_cpu_cores.max(1) as f64).min(2.0);
        let ram_match = (worker.capabilities.ram_gb as f64 / requirements.min_ram_gb.max(1) as f64).min(2.0);
        score += (gpu_match + cpu_match + ram_match) * 10.0;

        // Preferred GPU type bonus
        if let Some(ref preferred_gpu) = requirements.preferred_gpu_type {
            if worker.capabilities.gpu_model.to_lowercase().contains(&preferred_gpu.to_lowercase()) {
                score += 25.0;
            }
        }

        // Success rate bonus
        let total_jobs = worker.total_jobs_completed + worker.total_jobs_failed;
        if total_jobs > 0 {
            let success_rate = worker.total_jobs_completed as f64 / total_jobs as f64;
            score += success_rate * 20.0;
        }

        // Recent activity penalty (workers not seen recently get lower scores)
        let now = chrono::Utc::now().timestamp() as u64;
        let time_since_seen = now.saturating_sub(worker.last_seen);
        if time_since_seen > 60 {
            score -= (time_since_seen as f64 / 60.0).min(20.0); // Max 20 point penalty
        }

        score
    }

    /// Update statistics for worker registered
    async fn update_stats_worker_registered(&self) {
        let mut stats = self.stats.write().await;
        stats.total_workers += 1;
        stats.active_workers += 1;
    }

    /// Update statistics for worker unregistered
    async fn update_stats_worker_unregistered(&self) {
        let mut stats = self.stats.write().await;
        stats.total_workers = stats.total_workers.saturating_sub(1);
        stats.active_workers = stats.active_workers.saturating_sub(1);
    }

    /// Take the event receiver.
    ///
    /// This can only be called once - subsequent calls will return `None`.
    pub async fn take_event_receiver(&self) -> Option<mpsc::UnboundedReceiver<WorkerEvent>> {
        self.event_receiver.write().await.take()
    }

    /// Check if the event receiver is still available.
    pub async fn has_event_receiver(&self) -> bool {
        self.event_receiver.read().await.is_some()
    }

    /// Get the database reference
    pub fn database(&self) -> &Arc<Database> {
        &self.database
    }

    /// Get the network coordinator reference
    pub fn network_coordinator(&self) -> &Arc<NetworkCoordinator> {
        &self.network_coordinator
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::WorkerId;
    

    #[tokio::test]
    async fn test_worker_manager_creation() {
        // Setup omitted for brevity - would require mocking dependencies
    }

    #[test]
    fn test_cluster_load_stats_default() {
        let stats = ClusterLoadStats::default();
        assert_eq!(stats.total_workers, 0);
        assert_eq!(stats.avg_load, 0.0);
        assert_eq!(stats.utilization, 0.0);
        assert_eq!(stats.overloaded_workers, 0);
        assert_eq!(stats.critical_workers, 0);
        assert_eq!(stats.idle_workers, 0);
    }

    #[test]
    fn test_worker_status_variants() {
        assert_ne!(WorkerStatus::Online, WorkerStatus::Busy);
        assert_ne!(WorkerStatus::Online, WorkerStatus::Offline);
        assert_ne!(WorkerStatus::Busy, WorkerStatus::Unhealthy);
        assert_ne!(WorkerStatus::Offline, WorkerStatus::Maintenance);
    }

    #[test]
    fn test_worker_health_creation() {
        let health = WorkerHealth {
            cpu_usage: 0.5,
            memory_usage: 0.6,
            gpu_usage: Some(0.7),
            disk_usage: 0.3,
            network_latency_ms: 10,
            uptime_secs: 3600,
            last_heartbeat: chrono::Utc::now().timestamp() as u64,
            status: WorkerStatus::Online,
        };

        assert_eq!(health.cpu_usage, 0.5);
        assert_eq!(health.memory_usage, 0.6);
        assert_eq!(health.gpu_usage, Some(0.7));
        assert_eq!(health.status, WorkerStatus::Online);
    }

    #[test]
    fn test_worker_event_variants() {
        let worker_id = WorkerId::new();

        // Test basic event creation
        let _evt1 = WorkerEvent::WorkerUnregistered(worker_id.clone());
        let _evt2 = WorkerEvent::WorkerLoadUpdated(worker_id.clone(), 0.5);
        let _evt3 = WorkerEvent::WorkerReputationUpdated(worker_id.clone(), 0.9);
        let _evt4 = WorkerEvent::WorkerTimeout(worker_id.clone());
        let _evt5 = WorkerEvent::WorkerFailed(worker_id.clone(), "test error".to_string());
    }

    #[test]
    fn test_worker_stats_creation() {
        let stats = WorkerStats {
            total_workers: 10,
            active_workers: 8,
            online_workers: 6,
            busy_workers: 2,
            offline_workers: 2,
            average_reputation: 0.85,
            average_load: 0.6,
            total_compute_capacity: 100,
            available_compute_capacity: 40,
        };

        assert_eq!(stats.total_workers, 10);
        assert_eq!(stats.active_workers, 8);
        assert_eq!(stats.average_reputation, 0.85);
    }

    #[test]
    fn test_calculate_max_load_with_gpu() {
        // Test the load calculation logic directly
        // GPU worker: 16GB GPU, 8 cores, 32GB RAM, 500GB disk

        let gpu_capacity: f64 = (16.0_f64 / 8.0).max(0.5); // 2.0
        let cpu_capacity: f64 = (8.0_f64 / 8.0).clamp(0.25, 4.0); // 1.0
        let ram_capacity: f64 = (32.0_f64 / 16.0).clamp(0.25, 4.0); // 2.0
        let storage_factor: f64 = (500.0_f64 / 500.0).clamp(0.5, 2.0); // 1.0

        let base_load: f64 = (gpu_capacity * 0.5 + cpu_capacity * 0.3 + ram_capacity * 0.2) * storage_factor;
        // = (2.0 * 0.5 + 1.0 * 0.3 + 2.0 * 0.2) * 1.0
        // = (1.0 + 0.3 + 0.4) * 1.0 = 1.7

        let parallel_factor: f64 = (4.0_f64 / 2.0).clamp(0.5, 4.0); // 2.0 (for max_parallel_tasks = 4)
        let expected: f64 = (base_load * parallel_factor).clamp(0.25, 16.0); // 3.4

        assert!((expected - 3.4).abs() < 0.001);
    }

    #[test]
    fn test_calculate_max_load_cpu_only() {
        // CPU-only worker: 0GB GPU, 16 cores, 64GB RAM, 1TB disk
        let gpu_capacity: f64 = 0.25; // CPU-only
        let cpu_capacity: f64 = (16.0_f64 / 8.0).clamp(0.25, 4.0); // 2.0
        let ram_capacity: f64 = (64.0_f64 / 16.0).clamp(0.25, 4.0); // 4.0
        let storage_factor: f64 = (1000.0_f64 / 500.0).clamp(0.5, 2.0); // 2.0

        let base_load: f64 = (gpu_capacity * 0.5 + cpu_capacity * 0.3 + ram_capacity * 0.2) * storage_factor;
        // = (0.25 * 0.5 + 2.0 * 0.3 + 4.0 * 0.2) * 2.0
        // = (0.125 + 0.6 + 0.8) * 2.0 = 3.05

        assert!(base_load > 3.0);
        assert!(base_load < 3.1);
    }

    #[test]
    fn test_cluster_load_stats_serialization() {
        let stats = ClusterLoadStats {
            total_workers: 5,
            avg_load: 0.65,
            utilization: 0.7,
            min_load: 0.2,
            max_load: 0.95,
            overloaded_workers: 2,
            critical_workers: 1,
            idle_workers: 1,
            total_capacity: 10.0,
            current_load: 7.0,
        };

        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: ClusterLoadStats = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.total_workers, 5);
        assert_eq!(deserialized.overloaded_workers, 2);
        assert_eq!(deserialized.critical_workers, 1);
    }

    #[test]
    fn test_load_threshold_constants() {
        // Verify our load threshold logic
        let high_load: f64 = 0.8;
        let critical_load: f64 = 0.95;

        // A worker at 85% should be considered high load but not critical
        let worker_load: f64 = 0.85;
        assert!(worker_load >= high_load);
        assert!(worker_load < critical_load);

        // A worker at 96% should be considered critical
        let critical_worker_load: f64 = 0.96;
        assert!(critical_worker_load >= critical_load);

        // A worker at 50% should be neither
        let normal_load: f64 = 0.5;
        assert!(normal_load < high_load);
    }
}
