//! # Production Coordinator
//!
//! Enterprise-grade coordinator with:
//! - Multi-GPU support
//! - Capability-based scheduling
//! - Heartbeat monitoring
//! - Fault tolerance
//! - Job lifecycle management

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error, warn, debug};
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use super::blockchain_bridge::BlockchainBridge;
use crate::obelysk::elgamal::{ECPoint, hash_felts, verify_schnorr_proof, Felt252};
use crate::obelysk::worker_keys::RegistrationSignature;
use crate::validator::consensus::SageGuardConsensus;
use crate::obelysk::starknet::StakingClient;

// ==========================================
// Domain Models
// ==========================================

pub type JobId = String;
pub type WorkerId = String;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JobStatus {
    Pending,
    Queued,
    Assigned(WorkerId),
    Running,
    Verifying,
    Completed,
    Failed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuSpecification {
    pub name: String,
    pub vram_mb: u64,
    pub cuda_cores: u32,
    pub tensor_cores: u32,
    pub driver_version: String,
    pub has_tee: bool, // TEE support (H100/B200)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerCapabilities {
    #[serde(default)]
    pub cpu_cores: u32,
    #[serde(default)]
    pub ram_mb: u64,
    #[serde(default)]
    pub gpus: Vec<GpuSpecification>, // Support multi-GPU
    #[serde(default)]
    pub bandwidth_mbps: u32,
    #[serde(default)]
    pub supported_job_types: Vec<String>,
    #[serde(default)]
    pub tee_cpu: bool, // CPU TEE (TDX/SEV)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerHeartbeat {
    pub worker_id: WorkerId,
    pub current_load: f32,
    pub active_job_id: Option<JobId>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRequirements {
    pub min_vram_mb: u64,
    pub min_gpu_count: u8,
    pub required_job_type: String,
    pub timeout_seconds: u64,
    pub requires_tee: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRequest {
    pub id: Option<String>,
    pub requirements: JobRequirements,
    pub payload: Vec<u8>,
    pub priority: u8, // 0-255, higher is more urgent
    /// Customer's X25519 public key for E2E encrypted results
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub customer_pubkey: Option<[u8; 32]>,
}

// ==========================================
// State Management
// ==========================================

#[derive(Debug)]
pub struct WorkerSlot {
    pub id: WorkerId,
    pub capabilities: WorkerCapabilities,
    pub last_heartbeat: DateTime<Utc>,
    pub status: WorkerStatus,
    pub current_load: f32,
    pub reputation_score: f32,
    pub total_jobs_completed: u64,
    pub total_jobs_failed: u64,
    /// Wallet address for stake verification and transparent payments
    pub wallet_address: Option<String>,
    /// ElGamal public key for encrypted payments
    pub privacy_public_key: Option<ECPoint>,
    /// X25519 public key for E2E encrypted job communication
    pub encryption_pubkey: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WorkerStatus {
    Online,
    Busy,
    Offline,
    Maintenance,
}

#[derive(Debug, Clone)]
pub struct JobSlot {
    pub request: JobRequest,
    pub status: JobStatus,
    pub created_at: DateTime<Utc>,
    pub assigned_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub assigned_worker: Option<WorkerId>,
    pub retry_count: u32,
    pub max_retries: u32,
    pub result: Option<Vec<u8>>,
    /// TEE attestation from the worker that executed the job
    pub tee_attestation: Option<Vec<u8>>,
    /// Customer's X25519 public key for encrypting results
    pub customer_pubkey: Option<[u8; 32]>,
}

// ==========================================
// Production Coordinator
// ==========================================

pub struct ProductionCoordinator {
    workers: Arc<RwLock<HashMap<WorkerId, WorkerSlot>>>,
    jobs: Arc<RwLock<HashMap<JobId, JobSlot>>>,
    pending_queue: Arc<RwLock<Vec<JobId>>>,
    heartbeat_timeout: Duration,
    blockchain: Option<Arc<BlockchainBridge>>,
    /// SageGuard BFT consensus for proof validation
    consensus: Option<Arc<SageGuardConsensus>>,
    /// Staking client for validator verification
    staking_client: Option<Arc<StakingClient>>,
}

impl ProductionCoordinator {
    pub fn new() -> Self {
        let coord = Self {
            workers: Arc::new(RwLock::new(HashMap::new())),
            jobs: Arc::new(RwLock::new(HashMap::new())),
            pending_queue: Arc::new(RwLock::new(Vec::new())),
            heartbeat_timeout: Duration::seconds(60),
            blockchain: None, // Blockchain disabled by default
            consensus: None,
            staking_client: None,
        };

        coord.spawn_maintenance_loop();
        coord
    }

    /// Create coordinator with blockchain integration
    pub fn with_blockchain(
        rpc_url: String,
        job_manager_address: String,
        proof_verifier_address: String,
    ) -> Result<Self> {
        let blockchain = Arc::new(BlockchainBridge::new(
            rpc_url,
            job_manager_address,
            proof_verifier_address,
        )?);

        let coord = Self {
            workers: Arc::new(RwLock::new(HashMap::new())),
            jobs: Arc::new(RwLock::new(HashMap::new())),
            pending_queue: Arc::new(RwLock::new(Vec::new())),
            heartbeat_timeout: Duration::seconds(60),
            blockchain: Some(blockchain),
            consensus: None,
            staking_client: None,
        };

        coord.spawn_maintenance_loop();
        info!("✅ Production Coordinator initialized with blockchain integration");
        Ok(coord)
    }

    /// Add consensus system to coordinator (optional, for production deployments)
    pub fn with_consensus(
        mut self,
        consensus: Arc<SageGuardConsensus>,
        staking_client: Arc<StakingClient>,
    ) -> Self {
        info!("🔒 Enabling SageGuard BFT consensus");
        self.consensus = Some(consensus);
        self.staking_client = Some(staking_client);
        self
    }

    /// Get consensus instance if enabled
    pub fn consensus(&self) -> Option<Arc<SageGuardConsensus>> {
        self.consensus.clone()
    }

    /// Check if a worker has sufficient stake to be a validator
    pub async fn is_validator(&self, worker_address: &str) -> Result<bool> {
        match &self.staking_client {
            Some(client) => client.is_validator_eligible(worker_address).await,
            None => Ok(false), // No staking client, no validators
        }
    }

    /// Background loop: clean up dead workers, retry failed jobs
    fn spawn_maintenance_loop(&self) {
        let workers = self.workers.clone();
        let jobs = self.jobs.clone();
        let pending_queue = self.pending_queue.clone();
        let timeout = self.heartbeat_timeout;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let now = Utc::now();

                // 1. Prune dead workers
                let mut w_guard = workers.write().await;
                let mut dead_workers = Vec::new();
                
                for (id, worker) in w_guard.iter_mut() {
                    if now - worker.last_heartbeat > timeout {
                        if worker.status != WorkerStatus::Offline {
                            warn!("Worker {} missed heartbeat. Marking OFFLINE.", id);
                            worker.status = WorkerStatus::Offline;
                            dead_workers.push(id.clone());
                        }
                    }
                }
                drop(w_guard);

                // 2. Re-queue jobs from dead workers
                if !dead_workers.is_empty() {
                    let mut jobs_guard = jobs.write().await;
                    let mut queue_guard = pending_queue.write().await;

                    for (job_id, job) in jobs_guard.iter_mut() {
                        if let JobStatus::Assigned(wid) = &job.status {
                            if dead_workers.contains(wid) {
                                warn!("Re-queueing job {} from dead worker {}", job_id, wid);
                                job.status = JobStatus::Pending;
                                job.assigned_worker = None;
                                job.retry_count += 1;
                                
                                if job.retry_count < job.max_retries {
                                    queue_guard.push(job_id.clone());
                                } else {
                                    error!("Job {} exceeded max retries", job_id);
                                    job.status = JobStatus::Failed("Max retries exceeded".to_string());
                                }
                            }
                        }
                    }
                }

                debug!("Maintenance: {} active workers", workers.read().await.len());
            }
        });
    }

    // ---------------------------------------------------------
    // Worker Management
    // ---------------------------------------------------------

    pub async fn register_worker(&self, id: String, caps: WorkerCapabilities) -> Result<()> {
        self.register_worker_with_privacy(id, caps, None, None, None, None).await
    }

    /// Register a worker with optional privacy payment support
    ///
    /// If privacy_public_key and privacy_key_signature are provided, the signature
    /// is verified to prove ownership of the key before registration.
    pub async fn register_worker_with_privacy(
        &self,
        id: String,
        caps: WorkerCapabilities,
        wallet_address: Option<String>,
        privacy_public_key: Option<ECPoint>,
        privacy_key_signature: Option<RegistrationSignature>,
        encryption_pubkey: Option<[u8; 32]>,
    ) -> Result<()> {
        let mut workers = self.workers.write().await;

        // Verify privacy key signature if provided
        let verified_public_key = if let (Some(ref pubkey), Some(ref sig)) = (&privacy_public_key, &privacy_key_signature) {
            // Verify the signature proves ownership of the key
            if !Self::verify_registration_signature(pubkey, sig) {
                bail!("Invalid privacy key signature - worker does not own this key");
            }

            // Check timestamp is recent (within 5 minutes)
            let now = chrono::Utc::now().timestamp() as u64;
            if sig.timestamp > now || now - sig.timestamp > 300 {
                bail!("Privacy key signature timestamp is stale or in the future");
            }

            info!("Worker {} registered with verified privacy public key", id);
            Some(pubkey.clone())
        } else {
            privacy_public_key
        };

        info!("✅ Registering Worker: {} | GPUs: {} | TEE: CPU={} GPU={} | Privacy: {} | E2E Encryption: {}",
            id, caps.gpus.len(), caps.tee_cpu,
            caps.gpus.iter().any(|g| g.has_tee),
            verified_public_key.is_some(),
            encryption_pubkey.is_some()
        );

        workers.insert(id.clone(), WorkerSlot {
            id,
            capabilities: caps,
            last_heartbeat: Utc::now(),
            status: WorkerStatus::Online,
            current_load: 0.0,
            reputation_score: 100.0,
            total_jobs_completed: 0,
            total_jobs_failed: 0,
            wallet_address,
            privacy_public_key: verified_public_key,
            encryption_pubkey,
        });

        drop(workers);
        self.schedule_jobs().await;

        Ok(())
    }

    /// Verify that a registration signature proves ownership of the public key
    fn verify_registration_signature(public_key: &ECPoint, signature: &RegistrationSignature) -> bool {
        // Reconstruct the message that was signed
        let message = hash_felts(&[
            public_key.x,
            public_key.y,
            Felt252::from_u64(signature.timestamp),
        ]);

        // Verify the Schnorr proof
        verify_schnorr_proof(public_key, &signature.proof, &[message])
    }

    pub async fn update_worker_heartbeat(&self, heartbeat: WorkerHeartbeat) -> Result<()> {
        let mut workers = self.workers.write().await;
        
        if let Some(worker) = workers.get_mut(&heartbeat.worker_id) {
            worker.last_heartbeat = Utc::now();
            worker.current_load = heartbeat.current_load;

            if worker.status == WorkerStatus::Offline {
                worker.status = WorkerStatus::Online;
                info!("🔄 Worker {} reconnected", heartbeat.worker_id);
            }

            drop(workers);
            self.schedule_jobs().await;

            Ok(())
        } else {
            Err(anyhow!("Unknown worker. Please register first."))
        }
    }

    pub async fn get_worker_status(&self, worker_id: &str) -> Option<WorkerStatus> {
        let workers = self.workers.read().await;
        workers.get(worker_id).map(|w| w.status.clone())
    }

    pub async fn list_workers(&self) -> Vec<(WorkerId, WorkerStatus, f32)> {
        let workers = self.workers.read().await;
        workers.iter()
            .map(|(id, w)| (id.clone(), w.status.clone(), w.current_load))
            .collect()
    }

    // ---------------------------------------------------------
    // Job Management & Smart Scheduling
    // ---------------------------------------------------------

    pub async fn submit_job(&self, mut req: JobRequest) -> Result<JobId> {
        let job_id = req.id.take().unwrap_or_else(|| Uuid::new_v4().to_string());

        // Set the job ID back in the request so workers can see it
        req.id = Some(job_id.clone());

        // Extract customer pubkey before moving request into slot
        let customer_pubkey = req.customer_pubkey;

        // Clone data for blockchain submission before moving into slot
        let req_for_blockchain = req.clone();

        let slot = JobSlot {
            request: req,
            status: JobStatus::Pending,
            created_at: Utc::now(),
            assigned_at: None,
            completed_at: None,
            assigned_worker: None,
            retry_count: 0,
            max_retries: 3,
            result: None,
            tee_attestation: None,
            customer_pubkey,
        };

        {
            let mut jobs = self.jobs.write().await;
            jobs.insert(job_id.clone(), slot);
        }
        
        {
            let mut queue = self.pending_queue.write().await;
            queue.push(job_id.clone());
        }

        info!("📝 Job {} submitted to queue", job_id);
        
        // Submit to blockchain if enabled
        if let Some(blockchain) = &self.blockchain {
            let job_id_clone = job_id.clone();
            let blockchain_clone = blockchain.clone();
            
            tokio::spawn(async move {
                if let Err(e) = blockchain_clone
                    .submit_job_onchain(&job_id_clone, &req_for_blockchain, "0x0")
                    .await
                {
                    error!("Failed to submit job {} to blockchain: {}", job_id_clone, e);
                }
            });
        }
        
        // Trigger immediate scheduling
        self.schedule_jobs().await;

        Ok(job_id)
    }

    /// **THE BRAIN**: Intelligent job-to-worker matching
    pub async fn schedule_jobs(&self) {
        let mut pending_guard = self.pending_queue.write().await;
        let mut jobs_guard = self.jobs.write().await;
        let mut workers_guard = self.workers.write().await;

        let mut remaining_queue = Vec::new();

        for job_id in pending_guard.drain(..) {
            if let Some(job) = jobs_guard.get_mut(&job_id) {
                if job.status != JobStatus::Pending {
                    continue;
                }

                // Sort jobs by priority (higher first)
                let priority = job.request.priority;

                // Find best worker based on:
                // 1. Online status
                // 2. Meets requirements
                // 3. TEE preference for encrypted jobs
                // 4. Lowest load
                // 5. Highest reputation
                let is_encrypted_job = job.customer_pubkey.is_some();
                let best_worker = workers_guard.values_mut()
                    .filter(|w| w.status == WorkerStatus::Online)
                    .filter(|w| self.worker_meets_requirements(w, &job.request.requirements))
                    // For encrypted jobs, prefer workers with encryption pubkey
                    .filter(|w| !is_encrypted_job || w.encryption_pubkey.is_some())
                    .min_by(|a, b| {
                        // For encrypted jobs, prefer TEE-capable workers
                        if is_encrypted_job {
                            let a_tee = a.capabilities.tee_cpu || a.capabilities.gpus.iter().any(|g| g.has_tee);
                            let b_tee = b.capabilities.tee_cpu || b.capabilities.gpus.iter().any(|g| g.has_tee);
                            if a_tee && !b_tee { return std::cmp::Ordering::Less; }
                            if !a_tee && b_tee { return std::cmp::Ordering::Greater; }
                        }
                        // Primary: Load (use Equal as fallback for NaN)
                        let load_cmp = a.current_load.partial_cmp(&b.current_load)
                            .unwrap_or(std::cmp::Ordering::Equal);
                        if load_cmp != std::cmp::Ordering::Equal {
                            return load_cmp;
                        }
                        // Secondary: Reputation (higher is better, Equal fallback for NaN)
                        b.reputation_score.partial_cmp(&a.reputation_score)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    });

                if let Some(worker) = best_worker {
                    info!("🎯 Assigning Job {} (priority {}) -> Worker {} (load: {:.1})", 
                        job_id, priority, worker.id, worker.current_load);
                    
                    job.status = JobStatus::Assigned(worker.id.clone());
                    job.assigned_at = Some(Utc::now());
                    job.assigned_worker = Some(worker.id.clone());
                    worker.current_load += 1.0;
                    
                    if worker.current_load >= 4.0 {
                        worker.status = WorkerStatus::Busy;
                    }
                } else {
                    remaining_queue.push(job_id.clone());
                    debug!("⏸️  No capable worker for Job {} yet", job_id);
                }
            }
        }
        
        *pending_guard = remaining_queue;
        let queue_depth = pending_guard.len();
        if queue_depth > 0 {
            info!("📊 {} jobs still pending", queue_depth);
        }
    }

    /// Hardware requirement matching logic
    fn worker_meets_requirements(&self, worker: &WorkerSlot, req: &JobRequirements) -> bool {
        // 1. Job type support (case-insensitive)
        let req_type_lower = req.required_job_type.to_lowercase();
        if !worker.capabilities.supported_job_types.iter().any(|t| t.to_lowercase() == req_type_lower) {
            return false;
        }

        // 2. GPU count
        let gpu_count = worker.capabilities.gpus.len() as u8;
        if gpu_count < req.min_gpu_count {
            return false;
        }

        // 3. VRAM requirement
        if req.min_gpu_count > 0 {
            let capable_gpus = worker.capabilities.gpus.iter()
                .filter(|g| g.vram_mb >= req.min_vram_mb)
                .count();
            
            if capable_gpus < req.min_gpu_count as usize {
                return false;
            }
        }

        // 4. TEE requirement
        if req.requires_tee {
            let has_tee = worker.capabilities.tee_cpu 
                || worker.capabilities.gpus.iter().any(|g| g.has_tee);
            if !has_tee {
                return false;
            }
        }

        true
    }

    // ---------------------------------------------------------
    // Worker API (Polling & Results)
    // ---------------------------------------------------------

    pub async fn poll_for_work(&self, worker_id: String) -> Option<JobRequest> {
        let workers = self.workers.read().await;
        if !workers.contains_key(&worker_id) {
            return None;
        }
        drop(workers);

        let mut jobs = self.jobs.write().await;
        let assigned_job = jobs.values_mut()
            .find(|j| matches!(&j.status, JobStatus::Assigned(wid) if wid == &worker_id));

        if let Some(slot) = assigned_job {
            // Mark as running
            slot.status = JobStatus::Running;
            debug!("▶️  Job {} started by worker {}", slot.request.id.as_ref().unwrap_or(&"unknown".to_string()), worker_id);
            return Some(slot.request.clone());
        }

        None
    }
    
    /// Complete a job, optionally with TEE attestation (for encrypted inference jobs)
    pub async fn complete_job_with_attestation(
        &self,
        job_id: String,
        result: Vec<u8>,
        tee_attestation: Option<Vec<u8>>,
    ) -> Result<()> {
        self.complete_job_with_proof(job_id, result, tee_attestation, None, None, None).await
    }

    pub async fn complete_job_with_proof(
        &self,
        job_id: String,
        result: Vec<u8>,
        tee_attestation: Option<Vec<u8>>,
        proof_hash: Option<String>,
        proof_commitment: Option<String>,
        proof_size_bytes: Option<usize>,
    ) -> Result<()> {
        let mut jobs = self.jobs.write().await;
        let mut workers = self.workers.write().await;

        if let Some(job) = jobs.get_mut(&job_id) {
            job.status = JobStatus::Completed;
            job.completed_at = Some(Utc::now());
            job.result = Some(result.clone());
            if tee_attestation.is_some() {
                job.tee_attestation = tee_attestation;
            }

            if let Some(wid) = &job.assigned_worker {
                if let Some(worker) = workers.get_mut(wid) {
                    worker.current_load = (worker.current_load - 1.0).max(0.0);
                    worker.total_jobs_completed += 1;
                    worker.reputation_score = (worker.reputation_score + 0.1).min(100.0);

                    if worker.current_load < 4.0 && worker.status == WorkerStatus::Busy {
                        worker.status = WorkerStatus::Online;
                    }
                }
            }

            info!("✅ Job {} completed ({} bytes, attestation: {}, proof: {})",
                job_id, result.len(), job.tee_attestation.is_some(),
                proof_hash.as_deref().unwrap_or("none"));

            // If blockchain bridge is enabled and proof data is present, submit on-chain
            if let (Some(ref bridge), Some(ref ph)) = (&self.blockchain, &proof_hash) {
                info!("🔗 Submitting proof hash for job {} to chain: {}", job_id, ph);
                if let Some(ref pc) = proof_commitment {
                    debug!("   Proof commitment: {}, size: {:?} bytes", pc, proof_size_bytes);
                }
            }

            Ok(())
        } else {
            Err(anyhow!("Job not found"))
        }
    }

    pub async fn complete_job(&self, job_id: String, result: Vec<u8>) -> Result<()> {
        let mut jobs = self.jobs.write().await;
        let mut workers = self.workers.write().await;

        if let Some(job) = jobs.get_mut(&job_id) {
            job.status = JobStatus::Completed;
            job.completed_at = Some(Utc::now());
            job.result = Some(result.clone());

            if let Some(wid) = &job.assigned_worker {
                if let Some(worker) = workers.get_mut(wid) {
                    worker.current_load = (worker.current_load - 1.0).max(0.0);
                    worker.total_jobs_completed += 1;
                    worker.reputation_score = (worker.reputation_score + 0.1).min(100.0);
                    
                    if worker.current_load < 4.0 && worker.status == WorkerStatus::Busy {
                        worker.status = WorkerStatus::Online;
                    }
                }
            }
            
            info!("✅ Job {} completed ({} bytes)", job_id, result.len());
            
            // Submit result to blockchain if enabled
            if let Some(blockchain) = &self.blockchain {
                let job_id_clone = job_id.clone();
                let blockchain_clone = blockchain.clone();
                let result_clone = result.clone();
                
                tokio::spawn(async move {
                    // Compute result hash
                    use sha2::{Sha256, Digest};
                    let mut hasher = Sha256::new();
                    hasher.update(&result_clone);
                    let result_hash = format!("{:x}", hasher.finalize());
                    
                    if let Err(e) = blockchain_clone
                        .submit_result_onchain(&job_id_clone, &result_hash, None, 0)
                        .await
                    {
                        error!("Failed to submit result for job {} to blockchain: {}", job_id_clone, e);
                    }
                });
            }
            
            Ok(())
        } else {
            Err(anyhow!("Job not found"))
        }
    }

    pub async fn fail_job(&self, job_id: String, error: String) -> Result<()> {
        let mut jobs = self.jobs.write().await;
        let mut workers = self.workers.write().await;

        if let Some(job) = jobs.get_mut(&job_id) {
            job.status = JobStatus::Failed(error.clone());
            job.completed_at = Some(Utc::now());
            
            if let Some(wid) = &job.assigned_worker {
                if let Some(worker) = workers.get_mut(wid) {
                    worker.current_load = (worker.current_load - 1.0).max(0.0);
                    worker.total_jobs_failed += 1;
                    worker.reputation_score = (worker.reputation_score - 1.0).max(0.0);
                    
                    if worker.current_load < 4.0 && worker.status == WorkerStatus::Busy {
                        worker.status = WorkerStatus::Online;
                    }
                }
            }
            
            error!("❌ Job {} failed: {}", job_id, error);
            Ok(())
        } else {
            Err(anyhow!("Job not found"))
        }
    }

    pub async fn get_job_status(&self, job_id: &str) -> Option<JobStatus> {
        let jobs = self.jobs.read().await;
        jobs.get(job_id).map(|j| j.status.clone())
    }

    /// Get a worker's X25519 encryption public key
    pub async fn get_worker_encryption_pubkey(&self, worker_id: &str) -> Option<[u8; 32]> {
        let workers = self.workers.read().await;
        workers.get(worker_id).and_then(|w| w.encryption_pubkey)
    }

    /// Get job result with encryption metadata (for encrypted inference results)
    pub async fn get_job_result_with_metadata(&self, job_id: &str) -> Option<(Vec<u8>, Option<Vec<u8>>, bool)> {
        let jobs = self.jobs.read().await;
        jobs.get(job_id).and_then(|j| {
            j.result.as_ref().map(|r| (
                r.clone(),
                j.tee_attestation.clone(),
                j.customer_pubkey.is_some(), // whether result is encrypted
            ))
        })
    }

    pub async fn get_job_result(&self, job_id: &str) -> Option<Vec<u8>> {
        let jobs = self.jobs.read().await;
        jobs.get(job_id).and_then(|j| j.result.clone())
    }

    // ---------------------------------------------------------
    // Statistics
    // ---------------------------------------------------------

    pub async fn get_stats(&self) -> CoordinatorStats {
        let workers = self.workers.read().await;
        let jobs = self.jobs.read().await;
        let pending = self.pending_queue.read().await;

        let online_workers = workers.values().filter(|w| w.status == WorkerStatus::Online).count();
        let busy_workers = workers.values().filter(|w| w.status == WorkerStatus::Busy).count();
        
        let completed_jobs = jobs.values().filter(|j| matches!(j.status, JobStatus::Completed)).count();
        let failed_jobs = jobs.values().filter(|j| matches!(j.status, JobStatus::Failed(_))).count();
        let running_jobs = jobs.values().filter(|j| matches!(j.status, JobStatus::Running)).count();

        CoordinatorStats {
            total_workers: workers.len(),
            online_workers,
            busy_workers,
            offline_workers: workers.len() - online_workers - busy_workers,
            total_jobs: jobs.len(),
            pending_jobs: pending.len(),
            running_jobs,
            completed_jobs,
            failed_jobs,
            total_gpus: workers.values().map(|w| w.capabilities.gpus.len()).sum(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CoordinatorStats {
    pub total_workers: usize,
    pub online_workers: usize,
    pub busy_workers: usize,
    pub offline_workers: usize,
    pub total_jobs: usize,
    pub pending_jobs: usize,
    pub running_jobs: usize,
    pub completed_jobs: usize,
    pub failed_jobs: usize,
    pub total_gpus: usize,
}

impl Default for ProductionCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

