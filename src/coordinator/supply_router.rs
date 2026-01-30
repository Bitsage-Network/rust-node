//! # Hybrid Supply Router
//!
//! Routes compute jobs between cloud providers and decentralized miners.
//!
//! ## Supply Sources:
//! 1. **Cloud Providers** - Aggregated via Brev/Shadeform/direct APIs
//!    - Guaranteed SLA, instant availability
//!    - Higher cost (provider rate + 20% markup)
//!    - TEE available on some providers (GCP, Azure, AWS)
//!
//! 2. **Decentralized Miners** - Individual GPU owners
//!    - Lower cost (market rate, 80% to miner)
//!    - Variable availability
//!    - SAGE mining rewards
//!    - TEE via Obelysk layer
//!
//! ## Routing Strategy:
//! - Cost-sensitive workloads → Miners first, fallback to cloud
//! - SLA-critical workloads → Cloud first (guaranteed)
//! - TEE/Confidential → Cloud (native TEE) or Miners (Obelysk FHE)
//!
//! ## Job Execution Flow:
//! 1. Client submits job → route_and_assign_job()
//! 2. Supply router finds best miner/cloud
//! 3. Job assigned to miner → poll_job_for_miner()
//! 4. Miner executes and submits result → complete_job()
//! 5. SAGE paid out to miner

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::{Result, anyhow};
use tracing::{info, warn, debug, error};
use chrono::{DateTime, Utc, Duration};

use crate::cloud::provider_integration::{ProviderManager, CloudGpuInstance};
use crate::coordinator::gpu_pricing::{get_gpu_pricing, GpuModel};

/// Supply source for compute jobs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SupplySource {
    /// Decentralized miner network
    Miner,
    /// Cloud provider (aggregated)
    Cloud,
    /// Hybrid (try miner first, fallback to cloud)
    Hybrid,
}

/// Routing preference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingPreference {
    /// Preferred supply source
    pub preferred_source: SupplySource,
    /// Maximum price willing to pay (USD cents/hour)
    pub max_price_cents: Option<u32>,
    /// Require TEE/confidential compute
    pub require_tee: bool,
    /// Require specific GPU model
    pub require_gpu_model: Option<String>,
    /// Maximum wait time for miner availability (seconds)
    pub max_miner_wait_secs: u64,
    /// Fallback to cloud if miners unavailable
    pub fallback_to_cloud: bool,
}

impl Default for RoutingPreference {
    fn default() -> Self {
        Self {
            preferred_source: SupplySource::Hybrid,
            max_price_cents: None,
            require_tee: false,
            require_gpu_model: None,
            max_miner_wait_secs: 60,
            fallback_to_cloud: true,
        }
    }
}

/// Registered miner in the network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredMiner {
    /// Unique miner ID
    pub miner_id: String,
    /// Wallet address for SAGE payments
    pub wallet_address: String,
    /// GPU model
    pub gpu_model: String,
    /// Number of GPUs
    pub gpu_count: u32,
    /// VRAM per GPU in GiB
    pub vram_gib: u32,
    /// Has TEE capability (via Obelysk)
    pub has_tee: bool,
    /// Current load (0.0 - 1.0)
    pub current_load: f64,
    /// Status
    pub status: MinerStatus,
    /// Last heartbeat
    pub last_heartbeat: DateTime<Utc>,
    /// Total jobs completed
    pub jobs_completed: u64,
    /// Reputation score (0-100)
    pub reputation: u32,
    /// Hourly rate in USD cents (set by miner, capped by market)
    pub hourly_rate_cents: u32,
    /// Total SAGE earned
    pub total_sage_earned: u64,
}

/// Miner status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MinerStatus {
    Online,
    Busy,
    Offline,
    Suspended,
}

// =============================================================================
// Job Management Types
// =============================================================================

/// Job status in the execution pipeline
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobExecutionStatus {
    /// Job submitted, waiting for routing
    Pending,
    /// Job routed, waiting for miner to pick up
    Queued,
    /// Job assigned to miner, in progress
    Running,
    /// Job completed successfully
    Completed,
    /// Job failed
    Failed,
    /// Job timed out
    TimedOut,
    /// Job cancelled by client
    Cancelled,
}

/// Job submitted for execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionJob {
    /// Unique job ID
    pub job_id: String,
    /// Job type (AIInference, STWOProof, ModelDeploy, etc.)
    pub job_type: String,
    /// Job payload (serialized)
    pub payload: Vec<u8>,
    /// Minimum GPUs required
    pub min_gpus: u32,
    /// Minimum VRAM required (GiB)
    pub min_vram_gib: u32,
    /// Require TEE
    pub require_tee: bool,
    /// Maximum price (USD cents/hour)
    pub max_price_cents: Option<u32>,
    /// Timeout in seconds
    pub timeout_secs: u64,
    /// Priority (higher = more urgent)
    pub priority: u32,
    /// Client wallet address (for billing)
    pub client_address: Option<String>,
    /// Current status
    pub status: JobExecutionStatus,
    /// Assigned miner (if any)
    pub assigned_miner: Option<String>,
    /// Route decision
    pub route_decision: Option<RouteDecision>,
    /// Timestamps
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    /// Execution metrics
    pub execution_time_ms: Option<u64>,
    /// Result (if completed)
    pub result: Option<JobResult>,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// Job result from miner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResult {
    /// Output data
    pub output: Vec<u8>,
    /// ZK proof (if applicable)
    pub proof: Option<Vec<u8>>,
    /// Proof hash for verification
    pub proof_hash: Option<String>,
    /// GPU time used (seconds)
    pub gpu_seconds: u64,
    /// Metrics
    pub metrics: Option<serde_json::Value>,
}

/// SAGE payout for completed job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SagePayout {
    /// Job ID
    pub job_id: String,
    /// Miner who completed the job
    pub miner_id: String,
    /// Miner wallet address
    pub miner_wallet: String,
    /// Total job cost (USD cents)
    pub total_cost_cents: u64,
    /// Worker payment (USD cents) - 80%
    pub worker_payment_cents: u64,
    /// Protocol fee (USD cents) - 20%
    pub protocol_fee_cents: u64,
    /// SAGE amount at current rate
    pub sage_amount: u64,
    /// SAGE price used (USD)
    pub sage_price_usd: f64,
    /// Mining bonus (reputation-based)
    pub mining_bonus_sage: u64,
    /// Total SAGE payout
    pub total_sage_payout: u64,
    /// Timestamp
    pub paid_at: DateTime<Utc>,
}

/// Route decision for a job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteDecision {
    /// Chosen supply source
    pub source: SupplySource,
    /// Specific miner (if source is Miner)
    pub miner: Option<RegisteredMiner>,
    /// Cloud instance (if source is Cloud)
    pub cloud_instance: Option<CloudGpuInstance>,
    /// Estimated hourly cost in USD cents
    pub estimated_cost_cents: u32,
    /// Worker payment (80% for miners, provider cost for cloud)
    pub worker_payment_cents: u32,
    /// Protocol fee (20% for miners, 20% markup for cloud)
    pub protocol_fee_cents: u32,
    /// Estimated wait time in seconds
    pub estimated_wait_secs: u32,
    /// Whether TEE is available
    pub tee_available: bool,
    /// Reasoning for the decision
    pub reasoning: String,
}

/// Supply router for hybrid cloud/miner routing
pub struct SupplyRouter {
    /// Cloud provider manager
    provider_manager: Arc<ProviderManager>,
    /// Registered miners
    miners: Arc<RwLock<HashMap<String, RegisteredMiner>>>,
    /// GPU pricing reference
    gpu_pricing: HashMap<&'static str, GpuModel>,
    /// Miner heartbeat timeout
    heartbeat_timeout_secs: u64,
    /// All jobs (by job_id)
    jobs: Arc<RwLock<HashMap<String, ExecutionJob>>>,
    /// Jobs queued for each miner (miner_id -> job_ids)
    miner_job_queues: Arc<RwLock<HashMap<String, VecDeque<String>>>>,
    /// Completed job payouts
    payouts: Arc<RwLock<Vec<SagePayout>>>,
    /// Job timeout (default 10 minutes)
    job_timeout_secs: u64,
    /// Current SAGE price in USD (TODO: get from oracle)
    sage_price_usd: f64,
}

impl SupplyRouter {
    /// Create a new supply router
    pub fn new(provider_manager: Arc<ProviderManager>) -> Self {
        Self {
            provider_manager,
            miners: Arc::new(RwLock::new(HashMap::new())),
            gpu_pricing: get_gpu_pricing(),
            heartbeat_timeout_secs: 60,
            jobs: Arc::new(RwLock::new(HashMap::new())),
            miner_job_queues: Arc::new(RwLock::new(HashMap::new())),
            payouts: Arc::new(RwLock::new(Vec::new())),
            job_timeout_secs: 600, // 10 minutes default
            sage_price_usd: 0.10, // $0.10 per SAGE (TODO: oracle)
        }
    }

    /// Register a miner to the network
    pub async fn register_miner(&self, miner: RegisteredMiner) -> Result<()> {
        let miner_id = miner.miner_id.clone();

        // Validate miner's hourly rate against market
        let market_rate = self.get_market_rate(&miner.gpu_model);
        if miner.hourly_rate_cents > market_rate.saturating_mul(2) {
            warn!(
                "Miner {} hourly rate (${:.2}) is 2x above market (${:.2})",
                miner_id,
                miner.hourly_rate_cents as f64 / 100.0,
                market_rate as f64 / 100.0
            );
        }

        let mut miners = self.miners.write().await;
        miners.insert(miner_id.clone(), miner);
        info!("Registered miner: {}", miner_id);
        Ok(())
    }

    /// Update miner heartbeat
    pub async fn update_miner_heartbeat(
        &self,
        miner_id: &str,
        load: f64,
        status: MinerStatus,
    ) -> Result<()> {
        let mut miners = self.miners.write().await;
        if let Some(miner) = miners.get_mut(miner_id) {
            miner.last_heartbeat = Utc::now();
            miner.current_load = load;
            miner.status = status;
            Ok(())
        } else {
            Err(anyhow!("Miner {} not found", miner_id))
        }
    }

    /// Unregister a miner
    pub async fn unregister_miner(&self, miner_id: &str) -> Result<()> {
        let mut miners = self.miners.write().await;
        miners.remove(miner_id);
        info!("Unregistered miner: {}", miner_id);
        Ok(())
    }

    /// Get market rate for a GPU model (USD cents/hour)
    fn get_market_rate(&self, gpu_model: &str) -> u32 {
        // Try to find exact match
        if let Some(gpu) = self.gpu_pricing.get(gpu_model) {
            return gpu.bitsage_rate_cents;
        }

        // Try to match by name
        for (_, gpu) in &self.gpu_pricing {
            if gpu.name.contains(gpu_model) || gpu_model.contains(gpu.name) {
                return gpu.bitsage_rate_cents;
            }
        }

        // Default to mid-range rate
        100 // $1.00/hr
    }

    /// Route a job to the best supply source
    pub async fn route_job(
        &self,
        min_gpus: u32,
        min_vram_gib: u32,
        preference: RoutingPreference,
    ) -> Result<RouteDecision> {
        match preference.preferred_source {
            SupplySource::Miner => {
                self.try_miner_route(min_gpus, min_vram_gib, &preference).await
            }
            SupplySource::Cloud => {
                self.try_cloud_route(min_gpus, min_vram_gib, &preference).await
            }
            SupplySource::Hybrid => {
                // Try miner first, fallback to cloud
                match self.try_miner_route(min_gpus, min_vram_gib, &preference).await {
                    Ok(decision) => Ok(decision),
                    Err(miner_err) => {
                        if preference.fallback_to_cloud {
                            debug!("Miner route failed ({}), trying cloud", miner_err);
                            self.try_cloud_route(min_gpus, min_vram_gib, &preference).await
                        } else {
                            Err(miner_err)
                        }
                    }
                }
            }
        }
    }

    /// Try to route to a miner
    async fn try_miner_route(
        &self,
        min_gpus: u32,
        min_vram_gib: u32,
        preference: &RoutingPreference,
    ) -> Result<RouteDecision> {
        let miners = self.miners.read().await;
        let cutoff = Utc::now() - Duration::seconds(self.heartbeat_timeout_secs as i64);

        // Find available miners matching requirements
        let mut candidates: Vec<_> = miners
            .values()
            .filter(|m| {
                // Basic requirements
                m.gpu_count >= min_gpus
                    && m.vram_gib >= min_vram_gib
                    && m.status == MinerStatus::Online
                    && m.last_heartbeat > cutoff
                    && m.current_load < 0.9 // Not overloaded
            })
            .filter(|m| {
                // Optional requirements
                if preference.require_tee && !m.has_tee {
                    return false;
                }
                if let Some(ref model) = preference.require_gpu_model {
                    if !m.gpu_model.contains(model) {
                        return false;
                    }
                }
                if let Some(max_price) = preference.max_price_cents {
                    if m.hourly_rate_cents > max_price {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        if candidates.is_empty() {
            return Err(anyhow!("No available miners matching requirements"));
        }

        // Sort by: reputation (desc), load (asc), price (asc)
        candidates.sort_by(|a, b| {
            b.reputation.cmp(&a.reputation)
                .then(a.current_load.partial_cmp(&b.current_load).unwrap_or(std::cmp::Ordering::Equal))
                .then(a.hourly_rate_cents.cmp(&b.hourly_rate_cents))
        });

        // Safe: candidates is non-empty (checked above)
        let best_miner = candidates[0].clone();

        // Calculate cost breakdown (80/20 split)
        let total_cost = best_miner.hourly_rate_cents;
        let worker_payment = total_cost * 80 / 100;
        let protocol_fee = total_cost - worker_payment;

        Ok(RouteDecision {
            source: SupplySource::Miner,
            miner: Some(best_miner.clone()),
            cloud_instance: None,
            estimated_cost_cents: total_cost,
            worker_payment_cents: worker_payment,
            protocol_fee_cents: protocol_fee,
            estimated_wait_secs: (best_miner.current_load * 30.0) as u32, // Estimate based on load
            tee_available: best_miner.has_tee,
            reasoning: format!(
                "Routed to miner {} ({}x {}, reputation: {}, load: {:.0}%)",
                best_miner.miner_id,
                best_miner.gpu_count,
                best_miner.gpu_model,
                best_miner.reputation,
                best_miner.current_load * 100.0
            ),
        })
    }

    /// Try to route to cloud
    async fn try_cloud_route(
        &self,
        min_gpus: u32,
        min_vram_gib: u32,
        preference: &RoutingPreference,
    ) -> Result<RouteDecision> {
        let instances = self.provider_manager
            .find_instances(
                min_gpus,
                min_vram_gib,
                preference.max_price_cents,
                preference.require_tee,
            )
            .await;

        if instances.is_empty() {
            return Err(anyhow!("No cloud instances matching requirements"));
        }

        // Filter by GPU model if specified
        let instances: Vec<_> = if let Some(ref model) = preference.require_gpu_model {
            instances
                .into_iter()
                .filter(|i| i.gpu_model.contains(model))
                .collect()
        } else {
            instances
        };

        if instances.is_empty() {
            return Err(anyhow!("No cloud instances matching GPU model requirement"));
        }

        // Safe: instances is non-empty (checked above)
        let best = instances[0].clone();

        // Cloud pricing: provider cost + 20% markup (already calculated in bitsage_price_cents)
        let total_cost = best.bitsage_price_cents;
        let provider_cost = best.provider_price_cents;
        let markup = total_cost - provider_cost;

        Ok(RouteDecision {
            source: SupplySource::Cloud,
            miner: None,
            cloud_instance: Some(best.clone()),
            estimated_cost_cents: total_cost,
            worker_payment_cents: provider_cost, // Provider gets their rate
            protocol_fee_cents: markup,          // BitSage keeps the markup
            estimated_wait_secs: best.ready_time_minutes * 60,
            tee_available: best.has_tee,
            reasoning: format!(
                "Routed to {} cloud ({}x {}, ${:.2}/hr, ready in {}min)",
                best.provider.display_name(),
                best.gpu_count,
                best.gpu_model,
                total_cost as f64 / 100.0,
                best.ready_time_minutes
            ),
        })
    }

    /// Get network supply statistics
    pub async fn get_supply_stats(&self) -> SupplyStats {
        let miners = self.miners.read().await;
        let cutoff = Utc::now() - Duration::seconds(self.heartbeat_timeout_secs as i64);

        let online_miners: Vec<_> = miners
            .values()
            .filter(|m| m.status == MinerStatus::Online && m.last_heartbeat > cutoff)
            .collect();

        let total_miner_gpus: u32 = online_miners.iter().map(|m| m.gpu_count).sum();
        let avg_miner_load = if !online_miners.is_empty() {
            online_miners.iter().map(|m| m.current_load).sum::<f64>() / online_miners.len() as f64
        } else {
            0.0
        };

        let provider_stats = self.provider_manager.get_provider_stats().await;
        let cloud_instances = self.provider_manager.list_all_instance_types().await;

        // Calculate cloud GPU availability
        let total_cloud_gpus: u32 = cloud_instances
            .iter()
            .map(|i| i.gpu_count)
            .max()
            .unwrap_or(0);

        SupplyStats {
            // Miner stats
            total_miners: miners.len(),
            online_miners: online_miners.len(),
            total_miner_gpus,
            avg_miner_load,

            // Cloud stats
            cloud_providers_enabled: provider_stats.providers_enabled,
            cloud_instance_types: cloud_instances.len(),
            cloud_active_instances: provider_stats.active_instances,
            cloud_hourly_spend_cents: provider_stats.hourly_spend_cents,
            max_cloud_gpus: total_cloud_gpus,

            // Pricing
            cheapest_miner_rate: online_miners
                .iter()
                .map(|m| m.hourly_rate_cents)
                .min()
                .unwrap_or(0),
            cheapest_cloud_rate: cloud_instances
                .iter()
                .filter(|i| i.gpu_count == 1)
                .map(|i| i.bitsage_price_cents)
                .min()
                .unwrap_or(0),
        }
    }

    /// List all online miners
    pub async fn list_online_miners(&self) -> Vec<RegisteredMiner> {
        let miners = self.miners.read().await;
        let cutoff = Utc::now() - Duration::seconds(self.heartbeat_timeout_secs as i64);

        miners
            .values()
            .filter(|m| m.status == MinerStatus::Online && m.last_heartbeat > cutoff)
            .cloned()
            .collect()
    }

    /// Award SAGE to a miner for completing a job
    pub async fn award_sage_to_miner(
        &self,
        miner_id: &str,
        sage_amount: u64,
    ) -> Result<()> {
        let mut miners = self.miners.write().await;
        if let Some(miner) = miners.get_mut(miner_id) {
            miner.total_sage_earned += sage_amount;
            miner.jobs_completed += 1;

            // Update reputation based on job completion
            miner.reputation = std::cmp::min(100, miner.reputation + 1);

            info!(
                "Awarded {} SAGE to miner {} (total: {} SAGE, jobs: {})",
                sage_amount, miner_id, miner.total_sage_earned, miner.jobs_completed
            );
            Ok(())
        } else {
            Err(anyhow!("Miner {} not found", miner_id))
        }
    }

    // =========================================================================
    // Job Execution Pipeline
    // =========================================================================

    /// Submit a job, route it, and assign to a miner
    pub async fn submit_job(&self, request: JobSubmitRequest) -> Result<JobSubmitResponse> {
        let job_id = format!("job-{}", uuid::Uuid::new_v4().to_string()[..12].to_string());

        // Create the execution job
        let mut job = ExecutionJob {
            job_id: job_id.clone(),
            job_type: request.job_type.clone(),
            payload: request.payload.clone(),
            min_gpus: request.min_gpus.unwrap_or(1),
            min_vram_gib: request.min_vram_gib.unwrap_or(24),
            require_tee: request.require_tee.unwrap_or(false),
            max_price_cents: request.max_price_cents,
            timeout_secs: request.timeout_secs.unwrap_or(self.job_timeout_secs),
            priority: request.priority.unwrap_or(100),
            client_address: request.client_address.clone(),
            status: JobExecutionStatus::Pending,
            assigned_miner: None,
            route_decision: None,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            execution_time_ms: None,
            result: None,
            error: None,
        };

        // Route the job
        let preference = RoutingPreference {
            preferred_source: match request.prefer_source.as_deref() {
                Some("miner") => SupplySource::Miner,
                Some("cloud") => SupplySource::Cloud,
                _ => SupplySource::Hybrid,
            },
            max_price_cents: request.max_price_cents,
            require_tee: request.require_tee.unwrap_or(false),
            require_gpu_model: request.require_gpu_model.clone(),
            max_miner_wait_secs: 60,
            fallback_to_cloud: true,
        };

        let route_decision = self.route_job(
            job.min_gpus,
            job.min_vram_gib,
            preference,
        ).await?;

        // Assign to miner if routed to miner
        if let Some(ref miner) = route_decision.miner {
            job.assigned_miner = Some(miner.miner_id.clone());
            job.status = JobExecutionStatus::Queued;

            // Add to miner's job queue
            let mut queues = self.miner_job_queues.write().await;
            queues
                .entry(miner.miner_id.clone())
                .or_insert_with(VecDeque::new)
                .push_back(job_id.clone());

            // Update miner status to busy if they have jobs
            let mut miners = self.miners.write().await;
            if let Some(m) = miners.get_mut(&miner.miner_id) {
                if m.status == MinerStatus::Online {
                    m.current_load = (m.current_load + 0.2).min(1.0);
                }
            }

            info!(
                "Job {} assigned to miner {} ({}x {})",
                job_id, miner.miner_id, miner.gpu_count, miner.gpu_model
            );
        }

        job.route_decision = Some(route_decision.clone());

        // Store the job
        {
            let mut jobs = self.jobs.write().await;
            jobs.insert(job_id.clone(), job);
        }

        let assigned_miner_id = route_decision.miner.as_ref().map(|m| m.miner_id.clone());

        Ok(JobSubmitResponse {
            job_id,
            status: JobExecutionStatus::Queued,
            assigned_miner: assigned_miner_id,
            estimated_cost_cents: route_decision.estimated_cost_cents,
            estimated_wait_secs: route_decision.estimated_wait_secs,
            route_decision,
        })
    }

    /// Miner polls for jobs assigned to them
    pub async fn poll_job_for_miner(&self, miner_id: &str) -> Option<MinerJobAssignment> {
        // Check if miner has jobs in queue
        let job_id = {
            let mut queues = self.miner_job_queues.write().await;
            let queue = queues.get_mut(miner_id)?;
            queue.pop_front()
        };

        let job_id = job_id?;

        // Get and update the job
        let mut jobs = self.jobs.write().await;
        let job = jobs.get_mut(&job_id)?;

        // Mark as running
        job.status = JobExecutionStatus::Running;
        job.started_at = Some(Utc::now());

        info!("Miner {} started job {} ({})", miner_id, job_id, job.job_type);

        Some(MinerJobAssignment {
            job_id: job.job_id.clone(),
            job_type: job.job_type.clone(),
            payload: job.payload.clone(),
            timeout_secs: job.timeout_secs,
            require_tee: job.require_tee,
            estimated_payment_cents: job.route_decision.as_ref()
                .map(|r| r.worker_payment_cents)
                .unwrap_or(0),
        })
    }

    /// Miner completes a job with result
    pub async fn complete_job(
        &self,
        miner_id: &str,
        job_id: &str,
        result: JobResult,
    ) -> Result<SagePayout> {
        let mut jobs = self.jobs.write().await;
        let job = jobs.get_mut(job_id)
            .ok_or_else(|| anyhow!("Job {} not found", job_id))?;

        // Verify this miner was assigned
        if job.assigned_miner.as_deref() != Some(miner_id) {
            return Err(anyhow!("Miner {} is not assigned to job {}", miner_id, job_id));
        }

        // Calculate execution time
        let started_at = job.started_at.ok_or_else(|| anyhow!("Job was never started"))?;
        let execution_time_ms = (Utc::now() - started_at).num_milliseconds() as u64;

        // Update job
        job.status = JobExecutionStatus::Completed;
        job.completed_at = Some(Utc::now());
        job.execution_time_ms = Some(execution_time_ms);
        job.result = Some(result.clone());

        // Calculate payout
        let route = job.route_decision.as_ref()
            .ok_or_else(|| anyhow!("No route decision for job"))?;

        // Get miner info for wallet address
        let miner_wallet = {
            let miners = self.miners.read().await;
            miners.get(miner_id)
                .map(|m| m.wallet_address.clone())
                .unwrap_or_default()
        };

        // Get miner reputation for bonus
        let (reputation, miner_hourly_rate) = {
            let miners = self.miners.read().await;
            miners.get(miner_id)
                .map(|m| (m.reputation, m.hourly_rate_cents))
                .unwrap_or((50, 100))
        };

        // Calculate actual cost based on execution time
        let execution_hours = execution_time_ms as f64 / 3_600_000.0;
        let total_cost_cents = ((miner_hourly_rate as f64 * execution_hours) as u64).max(1);
        let worker_payment_cents = total_cost_cents * 80 / 100;
        let protocol_fee_cents = total_cost_cents - worker_payment_cents;

        // Convert to SAGE
        let sage_amount = ((worker_payment_cents as f64 / 100.0) / self.sage_price_usd) as u64;

        // Mining bonus based on reputation
        let mining_bonus_pct = if reputation >= 90 {
            10.0
        } else if reputation >= 70 {
            5.0
        } else if reputation >= 50 {
            2.0
        } else {
            0.0
        };
        let mining_bonus_sage = (sage_amount as f64 * mining_bonus_pct / 100.0) as u64;
        let total_sage_payout = sage_amount + mining_bonus_sage;

        let payout = SagePayout {
            job_id: job_id.to_string(),
            miner_id: miner_id.to_string(),
            miner_wallet: miner_wallet.clone(),
            total_cost_cents,
            worker_payment_cents,
            protocol_fee_cents,
            sage_amount,
            sage_price_usd: self.sage_price_usd,
            mining_bonus_sage,
            total_sage_payout,
            paid_at: Utc::now(),
        };

        // Award SAGE to miner
        drop(jobs); // Release lock before calling award_sage_to_miner
        self.award_sage_to_miner(miner_id, total_sage_payout).await?;

        // Store payout
        {
            let mut payouts = self.payouts.write().await;
            payouts.push(payout.clone());
        }

        // Update miner load
        {
            let mut miners = self.miners.write().await;
            if let Some(m) = miners.get_mut(miner_id) {
                m.current_load = (m.current_load - 0.2).max(0.0);
            }
        }

        info!(
            "Job {} completed by miner {}. Payout: {} SAGE (+ {} bonus)",
            job_id, miner_id, sage_amount, mining_bonus_sage
        );

        Ok(payout)
    }

    /// Miner reports job failure
    pub async fn fail_job(
        &self,
        miner_id: &str,
        job_id: &str,
        error: String,
    ) -> Result<()> {
        let mut jobs = self.jobs.write().await;
        let job = jobs.get_mut(job_id)
            .ok_or_else(|| anyhow!("Job {} not found", job_id))?;

        // Verify this miner was assigned
        if job.assigned_miner.as_deref() != Some(miner_id) {
            return Err(anyhow!("Miner {} is not assigned to job {}", miner_id, job_id));
        }

        job.status = JobExecutionStatus::Failed;
        job.completed_at = Some(Utc::now());
        job.error = Some(error.clone());

        // Update miner reputation (penalty for failure)
        drop(jobs);
        {
            let mut miners = self.miners.write().await;
            if let Some(m) = miners.get_mut(miner_id) {
                m.reputation = m.reputation.saturating_sub(2);
                m.current_load = (m.current_load - 0.2).max(0.0);
            }
        }

        warn!("Job {} failed by miner {}: {}", job_id, miner_id, error);

        // TODO: Optionally reassign to another miner
        Ok(())
    }

    /// Get job status
    pub async fn get_job(&self, job_id: &str) -> Option<ExecutionJob> {
        let jobs = self.jobs.read().await;
        jobs.get(job_id).cloned()
    }

    /// Get all jobs for a miner
    pub async fn get_miner_jobs(&self, miner_id: &str) -> Vec<ExecutionJob> {
        let jobs = self.jobs.read().await;
        jobs.values()
            .filter(|j| j.assigned_miner.as_deref() == Some(miner_id))
            .cloned()
            .collect()
    }

    /// Get job execution stats
    pub async fn get_job_stats(&self) -> JobStats {
        let jobs = self.jobs.read().await;
        let payouts = self.payouts.read().await;

        let total_jobs = jobs.len();
        let pending_jobs = jobs.values().filter(|j| j.status == JobExecutionStatus::Pending).count();
        let queued_jobs = jobs.values().filter(|j| j.status == JobExecutionStatus::Queued).count();
        let running_jobs = jobs.values().filter(|j| j.status == JobExecutionStatus::Running).count();
        let completed_jobs = jobs.values().filter(|j| j.status == JobExecutionStatus::Completed).count();
        let failed_jobs = jobs.values().filter(|j| j.status == JobExecutionStatus::Failed).count();

        let total_sage_paid: u64 = payouts.iter().map(|p| p.total_sage_payout).sum();
        let total_revenue_cents: u64 = payouts.iter().map(|p| p.protocol_fee_cents).sum();

        let avg_execution_time_ms = if completed_jobs > 0 {
            jobs.values()
                .filter(|j| j.status == JobExecutionStatus::Completed)
                .filter_map(|j| j.execution_time_ms)
                .sum::<u64>() / completed_jobs as u64
        } else {
            0
        };

        JobStats {
            total_jobs,
            pending_jobs,
            queued_jobs,
            running_jobs,
            completed_jobs,
            failed_jobs,
            total_sage_paid,
            total_revenue_cents,
            avg_execution_time_ms,
        }
    }

    /// Check for timed out jobs
    pub async fn check_timeouts(&self) {
        let now = Utc::now();
        let mut jobs = self.jobs.write().await;

        for job in jobs.values_mut() {
            if job.status == JobExecutionStatus::Running {
                if let Some(started_at) = job.started_at {
                    let elapsed = (now - started_at).num_seconds() as u64;
                    if elapsed > job.timeout_secs {
                        job.status = JobExecutionStatus::TimedOut;
                        job.completed_at = Some(now);
                        job.error = Some(format!("Job timed out after {} seconds", elapsed));

                        warn!("Job {} timed out after {} seconds", job.job_id, elapsed);

                        // TODO: Penalize miner, possibly reassign
                    }
                }
            }
        }
    }
}

// =============================================================================
// Job Request/Response Types
// =============================================================================

/// Job submission request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSubmitRequest {
    /// Job type
    pub job_type: String,
    /// Job payload
    pub payload: Vec<u8>,
    /// Minimum GPUs required
    pub min_gpus: Option<u32>,
    /// Minimum VRAM required (GiB)
    pub min_vram_gib: Option<u32>,
    /// Require TEE
    pub require_tee: Option<bool>,
    /// Maximum price (USD cents/hour)
    pub max_price_cents: Option<u32>,
    /// Timeout in seconds
    pub timeout_secs: Option<u64>,
    /// Priority
    pub priority: Option<u32>,
    /// Client wallet address
    pub client_address: Option<String>,
    /// Preferred supply source
    pub prefer_source: Option<String>,
    /// Require specific GPU model
    pub require_gpu_model: Option<String>,
}

/// Job submission response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSubmitResponse {
    pub job_id: String,
    pub status: JobExecutionStatus,
    pub assigned_miner: Option<String>,
    pub estimated_cost_cents: u32,
    pub estimated_wait_secs: u32,
    pub route_decision: RouteDecision,
}

/// Job assignment for miner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerJobAssignment {
    pub job_id: String,
    pub job_type: String,
    pub payload: Vec<u8>,
    pub timeout_secs: u64,
    pub require_tee: bool,
    pub estimated_payment_cents: u32,
}

/// Job execution statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobStats {
    pub total_jobs: usize,
    pub pending_jobs: usize,
    pub queued_jobs: usize,
    pub running_jobs: usize,
    pub completed_jobs: usize,
    pub failed_jobs: usize,
    pub total_sage_paid: u64,
    pub total_revenue_cents: u64,
    pub avg_execution_time_ms: u64,
}

/// Supply network statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyStats {
    // Miner network
    pub total_miners: usize,
    pub online_miners: usize,
    pub total_miner_gpus: u32,
    pub avg_miner_load: f64,

    // Cloud supply
    pub cloud_providers_enabled: usize,
    pub cloud_instance_types: usize,
    pub cloud_active_instances: usize,
    pub cloud_hourly_spend_cents: u64,
    pub max_cloud_gpus: u32,

    // Pricing
    pub cheapest_miner_rate: u32,
    pub cheapest_cloud_rate: u32,
}

/// Miner registration request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerRegistrationRequest {
    pub wallet_address: String,
    pub gpu_model: String,
    pub gpu_count: u32,
    pub vram_gib: u32,
    pub has_tee: bool,
    pub hourly_rate_cents: u32,
    /// Optional: TEE attestation for Obelysk verification
    pub tee_attestation: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_supply_router() {
        let provider_manager = Arc::new(ProviderManager::new(vec![]));
        provider_manager.initialize_static_pricing().await;

        let router = SupplyRouter::new(provider_manager);

        // Register a test miner
        let miner = RegisteredMiner {
            miner_id: "test-miner-1".to_string(),
            wallet_address: "0x123".to_string(),
            gpu_model: "RTX 4090".to_string(),
            gpu_count: 2,
            vram_gib: 24,
            has_tee: true,
            current_load: 0.3,
            status: MinerStatus::Online,
            last_heartbeat: Utc::now(),
            jobs_completed: 10,
            reputation: 85,
            hourly_rate_cents: 70, // $0.70/hr
            total_sage_earned: 1000,
        };

        router.register_miner(miner).await.unwrap();

        // Route a job
        let decision = router.route_job(
            1, 24,
            RoutingPreference::default(),
        ).await.unwrap();

        println!("Route decision: {:?}", decision);
        assert_eq!(decision.source, SupplySource::Miner);

        // Stats
        let stats = router.get_supply_stats().await;
        println!("Supply stats: {:?}", stats);
        assert_eq!(stats.online_miners, 1);
    }
}
