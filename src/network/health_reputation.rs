//! # Network Health and Reputation System
//!
//! This module implements the network health monitoring and worker reputation tracking system.
//! It integrates with the P2P network to maintain a decentralized view of node reliability
//! and network performance.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn};

use crate::types::WorkerId;
use crate::blockchain::types::WorkerCapabilities;

/// Health and Reputation Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReputationConfig {
    pub health_check_interval_secs: u64,
    pub reputation_update_interval_secs: u64,
    pub history_window_size: usize,
    pub penalty_decay_factor: f64,
    pub min_reputation_threshold: f64,
    /// Decay configuration
    pub decay_config: ReputationDecayConfig,
}

/// Configuration for reputation decay system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationDecayConfig {
    /// Hours of inactivity before decay starts
    pub inactivity_threshold_hours: u64,
    /// Decay rate per day (0.0-1.0, where 0.01 = 1% per day)
    pub daily_decay_rate: f64,
    /// Minimum reputation after decay (floor)
    pub decay_floor: f64,
    /// Maximum reputation recovery per job
    pub max_recovery_per_job: f64,
    /// Enable exponential decay (vs linear)
    pub use_exponential_decay: bool,
    /// Grace period for new workers (hours without decay)
    pub new_worker_grace_period_hours: u64,
    /// Penalty decay rate (how fast old penalties stop affecting score)
    pub penalty_decay_rate: f64,
}

impl Default for ReputationDecayConfig {
    fn default() -> Self {
        Self {
            inactivity_threshold_hours: 24,       // Start decay after 24h inactive
            daily_decay_rate: 0.02,               // 2% decay per day
            decay_floor: 0.3,                     // Never decay below 30%
            max_recovery_per_job: 0.05,           // Max 5% recovery per successful job
            use_exponential_decay: true,          // Smoother decay curve
            new_worker_grace_period_hours: 168,   // 7 days grace for new workers
            penalty_decay_rate: 0.1,              // 10% penalty forgiveness per day
        }
    }
}

impl Default for HealthReputationConfig {
    fn default() -> Self {
        Self {
            health_check_interval_secs: 60,
            reputation_update_interval_secs: 300,
            history_window_size: 100,
            penalty_decay_factor: 0.95,
            min_reputation_threshold: 0.5,
            decay_config: ReputationDecayConfig::default(),
        }
    }
}

/// Worker health metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerHealth {
    pub response_time_ms: u32,
    pub cpu_usage_percent: f32,
    pub memory_usage_percent: f32,
    pub disk_usage_percent: f32,
    pub network_latency_ms: u32,
    pub uptime_seconds: u64,
    pub load_average: f32,
    pub temperature_celsius: f32,
    pub gpu_utilization_percent: Option<f32>,
    pub gpu_memory_usage_percent: Option<f32>,
    pub network_bandwidth_mbps: u32,
}

/// Health metrics for reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthMetrics {
    pub response_time_ms: u32,
    pub cpu_usage_percent: f32,
    pub memory_usage_percent: f32,
    pub disk_usage_percent: f32,
    pub network_latency_ms: u32,
    pub uptime_seconds: u64,
    pub load_average: f32,
    pub temperature_celsius: f32,
    pub gpu_utilization_percent: Option<f32>,
    pub gpu_memory_usage_percent: Option<f32>,
    pub network_bandwidth_mbps: u32,
}

/// Worker reputation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerReputation {
    pub worker_id: WorkerId,
    pub reputation_score: f64,
    pub jobs_completed: u64,
    pub jobs_failed: u64,
    pub jobs_timeout: u64,
    pub total_earnings: u128,
    pub average_completion_time_ms: u64,
    pub last_job_completion: Option<u64>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub capabilities: WorkerCapabilities,
    pub network_address: Option<String>,
    
    // Detailed metrics
    pub success_rate: f64,
    pub reliability_score: f64,
    pub efficiency_score: f64,
    pub consistency_score: f64,
    
    // History
    pub penalty_history: VecDeque<PenaltyRecord>,
    pub total_penalties: u64,
    
    // Status
    pub is_banned: bool,
    pub ban_reason: Option<String>,
    pub ban_expiry: Option<u64>,
    
    // Decay
    pub reputation_decay_start: Option<u64>,
    pub last_decay_calculation: chrono::DateTime<chrono::Utc>,
    
    // Verification
    pub result_quality_score: f64,
    pub average_result_confidence: f64,
    
    // Security
    pub malicious_behavior_count: u64,
    pub suspicious_activity_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PenaltyRecord {
    pub penalty_type: PenaltyType,
    pub penalty_score: f64,
    pub reason: String,
    pub timestamp: u64,
    pub job_id: Option<crate::types::JobId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PenaltyType {
    JobFailure,
    JobTimeout,
    MaliciousBehavior,
    OfflineDuringJob,
    LowQualityResult,
    ProtocolViolation,
}

/// Network-wide health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHealth {
    pub total_active_workers: usize,
    pub average_reputation: f64,
    pub network_load_percent: f32,
    pub successful_jobs_24h: u64,
    pub failed_jobs_24h: u64,
    pub average_job_latency_ms: u64,
}

/// Main health and reputation system
pub struct HealthReputationSystem {
    config: HealthReputationConfig,
    worker_reputations: Arc<RwLock<HashMap<WorkerId, WorkerReputation>>>,
    worker_health_status: Arc<RwLock<HashMap<WorkerId, WorkerHealth>>>,
    event_sender: mpsc::UnboundedSender<HealthEvent>,
    running: Arc<RwLock<bool>>,
}

#[derive(Debug, Clone)]
pub enum HealthEvent {
    ReputationUpdated(WorkerId, f64),
    WorkerHealthUpdated(WorkerId, WorkerHealth),
    WorkerBanned(WorkerId, String),
    WorkerUnbanned(WorkerId),
    NetworkHealthUpdated(NetworkHealth),
}

impl HealthReputationSystem {
    pub fn new(config: HealthReputationConfig) -> Self {
        let (event_sender, _event_receiver) = mpsc::unbounded_channel();
        
        Self {
            config,
            worker_reputations: Arc::new(RwLock::new(HashMap::new())),
            worker_health_status: Arc::new(RwLock::new(HashMap::new())),
            event_sender,
            running: Arc::new(RwLock::new(false)),
        }
    }

    pub async fn start(&self) -> Result<()> {
        info!("Starting Health Reputation System...");
        
        {
            let mut running = self.running.write().await;
            if *running {
                return Err(anyhow::anyhow!("Health reputation system already running"));
            }
            *running = true;
        }

        // Start background tasks
        // TODO: Implement background monitoring tasks

        info!("Health reputation system started successfully");
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        info!("Stopping Health Reputation System...");
        
        let mut running = self.running.write().await;
        *running = false;
        
        info!("Health reputation system stopped");
        Ok(())
    }

    pub async fn update_worker_health(&self, worker_id: WorkerId, metrics: HealthMetrics) -> Result<()> {
        let health = WorkerHealth {
            response_time_ms: metrics.response_time_ms,
            cpu_usage_percent: metrics.cpu_usage_percent,
            memory_usage_percent: metrics.memory_usage_percent,
            disk_usage_percent: metrics.disk_usage_percent,
            network_latency_ms: metrics.network_latency_ms,
            uptime_seconds: metrics.uptime_seconds,
            load_average: metrics.load_average,
            temperature_celsius: metrics.temperature_celsius,
            gpu_utilization_percent: metrics.gpu_utilization_percent,
            gpu_memory_usage_percent: metrics.gpu_memory_usage_percent,
            network_bandwidth_mbps: metrics.network_bandwidth_mbps,
        };
        
        {
            let mut status = self.worker_health_status.write().await;
            status.insert(worker_id.clone(), health.clone());
        }
        
        // Send event
        let _ = self.event_sender.send(HealthEvent::WorkerHealthUpdated(worker_id, health));
        
        Ok(())
    }

    pub async fn update_worker_reputation(
        &self, 
        worker_id: WorkerId, 
        success: bool, 
        execution_time_ms: u64,
        earnings: u128,
        result_quality: Option<f64>
    ) -> Result<()> {
        let mut reputations = self.worker_reputations.write().await;
        
        if let Some(rep) = reputations.get_mut(&worker_id) {
            if success {
                rep.jobs_completed += 1;
                rep.total_earnings += earnings;
                
                // Update scores
                rep.success_rate = rep.jobs_completed as f64 / (rep.jobs_completed + rep.jobs_failed) as f64;
                
                if let Some(quality) = result_quality {
                    // Weighted average for quality score
                    rep.result_quality_score = rep.result_quality_score * 0.9 + quality * 0.1;
                }
                
                // Boost reputation slightly for success
                rep.reputation_score = (rep.reputation_score + 0.01).min(1.0);
            } else {
                rep.jobs_failed += 1;
                rep.success_rate = rep.jobs_completed as f64 / (rep.jobs_completed + rep.jobs_failed) as f64;
                
                // Penalty for failure handled separately, but we lower score here too
                rep.reputation_score = (rep.reputation_score - 0.05).max(0.0);
            }
            
            // Update averages
            // Use exponential moving average for completion time
            let current_avg = rep.average_completion_time_ms as f64;
            rep.average_completion_time_ms = (current_avg * 0.9 + execution_time_ms as f64 * 0.1) as u64;
            
            rep.last_job_completion = Some(chrono::Utc::now().timestamp() as u64);
            rep.last_seen = chrono::Utc::now();
            
            // Notify
            let _ = self.event_sender.send(HealthEvent::ReputationUpdated(worker_id, rep.reputation_score));
        }
        
        Ok(())
    }

    pub async fn apply_penalty(
        &self, 
        worker_id: WorkerId, 
        penalty_type: PenaltyType, 
        score_deduction: f64, 
        reason: String, 
        job_id: Option<crate::types::JobId>
    ) -> Result<()> {
        let mut reputations = self.worker_reputations.write().await;
        
        if let Some(rep) = reputations.get_mut(&worker_id) {
            // Apply penalty
            rep.reputation_score = (rep.reputation_score - score_deduction).max(0.0);
            rep.total_penalties += 1;
            
            // Record penalty
            let record = PenaltyRecord {
                penalty_type: penalty_type.clone(),
                penalty_score: score_deduction,
                reason: reason.clone(),
                timestamp: chrono::Utc::now().timestamp() as u64,
                job_id,
            };
            
            rep.penalty_history.push_front(record);
            if rep.penalty_history.len() > self.config.history_window_size {
                rep.penalty_history.pop_back();
            }
            
            // Check for ban condition
            if rep.reputation_score < 0.1 {
                rep.is_banned = true;
                rep.ban_reason = Some("Reputation score too low".to_string());
                let _ = self.event_sender.send(HealthEvent::WorkerBanned(worker_id.clone(), "Low reputation".to_string()));
            }
            
            // Notify
            let _ = self.event_sender.send(HealthEvent::ReputationUpdated(worker_id, rep.reputation_score));
        }
        
        Ok(())
    }

    pub async fn detect_malicious_behavior(&self, worker_id: WorkerId, behavior: String) -> Result<()> {
        let mut reputations = self.worker_reputations.write().await;
        
        if let Some(rep) = reputations.get_mut(&worker_id) {
            rep.malicious_behavior_count += 1;
            rep.reputation_score = 0.0;
            rep.is_banned = true;
            rep.ban_reason = Some(format!("Malicious behavior detected: {}", behavior));
            
            warn!("Worker {} banned due to malicious behavior: {}", worker_id, behavior);
            let _ = self.event_sender.send(HealthEvent::WorkerBanned(worker_id, behavior));
        }
        
        Ok(())
    }

    pub async fn is_worker_eligible(&self, worker_id: &WorkerId) -> bool {
        let reputations = self.worker_reputations.read().await;
        
        if let Some(rep) = reputations.get(worker_id) {
            return !rep.is_banned && rep.reputation_score >= self.config.min_reputation_threshold;
        }
        
        // If worker not found, assume not eligible (must register first)
        false
    }

    pub async fn get_network_health(&self) -> NetworkHealth {
        let reputations = self.worker_reputations.read().await;
        let active_count = reputations.len(); // Simplified
        
        let total_reputation: f64 = reputations.values().map(|r| r.reputation_score).sum();
        let average_reputation = if active_count > 0 { total_reputation / active_count as f64 } else { 0.0 };
        
        NetworkHealth {
            total_active_workers: active_count,
            average_reputation,
            network_load_percent: 0.5, // Placeholder
            successful_jobs_24h: 0, // Placeholder
            failed_jobs_24h: 0, // Placeholder
            average_job_latency_ms: 0, // Placeholder
        }
    }

    pub async fn get_all_reputations(&self) -> Vec<WorkerReputation> {
        let reputations = self.worker_reputations.read().await;
        reputations.values().cloned().collect()
    }

    pub async fn periodic_maintenance(&self) -> Result<()> {
        self.apply_reputation_decay().await?;
        self.apply_penalty_decay().await?;
        self.cleanup_old_records().await?;
        self.check_ban_expiry().await?;
        Ok(())
    }

    /// Apply reputation decay to inactive workers
    pub async fn apply_reputation_decay(&self) -> Result<()> {
        let now = chrono::Utc::now();
        let decay_config = &self.config.decay_config;
        let mut reputations = self.worker_reputations.write().await;

        for (worker_id, rep) in reputations.iter_mut() {
            // Skip banned workers
            if rep.is_banned {
                continue;
            }

            // Check grace period for new workers
            let registration_age = now.signed_duration_since(rep.last_decay_calculation);
            if registration_age.num_hours() < decay_config.new_worker_grace_period_hours as i64
               && rep.jobs_completed < 10 {
                continue;
            }

            // Calculate hours since last activity
            let hours_inactive = now.signed_duration_since(rep.last_seen).num_hours() as u64;

            // Only decay if inactive beyond threshold
            if hours_inactive <= decay_config.inactivity_threshold_hours {
                // Worker is active, reset decay start
                rep.reputation_decay_start = None;
                continue;
            }

            // Start decay tracking if not already
            if rep.reputation_decay_start.is_none() {
                rep.reputation_decay_start = Some(now.timestamp() as u64);
            }

            // Calculate decay amount
            let decay_hours = hours_inactive - decay_config.inactivity_threshold_hours;
            let decay_days = decay_hours as f64 / 24.0;

            let decay_amount = if decay_config.use_exponential_decay {
                // Exponential decay: score * (1 - rate)^days
                let decay_factor = (1.0 - decay_config.daily_decay_rate).powf(decay_days);
                rep.reputation_score * (1.0 - decay_factor)
            } else {
                // Linear decay: rate * days
                decay_config.daily_decay_rate * decay_days
            };

            // Apply decay with floor
            let new_score = (rep.reputation_score - decay_amount).max(decay_config.decay_floor);

            if new_score != rep.reputation_score {
                info!(
                    "Reputation decay applied to worker {}: {:.3} -> {:.3} (inactive {} hours)",
                    worker_id, rep.reputation_score, new_score, hours_inactive
                );
                rep.reputation_score = new_score;
                rep.last_decay_calculation = now;

                let _ = self.event_sender.send(
                    HealthEvent::ReputationUpdated(worker_id.clone(), new_score)
                );
            }
        }

        Ok(())
    }

    /// Apply decay to penalties (forgiveness over time)
    pub async fn apply_penalty_decay(&self) -> Result<()> {
        let now = chrono::Utc::now().timestamp() as u64;
        let decay_rate = self.config.decay_config.penalty_decay_rate;
        let mut reputations = self.worker_reputations.write().await;

        for rep in reputations.values_mut() {
            // Skip if no penalties
            if rep.penalty_history.is_empty() {
                continue;
            }

            // Calculate penalty score reduction
            let mut total_decayed_penalty: f64 = 0.0;

            for penalty in rep.penalty_history.iter_mut() {
                let days_old = (now - penalty.timestamp) as f64 / 86400.0;
                let decay_factor = decay_rate * days_old;
                let decayed_amount = penalty.penalty_score * decay_factor.min(1.0);
                total_decayed_penalty += decayed_amount;
            }

            // Apply partial recovery from penalty decay
            if total_decayed_penalty > 0.0 {
                let recovery = (total_decayed_penalty * 0.1).min(0.02); // Max 2% recovery
                rep.reputation_score = (rep.reputation_score + recovery).min(1.0);
            }

            // Remove very old penalties (>30 days)
            let cutoff = now - (30 * 86400);
            while let Some(oldest) = rep.penalty_history.back() {
                if oldest.timestamp < cutoff {
                    rep.penalty_history.pop_back();
                } else {
                    break;
                }
            }
        }

        Ok(())
    }

    /// Cleanup old records and optimize memory
    async fn cleanup_old_records(&self) -> Result<()> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(90);
        let mut reputations = self.worker_reputations.write().await;

        // Remove workers not seen in 90 days with no activity
        reputations.retain(|_, rep| {
            rep.last_seen > cutoff || rep.jobs_completed > 0 || rep.is_banned
        });

        Ok(())
    }

    /// Check and lift expired bans
    async fn check_ban_expiry(&self) -> Result<()> {
        let now = chrono::Utc::now().timestamp() as u64;
        let mut reputations = self.worker_reputations.write().await;

        for (worker_id, rep) in reputations.iter_mut() {
            if rep.is_banned {
                if let Some(expiry) = rep.ban_expiry {
                    if now >= expiry {
                        rep.is_banned = false;
                        rep.ban_reason = None;
                        rep.ban_expiry = None;
                        // Start fresh with low reputation
                        rep.reputation_score = self.config.decay_config.decay_floor;

                        info!("Worker {} ban expired, reputation reset to {}",
                              worker_id, rep.reputation_score);
                        let _ = self.event_sender.send(
                            HealthEvent::WorkerUnbanned(worker_id.clone())
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Calculate effective reputation with decay applied
    pub async fn get_effective_reputation(&self, worker_id: &WorkerId) -> f64 {
        let reputations = self.worker_reputations.read().await;

        if let Some(rep) = reputations.get(worker_id) {
            if rep.is_banned {
                return 0.0;
            }

            let now = chrono::Utc::now();
            let hours_inactive = now.signed_duration_since(rep.last_seen).num_hours() as u64;
            let decay_config = &self.config.decay_config;

            // Real-time decay calculation
            if hours_inactive > decay_config.inactivity_threshold_hours {
                let decay_hours = hours_inactive - decay_config.inactivity_threshold_hours;
                let decay_days = decay_hours as f64 / 24.0;

                let decay_factor = if decay_config.use_exponential_decay {
                    (1.0 - decay_config.daily_decay_rate).powf(decay_days)
                } else {
                    1.0 - (decay_config.daily_decay_rate * decay_days)
                };

                return (rep.reputation_score * decay_factor).max(decay_config.decay_floor);
            }

            rep.reputation_score
        } else {
            0.0
        }
    }

    /// Boost reputation for successful job (with cap)
    pub async fn boost_reputation(&self, worker_id: WorkerId, boost_amount: f64) -> Result<()> {
        let max_recovery = self.config.decay_config.max_recovery_per_job;
        let capped_boost = boost_amount.min(max_recovery);

        let mut reputations = self.worker_reputations.write().await;

        if let Some(rep) = reputations.get_mut(&worker_id) {
            let old_score = rep.reputation_score;
            rep.reputation_score = (rep.reputation_score + capped_boost).min(1.0);

            // Reset decay timer on activity
            rep.last_seen = chrono::Utc::now();
            rep.reputation_decay_start = None;

            info!(
                "Reputation boost for worker {}: {:.3} -> {:.3}",
                worker_id, old_score, rep.reputation_score
            );

            let _ = self.event_sender.send(
                HealthEvent::ReputationUpdated(worker_id, rep.reputation_score)
            );
        }

        Ok(())
    }

    /// Get workers ranked by effective reputation
    pub async fn get_workers_ranked(&self, limit: usize) -> Vec<(WorkerId, f64)> {
        let reputations = self.worker_reputations.read().await;
        let now = chrono::Utc::now();
        let decay_config = &self.config.decay_config;

        let mut ranked: Vec<(WorkerId, f64)> = reputations.iter()
            .filter(|(_, rep)| !rep.is_banned)
            .map(|(id, rep)| {
                let hours_inactive = now.signed_duration_since(rep.last_seen).num_hours() as u64;

                let effective_score = if hours_inactive > decay_config.inactivity_threshold_hours {
                    let decay_days = (hours_inactive - decay_config.inactivity_threshold_hours) as f64 / 24.0;
                    let decay_factor = (1.0 - decay_config.daily_decay_rate).powf(decay_days);
                    (rep.reputation_score * decay_factor).max(decay_config.decay_floor)
                } else {
                    rep.reputation_score
                };

                (id.clone(), effective_score)
            })
            .collect();

        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        ranked.truncate(limit);
        ranked
    }
}
