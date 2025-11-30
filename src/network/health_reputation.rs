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
use tokio::time::{sleep, Duration};
use tracing::{info, warn, error};

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
}

impl Default for HealthReputationConfig {
    fn default() -> Self {
        Self {
            health_check_interval_secs: 60,
            reputation_update_interval_secs: 300,
            history_window_size: 100,
            penalty_decay_factor: 0.95,
            min_reputation_threshold: 0.5,
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
        // TODO: Implement decay logic and cleanup
        Ok(())
    }
}
