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
use tracing::{info, debug, error};

use crate::types::{WorkerId, NodeId};
use crate::node::coordinator::{WorkerInfo, WorkerCapabilities, ComputeRequirements};
use crate::storage::Database;
use crate::network::NetworkCoordinator;
use crate::coordinator::config::WorkerManagerConfig;
use crate::blockchain::{StarknetClient, JobManagerContract};

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

/// Main worker manager service
pub struct WorkerManager {
    config: WorkerManagerConfig,
    database: Arc<Database>,
    network_coordinator: Arc<NetworkCoordinator>,
    
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
        
        Self {
            config,
            database,
            network_coordinator,
            active_workers: Arc::new(RwLock::new(HashMap::new())),
            worker_loads: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(stats)),
            event_sender,
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
            running: Arc::new(RwLock::new(false)),
            next_worker_id: Arc::new(Mutex::new(1)),
        }
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
        let health_monitoring_handle = self.start_health_monitoring().await?;
        let load_monitoring_handle = self.start_load_monitoring().await?;
        let stats_collection_handle = self.start_stats_collection().await?;

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
    pub async fn register_worker(&self, worker_info: WorkerInfo) -> Result<WorkerId> {
        info!("Registering new worker: {:?}", worker_info.node_id);
        
        // Validate worker info
        self.validate_worker_info(&worker_info).await?;
        
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
        
        // Store worker
        self.active_workers.write().await.insert(worker_id, worker_details.clone());
        
        // Initialize worker load
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

    /// Find best worker for job
    pub async fn find_best_worker(&self, requirements: &ComputeRequirements) -> Option<WorkerDetails> {
        let available_workers = self.find_workers_by_capabilities(requirements).await;
        
        if available_workers.is_empty() {
            return None;
        }
        
        // Sort by reputation and load (higher reputation, lower load is better)
        let mut sorted_workers = available_workers;
        sorted_workers.sort_by(|a, b| {
            let a_score = a.reputation * (1.0 - a.load);
            let b_score = b.reputation * (1.0 - b.load);
            b_score.partial_cmp(&a_score).unwrap_or(std::cmp::Ordering::Equal)
        });
        
        sorted_workers.first().cloned()
    }

    /// Start health monitoring
    async fn start_health_monitoring(&self) -> Result<()> {
        let config = self.config.clone();
        let active_workers = Arc::clone(&self.active_workers);
        let event_sender = self.event_sender.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(config.health_check_interval_secs));
            
            loop {
                interval.tick().await;
                
                let now = chrono::Utc::now().timestamp() as u64;
                let mut workers = active_workers.write().await;
                let mut timed_out_workers = Vec::new();
                
                for (worker_id, worker_details) in workers.iter_mut() {
                    // Check if worker has timed out
                    if now - worker_details.last_seen > config.worker_timeout_secs {
                        worker_details.health.status = WorkerStatus::Offline;
                        timed_out_workers.push(*worker_id);
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
        let event_sender = self.event_sender.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(config.monitoring.metrics_interval_secs));
            
            loop {
                interval.tick().await;
                
                // Update load metrics
                let loads = worker_loads.read().await;
                for (_worker_id, _load) in loads.iter() {
                    // TODO: Implement actual load monitoring logic
                    debug!("Monitoring load for worker {}: {}", _worker_id, _load.current_load);
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

    /// Validate worker info
    async fn validate_worker_info(&self, worker_info: &WorkerInfo) -> Result<()> {
        // Check if worker already exists
        let workers = self.active_workers.read().await;
        if workers.values().any(|w| w.info.node_id == worker_info.node_id) {
            return Err(anyhow::anyhow!("Worker with node ID {} already registered", worker_info.node_id));
        }
        
        // Validate capabilities
        if !self.config.registration.enable_capability_validation {
            return Ok(());
        }
        
        // TODO: Implement capability validation
        Ok(())
    }

    /// Generate worker ID
    async fn generate_worker_id(&self) -> WorkerId {
        let mut next_id = self.next_worker_id.lock().await;
        *next_id += 1;
        WorkerId::new()
    }

    /// Extract worker tags
    fn extract_worker_tags(&self, worker_info: &WorkerInfo) -> Vec<String> {
        // TODO: Implement tag extraction based on capabilities, location, etc.
        vec!["worker".to_string()]
    }

    /// Calculate max load for worker
    fn calculate_max_load(&self, capabilities: &WorkerCapabilities) -> f64 {
        // TODO: Implement max load calculation based on capabilities
        1.0
    }

    /// Check if worker meets requirements
    fn worker_meets_requirements(&self, worker: &WorkerDetails, requirements: &ComputeRequirements) -> bool {
        // TODO: Implement capability matching logic
        true
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

    /// Get event receiver
    pub async fn event_receiver(&self) -> mpsc::UnboundedReceiver<WorkerEvent> {
        self.event_receiver.write().await.take().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{WorkerId, NodeId};
    use crate::node::coordinator::{WorkerInfo, WorkerCapabilities};

    #[tokio::test]
    async fn test_worker_manager_creation() {
        // Setup omitted for brevity - would require mocking dependencies
    }
}
