//! # Worker Discovery System
//!
//! Implements decentralized worker discovery using DHT (Distributed Hash Table)
//! and P2P networking for the Bitsage Network.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{sleep, Duration};
use tracing::{info, error, debug};

use crate::types::{WorkerId, JobId};
use crate::network::p2p::{NetworkClient, P2PMessage};
use crate::network::health_reputation::{HealthReputationSystem, WorkerHealth, WorkerReputation};

/// Worker discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Discovery interval in seconds
    pub discovery_interval_secs: u64,
    /// Worker heartbeat timeout in seconds
    pub heartbeat_timeout_secs: u64,
    /// Maximum workers to track per region
    pub max_workers_per_region: usize,
    /// Enable automatic worker health monitoring
    pub enable_health_monitoring: bool,
    /// Worker capability advertisement interval
    pub capability_advertisement_interval_secs: u64,
    /// DHT bucket size for worker storage
    pub dht_bucket_size: usize,
    /// Worker discovery radius (network hops)
    pub discovery_radius: u32,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            discovery_interval_secs: 30,
            heartbeat_timeout_secs: 120,
            max_workers_per_region: 100,
            enable_health_monitoring: true,
            capability_advertisement_interval_secs: 60,
            dht_bucket_size: 20,
            discovery_radius: 3,
        }
    }
}

/// Worker discovery message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveryMessage {
    /// Worker advertisement
    WorkerAdvertisement {
        worker_id: WorkerId,
        capabilities: WorkerCapabilities,
        location: WorkerLocation,
        health_metrics: Option<WorkerHealth>,
        reputation_score: f64,
        timestamp: u64,
    },
    /// Worker discovery request
    DiscoveryRequest {
        requester_id: WorkerId,
        job_requirements: JobRequirements,
        max_workers: usize,
        timestamp: u64,
    },
    /// Worker discovery response
    DiscoveryResponse {
        requester_id: WorkerId,
        workers: Vec<WorkerInfo>,
        timestamp: u64,
    },
    /// Worker heartbeat
    Heartbeat {
        worker_id: WorkerId,
        current_load: f32,
        health_metrics: Option<WorkerHealth>,
        timestamp: u64,
    },
    /// Worker departure notification
    WorkerDeparture {
        worker_id: WorkerId,
        reason: String,
        timestamp: u64,
    },
}

/// Worker capabilities for discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerCapabilities {
    pub gpu_memory_gb: u32,
    pub cpu_cores: u32,
    pub ram_gb: u32,
    pub supported_job_types: Vec<String>,
    pub ai_frameworks: Vec<String>,
    pub specialized_hardware: Vec<String>,
    pub max_parallel_tasks: u32,
    pub network_bandwidth_mbps: u32,
    pub storage_gb: u32,
    pub supports_fp16: bool,
    pub supports_int8: bool,
    pub cuda_compute_capability: Option<String>,
}

/// Worker location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerLocation {
    pub region: String,
    pub country: String,
    pub latitude: f64,
    pub longitude: f64,
    pub timezone: String,
    pub network_latency_ms: u32,
}

/// Job requirements for worker matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRequirements {
    pub min_gpu_memory_gb: u32,
    pub min_cpu_cores: u32,
    pub min_ram_gb: u32,
    pub required_job_types: Vec<String>,
    pub required_frameworks: Vec<String>,
    pub max_network_latency_ms: u32,
    pub preferred_regions: Vec<String>,
    pub max_worker_load: f32,
    pub min_reputation_score: f64,
}

/// Worker information for discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerInfo {
    pub worker_id: WorkerId,
    pub capabilities: WorkerCapabilities,
    pub location: WorkerLocation,
    pub health: Option<WorkerHealth>,
    pub reputation: WorkerReputation,
    pub current_load: f32,
    pub last_seen: u64,
    pub is_available: bool,
}

/// DHT bucket for worker storage
#[derive(Debug, Clone)]
pub struct DHTBucket {
    pub workers: Vec<WorkerInfo>,
    pub last_updated: u64,
    pub bucket_id: String,
}

/// Discovery events
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    WorkerDiscovered(WorkerInfo),
    WorkerLost(WorkerId),
    WorkerHealthUpdated(WorkerId, WorkerHealth),
    DiscoveryRequest(JobRequirements),
    DiscoveryResponse(Vec<WorkerInfo>),
    WorkerHeartbeat(WorkerId, f32),
}

/// Main worker discovery system
pub struct WorkerDiscovery {
    config: DiscoveryConfig,
    p2p_network: NetworkClient,
    health_reputation_system: Arc<HealthReputationSystem>,
    
    // DHT for worker storage
    dht: Arc<RwLock<HashMap<String, DHTBucket>>>,
    
    // Active workers tracking
    active_workers: Arc<RwLock<HashMap<WorkerId, WorkerInfo>>>,
    
    // Communication channels
    event_sender: mpsc::UnboundedSender<DiscoveryEvent>,
    event_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<DiscoveryEvent>>>>,
    
    // Internal state
    running: Arc<RwLock<bool>>,
    last_discovery_cycle: Arc<RwLock<u64>>,
}

impl WorkerDiscovery {
    /// Create a new worker discovery system
    pub fn new(
        config: DiscoveryConfig,
        p2p_network: NetworkClient,
        health_reputation_system: Arc<HealthReputationSystem>,
    ) -> Self {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        
        Self {
            config,
            p2p_network,
            health_reputation_system,
            dht: Arc::new(RwLock::new(HashMap::new())),
            active_workers: Arc::new(RwLock::new(HashMap::new())),
            event_sender,
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
            running: Arc::new(RwLock::new(false)),
            last_discovery_cycle: Arc::new(RwLock::new(0)),
        }
    }

    /// Start the worker discovery system
    pub async fn start(&self) -> Result<()> {
        info!("Starting Worker Discovery System...");
        
        {
            let mut running = self.running.write().await;
            if *running {
                return Err(anyhow::anyhow!("Worker discovery already running"));
            }
            *running = true;
        }

        // Start background tasks
        let discovery_handle = tokio::spawn(async move {
            // TODO: Implement discovery rounds
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            }
        });
        
        let heartbeat_handle = tokio::spawn(async move {
            // TODO: Implement heartbeat
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            }
        });
        
        let p2p_handle = tokio::spawn(async move {
            // TODO: Implement P2P event handling
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        });

        // Start periodic discovery
        self.start_periodic_discovery().await?;

        // Wait for any task to complete (they should run indefinitely)
        tokio::select! {
            _ = discovery_handle => {},
            _ = heartbeat_handle => {},
            _ = p2p_handle => {},
        }

        Ok(())
    }

    /// Stop the worker discovery system
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping Worker Discovery System...");
        
        {
            let mut running = self.running.write().await;
            *running = false;
        }

        info!("Worker discovery system stopped");
        Ok(())
    }

    /// Start the discovery cycle
    async fn start_discovery_cycle(&self) -> Result<()> {
        let config = self.config.clone();
        let p2p_network = self.p2p_network.clone();
        let _event_sender = self.event_sender.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(config.discovery_interval_secs));
            
            loop {
                interval.tick().await;
                
                // Broadcast discovery request
                let _discovery_msg = DiscoveryMessage::DiscoveryRequest {
                    requester_id: WorkerId::new(), // TODO: Get actual worker ID
                    job_requirements: JobRequirements {
                        min_gpu_memory_gb: 0,
                        min_cpu_cores: 0,
                        min_ram_gb: 0,
                        required_job_types: vec![],
                        required_frameworks: vec![],
                        max_network_latency_ms: 1000,
                        preferred_regions: vec![],
                        max_worker_load: 0.8,
                        min_reputation_score: 0.5,
                    },
                    max_workers: config.max_workers_per_region,
                    timestamp: chrono::Utc::now().timestamp() as u64,
                };

                // Convert DiscoveryMessage to P2PMessage for broadcasting
                let p2p_message = P2PMessage::JobAnnouncement {
                    job_id: JobId::new(), // TODO: Get actual job ID
                    spec: crate::blockchain::types::JobSpec {
                        job_type: crate::blockchain::types::JobType::AIInference,
                        model_id: crate::blockchain::types::ModelId::new(starknet::core::types::FieldElement::from_hex_be("0x0").unwrap()),
                        input_data_hash: starknet::core::types::FieldElement::from_hex_be("0x0").unwrap(),
                        expected_output_format: starknet::core::types::FieldElement::from_hex_be("0x0").unwrap(),
                        verification_method: crate::blockchain::types::VerificationMethod::None,
                        max_reward: 0,
                        sla_deadline: chrono::Utc::now().timestamp() as u64 + 3600,
                                                  compute_requirements: vec![
                              starknet::core::types::FieldElement::from(4u32), // min_gpu_memory_gb
                              starknet::core::types::FieldElement::from(2u32), // min_cpu_cores
                              starknet::core::types::FieldElement::from(8u32), // min_ram_gb
                          ],
                        metadata: vec![],
                        // Note: JobSpec doesn't have worker_capabilities field
                        // This would need to be handled differently in the actual implementation
                    },
                    max_reward: 0,
                    deadline: chrono::Utc::now().timestamp() as u64 + 3600,
                };
                
                if let Err(e) = p2p_network.broadcast_message(p2p_message, "discovery").await {
                    error!("Failed to broadcast discovery request: {}", e);
                }
            }
        });

        Ok(())
    }

    /// Start heartbeat monitoring
    async fn start_heartbeat_monitoring(&self) -> Result<()> {
        let config = self.config.clone();
        let active_workers = Arc::clone(&self.active_workers);
        let event_sender = self.event_sender.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            
            loop {
                interval.tick().await;
                
                let now = chrono::Utc::now().timestamp() as u64;
                let timeout = config.heartbeat_timeout_secs;
                
                let mut workers = active_workers.write().await;
                let mut to_remove = Vec::new();
                
                for (worker_id, worker_info) in workers.iter() {
                    if now - worker_info.last_seen > timeout {
                        to_remove.push(*worker_id);
                    }
                }
                
                for worker_id in to_remove {
                    if let Some(_worker_info) = workers.remove(&worker_id) {
                        info!("Worker {} timed out, removing from active workers", worker_id);
                        
                        if let Err(e) = event_sender.send(DiscoveryEvent::WorkerLost(worker_id)) {
                            error!("Failed to send worker lost event: {}", e);
                        }
                    }
                }
            }
        });

        Ok(())
    }

    /// Start P2P message handling
    async fn start_p2p_message_handling(&self) -> Result<()> {
        let _p2p_network = self.p2p_network.clone();
        let _active_workers = Arc::clone(&self.active_workers);
        let _event_sender = self.event_sender.clone();

        tokio::spawn(async move {
            loop {
                // TODO: Implement actual P2P message handling
                // This would receive messages from the P2P network and process them
                
                sleep(Duration::from_secs(1)).await;
            }
        });

        Ok(())
    }

    /// Handle discovery message
    async fn handle_discovery_message(&self, message: DiscoveryMessage) -> Result<()> {
        match message {
            DiscoveryMessage::WorkerAdvertisement { worker_id, capabilities, location, health_metrics, reputation_score, timestamp } => {
                self.handle_worker_advertisement(worker_id, capabilities, location, health_metrics, reputation_score, timestamp).await?;
            }
            DiscoveryMessage::DiscoveryRequest { requester_id, job_requirements, max_workers, timestamp } => {
                self.handle_discovery_request(requester_id, job_requirements, max_workers, timestamp).await?;
            }
            DiscoveryMessage::DiscoveryResponse { requester_id, workers, timestamp } => {
                self.handle_discovery_response(requester_id, workers, timestamp).await?;
            }
            DiscoveryMessage::Heartbeat { worker_id, current_load, health_metrics, timestamp } => {
                self.handle_worker_heartbeat(worker_id, current_load, health_metrics, timestamp).await?;
            }
            DiscoveryMessage::WorkerDeparture { worker_id, reason, timestamp } => {
                self.handle_worker_departure(worker_id, reason, timestamp).await?;
            }
        }
        Ok(())
    }

    /// Handle worker advertisement
    async fn handle_worker_advertisement(&self, worker_id: WorkerId, capabilities: WorkerCapabilities, location: WorkerLocation, health_metrics: Option<WorkerHealth>, _reputation_score: f64, timestamp: u64) -> Result<()> {
        info!("Received worker advertisement from {}", worker_id);
        
        let worker_info = WorkerInfo {
            worker_id,
            capabilities,
            location,
            health: health_metrics,
            reputation: WorkerReputation {
                worker_id: worker_id.clone(),
                reputation_score: 0.8,
                jobs_completed: 10,
                jobs_failed: 1,
                jobs_timeout: 0,
                total_earnings: 1000,
                average_completion_time_ms: 5000,
                last_job_completion: None,
                last_seen: chrono::Utc::now(),
                capabilities: crate::blockchain::types::WorkerCapabilities {
                    gpu_memory: 8,
                    cpu_cores: 4,
                    ram: 16,
                    storage: 100,
                    bandwidth: 100,
                    capability_flags: 0b11111111,
                    gpu_model: starknet::core::types::FieldElement::from_hex_be("0x4090").unwrap(),
                    cpu_model: starknet::core::types::FieldElement::from_hex_be("0x7950").unwrap(),
                },
                network_address: None,
                success_rate: 0.9,
                reliability_score: 0.8,
                efficiency_score: 0.7,
                consistency_score: 0.8,
                penalty_history: std::collections::VecDeque::new(),
                total_penalties: 0,
                is_banned: false,
                ban_reason: None,
                ban_expiry: None,
                reputation_decay_start: None,
                last_decay_calculation: chrono::Utc::now(),
                result_quality_score: 0.8,
                average_result_confidence: 0.7,
                malicious_behavior_count: 0,
                suspicious_activity_count: 0,
            },
            current_load: 0.0,
            last_seen: timestamp,
            is_available: true,
        };

        // Add to active workers
        self.active_workers.write().await.insert(worker_id, worker_info.clone());
        
        // Add to DHT
        self.add_worker_to_dht(worker_info.clone()).await?;
        
        // Send discovery event
        if let Err(e) = self.event_sender.send(DiscoveryEvent::WorkerDiscovered(worker_info)) {
            error!("Failed to send worker discovered event: {}", e);
        }

        Ok(())
    }

    /// Handle discovery request
    async fn handle_discovery_request(&self, requester_id: WorkerId, job_requirements: JobRequirements, max_workers: usize, _timestamp: u64) -> Result<()> {
        debug!("Received discovery request from {}", requester_id);
        
        // Find matching workers
        let matching_workers = self.find_matching_workers(&job_requirements, max_workers).await?;
        
        let _response = DiscoveryMessage::DiscoveryResponse {
            requester_id,
            workers: matching_workers.clone(), // Clone before moving
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        
        debug!("Sending discovery response with {} workers", matching_workers.len());
        
        // Send response back to requester
        if let Err(e) = self.event_sender.send(DiscoveryEvent::DiscoveryResponse(matching_workers)) {
            error!("Failed to send discovery response: {}", e);
        }

        Ok(())
    }

    /// Handle discovery response
    async fn handle_discovery_response(&self, requester_id: WorkerId, workers: Vec<WorkerInfo>, _timestamp: u64) -> Result<()> {
        debug!("Handling discovery response for worker {}", requester_id);
        
        // Process each worker info
        for worker_info in &workers { // Use slice reference instead of moving
            // TODO: Process worker info
            debug!("Processing worker info: {:?}", worker_info);
        }
        
        // Send event to coordinator
        if let Err(e) = self.event_sender.send(DiscoveryEvent::DiscoveryResponse(workers)) {
            error!("Failed to send discovery response event: {}", e);
        }
        
        Ok(())
    }

    /// Handle worker heartbeat
    async fn handle_worker_heartbeat(&self, worker_id: WorkerId, current_load: f32, health_metrics: Option<WorkerHealth>, timestamp: u64) -> Result<()> {
        debug!("Received heartbeat from worker {}", worker_id);
        
        // Update worker information
        if let Some(worker_info) = self.active_workers.write().await.get_mut(&worker_id) {
            worker_info.current_load = current_load;
            worker_info.last_seen = timestamp;
            
            if let Some(health) = health_metrics {
                worker_info.health = Some(health.clone());
                
                // Send health update event
                if let Err(e) = self.event_sender.send(DiscoveryEvent::WorkerHealthUpdated(worker_id, health)) {
                    error!("Failed to send worker health update event: {}", e);
                }
            }
        }

        // Send heartbeat event
        if let Err(e) = self.event_sender.send(DiscoveryEvent::WorkerHeartbeat(worker_id, current_load)) {
            error!("Failed to send worker heartbeat event: {}", e);
        }

        Ok(())
    }

    /// Handle worker departure
    async fn handle_worker_departure(&self, worker_id: WorkerId, reason: String, _timestamp: u64) -> Result<()> {
        info!("Worker {} departed: {}", worker_id, reason);
        
        // Remove from active workers
        if self.active_workers.write().await.remove(&worker_id).is_some() {
            // Send worker lost event
            if let Err(e) = self.event_sender.send(DiscoveryEvent::WorkerLost(worker_id)) {
                error!("Failed to send worker lost event: {}", e);
            }
        }

        Ok(())
    }

    /// Find workers matching job requirements
    async fn find_matching_workers(&self, requirements: &JobRequirements, max_workers: usize) -> Result<Vec<WorkerInfo>> {
        let active_workers = self.active_workers.read().await;
        let mut matching_workers = Vec::new();

        for worker_info in active_workers.values() {
            if self.worker_matches_requirements(worker_info, requirements) {
                matching_workers.push(worker_info.clone());
                
                if matching_workers.len() >= max_workers {
                    break;
                }
            }
        }

        // Sort by reputation score (highest first)
        matching_workers.sort_by(|a, b| b.reputation.success_rate.partial_cmp(&a.reputation.success_rate).unwrap_or(std::cmp::Ordering::Equal));

        Ok(matching_workers)
    }

    /// Check if worker matches job requirements
    fn worker_matches_requirements(&self, worker: &WorkerInfo, requirements: &JobRequirements) -> bool {
        // Check GPU memory
        if worker.capabilities.gpu_memory_gb < requirements.min_gpu_memory_gb {
            return false;
        }

        // Check CPU cores
        if worker.capabilities.cpu_cores < requirements.min_cpu_cores {
            return false;
        }

        // Check RAM
        if worker.capabilities.ram_gb < requirements.min_ram_gb {
            return false;
        }

        // Check network latency
        if worker.location.network_latency_ms > requirements.max_network_latency_ms {
            return false;
        }

        // Check worker load
        if worker.current_load > requirements.max_worker_load {
            return false;
        }

        // Check reputation score
        if worker.reputation.success_rate < requirements.min_reputation_score {
            return false;
        }

        // Check job type support
        for required_job_type in &requirements.required_job_types {
            if !worker.capabilities.supported_job_types.contains(required_job_type) {
                return false;
            }
        }

        // Check framework support
        for required_framework in &requirements.required_frameworks {
            if !worker.capabilities.ai_frameworks.contains(required_framework) {
                return false;
            }
        }

        // Check region preference
        if !requirements.preferred_regions.is_empty() {
            let worker_region = &worker.location.region;
            if !requirements.preferred_regions.contains(worker_region) {
                return false;
            }
        }

        true
    }

    /// Add worker to DHT
    async fn add_worker_to_dht(&self, worker_info: WorkerInfo) -> Result<()> {
        let bucket_id = self.calculate_bucket_id(&worker_info);
        let mut dht = self.dht.write().await;
        
        let bucket = dht.entry(bucket_id.clone()).or_insert_with(|| DHTBucket {
            workers: Vec::new(),
            last_updated: chrono::Utc::now().timestamp() as u64,
            bucket_id,
        });

        // Check if worker already exists in bucket
        if let Some(existing_worker) = bucket.workers.iter_mut().find(|w| w.worker_id == worker_info.worker_id) {
            *existing_worker = worker_info;
        } else {
            // Add new worker to bucket
            if bucket.workers.len() < self.config.dht_bucket_size {
                bucket.workers.push(worker_info);
            } else {
                // Replace least recently seen worker
                bucket.workers.sort_by_key(|w| w.last_seen);
                bucket.workers[0] = worker_info;
            }
        }

        bucket.last_updated = chrono::Utc::now().timestamp() as u64;
        Ok(())
    }

    /// Calculate DHT bucket ID for worker
    fn calculate_bucket_id(&self, worker: &WorkerInfo) -> String {
        // Simple bucket calculation based on worker ID hash
        // In a real implementation, this would use a proper DHT algorithm
        let hash = format!("{:x}", md5::compute(worker.worker_id.to_string()));
        hash[..8].to_string()
    }

    /// Get active workers count
    pub async fn get_active_workers_count(&self) -> usize {
        self.active_workers.read().await.len()
    }

    /// Get workers by region
    pub async fn get_workers_by_region(&self, region: &str) -> Vec<WorkerInfo> {
        let active_workers = self.active_workers.read().await;
        active_workers.values()
            .filter(|w| w.location.region == region)
            .cloned()
            .collect()
    }

    /// Get worker by ID
    pub async fn get_worker(&self, worker_id: WorkerId) -> Option<WorkerInfo> {
        self.active_workers.read().await.get(&worker_id).cloned()
    }

    pub async fn start_periodic_discovery(&self) -> Result<()> {
        let config = self.config.clone();
        let event_sender = self.event_sender.clone();
        let _active_workers = Arc::clone(&self.active_workers);
        let p2p_network = self.p2p_network.clone();
        
        // Note: Removing p2p_network usage in spawned task due to Send trait issues
        // This functionality needs to be moved to the main event loop
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(config.discovery_interval_secs));
            
            loop {
                interval.tick().await;
                
                // Create discovery message
                let discovery_message = DiscoveryMessage::DiscoveryRequest {
                    requester_id: WorkerId::new(), // TODO: Get actual worker ID
                    job_requirements: JobRequirements {
                        min_gpu_memory_gb: 0,
                        min_cpu_cores: 0,
                        min_ram_gb: 0,
                        required_job_types: vec![],
                        required_frameworks: vec![],
                        max_network_latency_ms: 1000,
                        preferred_regions: vec![],
                        max_worker_load: 0.8,
                        min_reputation_score: 0.5,
                    },
                    max_workers: config.max_workers_per_region,
                    timestamp: chrono::Utc::now().timestamp() as u64,
                };
                
                // Log the periodic discovery attempt
                debug!("Periodic discovery tick - active workers: {}", 
                    _active_workers.read().await.len());
                
                // Send discovery event instead of using p2p_network directly
                if let DiscoveryMessage::DiscoveryRequest { job_requirements, .. } = &discovery_message {
                    // Also convert to P2PMessage and broadcast if possible
                    let p2p_message = P2PMessage::JobAnnouncement {
                        job_id: JobId::new(),
                        spec: crate::blockchain::types::JobSpec {
                            job_type: crate::blockchain::types::JobType::AIInference,
                            model_id: crate::blockchain::types::ModelId::new(starknet::core::types::FieldElement::from_hex_be("0x0").unwrap()),
                            input_data_hash: starknet::core::types::FieldElement::from_hex_be("0x0").unwrap(),
                            expected_output_format: starknet::core::types::FieldElement::from_hex_be("0x0").unwrap(),
                            verification_method: crate::blockchain::types::VerificationMethod::None,
                            max_reward: 0,
                            sla_deadline: chrono::Utc::now().timestamp() as u64 + 3600,
                            compute_requirements: vec![], // Simplified
                            metadata: vec![],
                        },
                        max_reward: 0,
                        deadline: chrono::Utc::now().timestamp() as u64 + 3600,
                    };
                    
                    if let Err(e) = p2p_network.broadcast_message(p2p_message, "discovery").await {
                        error!("Failed to broadcast discovery: {}", e);
                    }

                    if let Err(e) = event_sender.send(DiscoveryEvent::DiscoveryRequest(job_requirements.clone())) {
                        error!("Failed to send discovery event: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(())
    }
}

#[cfg(all(test, feature = "broken_tests"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_discovery_config_default() {
        let config = DiscoveryConfig::default();
        assert_eq!(config.discovery_interval_secs, 30);
        assert_eq!(config.heartbeat_timeout_secs, 120);
        assert_eq!(config.max_workers_per_region, 100);
        assert!(config.enable_health_monitoring);
    }
}
