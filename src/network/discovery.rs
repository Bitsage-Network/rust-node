//! # Worker Discovery System
//!
//! Implements decentralized worker discovery using DHT (Distributed Hash Table)
//! and P2P networking for the Bitsage Network.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::time::Duration;
use tracing::{info, error, debug};

use crate::types::WorkerId;
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

    // P2P network event receiver for incoming messages
    network_event_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<crate::network::p2p::NetworkEvent>>>>,

    // Local node's worker ID for self-identification
    local_worker_id: WorkerId,

    // Internal state
    running: Arc<RwLock<bool>>,
    last_discovery_cycle: Arc<RwLock<u64>>,

    // Discovery statistics
    stats: Arc<RwLock<DiscoveryStats>>,
}

/// Discovery statistics
#[derive(Debug, Clone, Default)]
pub struct DiscoveryStats {
    pub discovery_rounds_completed: u64,
    pub workers_discovered: u64,
    pub workers_lost: u64,
    pub heartbeats_sent: u64,
    pub heartbeats_received: u64,
    pub messages_processed: u64,
    pub last_discovery_time: Option<u64>,
    pub last_heartbeat_time: Option<u64>,
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
            network_event_receiver: Arc::new(RwLock::new(None)),
            local_worker_id: WorkerId::new(),
            running: Arc::new(RwLock::new(false)),
            last_discovery_cycle: Arc::new(RwLock::new(0)),
            stats: Arc::new(RwLock::new(DiscoveryStats::default())),
        }
    }

    /// Create a new worker discovery system with a network event receiver
    pub fn with_network_events(
        config: DiscoveryConfig,
        p2p_network: NetworkClient,
        health_reputation_system: Arc<HealthReputationSystem>,
        network_event_receiver: mpsc::UnboundedReceiver<crate::network::p2p::NetworkEvent>,
        local_worker_id: WorkerId,
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
            network_event_receiver: Arc::new(RwLock::new(Some(network_event_receiver))),
            local_worker_id,
            running: Arc::new(RwLock::new(false)),
            last_discovery_cycle: Arc::new(RwLock::new(0)),
            stats: Arc::new(RwLock::new(DiscoveryStats::default())),
        }
    }

    /// Set the network event receiver (for cases where it wasn't available at construction)
    pub async fn set_network_event_receiver(
        &self,
        receiver: mpsc::UnboundedReceiver<crate::network::p2p::NetworkEvent>,
    ) {
        *self.network_event_receiver.write().await = Some(receiver);
    }

    /// Set the local worker ID
    pub async fn set_local_worker_id(&self, worker_id: WorkerId) {
        // Note: This requires interior mutability - for now we just log
        info!("Local worker ID set to: {}", worker_id);
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

        // Start discovery round loop
        let discovery_config = self.config.clone();
        let discovery_p2p = self.p2p_network.clone();
        let discovery_active_workers = Arc::clone(&self.active_workers);
        let discovery_event_sender = self.event_sender.clone();
        let discovery_running = Arc::clone(&self.running);
        let discovery_stats = Arc::clone(&self.stats);
        let local_worker_id = self.local_worker_id;

        let discovery_handle = tokio::spawn(async move {
            Self::run_discovery_loop(
                discovery_config,
                discovery_p2p,
                discovery_active_workers,
                discovery_event_sender,
                discovery_running,
                discovery_stats,
                local_worker_id,
            ).await;
        });

        // Start heartbeat monitoring loop
        let heartbeat_config = self.config.clone();
        let heartbeat_active_workers = Arc::clone(&self.active_workers);
        let heartbeat_event_sender = self.event_sender.clone();
        let heartbeat_running = Arc::clone(&self.running);
        let heartbeat_stats = Arc::clone(&self.stats);

        let heartbeat_handle = tokio::spawn(async move {
            Self::run_heartbeat_loop(
                heartbeat_config,
                heartbeat_active_workers,
                heartbeat_event_sender,
                heartbeat_running,
                heartbeat_stats,
            ).await;
        });

        // Start P2P event handling loop (only if we have a receiver)
        let p2p_event_receiver = self.network_event_receiver.write().await.take();
        let p2p_active_workers = Arc::clone(&self.active_workers);
        let p2p_dht = Arc::clone(&self.dht);
        let p2p_event_sender = self.event_sender.clone();
        let p2p_running = Arc::clone(&self.running);
        let p2p_stats = Arc::clone(&self.stats);
        let p2p_config = self.config.clone();

        let p2p_handle = tokio::spawn(async move {
            if let Some(receiver) = p2p_event_receiver {
                Self::run_p2p_event_loop(
                    receiver,
                    p2p_active_workers,
                    p2p_dht,
                    p2p_event_sender,
                    p2p_running,
                    p2p_stats,
                    p2p_config,
                ).await;
            } else {
                info!("No P2P event receiver available, skipping P2P event handling");
                // Keep the task alive so select doesn't exit immediately
                loop {
                    if !*p2p_running.read().await {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            }
        });

        info!("Worker discovery system started successfully");

        // Note: We don't wait for tasks to complete here - they run independently
        // The stop() method will set running to false, causing loops to exit
        // Detach the handles - they'll run until stop() is called
        drop(discovery_handle);
        drop(heartbeat_handle);
        drop(p2p_handle);

        Ok(())
    }

    /// Run the discovery round loop
    async fn run_discovery_loop(
        config: DiscoveryConfig,
        p2p_network: NetworkClient,
        active_workers: Arc<RwLock<HashMap<WorkerId, WorkerInfo>>>,
        event_sender: mpsc::UnboundedSender<DiscoveryEvent>,
        running: Arc<RwLock<bool>>,
        stats: Arc<RwLock<DiscoveryStats>>,
        local_worker_id: WorkerId,
    ) {
        info!("Discovery loop started with interval: {}s", config.discovery_interval_secs);
        let mut interval = tokio::time::interval(Duration::from_secs(config.discovery_interval_secs));

        loop {
            interval.tick().await;

            // Check if we should stop
            if !*running.read().await {
                info!("Discovery loop stopping");
                break;
            }

            let now = chrono::Utc::now().timestamp() as u64;
            let active_count = active_workers.read().await.len();
            debug!("Running discovery round, active workers: {}", active_count);

            // Create and broadcast worker advertisement (announce ourselves)
            let advertisement = P2PMessage::Heartbeat {
                worker_id: local_worker_id,
                timestamp: chrono::Utc::now(),
                load: 0.5, // TODO: Get actual load from system
            };

            if let Err(e) = p2p_network.broadcast_message(advertisement, "bitsage-nodes").await {
                error!("Failed to broadcast worker advertisement: {}", e);
            }

            // Also broadcast peer discovery request to find new workers
            let discovery_msg = P2PMessage::PeerDiscovery {
                capability_query: None,
                max_peers: config.max_workers_per_region,
            };

            if let Err(e) = p2p_network.broadcast_message(discovery_msg, "bitsage-nodes").await {
                error!("Failed to broadcast peer discovery request: {}", e);
            }

            // Update statistics
            {
                let mut s = stats.write().await;
                s.discovery_rounds_completed += 1;
                s.last_discovery_time = Some(now);
            }

            // Send discovery event for monitoring
            let job_requirements = JobRequirements {
                min_gpu_memory_gb: 0,
                min_cpu_cores: 0,
                min_ram_gb: 0,
                required_job_types: vec![],
                required_frameworks: vec![],
                max_network_latency_ms: 1000,
                preferred_regions: vec![],
                max_worker_load: 0.8,
                min_reputation_score: 0.5,
            };

            if let Err(e) = event_sender.send(DiscoveryEvent::DiscoveryRequest(job_requirements)) {
                error!("Failed to send discovery event: {}", e);
                break;
            }
        }
    }

    /// Run the heartbeat monitoring loop
    async fn run_heartbeat_loop(
        config: DiscoveryConfig,
        active_workers: Arc<RwLock<HashMap<WorkerId, WorkerInfo>>>,
        event_sender: mpsc::UnboundedSender<DiscoveryEvent>,
        running: Arc<RwLock<bool>>,
        stats: Arc<RwLock<DiscoveryStats>>,
    ) {
        info!("Heartbeat monitoring loop started with timeout: {}s", config.heartbeat_timeout_secs);
        // Check heartbeats more frequently than the timeout
        let check_interval = config.heartbeat_timeout_secs / 4;
        let mut interval = tokio::time::interval(Duration::from_secs(check_interval.max(5)));

        loop {
            interval.tick().await;

            // Check if we should stop
            if !*running.read().await {
                info!("Heartbeat monitoring loop stopping");
                break;
            }

            let now = chrono::Utc::now().timestamp() as u64;
            let timeout = config.heartbeat_timeout_secs;

            // Find workers that have timed out
            let mut workers_to_remove = Vec::new();
            {
                let workers = active_workers.read().await;
                for (worker_id, worker_info) in workers.iter() {
                    let time_since_seen = now.saturating_sub(worker_info.last_seen);
                    if time_since_seen > timeout {
                        debug!("Worker {} timed out (last seen {}s ago, timeout {}s)",
                            worker_id, time_since_seen, timeout);
                        workers_to_remove.push(*worker_id);
                    }
                }
            }

            // Remove timed out workers
            if !workers_to_remove.is_empty() {
                let mut workers = active_workers.write().await;
                for worker_id in workers_to_remove {
                    if workers.remove(&worker_id).is_some() {
                        info!("Removed timed out worker: {}", worker_id);

                        // Update stats
                        {
                            let mut s = stats.write().await;
                            s.workers_lost += 1;
                        }

                        // Notify listeners
                        if let Err(e) = event_sender.send(DiscoveryEvent::WorkerLost(worker_id)) {
                            error!("Failed to send worker lost event: {}", e);
                        }
                    }
                }
            }

            // Update heartbeat time
            {
                let mut s = stats.write().await;
                s.last_heartbeat_time = Some(now);
            }
        }
    }

    /// Run the P2P event handling loop
    async fn run_p2p_event_loop(
        mut receiver: mpsc::UnboundedReceiver<crate::network::p2p::NetworkEvent>,
        active_workers: Arc<RwLock<HashMap<WorkerId, WorkerInfo>>>,
        dht: Arc<RwLock<HashMap<String, DHTBucket>>>,
        event_sender: mpsc::UnboundedSender<DiscoveryEvent>,
        running: Arc<RwLock<bool>>,
        stats: Arc<RwLock<DiscoveryStats>>,
        config: DiscoveryConfig,
    ) {
        info!("P2P event handling loop started");

        loop {
            tokio::select! {
                // Check running flag periodically
                _ = tokio::time::sleep(Duration::from_secs(1)) => {
                    if !*running.read().await {
                        info!("P2P event handling loop stopping");
                        break;
                    }
                }
                // Process incoming P2P events
                event = receiver.recv() => {
                    match event {
                        Some(network_event) => {
                            Self::handle_p2p_event(
                                network_event,
                                &active_workers,
                                &dht,
                                &event_sender,
                                &stats,
                                &config,
                            ).await;
                        }
                        None => {
                            info!("P2P event channel closed");
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Handle a single P2P network event
    async fn handle_p2p_event(
        event: crate::network::p2p::NetworkEvent,
        active_workers: &Arc<RwLock<HashMap<WorkerId, WorkerInfo>>>,
        dht: &Arc<RwLock<HashMap<String, DHTBucket>>>,
        event_sender: &mpsc::UnboundedSender<DiscoveryEvent>,
        stats: &Arc<RwLock<DiscoveryStats>>,
        config: &DiscoveryConfig,
    ) {
        use crate::network::p2p::NetworkEvent;

        match event {
            NetworkEvent::PeerConnected(peer_id) => {
                info!("Peer connected: {}", peer_id);
                // Could track connected peers separately if needed
            }

            NetworkEvent::PeerDisconnected(peer_id) => {
                info!("Peer disconnected: {}", peer_id);
                // Could remove worker if we track peer_id -> worker_id mapping
            }

            NetworkEvent::MessageReceived { peer_id, message } => {
                debug!("Message received from {}: {:?}", peer_id, message);
                stats.write().await.messages_processed += 1;

                // Process different message types
                match message {
                    P2PMessage::WorkerCapabilities { worker_id, capabilities, network_address, stake_amount: _ } => {
                        // Convert blockchain WorkerCapabilities to discovery WorkerCapabilities
                        let discovery_caps = WorkerCapabilities {
                            gpu_memory_gb: capabilities.gpu_memory as u32,
                            cpu_cores: capabilities.cpu_cores as u32,
                            ram_gb: capabilities.ram as u32,
                            supported_job_types: vec!["ai_inference".to_string(), "training".to_string()],
                            ai_frameworks: vec!["pytorch".to_string(), "tensorflow".to_string()],
                            specialized_hardware: vec![],
                            max_parallel_tasks: 4,
                            network_bandwidth_mbps: capabilities.bandwidth as u32,
                            storage_gb: capabilities.storage as u32,
                            supports_fp16: (capabilities.capability_flags & 0x01) != 0,
                            supports_int8: (capabilities.capability_flags & 0x02) != 0,
                            cuda_compute_capability: Some("8.0".to_string()),
                        };

                        let worker_info = WorkerInfo {
                            worker_id,
                            capabilities: discovery_caps,
                            location: WorkerLocation {
                                region: "unknown".to_string(),
                                country: "unknown".to_string(),
                                latitude: 0.0,
                                longitude: 0.0,
                                timezone: "UTC".to_string(),
                                network_latency_ms: 50,
                            },
                            health: None,
                            reputation: WorkerReputation {
                                worker_id,
                                reputation_score: 0.8,
                                jobs_completed: 0,
                                jobs_failed: 0,
                                jobs_timeout: 0,
                                total_earnings: 0,
                                average_completion_time_ms: 0,
                                last_job_completion: None,
                                last_seen: chrono::Utc::now(),
                                capabilities,
                                network_address: Some(network_address.to_string()),
                                success_rate: 0.8,
                                reliability_score: 0.8,
                                efficiency_score: 0.8,
                                consistency_score: 0.8,
                                penalty_history: std::collections::VecDeque::new(),
                                total_penalties: 0,
                                is_banned: false,
                                ban_reason: None,
                                ban_expiry: None,
                                reputation_decay_start: None,
                                last_decay_calculation: chrono::Utc::now(),
                                result_quality_score: 0.8,
                                average_result_confidence: 0.8,
                                malicious_behavior_count: 0,
                                suspicious_activity_count: 0,
                            },
                            current_load: 0.0,
                            last_seen: chrono::Utc::now().timestamp() as u64,
                            is_available: true,
                        };

                        // Add to active workers
                        active_workers.write().await.insert(worker_id, worker_info.clone());

                        // Add to DHT
                        let bucket_id = format!("{:x}", md5::compute(worker_id.to_string()))[..8].to_string();
                        let mut dht_map = dht.write().await;
                        let bucket = dht_map.entry(bucket_id.clone()).or_insert_with(|| DHTBucket {
                            workers: Vec::new(),
                            last_updated: chrono::Utc::now().timestamp() as u64,
                            bucket_id: bucket_id.clone(),
                        });

                        // Update or add worker in bucket
                        if let Some(existing) = bucket.workers.iter_mut().find(|w| w.worker_id == worker_id) {
                            *existing = worker_info.clone();
                        } else if bucket.workers.len() < config.dht_bucket_size {
                            bucket.workers.push(worker_info.clone());
                        }
                        bucket.last_updated = chrono::Utc::now().timestamp() as u64;

                        // Update stats and notify
                        stats.write().await.workers_discovered += 1;
                        let _ = event_sender.send(DiscoveryEvent::WorkerDiscovered(worker_info));
                    }

                    P2PMessage::Heartbeat { worker_id, timestamp: _, load } => {
                        debug!("Received heartbeat from worker {}, load: {}", worker_id, load);

                        // Update worker's last seen time and load
                        if let Some(worker) = active_workers.write().await.get_mut(&worker_id) {
                            worker.last_seen = chrono::Utc::now().timestamp() as u64;
                            worker.current_load = load;
                        }

                        stats.write().await.heartbeats_received += 1;
                        let _ = event_sender.send(DiscoveryEvent::WorkerHeartbeat(worker_id, load));
                    }

                    P2PMessage::PeerDiscovery { capability_query, max_peers } => {
                        debug!("Received peer discovery request: query={:?}, max={}", capability_query, max_peers);
                        // Could respond with known workers matching the query
                    }

                    P2PMessage::ReputationUpdate { worker_id, reputation_score, performance_metrics: _ } => {
                        debug!("Received reputation update for {}: {}", worker_id, reputation_score);
                        if let Some(worker) = active_workers.write().await.get_mut(&worker_id) {
                            worker.reputation.reputation_score = reputation_score;
                        }
                    }

                    _ => {
                        // Other message types handled elsewhere (job distribution, etc.)
                        debug!("Unhandled message type in discovery: {:?}", message);
                    }
                }
            }

            NetworkEvent::PeerDiscovered { peer_id, addresses } => {
                info!("Peer discovered: {} at {:?}", peer_id, addresses);
                // Could proactively request capabilities from new peers
            }

            NetworkEvent::NetworkError(error) => {
                error!("Network error in discovery: {}", error);
            }
        }
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

    /// Get discovery statistics
    pub async fn get_discovery_stats(&self) -> DiscoveryStats {
        self.stats.read().await.clone()
    }

    /// Get event receiver for discovery events
    pub async fn take_event_receiver(&self) -> Option<mpsc::UnboundedReceiver<DiscoveryEvent>> {
        self.event_receiver.write().await.take()
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

    /// Get all active workers
    pub async fn get_all_active_workers(&self) -> Vec<WorkerInfo> {
        self.active_workers.read().await.values().cloned().collect()
    }

    /// Check if discovery is running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Manually trigger a discovery round (for testing or immediate refresh)
    pub async fn trigger_discovery(&self) -> Result<()> {
        if !*self.running.read().await {
            return Err(anyhow::anyhow!("Discovery system is not running"));
        }

        let discovery_msg = P2PMessage::PeerDiscovery {
            capability_query: None,
            max_peers: self.config.max_workers_per_region,
        };

        self.p2p_network.broadcast_message(discovery_msg, "bitsage-nodes").await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_discovery_config_default() {
        let config = DiscoveryConfig::default();
        assert_eq!(config.discovery_interval_secs, 30);
        assert_eq!(config.heartbeat_timeout_secs, 120);
        assert_eq!(config.max_workers_per_region, 100);
        assert!(config.enable_health_monitoring);
        assert_eq!(config.capability_advertisement_interval_secs, 60);
        assert_eq!(config.dht_bucket_size, 20);
        assert_eq!(config.discovery_radius, 3);
    }

    #[test]
    fn test_discovery_stats_default() {
        let stats = DiscoveryStats::default();
        assert_eq!(stats.discovery_rounds_completed, 0);
        assert_eq!(stats.workers_discovered, 0);
        assert_eq!(stats.workers_lost, 0);
        assert_eq!(stats.heartbeats_sent, 0);
        assert_eq!(stats.heartbeats_received, 0);
        assert_eq!(stats.messages_processed, 0);
        assert!(stats.last_discovery_time.is_none());
        assert!(stats.last_heartbeat_time.is_none());
    }

    #[test]
    fn test_worker_capabilities() {
        let caps = WorkerCapabilities {
            gpu_memory_gb: 80,
            cpu_cores: 64,
            ram_gb: 512,
            supported_job_types: vec!["ai_inference".to_string(), "training".to_string()],
            ai_frameworks: vec!["pytorch".to_string(), "tensorflow".to_string()],
            specialized_hardware: vec!["h100".to_string()],
            max_parallel_tasks: 8,
            network_bandwidth_mbps: 10000,
            storage_gb: 2000,
            supports_fp16: true,
            supports_int8: true,
            cuda_compute_capability: Some("9.0".to_string()),
        };

        assert_eq!(caps.gpu_memory_gb, 80);
        assert_eq!(caps.cpu_cores, 64);
        assert!(caps.supported_job_types.contains(&"ai_inference".to_string()));
        assert!(caps.supports_fp16);
    }

    #[test]
    fn test_worker_location() {
        let location = WorkerLocation {
            region: "us-east-1".to_string(),
            country: "US".to_string(),
            latitude: 37.7749,
            longitude: -122.4194,
            timezone: "America/Los_Angeles".to_string(),
            network_latency_ms: 25,
        };

        assert_eq!(location.region, "us-east-1");
        assert_eq!(location.network_latency_ms, 25);
    }

    #[test]
    fn test_job_requirements() {
        let requirements = JobRequirements {
            min_gpu_memory_gb: 24,
            min_cpu_cores: 8,
            min_ram_gb: 64,
            required_job_types: vec!["ai_inference".to_string()],
            required_frameworks: vec!["pytorch".to_string()],
            max_network_latency_ms: 100,
            preferred_regions: vec!["us-east-1".to_string()],
            max_worker_load: 0.8,
            min_reputation_score: 0.7,
        };

        assert_eq!(requirements.min_gpu_memory_gb, 24);
        assert_eq!(requirements.max_worker_load, 0.8);
        assert!(requirements.required_job_types.contains(&"ai_inference".to_string()));
    }

    #[test]
    fn test_discovery_message_serialization() {
        let msg = DiscoveryMessage::Heartbeat {
            worker_id: WorkerId::new(),
            current_load: 0.5,
            health_metrics: None,
            timestamp: 1234567890,
        };

        // Test that message can be serialized
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("Heartbeat"));
        assert!(serialized.contains("0.5"));
    }

    #[test]
    fn test_discovery_event_variants() {
        let worker_id = WorkerId::new();

        let event1 = DiscoveryEvent::WorkerLost(worker_id);
        if let DiscoveryEvent::WorkerLost(id) = event1 {
            assert_eq!(id, worker_id);
        }

        let event2 = DiscoveryEvent::WorkerHeartbeat(worker_id, 0.75);
        if let DiscoveryEvent::WorkerHeartbeat(id, load) = event2 {
            assert_eq!(id, worker_id);
            assert_eq!(load, 0.75);
        }
    }

    #[test]
    fn test_dht_bucket() {
        let bucket = DHTBucket {
            workers: Vec::new(),
            last_updated: chrono::Utc::now().timestamp() as u64,
            bucket_id: "test_bucket".to_string(),
        };

        assert!(bucket.workers.is_empty());
        assert_eq!(bucket.bucket_id, "test_bucket");
    }
}
