//! # Network Coordinator Service
//!
//! Network coordination service that integrates with the existing network components
//! and provides a unified interface for P2P networking, job distribution, and
//! health reputation management.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{Duration, Instant};
use tracing::{info, debug, error};

use crate::types::{WorkerId, NodeId, JobId, PeerInfo};
use crate::network::{
    NetworkCoordinator as BaseNetworkCoordinator,
    NetworkStats,
};
use crate::network::health_reputation::NetworkHealth;
use crate::blockchain::{client::StarknetClient, contracts::JobManagerContract};
use crate::coordinator::config::NetworkCoordinatorConfig;

/// Network coordinator events
#[derive(Debug, Clone)]
pub enum NetworkCoordinatorEvent {
    PeerDiscovered(NodeId, PeerInfo),
    PeerLost(NodeId),
    JobAnnounced(JobId, NodeId),
    JobBidReceived(JobId, WorkerId, u64), // job_id, worker_id, bid_amount
    JobAssigned(JobId, WorkerId),
    JobResultReceived(JobId, WorkerId, Vec<u8>),
    HealthReputationUpdated(NodeId, f64),
    NetworkStatsUpdated(NetworkStats),
    NetworkHealthChanged(NetworkHealth),
}

/// Network coordinator statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCoordinatorStats {
    pub total_peers: u64,
    pub active_peers: u64,
    pub jobs_announced: u64,
    pub jobs_bid_on: u64,
    pub jobs_assigned: u64,
    pub jobs_completed: u64,
    pub jobs_failed: u64,
    pub average_reputation: f64,
    pub network_latency_ms: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
}

/// Main network coordinator service
pub struct NetworkCoordinatorService {
    config: NetworkCoordinatorConfig,
    starknet_client: Arc<StarknetClient>,
    job_manager_contract: Arc<JobManagerContract>,
    
    // Base network coordinator
    base_coordinator: Arc<BaseNetworkCoordinator>,
    
    // Network state
    active_peers: Arc<RwLock<HashMap<NodeId, PeerInfo>>>,
    job_announcements: Arc<RwLock<HashMap<JobId, JobAnnouncement>>>,
    job_bids: Arc<RwLock<HashMap<JobId, Vec<JobBid>>>>,
    
    // Network statistics
    stats: Arc<RwLock<NetworkCoordinatorStats>>,
    
    // Communication channels
    event_sender: mpsc::UnboundedSender<NetworkCoordinatorEvent>,
    event_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<NetworkCoordinatorEvent>>>>,
    
    // Internal state
    running: Arc<RwLock<bool>>,
    connected: Arc<RwLock<bool>>,
}

/// Job announcement information
#[derive(Debug, Clone)]
struct JobAnnouncement {
    job_id: JobId,
    announced_by: NodeId,
    announced_at: Instant,
    requirements: Vec<String>,
    max_bid: u64,
}

/// Job bid information
#[derive(Debug, Clone)]
struct JobBid {
    worker_id: WorkerId,
    bid_amount: u64,
    bid_at: Instant,
    capabilities: Vec<String>,
}

impl NetworkCoordinatorService {
    /// Create a new network coordinator service
    pub fn new(
        config: NetworkCoordinatorConfig,
        starknet_client: Arc<StarknetClient>,
        job_manager_contract: Arc<JobManagerContract>,
    ) -> Result<Self> {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        
        let stats = NetworkCoordinatorStats {
            total_peers: 0,
            active_peers: 0,
            jobs_announced: 0,
            jobs_bid_on: 0,
            jobs_assigned: 0,
            jobs_completed: 0,
            jobs_failed: 0,
            average_reputation: 0.0,
            network_latency_ms: 0,
            messages_sent: 0,
            messages_received: 0,
        };
        
        // Create network config from individual configs
        let network_config = crate::network::NetworkConfig {
            p2p: config.p2p.clone(),
            job_distribution: config.job_distribution.clone(),
            health_reputation: config.health_reputation.clone(),
            result_collection: config.result_collection.clone(),
            discovery: config.discovery.clone(),
            gossip: config.gossip.clone(),
        };
        
        // Create base network coordinator
        let base_coordinator = Arc::new(BaseNetworkCoordinator::new(
            network_config,
            starknet_client.clone(),
            job_manager_contract.clone(),
        )?);
        
        Ok(Self {
            config,
            starknet_client,
            job_manager_contract,
            base_coordinator,
            active_peers: Arc::new(RwLock::new(HashMap::new())),
            job_announcements: Arc::new(RwLock::new(HashMap::new())),
            job_bids: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(stats)),
            event_sender,
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
            running: Arc::new(RwLock::new(false)),
            connected: Arc::new(RwLock::new(false)),
        })
    }

    /// Start the network coordinator service
    pub async fn start(&self) -> Result<()> {
        info!("Starting Network Coordinator Service...");
        
        {
            let mut running = self.running.write().await;
            if *running {
                return Err(anyhow::anyhow!("Network coordinator already running"));
            }
            *running = true;
        }

        // Start base network coordinator
        self.base_coordinator.start().await?;
        
        // Start monitoring tasks
        let _network_monitoring_handle = self.start_network_monitoring().await?;
        let _stats_collection_handle = self.start_stats_collection().await?;
        let _event_processing_handle = self.start_event_processing().await?;

        // Update connection status
        {
            let mut connected = self.connected.write().await;
            *connected = true;
        }

        info!("Network coordinator service started successfully");

        // Start all tasks and wait for them to complete
        // Note: These are now () since we're not awaiting them
        let _network_result = ();
        let _stats_result = ();
        let _event_result = ();
        
        // Log any errors (simplified since we're not actually checking results)
        debug!("Network coordinator tasks completed");

        Ok(())
    }

    /// Stop the network coordinator service
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping Network Coordinator Service...");
        
        {
            let mut running = self.running.write().await;
            *running = false;
        }

        // Stop base network coordinator
        self.base_coordinator.stop().await?;

        // Update connection status
        {
            let mut connected = self.connected.write().await;
            *connected = false;
        }

        info!("Network coordinator service stopped");
        Ok(())
    }

    /// Announce a job to the network
    pub async fn announce_job(&self, job_id: JobId, requirements: Vec<String>, max_bid: u64) -> Result<()> {
        info!("Announcing job {} to network", job_id);

        // Get our node ID from the gossip state
        let gossip = self.base_coordinator.gossip_protocol();
        let gossip_state = gossip.get_gossip_state().await;
        let our_node_id = gossip_state.node_id;

        // Create job announcement
        let announcement = JobAnnouncement {
            job_id,
            announced_by: our_node_id,
            announced_at: Instant::now(),
            requirements: requirements.clone(),
            max_bid,
        };

        // Store announcement
        self.job_announcements.write().await.insert(job_id, announcement.clone());

        // Build gossip payload with proper types
        let job_requirements = crate::network::gossip::JobRequirements {
            min_gpu_memory_gb: 0,
            min_cpu_cores: 0,
            min_ram_gb: 0,
            required_job_types: requirements.clone(),
            required_frameworks: vec![],
            max_network_latency_ms: 1000,
            preferred_regions: vec![],
            max_worker_load: 0.9,
            min_reputation_score: 0.5,
        };

        let deadline = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() + 3600; // 1 hour deadline

        let payload = crate::network::gossip::GossipPayload::JobAnnouncement {
            job_id,
            job_type: "general".to_string(),
            requirements: job_requirements,
            max_reward: max_bid as u128,
            deadline,
        };

        // Broadcast via gossip
        if let Err(e) = gossip.broadcast_message(
            crate::network::gossip::GossipMessageType::JobAnnouncement,
            payload,
        ).await {
            error!("Failed to broadcast job announcement via gossip: {}", e);
        } else {
            debug!("Job announcement {} broadcast via gossip", job_id);
        }

        // Update statistics
        self.update_stats_job_announced().await;

        // Send event
        if let Err(e) = self.event_sender.send(NetworkCoordinatorEvent::JobAnnounced(job_id, announcement.announced_by)) {
            error!("Failed to send job announced event: {}", e);
        }

        info!("Job {} announced to network with requirements: {:?}, max_bid: {}", job_id, requirements, max_bid);
        Ok(())
    }

    /// Submit a bid for a job
    pub async fn submit_job_bid(&self, job_id: JobId, worker_id: WorkerId, bid_amount: u64, capabilities: Vec<String>) -> Result<()> {
        info!("Submitting bid for job {} by worker {}: {}", job_id, worker_id, bid_amount);

        // Create job bid
        let bid = JobBid {
            worker_id: worker_id.clone(),
            bid_amount,
            bid_at: Instant::now(),
            capabilities: capabilities.clone(),
        };

        // Store bid
        let mut bids = self.job_bids.write().await;
        bids.entry(job_id).or_insert_with(Vec::new).push(bid.clone());

        // Update statistics
        self.update_stats_job_bid().await;

        // Send event
        if let Err(e) = self.event_sender.send(NetworkCoordinatorEvent::JobBidReceived(job_id, worker_id.clone(), bid_amount)) {
            error!("Failed to send job bid received event: {}", e);
        }

        info!("Bid submitted for job {} by worker {}: {}", job_id, worker_id, bid_amount);
        Ok(())
    }

    /// Assign a job to a worker
    pub async fn assign_job(&self, job_id: JobId, worker_id: WorkerId) -> Result<()> {
        info!("Assigning job {} to worker {}", job_id, worker_id);

        // Remove from announcements (job has been assigned)
        self.job_announcements.write().await.remove(&job_id);

        // Clear bids for this job
        self.job_bids.write().await.remove(&job_id);

        // Update statistics
        self.update_stats_job_assigned().await;

        // Send event
        if let Err(e) = self.event_sender.send(NetworkCoordinatorEvent::JobAssigned(job_id, worker_id.clone())) {
            error!("Failed to send job assigned event: {}", e);
        }

        info!("Job {} assigned to worker {}", job_id, worker_id);
        Ok(())
    }

    /// Submit job result
    pub async fn submit_job_result(&self, job_id: JobId, worker_id: WorkerId, result: Vec<u8>) -> Result<()> {
        info!("Submitting result for job {} by worker {}", job_id, worker_id);

        // Calculate result hash for verification
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&result);
        let result_hash = hex::encode(hasher.finalize());

        // Update statistics
        self.update_stats_job_completed().await;

        // Send event
        if let Err(e) = self.event_sender.send(NetworkCoordinatorEvent::JobResultReceived(job_id, worker_id.clone(), result.clone())) {
            error!("Failed to send job result received event: {}", e);
        }

        info!("Result submitted for job {} by worker {} ({} bytes, hash: {})", job_id, worker_id, result.len(), result_hash);
        Ok(())
    }

    /// Get network statistics
    pub async fn get_network_stats(&self) -> NetworkStats {
        self.base_coordinator.get_network_stats().await
    }

    /// Get network health
    pub async fn get_network_health(&self) -> NetworkHealth {
        // For now, return a default health status
        NetworkHealth {
            total_active_workers: 0,
            average_reputation: 0.0,
            network_load_percent: 0.0,
            successful_jobs_24h: 0,
            failed_jobs_24h: 0,
            average_job_latency_ms: 0,
        }
    }

    /// Get active peers
    pub async fn get_active_peers(&self) -> Vec<PeerInfo> {
        let peers = self.active_peers.read().await;
        peers.values().cloned().collect()
    }

    /// Check if connected to network
    pub async fn is_connected(&self) -> bool {
        *self.connected.read().await
    }

    /// Health check for network coordinator
    pub async fn health_check(&self) -> Result<()> {
        // Check connection status
        let connected = *self.connected.read().await;
        if !connected {
            return Err(anyhow::anyhow!("Network coordinator not connected"));
        }
        
        // Check if running
        let running = *self.running.read().await;
        if !running {
            return Err(anyhow::anyhow!("Network coordinator not running"));
        }
        
        Ok(())
    }

    /// Start network monitoring
    async fn start_network_monitoring(&self) -> Result<()> {
        let config = self.config.clone();
        let event_sender = self.event_sender.clone();
        let running = self.running_handle();
        let stats = self.stats_handle();
        let active_peers = self.active_peers_handle();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(config.monitoring.health_check_interval_secs));

            loop {
                interval.tick().await;

                // Check if we should stop
                if !*running.read().await {
                    info!("Network monitoring loop stopping");
                    break;
                }

                // Get stats from the Send+Sync handle
                let current_stats = stats.read().await;
                let peers = active_peers.read().await;

                // Build network health from actual stats
                let health = NetworkHealth {
                    total_active_workers: peers.len(),
                    average_reputation: current_stats.average_reputation,
                    network_load_percent: if current_stats.active_peers > 0 {
                        ((current_stats.jobs_announced as f64 / current_stats.active_peers as f64 * 10.0).min(100.0)) as f32
                    } else {
                        0.0
                    },
                    successful_jobs_24h: current_stats.jobs_completed,
                    failed_jobs_24h: current_stats.jobs_failed,
                    average_job_latency_ms: current_stats.network_latency_ms,
                };

                if let Err(e) = event_sender.send(NetworkCoordinatorEvent::NetworkHealthChanged(health)) {
                    error!("Failed to send network health changed event: {}", e);
                }
            }
        });

        Ok(())
    }

    /// Start statistics collection
    async fn start_stats_collection(&self) -> Result<()> {
        let stats = self.stats_handle();
        let active_peers = self.active_peers_handle();
        let running = self.running_handle();
        let event_sender = self.event_sender.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));

            loop {
                interval.tick().await;

                // Check if we should stop
                if !*running.read().await {
                    info!("Network stats collection loop stopping");
                    break;
                }

                // Update peer counts from active peers
                let peers = active_peers.read().await;
                let peer_count = peers.len() as u64;
                drop(peers); // Release read lock before acquiring write lock

                // Update stats with current peer information
                let mut stats_guard = stats.write().await;
                stats_guard.total_peers = peer_count;

                // Filter active peers by their is_active status
                let peers_read = active_peers.read().await;
                let active_count = peers_read.values().filter(|p| p.is_active).count() as u64;
                drop(peers_read);
                stats_guard.active_peers = active_count;

                // Calculate average reputation from peers (if we have reputation data)
                // For now, maintain the current average
                let current_stats = stats_guard.clone();
                drop(stats_guard);

                // Send stats update event
                if let Err(e) = event_sender.send(NetworkCoordinatorEvent::NetworkStatsUpdated(
                    crate::network::NetworkStats {
                        active_workers: current_stats.active_peers as usize,
                        active_jobs: current_stats.jobs_assigned as usize,
                        active_peers: current_stats.total_peers as usize,
                        known_messages: (current_stats.messages_sent + current_stats.messages_received) as usize,
                        network_health: NetworkHealth {
                            total_active_workers: current_stats.active_peers as usize,
                            average_reputation: current_stats.average_reputation,
                            network_load_percent: 0.0,
                            successful_jobs_24h: current_stats.jobs_completed,
                            failed_jobs_24h: current_stats.jobs_failed,
                            average_job_latency_ms: current_stats.network_latency_ms,
                        },
                    }
                )) {
                    error!("Failed to send network stats updated event: {}", e);
                }

                debug!(
                    "Network stats collected - Peers: {}, Messages: sent={} recv={}, Latency: {}ms",
                    current_stats.total_peers,
                    current_stats.messages_sent,
                    current_stats.messages_received,
                    current_stats.network_latency_ms
                );
            }
        });

        Ok(())
    }

    /// Start event processing
    async fn start_event_processing(&self) -> Result<()> {
        let active_peers = self.active_peers_handle();
        let running = self.running_handle();
        let _event_sender = self.event_sender.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));

            loop {
                interval.tick().await;

                // Check if we should stop
                if !*running.read().await {
                    info!("Network event processing loop stopping");
                    break;
                }

                // Check for peer changes and send discovery events
                let peers = active_peers.read().await;
                let peer_count = peers.len();
                drop(peers);

                debug!("Network event processing tick - {} active peers", peer_count);
            }
        });

        Ok(())
    }

    /// Update statistics for job announced
    async fn update_stats_job_announced(&self) {
        let mut stats = self.stats.write().await;
        stats.jobs_announced += 1;
    }

    /// Update statistics for job bid
    async fn update_stats_job_bid(&self) {
        let mut stats = self.stats.write().await;
        stats.jobs_bid_on += 1;
    }

    /// Update statistics for job assigned
    async fn update_stats_job_assigned(&self) {
        let mut stats = self.stats.write().await;
        stats.jobs_assigned += 1;
    }

    /// Update statistics for job completed
    async fn update_stats_job_completed(&self) {
        let mut stats = self.stats.write().await;
        stats.jobs_completed += 1;
    }

    /// Take the event receiver.
    ///
    /// This can only be called once - subsequent calls will return `None`.
    pub async fn take_event_receiver(&self) -> Option<mpsc::UnboundedReceiver<NetworkCoordinatorEvent>> {
        self.event_receiver.write().await.take()
    }

    /// Check if the event receiver is still available.
    pub async fn has_event_receiver(&self) -> bool {
        self.event_receiver.read().await.is_some()
    }

    /// Get a Send+Sync handle to the stats for use in spawned tasks
    /// This allows metrics collection from within tokio::spawn without
    /// moving the entire NetworkCoordinatorService (which contains non-Send fields)
    pub fn stats_handle(&self) -> Arc<RwLock<NetworkCoordinatorStats>> {
        Arc::clone(&self.stats)
    }

    /// Get a Send+Sync handle to active peers for use in spawned tasks
    pub fn active_peers_handle(&self) -> Arc<RwLock<HashMap<NodeId, PeerInfo>>> {
        Arc::clone(&self.active_peers)
    }

    /// Get a Send+Sync handle to the connected state for use in spawned tasks
    pub fn connected_handle(&self) -> Arc<RwLock<bool>> {
        Arc::clone(&self.connected)
    }

    /// Get a Send+Sync handle to the running state for use in spawned tasks
    pub fn running_handle(&self) -> Arc<RwLock<bool>> {
        Arc::clone(&self.running)
    }

    /// Get announcement details for a job
    pub async fn get_announcement(&self, job_id: &JobId) -> Option<(JobId, Instant, Vec<String>, u64)> {
        let announcements = self.job_announcements.read().await;
        announcements.get(job_id).map(|a| (a.job_id, a.announced_at, a.requirements.clone(), a.max_bid))
    }

    /// Get all bids for a job
    pub async fn get_job_bids(&self, job_id: &JobId) -> Vec<(WorkerId, u64, Instant, Vec<String>)> {
        let bids = self.job_bids.read().await;
        bids.get(job_id)
            .map(|job_bids| {
                job_bids.iter()
                    .map(|b| (b.worker_id.clone(), b.bid_amount, b.bid_at, b.capabilities.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get the Starknet client
    pub fn starknet_client(&self) -> &Arc<StarknetClient> {
        &self.starknet_client
    }

    /// Get the job manager contract
    pub fn job_manager_contract(&self) -> &Arc<JobManagerContract> {
        &self.job_manager_contract
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_network_coordinator_creation() {
        let config = NetworkCoordinatorConfig::default();
        let starknet_client = Arc::new(StarknetClient::new("https://starknet-sepolia-rpc.publicnode.com".to_string()).unwrap());
        let job_manager_contract = Arc::new(JobManagerContract::new_from_address(
            starknet_client.clone(),
            "0x00bf025663b8a7c7e43393f082b10afe66bd9ddb06fb5e521e3adbcf693094bd",
        ).unwrap());
        
        let coordinator = NetworkCoordinatorService::new(
            config,
            starknet_client,
            job_manager_contract,
        ).unwrap();
        
        assert!(!coordinator.is_connected().await);
    }

    #[tokio::test]
    async fn test_job_announcement() {
        let config = NetworkCoordinatorConfig::default();
        let starknet_client = Arc::new(StarknetClient::new("https://starknet-sepolia-rpc.publicnode.com".to_string()).unwrap());
        let job_manager_contract = Arc::new(JobManagerContract::new_from_address(
            starknet_client.clone(),
            "0x00bf025663b8a7c7e43393f082b10afe66bd9ddb06fb5e521e3adbcf693094bd",
        ).unwrap());
        
        let coordinator = NetworkCoordinatorService::new(
            config,
            starknet_client,
            job_manager_contract,
        ).unwrap();
        
        let job_id = JobId::new();
        let requirements = vec!["gpu".to_string(), "high_memory".to_string()];
        let max_bid = 1000;

        // Test that job announcement succeeds (it logs errors but doesn't fail hard)
        let result = coordinator.announce_job(job_id, requirements.clone(), max_bid).await;
        assert!(result.is_ok());

        // Verify the announcement was stored
        let announcements = coordinator.job_announcements.read().await;
        assert!(announcements.contains_key(&job_id));

        // Verify the announcement details
        let announcement = announcements.get(&job_id).unwrap();
        assert_eq!(announcement.job_id, job_id);
        assert_eq!(announcement.requirements, requirements);
        assert_eq!(announcement.max_bid, max_bid);
    }
} 