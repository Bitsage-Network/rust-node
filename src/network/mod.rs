//! # Network Layer
//!
//! Implements the P2P networking layer for the Bitsage Network, including
//! job distribution, worker discovery, health monitoring, and result collection.

pub mod p2p;
pub mod job_distribution;
pub mod health_reputation;
pub mod result_collection;
pub mod discovery;
pub mod gossip;
pub mod encrypted_jobs;
pub mod nonce_tracker;
pub mod dht;

// Re-export main components
pub use p2p::{NetworkActor, NetworkClient, P2PConfig, P2PMessage, NetworkEvent};
pub use job_distribution::{JobDistributor, JobDistributionConfig, JobDistributionEvent};
pub use health_reputation::{HealthReputationSystem, HealthReputationConfig, HealthMetrics};
pub use result_collection::{ResultCollector, ResultCollectionConfig, ResultCollectionEvent};
pub use discovery::{WorkerDiscovery, DiscoveryConfig, DiscoveryEvent, DiscoveryStats};
pub use gossip::{GossipProtocol, GossipConfig, GossipEvent};
pub use encrypted_jobs::{
    EncryptedJobManager, EncryptedJobConfig, EncryptedJobAnnouncement,
    EncryptedWorkerBid, EncryptedJobResult, CapabilityGroupManager,
};
pub use nonce_tracker::{
    NonceTracker, NonceTrackerConfig, NonceValidation, NonceSource,
    SharedNonceTracker, create_nonce_tracker, NonceTrackerStats,
};
pub use dht::{
    DhtNode, DhtConfig, DhtMessage, DhtPeer, DhtJobEntry, DhtJobStatus,
    NodeId as DhtNodeId, DhtStats,
};

// Import required types
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock, Mutex};
use anyhow::Result;
use tracing::{info, warn};

use crate::blockchain::{client::StarknetClient, contracts::JobManagerContract};
use crate::types::NodeId;
use crate::network::health_reputation::NetworkHealth;

/// Network layer configuration
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub p2p: P2PConfig,
    pub job_distribution: JobDistributionConfig,
    pub health_reputation: HealthReputationConfig,
    pub result_collection: ResultCollectionConfig,
    pub discovery: DiscoveryConfig,
    pub gossip: GossipConfig,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            p2p: P2PConfig::default(),
            job_distribution: JobDistributionConfig::default(),
            health_reputation: HealthReputationConfig::default(),
            result_collection: ResultCollectionConfig::default(),
            discovery: DiscoveryConfig::default(),
            gossip: GossipConfig::default(),
        }
    }
}

/// Main network coordinator that manages all network components
pub struct NetworkCoordinator {
    config: NetworkConfig,
    p2p_client: NetworkClient,
    job_distributor: Arc<JobDistributor>,
    health_reputation_system: Arc<HealthReputationSystem>,
    result_collector: Arc<ResultCollector>,
    worker_discovery: Arc<WorkerDiscovery>,
    gossip_protocol: Arc<GossipProtocol>,

    // Internal state
    running: Arc<RwLock<bool>>,
    /// Event receiver from the P2P network actor.
    /// Use `take_event_receiver()` to consume this - it can only be taken once.
    event_receiver: Arc<Mutex<Option<mpsc::UnboundedReceiver<NetworkEvent>>>>,
}

impl NetworkCoordinator {
    /// Create a new network coordinator
    pub fn new(
        config: NetworkConfig,
        blockchain_client: Arc<StarknetClient>,
        job_manager: Arc<JobManagerContract>,
    ) -> Result<Self> {
        // Create P2P network (Actor + Client)
        // The actor is spawned in the background immediately
        let (p2p_client, event_receiver) = NetworkActor::new(config.p2p.clone())?;
        
        // Create health reputation system
        let health_reputation_system = Arc::new(HealthReputationSystem::new(config.health_reputation.clone()));
        
        // Create job distributor
        let job_distributor = Arc::new(JobDistributor::new(
            config.job_distribution.clone(),
            blockchain_client.clone(),
            job_manager.clone(),
            Arc::new(p2p_client.clone()),
        ));
        
        // Create result collector
        let result_collector = Arc::new(ResultCollector::new(
            config.result_collection.clone(),
            blockchain_client.clone(),
            job_manager.clone(),
            Arc::new(p2p_client.clone()),
        ));
        
        // Create worker discovery
        let worker_discovery = Arc::new(WorkerDiscovery::new(
            config.discovery.clone(),
            p2p_client.clone(),
            health_reputation_system.clone(),
        ));
        
        // Create gossip protocol
        let node_id = NodeId::new(); // TODO: Get actual node ID
        let gossip_protocol = Arc::new(GossipProtocol::new(
            config.gossip.clone(),
            p2p_client.clone(),
            health_reputation_system.clone(),
            node_id,
        ));
        
        Ok(Self {
            config,
            p2p_client,
            job_distributor,
            health_reputation_system,
            result_collector,
            worker_discovery,
            gossip_protocol,
            running: Arc::new(RwLock::new(false)),
            event_receiver: Arc::new(Mutex::new(Some(event_receiver))),
        })
    }

    /// Start all network components
    pub async fn start(&self) -> Result<()> {
        info!("Starting Network Coordinator...");
        
        {
            let mut running = self.running.write().await;
            if *running {
                return Err(anyhow::anyhow!("Network coordinator already running"));
            }
            *running = true;
        }

        // P2P Network Actor is already running via new()
        
        // Start job distributor
        self.job_distributor.start().await?;
        
        // Start result collector
        self.result_collector.start().await?;
        
        // Start worker discovery
        self.worker_discovery.start().await?;
        
        // Start gossip protocol
        self.gossip_protocol.start().await?;

        info!("Network coordinator started successfully");
        Ok(())
    }

    /// Stop all network components
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping Network Coordinator...");
        
        {
            let mut running = self.running.write().await;
            *running = false;
        }

        // Stop all components
        self.gossip_protocol.stop().await?;
        self.worker_discovery.stop().await?;
        self.result_collector.stop().await?;
        self.job_distributor.stop().await?;
        
        // P2P Network Actor stops when all clients (senders) are dropped or explicitly via command
        // For now we don't have an explicit stop command but we could add one.

        info!("Network coordinator stopped");
        Ok(())
    }

    /// Get job distributor reference
    pub fn job_distributor(&self) -> Arc<JobDistributor> {
        self.job_distributor.clone()
    }

    /// Get health reputation system reference
    pub fn health_reputation_system(&self) -> Arc<HealthReputationSystem> {
        self.health_reputation_system.clone()
    }

    /// Get result collector reference
    pub fn result_collector(&self) -> Arc<ResultCollector> {
        self.result_collector.clone()
    }

    /// Get worker discovery reference
    pub fn worker_discovery(&self) -> Arc<WorkerDiscovery> {
        self.worker_discovery.clone()
    }

    /// Get gossip protocol reference
    pub fn gossip_protocol(&self) -> Arc<GossipProtocol> {
        self.gossip_protocol.clone()
    }

    /// Get network statistics
    pub async fn get_network_stats(&self) -> NetworkStats {
        NetworkStats {
            active_workers: self.worker_discovery.get_active_workers_count().await,
            active_jobs: self.job_distributor.get_job_stats().await.values().sum(),
            active_peers: self.gossip_protocol.get_active_peers_count().await,
            known_messages: self.gossip_protocol.get_known_messages_count().await,
            network_health: self.health_reputation_system.get_network_health().await,
        }
    }

    /// Take the event receiver from the P2P network.
    ///
    /// This can only be called once - subsequent calls will return `None`.
    /// The receiver provides network events like peer connections, disconnections,
    /// incoming messages, and other network activity.
    pub async fn take_event_receiver(&self) -> Option<mpsc::UnboundedReceiver<NetworkEvent>> {
        let mut receiver_guard = self.event_receiver.lock().await;
        receiver_guard.take()
    }

    /// Check if the event receiver is still available (hasn't been taken yet).
    pub async fn has_event_receiver(&self) -> bool {
        let receiver_guard = self.event_receiver.lock().await;
        receiver_guard.is_some()
    }

    /// Subscribe to network events by providing a callback handler.
    ///
    /// This is an alternative to `take_event_receiver()` that spawns a background
    /// task to process events. Returns an error if the receiver has already been taken.
    pub async fn subscribe_to_events<F>(&self, handler: F) -> Result<()>
    where
        F: Fn(NetworkEvent) + Send + 'static,
    {
        let receiver = self.take_event_receiver().await
            .ok_or_else(|| anyhow::anyhow!("Event receiver already taken"))?;

        tokio::spawn(async move {
            let mut receiver = receiver;
            while let Some(event) = receiver.recv().await {
                handler(event);
            }
        });

        Ok(())
    }

    pub async fn is_connected(&self) -> bool {
        true
    }
}

/// Network statistics
#[derive(Debug, Clone)]
pub struct NetworkStats {
    pub active_workers: usize,
    pub active_jobs: usize,
    pub active_peers: usize,
    pub known_messages: usize,
    pub network_health: NetworkHealth,
}
