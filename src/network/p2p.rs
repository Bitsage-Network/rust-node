//! # P2P Network Implementation
//!
//! This module implements the peer-to-peer networking layer using libp2p.
//!
//! It uses an Actor pattern where the `NetworkActor` owns the `Swarm` and runs in a background task,
//! and other components interact with it via a `NetworkClient` that sends `NetworkCommand`s.

use anyhow::{Result, anyhow, Context};
use async_trait::async_trait;
use futures::prelude::*;
use libp2p::{
    gossipsub, identify, kad, mdns, noise, ping, tcp, yamux,
    core::upgrade::Version,
    identity::Keypair,
    swarm::{NetworkBehaviour, SwarmEvent, Swarm},
    Multiaddr, PeerId, Transport,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tokio::sync::{mpsc, RwLock, oneshot};
use tracing::{debug, error, info, warn};

use crate::types::{JobId, WorkerId, NetworkAddress};
use crate::blockchain::types::WorkerCapabilities;
use crate::network::encrypted_jobs::{
    EncryptedJobAnnouncement, EncryptedWorkerBid, EncryptedJobResult,
    X25519PublicKey,
};

/// P2P network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2PConfig {
    /// Local peer identity keypair
    pub keypair: Option<Vec<u8>>,
    /// Listen addresses for the network
    pub listen_addresses: Vec<Multiaddr>,
    /// Bootstrap peers for initial discovery
    pub bootstrap_peers: Vec<(PeerId, Multiaddr)>,
    /// Maximum number of peers to connect to
    pub max_peers: usize,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Gossip configuration
    pub gossip_config: GossipConfig,
    /// Kademlia DHT configuration
    pub kad_config: KademliaConfig,
    /// Enable mDNS local discovery
    pub enable_mdns: bool,
}

/// Gossip protocol configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipConfig {
    /// Topics to subscribe to
    pub topics: Vec<String>,
    /// Message ID function
    pub message_id_fn: String,
    /// Duplicate cache time in seconds
    pub duplicate_cache_time: u64,
    /// Heartbeat interval
    pub heartbeat_interval: Duration,
}

/// Kademlia DHT configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KademliaConfig {
    /// Replication factor
    pub replication_factor: usize,
    /// Query timeout
    pub query_timeout: Duration,
    /// Enable automatic mode
    pub automatic_mode: bool,
}

/// Messages that can be sent over the P2P network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2PMessage {
    /// Job announcement to the network
    JobAnnouncement {
        job_id: JobId,
        spec: crate::blockchain::types::JobSpec,
        max_reward: u128,
        deadline: u64,
    },
    /// Worker capability announcement
    WorkerCapabilities {
        worker_id: WorkerId,
        capabilities: crate::blockchain::types::WorkerCapabilities,
        network_address: NetworkAddress,
        stake_amount: u64,
    },
    /// Job result submission
    JobResult {
        job_id: JobId,
        worker_id: WorkerId,
        success: bool,
        data: Vec<u8>,
    },
    /// Worker bid for a job
    WorkerBid {
        job_id: JobId,
        worker_id: WorkerId,
        bid_amount: u128,
        estimated_completion_time: u64,
        reputation_score: f64,
    },
    /// Job assignment notification
    JobAssignment {
        job_id: JobId,
        worker_id: WorkerId,
        assignment_id: String,
        reward_amount: u128,
    },
    /// Reputation update
    ReputationUpdate {
        worker_id: WorkerId,
        reputation_score: f64,
        performance_metrics: HashMap<String, f64>,
    },
    /// Peer discovery request
    PeerDiscovery {
        capability_query: Option<String>,
        max_peers: usize,
    },
    /// Heartbeat/ping message
    Heartbeat {
        worker_id: WorkerId,
        timestamp: chrono::DateTime<chrono::Utc>,
        load: f32,
    },

    // =========================================================================
    // ENCRYPTED JOB MESSAGES (Privacy-Preserving)
    // =========================================================================

    /// Encrypted job announcement - only eligible workers can decrypt
    EncryptedAnnouncement(EncryptedJobAnnouncement),

    /// Encrypted bid from a worker
    EncryptedBid(EncryptedWorkerBid),

    /// Encrypted job result
    EncryptedResult(EncryptedJobResult),

    /// Worker public key advertisement for encrypted communications
    WorkerKeyAdvertisement {
        worker_id: WorkerId,
        public_key: X25519PublicKey,
        capabilities_hash: [u8; 32],
        timestamp: u64,
        signature: Vec<u8>,
    },

    /// Request for worker's public key
    WorkerKeyRequest {
        requester_id: WorkerId,
        target_worker_id: WorkerId,
    },

    /// Response with worker's public key
    WorkerKeyResponse {
        worker_id: WorkerId,
        public_key: X25519PublicKey,
        capabilities_hash: [u8; 32],
    },
}

/// Network events that can be emitted
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// New peer connected
    PeerConnected(PeerId),
    /// Peer disconnected
    PeerDisconnected(PeerId),
    /// Message received from peer
    MessageReceived {
        peer_id: PeerId,
        message: P2PMessage,
    },
    /// Peer discovered through DHT
    PeerDiscovered {
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
    },
    /// Network error occurred
    NetworkError(String),
}

/// Commands sent to the NetworkActor
#[derive(Debug)]
pub enum NetworkCommand {
    BroadcastMessage {
        message: P2PMessage,
        topic: String,
        response: oneshot::Sender<Result<()>>,
    },
    SendMessage {
        peer_id: PeerId,
        message: P2PMessage,
        topic: String,
        response: oneshot::Sender<Result<()>>,
    },
    GetConnectedPeers {
        response: oneshot::Sender<Vec<PeerId>>,
    },
    GetPeerAddresses {
        peer_id: PeerId,
        response: oneshot::Sender<Option<Vec<Multiaddr>>>,
    },
    RegisterWorkerCapabilities {
        peer_id: PeerId,
        capabilities: WorkerCapabilities,
        response: oneshot::Sender<()>,
    },
}

/// Client to interact with the P2P network
#[derive(Clone)]
pub struct NetworkClient {
    command_sender: mpsc::Sender<NetworkCommand>,
    local_peer_id: PeerId,
    config: P2PConfig,
    // Shared state for direct read access (if needed for performance, otherwise better to use commands)
    // For now, we'll keep some state accessible via commands or shared locks if critical
    connected_peers: std::sync::Arc<RwLock<HashSet<PeerId>>>,
    worker_capabilities: std::sync::Arc<RwLock<HashMap<PeerId, WorkerCapabilities>>>,
}

impl NetworkClient {
    pub async fn broadcast_message(&self, message: P2PMessage, topic: &str) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.command_sender.send(NetworkCommand::BroadcastMessage {
            message,
            topic: topic.to_string(),
            response: tx,
        }).await.map_err(|e| anyhow!("Failed to send command to network actor: {}", e))?;
        rx.await.context("Failed to receive response from network actor")?
    }

    pub async fn send_message(&self, peer_id: PeerId, message: P2PMessage, topic: &str) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.command_sender.send(NetworkCommand::SendMessage {
            peer_id,
            message,
            topic: topic.to_string(),
            response: tx,
        }).await.map_err(|e| anyhow!("Failed to send command to network actor: {}", e))?;
        rx.await.context("Failed to receive response from network actor")?
    }

    pub async fn get_connected_peers(&self) -> Vec<PeerId> {
        // Can read directly from shared state for performance
        self.connected_peers.read().await.iter().cloned().collect()
    }

    pub async fn get_peer_addresses(&self, peer_id: PeerId) -> Result<Option<Vec<Multiaddr>>> {
        let (tx, rx) = oneshot::channel();
        self.command_sender.send(NetworkCommand::GetPeerAddresses {
            peer_id,
            response: tx,
        }).await.map_err(|e| anyhow!("Failed to send command to network actor: {}", e))?;
        Ok(rx.await.context("Failed to receive response from network actor")?)
    }

    pub async fn register_worker_capabilities(&self, peer_id: PeerId, capabilities: WorkerCapabilities) {
        // Update local shared state immediately
        self.worker_capabilities.write().await.insert(peer_id, capabilities.clone());
        
        // Also notify actor if needed (e.g. to store in DHT)
        let (tx, rx) = oneshot::channel();
        let _ = self.command_sender.send(NetworkCommand::RegisterWorkerCapabilities {
            peer_id,
            capabilities,
            response: tx,
        }).await;
        let _ = rx.await;
    }

    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    pub fn config(&self) -> &P2PConfig {
        &self.config
    }
}

/// Custom network behavior combining multiple protocols
#[derive(NetworkBehaviour)]
pub struct BitsageBehaviour {
    /// Gossip protocol for message broadcasting
    pub gossipsub: gossipsub::Behaviour,
    /// Kademlia DHT for peer discovery
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    /// Identify protocol for peer identification
    pub identify: identify::Behaviour,
    /// Ping protocol for connection health
    pub ping: ping::Behaviour,
    /// mDNS for local peer discovery
    pub mdns: mdns::tokio::Behaviour,
}

/// P2P network actor that owns the Swarm
pub struct NetworkActor {
    /// The libp2p swarm
    swarm: Swarm<BitsageBehaviour>,
    /// Local peer ID
    local_peer_id: PeerId,
    /// Network configuration
    config: P2PConfig,
    /// Command receiver
    command_receiver: mpsc::Receiver<NetworkCommand>,
    /// Event sender
    event_sender: mpsc::UnboundedSender<NetworkEvent>,
    /// Connected peers (shared with client)
    connected_peers: std::sync::Arc<RwLock<HashSet<PeerId>>>,
    /// Peer addresses
    peer_addresses: HashMap<PeerId, Vec<Multiaddr>>,
    /// Worker capabilities (shared with client)
    worker_capabilities: std::sync::Arc<RwLock<HashMap<PeerId, WorkerCapabilities>>>,
    /// Gossip topics
    gossip_topics: Vec<gossipsub::IdentTopic>,
}

impl NetworkActor {
    /// Create a new P2P network actor and client
    pub fn new(config: P2PConfig) -> Result<(NetworkClient, mpsc::UnboundedReceiver<NetworkEvent>)> {
        // Generate or load keypair
        let keypair = if let Some(keypair_bytes) = &config.keypair {
            Keypair::from_protobuf_encoding(keypair_bytes)
                .context("Failed to decode keypair")?
        } else {
            Keypair::generate_ed25519()
        };

        let local_peer_id = PeerId::from(keypair.public());
        info!("Local peer ID: {}", local_peer_id);

        // Create transport
        let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
            .upgrade(Version::V1)
            .authenticate(noise::Config::new(&keypair).context("Failed to create noise config")?)
            .multiplex(yamux::Config::default())
            .timeout(config.connection_timeout)
            .boxed();

        // Create network behavior
        let behaviour = Self::create_behaviour(&keypair, &config)?;

        // Create swarm
        let swarm = Swarm::new(transport, behaviour, local_peer_id, libp2p::swarm::Config::with_tokio_executor());

        // Create channels
        let (command_sender, command_receiver) = mpsc::channel(100);
        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        // Create shared state
        let connected_peers = std::sync::Arc::new(RwLock::new(HashSet::new()));
        let worker_capabilities = std::sync::Arc::new(RwLock::new(HashMap::new()));

        // Create gossip topics
        let gossip_topics = config.gossip_config.topics
            .iter()
            .map(|topic| gossipsub::IdentTopic::new(topic))
            .collect();

        let client = NetworkClient {
            command_sender,
            local_peer_id,
            config: config.clone(),
            connected_peers: connected_peers.clone(),
            worker_capabilities: worker_capabilities.clone(),
        };

        let actor = Self {
            swarm,
            local_peer_id,
            config,
            command_receiver,
            event_sender,
            connected_peers,
            peer_addresses: HashMap::new(),
            worker_capabilities,
            gossip_topics,
        };

        // Spawn actor loop
        tokio::spawn(actor.run());

        Ok((client, event_receiver))
    }

    /// Create the network behavior
    fn create_behaviour(keypair: &Keypair, config: &P2PConfig) -> Result<BitsageBehaviour> {
        // Create gossipsub behavior
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(config.gossip_config.heartbeat_interval)
            .validation_mode(gossipsub::ValidationMode::Strict)
            .build()
            .context("Failed to create gossipsub config")?;

        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(keypair.clone()),
            gossipsub_config,
        ).map_err(|e| anyhow!("Failed to create gossipsub behavior: {}", e))?;

        // Create Kademlia behavior
        let store = kad::store::MemoryStore::new(keypair.public().to_peer_id());
        let kademlia = kad::Behaviour::new(keypair.public().to_peer_id(), store);

        // Create identify behavior
        let identify = identify::Behaviour::new(
            identify::Config::new("/bitsage/1.0.0".to_string(), keypair.public())
                .with_agent_version("bitsage-node/0.1.0".to_string()),
        );

        // Create ping behavior
        let ping = ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(30)));

        // Create mDNS behavior
        let mdns = mdns::tokio::Behaviour::new(
            mdns::Config::default(),
            keypair.public().to_peer_id(),
        ).context("Failed to create mDNS behavior")?;

        Ok(BitsageBehaviour {
            gossipsub,
            kademlia,
            identify,
            ping,
            mdns,
        })
    }

    /// Run the actor loop
    pub async fn run(mut self) {
        info!("Starting P2P network actor...");

        // Start listening on configured addresses
        for addr in &self.config.listen_addresses {
            if let Err(e) = self.swarm.listen_on(addr.clone()) {
                error!("Failed to listen on address {}: {}", addr, e);
            } else {
                info!("Listening on: {}", addr);
            }
        }

        // Subscribe to gossip topics
        for topic in &self.gossip_topics {
            if let Err(e) = self.swarm.behaviour_mut().gossipsub.subscribe(topic) {
                error!("Failed to subscribe to gossip topic {}: {}", topic, e);
            } else {
                info!("Subscribed to gossip topic: {}", topic);
            }
        }

        // Add bootstrap peers to Kademlia
        for (peer_id, addr) in &self.config.bootstrap_peers {
            self.swarm.behaviour_mut().kademlia.add_address(peer_id, addr.clone());
            info!("Added bootstrap peer: {} at {}", peer_id, addr);
        }

        // Start Kademlia bootstrap
        if !self.config.bootstrap_peers.is_empty() {
            if let Err(e) = self.swarm.behaviour_mut().kademlia.bootstrap() {
                error!("Failed to start Kademlia bootstrap: {}", e);
            } else {
                info!("Started Kademlia bootstrap");
            }
        }

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await;
                }
                command = self.command_receiver.recv() => {
                    match command {
                        Some(cmd) => self.handle_command(cmd).await,
                        None => {
                            info!("Network command channel closed, stopping actor");
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Handle swarm events
    async fn handle_swarm_event(&mut self, event: SwarmEvent<BitsageBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Local node is listening on {}", address);
            }
            SwarmEvent::Behaviour(event) => {
                self.handle_behaviour_event(event).await;
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                info!("Connected to peer: {}", peer_id);
                self.connected_peers.write().await.insert(peer_id);
                self.send_event(NetworkEvent::PeerConnected(peer_id));
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                info!("Disconnected from peer: {}", peer_id);
                self.connected_peers.write().await.remove(&peer_id);
                self.send_event(NetworkEvent::PeerDisconnected(peer_id));
            }
            SwarmEvent::IncomingConnectionError { error, .. } => {
                warn!("Incoming connection error: {}", error);
            }
            SwarmEvent::OutgoingConnectionError { error, .. } => {
                warn!("Outgoing connection error: {}", error);
            }
            _ => {}
        }
    }

    /// Handle behavior-specific events
    async fn handle_behaviour_event(&mut self, event: <BitsageBehaviour as NetworkBehaviour>::ToSwarm) {
        match event {
            // Gossipsub events
            BitsageBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. }) => {
                self.handle_gossip_message(message).await;
            }
            BitsageBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic }) => {
                debug!("Peer {} subscribed to topic {}", peer_id, topic);
            }
            BitsageBehaviourEvent::Gossipsub(gossipsub::Event::Unsubscribed { peer_id, topic }) => {
                debug!("Peer {} unsubscribed from topic {}", peer_id, topic);
            }

            // Kademlia events
            BitsageBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed { result, .. }) => {
                self.handle_kademlia_query_result(result).await;
            }
            BitsageBehaviourEvent::Kademlia(kad::Event::RoutingUpdated { peer, .. }) => {
                debug!("Routing table updated with peer: {}", peer);
            }

            // Identify events
            BitsageBehaviourEvent::Identify(identify::Event::Received { peer_id, info }) => {
                debug!("Received identify info from {}: {:?}", peer_id, info);
                // Store peer addresses
                self.peer_addresses.insert(peer_id, info.listen_addrs);
            }

            // Ping events
            BitsageBehaviourEvent::Ping(ping::Event { peer, result, connection: _ }) => {
                match result {
                    Ok(rtt) => {
                        debug!("Ping to {} successful: {:?}", peer, rtt);
                    }
                    Err(failure) => {
                        warn!("Ping to {} failed: {:?}", peer, failure);
                    }
                }
            }

            // mDNS events
            BitsageBehaviourEvent::Mdns(mdns::Event::Discovered(list)) => {
                for (peer_id, addr) in list {
                    info!("Discovered peer {} at {}", peer_id, addr);
                    self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                    self.send_event(NetworkEvent::PeerDiscovered {
                        peer_id,
                        addresses: vec![addr],
                    });
                }
            }
            BitsageBehaviourEvent::Mdns(mdns::Event::Expired(list)) => {
                for (peer_id, addr) in list {
                    debug!("mDNS record expired for peer {} at {}", peer_id, addr);
                }
            }

            _ => {}
        }
    }

    /// Handle commands
    async fn handle_command(&mut self, command: NetworkCommand) {
        match command {
            NetworkCommand::BroadcastMessage { message, topic, response } => {
                let topic = gossipsub::IdentTopic::new(topic);
                let result = match bincode::serialize(&message) {
                    Ok(data) => {
                        self.swarm.behaviour_mut().gossipsub.publish(topic, data)
                            .map(|_| ())
                            .map_err(|e| anyhow!("Failed to publish message: {}", e))
                    }
                    Err(e) => Err(anyhow!("Failed to serialize message: {}", e)),
                };
                let _ = response.send(result);
            }
            NetworkCommand::SendMessage { peer_id: _, message, topic, response } => {
                 // For now, we'll use gossip for direct messages as in original code
                 // In production, this should use a direct messaging protocol
                 let topic = gossipsub::IdentTopic::new(topic);
                 let result = match bincode::serialize(&message) {
                     Ok(data) => {
                         self.swarm.behaviour_mut().gossipsub.publish(topic, data)
                             .map(|_| ())
                             .map_err(|e| anyhow!("Failed to publish message: {}", e))
                     }
                     Err(e) => Err(anyhow!("Failed to serialize message: {}", e)),
                 };
                 let _ = response.send(result);
            }
            NetworkCommand::GetConnectedPeers { response } => {
                let peers: Vec<PeerId> = self.connected_peers.read().await.iter().cloned().collect();
                let _ = response.send(peers);
            }
            NetworkCommand::GetPeerAddresses { peer_id, response } => {
                let addrs = self.peer_addresses.get(&peer_id).cloned();
                let _ = response.send(addrs);
            }
            NetworkCommand::RegisterWorkerCapabilities { peer_id, capabilities, response } => {
                self.worker_capabilities.write().await.insert(peer_id, capabilities);
                let _ = response.send(());
            }
        }
    }

    /// Handle gossip messages
    async fn handle_gossip_message(&mut self, message: gossipsub::Message) {
        if let Ok(p2p_message) = bincode::deserialize::<P2PMessage>(&message.data) {
            debug!("Received gossip message: {:?}", p2p_message);
            self.send_event(NetworkEvent::MessageReceived {
                peer_id: message.source.unwrap_or(PeerId::random()),
                message: p2p_message,
            });
        }
    }

    /// Handle Kademlia query results
    async fn handle_kademlia_query_result(&mut self, result: kad::QueryResult) {
        match result {
            kad::QueryResult::GetClosestPeers(Ok(kad::GetClosestPeersOk { peers, .. })) => {
                debug!("Found {} closest peers", peers.len());
                for peer in peers {
                    if let Some(addrs) = self.peer_addresses.get(&peer) {
                        self.send_event(NetworkEvent::PeerDiscovered {
                            peer_id: peer,
                            addresses: addrs.clone(),
                        });
                    }
                }
            }
            kad::QueryResult::GetClosestPeers(Err(kad::GetClosestPeersError::Timeout { .. })) => {
                warn!("Kademlia query timed out");
            }
            _ => {}
        }
    }

    /// Send event to event channel
    fn send_event(&self, event: NetworkEvent) {
        if let Err(e) = self.event_sender.send(event) {
            error!("Failed to send network event: {}", e);
        }
    }
}

impl Default for P2PConfig {
    fn default() -> Self {
        Self {
            keypair: None,
            listen_addresses: vec![
                "/ip4/0.0.0.0/tcp/4001".parse().unwrap(),
                "/ip6/::/tcp/4001".parse().unwrap(),
            ],
            bootstrap_peers: vec![],
            max_peers: 100,
            connection_timeout: Duration::from_secs(30),
            gossip_config: GossipConfig::default(),
            kad_config: KademliaConfig::default(),
            enable_mdns: true,
        }
    }
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            topics: vec![
                "sage-jobs".to_string(),
                "bitsage-nodes".to_string(),
                "sage-results".to_string(),
                "sage-reputation".to_string(),
            ],
            message_id_fn: "sha256".to_string(),
            duplicate_cache_time: 60,
            heartbeat_interval: Duration::from_secs(1),
        }
    }
}

impl Default for KademliaConfig {
    fn default() -> Self {
        Self {
            replication_factor: 20,
            query_timeout: Duration::from_secs(10),
            automatic_mode: true,
        }
    }
}

/// Trait for handling P2P network events
#[async_trait]
pub trait NetworkEventHandler {
    /// Handle network events
    async fn handle_network_event(&mut self, event: NetworkEvent) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};
    use starknet::core::types::FieldElement;

    #[tokio::test]
    async fn test_p2p_network_creation() {
        // Create a test P2P network with default configuration
        let config = P2PConfig::default();
        let result = NetworkActor::new(config);
        
        assert!(result.is_ok());
        let (client, _event_receiver) = result.unwrap();
        
        // Verify the network has the expected local peer ID
        assert!(!client.local_peer_id().to_string().is_empty());
        
        // Verify the configuration is stored correctly
        assert!(client.config().enable_mdns);
        assert_eq!(client.config().max_peers, 100);
    }
}
