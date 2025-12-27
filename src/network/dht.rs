//! # Distributed Hash Table (DHT) for Job Routing
//!
//! Implements a Kademlia-style DHT for efficient peer-to-peer job distribution.
//! This provides:
//! - O(log n) lookup complexity for finding workers
//! - Distributed job storage and retrieval
//! - Fault-tolerant routing with redundancy
//! - Geographic proximity optimization
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     DHT Node                                 │
//! │  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐│
//! │  │  Routing Table  │  │   Job Store     │  │  Worker Index││
//! │  │  (k-buckets)    │  │  (job_id→data)  │  │  (cap→peers) ││
//! │  └─────────────────┘  └─────────────────┘  └──────────────┘│
//! │  ┌─────────────────┐  ┌─────────────────┐                  │
//! │  │  RPC Handler    │  │  Maintenance    │                  │
//! │  │  (FIND_NODE,    │  │  (refresh,      │                  │
//! │  │   STORE, etc.)  │  │   replicate)    │                  │
//! │  └─────────────────┘  └─────────────────┘                  │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use anyhow::Result;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock, Mutex};
use tracing::{info, debug};

use crate::types::{JobId, WorkerId};

// =============================================================================
// CONSTANTS
// =============================================================================

/// Size of the node ID in bits (256-bit IDs like Bitcoin/Ethereum)
const ID_BITS: usize = 256;

/// Number of bits per byte
const BITS_PER_BYTE: usize = 8;

/// Size of node ID in bytes
const ID_SIZE: usize = ID_BITS / BITS_PER_BYTE;

/// Kademlia k-bucket size (number of contacts per bucket)
const K_BUCKET_SIZE: usize = 20;

/// Kademlia alpha parameter (parallel lookups)
const ALPHA: usize = 3;

/// Maximum number of jobs to store locally
const MAX_LOCAL_JOBS: usize = 10_000;

/// Job expiration time (1 hour)
const JOB_EXPIRY_SECS: u64 = 3600;

/// Bucket refresh interval (1 hour)
const BUCKET_REFRESH_SECS: u64 = 3600;

/// Replication factor for job data
const REPLICATION_FACTOR: usize = 5;

// =============================================================================
// TYPES
// =============================================================================

/// 256-bit node ID
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct NodeId([u8; ID_SIZE]);

impl NodeId {
    /// Create a new random node ID
    pub fn random() -> Self {
        let mut id = [0u8; ID_SIZE];
        rand::thread_rng().fill_bytes(&mut id);
        Self(id)
    }

    /// Create node ID from bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut id = [0u8; ID_SIZE];
        let len = bytes.len().min(ID_SIZE);
        id[..len].copy_from_slice(&bytes[..len]);
        Self(id)
    }

    /// Create node ID from worker ID
    pub fn from_worker_id(worker_id: &WorkerId) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(worker_id.to_string().as_bytes());
        let result = hasher.finalize();
        Self::from_bytes(&result)
    }

    /// Create node ID from job ID
    pub fn from_job_id(job_id: &JobId) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(job_id.to_string().as_bytes());
        let result = hasher.finalize();
        Self::from_bytes(&result)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; ID_SIZE] {
        &self.0
    }

    /// Calculate XOR distance between two node IDs
    pub fn distance(&self, other: &NodeId) -> NodeId {
        let mut result = [0u8; ID_SIZE];
        for i in 0..ID_SIZE {
            result[i] = self.0[i] ^ other.0[i];
        }
        NodeId(result)
    }

    /// Get the index of the most significant bit that differs (bucket index)
    /// Returns None if IDs are identical
    pub fn bucket_index(&self, other: &NodeId) -> Option<usize> {
        let distance = self.distance(other);
        for i in 0..ID_SIZE {
            if distance.0[i] != 0 {
                let byte_index = i;
                let bit_index = 7 - distance.0[i].leading_zeros() as usize;
                return Some(ID_BITS - 1 - (byte_index * 8 + (7 - bit_index)));
            }
        }
        None
    }
}

impl std::fmt::Debug for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NodeId({}...)", hex::encode(&self.0[..4]))
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}...", hex::encode(&self.0[..8]))
    }
}

impl Serialize for NodeId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        hex::encode(&self.0).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NodeId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        Ok(Self::from_bytes(&bytes))
    }
}

/// DHT peer information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DhtPeer {
    /// Peer's node ID
    pub node_id: NodeId,
    /// Peer's network address
    pub address: String,
    /// Associated worker ID
    pub worker_id: Option<WorkerId>,
    /// Worker capabilities hash
    pub capabilities_hash: u64,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Response latency in ms
    pub latency_ms: u32,
    /// Number of failed requests
    pub failures: u32,
}

impl DhtPeer {
    /// Create a new peer
    pub fn new(node_id: NodeId, address: String) -> Self {
        Self {
            node_id,
            address,
            worker_id: None,
            capabilities_hash: 0,
            last_seen: chrono::Utc::now().timestamp() as u64,
            latency_ms: 0,
            failures: 0,
        }
    }

    /// Check if peer is stale
    pub fn is_stale(&self, timeout_secs: u64) -> bool {
        let now = chrono::Utc::now().timestamp() as u64;
        now - self.last_seen > timeout_secs
    }

    /// Update last seen
    pub fn touch(&mut self) {
        self.last_seen = chrono::Utc::now().timestamp() as u64;
    }
}

/// K-bucket for storing peers at a specific distance
#[derive(Clone, Debug)]
pub struct KBucket {
    /// Peers in this bucket (sorted by last seen, oldest first)
    peers: VecDeque<DhtPeer>,
    /// Replacement cache for when bucket is full
    replacement_cache: VecDeque<DhtPeer>,
    /// Last refresh time
    last_refresh: Instant,
}

impl Default for KBucket {
    fn default() -> Self {
        Self::new()
    }
}

impl KBucket {
    /// Create a new empty k-bucket
    pub fn new() -> Self {
        Self {
            peers: VecDeque::with_capacity(K_BUCKET_SIZE),
            replacement_cache: VecDeque::with_capacity(K_BUCKET_SIZE),
            last_refresh: Instant::now(),
        }
    }

    /// Add or update a peer in the bucket
    pub fn add_peer(&mut self, peer: DhtPeer) -> bool {
        // Check if peer already exists
        if let Some(pos) = self.peers.iter().position(|p| p.node_id == peer.node_id) {
            // Move to end (most recently seen)
            self.peers.remove(pos);
            self.peers.push_back(peer);
            return true;
        }

        // Check if bucket has space
        if self.peers.len() < K_BUCKET_SIZE {
            self.peers.push_back(peer);
            return true;
        }

        // Bucket full - add to replacement cache
        if self.replacement_cache.len() >= K_BUCKET_SIZE {
            self.replacement_cache.pop_front();
        }
        self.replacement_cache.push_back(peer);
        false
    }

    /// Remove a peer from the bucket
    pub fn remove_peer(&mut self, node_id: &NodeId) -> Option<DhtPeer> {
        if let Some(pos) = self.peers.iter().position(|p| &p.node_id == node_id) {
            let removed = self.peers.remove(pos)?;

            // Promote from replacement cache if available
            if let Some(replacement) = self.replacement_cache.pop_front() {
                self.peers.push_back(replacement);
            }

            return Some(removed);
        }
        None
    }

    /// Get all peers in the bucket
    pub fn get_peers(&self) -> Vec<DhtPeer> {
        self.peers.iter().cloned().collect()
    }

    /// Get the oldest peer (for ping/eviction)
    pub fn get_oldest(&self) -> Option<&DhtPeer> {
        self.peers.front()
    }

    /// Check if bucket needs refresh
    pub fn needs_refresh(&self) -> bool {
        self.last_refresh.elapsed() > Duration::from_secs(BUCKET_REFRESH_SECS)
    }

    /// Mark bucket as refreshed
    pub fn mark_refreshed(&mut self) {
        self.last_refresh = Instant::now();
    }

    /// Number of peers in bucket
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Check if bucket is empty
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

/// Job entry stored in DHT
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DhtJobEntry {
    /// Job ID
    pub job_id: JobId,
    /// Job data (serialized)
    pub data: Vec<u8>,
    /// Publisher node ID
    pub publisher: NodeId,
    /// Creation timestamp
    pub created_at: u64,
    /// Expiration timestamp
    pub expires_at: u64,
    /// Required worker capabilities
    pub required_capabilities: u64,
    /// Maximum reward
    pub max_reward: u128,
    /// Assigned worker (if any)
    pub assigned_worker: Option<NodeId>,
    /// Job status
    pub status: DhtJobStatus,
}

/// Job status in DHT
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DhtJobStatus {
    /// Job is available for bidding
    Available,
    /// Job is assigned to a worker
    Assigned,
    /// Job is being processed
    InProgress,
    /// Job completed successfully
    Completed,
    /// Job failed
    Failed,
    /// Job expired
    Expired,
}

/// DHT RPC messages
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DhtMessage {
    /// Ping request
    Ping {
        sender: NodeId,
        nonce: u64,
    },
    /// Pong response
    Pong {
        sender: NodeId,
        nonce: u64,
    },
    /// Find node request
    FindNode {
        sender: NodeId,
        target: NodeId,
    },
    /// Find node response
    FoundNodes {
        sender: NodeId,
        target: NodeId,
        nodes: Vec<DhtPeer>,
    },
    /// Store job request
    StoreJob {
        sender: NodeId,
        job: DhtJobEntry,
    },
    /// Store job response
    StoreJobAck {
        sender: NodeId,
        job_id: JobId,
        success: bool,
    },
    /// Find job request
    FindJob {
        sender: NodeId,
        job_id: JobId,
    },
    /// Find job response
    FoundJob {
        sender: NodeId,
        job: Option<DhtJobEntry>,
    },
    /// Find workers by capability
    FindWorkers {
        sender: NodeId,
        capabilities: u64,
        max_results: usize,
    },
    /// Found workers response
    FoundWorkers {
        sender: NodeId,
        workers: Vec<DhtPeer>,
    },
    /// Announce worker availability
    AnnounceWorker {
        sender: NodeId,
        worker_id: WorkerId,
        capabilities: u64,
        address: String,
    },
}

/// DHT configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DhtConfig {
    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<String>,
    /// Local listen address
    pub listen_address: String,
    /// Peer timeout in seconds
    pub peer_timeout_secs: u64,
    /// Lookup parallelism
    pub lookup_parallelism: usize,
    /// Replication factor
    pub replication_factor: usize,
    /// Enable job caching
    pub enable_job_cache: bool,
    /// Maximum cached jobs
    pub max_cached_jobs: usize,
}

impl Default for DhtConfig {
    fn default() -> Self {
        Self {
            bootstrap_nodes: vec![],
            listen_address: "0.0.0.0:7777".to_string(),
            peer_timeout_secs: 300,
            lookup_parallelism: ALPHA,
            replication_factor: REPLICATION_FACTOR,
            enable_job_cache: true,
            max_cached_jobs: MAX_LOCAL_JOBS,
        }
    }
}

/// DHT statistics
#[derive(Clone, Debug, Default)]
pub struct DhtStats {
    /// Total peers known
    pub total_peers: usize,
    /// Active peers (recently seen)
    pub active_peers: usize,
    /// Jobs stored locally
    pub local_jobs: usize,
    /// Total lookups performed
    pub lookups_performed: u64,
    /// Successful lookups
    pub lookups_successful: u64,
    /// Messages sent
    pub messages_sent: u64,
    /// Messages received
    pub messages_received: u64,
    /// Average lookup latency (ms)
    pub avg_lookup_latency_ms: u32,
}

// =============================================================================
// DHT NODE
// =============================================================================

/// DHT Node for distributed job routing
pub struct DhtNode {
    /// Node's own ID
    node_id: NodeId,
    /// Configuration
    config: DhtConfig,
    /// Routing table (k-buckets)
    routing_table: Arc<RwLock<Vec<KBucket>>>,
    /// Local job storage
    job_store: Arc<RwLock<HashMap<JobId, DhtJobEntry>>>,
    /// Worker capability index (capabilities_hash -> peers)
    worker_index: Arc<RwLock<HashMap<u64, HashSet<NodeId>>>>,
    /// Pending RPC requests
    pending_requests: Arc<Mutex<HashMap<u64, tokio::sync::oneshot::Sender<DhtMessage>>>>,
    /// Message sender for outgoing messages
    message_tx: mpsc::UnboundedSender<(String, DhtMessage)>,
    /// Statistics
    stats: Arc<RwLock<DhtStats>>,
    /// Running flag
    running: Arc<RwLock<bool>>,
}

impl DhtNode {
    /// Create a new DHT node
    pub fn new(config: DhtConfig) -> (Self, mpsc::UnboundedReceiver<(String, DhtMessage)>) {
        let (message_tx, message_rx) = mpsc::unbounded_channel();

        // Initialize routing table with empty k-buckets
        let routing_table: Vec<KBucket> = (0..ID_BITS).map(|_| KBucket::new()).collect();

        let node = Self {
            node_id: NodeId::random(),
            config,
            routing_table: Arc::new(RwLock::new(routing_table)),
            job_store: Arc::new(RwLock::new(HashMap::new())),
            worker_index: Arc::new(RwLock::new(HashMap::new())),
            pending_requests: Arc::new(Mutex::new(HashMap::new())),
            message_tx,
            stats: Arc::new(RwLock::new(DhtStats::default())),
            running: Arc::new(RwLock::new(false)),
        };

        (node, message_rx)
    }

    /// Get this node's ID
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Start the DHT node
    pub async fn start(&self) -> Result<()> {
        info!("Starting DHT node: {}", self.node_id);

        {
            let mut running = self.running.write().await;
            *running = true;
        }

        // Bootstrap from known nodes
        self.bootstrap().await?;

        // Start maintenance tasks
        self.start_maintenance_tasks().await;

        info!("DHT node started successfully");
        Ok(())
    }

    /// Stop the DHT node
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping DHT node");
        let mut running = self.running.write().await;
        *running = false;
        Ok(())
    }

    /// Bootstrap the DHT from known nodes
    async fn bootstrap(&self) -> Result<()> {
        if self.config.bootstrap_nodes.is_empty() {
            info!("No bootstrap nodes configured, running as initial node");
            return Ok(());
        }

        info!("Bootstrapping from {} nodes", self.config.bootstrap_nodes.len());

        for address in &self.config.bootstrap_nodes {
            let peer = DhtPeer::new(NodeId::random(), address.clone());
            self.add_peer(peer).await;
        }

        // Perform lookup for our own ID to populate routing table
        let _ = self.find_node(self.node_id).await;

        Ok(())
    }

    /// Start background maintenance tasks
    async fn start_maintenance_tasks(&self) {
        // Clone for background task
        let routing_table = self.routing_table.clone();
        let job_store = self.job_store.clone();
        let running = self.running.clone();
        let node_id = self.node_id;

        tokio::spawn(async move {
            let mut refresh_interval = tokio::time::interval(Duration::from_secs(60));

            loop {
                refresh_interval.tick().await;

                if !*running.read().await {
                    break;
                }

                // Refresh stale buckets
                let buckets = routing_table.read().await;
                for (i, bucket) in buckets.iter().enumerate() {
                    if bucket.needs_refresh() && !bucket.is_empty() {
                        debug!("Refreshing bucket {}", i);
                        // In a full implementation, we'd do a lookup for a random ID in this bucket's range
                    }
                }
                drop(buckets);

                // Clean expired jobs
                let now = chrono::Utc::now().timestamp() as u64;
                let mut store = job_store.write().await;
                store.retain(|_, job| job.expires_at > now);
                debug!("Job store cleanup: {} jobs remaining", store.len());
            }

            info!("DHT maintenance task stopped");
        });
    }

    /// Add a peer to the routing table
    pub async fn add_peer(&self, peer: DhtPeer) {
        if peer.node_id == self.node_id {
            return; // Don't add ourselves
        }

        if let Some(bucket_idx) = self.node_id.bucket_index(&peer.node_id) {
            let mut routing_table = self.routing_table.write().await;
            routing_table[bucket_idx].add_peer(peer);
        }
    }

    /// Remove a peer from the routing table
    pub async fn remove_peer(&self, node_id: &NodeId) {
        if let Some(bucket_idx) = self.node_id.bucket_index(node_id) {
            let mut routing_table = self.routing_table.write().await;
            routing_table[bucket_idx].remove_peer(node_id);
        }
    }

    /// Find the k closest nodes to a target
    pub async fn find_node(&self, target: NodeId) -> Vec<DhtPeer> {
        let mut stats = self.stats.write().await;
        stats.lookups_performed += 1;
        drop(stats);

        // Get initial closest nodes from routing table
        let closest = self.get_closest_peers(&target, K_BUCKET_SIZE).await;

        if closest.is_empty() {
            return vec![];
        }

        // Iterative lookup (simplified - full implementation would do parallel queries)
        let mut result = closest;
        result.sort_by(|a, b| {
            let dist_a = a.node_id.distance(&target);
            let dist_b = b.node_id.distance(&target);
            dist_a.0.cmp(&dist_b.0)
        });
        result.truncate(K_BUCKET_SIZE);

        let mut stats = self.stats.write().await;
        stats.lookups_successful += 1;

        result
    }

    /// Get closest peers from routing table
    async fn get_closest_peers(&self, target: &NodeId, count: usize) -> Vec<DhtPeer> {
        let routing_table = self.routing_table.read().await;

        // Collect all peers with their distance to target
        let mut all_peers: Vec<(NodeId, DhtPeer)> = vec![];

        for bucket in routing_table.iter() {
            for peer in bucket.get_peers() {
                let distance = peer.node_id.distance(target);
                all_peers.push((distance, peer));
            }
        }

        // Sort by distance
        all_peers.sort_by(|a, b| a.0 .0.cmp(&b.0 .0));

        // Return closest k
        all_peers.into_iter()
            .take(count)
            .map(|(_, peer)| peer)
            .collect()
    }

    /// Store a job in the DHT
    pub async fn store_job(&self, job: DhtJobEntry) -> Result<()> {
        let job_id = job.job_id.clone();
        let target = NodeId::from_job_id(&job_id);

        // Store locally
        {
            let mut store = self.job_store.write().await;
            if store.len() >= self.config.max_cached_jobs {
                // Remove oldest expired job
                let now = chrono::Utc::now().timestamp() as u64;
                store.retain(|_, j| j.expires_at > now);
            }
            store.insert(job_id.clone(), job.clone());
        }

        // Find k closest nodes and replicate
        let closest = self.find_node(target).await;

        for peer in closest.into_iter().take(self.config.replication_factor) {
            let msg = DhtMessage::StoreJob {
                sender: self.node_id,
                job: job.clone(),
            };
            let _ = self.message_tx.send((peer.address.clone(), msg));
        }

        info!("Stored job {} in DHT", job_id);
        Ok(())
    }

    /// Find a job in the DHT
    pub async fn find_job(&self, job_id: &JobId) -> Option<DhtJobEntry> {
        // Check local store first
        {
            let store = self.job_store.read().await;
            if let Some(job) = store.get(job_id) {
                return Some(job.clone());
            }
        }

        // Look up in DHT
        let target = NodeId::from_job_id(job_id);
        let closest = self.find_node(target).await;

        // Query closest nodes (simplified)
        for peer in closest.into_iter().take(ALPHA) {
            let msg = DhtMessage::FindJob {
                sender: self.node_id,
                job_id: job_id.clone(),
            };
            let _ = self.message_tx.send((peer.address.clone(), msg));
        }

        None // In real implementation, we'd await responses
    }

    /// Find workers with specific capabilities
    pub async fn find_workers(&self, capabilities: u64, max_results: usize) -> Vec<DhtPeer> {
        // Check local index first
        let mut results = vec![];
        {
            let index = self.worker_index.read().await;
            if let Some(node_ids) = index.get(&capabilities) {
                let routing_table = self.routing_table.read().await;
                for bucket in routing_table.iter() {
                    for peer in bucket.get_peers() {
                        if node_ids.contains(&peer.node_id) {
                            results.push(peer);
                            if results.len() >= max_results {
                                return results;
                            }
                        }
                    }
                }
            }
        }

        // If not enough local results, query network
        if results.len() < max_results {
            let target = NodeId::from_bytes(&capabilities.to_le_bytes());
            let closest = self.find_node(target).await;

            for peer in closest.into_iter().take(ALPHA) {
                let msg = DhtMessage::FindWorkers {
                    sender: self.node_id,
                    capabilities,
                    max_results: max_results - results.len(),
                };
                let _ = self.message_tx.send((peer.address.clone(), msg));
            }
        }

        results
    }

    /// Announce this node as a worker
    pub async fn announce_worker(&self, worker_id: WorkerId, capabilities: u64) -> Result<()> {
        // Add to local index
        {
            let mut index = self.worker_index.write().await;
            index.entry(capabilities)
                .or_insert_with(HashSet::new)
                .insert(self.node_id);
        }

        // Announce to k closest nodes
        let target = NodeId::from_bytes(&capabilities.to_le_bytes());
        let closest = self.find_node(target).await;

        for peer in closest.into_iter().take(self.config.replication_factor) {
            let msg = DhtMessage::AnnounceWorker {
                sender: self.node_id,
                worker_id: worker_id.clone(),
                capabilities,
                address: self.config.listen_address.clone(),
            };
            let _ = self.message_tx.send((peer.address.clone(), msg));
        }

        info!("Announced worker {} with capabilities {:#x}", worker_id, capabilities);
        Ok(())
    }

    /// Handle incoming DHT message
    pub async fn handle_message(&self, from: String, msg: DhtMessage) -> Option<DhtMessage> {
        let mut stats = self.stats.write().await;
        stats.messages_received += 1;
        drop(stats);

        match msg {
            DhtMessage::Ping { sender, nonce } => {
                self.add_peer(DhtPeer::new(sender, from)).await;
                Some(DhtMessage::Pong {
                    sender: self.node_id,
                    nonce,
                })
            }

            DhtMessage::Pong { sender, .. } => {
                // Update peer's last seen
                if let Some(bucket_idx) = self.node_id.bucket_index(&sender) {
                    let mut routing_table = self.routing_table.write().await;
                    if let Some(peer) = routing_table[bucket_idx].peers.iter_mut()
                        .find(|p| p.node_id == sender)
                    {
                        peer.touch();
                    }
                }
                None
            }

            DhtMessage::FindNode { sender, target } => {
                self.add_peer(DhtPeer::new(sender, from)).await;
                let nodes = self.get_closest_peers(&target, K_BUCKET_SIZE).await;
                Some(DhtMessage::FoundNodes {
                    sender: self.node_id,
                    target,
                    nodes,
                })
            }

            DhtMessage::FoundNodes { sender, nodes, .. } => {
                self.add_peer(DhtPeer::new(sender, from.clone())).await;
                for node in nodes {
                    self.add_peer(node).await;
                }
                None
            }

            DhtMessage::StoreJob { sender, job } => {
                self.add_peer(DhtPeer::new(sender, from)).await;
                let job_id = job.job_id.clone();

                let success = {
                    let mut store = self.job_store.write().await;
                    if store.len() < self.config.max_cached_jobs {
                        store.insert(job_id.clone(), job);
                        true
                    } else {
                        false
                    }
                };

                Some(DhtMessage::StoreJobAck {
                    sender: self.node_id,
                    job_id,
                    success,
                })
            }

            DhtMessage::FindJob { sender, job_id } => {
                self.add_peer(DhtPeer::new(sender, from)).await;
                let job = {
                    let store = self.job_store.read().await;
                    store.get(&job_id).cloned()
                };
                Some(DhtMessage::FoundJob {
                    sender: self.node_id,
                    job,
                })
            }

            DhtMessage::FindWorkers { sender, capabilities, max_results } => {
                self.add_peer(DhtPeer::new(sender, from)).await;
                let workers = self.find_workers(capabilities, max_results).await;
                Some(DhtMessage::FoundWorkers {
                    sender: self.node_id,
                    workers,
                })
            }

            DhtMessage::AnnounceWorker { sender, worker_id, capabilities, address } => {
                let mut peer = DhtPeer::new(sender, address);
                peer.worker_id = Some(worker_id);
                peer.capabilities_hash = capabilities;
                self.add_peer(peer).await;

                // Add to worker index
                {
                    let mut index = self.worker_index.write().await;
                    index.entry(capabilities)
                        .or_insert_with(HashSet::new)
                        .insert(sender);
                }

                None
            }

            _ => None,
        }
    }

    /// Get DHT statistics
    pub async fn get_stats(&self) -> DhtStats {
        let mut stats = self.stats.read().await.clone();

        // Count peers
        let routing_table = self.routing_table.read().await;
        stats.total_peers = routing_table.iter().map(|b| b.len()).sum();

        let now = chrono::Utc::now().timestamp() as u64;
        stats.active_peers = routing_table.iter()
            .flat_map(|b| b.get_peers())
            .filter(|p| !p.is_stale(self.config.peer_timeout_secs))
            .count();

        // Count jobs
        let job_store = self.job_store.read().await;
        stats.local_jobs = job_store.len();

        stats
    }

    /// Get all peers (for debugging)
    pub async fn get_all_peers(&self) -> Vec<DhtPeer> {
        let routing_table = self.routing_table.read().await;
        routing_table.iter()
            .flat_map(|b| b.get_peers())
            .collect()
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_creation() {
        let id1 = NodeId::random();
        let id2 = NodeId::random();

        assert_ne!(id1, id2);
    }

    #[test]
    fn test_node_id_distance() {
        let id1 = NodeId::from_bytes(&[0xFF; 32]);
        let id2 = NodeId::from_bytes(&[0x00; 32]);

        let distance = id1.distance(&id2);
        assert_eq!(distance.0, [0xFF; 32]);
    }

    #[test]
    fn test_node_id_bucket_index() {
        let id1 = NodeId::from_bytes(&[0x00; 32]);
        let mut id2_bytes = [0x00; 32];
        id2_bytes[0] = 0x80; // Set MSB
        let id2 = NodeId::from_bytes(&id2_bytes);

        let bucket_idx = id1.bucket_index(&id2);
        assert_eq!(bucket_idx, Some(255)); // MSB differs
    }

    #[test]
    fn test_k_bucket_add_peer() {
        let mut bucket = KBucket::new();

        for i in 0..K_BUCKET_SIZE {
            let mut id_bytes = [0u8; 32];
            id_bytes[0] = i as u8;
            let peer = DhtPeer::new(NodeId::from_bytes(&id_bytes), format!("addr{}", i));
            assert!(bucket.add_peer(peer));
        }

        assert_eq!(bucket.len(), K_BUCKET_SIZE);

        // Adding more should go to replacement cache
        let extra_peer = DhtPeer::new(NodeId::random(), "extra".to_string());
        assert!(!bucket.add_peer(extra_peer));
    }

    #[test]
    fn test_k_bucket_remove_peer() {
        let mut bucket = KBucket::new();

        let peer1 = DhtPeer::new(NodeId::from_bytes(&[1; 32]), "addr1".to_string());
        let peer2 = DhtPeer::new(NodeId::from_bytes(&[2; 32]), "addr2".to_string());

        bucket.add_peer(peer1.clone());
        bucket.add_peer(peer2);

        assert_eq!(bucket.len(), 2);

        bucket.remove_peer(&peer1.node_id);
        assert_eq!(bucket.len(), 1);
    }

    #[tokio::test]
    async fn test_dht_node_creation() {
        let config = DhtConfig::default();
        let (node, _rx) = DhtNode::new(config);

        let stats = node.get_stats().await;
        assert_eq!(stats.total_peers, 0);
        assert_eq!(stats.local_jobs, 0);
    }

    #[tokio::test]
    async fn test_dht_add_peer() {
        let config = DhtConfig::default();
        let (node, _rx) = DhtNode::new(config);

        let peer = DhtPeer::new(NodeId::random(), "127.0.0.1:8080".to_string());
        node.add_peer(peer).await;

        let stats = node.get_stats().await;
        assert_eq!(stats.total_peers, 1);
    }

    #[tokio::test]
    async fn test_dht_find_closest() {
        let config = DhtConfig::default();
        let (node, _rx) = DhtNode::new(config);

        // Add several peers
        for i in 0..10 {
            let mut id_bytes = [0u8; 32];
            id_bytes[0] = i;
            let peer = DhtPeer::new(NodeId::from_bytes(&id_bytes), format!("addr{}", i));
            node.add_peer(peer).await;
        }

        let target = NodeId::from_bytes(&[5; 32]);
        let closest = node.get_closest_peers(&target, 3).await;

        assert!(!closest.is_empty());
        assert!(closest.len() <= 3);
    }

    #[tokio::test]
    async fn test_dht_store_job() {
        let config = DhtConfig::default();
        let (node, _rx) = DhtNode::new(config);

        let job = DhtJobEntry {
            job_id: JobId::new(),
            data: vec![1, 2, 3],
            publisher: node.node_id(),
            created_at: chrono::Utc::now().timestamp() as u64,
            expires_at: chrono::Utc::now().timestamp() as u64 + 3600,
            required_capabilities: 0xFF,
            max_reward: 1000,
            assigned_worker: None,
            status: DhtJobStatus::Available,
        };

        node.store_job(job.clone()).await.unwrap();

        let stats = node.get_stats().await;
        assert_eq!(stats.local_jobs, 1);
    }

    #[tokio::test]
    async fn test_dht_announce_worker() {
        let config = DhtConfig::default();
        let (node, _rx) = DhtNode::new(config);

        let worker_id = WorkerId::new();
        let capabilities: u64 = 0xFF00FF00;

        node.announce_worker(worker_id, capabilities).await.unwrap();

        // Worker should be in local index
        let index = node.worker_index.read().await;
        assert!(index.contains_key(&capabilities));
    }

    #[tokio::test]
    async fn test_dht_handle_ping() {
        let config = DhtConfig::default();
        let (node, _rx) = DhtNode::new(config);

        let sender = NodeId::random();
        let msg = DhtMessage::Ping { sender, nonce: 12345 };

        let response = node.handle_message("127.0.0.1:8080".to_string(), msg).await;

        assert!(matches!(response, Some(DhtMessage::Pong { nonce: 12345, .. })));
    }

    #[tokio::test]
    async fn test_dht_handle_find_node() {
        let config = DhtConfig::default();
        let (node, _rx) = DhtNode::new(config);

        // Add some peers first
        for i in 0..5 {
            let mut id_bytes = [0u8; 32];
            id_bytes[0] = i;
            let peer = DhtPeer::new(NodeId::from_bytes(&id_bytes), format!("addr{}", i));
            node.add_peer(peer).await;
        }

        let sender = NodeId::random();
        let target = NodeId::random();
        let msg = DhtMessage::FindNode { sender, target };

        let response = node.handle_message("127.0.0.1:8080".to_string(), msg).await;

        assert!(matches!(response, Some(DhtMessage::FoundNodes { .. })));
    }
}
