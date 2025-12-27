//! # Enhanced Coordinator System
//!
//! Comprehensive coordinator system that integrates Kafka, network coordination,
//! blockchain integration, and production-ready features for the Bitsage Network.

pub mod kafka;
pub mod network_coordinator;
pub mod job_processor;
pub mod worker_manager;
pub mod blockchain_integration;
pub mod metrics;
pub mod config;
pub mod simple_coordinator;
pub mod production_coordinator;
pub mod blockchain_bridge;

use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;
use tracing::{info, warn, error, debug};

use crate::blockchain::{client::StarknetClient, contracts::JobManagerContract};
use crate::coordinator::{
    kafka::KafkaCoordinator,
    network_coordinator::{NetworkCoordinatorService, NetworkCoordinatorStats},
    job_processor::JobProcessor,
    worker_manager::WorkerManager,
    blockchain_integration::BlockchainIntegration,
    metrics::MetricsCollector,
    config::CoordinatorConfig,
};
use crate::network::NetworkEvent;
use crate::network::NetworkCoordinator;
use crate::storage::Database;
use crate::types::NodeId;

// Re-export main components
pub use kafka::{KafkaConfig, KafkaEvent};
pub use config::{NetworkCoordinatorConfig, JobProcessorConfig, WorkerManagerConfig, BlockchainConfig, MetricsConfig};

/// Main coordinator service that orchestrates all components
pub struct EnhancedCoordinator {
    config: CoordinatorConfig,
    
    // Core components
    kafka_coordinator: Arc<KafkaCoordinator>,
    network_coordinator: Arc<NetworkCoordinator>,
    job_processor: Arc<JobProcessor>,
    worker_manager: Arc<WorkerManager>,
    blockchain_integration: Arc<BlockchainIntegration>,
    metrics_collector: Arc<MetricsCollector>,
    
    // Shared state
    database: Arc<Database>,
    starknet_client: Arc<StarknetClient>,
    job_manager_contract: Arc<JobManagerContract>,
    
    // Internal state
    running: Arc<RwLock<bool>>,
    node_id: NodeId,
}

impl EnhancedCoordinator {
    /// Create a new enhanced coordinator
    pub async fn new(config: CoordinatorConfig) -> Result<Self> {
        info!("Initializing Enhanced Coordinator...");
        
        // Initialize database
        let database = Arc::new(Database::new(&config.database_url).await?);
        database.initialize().await?;
        
        // Initialize blockchain components
        let starknet_client = Arc::new(StarknetClient::new(config.blockchain.rpc_url.clone())?);
        starknet_client.connect().await?;
        
        let job_manager_contract = Arc::new(JobManagerContract::new_from_address(
            starknet_client.clone(),
            &config.blockchain.job_manager_address,
        )?);
        
        // Initialize Kafka coordinator
        let kafka_coordinator = Arc::new(KafkaCoordinator::new(config.kafka.clone()));
        
        // Create a NetworkCoordinator for WorkerManager
        let network_config = crate::network::NetworkConfig {
            p2p: config.network.p2p.clone(),
            job_distribution: config.network.job_distribution.clone(),
            health_reputation: config.network.health_reputation.clone(),
            result_collection: config.network.result_collection.clone(),
            discovery: config.network.discovery.clone(),
            gossip: config.network.gossip.clone(),
        };
        let network_coordinator = NetworkCoordinator::new(
            network_config,
            starknet_client.clone(),
            job_manager_contract.clone(),
        )?;
        let network_coordinator = Arc::new(network_coordinator);

        // Initialize network coordinator
        let network_coordinator_service = NetworkCoordinatorService::new(
            config.network.clone(),
            starknet_client.clone(),
            job_manager_contract.clone(),
        )?;
        let _network_coordinator_service = Arc::new(network_coordinator_service);
        
        // Initialize worker manager
        let worker_manager = Arc::new(WorkerManager::new(
            config.worker_manager.clone(),
            database.clone(),
            network_coordinator.clone(),
        ));
        
        // Initialize blockchain integration
        let blockchain_integration = Arc::new(BlockchainIntegration::new(
            config.blockchain.clone(),
            starknet_client.clone(),
            job_manager_contract.clone(),
        ));
        
        // Initialize job processor
        let job_processor = Arc::new(JobProcessor::new(
            config.job_processor.clone(),
            database.clone(),
            job_manager_contract.clone(),
        ));
        
        // Initialize metrics collector
        let metrics_collector = Arc::new(MetricsCollector::new(config.metrics.clone()));
        
        let node_id = NodeId::new();
        
        Ok(Self {
            config,
            kafka_coordinator,
            network_coordinator,
            job_processor,
            worker_manager,
            blockchain_integration,
            metrics_collector,
            database,
            starknet_client,
            job_manager_contract,
            running: Arc::new(RwLock::new(false)),
            node_id,
        })
    }

    /// Start the enhanced coordinator
    pub async fn start(&self) -> Result<()> {
        info!("Starting Enhanced Coordinator (Node ID: {})", self.node_id);
        
        {
            let mut running = self.running.write().await;
            if *running {
                return Err(anyhow::anyhow!("Coordinator already running"));
            }
            *running = true;
        }

        // Start all components
        self.start_components().await?;
        
        // Start event processing
        self.start_event_processing().await?;
        
        // Start health monitoring
        self.start_health_monitoring().await?;
        
        // Start metrics collection
        self.start_metrics_collection().await?;

        info!("Enhanced Coordinator started successfully");
        Ok(())
    }

    /// Stop the enhanced coordinator
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping Enhanced Coordinator...");
        
        {
            let mut running = self.running.write().await;
            *running = false;
        }

        // Stop all components gracefully
        self.stop_components().await?;

        info!("Enhanced Coordinator stopped");
        Ok(())
    }

    /// Start all coordinator components
    async fn start_components(&self) -> Result<()> {
        // Start Kafka coordinator
        self.kafka_coordinator.start().await?;
        
        // Start network coordinator
        self.network_coordinator.start().await?;
        
        // Start job processor
        self.job_processor.start().await?;
        
        // Start worker manager
        self.worker_manager.start().await?;
        
        // Start blockchain integration
        self.blockchain_integration.start().await?;
        
        // Start metrics collector
        self.metrics_collector.start().await?;

        Ok(())
    }

    /// Stop all coordinator components
    async fn stop_components(&self) -> Result<()> {
        // Stop components in reverse order
        self.metrics_collector.stop().await?;
        self.blockchain_integration.stop().await?;
        self.worker_manager.stop().await?;
        self.job_processor.stop().await?;
        self.network_coordinator.stop().await?;
        self.kafka_coordinator.stop().await?;

        Ok(())
    }

    /// Start event processing loop
    async fn start_event_processing(&self) -> Result<()> {
        // Take event receivers - these can only be taken once
        let mut kafka_events = self.kafka_coordinator.take_event_receiver().await
            .ok_or_else(|| anyhow::anyhow!("Kafka event receiver already taken"))?;
        let mut network_events = self.network_coordinator.take_event_receiver().await
            .ok_or_else(|| anyhow::anyhow!("Network event receiver already taken"))?;
        let mut job_events = self.job_processor.take_event_receiver().await
            .ok_or_else(|| anyhow::anyhow!("Job event receiver already taken"))?;
        let mut worker_events = self.worker_manager.take_event_receiver().await
            .ok_or_else(|| anyhow::anyhow!("Worker event receiver already taken"))?;

        // Clone components for use in spawned task
        let job_processor = self.job_processor.clone();
        let worker_manager = self.worker_manager.clone();
        let blockchain_integration = self.blockchain_integration.clone();
        let database = self.database.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            loop {
                // Check if we should stop
                if !*running.read().await {
                    info!("Event processing loop stopping");
                    break;
                }

                tokio::select! {
                    // Process Kafka events
                    Some(event) = kafka_events.recv() => {
                        if let Err(e) = handle_kafka_event_impl(
                            event,
                            &job_processor,
                            &worker_manager,
                            &blockchain_integration,
                            &database,
                        ).await {
                            error!("Failed to handle Kafka event: {}", e);
                        }
                    }

                    // Process network events
                    Some(event) = network_events.recv() => {
                        if let Err(e) = handle_network_event_impl(
                            event,
                            &job_processor,
                            &worker_manager,
                        ).await {
                            error!("Failed to handle network event: {}", e);
                        }
                    }

                    // Process job events
                    Some(event) = job_events.recv() => {
                        if let Err(e) = handle_job_event_impl(
                            event,
                            &worker_manager,
                            &blockchain_integration,
                        ).await {
                            error!("Failed to handle job event: {}", e);
                        }
                    }

                    // Process worker events
                    Some(event) = worker_events.recv() => {
                        if let Err(e) = handle_worker_event_impl(
                            event,
                            &job_processor,
                            &database,
                        ).await {
                            error!("Failed to handle worker event: {}", e);
                        }
                    }

                    else => {
                        // No events, continue
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                }
            }
        });

        Ok(())
    }

    /// Start health monitoring
    async fn start_health_monitoring(&self) -> Result<()> {
        // Start network health monitoring (simplified to avoid Send issues)
        let interval = tokio::time::Duration::from_secs(30);
        
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            
            loop {
                interval_timer.tick().await;
                
                // Log health check attempt (simplified)
                debug!("Network health check tick");
            }
        });

        Ok(())
    }

    /// Start metrics collection
    async fn start_metrics_collection(&self) -> Result<()> {
        let interval = tokio::time::Duration::from_secs(60);
        let metrics_collector = self.metrics_collector.clone();
        let kafka_coordinator = self.kafka_coordinator.clone();
        let running = self.running.clone();
        let node_id = self.node_id;

        // Get Send+Sync handles to the stats - these are Arc<RwLock<T>> which ARE Send+Sync
        // This is the key fix: instead of capturing the whole components (which contain
        // non-Send fields like mpsc::UnboundedReceiver), we only capture the stats Arcs
        let job_stats_handle = self.job_processor.stats_handle();
        let worker_stats_handle = self.worker_manager.stats_handle();

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);

            loop {
                interval_timer.tick().await;

                // Check if we should stop
                if !*running.read().await {
                    info!("Metrics collection loop stopping");
                    break;
                }

                // Collect metrics from all components using the Send+Sync handles
                let kafka_stats = kafka_coordinator.get_kafka_stats().await;

                // Now we can actually read the stats from the handles!
                let job_stats = job_stats_handle.read().await.clone();
                let worker_stats = worker_stats_handle.read().await.clone();

                // Create network stats (network coordinator stats would need similar handle treatment)
                let network_stats = NetworkCoordinatorStats {
                    total_peers: 0, // TODO: Add network stats handle
                    active_peers: 0,
                    messages_sent: 0,
                    messages_received: 0,
                    network_latency_ms: 0,
                    jobs_announced: 0,
                    jobs_bid_on: 0,
                    jobs_assigned: 0,
                    jobs_completed: 0,
                    average_reputation: 0.0,
                };

                // Update metrics collector with actual data
                metrics_collector.update_component_metrics(
                    Some(kafka_stats),
                    Some(network_stats),
                    Some(job_stats.clone()),
                    Some(worker_stats.clone()),
                ).await;

                // Log metrics summary
                debug!(
                    "Metrics collected - Jobs: {}/{} active, Workers: {}/{} active, Health: {:.1}%",
                    job_stats.active_jobs,
                    job_stats.total_jobs,
                    worker_stats.active_workers,
                    worker_stats.total_workers,
                    metrics_collector.get_metrics().await
                        .map(|m| m.system_health_score * 100.0)
                        .unwrap_or(0.0)
                );
            }
        });

        Ok(())
    }


    /// Get coordinator status
    pub async fn get_status(&self) -> CoordinatorStatus {
        let running = *self.running.read().await;
        
        CoordinatorStatus {
            node_id: self.node_id,
            running,
            kafka_connected: self.kafka_coordinator.is_connected().await,
            network_connected: self.network_coordinator.is_connected().await,
            blockchain_connected: self.blockchain_integration.is_connected().await,
            active_jobs: self.job_processor.get_active_jobs_count().await,
            active_workers: self.worker_manager.get_active_workers_count().await,
        }
    }

    /// Get component references for external access
    pub fn kafka_coordinator(&self) -> Arc<KafkaCoordinator> {
        self.kafka_coordinator.clone()
    }

    pub fn network_coordinator(&self) -> Arc<NetworkCoordinator> {
        self.network_coordinator.clone()
    }

    pub fn job_processor(&self) -> Arc<JobProcessor> {
        self.job_processor.clone()
    }

    pub fn worker_manager(&self) -> Arc<WorkerManager> {
        self.worker_manager.clone()
    }

    pub fn blockchain_integration(&self) -> Arc<BlockchainIntegration> {
        self.blockchain_integration.clone()
    }

    pub fn metrics_collector(&self) -> Arc<MetricsCollector> {
        self.metrics_collector.clone()
    }
}

/// Coordinator status information
#[derive(Debug, Clone)]
pub struct CoordinatorStatus {
    pub node_id: NodeId,
    pub running: bool,
    pub kafka_connected: bool,
    pub network_connected: bool,
    pub blockchain_connected: bool,
    pub active_jobs: usize,
    pub active_workers: usize,
}

impl std::fmt::Display for CoordinatorStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Coordinator Status:\n")?;
        write!(f, "  Node ID: {}\n", self.node_id)?;
        write!(f, "  Running: {}\n", self.running)?;
        write!(f, "  Kafka Connected: {}\n", self.kafka_connected)?;
        write!(f, "  Network Connected: {}\n", self.network_connected)?;
        write!(f, "  Blockchain Connected: {}\n", self.blockchain_connected)?;
        write!(f, "  Active Jobs: {}\n", self.active_jobs)?;
        write!(f, "  Active Workers: {}", self.active_workers)?;
        Ok(())
    }
}

// =============================================================================
// Event Handler Implementations
// =============================================================================

use crate::node::coordinator::JobResult as CoordinatorJobResult;

/// Handle Kafka events with full component access
async fn handle_kafka_event_impl(
    event: KafkaEvent,
    job_processor: &Arc<JobProcessor>,
    worker_manager: &Arc<WorkerManager>,
    blockchain_integration: &Arc<BlockchainIntegration>,
    _database: &Arc<Database>,
) -> Result<()> {
    match event {
        KafkaEvent::JobReceived(job_message) => {
            info!("Received job from Kafka: {}", job_message.job_id);

            // Submit job to job processor queue
            let job_id = job_processor.submit_job(job_message.job_request.clone()).await?;

            // Register job on blockchain
            if let Err(e) = blockchain_integration.register_job(
                job_id.clone(),
                &job_message.job_request,
            ).await {
                warn!("Failed to register job on blockchain: {} (continuing with off-chain processing)", e);
            }

            info!("Job {} queued for processing", job_id);
        }

        KafkaEvent::WorkerRegistered(worker_id, capabilities) => {
            info!("Worker {} registered via Kafka with capabilities: {:?}", worker_id, capabilities);
            // Worker registration is handled by the worker_manager's internal mechanisms
            // The capabilities are logged for monitoring purposes
        }

        KafkaEvent::WorkerHeartbeat(worker_id, load) => {
            debug!("Worker heartbeat via Kafka: {} (load: {})", worker_id, load);

            // Update worker load in worker manager
            if let Err(e) = worker_manager.update_worker_load(worker_id.clone(), load as f64).await {
                debug!("Worker {} not found in manager, may need registration first: {}", worker_id, e);
            }
        }

        KafkaEvent::WorkerDeparted(worker_id, reason) => {
            warn!("Worker departed via Kafka: {} (reason: {})", worker_id, reason);

            // Unregister the worker
            if let Err(e) = worker_manager.unregister_worker(worker_id.clone()).await {
                warn!("Failed to unregister departed worker: {}", e);
            }
        }

        KafkaEvent::JobAssigned(job_id, worker_id) => {
            info!("Job assigned via Kafka: {} -> {}", job_id, worker_id);

            // Update job assignment in processor
            if let Err(e) = job_processor.assign_job_to_worker(job_id.clone(), worker_id.clone()).await {
                warn!("Failed to update job assignment: {}", e);
            }

            // Record assignment on blockchain
            if let Err(e) = blockchain_integration.assign_job_to_worker(job_id, worker_id).await {
                warn!("Failed to record job assignment on blockchain: {}", e);
            }
        }

        KafkaEvent::JobCompleted(job_id, result) => {
            info!("Job completed via Kafka: {}", job_id);

            // Convert to CoordinatorJobResult
            let coordinator_result = CoordinatorJobResult {
                job_id: job_id.clone(),
                status: crate::node::coordinator::JobStatus::Completed,
                output_files: result.output_files.clone(),
                execution_time: result.execution_time,
                total_cost: result.total_cost,
                completed_tasks: 1,
                total_tasks: 1,
                error_message: None,
            };

            // Complete job in processor
            if let Err(e) = job_processor.complete_job(job_id.clone(), coordinator_result.clone()).await {
                warn!("Failed to complete job: {}", e);
            }

            // Submit result to blockchain
            if let Err(e) = blockchain_integration.complete_job(job_id, &coordinator_result).await {
                warn!("Failed to submit job result to blockchain: {}", e);
            }
        }

        KafkaEvent::JobFailed(job_id, error) => {
            error!("Job failed via Kafka: {} (error: {})", job_id, error);

            // Fail job in processor
            if let Err(e) = job_processor.fail_job(job_id, error).await {
                warn!("Failed to mark job as failed: {}", e);
            }
        }

        KafkaEvent::HealthMetricsUpdated(worker_id, metrics) => {
            debug!("Health metrics updated via Kafka for worker {}: response_time={}ms, cpu={}%, mem={}%",
                worker_id,
                metrics.response_time_ms,
                metrics.cpu_usage_percent,
                metrics.memory_usage_percent
            );

            // Check if worker is overloaded
            if metrics.cpu_usage_percent > 95.0 || metrics.memory_usage_percent > 95.0 {
                warn!("Worker {} is overloaded (CPU: {}%, Memory: {}%)",
                    worker_id, metrics.cpu_usage_percent, metrics.memory_usage_percent);
            }
        }
    }
    Ok(())
}

/// Handle network events with component access
async fn handle_network_event_impl(
    event: NetworkEvent,
    _job_processor: &Arc<JobProcessor>,
    _worker_manager: &Arc<WorkerManager>,
) -> Result<()> {
    match event {
        NetworkEvent::PeerConnected(peer_id) => {
            info!("Peer connected: {}", peer_id);
        }

        NetworkEvent::PeerDisconnected(peer_id) => {
            warn!("Peer disconnected: {}", peer_id);
        }

        NetworkEvent::MessageReceived { peer_id, message } => {
            debug!("Message received from peer {}: {:?}", peer_id, message);
        }

        NetworkEvent::PeerDiscovered { peer_id, addresses } => {
            info!("Peer discovered: {} at {:?}", peer_id, addresses);
        }

        NetworkEvent::NetworkError(error) => {
            error!("Network error: {}", error);
        }
    }
    Ok(())
}

/// Handle job processor events
async fn handle_job_event_impl(
    event: crate::coordinator::job_processor::JobEvent,
    _worker_manager: &Arc<WorkerManager>,
    _blockchain_integration: &Arc<BlockchainIntegration>,
) -> Result<()> {
    use crate::coordinator::job_processor::JobEvent;

    match event {
        JobEvent::JobSubmitted(job_id, _request) => {
            debug!("Job {} submitted", job_id);
        }

        JobEvent::JobStarted(job_id, worker_id) => {
            info!("Job {} started on worker {}", job_id, worker_id);
        }

        JobEvent::JobCompleted(job_id, _result) => {
            info!("Job {} completed", job_id);
        }

        JobEvent::JobFailed(job_id, error) => {
            error!("Job {} failed: {}", job_id, error);
        }

        JobEvent::JobCancelled(job_id) => {
            warn!("Job {} cancelled", job_id);
        }

        JobEvent::JobTimeout(job_id) => {
            error!("Job {} timed out", job_id);
        }

        JobEvent::JobAssigned(job_id, worker_id) => {
            info!("Job {} assigned to worker {}", job_id, worker_id);
        }

        JobEvent::JobUnassigned(job_id, worker_id) => {
            info!("Job {} unassigned from worker {}", job_id, worker_id);
        }
    }
    Ok(())
}

/// Handle worker manager events
async fn handle_worker_event_impl(
    event: crate::coordinator::worker_manager::WorkerEvent,
    _job_processor: &Arc<JobProcessor>,
    _database: &Arc<Database>,
) -> Result<()> {
    use crate::coordinator::worker_manager::WorkerEvent;

    match event {
        WorkerEvent::WorkerRegistered(worker_id, _info) => {
            info!("Worker {} registered", worker_id);
        }

        WorkerEvent::WorkerUnregistered(worker_id) => {
            info!("Worker {} unregistered", worker_id);
        }

        WorkerEvent::WorkerHeartbeat(worker_id, _health) => {
            debug!("Worker {} heartbeat received", worker_id);
        }

        WorkerEvent::WorkerHealthChanged(worker_id, health) => {
            debug!("Worker {} health changed: cpu={}%, mem={}%",
                worker_id, health.cpu_usage, health.memory_usage);
        }

        WorkerEvent::WorkerCapabilitiesUpdated(worker_id, _capabilities) => {
            info!("Worker {} capabilities updated", worker_id);
        }

        WorkerEvent::WorkerLoadUpdated(worker_id, load) => {
            debug!("Worker {} load updated: {}", worker_id, load);
        }

        WorkerEvent::WorkerReputationUpdated(worker_id, reputation) => {
            info!("Worker {} reputation updated: {}", worker_id, reputation);
        }

        WorkerEvent::WorkerTimeout(worker_id) => {
            warn!("Worker {} timed out", worker_id);
        }

        WorkerEvent::WorkerFailed(worker_id, error) => {
            error!("Worker {} failed: {}", worker_id, error);
        }
    }
    Ok(())
} 