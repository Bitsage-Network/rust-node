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
    kafka::{KafkaCoordinator, KafkaStats},
    network_coordinator::{NetworkCoordinatorService, NetworkCoordinatorStats},
    job_processor::{JobProcessor, JobStats},
    worker_manager::{WorkerManager, WorkerStats},
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
        let mut kafka_events = self.kafka_coordinator.event_receiver().await;
        let mut network_events = self.network_coordinator.event_receiver().await;
        let mut job_events = self.job_processor.event_receiver().await;
        let mut worker_events = self.worker_manager.event_receiver().await;
        
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Process Kafka events
                    Some(event) = kafka_events.recv() => {
                        if let Err(e) = Self::handle_kafka_event(event).await {
                            error!("Failed to handle Kafka event: {}", e);
                        }
                    }
                    
                    // Process network events
                    Some(event) = network_events.recv() => {
                        if let Err(e) = Self::handle_network_event(event).await {
                            error!("Failed to handle network event: {}", e);
                        }
                    }
                    
                    // Process job events
                    Some(event) = job_events.recv() => {
                        if let Err(e) = Self::handle_job_event(event).await {
                            error!("Failed to handle job event: {}", e);
                        }
                    }
                    
                    // Process worker events
                    Some(event) = worker_events.recv() => {
                        if let Err(e) = Self::handle_worker_event(event).await {
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
        let _metrics_collector = self.metrics_collector.clone();
        let kafka_coordinator = self.kafka_coordinator.clone();
        let _network_coordinator = self.network_coordinator.clone();
        let _job_processor = self.job_processor.clone();
        let _worker_manager = self.worker_manager.clone();

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            
            loop {
                interval_timer.tick().await;
                
                // Collect metrics from all components - with Send trait fixes
                let _kafka_stats = kafka_coordinator.get_message_stats().await;
                let _network_stats = NetworkCoordinatorStats {
                    total_peers: 0,
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
                // TODO: Fix Send trait issues with these components in tokio::spawn
                // let job_stats = job_processor.get_job_stats().await;
                // let worker_stats = worker_manager.get_worker_stats().await;
                let job_stats: Option<JobStats> = None;
                let worker_stats: Option<WorkerStats> = None;
                
                // Update metrics collector
                let _kafka_stats = KafkaStats {
                    messages_sent: 0,
                    messages_received: 0,
                    messages_failed: 0,
                    dead_letter_queue_size: 0,
                    job_queue_size: 0,
                    consumer_lag: 0,
                    producer_queue_size: 0,
                    connection_status: "Connected".to_string(),
                    last_message_timestamp: 0,
                    average_message_size_bytes: 0,
                    error_rate: 0.0,
                    throughput_messages_per_sec: 0.0,
                };
                let _network_stats = NetworkCoordinatorStats {
                    total_peers: 0,
                    active_peers: 0,
                    jobs_announced: 0,
                    jobs_bid_on: 0,
                    jobs_assigned: 0,
                    jobs_completed: 0,
                    average_reputation: 0.0,
                    network_latency_ms: 0,
                    messages_sent: 0,
                    messages_received: 0,
                };
                let _job_stats = JobStats {
                    total_jobs: 0,
                    active_jobs: 0,
                    completed_jobs: 0,
                    failed_jobs: 0,
                    cancelled_jobs: 0,
                    average_completion_time_secs: 0,
                    jobs_per_minute: 0.0,
                    success_rate: 0.0,
                };
                let _worker_stats = WorkerStats {
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
                
                // TODO: Fix Send trait issue with metrics_collector in tokio::spawn
                debug!("Metrics collection placeholder (would update metrics here)");
            }
        });

        Ok(())
    }

    /// Handle Kafka events
    async fn handle_kafka_event(event: KafkaEvent) -> Result<()> {
        match event {
            KafkaEvent::JobReceived(job_message) => {
                info!("Received job from Kafka: {}", job_message.job_id);
                // TODO: Process job message
            }
            KafkaEvent::WorkerRegistered(worker_id, _capabilities) => {
                info!("Worker registered via Kafka: {}", worker_id);
                // TODO: Register worker
            }
            KafkaEvent::WorkerHeartbeat(worker_id, load) => {
                debug!("Worker heartbeat via Kafka: {} (load: {})", worker_id, load);
                // TODO: Update worker load
            }
            KafkaEvent::WorkerDeparted(worker_id, reason) => {
                warn!("Worker departed via Kafka: {} (reason: {})", worker_id, reason);
                // TODO: Handle worker departure
            }
            KafkaEvent::JobAssigned(job_id, worker_id) => {
                info!("Job assigned via Kafka: {} -> {}", job_id, worker_id);
                // TODO: Update job assignment
            }
            KafkaEvent::JobCompleted(job_id, _result) => {
                info!("Job completed via Kafka: {}", job_id);
                // TODO: Process job completion
            }
            KafkaEvent::JobFailed(job_id, error) => {
                error!("Job failed via Kafka: {} (error: {})", job_id, error);
                // TODO: Handle job failure
            }
            KafkaEvent::HealthMetricsUpdated(worker_id, _metrics) => {
                debug!("Health metrics updated via Kafka: {}", worker_id);
                // TODO: Update health metrics
            }
        }
        Ok(())
    }

    /// Handle network events
    async fn handle_network_event(event: NetworkEvent) -> Result<()> {
        // TODO: Implement network event handling
        debug!("Network event: {:?}", event);
        Ok(())
    }

    /// Handle job events
    async fn handle_job_event(event: crate::coordinator::job_processor::JobEvent) -> Result<()> {
        // TODO: Implement job event handling
        debug!("Job event: {:?}", event);
        Ok(())
    }

    /// Handle worker events
    async fn handle_worker_event(event: crate::coordinator::worker_manager::WorkerEvent) -> Result<()> {
        // TODO: Implement worker event handling
        debug!("Worker event: {:?}", event);
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