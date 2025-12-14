//! # Metrics Collector
//!
//! Comprehensive metrics collection system for the Bitsage Network coordinator,
//! aggregating metrics from all components and providing monitoring capabilities.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::time::Duration;
use tracing::{info, debug, error};

use crate::coordinator::config::MetricsConfig;
use crate::coordinator::{
    kafka::{KafkaCoordinator, KafkaStats},
    network_coordinator::{NetworkCoordinatorService, NetworkCoordinatorStats},
    job_processor::{JobProcessor, JobStats},
    worker_manager::{WorkerManager, WorkerStats},
    blockchain_integration::{BlockchainIntegration, BlockchainMetrics, BlockchainStats},
};

/// Metrics collector events
#[derive(Debug, Clone)]
pub enum MetricsEvent {
    MetricsUpdated(CoordinatorMetrics),
    HealthMetricsUpdated(HealthMetrics),
    PerformanceMetricsUpdated(PerformanceMetrics),
    ExportMetrics(ExportFormat),
}

/// Export format
#[derive(Debug, Clone)]
pub enum ExportFormat {
    Prometheus,
    Graphite,
    Json,
}

/// Comprehensive coordinator metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatorMetrics {
    pub timestamp: u64,
    pub node_id: String,
    pub environment: String,
    
    // Component metrics
    pub kafka: Option<KafkaStats>,
    pub network: Option<NetworkCoordinatorStats>,
    pub jobs: Option<JobStats>,
    pub workers: Option<WorkerStats>,
    pub blockchain: Option<BlockchainMetrics>,
    
    // Aggregated metrics
    pub total_jobs: u64,
    pub active_jobs: u64,
    pub total_workers: u64,
    pub active_workers: u64,
    pub total_transactions: u64,
    pub successful_transactions: u64,
    pub network_peers: u64,
    pub kafka_messages: u64,
    
    // Performance metrics
    pub average_job_completion_time_secs: u64,
    pub average_worker_reputation: f64,
    pub average_worker_load: f64,
    pub network_latency_ms: u64,
    pub blockchain_confirmation_time_ms: u64,
    
    // Health metrics
    pub system_health_score: f64,
    pub component_health: HashMap<String, ComponentHealth>,
}

/// Component health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub status: HealthStatus,
    pub last_check: u64,
    pub error_count: u64,
    pub response_time_ms: u64,
    pub uptime_secs: u64,
}

/// Health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

/// Health metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthMetrics {
    pub timestamp: u64,
    pub overall_health: f64,
    pub kafka_health: f64,
    pub network_health: f64,
    pub blockchain_health: f64,
    pub database_health: f64,
    pub memory_usage: f64,
    pub cpu_usage: f64,
    pub disk_usage: f64,
}

/// Performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub timestamp: u64,
    pub jobs_per_second: f64,
    pub workers_per_second: f64,
    pub transactions_per_second: f64,
    pub messages_per_second: f64,
    pub average_response_time_ms: u64,
    pub error_rate: f64,
    pub throughput: f64,
}

/// Metrics storage entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsStorageEntry {
    pub timestamp: u64,
    pub metrics: CoordinatorMetrics,
    pub retention_days: u32,
}

/// Main metrics collector service
pub struct MetricsCollector {
    config: MetricsConfig,
    
    // Component references
    kafka_coordinator: Option<Arc<KafkaCoordinator>>,
    network_coordinator: Option<Arc<NetworkCoordinatorService>>,
    job_processor: Option<Arc<JobProcessor>>,
    worker_manager: Option<Arc<WorkerManager>>,
    blockchain_integration: Option<Arc<BlockchainIntegration>>,
    
    // Metrics storage
    metrics_history: Arc<RwLock<Vec<MetricsStorageEntry>>>,
    current_metrics: Arc<RwLock<Option<CoordinatorMetrics>>>,
    
    // Communication channels
    event_sender: mpsc::UnboundedSender<MetricsEvent>,
    event_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<MetricsEvent>>>>,
    
    // Internal state
    running: Arc<RwLock<bool>>,
    last_collection: Arc<RwLock<u64>>,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new(config: MetricsConfig) -> Self {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        
        Self {
            config,
            kafka_coordinator: None,
            network_coordinator: None,
            job_processor: None,
            worker_manager: None,
            blockchain_integration: None,
            metrics_history: Arc::new(RwLock::new(Vec::new())),
            current_metrics: Arc::new(RwLock::new(None)),
            event_sender,
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
            running: Arc::new(RwLock::new(false)),
            last_collection: Arc::new(RwLock::new(0)),
        }
    }

    /// Set component references
    pub fn set_components(
        &mut self,
        kafka_coordinator: Option<Arc<KafkaCoordinator>>,
        network_coordinator: Option<Arc<NetworkCoordinatorService>>,
        job_processor: Option<Arc<JobProcessor>>,
        worker_manager: Option<Arc<WorkerManager>>,
        blockchain_integration: Option<Arc<BlockchainIntegration>>,
    ) {
        self.kafka_coordinator = kafka_coordinator;
        self.network_coordinator = network_coordinator;
        self.job_processor = job_processor;
        self.worker_manager = worker_manager;
        self.blockchain_integration = blockchain_integration;
    }

    /// Start the metrics collector
    pub async fn start(&self) -> Result<()> {
        info!("Starting Metrics Collector...");
        
        {
            let mut running = self.running.write().await;
            if *running {
                return Err(anyhow::anyhow!("Metrics collector already running"));
            }
            *running = true;
        }

        // Start collection tasks
        self.start_metrics_collection().await?;
        self.start_health_monitoring().await?;
        self.start_storage_cleanup().await?;

        info!("Metrics collector started successfully");
        
        // Return immediately - tasks are running in background
        Ok(())
    }

    /// Stop the metrics collector
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping Metrics Collector...");
        
        {
            let mut running = self.running.write().await;
            *running = false;
        }

        info!("Metrics collector stopped");
        Ok(())
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> Option<CoordinatorMetrics> {
        self.current_metrics.read().await.clone()
    }

    /// Get metrics history
    pub async fn get_metrics_history(&self, hours: u32) -> Vec<CoordinatorMetrics> {
        let history = self.metrics_history.read().await;
        let cutoff_time = chrono::Utc::now().timestamp() as u64 - (hours * 3600) as u64;
        
        history.iter()
            .filter(|entry| entry.timestamp >= cutoff_time)
            .map(|entry| entry.metrics.clone())
            .collect()
    }

    /// Export metrics
    pub async fn export_metrics(&self, format: ExportFormat) -> Result<String> {
        let metrics = self.get_metrics().await;
        
        match format {
            ExportFormat::Prometheus => self.export_prometheus(metrics).await,
            ExportFormat::Graphite => self.export_graphite(metrics).await,
            ExportFormat::Json => self.export_json(metrics).await,
        }
    }

    /// Update component metrics
    pub async fn update_component_metrics(
        &self,
        kafka_stats: Option<KafkaStats>,
        network_stats: Option<NetworkCoordinatorStats>,
        job_stats: Option<JobStats>,
        worker_stats: Option<WorkerStats>,
    ) {
        let mut current = self.current_metrics.write().await;
        
        let metrics = CoordinatorMetrics {
            timestamp: chrono::Utc::now().timestamp() as u64,
            node_id: "coordinator".to_string(), // TODO: Get actual node ID
            environment: "development".to_string(), // TODO: Get from config
            kafka: kafka_stats,
            network: network_stats,
            jobs: job_stats,
            workers: worker_stats,
            blockchain: None, // TODO: Get blockchain metrics
            total_jobs: 0, // TODO: Calculate from component stats
            active_jobs: 0,
            total_workers: 0,
            active_workers: 0,
            total_transactions: 0,
            successful_transactions: 0,
            network_peers: 0,
            kafka_messages: 0,
            average_job_completion_time_secs: 0,
            average_worker_reputation: 0.0,
            average_worker_load: 0.0,
            network_latency_ms: 0,
            blockchain_confirmation_time_ms: 0,
            system_health_score: 1.0,
            component_health: HashMap::new(),
        };
        
        // Store current metrics
        *current = Some(metrics.clone());
        
        // Store metrics in database
        self.store_metrics(metrics.clone()).await;
        
        // Send metrics update event
        if let Err(e) = self.event_sender.send(MetricsEvent::MetricsUpdated(metrics)) {
            error!("Failed to send metrics update event: {}", e);
        }
    }

    /// Update health metrics
    pub async fn update_health_metrics(&self) {
        let health_metrics = HealthMetrics {
            timestamp: chrono::Utc::now().timestamp() as u64,
            overall_health: 1.0, // TODO: Calculate from component health
            kafka_health: 1.0,
            network_health: 1.0,
            blockchain_health: 1.0,
            database_health: 1.0,
            memory_usage: 0.0, // TODO: Get system metrics
            cpu_usage: 0.0,
            disk_usage: 0.0,
        };
        
        // Send event
        if let Err(e) = self.event_sender.send(MetricsEvent::HealthMetricsUpdated(health_metrics)) {
            error!("Failed to send health metrics updated event: {}", e);
        }
    }

    /// Start metrics collection
    async fn start_metrics_collection(&self) -> Result<()> {
        let config = self.config.clone();
        let job_processor = self.job_processor.clone();
        let worker_manager = self.worker_manager.clone();
        let blockchain_integration = self.blockchain_integration.clone();
        let network_coordinator = self.network_coordinator.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(config.collection_interval_secs));
            
            loop {
                interval.tick().await;
                
                // Collect metrics from all components
                let job_stats = if let Some(job_processor) = &job_processor {
                    Some(job_processor.get_job_stats().await)
                } else {
                    None
                };
                // TODO: Fix Send trait issues with components in tokio::spawn
                let worker_stats: Option<WorkerStats> = None; // if let Some(worker_manager) = &worker_manager {
                    // Some(worker_manager.get_worker_stats().await)
                // } else {
                    // None
                // };
                let blockchain_stats: Option<BlockchainStats> = None; // if let Some(blockchain_integration) = &blockchain_integration {
                    // Some(blockchain_integration.get_blockchain_stats().await)
                // } else {
                    // None
                // };
                
                // Collect network stats if available
                // TODO: Fix Send trait issue with NetworkCoordinatorService in tokio::spawn
                let network_stats: Option<NetworkCoordinatorStats> = None;
                
                // Aggregate metrics
                let metrics = CoordinatorMetrics {
                    timestamp: chrono::Utc::now().timestamp() as u64,
                    node_id: "coordinator".to_string(), // TODO: Get actual node ID
                    environment: "development".to_string(), // TODO: Get from config
                    kafka: None, // TODO: Get kafka metrics
                    network: None, // TODO: Get network metrics
                    jobs: job_stats,
                    workers: worker_stats,
                    blockchain: blockchain_stats.map(|stats| BlockchainMetrics {
                        total_transactions: stats.total_transactions,
                        successful_transactions: 0, // Not available in BlockchainStats
                        failed_transactions: 0,     // Not available in BlockchainStats  
                        average_gas_used: stats.gas_price,
                        average_confirmation_time_ms: 0, // Not available in BlockchainStats
                        last_block_number: stats.last_block_number,
                        contract_events_received: 0, // Not available in BlockchainStats
                        active_jobs_on_chain: 0,     // Not available in BlockchainStats
                        total_workers_registered: 0, // Not available in BlockchainStats
                    }),
                    total_jobs: 0, // TODO: Calculate from component stats
                    active_jobs: 0,
                    total_workers: 0,
                    active_workers: 0,
                    total_transactions: 0,
                    successful_transactions: 0,
                    network_peers: 0,
                    kafka_messages: 0,
                    average_job_completion_time_secs: 0,
                    average_worker_reputation: 0.0,
                    average_worker_load: 0.0,
                    network_latency_ms: 0,
                    blockchain_confirmation_time_ms: 0,
                    system_health_score: 1.0,
                    component_health: HashMap::new(),
                };
                
                // TODO: Store or send metrics
                info!("Collected metrics: {:?}", metrics);
            }
        });

        Ok(())
    }

    /// Start health monitoring
    async fn start_health_monitoring(&self) -> Result<()> {
        let event_sender = self.event_sender.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                // TODO: Implement health monitoring logic
                debug!("Monitoring system health");
            }
        });

        Ok(())
    }

    /// Start storage cleanup
    async fn start_storage_cleanup(&self) -> Result<()> {
        let config = self.config.clone();
        let metrics_history = Arc::clone(&self.metrics_history);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Every hour
            
            loop {
                interval.tick().await;
                
                if config.storage.enable_storage {
                    let cutoff_time = chrono::Utc::now().timestamp() as u64 - 
                        (config.storage.retention_days * 24 * 3600) as u64;
                    
                    let mut history = metrics_history.write().await;
                    history.retain(|entry| entry.timestamp >= cutoff_time);
                    
                    debug!("Cleaned up metrics storage, retained {} entries", history.len());
                }
            }
        });

        Ok(())
    }

    /// Store metrics in history
    async fn store_metrics(&self, metrics: CoordinatorMetrics) {
        if self.config.storage.enable_storage {
            let entry = MetricsStorageEntry {
                timestamp: metrics.timestamp,
                metrics,
                retention_days: self.config.storage.retention_days,
            };
            
            let mut history = self.metrics_history.write().await;
            history.push(entry);
            
            // Limit history size
            if history.len() > 10000 {
                history.remove(0);
            }
        }
    }

    /// Export metrics as Prometheus format
    async fn export_prometheus(&self, metrics: Option<CoordinatorMetrics>) -> Result<String> {
        let mut output = String::new();
        
        if let Some(metrics) = metrics {
            output.push_str(&format!("# HELP sage_coordinator_total_jobs Total number of jobs\n"));
            output.push_str(&format!("# TYPE sage_coordinator_total_jobs counter\n"));
            output.push_str(&format!("sage_coordinator_total_jobs {}\n", metrics.total_jobs));
            
            output.push_str(&format!("# HELP sage_coordinator_active_jobs Number of active jobs\n"));
            output.push_str(&format!("# TYPE sage_coordinator_active_jobs gauge\n"));
            output.push_str(&format!("sage_coordinator_active_jobs {}\n", metrics.active_jobs));
            
            output.push_str(&format!("# HELP sage_coordinator_total_workers Total number of workers\n"));
            output.push_str(&format!("# TYPE sage_coordinator_total_workers counter\n"));
            output.push_str(&format!("sage_coordinator_total_workers {}\n", metrics.total_workers));
            
            output.push_str(&format!("# HELP sage_coordinator_active_workers Number of active workers\n"));
            output.push_str(&format!("# TYPE sage_coordinator_active_workers gauge\n"));
            output.push_str(&format!("sage_coordinator_active_workers {}\n", metrics.active_workers));
            
            output.push_str(&format!("# HELP sage_coordinator_system_health_score Overall system health score\n"));
            output.push_str(&format!("# TYPE sage_coordinator_system_health_score gauge\n"));
            output.push_str(&format!("sage_coordinator_system_health_score {}\n", metrics.system_health_score));
        }
        
        Ok(output)
    }

    /// Export metrics as Graphite format
    async fn export_graphite(&self, metrics: Option<CoordinatorMetrics>) -> Result<String> {
        let mut output = String::new();
        
        if let Some(metrics) = metrics {
            output.push_str(&format!("sage.coordinator.total_jobs {}\n", metrics.total_jobs));
            output.push_str(&format!("sage.coordinator.active_jobs {}\n", metrics.active_jobs));
            output.push_str(&format!("sage.coordinator.total_workers {}\n", metrics.total_workers));
            output.push_str(&format!("sage.coordinator.active_workers {}\n", metrics.active_workers));
            output.push_str(&format!("sage.coordinator.system_health_score {}\n", metrics.system_health_score));
        }
        
        Ok(output)
    }

    /// Export metrics as JSON format
    async fn export_json(&self, metrics: Option<CoordinatorMetrics>) -> Result<String> {
        if let Some(metrics) = metrics {
            Ok(serde_json::to_string_pretty(&metrics)?)
        } else {
            Ok("{}".to_string())
        }
    }

    /// Get event receiver
    pub async fn event_receiver(&self) -> mpsc::UnboundedReceiver<MetricsEvent> {
        self.event_receiver.write().await.take().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_collector_creation() {
        let config = MetricsConfig::default();
        let collector = MetricsCollector::new(config);
        
        assert!(collector.get_metrics().await.is_none());
    }

    #[tokio::test]
    async fn test_metrics_export() {
        let config = MetricsConfig::default();
        let collector = MetricsCollector::new(config);
        
        let json_export = collector.export_metrics(ExportFormat::Json).await.unwrap();
        assert_eq!(json_export, "{}");
    }

    #[tokio::test]
    async fn test_prometheus_export() {
        let config = MetricsConfig::default();
        let collector = MetricsCollector::new(config);
        
        let prometheus_export = collector.export_metrics(ExportFormat::Prometheus).await.unwrap();
        assert!(prometheus_export.contains("# HELP"));
    }
} 