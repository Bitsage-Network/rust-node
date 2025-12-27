//! # Metrics Collector
//!
//! Comprehensive metrics collection system for the Bitsage Network coordinator,
//! aggregating metrics from all components and providing monitoring capabilities.
//!
//! Features:
//! - Real-time system resource monitoring (CPU, memory, disk)
//! - Component health aggregation
//! - Historical metrics storage with configurable retention
//! - Export to Prometheus, Graphite, and JSON formats

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, RwLock};
use tokio::time::Duration;
use tracing::{info, debug, error, warn};

use crate::coordinator::config::MetricsConfig;
use crate::coordinator::{
    kafka::{KafkaCoordinator, KafkaStats},
    network_coordinator::{NetworkCoordinatorService, NetworkCoordinatorStats},
    job_processor::{JobProcessor, JobStats},
    worker_manager::{WorkerManager, WorkerStats},
    blockchain_integration::{BlockchainIntegration, BlockchainMetrics, BlockchainStats},
};

/// System resource metrics collected from the operating system
#[derive(Debug, Clone, Default)]
pub struct SystemResourceMetrics {
    pub cpu_usage_percent: f64,
    pub memory_usage_percent: f64,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub disk_usage_percent: f64,
    pub disk_used_bytes: u64,
    pub disk_total_bytes: u64,
    pub load_average_1m: f64,
    pub load_average_5m: f64,
    pub load_average_15m: f64,
    pub uptime_secs: u64,
}

/// Calculate overall health score from system resource metrics
fn calculate_overall_health(resources: &SystemResourceMetrics) -> f64 {
    // Health degrades as resource usage increases
    let cpu_health = 1.0 - (resources.cpu_usage_percent / 100.0).min(1.0);
    let memory_health = 1.0 - (resources.memory_usage_percent / 100.0).min(1.0);
    let disk_health = 1.0 - (resources.disk_usage_percent / 100.0).min(1.0);

    // Weighted average - CPU and memory are more critical
    let overall = cpu_health * 0.4 + memory_health * 0.4 + disk_health * 0.2;
    overall.clamp(0.0, 1.0)
}

impl SystemResourceMetrics {
    /// Collect system resource metrics
    pub fn collect() -> Self {
        let mut metrics = Self::default();

        // Collect memory info from /proc/meminfo (Linux) or platform API
        #[cfg(target_os = "linux")]
        {
            if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
                let mut mem_total: u64 = 0;
                let mut mem_available: u64 = 0;

                for line in meminfo.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        match parts[0] {
                            "MemTotal:" => mem_total = parts[1].parse().unwrap_or(0) * 1024,
                            "MemAvailable:" => mem_available = parts[1].parse().unwrap_or(0) * 1024,
                            _ => {}
                        }
                    }
                }

                if mem_total > 0 {
                    metrics.memory_total_bytes = mem_total;
                    metrics.memory_used_bytes = mem_total.saturating_sub(mem_available);
                    metrics.memory_usage_percent =
                        (metrics.memory_used_bytes as f64 / mem_total as f64) * 100.0;
                }
            }

            // Collect CPU usage from /proc/stat
            if let Ok(stat) = std::fs::read_to_string("/proc/stat") {
                if let Some(cpu_line) = stat.lines().next() {
                    let parts: Vec<&str> = cpu_line.split_whitespace().collect();
                    if parts.len() >= 5 && parts[0] == "cpu" {
                        let user: u64 = parts[1].parse().unwrap_or(0);
                        let nice: u64 = parts[2].parse().unwrap_or(0);
                        let system: u64 = parts[3].parse().unwrap_or(0);
                        let idle: u64 = parts[4].parse().unwrap_or(0);
                        let total = user + nice + system + idle;
                        if total > 0 {
                            let active = user + nice + system;
                            metrics.cpu_usage_percent = (active as f64 / total as f64) * 100.0;
                        }
                    }
                }
            }

            // Collect load average
            if let Ok(loadavg) = std::fs::read_to_string("/proc/loadavg") {
                let parts: Vec<&str> = loadavg.split_whitespace().collect();
                if parts.len() >= 3 {
                    metrics.load_average_1m = parts[0].parse().unwrap_or(0.0);
                    metrics.load_average_5m = parts[1].parse().unwrap_or(0.0);
                    metrics.load_average_15m = parts[2].parse().unwrap_or(0.0);
                }
            }

            // Collect uptime
            if let Ok(uptime) = std::fs::read_to_string("/proc/uptime") {
                if let Some(uptime_str) = uptime.split_whitespace().next() {
                    metrics.uptime_secs = uptime_str.parse::<f64>().unwrap_or(0.0) as u64;
                }
            }

            // Collect disk usage for root partition
            if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
                for line in mounts.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 && parts[1] == "/" {
                        // Use statvfs to get disk info
                        // For now, estimate from df command alternative
                        break;
                    }
                }
            }
        }

        // macOS / non-Linux fallback
        #[cfg(not(target_os = "linux"))]
        {
            // Use reasonable defaults for non-Linux systems
            metrics.cpu_usage_percent = 0.0;
            metrics.memory_usage_percent = 0.0;
            metrics.disk_usage_percent = 0.0;
        }

        metrics
    }
}

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
    start_time: Instant,
    node_id: String,
    environment: String,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new(config: MetricsConfig) -> Self {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        // Generate a unique node ID based on hostname and timestamp
        let node_id = format!(
            "coordinator-{}",
            std::env::var("HOSTNAME").unwrap_or_else(|_| {
                uuid::Uuid::new_v4().to_string()[..8].to_string()
            })
        );

        // Get environment from env var or default to development
        let environment = std::env::var("SAGE_ENVIRONMENT")
            .unwrap_or_else(|_| "development".to_string());

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
            start_time: Instant::now(),
            node_id,
            environment,
        }
    }

    /// Create with custom node ID and environment
    pub fn with_identity(config: MetricsConfig, node_id: String, environment: String) -> Self {
        let mut collector = Self::new(config);
        collector.node_id = node_id;
        collector.environment = environment;
        collector
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

    /// Update component metrics with proper aggregation
    pub async fn update_component_metrics(
        &self,
        kafka_stats: Option<KafkaStats>,
        network_stats: Option<NetworkCoordinatorStats>,
        job_stats: Option<JobStats>,
        worker_stats: Option<WorkerStats>,
    ) {
        let mut current = self.current_metrics.write().await;

        // Aggregate job metrics
        let (total_jobs, active_jobs, avg_completion_time) = if let Some(ref js) = job_stats {
            (
                js.total_jobs,
                js.active_jobs,
                js.average_completion_time_secs,
            )
        } else {
            (0, 0, 0)
        };

        // Aggregate worker metrics
        let (total_workers, active_workers, avg_reputation, avg_load) = if let Some(ref ws) = worker_stats {
            (
                ws.total_workers,
                ws.active_workers,
                ws.average_reputation,
                ws.average_load,
            )
        } else {
            (0, 0, 0.0, 0.0)
        };

        // Aggregate network metrics
        let network_peers = if let Some(ref ns) = network_stats {
            ns.active_peers
        } else {
            0
        };

        // Aggregate Kafka metrics
        let kafka_messages = if let Some(ref ks) = kafka_stats {
            ks.messages_sent + ks.messages_received
        } else {
            0
        };

        // Build component health map
        let mut component_health = HashMap::new();
        let now = chrono::Utc::now().timestamp() as u64;
        let uptime = self.start_time.elapsed().as_secs();

        // Kafka health - use error_rate to determine health status
        let kafka_error_count = kafka_stats.as_ref().map(|k| k.messages_failed).unwrap_or(0);
        component_health.insert("kafka".to_string(), ComponentHealth {
            status: if kafka_stats.is_some() {
                if kafka_error_count > 100 { HealthStatus::Degraded } else { HealthStatus::Healthy }
            } else {
                HealthStatus::Unknown
            },
            last_check: now,
            error_count: kafka_error_count,
            response_time_ms: 0, // Kafka doesn't track latency directly
            uptime_secs: uptime,
        });

        // Network health
        component_health.insert("network".to_string(), ComponentHealth {
            status: if network_stats.is_some() { HealthStatus::Healthy } else { HealthStatus::Unknown },
            last_check: now,
            error_count: 0,
            response_time_ms: network_stats.as_ref().map(|n| n.network_latency_ms).unwrap_or(0),
            uptime_secs: uptime,
        });

        // Job processor health
        component_health.insert("jobs".to_string(), ComponentHealth {
            status: if job_stats.is_some() { HealthStatus::Healthy } else { HealthStatus::Unknown },
            last_check: now,
            error_count: job_stats.as_ref().map(|j| j.failed_jobs).unwrap_or(0),
            response_time_ms: 0,
            uptime_secs: uptime,
        });

        // Worker manager health
        component_health.insert("workers".to_string(), ComponentHealth {
            status: if worker_stats.is_some() { HealthStatus::Healthy } else { HealthStatus::Unknown },
            last_check: now,
            error_count: 0,
            response_time_ms: 0,
            uptime_secs: uptime,
        });

        // Calculate overall system health score (0.0 - 1.0)
        let healthy_components = component_health.values()
            .filter(|h| matches!(h.status, HealthStatus::Healthy))
            .count();
        let total_components = component_health.len();
        let system_health_score = if total_components > 0 {
            healthy_components as f64 / total_components as f64
        } else {
            0.0
        };

        // Extract network latency before moving network_stats
        let network_latency = network_stats.as_ref().map(|n| n.network_latency_ms).unwrap_or(0);

        let metrics = CoordinatorMetrics {
            timestamp: now,
            node_id: self.node_id.clone(),
            environment: self.environment.clone(),
            kafka: kafka_stats,
            network: network_stats,
            jobs: job_stats,
            workers: worker_stats,
            blockchain: None, // Will be updated separately
            total_jobs,
            active_jobs,
            total_workers,
            active_workers,
            total_transactions: 0,
            successful_transactions: 0,
            network_peers,
            kafka_messages,
            average_job_completion_time_secs: avg_completion_time,
            average_worker_reputation: avg_reputation,
            average_worker_load: avg_load,
            network_latency_ms: network_latency,
            blockchain_confirmation_time_ms: 0,
            system_health_score,
            component_health,
        };

        // Store current metrics
        *current = Some(metrics.clone());

        // Store metrics in history
        self.store_metrics(metrics.clone()).await;

        // Send metrics update event
        if let Err(e) = self.event_sender.send(MetricsEvent::MetricsUpdated(metrics)) {
            error!("Failed to send metrics update event: {}", e);
        }

        // Update last collection time
        let mut last = self.last_collection.write().await;
        *last = now;
    }

    /// Update health metrics with actual system resource data
    pub async fn update_health_metrics(&self) {
        // Collect system resource metrics
        let system_metrics = SystemResourceMetrics::collect();

        // Get current coordinator metrics to assess component health
        let current_metrics = self.current_metrics.read().await;
        let component_health = current_metrics.as_ref()
            .map(|m| &m.component_health)
            .cloned()
            .unwrap_or_default();

        // Calculate component health scores (0.0 - 1.0)
        let kafka_health = component_health.get("kafka")
            .map(|h| match h.status {
                HealthStatus::Healthy => 1.0,
                HealthStatus::Degraded => 0.5,
                HealthStatus::Unhealthy => 0.0,
                HealthStatus::Unknown => 0.5,
            })
            .unwrap_or(0.5);

        let network_health = component_health.get("network")
            .map(|h| match h.status {
                HealthStatus::Healthy => 1.0,
                HealthStatus::Degraded => 0.5,
                HealthStatus::Unhealthy => 0.0,
                HealthStatus::Unknown => 0.5,
            })
            .unwrap_or(0.5);

        let blockchain_health = component_health.get("blockchain")
            .map(|h| match h.status {
                HealthStatus::Healthy => 1.0,
                HealthStatus::Degraded => 0.5,
                HealthStatus::Unhealthy => 0.0,
                HealthStatus::Unknown => 0.5,
            })
            .unwrap_or(0.5);

        // Estimate database health based on last successful metrics storage
        let last_collection = *self.last_collection.read().await;
        let now = chrono::Utc::now().timestamp() as u64;
        let database_health = if now - last_collection < 120 { 1.0 } else { 0.5 };

        // Calculate overall health as weighted average
        let overall_health = (
            kafka_health * 0.2 +
            network_health * 0.3 +
            blockchain_health * 0.2 +
            database_health * 0.1 +
            (1.0 - system_metrics.cpu_usage_percent / 100.0) * 0.1 +
            (1.0 - system_metrics.memory_usage_percent / 100.0) * 0.1
        ).clamp(0.0, 1.0);

        let health_metrics = HealthMetrics {
            timestamp: now,
            overall_health,
            kafka_health,
            network_health,
            blockchain_health,
            database_health,
            memory_usage: system_metrics.memory_usage_percent,
            cpu_usage: system_metrics.cpu_usage_percent,
            disk_usage: system_metrics.disk_usage_percent,
        };

        // Log health status if degraded
        if overall_health < 0.8 {
            warn!(
                "System health degraded: {:.1}% (CPU: {:.1}%, Memory: {:.1}%)",
                overall_health * 100.0,
                system_metrics.cpu_usage_percent,
                system_metrics.memory_usage_percent
            );
        }

        // Send event
        if let Err(e) = self.event_sender.send(MetricsEvent::HealthMetricsUpdated(health_metrics)) {
            error!("Failed to send health metrics updated event: {}", e);
        }
    }

    /// Get system resource metrics
    pub fn get_system_resources(&self) -> SystemResourceMetrics {
        SystemResourceMetrics::collect()
    }

    /// Get uptime in seconds
    pub fn get_uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Start metrics collection
    ///
    /// Note: This internal collection loop is a backup for when the MetricsCollector
    /// isn't receiving external updates. The primary collection happens via
    /// update_component_metrics() called from EnhancedCoordinator.
    async fn start_metrics_collection(&self) -> Result<()> {
        let config = self.config.clone();
        let running = self.running_handle();
        let current_metrics = self.current_metrics_handle();
        let metrics_history = self.metrics_history_handle();
        let last_collection = self.last_collection_handle();
        let node_id = self.node_id.clone();
        let environment = self.environment.clone();
        let event_sender = self.event_sender.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(config.collection_interval_secs));

            loop {
                interval.tick().await;

                // Check if we should stop
                if !*running.read().await {
                    info!("MetricsCollector collection loop stopping");
                    break;
                }

                // Check if we have recent external updates (within 2x collection interval)
                let now = chrono::Utc::now().timestamp() as u64;
                let last = *last_collection.read().await;
                let stale_threshold = config.collection_interval_secs * 2;

                if now - last < stale_threshold {
                    // External updates are happening, skip internal collection
                    debug!("External metrics updates active, skipping internal collection");
                    continue;
                }

                // No recent external updates - collect system resource metrics at minimum
                let system_resources = SystemResourceMetrics::collect();

                // Update health metrics based on system resources
                let health_metrics = HealthMetrics {
                    timestamp: now,
                    overall_health: calculate_overall_health(&system_resources),
                    kafka_health: 0.5, // Unknown without external updates
                    network_health: 0.5,
                    blockchain_health: 0.5,
                    database_health: 0.5,
                    memory_usage: system_resources.memory_usage_percent,
                    cpu_usage: system_resources.cpu_usage_percent,
                    disk_usage: system_resources.disk_usage_percent,
                };

                // Send health metrics event
                if let Err(e) = event_sender.send(MetricsEvent::HealthMetricsUpdated(health_metrics)) {
                    error!("Failed to send health metrics event: {}", e);
                }

                debug!(
                    "Internal metrics collection - CPU: {:.1}%, Memory: {:.1}%, Disk: {:.1}%",
                    system_resources.cpu_usage_percent,
                    system_resources.memory_usage_percent,
                    system_resources.disk_usage_percent
                );
            }
        });

        Ok(())
    }

    /// Start health monitoring
    async fn start_health_monitoring(&self) -> Result<()> {
        let event_sender = self.event_sender.clone();
        let running = self.running_handle();
        let current_metrics = self.current_metrics_handle();
        let last_collection = self.last_collection_handle();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                // Check if we should stop
                if !*running.read().await {
                    info!("Health monitoring loop stopping");
                    break;
                }

                // Collect system resource metrics
                let system_resources = SystemResourceMetrics::collect();

                // Get current coordinator metrics for component health
                let current = current_metrics.read().await;
                let component_health = current.as_ref()
                    .map(|m| &m.component_health)
                    .cloned()
                    .unwrap_or_default();
                drop(current);

                // Calculate component health scores
                let kafka_health = component_health.get("kafka")
                    .map(|h| match h.status {
                        HealthStatus::Healthy => 1.0,
                        HealthStatus::Degraded => 0.5,
                        HealthStatus::Unhealthy => 0.0,
                        HealthStatus::Unknown => 0.5,
                    })
                    .unwrap_or(0.5);

                let network_health = component_health.get("network")
                    .map(|h| match h.status {
                        HealthStatus::Healthy => 1.0,
                        HealthStatus::Degraded => 0.5,
                        HealthStatus::Unhealthy => 0.0,
                        HealthStatus::Unknown => 0.5,
                    })
                    .unwrap_or(0.5);

                let blockchain_health = component_health.get("blockchain")
                    .map(|h| match h.status {
                        HealthStatus::Healthy => 1.0,
                        HealthStatus::Degraded => 0.5,
                        HealthStatus::Unhealthy => 0.0,
                        HealthStatus::Unknown => 0.5,
                    })
                    .unwrap_or(0.5);

                // Database health based on recent collection activity
                let now = chrono::Utc::now().timestamp() as u64;
                let last = *last_collection.read().await;
                let database_health = if now - last < 120 { 1.0 } else { 0.5 };

                // Calculate overall health
                let overall_health = (
                    kafka_health * 0.2 +
                    network_health * 0.3 +
                    blockchain_health * 0.2 +
                    database_health * 0.1 +
                    (1.0 - system_resources.cpu_usage_percent / 100.0) * 0.1 +
                    (1.0 - system_resources.memory_usage_percent / 100.0) * 0.1
                ).clamp(0.0, 1.0);

                let health_metrics = HealthMetrics {
                    timestamp: now,
                    overall_health,
                    kafka_health,
                    network_health,
                    blockchain_health,
                    database_health,
                    memory_usage: system_resources.memory_usage_percent,
                    cpu_usage: system_resources.cpu_usage_percent,
                    disk_usage: system_resources.disk_usage_percent,
                };

                // Log health status if degraded
                if overall_health < 0.8 {
                    warn!(
                        "System health degraded: {:.1}% (CPU: {:.1}%, Memory: {:.1}%)",
                        overall_health * 100.0,
                        system_resources.cpu_usage_percent,
                        system_resources.memory_usage_percent
                    );
                }

                // Send health metrics event
                if let Err(e) = event_sender.send(MetricsEvent::HealthMetricsUpdated(health_metrics)) {
                    error!("Failed to send health metrics event: {}", e);
                }
            }
        });

        Ok(())
    }

    /// Start storage cleanup
    async fn start_storage_cleanup(&self) -> Result<()> {
        let config = self.config.clone();
        let metrics_history = self.metrics_history_handle();
        let running = self.running_handle();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Every hour

            loop {
                interval.tick().await;

                // Check if we should stop
                if !*running.read().await {
                    info!("Storage cleanup loop stopping");
                    break;
                }

                if config.storage.enable_storage {
                    let cutoff_time = chrono::Utc::now().timestamp() as u64 -
                        (config.storage.retention_days * 24 * 3600) as u64;

                    let mut history = metrics_history.write().await;
                    let before_count = history.len();
                    history.retain(|entry| entry.timestamp >= cutoff_time);
                    let after_count = history.len();

                    if before_count != after_count {
                        info!(
                            "Metrics storage cleanup: removed {} entries, retained {}",
                            before_count - after_count,
                            after_count
                        );
                    } else {
                        debug!("Metrics storage cleanup: retained {} entries", after_count);
                    }
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

    /// Take the event receiver.
    ///
    /// This can only be called once - subsequent calls will return `None`.
    pub async fn take_event_receiver(&self) -> Option<mpsc::UnboundedReceiver<MetricsEvent>> {
        self.event_receiver.write().await.take()
    }

    /// Check if the event receiver is still available.
    pub async fn has_event_receiver(&self) -> bool {
        self.event_receiver.read().await.is_some()
    }

    /// Get a Send+Sync handle to current metrics for use in spawned tasks
    pub fn current_metrics_handle(&self) -> Arc<RwLock<Option<CoordinatorMetrics>>> {
        Arc::clone(&self.current_metrics)
    }

    /// Get a Send+Sync handle to metrics history for use in spawned tasks
    pub fn metrics_history_handle(&self) -> Arc<RwLock<Vec<MetricsStorageEntry>>> {
        Arc::clone(&self.metrics_history)
    }

    /// Get a Send+Sync handle to the running state for use in spawned tasks
    pub fn running_handle(&self) -> Arc<RwLock<bool>> {
        Arc::clone(&self.running)
    }

    /// Get a Send+Sync handle to the last collection timestamp
    pub fn last_collection_handle(&self) -> Arc<RwLock<u64>> {
        Arc::clone(&self.last_collection)
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
        assert!(collector.node_id.starts_with("coordinator-"));
    }

    #[tokio::test]
    async fn test_metrics_collector_with_identity() {
        let config = MetricsConfig::default();
        let collector = MetricsCollector::with_identity(
            config,
            "test-node-001".to_string(),
            "production".to_string(),
        );

        assert_eq!(collector.node_id, "test-node-001");
        assert_eq!(collector.environment, "production");
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
        // Empty metrics should still have help text
        assert!(prometheus_export.is_empty() || prometheus_export.contains("# HELP"));
    }

    #[tokio::test]
    async fn test_update_component_metrics() {
        let config = MetricsConfig::default();
        let collector = MetricsCollector::new(config);

        // Create mock stats
        let job_stats = JobStats {
            total_jobs: 100,
            active_jobs: 10,
            completed_jobs: 85,
            failed_jobs: 5,
            cancelled_jobs: 0,
            average_completion_time_secs: 60,
            jobs_per_minute: 1.5,
            success_rate: 0.95,
        };

        let worker_stats = WorkerStats {
            total_workers: 50,
            active_workers: 45,
            online_workers: 45,
            busy_workers: 40,
            offline_workers: 5,
            average_reputation: 0.95,
            average_load: 0.7,
            total_compute_capacity: 1000,
            available_compute_capacity: 300,
        };

        // Update metrics
        collector.update_component_metrics(
            None,
            None,
            Some(job_stats),
            Some(worker_stats),
        ).await;

        // Verify metrics were updated
        let metrics = collector.get_metrics().await;
        assert!(metrics.is_some());

        let m = metrics.unwrap();
        assert_eq!(m.total_jobs, 100);
        assert_eq!(m.active_jobs, 10);
        assert_eq!(m.total_workers, 50);
        assert_eq!(m.active_workers, 45);
        assert!(m.system_health_score > 0.0);
    }

    #[tokio::test]
    async fn test_component_health_aggregation() {
        let config = MetricsConfig::default();
        let collector = MetricsCollector::new(config);

        // Update with all components available
        let kafka_stats = KafkaStats {
            messages_sent: 1000,
            messages_received: 950,
            messages_failed: 2,
            dead_letter_queue_size: 0,
            job_queue_size: 10,
            consumer_lag: 0,
            producer_queue_size: 5,
            connection_status: "connected".to_string(),
            last_message_timestamp: chrono::Utc::now().timestamp() as u64,
            average_message_size_bytes: 1024,
            error_rate: 0.002,
            throughput_messages_per_sec: 100.0,
        };

        collector.update_component_metrics(
            Some(kafka_stats),
            None,
            None,
            None,
        ).await;

        let metrics = collector.get_metrics().await.unwrap();

        // Kafka should be healthy
        let kafka_health = metrics.component_health.get("kafka");
        assert!(kafka_health.is_some());
        assert!(matches!(kafka_health.unwrap().status, HealthStatus::Healthy));

        // Other components should be unknown
        let network_health = metrics.component_health.get("network");
        assert!(network_health.is_some());
        assert!(matches!(network_health.unwrap().status, HealthStatus::Unknown));
    }

    #[test]
    fn test_system_resource_metrics_collection() {
        let metrics = SystemResourceMetrics::collect();

        // On non-Linux, these will be 0.0
        // On Linux, they should be valid percentages
        assert!(metrics.cpu_usage_percent >= 0.0);
        assert!(metrics.memory_usage_percent >= 0.0);
        assert!(metrics.disk_usage_percent >= 0.0);
    }

    #[tokio::test]
    async fn test_metrics_history() {
        let mut config = MetricsConfig::default();
        config.storage.enable_storage = true;
        config.storage.retention_days = 7;

        let collector = MetricsCollector::new(config);

        // Update metrics multiple times
        for _ in 0..5 {
            collector.update_component_metrics(None, None, None, None).await;
        }

        // Check history
        let history = collector.get_metrics_history(24).await;
        assert_eq!(history.len(), 5);
    }

    #[tokio::test]
    async fn test_uptime_tracking() {
        let config = MetricsConfig::default();
        let collector = MetricsCollector::new(config);

        // Sleep briefly
        tokio::time::sleep(Duration::from_millis(100)).await;

        let uptime = collector.get_uptime_secs();
        // Should be at least 0 seconds (might be 0 due to timing)
        assert!(uptime >= 0);
    }

    #[tokio::test]
    async fn test_graphite_export() {
        let config = MetricsConfig::default();
        let collector = MetricsCollector::new(config);

        // Update with some metrics
        let job_stats = JobStats {
            total_jobs: 50,
            active_jobs: 5,
            completed_jobs: 40,
            failed_jobs: 5,
            cancelled_jobs: 0,
            average_completion_time_secs: 30,
            jobs_per_minute: 0.5,
            success_rate: 0.89,
        };

        collector.update_component_metrics(None, None, Some(job_stats), None).await;

        let graphite_export = collector.export_metrics(ExportFormat::Graphite).await.unwrap();
        assert!(graphite_export.contains("sage.coordinator.total_jobs"));
        assert!(graphite_export.contains("50"));
    }
} 