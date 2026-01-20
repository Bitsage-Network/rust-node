//! Health Check Endpoints
//!
//! Provides comprehensive health monitoring for the BitSage coordinator,
//! including database, GPU, worker, and system resource checks.

use axum::{
    extract::State,
    http::StatusCode,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, warn};
use sqlx::PgPool;

// ============================================================================
// Health Check Types
// ============================================================================

/// Overall system health status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// All systems operational
    Healthy,
    /// Some non-critical issues detected
    Degraded,
    /// Critical issues detected
    Unhealthy,
}

/// Individual component health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component name
    pub name: String,
    /// Component status
    pub status: HealthStatus,
    /// Optional status message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Response time in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_time_ms: Option<u64>,
    /// Last check timestamp
    pub last_check: u64,
}

/// Complete health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResponse {
    /// Overall system status
    pub status: HealthStatus,
    /// Timestamp of the health check
    pub timestamp: u64,
    /// Coordinator version
    pub version: String,
    /// Uptime in seconds
    pub uptime_seconds: u64,
    /// Individual component health checks
    pub components: Vec<ComponentHealth>,
    /// System metrics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<SystemMetrics>,
}

/// System resource metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    /// Memory usage in MB
    pub memory_used_mb: u64,
    /// Memory total in MB
    pub memory_total_mb: u64,
    /// Memory usage percentage
    pub memory_usage_percent: f64,
    /// Number of active workers
    pub active_workers: usize,
    /// Number of pending jobs
    pub pending_jobs: usize,
    /// Number of completed jobs (last hour)
    pub completed_jobs_1h: usize,
    /// WebSocket subscriber count
    #[serde(skip_serializing_if = "Option::is_none")]
    pub websocket_subscribers: Option<usize>,
    /// Last indexed block number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_indexed_block: Option<u64>,
    /// Rate limiter active buckets
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limiter_buckets: Option<usize>,
}

/// Readiness check response (simpler than health check)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessResponse {
    /// Ready to accept requests?
    pub ready: bool,
    /// Reason if not ready
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Liveness check response (simplest check)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessResponse {
    /// Service is alive
    pub alive: bool,
}

// ============================================================================
// Health Check State
// ============================================================================

/// Coordinator state for worker health checks
#[derive(Debug, Clone)]
pub struct CoordinatorHealthState {
    /// Active job count
    pub active_jobs: usize,
    /// Pending job count
    pub pending_jobs: usize,
    /// Connected worker count
    pub connected_workers: usize,
    /// Active workers (currently processing)
    pub active_workers: usize,
    /// Total completed jobs in last hour
    pub completed_jobs_1h: usize,
}

/// Extended coordinator state for validator dashboard health checks
pub struct ExtendedHealthState {
    /// Base coordinator state
    pub coordinator: CoordinatorHealthState,
    /// WebSocket subscriber count
    pub websocket_subscribers: Option<usize>,
    /// Last indexed block
    pub last_indexed_block: Option<u64>,
    /// Rate limiter bucket count
    pub rate_limiter_buckets: Option<usize>,
    /// StarkNet RPC URL for health check
    pub rpc_url: Option<String>,
}

/// Health checker that monitors system components
pub struct HealthChecker {
    start_time: SystemTime,
    version: String,
    last_health_check: Arc<RwLock<Option<HealthCheckResponse>>>,
    /// Optional database pool for health checks
    db_pool: Option<PgPool>,
    /// Optional coordinator state callback
    coordinator_state: Arc<RwLock<Option<CoordinatorHealthState>>>,
    /// Extended state for validator dashboard
    extended_state: Arc<RwLock<Option<ExtendedHealthState>>>,
}

impl HealthChecker {
    /// Create a new health checker
    pub fn new(version: String) -> Self {
        Self {
            start_time: SystemTime::now(),
            version,
            last_health_check: Arc::new(RwLock::new(None)),
            db_pool: None,
            coordinator_state: Arc::new(RwLock::new(None)),
            extended_state: Arc::new(RwLock::new(None)),
        }
    }

    /// Create a health checker with database pool
    pub fn with_db(version: String, db_pool: PgPool) -> Self {
        Self {
            start_time: SystemTime::now(),
            version,
            last_health_check: Arc::new(RwLock::new(None)),
            db_pool: Some(db_pool),
            coordinator_state: Arc::new(RwLock::new(None)),
            extended_state: Arc::new(RwLock::new(None)),
        }
    }

    /// Update coordinator state for health checks
    pub async fn update_coordinator_state(&self, state: CoordinatorHealthState) {
        *self.coordinator_state.write().await = Some(state);
    }

    /// Update extended state for validator dashboard health checks
    pub async fn update_extended_state(&self, state: ExtendedHealthState) {
        // Also update the basic coordinator state
        *self.coordinator_state.write().await = Some(state.coordinator.clone());
        *self.extended_state.write().await = Some(state);
    }

    /// Get uptime in seconds
    fn uptime_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(self.start_time)
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }

    /// Perform complete health check
    pub async fn check_health(&self) -> HealthCheckResponse {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let uptime_seconds = self.uptime_seconds();

        let mut components = Vec::new();

        // Check database connectivity
        components.push(self.check_database().await);

        // Check GPU availability
        components.push(self.check_gpu().await);

        // Check system resources
        components.push(self.check_system_resources().await);

        // Check worker connectivity
        components.push(self.check_workers().await);

        // Check blockchain/RPC connectivity
        components.push(self.check_blockchain().await);

        // Check indexer sync status
        components.push(self.check_indexer().await);

        // Determine overall status
        let status = if components.iter().any(|c| c.status == HealthStatus::Unhealthy) {
            HealthStatus::Unhealthy
        } else if components.iter().any(|c| c.status == HealthStatus::Degraded) {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        // Gather system metrics
        let metrics = self.gather_system_metrics().await;

        let response = HealthCheckResponse {
            status,
            timestamp,
            version: self.version.clone(),
            uptime_seconds,
            components,
            metrics: Some(metrics),
        };

        // Cache the result
        *self.last_health_check.write().await = Some(response.clone());

        response
    }

    /// Check database connectivity
    async fn check_database(&self) -> ComponentHealth {
        let start = std::time::Instant::now();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let (status, message) = if let Some(ref pool) = self.db_pool {
            // Execute a simple query to test connectivity
            match sqlx::query("SELECT 1 as health_check")
                .fetch_one(pool)
                .await
            {
                Ok(_) => {
                    // Also check pool statistics
                    let pool_size = pool.size();
                    let idle_connections = pool.num_idle();
                    (
                        HealthStatus::Healthy,
                        Some(format!(
                            "Database OK (pool: {}/{} connections)",
                            pool_size - idle_connections as u32,
                            pool_size
                        )),
                    )
                }
                Err(e) => {
                    warn!("Database health check failed: {}", e);
                    (
                        HealthStatus::Unhealthy,
                        Some(format!("Database connection failed: {}", e)),
                    )
                }
            }
        } else {
            // No database pool configured
            (
                HealthStatus::Degraded,
                Some("Database pool not configured".to_string()),
            )
        };

        let response_time_ms = start.elapsed().as_millis() as u64;

        // Warn if response time is too slow
        let status = if response_time_ms > 5000 && status == HealthStatus::Healthy {
            HealthStatus::Degraded
        } else {
            status
        };

        ComponentHealth {
            name: "database".to_string(),
            status,
            message,
            response_time_ms: Some(response_time_ms),
            last_check: timestamp,
        }
    }

    /// Check GPU availability
    async fn check_gpu(&self) -> ComponentHealth {
        use crate::obelysk::stwo_adapter::is_gpu_available;

        let start = std::time::Instant::now();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let gpu_available = is_gpu_available();

        let (status, message) = if gpu_available {
            (HealthStatus::Healthy, Some("GPU acceleration available".to_string()))
        } else {
            (HealthStatus::Degraded, Some("No GPU available, using CPU fallback".to_string()))
        };

        let response_time_ms = start.elapsed().as_millis() as u64;

        ComponentHealth {
            name: "gpu".to_string(),
            status,
            message,
            response_time_ms: Some(response_time_ms),
            last_check: timestamp,
        }
    }

    /// Check system resources
    async fn check_system_resources(&self) -> ComponentHealth {
        let start = std::time::Instant::now();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check available system memory using sys-info
        #[cfg(target_os = "linux")]
        let (status, message) = {
            match sys_info::mem_info() {
                Ok(mem) => {
                    let total_mb = mem.total / 1024;
                    let avail_mb = mem.avail / 1024;
                    let usage_percent = ((total_mb - avail_mb) as f64 / total_mb as f64) * 100.0;

                    if usage_percent > 90.0 {
                        (
                            HealthStatus::Unhealthy,
                            Some(format!("Critical: Memory usage at {:.1}%", usage_percent)),
                        )
                    } else if usage_percent > 80.0 {
                        (
                            HealthStatus::Degraded,
                            Some(format!("Warning: Memory usage at {:.1}%", usage_percent)),
                        )
                    } else {
                        (
                            HealthStatus::Healthy,
                            Some(format!("Memory usage: {:.1}%", usage_percent)),
                        )
                    }
                }
                Err(e) => {
                    warn!("Failed to get memory info: {}", e);
                    (
                        HealthStatus::Degraded,
                        Some("Unable to read system memory".to_string()),
                    )
                }
            }
        };

        #[cfg(not(target_os = "linux"))]
        let (status, message) = (
            HealthStatus::Healthy,
            Some("System resources OK (limited metrics on this platform)".to_string()),
        );

        let response_time_ms = start.elapsed().as_millis() as u64;

        ComponentHealth {
            name: "system_resources".to_string(),
            status,
            message,
            response_time_ms: Some(response_time_ms),
            last_check: timestamp,
        }
    }

    /// Check worker node connectivity
    async fn check_workers(&self) -> ComponentHealth {
        let start = std::time::Instant::now();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let (status, message) = if let Some(ref state) = *self.coordinator_state.read().await {
            if state.connected_workers == 0 {
                (
                    HealthStatus::Unhealthy,
                    Some("No workers connected".to_string()),
                )
            } else if state.active_workers == 0 && state.pending_jobs > 0 {
                (
                    HealthStatus::Degraded,
                    Some(format!(
                        "Workers idle with {} pending jobs ({} connected)",
                        state.pending_jobs, state.connected_workers
                    )),
                )
            } else {
                (
                    HealthStatus::Healthy,
                    Some(format!(
                        "{} workers connected, {} active, {} jobs pending",
                        state.connected_workers, state.active_workers, state.pending_jobs
                    )),
                )
            }
        } else {
            // No coordinator state available - try database fallback
            if let Some(ref pool) = self.db_pool {
                match sqlx::query(
                    r#"
                    SELECT
                        COUNT(*) FILTER (WHERE status = 'active') as connected,
                        COUNT(*) FILTER (WHERE status = 'busy') as active
                    FROM workers
                    WHERE last_seen > NOW() - INTERVAL '5 minutes'
                    "#
                )
                .fetch_optional(pool)
                .await
                {
                    Ok(Some(row)) => {
                        use sqlx::Row;
                        let connected: i64 = row.try_get("connected").unwrap_or(0);
                        let active: i64 = row.try_get("active").unwrap_or(0);

                        if connected == 0 {
                            (
                                HealthStatus::Degraded,
                                Some("No workers seen recently (from DB)".to_string()),
                            )
                        } else {
                            (
                                HealthStatus::Healthy,
                                Some(format!(
                                    "{} workers connected, {} active (from DB)",
                                    connected, active
                                )),
                            )
                        }
                    }
                    Ok(None) | Err(_) => (
                        HealthStatus::Degraded,
                        Some("Could not query worker status".to_string()),
                    ),
                }
            } else {
                (
                    HealthStatus::Degraded,
                    Some("Worker state not available".to_string()),
                )
            }
        };

        let response_time_ms = start.elapsed().as_millis() as u64;

        ComponentHealth {
            name: "workers".to_string(),
            status,
            message,
            response_time_ms: Some(response_time_ms),
            last_check: timestamp,
        }
    }

    /// Check blockchain/RPC connectivity
    async fn check_blockchain(&self) -> ComponentHealth {
        let start = std::time::Instant::now();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let (status, message) = if let Some(ref state) = *self.extended_state.read().await {
            if let Some(ref rpc_url) = state.rpc_url {
                // Try to make a simple RPC call to check connectivity
                match reqwest::Client::new()
                    .post(rpc_url)
                    .json(&serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "starknet_blockNumber",
                        "params": [],
                        "id": 1
                    }))
                    .timeout(std::time::Duration::from_secs(10))
                    .send()
                    .await
                {
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(json) = resp.json::<serde_json::Value>().await {
                            if let Some(block) = json.get("result") {
                                (
                                    HealthStatus::Healthy,
                                    Some(format!("StarkNet RPC OK (block: {})", block)),
                                )
                            } else {
                                (HealthStatus::Healthy, Some("StarkNet RPC connected".to_string()))
                            }
                        } else {
                            (HealthStatus::Healthy, Some("StarkNet RPC connected".to_string()))
                        }
                    }
                    Ok(resp) => {
                        (
                            HealthStatus::Degraded,
                            Some(format!("StarkNet RPC error: {}", resp.status())),
                        )
                    }
                    Err(e) => {
                        warn!("StarkNet RPC health check failed: {}", e);
                        (
                            HealthStatus::Unhealthy,
                            Some(format!("StarkNet RPC unreachable: {}", e)),
                        )
                    }
                }
            } else {
                (HealthStatus::Degraded, Some("RPC URL not configured".to_string()))
            }
        } else {
            // No extended state - check database for last indexed block as proxy
            if let Some(ref pool) = self.db_pool {
                match sqlx::query("SELECT MAX(block_number) as latest FROM blockchain_events")
                    .fetch_optional(pool)
                    .await
                {
                    Ok(Some(row)) => {
                        use sqlx::Row;
                        let block: Option<i64> = row.try_get("latest").ok();
                        if let Some(b) = block {
                            (HealthStatus::Healthy, Some(format!("Indexer at block {}", b)))
                        } else {
                            (HealthStatus::Degraded, Some("No blocks indexed yet".to_string()))
                        }
                    }
                    _ => (HealthStatus::Degraded, Some("Could not query blockchain status".to_string())),
                }
            } else {
                (HealthStatus::Degraded, Some("Blockchain health check not configured".to_string()))
            }
        };

        let response_time_ms = start.elapsed().as_millis() as u64;

        ComponentHealth {
            name: "blockchain".to_string(),
            status,
            message,
            response_time_ms: Some(response_time_ms),
            last_check: timestamp,
        }
    }

    /// Check indexer sync status
    async fn check_indexer(&self) -> ComponentHealth {
        let start = std::time::Instant::now();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let (status, message) = if let Some(ref pool) = self.db_pool {
            // Query indexer state
            match sqlx::query(
                r#"
                SELECT
                    last_indexed_block,
                    last_indexed_at,
                    EXTRACT(EPOCH FROM (NOW() - last_indexed_at)) as seconds_behind
                FROM indexer_state
                ORDER BY last_indexed_at DESC
                LIMIT 1
                "#
            )
            .fetch_optional(pool)
            .await
            {
                Ok(Some(row)) => {
                    use sqlx::Row;
                    let block: i64 = row.try_get("last_indexed_block").unwrap_or(0);
                    let seconds_behind: f64 = row.try_get("seconds_behind").unwrap_or(0.0);

                    if seconds_behind > 300.0 {
                        // More than 5 minutes behind
                        (
                            HealthStatus::Unhealthy,
                            Some(format!("Indexer stalled at block {} ({:.0}s behind)", block, seconds_behind)),
                        )
                    } else if seconds_behind > 60.0 {
                        // More than 1 minute behind
                        (
                            HealthStatus::Degraded,
                            Some(format!("Indexer slow at block {} ({:.0}s behind)", block, seconds_behind)),
                        )
                    } else {
                        (
                            HealthStatus::Healthy,
                            Some(format!("Indexer synced at block {} ({:.0}s ago)", block, seconds_behind)),
                        )
                    }
                }
                Ok(None) => {
                    (HealthStatus::Degraded, Some("Indexer not initialized".to_string()))
                }
                Err(e) => {
                    debug!("Could not query indexer state: {}", e);
                    (HealthStatus::Degraded, Some("Indexer state unknown".to_string()))
                }
            }
        } else {
            (HealthStatus::Degraded, Some("Database not configured for indexer check".to_string()))
        };

        let response_time_ms = start.elapsed().as_millis() as u64;

        ComponentHealth {
            name: "indexer".to_string(),
            status,
            message,
            response_time_ms: Some(response_time_ms),
            last_check: timestamp,
        }
    }

    /// Gather system metrics
    async fn gather_system_metrics(&self) -> SystemMetrics {
        #[cfg(target_os = "linux")]
        let (memory_used_mb, memory_total_mb, memory_usage_percent) = {
            match sys_info::mem_info() {
                Ok(mem) => {
                    let total_mb = mem.total / 1024;
                    let avail_mb = mem.avail / 1024;
                    let used_mb = total_mb - avail_mb;
                    let usage = (used_mb as f64 / total_mb as f64) * 100.0;
                    (used_mb, total_mb, usage)
                }
                Err(_) => (0, 0, 0.0),
            }
        };

        #[cfg(not(target_os = "linux"))]
        let (memory_used_mb, memory_total_mb, memory_usage_percent) = (0, 0, 0.0);

        // Get job/worker counts from coordinator state or database
        let (active_workers, pending_jobs, completed_jobs_1h) = if let Some(ref state) =
            *self.coordinator_state.read().await
        {
            (
                state.active_workers,
                state.pending_jobs,
                state.completed_jobs_1h,
            )
        } else if let Some(ref pool) = self.db_pool {
            // Fallback to database queries
            let counts = sqlx::query(
                r#"
                SELECT
                    (SELECT COUNT(*) FROM workers WHERE status = 'active' AND last_seen > NOW() - INTERVAL '5 minutes') as active_workers,
                    (SELECT COUNT(*) FROM jobs WHERE status = 'pending') as pending_jobs,
                    (SELECT COUNT(*) FROM jobs WHERE status = 'completed' AND completed_at > NOW() - INTERVAL '1 hour') as completed_jobs
                "#
            )
            .fetch_optional(pool)
            .await;

            match counts {
                Ok(Some(row)) => {
                    use sqlx::Row;
                    let workers: i64 = row.try_get("active_workers").unwrap_or(0);
                    let pending: i64 = row.try_get("pending_jobs").unwrap_or(0);
                    let completed: i64 = row.try_get("completed_jobs").unwrap_or(0);
                    (workers as usize, pending as usize, completed as usize)
                }
                _ => (0, 0, 0),
            }
        } else {
            (0, 0, 0)
        };

        // Get extended state metrics
        let (websocket_subscribers, last_indexed_block, rate_limiter_buckets) =
            if let Some(ref ext) = *self.extended_state.read().await {
                (
                    ext.websocket_subscribers,
                    ext.last_indexed_block,
                    ext.rate_limiter_buckets,
                )
            } else {
                (None, None, None)
            };

        SystemMetrics {
            memory_used_mb,
            memory_total_mb,
            memory_usage_percent,
            active_workers,
            pending_jobs,
            completed_jobs_1h,
            websocket_subscribers,
            last_indexed_block,
            rate_limiter_buckets,
        }
    }

    /// Check if system is ready to accept requests
    pub async fn check_readiness(&self) -> ReadinessResponse {
        // Simple readiness check: system has been up for at least 5 seconds
        let uptime = self.uptime_seconds();

        if uptime < 5 {
            return ReadinessResponse {
                ready: false,
                reason: Some(format!("System still initializing (uptime: {}s)", uptime)),
            };
        }

        // Check if any critical components are unhealthy
        if let Some(last_check) = self.last_health_check.read().await.as_ref() {
            if last_check.status == HealthStatus::Unhealthy {
                return ReadinessResponse {
                    ready: false,
                    reason: Some("System health check failed".to_string()),
                };
            }
        }

        ReadinessResponse {
            ready: true,
            reason: None,
        }
    }

    /// Simple liveness check
    pub async fn check_liveness(&self) -> LivenessResponse {
        LivenessResponse { alive: true }
    }
}

// ============================================================================
// HTTP Handlers
// ============================================================================

/// Handler for /health endpoint
async fn health_handler(State(checker): State<Arc<HealthChecker>>) -> impl axum::response::IntoResponse {
    debug!("Health check requested");

    let health = checker.check_health().await;

    let status_code = match health.status {
        HealthStatus::Healthy => StatusCode::OK,
        HealthStatus::Degraded => StatusCode::OK, // Still return 200 for degraded
        HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    };

    (status_code, Json(health))
}

/// Handler for /health/ready endpoint
async fn readiness_handler(State(checker): State<Arc<HealthChecker>>) -> impl axum::response::IntoResponse {
    debug!("Readiness check requested");

    let readiness = checker.check_readiness().await;

    let status_code = if readiness.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status_code, Json(readiness))
}

/// Handler for /health/live endpoint
async fn liveness_handler(State(checker): State<Arc<HealthChecker>>) -> impl axum::response::IntoResponse {
    let liveness = checker.check_liveness().await;
    (StatusCode::OK, Json(liveness))
}

/// Handler for /stats endpoint - human-readable text stats (Cocoon-style)
async fn stats_handler(State(checker): State<Arc<HealthChecker>>) -> impl axum::response::IntoResponse {
    let health = checker.check_health().await;

    let status_str = match health.status {
        HealthStatus::Healthy => "HEALTHY",
        HealthStatus::Degraded => "DEGRADED",
        HealthStatus::Unhealthy => "UNHEALTHY",
    };

    let uptime_hours = health.uptime_seconds / 3600;
    let uptime_mins = (health.uptime_seconds % 3600) / 60;
    let uptime_secs = health.uptime_seconds % 60;

    let mut output = format!(
        "BitSage Coordinator v{}\n\
         ========================\n\
         Status:  {}\n\
         Uptime:  {}h {}m {}s\n\n",
        health.version, status_str, uptime_hours, uptime_mins, uptime_secs
    );

    // Add component status
    output.push_str("Components:\n");
    for component in &health.components {
        let status_icon = match component.status {
            HealthStatus::Healthy => "[OK]",
            HealthStatus::Degraded => "[WARN]",
            HealthStatus::Unhealthy => "[FAIL]",
        };
        let msg = component.message.as_deref().unwrap_or("");
        let time = component.response_time_ms.map(|ms| format!(" ({}ms)", ms)).unwrap_or_default();
        output.push_str(&format!("  {} {}: {}{}\n", status_icon, component.name, msg, time));
    }

    // Add metrics if available
    if let Some(ref metrics) = health.metrics {
        output.push_str(&format!(
            "\nMetrics:\n\
             Active Workers:     {}\n\
             Pending Jobs:       {}\n\
             Completed (1h):     {}\n\
             Memory Usage:       {:.1}%\n",
            metrics.active_workers,
            metrics.pending_jobs,
            metrics.completed_jobs_1h,
            metrics.memory_usage_percent
        ));
    }

    (StatusCode::OK, output)
}

/// Handler for /status endpoint - JSON status (like /health but simpler)
async fn status_handler(State(checker): State<Arc<HealthChecker>>) -> impl axum::response::IntoResponse {
    let health = checker.check_health().await;

    #[derive(Serialize)]
    struct SimpleStatus {
        status: String,
        version: String,
        uptime_seconds: u64,
        workers_online: usize,
        jobs_pending: usize,
    }

    let (workers_online, jobs_pending) = health.metrics
        .as_ref()
        .map(|m| (m.active_workers, m.pending_jobs))
        .unwrap_or((0, 0));

    let status = SimpleStatus {
        status: match health.status {
            HealthStatus::Healthy => "ok".to_string(),
            HealthStatus::Degraded => "degraded".to_string(),
            HealthStatus::Unhealthy => "error".to_string(),
        },
        version: health.version,
        uptime_seconds: health.uptime_seconds,
        workers_online,
        jobs_pending,
    };

    (StatusCode::OK, Json(status))
}

// ============================================================================
// Router Configuration
// ============================================================================

/// Create health check routes
///
/// Provides the following endpoints:
/// - GET /health - Comprehensive health check (all components, JSON)
/// - GET /health/ready - Readiness probe (is system ready for traffic?)
/// - GET /health/live - Liveness probe (is process alive?)
/// - GET /stats - Human-readable text stats (Cocoon-style)
/// - GET /status - Simple JSON status
pub fn health_routes(version: String) -> Router {
    let checker = Arc::new(HealthChecker::new(version));

    Router::new()
        .route("/health", get(health_handler))
        .route("/health/ready", get(readiness_handler))
        .route("/health/live", get(liveness_handler))
        .route("/stats", get(stats_handler))
        .route("/status", get(status_handler))
        .with_state(checker)
}

/// Create health check routes with database connection
///
/// Same as health_routes but with database health checks enabled
pub fn health_routes_with_db(version: String, db_pool: PgPool) -> (Router, Arc<HealthChecker>) {
    let checker = Arc::new(HealthChecker::with_db(version, db_pool));

    let router = Router::new()
        .route("/health", get(health_handler))
        .route("/health/ready", get(readiness_handler))
        .route("/health/live", get(liveness_handler))
        .route("/stats", get(stats_handler))
        .route("/status", get(status_handler))
        .with_state(checker.clone());

    (router, checker)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_checker_creation() {
        let checker = HealthChecker::new("1.0.0".to_string());
        assert_eq!(checker.version, "1.0.0");
        assert!(checker.uptime_seconds() < 1);
    }

    #[tokio::test]
    async fn test_liveness_check() {
        let checker = HealthChecker::new("1.0.0".to_string());
        let liveness = checker.check_liveness().await;
        assert!(liveness.alive);
    }

    #[tokio::test]
    async fn test_readiness_check_not_ready() {
        let checker = HealthChecker::new("1.0.0".to_string());
        let readiness = checker.check_readiness().await;
        // Should not be ready immediately (needs 5s uptime)
        assert!(!readiness.ready);
        assert!(readiness.reason.is_some());
    }

    #[tokio::test]
    async fn test_health_check() {
        let checker = HealthChecker::new("1.0.0".to_string());
        let health = checker.check_health().await;

        assert!(!health.components.is_empty());
        assert!(health.uptime_seconds < 2);
        assert_eq!(health.version, "1.0.0");
    }

    #[tokio::test]
    async fn test_component_health_serialization() {
        let component = ComponentHealth {
            name: "test".to_string(),
            status: HealthStatus::Healthy,
            message: Some("All good".to_string()),
            response_time_ms: Some(10),
            last_check: 1234567890,
        };

        let json = serde_json::to_string(&component).unwrap();
        assert!(json.contains("\"status\":\"healthy\""));
        assert!(json.contains("\"test\""));
    }
}
