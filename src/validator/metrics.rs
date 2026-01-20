//! Consensus Metrics
//!
//! Prometheus metrics for monitoring SageGuard BFT consensus operations.
//!
//! ## Metrics Exposed
//!
//! ### Counters
//! - `consensus_votes_total` - Total votes submitted (by validator, job_id)
//! - `consensus_rounds_total` - Total consensus rounds (by outcome)
//! - `consensus_fraud_detected_total` - Total fraud cases detected
//! - `consensus_validators_registered_total` - Total validators registered
//! - `consensus_validators_removed_total` - Total validators removed
//! - `consensus_view_changes_total` - Total view changes (leader rotation)
//! - `consensus_persistence_operations_total` - Persistence operations (by operation, status)
//!
//! ### Gauges
//! - `consensus_active_validators` - Current number of active validators
//! - `consensus_pending_votes` - Current pending votes (by job_id)
//! - `consensus_current_view` - Current view number (leader election)
//!
//! ### Histograms
//! - `consensus_vote_duration_seconds` - Time to collect votes
//! - `consensus_finalization_duration_seconds` - Time to finalize consensus
//! - `consensus_persistence_duration_seconds` - Time for persistence operations

use lazy_static::lazy_static;
use prometheus::{
    register_counter_vec, register_gauge, register_gauge_vec, register_histogram_vec,
    CounterVec, Encoder, Gauge, GaugeVec, HistogramVec, TextEncoder,
};

lazy_static! {
    // ========================================================================
    // Counters
    // ========================================================================

    /// Total votes submitted
    pub static ref VOTES_TOTAL: CounterVec = register_counter_vec!(
        "consensus_votes_total",
        "Total number of votes submitted",
        &["validator", "job_id"]
    )
    .unwrap();

    /// Total consensus rounds by outcome
    pub static ref ROUNDS_TOTAL: CounterVec = register_counter_vec!(
        "consensus_rounds_total",
        "Total consensus rounds completed",
        &["outcome"]  // approved, rejected, timeout, fraud_detected
    )
    .unwrap();

    /// Total fraud cases detected
    pub static ref FRAUD_DETECTED_TOTAL: CounterVec = register_counter_vec!(
        "consensus_fraud_detected_total",
        "Total fraud cases detected",
        &["job_id"]
    )
    .unwrap();

    /// Total validators registered
    pub static ref VALIDATORS_REGISTERED_TOTAL: CounterVec = register_counter_vec!(
        "consensus_validators_registered_total",
        "Total validators registered",
        &["validator"]
    )
    .unwrap();

    /// Total validators removed
    pub static ref VALIDATORS_REMOVED_TOTAL: CounterVec = register_counter_vec!(
        "consensus_validators_removed_total",
        "Total validators removed",
        &["validator", "reason"]
    )
    .unwrap();

    /// Total view changes (leader rotation)
    pub static ref VIEW_CHANGES_TOTAL: CounterVec = register_counter_vec!(
        "consensus_view_changes_total",
        "Total view changes (leader rotation)",
        &["reason"]  // timeout, explicit_request, consensus_reached
    )
    .unwrap();

    /// Persistence operations
    pub static ref PERSISTENCE_OPS_TOTAL: CounterVec = register_counter_vec!(
        "consensus_persistence_operations_total",
        "Total persistence operations",
        &["operation", "status"]  // operation: save_validator, load_result, etc. status: success, error
    )
    .unwrap();

    // ========================================================================
    // Gauges
    // ========================================================================

    /// Current number of active validators
    pub static ref ACTIVE_VALIDATORS: Gauge = register_gauge!(
        "consensus_active_validators",
        "Current number of active validators"
    )
    .unwrap();

    /// Current pending votes by job
    pub static ref PENDING_VOTES: GaugeVec = register_gauge_vec!(
        "consensus_pending_votes",
        "Current number of pending votes",
        &["job_id"]
    )
    .unwrap();

    /// Current view number
    pub static ref CURRENT_VIEW: Gauge = register_gauge!(
        "consensus_current_view",
        "Current view number (for leader election)"
    )
    .unwrap();

    // ========================================================================
    // Histograms
    // ========================================================================

    /// Vote collection duration
    pub static ref VOTE_DURATION: HistogramVec = register_histogram_vec!(
        "consensus_vote_duration_seconds",
        "Duration of vote collection in seconds",
        &["job_id"],
        vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]  // Buckets in seconds
    )
    .unwrap();

    /// Consensus finalization duration
    pub static ref FINALIZATION_DURATION: HistogramVec = register_histogram_vec!(
        "consensus_finalization_duration_seconds",
        "Duration of consensus finalization in seconds",
        &["outcome"],
        vec![0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0]
    )
    .unwrap();

    /// Persistence operation duration
    pub static ref PERSISTENCE_DURATION: HistogramVec = register_histogram_vec!(
        "consensus_persistence_duration_seconds",
        "Duration of persistence operations in seconds",
        &["operation"],
        vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
    )
    .unwrap();

    // ========================================================================
    // Dashboard/Validator Metrics
    // ========================================================================

    /// Dashboard API request counter
    pub static ref DASHBOARD_REQUESTS_TOTAL: CounterVec = register_counter_vec!(
        "dashboard_requests_total",
        "Total dashboard API requests",
        &["endpoint", "status"]
    )
    .unwrap();

    /// Dashboard API latency histogram
    pub static ref DASHBOARD_REQUEST_DURATION: HistogramVec = register_histogram_vec!(
        "dashboard_request_duration_seconds",
        "Dashboard API request duration in seconds",
        &["endpoint"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
    )
    .unwrap();

    /// WebSocket subscriber count gauge
    pub static ref WEBSOCKET_SUBSCRIBERS: Gauge = register_gauge!(
        "websocket_subscribers_total",
        "Current number of WebSocket subscribers"
    )
    .unwrap();

    /// Worker heartbeat counter
    pub static ref WORKER_HEARTBEATS_TOTAL: CounterVec = register_counter_vec!(
        "worker_heartbeats_total",
        "Total worker heartbeats received",
        &["worker_id"]
    )
    .unwrap();

    /// Worker uptime percentage gauge (by worker)
    pub static ref WORKER_UPTIME_PERCENT: GaugeVec = register_gauge_vec!(
        "worker_uptime_percent",
        "Worker uptime percentage (24h)",
        &["worker_id"]
    )
    .unwrap();

    /// Active workers gauge
    pub static ref ACTIVE_WORKERS: Gauge = register_gauge!(
        "active_workers_total",
        "Current number of active workers"
    )
    .unwrap();

    /// Jobs in queue gauge
    pub static ref JOBS_PENDING: Gauge = register_gauge!(
        "jobs_pending_total",
        "Current number of pending jobs"
    )
    .unwrap();

    /// Jobs completed counter
    pub static ref JOBS_COMPLETED_TOTAL: CounterVec = register_counter_vec!(
        "jobs_completed_total",
        "Total completed jobs",
        &["status"]  // success, failed, cancelled
    )
    .unwrap();

    /// GPU utilization gauge (by worker)
    pub static ref GPU_UTILIZATION: GaugeVec = register_gauge_vec!(
        "gpu_utilization_percent",
        "GPU utilization percentage",
        &["worker_id", "gpu_index"]
    )
    .unwrap();

    /// Indexer block height gauge
    pub static ref INDEXER_BLOCK_HEIGHT: Gauge = register_gauge!(
        "indexer_block_height",
        "Current indexed block height"
    )
    .unwrap();

    /// Indexer lag gauge (seconds behind head)
    pub static ref INDEXER_LAG_SECONDS: Gauge = register_gauge!(
        "indexer_lag_seconds",
        "Indexer seconds behind chain head"
    )
    .unwrap();

    /// Rate limiter active buckets gauge
    pub static ref RATE_LIMITER_BUCKETS: Gauge = register_gauge!(
        "rate_limiter_active_buckets",
        "Number of active rate limiter buckets"
    )
    .unwrap();

    /// Blockchain RPC latency histogram
    pub static ref BLOCKCHAIN_RPC_DURATION: HistogramVec = register_histogram_vec!(
        "blockchain_rpc_duration_seconds",
        "Blockchain RPC call duration in seconds",
        &["method"],
        vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .unwrap();

    /// Staking total gauge (in SAGE)
    pub static ref TOTAL_STAKED_SAGE: Gauge = register_gauge!(
        "total_staked_sage",
        "Total SAGE tokens staked across all validators"
    )
    .unwrap();

    /// Rewards claimed counter
    pub static ref REWARDS_CLAIMED_TOTAL: CounterVec = register_counter_vec!(
        "rewards_claimed_total",
        "Total rewards claimed",
        &["claim_type"]  // staking, mining, referral
    )
    .unwrap();
}

/// Get Prometheus metrics as text
pub fn gather_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

/// Reset all metrics (useful for testing)
#[allow(dead_code)]
pub fn reset_metrics() {
    VOTES_TOTAL.reset();
    ROUNDS_TOTAL.reset();
    FRAUD_DETECTED_TOTAL.reset();
    VALIDATORS_REGISTERED_TOTAL.reset();
    VALIDATORS_REMOVED_TOTAL.reset();
    VIEW_CHANGES_TOTAL.reset();
    PERSISTENCE_OPS_TOTAL.reset();

    ACTIVE_VALIDATORS.set(0.0);
    CURRENT_VIEW.set(0.0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_registration() {
        // Just ensure all metrics are registered without panic
        let _ = &*VOTES_TOTAL;
        let _ = &*ROUNDS_TOTAL;
        let _ = &*FRAUD_DETECTED_TOTAL;
        let _ = &*VALIDATORS_REGISTERED_TOTAL;
        let _ = &*ACTIVE_VALIDATORS;
        let _ = &*VOTE_DURATION;
    }

    #[test]
    fn test_gather_metrics() {
        // Increment some metrics
        VOTES_TOTAL.with_label_values(&["validator1", "job123"]).inc();
        ACTIVE_VALIDATORS.set(5.0);

        // Gather metrics
        let metrics = gather_metrics();

        // Should contain our metrics
        assert!(metrics.contains("consensus_votes_total"));
        assert!(metrics.contains("consensus_active_validators"));
    }
}
