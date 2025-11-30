//! # Health Monitoring
//!
//! Health monitoring for worker and coordinator nodes.

use serde::{Deserialize, Serialize};

/// Health status of a node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub healthy: bool,
    pub cpu_usage: f32,
    pub memory_usage: f32,
    pub disk_usage: f32,
    pub network_latency: u64,
    pub last_check: chrono::DateTime<chrono::Utc>,
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self {
            healthy: true,
            cpu_usage: 0.0,
            memory_usage: 0.0,
            disk_usage: 0.0,
            network_latency: 0,
            last_check: chrono::Utc::now(),
        }
    }
} 