//! # Core Types
//!
//! This module defines the fundamental types used throughout the Bitsage Network system.

use std::fmt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a job
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JobId(pub Uuid);

impl JobId {
    /// Create a new job ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the inner UUID
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for JobId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl std::str::FromStr for JobId {
    type Err = uuid::Error;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

/// Unique identifier for a task
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaskId(Uuid);

impl TaskId {
    /// Create a new task ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the inner UUID
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl fmt::Display for TaskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for TaskId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

/// Unique identifier for a worker
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkerId(Uuid);

impl WorkerId {
    /// Create a new worker ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the inner UUID
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl fmt::Display for WorkerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for WorkerId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl WorkerId {
    /// Create from string
    pub fn from_string(s: &str) -> Result<Self, anyhow::Error> {
        let uuid = Uuid::parse_str(s)?;
        Ok(Self(uuid))
    }
}

/// Unique identifier for a network node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(Uuid);

impl NodeId {
    /// Create a new node ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the inner UUID
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for NodeId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

/// Network address for peer-to-peer communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAddress {
    pub ip: std::net::IpAddr,
    pub port: u16,
}

impl fmt::Display for NetworkAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

/// Starknet address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarknetAddress(String);

impl StarknetAddress {
    /// Create a new Starknet address
    pub fn new(address: String) -> Self {
        Self(address)
    }

    /// Get the address as a string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StarknetAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// SAGE token amount (in wei)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitsageAmount(u128);

impl BitsageAmount {
    /// Create a new SAGE amount
    pub fn new(amount: u128) -> Self {
        Self(amount)
    }

    /// Get the amount in wei
    pub fn as_wei(&self) -> u128 {
        self.0
    }

    /// Get the amount in SAGE tokens (dividing by 10^18)
    pub fn as_sage(&self) -> f64 {
        self.0 as f64 / 1_000_000_000_000_000_000.0
    }

    /// Create from SAGE tokens (multiplying by 10^18)
    pub fn from_sage(sage: f64) -> Self {
        Self((sage * 1_000_000_000_000_000_000.0) as u128)
    }
}

impl fmt::Display for BitsageAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} SAGE", self.as_sage())
    }
}

/// Compute resource requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequirements {
    pub cpu_cores: u32,
    pub memory_gb: u32,
    pub gpu_memory_gb: Option<u32>,
    pub storage_gb: u32,
    pub network_bandwidth_mbps: u32,
}

impl Default for ResourceRequirements {
    fn default() -> Self {
        Self {
            cpu_cores: 1,
            memory_gb: 1,
            gpu_memory_gb: None,
            storage_gb: 1,
            network_bandwidth_mbps: 10,
        }
    }
}

/// Job priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Priority {
    Low = 1,
    Medium = 5,
    High = 8,
    Critical = 10,
}

impl Default for Priority {
    fn default() -> Self {
        Self::Medium
    }
}

impl fmt::Display for Priority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Priority::Low => write!(f, "Low"),
            Priority::Medium => write!(f, "Medium"),
            Priority::High => write!(f, "High"),
            Priority::Critical => write!(f, "Critical"),
        }
    }
}

/// Error types for the Bitsage Network
#[derive(Debug, thiserror::Error)]
pub enum BitsageError {
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Database error: {0}")]
    Database(String),
    
    #[error("Blockchain error: {0}")]
    Blockchain(String),
    
    #[error("Job not found: {0}")]
    JobNotFound(JobId),
    
    #[error("Task not found: {0}")]
    TaskNotFound(TaskId),
    
    #[error("Worker not found: {0}")]
    WorkerNotFound(WorkerId),
    
    #[error("Insufficient resources: {0}")]
    InsufficientResources(String),
    
    #[error("Invalid configuration: {0}")]
    Configuration(String),
    
    #[error("Validation error: {0}")]
    Validation(String),
}

/// Result type for Bitsage Network operations
pub type BitsageResult<T> = Result<T, BitsageError>;

/// Network peer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub node_id: NodeId,
    pub address: NetworkAddress,
    pub capabilities: Vec<String>,
    pub reputation_score: f64,
    pub last_seen: u64,
    pub is_active: bool,
}

impl PeerInfo {
    /// Create a new peer info
    pub fn new(node_id: NodeId, address: NetworkAddress) -> Self {
        Self {
            node_id,
            address,
            capabilities: Vec::new(),
            reputation_score: 0.0,
            last_seen: 0,
            is_active: true,
        }
    }
}

/// Type of Trusted Execution Environment support
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TeeType {
    None,
    CpuOnly, // Intel TDX, AMD SEV-SNP (protects code, but GPU is external)
    Full,    // NVIDIA H100/B200 (GPU memory is also encrypted)
}

/// Worker capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerCapabilities {
    pub gpu_count: u32,
    pub gpu_memory_gb: u32,
    pub gpu_model: String,
    pub tee_type: TeeType,
    pub gpu_tee_support: bool,
    pub cpu_cores: u32,
    pub ram_gb: u32,
    pub disk_gb: u32,
    pub max_concurrent_jobs: u32,
    // Legacy fields for backward compatibility
    #[serde(default)]
    pub gpu_memory: u64,
    #[serde(default)]
    pub supported_job_types: Vec<String>,
    #[serde(default)]
    pub docker_enabled: bool,
    #[serde(default)]
    pub max_parallel_tasks: u32,
    #[serde(default)]
    pub supported_frameworks: Vec<String>,
    #[serde(default)]
    pub ai_accelerators: Vec<String>,
    #[serde(default)]
    pub specialized_hardware: Vec<String>,
    #[serde(default)]
    pub model_cache_size_gb: u32,
    #[serde(default)]
    pub max_model_size_gb: u32,
    #[serde(default)]
    pub supports_fp16: bool,
    #[serde(default)]
    pub supports_int8: bool,
    #[serde(default)]
    pub cuda_compute_capability: Option<String>,
    #[serde(default)]
    pub secure_enclave_memory_mb: u32, // Memory available inside the TEE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_id_creation() {
        let id1 = JobId::new();
        let id2 = JobId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_bitsage_amount_conversion() {
        let amount = BitsageAmount::from_sage(1.5);
        assert_eq!(amount.as_sage(), 1.5);
        assert_eq!(amount.as_wei(), 1_500_000_000_000_000_000);
    }

    #[test]
    fn test_priority_ordering() {
        assert!(Priority::Critical > Priority::High);
        assert!(Priority::High > Priority::Medium);
        assert!(Priority::Medium > Priority::Low);
    }
}
