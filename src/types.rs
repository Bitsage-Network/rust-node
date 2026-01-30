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

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
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
    /// GPU hardware UUIDs for deduplication (e.g. "GPU-a1b2c3d4-...")
    #[serde(default)]
    pub gpu_uuids: Vec<String>,
}

impl Default for WorkerCapabilities {
    fn default() -> Self {
        Self {
            gpu_count: 0,
            gpu_memory_gb: 0,
            gpu_model: String::new(),
            tee_type: TeeType::None,
            gpu_tee_support: false,
            cpu_cores: 0,
            ram_gb: 0,
            disk_gb: 0,
            max_concurrent_jobs: 1,
            gpu_memory: 0,
            supported_job_types: Vec::new(),
            docker_enabled: false,
            max_parallel_tasks: 1,
            supported_frameworks: Vec::new(),
            ai_accelerators: Vec::new(),
            specialized_hardware: Vec::new(),
            model_cache_size_gb: 0,
            max_model_size_gb: 0,
            supports_fp16: false,
            supports_int8: false,
            cuda_compute_capability: None,
            secure_enclave_memory_mb: 0,
            gpu_uuids: Vec::new(),
        }
    }
}

/// Validation errors for worker capabilities
#[derive(Debug, Clone, PartialEq)]
pub enum CapabilityValidationError {
    /// No GPU available when GPU is required
    NoGpuAvailable,
    /// Insufficient GPU memory
    InsufficientGpuMemory { required: u32, available: u32 },
    /// Insufficient CPU cores
    InsufficientCpuCores { required: u32, available: u32 },
    /// Insufficient RAM
    InsufficientRam { required: u32, available: u32 },
    /// Insufficient disk space
    InsufficientDisk { required: u32, available: u32 },
    /// TEE type not supported
    TeeNotSupported { required: TeeType, available: TeeType },
    /// GPU TEE not available
    GpuTeeNotSupported,
    /// Compute capability too low
    InsufficientComputeCapability { required: String, available: Option<String> },
    /// Required framework not supported
    FrameworkNotSupported { framework: String },
    /// Required job type not supported
    JobTypeNotSupported { job_type: String },
}

impl std::fmt::Display for CapabilityValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoGpuAvailable => write!(f, "No GPU available"),
            Self::InsufficientGpuMemory { required, available } =>
                write!(f, "Insufficient GPU memory: required {}GB, available {}GB", required, available),
            Self::InsufficientCpuCores { required, available } =>
                write!(f, "Insufficient CPU cores: required {}, available {}", required, available),
            Self::InsufficientRam { required, available } =>
                write!(f, "Insufficient RAM: required {}GB, available {}GB", required, available),
            Self::InsufficientDisk { required, available } =>
                write!(f, "Insufficient disk: required {}GB, available {}GB", required, available),
            Self::TeeNotSupported { required, available } =>
                write!(f, "TEE type not supported: required {:?}, available {:?}", required, available),
            Self::GpuTeeNotSupported => write!(f, "GPU TEE not supported"),
            Self::InsufficientComputeCapability { required, available } =>
                write!(f, "Insufficient CUDA compute capability: required {}, available {:?}", required, available),
            Self::FrameworkNotSupported { framework } =>
                write!(f, "Framework not supported: {}", framework),
            Self::JobTypeNotSupported { job_type } =>
                write!(f, "Job type not supported: {}", job_type),
        }
    }
}

impl std::error::Error for CapabilityValidationError {}

/// Job requirements that a worker must satisfy
#[derive(Debug, Clone, Default)]
pub struct JobRequirements {
    pub min_gpu_count: Option<u32>,
    pub min_gpu_memory_gb: Option<u32>,
    pub min_cpu_cores: Option<u32>,
    pub min_ram_gb: Option<u32>,
    pub min_disk_gb: Option<u32>,
    pub required_tee: Option<TeeType>,
    pub require_gpu_tee: bool,
    pub min_compute_capability: Option<String>,
    pub required_frameworks: Vec<String>,
    pub required_job_types: Vec<String>,
}

impl WorkerCapabilities {
    /// Validate that this worker can satisfy the given job requirements
    pub fn validate_for_job(&self, requirements: &JobRequirements) -> Result<(), Vec<CapabilityValidationError>> {
        let mut errors = Vec::new();

        // Check GPU count
        if let Some(min_gpus) = requirements.min_gpu_count {
            if self.gpu_count < min_gpus {
                if self.gpu_count == 0 {
                    errors.push(CapabilityValidationError::NoGpuAvailable);
                } else {
                    errors.push(CapabilityValidationError::InsufficientGpuMemory {
                        required: min_gpus,
                        available: self.gpu_count,
                    });
                }
            }
        }

        // Check GPU memory
        if let Some(min_mem) = requirements.min_gpu_memory_gb {
            if self.gpu_memory_gb < min_mem {
                errors.push(CapabilityValidationError::InsufficientGpuMemory {
                    required: min_mem,
                    available: self.gpu_memory_gb,
                });
            }
        }

        // Check CPU cores
        if let Some(min_cores) = requirements.min_cpu_cores {
            if self.cpu_cores < min_cores {
                errors.push(CapabilityValidationError::InsufficientCpuCores {
                    required: min_cores,
                    available: self.cpu_cores,
                });
            }
        }

        // Check RAM
        if let Some(min_ram) = requirements.min_ram_gb {
            if self.ram_gb < min_ram {
                errors.push(CapabilityValidationError::InsufficientRam {
                    required: min_ram,
                    available: self.ram_gb,
                });
            }
        }

        // Check disk space
        if let Some(min_disk) = requirements.min_disk_gb {
            if self.disk_gb < min_disk {
                errors.push(CapabilityValidationError::InsufficientDisk {
                    required: min_disk,
                    available: self.disk_gb,
                });
            }
        }

        // Check TEE type
        if let Some(ref required_tee) = requirements.required_tee {
            if !self.tee_type.satisfies(required_tee) {
                errors.push(CapabilityValidationError::TeeNotSupported {
                    required: required_tee.clone(),
                    available: self.tee_type.clone(),
                });
            }
        }

        // Check GPU TEE
        if requirements.require_gpu_tee && !self.gpu_tee_support {
            errors.push(CapabilityValidationError::GpuTeeNotSupported);
        }

        // Check compute capability
        if let Some(ref min_cc) = requirements.min_compute_capability {
            if !self.satisfies_compute_capability(min_cc) {
                errors.push(CapabilityValidationError::InsufficientComputeCapability {
                    required: min_cc.clone(),
                    available: self.cuda_compute_capability.clone(),
                });
            }
        }

        // Check required frameworks
        for framework in &requirements.required_frameworks {
            if !self.supported_frameworks.iter().any(|f| f.eq_ignore_ascii_case(framework)) {
                errors.push(CapabilityValidationError::FrameworkNotSupported {
                    framework: framework.clone(),
                });
            }
        }

        // Check required job types
        for job_type in &requirements.required_job_types {
            if !self.supported_job_types.iter().any(|j| j.eq_ignore_ascii_case(job_type)) {
                errors.push(CapabilityValidationError::JobTypeNotSupported {
                    job_type: job_type.clone(),
                });
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Check if this worker can handle the job (returns bool for simple checks)
    pub fn can_handle_job(&self, requirements: &JobRequirements) -> bool {
        self.validate_for_job(requirements).is_ok()
    }

    /// Check if compute capability satisfies the minimum requirement
    fn satisfies_compute_capability(&self, min_cc: &str) -> bool {
        match &self.cuda_compute_capability {
            None => false,
            Some(cc) => {
                // Parse compute capability as X.Y format
                let parse_cc = |s: &str| -> Option<(u32, u32)> {
                    let parts: Vec<&str> = s.split('.').collect();
                    if parts.len() == 2 {
                        Some((parts[0].parse().ok()?, parts[1].parse().ok()?))
                    } else {
                        None
                    }
                };

                match (parse_cc(cc), parse_cc(min_cc)) {
                    (Some((maj1, min1)), Some((maj2, min2))) => {
                        (maj1, min1) >= (maj2, min2)
                    }
                    _ => false,
                }
            }
        }
    }

    /// Calculate a capability score for ranking workers
    pub fn capability_score(&self) -> u64 {
        let mut score: u64 = 0;

        // Weight GPU capabilities heavily
        score += (self.gpu_count as u64) * 1000;
        score += (self.gpu_memory_gb as u64) * 100;

        // CPU and RAM
        score += (self.cpu_cores as u64) * 10;
        score += (self.ram_gb as u64) * 5;

        // TEE bonus
        match self.tee_type {
            TeeType::None => {}
            TeeType::Full => score += 500,
            TeeType::CpuOnly => score += 200,
        }

        // GPU TEE bonus
        if self.gpu_tee_support {
            score += 300;
        }

        score
    }
}

impl TeeType {
    /// Check if this TEE type satisfies the required TEE type
    pub fn satisfies(&self, required: &TeeType) -> bool {
        match (self, required) {
            // Any TEE satisfies None requirement
            (_, TeeType::None) => true,
            // None doesn't satisfy any TEE requirement
            (TeeType::None, _) => false,
            // Exact matches
            (TeeType::Full, TeeType::Full) => true,
            (TeeType::CpuOnly, TeeType::CpuOnly) => true,
            // Full TEE can satisfy CpuOnly requirement (it's a superset)
            (TeeType::Full, TeeType::CpuOnly) => true,
            // CpuOnly cannot satisfy Full requirement
            (TeeType::CpuOnly, TeeType::Full) => false,
        }
    }
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

    #[test]
    fn test_worker_capabilities_validation_success() {
        let capabilities = WorkerCapabilities {
            gpu_count: 4,
            gpu_memory_gb: 80,
            gpu_model: "H100".to_string(),
            tee_type: TeeType::Full,
            gpu_tee_support: true,
            cpu_cores: 64,
            ram_gb: 512,
            disk_gb: 2000,
            max_concurrent_jobs: 4,
            ..Default::default()
        };

        let requirements = JobRequirements {
            min_gpu_count: Some(2),
            min_gpu_memory_gb: Some(40),
            min_cpu_cores: Some(32),
            min_ram_gb: Some(128),
            required_tee: Some(TeeType::Full),
            require_gpu_tee: true,
            ..Default::default()
        };

        assert!(capabilities.validate_for_job(&requirements).is_ok());
        assert!(capabilities.can_handle_job(&requirements));
    }

    #[test]
    fn test_worker_capabilities_validation_failure() {
        let capabilities = WorkerCapabilities {
            gpu_count: 1,
            gpu_memory_gb: 8,
            gpu_model: "RTX 3060".to_string(),
            tee_type: TeeType::None,
            gpu_tee_support: false,
            cpu_cores: 8,
            ram_gb: 32,
            disk_gb: 500,
            max_concurrent_jobs: 1,
            ..Default::default()
        };

        let requirements = JobRequirements {
            min_gpu_count: Some(2),
            min_gpu_memory_gb: Some(40),
            required_tee: Some(TeeType::Full),
            require_gpu_tee: true,
            ..Default::default()
        };

        let result = capabilities.validate_for_job(&requirements);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.len() >= 3); // GPU count, GPU mem, TEE, GPU TEE
    }

    #[test]
    fn test_tee_type_satisfies() {
        // Any TEE satisfies None
        assert!(TeeType::Full.satisfies(&TeeType::None));
        assert!(TeeType::CpuOnly.satisfies(&TeeType::None));
        assert!(TeeType::None.satisfies(&TeeType::None));

        // Exact matches
        assert!(TeeType::Full.satisfies(&TeeType::Full));
        assert!(TeeType::CpuOnly.satisfies(&TeeType::CpuOnly));

        // Full can satisfy CpuOnly (it's a superset)
        assert!(TeeType::Full.satisfies(&TeeType::CpuOnly));

        // None doesn't satisfy any real TEE requirement
        assert!(!TeeType::None.satisfies(&TeeType::Full));
        assert!(!TeeType::None.satisfies(&TeeType::CpuOnly));

        // CpuOnly cannot satisfy Full
        assert!(!TeeType::CpuOnly.satisfies(&TeeType::Full));
    }

    #[test]
    fn test_capability_score() {
        let basic = WorkerCapabilities {
            gpu_count: 1,
            gpu_memory_gb: 8,
            cpu_cores: 8,
            ram_gb: 16,
            tee_type: TeeType::None,
            gpu_tee_support: false,
            ..Default::default()
        };

        let powerful = WorkerCapabilities {
            gpu_count: 8,
            gpu_memory_gb: 80,
            cpu_cores: 128,
            ram_gb: 1024,
            tee_type: TeeType::Full,
            gpu_tee_support: true,
            ..Default::default()
        };

        assert!(powerful.capability_score() > basic.capability_score());
    }
}
