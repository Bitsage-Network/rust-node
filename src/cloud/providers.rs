//! # Cloud Provider Abstraction
//!
//! Unified interface for interacting with multiple cloud GPU providers.

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Supported cloud provider types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProviderType {
    Aws,
    Azure,
    Gcp,
    Ibm,
    NvidiaCloud, // DGX Cloud
}

impl std::fmt::Display for ProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderType::Aws => write!(f, "AWS"),
            ProviderType::Azure => write!(f, "Azure"),
            ProviderType::Gcp => write!(f, "GCP"),
            ProviderType::Ibm => write!(f, "IBM"),
            ProviderType::NvidiaCloud => write!(f, "NVIDIA Cloud"),
        }
    }
}

/// GPU specification details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuSpec {
    pub model: String,              // "A100", "H100", "V100"
    pub memory_gb: u32,             // 40, 80, 16
    pub compute_capability: String, // "8.0", "9.0"
    pub cuda_cores: u32,
    pub tensor_cores: u32,
    pub fp16_tflops: f32,
    pub supports_mig: bool,         // Multi-Instance GPU
    pub supports_nvlink: bool,
    pub supports_confidential_compute: bool, // TDX/TEE support
}

impl GpuSpec {
    /// NVIDIA A100 (40GB)
    pub fn a100_40gb() -> Self {
        Self {
            model: "A100".to_string(),
            memory_gb: 40,
            compute_capability: "8.0".to_string(),
            cuda_cores: 6912,
            tensor_cores: 432,
            fp16_tflops: 312.0,
            supports_mig: true,
            supports_nvlink: true,
            supports_confidential_compute: false,
        }
    }

    /// NVIDIA A100 (80GB)
    pub fn a100_80gb() -> Self {
        Self {
            model: "A100".to_string(),
            memory_gb: 80,
            compute_capability: "8.0".to_string(),
            cuda_cores: 6912,
            tensor_cores: 432,
            fp16_tflops: 312.0,
            supports_mig: true,
            supports_nvlink: true,
            supports_confidential_compute: false,
        }
    }

    /// NVIDIA H100 (80GB) - Hopper with Confidential Computing
    pub fn h100_80gb() -> Self {
        Self {
            model: "H100".to_string(),
            memory_gb: 80,
            compute_capability: "9.0".to_string(),
            cuda_cores: 16896,
            tensor_cores: 528,
            fp16_tflops: 1979.0,
            supports_mig: true,
            supports_nvlink: true,
            supports_confidential_compute: true, // TEE-enabled
        }
    }

    /// NVIDIA V100 (16GB)
    pub fn v100_16gb() -> Self {
        Self {
            model: "V100".to_string(),
            memory_gb: 16,
            compute_capability: "7.0".to_string(),
            cuda_cores: 5120,
            tensor_cores: 640,
            fp16_tflops: 125.0,
            supports_mig: false,
            supports_nvlink: true,
            supports_confidential_compute: false,
        }
    }
}

/// A running GPU instance in the cloud
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuInstance {
    pub instance_id: String,
    pub provider: ProviderType,
    pub instance_type: String,      // "p5.48xlarge", "Standard_ND96isr_H100_v5"
    pub gpu_count: u32,
    pub gpu_spec: GpuSpec,
    pub region: String,
    pub status: InstanceStatus,
    pub public_ip: Option<String>,
    pub private_ip: Option<String>,
    pub launch_time: chrono::DateTime<chrono::Utc>,
    pub hourly_cost_usd: f32,
    pub tags: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstanceStatus {
    Pending,
    Running,
    Stopping,
    Stopped,
    Terminated,
}

/// Trait for cloud provider implementations
#[async_trait]
pub trait CloudProvider: Send + Sync {
    /// Get the provider type
    fn provider_type(&self) -> ProviderType;

    /// List available GPU instance types in the region
    async fn list_available_gpu_types(&self) -> Result<Vec<String>>;

    /// Launch a new GPU instance
    async fn launch_instance(
        &self,
        instance_type: &str,
        tags: std::collections::HashMap<String, String>,
    ) -> Result<GpuInstance>;

    /// Get instance status
    async fn get_instance_status(&self, instance_id: &str) -> Result<InstanceStatus>;

    /// Terminate an instance
    async fn terminate_instance(&self, instance_id: &str) -> Result<()>;

    /// List all running instances
    async fn list_instances(&self) -> Result<Vec<GpuInstance>>;

    /// Get GPU specifications for an instance type
    async fn get_gpu_spec(&self, instance_type: &str) -> Result<GpuSpec>;

    /// Check if instance supports confidential computing
    async fn supports_confidential_compute(&self, instance_type: &str) -> Result<bool>;

    /// Get estimated hourly cost for instance type
    async fn get_hourly_cost(&self, instance_type: &str) -> Result<f32>;
}

/// Mock implementation for testing (simulates cloud API calls)
pub struct MockCloudProvider {
    provider_type: ProviderType,
    instances: std::sync::Arc<tokio::sync::RwLock<Vec<GpuInstance>>>,
}

impl MockCloudProvider {
    pub fn new(provider_type: ProviderType) -> Self {
        Self {
            provider_type,
            instances: std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new())),
        }
    }
}

#[async_trait]
impl CloudProvider for MockCloudProvider {
    fn provider_type(&self) -> ProviderType {
        self.provider_type
    }

    async fn list_available_gpu_types(&self) -> Result<Vec<String>> {
        Ok(match self.provider_type {
            ProviderType::Aws => vec![
                "p4d.24xlarge".to_string(),
                "p5.48xlarge".to_string(),
            ],
            ProviderType::Azure => vec![
                "Standard_NC96ads_A100_v4".to_string(),
                "Standard_ND96isr_H100_v5".to_string(),
            ],
            ProviderType::Gcp => vec![
                "a2-highgpu-8g".to_string(),
                "a3-highgpu-8g".to_string(),
            ],
            ProviderType::Ibm => vec!["gx2-16x128x2v100".to_string()],
            ProviderType::NvidiaCloud => vec!["dgx-h100-8gpu".to_string()],
        })
    }

    async fn launch_instance(
        &self,
        instance_type: &str,
        tags: std::collections::HashMap<String, String>,
    ) -> Result<GpuInstance> {
        let instance_id = format!("{}-{}", self.provider_type, uuid::Uuid::new_v4());
        let gpu_spec = self.get_gpu_spec(instance_type).await?;
        
        let instance = GpuInstance {
            instance_id: instance_id.clone(),
            provider: self.provider_type,
            instance_type: instance_type.to_string(),
            gpu_count: 8, // Most cloud instances come with 8 GPUs
            gpu_spec,
            region: "us-east-1".to_string(),
            status: InstanceStatus::Running,
            public_ip: Some(format!("203.0.113.{}", rand::random::<u8>())),
            private_ip: Some(format!("10.0.1.{}", rand::random::<u8>())),
            launch_time: chrono::Utc::now(),
            hourly_cost_usd: self.get_hourly_cost(instance_type).await?,
            tags,
        };

        self.instances.write().await.push(instance.clone());
        Ok(instance)
    }

    async fn get_instance_status(&self, instance_id: &str) -> Result<InstanceStatus> {
        let instances = self.instances.read().await;
        instances
            .iter()
            .find(|i| i.instance_id == instance_id)
            .map(|i| i.status)
            .ok_or_else(|| anyhow!("Instance not found: {}", instance_id))
    }

    async fn terminate_instance(&self, instance_id: &str) -> Result<()> {
        let mut instances = self.instances.write().await;
        if let Some(pos) = instances.iter().position(|i| i.instance_id == instance_id) {
            instances[pos].status = InstanceStatus::Terminated;
            Ok(())
        } else {
            Err(anyhow!("Instance not found: {}", instance_id))
        }
    }

    async fn list_instances(&self) -> Result<Vec<GpuInstance>> {
        Ok(self.instances.read().await.clone())
    }

    async fn get_gpu_spec(&self, instance_type: &str) -> Result<GpuSpec> {
        // Map instance types to GPU specs
        Ok(if instance_type.contains("p5") || instance_type.contains("H100") || instance_type.contains("a3") {
            GpuSpec::h100_80gb()
        } else if instance_type.contains("p4") || instance_type.contains("A100") || instance_type.contains("a2") {
            GpuSpec::a100_80gb()
        } else {
            GpuSpec::v100_16gb()
        })
    }

    async fn supports_confidential_compute(&self, instance_type: &str) -> Result<bool> {
        let spec = self.get_gpu_spec(instance_type).await?;
        Ok(spec.supports_confidential_compute)
    }

    async fn get_hourly_cost(&self, instance_type: &str) -> Result<f32> {
        // Approximate costs (as of 2024)
        Ok(if instance_type.contains("p5") || instance_type.contains("H100") {
            98.32 // H100 instances
        } else if instance_type.contains("p4") || instance_type.contains("A100") {
            32.77 // A100 instances
        } else {
            10.00 // V100 instances
        })
    }
}

