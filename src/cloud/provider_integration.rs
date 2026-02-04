//! # Cloud Provider Integration Layer
//!
//! Integrates with external GPU cloud providers to supplement decentralized miner supply.
//! This enables BitSage to offer guaranteed SLA compute while building miner network.
//!
//! ## Supported Providers (via APIs):
//! - Brev/Shadeform (aggregator for Hyperstack, IMWT, Lambda, Nebius, etc.)
//! - Lambda Labs (direct)
//! - Hyperstack (direct)
//! - Vast.ai (marketplace)
//! - CoreWeave
//!
//! ## Value Add:
//! - TEE/FHE confidential compute layer
//! - STWO ZK proofs for verifiable computation
//! - Unified API across all providers
//! - 20% protocol markup on cloud compute

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::{Result, anyhow};
use tracing::info;
use chrono::{DateTime, Utc};

/// Cloud provider identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CloudProvider {
    /// Brev.dev - Aggregates multiple providers via Shadeform
    Brev,
    /// Shadeform - GPU cloud aggregator
    Shadeform,
    /// Lambda Labs - Direct API
    Lambda,
    /// Hyperstack - Direct API
    Hyperstack,
    /// Vast.ai - GPU marketplace
    VastAi,
    /// CoreWeave - Enterprise GPU cloud
    CoreWeave,
    /// Nebius - Cloud provider
    Nebius,
    /// IMWT - Infrastructure provider
    IMWT,
    /// Massed Compute
    MassedCompute,
    /// Scaleway
    Scaleway,
    /// Voltage Park
    VoltagePark,
    /// Paperspace
    Paperspace,
    /// Google Cloud Platform
    GCP,
    /// Amazon Web Services
    AWS,
    /// Microsoft Azure
    Azure,
}

impl CloudProvider {
    pub fn display_name(&self) -> &'static str {
        match self {
            CloudProvider::Brev => "Brev",
            CloudProvider::Shadeform => "Shadeform",
            CloudProvider::Lambda => "Lambda Labs",
            CloudProvider::Hyperstack => "Hyperstack",
            CloudProvider::VastAi => "vast.ai",
            CloudProvider::CoreWeave => "CoreWeave",
            CloudProvider::Nebius => "Nebius",
            CloudProvider::IMWT => "IMWT",
            CloudProvider::MassedCompute => "Massed Compute",
            CloudProvider::Scaleway => "Scaleway",
            CloudProvider::VoltagePark => "Voltage Park",
            CloudProvider::Paperspace => "Paperspace",
            CloudProvider::GCP => "Google Cloud",
            CloudProvider::AWS => "AWS",
            CloudProvider::Azure => "Azure",
        }
    }

    pub fn api_base_url(&self) -> &'static str {
        match self {
            CloudProvider::Brev => "https://api.brev.dev/v1",
            CloudProvider::Shadeform => "https://api.shadeform.ai/v1",
            CloudProvider::Lambda => "https://cloud.lambdalabs.com/api/v1",
            CloudProvider::Hyperstack => "https://api.hyperstack.cloud/v1",
            CloudProvider::VastAi => "https://cloud.vast.ai/api/v0",
            CloudProvider::CoreWeave => "https://api.coreweave.com/v1",
            CloudProvider::Nebius => "https://api.nebius.ai/v1",
            _ => "",
        }
    }

    /// Whether this provider supports TEE (Trusted Execution Environment)
    pub fn supports_tee(&self) -> bool {
        matches!(self,
            CloudProvider::Azure | // Azure Confidential Computing
            CloudProvider::GCP |   // GCP Confidential VMs
            CloudProvider::AWS     // AWS Nitro Enclaves
        )
    }
}

/// GPU instance type available from a provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudGpuInstance {
    /// Provider offering this instance
    pub provider: CloudProvider,
    /// Provider's instance type ID
    pub instance_type: String,
    /// GPU model (e.g., "NVIDIA H100 SXM")
    pub gpu_model: String,
    /// Number of GPUs
    pub gpu_count: u32,
    /// VRAM per GPU in GiB
    pub vram_gib: u32,
    /// Total system RAM in GiB
    pub ram_gib: u32,
    /// Number of CPUs
    pub cpu_count: u32,
    /// SSD storage in GiB
    pub storage_gib: u32,
    /// GPU interconnect type (PCIe, SXM5, NVLink)
    pub interconnect: GpuInterconnect,
    /// Hourly price from provider in USD cents
    pub provider_price_cents: u32,
    /// BitSage price (provider + 20% markup) in USD cents
    pub bitsage_price_cents: u32,
    /// Estimated ready time in minutes
    pub ready_time_minutes: u32,
    /// Whether instance supports stop/start
    pub supports_stop_start: bool,
    /// Whether this instance has TEE capability
    pub has_tee: bool,
    /// Availability status
    pub availability: InstanceAvailability,
    /// Last price update
    pub last_updated: DateTime<Utc>,
}

/// GPU interconnect type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GpuInterconnect {
    PCIe,
    SXM5,
    NVLink,
    Unknown,
}

impl std::fmt::Display for GpuInterconnect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GpuInterconnect::PCIe => write!(f, "PCIe"),
            GpuInterconnect::SXM5 => write!(f, "SXM5"),
            GpuInterconnect::NVLink => write!(f, "NVLink"),
            GpuInterconnect::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Instance availability status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstanceAvailability {
    Available,
    Limited,
    Unavailable,
    Unknown,
}

/// Provisioned instance from a cloud provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionedInstance {
    /// Unique instance ID
    pub instance_id: String,
    /// Provider that owns this instance
    pub provider: CloudProvider,
    /// Instance type
    pub instance_type: String,
    /// Public IP address
    pub ip_address: Option<String>,
    /// SSH port
    pub ssh_port: u16,
    /// Status
    pub status: InstanceStatus,
    /// When provisioned
    pub created_at: DateTime<Utc>,
    /// Hourly cost in USD cents
    pub hourly_cost_cents: u32,
    /// Total cost accrued in USD cents
    pub total_cost_cents: u64,
}

/// Instance status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstanceStatus {
    Provisioning,
    Starting,
    Running,
    Stopping,
    Stopped,
    Terminating,
    Terminated,
    Error,
}

/// Cloud provider client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub provider: CloudProvider,
    pub api_key: Option<String>,
    pub api_secret: Option<String>,
    pub enabled: bool,
    pub max_instances: u32,
    pub max_hourly_spend_cents: u64,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            provider: CloudProvider::Brev,
            api_key: None,
            api_secret: None,
            enabled: false,
            max_instances: 10,
            max_hourly_spend_cents: 10000, // $100/hr max
        }
    }
}

/// Provider integration manager
#[allow(dead_code)]
pub struct ProviderManager {
    /// HTTP client for API calls
    client: reqwest::Client,
    /// Provider configurations
    configs: HashMap<CloudProvider, ProviderConfig>,
    /// Cached instance types
    instance_cache: Arc<RwLock<HashMap<CloudProvider, Vec<CloudGpuInstance>>>>,
    /// Active provisioned instances
    active_instances: Arc<RwLock<HashMap<String, ProvisionedInstance>>>,
    /// Total hourly spend tracking
    hourly_spend_cents: Arc<RwLock<u64>>,
}

impl ProviderManager {
    /// Create a new provider manager
    pub fn new(configs: Vec<ProviderConfig>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        let config_map: HashMap<CloudProvider, ProviderConfig> = configs
            .into_iter()
            .map(|c| (c.provider, c))
            .collect();

        Self {
            client,
            configs: config_map,
            instance_cache: Arc::new(RwLock::new(HashMap::new())),
            active_instances: Arc::new(RwLock::new(HashMap::new())),
            hourly_spend_cents: Arc::new(RwLock::new(0)),
        }
    }

    /// Initialize with static pricing data (until APIs are connected)
    pub async fn initialize_static_pricing(&self) {
        let mut cache = self.instance_cache.write().await;

        // H100 instances from Brev/providers (from user's data)
        let h100_instances = vec![
            // 1x H100 PCIe
            CloudGpuInstance {
                provider: CloudProvider::Hyperstack,
                instance_type: "h100-pcie-1x".to_string(),
                gpu_model: "NVIDIA H100 PCIe".to_string(),
                gpu_count: 1,
                vram_gib: 80,
                ram_gib: 180,
                cpu_count: 28,
                storage_gib: 850,
                interconnect: GpuInterconnect::PCIe,
                provider_price_cents: 228,
                bitsage_price_cents: 274, // +20%
                ready_time_minutes: 15,
                supports_stop_start: false,
                has_tee: false,
                availability: InstanceAvailability::Available,
                last_updated: Utc::now(),
            },
            CloudGpuInstance {
                provider: CloudProvider::IMWT,
                instance_type: "h100-pcie-1x".to_string(),
                gpu_model: "NVIDIA H100 PCIe".to_string(),
                gpu_count: 1,
                vram_gib: 80,
                ram_gib: 128,
                cpu_count: 20,
                storage_gib: 1220,
                interconnect: GpuInterconnect::PCIe,
                provider_price_cents: 298,
                bitsage_price_cents: 358,
                ready_time_minutes: 8,
                supports_stop_start: false,
                has_tee: false,
                availability: InstanceAvailability::Available,
                last_updated: Utc::now(),
            },
            CloudGpuInstance {
                provider: CloudProvider::Lambda,
                instance_type: "gpu_1x_h100_pcie".to_string(),
                gpu_model: "NVIDIA H100 PCIe".to_string(),
                gpu_count: 1,
                vram_gib: 80,
                ram_gib: 200,
                cpu_count: 26,
                storage_gib: 1000,
                interconnect: GpuInterconnect::PCIe,
                provider_price_cents: 299,
                bitsage_price_cents: 359,
                ready_time_minutes: 10,
                supports_stop_start: false,
                has_tee: false,
                availability: InstanceAvailability::Available,
                last_updated: Utc::now(),
            },
            CloudGpuInstance {
                provider: CloudProvider::Nebius,
                instance_type: "h100-1x".to_string(),
                gpu_model: "NVIDIA H100".to_string(),
                gpu_count: 1,
                vram_gib: 80,
                ram_gib: 200,
                cpu_count: 16,
                storage_gib: 500,
                interconnect: GpuInterconnect::PCIe,
                provider_price_cents: 354,
                bitsage_price_cents: 425,
                ready_time_minutes: 10,
                supports_stop_start: true,
                has_tee: false,
                availability: InstanceAvailability::Available,
                last_updated: Utc::now(),
            },
            // 1x H100 SXM5
            CloudGpuInstance {
                provider: CloudProvider::Lambda,
                instance_type: "gpu_1x_h100_sxm5".to_string(),
                gpu_model: "NVIDIA H100 SXM5".to_string(),
                gpu_count: 1,
                vram_gib: 80,
                ram_gib: 225,
                cpu_count: 26,
                storage_gib: 2750,
                interconnect: GpuInterconnect::SXM5,
                provider_price_cents: 395,
                bitsage_price_cents: 474,
                ready_time_minutes: 10,
                supports_stop_start: false,
                has_tee: false,
                availability: InstanceAvailability::Available,
                last_updated: Utc::now(),
            },
            // 2x H100 PCIe
            CloudGpuInstance {
                provider: CloudProvider::Hyperstack,
                instance_type: "h100-pcie-2x".to_string(),
                gpu_model: "NVIDIA H100 PCIe".to_string(),
                gpu_count: 2,
                vram_gib: 80,
                ram_gib: 360,
                cpu_count: 60,
                storage_gib: 1560,
                interconnect: GpuInterconnect::PCIe,
                provider_price_cents: 456,
                bitsage_price_cents: 547,
                ready_time_minutes: 15,
                supports_stop_start: false,
                has_tee: false,
                availability: InstanceAvailability::Available,
                last_updated: Utc::now(),
            },
            CloudGpuInstance {
                provider: CloudProvider::VoltagePark,
                instance_type: "h100-sxm5-2x".to_string(),
                gpu_model: "NVIDIA H100 SXM5".to_string(),
                gpu_count: 2,
                vram_gib: 80,
                ram_gib: 232,
                cpu_count: 52,
                storage_gib: 2340,
                interconnect: GpuInterconnect::SXM5,
                provider_price_cents: 478,
                bitsage_price_cents: 574,
                ready_time_minutes: 8,
                supports_stop_start: false,
                has_tee: false,
                availability: InstanceAvailability::Available,
                last_updated: Utc::now(),
            },
            // 2x H100 SXM5
            CloudGpuInstance {
                provider: CloudProvider::Lambda,
                instance_type: "gpu_2x_h100_sxm5".to_string(),
                gpu_model: "NVIDIA H100 SXM5".to_string(),
                gpu_count: 2,
                vram_gib: 80,
                ram_gib: 450,
                cpu_count: 52,
                storage_gib: 5500,
                interconnect: GpuInterconnect::SXM5,
                provider_price_cents: 766,
                bitsage_price_cents: 919,
                ready_time_minutes: 10,
                supports_stop_start: false,
                has_tee: false,
                availability: InstanceAvailability::Available,
                last_updated: Utc::now(),
            },
            // 4x H100 PCIe
            CloudGpuInstance {
                provider: CloudProvider::Hyperstack,
                instance_type: "h100-pcie-4x".to_string(),
                gpu_model: "NVIDIA H100 PCIe".to_string(),
                gpu_count: 4,
                vram_gib: 80,
                ram_gib: 720,
                cpu_count: 124,
                storage_gib: 3220,
                interconnect: GpuInterconnect::PCIe,
                provider_price_cents: 912,
                bitsage_price_cents: 1094,
                ready_time_minutes: 15,
                supports_stop_start: false,
                has_tee: false,
                availability: InstanceAvailability::Available,
                last_updated: Utc::now(),
            },
            // 4x H100 SXM5
            CloudGpuInstance {
                provider: CloudProvider::Lambda,
                instance_type: "gpu_4x_h100_sxm5".to_string(),
                gpu_model: "NVIDIA H100 SXM5".to_string(),
                gpu_count: 4,
                vram_gib: 80,
                ram_gib: 900,
                cpu_count: 104,
                storage_gib: 11000,
                interconnect: GpuInterconnect::SXM5,
                provider_price_cents: 1483,
                bitsage_price_cents: 1780,
                ready_time_minutes: 10,
                supports_stop_start: false,
                has_tee: false,
                availability: InstanceAvailability::Available,
                last_updated: Utc::now(),
            },
            // 8x H100 PCIe
            CloudGpuInstance {
                provider: CloudProvider::Hyperstack,
                instance_type: "h100-pcie-8x".to_string(),
                gpu_model: "NVIDIA H100 PCIe".to_string(),
                gpu_count: 8,
                vram_gib: 80,
                ram_gib: 1440,
                cpu_count: 252,
                storage_gib: 6450,
                interconnect: GpuInterconnect::PCIe,
                provider_price_cents: 1872,
                bitsage_price_cents: 2246,
                ready_time_minutes: 9,
                supports_stop_start: false,
                has_tee: false,
                availability: InstanceAvailability::Available,
                last_updated: Utc::now(),
            },
            CloudGpuInstance {
                provider: CloudProvider::VoltagePark,
                instance_type: "h100-sxm5-8x".to_string(),
                gpu_model: "NVIDIA H100 SXM5".to_string(),
                gpu_count: 8,
                vram_gib: 80,
                ram_gib: 1024,
                cpu_count: 104,
                storage_gib: 17580,
                interconnect: GpuInterconnect::SXM5,
                provider_price_cents: 1910,
                bitsage_price_cents: 2292,
                ready_time_minutes: 8,
                supports_stop_start: false,
                has_tee: false,
                availability: InstanceAvailability::Available,
                last_updated: Utc::now(),
            },
            // 8x H100 SXM5
            CloudGpuInstance {
                provider: CloudProvider::Hyperstack,
                instance_type: "h100-sxm5-8x".to_string(),
                gpu_model: "NVIDIA H100 SXM5".to_string(),
                gpu_count: 8,
                vram_gib: 80,
                ram_gib: 960,
                cpu_count: 192,
                storage_gib: 19530,
                interconnect: GpuInterconnect::SXM5,
                provider_price_cents: 2304,
                bitsage_price_cents: 2765,
                ready_time_minutes: 9,
                supports_stop_start: false,
                has_tee: false,
                availability: InstanceAvailability::Available,
                last_updated: Utc::now(),
            },
            CloudGpuInstance {
                provider: CloudProvider::Nebius,
                instance_type: "h100-8x".to_string(),
                gpu_model: "NVIDIA H100".to_string(),
                gpu_count: 8,
                vram_gib: 80,
                ram_gib: 1560,
                cpu_count: 128,
                storage_gib: 2000,
                interconnect: GpuInterconnect::SXM5,
                provider_price_cents: 2832,
                bitsage_price_cents: 3398,
                ready_time_minutes: 10,
                supports_stop_start: true,
                has_tee: false,
                availability: InstanceAvailability::Available,
                last_updated: Utc::now(),
            },
            CloudGpuInstance {
                provider: CloudProvider::Lambda,
                instance_type: "gpu_8x_h100_sxm5".to_string(),
                gpu_model: "NVIDIA H100 SXM5".to_string(),
                gpu_count: 8,
                vram_gib: 80,
                ram_gib: 1800,
                cpu_count: 208,
                storage_gib: 22000,
                interconnect: GpuInterconnect::SXM5,
                provider_price_cents: 2870,
                bitsage_price_cents: 3444,
                ready_time_minutes: 10,
                supports_stop_start: false,
                has_tee: false,
                availability: InstanceAvailability::Available,
                last_updated: Utc::now(),
            },
            // GCP (premium pricing with TEE support)
            CloudGpuInstance {
                provider: CloudProvider::GCP,
                instance_type: "a3-highgpu-8g".to_string(),
                gpu_model: "NVIDIA H100".to_string(),
                gpu_count: 8,
                vram_gib: 80,
                ram_gib: 1832,
                cpu_count: 208,
                storage_gib: 2000,
                interconnect: GpuInterconnect::SXM5,
                provider_price_cents: 9930,
                bitsage_price_cents: 11916,
                ready_time_minutes: 5,
                supports_stop_start: true,
                has_tee: true, // GCP Confidential Computing
                availability: InstanceAvailability::Available,
                last_updated: Utc::now(),
            },
        ];

        // Group by provider
        for instance in h100_instances {
            cache
                .entry(instance.provider)
                .or_insert_with(Vec::new)
                .push(instance);
        }

        // Add A100 instances
        let a100_instances = vec![
            CloudGpuInstance {
                provider: CloudProvider::Lambda,
                instance_type: "gpu_1x_a100_sxm4".to_string(),
                gpu_model: "NVIDIA A100 SXM4".to_string(),
                gpu_count: 1,
                vram_gib: 40,
                ram_gib: 120,
                cpu_count: 30,
                storage_gib: 500,
                interconnect: GpuInterconnect::SXM5,
                provider_price_cents: 129,
                bitsage_price_cents: 155,
                ready_time_minutes: 10,
                supports_stop_start: false,
                has_tee: false,
                availability: InstanceAvailability::Available,
                last_updated: Utc::now(),
            },
            CloudGpuInstance {
                provider: CloudProvider::Lambda,
                instance_type: "gpu_8x_a100_sxm4".to_string(),
                gpu_model: "NVIDIA A100 SXM4".to_string(),
                gpu_count: 8,
                vram_gib: 40,
                ram_gib: 1000,
                cpu_count: 240,
                storage_gib: 10000,
                interconnect: GpuInterconnect::SXM5,
                provider_price_cents: 1032,
                bitsage_price_cents: 1238,
                ready_time_minutes: 10,
                supports_stop_start: false,
                has_tee: false,
                availability: InstanceAvailability::Available,
                last_updated: Utc::now(),
            },
        ];

        for instance in a100_instances {
            cache
                .entry(instance.provider)
                .or_insert_with(Vec::new)
                .push(instance);
        }

        info!("Initialized static pricing for {} providers", cache.len());
    }

    /// Get available instances matching requirements
    pub async fn find_instances(
        &self,
        min_gpus: u32,
        min_vram_gib: u32,
        max_price_cents: Option<u32>,
        require_tee: bool,
    ) -> Vec<CloudGpuInstance> {
        let cache = self.instance_cache.read().await;
        let mut results = Vec::new();

        for instances in cache.values() {
            for instance in instances {
                // Filter by requirements
                if instance.gpu_count < min_gpus {
                    continue;
                }
                if instance.vram_gib < min_vram_gib {
                    continue;
                }
                if let Some(max) = max_price_cents {
                    if instance.bitsage_price_cents > max {
                        continue;
                    }
                }
                if require_tee && !instance.has_tee {
                    continue;
                }
                if instance.availability == InstanceAvailability::Unavailable {
                    continue;
                }

                results.push(instance.clone());
            }
        }

        // Sort by BitSage price (cheapest first)
        results.sort_by(|a, b| a.bitsage_price_cents.cmp(&b.bitsage_price_cents));
        results
    }

    /// Get cheapest instance matching requirements
    pub async fn find_cheapest_instance(
        &self,
        min_gpus: u32,
        min_vram_gib: u32,
        require_tee: bool,
    ) -> Option<CloudGpuInstance> {
        self.find_instances(min_gpus, min_vram_gib, None, require_tee)
            .await
            .into_iter()
            .next()
    }

    /// Provision an instance from a cloud provider
    pub async fn provision_instance(
        &self,
        instance_type: &CloudGpuInstance,
        _ssh_public_key: &str,
    ) -> Result<ProvisionedInstance> {
        let config = self.configs.get(&instance_type.provider)
            .ok_or_else(|| anyhow!("Provider {:?} not configured", instance_type.provider))?;

        if !config.enabled {
            return Err(anyhow!("Provider {:?} is disabled", instance_type.provider));
        }

        // Check spend limits
        let current_spend = *self.hourly_spend_cents.read().await;
        if current_spend + instance_type.bitsage_price_cents as u64 > config.max_hourly_spend_cents {
            return Err(anyhow!(
                "Would exceed hourly spend limit (current: ${:.2}, instance: ${:.2}, limit: ${:.2})",
                current_spend as f64 / 100.0,
                instance_type.bitsage_price_cents as f64 / 100.0,
                config.max_hourly_spend_cents as f64 / 100.0
            ));
        }

        // For now, return a placeholder - real implementation would call provider API
        // TODO: Implement actual API calls to providers
        let instance = ProvisionedInstance {
            instance_id: format!("bitsage-{}-{}",
                instance_type.provider.display_name().to_lowercase(),
                uuid::Uuid::new_v4().to_string()[..8].to_string()
            ),
            provider: instance_type.provider,
            instance_type: instance_type.instance_type.clone(),
            ip_address: None,
            ssh_port: 22,
            status: InstanceStatus::Provisioning,
            created_at: Utc::now(),
            hourly_cost_cents: instance_type.bitsage_price_cents,
            total_cost_cents: 0,
        };

        // Track the instance
        {
            let mut instances = self.active_instances.write().await;
            instances.insert(instance.instance_id.clone(), instance.clone());
        }

        // Update spend tracking
        {
            let mut spend = self.hourly_spend_cents.write().await;
            *spend += instance.hourly_cost_cents as u64;
        }

        info!(
            "Provisioning {} instance {} (${:.2}/hr)",
            instance_type.provider.display_name(),
            instance.instance_id,
            instance.hourly_cost_cents as f64 / 100.0
        );

        Ok(instance)
    }

    /// Terminate a provisioned instance
    pub async fn terminate_instance(&self, instance_id: &str) -> Result<()> {
        let instance = {
            let mut instances = self.active_instances.write().await;
            instances.remove(instance_id)
        };

        if let Some(instance) = instance {
            // Update spend tracking
            {
                let mut spend = self.hourly_spend_cents.write().await;
                *spend = spend.saturating_sub(instance.hourly_cost_cents as u64);
            }

            info!(
                "Terminated {} instance {}",
                instance.provider.display_name(),
                instance_id
            );
            Ok(())
        } else {
            Err(anyhow!("Instance {} not found", instance_id))
        }
    }

    /// Get all active instances
    pub async fn list_active_instances(&self) -> Vec<ProvisionedInstance> {
        self.active_instances.read().await.values().cloned().collect()
    }

    /// Get all cached instance types
    pub async fn list_all_instance_types(&self) -> Vec<CloudGpuInstance> {
        let cache = self.instance_cache.read().await;
        cache.values().flatten().cloned().collect()
    }

    /// Get provider statistics
    pub async fn get_provider_stats(&self) -> ProviderStats {
        let active = self.active_instances.read().await;
        let hourly_spend = *self.hourly_spend_cents.read().await;

        ProviderStats {
            active_instances: active.len(),
            hourly_spend_cents: hourly_spend,
            providers_enabled: self.configs.values().filter(|c| c.enabled).count(),
            total_instance_types_cached: self.instance_cache.read().await.values().map(|v| v.len()).sum(),
        }
    }
}

/// Provider statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderStats {
    pub active_instances: usize,
    pub hourly_spend_cents: u64,
    pub providers_enabled: usize,
    pub total_instance_types_cached: usize,
}

/// Shadeform API client for aggregated access
pub struct ShadeformClient {
    client: reqwest::Client,
    api_key: String,
}

impl ShadeformClient {
    pub fn new(api_key: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key,
        }
    }

    /// List available GPU instances from Shadeform
    pub async fn list_instances(&self, gpu_type: Option<&str>) -> Result<Vec<ShadeformInstance>> {
        let mut url = format!("{}/instances", CloudProvider::Shadeform.api_base_url());
        if let Some(gpu) = gpu_type {
            url = format!("{}?gpu_type={}", url, gpu);
        }

        let response = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!("Shadeform API error: {}", response.status()));
        }

        let instances: Vec<ShadeformInstance> = response.json().await?;
        Ok(instances)
    }

    /// Launch an instance
    pub async fn launch_instance(
        &self,
        instance_type: &str,
        cloud_provider: &str,
        ssh_key: &str,
    ) -> Result<String> {
        let response = self.client
            .post(&format!("{}/instances", CloudProvider::Shadeform.api_base_url()))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&serde_json::json!({
                "instance_type": instance_type,
                "cloud": cloud_provider,
                "ssh_key": ssh_key,
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!("Failed to launch instance: {}", response.status()));
        }

        let result: serde_json::Value = response.json().await?;
        result["instance_id"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("No instance_id in response"))
    }
}

/// Shadeform instance type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadeformInstance {
    pub id: String,
    pub cloud: String,
    pub instance_type: String,
    pub gpu_type: String,
    pub num_gpus: u32,
    pub price_per_hour: f64,
    pub availability: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_provider_manager() {
        let manager = ProviderManager::new(vec![]);
        manager.initialize_static_pricing().await;

        // Find H100 instances
        let h100s = manager.find_instances(1, 80, None, false).await;
        assert!(!h100s.is_empty(), "Should find H100 instances");

        // Find cheapest
        let cheapest = manager.find_cheapest_instance(1, 80, false).await;
        assert!(cheapest.is_some());
        println!("Cheapest H100: {:?}", cheapest);
    }
}
