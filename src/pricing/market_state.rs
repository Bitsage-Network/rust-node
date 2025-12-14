//! Market State Tracking
//!
//! Tracks the current state of the compute marketplace including:
//! - Active GPU providers and their capabilities
//! - Job queue status
//! - Network health metrics

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::gpu_database::{GpuArchitecture, FormFactor};

/// GPU Provider status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderStatus {
    /// Provider is online and accepting jobs
    Online,
    /// Provider is busy processing a job
    Busy,
    /// Provider is online but not accepting jobs
    Idle,
    /// Provider is offline
    Offline,
    /// Provider is suspended (slashed or under review)
    Suspended,
}

/// GPU tier for staking requirements
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GpuTier {
    /// Consumer GPUs (RTX 30xx, 40xx, 50xx)
    Consumer,
    /// Workstation GPUs (RTX A6000, L40S)
    Workstation,
    /// Data Center (A100)
    DataCenter,
    /// Enterprise (H100, H200)
    Enterprise,
    /// Frontier (B200, B300)
    Frontier,
}

impl GpuTier {
    /// Get minimum stake required for this tier (in CIRO tokens)
    pub fn min_stake(&self) -> u64 {
        match self {
            GpuTier::Consumer => 1_000,
            GpuTier::Workstation => 2_500,
            GpuTier::DataCenter => 5_000,
            GpuTier::Enterprise => 10_000,
            GpuTier::Frontier => 25_000,
        }
    }
}

/// A GPU in the provider's setup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuInfo {
    /// Model name (e.g., "H100 SXM", "RTX 4090")
    pub model: String,
    /// Architecture
    pub architecture: GpuArchitecture,
    /// Form factor
    pub form_factor: FormFactor,
    /// VRAM in GB
    pub vram_gb: u32,
    /// Memory bandwidth in GB/s
    pub bandwidth_gb_s: u32,
    /// Verified via benchmark
    pub verified: bool,
}

/// A registered GPU Provider in the network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuProvider {
    /// Unique provider ID (wallet address)
    pub id: String,
    /// Provider's staked amount (in CIRO tokens)
    pub stake_amount: u64,
    /// Current status
    pub status: ProviderStatus,
    /// GPUs owned by this provider
    pub gpus: Vec<GpuInfo>,
    /// Reputation score (0.0 to 1.0)
    pub reputation: f32,
    /// Total jobs completed
    pub total_jobs: u64,
    /// Failed jobs
    pub failed_jobs: u64,
    /// Average job completion time (ms)
    pub avg_completion_time_ms: u64,
    /// Last heartbeat timestamp
    pub last_heartbeat: u64,
    /// Geographic region
    pub region: String,
    /// Hourly rate they're offering (USD)
    pub hourly_rate_usd: f64,
}

impl GpuProvider {
    /// Get total bandwidth in GB/s
    pub fn total_bandwidth(&self) -> u32 {
        self.gpus.iter().map(|g| g.bandwidth_gb_s).sum()
    }

    /// Get total VRAM in GB
    pub fn total_vram(&self) -> u32 {
        self.gpus.iter().map(|g| g.vram_gb).sum()
    }

    /// Get GPU tier based on best GPU
    pub fn gpu_tier(&self) -> GpuTier {
        // Determine tier based on best GPU model
        for gpu in &self.gpus {
            match gpu.architecture {
                GpuArchitecture::Blackwell => return GpuTier::Frontier,
                GpuArchitecture::Hopper => return GpuTier::Enterprise,
                GpuArchitecture::Ampere if gpu.model.contains("A100") => return GpuTier::DataCenter,
                GpuArchitecture::AdaLovelace if gpu.model.contains("L40") || gpu.model.contains("A6000") => return GpuTier::Workstation,
                _ => continue,
            }
        }
        GpuTier::Consumer
    }

    /// Calculate success rate
    pub fn success_rate(&self) -> f64 {
        if self.total_jobs == 0 {
            1.0
        } else {
            (self.total_jobs - self.failed_jobs) as f64 / self.total_jobs as f64
        }
    }

    /// Check if provider is healthy and can accept jobs
    pub fn is_healthy(&self) -> bool {
        matches!(self.status, ProviderStatus::Online | ProviderStatus::Idle)
            && self.reputation > 0.5
            && self.success_rate() > 0.9
            && self.stake_amount >= self.gpu_tier().min_stake()
    }

    /// Check if provider meets minimum stake for their tier
    pub fn meets_stake_requirement(&self) -> bool {
        self.stake_amount >= self.gpu_tier().min_stake()
    }
}

/// Provider pool statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderPoolStats {
    /// Total providers registered
    pub total_providers: u64,
    /// Providers currently online
    pub online_providers: u64,
    /// Providers currently busy
    pub busy_providers: u64,
    /// Total network bandwidth (GB/s)
    pub total_bandwidth: u64,
    /// Total network VRAM (GB)
    pub total_vram: u64,
    /// Providers by tier
    pub providers_by_tier: HashMap<String, u64>,
    /// Providers by region
    pub providers_by_region: HashMap<String, u64>,
    /// Average reputation
    pub avg_reputation: f64,
    /// Total staked CIRO
    pub total_staked: u64,
}

/// Provider pool management
#[derive(Default)]
pub struct WorkerPool {
    providers: HashMap<String, GpuProvider>,
}

impl WorkerPool {
    /// Create a new provider pool
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
        }
    }

    /// Register a new provider
    pub fn register(&mut self, provider: GpuProvider) {
        self.providers.insert(provider.id.clone(), provider);
    }

    /// Update provider status
    pub fn update_status(&mut self, provider_id: &str, status: ProviderStatus) {
        if let Some(provider) = self.providers.get_mut(provider_id) {
            provider.status = status;
        }
    }

    /// Update provider heartbeat
    pub fn heartbeat(&mut self, provider_id: &str, timestamp: u64) {
        if let Some(provider) = self.providers.get_mut(provider_id) {
            provider.last_heartbeat = timestamp;
            if provider.status == ProviderStatus::Offline {
                provider.status = ProviderStatus::Online;
            }
        }
    }

    /// Get provider by ID
    pub fn get(&self, provider_id: &str) -> Option<&GpuProvider> {
        self.providers.get(provider_id)
    }

    /// Get all online providers
    pub fn online_providers(&self) -> Vec<&GpuProvider> {
        self.providers
            .values()
            .filter(|p| matches!(p.status, ProviderStatus::Online | ProviderStatus::Idle))
            .collect()
    }

    /// Get providers by GPU tier
    pub fn providers_by_tier(&self, tier: GpuTier) -> Vec<&GpuProvider> {
        self.providers
            .values()
            .filter(|p| p.gpu_tier() == tier && p.is_healthy())
            .collect()
    }

    /// Calculate pool statistics
    pub fn stats(&self) -> ProviderPoolStats {
        let mut stats = ProviderPoolStats {
            total_providers: self.providers.len() as u64,
            online_providers: 0,
            busy_providers: 0,
            total_bandwidth: 0,
            total_vram: 0,
            providers_by_tier: HashMap::new(),
            providers_by_region: HashMap::new(),
            avg_reputation: 0.0,
            total_staked: 0,
        };

        let mut total_rep = 0.0;

        for provider in self.providers.values() {
            match provider.status {
                ProviderStatus::Online | ProviderStatus::Idle => stats.online_providers += 1,
                ProviderStatus::Busy => {
                    stats.online_providers += 1;
                    stats.busy_providers += 1;
                }
                _ => {}
            }

            stats.total_bandwidth += provider.total_bandwidth() as u64;
            stats.total_vram += provider.total_vram() as u64;
            stats.total_staked += provider.stake_amount;

            let tier = format!("{:?}", provider.gpu_tier());
            *stats.providers_by_tier.entry(tier).or_insert(0) += 1;

            *stats.providers_by_region.entry(provider.region.clone()).or_insert(0) += 1;

            total_rep += provider.reputation as f64;
        }

        if !self.providers.is_empty() {
            stats.avg_reputation = total_rep / self.providers.len() as f64;
        }

        stats
    }

    /// Find cheapest available provider for a job
    pub fn find_cheapest(&self, min_vram_gb: u32) -> Option<&GpuProvider> {
        self.providers
            .values()
            .filter(|p| {
                p.is_healthy()
                    && p.status == ProviderStatus::Online
                    && p.total_vram() >= min_vram_gb
            })
            .min_by(|a, b| {
                a.hourly_rate_usd.partial_cmp(&b.hourly_rate_usd).unwrap()
            })
    }

    /// Find fastest available provider for a job
    pub fn find_fastest(&self, min_vram_gb: u32) -> Option<&GpuProvider> {
        self.providers
            .values()
            .filter(|p| {
                p.is_healthy()
                    && p.status == ProviderStatus::Online
                    && p.total_vram() >= min_vram_gb
            })
            .max_by_key(|p| p.total_bandwidth())
    }
}

/// Market state tracker (simplified - no dynamic pricing)
pub struct MarketState {
    /// Provider pool
    pub provider_pool: Arc<RwLock<WorkerPool>>,
    /// Current queue depth
    pub queue_depth: u64,
}

impl MarketState {
    /// Create a new market state tracker
    pub fn new() -> Self {
        Self {
            provider_pool: Arc::new(RwLock::new(WorkerPool::new())),
            queue_depth: 0,
        }
    }

    /// Update queue depth
    pub fn set_queue_depth(&mut self, depth: u64) {
        self.queue_depth = depth;
    }
}

impl Default for MarketState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_pool() {
        let mut pool = WorkerPool::new();

        pool.register(GpuProvider {
            id: "0x1234".to_string(),
            stake_amount: 10_000,
            status: ProviderStatus::Online,
            gpus: vec![GpuInfo {
                model: "RTX 4090".to_string(),
                architecture: GpuArchitecture::AdaLovelace,
                form_factor: FormFactor::PCIe,
                vram_gb: 24,
                bandwidth_gb_s: 1008,
                verified: true,
            }],
            reputation: 0.95,
            total_jobs: 1000,
            failed_jobs: 5,
            avg_completion_time_ms: 6000,
            last_heartbeat: 0,
            region: "us-east".to_string(),
            hourly_rate_usd: 0.50,
        });

        pool.register(GpuProvider {
            id: "0x5678".to_string(),
            stake_amount: 50_000,
            status: ProviderStatus::Busy,
            gpus: vec![
                GpuInfo {
                    model: "H100 SXM".to_string(),
                    architecture: GpuArchitecture::Hopper,
                    form_factor: FormFactor::SXM5,
                    vram_gb: 80,
                    bandwidth_gb_s: 3350,
                    verified: true,
                },
                GpuInfo {
                    model: "H100 SXM".to_string(),
                    architecture: GpuArchitecture::Hopper,
                    form_factor: FormFactor::SXM5,
                    vram_gb: 80,
                    bandwidth_gb_s: 3350,
                    verified: true,
                },
            ],
            reputation: 0.99,
            total_jobs: 50000,
            failed_jobs: 10,
            avg_completion_time_ms: 3000,
            last_heartbeat: 0,
            region: "eu-west".to_string(),
            hourly_rate_usd: 5.00,
        });

        let stats = pool.stats();
        println!("Total providers: {}", stats.total_providers);
        println!("Online providers: {}", stats.online_providers);
        println!("Total bandwidth: {} GB/s", stats.total_bandwidth);
        println!("Total staked: {} CIRO", stats.total_staked);
        println!("Average reputation: {:.2}", stats.avg_reputation);

        assert_eq!(stats.total_providers, 2);
        assert_eq!(stats.online_providers, 2);
        assert!(stats.total_bandwidth > 1000);
        assert_eq!(stats.total_staked, 60_000);
    }

    #[test]
    fn test_provider_tier_detection() {
        let consumer = GpuProvider {
            id: "consumer".to_string(),
            stake_amount: 1_000,
            status: ProviderStatus::Online,
            gpus: vec![GpuInfo {
                model: "RTX 4090".to_string(),
                architecture: GpuArchitecture::AdaLovelace,
                form_factor: FormFactor::PCIe,
                vram_gb: 24,
                bandwidth_gb_s: 1008,
                verified: true,
            }],
            reputation: 0.9,
            total_jobs: 100,
            failed_jobs: 1,
            avg_completion_time_ms: 5000,
            last_heartbeat: 0,
            region: "us-east".to_string(),
            hourly_rate_usd: 0.50,
        };

        let enterprise = GpuProvider {
            id: "enterprise".to_string(),
            stake_amount: 50_000,
            status: ProviderStatus::Online,
            gpus: vec![GpuInfo {
                model: "H100 SXM".to_string(),
                architecture: GpuArchitecture::Hopper,
                form_factor: FormFactor::SXM5,
                vram_gb: 80,
                bandwidth_gb_s: 3350,
                verified: true,
            }],
            reputation: 0.99,
            total_jobs: 10000,
            failed_jobs: 5,
            avg_completion_time_ms: 3000,
            last_heartbeat: 0,
            region: "us-west".to_string(),
            hourly_rate_usd: 3.00,
        };

        assert_eq!(consumer.gpu_tier(), GpuTier::Consumer);
        assert_eq!(enterprise.gpu_tier(), GpuTier::Enterprise);
        assert!(consumer.meets_stake_requirement());
        assert!(enterprise.meets_stake_requirement());
    }
}
