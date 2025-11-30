//! # Cloud GPU Manager
//!
//! Orchestrates GPU provisioning and lifecycle management across multiple cloud providers.

use super::providers::{CloudProvider, GpuInstance, ProviderType, InstanceStatus};
use super::CloudConfig;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error};

/// Manages GPU instances across multiple cloud providers
pub struct CloudGpuManager {
    config: CloudConfig,
    providers: HashMap<ProviderType, Box<dyn CloudProvider>>,
    active_instances: Arc<RwLock<HashMap<String, GpuInstance>>>,
}

impl CloudGpuManager {
    /// Create a new cloud GPU manager with the given providers
    pub fn new(
        config: CloudConfig,
        providers: HashMap<ProviderType, Box<dyn CloudProvider>>,
    ) -> Self {
        Self {
            config,
            providers,
            active_instances: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// List all available GPU types across all enabled providers
    pub async fn list_all_available_gpus(&self) -> Result<HashMap<ProviderType, Vec<String>>> {
        let mut available = HashMap::new();

        for provider_type in &self.config.enabled_providers {
            if let Some(provider) = self.providers.get(provider_type) {
                match provider.list_available_gpu_types().await {
                    Ok(types) => {
                        info!("Available GPU types for {}: {:?}", provider_type, types);
                        available.insert(*provider_type, types);
                    }
                    Err(e) => {
                        warn!("Failed to list GPUs for {}: {}", provider_type, e);
                    }
                }
            }
        }

        Ok(available)
    }

    /// Launch a GPU instance with automatic provider selection
    pub async fn launch_best_available_gpu(
        &self,
        min_gpu_memory_gb: u32,
        requires_confidential_compute: bool,
        tags: HashMap<String, String>,
    ) -> Result<GpuInstance> {
        // Try each enabled provider in order
        for provider_type in &self.config.enabled_providers {
            if let Some(provider) = self.providers.get(provider_type) {
                match self.try_launch_on_provider(
                    provider.as_ref(),
                    min_gpu_memory_gb,
                    requires_confidential_compute,
                    tags.clone(),
                ).await {
                    Ok(instance) => {
                        info!("Successfully launched instance {} on {}", 
                              instance.instance_id, provider_type);
                        self.active_instances.write().await
                            .insert(instance.instance_id.clone(), instance.clone());
                        return Ok(instance);
                    }
                    Err(e) => {
                        warn!("Failed to launch on {}: {}", provider_type, e);
                        continue;
                    }
                }
            }
        }

        Err(anyhow!("Failed to launch GPU instance on any provider"))
    }

    /// Launch on a specific provider
    pub async fn launch_on_provider(
        &self,
        provider_type: ProviderType,
        instance_type: &str,
        tags: HashMap<String, String>,
    ) -> Result<GpuInstance> {
        let provider = self.providers.get(&provider_type)
            .ok_or_else(|| anyhow!("Provider {} not configured", provider_type))?;

        let instance = provider.launch_instance(instance_type, tags).await?;
        
        info!("Launched {} instance {} ({})", 
              provider_type, instance.instance_id, instance_type);

        self.active_instances.write().await
            .insert(instance.instance_id.clone(), instance.clone());

        Ok(instance)
    }

    /// Try to launch on a specific provider
    async fn try_launch_on_provider(
        &self,
        provider: &dyn CloudProvider,
        min_gpu_memory_gb: u32,
        requires_confidential_compute: bool,
        tags: HashMap<String, String>,
    ) -> Result<GpuInstance> {
        let available_types = provider.list_available_gpu_types().await?;

        // Find the cheapest instance that meets requirements
        let mut best_option: Option<(String, f32, bool)> = None;

        for instance_type in available_types {
            let spec = provider.get_gpu_spec(&instance_type).await?;
            let cost = provider.get_hourly_cost(&instance_type).await?;
            let has_tee = provider.supports_confidential_compute(&instance_type).await?;

            // Check requirements
            if spec.memory_gb < min_gpu_memory_gb {
                continue;
            }
            if requires_confidential_compute && !has_tee {
                continue;
            }

            // Update best option if cheaper
            if best_option.is_none() || cost < best_option.as_ref().unwrap().1 {
                best_option = Some((instance_type.clone(), cost, has_tee));
            }
        }

        let (instance_type, cost, has_tee) = best_option
            .ok_or_else(|| anyhow!("No suitable instance found"))?;

        info!("Selected instance type: {} (${:.2}/hr, TEE: {})", 
              instance_type, cost, has_tee);

        provider.launch_instance(&instance_type, tags).await
    }

    /// Get status of all active instances
    pub async fn get_all_instance_statuses(&self) -> Result<HashMap<String, InstanceStatus>> {
        let instances = self.active_instances.read().await;
        let mut statuses = HashMap::new();

        for (instance_id, instance) in instances.iter() {
            if let Some(provider) = self.providers.get(&instance.provider) {
                match provider.get_instance_status(instance_id).await {
                    Ok(status) => {
                        statuses.insert(instance_id.clone(), status);
                    }
                    Err(e) => {
                        error!("Failed to get status for {}: {}", instance_id, e);
                    }
                }
            }
        }

        Ok(statuses)
    }

    /// Terminate an instance
    pub async fn terminate_instance(&self, instance_id: &str) -> Result<()> {
        let instances = self.active_instances.read().await;
        let instance = instances.get(instance_id)
            .ok_or_else(|| anyhow!("Instance not found: {}", instance_id))?;

        let provider = self.providers.get(&instance.provider)
            .ok_or_else(|| anyhow!("Provider not found"))?;

        provider.terminate_instance(instance_id).await?;
        drop(instances);

        self.active_instances.write().await.remove(instance_id);
        info!("Terminated instance {}", instance_id);

        Ok(())
    }

    /// Get total cost of all running instances
    pub async fn get_total_hourly_cost(&self) -> f32 {
        let instances = self.active_instances.read().await;
        instances.values()
            .filter(|i| i.status == InstanceStatus::Running)
            .map(|i| i.hourly_cost_usd)
            .sum()
    }

    /// List all active instances
    pub async fn list_active_instances(&self) -> Vec<GpuInstance> {
        self.active_instances.read().await.values().cloned().collect()
    }

    /// Get count of running instances per provider
    pub async fn get_instance_count_by_provider(&self) -> HashMap<ProviderType, usize> {
        let instances = self.active_instances.read().await;
        let mut counts = HashMap::new();

        for instance in instances.values() {
            if instance.status == InstanceStatus::Running {
                *counts.entry(instance.provider).or_insert(0) += 1;
            }
        }

        counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::providers::MockCloudProvider;

    #[tokio::test]
    async fn test_launch_best_available_gpu() {
        let config = CloudConfig::default();
        let mut providers: HashMap<ProviderType, Box<dyn CloudProvider>> = HashMap::new();
        providers.insert(ProviderType::Aws, Box::new(MockCloudProvider::new(ProviderType::Aws)));
        providers.insert(ProviderType::Azure, Box::new(MockCloudProvider::new(ProviderType::Azure)));

        let manager = CloudGpuManager::new(config, providers);

        let mut tags = HashMap::new();
        tags.insert("job_id".to_string(), "test-123".to_string());

        let instance = manager.launch_best_available_gpu(40, false, tags).await.unwrap();
        assert_eq!(instance.status, InstanceStatus::Running);
        assert!(instance.gpu_spec.memory_gb >= 40);
    }
}

