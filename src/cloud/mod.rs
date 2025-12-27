//! # Cloud Provider Integration
//!
//! This module provides a unified interface for provisioning and managing
//! GPU compute resources across multiple cloud providers.

pub mod providers;
pub mod gpu_manager;

pub use providers::{CloudProvider, ProviderType, GpuInstance, GpuSpec};
pub use gpu_manager::CloudGpuManager;

use serde::{Deserialize, Serialize};

/// Cloud provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudConfig {
    pub enabled_providers: Vec<ProviderType>,
    pub aws: Option<AwsConfig>,
    pub azure: Option<AzureConfig>,
    pub gcp: Option<GcpConfig>,
    pub ibm: Option<IbmConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsConfig {
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub instance_types: Vec<String>, // e.g., ["p4d.24xlarge", "p5.48xlarge"]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureConfig {
    pub subscription_id: String,
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
    pub instance_types: Vec<String>, // e.g., ["Standard_NC96ads_A100_v4"]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpConfig {
    pub project_id: String,
    pub zone: String,
    pub credentials_path: String,
    pub instance_types: Vec<String>, // e.g., ["a2-highgpu-8g"]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IbmConfig {
    pub api_key: String,
    pub region: String,
    pub instance_types: Vec<String>,
}

impl Default for CloudConfig {
    fn default() -> Self {
        Self {
            enabled_providers: vec![ProviderType::Aws, ProviderType::Azure, ProviderType::Gcp],
            aws: Some(AwsConfig {
                region: "us-east-1".to_string(),
                access_key_id: std::env::var("AWS_ACCESS_KEY_ID").unwrap_or_default(),
                secret_access_key: std::env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default(),
                instance_types: vec![
                    "p4d.24xlarge".to_string(),  // 8x A100 (40GB)
                    "p5.48xlarge".to_string(),   // 8x H100 (80GB)
                ],
            }),
            azure: Some(AzureConfig {
                subscription_id: std::env::var("AZURE_SUBSCRIPTION_ID").unwrap_or_default(),
                tenant_id: std::env::var("AZURE_TENANT_ID").unwrap_or_default(),
                client_id: std::env::var("AZURE_CLIENT_ID").unwrap_or_default(),
                client_secret: std::env::var("AZURE_CLIENT_SECRET").unwrap_or_default(),
                instance_types: vec![
                    "Standard_NC96ads_A100_v4".to_string(), // 4x A100
                    "Standard_ND96isr_H100_v5".to_string(), // 8x H100
                ],
            }),
            gcp: Some(GcpConfig {
                project_id: std::env::var("GCP_PROJECT_ID").unwrap_or_default(),
                zone: "us-central1-a".to_string(),
                credentials_path: std::env::var("GOOGLE_APPLICATION_CREDENTIALS").unwrap_or_default(),
                instance_types: vec![
                    "a2-highgpu-8g".to_string(),     // 8x A100 (40GB)
                    "a3-highgpu-8g".to_string(),     // 8x H100 (80GB)
                ],
            }),
            ibm: Some(IbmConfig {
                api_key: std::env::var("IBM_API_KEY").unwrap_or_default(),
                region: "us-south".to_string(),
                instance_types: vec!["gx2-16x128x2v100".to_string()],
            }),
        }
    }
}

