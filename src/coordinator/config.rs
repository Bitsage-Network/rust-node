//! # Coordinator Configuration System
//!
//! Comprehensive configuration management for the enhanced coordinator system,
//! supporting multiple environments and deployment scenarios.

use serde::{Deserialize, Serialize};
use std::path::Path;
use anyhow::{Result, Context};
use tracing::{info, warn};

use crate::coordinator::kafka::KafkaConfig;

/// Main coordinator configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatorConfig {
    /// Database configuration
    pub database_url: String,
    
    /// Kafka configuration
    pub kafka: KafkaConfig,
    
    /// Network coordination configuration
    pub network: NetworkCoordinatorConfig,
    
    /// Job processor configuration
    pub job_processor: JobProcessorConfig,
    
    /// Worker manager configuration
    pub worker_manager: WorkerManagerConfig,
    
    /// Blockchain integration configuration
    pub blockchain: BlockchainConfig,
    
    /// Metrics configuration
    pub metrics: MetricsConfig,
    
    /// Environment-specific settings
    pub environment: Environment,
    
    /// Logging configuration
    pub logging: LoggingConfig,
    
    /// Security configuration
    pub security: SecurityConfig,
}

/// Environment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(PartialEq)]
pub enum Environment {
    Development,
    Staging,
    Production,
    Test,
}

impl Default for Environment {
    fn default() -> Self {
        Environment::Development
    }
}

/// Network coordinator configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCoordinatorConfig {
    /// P2P network configuration
    pub p2p: crate::network::P2PConfig,
    
    /// Job distribution configuration
    pub job_distribution: crate::network::JobDistributionConfig,
    
    /// Health reputation configuration
    pub health_reputation: crate::network::HealthReputationConfig,
    
    /// Result collection configuration
    pub result_collection: crate::network::ResultCollectionConfig,
    
    /// Discovery configuration
    pub discovery: crate::network::DiscoveryConfig,
    
    /// Gossip configuration
    pub gossip: crate::network::GossipConfig,
    
    /// Network monitoring settings
    pub monitoring: NetworkMonitoringConfig,
}

/// Network monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMonitoringConfig {
    /// Enable network metrics collection
    pub enable_metrics: bool,
    
    /// Network health check interval in seconds
    pub health_check_interval_secs: u64,
    
    /// Network performance monitoring
    pub enable_performance_monitoring: bool,
    
    /// Network topology discovery
    pub enable_topology_discovery: bool,
}

impl Default for NetworkMonitoringConfig {
    fn default() -> Self {
        Self {
            enable_metrics: true,
            health_check_interval_secs: 30,
            enable_performance_monitoring: true,
            enable_topology_discovery: true,
        }
    }
}

/// Job processor configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobProcessorConfig {
    /// Maximum concurrent jobs
    pub max_concurrent_jobs: usize,
    
    /// Job queue size
    pub job_queue_size: usize,
    
    /// Job timeout in seconds
    pub job_timeout_secs: u64,
    
    /// Job retry configuration
    pub retry_config: RetryConfig,
    
    /// Job scheduling configuration
    pub scheduling: JobSchedulingConfig,
    
    /// Job validation configuration
    pub validation: JobValidationConfig,
}

/// Job retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum retry attempts
    pub max_retries: u32,
    
    /// Retry delay in seconds
    pub retry_delay_secs: u64,
    
    /// Exponential backoff multiplier
    pub backoff_multiplier: f64,
    
    /// Maximum retry delay in seconds
    pub max_retry_delay_secs: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_delay_secs: 5,
            backoff_multiplier: 2.0,
            max_retry_delay_secs: 300,
        }
    }
}

/// Job scheduling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSchedulingConfig {
    /// Enable priority-based scheduling
    pub enable_priority_scheduling: bool,
    
    /// Enable load balancing
    pub enable_load_balancing: bool,
    
    /// Enable geographic distribution
    pub enable_geographic_distribution: bool,
    
    /// Scheduling algorithm
    pub algorithm: SchedulingAlgorithm,
    
    /// Worker selection strategy
    pub worker_selection: WorkerSelectionStrategy,
}

/// Scheduling algorithm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SchedulingAlgorithm {
    RoundRobin,
    LeastLoaded,
    Geographic,
    ReputationBased,
    Hybrid,
}

/// Worker selection strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkerSelectionStrategy {
    BestMatch,
    FastestResponse,
    LowestCost,
    HighestReputation,
    Balanced,
}

/// Job validation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobValidationConfig {
    /// Enable job validation
    pub enable_validation: bool,
    
    /// Maximum job size in bytes
    pub max_job_size_bytes: u64,
    
    /// Allowed job types
    pub allowed_job_types: Vec<String>,
    
    /// Maximum job duration in seconds
    pub max_job_duration_secs: u64,
    
    /// Enable security validation
    pub enable_security_validation: bool,
}

/// Worker manager configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerManagerConfig {
    /// Maximum workers per region
    pub max_workers_per_region: usize,
    
    /// Worker health check interval in seconds
    pub health_check_interval_secs: u64,
    
    /// Worker timeout in seconds
    pub worker_timeout_secs: u64,
    
    /// Worker registration configuration
    pub registration: WorkerRegistrationConfig,
    
    /// Worker monitoring configuration
    pub monitoring: WorkerMonitoringConfig,
}

/// Worker registration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRegistrationConfig {
    /// Enable automatic worker registration
    pub enable_auto_registration: bool,
    
    /// Require worker authentication
    pub require_authentication: bool,
    
    /// Worker capability validation
    pub enable_capability_validation: bool,
    
    /// Worker reputation threshold
    pub min_reputation_threshold: f64,
}

/// Worker monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerMonitoringConfig {
    /// Enable worker performance monitoring
    pub enable_performance_monitoring: bool,
    
    /// Enable worker health monitoring
    pub enable_health_monitoring: bool,
    
    /// Enable worker load monitoring
    pub enable_load_monitoring: bool,
    
    /// Worker metrics collection interval in seconds
    pub metrics_interval_secs: u64,
}

/// Blockchain configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainConfig {
    /// Starknet RPC URL
    pub rpc_url: String,

    /// Job manager contract address
    pub job_manager_address: String,

    /// CDC pool contract address
    pub cdc_pool_address: String,

    /// SAGE token contract address
    pub sage_token_address: String,

    /// Prover staking contract address for worker registration verification
    pub staking_contract_address: String,

    /// Reputation manager contract address for worker reputation queries
    pub reputation_contract_address: String,

    /// Enable on-chain staking verification for worker registration
    pub enable_staking_verification: bool,

    /// Enable on-chain reputation queries for worker selection
    pub enable_reputation_queries: bool,

    /// Blockchain monitoring configuration
    pub monitoring: BlockchainMonitoringConfig,

    /// Gas optimization settings
    pub gas_optimization: GasOptimizationConfig,

    /// Signer private key (hex string)
    pub signer_private_key: String,

    /// Signer account address (hex string)
    pub signer_account_address: String,
}

/// Blockchain monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainMonitoringConfig {
    /// Enable blockchain monitoring
    pub enable_monitoring: bool,
    
    /// Block polling interval in seconds
    pub block_polling_interval_secs: u64,
    
    /// Transaction monitoring
    pub enable_transaction_monitoring: bool,
    
    /// Contract event monitoring
    pub enable_event_monitoring: bool,
}

/// Gas optimization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasOptimizationConfig {
    /// Enable gas optimization
    pub enable_optimization: bool,
    
    /// Maximum gas price in wei
    pub max_gas_price: u64,
    
    /// Gas price multiplier
    pub gas_price_multiplier: f64,
    
    /// Priority gas price in wei
    pub priority_gas_price: u64,
}

/// Metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable metrics collection
    pub enable_metrics: bool,
    
    /// Metrics collection interval in seconds
    pub collection_interval_secs: u64,
    
    /// Metrics export configuration
    pub export: MetricsExportConfig,
    
    /// Metrics storage configuration
    pub storage: MetricsStorageConfig,
}

/// Metrics export configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsExportConfig {
    /// Enable Prometheus export
    pub enable_prometheus: bool,
    
    /// Prometheus endpoint
    pub prometheus_endpoint: String,
    
    /// Enable Graphite export
    pub enable_graphite: bool,
    
    /// Graphite endpoint
    pub graphite_endpoint: String,
}

/// Metrics storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsStorageConfig {
    /// Enable metrics storage
    pub enable_storage: bool,
    
    /// Storage retention period in days
    pub retention_days: u32,
    
    /// Storage compression
    pub enable_compression: bool,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: String,
    
    /// Log format
    pub format: LogFormat,
    
    /// Enable structured logging
    pub enable_structured_logging: bool,
    
    /// Log file configuration
    pub file: LogFileConfig,
}

/// Log format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogFormat {
    Json,
    Text,
    Compact,
}

/// Log file configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogFileConfig {
    /// Enable file logging
    pub enable_file_logging: bool,
    
    /// Log file path
    pub log_file_path: String,
    
    /// Log file rotation
    pub enable_rotation: bool,
    
    /// Maximum log file size in MB
    pub max_file_size_mb: u64,
    
    /// Maximum log files
    pub max_files: u32,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable authentication
    pub enable_authentication: bool,
    
    /// Enable authorization
    pub enable_authorization: bool,
    
    /// API key configuration
    pub api_keys: ApiKeyConfig,
    
    /// Rate limiting configuration
    pub rate_limiting: RateLimitingConfig,
    
    /// TLS configuration
    pub tls: TlsConfig,
}

/// API key configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    /// API key file path
    pub api_key_file: String,
    
    /// API key rotation interval in days
    pub rotation_interval_days: u32,
    
    /// Enable API key validation
    pub enable_validation: bool,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    /// Enable rate limiting
    pub enable_rate_limiting: bool,
    
    /// Requests per minute
    pub requests_per_minute: u32,
    
    /// Burst size
    pub burst_size: u32,
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Enable TLS
    pub enable_tls: bool,
    
    /// Certificate file path
    pub certificate_file: String,
    
    /// Private key file path
    pub private_key_file: String,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            database_url: "postgresql://localhost/sage".to_string(),
            kafka: KafkaConfig::default(),
            network: NetworkCoordinatorConfig::default(),
            job_processor: JobProcessorConfig::default(),
            worker_manager: WorkerManagerConfig::default(),
            blockchain: BlockchainConfig::default(),
            metrics: MetricsConfig::default(),
            environment: Environment::Development,
            logging: LoggingConfig::default(),
            security: SecurityConfig::default(),
        }
    }
}

impl Default for NetworkCoordinatorConfig {
    fn default() -> Self {
        Self {
            p2p: crate::network::P2PConfig::default(),
            job_distribution: crate::network::JobDistributionConfig::default(),
            health_reputation: crate::network::HealthReputationConfig::default(),
            result_collection: crate::network::ResultCollectionConfig::default(),
            discovery: crate::network::DiscoveryConfig::default(),
            gossip: crate::network::GossipConfig::default(),
            monitoring: NetworkMonitoringConfig::default(),
        }
    }
}

impl Default for JobProcessorConfig {
    fn default() -> Self {
        Self {
            max_concurrent_jobs: 100,
            job_queue_size: 1000,
            job_timeout_secs: 3600,
            retry_config: RetryConfig::default(),
            scheduling: JobSchedulingConfig::default(),
            validation: JobValidationConfig::default(),
        }
    }
}

impl Default for JobSchedulingConfig {
    fn default() -> Self {
        Self {
            enable_priority_scheduling: true,
            enable_load_balancing: true,
            enable_geographic_distribution: true,
            algorithm: SchedulingAlgorithm::Hybrid,
            worker_selection: WorkerSelectionStrategy::Balanced,
        }
    }
}

impl Default for JobValidationConfig {
    fn default() -> Self {
        Self {
            enable_validation: true,
            max_job_size_bytes: 100 * 1024 * 1024, // 100MB
            allowed_job_types: vec![
                "render3d".to_string(),
                "ai".to_string(),
                "video".to_string(),
                "computer_vision".to_string(),
                "nlp".to_string(),
            ],
            max_job_duration_secs: 86400, // 24 hours
            enable_security_validation: true,
        }
    }
}

impl Default for WorkerManagerConfig {
    fn default() -> Self {
        Self {
            max_workers_per_region: 100,
            health_check_interval_secs: 30,
            worker_timeout_secs: 300,
            registration: WorkerRegistrationConfig::default(),
            monitoring: WorkerMonitoringConfig::default(),
        }
    }
}

impl Default for WorkerRegistrationConfig {
    fn default() -> Self {
        Self {
            enable_auto_registration: true,
            require_authentication: false,
            enable_capability_validation: true,
            min_reputation_threshold: 0.5,
        }
    }
}

impl Default for WorkerMonitoringConfig {
    fn default() -> Self {
        Self {
            enable_performance_monitoring: true,
            enable_health_monitoring: true,
            enable_load_monitoring: true,
            metrics_interval_secs: 60,
        }
    }
}

impl Default for BlockchainConfig {
    fn default() -> Self {
        Self {
            rpc_url: "https://starknet-sepolia.public.blastapi.io".to_string(),
            job_manager_address: "0x00bf025663b8a7c7e43393f082b10afe66bd9ddb06fb5e521e3adbcf693094bd".to_string(),
            cdc_pool_address: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            sage_token_address: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            staking_contract_address: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            reputation_contract_address: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            enable_staking_verification: true,
            enable_reputation_queries: true,
            monitoring: BlockchainMonitoringConfig::default(),
            gas_optimization: GasOptimizationConfig::default(),
            signer_private_key: "".to_string(),
            signer_account_address: "".to_string(),
        }
    }
}

impl Default for BlockchainMonitoringConfig {
    fn default() -> Self {
        Self {
            enable_monitoring: true,
            block_polling_interval_secs: 10,
            enable_transaction_monitoring: true,
            enable_event_monitoring: true,
        }
    }
}

impl Default for GasOptimizationConfig {
    fn default() -> Self {
        Self {
            enable_optimization: true,
            max_gas_price: 1000000000, // 1 gwei
            gas_price_multiplier: 1.1,
            priority_gas_price: 2000000000, // 2 gwei
        }
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enable_metrics: true,
            collection_interval_secs: 60,
            export: MetricsExportConfig::default(),
            storage: MetricsStorageConfig::default(),
        }
    }
}

impl Default for MetricsExportConfig {
    fn default() -> Self {
        Self {
            enable_prometheus: true,
            prometheus_endpoint: "0.0.0.0:9090".to_string(),
            enable_graphite: false,
            graphite_endpoint: "localhost:2003".to_string(),
        }
    }
}

impl Default for MetricsStorageConfig {
    fn default() -> Self {
        Self {
            enable_storage: true,
            retention_days: 30,
            enable_compression: true,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: LogFormat::Json,
            enable_structured_logging: true,
            file: LogFileConfig::default(),
        }
    }
}

impl Default for LogFileConfig {
    fn default() -> Self {
        Self {
            enable_file_logging: true,
            log_file_path: "logs/coordinator.log".to_string(),
            enable_rotation: true,
            max_file_size_mb: 100,
            max_files: 10,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_authentication: false,
            enable_authorization: false,
            api_keys: ApiKeyConfig::default(),
            rate_limiting: RateLimitingConfig::default(),
            tls: TlsConfig::default(),
        }
    }
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            api_key_file: "config/api_keys.json".to_string(),
            rotation_interval_days: 30,
            enable_validation: true,
        }
    }
}

impl Default for RateLimitingConfig {
    fn default() -> Self {
        Self {
            enable_rate_limiting: true,
            requests_per_minute: 1000,
            burst_size: 100,
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enable_tls: false,
            certificate_file: "config/cert.pem".to_string(),
            private_key_file: "config/key.pem".to_string(),
        }
    }
}

/// Load configuration from file
pub fn load_config<P: AsRef<Path>>(path: P) -> Result<CoordinatorConfig> {
    let path = path.as_ref();
    info!("Loading configuration from: {}", path.display());
    
    if !path.exists() {
        warn!("Configuration file does not exist, using default configuration");
        return Ok(CoordinatorConfig::default());
    }
    
    let content = std::fs::read_to_string(path)
        .context("Failed to read configuration file")?;
    
    let config: CoordinatorConfig = toml::from_str(&content)
        .context("Failed to parse configuration file")?;
    
    info!("Configuration loaded successfully");
    Ok(config)
}

/// Save configuration to file
pub fn save_config<P: AsRef<Path>>(config: &CoordinatorConfig, path: P) -> Result<()> {
    let path = path.as_ref();
    info!("Saving configuration to: {}", path.display());
    
    // Create directory if it doesn't exist
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .context("Failed to create configuration directory")?;
    }
    
    let content = toml::to_string_pretty(config)
        .context("Failed to serialize configuration")?;
    
    std::fs::write(path, content)
        .context("Failed to write configuration file")?;
    
    info!("Configuration saved successfully");
    Ok(())
}

/// Generate default configuration for environment
pub fn generate_default_config(environment: Environment) -> CoordinatorConfig {
    let mut config = CoordinatorConfig::default();
    config.environment = environment.clone();
    
    match environment {
        Environment::Development => {
            config.database_url = "postgresql://localhost/sage_dev".to_string();
            config.blockchain.rpc_url = "https://starknet-sepolia.public.blastapi.io".to_string();
            config.logging.level = "debug".to_string();
            config.metrics.enable_metrics = false;
        }
        Environment::Staging => {
            config.database_url = "postgresql://localhost/sage_staging".to_string();
            config.blockchain.rpc_url = "https://starknet-sepolia.public.blastapi.io".to_string();
            config.logging.level = "info".to_string();
            config.security.enable_authentication = true;
        }
        Environment::Production => {
            config.database_url = "postgresql://sage:password@localhost/sage_prod".to_string();
            config.blockchain.rpc_url = "https://starknet-mainnet.public.blastapi.io".to_string();
            config.logging.level = "warn".to_string();
            config.security.enable_authentication = true;
            config.security.enable_authorization = true;
            config.metrics.enable_metrics = true;
        }
        Environment::Test => {
            config.database_url = "postgresql://localhost/sage_test".to_string();
            config.blockchain.rpc_url = "https://starknet-sepolia.public.blastapi.io".to_string();
            config.logging.level = "error".to_string();
            config.metrics.enable_metrics = false;
        }
    }
    
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = CoordinatorConfig::default();
        assert_eq!(config.database_url, "postgresql://localhost/sage");
        assert_eq!(config.environment, Environment::Development);
    }

    #[test]
    fn test_production_config() {
        let config = generate_default_config(Environment::Production);
        assert_eq!(config.environment, Environment::Production);
        assert!(config.security.enable_authentication);
        assert!(config.metrics.enable_metrics);
    }

    #[test]
    fn test_config_serialization() {
        let config = CoordinatorConfig::default();
        let serialized = toml::to_string(&config).unwrap();
        let deserialized: CoordinatorConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(config.database_url, deserialized.database_url);
    }
} 