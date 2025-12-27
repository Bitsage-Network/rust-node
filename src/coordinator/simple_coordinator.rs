//! # DEPRECATED: Simple Coordinator
//!
//! **WARNING**: This module is deprecated and should not be used in new code.
//! Use `EnhancedCoordinator` from `coordinator/mod.rs` instead.
//!
//! This module contains placeholder stub types that shadow the real types.
//! It exists only for backwards compatibility and will be removed in a future version.
//!
//! ## Migration Guide
//!
//! Replace:
//! ```ignore
//! use crate::coordinator::simple_coordinator::SimpleCoordinator;
//! ```
//!
//! With:
//! ```ignore
//! use crate::coordinator::EnhancedCoordinator;
//! ```

#![deprecated(since = "0.2.0", note = "Use EnhancedCoordinator instead")]

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, debug, warn};
use uuid::Uuid;

// DEPRECATED: Placeholder types - use crate::types instead
#[deprecated(note = "Use crate::types::JobId instead")]
pub type JobId = String;
#[deprecated(note = "Use crate::types::WorkerId instead")]
pub type WorkerId = String;
#[deprecated(note = "Use crate::types::NodeId instead")]
pub type NodeId = String;

#[derive(Debug, Clone)]
pub struct JobRequest {
    pub job_type: JobType,
}

#[derive(Debug, Clone)]
pub enum JobType {
    Placeholder,
}

#[derive(Debug, Clone, PartialEq)]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone)]
pub struct WorkerInfo {
    pub worker_id: WorkerId,
    pub capabilities: WorkerCapabilities,
    pub current_load: f32,
    pub reputation: f32,
    pub node_id: NodeId,
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct WorkerCapabilities {
    pub cpu_cores: u32,
    pub ram_gb: u32,
    pub gpu_memory: u64,
}

#[derive(Debug, Clone)]
pub struct StarknetClient;

impl StarknetClient {
    pub fn new(_rpc_url: String) -> Result<Self> {
        Ok(Self)
    }
}

#[derive(Debug, Clone)]
pub struct JobManagerContract;

impl JobManagerContract {
    pub fn new_from_address(_client: Arc<StarknetClient>, _address: &str) -> Result<Self> {
        Ok(Self)
    }
}

/// Simplified coordinator configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleCoordinatorConfig {
    pub environment: String,
    pub port: u16,
    pub blockchain_rpc_url: String,
    pub job_manager_contract_address: String,
    pub kafka_bootstrap_servers: String,
    pub p2p_port: u16,
}

impl Default for SimpleCoordinatorConfig {
    fn default() -> Self {
        Self {
            environment: "development".to_string(),
            port: 8080,
            blockchain_rpc_url: "https://starknet-sepolia.public.blastapi.io".to_string(),
            job_manager_contract_address: "0x00bf025663b8a7c7e43393f082b10afe66bd9ddb06fb5e521e3adbcf693094bd".to_string(),
            kafka_bootstrap_servers: "localhost:9092".to_string(),
            p2p_port: 4001,
        }
    }
}

/// Simplified coordinator state
#[derive(Debug, Clone)]
pub struct SimpleCoordinatorState {
    pub jobs: HashMap<JobId, JobInfo>,
    pub workers: HashMap<WorkerId, WorkerInfo>,
    pub running: bool,
}

#[derive(Debug, Clone)]
pub struct JobInfo {
    pub job_id: JobId,
    pub job_type: JobType,
    pub status: JobStatus,
    pub submitted_at: chrono::DateTime<chrono::Utc>,
    pub assigned_worker: Option<WorkerId>,
    pub result: Option<Vec<u8>>,
}

/// DEPRECATED: Simplified coordinator service
///
/// **Use `EnhancedCoordinator` instead.**
///
/// This coordinator uses placeholder types and doesn't connect to real services.
#[deprecated(since = "0.2.0", note = "Use EnhancedCoordinator from coordinator/mod.rs instead")]
pub struct SimpleCoordinator {
    config: SimpleCoordinatorConfig,
    state: Arc<RwLock<SimpleCoordinatorState>>,
    starknet_client: Arc<StarknetClient>,
    job_manager_contract: Arc<JobManagerContract>,
}

#[allow(deprecated)]
impl SimpleCoordinator {
    pub fn new(config: SimpleCoordinatorConfig) -> Result<Self> {
        warn!(
            "SimpleCoordinator is DEPRECATED. Please migrate to EnhancedCoordinator. \
             See coordinator/simple_coordinator.rs for migration guide."
        );

        let starknet_client = Arc::new(StarknetClient::new(config.blockchain_rpc_url.clone())?);
        let job_manager_contract = Arc::new(JobManagerContract::new_from_address(
            starknet_client.clone(),
            &config.job_manager_contract_address,
        )?);

        let state = Arc::new(RwLock::new(SimpleCoordinatorState {
            jobs: HashMap::new(),
            workers: HashMap::new(),
            running: false,
        }));

        Ok(Self {
            config,
            state,
            starknet_client,
            job_manager_contract,
        })
    }

    /// Start the coordinator
    pub async fn start(&self) -> Result<()> {
        info!("Starting simple coordinator on port {}", self.config.port);
        
        let mut state = self.state.write().await;
        state.running = true;
        drop(state);

        // Start health monitoring
        self.start_health_monitoring().await?;

        info!("Simple coordinator started successfully");
        Ok(())
    }

    /// Stop the coordinator
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping simple coordinator");
        
        let mut state = self.state.write().await;
        state.running = false;
        
        info!("Simple coordinator stopped");
        Ok(())
    }

    /// Submit a new job
    pub async fn submit_job(&self, request: JobRequest) -> Result<JobId> {
        info!("Submitting job: {:?}", request);
        
        // Generate job ID (using UUID since JobId is now String)
        let job_id = uuid::Uuid::new_v4().to_string();
        
        // Create job details
        let job_details = JobInfo {
            job_id: job_id.clone(),
            job_type: request.job_type,
            status: JobStatus::Pending,
            submitted_at: chrono::Utc::now(),
            assigned_worker: None,
            result: None,
        };
        
        // Store job in state
        {
            let mut state = self.state.write().await;
            state.jobs.insert(job_id.clone(), job_details);
        }
        
        // Update statistics
        self.update_job_stats().await;
        
        info!("Job {} submitted successfully", job_id);
        Ok(job_id)
    }

    /// Register a worker
    pub async fn register_worker(&self, worker_id: WorkerId, capabilities: WorkerCapabilities) -> Result<()> {
        let worker_info = WorkerInfo {
            worker_id: worker_id.clone(),
            node_id: Uuid::new_v4().to_string(),
            capabilities,
            current_load: 0.0,
            reputation: 1.0,
            last_seen: chrono::Utc::now(),
        };

        {
            let mut state = self.state.write().await;
            state.workers.insert(worker_id.clone(), worker_info);
        }

        info!("Worker {} registered successfully", worker_id);
        Ok(())
    }

    /// Get all jobs
    pub async fn get_jobs(&self) -> Vec<JobInfo> {
        let state = self.state.read().await;
        state.jobs.values().cloned().collect()
    }

    /// Get all workers
    pub async fn get_workers(&self) -> Vec<WorkerInfo> {
        let state = self.state.read().await;
        state.workers.values().cloned().collect()
    }

    /// Get coordinator status
    pub async fn get_status(&self) -> CoordinatorStatus {
        let state = self.state.read().await;
        
        CoordinatorStatus {
            running: state.running,
            total_jobs: state.jobs.len() as u64,
            total_workers: state.workers.len() as u64,
            pending_jobs: state.jobs.values().filter(|j| j.status == JobStatus::Pending).count() as u64,
            active_workers: state.workers.values().filter(|w| w.current_load < 1.0).count() as u64,
        }
    }

    /// Health check
    pub async fn health_check(&self) -> Result<()> {
        let state = self.state.read().await;
        if !state.running {
            return Err(anyhow::anyhow!("Coordinator not running"));
        }
        Ok(())
    }

    /// Start health monitoring
    async fn start_health_monitoring(&self) -> Result<()> {
        let state = Arc::clone(&self.state);
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                let running = {
                    let state_guard = state.read().await;
                    state_guard.running
                };
                
                if !running {
                    break;
                }
                
                // Simple health check
                info!("Coordinator health check passed");
            }
        });

        Ok(())
    }

    async fn update_job_stats(&self) {
        // TODO: Implement job statistics update
        debug!("Updating job statistics");
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatorStatus {
    pub running: bool,
    pub total_jobs: u64,
    pub total_workers: u64,
    pub pending_jobs: u64,
    pub active_workers: u64,
}

#[cfg(all(test, feature = "broken_tests"))]
mod tests {
    use super::*;
    use crate::node::coordinator::{JobType, JobRequest};

    #[tokio::test]
    async fn test_simple_coordinator_creation() {
        let config = SimpleCoordinatorConfig::default();
        let coordinator = SimpleCoordinator::new(config).unwrap();
        
        assert!(!coordinator.get_status().await.running);
    }

    #[tokio::test]
    async fn test_job_submission() {
        let config = SimpleCoordinatorConfig::default();
        let coordinator = SimpleCoordinator::new(config).unwrap();
        
        let request = JobRequest {
            job_type: JobType::Render3D { 
                scene_data: vec![1, 2, 3],
                resolution: (1920, 1080),
                quality: "high".to_string(),
            },
            priority: 1,
            max_cost: 1000,
            deadline: None,
            client_address: "0x123".to_string(),
            callback_url: None,
            data: vec![1, 2, 3],
            max_duration_secs: 3600,
        };
        
        let job_id = coordinator.submit_job(request).await.unwrap();
        let jobs = coordinator.get_jobs().await;
        
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].job_id, job_id);
    }

    #[tokio::test]
    async fn test_worker_registration() {
        let config = SimpleCoordinatorConfig::default();
        let coordinator = SimpleCoordinator::new(config).unwrap();
        
        let worker_id = WorkerId::new();
        let capabilities = WorkerCapabilities {
            cpu_cores: 8,
            memory_gb: 16,
            gpu_memory_gb: 8,
            storage_gb: 1000,
            network_bandwidth_mbps: 1000,
            supported_job_types: vec!["render3d".to_string(), "ai_inference".to_string()],
        };
        
        coordinator.register_worker(worker_id, capabilities).await.unwrap();
        let workers = coordinator.get_workers().await;
        
        assert_eq!(workers.len(), 1);
        assert_eq!(workers[0].worker_id, worker_id);
    }
} 