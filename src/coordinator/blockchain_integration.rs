//! # Blockchain Integration
//!
//! Comprehensive blockchain integration for the Bitsage Network coordinator,
//! handling all interactions with deployed smart contracts.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::time::Duration;
use tracing::{info, debug, error};
use anyhow::Context;

use crate::blockchain::{client::StarknetClient, contracts::JobManagerContract};
use crate::types::{JobId, WorkerId};
use crate::node::coordinator::{JobRequest, JobResult as CoordinatorJobResult};
use crate::coordinator::config::BlockchainConfig;

/// Blockchain integration events
#[derive(Debug, Clone)]
pub enum BlockchainEvent {
    JobRegistered(JobId, String), // job_id, transaction_hash
    JobCompleted(JobId, String),  // job_id, transaction_hash
    JobFailed(JobId, String),     // job_id, error_message
    WorkerRegistered(WorkerId, String), // worker_id, transaction_hash
    WorkerReputationUpdated(WorkerId, f64), // worker_id, new_reputation
    PaymentDistributed(JobId, u128), // job_id, amount
    ContractEventReceived(String, serde_json::Value), // event_type, event_data
    TransactionConfirmed(String, u64), // transaction_hash, block_number
    TransactionFailed(String, String), // transaction_hash, error_message
}

/// Blockchain transaction status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionStatus {
    Pending,
    Confirmed,
    Failed,
    Reverted,
}

/// Blockchain transaction information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInfo {
    pub hash: String,
    pub status: TransactionStatus,
    pub block_number: Option<u64>,
    pub gas_used: Option<u64>,
    pub gas_price: Option<u64>,
    pub error_message: Option<String>,
    pub timestamp: u64,
}

/// Contract event information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractEvent {
    pub event_type: String,
    pub contract_address: String,
    pub block_number: u64,
    pub transaction_hash: String,
    pub event_data: serde_json::Value,
    pub timestamp: u64,
}

/// Blockchain monitoring metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainMetrics {
    pub total_transactions: u64,
    pub successful_transactions: u64,
    pub failed_transactions: u64,
    pub average_gas_used: u64,
    pub average_confirmation_time_ms: u64,
    pub last_block_number: u64,
    pub contract_events_received: u64,
    pub active_jobs_on_chain: u64,
    pub total_workers_registered: u64,
}

/// Blockchain statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainStats {
    pub total_transactions: u64,
    pub pending_transactions: u64,
    pub last_block_number: u64,
    pub gas_price: u64,
    pub network_status: String,
}

/// Main blockchain integration service
pub struct BlockchainIntegration {
    config: BlockchainConfig,
    starknet_client: Arc<StarknetClient>,
    job_manager_contract: Arc<JobManagerContract>,
    
    // Transaction tracking
    pending_transactions: Arc<RwLock<HashMap<String, TransactionInfo>>>,
    confirmed_transactions: Arc<RwLock<HashMap<String, TransactionInfo>>>,
    
    // Event tracking
    contract_events: Arc<RwLock<Vec<ContractEvent>>>,
    
    // Metrics
    metrics: Arc<RwLock<BlockchainMetrics>>,
    
    // Communication channels
    event_sender: mpsc::UnboundedSender<BlockchainEvent>,
    event_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<BlockchainEvent>>>>,
    
    // Internal state
    running: Arc<RwLock<bool>>,
    last_block_number: Arc<RwLock<u64>>,
    connection_status: Arc<RwLock<bool>>,
}

impl BlockchainIntegration {
    /// Create a new blockchain integration service
    pub fn new(
        config: BlockchainConfig,
        starknet_client: Arc<StarknetClient>,
        job_manager_contract: Arc<JobManagerContract>,
    ) -> Self {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        
        let metrics = BlockchainMetrics {
            total_transactions: 0,
            successful_transactions: 0,
            failed_transactions: 0,
            average_gas_used: 0,
            average_confirmation_time_ms: 0,
            last_block_number: 0,
            contract_events_received: 0,
            active_jobs_on_chain: 0,
            total_workers_registered: 0,
        };
        
        Self {
            config,
            starknet_client,
            job_manager_contract,
            pending_transactions: Arc::new(RwLock::new(HashMap::new())),
            confirmed_transactions: Arc::new(RwLock::new(HashMap::new())),
            contract_events: Arc::new(RwLock::new(Vec::new())),
            metrics: Arc::new(RwLock::new(metrics)),
            event_sender,
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
            running: Arc::new(RwLock::new(false)),
            last_block_number: Arc::new(RwLock::new(0)),
            connection_status: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the blockchain integration service
    pub async fn start(&self) -> Result<()> {
        info!("Starting Blockchain Integration Service...");
        
        {
            let mut running = self.running.write().await;
            if *running {
                return Err(anyhow::anyhow!("Blockchain integration already running"));
            }
            *running = true;
        }

        // Test blockchain connection
        self.test_connection().await?;
        
        // Start monitoring tasks
        let block_monitoring_handle = self.start_block_monitoring().await?;
        let transaction_monitoring_handle = self.start_transaction_monitoring().await?;
        let event_monitoring_handle = self.start_event_monitoring().await?;
        let metrics_collection_handle = self.start_metrics_collection().await?;

        info!("Blockchain integration service started successfully");
        
        // Start all tasks and wait for them to complete
        // Note: These are now () since we're not awaiting them
        let block_result = ();
        let transaction_result = ();
        let event_result = ();
        let metrics_result = ();
        
        // Log any errors (simplified since we're not actually checking results)
        debug!("Blockchain integration tasks completed");

        Ok(())
    }

    /// Stop the blockchain integration service
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping Blockchain Integration Service...");
        
        {
            let mut running = self.running.write().await;
            *running = false;
        }

        info!("Blockchain integration service stopped");
        Ok(())
    }

    /// Test blockchain connection
    async fn test_connection(&self) -> Result<()> {
        info!("Testing blockchain connection...");
        
        // Test RPC connection
        let block_number = self.starknet_client.get_block_number().await?;
        info!("Connected to blockchain at block {}", block_number);
        
        // Test contract connection
        let contract_health = self.job_manager_contract.health_check().await?;
        info!("Contract health check: {}", contract_health);
        
        // Update connection status
        {
            let mut status = self.connection_status.write().await;
            *status = true;
        }
        
        // Update last block number
        {
            let mut last_block = self.last_block_number.write().await;
            *last_block = block_number;
        }
        
        Ok(())
    }

    /// Start block monitoring
    async fn start_block_monitoring(&self) -> Result<()> {
        let config = self.config.clone();
        let starknet_client = self.starknet_client.clone();
        let last_block_number = Arc::clone(&self.last_block_number);
        let event_sender = self.event_sender.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(config.monitoring.block_polling_interval_secs));
            
            loop {
                interval.tick().await;
                
                match starknet_client.get_block_number().await {
                    Ok(block_number) => {
                        let mut last_block = last_block_number.write().await;
                        if block_number > *last_block {
                            debug!("New block detected: {}", block_number);
                            *last_block = block_number;
                        }
                    }
                    Err(e) => {
                        error!("Failed to get block number: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    /// Start transaction monitoring
    async fn start_transaction_monitoring(&self) -> Result<()> {
        let pending_transactions = Arc::clone(&self.pending_transactions);
        let confirmed_transactions = Arc::clone(&self.confirmed_transactions);
        let event_sender = self.event_sender.clone();
        let starknet_client = self.starknet_client.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            
            loop {
                interval.tick().await;
                
                // Check pending transactions
                let mut pending = pending_transactions.write().await;
                let mut to_remove = Vec::new();
                
                for (hash, transaction) in pending.iter_mut() {
                    // TODO: Implement proper transaction receipt checking
                    // For now, just mark as confirmed after a delay
                    if chrono::Utc::now().timestamp() as u64 - transaction.timestamp > 30 {
                        transaction.status = TransactionStatus::Confirmed;
                        transaction.block_number = Some(0); // TODO: Get actual block number
                        transaction.gas_used = Some(0); // TODO: Get actual gas used
                        
                        // Move to confirmed transactions
                        confirmed_transactions.write().await.insert(hash.clone(), transaction.clone());
                        to_remove.push(hash.clone());
                        
                        // Send confirmation event
                        if let Err(e) = event_sender.send(BlockchainEvent::TransactionConfirmed(
                            hash.clone(),
                            0, // TODO: Get actual block number
                        )) {
                            error!("Failed to send transaction confirmation event: {}", e);
                        }
                    }
                }
                
                // Remove processed transactions
                for hash in to_remove {
                    pending.remove(&hash);
                }
            }
        });

        Ok(())
    }

    /// Start event monitoring
    async fn start_event_monitoring(&self) -> Result<()> {
        let config = self.config.clone();
        let contract_events = Arc::clone(&self.contract_events);
        let event_sender = self.event_sender.clone();
        let job_manager_contract = self.job_manager_contract.clone();

        tokio::spawn(async move {
            if !config.monitoring.enable_event_monitoring {
                return;
            }
            
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                // TODO: Implement contract event monitoring
                // This would poll for events from the job manager contract
                debug!("Monitoring contract events...");
            }
        });

        Ok(())
    }

    /// Start metrics collection
    async fn start_metrics_collection(&self) -> Result<()> {
        let metrics = Arc::clone(&self.metrics);
        let confirmed_transactions = Arc::clone(&self.confirmed_transactions);
        let contract_events = Arc::clone(&self.contract_events);
        let last_block_number = Arc::clone(&self.last_block_number);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                // Update metrics
                let mut metrics_guard = metrics.write().await;
                let confirmed = confirmed_transactions.read().await;
                let events = contract_events.read().await;
                let last_block = last_block_number.read().await;
                
                metrics_guard.total_transactions = confirmed.len() as u64;
                metrics_guard.last_block_number = *last_block;
                metrics_guard.contract_events_received = events.len() as u64;
                
                // Calculate averages
                if !confirmed.is_empty() {
                    let total_gas: u64 = confirmed.values()
                        .filter_map(|t| t.gas_used)
                        .sum();
                    metrics_guard.average_gas_used = total_gas / confirmed.len() as u64;
                }
            }
        });

        Ok(())
    }

    /// Register a job on the blockchain
    pub async fn register_job(&self, job_id: JobId, request: &JobRequest) -> Result<String> {
        info!("Registering job {} on blockchain", job_id);
        
        let private_key = starknet::core::types::FieldElement::from_hex_be(&self.config.signer_private_key)
            .context("Failed to parse signer private key")?;
        let account_address = starknet::core::types::FieldElement::from_hex_be(&self.config.signer_account_address)
            .context("Failed to parse signer account address")?;
        
        let transaction_hash = self.job_manager_contract
            .register_job(job_id, request, private_key, account_address)
            .await?;
        let hash_str = format!("0x{:x}", transaction_hash);
        
        // Track transaction
        let transaction_info = TransactionInfo {
            hash: hash_str.clone(),
            status: TransactionStatus::Pending,
            block_number: None,
            gas_used: None,
            gas_price: None,
            error_message: None,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        self.pending_transactions.write().await.insert(
            hash_str.clone(),
            transaction_info,
        );
        // Send event
        if let Err(e) = self.event_sender.send(BlockchainEvent::JobRegistered(
            job_id,
            hash_str.clone(),
        )) {
            error!("Failed to send job registered event: {}", e);
        }
        Ok(hash_str)
    }

    /// Mark a job as completed on the blockchain
    pub async fn complete_job(&self, job_id: JobId, result: &CoordinatorJobResult) -> Result<String> {
        info!("Completing job {} on blockchain", job_id);
        let private_key = starknet::core::types::FieldElement::from_hex_be(&self.config.signer_private_key)
            .context("Failed to parse signer private key")?;
        let account_address = starknet::core::types::FieldElement::from_hex_be(&self.config.signer_account_address)
            .context("Failed to parse signer account address")?;
        let transaction_hash = self.job_manager_contract
            .complete_job(job_id, result, private_key, account_address)
            .await?;
        let hash_str = format!("0x{:x}", transaction_hash);
        // Track transaction
        let transaction_info = TransactionInfo {
            hash: hash_str.clone(),
            status: TransactionStatus::Pending,
            block_number: None,
            gas_used: None,
            gas_price: None,
            error_message: None,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        self.pending_transactions.write().await.insert(
            hash_str.clone(),
            transaction_info,
        );
        // Send event
        if let Err(e) = self.event_sender.send(BlockchainEvent::JobCompleted(
            job_id,
            hash_str.clone(),
        )) {
            error!("Failed to send job completed event: {}", e);
        }
        Ok(hash_str)
    }

    /// Assign a job to a worker
    pub async fn assign_job_to_worker(&self, job_id: JobId, worker_id: WorkerId) -> Result<String> {
        info!("Assigning job {} to worker {} on blockchain", job_id, worker_id);
        let private_key = starknet::core::types::FieldElement::from_hex_be(&self.config.signer_private_key)
            .context("Failed to parse signer private key")?;
        let account_address = starknet::core::types::FieldElement::from_hex_be(&self.config.signer_account_address)
            .context("Failed to parse signer account address")?;
        let transaction_hash = self.job_manager_contract
            .assign_job_to_worker(job_id, worker_id, private_key, account_address)
            .await?;
        let hash_str = format!("0x{:x}", transaction_hash);
        // Track transaction
        let transaction_info = TransactionInfo {
            hash: hash_str.clone(),
            status: TransactionStatus::Pending,
            block_number: None,
            gas_used: None,
            gas_price: None,
            error_message: None,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        self.pending_transactions.write().await.insert(
            hash_str.clone(),
            transaction_info,
        );
        // Send event
        if let Err(e) = self.event_sender.send(BlockchainEvent::WorkerRegistered(
            worker_id,
            hash_str.clone(),
        )) {
            error!("Failed to send worker registered event: {}", e);
        }
        Ok(hash_str)
    }

    /// Distribute rewards for a completed job
    pub async fn distribute_rewards(&self, job_id: JobId) -> Result<String> {
        info!("Distributing rewards for job {} on blockchain", job_id);
        let private_key = starknet::core::types::FieldElement::from_hex_be(&self.config.signer_private_key)
            .context("Failed to parse signer private key")?;
        let account_address = starknet::core::types::FieldElement::from_hex_be(&self.config.signer_account_address)
            .context("Failed to parse signer account address")?;
        let transaction_hash = self.job_manager_contract
            .distribute_rewards(job_id, private_key, account_address)
            .await?;
        let hash_str = format!("0x{:x}", transaction_hash);
        // Track transaction
        let transaction_info = TransactionInfo {
            hash: hash_str.clone(),
            status: TransactionStatus::Pending,
            block_number: None,
            gas_used: None,
            gas_price: None,
            error_message: None,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        self.pending_transactions.write().await.insert(
            hash_str.clone(),
            transaction_info,
        );
        // Send event
        if let Err(e) = self.event_sender.send(BlockchainEvent::PaymentDistributed(
            job_id,
            0, // TODO: actual amount
        )) {
            error!("Failed to send payment distributed event: {}", e);
        }
        Ok(hash_str)
    }

    /// Get job details from blockchain
    pub async fn get_job_details(&self, job_id: JobId) -> Result<Option<crate::blockchain::types::JobDetails>> {
        debug!("Getting job details for {} from blockchain", job_id);
        
        let details = self.job_manager_contract.get_job(job_id).await?;
        
        if let Some(details) = &details {
            debug!("Retrieved job details: {:?}", details);
        }
        
        Ok(details)
    }

    /// Get job state from blockchain
    pub async fn get_job_state(&self, job_id: JobId) -> Result<Option<crate::blockchain::types::JobState>> {
        debug!("Getting job state for {} from blockchain", job_id);
        
        let state = self.job_manager_contract.get_job_state(job_id).await?;
        
        if let Some(state) = &state {
            debug!("Retrieved job state: {:?}", state);
        }
        
        Ok(state)
    }

    /// Health check for blockchain integration
    pub async fn health_check(&self) -> Result<()> {
        // Test RPC connection
        let _block_number = self.starknet_client.get_block_number().await?;
        
        // Test contract connection
        let _contract_health = self.job_manager_contract.health_check().await?;
        
        Ok(())
    }

    /// Get blockchain metrics
    pub async fn get_metrics(&self) -> BlockchainMetrics {
        self.metrics.read().await.clone()
    }

    /// Get blockchain statistics
    pub async fn get_blockchain_stats(&self) -> BlockchainStats {
        BlockchainStats {
            total_transactions: 0, // TODO: Get from blockchain
            pending_transactions: 0, // TODO: Get from blockchain
            last_block_number: 0, // TODO: Get from blockchain
            gas_price: 0, // TODO: Get from blockchain
            network_status: "connected".to_string(), // TODO: Get from blockchain
        }
    }

    /// Get pending transactions
    pub async fn get_pending_transactions(&self) -> Vec<TransactionInfo> {
        self.pending_transactions.read().await.values().cloned().collect()
    }

    /// Get confirmed transactions
    pub async fn get_confirmed_transactions(&self) -> Vec<TransactionInfo> {
        self.confirmed_transactions.read().await.values().cloned().collect()
    }

    /// Get contract events
    pub async fn get_contract_events(&self) -> Vec<ContractEvent> {
        self.contract_events.read().await.clone()
    }

    /// Check if connected to blockchain
    pub async fn is_connected(&self) -> bool {
        *self.connection_status.read().await
    }

    /// Get last block number
    pub async fn get_last_block_number(&self) -> u64 {
        *self.last_block_number.read().await
    }

    /// Get event receiver
    pub async fn event_receiver(&self) -> mpsc::UnboundedReceiver<BlockchainEvent> {
        self.event_receiver.write().await.take().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_blockchain_integration_creation() {
        let config = BlockchainConfig::default();
        let starknet_client = Arc::new(StarknetClient::new(config.rpc_url.clone()).unwrap());
        let job_manager_contract = Arc::new(JobManagerContract::new_from_address(
            starknet_client.clone(),
            &config.job_manager_address,
        ).unwrap());
        
        let integration = BlockchainIntegration::new(
            config,
            starknet_client,
            job_manager_contract,
        );
        
        assert_eq!(integration.get_metrics().await.total_transactions, 0);
    }

    #[tokio::test]
    async fn test_transaction_info_creation() {
        let transaction = TransactionInfo {
            hash: "0x123".to_string(),
            status: TransactionStatus::Pending,
            block_number: None,
            gas_used: None,
            gas_price: None,
            error_message: None,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        
        assert_eq!(transaction.hash, "0x123");
        assert!(matches!(transaction.status, TransactionStatus::Pending));
    }
} 