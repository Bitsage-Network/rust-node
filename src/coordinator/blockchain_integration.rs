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
    ///
    /// This monitors pending transactions by querying their receipts from the blockchain.
    /// When a transaction is confirmed, it updates the status and emits an event.
    async fn start_transaction_monitoring(&self) -> Result<()> {
        let pending_transactions = Arc::clone(&self.pending_transactions);
        let confirmed_transactions = Arc::clone(&self.confirmed_transactions);
        let event_sender = self.event_sender.clone();
        let starknet_client = self.starknet_client.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));

            loop {
                interval.tick().await;

                // Get list of pending transactions to check
                let pending_hashes: Vec<(String, TransactionInfo)> = {
                    let pending = pending_transactions.read().await;
                    pending.iter().map(|(h, t)| (h.clone(), t.clone())).collect()
                };

                if pending_hashes.is_empty() {
                    continue;
                }

                debug!("Checking {} pending transactions", pending_hashes.len());

                for (hash, mut transaction) in pending_hashes {
                    // Parse the transaction hash as FieldElement
                    let tx_hash = match starknet::core::types::FieldElement::from_hex_be(&hash) {
                        Ok(h) => h,
                        Err(e) => {
                            error!("Invalid transaction hash {}: {}", hash, e);
                            continue;
                        }
                    };

                    // Check transaction status
                    match starknet_client.is_transaction_finalized(tx_hash).await {
                        Ok(status) => {
                            if status.is_finalized {
                                let block_num = status.block_number.unwrap_or(0);

                                if status.is_successful {
                                    info!("Transaction {} confirmed in block {}", hash, block_num);
                                    transaction.status = TransactionStatus::Confirmed;
                                    transaction.block_number = Some(block_num);

                                    // Move to confirmed
                                    confirmed_transactions.write().await.insert(hash.clone(), transaction.clone());
                                    pending_transactions.write().await.remove(&hash);

                                    // Emit event
                                    if let Err(e) = event_sender.send(BlockchainEvent::TransactionConfirmed(
                                        hash.clone(),
                                        block_num,
                                    )) {
                                        error!("Failed to send transaction confirmation event: {}", e);
                                    }
                                } else {
                                    // Transaction reverted
                                    let error_msg = status.error_message.unwrap_or_else(|| "Transaction reverted".to_string());
                                    error!("Transaction {} reverted: {}", hash, error_msg);

                                    transaction.status = TransactionStatus::Reverted;
                                    transaction.error_message = Some(error_msg.clone());
                                    transaction.block_number = Some(block_num);

                                    // Move to confirmed (with failed status)
                                    confirmed_transactions.write().await.insert(hash.clone(), transaction.clone());
                                    pending_transactions.write().await.remove(&hash);

                                    // Emit event
                                    if let Err(e) = event_sender.send(BlockchainEvent::TransactionFailed(
                                        hash.clone(),
                                        error_msg,
                                    )) {
                                        error!("Failed to send transaction failed event: {}", e);
                                    }
                                }
                            }
                            // If not finalized, keep in pending
                        }
                        Err(e) => {
                            // Check if transaction has been pending too long (timeout after 10 minutes)
                            let now = chrono::Utc::now().timestamp() as u64;
                            if now - transaction.timestamp > 600 {
                                error!("Transaction {} timed out after 10 minutes", hash);
                                transaction.status = TransactionStatus::Failed;
                                transaction.error_message = Some(format!("Transaction timeout: {}", e));

                                confirmed_transactions.write().await.insert(hash.clone(), transaction.clone());
                                pending_transactions.write().await.remove(&hash);

                                if let Err(e) = event_sender.send(BlockchainEvent::TransactionFailed(
                                    hash.clone(),
                                    "Transaction timeout".to_string(),
                                )) {
                                    error!("Failed to send transaction failed event: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        });

        Ok(())
    }

    /// Start event monitoring
    ///
    /// Monitors contract events like JobCompleted, JobFailed, RewardsDistributed, etc.
    /// This is used for tracking on-chain activity and updating local state accordingly.
    async fn start_event_monitoring(&self) -> Result<()> {
        let config = self.config.clone();
        let contract_events = Arc::clone(&self.contract_events);
        let event_sender = self.event_sender.clone();
        let job_manager_contract = self.job_manager_contract.clone();
        let starknet_client = self.starknet_client.clone();

        // Track last processed block for event monitoring
        let last_event_block = Arc::new(RwLock::new(0u64));

        tokio::spawn(async move {
            if !config.monitoring.enable_event_monitoring {
                info!("Contract event monitoring disabled by config");
                return;
            }

            let mut interval = tokio::time::interval(Duration::from_secs(15));

            loop {
                interval.tick().await;

                // Get current block
                let current_block = match starknet_client.get_block_number().await {
                    Ok(block) => block,
                    Err(e) => {
                        debug!("Failed to get current block for event monitoring: {}", e);
                        continue;
                    }
                };

                // Get last processed block
                let from_block = {
                    let last = *last_event_block.read().await;
                    if last == 0 {
                        // First run - start from current block (don't replay history)
                        current_block.saturating_sub(10)
                    } else {
                        last + 1
                    }
                };

                if from_block >= current_block {
                    continue;
                }

                debug!("Monitoring contract events from block {} to {}", from_block, current_block);

                let contract_address = job_manager_contract.contract_address();

                // Monitor multiple event types
                let event_types = vec![
                    ("JobCompleted", *crate::blockchain::types::selectors::EVENT_JOB_COMPLETED),
                    ("JobFailed", *crate::blockchain::types::selectors::EVENT_JOB_FAILED),
                    ("RewardsDistributed", *crate::blockchain::types::selectors::EVENT_REWARDS_DISTRIBUTED),
                    ("JobAssigned", *crate::blockchain::types::selectors::EVENT_JOB_ASSIGNED),
                ];

                for (event_name, event_selector) in event_types {
                    match starknet_client.get_events_by_key(
                        contract_address,
                        event_selector,
                        from_block,
                        Some(current_block),
                    ).await {
                        Ok(events) => {
                            for event in events {
                                let contract_event = ContractEvent {
                                    event_type: event_name.to_string(),
                                    contract_address: format!("{:#x}", contract_address),
                                    block_number: event.block_number,
                                    transaction_hash: format!("{:#x}", event.transaction_hash),
                                    event_data: serde_json::json!({
                                        "keys": event.keys.iter().map(|k| format!("{:#x}", k)).collect::<Vec<_>>(),
                                        "data": event.data.iter().map(|d| format!("{:#x}", d)).collect::<Vec<_>>(),
                                    }),
                                    timestamp: chrono::Utc::now().timestamp() as u64,
                                };

                                // Store the event
                                contract_events.write().await.push(contract_event.clone());

                                // Emit the event to listeners
                                if let Err(e) = event_sender.send(BlockchainEvent::ContractEventReceived(
                                    event_name.to_string(),
                                    contract_event.event_data.clone(),
                                )) {
                                    error!("Failed to send contract event: {}", e);
                                }

                                // Process specific event types
                                match event_name {
                                    "JobCompleted" => {
                                        if !event.data.is_empty() {
                                            // First data element is typically job_id
                                            let job_id_bytes = event.data[0].to_bytes_be();
                                            let mut uuid_bytes = [0u8; 16];
                                            uuid_bytes.copy_from_slice(&job_id_bytes[16..32]);
                                            let job_id = crate::types::JobId::from(uuid::Uuid::from_bytes(uuid_bytes));

                                            info!("Received JobCompleted event for job {}", job_id);
                                            if let Err(e) = event_sender.send(BlockchainEvent::JobCompleted(
                                                job_id,
                                                format!("{:#x}", event.transaction_hash),
                                            )) {
                                                error!("Failed to send job completed event: {}", e);
                                            }
                                        }
                                    }
                                    "JobFailed" => {
                                        if !event.data.is_empty() {
                                            let job_id_bytes = event.data[0].to_bytes_be();
                                            let mut uuid_bytes = [0u8; 16];
                                            uuid_bytes.copy_from_slice(&job_id_bytes[16..32]);
                                            let job_id = crate::types::JobId::from(uuid::Uuid::from_bytes(uuid_bytes));

                                            let error_msg = if event.data.len() > 1 {
                                                format!("Error code: {:#x}", event.data[1])
                                            } else {
                                                "Unknown error".to_string()
                                            };

                                            info!("Received JobFailed event for job {}: {}", job_id, error_msg);
                                            if let Err(e) = event_sender.send(BlockchainEvent::JobFailed(
                                                job_id,
                                                error_msg,
                                            )) {
                                                error!("Failed to send job failed event: {}", e);
                                            }
                                        }
                                    }
                                    "RewardsDistributed" => {
                                        if event.data.len() >= 2 {
                                            let job_id_bytes = event.data[0].to_bytes_be();
                                            let mut uuid_bytes = [0u8; 16];
                                            uuid_bytes.copy_from_slice(&job_id_bytes[16..32]);
                                            let job_id = crate::types::JobId::from(uuid::Uuid::from_bytes(uuid_bytes));

                                            // Get amount from second data element
                                            let amount_bytes = event.data[1].to_bytes_be();
                                            let amount = u128::from_be_bytes(amount_bytes[16..32].try_into().unwrap_or([0; 16]));

                                            info!("Rewards distributed for job {}: {} tokens", job_id, amount);
                                            if let Err(e) = event_sender.send(BlockchainEvent::PaymentDistributed(
                                                job_id,
                                                amount,
                                            )) {
                                                error!("Failed to send payment distributed event: {}", e);
                                            }
                                        }
                                    }
                                    _ => {
                                        debug!("Received {} event", event_name);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            debug!("Failed to get {} events: {}", event_name, e);
                        }
                    }
                }

                // Update last processed block
                *last_event_block.write().await = current_block;
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
        // Get last block number from cached value
        let last_block = *self.last_block_number.read().await;

        // Count pending and confirmed transactions
        let pending_count = self.pending_transactions.read().await.len() as u64;
        let confirmed_count = self.confirmed_transactions.read().await.len() as u64;

        // Determine network status from connection status
        let is_connected = *self.connection_status.read().await;
        let network_status = if is_connected {
            "connected".to_string()
        } else {
            "disconnected".to_string()
        };

        BlockchainStats {
            total_transactions: confirmed_count + pending_count,
            pending_transactions: pending_count,
            last_block_number: last_block,
            gas_price: 0, // Gas price estimation would require additional RPC call
            network_status,
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

    /// Take the event receiver.
    ///
    /// This can only be called once - subsequent calls will return `None`.
    pub async fn take_event_receiver(&self) -> Option<mpsc::UnboundedReceiver<BlockchainEvent>> {
        self.event_receiver.write().await.take()
    }

    /// Check if the event receiver is still available.
    pub async fn has_event_receiver(&self) -> bool {
        self.event_receiver.read().await.is_some()
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