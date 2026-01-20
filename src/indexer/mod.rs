//! # BitSage Event Indexer
//!
//! This module provides event indexing from Starknet smart contracts.
//! It polls the RPC for new blocks, fetches events, and stores them in PostgreSQL.

pub mod event_listener;
pub mod event_processor;
pub mod contract_events;
pub mod db_writer;

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error, warn};

pub use event_listener::EventListener;
pub use event_processor::EventProcessor;
pub use contract_events::*;
pub use db_writer::DbWriter;

use crate::api::websocket::WebSocketState;

/// Contracts to index with their addresses (Sepolia)
pub const INDEXED_CONTRACTS: &[(&str, &str)] = &[
    ("JobManager", "0x355b8c5e9dd3310a3c361559b53cfcfdc20b2bf7d5bd87a84a83389b8cbb8d3"),
    ("CDCPool", "0x1f978cad424f87a6cea8aa27cbcbba10b9a50d41e296ae07e1c635392a2339"),
    ("Staking", "0x3287a0af5ab2d74fbf968204ce2291adde008d645d42bc363cb741ebfa941b"),
    ("ProofVerifier", "0x17ada59ab642b53e6620ef2026f21eb3f2d1a338d6e85cb61d5bcd8dfbebc8b"),
    ("OTCOrderbook", "0x7b2b59d93764ccf1ea85edca2720c37bba7742d05a2791175982eaa59cedef0"),
    ("Governance", "0xdf4c3ced8c8eafe33532965fe29081e6f94fb7d54bc976721985c647a7ef92"),
    ("PrivacyRouter", "0x7d1a6c242a4f0573696e117790f431fd60518a000b85fe5ee507456049ffc53"),
    ("Reputation", "0x4ef80990256fb016381f57c340a306e37376c1de70fa11147a4f1fc57a834de"),
    ("Referral", "0x1d400338a38fca24e67c113bcecac4875ec1b85a00b14e4e541ed224fee59e4"),
    ("Faucet", "0x62d3231450645503345e2e022b60a96aceff73898d26668f3389547a61471d3"),
];

/// Events to capture per contract
pub const JOB_EVENTS: &[&str] = &[
    "JobSubmitted", "JobAssigned", "JobCompleted",
    "JobCancelled", "PaymentReleased"
];

pub const STAKING_EVENTS: &[&str] = &[
    "Staked", "UnstakeInitiated", "Unstaked", "Slashed", "StakeIncreased"
];

pub const OTC_EVENTS: &[&str] = &[
    "OrderPlaced", "OrderFilled", "OrderCancelled", "TradeExecuted", "PairAdded"
];

pub const GOVERNANCE_EVENTS: &[&str] = &[
    "ProposalCreated", "VoteCast", "ProposalExecuted", "ProposalCancelled"
];

pub const PRIVACY_EVENTS: &[&str] = &[
    "PrivateTransferInitiated", "PrivateTransferCompleted",
    "PrivateDepositMade", "PrivateWithdrawalRequested", "StealthAddressRegistered"
];

pub const PROOF_EVENTS: &[&str] = &[
    "ProofSubmitted", "ProofVerified", "ProofRejected"
];

pub const REPUTATION_EVENTS: &[&str] = &[
    "ReputationUpdated", "WorkerRegistered", "WorkerSlashed"
];

pub const REFERRAL_EVENTS: &[&str] = &[
    "ReferrerRegistered", "ReferralRecorded", "CommissionPaid"
];

pub const FAUCET_EVENTS: &[&str] = &[
    "Claimed", "ConfigUpdated"
];

/// Indexer configuration
#[derive(Debug, Clone)]
pub struct IndexerConfig {
    pub enabled: bool,
    pub rpc_url: String,
    pub poll_interval_ms: u64,
    pub batch_size: usize,
    pub start_block: u64,
    pub max_retries: u32,
    pub database_url: String,
}

impl Default for IndexerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rpc_url: "https://starknet-sepolia-rpc.publicnode.com".to_string(),
            poll_interval_ms: 3000,
            batch_size: 100,
            start_block: 0, // 0 means start from latest
            max_retries: 5,
            database_url: "postgresql://bitsage:password@localhost:5432/bitsage".to_string(),
        }
    }
}

/// Indexer state
#[derive(Debug, Clone)]
pub struct IndexerState {
    pub is_running: bool,
    pub last_indexed_block: u64,
    pub events_processed: u64,
    pub errors_count: u64,
}

impl Default for IndexerState {
    fn default() -> Self {
        Self {
            is_running: false,
            last_indexed_block: 0,
            events_processed: 0,
            errors_count: 0,
        }
    }
}

/// Main Indexer service
pub struct Indexer {
    config: IndexerConfig,
    state: Arc<RwLock<IndexerState>>,
    listener: EventListener,
    processor: EventProcessor,
    db_writer: DbWriter,
}

impl Indexer {
    /// Create a new Indexer instance
    pub async fn new(config: IndexerConfig) -> Result<Self, IndexerError> {
        let state = Arc::new(RwLock::new(IndexerState::default()));

        let listener = EventListener::new(
            config.rpc_url.clone(),
            config.poll_interval_ms,
        );

        let processor = EventProcessor::new();

        let db_writer = DbWriter::new(&config.database_url).await?;

        Ok(Self {
            config,
            state,
            listener,
            processor,
            db_writer,
        })
    }

    /// Create a new Indexer instance with WebSocket broadcasting
    pub async fn new_with_websocket(
        config: IndexerConfig,
        ws_state: Arc<WebSocketState>,
    ) -> Result<Self, IndexerError> {
        let state = Arc::new(RwLock::new(IndexerState::default()));

        let listener = EventListener::new(
            config.rpc_url.clone(),
            config.poll_interval_ms,
        );

        let processor = EventProcessor::new();

        let db_writer = DbWriter::new_with_websocket(&config.database_url, ws_state).await?;

        info!("Indexer created with WebSocket broadcasting enabled");

        Ok(Self {
            config,
            state,
            listener,
            processor,
            db_writer,
        })
    }

    /// Set WebSocket state for real-time broadcasting (for existing instances)
    pub fn set_websocket_state(&mut self, ws_state: Arc<WebSocketState>) {
        self.db_writer.set_websocket_state(ws_state);
    }
    
    /// Start the indexer service
    pub async fn start(&mut self) -> Result<(), IndexerError> {
        if !self.config.enabled {
            warn!("Indexer is disabled, not starting");
            return Ok(());
        }
        
        info!("Starting BitSage Event Indexer...");
        
        // Update state
        {
            let mut state = self.state.write().await;
            state.is_running = true;
        }
        
        // Get starting block - prioritize: 1) config, 2) database resume point, 3) latest block
        let start_block = if self.config.start_block > 0 {
            // Config specifies a start block
            info!("Using configured start block: {}", self.config.start_block);
            self.config.start_block
        } else {
            // Check database for resume point
            match self.db_writer.get_min_indexed_block().await {
                Ok(Some(db_block)) if db_block > 0 => {
                    info!("Resuming from database state at block: {}", db_block);
                    db_block
                }
                _ => {
                    // Start from latest block
                    let latest = self.listener.get_latest_block().await?;
                    info!("No resume point found, starting from latest block: {}", latest);
                    latest
                }
            }
        };

        info!("Starting from block {}", start_block);
        
        // Main indexing loop
        let mut current_block = start_block;
        
        loop {
            // Check if we should stop
            {
                let state = self.state.read().await;
                if !state.is_running {
                    info!("Indexer stopped");
                    break;
                }
            }
            
            // Poll for new blocks
            match self.listener.get_latest_block().await {
                Ok(latest_block) => {
                    if latest_block > current_block {
                        // Process blocks
                        for block_num in current_block..=latest_block {
                            if let Err(e) = self.process_block(block_num).await {
                                error!("Error processing block {}: {}", block_num, e);
                                let mut state = self.state.write().await;
                                state.errors_count += 1;
                            }
                        }
                        current_block = latest_block + 1;
                    }
                }
                Err(e) => {
                    error!("Error getting latest block: {}", e);
                    let mut state = self.state.write().await;
                    state.errors_count += 1;
                }
            }
            
            // Wait before next poll
            tokio::time::sleep(tokio::time::Duration::from_millis(
                self.config.poll_interval_ms
            )).await;
        }
        
        Ok(())
    }
    
    /// Process a single block
    async fn process_block(&mut self, block_number: u64) -> Result<(), IndexerError> {
        // Get events for all indexed contracts
        for (contract_name, contract_address) in INDEXED_CONTRACTS {
            let events = self.listener.get_events(
                contract_address,
                block_number,
                block_number,
            ).await?;
            
            for event in events {
                // Process the event
                let processed = self.processor.process_event(
                    contract_name,
                    &event,
                )?;
                
                // Write to database
                self.db_writer.write_event(&processed).await?;
                
                // Update state
                let mut state = self.state.write().await;
                state.events_processed += 1;
            }
        }
        
        // Update last indexed block
        {
            let mut state = self.state.write().await;
            state.last_indexed_block = block_number;
        }
        
        // Update indexer state in database
        self.db_writer.update_indexer_state(block_number).await?;
        
        Ok(())
    }
    
    /// Stop the indexer
    pub async fn stop(&self) {
        let mut state = self.state.write().await;
        state.is_running = false;
        info!("Indexer stopping...");
    }
    
    /// Get current state
    pub async fn get_state(&self) -> IndexerState {
        self.state.read().await.clone()
    }
}

/// Indexer errors
#[derive(Debug, thiserror::Error)]
pub enum IndexerError {
    #[error("RPC error: {0}")]
    RpcError(String),
    
    #[error("Database error: {0}")]
    DatabaseError(String),
    
    #[error("Event processing error: {0}")]
    ProcessingError(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Connection error: {0}")]
    ConnectionError(String),
}

impl From<sqlx::Error> for IndexerError {
    fn from(e: sqlx::Error) -> Self {
        IndexerError::DatabaseError(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_indexed_contracts() {
        assert_eq!(INDEXED_CONTRACTS.len(), 10);
        assert!(INDEXED_CONTRACTS.iter().any(|(name, _)| *name == "JobManager"));
    }
    
    #[test]
    fn test_default_config() {
        let config = IndexerConfig::default();
        assert!(config.enabled);
        assert_eq!(config.poll_interval_ms, 3000);
        assert_eq!(config.batch_size, 100);
    }
}
