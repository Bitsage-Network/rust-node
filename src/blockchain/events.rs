//! # Blockchain Event Indexer
//!
//! Simplified event indexer for Bitsage Network smart contracts on Starknet.

use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use starknet::core::types::{
    BlockId,
    FieldElement,
    MaybePendingBlockWithTxs,
    Transaction,
    MaybePendingTransactionReceipt,
    Event,
    EventFilter,
};
use starknet::providers::Provider;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, debug, error};
use tokio::time::{Duration, interval, sleep};

use crate::blockchain::client::StarknetClient;
use crate::storage::database_simple::SimpleDatabase as DatabaseManager;

/// Configuration for the event indexer
#[derive(Debug, Clone)]
pub struct IndexerConfig {
    /// How often to poll for new blocks (in seconds)
    pub poll_interval_secs: u64,
    /// Number of blocks to process in each batch
    pub batch_size: u64,
    /// Maximum number of retries for failed operations
    pub max_retries: u32,
    /// Delay between retries (in milliseconds)
    pub retry_delay_ms: u64,
    /// Whether to index historical blocks on startup
    pub index_historical: bool,
    /// Starting block for historical indexing
    pub start_block: u64,
}

impl Default for IndexerConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: 5,
            batch_size: 100,
            max_retries: 3,
            retry_delay_ms: 1000,
            index_historical: true,
            start_block: 0,
        }
    }
}

/// Simple event type for indexing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiroEvent {
    pub contract_address: String,
    pub event_type: String,
    pub block_number: u64,
    pub timestamp: u64,
    pub data: serde_json::Value,
}

/// Event indexer state
#[derive(Debug, Clone)]
pub struct IndexerState {
    /// Last processed block number
    pub last_block: u64,
    /// Number of events indexed
    pub events_indexed: u64,
    /// Number of blocks processed
    pub blocks_processed: u64,
    /// Indexer start time
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// Last update time
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

/// Smart contract addresses we're monitoring
#[derive(Debug, Clone)]
pub struct ContractAddresses {
    pub job_manager: FieldElement,
    pub cdc_pool: FieldElement,
    pub treasury_timelock: FieldElement,
    pub sage_token: FieldElement,
    pub governance_treasury: FieldElement,
    pub reputation_manager: FieldElement,
    pub simple_events: FieldElement,
    // Extensions
    pub linear_vesting: FieldElement,
    pub milestone_vesting: FieldElement,
    pub burn_manager: FieldElement,
}

/// Main blockchain event indexer
#[derive(Clone)]
pub struct EventIndexer {
    client: Arc<StarknetClient>,
    database: Arc<DatabaseManager>,
    config: IndexerConfig,
    contracts: ContractAddresses,
    state: Arc<RwLock<IndexerState>>,
    running: Arc<RwLock<bool>>,
}

impl EventIndexer {
    /// Sleep with exponential backoff based on attempt number
    async fn backoff_sleep(&self, attempt: u32) {
        let base_ms = self.config.retry_delay_ms;
        let delay_ms = base_ms.saturating_mul(1u64 << attempt.min(8));
        sleep(Duration::from_millis(delay_ms)).await;
    }

    /// Retry wrapper for get_block_with_txs
    async fn get_block_with_txs_retry(
        &self,
        block_id: BlockId,
    ) -> Result<MaybePendingBlockWithTxs> {
        let mut last_err: Option<anyhow::Error> = None;
        for attempt in 0..self.config.max_retries {
            match self.client.provider().get_block_with_txs(block_id).await {
                Ok(b) => return Ok(b),
                Err(e) => {
                    last_err = Some(e.into());
                    error!("get_block_with_txs failed (attempt {}): {}", attempt + 1, last_err.as_ref().unwrap());
                    self.backoff_sleep(attempt).await;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("get_block_with_txs failed")))
    }

    /// Retry wrapper for get_transaction_receipt
    async fn get_tx_receipt_retry(
        &self,
        tx_hash: FieldElement,
    ) -> Result<MaybePendingTransactionReceipt> {
        let mut last_err: Option<anyhow::Error> = None;
        for attempt in 0..self.config.max_retries {
            match self.client.provider().get_transaction_receipt(tx_hash).await {
                Ok(r) => return Ok(r),
                Err(e) => {
                    last_err = Some(e.into());
                    error!("get_transaction_receipt failed for 0x{:x} (attempt {}): {}", tx_hash, attempt + 1, last_err.as_ref().unwrap());
                    self.backoff_sleep(attempt).await;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("get_transaction_receipt failed")))
    }

    /// Retry wrapper for get_events
    async fn get_events_retry(
        &self,
        filter: EventFilter,
        continuation: Option<String>,
        chunk_size: u64,
    ) -> Result<starknet::core::types::EventsPage> {
        let mut last_err: Option<anyhow::Error> = None;
        for attempt in 0..self.config.max_retries {
            match self.client.provider().get_events(filter.clone(), continuation.clone(), chunk_size).await {
                Ok(p) => return Ok(p),
                Err(e) => {
                    last_err = Some(e.into());
                    error!("get_events failed (attempt {}): {}", attempt + 1, last_err.as_ref().unwrap());
                    self.backoff_sleep(attempt).await;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("get_events failed")))
    }
    /// Create a new event indexer
    pub fn new(
        client: Arc<StarknetClient>,
        database: Arc<DatabaseManager>,
        config: IndexerConfig,
        contracts: ContractAddresses,
    ) -> Self {
        let state = IndexerState {
            last_block: config.start_block,
            events_indexed: 0,
            blocks_processed: 0,
            started_at: chrono::Utc::now(),
            last_updated: chrono::Utc::now(),
        };

        Self {
            client,
            database,
            config,
            contracts,
            state: Arc::new(RwLock::new(state)),
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the indexer
    pub async fn start(&self) -> Result<()> {
        let mut running_guard = self.running.write().await;
        if *running_guard {
            return Ok(());
        }
        *running_guard = true;
        drop(running_guard);

        info!("Starting Bitsage Network Event Indexer");

        // Start real-time indexing
        self.start_real_time_indexing().await?;

        Ok(())
    }

    /// Stop the indexer
    pub async fn stop(&self) {
        let mut running_guard = self.running.write().await;
        *running_guard = false;
        info!("Stopping Bitsage Network Event Indexer");
    }

    /// Start real-time indexing loop
    async fn start_real_time_indexing(&self) -> Result<()> {
        info!("Starting real-time indexing");
        
        let mut ticker = interval(Duration::from_secs(self.config.poll_interval_secs));
        
        while *self.running.read().await {
            ticker.tick().await;
            
            if let Err(e) = self.process_new_blocks().await {
                error!("Failed to process new blocks: {}", e);
            }
        }

        Ok(())
    }

    /// Process new blocks since last update
    async fn process_new_blocks(&self) -> Result<()> {
        let current_block = self.client.get_block_number().await?;
        let state = self.state.read().await;
        let last_processed = state.last_block;
        drop(state);

        debug!("⛓️  current_block={}, last_processed={}", current_block, last_processed);
        if current_block <= last_processed {
            debug!("No new blocks to process");
            return Ok(());
        }

        debug!("Processing blocks {} to {}", last_processed + 1, current_block);
        
        let mut total_events = 0;
        
        // Process each block individually for now (can batch later)
        // If provider block decoding fails, immediately fall back to a range
        // sweep via get_events so we do not stall.
        let mut fell_back_range = false;
        for block_num in (last_processed + 1)..=current_block {
            match self.process_single_block(block_num).await {
                Ok(event_count) => {
                    total_events += event_count;
                    debug!("Block {} processed: {} events", block_num, event_count);
                },
                Err(e) => {
                    error!("Failed to process block {}: {}", block_num, e);
                    // Immediate range fallback once on first failure
                    if !fell_back_range {
                        fell_back_range = true;
                        match self.fetch_events_via_filter_range(block_num, current_block).await {
                            Ok(n) => {
                                if n > 0 { info!("⬇️ Immediate range fallback captured {} events across {}..{}", n, block_num, current_block); }
                                total_events += n;
                            },
                            Err(err) => error!("Immediate range fallback failed: {}", err),
                        }
                        // After the range sweep, break the per-block loop to avoid long retries
                        break;
                    }
                }
            }
        }

        // Additional range-based fallback at the end as a safety net
        if !fell_back_range && current_block > last_processed {
            match self.fetch_events_via_filter_range(last_processed + 1, current_block).await {
                Ok(n) => {
                    if n > 0 { info!("⬇️ get_events range fallback captured {} events across blocks {}..{}", n, last_processed + 1, current_block); }
                    total_events += n;
                }
                Err(e) => error!("Range fallback via get_events failed: {}", e),
            }
        }
        
        // One-time explicit fetch for a known RM event block (temporary fast path)
        let _ = self.fetch_events_for_address_range(self.contracts.reputation_manager, 1474511, 1474511).await;

        // Targeted RM backfill over a recent window to force-capture events
        let backfill_from = if current_block > 1000 { current_block - 1000 } else { 0 };
        match self.fetch_events_for_address_range(self.contracts.reputation_manager, backfill_from, current_block).await {
            Ok(n) => {
                if n > 0 { info!("🎯 Targeted RM backfill captured {} events across {}..{}", n, backfill_from, current_block); }
                total_events += n;
            },
            Err(e) => error!("Targeted RM backfill failed: {}", e),
        }

        // Update state
        let mut state = self.state.write().await;
        state.last_block = current_block;
        state.blocks_processed += current_block - last_processed;
        state.events_indexed += total_events;
        state.last_updated = chrono::Utc::now();

        info!("Processed {} blocks, current block: {}, found {} events", 
              current_block - last_processed, current_block, total_events);

        Ok(())
    }

    /// Process a single block and extract events
    async fn process_single_block(&self, block_number: u64) -> Result<u64> {
        // Get block with transactions; if RPC parsing fails, immediately fall back
        // to get_events for monitored contracts in this block so we don't stall.
        let block_id = BlockId::Number(block_number);
        let block = match self.get_block_with_txs_retry(block_id).await {
            Ok(b) => b,
            Err(e) => {
                error!(
                    "get_block_with_txs failed for block {}: {}. Falling back to get_events for this block",
                    block_number,
                    e
                );
                let ts = chrono::Utc::now().timestamp() as u64;
                let fetched = self.fetch_events_via_filter(block_number, ts).await?;
                if fetched > 0 {
                    info!(
                        "⬇️ Fallback captured {} events via get_events for block {}",
                        fetched, block_number
                    );
                }
                return Ok(fetched);
            }
        };

        let mut event_count = 0;

        // Handle MaybePendingBlockWithTxs
        match block {
            MaybePendingBlockWithTxs::Block(block) => {
                debug!("📦 Processing block {} with {} transactions", block_number, block.transactions.len());
                for (i, tx) in block.transactions.iter().enumerate() {
                    let tx_events = self.process_transaction_events(tx, block_number, block.timestamp).await?;
                    if tx_events > 0 {
                        info!("🎉 Found {} events in transaction {} of block {}", tx_events, i, block_number);
                    }
                    event_count += tx_events;
                }

                // Fallback: query events directly via get_events for monitored contracts
                event_count += self.fetch_events_via_filter(block_number, block.timestamp).await?;
            },
            MaybePendingBlockWithTxs::PendingBlock(pending_block) => {
                debug!("📦 Processing pending block {} with {} transactions", block_number, pending_block.transactions.len());
                // For pending blocks, use current timestamp
                let timestamp = chrono::Utc::now().timestamp() as u64;
                for (i, tx) in pending_block.transactions.iter().enumerate() {
                    let tx_events = self.process_transaction_events(tx, block_number, timestamp).await?;
                    if tx_events > 0 {
                        info!("🎉 Found {} events in pending transaction {} of block {}", tx_events, i, block_number);
                    }
                    event_count += tx_events;
                }

                // Fallback for pending blocks as well
                event_count += self.fetch_events_via_filter(block_number, timestamp).await?;
            }
        }

        if event_count > 0 {
            info!("🎯 Block {} total: {} events captured!", block_number, event_count);
        }

        Ok(event_count)
    }

    /// Fallback: fetch events via JSON-RPC get_events for monitored contracts
    async fn fetch_events_via_filter(&self, block_number: u64, block_timestamp: u64) -> Result<u64> {
        let mut total = 0u64;

        // Helper to fetch and store events for a single address
        async fn fetch_for_address(
            this_: &EventIndexer,
            address: FieldElement,
            block_number: u64,
            block_timestamp: u64,
        ) -> Result<u64> {
            let mut fetched = 0u64;
            let mut continuation: Option<String> = None;

            loop {
                let filter = EventFilter {
                    from_block: Some(BlockId::Number(block_number)),
                    to_block: Some(BlockId::Number(block_number)),
                    address: Some(address),
                    keys: None,
                };

                let page = this_
                    .get_events_retry(filter, continuation.clone(), 100)
                    .await?;

                for emitted in &page.events {
                    // Convert EmittedEvent to Event-like structure for reuse
                    let evt = Event {
                        from_address: emitted.from_address,
                        keys: emitted.keys.clone(),
                        data: emitted.data.clone(),
                    };
                    // Store using existing pipeline
                    if let Err(e) = this_.process_and_store_event(&evt, block_number, block_timestamp).await {
                        error!("❌ Failed to store event via filter: {}", e);
                    } else {
                        fetched += 1;
                    }
                }

                if let Some(token) = page.continuation_token {
                    continuation = Some(token);
                } else {
                    break;
                }
            }

            Ok(fetched)
        }

        // Query monitored contracts (skip zero/empty addresses implicitly; provider returns empty)
        for addr in [
            self.contracts.reputation_manager,
            self.contracts.simple_events,
            self.contracts.sage_token,
            self.contracts.job_manager,
            self.contracts.cdc_pool,
            self.contracts.treasury_timelock,
            self.contracts.governance_treasury,
            self.contracts.linear_vesting,
            self.contracts.milestone_vesting,
            self.contracts.burn_manager,
        ] {
            match fetch_for_address(self, addr, block_number, block_timestamp).await {
                Ok(n) if n > 0 => {
                    info!("⬇️ get_events fallback captured {} events for 0x{:x} in block {}", n, addr, block_number);
                    total += n;
                }
                Ok(_) => {}
                Err(e) => error!("get_events fallback failed for 0x{:x}: {}", addr, e),
            }
        }

        Ok(total)
    }

    /// Fallback: fetch events via JSON-RPC get_events across a block range for monitored contracts
    async fn fetch_events_via_filter_range(&self, from_block: u64, to_block: u64) -> Result<u64> {
        let mut total = 0u64;

        async fn fetch_for_address_range(
            this_: &EventIndexer,
            address: FieldElement,
            from_block: u64,
            to_block: u64,
        ) -> Result<u64> {
            let mut fetched = 0u64;
            let mut continuation: Option<String> = None;

            loop {
                let filter = EventFilter {
                    from_block: Some(BlockId::Number(from_block)),
                    to_block: Some(BlockId::Number(to_block)),
                    address: Some(address),
                    keys: None,
                };

                 let page = this_
                     .get_events_retry(filter, continuation.clone(), 100)
                     .await?;

                for emitted in &page.events {
                    let evt = Event {
                        from_address: emitted.from_address,
                        keys: emitted.keys.clone(),
                        data: emitted.data.clone(),
                    };

                    // Best-effort timestamp: use current time if we can't easily map block timestamp here
                    let timestamp = chrono::Utc::now().timestamp() as u64;
                    if let Err(e) = this_.process_and_store_event(&evt, to_block, timestamp).await {
                        error!("❌ Failed to store event via range filter: {}", e);
                    } else {
                        fetched += 1;
                    }
                }

                if let Some(token) = page.continuation_token {
                    continuation = Some(token);
                } else {
                    break;
                }
            }

            Ok(fetched)
        }

        for addr in [
            self.contracts.reputation_manager,
            self.contracts.simple_events,
            self.contracts.sage_token,
            self.contracts.job_manager,
            self.contracts.cdc_pool,
            self.contracts.treasury_timelock,
            self.contracts.governance_treasury,
            self.contracts.linear_vesting,
            self.contracts.milestone_vesting,
            self.contracts.burn_manager,
        ] {
            match fetch_for_address_range(self, addr, from_block, to_block).await {
                Ok(n) => total += n,
                Err(e) => error!("get_events range failed for 0x{:x}: {}", addr, e),
            }
        }

        Ok(total)
    }

    /// Targeted: fetch events for a specific contract address across a block range
    async fn fetch_events_for_address_range(
        &self,
        address: FieldElement,
        from_block: u64,
        to_block: u64,
    ) -> Result<u64> {
        let mut fetched = 0u64;
        let mut continuation: Option<String> = None;

        loop {
            let filter = EventFilter {
                from_block: Some(BlockId::Number(from_block)),
                to_block: Some(BlockId::Number(to_block)),
                address: Some(address),
                keys: None,
            };

            let page = self
                .get_events_retry(filter, continuation.clone(), 100)
                .await?;

            for emitted in &page.events {
                let evt = Event {
                    from_address: emitted.from_address,
                    keys: emitted.keys.clone(),
                    data: emitted.data.clone(),
                };
                // Best-effort timestamp for range queries
                let timestamp = chrono::Utc::now().timestamp() as u64;
                if let Err(e) = self.process_and_store_event(&evt, to_block, timestamp).await {
                    error!("❌ Failed to store targeted event: {}", e);
                } else {
                    fetched += 1;
                }
            }

            if let Some(token) = page.continuation_token {
                continuation = Some(token);
            } else {
                break;
            }
        }

        Ok(fetched)
    }

    /// Process events from a single transaction
    async fn process_transaction_events(&self, transaction: &Transaction, block_number: u64, block_timestamp: u64) -> Result<u64> {
        let tx_hash = match transaction {
            Transaction::Invoke(tx) => *tx.transaction_hash(),
            Transaction::Declare(tx) => *tx.transaction_hash(),
            Transaction::Deploy(tx) => tx.transaction_hash,
            Transaction::DeployAccount(tx) => tx.transaction_hash,
            Transaction::L1Handler(tx) => tx.transaction_hash,
        };

        debug!("🔍 Processing transaction: 0x{:x}", tx_hash);

        // Get transaction receipt to access events
        let receipt = match self.client.provider().get_transaction_receipt(tx_hash).await {
            Ok(receipt) => receipt,
            Err(e) => {
                debug!("❌ Could not get receipt for tx 0x{:x}: {}", tx_hash, e);
                return Ok(0);
            }
        };

        debug!("✅ Got receipt for tx 0x{:x}", tx_hash);

        let events: Vec<Event> = match receipt {
            MaybePendingTransactionReceipt::Receipt(receipt) => {
                match receipt {
                    starknet::core::types::TransactionReceipt::Invoke(receipt) => {
                        debug!("📄 Invoke receipt with {} events", receipt.events.len());
                        receipt.events
                    },
                    starknet::core::types::TransactionReceipt::Declare(receipt) => {
                        debug!("📄 Declare receipt with {} events", receipt.events.len());
                        receipt.events
                    },
                    starknet::core::types::TransactionReceipt::Deploy(receipt) => {
                        debug!("📄 Deploy receipt with {} events", receipt.events.len());
                        receipt.events
                    },
                    starknet::core::types::TransactionReceipt::DeployAccount(receipt) => {
                        debug!("📄 DeployAccount receipt with {} events", receipt.events.len());
                        receipt.events
                    },
                    starknet::core::types::TransactionReceipt::L1Handler(receipt) => {
                        debug!("📄 L1Handler receipt with {} events", receipt.events.len());
                        receipt.events
                    },
                }
            },
            MaybePendingTransactionReceipt::PendingReceipt(_) => {
                debug!("⏳ Skipping pending transaction 0x{:x}", tx_hash);
                return Ok(0);
            }
        };

        let mut processed_events = 0;

        debug!("🔎 Checking {} events in transaction 0x{:x}", events.len(), tx_hash);

        for (i, event) in events.iter().enumerate() {
            debug!("📋 Event {}: from_address=0x{:x}, keys={}, data={}", 
                   i, event.from_address, event.keys.len(), event.data.len());
            
            if self.is_monitored_contract(&event.from_address) {
                info!("🎯 MONITORED EVENT FOUND! Contract: 0x{:x}", event.from_address);
                match self.process_and_store_event(event, block_number, block_timestamp).await {
                    Ok(()) => {
                        processed_events += 1;
                        info!("✅ Stored event {} from contract 0x{:x}", processed_events, event.from_address);
                    },
                    Err(e) => {
                        error!("❌ Failed to store event: {}", e);
                    }
                }
            } else {
                debug!("⏭️ Skipping event from unmonitored contract 0x{:x}", event.from_address);
            }
        }

        if processed_events > 0 {
            info!("🎊 Transaction 0x{:x} yielded {} monitored events!", tx_hash, processed_events);
        }

        Ok(processed_events)
    }

    /// Check if a contract address is being monitored
    fn is_monitored_contract(&self, address: &FieldElement) -> bool {
        *address == self.contracts.treasury_timelock ||
        *address == self.contracts.reputation_manager ||
        *address == self.contracts.job_manager ||
        *address == self.contracts.cdc_pool ||
        *address == self.contracts.sage_token ||
        *address == self.contracts.governance_treasury ||
        *address == self.contracts.simple_events ||
        *address == self.contracts.linear_vesting ||
        *address == self.contracts.milestone_vesting ||
        *address == self.contracts.burn_manager
    }

    /// Process and store a single event
    async fn process_and_store_event(&self, event: &Event, block_number: u64, block_timestamp: u64) -> Result<()> {
        let contract_address = format!("0x{:x}", event.from_address);
        
        // Determine event type and contract type
        let (event_type, contract_type) = self.classify_event(event);
        
        // Create event data
        let event_data = serde_json::json!({
            "keys": event.keys.iter().map(|k| format!("0x{:x}", k)).collect::<Vec<_>>(),
            "data": event.data.iter().map(|d| format!("0x{:x}", d)).collect::<Vec<_>>(),
            "contract_type": contract_type,
        });

        let sage_event = CiroEvent {
            contract_address: contract_address.clone(),
            event_type: event_type.clone(),
            block_number,
            timestamp: block_timestamp,
            data: event_data,
        };

        // Store in database
        self.database.store_event(&sage_event).await
            .context("Failed to store event in database")?;

        // Extra visibility for SAGE token events while validating ingestion
        if contract_type == "sage_token" {
            info!(
                "🟣 SAGE {} captured at block {} from {}",
                event_type,
                block_number,
                contract_address
            );
        } else {
            debug!("Stored {} event from {}", event_type, contract_address);
        }
        Ok(())
    }

    /// Classify event based on contract address and event signature
    fn classify_event(&self, event: &Event) -> (String, String) {
        let contract_type = if event.from_address == self.contracts.treasury_timelock {
            "treasury_timelock"
        } else if event.from_address == self.contracts.reputation_manager {
            "reputation_manager"
        } else if event.from_address == self.contracts.job_manager {
            "job_manager"
        } else if event.from_address == self.contracts.cdc_pool {
            "cdc_pool"
        } else if event.from_address == self.contracts.sage_token {
            "sage_token"
        } else if event.from_address == self.contracts.governance_treasury {
            "governance_treasury"
        } else if event.from_address == self.contracts.simple_events {
            "simple_events"
        } else if event.from_address == self.contracts.linear_vesting {
            "linear_vesting"
        } else if event.from_address == self.contracts.milestone_vesting {
            "milestone_vesting"
        } else if event.from_address == self.contracts.burn_manager {
            "burn_manager"
        } else {
            "unknown"
        };

        // For SimpleEvents and ReputationManager, apply explicit labels
        let event_type = if contract_type == "simple_events" && !event.keys.is_empty() {
            "TestEvent"
        } else if contract_type == "reputation_manager" && !event.keys.is_empty() {
            // Label RM events for visibility; we can refine by key later if needed
            "AdminAdjusted"
        } else if contract_type == "sage_token" {
            // Common ERC20 events
            if !event.keys.is_empty() {
                match format!("0x{:x}", event.keys[0]).as_str() {
                    "0x99cd8bde557814842a3121e8ddfd433a539b8c9f14bf31ebf108d12e6196e9" => "Transfer",
                    "0x134692b230b9e1ffa39098904722134159652b09c5bc41d88d6698779d228ff" => "Approval",
                    _ => "TokenEvent"
                }
            } else {
                "TokenEvent"
            }
        } else if contract_type == "linear_vesting" {
            if !event.keys.is_empty() { "VestingEvent" } else { "VestingEvent" }
        } else if contract_type == "milestone_vesting" {
            if !event.keys.is_empty() { "MilestoneEvent" } else { "MilestoneEvent" }
        } else if contract_type == "burn_manager" {
            if !event.keys.is_empty() { "BurnEvent" } else { "BurnEvent" }
        } else {
            "GenericEvent"
        };

        (event_type.to_string(), contract_type.to_string())
    }

    /// Get indexer statistics
    pub async fn get_stats(&self) -> IndexerState {
        self.state.read().await.clone()
    }

    /// Get recent events from database
    pub async fn get_recent_events(&self, limit: usize) -> Result<Vec<CiroEvent>> {
        self.database.get_recent_events(limit as i64).await
    }

    /// Get events for specific contract from database
    pub async fn get_contract_events(
        &self,
        contract_address: &str,
        limit: usize,
    ) -> Result<Vec<CiroEvent>> {
        self.database.get_contract_events(contract_address, limit as i64).await
    }
}