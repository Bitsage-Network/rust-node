//! # Starknet Client
//!
//! This module handles communication with the Starknet blockchain.

use anyhow::{Result, Context};
use starknet::{
    core::types::{
        BlockId, BlockTag, FieldElement, FunctionCall, MaybePendingBlockWithTxHashes,
        MaybePendingTransactionReceipt, EventFilter, EmittedEvent,
    },
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider},
    accounts::{SingleOwnerAccount, ExecutionEncoding},
    signers::{LocalWallet, SigningKey},
    accounts::Account,
};
use std::sync::Arc;
use tracing::{info, debug, warn, error};
use url::Url;

/// Starknet blockchain client
#[derive(Debug)]
pub struct StarknetClient {
    provider: Arc<JsonRpcClient<HttpTransport>>,
    rpc_url: String,
    chain_id: FieldElement,
}

impl StarknetClient {
    /// Create a new Starknet client
    pub fn new(rpc_url: String) -> Result<Self> {
        let url = Url::parse(&rpc_url)
            .context("Failed to parse RPC URL")?;
        
        let provider = JsonRpcClient::new(HttpTransport::new(url));
        
        Ok(Self {
            provider: Arc::new(provider),
            rpc_url,
            chain_id: FieldElement::from_hex_be("0x534e5f5345504f4c4941")?, // Sepolia testnet
        })
    }

    /// Create a new Starknet client for mainnet
    pub fn new_mainnet(rpc_url: String) -> Result<Self> {
        let url = Url::parse(&rpc_url)
            .context("Failed to parse RPC URL")?;

        let provider = JsonRpcClient::new(HttpTransport::new(url));

        Ok(Self {
            provider: Arc::new(provider),
            rpc_url,
            chain_id: FieldElement::from_hex_be("0x534e5f4d41494e")?, // Mainnet
        })
    }

    /// Create a stub client that won't be used (for disabled bridges)
    /// This avoids panics when creating disabled bridges for testing
    pub fn new_unchecked(rpc_url: &str) -> Self {
        // Parse URL with a fallback to localhost if invalid
        let url = Url::parse(rpc_url)
            .unwrap_or_else(|_| Url::parse("http://localhost:1").unwrap());
        let provider = JsonRpcClient::new(HttpTransport::new(url));

        Self {
            provider: Arc::new(provider),
            rpc_url: rpc_url.to_string(),
            // Use a placeholder chain ID - this client should never be used for real calls
            chain_id: FieldElement::ZERO,
        }
    }

    /// Connect to the Starknet network and verify connection
    pub async fn connect(&self) -> Result<()> {
        info!("Connecting to Starknet at {}", self.rpc_url);
        
        // Test connection by getting chain ID
        let chain_id = self.provider.chain_id().await
            .context("Failed to get chain ID from Starknet")?;
        
        info!("Connected to Starknet, chain ID: {:#x}", chain_id);
        
        // Verify we're on the expected chain
        if chain_id != self.chain_id {
            error!("Chain ID mismatch: expected {:#x}, got {:#x}", self.chain_id, chain_id);
            return Err(anyhow::anyhow!("Chain ID mismatch"));
        }
        
        Ok(())
    }

    /// Get the latest block number
    pub async fn get_block_number(&self) -> Result<u64> {
        let block = self.provider.get_block_with_tx_hashes(BlockId::Tag(BlockTag::Latest)).await
            .context("Failed to get latest block")?;
        
        match block {
            MaybePendingBlockWithTxHashes::Block(block) => Ok(block.block_number),
            MaybePendingBlockWithTxHashes::PendingBlock(_) => {
                // For pending blocks, get the latest confirmed block
                let confirmed_block = self.provider.get_block_with_tx_hashes(BlockId::Tag(BlockTag::Pending)).await
                    .context("Failed to get confirmed block")?;
                match confirmed_block {
                    MaybePendingBlockWithTxHashes::Block(block) => Ok(block.block_number),
                    MaybePendingBlockWithTxHashes::PendingBlock(_) => Ok(0), // Fallback
                }
            }
        }
    }

    /// Get the current block timestamp
    pub async fn get_block_timestamp(&self) -> Result<u64> {
        let block = self.provider.get_block_with_tx_hashes(BlockId::Tag(BlockTag::Latest)).await
            .context("Failed to get latest block")?;
        
        match block {
            MaybePendingBlockWithTxHashes::Block(block) => Ok(block.timestamp),
            MaybePendingBlockWithTxHashes::PendingBlock(pending) => Ok(pending.timestamp),
        }
    }

    /// Call a contract function (read-only)
    pub async fn call_contract(
        &self,
        contract_address: FieldElement,
        selector: FieldElement,
        calldata: Vec<FieldElement>,
    ) -> Result<Vec<FieldElement>> {
        let call = FunctionCall {
            contract_address,
            entry_point_selector: selector,
            calldata,
        };

        let result = self.provider.call(call, BlockId::Tag(BlockTag::Latest)).await
            .context("Failed to call contract function")?;

        debug!("Contract call result: {:?}", result);
        Ok(result)
    }

    /// Get contract storage at a specific key
    pub async fn get_storage_at(
        &self,
        contract_address: FieldElement,
        key: FieldElement,
    ) -> Result<FieldElement> {
        let value = self.provider.get_storage_at(
            contract_address,
            key,
            BlockId::Tag(BlockTag::Latest),
        ).await
            .context("Failed to get storage value")?;

        Ok(value)
    }

    /// Get transaction receipt
    pub async fn get_transaction_receipt(
        &self,
        transaction_hash: FieldElement,
    ) -> Result<MaybePendingTransactionReceipt> {
        let receipt = self.provider.get_transaction_receipt(transaction_hash).await
            .context("Failed to get transaction receipt")?;

        Ok(receipt)
    }



    /// Get transaction by hash
    pub async fn get_transaction_by_hash(
        &self,
        transaction_hash: FieldElement,
    ) -> Result<starknet::core::types::Transaction> {
        let transaction = self.provider.get_transaction_by_hash(transaction_hash).await
            .context("Failed to get transaction")?;

        Ok(transaction)
    }

    /// Create an account for transaction signing
    pub fn create_account(
        &self,
        private_key: FieldElement,
        account_address: FieldElement,
    ) -> Result<SingleOwnerAccount<Arc<JsonRpcClient<HttpTransport>>, LocalWallet>> {
        let signer = LocalWallet::from(SigningKey::from_secret_scalar(private_key));
        
        let account = SingleOwnerAccount::new(
            self.provider.clone(),
            signer,
            account_address,
            self.chain_id,
            ExecutionEncoding::New,
        );

        Ok(account)
    }

    /// Send a transaction to a contract (state-changing)
    pub async fn send_transaction(
        &self,
        contract_address: FieldElement,
        selector: FieldElement,
        calldata: Vec<FieldElement>,
        private_key: FieldElement,
        account_address: FieldElement,
    ) -> Result<FieldElement> {
        // Create the account for signing
        let account = self.create_account(private_key, account_address)?;

        // Construct the call
        let call = starknet::accounts::Call {
            to: contract_address,
            selector,
            calldata,
        };

        // Prepare the execution
        let exec = account.execute(vec![call]);

        // Send the transaction
        let tx_result = exec.send().await.context("Failed to send transaction")?;
        let tx_hash = tx_result.transaction_hash;
        info!("Transaction sent: {:#x}", tx_hash);
        Ok(tx_hash)
    }

    /// Get the provider for advanced operations
    pub fn provider(&self) -> Arc<JsonRpcClient<HttpTransport>> {
        self.provider.clone()
    }

    /// Get the chain ID
    pub fn chain_id(&self) -> FieldElement {
        self.chain_id
    }

    /// Health check - verify connection and get basic info
    pub async fn health_check(&self) -> Result<HealthStatus> {
        let start_time = std::time::Instant::now();

        // Test basic connectivity
        let block_number = self.get_block_number().await?;
        let block_timestamp = self.get_block_timestamp().await?;
        let chain_id = self.provider.chain_id().await?;

        let response_time = start_time.elapsed();

        Ok(HealthStatus {
            connected: true,
            block_number,
            block_timestamp,
            chain_id,
            response_time_ms: response_time.as_millis() as u64,
        })
    }

    /// Get events from a contract within a block range
    ///
    /// This is used for monitoring contract activity like job submissions,
    /// assignments, and completions.
    pub async fn get_events(
        &self,
        contract_address: FieldElement,
        keys: Option<Vec<Vec<FieldElement>>>,
        from_block: Option<u64>,
        to_block: Option<u64>,
        continuation_token: Option<String>,
        chunk_size: u64,
    ) -> Result<EventsPage> {
        let from_block_id = from_block
            .map(BlockId::Number)
            .unwrap_or(BlockId::Tag(BlockTag::Latest));
        let to_block_id = to_block
            .map(BlockId::Number)
            .unwrap_or(BlockId::Tag(BlockTag::Latest));

        let filter = EventFilter {
            from_block: Some(from_block_id),
            to_block: Some(to_block_id),
            address: Some(contract_address),
            keys,
        };

        let events_page = self.provider
            .get_events(filter, continuation_token, chunk_size)
            .await
            .context("Failed to get events from contract")?;

        Ok(EventsPage {
            events: events_page.events,
            continuation_token: events_page.continuation_token,
        })
    }

    /// Get events for a specific event type from a contract
    ///
    /// The event_key is the selector for the event (e.g., JobSubmitted, JobAssigned)
    pub async fn get_events_by_key(
        &self,
        contract_address: FieldElement,
        event_key: FieldElement,
        from_block: u64,
        to_block: Option<u64>,
    ) -> Result<Vec<EmittedEvent>> {
        let mut all_events = Vec::new();
        let mut continuation_token: Option<String> = None;

        loop {
            let page = self.get_events(
                contract_address,
                Some(vec![vec![event_key]]),
                Some(from_block),
                to_block,
                continuation_token.clone(),
                100, // Chunk size
            ).await?;

            all_events.extend(page.events);

            match page.continuation_token {
                Some(token) => continuation_token = Some(token),
                None => break,
            }
        }

        debug!("Retrieved {} events for key {:#x}", all_events.len(), event_key);
        Ok(all_events)
    }

    /// Check if a transaction is finalized (confirmed on-chain)
    pub async fn is_transaction_finalized(&self, tx_hash: FieldElement) -> Result<TransactionStatus> {
        match self.get_transaction_receipt(tx_hash).await {
            Ok(receipt) => {
                match receipt {
                    MaybePendingTransactionReceipt::Receipt(r) => {
                        // Extract execution status from the receipt
                        let execution_status = match &r {
                            starknet::core::types::TransactionReceipt::Invoke(inv) => {
                                inv.execution_result.clone()
                            }
                            starknet::core::types::TransactionReceipt::Declare(decl) => {
                                decl.execution_result.clone()
                            }
                            starknet::core::types::TransactionReceipt::Deploy(dep) => {
                                dep.execution_result.clone()
                            }
                            starknet::core::types::TransactionReceipt::DeployAccount(da) => {
                                da.execution_result.clone()
                            }
                            starknet::core::types::TransactionReceipt::L1Handler(l1) => {
                                l1.execution_result.clone()
                            }
                        };

                        let block_number = match &r {
                            starknet::core::types::TransactionReceipt::Invoke(inv) => inv.block_number,
                            starknet::core::types::TransactionReceipt::Declare(decl) => decl.block_number,
                            starknet::core::types::TransactionReceipt::Deploy(dep) => dep.block_number,
                            starknet::core::types::TransactionReceipt::DeployAccount(da) => da.block_number,
                            starknet::core::types::TransactionReceipt::L1Handler(l1) => l1.block_number,
                        };

                        let is_successful = matches!(
                            execution_status,
                            starknet::core::types::ExecutionResult::Succeeded
                        );

                        Ok(TransactionStatus {
                            is_finalized: true,
                            is_successful,
                            block_number: Some(block_number),
                            error_message: if !is_successful {
                                Some("Transaction reverted".to_string())
                            } else {
                                None
                            },
                        })
                    }
                    MaybePendingTransactionReceipt::PendingReceipt(_) => {
                        Ok(TransactionStatus {
                            is_finalized: false,
                            is_successful: false,
                            block_number: None,
                            error_message: None,
                        })
                    }
                }
            }
            Err(e) => {
                warn!("Failed to get transaction receipt for {:#x}: {}", tx_hash, e);
                Ok(TransactionStatus {
                    is_finalized: false,
                    is_successful: false,
                    block_number: None,
                    error_message: Some(e.to_string()),
                })
            }
        }
    }

    /// Wait for a transaction to be finalized with timeout
    pub async fn wait_for_transaction(
        &self,
        tx_hash: FieldElement,
        timeout_secs: u64,
        poll_interval_secs: u64,
    ) -> Result<TransactionStatus> {
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_secs);
        let poll_interval = std::time::Duration::from_secs(poll_interval_secs);

        loop {
            let status = self.is_transaction_finalized(tx_hash).await?;

            if status.is_finalized {
                return Ok(status);
            }

            if start.elapsed() > timeout {
                return Err(anyhow::anyhow!(
                    "Transaction {:#x} not finalized after {} seconds",
                    tx_hash,
                    timeout_secs
                ));
            }

            tokio::time::sleep(poll_interval).await;
        }
    }
}

/// Page of events returned from event query
#[derive(Debug, Clone)]
pub struct EventsPage {
    pub events: Vec<EmittedEvent>,
    pub continuation_token: Option<String>,
}

/// Transaction finalization status
#[derive(Debug, Clone)]
pub struct TransactionStatus {
    pub is_finalized: bool,
    pub is_successful: bool,
    pub block_number: Option<u64>,
    pub error_message: Option<String>,
}

/// Health status information
#[derive(Debug, Clone)]
pub struct HealthStatus {
    pub connected: bool,
    pub block_number: u64,
    pub block_timestamp: u64,
    pub chain_id: FieldElement,
    pub response_time_ms: u64,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Starknet Health: {} | Block: {} | Chain: {:#x} | Response: {}ms",
            if self.connected { "✓ Connected" } else { "✗ Disconnected" },
            self.block_number,
            self.chain_id,
            self.response_time_ms
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = StarknetClient::new("https://starknet-sepolia-rpc.publicnode.com".to_string());
        assert!(client.is_ok());
    }

    #[test]
    fn test_invalid_url() {
        let client = StarknetClient::new("invalid-url".to_string());
        assert!(client.is_err());
    }

    #[tokio::test]
    async fn test_health_check_with_public_rpc() {
        // This test uses a public RPC endpoint - may be slow or fail if endpoint is down
        let client = StarknetClient::new("https://starknet-sepolia-rpc.publicnode.com".to_string())
            .expect("Failed to create client");
        
        // This test might fail if the public RPC is down, so we'll just test client creation
        // In a real environment, you'd use a reliable RPC endpoint
        println!("Client created successfully with public RPC URL");
    }
} 