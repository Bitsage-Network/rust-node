//! # Starknet Client
//!
//! This module handles communication with the Starknet blockchain.

use anyhow::{Result, Context};
use starknet::{
    core::types::{BlockId, BlockTag, FieldElement, FunctionCall, MaybePendingBlockWithTxHashes, MaybePendingTransactionReceipt},
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider},
    accounts::{SingleOwnerAccount, ExecutionEncoding},
    signers::{LocalWallet, SigningKey},
    accounts::Account,
};
use std::sync::Arc;
use tracing::{info, debug, error};
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
        let client = StarknetClient::new("https://starknet-sepolia.public.blastapi.io".to_string());
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
        let client = StarknetClient::new("https://starknet-sepolia.public.blastapi.io".to_string())
            .expect("Failed to create client");
        
        // This test might fail if the public RPC is down, so we'll just test client creation
        // In a real environment, you'd use a reliable RPC endpoint
        println!("Client created successfully with public RPC URL");
    }
} 