//! # Event Listener
//!
//! Polls Starknet RPC for new blocks and fetches events from indexed contracts.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::IndexerError;

/// Raw event from Starknet RPC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvent {
    pub from_address: String,
    pub keys: Vec<String>,
    pub data: Vec<String>,
    pub block_number: u64,
    pub block_hash: Option<String>,
    pub transaction_hash: String,
}

/// Event listener that polls Starknet RPC
pub struct EventListener {
    rpc_url: String,
    poll_interval_ms: u64,
    client: reqwest::Client,
}

impl EventListener {
    /// Create a new EventListener
    pub fn new(rpc_url: String, poll_interval_ms: u64) -> Self {
        Self {
            rpc_url,
            poll_interval_ms,
            client: reqwest::Client::new(),
        }
    }

    /// Get the configured poll interval in milliseconds
    pub fn poll_interval(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.poll_interval_ms)
    }

    /// Get the latest block number
    pub async fn get_latest_block(&self) -> Result<u64, IndexerError> {
        let response = self.rpc_call("starknet_blockNumber", json!([])).await?;
        
        let block_number = response
            .as_u64()
            .or_else(|| {
                response.as_str()
                    .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            })
            .ok_or_else(|| IndexerError::RpcError("Invalid block number response".to_string()))?;
        
        Ok(block_number)
    }
    
    /// Get block timestamp
    pub async fn get_block_timestamp(&self, block_number: u64) -> Result<u64, IndexerError> {
        let params = json!({
            "block_id": {
                "block_number": block_number
            }
        });
        
        let response = self.rpc_call("starknet_getBlockWithTxHashes", params).await?;
        
        let timestamp = response["timestamp"]
            .as_u64()
            .or_else(|| {
                response["timestamp"].as_str()
                    .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            })
            .unwrap_or(0);
        
        Ok(timestamp)
    }
    
    /// Get events from a contract within a block range
    pub async fn get_events(
        &self,
        contract_address: &str,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<RawEvent>, IndexerError> {
        let params = json!({
            "filter": {
                "from_block": { "block_number": from_block },
                "to_block": { "block_number": to_block },
                "address": contract_address,
                "chunk_size": 100
            }
        });
        
        let response = self.rpc_call("starknet_getEvents", params).await?;
        
        let events_array = response["events"]
            .as_array()
            .ok_or_else(|| IndexerError::RpcError("No events array in response".to_string()))?;
        
        let mut events = Vec::new();
        
        for event_value in events_array {
            let event = self.parse_event(event_value)?;
            events.push(event);
        }
        
        Ok(events)
    }
    
    /// Get events for multiple contracts
    pub async fn get_events_batch(
        &self,
        contracts: &[(&str, &str)], // (name, address)
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<(String, RawEvent)>, IndexerError> {
        let mut all_events = Vec::new();
        
        for (contract_name, contract_address) in contracts {
            let events = self.get_events(contract_address, from_block, to_block).await?;
            
            for event in events {
                all_events.push((contract_name.to_string(), event));
            }
        }
        
        // Sort by block number
        all_events.sort_by_key(|(_, e)| e.block_number);
        
        Ok(all_events)
    }
    
    /// Get transaction receipt for more details
    pub async fn get_transaction_receipt(
        &self,
        tx_hash: &str,
    ) -> Result<Value, IndexerError> {
        let params = json!({
            "transaction_hash": tx_hash
        });
        
        self.rpc_call("starknet_getTransactionReceipt", params).await
    }
    
    /// Parse a raw event from JSON
    fn parse_event(&self, value: &Value) -> Result<RawEvent, IndexerError> {
        let from_address = value["from_address"]
            .as_str()
            .unwrap_or("0x0")
            .to_string();
        
        let keys: Vec<String> = value["keys"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        
        let data: Vec<String> = value["data"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        
        let block_number = value["block_number"]
            .as_u64()
            .or_else(|| {
                value["block_number"].as_str()
                    .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            })
            .unwrap_or(0);
        
        let block_hash = value["block_hash"]
            .as_str()
            .map(String::from);
        
        let transaction_hash = value["transaction_hash"]
            .as_str()
            .unwrap_or("0x0")
            .to_string();
        
        Ok(RawEvent {
            from_address,
            keys,
            data,
            block_number,
            block_hash,
            transaction_hash,
        })
    }
    
    /// Make an RPC call to Starknet
    async fn rpc_call(&self, method: &str, params: Value) -> Result<Value, IndexerError> {
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        });
        
        let response = self.client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| IndexerError::ConnectionError(e.to_string()))?;
        
        let response_json: Value = response
            .json()
            .await
            .map_err(|e| IndexerError::RpcError(format!("Failed to parse response: {}", e)))?;
        
        if let Some(error) = response_json.get("error") {
            return Err(IndexerError::RpcError(error.to_string()));
        }
        
        response_json.get("result")
            .cloned()
            .ok_or_else(|| IndexerError::RpcError("No result in response".to_string()))
    }
}

/// Event filter for selective indexing
#[derive(Debug, Clone)]
pub struct EventFilter {
    pub contract_addresses: Vec<String>,
    pub event_names: Vec<String>,
    pub from_block: Option<u64>,
    pub to_block: Option<u64>,
}

impl EventFilter {
    pub fn new() -> Self {
        Self {
            contract_addresses: Vec::new(),
            event_names: Vec::new(),
            from_block: None,
            to_block: None,
        }
    }
    
    pub fn with_contract(mut self, address: &str) -> Self {
        self.contract_addresses.push(address.to_string());
        self
    }
    
    pub fn with_event(mut self, event_name: &str) -> Self {
        self.event_names.push(event_name.to_string());
        self
    }
    
    pub fn from_block(mut self, block: u64) -> Self {
        self.from_block = Some(block);
        self
    }
    
    pub fn to_block(mut self, block: u64) -> Self {
        self.to_block = Some(block);
        self
    }
}

impl Default for EventFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_event_filter_builder() {
        let filter = EventFilter::new()
            .with_contract("0x123")
            .with_event("Transfer")
            .from_block(100)
            .to_block(200);
        
        assert_eq!(filter.contract_addresses.len(), 1);
        assert_eq!(filter.event_names.len(), 1);
        assert_eq!(filter.from_block, Some(100));
        assert_eq!(filter.to_block, Some(200));
    }
}
