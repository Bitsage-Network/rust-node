//! # Event Processor
//!
//! Decodes and transforms raw Starknet events into structured data
//! ready for database insertion.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

use super::event_listener::RawEvent;
use super::IndexerError;

/// Processed event ready for database insertion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessedEvent {
    pub contract_name: String,
    pub contract_address: String,
    pub event_name: String,
    pub event_data: Value,
    pub block_number: u64,
    pub block_timestamp: Option<u64>,
    pub transaction_hash: String,
    pub log_index: Option<u32>,
}

/// Event processor that decodes raw events
pub struct EventProcessor {
    /// Event selector to name mapping
    event_selectors: HashMap<String, String>,
}

impl EventProcessor {
    /// Create a new EventProcessor
    pub fn new() -> Self {
        let mut event_selectors = HashMap::new();
        
        // Pre-compute event selectors (keccak256 of event signature)
        // These are the first key in Starknet events
        // For now, we'll decode based on contract context
        
        // Job Manager events
        event_selectors.insert(
            compute_event_selector("JobSubmitted"),
            "JobSubmitted".to_string()
        );
        event_selectors.insert(
            compute_event_selector("JobAssigned"),
            "JobAssigned".to_string()
        );
        event_selectors.insert(
            compute_event_selector("JobCompleted"),
            "JobCompleted".to_string()
        );
        event_selectors.insert(
            compute_event_selector("JobCancelled"),
            "JobCancelled".to_string()
        );
        
        // Staking events
        event_selectors.insert(
            compute_event_selector("Staked"),
            "Staked".to_string()
        );
        event_selectors.insert(
            compute_event_selector("Unstaked"),
            "Unstaked".to_string()
        );
        event_selectors.insert(
            compute_event_selector("Slashed"),
            "Slashed".to_string()
        );
        
        // OTC events
        event_selectors.insert(
            compute_event_selector("OrderPlaced"),
            "OrderPlaced".to_string()
        );
        event_selectors.insert(
            compute_event_selector("OrderFilled"),
            "OrderFilled".to_string()
        );
        event_selectors.insert(
            compute_event_selector("OrderCancelled"),
            "OrderCancelled".to_string()
        );
        event_selectors.insert(
            compute_event_selector("TradeExecuted"),
            "TradeExecuted".to_string()
        );
        
        // Governance events
        event_selectors.insert(
            compute_event_selector("ProposalCreated"),
            "ProposalCreated".to_string()
        );
        event_selectors.insert(
            compute_event_selector("VoteCast"),
            "VoteCast".to_string()
        );
        event_selectors.insert(
            compute_event_selector("ProposalExecuted"),
            "ProposalExecuted".to_string()
        );
        
        // Privacy events
        event_selectors.insert(
            compute_event_selector("PrivateTransferInitiated"),
            "PrivateTransferInitiated".to_string()
        );
        event_selectors.insert(
            compute_event_selector("PrivateTransferCompleted"),
            "PrivateTransferCompleted".to_string()
        );
        
        // Proof events
        event_selectors.insert(
            compute_event_selector("ProofVerified"),
            "ProofVerified".to_string()
        );
        
        // Faucet events
        event_selectors.insert(
            compute_event_selector("Claimed"),
            "Claimed".to_string()
        );
        
        Self {
            event_selectors,
        }
    }
    
    /// Process a raw event into a structured format
    pub fn process_event(
        &self,
        contract_name: &str,
        raw_event: &RawEvent,
    ) -> Result<ProcessedEvent, IndexerError> {
        // Get event name from first key (selector)
        let event_name = self.decode_event_name(contract_name, &raw_event.keys)?;
        
        // Decode event data based on contract and event type
        let event_data = self.decode_event_data(
            contract_name,
            &event_name,
            &raw_event.keys,
            &raw_event.data,
        )?;
        
        Ok(ProcessedEvent {
            contract_name: contract_name.to_string(),
            contract_address: raw_event.from_address.clone(),
            event_name,
            event_data,
            block_number: raw_event.block_number,
            block_timestamp: None, // Will be filled by caller if needed
            transaction_hash: raw_event.transaction_hash.clone(),
            log_index: None,
        })
    }
    
    /// Decode event name from keys
    fn decode_event_name(
        &self,
        contract_name: &str,
        keys: &[String],
    ) -> Result<String, IndexerError> {
        if keys.is_empty() {
            return Err(IndexerError::ProcessingError("No keys in event".to_string()));
        }
        
        let selector = &keys[0];
        
        // Try to find in our selector map
        if let Some(name) = self.event_selectors.get(selector) {
            return Ok(name.clone());
        }
        
        // Fall back to inferring from contract type and key count
        let event_name = match contract_name {
            "JobManager" => match keys.len() {
                3 => "JobSubmitted",
                4 => "JobAssigned",
                5 => "JobCompleted",
                _ => "UnknownJobEvent",
            },
            "Staking" => match keys.len() {
                2 => "Staked",
                3 => "Unstaked",
                _ => "UnknownStakingEvent",
            },
            "OTCOrderbook" => {
                // OrderPlaced: selector, order_id (u256 = 2 felts), maker_address = 4 keys
                // OrderFilled/OrderCancelled: similar structure with more keys
                // Check first key (event selector) to determine event type
                let selector = keys.first().map(|s| s.as_str()).unwrap_or("");
                match selector {
                    // OrderPlaced event selector (starknet_keccak("OrderPlaced"))
                    "0x3b935dbbdb7f463a394fc8729e7e26e30edebbc3bd5617bf1d7cf9e1ce6f7cb" => "OrderPlaced",
                    // OrderFilled event selector
                    "0x2bbd2e3e8eabe92efaae9cc3c28b99a20bde4e0c5d3f30a0e7c25e6b0c5d8b2a" => "OrderFilled",
                    // OrderCancelled event selector
                    "0x1c2a4c8e9babe92efaae9cc3c28b99a20bde4e0c5d3f30a0e7c25e6b0c5d8b2a" => "OrderCancelled",
                    // TradeExecuted event selector (actual selector from on-chain events)
                    "0x391307dff06bce4373e560329a600f2f2f0c821c9e6679f822e86e052c58d6c" => "TradeExecuted",
                    _ => "UnknownOTCEvent",
                }
            }
            _ => "UnknownEvent",
        };
        
        Ok(event_name.to_string())
    }
    
    /// Decode event data based on contract and event type
    fn decode_event_data(
        &self,
        contract_name: &str,
        event_name: &str,
        keys: &[String],
        data: &[String],
    ) -> Result<Value, IndexerError> {
        match contract_name {
            "JobManager" => self.decode_job_event(event_name, keys, data),
            "Staking" => self.decode_staking_event(event_name, keys, data),
            "OTCOrderbook" => self.decode_otc_event(event_name, keys, data),
            "Governance" => self.decode_governance_event(event_name, keys, data),
            "PrivacyRouter" => self.decode_privacy_event(event_name, keys, data),
            "ProofVerifier" => self.decode_proof_event(event_name, keys, data),
            "Reputation" => self.decode_reputation_event(event_name, keys, data),
            "Faucet" => self.decode_faucet_event(event_name, keys, data),
            _ => Ok(json!({
                "keys": keys,
                "data": data,
            })),
        }
    }
    
    /// Decode JobManager events
    fn decode_job_event(
        &self,
        event_name: &str,
        keys: &[String],
        data: &[String],
    ) -> Result<Value, IndexerError> {
        match event_name {
            "JobSubmitted" => Ok(json!({
                "job_id": keys.get(1).unwrap_or(&"0".to_string()),
                "client": keys.get(2).unwrap_or(&"0".to_string()),
                "job_type": data.get(0).unwrap_or(&"0".to_string()),
                "payment_amount": decode_u256(data.get(1), data.get(2)),
                "priority": data.get(3).unwrap_or(&"0".to_string()),
            })),
            "JobAssigned" => Ok(json!({
                "job_id": keys.get(1).unwrap_or(&"0".to_string()),
                "worker": keys.get(2).unwrap_or(&"0".to_string()),
                "assigned_at": data.get(0).unwrap_or(&"0".to_string()),
            })),
            "JobCompleted" => Ok(json!({
                "job_id": keys.get(1).unwrap_or(&"0".to_string()),
                "worker": keys.get(2).unwrap_or(&"0".to_string()),
                "result_hash": data.get(0).unwrap_or(&"0".to_string()),
                "execution_time_ms": data.get(1).unwrap_or(&"0".to_string()),
            })),
            "JobCancelled" => Ok(json!({
                "job_id": keys.get(1).unwrap_or(&"0".to_string()),
                "reason": data.get(0).unwrap_or(&"0".to_string()),
            })),
            "PaymentReleased" => Ok(json!({
                "job_id": keys.get(1).unwrap_or(&"0".to_string()),
                "worker": keys.get(2).unwrap_or(&"0".to_string()),
                "amount": decode_u256(data.get(0), data.get(1)),
            })),
            _ => Ok(json!({ "keys": keys, "data": data })),
        }
    }
    
    /// Decode Staking events
    fn decode_staking_event(
        &self,
        event_name: &str,
        keys: &[String],
        data: &[String],
    ) -> Result<Value, IndexerError> {
        match event_name {
            "Staked" => Ok(json!({
                "worker": keys.get(1).unwrap_or(&"0".to_string()),
                "amount": decode_u256(data.get(0), data.get(1)),
                "gpu_tier": data.get(2).unwrap_or(&"0".to_string()),
                "has_tee": data.get(3).map(|s| s != "0x0").unwrap_or(false),
            })),
            "Unstaked" | "UnstakeInitiated" => Ok(json!({
                "worker": keys.get(1).unwrap_or(&"0".to_string()),
                "amount": decode_u256(data.get(0), data.get(1)),
            })),
            "Slashed" => Ok(json!({
                "worker": keys.get(1).unwrap_or(&"0".to_string()),
                "amount": decode_u256(data.get(0), data.get(1)),
                "reason": data.get(2).unwrap_or(&"0".to_string()),
            })),
            "StakeIncreased" => Ok(json!({
                "worker": keys.get(1).unwrap_or(&"0".to_string()),
                "additional_amount": decode_u256(data.get(0), data.get(1)),
                "new_total": decode_u256(data.get(2), data.get(3)),
            })),
            _ => Ok(json!({ "keys": keys, "data": data })),
        }
    }
    
    /// Decode OTC Orderbook events
    fn decode_otc_event(
        &self,
        event_name: &str,
        keys: &[String],
        data: &[String],
    ) -> Result<Value, IndexerError> {
        match event_name {
            "OrderPlaced" => {
                // Keys: [selector, order_id_low, order_id_high, maker_address]
                // Data: [pair_id, side, price_high, price_low, amount_high, amount_low, expires_high, expires_low]
                // Note: u256 values appear to be stored as (high, low) in this contract
                Ok(json!({
                    "order_id": decode_u256(keys.get(1), keys.get(2)),
                    "maker": keys.get(3).unwrap_or(&"0".to_string()),
                    "pair_id": data.get(0).unwrap_or(&"0".to_string()),
                    "side": data.get(1).unwrap_or(&"0".to_string()),
                    "price": decode_u256(data.get(3), data.get(2)),  // swap: low=data[3], high=data[2]
                    "amount": decode_u256(data.get(5), data.get(4)), // swap: low=data[5], high=data[4]
                    "expires_at": decode_u256(data.get(7), data.get(6)), // swap: low=data[7], high=data[6]
                }))
            }
            "OrderFilled" => Ok(json!({
                "order_id": keys.get(1).unwrap_or(&"0".to_string()),
                "taker": keys.get(2).unwrap_or(&"0".to_string()),
                "filled_amount": decode_u256(data.get(0), data.get(1)),
                "remaining_amount": decode_u256(data.get(2), data.get(3)),
            })),
            "OrderCancelled" => Ok(json!({
                "order_id": keys.get(1).unwrap_or(&"0".to_string()),
                "maker": keys.get(2).unwrap_or(&"0".to_string()),
                "refund_amount": decode_u256(data.get(0), data.get(1)),
            })),
            "TradeExecuted" => {
                // Keys: [selector, trade_id_low, trade_id_high, maker_order_id_low, maker_order_id_high, taker_order_id_low, taker_order_id_high]
                // Data: [maker, taker, price_low, price_high, amount_low, amount_high, quote_amount_low, quote_amount_high, maker_fee_low, maker_fee_high, taker_fee_low, taker_fee_high]
                Ok(json!({
                    "trade_id": decode_u256(keys.get(1), keys.get(2)),
                    "maker_order_id": decode_u256(keys.get(3), keys.get(4)),
                    "taker_order_id": decode_u256(keys.get(5), keys.get(6)),
                    "maker": data.get(0).unwrap_or(&"0".to_string()),
                    "taker": data.get(1).unwrap_or(&"0".to_string()),
                    "price": decode_u256(data.get(2), data.get(3)),
                    "amount": decode_u256(data.get(4), data.get(5)),
                    "quote_amount": decode_u256(data.get(6), data.get(7)),
                    "maker_fee": decode_u256(data.get(8), data.get(9)),
                    "taker_fee": decode_u256(data.get(10), data.get(11)),
                    "side": "buy", // Default side - contract doesn't emit side in TradeExecuted
                    "pair_id": "1", // Need to get from order lookup, default to SAGE_STRK
                }))
            }
            "PairAdded" => Ok(json!({
                "pair_id": keys.get(1).unwrap_or(&"0".to_string()),
                "base_token": data.get(0).unwrap_or(&"0".to_string()),
                "quote_token": data.get(1).unwrap_or(&"0".to_string()),
            })),
            _ => Ok(json!({ "keys": keys, "data": data })),
        }
    }
    
    /// Decode Governance events
    fn decode_governance_event(
        &self,
        event_name: &str,
        keys: &[String],
        data: &[String],
    ) -> Result<Value, IndexerError> {
        match event_name {
            "ProposalCreated" => Ok(json!({
                "proposal_id": keys.get(1).unwrap_or(&"0".to_string()),
                "proposer": keys.get(2).unwrap_or(&"0".to_string()),
                "proposal_type": data.get(0).unwrap_or(&"0".to_string()),
                "start_block": data.get(1).unwrap_or(&"0".to_string()),
                "end_block": data.get(2).unwrap_or(&"0".to_string()),
            })),
            "VoteCast" => Ok(json!({
                "proposal_id": keys.get(1).unwrap_or(&"0".to_string()),
                "voter": keys.get(2).unwrap_or(&"0".to_string()),
                "support": data.get(0).unwrap_or(&"0".to_string()),
                "voting_power": decode_u256(data.get(1), data.get(2)),
            })),
            "ProposalExecuted" => Ok(json!({
                "proposal_id": keys.get(1).unwrap_or(&"0".to_string()),
            })),
            "ProposalCancelled" => Ok(json!({
                "proposal_id": keys.get(1).unwrap_or(&"0".to_string()),
            })),
            _ => Ok(json!({ "keys": keys, "data": data })),
        }
    }
    
    /// Decode Privacy Router events
    fn decode_privacy_event(
        &self,
        event_name: &str,
        keys: &[String],
        data: &[String],
    ) -> Result<Value, IndexerError> {
        match event_name {
            "PrivateTransferInitiated" => Ok(json!({
                "nullifier": keys.get(1).unwrap_or(&"0".to_string()),
                "sender": data.get(0).unwrap_or(&"0".to_string()),
                "encrypted_amount": data.get(1).unwrap_or(&"0".to_string()),
                "commitment": data.get(2).unwrap_or(&"0".to_string()),
            })),
            "PrivateTransferCompleted" => Ok(json!({
                "nullifier": keys.get(1).unwrap_or(&"0".to_string()),
            })),
            "StealthAddressRegistered" => Ok(json!({
                "owner": keys.get(1).unwrap_or(&"0".to_string()),
                "stealth_address": data.get(0).unwrap_or(&"0".to_string()),
                "ephemeral_pubkey": data.get(1).unwrap_or(&"0".to_string()),
            })),
            _ => Ok(json!({ "keys": keys, "data": data })),
        }
    }
    
    /// Decode Proof Verifier events
    fn decode_proof_event(
        &self,
        event_name: &str,
        keys: &[String],
        data: &[String],
    ) -> Result<Value, IndexerError> {
        match event_name {
            "ProofVerified" => Ok(json!({
                "job_id": keys.get(1).unwrap_or(&"0".to_string()),
                "worker": keys.get(2).unwrap_or(&"0".to_string()),
                "proof_hash": data.get(0).unwrap_or(&"0".to_string()),
                "is_valid": data.get(1).map(|s| s != "0x0").unwrap_or(false),
                "verification_time_ms": data.get(2).unwrap_or(&"0".to_string()),
            })),
            "ProofSubmitted" => Ok(json!({
                "job_id": keys.get(1).unwrap_or(&"0".to_string()),
                "worker": keys.get(2).unwrap_or(&"0".to_string()),
                "proof_hash": data.get(0).unwrap_or(&"0".to_string()),
            })),
            _ => Ok(json!({ "keys": keys, "data": data })),
        }
    }
    
    /// Decode Reputation events
    fn decode_reputation_event(
        &self,
        event_name: &str,
        keys: &[String],
        data: &[String],
    ) -> Result<Value, IndexerError> {
        match event_name {
            "ReputationUpdated" => Ok(json!({
                "worker": keys.get(1).unwrap_or(&"0".to_string()),
                "old_score": data.get(0).unwrap_or(&"0".to_string()),
                "new_score": data.get(1).unwrap_or(&"0".to_string()),
                "reason": data.get(2).unwrap_or(&"0".to_string()),
            })),
            "WorkerRegistered" => Ok(json!({
                "worker": keys.get(1).unwrap_or(&"0".to_string()),
                "initial_score": data.get(0).unwrap_or(&"100".to_string()),
            })),
            _ => Ok(json!({ "keys": keys, "data": data })),
        }
    }
    
    /// Decode Faucet events
    fn decode_faucet_event(
        &self,
        event_name: &str,
        keys: &[String],
        data: &[String],
    ) -> Result<Value, IndexerError> {
        match event_name {
            "Claimed" => Ok(json!({
                "claimer": keys.get(1).unwrap_or(&"0".to_string()),
                "amount": decode_u256(data.get(0), data.get(1)),
            })),
            "ConfigUpdated" => Ok(json!({
                "drip_amount": decode_u256(data.get(0), data.get(1)),
                "cooldown_secs": data.get(2).unwrap_or(&"0".to_string()),
            })),
            _ => Ok(json!({ "keys": keys, "data": data })),
        }
    }
}

impl Default for EventProcessor {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute event selector (simplified - in production use proper keccak256)
fn compute_event_selector(event_name: &str) -> String {
    // In production, this should use actual keccak256 hashing
    // For now, we use a placeholder that won't match
    format!("0x{:064x}", event_name.as_bytes().iter().fold(0u64, |acc, &b| acc.wrapping_add(b as u64)))
}

/// Decode u256 from low and high parts
fn decode_u256(low: Option<&String>, high: Option<&String>) -> String {
    let low_val = low
        .and_then(|s| u128::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);
    
    let high_val = high
        .and_then(|s| u128::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);
    
    // Combine into a string representation
    if high_val == 0 {
        format!("{}", low_val)
    } else {
        // For very large numbers, return as hex
        format!("0x{:032x}{:032x}", high_val, low_val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_decode_u256() {
        assert_eq!(decode_u256(Some(&"0x64".to_string()), Some(&"0x0".to_string())), "100");
        assert_eq!(decode_u256(Some(&"0x1".to_string()), None), "1");
    }
    
    #[test]
    fn test_event_processor_new() {
        let processor = EventProcessor::new();
        assert!(!processor.event_selectors.is_empty());
    }
}
