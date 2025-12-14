//! Starknet Client for Proof Submission
//!
//! This module provides the client for submitting proofs to Starknet L2
//! and interacting with the on-chain verifier contract.

use super::proof_serializer::{CairoSerializedProof, Felt252};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Starknet network configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StarknetNetwork {
    /// Starknet mainnet
    Mainnet,
    /// Starknet Sepolia testnet
    Sepolia,
    /// Local devnet
    Devnet { url: String },
}

impl StarknetNetwork {
    /// Get the RPC URL for this network
    pub fn rpc_url(&self) -> &str {
        match self {
            StarknetNetwork::Mainnet => "https://starknet-mainnet.public.blastapi.io",
            StarknetNetwork::Sepolia => "https://starknet-sepolia.public.blastapi.io",
            StarknetNetwork::Devnet { url } => url,
        }
    }

    /// Get the chain ID
    pub fn chain_id(&self) -> &str {
        match self {
            StarknetNetwork::Mainnet => "SN_MAIN",
            StarknetNetwork::Sepolia => "SN_SEPOLIA",
            StarknetNetwork::Devnet { .. } => "SN_DEVNET",
        }
    }
}

/// Configuration for the Starknet client
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StarknetClientConfig {
    /// Network to connect to
    pub network: StarknetNetwork,
    /// Verifier contract address
    pub verifier_address: Felt252,
    /// Account address for signing transactions
    pub account_address: Option<Felt252>,
    /// Private key for signing (in production, use a secure key manager)
    pub private_key: Option<String>,
    /// Maximum fee willing to pay (in wei)
    pub max_fee: u64,
    /// Transaction timeout
    pub timeout: Duration,
}

impl Default for StarknetClientConfig {
    fn default() -> Self {
        Self {
            network: StarknetNetwork::Sepolia,
            verifier_address: Felt252::ZERO,
            account_address: None,
            private_key: None,
            max_fee: 1_000_000_000_000_000, // 0.001 ETH
            timeout: Duration::from_secs(60),
        }
    }
}

/// Result of a proof submission
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmissionResult {
    /// Transaction hash
    pub transaction_hash: Felt252,
    /// Block number (if confirmed)
    pub block_number: Option<u64>,
    /// Status of the submission
    pub status: SubmissionStatus,
    /// Gas used
    pub gas_used: Option<u64>,
    /// Actual fee paid
    pub actual_fee: Option<u64>,
}

/// Status of a proof submission
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubmissionStatus {
    /// Transaction pending
    Pending,
    /// Transaction accepted on L2
    AcceptedOnL2,
    /// Transaction accepted on L1
    AcceptedOnL1,
    /// Transaction rejected
    Rejected { reason: String },
    /// Transaction reverted
    Reverted { reason: String },
}

/// Result of proof verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the proof is valid
    pub is_valid: bool,
    /// Verification transaction hash
    pub transaction_hash: Option<Felt252>,
    /// Error message if verification failed
    pub error: Option<String>,
    /// Gas used for verification
    pub gas_used: Option<u64>,
}

/// Starknet client for proof operations
pub struct StarknetClient {
    config: StarknetClientConfig,
    http_client: reqwest::Client,
}

impl StarknetClient {
    /// Create a new Starknet client
    pub fn new(config: StarknetClientConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            http_client,
        }
    }

    /// Create a client for Sepolia testnet
    pub fn sepolia(verifier_address: Felt252) -> Self {
        Self::new(StarknetClientConfig {
            network: StarknetNetwork::Sepolia,
            verifier_address,
            ..Default::default()
        })
    }

    /// Submit a proof for on-chain verification
    pub async fn submit_proof(
        &self,
        proof: &CairoSerializedProof,
    ) -> Result<SubmissionResult, StarknetError> {
        // Build the calldata for the verify_proof function
        let calldata = self.build_verify_calldata(proof)?;

        // Estimate fee
        let estimated_fee = self.estimate_fee(&calldata).await?;

        // Check if fee is acceptable
        if estimated_fee > self.config.max_fee {
            return Err(StarknetError::FeeTooHigh {
                estimated: estimated_fee,
                max: self.config.max_fee,
            });
        }

        // Submit transaction
        let tx_hash = self.invoke_contract(&calldata, estimated_fee).await?;

        Ok(SubmissionResult {
            transaction_hash: tx_hash,
            block_number: None,
            status: SubmissionStatus::Pending,
            gas_used: None,
            actual_fee: Some(estimated_fee),
        })
    }

    /// Verify a proof (view call, no transaction)
    pub async fn verify_proof_view(
        &self,
        proof: &CairoSerializedProof,
    ) -> Result<VerificationResult, StarknetError> {
        let calldata = self.build_verify_calldata(proof)?;

        // Make a call (not a transaction)
        let result = self.call_contract("verify_proof", &calldata).await?;

        // Parse the result
        let is_valid = result.first()
            .map(|f| *f != Felt252::ZERO)
            .unwrap_or(false);

        Ok(VerificationResult {
            is_valid,
            transaction_hash: None,
            error: if is_valid { None } else { Some("Proof verification failed".to_string()) },
            gas_used: None,
        })
    }

    /// Wait for a transaction to be confirmed
    pub async fn wait_for_confirmation(
        &self,
        tx_hash: &Felt252,
        max_retries: u32,
    ) -> Result<SubmissionResult, StarknetError> {
        let mut retries = 0;
        let retry_delay = Duration::from_secs(5);

        loop {
            let status = self.get_transaction_status(tx_hash).await?;

            match &status.status {
                SubmissionStatus::AcceptedOnL2 | SubmissionStatus::AcceptedOnL1 => {
                    return Ok(status);
                }
                SubmissionStatus::Rejected { reason } | SubmissionStatus::Reverted { reason } => {
                    return Err(StarknetError::TransactionFailed {
                        hash: *tx_hash,
                        reason: reason.clone(),
                    });
                }
                SubmissionStatus::Pending => {
                    retries += 1;
                    if retries >= max_retries {
                        return Err(StarknetError::Timeout);
                    }
                    tokio::time::sleep(retry_delay).await;
                }
            }
        }
    }

    /// Get transaction status
    pub async fn get_transaction_status(
        &self,
        tx_hash: &Felt252,
    ) -> Result<SubmissionResult, StarknetError> {
        let request = json_rpc_request(
            "starknet_getTransactionStatus",
            serde_json::json!({
                "transaction_hash": tx_hash.to_hex()
            }),
        );

        let response = self.rpc_call(&request).await?;

        // Parse response
        let status = parse_transaction_status(&response)?;

        Ok(SubmissionResult {
            transaction_hash: *tx_hash,
            block_number: response.get("block_number")
                .and_then(|v| v.as_u64()),
            status,
            gas_used: response.get("actual_fee")
                .and_then(|v| v.as_str())
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()),
            actual_fee: None,
        })
    }

    /// Get the current nonce for an account
    pub async fn get_nonce(&self) -> Result<u64, StarknetError> {
        let account = self.config.account_address
            .ok_or(StarknetError::NoAccount)?;

        let request = json_rpc_request(
            "starknet_getNonce",
            serde_json::json!({
                "block_id": "latest",
                "contract_address": account.to_hex()
            }),
        );

        let response = self.rpc_call(&request).await?;

        let nonce_str = response.as_str()
            .ok_or_else(|| StarknetError::InvalidResponse("Expected nonce string".to_string()))?;

        u64::from_str_radix(nonce_str.trim_start_matches("0x"), 16)
            .map_err(|_| StarknetError::InvalidResponse("Invalid nonce format".to_string()))
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    /// Build calldata for verify_proof function
    fn build_verify_calldata(&self, proof: &CairoSerializedProof) -> Result<Vec<Felt252>, StarknetError> {
        // The calldata format for Cairo:
        // [proof_data_length, proof_data[0], proof_data[1], ...]
        let mut calldata = Vec::with_capacity(proof.data.len() + 1);
        calldata.push(Felt252::from_u64(proof.data.len() as u64));
        calldata.extend_from_slice(&proof.data);
        Ok(calldata)
    }

    /// Estimate fee for a transaction
    async fn estimate_fee(&self, calldata: &[Felt252]) -> Result<u64, StarknetError> {
        let account = self.config.account_address
            .ok_or(StarknetError::NoAccount)?;

        let nonce = self.get_nonce().await?;

        let request = json_rpc_request(
            "starknet_estimateFee",
            serde_json::json!({
                "request": [{
                    "type": "INVOKE",
                    "sender_address": account.to_hex(),
                    "calldata": calldata.iter().map(|f| f.to_hex()).collect::<Vec<_>>(),
                    "version": "0x1",
                    "nonce": format!("0x{:x}", nonce),
                }],
                "simulation_flags": [],
                "block_id": "latest"
            }),
        );

        let response = self.rpc_call(&request).await?;

        // Parse fee from response
        let fee_array = response.as_array()
            .ok_or_else(|| StarknetError::InvalidResponse("Expected array".to_string()))?;

        let fee_obj = fee_array.first()
            .ok_or_else(|| StarknetError::InvalidResponse("Empty fee array".to_string()))?;

        let fee_str = fee_obj.get("overall_fee")
            .and_then(|v| v.as_str())
            .ok_or_else(|| StarknetError::InvalidResponse("Missing overall_fee".to_string()))?;

        u64::from_str_radix(fee_str.trim_start_matches("0x"), 16)
            .map_err(|_| StarknetError::InvalidResponse("Invalid fee format".to_string()))
    }

    /// Invoke a contract function
    async fn invoke_contract(
        &self,
        calldata: &[Felt252],
        max_fee: u64,
    ) -> Result<Felt252, StarknetError> {
        let account = self.config.account_address
            .ok_or(StarknetError::NoAccount)?;

        let nonce = self.get_nonce().await?;

        // In production, this would sign the transaction properly
        // For now, we just show the structure
        let request = json_rpc_request(
            "starknet_addInvokeTransaction",
            serde_json::json!({
                "invoke_transaction": {
                    "type": "INVOKE",
                    "sender_address": account.to_hex(),
                    "calldata": calldata.iter().map(|f| f.to_hex()).collect::<Vec<_>>(),
                    "max_fee": format!("0x{:x}", max_fee),
                    "version": "0x1",
                    "signature": [], // Would be actual signature
                    "nonce": format!("0x{:x}", nonce),
                }
            }),
        );

        let response = self.rpc_call(&request).await?;

        let tx_hash_str = response.get("transaction_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| StarknetError::InvalidResponse("Missing transaction_hash".to_string()))?;

        Felt252::from_hex(tx_hash_str)
            .map_err(|_| StarknetError::InvalidResponse("Invalid tx hash format".to_string()))
    }

    /// Make a view call to a contract
    async fn call_contract(
        &self,
        function_name: &str,
        calldata: &[Felt252],
    ) -> Result<Vec<Felt252>, StarknetError> {
        // Get function selector
        let selector = starknet_keccak(function_name.as_bytes());

        let request = json_rpc_request(
            "starknet_call",
            serde_json::json!({
                "request": {
                    "contract_address": self.config.verifier_address.to_hex(),
                    "entry_point_selector": selector.to_hex(),
                    "calldata": calldata.iter().map(|f| f.to_hex()).collect::<Vec<_>>(),
                },
                "block_id": "latest"
            }),
        );

        let response = self.rpc_call(&request).await?;

        let result_array = response.as_array()
            .ok_or_else(|| StarknetError::InvalidResponse("Expected array result".to_string()))?;

        result_array.iter()
            .map(|v| {
                let s = v.as_str()
                    .ok_or_else(|| StarknetError::InvalidResponse("Expected string".to_string()))?;
                Felt252::from_hex(s)
                    .map_err(|_| StarknetError::InvalidResponse("Invalid felt format".to_string()))
            })
            .collect()
    }

    /// Make an RPC call
    async fn rpc_call(&self, request: &serde_json::Value) -> Result<serde_json::Value, StarknetError> {
        let response = self.http_client
            .post(self.config.network.rpc_url())
            .json(request)
            .send()
            .await
            .map_err(|e| StarknetError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(StarknetError::NetworkError(
                format!("HTTP error: {}", response.status())
            ));
        }

        let json: serde_json::Value = response.json().await
            .map_err(|e| StarknetError::InvalidResponse(e.to_string()))?;

        // Check for JSON-RPC error
        if let Some(error) = json.get("error") {
            let message = error.get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown error");
            return Err(StarknetError::RpcError(message.to_string()));
        }

        json.get("result")
            .cloned()
            .ok_or_else(|| StarknetError::InvalidResponse("Missing result".to_string()))
    }
}

// =============================================================================
// Error types
// =============================================================================

/// Errors that can occur when interacting with Starknet
#[derive(Debug, thiserror::Error)]
pub enum StarknetError {
    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("RPC error: {0}")]
    RpcError(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("No account configured")]
    NoAccount,

    #[error("Fee too high: estimated {estimated}, max {max}")]
    FeeTooHigh { estimated: u64, max: u64 },

    #[error("Transaction failed: {hash} - {reason}")]
    TransactionFailed { hash: Felt252, reason: String },

    #[error("Transaction timeout")]
    Timeout,

    #[error("Proof serialization error: {0}")]
    SerializationError(String),
}

// =============================================================================
// Helper functions
// =============================================================================

/// Create a JSON-RPC request
fn json_rpc_request(method: &str, params: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params
    })
}

/// Parse transaction status from response
fn parse_transaction_status(response: &serde_json::Value) -> Result<SubmissionStatus, StarknetError> {
    let finality = response.get("finality_status")
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN");

    let execution = response.get("execution_status")
        .and_then(|v| v.as_str());

    match (finality, execution) {
        ("ACCEPTED_ON_L1", _) => Ok(SubmissionStatus::AcceptedOnL1),
        ("ACCEPTED_ON_L2", Some("SUCCEEDED")) => Ok(SubmissionStatus::AcceptedOnL2),
        ("ACCEPTED_ON_L2", Some("REVERTED")) => {
            let reason = response.get("revert_reason")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string();
            Ok(SubmissionStatus::Reverted { reason })
        }
        ("REJECTED", _) => {
            let reason = response.get("transaction_failure_reason")
                .and_then(|v| v.get("error_message"))
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string();
            Ok(SubmissionStatus::Rejected { reason })
        }
        _ => Ok(SubmissionStatus::Pending),
    }
}

/// Compute Starknet keccak (sn_keccak)
/// This is keccak256 with the high 6 bits masked off
fn starknet_keccak(data: &[u8]) -> Felt252 {
    use sha3::{Digest, Keccak256};

    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    // Mask off high 6 bits to fit in felt252
    bytes[0] &= 0x03;

    Felt252(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_starknet_keccak() {
        // Test vector: sn_keccak("verify_proof")
        let selector = starknet_keccak(b"verify_proof");
        // The selector should fit in felt252 (high bits masked)
        assert!(selector.0[0] <= 0x03);
    }

    #[test]
    fn test_network_urls() {
        assert!(StarknetNetwork::Mainnet.rpc_url().contains("mainnet"));
        assert!(StarknetNetwork::Sepolia.rpc_url().contains("sepolia"));
    }

    #[test]
    fn test_default_config() {
        let config = StarknetClientConfig::default();
        assert!(matches!(config.network, StarknetNetwork::Sepolia));
    }
}

