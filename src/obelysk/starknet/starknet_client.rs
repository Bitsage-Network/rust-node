//! Starknet Client for Proof Submission
//!
//! This module provides the client for submitting proofs to Starknet L2
//! and interacting with the on-chain verifier contract.

use super::proof_serializer::{CairoSerializedProof, Felt252};
use super::proof_compression::{
    ProofCompressor, CompressedProof, CompressionLevel, CompressionStats,
    OnChainCompressedProof,
};
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

/// Compression estimate for gas savings analysis
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompressionEstimate {
    /// Original size in bytes
    pub original_size: usize,
    /// Compressed size in bytes
    pub compressed_size: usize,
    /// Compression ratio (original / compressed)
    pub compression_ratio: f64,
    /// Savings percentage
    pub savings_percent: f64,
    /// Estimated gas saved
    pub estimated_gas_saved: u64,
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

    /// Submit a compressed proof for on-chain verification
    ///
    /// Uses LZ4 compression to reduce calldata by 30-50%, significantly
    /// reducing gas costs for proof submission.
    ///
    /// Returns both the submission result and compression statistics.
    pub async fn submit_compressed_proof(
        &self,
        proof: &CairoSerializedProof,
        compression_level: CompressionLevel,
    ) -> Result<(SubmissionResult, CompressionStats), StarknetError> {
        // Compress the proof
        let mut compressor = ProofCompressor::new(compression_level);
        let compressed = compressor.compress_proof(proof)
            .map_err(|e| StarknetError::CompressionError(e.to_string()))?;

        // Convert to on-chain format
        let on_chain = OnChainCompressedProof::from_compressed(&compressed)
            .map_err(|e| StarknetError::CompressionError(e.to_string()))?;

        // Build calldata for compressed verification
        let calldata = self.build_compressed_verify_calldata(&on_chain)?;

        // Estimate fee
        let estimated_fee = self.estimate_fee(&calldata).await?;

        // Log compression savings
        let savings = compressed.savings_percent();
        tracing::info!(
            "Proof compressed: {}% savings ({} -> {} bytes)",
            savings as u32,
            compressed.original_size,
            compressed.compressed_size
        );

        // Check if fee is acceptable
        if estimated_fee > self.config.max_fee {
            return Err(StarknetError::FeeTooHigh {
                estimated: estimated_fee,
                max: self.config.max_fee,
            });
        }

        // Submit transaction
        let tx_hash = self.invoke_contract(&calldata, estimated_fee).await?;

        let result = SubmissionResult {
            transaction_hash: tx_hash,
            block_number: None,
            status: SubmissionStatus::Pending,
            gas_used: None,
            actual_fee: Some(estimated_fee),
        };

        Ok((result, compressor.stats().clone()))
    }

    /// Build calldata for compressed proof verification
    fn build_compressed_verify_calldata(
        &self,
        proof: &OnChainCompressedProof,
    ) -> Result<Vec<Felt252>, StarknetError> {
        // Calldata format for compressed verification:
        // [scheme, original_count, checksum, compressed_length, compressed_data...]
        let mut calldata = Vec::with_capacity(proof.compressed_felts.len() + 4);

        calldata.push(Felt252::from_u32(proof.scheme as u32));
        calldata.push(Felt252::from_u64(proof.original_felt_count as u64));
        calldata.push(proof.checksum);
        calldata.push(Felt252::from_u64(proof.compressed_felts.len() as u64));
        calldata.extend_from_slice(&proof.compressed_felts);

        Ok(calldata)
    }

    /// Estimate gas savings from compression
    pub fn estimate_compression_savings(
        &self,
        proof: &CairoSerializedProof,
    ) -> Result<CompressionEstimate, StarknetError> {
        let mut compressor = ProofCompressor::new(CompressionLevel::Fast);
        let compressed = compressor.compress_proof(proof)
            .map_err(|e| StarknetError::CompressionError(e.to_string()))?;

        // Gas per calldata byte (approximate: 16 for non-zero, 4 for zero)
        const AVG_GAS_PER_BYTE: u64 = 12;

        let original_calldata_gas = (proof.data.len() * 32) as u64 * AVG_GAS_PER_BYTE;
        let compressed_calldata_gas = compressed.compressed_size as u64 * AVG_GAS_PER_BYTE;

        Ok(CompressionEstimate {
            original_size: proof.data.len() * 32,
            compressed_size: compressed.compressed_size,
            compression_ratio: compressed.compression_ratio(),
            savings_percent: compressed.savings_percent(),
            estimated_gas_saved: original_calldata_gas.saturating_sub(compressed_calldata_gas),
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

    #[error("Compression error: {0}")]
    CompressionError(String),

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

// =============================================================================
// FRI Verification Interface
// =============================================================================

/// FRI configuration for verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriConfig {
    /// Log2 of the blowup factor
    pub log_blowup_factor: u32,
    /// Log2 of the last layer size
    pub log_last_layer_size: u32,
    /// Number of queries
    pub n_queries: u32,
    /// Security bits from proof-of-work
    pub pow_bits: u32,
}

impl Default for FriConfig {
    fn default() -> Self {
        Self {
            log_blowup_factor: 4,
            log_last_layer_size: 5,
            n_queries: 30,
            pow_bits: 26,
        }
    }
}

/// FRI layer commitment
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriLayerCommitment {
    /// Merkle root of this layer
    pub commitment: Felt252,
    /// Folding alpha (random challenge)
    pub alpha: Felt252,
    /// Log2 size of domain
    pub log_size: u32,
}

/// FRI verification request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriVerificationRequest {
    /// FRI configuration
    pub config: FriConfig,
    /// Initial trace commitment
    pub initial_commitment: Felt252,
    /// Layer commitments
    pub layer_commitments: Vec<FriLayerCommitment>,
    /// Query indices
    pub query_indices: Vec<u32>,
    /// Query values (f(x), f(-x) pairs)
    pub query_values: Vec<(Felt252, Felt252)>,
    /// Merkle authentication paths
    pub merkle_paths: Vec<Vec<Felt252>>,
    /// Final polynomial coefficients
    pub final_poly_coeffs: Vec<Felt252>,
    /// Channel seed for Fiat-Shamir
    pub channel_seed: Felt252,
}

/// Result of FRI verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriVerificationResult {
    /// Whether the proof is valid
    pub is_valid: bool,
    /// Error code if verification failed
    pub error_code: u32,
    /// Number of layers verified
    pub verified_layers: u32,
    /// Number of queries verified
    pub verified_queries: u32,
}

impl StarknetClient {
    /// Verify a FRI proof on-chain using the Cairo FRI verifier
    ///
    /// This calls the `verify_fri_proof` function in the deployed
    /// fri_verifier.cairo contract.
    pub async fn verify_fri_proof(
        &self,
        request: &FriVerificationRequest,
    ) -> Result<FriVerificationResult, StarknetError> {
        // Build calldata for FRI verification
        let calldata = self.build_fri_verify_calldata(request)?;

        // Make a view call (no gas cost)
        let result = self.call_contract("verify_fri_proof", &calldata).await?;

        // Parse the result
        // Result format: [is_valid, error_code, verified_layers, verified_queries]
        if result.len() < 4 {
            return Err(StarknetError::InvalidResponse(
                "FRI verification returned insufficient data".to_string()
            ));
        }

        let is_valid = result[0] != Felt252::ZERO;
        let error_code: u32 = felt_to_u32(&result[1]).unwrap_or(0);
        let verified_layers: u32 = felt_to_u32(&result[2]).unwrap_or(0);
        let verified_queries: u32 = felt_to_u32(&result[3]).unwrap_or(0);

        Ok(FriVerificationResult {
            is_valid,
            error_code,
            verified_layers,
            verified_queries,
        })
    }

    /// Submit a FRI proof for on-chain verification (with transaction)
    ///
    /// This creates a transaction that calls `verify_fri_proof` and
    /// stores the verification result on-chain.
    pub async fn submit_fri_proof(
        &self,
        request: &FriVerificationRequest,
    ) -> Result<SubmissionResult, StarknetError> {
        let calldata = self.build_fri_verify_calldata(request)?;

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

    /// Verify a Merkle path on-chain
    ///
    /// Useful for verifying individual query decommitments.
    pub async fn verify_merkle_path(
        &self,
        leaf_hash: Felt252,
        index: u32,
        path: &[Felt252],
        root: Felt252,
    ) -> Result<bool, StarknetError> {
        let mut calldata = Vec::with_capacity(path.len() + 4);
        calldata.push(leaf_hash);
        calldata.push(Felt252::from_u32(index));
        calldata.push(Felt252::from_u64(path.len() as u64));
        calldata.extend_from_slice(path);
        calldata.push(root);

        let result = self.call_contract("verify_merkle_path", &calldata).await?;

        Ok(result.first().map(|f| *f != Felt252::ZERO).unwrap_or(false))
    }

    /// Build calldata for FRI verification
    fn build_fri_verify_calldata(
        &self,
        request: &FriVerificationRequest,
    ) -> Result<Vec<Felt252>, StarknetError> {
        let mut calldata = Vec::new();

        // FRI config (4 elements)
        calldata.push(Felt252::from_u32(request.config.log_blowup_factor));
        calldata.push(Felt252::from_u32(request.config.log_last_layer_size));
        calldata.push(Felt252::from_u32(request.config.n_queries));
        calldata.push(Felt252::from_u32(request.config.pow_bits));

        // Initial commitment
        calldata.push(request.initial_commitment);

        // Layer commitments: [count, (commitment, alpha, log_size)...]
        calldata.push(Felt252::from_u64(request.layer_commitments.len() as u64));
        for layer in &request.layer_commitments {
            calldata.push(layer.commitment);
            calldata.push(layer.alpha);
            calldata.push(Felt252::from_u32(layer.log_size));
        }

        // Query responses: [count, (index, values_count, values..., path_count, path...)...]
        calldata.push(Felt252::from_u64(request.query_indices.len() as u64));
        for i in 0..request.query_indices.len() {
            calldata.push(Felt252::from_u32(request.query_indices[i]));

            // Query values (f(x), f(-x))
            if i < request.query_values.len() {
                calldata.push(Felt252::from_u32(2)); // 2 values per query
                calldata.push(request.query_values[i].0);
                calldata.push(request.query_values[i].1);
            } else {
                calldata.push(Felt252::from_u32(0));
            }

            // Merkle path
            if i < request.merkle_paths.len() {
                let path = &request.merkle_paths[i];
                calldata.push(Felt252::from_u64(path.len() as u64));
                calldata.extend_from_slice(path);
            } else {
                calldata.push(Felt252::from_u32(0));
            }
        }

        // Final polynomial coefficients
        calldata.push(Felt252::from_u64(request.final_poly_coeffs.len() as u64));
        calldata.extend_from_slice(&request.final_poly_coeffs);

        // Channel seed
        calldata.push(request.channel_seed);

        Ok(calldata)
    }

    /// Estimate gas for FRI verification
    pub fn estimate_fri_verification_gas(&self, request: &FriVerificationRequest) -> u64 {
        // Base cost for FRI verification
        let base_cost: u64 = 50_000;

        // Per-layer cost (hash operations, field arithmetic)
        let layer_cost = request.layer_commitments.len() as u64 * 5_000;

        // Per-query cost (Merkle path verification, folding)
        let query_cost = request.query_indices.len() as u64 * 8_000;

        // Merkle path cost (per hash in paths)
        let path_cost: u64 = request.merkle_paths.iter()
            .map(|p| p.len() as u64 * 500)
            .sum();

        // Final polynomial evaluation cost
        let poly_cost = request.final_poly_coeffs.len() as u64 * 1_000;

        base_cost + layer_cost + query_cost + path_cost + poly_cost
    }
}

/// Convert Felt252 to u32
fn felt_to_u32(felt: &Felt252) -> Option<u32> {
    // Take lowest 4 bytes
    let bytes = &felt.0[28..32];
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
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

