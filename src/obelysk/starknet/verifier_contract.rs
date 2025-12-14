//! Verifier Contract Interface
//!
//! This module provides the interface for interacting with the STWO verifier
//! contract deployed on Starknet.

use super::proof_serializer::{CairoSerializedProof, Felt252, ProofMetadata};
use super::starknet_client::{StarknetClient, StarknetError, SubmissionResult, VerificationResult};
use serde::{Deserialize, Serialize};

/// Configuration for the verifier contract
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifierContractConfig {
    /// Contract address
    pub address: Felt252,
    /// Minimum security bits required
    pub min_security_bits: u32,
    /// Maximum proof size (in felt252 elements)
    pub max_proof_size: usize,
    /// Whether to use optimistic verification
    pub optimistic_mode: bool,
}

impl Default for VerifierContractConfig {
    fn default() -> Self {
        Self {
            address: Felt252::ZERO,
            min_security_bits: 96,
            max_proof_size: 100_000,
            optimistic_mode: false,
        }
    }
}

/// Interface for the on-chain STWO verifier contract
pub struct VerifierContract {
    config: VerifierContractConfig,
    client: StarknetClient,
}

impl VerifierContract {
    /// Create a new verifier contract interface
    pub fn new(config: VerifierContractConfig, client: StarknetClient) -> Self {
        Self { config, client }
    }

    /// Verify a proof on-chain
    pub async fn verify_proof(
        &self,
        proof: &CairoSerializedProof,
    ) -> Result<VerificationResult, VerifierError> {
        // Validate proof before submission
        self.validate_proof(proof)?;

        // Verify using view call first (no gas cost)
        let result = self.client.verify_proof_view(proof).await
            .map_err(|e| VerifierError::StarknetError(e))?;

        Ok(result)
    }

    /// Submit a proof for on-chain verification (with transaction)
    pub async fn submit_proof(
        &self,
        proof: &CairoSerializedProof,
    ) -> Result<SubmissionResult, VerifierError> {
        // Validate proof before submission
        self.validate_proof(proof)?;

        // Submit to Starknet
        let result = self.client.submit_proof(proof).await
            .map_err(|e| VerifierError::StarknetError(e))?;

        Ok(result)
    }

    /// Submit and wait for confirmation
    pub async fn submit_and_confirm(
        &self,
        proof: &CairoSerializedProof,
        max_retries: u32,
    ) -> Result<SubmissionResult, VerifierError> {
        let submission = self.submit_proof(proof).await?;

        let confirmed = self.client
            .wait_for_confirmation(&submission.transaction_hash, max_retries)
            .await
            .map_err(|e| VerifierError::StarknetError(e))?;

        Ok(confirmed)
    }

    /// Get the contract address
    pub fn address(&self) -> &Felt252 {
        &self.config.address
    }

    /// Get the minimum security bits
    pub fn min_security_bits(&self) -> u32 {
        self.config.min_security_bits
    }

    /// Validate a proof before submission
    fn validate_proof(&self, proof: &CairoSerializedProof) -> Result<(), VerifierError> {
        // Check proof size
        if proof.data.len() > self.config.max_proof_size {
            return Err(VerifierError::ProofTooLarge {
                size: proof.data.len(),
                max: self.config.max_proof_size,
            });
        }

        // Check security bits
        let security_bits = proof.metadata.config.log_blowup_factor
            * proof.metadata.config.n_queries as u32;
        if security_bits < self.config.min_security_bits {
            return Err(VerifierError::InsufficientSecurity {
                bits: security_bits,
                required: self.config.min_security_bits,
            });
        }

        Ok(())
    }

    /// Estimate gas cost for verification
    pub fn estimate_gas(&self, proof: &CairoSerializedProof) -> u64 {
        proof.estimate_gas_cost()
    }
}

/// Errors that can occur during verification
#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    #[error("Proof too large: {size} elements, max {max}")]
    ProofTooLarge { size: usize, max: usize },

    #[error("Insufficient security: {bits} bits, required {required}")]
    InsufficientSecurity { bits: u32, required: u32 },

    #[error("Starknet error: {0}")]
    StarknetError(#[from] StarknetError),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),
}

// =============================================================================
// Proof Registration for Obelysk
// =============================================================================

/// Represents a registered proof on-chain
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisteredProof {
    /// Unique proof ID (hash of the proof)
    pub proof_id: Felt252,
    /// Transaction hash of registration
    pub registration_tx: Felt252,
    /// Block number when registered
    pub block_number: u64,
    /// Timestamp of registration
    pub registered_at: u64,
    /// Metadata about the proof
    pub metadata: ProofMetadata,
    /// Whether the proof has been verified
    pub is_verified: bool,
}

/// Registry for tracking on-chain proofs
pub struct ProofRegistry {
    /// Registered proofs by ID
    proofs: std::collections::HashMap<Felt252, RegisteredProof>,
}

impl ProofRegistry {
    /// Create a new proof registry
    pub fn new() -> Self {
        Self {
            proofs: std::collections::HashMap::new(),
        }
    }

    /// Register a proof
    pub fn register(&mut self, proof: RegisteredProof) {
        self.proofs.insert(proof.proof_id, proof);
    }

    /// Get a proof by ID
    pub fn get(&self, proof_id: &Felt252) -> Option<&RegisteredProof> {
        self.proofs.get(proof_id)
    }

    /// Check if a proof is registered
    pub fn is_registered(&self, proof_id: &Felt252) -> bool {
        self.proofs.contains_key(proof_id)
    }

    /// Mark a proof as verified
    pub fn mark_verified(&mut self, proof_id: &Felt252) -> bool {
        if let Some(proof) = self.proofs.get_mut(proof_id) {
            proof.is_verified = true;
            true
        } else {
            false
        }
    }

    /// Get all registered proofs
    pub fn all_proofs(&self) -> impl Iterator<Item = &RegisteredProof> {
        self.proofs.values()
    }

    /// Get verified proofs
    pub fn verified_proofs(&self) -> impl Iterator<Item = &RegisteredProof> {
        self.proofs.values().filter(|p| p.is_verified)
    }
}

impl Default for ProofRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Batch Verification
// =============================================================================

/// Batch verifier for multiple proofs
pub struct BatchVerifier {
    contract: VerifierContract,
    pending: Vec<CairoSerializedProof>,
    max_batch_size: usize,
}

impl BatchVerifier {
    /// Create a new batch verifier
    pub fn new(contract: VerifierContract, max_batch_size: usize) -> Self {
        Self {
            contract,
            pending: Vec::new(),
            max_batch_size,
        }
    }

    /// Add a proof to the batch
    pub fn add_proof(&mut self, proof: CairoSerializedProof) -> Result<(), VerifierError> {
        if self.pending.len() >= self.max_batch_size {
            return Err(VerifierError::VerificationFailed(
                "Batch is full".to_string()
            ));
        }
        self.pending.push(proof);
        Ok(())
    }

    /// Get the number of pending proofs
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Verify all pending proofs
    pub async fn verify_all(&mut self) -> Vec<Result<VerificationResult, VerifierError>> {
        let proofs = std::mem::take(&mut self.pending);
        let mut results = Vec::with_capacity(proofs.len());

        for proof in proofs {
            let result = self.contract.verify_proof(&proof).await;
            results.push(result);
        }

        results
    }

    /// Clear pending proofs
    pub fn clear(&mut self) {
        self.pending.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_registry() {
        let mut registry = ProofRegistry::new();

        let proof = RegisteredProof {
            proof_id: Felt252::from_u32(1),
            registration_tx: Felt252::from_u32(100),
            block_number: 1000,
            registered_at: 1234567890,
            metadata: ProofMetadata {
                original_size_bytes: 1000,
                serialized_elements: 500,
                public_input_hash: Felt252::ZERO,
                config: super::super::proof_serializer::ProofConfig {
                    log_blowup_factor: 4,
                    log_last_layer_degree_bound: 5,
                    n_queries: 30,
                    pow_bits: 26,
                },
                generated_at: 1234567890,
            },
            is_verified: false,
        };

        registry.register(proof.clone());
        assert!(registry.is_registered(&Felt252::from_u32(1)));
        assert!(!registry.get(&Felt252::from_u32(1)).unwrap().is_verified);

        registry.mark_verified(&Felt252::from_u32(1));
        assert!(registry.get(&Felt252::from_u32(1)).unwrap().is_verified);
    }
}

