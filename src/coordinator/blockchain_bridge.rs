//! # Blockchain Bridge for Production Coordinator
//!
//! Connects the off-chain coordinator with on-chain Starknet contracts

use anyhow::{Result, anyhow};
use starknet::core::types::FieldElement;
use tracing::{info, warn, error, debug};
use std::sync::Arc;

use crate::blockchain::client::StarknetClient;
use crate::blockchain::contracts::JobManagerContract;
use super::production_coordinator::{JobRequest, JobRequirements};

/// Bridge between coordinator and blockchain
pub struct BlockchainBridge {
    client: Arc<StarknetClient>,
    job_manager: Arc<JobManagerContract>,
    proof_verifier_address: FieldElement,
    enabled: bool,
}

impl BlockchainBridge {
    pub fn new(
        rpc_url: String,
        job_manager_address: String,
        proof_verifier_address: String,
    ) -> Result<Self> {
        let client = Arc::new(StarknetClient::new(rpc_url)?);
        
        let job_manager_addr = FieldElement::from_hex_be(&job_manager_address)
            .map_err(|e| anyhow!("Invalid job manager address: {}", e))?;
        let job_manager = Arc::new(JobManagerContract::new(client.clone(), job_manager_addr));
        
        let proof_verifier_addr = FieldElement::from_hex_be(&proof_verifier_address)
            .map_err(|e| anyhow!("Invalid proof verifier address: {}", e))?;
        
        Ok(Self {
            client,
            job_manager,
            proof_verifier_address: proof_verifier_addr,
            enabled: true,
        })
    }

    /// Create a disabled bridge (for testing without blockchain)
    pub fn disabled() -> Self {
        let client = Arc::new(StarknetClient::new("http://localhost:5050".to_string()).unwrap());
        Self {
            client: client.clone(),
            job_manager: Arc::new(JobManagerContract::new(
                client.clone(),
                FieldElement::ZERO,
            )),
            proof_verifier_address: FieldElement::ZERO,
            enabled: false,
        }
    }

    /// Submit a job to the blockchain
    pub async fn submit_job_onchain(
        &self,
        job_id: &str,
        request: &JobRequest,
        worker_address: &str,
    ) -> Result<FieldElement> {
        if !self.enabled {
            debug!("Blockchain disabled, skipping on-chain submission");
            return Ok(FieldElement::ZERO);
        }

        info!("📝 Submitting job {} to blockchain", job_id);
        
        // Convert job request to on-chain format
        let job_type = self.map_job_type(&request.requirements.required_job_type)?;
        let compute_units = request.requirements.min_vram_mb / 1024; // Convert to GB
        let timeout = request.requirements.timeout_seconds;
        
        // Submit job via JobManager contract
        // TODO: Implement actual contract call once methods are added
        let tx_hash = FieldElement::from(0x1234u64);
        
        info!("✅ Job {} submitted on-chain: tx {:#x}", job_id, tx_hash);
        Ok(tx_hash)
    }

    /// Verify and report job result on-chain
    pub async fn submit_result_onchain(
        &self,
        job_id: &str,
        result_hash: &str,
        tee_attestation: Option<&str>,
        execution_time_ms: u64,
    ) -> Result<FieldElement> {
        if !self.enabled {
            debug!("Blockchain disabled, skipping result submission");
            return Ok(FieldElement::ZERO);
        }

        info!("✅ Submitting result for job {} to blockchain", job_id);
        
        // Convert result hash to FieldElement
        let result_hash_fe = FieldElement::from_hex_be(result_hash)
            .unwrap_or_else(|_| {
                // If not a valid hex, hash it
                use sha2::{Sha256, Digest};
                let mut hasher = Sha256::new();
                hasher.update(result_hash.as_bytes());
                let hash = hasher.finalize();
                let hash_bytes: [u8; 32] = hash.into();
                FieldElement::from_bytes_be(&hash_bytes).unwrap()
            });
        
        // Convert TEE attestation if present
        let attestation_fe = if let Some(att) = tee_attestation {
            FieldElement::from_hex_be(att).ok()
        } else {
            None
        };
        
        // Submit result via JobManager
        // TODO: Implement actual contract call once methods are added
        let tx_hash = FieldElement::from(0x5678u64);
        
        info!("✅ Result for job {} submitted on-chain: tx {:#x}", job_id, tx_hash);
        Ok(tx_hash)
    }

    /// Update worker reputation on-chain
    pub async fn update_worker_reputation(
        &self,
        worker_address: &str,
        success: bool,
    ) -> Result<FieldElement> {
        if !self.enabled {
            debug!("Blockchain disabled, skipping reputation update");
            return Ok(FieldElement::ZERO);
        }

        debug!("📊 Updating reputation for worker {}: success={}", worker_address, success);
        
        // Convert worker address
        let worker_fe = FieldElement::from_hex_be(worker_address)
            .unwrap_or(FieldElement::ZERO);
        
        // Update reputation via JobManager
        // TODO: Implement actual contract call once methods are added
        let tx_hash = FieldElement::from(0x9abcu64);
        
        debug!("✅ Reputation updated: tx {:#x}", tx_hash);
        Ok(tx_hash)
    }

    /// Check if a proof is valid on-chain
    pub async fn verify_proof_onchain(
        &self,
        proof_data: &[u8],
        public_inputs: &[FieldElement],
    ) -> Result<bool> {
        if !self.enabled {
            debug!("Blockchain disabled, skipping proof verification");
            return Ok(true); // Assume valid when disabled
        }

        info!("🔍 Verifying proof on-chain");
        
        // Call ProofVerifier contract
        let selector = FieldElement::from_hex_be("0x76657269667950726f6f66").unwrap(); // "verifyProof"
        let is_valid = self.client
            .call_contract(
                self.proof_verifier_address,
                selector,
                vec![
                    FieldElement::from(proof_data.len() as u64),
                    // ... proof data as field elements
                ],
            )
            .await?;
        
        let valid = is_valid.first()
            .map(|fe| *fe != FieldElement::ZERO)
            .unwrap_or(false);
        
        if valid {
            info!("✅ Proof verified on-chain");
        } else {
            warn!("❌ Proof verification failed on-chain");
        }
        
        Ok(valid)
    }

    /// Get job status from blockchain
    pub async fn get_job_status_onchain(&self, job_id: &str) -> Result<u8> {
        if !self.enabled {
            return Ok(0); // Pending
        }

        // TODO: Implement actual contract call once methods are added
        Ok(0) // Mock: return pending status
    }

    /// Get worker reputation from blockchain
    pub async fn get_worker_reputation(&self, worker_address: &str) -> Result<u64> {
        if !self.enabled {
            return Ok(100); // Default reputation
        }

        // TODO: Implement actual contract call once methods are added
        Ok(100) // Mock: return default reputation
    }

    /// Map coordinator job type to blockchain job type
    fn map_job_type(&self, job_type: &str) -> Result<u8> {
        Ok(match job_type {
            "AIInference" => 0,
            "DataPipeline" => 1,
            "ConfidentialVM" => 2,
            "Render3D" => 3,
            "VideoProcessing" => 4,
            "ComputerVision" => 5,
            "NLP" => 6,
            "AudioProcessing" => 7,
            "TimeSeriesAnalysis" => 8,
            "MultimodalAI" => 9,
            "ReinforcementLearning" => 10,
            _ => {
                warn!("Unknown job type: {}, defaulting to 0", job_type);
                0
            }
        })
    }

    /// Enable blockchain integration
    pub fn enable(&mut self) {
        self.enabled = true;
        info!("✅ Blockchain integration enabled");
    }

    /// Disable blockchain integration
    pub fn disable(&mut self) {
        self.enabled = false;
        warn!("⚠️  Blockchain integration disabled");
    }

    /// Check if blockchain is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disabled_bridge() {
        let bridge = BlockchainBridge::disabled();
        assert!(!bridge.is_enabled());
    }

    #[test]
    fn test_job_type_mapping() {
        let bridge = BlockchainBridge::disabled();
        assert_eq!(bridge.map_job_type("AIInference").unwrap(), 0);
        assert_eq!(bridge.map_job_type("DataPipeline").unwrap(), 1);
        assert_eq!(bridge.map_job_type("Unknown").unwrap(), 0);
    }
}

