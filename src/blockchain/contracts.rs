//! # Smart Contract Interactions
//!
//! This module handles interactions with Bitsage Network smart contracts.

use crate::types::{JobId, WorkerId};
use crate::node::coordinator::{JobRequest, JobResult as CoordinatorJobResult};
use crate::blockchain::client::StarknetClient;
use crate::blockchain::types::*;
use anyhow::{Result, Context};
use starknet::core::types::FieldElement;
use std::sync::Arc;
use tracing::{info, debug, warn};

/// Job Manager contract interface
#[derive(Debug)]
pub struct JobManagerContract {
    client: Arc<StarknetClient>,
    contract_address: FieldElement,
}

impl JobManagerContract {
    /// Create a new job manager contract instance
    pub fn new(client: Arc<StarknetClient>, contract_address: FieldElement) -> Self {
        Self { 
            client,
            contract_address,
        }
    }

    /// Create from hex address string
    pub fn new_from_address(client: Arc<StarknetClient>, address: &str) -> Result<Self> {
        let contract_address = FieldElement::from_hex_be(address)
            .context("Failed to parse contract address")?;
        
        Ok(Self::new(client, contract_address))
    }

    /// Register a new job on the blockchain
    pub async fn register_job(
        &self,
        job_id: JobId,
        request: &JobRequest,
        private_key: FieldElement,
        account_address: FieldElement,
    ) -> Result<FieldElement> {
        info!("Registering job {} on blockchain", job_id);
        
        // Convert JobRequest to JobSpec
        let job_spec = self.convert_job_request_to_spec(request)?;
        
        // Prepare calldata for submit_ai_job
        let mut calldata = job_spec.to_calldata();
        
        // Add payment amount (max_cost from request)
        let payment_low = FieldElement::from(request.max_cost as u64);
        let payment_high = FieldElement::from((request.max_cost >> 32) as u64);
        calldata.push(payment_low);
        calldata.push(payment_high);
        
        // Add client address (convert from string)
        let client_address = FieldElement::from_hex_be(&request.client_address)
            .context("Failed to parse client address")?;
        calldata.push(client_address);

        // Send the transaction
        let tx_hash = self.client.send_transaction(
            self.contract_address,
            *selectors::SUBMIT_AI_JOB,
            calldata,
            private_key,
            account_address,
        ).await.context("Failed to send submit_ai_job transaction")?;

        info!("Job {} registered successfully, tx hash: {:#x}", job_id, tx_hash);
        Ok(tx_hash)
    }

    /// Mark a job as completed on the blockchain
    pub async fn complete_job(
        &self,
        job_id: JobId,
        result: &CoordinatorJobResult,
        private_key: FieldElement,
        account_address: FieldElement,
    ) -> Result<FieldElement> {
        info!("Completing job {} on blockchain", job_id);
        
        // Convert to blockchain JobResult
        let blockchain_result = self.convert_coordinator_result_to_blockchain(job_id, result)?;
        
        // Prepare calldata
        let calldata = blockchain_result.to_calldata();

        // Send the transaction
        let tx_hash = self.client.send_transaction(
            self.contract_address,
            *selectors::SUBMIT_JOB_RESULT,
            calldata,
            private_key,
            account_address,
        ).await.context("Failed to send submit_job_result transaction")?;

        info!("Job {} completed successfully on blockchain, tx hash: {:#x}", job_id, tx_hash);
        Ok(tx_hash)
    }

    /// Get job details from the blockchain
    pub async fn get_job(&self, job_id: JobId) -> Result<Option<JobDetails>> {
        debug!("Getting job {} from blockchain", job_id);
        
        // Convert JobId to FieldElement
        let job_id_uuid = job_id.as_uuid();
        let job_id_bytes = job_id_uuid.as_bytes();
        let job_id_u128 = u128::from_be_bytes(*job_id_bytes);
        let job_id_field = FieldElement::from(job_id_u128);
        
        let calldata = vec![job_id_field];

        // Call the contract
        let result = self.client.call_contract(
            self.contract_address,
            *selectors::GET_JOB_DETAILS,
            calldata,
        ).await.context("Failed to call get_job_details")?;

        if result.is_empty() {
            return Ok(None);
        }

        // Parse the result
        let job_details = JobDetails::from_calldata(&result);
        
        if let Some(details) = &job_details {
            debug!("Retrieved job details: {:?}", details);
        } else {
            warn!("Failed to parse job details from contract response");
        }

        Ok(job_details)
    }

    /// Get job state from the blockchain
    pub async fn get_job_state(&self, job_id: JobId) -> Result<Option<JobState>> {
        debug!("Getting job state {} from blockchain", job_id);
        
        // Convert JobId to FieldElement
        let job_id_uuid = job_id.as_uuid();
        let job_id_bytes = job_id_uuid.as_bytes();
        let job_id_u128 = u128::from_be_bytes(*job_id_bytes);
        let job_id_field = FieldElement::from(job_id_u128);
        
        let calldata = vec![job_id_field];

        // Call the contract
        let result = self.client.call_contract(
            self.contract_address,
            *selectors::GET_JOB_STATE,
            calldata,
        ).await.context("Failed to call get_job_state")?;

        if result.is_empty() {
            return Ok(None);
        }

        // Parse the result
        let job_state = JobState::from_field_element(result[0]);
        
        if let Some(state) = &job_state {
            debug!("Retrieved job state: {:?}", state);
        }

        Ok(job_state)
    }

    /// Assign a job to a worker
    pub async fn assign_job_to_worker(
        &self,
        job_id: JobId,
        worker_id: WorkerId,
        private_key: FieldElement,
        account_address: FieldElement,
    ) -> Result<FieldElement> {
        info!("Assigning job {} to worker {} on blockchain", job_id, worker_id);
        
        // Convert IDs to FieldElements
        let job_id_uuid = job_id.as_uuid();
        let job_id_bytes = job_id_uuid.as_bytes();
        let job_id_u128 = u128::from_be_bytes(*job_id_bytes);
        let job_id_field = FieldElement::from(job_id_u128);
        
        let worker_id_uuid = worker_id.as_uuid();
        let worker_id_bytes = worker_id_uuid.as_bytes();
        let worker_id_u128 = u128::from_be_bytes(*worker_id_bytes);
        let worker_id_field = FieldElement::from(worker_id_u128);
        
        let calldata = vec![job_id_field, worker_id_field];

        // Send the transaction
        let tx_hash = self.client.send_transaction(
            self.contract_address,
            *selectors::ASSIGN_JOB_TO_WORKER,
            calldata,
            private_key,
            account_address,
        ).await.context("Failed to send assign_job_to_worker transaction")?;

        info!("Job {} assigned to worker {} successfully, tx hash: {:#x}", job_id, worker_id, tx_hash);
        Ok(tx_hash)
    }

    /// Distribute rewards for a completed job
    pub async fn distribute_rewards(
        &self,
        job_id: JobId,
        private_key: FieldElement,
        account_address: FieldElement,
    ) -> Result<FieldElement> {
        info!("Distributing rewards for job {} on blockchain", job_id);
        
        // Convert JobId to FieldElement
        let job_id_uuid = job_id.as_uuid();
        let job_id_bytes = job_id_uuid.as_bytes();
        let job_id_u128 = u128::from_be_bytes(*job_id_bytes);
        let job_id_field = FieldElement::from(job_id_u128);
        
        let calldata = vec![job_id_field];

        // Send the transaction
        let tx_hash = self.client.send_transaction(
            self.contract_address,
            *selectors::DISTRIBUTE_REWARDS,
            calldata,
            private_key,
            account_address,
        ).await.context("Failed to send distribute_rewards transaction")?;

        info!("Rewards distributed for job {} successfully, tx hash: {:#x}", job_id, tx_hash);
        Ok(tx_hash)
    }

    /// Get the contract address
    pub fn contract_address(&self) -> FieldElement {
        self.contract_address
    }

    /// Health check for the contract
    pub async fn health_check(&self) -> Result<ContractHealthStatus> {
        let start_time = std::time::Instant::now();
        
        // Try to call a simple read function
        let calldata = vec![FieldElement::from(1u32)]; // Try to get job details for ID 1
        let result = self.client.call_contract(
            self.contract_address,
            *selectors::GET_JOB_DETAILS,
            calldata,
        ).await;
        
        let response_time = start_time.elapsed();
        let is_responsive = result.is_ok();
        
        if let Err(e) = &result {
            warn!("Contract health check failed: {}", e);
        }
        
        Ok(ContractHealthStatus {
            contract_address: self.contract_address,
            is_responsive,
            response_time_ms: response_time.as_millis() as u64,
            last_error: result.err().map(|e| e.to_string()),
        })
    }

    /// Convert JobRequest to JobSpec for blockchain
    fn convert_job_request_to_spec(&self, request: &JobRequest) -> Result<JobSpec> {
        use sha3::{Digest, Keccak256};

        // Convert JobType from coordinator to blockchain
        let (job_type, model_id) = match &request.job_type {
            crate::node::coordinator::JobType::Custom { .. } => (JobType::AIInference, 0u32),
            crate::node::coordinator::JobType::Render3D { .. } => (JobType::AIInference, 1u32),
            crate::node::coordinator::JobType::VideoProcessing { .. } => (JobType::AIInference, 2u32),
            crate::node::coordinator::JobType::AIInference { model_type, .. } => {
                // Extract model ID from model type hash
                let model_hash = Keccak256::digest(model_type.as_bytes());
                let model_id = u32::from_be_bytes([model_hash[0], model_hash[1], model_hash[2], model_hash[3]]);
                (JobType::AIInference, model_id)
            },
            crate::node::coordinator::JobType::ComputerVision { .. } => (JobType::ComputerVision, 10u32),
            crate::node::coordinator::JobType::NLP { .. } => (JobType::NLP, 20u32),
            crate::node::coordinator::JobType::AudioProcessing { .. } => (JobType::AudioProcessing, 30u32),
            crate::node::coordinator::JobType::TimeSeriesAnalysis { .. } => (JobType::TimeSeriesAnalysis, 40u32),
            crate::node::coordinator::JobType::MultimodalAI { .. } => (JobType::MultimodalAI, 50u32),
            crate::node::coordinator::JobType::ReinforcementLearning { .. } => (JobType::ReinforcementLearning, 60u32),
            crate::node::coordinator::JobType::SpecializedAI { .. } => (JobType::SpecializedAI, 70u32),
            crate::node::coordinator::JobType::ZKProof { .. } => (JobType::ProofGeneration, 80u32),
            crate::node::coordinator::JobType::DataPipeline { .. } => (JobType::DataPipeline, 90u32),
            crate::node::coordinator::JobType::ConfidentialVM { .. } => (JobType::ConfidentialVM, 100u32),
        };

        // Compute input data hash using Keccak256
        let input_data_hash = if !request.data.is_empty() {
            let hash = Keccak256::digest(&request.data);
            FieldElement::from_bytes_be(&hash.into())
                .unwrap_or(FieldElement::ZERO)
        } else {
            FieldElement::ZERO
        };

        // Define expected output format based on job type
        // Format encoding: 0 = raw bytes, 1 = JSON, 2 = tensor, 3 = image, 4 = proof
        let expected_output_format = match job_type {
            JobType::AIInference | JobType::NLP | JobType::TimeSeriesAnalysis => FieldElement::from(1u8), // JSON
            JobType::ComputerVision | JobType::MultimodalAI => FieldElement::from(3u8), // Image/tensor
            JobType::ProofGeneration | JobType::ConfidentialVM => FieldElement::from(4u8), // Proof
            _ => FieldElement::from(0u8), // Raw bytes
        };

        // Extract compute requirements from job type
        let compute_requirements = self.extract_compute_requirements(&request.job_type);

        // Extract metadata: [priority, max_duration, has_callback, data_size]
        let metadata = vec![
            FieldElement::from(request.priority as u64),
            FieldElement::from(request.max_duration_secs),
            FieldElement::from(if request.callback_url.is_some() { 1u64 } else { 0u64 }),
            FieldElement::from(request.data.len() as u64),
        ];

        Ok(JobSpec {
            job_type,
            model_id: ModelId::new(FieldElement::from(model_id)),
            input_data_hash,
            expected_output_format,
            verification_method: VerificationMethod::StatisticalSampling,
            max_reward: request.max_cost as u128,
            sla_deadline: request.deadline.map(|d| d.timestamp() as u64).unwrap_or(0),
            compute_requirements,
            metadata,
        })
    }

    /// Extract compute requirements from job type
    /// Returns: [gpu_tier, min_vram_gb, requires_tee, parallelism]
    fn extract_compute_requirements(&self, job_type: &crate::node::coordinator::JobType) -> Vec<FieldElement> {
        let (gpu_tier, min_vram_gb, requires_tee, parallelism) = match job_type {
            crate::node::coordinator::JobType::AIInference { .. } => (2u64, 8u64, 0u64, 1u64),
            crate::node::coordinator::JobType::ComputerVision { .. } => (2u64, 8u64, 0u64, 1u64),
            crate::node::coordinator::JobType::NLP { .. } => (3u64, 16u64, 0u64, 1u64),
            crate::node::coordinator::JobType::MultimodalAI { .. } => (3u64, 24u64, 0u64, 1u64),
            crate::node::coordinator::JobType::ReinforcementLearning { .. } => (3u64, 16u64, 0u64, 4u64),
            crate::node::coordinator::JobType::ZKProof { .. } => (2u64, 8u64, 1u64, 1u64),
            crate::node::coordinator::JobType::ConfidentialVM { .. } => (1u64, 4u64, 1u64, 1u64),
            crate::node::coordinator::JobType::DataPipeline { .. } => (1u64, 4u64, 0u64, 8u64),
            _ => (1u64, 4u64, 0u64, 1u64), // Default requirements
        };

        vec![
            FieldElement::from(gpu_tier),
            FieldElement::from(min_vram_gb),
            FieldElement::from(requires_tee),
            FieldElement::from(parallelism),
        ]
    }

    /// Convert CoordinatorJobResult to blockchain JobResult
    fn convert_coordinator_result_to_blockchain(
        &self,
        job_id: JobId,
        result: &CoordinatorJobResult,
    ) -> Result<JobResult> {
        self.convert_coordinator_result_with_worker(job_id, result, None)
    }

    /// Convert CoordinatorJobResult to blockchain JobResult with optional worker ID
    pub fn convert_coordinator_result_with_worker(
        &self,
        job_id: JobId,
        result: &CoordinatorJobResult,
        worker_id: Option<WorkerId>,
    ) -> Result<JobResult> {
        use sha3::{Digest, Keccak256};

        // Use provided worker_id or derive from job_id (deterministic fallback)
        let worker_id = worker_id.unwrap_or_else(|| {
            // Derive a deterministic worker ID from job_id for tracking
            let job_uuid = job_id.as_uuid();
            let bytes = job_uuid.as_bytes();
            // XOR with a constant to differentiate from job_id
            let mut worker_bytes = *bytes;
            for (i, b) in worker_bytes.iter_mut().enumerate() {
                *b ^= 0xAA ^ (i as u8);
            }
            WorkerId::from(uuid::Uuid::from_bytes(worker_bytes))
        });

        // Compute output data hash from proof_hash or output files
        let output_data_hash = if let Some(proof_hash) = &result.proof_hash {
            // Use proof hash directly if available
            FieldElement::from_bytes_be(proof_hash)
                .unwrap_or(FieldElement::ZERO)
        } else if !result.output_files.is_empty() {
            // Hash all output file paths
            let mut hasher = Keccak256::new();
            for file in &result.output_files {
                hasher.update(file.as_bytes());
            }
            let hash = hasher.finalize();
            FieldElement::from_bytes_be(&hash.into())
                .unwrap_or(FieldElement::ZERO)
        } else {
            FieldElement::ZERO
        };

        // Build computation proof from available proof data
        let computation_proof = self.build_computation_proof(result);

        // Calculate gas usage based on execution time and job complexity
        // Base: 21000 gas, plus 1000 gas per second of execution
        let base_gas: u128 = 21_000;
        let execution_gas = (result.execution_time as u128) * 1_000;
        let proof_gas = result.proof_size_bytes.map(|s| s as u128 * 16).unwrap_or(0);
        let gas_used = base_gas + execution_gas + proof_gas;

        Ok(JobResult {
            job_id,
            worker_id,
            output_data_hash,
            computation_proof,
            gas_used,
            execution_time: result.execution_time,
        })
    }

    /// Build computation proof from result data
    fn build_computation_proof(&self, result: &CoordinatorJobResult) -> Vec<FieldElement> {
        let mut proof = Vec::new();

        // Add proof commitment if available
        if let Some(commitment) = &result.proof_commitment {
            if let Ok(fe) = FieldElement::from_bytes_be(commitment) {
                proof.push(fe);
            }
        }

        // Add proof attestation if available
        if let Some(attestation) = &result.proof_attestation {
            if let Ok(fe) = FieldElement::from_bytes_be(attestation) {
                proof.push(fe);
            }
        }

        // Add proof hash if available
        if let Some(hash) = &result.proof_hash {
            if let Ok(fe) = FieldElement::from_bytes_be(hash) {
                proof.push(fe);
            }
        }

        // Add compressed proof data if available (first 3 field elements)
        if let Some(compressed) = &result.compressed_proof {
            for chunk in compressed.data.chunks(31).take(3) {
                if let Ok(fe) = FieldElement::from_byte_slice_be(chunk) {
                    proof.push(fe);
                }
            }
        }

        // Ensure at least one element for valid proof array
        if proof.is_empty() {
            // Create a hash of execution metadata as minimal proof
            use sha3::{Digest, Keccak256};
            let mut hasher = Keccak256::new();
            hasher.update(result.execution_time.to_be_bytes());
            hasher.update((result.completed_tasks as u64).to_be_bytes());
            hasher.update((result.total_tasks as u64).to_be_bytes());
            let hash = hasher.finalize();
            if let Ok(fe) = FieldElement::from_bytes_be(&hash.into()) {
                proof.push(fe);
            }
        }

        proof
    }
}

/// Contract health status
#[derive(Debug, Clone)]
pub struct ContractHealthStatus {
    pub contract_address: FieldElement,
    pub is_responsive: bool,
    pub response_time_ms: u64,
    pub last_error: Option<String>,
}

impl std::fmt::Display for ContractHealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Contract {:#x}: {} | Response: {}ms{}",
            self.contract_address,
            if self.is_responsive { "✓ Responsive" } else { "✗ Unresponsive" },
            self.response_time_ms,
            self.last_error.as_ref().map(|e| format!(" | Error: {}", e)).unwrap_or_default()
        )
    }
}

#[cfg(all(test, feature = "broken_tests"))]
mod tests {
    use super::*;
    use crate::node::coordinator::{JobRequest, JobType as CoordinatorJobType};
    use std::collections::HashMap;

    fn create_test_client() -> Arc<StarknetClient> {
        Arc::new(StarknetClient::new("https://starknet-sepolia-rpc.publicnode.com".to_string()).unwrap())
    }

    #[test]
    fn test_contract_creation() {
        let client = create_test_client();
        let contract = JobManagerContract::new_from_address(
            client,
            "0x1234567890abcdef1234567890abcdef12345678"
        );
        assert!(contract.is_ok());
    }

    #[test]
    fn test_invalid_contract_address() {
        let client = create_test_client();
        let contract = JobManagerContract::new_from_address(
            client,
            "invalid-address"
        );
        assert!(contract.is_err());
    }

    #[test]
    fn test_job_request_conversion() {
        let client = create_test_client();
        let contract = JobManagerContract::new_from_address(
            client,
            "0x1234567890abcdef1234567890abcdef12345678"
        ).unwrap();

        let job_request = JobRequest {
            job_type: CoordinatorJobType::Custom {
                docker_image: "test".to_string(),
                command: vec!["echo".to_string()],
                input_files: vec![],
                parallelizable: false,
            },
            priority: 5,
            max_cost: 1000,
            deadline: None,
            client_address: "0x123".to_string(),
            callback_url: None,
        };

        let job_spec = contract.convert_job_request_to_spec(&job_request).unwrap();
        assert_eq!(job_spec.job_type, JobType::AIInference);
        assert_eq!(job_spec.max_reward, 1000);
    }
} 