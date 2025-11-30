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
        // Convert JobType from coordinator to blockchain
        let job_type = match request.job_type {
            crate::node::coordinator::JobType::Custom { .. } => JobType::AIInference,
            crate::node::coordinator::JobType::Render3D { .. } => JobType::AIInference,
            crate::node::coordinator::JobType::VideoProcessing { .. } => JobType::AIInference,
            crate::node::coordinator::JobType::AIInference { .. } => JobType::AIInference,
            crate::node::coordinator::JobType::ComputerVision { .. } => JobType::ComputerVision,
            crate::node::coordinator::JobType::NLP { .. } => JobType::NLP,
            crate::node::coordinator::JobType::AudioProcessing { .. } => JobType::AudioProcessing,
            crate::node::coordinator::JobType::TimeSeriesAnalysis { .. } => JobType::TimeSeriesAnalysis,
            crate::node::coordinator::JobType::MultimodalAI { .. } => JobType::MultimodalAI,
            crate::node::coordinator::JobType::ReinforcementLearning { .. } => JobType::ReinforcementLearning,
            crate::node::coordinator::JobType::SpecializedAI { .. } => JobType::SpecializedAI,
            crate::node::coordinator::JobType::ZKProof { .. } => JobType::ProofGeneration,
            // Map new confidential types to appropriate blockchain types
            crate::node::coordinator::JobType::DataPipeline { .. } => JobType::DataPipeline,
            crate::node::coordinator::JobType::ConfidentialVM { .. } => JobType::ConfidentialVM,
        };

        Ok(JobSpec {
            job_type,
            model_id: ModelId::new(FieldElement::from(1u32)), // Default model
            input_data_hash: FieldElement::from_hex_be("0x0").unwrap(), // TODO: Compute actual hash
            expected_output_format: FieldElement::from_hex_be("0x0").unwrap(), // TODO: Define format
            verification_method: VerificationMethod::StatisticalSampling,
            max_reward: request.max_cost as u128,
            sla_deadline: request.deadline.map(|d| d.timestamp() as u64).unwrap_or(0),
            compute_requirements: vec![], // TODO: Extract from JobRequest
            metadata: vec![], // TODO: Extract from JobRequest
        })
    }

    /// Convert CoordinatorJobResult to blockchain JobResult
    fn convert_coordinator_result_to_blockchain(
        &self, 
        job_id: JobId, 
        result: &CoordinatorJobResult
    ) -> Result<JobResult> {
        Ok(JobResult {
            job_id,
            worker_id: WorkerId::new(), // TODO: Get actual worker ID
            output_data_hash: FieldElement::from_hex_be("0x0").unwrap(), // TODO: Compute actual hash
            computation_proof: vec![], // TODO: Generate proof
            gas_used: 0, // TODO: Calculate gas usage
            execution_time: result.execution_time as u64,
        })
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
        Arc::new(StarknetClient::new("https://starknet-sepolia.public.blastapi.io".to_string()).unwrap())
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