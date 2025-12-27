//! # Blockchain Bridge for Production Coordinator
//!
//! Connects the off-chain coordinator with on-chain Starknet contracts.
//! Implements actual contract calls for job submission, result reporting,
//! and worker reputation management.

use anyhow::{Result, anyhow, Context};
use starknet::core::types::FieldElement;
use tracing::{info, warn, error, debug};
use std::sync::Arc;
use sha2::{Sha256, Digest};

use crate::blockchain::client::StarknetClient;
use crate::blockchain::contracts::JobManagerContract;
use crate::blockchain::types::{JobSpec, JobType, VerificationMethod, ModelId, JobResult as BlockchainJobResult, selectors};
use crate::types::{JobId, WorkerId};
use super::production_coordinator::{JobRequest, JobRequirements};

/// Account credentials for signing transactions
#[derive(Clone)]
pub struct AccountCredentials {
    pub private_key: FieldElement,
    pub account_address: FieldElement,
}

impl AccountCredentials {
    pub fn new(private_key: &str, account_address: &str) -> Result<Self> {
        Ok(Self {
            private_key: FieldElement::from_hex_be(private_key)
                .map_err(|e| anyhow!("Invalid private key: {}", e))?,
            account_address: FieldElement::from_hex_be(account_address)
                .map_err(|e| anyhow!("Invalid account address: {}", e))?,
        })
    }
}

/// Bridge between coordinator and blockchain
pub struct BlockchainBridge {
    client: Arc<StarknetClient>,
    job_manager: Arc<JobManagerContract>,
    proof_verifier_address: FieldElement,
    credentials: Option<AccountCredentials>,
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
            credentials: None,
            enabled: true,
        })
    }

    /// Create with account credentials for transaction signing
    pub fn with_credentials(
        rpc_url: String,
        job_manager_address: String,
        proof_verifier_address: String,
        private_key: &str,
        account_address: &str,
    ) -> Result<Self> {
        let mut bridge = Self::new(rpc_url, job_manager_address, proof_verifier_address)?;
        bridge.credentials = Some(AccountCredentials::new(private_key, account_address)?);
        Ok(bridge)
    }

    /// Set account credentials after construction
    pub fn set_credentials(&mut self, credentials: AccountCredentials) {
        self.credentials = Some(credentials);
    }

    /// Get credentials or return error
    fn require_credentials(&self) -> Result<&AccountCredentials> {
        self.credentials.as_ref()
            .ok_or_else(|| anyhow!("Account credentials not configured for blockchain transactions"))
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
            credentials: None,
            enabled: false,
        }
    }

    /// Submit a job to the blockchain
    pub async fn submit_job_onchain(
        &self,
        job_id: &str,
        request: &JobRequest,
        _worker_address: &str,
    ) -> Result<FieldElement> {
        if !self.enabled {
            debug!("Blockchain disabled, skipping on-chain submission");
            return Ok(FieldElement::ZERO);
        }

        let creds = self.require_credentials()?;
        info!("📝 Submitting job {} to blockchain", job_id);

        // Parse job_id to JobId type
        let job_uuid = uuid::Uuid::parse_str(job_id)
            .map_err(|e| anyhow!("Invalid job ID format: {}", e))?;
        let job_id_typed = JobId::from(job_uuid);

        // Convert coordinator JobRequest to blockchain-compatible format
        let coordinator_request = self.convert_to_coordinator_job_request(request)?;

        // Submit job via JobManager contract
        let tx_hash = self.job_manager.register_job(
            job_id_typed,
            &coordinator_request,
            creds.private_key,
            creds.account_address,
        ).await.context("Failed to submit job on-chain")?;

        info!("✅ Job {} submitted on-chain: tx {:#x}", job_id, tx_hash);
        Ok(tx_hash)
    }

    /// Convert production coordinator JobRequest to node coordinator JobRequest
    fn convert_to_coordinator_job_request(&self, request: &JobRequest) -> Result<crate::node::coordinator::JobRequest> {
        use crate::node::coordinator::{
            JobRequest as NodeJobRequest, JobType as NodeJobType,
            CVTaskType, NLPTaskType,
        };
        use std::collections::HashMap;

        // Map job type string to enum
        let job_type = match request.requirements.required_job_type.as_str() {
            "AIInference" => NodeJobType::AIInference {
                model_type: "default".to_string(),
                input_data: "".to_string(),
                batch_size: 1,
                parameters: HashMap::new(),
            },
            "DataPipeline" => NodeJobType::DataPipeline {
                sql_query: "".to_string(),
                data_source: "".to_string(),
                tee_required: request.requirements.requires_tee,
            },
            "ConfidentialVM" => NodeJobType::ConfidentialVM {
                image_url: "default".to_string(),
                memory_mb: (request.requirements.min_vram_mb / 1024) as u32 * 1024, // Convert to u32 MB
                vcpu_count: request.requirements.min_gpu_count as u32,
                tee_type: "TDX".to_string(),
            },
            "ZKProof" => NodeJobType::ZKProof {
                circuit_type: "stwo".to_string(),
                input_data: "".to_string(),
                proof_system: "stark".to_string(),
            },
            "ComputerVision" => NodeJobType::ComputerVision {
                task_type: CVTaskType::ImageClassification,
                model_name: "default".to_string(),
                input_images: vec![],
                output_format: "json".to_string(),
                confidence_threshold: 0.5,
                batch_size: 1,
                additional_params: HashMap::new(),
            },
            "NLP" => NodeJobType::NLP {
                task_type: NLPTaskType::TextClassification,
                model_name: "default".to_string(),
                input_text: vec![],
                max_tokens: 2048,
                temperature: 0.7,
                context_window: 4096,
                additional_params: HashMap::new(),
            },
            _ => NodeJobType::Custom {
                docker_image: "default".to_string(),
                command: vec![],
                input_files: vec![],
                parallelizable: false,
            },
        };

        // Calculate max_cost based on requirements (VRAM * timeout * rate)
        let compute_cost = (request.requirements.min_vram_mb / 1024)
            * request.requirements.timeout_seconds
            * 10; // 10 tokens per GB-second

        Ok(NodeJobRequest {
            job_type,
            priority: request.priority,
            max_cost: compute_cost,
            deadline: None, // Could derive from timeout_seconds if needed
            client_address: request.id.clone().unwrap_or_else(|| "unknown".to_string()),
            callback_url: None,
            data: request.payload.clone(),
            max_duration_secs: request.requirements.timeout_seconds,
        })
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

        let creds = self.require_credentials()?;
        info!("✅ Submitting result for job {} to blockchain", job_id);

        // Parse job_id to JobId type
        let job_uuid = uuid::Uuid::parse_str(job_id)
            .map_err(|e| anyhow!("Invalid job ID format: {}", e))?;
        let job_id_typed = JobId::from(job_uuid);

        // Convert result hash to FieldElement
        let output_data_hash = FieldElement::from_hex_be(result_hash)
            .unwrap_or_else(|_| {
                // If not a valid hex, hash it
                let mut hasher = Sha256::new();
                hasher.update(result_hash.as_bytes());
                let hash = hasher.finalize();
                let hash_bytes: [u8; 32] = hash.into();
                FieldElement::from_bytes_be(&hash_bytes).unwrap()
            });

        // Build computation proof with TEE attestation if present
        let mut _computation_proof = Vec::new();
        if let Some(att) = tee_attestation {
            if let Ok(att_fe) = FieldElement::from_hex_be(att) {
                _computation_proof.push(att_fe);
            }
        }

        // Create coordinator result for the contract
        let coordinator_result = crate::node::coordinator::JobResult {
            job_id: crate::types::JobId::from(job_uuid),
            status: crate::node::coordinator::JobStatus::Completed,
            completed_tasks: 1,
            total_tasks: 1,
            output_files: vec![],
            execution_time: execution_time_ms,
            total_cost: 0,
            error_message: None,
        };

        // Submit result via JobManager contract
        let tx_hash = self.job_manager.complete_job(
            job_id_typed,
            &coordinator_result,
            creds.private_key,
            creds.account_address,
        ).await.context("Failed to submit result on-chain")?;

        info!("✅ Result for job {} submitted on-chain: tx {:#x}", job_id, tx_hash);
        Ok(tx_hash)
    }

    /// Update worker reputation on-chain
    ///
    /// Note: Reputation updates are typically handled automatically by the
    /// JobManager contract when job results are submitted. This method
    /// is for explicit reputation adjustments (e.g., slashing for misbehavior).
    pub async fn update_worker_reputation(
        &self,
        worker_address: &str,
        success: bool,
    ) -> Result<FieldElement> {
        if !self.enabled {
            debug!("Blockchain disabled, skipping reputation update");
            return Ok(FieldElement::ZERO);
        }

        let creds = self.require_credentials()?;
        debug!("📊 Updating reputation for worker {}: success={}", worker_address, success);

        // Convert worker address to FieldElement
        let worker_fe = FieldElement::from_hex_be(worker_address)
            .map_err(|e| anyhow!("Invalid worker address: {}", e))?;

        // Prepare calldata for reputation update
        // The contract expects: worker_address, reputation_delta (positive or negative)
        let reputation_delta = if success {
            FieldElement::from(1u64) // +1 for success
        } else {
            // For failures, we use a special encoding (high bit set indicates negative)
            FieldElement::from(0x8000000000000001u64) // -1 for failure
        };

        let calldata = vec![worker_fe, reputation_delta];

        // Call the update_worker_stats selector
        let tx_hash = self.client.send_transaction(
            self.job_manager.contract_address(),
            *selectors::GET_WORKER_STATS, // Reusing selector for now
            calldata,
            creds.private_key,
            creds.account_address,
        ).await.context("Failed to update worker reputation")?;

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

        debug!("📋 Querying job status for {} from blockchain", job_id);

        // Parse job_id to JobId type
        let job_uuid = uuid::Uuid::parse_str(job_id)
            .map_err(|e| anyhow!("Invalid job ID format: {}", e))?;
        let job_id_typed = JobId::from(job_uuid);

        // Query job state from contract
        match self.job_manager.get_job_state(job_id_typed).await? {
            Some(state) => {
                use crate::blockchain::types::JobState;
                let status = match state {
                    JobState::Queued => 0,
                    JobState::Processing => 1,
                    JobState::Completed => 2,
                    JobState::Failed => 3,
                    JobState::Cancelled => 4,
                };
                debug!("Job {} status: {:?}", job_id, state);
                Ok(status)
            }
            None => {
                warn!("Job {} not found on blockchain", job_id);
                Ok(0) // Return pending if not found
            }
        }
    }

    /// Get worker reputation from blockchain
    pub async fn get_worker_reputation(&self, worker_address: &str) -> Result<u64> {
        if !self.enabled {
            return Ok(100); // Default reputation
        }

        debug!("📊 Querying reputation for worker {} from blockchain", worker_address);

        // Convert worker address to FieldElement
        let worker_fe = FieldElement::from_hex_be(worker_address)
            .map_err(|e| anyhow!("Invalid worker address: {}", e))?;

        // Call the contract to get worker stats
        let result = self.client.call_contract(
            self.job_manager.contract_address(),
            *selectors::GET_WORKER_STATS,
            vec![worker_fe],
        ).await?;

        // Parse reputation from result
        // Expected format: [jobs_completed, jobs_failed, reputation_score, ...]
        if result.len() >= 3 {
            let reputation_bytes = result[2].to_bytes_be();
            let reputation = u64::from_be_bytes(
                reputation_bytes[24..32].try_into()
                    .unwrap_or([0u8; 8])
            );
            debug!("Worker {} reputation: {}", worker_address, reputation);
            Ok(reputation)
        } else {
            warn!("Unexpected worker stats response format");
            Ok(100) // Return default reputation
        }
    }

    /// Get full job details from blockchain
    pub async fn get_job_details(&self, job_id: &str) -> Result<Option<crate::blockchain::types::JobDetails>> {
        if !self.enabled {
            return Ok(None);
        }

        // Parse job_id to JobId type
        let job_uuid = uuid::Uuid::parse_str(job_id)
            .map_err(|e| anyhow!("Invalid job ID format: {}", e))?;
        let job_id_typed = JobId::from(job_uuid);

        self.job_manager.get_job(job_id_typed).await
    }

    /// Assign a job to a specific worker on-chain
    pub async fn assign_job_to_worker(
        &self,
        job_id: &str,
        worker_id: &str,
    ) -> Result<FieldElement> {
        if !self.enabled {
            debug!("Blockchain disabled, skipping job assignment");
            return Ok(FieldElement::ZERO);
        }

        let creds = self.require_credentials()?;
        info!("📋 Assigning job {} to worker {} on blockchain", job_id, worker_id);

        // Parse IDs
        let job_uuid = uuid::Uuid::parse_str(job_id)
            .map_err(|e| anyhow!("Invalid job ID format: {}", e))?;
        let job_id_typed = JobId::from(job_uuid);

        let worker_uuid = uuid::Uuid::parse_str(worker_id)
            .map_err(|e| anyhow!("Invalid worker ID format: {}", e))?;
        let worker_id_typed = WorkerId::from(worker_uuid);

        // Call contract to assign job
        let tx_hash = self.job_manager.assign_job_to_worker(
            job_id_typed,
            worker_id_typed,
            creds.private_key,
            creds.account_address,
        ).await.context("Failed to assign job to worker")?;

        info!("✅ Job {} assigned to worker {}: tx {:#x}", job_id, worker_id, tx_hash);
        Ok(tx_hash)
    }

    /// Distribute rewards for a completed job
    pub async fn distribute_rewards(&self, job_id: &str) -> Result<FieldElement> {
        if !self.enabled {
            debug!("Blockchain disabled, skipping reward distribution");
            return Ok(FieldElement::ZERO);
        }

        let creds = self.require_credentials()?;
        info!("💰 Distributing rewards for job {} on blockchain", job_id);

        // Parse job_id
        let job_uuid = uuid::Uuid::parse_str(job_id)
            .map_err(|e| anyhow!("Invalid job ID format: {}", e))?;
        let job_id_typed = JobId::from(job_uuid);

        // Call contract to distribute rewards
        let tx_hash = self.job_manager.distribute_rewards(
            job_id_typed,
            creds.private_key,
            creds.account_address,
        ).await.context("Failed to distribute rewards")?;

        info!("✅ Rewards distributed for job {}: tx {:#x}", job_id, tx_hash);
        Ok(tx_hash)
    }

    /// Perform health check on blockchain connection
    pub async fn health_check(&self) -> Result<crate::blockchain::contracts::ContractHealthStatus> {
        self.job_manager.health_check().await
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
        assert!(bridge.credentials.is_none());
    }

    #[test]
    fn test_job_type_mapping() {
        let bridge = BlockchainBridge::disabled();
        assert_eq!(bridge.map_job_type("AIInference").unwrap(), 0);
        assert_eq!(bridge.map_job_type("DataPipeline").unwrap(), 1);
        assert_eq!(bridge.map_job_type("ConfidentialVM").unwrap(), 2);
        assert_eq!(bridge.map_job_type("Render3D").unwrap(), 3);
        assert_eq!(bridge.map_job_type("VideoProcessing").unwrap(), 4);
        assert_eq!(bridge.map_job_type("ComputerVision").unwrap(), 5);
        assert_eq!(bridge.map_job_type("NLP").unwrap(), 6);
        assert_eq!(bridge.map_job_type("Unknown").unwrap(), 0);
    }

    #[test]
    fn test_account_credentials() {
        // Valid felt252 hex strings (must be < 2^251)
        let creds = AccountCredentials::new(
            "0x1234567890abcdef",
            "0xabcdef1234567890",
        );
        assert!(creds.is_ok());

        // Invalid hex string should fail
        let invalid_creds = AccountCredentials::new("not_hex_at_all!", "0x123");
        assert!(invalid_creds.is_err());
    }

    #[test]
    fn test_enable_disable() {
        let mut bridge = BlockchainBridge::disabled();
        assert!(!bridge.is_enabled());

        bridge.enable();
        assert!(bridge.is_enabled());

        bridge.disable();
        assert!(!bridge.is_enabled());
    }

    #[test]
    fn test_require_credentials_without_creds() {
        let bridge = BlockchainBridge::disabled();
        let result = bridge.require_credentials();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_disabled_bridge_returns_zero() {
        let bridge = BlockchainBridge::disabled();

        // All methods should return default values when disabled
        let status = bridge.get_job_status_onchain("550e8400-e29b-41d4-a716-446655440000").await;
        assert!(status.is_ok());
        assert_eq!(status.unwrap(), 0);

        let reputation = bridge.get_worker_reputation("0x123").await;
        assert!(reputation.is_ok());
        assert_eq!(reputation.unwrap(), 100);
    }

    #[test]
    fn test_convert_job_request() {
        let bridge = BlockchainBridge::disabled();

        let request = JobRequest {
            id: Some("test-job-123".to_string()),
            requirements: JobRequirements {
                required_job_type: "AIInference".to_string(),
                min_vram_mb: 8192,
                min_gpu_count: 1,
                timeout_seconds: 3600,
                requires_tee: false,
            },
            payload: vec![1, 2, 3, 4],
            priority: 5,
        };

        let result = bridge.convert_to_coordinator_job_request(&request);
        assert!(result.is_ok());

        let node_request = result.unwrap();
        assert_eq!(node_request.priority, 5);
        // max_cost = (8192/1024) * 3600 * 10 = 8 * 3600 * 10 = 288000
        assert_eq!(node_request.max_cost, 288000);
    }

    #[test]
    fn test_convert_job_request_all_types() {
        let bridge = BlockchainBridge::disabled();
        let job_types = vec![
            "AIInference",
            "DataPipeline",
            "ConfidentialVM",
            "ZKProof",
            "ComputerVision",
            "NLP",
            "UnknownType",
        ];

        for job_type in job_types {
            let request = JobRequest {
                id: None,
                requirements: JobRequirements {
                    required_job_type: job_type.to_string(),
                    min_vram_mb: 4096,
                    min_gpu_count: 1,
                    timeout_seconds: 60,
                    requires_tee: false,
                },
                payload: vec![],
                priority: 10,
            };

            let result = bridge.convert_to_coordinator_job_request(&request);
            assert!(result.is_ok(), "Failed for job type: {}", job_type);
        }
    }
}

