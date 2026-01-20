//! # Blockchain Contract Types
//!
//! This module defines Rust types that correspond to Cairo contract interfaces.

use serde::{Deserialize, Serialize};
use starknet::core::types::FieldElement;
use crate::types::{JobId, WorkerId};

/// Job type enumeration matching Cairo contract
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JobType {
    AIInference,
    AITraining,
    ComputerVision,
    NLP,
    AudioProcessing,
    TimeSeriesAnalysis,
    MultimodalAI,
    ReinforcementLearning,
    SpecializedAI,
    ProofGeneration,
    ProofVerification,
    DataPipeline,      // NEW
    ConfidentialVM,    // NEW
}

impl JobType {
    /// Convert to FieldElement for Cairo contract calls
    /// Uses infallible FieldElement::from() for small integer constants
    pub fn to_field_element(&self) -> FieldElement {
        match self {
            JobType::AIInference => FieldElement::from(0u8),
            JobType::AITraining => FieldElement::from(1u8),
            JobType::ComputerVision => FieldElement::from(2u8),
            JobType::NLP => FieldElement::from(3u8),
            JobType::AudioProcessing => FieldElement::from(4u8),
            JobType::TimeSeriesAnalysis => FieldElement::from(5u8),
            JobType::MultimodalAI => FieldElement::from(6u8),
            JobType::ReinforcementLearning => FieldElement::from(7u8),
            JobType::SpecializedAI => FieldElement::from(8u8),
            JobType::ProofGeneration => FieldElement::from(9u8),
            JobType::ProofVerification => FieldElement::from(10u8),
            JobType::DataPipeline => FieldElement::from(11u8),
            JobType::ConfidentialVM => FieldElement::from(12u8),
        }
    }

    /// Convert from FieldElement received from Cairo contract
    pub fn from_field_element(field: FieldElement) -> Option<Self> {
        match field {
            f if f == FieldElement::from(0u8) => Some(JobType::AIInference),
            f if f == FieldElement::from(1u8) => Some(JobType::AITraining),
            f if f == FieldElement::from(2u8) => Some(JobType::ComputerVision),
            f if f == FieldElement::from(3u8) => Some(JobType::NLP),
            f if f == FieldElement::from(4u8) => Some(JobType::AudioProcessing),
            f if f == FieldElement::from(5u8) => Some(JobType::TimeSeriesAnalysis),
            f if f == FieldElement::from(6u8) => Some(JobType::MultimodalAI),
            f if f == FieldElement::from(7u8) => Some(JobType::ReinforcementLearning),
            f if f == FieldElement::from(8u8) => Some(JobType::SpecializedAI),
            f if f == FieldElement::from(9u8) => Some(JobType::ProofGeneration),
            f if f == FieldElement::from(10u8) => Some(JobType::ProofVerification),
            f if f == FieldElement::from(11u8) => Some(JobType::DataPipeline),
            f if f == FieldElement::from(12u8) => Some(JobType::ConfidentialVM),
            _ => None,
        }
    }
}

/// Verification method enumeration matching Cairo contract
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VerificationMethod {
    None,
    StatisticalSampling,
    ZeroKnowledgeProof,
    ConsensusValidation,
}

impl VerificationMethod {
    /// Convert to FieldElement for Cairo contract calls
    /// Uses infallible FieldElement::from() for small integer constants
    pub fn to_field_element(&self) -> FieldElement {
        match self {
            VerificationMethod::None => FieldElement::from(0u8),
            VerificationMethod::StatisticalSampling => FieldElement::from(1u8),
            VerificationMethod::ZeroKnowledgeProof => FieldElement::from(2u8),
            VerificationMethod::ConsensusValidation => FieldElement::from(3u8),
        }
    }
}

/// Job state enumeration matching Cairo contract
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JobState {
    Queued,
    Processing,
    Completed,
    Failed,
    Cancelled,
}

impl JobState {
    /// Convert from FieldElement received from Cairo contract
    /// Uses infallible FieldElement::from() for comparison
    pub fn from_field_element(field: FieldElement) -> Option<Self> {
        match field {
            f if f == FieldElement::from(0u8) => Some(JobState::Queued),
            f if f == FieldElement::from(1u8) => Some(JobState::Processing),
            f if f == FieldElement::from(2u8) => Some(JobState::Completed),
            f if f == FieldElement::from(3u8) => Some(JobState::Failed),
            f if f == FieldElement::from(4u8) => Some(JobState::Cancelled),
            _ => None,
        }
    }
}

/// Model ID wrapper
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModelId(pub FieldElement);

impl ModelId {
    pub fn new(value: FieldElement) -> Self {
        Self(value)
    }
    
    pub fn value(&self) -> FieldElement {
        self.0
    }
}

/// Job specification for AI workloads
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSpec {
    pub job_type: JobType,
    pub model_id: ModelId,
    pub input_data_hash: FieldElement,
    pub expected_output_format: FieldElement,
    pub verification_method: VerificationMethod,
    pub max_reward: u128, // Will be converted to FieldElement
    pub sla_deadline: u64,
    pub compute_requirements: Vec<FieldElement>,
    pub metadata: Vec<FieldElement>,
}

impl JobSpec {
    /// Convert to calldata for Cairo contract calls
    pub fn to_calldata(&self) -> Vec<FieldElement> {
        let mut calldata = Vec::new();
        
        // Add job type
        calldata.push(self.job_type.to_field_element());
        
        // Add model ID
        calldata.push(self.model_id.value());
        
        // Add input data hash
        calldata.push(self.input_data_hash);
        
        // Add expected output format
        calldata.push(self.expected_output_format);
        
        // Add verification method
        calldata.push(self.verification_method.to_field_element());
        
        // Add max reward (split into high and low parts for u256)
        let max_reward_low = FieldElement::from(self.max_reward as u64);
        let max_reward_high = FieldElement::from((self.max_reward >> 64) as u64);
        calldata.push(max_reward_low);
        calldata.push(max_reward_high);
        
        // Add SLA deadline
        calldata.push(FieldElement::from(self.sla_deadline));
        
        // Add compute requirements array length
        calldata.push(FieldElement::from(self.compute_requirements.len()));
        calldata.extend(self.compute_requirements.clone());
        
        // Add metadata array length
        calldata.push(FieldElement::from(self.metadata.len()));
        calldata.extend(self.metadata.clone());
        
        calldata
    }
}

/// Job result from workers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResult {
    pub job_id: JobId,
    pub worker_id: WorkerId,
    pub output_data_hash: FieldElement,
    pub computation_proof: Vec<FieldElement>,
    pub gas_used: u128,
    pub execution_time: u64,
}

impl JobResult {
    /// Convert to calldata for Cairo contract calls
    pub fn to_calldata(&self) -> Vec<FieldElement> {
        let mut calldata = Vec::new();
        
        // Add job ID (convert UUID to bytes and then to FieldElement)
        let job_id_uuid = self.job_id.as_uuid();
        let job_id_bytes = job_id_uuid.as_bytes();
        let job_id_u128 = u128::from_be_bytes(*job_id_bytes);
        calldata.push(FieldElement::from(job_id_u128));
        
        // Add worker ID (convert UUID to bytes and then to FieldElement)
        let worker_id_uuid = self.worker_id.as_uuid();
        let worker_id_bytes = worker_id_uuid.as_bytes();
        let worker_id_u128 = u128::from_be_bytes(*worker_id_bytes);
        calldata.push(FieldElement::from(worker_id_u128));
        
        // Add output data hash
        calldata.push(self.output_data_hash);
        
        // Add computation proof array length
        calldata.push(FieldElement::from(self.computation_proof.len()));
        calldata.extend(self.computation_proof.clone());
        
        // Add gas used (split into high and low parts for u256)
        let gas_used_low = FieldElement::from(self.gas_used as u64);
        let gas_used_high = FieldElement::from((self.gas_used >> 64) as u64);
        calldata.push(gas_used_low);
        calldata.push(gas_used_high);
        
        // Add execution time
        calldata.push(FieldElement::from(self.execution_time));
        
        calldata
    }
}

/// Job details for queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobDetails {
    pub job_id: JobId,
    pub job_type: JobType,
    pub client: FieldElement, // ContractAddress
    pub worker: FieldElement, // ContractAddress
    pub state: JobState,
    pub payment_amount: u128,
    pub created_at: u64,
    pub assigned_at: u64,
    pub completed_at: u64,
    pub result_hash: FieldElement,
}

impl JobDetails {
    /// Parse from contract call result
    pub fn from_calldata(data: &[FieldElement]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }
        
        // Parse job ID from first field element
        let job_id_bytes = data[0].to_bytes_be();
        let job_id = JobId::from(uuid::Uuid::from_bytes(job_id_bytes[16..32].try_into().ok()?));
        
        // Parse job type
        let job_type = JobType::from_field_element(data[1])?;
        
        // Parse job state
        let state = JobState::from_field_element(data[4])?;
        
        // Parse payment amount (combine high and low parts)
        let payment_low = data[5].to_bytes_be();
        let payment_high = data[6].to_bytes_be();
        let payment_low_bytes: [u8; 8] = payment_low[24..32].try_into().ok()?;
        let payment_high_bytes: [u8; 8] = payment_high[24..32].try_into().ok()?;
        let mut payment_bytes = [0u8; 16];
        payment_bytes[0..8].copy_from_slice(&payment_high_bytes);
        payment_bytes[8..16].copy_from_slice(&payment_low_bytes);
        let payment_amount = u128::from_be_bytes(payment_bytes);
        
        Some(JobDetails {
            job_id,
            job_type,
            client: data[2],
            worker: data[3],
            state,
            payment_amount,
            created_at: u64::from_be_bytes(data[7].to_bytes_be()[24..32].try_into().ok()?),
            assigned_at: u64::from_be_bytes(data[8].to_bytes_be()[24..32].try_into().ok()?),
            completed_at: u64::from_be_bytes(data[9].to_bytes_be()[24..32].try_into().ok()?),
            result_hash: data[10],
        })
    }
}

/// Worker status enumeration matching Cairo contract
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WorkerStatus {
    Active,
    Inactive,
    Slashed,
    Exiting,
    Banned,
}

impl WorkerStatus {
    /// Convert from FieldElement received from Cairo contract
    /// Uses infallible FieldElement::from() for bitmask constants
    pub fn from_field_element(field: FieldElement) -> Option<Self> {
        match field {
            f if f == FieldElement::from(1u8) => Some(WorkerStatus::Active),
            f if f == FieldElement::from(2u8) => Some(WorkerStatus::Inactive),
            f if f == FieldElement::from(4u8) => Some(WorkerStatus::Slashed),
            f if f == FieldElement::from(8u8) => Some(WorkerStatus::Exiting),
            f if f == FieldElement::from(16u8) => Some(WorkerStatus::Banned),
            _ => None,
        }
    }
}

/// Worker capabilities matching Cairo contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerCapabilities {
    pub gpu_memory: u64,
    pub cpu_cores: u8,
    pub ram: u64,
    pub storage: u64,
    pub bandwidth: u32,
    pub capability_flags: u64,
    pub gpu_model: FieldElement,
    pub cpu_model: FieldElement,
}

impl WorkerCapabilities {
    /// Convert to calldata for Cairo contract calls
    pub fn to_calldata(&self) -> Vec<FieldElement> {
        vec![
            FieldElement::from(self.gpu_memory),
            FieldElement::from(self.cpu_cores),
            FieldElement::from(self.ram),
            FieldElement::from(self.storage),
            FieldElement::from(self.bandwidth),
            FieldElement::from(self.capability_flags),
            self.gpu_model,
            self.cpu_model,
        ]
    }
}

/// Worker profile matching Cairo contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerProfile {
    pub worker_id: WorkerId,
    pub owner: FieldElement, // ContractAddress
    pub capabilities: WorkerCapabilities,
    pub status: WorkerStatus,
    pub registered_at: u64,
    pub last_heartbeat: u64,
    pub stake_amount: u128,
    pub reputation_score: u64,
    pub jobs_completed: u32,
    pub jobs_failed: u32,
    pub total_earnings: u128,
    pub location_hash: FieldElement,
}

/// Contract function selectors (computed from function names)
/// These are compile-time constants that use `expect` with clear error messages
/// since get_selector_from_name only fails for non-ASCII strings (which we don't use)
pub mod selectors {
    use starknet::core::types::FieldElement;
    use starknet::core::utils::get_selector_from_name;

    lazy_static::lazy_static! {
        // Job Manager contract selectors (functions)
        pub static ref SUBMIT_AI_JOB: FieldElement = get_selector_from_name("submit_ai_job")
            .expect("Invalid selector name: submit_ai_job");
        pub static ref SUBMIT_PROVE_JOB: FieldElement = get_selector_from_name("submit_prove_job")
            .expect("Invalid selector name: submit_prove_job");
        pub static ref ASSIGN_JOB_TO_WORKER: FieldElement = get_selector_from_name("assign_job_to_worker")
            .expect("Invalid selector name: assign_job_to_worker");
        pub static ref SUBMIT_JOB_RESULT: FieldElement = get_selector_from_name("submit_job_result")
            .expect("Invalid selector name: submit_job_result");
        pub static ref DISTRIBUTE_REWARDS: FieldElement = get_selector_from_name("distribute_rewards")
            .expect("Invalid selector name: distribute_rewards");
        pub static ref GET_JOB_DETAILS: FieldElement = get_selector_from_name("get_job_details")
            .expect("Invalid selector name: get_job_details");
        pub static ref GET_JOB_STATE: FieldElement = get_selector_from_name("get_job_state")
            .expect("Invalid selector name: get_job_state");
        pub static ref GET_WORKER_STATS: FieldElement = get_selector_from_name("get_worker_stats")
            .expect("Invalid selector name: get_worker_stats");
        pub static ref GET_PENDING_JOBS_COUNT: FieldElement = get_selector_from_name("get_pending_jobs_count")
            .expect("Invalid selector name: get_pending_jobs_count");
        pub static ref GET_JOB_BY_INDEX: FieldElement = get_selector_from_name("get_job_by_index")
            .expect("Invalid selector name: get_job_by_index");
        pub static ref REGISTER_JOB: FieldElement = get_selector_from_name("register_job")
            .expect("Invalid selector name: register_job");
        pub static ref COMPLETE_JOB: FieldElement = get_selector_from_name("complete_job")
            .expect("Invalid selector name: complete_job");

        // CDC Pool contract selectors (functions)
        pub static ref REGISTER_WORKER: FieldElement = get_selector_from_name("register_worker")
            .expect("Invalid selector name: register_worker");
        pub static ref STAKE_TOKENS: FieldElement = get_selector_from_name("stake_tokens")
            .expect("Invalid selector name: stake_tokens");
        pub static ref UNSTAKE_TOKENS: FieldElement = get_selector_from_name("unstake_tokens")
            .expect("Invalid selector name: unstake_tokens");
        pub static ref GET_WORKER_PROFILE: FieldElement = get_selector_from_name("get_worker_profile")
            .expect("Invalid selector name: get_worker_profile");
        pub static ref UPDATE_WORKER_STATUS: FieldElement = get_selector_from_name("update_worker_status")
            .expect("Invalid selector name: update_worker_status");

        // Event selectors (for filtering contract events)
        pub static ref EVENT_JOB_SUBMITTED: FieldElement = get_selector_from_name("JobSubmitted")
            .expect("Invalid selector name: JobSubmitted");
        pub static ref EVENT_JOB_ASSIGNED: FieldElement = get_selector_from_name("JobAssigned")
            .expect("Invalid selector name: JobAssigned");
        pub static ref EVENT_JOB_COMPLETED: FieldElement = get_selector_from_name("JobCompleted")
            .expect("Invalid selector name: JobCompleted");
        pub static ref EVENT_JOB_FAILED: FieldElement = get_selector_from_name("JobFailed")
            .expect("Invalid selector name: JobFailed");
        pub static ref EVENT_JOB_CANCELLED: FieldElement = get_selector_from_name("JobCancelled")
            .expect("Invalid selector name: JobCancelled");
        pub static ref EVENT_WORKER_REGISTERED: FieldElement = get_selector_from_name("WorkerRegistered")
            .expect("Invalid selector name: WorkerRegistered");
        pub static ref EVENT_WORKER_UPDATED: FieldElement = get_selector_from_name("WorkerUpdated")
            .expect("Invalid selector name: WorkerUpdated");
        pub static ref EVENT_REWARDS_DISTRIBUTED: FieldElement = get_selector_from_name("RewardsDistributed")
            .expect("Invalid selector name: RewardsDistributed");
        pub static ref EVENT_STAKE_DEPOSITED: FieldElement = get_selector_from_name("StakeDeposited")
            .expect("Invalid selector name: StakeDeposited");
        pub static ref EVENT_STAKE_WITHDRAWN: FieldElement = get_selector_from_name("StakeWithdrawn")
            .expect("Invalid selector name: StakeWithdrawn");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_type_conversion() {
        let job_type = JobType::AIInference;
        let field = job_type.to_field_element();
        let converted_back = JobType::from_field_element(field).unwrap();
        assert_eq!(job_type, converted_back);
    }

    #[test]
    fn test_job_spec_calldata() {
        let job_spec = JobSpec {
            job_type: JobType::AIInference,
            model_id: ModelId::new(FieldElement::from_hex_be("0x123").unwrap()),
            input_data_hash: FieldElement::from_hex_be("0x456").unwrap(),
            expected_output_format: FieldElement::from_hex_be("0x789").unwrap(),
            verification_method: VerificationMethod::StatisticalSampling,
            max_reward: 1000,
            sla_deadline: 3600,
            compute_requirements: vec![FieldElement::from(8u32), FieldElement::from(16u32)],
            metadata: vec![FieldElement::from_hex_be("0xabc").unwrap()],
        };
        
        let calldata = job_spec.to_calldata();
        assert!(!calldata.is_empty());
        assert_eq!(calldata[0], JobType::AIInference.to_field_element());
    }

    #[test]
    fn test_worker_capabilities_calldata() {
        let capabilities = WorkerCapabilities {
            gpu_memory: 8192,
            cpu_cores: 16,
            ram: 32768,
            storage: 1000,
            bandwidth: 1000,
            capability_flags: 0b11111111,
            gpu_model: FieldElement::from_hex_be("0x4090").unwrap(),
            cpu_model: FieldElement::from_hex_be("0x7950").unwrap(),
        };
        
        let calldata = capabilities.to_calldata();
        assert_eq!(calldata.len(), 8);
        assert_eq!(calldata[0], FieldElement::from(8192u64));
    }
} 